import { deflateSync, inflateSync } from "node:zlib";
import { inspectStructure } from "./inspectors.js";
import { PixwardenError, type ResourceLimits } from "./types.js";

const limits: ResourceLimits = Object.freeze({
  maxBytes: 10 * 1024 * 1024, maxWidth: 40_000, maxHeight: 40_000,
  maxPixels: 1_000_000, maxFrames: 1, maxMetadataBytes: 1024 * 1024
});
const signature = Uint8Array.of(137, 80, 78, 71, 13, 10, 26, 10);

export interface PngRasterSanitizationResult {
  readonly bytes: Uint8Array;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly width: number;
  readonly height: number;
  readonly removedChunks: Readonly<Record<string, number>>;
  readonly postCheckStatus: "passed";
}

/**
 * Decode and reconstruct non-interlaced 8-bit RGBA PNG pixels, then emit a
 * minimal PNG containing only IHDR, IDAT, and IEND. This deliberately narrow
 * transform rejects animation and other PNG color/interlace profiles.
 */
export function sanitizePngRgba8(input: Uint8Array): PngRasterSanitizationResult {
  if (!(input instanceof Uint8Array)) throw new PixwardenError("INVALID_OPTIONS", "PNG input must be a Uint8Array.");
  const snapshot = Uint8Array.from(input);
  if (snapshot.byteLength > limits.maxBytes) throw new PixwardenError("INPUT_TOO_LARGE", "PNG input exceeds the raster sanitizer byte limit.");
  const inspection = inspectStructure(snapshot, limits);
  if (inspection.format !== "png" || inspection.validity !== "valid" || inspection.findings.some((item) => item.id.startsWith("IMG-") || item.id === "DEC-007")) {
    throw new PixwardenError("SANITIZATION_FAILURE", "Only structurally valid PNGs within the raster sanitizer limits can be decoded.");
  }

  const width = readU32BE(snapshot, 16);
  const height = readU32BE(snapshot, 20);
  if (width < 1 || height < 1 || width > Math.floor(limits.maxPixels / height)) {
    throw new PixwardenError("LIMIT_EXCEEDED", "PNG dimensions exceed the one-million-pixel raster sanitizer limit.");
  }
  if (snapshot[24] !== 8 || snapshot[25] !== 6 || snapshot[28] !== 0) {
    throw new PixwardenError("UNSUPPORTED_CAPABILITY", "Raster sanitization supports only non-interlaced 8-bit RGBA PNG images.");
  }

  const idat: Buffer[] = [];
  const removedChunks: Record<string, number> = {};
  let offset = 8;
  while (offset < snapshot.byteLength) {
    const length = readU32BE(snapshot, offset);
    const type = String.fromCharCode(snapshot[offset + 4]!, snapshot[offset + 5]!, snapshot[offset + 6]!, snapshot[offset + 7]!);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (["acTL", "fcTL", "fdAT"].includes(type)) {
      throw new PixwardenError("UNSUPPORTED_CAPABILITY", "Animated PNG is not supported by the raster sanitizer.");
    }
    if (type === "IDAT") idat.push(Buffer.from(snapshot.subarray(dataStart, dataEnd)));
    else if (type !== "IHDR" && type !== "IEND") removedChunks[type] = (removedChunks[type] ?? 0) + 1;
    offset = dataEnd + 4;
  }

  const rowBytes = width * 4;
  const expectedInflatedBytes = height * (rowBytes + 1);
  let filtered: Buffer;
  let compressedInput: Buffer;
  let consumedBytes: number;
  try {
    compressedInput = Buffer.concat(idat);
    const output: unknown = inflateSync(compressedInput, { maxOutputLength: expectedInflatedBytes, info: true });
    if (output === null || typeof output !== "object" || !("buffer" in output) || !("engine" in output)) throw new Error("Invalid zlib result");
    const details = output as { readonly buffer: unknown; readonly engine: unknown };
    if (!Buffer.isBuffer(details.buffer) || details.engine === null || typeof details.engine !== "object" || !("bytesWritten" in details.engine)) {
      throw new Error("Invalid zlib result metadata");
    }
    const bytesWritten = details.engine.bytesWritten;
    if (typeof bytesWritten !== "number" || !Number.isSafeInteger(bytesWritten)) throw new Error("Invalid zlib input count");
    filtered = details.buffer;
    consumedBytes = bytesWritten;
  } catch {
    throw new PixwardenError("MALFORMED_INPUT", "PNG image data could not be inflated within the sanitizer output bound.");
  }
  if (consumedBytes !== compressedInput.byteLength) throw new PixwardenError("MALFORMED_INPUT", "PNG image data has trailing bytes after its compressed stream.");
  if (filtered.byteLength !== expectedInflatedBytes) throw new PixwardenError("MALFORMED_INPUT", "Inflated PNG scanline size does not match its dimensions.");
  const pixels = unfilterRgba(filtered, width, height);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6;
  const encodedPixels = Buffer.alloc(expectedInflatedBytes);
  for (let y = 0; y < height; y++) encodedPixels.set(pixels.subarray(y * rowBytes, (y + 1) * rowBytes), y * (rowBytes + 1) + 1);
  const compressedPixels = deflateSync(encodedPixels);
  try {
    if (!inflateSync(compressedPixels, { maxOutputLength: expectedInflatedBytes, rejectGarbageAfterEnd: true }).equals(encodedPixels)) {
      throw new Error("PNG pixel post-check mismatch");
    }
  } catch {
    throw new PixwardenError("SANITIZATION_FAILURE", "Recompressed PNG pixels failed post-check.");
  }
  const output = Buffer.concat([Buffer.from(signature), pngChunk("IHDR", ihdr), pngChunk("IDAT", compressedPixels), pngChunk("IEND", Buffer.alloc(0))]);
  if (output.byteLength > limits.maxBytes) throw new PixwardenError("LIMIT_EXCEEDED", "Sanitized PNG output exceeds the byte limit.");
  const postCheck = inspectStructure(output, limits);
  if (postCheck.format !== "png" || postCheck.validity !== "valid" || postCheck.findings.some((item) => item.id.startsWith("IMG-") || item.id === "DEC-007")) {
    throw new PixwardenError("SANITIZATION_FAILURE", "Reconstructed PNG did not pass structural post-check.");
  }
  return Object.freeze({ bytes: Uint8Array.from(output), inputBytes: snapshot.byteLength, outputBytes: output.byteLength, width, height, removedChunks: Object.freeze(removedChunks), postCheckStatus: "passed" });
}

function unfilterRgba(filtered: Buffer, width: number, height: number): Buffer {
  const rowBytes = width * 4;
  const pixels = Buffer.alloc(rowBytes * height);
  let sourceOffset = 0;
  for (let y = 0; y < height; y++) {
    const filter = filtered[sourceOffset++]!;
    if (filter > 4) throw new PixwardenError("MALFORMED_INPUT", "PNG scanline uses an unknown filter type.");
    const rowStart = y * rowBytes;
    const previousStart = rowStart - rowBytes;
    for (let x = 0; x < rowBytes; x++) {
      const raw = filtered[sourceOffset++]!;
      const left = x >= 4 ? pixels[rowStart + x - 4]! : 0;
      const above = y > 0 ? pixels[previousStart + x]! : 0;
      const upperLeft = y > 0 && x >= 4 ? pixels[previousStart + x - 4]! : 0;
      let predictor = 0;
      if (filter === 1) predictor = left;
      else if (filter === 2) predictor = above;
      else if (filter === 3) predictor = Math.floor((left + above) / 2);
      else if (filter === 4) predictor = paeth(left, above, upperLeft);
      pixels[rowStart + x] = (raw + predictor) & 0xff;
    }
  }
  return pixels;
}

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a); const pb = Math.abs(p - b); const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

function pngChunk(type: string, payload: Buffer): Buffer {
  const typeAndPayload = Buffer.concat([Buffer.from(type, "ascii"), payload]);
  const header = Buffer.alloc(4); header.writeUInt32BE(payload.byteLength);
  const checksum = Buffer.alloc(4); checksum.writeUInt32BE(crc32(typeAndPayload));
  return Buffer.concat([header, typeAndPayload, checksum]);
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffff_ffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb8_8320 : 0);
  }
  return (crc ^ 0xffff_ffff) >>> 0;
}

function readU32BE(bytes: Uint8Array, offset: number): number {
  return bytes[offset]! * 0x1000000 + bytes[offset + 1]! * 0x10000 + bytes[offset + 2]! * 0x100 + bytes[offset + 3]!;
}
