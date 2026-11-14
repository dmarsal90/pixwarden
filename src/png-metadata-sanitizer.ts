import { inspectStructure } from "./inspectors.js";
import { PixwardenError, type ResourceLimits } from "./types.js";

const limits: ResourceLimits = Object.freeze({
  maxBytes: 10 * 1024 * 1024, maxWidth: 40_000, maxHeight: 40_000,
  maxPixels: 40_000_000, maxFrames: 200, maxMetadataBytes: 1024 * 1024
});
const removedTypes = new Set(["eXIf", "tEXt", "zTXt", "iTXt"]);
const signature = [137, 80, 78, 71, 13, 10, 26, 10] as const;

export interface PngMetadataSanitizationResult {
  readonly bytes: Uint8Array;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly removedChunks: Readonly<Record<string, number>>;
  readonly postCheckStatus: "passed";
}

/**
 * Remove PNG EXIF and textual metadata chunks without decoding image data.
 * This is a limited privacy transform, not raster canonicalization. ICC,
 * unknown ancillary chunks, and all IDAT bytes are retained.
 */
export function stripPngExifAndTextMetadata(input: Uint8Array): PngMetadataSanitizationResult {
  if (!(input instanceof Uint8Array)) throw new PixwardenError("INVALID_OPTIONS", "PNG input must be a Uint8Array.");
  const snapshot = Uint8Array.from(input);
  if (snapshot.byteLength > limits.maxBytes) throw new PixwardenError("INPUT_TOO_LARGE", "PNG input exceeds the sanitizer byte limit.");
  const inspection = inspectStructure(snapshot, limits);
  if (inspection.format !== "png" || inspection.validity !== "valid" || inspection.findings.some((item) => item.id.startsWith("IMG-") || item.id === "DEC-007")) {
    throw new PixwardenError("SANITIZATION_FAILURE", "Only structurally valid PNGs within the built-in dimension limits can be transformed.");
  }

  const pieces: Uint8Array[] = [snapshot.subarray(0, 8)];
  const removedChunks: Record<string, number> = {};
  let offset = 8;
  while (offset < snapshot.byteLength) {
    const length = snapshot[offset]! * 0x1000000 + snapshot[offset + 1]! * 0x10000 + snapshot[offset + 2]! * 0x100 + snapshot[offset + 3]!;
    const end = offset + 12 + length;
    const type = String.fromCharCode(snapshot[offset + 4]!, snapshot[offset + 5]!, snapshot[offset + 6]!, snapshot[offset + 7]!);
    if (removedTypes.has(type)) removedChunks[type] = (removedChunks[type] ?? 0) + 1;
    else pieces.push(snapshot.subarray(offset, end));
    offset = end;
  }
  const outputLength = pieces.reduce((total, piece) => total + piece.byteLength, 0);
  const bytes = new Uint8Array(outputLength);
  let cursor = 0;
  for (const piece of pieces) { bytes.set(piece, cursor); cursor += piece.byteLength; }
  const check = inspectStructure(bytes, limits);
  if (check.format !== "png" || check.validity !== "valid" || check.findings.some((item) => item.id.startsWith("IMG-") || item.id === "DEC-007")) {
    throw new PixwardenError("SANITIZATION_FAILURE", "PNG output failed structural post-check.");
  }
  for (let i = 0; i < signature.length; i++) if (bytes[i] !== signature[i]) throw new PixwardenError("SANITIZATION_FAILURE", "PNG output signature changed unexpectedly.");
  if (containsRemovedChunk(bytes)) throw new PixwardenError("SANITIZATION_FAILURE", "PNG metadata targeted by this transform remains in the output.");
  return Object.freeze({ bytes, inputBytes: snapshot.byteLength, outputBytes: bytes.byteLength, removedChunks: Object.freeze(removedChunks), postCheckStatus: "passed" });
}

function containsRemovedChunk(bytes: Uint8Array): boolean {
  let offset = 8;
  while (offset < bytes.byteLength) {
    const length = bytes[offset]! * 0x1000000 + bytes[offset + 1]! * 0x10000 + bytes[offset + 2]! * 0x100 + bytes[offset + 3]!;
    const type = String.fromCharCode(bytes[offset + 4]!, bytes[offset + 5]!, bytes[offset + 6]!, bytes[offset + 7]!);
    if (removedTypes.has(type)) return true;
    offset += 12 + length;
  }
  return false;
}
