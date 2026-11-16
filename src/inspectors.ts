import type { BinaryInspectionResult, Evidence, Finding, ImageFormat, ResourceLimits } from "./types.js";
import { crc32 } from "./crc32.js";
import { inspectSvg } from "./svg-guard.js";

export interface StructuralInspection {
  readonly format: ImageFormat;
  readonly validity: "valid" | "invalid" | "unknown";
  readonly findings: readonly Finding[];
  readonly metadataBytes: number;
  readonly width?: number;
  readonly height?: number;
  readonly frameCount?: number;
}

const pngSignature = [137, 80, 78, 71, 13, 10, 26, 10] as const;
const jpegSof = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

function eqAscii(data: Uint8Array, offset: number, text: string): boolean {
  if (offset < 0 || offset + text.length > data.length) return false;
  for (let i = 0; i < text.length; i++) if (data[offset + i] !== text.charCodeAt(i)) return false;
  return true;
}

function isPng(data: Uint8Array): boolean {
  return data.length >= pngSignature.length && pngSignature.every((byte, index) => data[index] === byte);
}

function detectFormat(data: Uint8Array): ImageFormat {
  if (isPng(data)) return "png";
  if (data.length >= 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff) return "jpeg";
  if (eqAscii(data, 0, "GIF87a") || eqAscii(data, 0, "GIF89a")) return "gif";
  if (eqAscii(data, 0, "RIFF") && eqAscii(data, 8, "WEBP")) return "webp";
  const prefix = new TextDecoder().decode(data.subarray(0, Math.min(data.length, 512))).replace(/^\uFEFF/, "").trimStart();
  if (prefix.startsWith("<svg") || (prefix.startsWith("<?xml") && prefix.includes("<svg"))) return "svg";
  return "unknown";
}

function finding(id: string, severity: Finding["severity"], stage: Finding["stage"], title: string, description: string, offset?: number, length?: number): Finding {
  const evidence: Evidence[] = offset === undefined
    ? [{ kind: "policy", summary: description }]
    : [{ kind: length === undefined ? "offset" : "range", summary: description, offset, ...(length === undefined ? {} : { length }) }];
  return { id, severity, stage, title, description, status: "confirmed", controlStatus: "failed", evidence };
}

function invalid(format: ImageFormat, id: string, title: string, description: string, offset?: number): StructuralInspection {
  return { format, validity: "invalid", findings: [finding(id, "high", "structural", title, description, offset)], metadataBytes: 0 };
}

function exceedsDimensions(width: number, height: number, limits: ResourceLimits): boolean {
  return width <= 0 || height <= 0 || width > limits.maxWidth || height > limits.maxHeight || width > Math.floor(limits.maxPixels / height);
}

function inspectPng(data: Uint8Array, limits: ResourceLimits): StructuralInspection {
  const findings: Finding[] = [];
  let offset = 8;
  let chunks = 0;
  let metadataBytes = 0;
  let width: number | undefined;
  let height: number | undefined;
  let colorType: number | undefined;
  let seenHeader = false;
  let seenData = false;
  let dataSequenceEnded = false;
  let seenPalette = false;
  let seenEnd = false;
  const reject = (id: string, title: string, description: string, offset?: number): StructuralInspection => {
    const result = invalid("png", id, title, description, offset);
    return { ...result, findings: [...findings, ...result.findings], metadataBytes, ...(width === undefined ? {} : { width }), ...(height === undefined ? {} : { height }) };
  };
  while (offset < data.length) {
    if (data.length - offset < 12) return reject("IMG-003", "Truncated PNG chunk", "A chunk is shorter than its length, type, and CRC fields.", offset);
    const size = readU32BE(data, offset);
    if (size > data.length - offset - 12) return reject("IMG-004", "PNG chunk length exceeds input", "The declared chunk length exceeds the remaining input.", offset);
    const typeOffset = offset + 4;
    const type = String.fromCharCode(data[typeOffset]!, data[typeOffset + 1]!, data[typeOffset + 2]!, data[typeOffset + 3]!);
    for (let i = 0; i < 4; i++) {
      const c = data[typeOffset + i]!;
      if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return reject("IMG-001", "Invalid PNG chunk type", "Chunk type bytes must be ASCII letters.", typeOffset + i);
    }
    if (data[typeOffset + 2]! >= 97 && data[typeOffset + 2]! <= 122) return reject("IMG-001", "Invalid PNG reserved chunk-type bit", "The third chunk-type letter must be uppercase in this PNG profile.", typeOffset + 2);
    const payloadOffset = offset + 8;
    if (type === "IHDR" && chunks === 0 && size === 13) {
      width = readU32BE(data, payloadOffset);
      height = readU32BE(data, payloadOffset + 4);
      if (exceedsDimensions(width, height, limits)) findings.push(finding("DEC-007", "high", "resource", "PNG dimensions exceed policy", "Declared dimensions exceed the configured image limits.", payloadOffset, 8));
    }
    const crcOffset = payloadOffset + size;
    const expectedCrc = readU32BE(data, crcOffset);
    if (crc32(data, typeOffset, crcOffset) !== expectedCrc) return reject("IMG-002", "PNG chunk CRC mismatch", `The ${type} chunk checksum does not match its contents.`, crcOffset);
    if (chunks === 0 && type !== "IHDR") return reject("IMG-005", "PNG header chunk is not first", "IHDR must be the first PNG chunk.", offset);
    if (type[0] === type[0]?.toUpperCase() && !new Set(["IHDR", "PLTE", "IDAT", "IEND"]).has(type)) return reject("IMG-006", "Unknown critical PNG chunk", "An unrecognized critical chunk prevents reliable validation.", offset);
    if (type === "IHDR") {
      if (seenHeader || chunks !== 0 || size !== 13) return reject("IMG-006", "Invalid PNG IHDR", "IHDR must occur once as the first chunk and contain 13 bytes.", offset);
      const bitDepth = data[payloadOffset + 8]!;
      colorType = data[payloadOffset + 9]!;
      const validDepths: Record<number, readonly number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
      if (!validDepths[colorType]?.includes(bitDepth) || data[payloadOffset + 10] !== 0 || data[payloadOffset + 11] !== 0 || data[payloadOffset + 12]! > 1) {
        return reject("IMG-006", "Invalid PNG image parameters", "Bit depth, color type, compression, filter, or interlace value is invalid.", payloadOffset + 8);
      }
      seenHeader = true;
    } else if (type === "PLTE") {
      if (!seenHeader || seenData || seenPalette || [0, 4].includes(colorType ?? -1) || size === 0 || size % 3 !== 0 || size > 768) return reject("IMG-006", "Invalid PNG palette", "PLTE must be a single valid palette before image data and is forbidden for grayscale color types.", offset);
      seenPalette = true;
    } else if (type === "IDAT") {
      if (!seenHeader || seenEnd || dataSequenceEnded) return reject("IMG-006", "PNG image data is out of order", "IDAT chunks must form one consecutive sequence after IHDR.", offset);
      seenData = true;
    } else if (type === "IEND") {
      if (size !== 0 || !seenData) return reject("IMG-006", "Invalid PNG IEND", "IEND must have an empty payload and follow image data.", offset);
      seenEnd = true;
      offset = crcOffset + 4;
      break;
    } else if (["eXIf", "tEXt", "zTXt", "iTXt", "iCCP"].includes(type)) {
      metadataBytes += size;
      if (metadataBytes > limits.maxMetadataBytes) findings.push(finding("META-006", "medium", "metadata", "PNG metadata limit exceeded", "Metadata byte count exceeds the configured limit.", offset, size));
    }
    if (seenData && type !== "IDAT" && type !== "IEND") dataSequenceEnded = true;
    chunks++;
    offset = crcOffset + 4;
  }
  if (!seenHeader || !seenData || !seenEnd) return reject("IMG-003", "Incomplete PNG structure", "PNG is missing IHDR, IDAT, or IEND.", offset);
  if (colorType === 3 && !seenPalette) return reject("IMG-006", "Indexed PNG has no palette", "PLTE is required for indexed-color PNG images.", 8);
  if (offset < data.length) findings.push(finding("IMG-008", "medium", "structural", "Data follows PNG IEND", "Bytes remain after the PNG end chunk.", offset, data.length - offset));
  return { format: "png", validity: findings.some((f) => f.id.startsWith("IMG-")) ? "invalid" : "valid", findings, metadataBytes, ...(width === undefined ? {} : { width }), ...(height === undefined ? {} : { height }) };
}

function readU32BE(data: Uint8Array, offset: number): number {
  return data[offset]! * 0x1000000 + data[offset + 1]! * 0x10000 + data[offset + 2]! * 0x100 + data[offset + 3]!;
}

function readU32LE(data: Uint8Array, offset: number): number {
  return data[offset]! + data[offset + 1]! * 0x100 + data[offset + 2]! * 0x10000 + data[offset + 3]! * 0x1000000;
}

function inspectGif(data: Uint8Array, limits: ResourceLimits): StructuralInspection {
  if (data.length < 13) return invalid("gif", "IMG-003", "Truncated GIF header", "The logical screen descriptor is incomplete.", data.length);
  const width = data[6]! | (data[7]! << 8);
  const height = data[8]! | (data[9]! << 8);
  const findings: Finding[] = [];
  const reject = (id: string, title: string, description: string, offset: number): StructuralInspection => {
    const result = invalid("gif", id, title, description, offset);
    return { ...result, findings: [...findings, ...result.findings] };
  };
  if (exceedsDimensions(width, height, limits)) findings.push(finding("DEC-007", "high", "resource", "GIF dimensions exceed policy", "Declared dimensions exceed configured image limits.", 6, 4));
  const packed = data[10]!;
  let offset = 13 + ((packed & 0x80) ? 3 * (1 << ((packed & 7) + 1)) : 0);
  let frames = 0;
  let metadataBytes = 0;
  const readSubBlocks = (start: number): { end: number; bytes: number } | null => {
    let cursor = start;
    let total = 0;
    while (cursor < data.length) {
      const length = data[cursor++]!;
      if (length === 0) return { end: cursor, bytes: total };
      if (length > data.length - cursor) return null;
      total += length;
      cursor += length;
    }
    return null;
  };
  while (offset < data.length) {
    const markerOffset = offset;
    const marker = data[offset++]!;
    if (marker === 0x3b) {
      if (offset < data.length) {
        findings.push(finding("IMG-008", "medium", "structural", "Data follows GIF trailer", "Bytes remain after the GIF trailer.", offset, data.length - offset));
        return { format: "gif", validity: "invalid", findings, metadataBytes, width, height };
      }
      if (frames === 0) return reject("IMG-006", "GIF contains no image frames", "At least one image descriptor is required before the trailer.", markerOffset);
      return { format: "gif", validity: "valid", findings, metadataBytes, width, height, frameCount: frames };
    }
    if (marker === 0x2c) {
      if (data.length - offset < 9) return reject("IMG-003", "Truncated GIF image descriptor", "Image descriptor is incomplete.", markerOffset);
      const left = data[offset]! | (data[offset + 1]! << 8);
      const top = data[offset + 2]! | (data[offset + 3]! << 8);
      const frameWidth = data[offset + 4]! | (data[offset + 5]! << 8);
      const frameHeight = data[offset + 6]! | (data[offset + 7]! << 8);
      if (frameWidth < 1 || frameHeight < 1) return reject("IMG-006", "GIF frame dimensions are zero", "GIF image descriptor width and height must be nonzero.", offset + 4);
      if (left + frameWidth > width || top + frameHeight > height) return reject("IMG-006", "GIF frame lies outside the logical screen", "Frame rectangle exceeds the logical screen dimensions.", offset);
      if (exceedsDimensions(frameWidth, frameHeight, limits)) findings.push(finding("DEC-007", "high", "resource", "GIF frame dimensions exceed policy", "Frame dimensions exceed configured image limits.", offset + 4, 4));
      const imagePacked = data[offset + 8]!;
      offset += 9;
      const localColorTableBytes = imagePacked & 0x80 ? 3 * (1 << ((imagePacked & 7) + 1)) : 0;
      if (localColorTableBytes > data.length - offset) return reject("IMG-003", "Truncated GIF local color table", "Local color table exceeds the input boundary.", offset);
      if ((imagePacked & 0x18) !== 0) {
        return reject("IMG-006", "GIF image descriptor reserved bits are set", "Reserved image descriptor bits must be zero.", markerOffset + 9);
      }
      offset += localColorTableBytes;
      if (offset >= data.length) return reject("IMG-003", "Truncated GIF image data", "Missing LZW minimum code size.", offset);
      const minimumCodeSize = data[offset]!;
      if (minimumCodeSize < 2 || minimumCodeSize > 8) {
        return reject("IMG-006", "Invalid GIF LZW minimum code size", "GIF LZW minimum code size must be between 2 and 8.", offset);
      }
      offset++;
      const blocks = readSubBlocks(offset);
      if (!blocks) return reject("IMG-003", "Truncated GIF data sub-block", "Image data sub-block exceeds input or lacks a terminator.", offset);
      offset = blocks.end;
      frames++;
      if (frames > limits.maxFrames) findings.push(finding("DEC-008", "high", "resource", "GIF frame limit exceeded", "Frame count exceeds configured limit.", markerOffset));
      continue;
    }
    if (marker === 0x21) {
      if (offset >= data.length) return reject("IMG-003", "Truncated GIF extension", "Extension label is missing.", offset);
      const label = data[offset++]!;
      if (label === 0xf9) {
        if (offset + 6 > data.length || data[offset] !== 4 || data[offset + 5] !== 0) return reject("IMG-006", "Invalid GIF graphic control extension", "Graphic control extension has invalid size or terminator.", offset);
        if ((data[offset + 1]! & 0xe0) !== 0) {
          return reject("IMG-006", "GIF graphic control reserved bits are set", "Reserved Graphic Control Extension bits must be zero.", offset + 1);
        }
        offset += 6;
      } else {
        const fixedBlockSize = label === 0x01 ? 12 : label === 0xff ? 11 : null;
        if (fixedBlockSize !== null && offset < data.length && data[offset] !== fixedBlockSize) {
          return reject("IMG-006", "Invalid GIF extension header size", "Plain Text and Application Extension headers require their specified fixed size.", offset);
        }
        if (label === 0xff && offset + 12 <= data.length) {
          for (let index = offset + 1; index < offset + 9; index++) {
            if (data[index]! < 0x20 || data[index]! > 0x7e) {
              return reject("IMG-006", "Invalid GIF application identifier", "Application identifiers must contain eight printable ASCII bytes.", index);
            }
          }
        }
        const blocks = readSubBlocks(offset);
        if (!blocks) return reject("IMG-003", "Truncated GIF extension blocks", "Extension data exceeds input or lacks a terminator.", offset);
        metadataBytes += blocks.bytes;
        if (metadataBytes > limits.maxMetadataBytes) findings.push(finding("META-006", "medium", "metadata", "GIF extension limit exceeded", "Extension bytes exceed configured metadata limit.", markerOffset, blocks.bytes));
        offset = blocks.end;
      }
      continue;
    }
    return reject("IMG-001", "Unknown GIF block marker", "Unexpected block marker in GIF structure.", markerOffset);
  }
  return reject("IMG-003", "Missing GIF trailer", "GIF structure ended without a trailer.", data.length);
}

function inspectWebp(data: Uint8Array, limits: ResourceLimits): StructuralInspection {
  if (data.length < 12) return invalid("webp", "IMG-003", "Truncated WebP header", "RIFF and WEBP headers are incomplete.", data.length);
  const declaredEnd = readU32LE(data, 4) + 8;
  if (declaredEnd < 12 || declaredEnd > data.length) return invalid("webp", "IMG-004", "Invalid RIFF length", "Declared RIFF length exceeds available bytes.", 4);
  if (declaredEnd < data.length) return { format: "webp", validity: "invalid", findings: [finding("IMG-008", "medium", "structural", "Data follows WebP RIFF container", "Bytes remain after the declared RIFF container.", declaredEnd, data.length - declaredEnd)], metadataBytes: 0 };
  const findings: Finding[] = [];
  let offset = 12;
  let frames = 0;
  let metadataBytes = 0;
  let hasImagePayload = false;
  let hasBitstream = false;
  let hasVp8x = false;
  let width: number | undefined;
  let height: number | undefined;
  while (offset < declaredEnd) {
    if (declaredEnd - offset < 8) return invalid("webp", "IMG-003", "Truncated WebP chunk header", "Chunk identifier and size are incomplete.", offset);
    const kind = String.fromCharCode(data[offset]!, data[offset + 1]!, data[offset + 2]!, data[offset + 3]!);
    const size = readU32LE(data, offset + 4);
    const end = offset + 8 + size + (size & 1);
    if (!Number.isSafeInteger(end) || end > declaredEnd) return invalid("webp", "IMG-004", "WebP chunk length exceeds RIFF boundary", "Chunk payload exceeds the declared container size.", offset + 4);
    const payload = offset + 8;
    if ((size & 1) === 1 && data[end - 1] !== 0) return invalid("webp", "IMG-003", "Invalid WebP chunk padding", "An odd-length RIFF chunk must have a zero padding byte.", end - 1);
    if (kind === "VP8X") {
      if (offset !== 12 || hasVp8x || size !== 10 || (data[payload]! & 0xc1) !== 0 || data[payload + 1] !== 0 || data[payload + 2] !== 0 || data[payload + 3] !== 0) return invalid("webp", "IMG-006", "Invalid VP8X chunk", "VP8X must be the first 10-byte chunk and reserved fields must be zero.", offset);
      hasVp8x = true;
      width = 1 + data[payload + 4]! + (data[payload + 5]! << 8) + (data[payload + 6]! << 16);
      height = 1 + data[payload + 7]! + (data[payload + 8]! << 8) + (data[payload + 9]! << 16);
      if (exceedsDimensions(width, height, limits)) findings.push(finding("DEC-007", "high", "resource", "WebP dimensions exceed policy", "Declared canvas dimensions exceed configured limits.", payload + 4, 6));
    } else if (kind === "ANMF") {
      if (size > 16) hasImagePayload = true;
      frames++;
      if (frames > limits.maxFrames) findings.push(finding("DEC-008", "high", "resource", "WebP frame limit exceeded", "Frame count exceeds configured limit.", offset));
    } else if (kind === "VP8 " || kind === "VP8L") {
      if (size === 0 || hasBitstream) return invalid("webp", "IMG-006", "Invalid WebP image bitstream", "Image payload chunk must be non-empty and unique in this bounded profile.", offset);
      hasBitstream = true;
      hasImagePayload = true;
    } else if (kind === "EXIF" || kind === "XMP " || kind === "ICCP") {
      metadataBytes += size;
      if (metadataBytes > limits.maxMetadataBytes) findings.push(finding("META-006", "medium", "metadata", "WebP metadata limit exceeded", "Metadata bytes exceed configured limit.", offset, size));
    }
    offset = end;
  }
  if (offset !== declaredEnd) return invalid("webp", "IMG-004", "WebP chunk boundary mismatch", "Chunks do not end at the declared RIFF boundary.", offset);
  if (!hasImagePayload) return invalid("webp", "IMG-006", "WebP image payload is missing", "No VP8, VP8L, or non-empty animated frame payload was found.", 12);
  return { format: "webp", validity: "valid", findings, metadataBytes, ...(width === undefined ? {} : { width }), ...(height === undefined ? {} : { height }), frameCount: frames };
}

function inspectJpeg(data: Uint8Array, limits: ResourceLimits): StructuralInspection {
  let offset = 2;
  let inScan = false;
  let sawSof = false;
  let sawScan = false;
  let metadataBytes = 0;
  let width: number | undefined;
  let height: number | undefined;
  const findings: Finding[] = [];
  while (offset < data.length) {
    if (inScan) {
      while (offset < data.length && data[offset] !== 0xff) offset++;
      if (offset >= data.length) return invalid("jpeg", "IMG-003", "Truncated JPEG entropy data", "JPEG scan has no terminating marker.", offset);
      while (offset < data.length && data[offset] === 0xff) offset++;
      if (offset >= data.length) return invalid("jpeg", "IMG-003", "Truncated JPEG marker", "Marker prefix is not followed by a marker code.", offset);
      if (data[offset] === 0x00 || (data[offset]! >= 0xd0 && data[offset]! <= 0xd7)) { offset++; continue; }
      inScan = false;
      offset--;
    }
    if (data[offset] !== 0xff) return invalid("jpeg", "IMG-001", "Invalid JPEG marker boundary", "Expected marker prefix FF.", offset);
    while (offset < data.length && data[offset] === 0xff) offset++;
    if (offset >= data.length) return invalid("jpeg", "IMG-003", "Truncated JPEG marker", "Marker code is missing.", offset);
    const marker = data[offset++]!;
    if (marker === 0xd9) {
      if (!sawSof || !sawScan) return invalid("jpeg", "IMG-006", "Incomplete JPEG structure", "JPEG must contain a frame header and scan before EOI.", offset - 2);
      if (offset < data.length) findings.push(finding("IMG-008", "medium", "structural", "Data follows JPEG EOI", "Bytes remain after the JPEG end marker.", offset, data.length - offset));
      return { format: "jpeg", validity: findings.some((f) => f.id === "IMG-008") ? "invalid" : "valid", findings, metadataBytes, ...(width === undefined ? {} : { width }), ...(height === undefined ? {} : { height }) };
    }
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > data.length) return invalid("jpeg", "IMG-003", "Truncated JPEG segment length", "Segment length field is incomplete.", offset);
    const length = (data[offset]! << 8) | data[offset + 1]!;
    if (length < 2 || length > data.length - offset) return invalid("jpeg", "IMG-004", "JPEG segment length exceeds input", "Segment length is invalid or exceeds remaining bytes.", offset);
    const payload = offset + 2;
    const payloadLength = length - 2;
    if (jpegSof.has(marker)) {
      if (payloadLength < 6) return invalid("jpeg", "IMG-003", "Truncated JPEG frame header", "Frame header lacks precision or dimensions.", payload);
      height = (data[payload + 1]! << 8) | data[payload + 2]!;
      width = (data[payload + 3]! << 8) | data[payload + 4]!;
      if (exceedsDimensions(width, height, limits)) findings.push(finding("DEC-007", "high", "resource", "JPEG dimensions exceed policy", "Declared dimensions exceed configured limits.", payload + 1, 4));
      sawSof = true;
    }
    if (marker === 0xe1 || marker === 0xe2 || marker === 0xed || marker === 0xfe) {
      metadataBytes += payloadLength;
      if (metadataBytes > limits.maxMetadataBytes) findings.push(finding("META-006", "medium", "metadata", "JPEG metadata limit exceeded", "Metadata segment bytes exceed configured limit.", offset, length));
    }
    offset += length;
    if (marker === 0xda) { sawScan = true; inScan = true; }
  }
  return invalid("jpeg", "IMG-003", "Missing JPEG EOI", "JPEG structure ended without an end-of-image marker.", data.length);
}

export function inspectStructure(data: Uint8Array, limits: ResourceLimits): StructuralInspection {
  const format = detectFormat(data);
  if (format === "png") return inspectPng(data, limits);
  if (format === "jpeg") return inspectJpeg(data, limits);
  if (format === "gif") return inspectGif(data, limits);
  if (format === "webp") return inspectWebp(data, limits);
  if (format === "svg") {
    const inspection = inspectSvg(data, limits);
    return { format, validity: inspection.validity, findings: [...inspection.findings], metadataBytes: inspection.metadataBytes };
  }
  return { format, validity: "unknown", findings: [], metadataBytes: 0 };
}

export function inspectBinaryIndicators(data: Uint8Array): BinaryInspectionResult {
  const findings: Finding[] = [];
  const regions: Array<{ start: number; end: number }> = [];
  let trailingData = false;
  let supported = false;
  // Only inspect ancillary/container regions whose boundaries are explicit in the
  // format. Compressed image streams are deliberately excluded to avoid matches
  // caused by ordinary pixel data.
  if (isPng(data)) {
    supported = true;
    let cursor = 8;
    while (cursor + 12 <= data.length) {
      const size = readU32BE(data, cursor);
      if (size > data.length - cursor - 12) break;
      const typeAt = cursor + 4;
      const type = String.fromCharCode(...data.subarray(typeAt, typeAt + 4));
      const payload = cursor + 8;
      const end = payload + size;
      if (type[0] === type[0]?.toLowerCase() && type !== "IDAT") regions.push({ start: payload, end });
      cursor = end + 4;
      if (type === "IEND") { if (cursor < data.length) { regions.push({ start: cursor, end: data.length }); trailingData = true; } break; }
    }
  } else if (data.length >= 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff) {
    supported = true;
    let cursor = 2;
    let inScan = false;
    while (cursor < data.length) {
      if (inScan) {
        while (cursor < data.length && data[cursor] !== 0xff) cursor++;
        while (cursor < data.length && data[cursor] === 0xff) cursor++;
        if (cursor >= data.length) break;
        const marker = data[cursor]!;
        if (marker === 0 || (marker >= 0xd0 && marker <= 0xd7)) { cursor++; continue; }
        inScan = false;
        // Rewind to the last marker-prefix byte so the segment parser below
        // processes this marker and can continue through EOI and the trailer.
        cursor--;
      }
      if (data[cursor] !== 0xff) break;
      while (cursor < data.length && data[cursor] === 0xff) cursor++;
      if (cursor >= data.length) break;
      const marker = data[cursor++]!;
      if (marker === 0xd9) { if (cursor < data.length) { regions.push({ start: cursor, end: data.length }); trailingData = true; } break; }
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (cursor + 2 > data.length) break;
      const length = (data[cursor]! << 8) | data[cursor + 1]!;
      if (length < 2 || length > data.length - cursor) break;
      const payloadStart = cursor + 2;
      const payloadEnd = cursor + length;
      if ((marker >= 0xe0 && marker <= 0xef) || marker === 0xfe) regions.push({ start: payloadStart, end: payloadEnd });
      cursor = payloadEnd;
      if (marker === 0xda) inScan = true;
    }
  } else if (eqAscii(data, 0, "GIF87a") || eqAscii(data, 0, "GIF89a")) {
    supported = true;
    if (data.length >= 13) {
      const packed = data[10]!;
      let cursor = 13 + ((packed & 0x80) ? 3 * (1 << ((packed & 7) + 1)) : 0);
      while (cursor < data.length) {
        const marker = data[cursor++]!;
        if (marker === 0x3b) { if (cursor < data.length) { regions.push({ start: cursor, end: data.length }); trailingData = true; } break; }
        if (marker === 0x2c) {
          if (cursor + 9 > data.length) break;
          const flags = data[cursor + 8]!;
          cursor += 9;
          if (flags & 0x80) cursor += 3 * (1 << ((flags & 7) + 1));
          if (cursor >= data.length) break;
          cursor++; // LZW minimum code size
          while (cursor < data.length) { const n = data[cursor++]!; if (!n) break; if (n > data.length - cursor) { cursor = data.length; break; } cursor += n; }
        } else if (marker === 0x21) {
          if (cursor >= data.length) break;
          const label = data[cursor++]!;
          if (label === 0xf9) { if (cursor + 6 > data.length) break; regions.push({ start: cursor + 1, end: cursor + 5 }); cursor += 6; }
          else while (cursor < data.length) { const n = data[cursor++]!; if (!n) break; if (n > data.length - cursor) { cursor = data.length; break; } regions.push({ start: cursor, end: cursor + n }); cursor += n; }
        } else break;
      }
    }
  } else if (eqAscii(data, 0, "RIFF") && eqAscii(data, 8, "WEBP") && data.length >= 12) {
    supported = true;
    const limit = Math.min(data.length, readU32LE(data, 4) + 8);
    let cursor = 12;
    while (cursor + 8 <= limit) {
      const kind = String.fromCharCode(...data.subarray(cursor, cursor + 4));
      const size = readU32LE(data, cursor + 4);
      const start = cursor + 8;
      const end = start + size;
      if (end > limit) break;
      if (["EXIF", "XMP ", "ICCP"].includes(kind)) regions.push({ start, end });
      cursor = end + (size & 1);
    }
    if (limit < data.length) { regions.push({ start: limit, end: data.length }); trailingData = true; }
  }
  const patterns: ReadonlyArray<{ readonly name: string; readonly bytes: readonly number[] }> = [
    { name: "ZIP local-file header", bytes: [0x50, 0x4b, 0x03, 0x04] },
    { name: "DOS/Windows executable signature", bytes: [0x4d, 0x5a] },
    { name: "ELF executable signature", bytes: [0x7f, 0x45, 0x4c, 0x46] },
    { name: "PDF header", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }
  ];
  for (const pattern of patterns) {
    for (const region of regions) for (let offset = region.start; offset <= region.end - pattern.bytes.length; offset++) {
      if (pattern.bytes.every((byte, index) => data[offset + index] === byte)) {
        findings.push({
          id: "BIN-009", severity: "medium", stage: "binary", title: "Embedded format signature",
          description: `A ${pattern.name} byte signature occurs in the image input. This is an indicator only and does not establish that a complete payload is present.`,
          status: "suspected", controlStatus: "passed",
          evidence: [{ kind: "range", summary: `Indicator: ${pattern.name}`, offset, length: pattern.bytes.length }]
        });
        break;
      }
    }
  }
  const bytesScanned = regions.reduce((total, region) => total + region.end - region.start, 0);
  return {
    status: !supported ? "unsupported" : findings.length > 0 ? "findings" : "passed",
    bytesScanned,
    findings,
    trailingData,
    recursiveInspection: false
  };
}
