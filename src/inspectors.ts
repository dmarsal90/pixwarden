import type { Evidence, Finding, ImageFormat, ResourceLimits } from "./types.js";
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
    : [{ kind: "range", summary: description, offset, ...(length === undefined ? {} : { length }) }];
  return { id, severity, stage, title, description, status: "confirmed", controlStatus: "failed", evidence };
}

function invalid(format: ImageFormat, id: string, title: string, description: string, offset?: number): StructuralInspection {
  return { format, validity: "invalid", findings: [finding(id, "high", "structural", title, description, offset)], metadataBytes: 0 };
}

function exceedsDimensions(width: number, height: number, limits: ResourceLimits): boolean {
  return width <= 0 || height <= 0 || width > limits.maxWidth || height > limits.maxHeight || width > Math.floor(limits.maxPixels / height);
}

function pngCrc(data: Uint8Array, start: number, end: number): number {
  let crc = 0xffff_ffff;
  for (let i = start; i < end; i++) {
    crc ^= data[i]!;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb8_8320 : 0);
  }
  return (crc ^ 0xffff_ffff) >>> 0;
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
  while (offset < data.length) {
    if (data.length - offset < 12) return invalid("png", "IMG-003", "Truncated PNG chunk", "A chunk is shorter than its length, type, and CRC fields.", offset);
    const size = readU32BE(data, offset);
    if (size > data.length - offset - 12) return invalid("png", "IMG-004", "PNG chunk length exceeds input", "The declared chunk length exceeds the remaining input.", offset);
    const typeOffset = offset + 4;
    const type = String.fromCharCode(data[typeOffset]!, data[typeOffset + 1]!, data[typeOffset + 2]!, data[typeOffset + 3]!);
    for (let i = 0; i < 4; i++) {
      const c = data[typeOffset + i]!;
      if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return invalid("png", "IMG-001", "Invalid PNG chunk type", "Chunk type bytes must be ASCII letters.", typeOffset + i);
    }
    const payloadOffset = offset + 8;
    const crcOffset = payloadOffset + size;
    const expectedCrc = readU32BE(data, crcOffset);
    if (pngCrc(data, typeOffset, crcOffset) !== expectedCrc) return invalid("png", "IMG-002", "PNG chunk CRC mismatch", `The ${type} chunk checksum does not match its contents.`, crcOffset);
    if (chunks === 0 && type !== "IHDR") return invalid("png", "IMG-005", "PNG header chunk is not first", "IHDR must be the first PNG chunk.", offset);
    if (type[0] === type[0]?.toUpperCase() && !new Set(["IHDR", "PLTE", "IDAT", "IEND"]).has(type)) return invalid("png", "IMG-006", "Unknown critical PNG chunk", "An unrecognized critical chunk prevents reliable validation.", offset);
    if (type === "IHDR") {
      if (seenHeader || chunks !== 0 || size !== 13) return invalid("png", "IMG-006", "Invalid PNG IHDR", "IHDR must occur once as the first chunk and contain 13 bytes.", offset);
      width = readU32BE(data, payloadOffset);
      height = readU32BE(data, payloadOffset + 4);
      if (exceedsDimensions(width, height, limits)) findings.push(finding("DEC-007", "high", "resource", "PNG dimensions exceed policy", "Declared dimensions exceed the configured image limits.", payloadOffset, 8));
      const bitDepth = data[payloadOffset + 8]!;
      colorType = data[payloadOffset + 9]!;
      const validDepths: Record<number, readonly number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
      if (!validDepths[colorType]?.includes(bitDepth) || data[payloadOffset + 10] !== 0 || data[payloadOffset + 11] !== 0 || data[payloadOffset + 12]! > 1) {
        return invalid("png", "IMG-006", "Invalid PNG image parameters", "Bit depth, color type, compression, filter, or interlace value is invalid.", payloadOffset + 8);
      }
      seenHeader = true;
    } else if (type === "PLTE") {
      if (!seenHeader || seenData || seenPalette || [0, 4].includes(colorType ?? -1) || size === 0 || size % 3 !== 0 || size > 768) return invalid("png", "IMG-006", "Invalid PNG palette", "PLTE must be a single valid palette before image data and is forbidden for grayscale color types.", offset);
      seenPalette = true;
    } else if (type === "IDAT") {
      if (!seenHeader || seenEnd || dataSequenceEnded) return invalid("png", "IMG-006", "PNG image data is out of order", "IDAT chunks must form one consecutive sequence after IHDR.", offset);
      seenData = true;
    } else if (type === "IEND") {
      if (size !== 0 || !seenData) return invalid("png", "IMG-006", "Invalid PNG IEND", "IEND must have an empty payload and follow image data.", offset);
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
  if (!seenHeader || !seenData || !seenEnd) return invalid("png", "IMG-003", "Incomplete PNG structure", "PNG is missing IHDR, IDAT, or IEND.", offset);
  if (colorType === 3 && !seenPalette) return invalid("png", "IMG-006", "Indexed PNG has no palette", "PLTE is required for indexed-color PNG images.", 8);
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
      if (offset < data.length) findings.push(finding("IMG-008", "medium", "structural", "Data follows GIF trailer", "Bytes remain after the GIF trailer.", offset, data.length - offset));
      if (frames === 0) return invalid("gif", "IMG-006", "GIF contains no image frames", "At least one image descriptor is required before the trailer.", markerOffset);
      return { format: "gif", validity: "valid", findings, metadataBytes, width, height, frameCount: frames };
    }
    if (marker === 0x2c) {
      if (data.length - offset < 9) return invalid("gif", "IMG-003", "Truncated GIF image descriptor", "Image descriptor is incomplete.", markerOffset);
      const left = data[offset]! | (data[offset + 1]! << 8);
      const top = data[offset + 2]! | (data[offset + 3]! << 8);
      const frameWidth = data[offset + 4]! | (data[offset + 5]! << 8);
      const frameHeight = data[offset + 6]! | (data[offset + 7]! << 8);
      if (left + frameWidth > width || top + frameHeight > height) return invalid("gif", "IMG-006", "GIF frame lies outside the logical screen", "Frame rectangle exceeds the logical screen dimensions.", offset);
      if (exceedsDimensions(frameWidth, frameHeight, limits)) findings.push(finding("DEC-007", "high", "resource", "GIF frame dimensions exceed policy", "Frame dimensions exceed configured image limits.", offset + 4, 4));
      const imagePacked = data[offset + 8]!;
      offset += 9;
      if (imagePacked & 0x80) offset += 3 * (1 << ((imagePacked & 7) + 1));
      if (offset >= data.length) return invalid("gif", "IMG-003", "Truncated GIF image data", "Missing LZW minimum code size.", offset);
      offset++;
      const blocks = readSubBlocks(offset);
      if (!blocks) return invalid("gif", "IMG-003", "Truncated GIF data sub-block", "Image data sub-block exceeds input or lacks a terminator.", offset);
      offset = blocks.end;
      frames++;
      if (frames > limits.maxFrames) findings.push(finding("DEC-008", "high", "resource", "GIF frame limit exceeded", "Frame count exceeds configured limit.", markerOffset));
      continue;
    }
    if (marker === 0x21) {
      if (offset >= data.length) return invalid("gif", "IMG-003", "Truncated GIF extension", "Extension label is missing.", offset);
      const label = data[offset++]!;
      if (label === 0xf9) {
        if (offset + 6 > data.length || data[offset] !== 4 || data[offset + 5] !== 0) return invalid("gif", "IMG-006", "Invalid GIF graphic control extension", "Graphic control extension has invalid size or terminator.", offset);
        offset += 6;
      } else {
        const blocks = readSubBlocks(offset);
        if (!blocks) return invalid("gif", "IMG-003", "Truncated GIF extension blocks", "Extension data exceeds input or lacks a terminator.", offset);
        metadataBytes += blocks.bytes;
        if (metadataBytes > limits.maxMetadataBytes) findings.push(finding("META-006", "medium", "metadata", "GIF extension limit exceeded", "Extension bytes exceed configured metadata limit.", markerOffset, blocks.bytes));
        offset = blocks.end;
      }
      continue;
    }
    return invalid("gif", "IMG-001", "Unknown GIF block marker", "Unexpected block marker in GIF structure.", markerOffset);
  }
  return invalid("gif", "IMG-003", "Missing GIF trailer", "GIF structure ended without a trailer.", data.length);
}

function inspectWebp(data: Uint8Array, limits: ResourceLimits): StructuralInspection {
  if (data.length < 12) return invalid("webp", "IMG-003", "Truncated WebP header", "RIFF and WEBP headers are incomplete.", data.length);
  const declaredEnd = readU32LE(data, 4) + 8;
  if (declaredEnd < 12 || declaredEnd > data.length) return invalid("webp", "IMG-004", "Invalid RIFF length", "Declared RIFF length exceeds available bytes.", 4);
  const findings: Finding[] = [];
  let offset = 12;
  let frames = 0;
  let metadataBytes = 0;
  let hasImagePayload = false;
  let width: number | undefined;
  let height: number | undefined;
  while (offset < declaredEnd) {
    if (declaredEnd - offset < 8) return invalid("webp", "IMG-003", "Truncated WebP chunk header", "Chunk identifier and size are incomplete.", offset);
    const kind = String.fromCharCode(data[offset]!, data[offset + 1]!, data[offset + 2]!, data[offset + 3]!);
    const size = readU32LE(data, offset + 4);
    const end = offset + 8 + size + (size & 1);
    if (!Number.isSafeInteger(end) || end > declaredEnd) return invalid("webp", "IMG-004", "WebP chunk length exceeds RIFF boundary", "Chunk payload exceeds the declared container size.", offset + 4);
    const payload = offset + 8;
    if (kind === "VP8X") {
      if (size !== 10) return invalid("webp", "IMG-006", "Invalid VP8X chunk", "VP8X payload must be 10 bytes.", offset);
      width = 1 + data[payload + 4]! + (data[payload + 5]! << 8) + (data[payload + 6]! << 16);
      height = 1 + data[payload + 7]! + (data[payload + 8]! << 8) + (data[payload + 9]! << 16);
      if (exceedsDimensions(width, height, limits)) findings.push(finding("DEC-007", "high", "resource", "WebP dimensions exceed policy", "Declared canvas dimensions exceed configured limits.", payload + 4, 6));
    } else if (kind === "ANMF") {
      if (size > 16) hasImagePayload = true;
      frames++;
      if (frames > limits.maxFrames) findings.push(finding("DEC-008", "high", "resource", "WebP frame limit exceeded", "Frame count exceeds configured limit.", offset));
    } else if (kind === "VP8 " || kind === "VP8L") {
      if (size === 0) return invalid("webp", "IMG-006", "Empty WebP image bitstream", "Image payload chunk must not be empty.", offset);
      hasImagePayload = true;
    } else if (kind === "EXIF" || kind === "XMP " || kind === "ICCP") {
      metadataBytes += size;
      if (metadataBytes > limits.maxMetadataBytes) findings.push(finding("META-006", "medium", "metadata", "WebP metadata limit exceeded", "Metadata bytes exceed configured limit.", offset, size));
    }
    offset = end;
  }
  if (offset !== declaredEnd) return invalid("webp", "IMG-004", "WebP chunk boundary mismatch", "Chunks do not end at the declared RIFF boundary.", offset);
  if (!hasImagePayload) return invalid("webp", "IMG-006", "WebP image payload is missing", "No VP8, VP8L, or non-empty animated frame payload was found.", 12);
  if (declaredEnd < data.length) findings.push(finding("IMG-008", "medium", "structural", "Data follows WebP RIFF container", "Bytes remain after the declared RIFF container.", declaredEnd, data.length - declaredEnd));
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

export function inspectBinaryIndicators(data: Uint8Array): Finding[] {
  const findings: Finding[] = [];
  const patterns: ReadonlyArray<{ readonly name: string; readonly bytes: readonly number[] }> = [
    { name: "ZIP local-file header", bytes: [0x50, 0x4b, 0x03, 0x04] },
    { name: "DOS/Windows executable signature", bytes: [0x4d, 0x5a] },
    { name: "ELF executable signature", bytes: [0x7f, 0x45, 0x4c, 0x46] },
    { name: "PDF header", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }
  ];
  for (const pattern of patterns) {
    for (let offset = 0; offset <= data.length - pattern.bytes.length; offset++) {
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
  return findings;
}
