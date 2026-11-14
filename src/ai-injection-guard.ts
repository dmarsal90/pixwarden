import type { AiInspectionResult, Finding } from "./types.js";
import { inflateSync } from "node:zlib";

const signature = [137, 80, 78, 71, 13, 10, 26, 10];
const patterns = [
  /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
  /(?:reveal|show|print)\s+(?:the\s+)?(?:system|developer)\s+prompt/i,
  /ignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)/i,
  /(?:revela|muestra)\s+(?:el\s+)?prompt\s+del\s+sistema/i
];

interface TextEntry { readonly start: number; readonly length: number; readonly text: string; readonly compressed: boolean }

/** Advisory inspection of bounded PNG tEXt/zTXt/iTXt metadata only. */
export function inspectInstructionMetadata(data: Uint8Array, format: string, maxMetadataBytes: number, ocrRequested: boolean): AiInspectionResult {
  if (format === "jpeg") return inspectJpegTextMetadata(data, maxMetadataBytes, ocrRequested);
  if (format !== "png") return unsupported(format);
  return inspectPngInstructionMetadata(data, maxMetadataBytes, ocrRequested);
}

function unsupported(format: string): AiInspectionResult {
  return { status: "unsupported", dataEgress: "none", signals: [], limitations: [`The ${format} format is not supported by the bounded metadata prompt-risk rules.`] };
}

function inspectJpegTextMetadata(data: Uint8Array, maximum: number, ocrRequested: boolean): AiInspectionResult {
  const limitations = [
    "Rules inspect JPEG COM comments and ASCII EXIF UserComment values only; visible pixels, XMP text, OCR output, non-ASCII UserComment encodings, and other formats are not inspected.",
    "Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior."
  ];
  const findings: Finding[] = [];
  let offset = 2;
  let consumed = 0;
  let partial = false;
  const addSignal = (text: string, start: number, length: number, source: string): void => {
    if (!patterns.some((pattern) => pattern.test(text))) return;
    findings.push({
      id: "AI-002", severity: "medium", stage: "ai", title: "Instruction-like text in JPEG metadata",
      description: `${source} metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.`,
      status: "suspected", controlStatus: "passed", evidence: [{ kind: "range", summary: `A bounded ${source} field matched a prompt-risk rule; field contents are redacted.`, offset: start, length }]
    });
  };
  while (offset < data.length) {
    if (data[offset] !== 0xff) { partial = true; break; }
    while (data[offset] === 0xff) offset++;
    if (offset >= data.length) { partial = true; break; }
    const marker = data[offset++]!;
    if (marker === 0xda) break;
    if (marker === 0xd9) break;
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > data.length) { partial = true; break; }
    const length = (data[offset]! << 8) | data[offset + 1]!;
    if (length < 2 || length > data.length - offset) { partial = true; break; }
    const start = offset + 2;
    const payloadLength = length - 2;
    if (marker === 0xfe || marker === 0xe1) {
      const allowed = Math.max(0, maximum - consumed);
      const inspectedLength = Math.min(payloadLength, allowed);
      if (marker === 0xfe) {
        const text = new TextDecoder("latin1").decode(data.subarray(start, start + inspectedLength));
        addSignal(text, start, inspectedLength, "JPEG COM comment");
      } else if (startsWith(data, start, [69, 120, 105, 102, 0, 0])) {
        const exif = inspectAsciiUserComment(data, start, start + inspectedLength);
        if (exif.text !== undefined && exif.offset !== undefined && exif.length !== undefined) addSignal(exif.text, exif.offset, exif.length, "JPEG EXIF UserComment");
        if (exif.partial) partial = true;
      }
      consumed += inspectedLength;
      if (inspectedLength < payloadLength) { partial = true; break; }
    }
    offset += length;
  }
  if (ocrRequested) limitations.push("OCR was requested but is not implemented; only metadata text rules ran.");
  if (partial) limitations.push("JPEG comment/EXIF metadata was malformed, used an unsupported UserComment encoding, or exceeded the configured inspection bound.");
  return { status: ocrRequested || partial ? "partial" : "completed", dataEgress: "none", signals: findings, limitations };
}

interface ExifComment { readonly text?: string; readonly offset?: number; readonly length?: number; readonly partial: boolean }

function inspectAsciiUserComment(data: Uint8Array, app1Start: number, app1End: number): ExifComment {
  const tiff = app1Start + 6;
  if (app1End - tiff < 8) return { partial: true };
  const little = data[tiff] === 0x49 && data[tiff + 1] === 0x49;
  if (!little && !(data[tiff] === 0x4d && data[tiff + 1] === 0x4d)) return { partial: true };
  const read16 = (at: number): number => little ? data[at]! + data[at + 1]! * 256 : data[at]! * 256 + data[at + 1]!;
  const read32 = (at: number): number => little
    ? data[at]! + data[at + 1]! * 0x100 + data[at + 2]! * 0x10000 + data[at + 3]! * 0x1000000
    : data[at]! * 0x1000000 + data[at + 1]! * 0x10000 + data[at + 2]! * 0x100 + data[at + 3]!;
  if (read16(tiff + 2) !== 42) return { partial: true };
  const readIfd = (relative: number): { readonly entries: number; readonly end: number } | undefined => {
    if (relative < 8 || relative > app1End - tiff - 2) return undefined;
    const start = tiff + relative;
    const count = read16(start);
    const end = start + 2 + count * 12 + 4;
    if (count > 1024 || end > app1End) return undefined;
    return { entries: start + 2, end };
  };
  const ifd0 = readIfd(read32(tiff + 4));
  if (!ifd0) return { partial: true };
  let exifRelative: number | undefined;
  const ifd0Count = read16(ifd0.entries - 2);
  for (let index = 0; index < ifd0Count; index++) {
    const entry = ifd0.entries + index * 12;
    if (read16(entry) === 0x8769 && read16(entry + 2) === 4 && read32(entry + 4) === 1) { exifRelative = read32(entry + 8); break; }
  }
  if (exifRelative === undefined) return { partial: false };
  const exifIfd = readIfd(exifRelative);
  if (!exifIfd) return { partial: true };
  const entryCount = read16(exifIfd.entries - 2);
  for (let index = 0; index < entryCount; index++) {
    const entry = exifIfd.entries + index * 12;
    if (read16(entry) !== 0x9286) continue;
    const type = read16(entry + 2);
    const byteCount = read32(entry + 4);
    if (type !== 7 || byteCount < 8) return { partial: true };
    const relative = read32(entry + 8);
    if (relative < 8 || relative > app1End - tiff || byteCount > app1End - (tiff + relative)) return { partial: true };
    const valueStart = tiff + relative;
    if (!startsWith(data, valueStart, [65, 83, 67, 73, 73, 0, 0, 0])) return { partial: true };
    const valueLength = byteCount - 8;
    return {
      text: new TextDecoder("latin1").decode(data.subarray(valueStart + 8, valueStart + byteCount)),
      offset: valueStart + 8,
      length: valueLength,
      partial: false
    };
  }
  return { partial: false };
}

function startsWith(data: Uint8Array, offset: number, bytes: readonly number[]): boolean {
  return offset >= 0 && offset + bytes.length <= data.length && bytes.every((byte, index) => data[offset + index] === byte);
}

/** Advisory, bounded prompt-risk rules for PNG text metadata. */
export function inspectPngInstructionMetadata(data: Uint8Array, maxMetadataBytes: number, ocrRequested: boolean): AiInspectionResult {
  const limitations = [
    "This rule set inspects PNG tEXt, zTXt and iTXt fields, with compressed output capped by the metadata budget; it does not inspect visible pixels, OCR output, or other formats.",
    "Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior."
  ];
  if (!signature.every((byte, index) => data[index] === byte)) {
    return { status: "unsupported", dataEgress: "none", signals: [], limitations: [...limitations, "The input is not a PNG profile supported by this metadata rule set."] };
  }
  const findings: Finding[] = [];
  let offset = 8;
  let consumed = 0;
  let partial = false;
  while (offset + 12 <= data.length && consumed < maxMetadataBytes) {
    const length = readU32(data, offset);
    if (length > data.length - offset - 12) break;
    const kind = String.fromCharCode(data[offset + 4]!, data[offset + 5]!, data[offset + 6]!, data[offset + 7]!);
    const payloadStart = offset + 8;
    const payloadEnd = payloadStart + length;
    if (kind === "tEXt" || kind === "iTXt" || kind === "zTXt") {
      const allowed = Math.max(0, maxMetadataBytes - consumed);
      const entry = extractText(data, payloadStart, payloadEnd, kind, allowed);
      if (entry) {
        const boundedText = entry.text;
        if (length + entry.text.length > allowed || (entry.compressed && entry.text.length >= allowed)) partial = true;
        consumed += Math.min(length + entry.text.length, allowed);
        if (patterns.some((pattern) => pattern.test(boundedText))) {
          findings.push({
            id: "AI-002", severity: "medium", stage: "ai",
            title: "Instruction-like text in PNG metadata",
            description: `${entry.compressed ? "Compressed" : "Uncompressed"} PNG text metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.`,
            status: "suspected", controlStatus: "passed",
            evidence: [{ kind: "range", summary: "A bounded PNG text field matched a prompt-risk rule; field contents are redacted.", offset: entry.start, length: entry.length }]
          });
        }
      } else partial = true;
    }
    offset = payloadEnd + 4;
    if (kind === "IEND") break;
  }
  if (ocrRequested) limitations.push("OCR was requested but is not implemented; only metadata text rules ran.");
  if (partial) limitations.push("Some PNG text metadata was malformed or exceeded the configured metadata inspection bound.");
  return {
    status: ocrRequested || partial ? "partial" : "completed",
    dataEgress: "none",
    signals: findings,
    limitations
  };
}

function extractText(data: Uint8Array, start: number, end: number, kind: "tEXt" | "zTXt" | "iTXt", maximumTextBytes: number): TextEntry | undefined {
  const keywordEnd = findZero(data, start, end);
  if (keywordEnd < 0) return undefined;
  let textStart: number;
  let compressed = false;
  if (kind === "tEXt") textStart = keywordEnd + 1;
  else if (kind === "zTXt") {
    if (keywordEnd + 2 > end || data[keywordEnd + 1] !== 0) return undefined;
    textStart = keywordEnd + 2;
    compressed = true;
  } else {
    if (keywordEnd + 3 > end || data[keywordEnd + 1]! > 1 || data[keywordEnd + 2] !== 0) return undefined;
    compressed = data[keywordEnd + 1] === 1;
    const languageEnd = findZero(data, keywordEnd + 3, end);
    if (languageEnd < 0) return undefined;
    const translatedEnd = findZero(data, languageEnd + 1, end);
    if (translatedEnd < 0) return undefined;
    textStart = translatedEnd + 1;
  }
  const textLength = end - textStart;
  let textBytes = data.subarray(textStart, textStart + textLength);
  if (compressed) {
    if (maximumTextBytes < 1 || textBytes.byteLength > maximumTextBytes) return undefined;
    try {
      textBytes = inflateSync(textBytes, { maxOutputLength: maximumTextBytes });
    } catch {
      return undefined;
    }
  }
  return { start: textStart, length: textLength, text: new TextDecoder("utf-8", { fatal: false }).decode(textBytes.subarray(0, maximumTextBytes)), compressed };
}

function findZero(data: Uint8Array, start: number, end: number): number {
  for (let index = start; index < end; index++) if (data[index] === 0) return index;
  return -1;
}

function readU32(data: Uint8Array, offset: number): number {
  return data[offset]! * 0x1000000 + data[offset + 1]! * 0x10000 + data[offset + 2]! * 0x100 + data[offset + 3]!;
}
