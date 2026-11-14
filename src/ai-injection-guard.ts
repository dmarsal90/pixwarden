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
  if (format === "jpeg") return inspectJpegComments(data, maxMetadataBytes, ocrRequested);
  if (format !== "png") return unsupported(format);
  return inspectPngInstructionMetadata(data, maxMetadataBytes, ocrRequested);
}

function unsupported(format: string): AiInspectionResult {
  return { status: "unsupported", dataEgress: "none", signals: [], limitations: [`The ${format} format is not supported by the bounded metadata prompt-risk rules.`] };
}

function inspectJpegComments(data: Uint8Array, maximum: number, ocrRequested: boolean): AiInspectionResult {
  const limitations = [
    "Rules inspect JPEG COM comment segments only; visible pixels, EXIF/XMP text, OCR output, and other formats are not inspected.",
    "Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior."
  ];
  const findings: Finding[] = [];
  let offset = 2;
  let consumed = 0;
  let partial = false;
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
    if (marker === 0xfe) {
      const allowed = Math.max(0, maximum - consumed);
      const inspectedLength = Math.min(payloadLength, allowed);
      const text = new TextDecoder("latin1").decode(data.subarray(start, start + inspectedLength));
      if (patterns.some((pattern) => pattern.test(text))) findings.push({
        id: "AI-002", severity: "medium", stage: "ai", title: "Instruction-like text in JPEG comment metadata",
        description: "JPEG COM metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.",
        status: "suspected", controlStatus: "passed", evidence: [{ kind: "range", summary: "A bounded JPEG COM field matched a prompt-risk rule; field contents are redacted.", offset: start, length: inspectedLength }]
      });
      consumed += inspectedLength;
      if (inspectedLength < payloadLength) { partial = true; break; }
    }
    offset += length;
  }
  if (ocrRequested) limitations.push("OCR was requested but is not implemented; only metadata text rules ran.");
  if (partial) limitations.push("JPEG comment metadata was malformed or exceeded the configured inspection bound.");
  return { status: ocrRequested || partial ? "partial" : "completed", dataEgress: "none", signals: findings, limitations };
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
