import type { AiInspectionResult, Finding } from "./types.js";

const signature = [137, 80, 78, 71, 13, 10, 26, 10];
const patterns = [
  /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
  /(?:reveal|show|print)\s+(?:the\s+)?(?:system|developer)\s+prompt/i,
  /ignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)/i,
  /(?:revela|muestra)\s+(?:el\s+)?prompt\s+del\s+sistema/i
];

interface TextEntry { readonly start: number; readonly length: number; readonly text: string }

/** Advisory inspection of uncompressed PNG tEXt/iTXt metadata only. */
export function inspectPngInstructionMetadata(data: Uint8Array, maxMetadataBytes: number, ocrRequested: boolean): AiInspectionResult {
  const limitations = [
    "This rule set inspects only uncompressed PNG tEXt and iTXt fields; it does not inspect visible pixels, OCR output, compressed metadata, or other formats.",
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
    if (kind === "tEXt" || kind === "iTXt") {
      const allowed = Math.max(0, maxMetadataBytes - consumed);
      const entry = extractText(data, payloadStart, payloadEnd, kind, allowed);
      if (entry) {
        const boundedText = entry.text;
        if (length > allowed) partial = true;
        consumed += Math.min(length, allowed);
        if (patterns.some((pattern) => pattern.test(boundedText))) {
          findings.push({
            id: "AI-002", severity: "medium", stage: "ai",
            title: "Instruction-like text in PNG metadata",
            description: "Uncompressed PNG text metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.",
            status: "suspected", controlStatus: "passed",
            evidence: [{ kind: "range", summary: "A bounded PNG text field matched a prompt-risk rule; field contents are redacted.", offset: entry.start, length: entry.length }]
          });
        }
      } else partial = true;
    } else if (kind === "zTXt") {
      partial = true;
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

function extractText(data: Uint8Array, start: number, end: number, kind: "tEXt" | "iTXt", maximumTextBytes: number): TextEntry | undefined {
  const keywordEnd = findZero(data, start, end);
  if (keywordEnd < 0) return undefined;
  let textStart: number;
  if (kind === "tEXt") textStart = keywordEnd + 1;
  else {
    if (keywordEnd + 3 > end || data[keywordEnd + 1] !== 0 || data[keywordEnd + 2] !== 0) return undefined;
    const languageEnd = findZero(data, keywordEnd + 3, end);
    if (languageEnd < 0) return undefined;
    const translatedEnd = findZero(data, languageEnd + 1, end);
    if (translatedEnd < 0) return undefined;
    textStart = translatedEnd + 1;
  }
  const textLength = end - textStart;
  return { start: textStart, length: textLength, text: new TextDecoder("utf-8", { fatal: false }).decode(data.subarray(textStart, textStart + Math.min(textLength, maximumTextBytes))) };
}

function findZero(data: Uint8Array, start: number, end: number): number {
  for (let index = start; index < end; index++) if (data[index] === 0) return index;
  return -1;
}

function readU32(data: Uint8Array, offset: number): number {
  return data[offset]! * 0x1000000 + data[offset + 1]! * 0x10000 + data[offset + 2]! * 0x100 + data[offset + 3]!;
}
