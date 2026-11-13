import { randomUUID } from "node:crypto";
import { inspectBinaryIndicators, inspectStructure } from "./inspectors.js";
import { sanitizeSvg } from "./svg-guard.js";
import { PixwardenError, type CapabilityReport, type ControlResult, type Finding, type ImageFormat, type ResourceLimits, type ScanHints, type ScanOptions, type ScanResult, type Verdict } from "./types.js";

export { PixwardenError } from "./types.js";
export type { CapabilityReport, ControlResult, Evidence, Finding, ImageFormat, ResourceLimits, ScanHints, ScanOptions, ScanResult, Verdict } from "./types.js";
export type { SvgSanitizationResult } from "./svg-guard.js";
export { sanitizeSvg } from "./svg-guard.js";

export const ENGINE_VERSION = "0.1.0";
export const SPEC_VERSION = "0.1.0";

const defaultLimits: ResourceLimits = Object.freeze({
  maxBytes: 10 * 1024 * 1024,
  maxWidth: 40_000,
  maxHeight: 40_000,
  maxPixels: 40_000_000,
  maxFrames: 200,
  maxMetadataBytes: 1024 * 1024
});

const formats: CapabilityReport["formats"] = Object.freeze({
  jpeg: { inspect: true, decode: false, sanitize: false, reason: "Bounded marker and segment structure inspection only; no decoder is bundled." },
  png: { inspect: true, decode: false, sanitize: false, reason: "Chunk bounds/order/CRC and dimensions are inspected; image data is not decompressed." },
  gif: { inspect: true, decode: false, sanitize: false, reason: "Block, sub-block and frame structure is inspected; LZW data is not decoded." },
  webp: { inspect: true, decode: false, sanitize: false, reason: "RIFF chunk bounds and selected dimensions/frame metadata are inspected; bitstreams are not decoded." },
  svg: { inspect: true, decode: false, sanitize: true, reason: "Saxes-backed XML profile and static allowlist sanitizer; unsupported active features are removed or reported." },
  unknown: { inspect: false, decode: false, sanitize: false, reason: "No structural profile is available." }
});

const capabilityReport: CapabilityReport = Object.freeze({
  runtime: "node",
  engineVersion: ENGINE_VERSION,
  specVersion: SPEC_VERSION,
  formats,
  networkAccess: false,
  hardLimits: Object.freeze({ inputBytes: true, dimensionsBeforeDecode: true, framesBeforeDecode: true, memory: false, cpu: false, wallTime: false })
});

function mergeLimits(input: Partial<ResourceLimits> | undefined): ResourceLimits {
  const merged = { ...defaultLimits, ...input };
  for (const [key, value] of Object.entries(merged)) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new PixwardenError("INVALID_OPTIONS", `Limit ${key} must be a positive safe integer.`);
    if (value > defaultLimits[key as keyof ResourceLimits]) throw new PixwardenError("INVALID_OPTIONS", `Limit ${key} cannot exceed the built-in maximum.`);
  }
  return merged;
}

function makeControl(status: ControlResult["status"], summary: string): ControlResult {
  return Object.freeze({ status, summary });
}

const extensions: Readonly<Record<string, ImageFormat>> = Object.freeze({ jpg: "jpeg", jpeg: "jpeg", png: "png", gif: "gif", webp: "webp", svg: "svg" });
const mediaTypes: Readonly<Record<string, ImageFormat>> = Object.freeze({
  "image/jpeg": "jpeg", "image/png": "png", "image/gif": "gif", "image/webp": "webp", "image/svg+xml": "svg"
});

function inspectHints(format: ImageFormat, hints: ScanHints | undefined): { control: ControlResult; findings: Finding[] } {
  if (!hints || (hints.filename === undefined && hints.mediaType === undefined)) {
    return { control: makeControl("skipped", "No filename or media-type hints were supplied."), findings: [] };
  }
  let unsupportedHint = false;
  const candidates: ImageFormat[] = [];
  if (hints.filename !== undefined) {
    const basename = hints.filename.split(/[\\/]/).at(-1) ?? "";
    const dot = basename.lastIndexOf(".");
    const extension = dot >= 0 ? basename.slice(dot + 1).toLowerCase() : "";
    const candidate = extensions[extension];
    if (candidate) candidates.push(candidate);
    else unsupportedHint = true;
  }
  if (hints.mediaType !== undefined) {
    const mediaType = hints.mediaType.split(";", 1)[0]!.trim().toLowerCase();
    const candidate = mediaTypes[mediaType];
    if (candidate) candidates.push(candidate);
    else unsupportedHint = true;
  }
  const findings: Finding[] = (format === "unknown" ? [] : [...new Set(candidates)].filter((candidate) => candidate !== format)).map((candidate) => ({
    id: "IMG-010",
    severity: "medium",
    stage: "identify",
    title: "Declared type disagrees with image bytes",
    description: "A recognized filename extension or media type does not match the format detected from the input bytes.",
    status: "suspected",
    controlStatus: "passed",
    evidence: [{ kind: "policy", summary: "Caller-provided type hint differs from byte-derived format." }]
  }));
  if (format === "unknown" || unsupportedHint) {
    return { control: makeControl("unsupported", "One or more type hints or the detected format could not be compared using a supported profile."), findings };
  }
  return { control: makeControl("passed", "Recognized caller hints were compared with the byte-derived format."), findings };
}

function validateHints(hints: ScanHints | undefined): void {
  if (hints === undefined) return;
  if (hints === null || typeof hints !== "object") throw new PixwardenError("INVALID_OPTIONS", "Hints must be an object.");
  if (hints.filename === undefined && hints.mediaType === undefined) throw new PixwardenError("INVALID_OPTIONS", "At least one filename or media-type hint is required.");
  if (hints.filename !== undefined && (typeof hints.filename !== "string" || hints.filename.length > 255 || /[\u0000-\u001f\u007f]/.test(hints.filename))) {
    throw new PixwardenError("INVALID_OPTIONS", "Filename hint must be a short string without control characters.");
  }
  if (hints.mediaType !== undefined && (typeof hints.mediaType !== "string" || hints.mediaType.length > 127 || /[\u0000-\u001f\u007f]/.test(hints.mediaType))) {
    throw new PixwardenError("INVALID_OPTIONS", "Media-type hint must be a short string without control characters.");
  }
}

function evaluateVerdict(
  findings: readonly Finding[],
  controls: Readonly<Record<string, ControlResult>>,
  required: readonly string[],
  unsupportedAction: "review" | "reject",
  incompleteAction: "review" | "reject"
): { verdict: Verdict; complete: boolean; compliant: boolean } {
  const incomplete = required.some((id) => controls[id]?.status !== "passed");
  if (findings.some((item) => item.severity === "critical" || item.severity === "high" || item.controlStatus === "failed")) {
    return { verdict: "reject", complete: !incomplete, compliant: false };
  }
  if (incomplete) {
    const hasUnsupported = required.some((id) => ["unsupported", "skipped"].includes(controls[id]?.status ?? "skipped"));
    return { verdict: hasUnsupported ? unsupportedAction : incompleteAction, complete: false, compliant: false };
  }
  if (findings.some((item) => item.status === "suspected" || item.status === "inconclusive")) {
    return { verdict: "review", complete: true, compliant: false };
  }
  return { verdict: "allow", complete: true, compliant: true };
}

/**
 * Inspect untrusted image bytes without decoding or modifying them.
 * `AbortSignal` can cancel before parsing starts. Once synchronous byte parsing
 * begins, this in-process implementation cannot safely interrupt it.
 */
export async function scanImage(input: Uint8Array, options: ScanOptions = {}): Promise<ScanResult> {
  const started = new Date().toISOString();
  if (!(input instanceof Uint8Array)) throw new PixwardenError("INVALID_OPTIONS", "Input must be a Uint8Array or Node.js Buffer.");
  const limits = mergeLimits(options.limits);
  if (input.byteLength > limits.maxBytes) throw new PixwardenError("INPUT_TOO_LARGE", "Input exceeds the configured byte limit.");
  await new Promise<void>((resolve) => setImmediate(resolve));
  if (options.signal?.aborted) throw new PixwardenError("CANCELLED", "Scan was cancelled before inspection started.");
  const snapshot = Uint8Array.from(input);
  return inspectSnapshot(snapshot, options, limits, started);
}

function inspectSnapshot(snapshot: Uint8Array, options: ScanOptions, limits: ResourceLimits, started: string): ScanResult {
  validateHints(options.hints);
  const structuralEnabled = options.structural ?? true;
  const binaryEnabled = options.binaryInspection ?? true;
  const metadataEnabled = options.metadata ?? true;
  const structural = structuralEnabled ? inspectStructure(snapshot, limits) : undefined;
  const format: ImageFormat = structural?.format ?? "unknown";
  const findings: Finding[] = [...(structural?.findings ?? [])];
  const hintInspection = inspectHints(format, options.hints);
  findings.push(...hintInspection.findings);
  const controls: Record<string, ControlResult> = {
    hints: hintInspection.control,
    structural: structuralEnabled
      ? structural?.validity === "unknown" ? makeControl("unsupported", "No structural profile is available for this format.") : makeControl(structural?.validity === "valid" ? "passed" : "failed", "A bounded format-specific structural profile ran.")
      : makeControl("skipped", "Structural inspection was disabled by the caller."),
    metadata: !metadataEnabled
      ? makeControl("skipped", "Metadata inspection was disabled by the caller.")
      : ["jpeg", "png", "gif", "webp"].includes(format) ? makeControl("unsupported", "Metadata segment locations and aggregate byte counts are bounded, but metadata tags and values are not parsed.") : makeControl("unsupported", "Metadata inspection is not implemented for this format."),
    binary: binaryEnabled
      ? makeControl("passed", "Read-only signature indicators were scanned; this is not malware scanning and may produce false positives.")
      : makeControl("skipped", "Binary signature inspection was disabled by the caller."),
    decode: makeControl("unsupported", "No image decoder is bundled or invoked."),
    sanitization: format === "svg"
      ? makeControl("skipped", "The SVG sanitizer is available separately and was not invoked by scanImage.")
      : makeControl("unsupported", "No raster sanitizer is implemented; the original input is unchanged.")
  };
  if (binaryEnabled) findings.push(...inspectBinaryIndicators(snapshot));
  for (const [name, maximum, observed] of [
    ["width", limits.maxWidth, structural?.width],
    ["height", limits.maxHeight, structural?.height],
    ["pixels", limits.maxPixels, structural?.width !== undefined && structural.height !== undefined ? structural.width * structural.height : undefined],
    ["frames", limits.maxFrames, structural?.frameCount]
  ] as const) {
    if (observed !== undefined && observed > maximum) {
      findings.push({ id: name === "frames" ? "DEC-008" : "DEC-007", severity: "high", stage: "resource", title: `${name} limit exceeded`, description: `Observed ${name} exceeds configured maximum.`, status: "confirmed", controlStatus: "failed", evidence: [{ kind: "statistic", summary: `${name}=${observed}; maximum=${maximum}` }] });
    }
  }
  const required = options.requiredControls ?? ["structural"];
  const availableControlNames = new Set(Object.keys(controls));
  if (required.length === 0 || required.some((id) => !availableControlNames.has(id))) {
    throw new PixwardenError("INVALID_OPTIONS", "requiredControls must contain known controls and cannot be empty.");
  }
  const evaluation = evaluateVerdict(findings, controls, required, options.unsupportedFormat ?? "review", options.incompleteAnalysis ?? "review");
  const enabledControls = ["structural", ...(binaryEnabled ? ["binary"] : []), ...(metadataEnabled ? ["metadata"] : []), ...(options.hints ? ["hints"] : [])];
  const coverage = enabledControls.some((id) => controls[id]?.status === "error")
    ? "incomplete"
    : enabledControls.some((id) => ["unsupported", "skipped"].includes(controls[id]?.status ?? "unsupported"))
      ? "partial"
      : "complete";
  const completed = new Date().toISOString();
  const limitations = [
    "Structural validity is limited to the implemented byte-level profile; it is not proof of safe rendering or decoding.",
    "No raster decoder/sanitizer, OCR, steganography detector, or model analysis is bundled. The SVG sanitizer is a separate operation and is not invoked by scanImage.",
    "In-process parsing has no hard CPU, memory, or wall-clock enforcement. Use a killable worker/container for hostile workloads.",
    "Binary signatures are indicators only; they neither prove a complete embedded file nor replace antivirus analysis."
  ];
  return Object.freeze({
    resultVersion: 1,
    scanId: randomUUID(),
    engineVersion: ENGINE_VERSION,
    specVersion: SPEC_VERSION,
    startedAt: started,
    completedAt: completed,
    format,
    validity: structural?.validity ?? "unknown",
    decodability: "not_attempted",
    sanitized: false,
    policyCompliant: evaluation.compliant,
    coverage,
    verdict: evaluation.verdict,
    controls: Object.freeze(controls),
    findings: Object.freeze(findings),
    capabilities: capabilityReport,
    limitations: Object.freeze(limitations),
    inputBytes: snapshot.byteLength
  });
}

/**
 * Read an async byte source without accepting more than the configured input cap.
 * Chunks are snapshotted as they arrive; scanning begins only after the bounded
 * input has been assembled. Cancellation is checked between yielded chunks.
 */
export async function scanImageStream(source: AsyncIterable<Uint8Array>, options: ScanOptions = {}): Promise<ScanResult> {
  const started = new Date().toISOString();
  if (source === null || typeof source !== "object" || typeof source[Symbol.asyncIterator] !== "function") {
    throw new PixwardenError("INVALID_OPTIONS", "Input source must be an AsyncIterable of Uint8Array chunks.");
  }
  const limits = mergeLimits(options.limits);
  validateHints(options.hints);
  if (options.signal?.aborted) throw new PixwardenError("CANCELLED", "Stream scan was cancelled before reading input.");
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  for await (const chunk of source) {
    if (options.signal?.aborted) throw new PixwardenError("CANCELLED", "Stream scan was cancelled while reading input.");
    if (!(chunk instanceof Uint8Array)) throw new PixwardenError("INVALID_OPTIONS", "Every stream chunk must be a Uint8Array or Node.js Buffer.");
    if (chunk.byteLength > limits.maxBytes - totalBytes) throw new PixwardenError("INPUT_TOO_LARGE", "Stream input exceeds the configured byte limit.");
    totalBytes += chunk.byteLength;
    chunks.push(Uint8Array.from(chunk));
  }
  if (options.signal?.aborted) throw new PixwardenError("CANCELLED", "Stream scan was cancelled before inspection started.");
  const snapshot = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    snapshot.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return inspectSnapshot(snapshot, options, limits, started);
}

export function getCapabilities(): CapabilityReport {
  return capabilityReport;
}
