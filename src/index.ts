import { randomUUID } from "node:crypto";
import { inspectBinaryIndicators, inspectStructure } from "./inspectors.js";
import { PixwardenError, type CapabilityReport, type ControlResult, type Finding, type ImageFormat, type ResourceLimits, type ScanOptions, type ScanResult, type Verdict } from "./types.js";

export { PixwardenError } from "./types.js";
export type { CapabilityReport, ControlResult, Evidence, Finding, ImageFormat, ResourceLimits, ScanOptions, ScanResult, Verdict } from "./types.js";

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
  svg: { inspect: false, decode: false, sanitize: false, reason: "Secure XML parser and allowlist sanitizer have not been selected; SVG is reported unsupported." },
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

  const structuralEnabled = options.structural ?? true;
  const binaryEnabled = options.binaryInspection ?? true;
  const metadataEnabled = options.metadata ?? true;
  const structural = structuralEnabled ? inspectStructure(snapshot, limits) : undefined;
  const format: ImageFormat = structural?.format ?? "unknown";
  const findings: Finding[] = [...(structural?.findings ?? [])];
  const controls: Record<string, ControlResult> = {
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
    sanitization: makeControl("unsupported", "No sanitizer is implemented; the original input is unchanged.")
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
  const enabledControls = ["structural", ...(binaryEnabled ? ["binary"] : []), ...(metadataEnabled ? ["metadata"] : [])];
  const coverage = enabledControls.some((id) => controls[id]?.status === "error")
    ? "incomplete"
    : enabledControls.some((id) => ["unsupported", "skipped"].includes(controls[id]?.status ?? "unsupported"))
      ? "partial"
      : "complete";
  const completed = new Date().toISOString();
  const limitations = [
    "Structural validity is limited to the implemented byte-level profile; it is not proof of safe rendering or decoding.",
    "No raster or SVG decoder, sanitizer, OCR, steganography detector, or model analysis is bundled.",
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

export function getCapabilities(): CapabilityReport {
  return capabilityReport;
}
