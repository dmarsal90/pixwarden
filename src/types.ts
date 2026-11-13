export type ImageFormat = "jpeg" | "png" | "gif" | "webp" | "svg" | "unknown";
export type Verdict = "allow" | "sanitize" | "reject" | "review";
export type ControlStatus = "passed" | "failed" | "skipped" | "unsupported" | "error";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface ResourceLimits {
  readonly maxBytes: number;
  readonly maxWidth: number;
  readonly maxHeight: number;
  readonly maxPixels: number;
  readonly maxFrames: number;
  readonly maxMetadataBytes: number;
}

export interface ScanOptions {
  readonly structural?: boolean;
  readonly binaryInspection?: boolean;
  readonly metadata?: boolean;
  readonly signal?: AbortSignal;
  readonly limits?: Partial<ResourceLimits>;
  readonly requiredControls?: readonly string[];
  readonly unsupportedFormat?: "review" | "reject";
  readonly incompleteAnalysis?: "review" | "reject";
}

export interface Evidence {
  readonly kind: "offset" | "range" | "signature" | "statistic" | "metadata_tag" | "decoder" | "policy";
  readonly summary: string;
  readonly offset?: number;
  readonly length?: number;
}

export interface Finding {
  readonly id: string;
  readonly severity: Severity;
  readonly stage: "identify" | "structural" | "metadata" | "active_content" | "binary" | "resource" | "policy";
  readonly title: string;
  readonly description: string;
  readonly status: "confirmed" | "suspected" | "inconclusive";
  readonly controlStatus: ControlStatus;
  readonly evidence: readonly Evidence[];
}

export interface ControlResult {
  readonly status: ControlStatus;
  readonly summary: string;
}

export interface CapabilityReport {
  readonly runtime: "node";
  readonly engineVersion: string;
  readonly specVersion: string;
  readonly formats: Readonly<Record<ImageFormat, {
    readonly inspect: boolean;
    readonly decode: boolean;
    readonly sanitize: boolean;
    readonly reason: string;
  }>>;
  readonly networkAccess: false;
  readonly hardLimits: Readonly<Record<string, boolean>>;
}

export interface ScanResult {
  readonly resultVersion: 1;
  readonly scanId: string;
  readonly engineVersion: string;
  readonly specVersion: string;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly format: ImageFormat;
  readonly validity: "valid" | "invalid" | "unknown";
  readonly decodability: "not_attempted" | "unsupported";
  readonly sanitized: false;
  readonly policyCompliant: boolean;
  readonly coverage: "complete" | "partial" | "incomplete";
  readonly verdict: Verdict;
  readonly controls: Readonly<Record<string, ControlResult>>;
  readonly findings: readonly Finding[];
  readonly capabilities: CapabilityReport;
  readonly limitations: readonly string[];
  readonly inputBytes: number;
}

export class PixwardenError extends Error {
  readonly code: "INVALID_OPTIONS" | "INPUT_TOO_LARGE" | "LIMIT_EXCEEDED" | "CANCELLED" | "MALFORMED_INPUT" | "SANITIZATION_FAILURE";

  constructor(code: PixwardenError["code"], message: string) {
    super(message);
    this.name = "PixwardenError";
    this.code = code;
  }
}
