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
  readonly aiInspection?: { readonly enabled: boolean; readonly ocr: boolean; readonly adapterId?: string };
  readonly steganography?: SteganographyOptions;
  readonly signal?: AbortSignal;
  readonly hints?: ScanHints;
  readonly limits?: Partial<ResourceLimits>;
  readonly requiredControls?: readonly string[];
  readonly unsupportedFormat?: "review" | "reject";
  readonly incompleteAnalysis?: "review" | "reject";
}

export interface SteganographyOptions {
  readonly enabled: boolean;
  readonly mode: "statistical" | "targeted";
  /** Maximum sampled PNG pixels; defaults to 100,000 and cannot exceed 1,000,000. */
  readonly maxSamples?: number;
}

export interface ScanIsolationOptions {
  /** Maximum time before the worker is terminated (default 10 seconds, maximum 60 seconds). */
  readonly timeoutMs?: number;
  /** V8 old-generation heap ceiling for the worker (default 64 MiB, maximum 256 MiB). */
  readonly maxOldGenerationSizeMb?: number;
}

export interface ScanHints {
  readonly filename?: string;
  readonly mediaType?: string;
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
  readonly stage: "identify" | "structural" | "metadata" | "active_content" | "binary" | "ai" | "resource" | "policy";
  readonly title: string;
  readonly description: string;
  readonly status: "confirmed" | "suspected" | "inconclusive";
  readonly controlStatus: ControlStatus;
  readonly evidence: readonly Evidence[];
}

export interface BinaryInspectionResult {
  readonly status: "passed" | "findings" | "unsupported" | "error";
  readonly bytesScanned: number;
  readonly findings: readonly Finding[];
  readonly trailingData: boolean;
  readonly recursiveInspection: false;
}

export interface MetadataInspectionResult {
  readonly status: "partial" | "unsupported" | "error";
  readonly metadataBytes: number;
  readonly entriesInspected: number;
  readonly findings: readonly Finding[];
}

export interface SteganographyResult {
  readonly status: "passed" | "anomalous" | "inconclusive" | "unsupported" | "error";
  readonly methods: readonly { readonly id: string; readonly applicable: boolean; readonly status: "passed" | "anomalous" | "inconclusive" | "skipped" | "unsupported" | "error"; readonly samples?: number; readonly score?: number }[];
  readonly limitations: readonly string[];
}

export interface AiInspectionResult {
  readonly status: "not_requested" | "completed" | "partial" | "unsupported" | "error";
  readonly dataEgress: "none" | "local" | "remote";
  readonly signals: readonly Finding[];
  readonly limitations: readonly string[];
}

export interface ControlResult {
  readonly status: ControlStatus;
  readonly summary: string;
}

export interface CapabilityReport {
  readonly runtime: "node";
  readonly runtimeVersion: string;
  readonly engineVersion: string;
  readonly specVersion: string;
  readonly formats: Readonly<Record<ImageFormat, {
    readonly inspect: boolean;
    readonly decode: boolean;
    readonly sanitize: boolean;
    readonly reason: string;
  }>>;
  readonly networkAccess: false;
  readonly optionalAdapters: Readonly<Record<string, boolean>>;
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
  readonly binaryInspection?: BinaryInspectionResult;
  readonly metadataInspection?: MetadataInspectionResult;
  readonly steganography: SteganographyResult;
  readonly aiInspection: AiInspectionResult;
  readonly capabilities: CapabilityReport;
  readonly limitations: readonly string[];
  readonly inputBytes: number;
}

export class PixwardenError extends Error {
  readonly code: "INVALID_OPTIONS" | "INPUT_TOO_LARGE" | "LIMIT_EXCEEDED" | "CANCELLED" | "MALFORMED_INPUT" | "UNSUPPORTED_CAPABILITY" | "SANITIZATION_FAILURE" | "IO_FAILURE";

  constructor(code: PixwardenError["code"], message: string) {
    super(message);
    this.name = "PixwardenError";
    this.code = code;
  }
}
