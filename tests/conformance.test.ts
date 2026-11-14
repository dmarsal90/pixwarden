import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { scanImage } from "../src/index.js";

interface ConformanceVector {
  readonly id: string;
  readonly inputHex: string;
  readonly sha256: string;
  readonly scanOptions?: { readonly limits?: { readonly maxWidth?: number; readonly maxHeight?: number; readonly maxPixels?: number; readonly maxFrames?: number }; readonly aiInspection?: { readonly enabled: boolean; readonly ocr: boolean } };
  readonly expected: {
    readonly format: string;
    readonly validity: string;
    readonly verdict: string;
    readonly coverage: string;
    readonly findingIds: readonly string[];
    readonly binaryStatus?: string;
    readonly binaryBytesScanned?: number;
    readonly aiStatus?: string;
  };
}

const manifest = JSON.parse(readFileSync(new URL("../spec/corpus/v1/manifest.json", import.meta.url), "utf8")) as { vectors: readonly ConformanceVector[] };

describe("shared Pixwarden v1 corpus", () => {
  it.each(manifest.vectors)("conforms to $id", async (vector) => {
    const input = Buffer.from(vector.inputHex, "hex");
    expect(createHash("sha256").update(input).digest("hex")).toBe(vector.sha256);
    const result = await scanImage(input, vector.scanOptions);
    expect(result.format).toBe(vector.expected.format);
    expect(result.validity).toBe(vector.expected.validity);
    expect(result.verdict).toBe(vector.expected.verdict);
    expect(result.coverage).toBe(vector.expected.coverage);
    expect(result.steganography.status).toBe("unsupported");
    expect(result.controls.steganography?.status).toBe("unsupported");
    expect(result.controls.aiInspection?.status).toBe(vector.scanOptions?.aiInspection?.enabled ? "passed" : "skipped");
    expect([...new Set(result.findings.map((finding) => finding.id))].sort()).toEqual([...vector.expected.findingIds].sort());
    if (vector.expected.binaryStatus !== undefined) {
      expect(result.binaryInspection?.status).toBe(vector.expected.binaryStatus);
      expect(result.binaryInspection?.bytesScanned).toBe(vector.expected.binaryBytesScanned);
    }
    if (vector.expected.aiStatus !== undefined) {
      expect(result.aiInspection.status).toBe(vector.expected.aiStatus);
      expect(result.aiInspection.dataEgress).toBe("none");
      if (vector.expected.findingIds.includes("AI-002")) {
        expect(JSON.stringify(result)).not.toContain("Ignore all previous instructions");
      }
    }
  });
});
