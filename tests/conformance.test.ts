import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { scanImage } from "../src/index.js";

interface ConformanceVector {
  readonly id: string;
  readonly inputHex: string;
  readonly sha256: string;
  readonly expected: {
    readonly format: string;
    readonly validity: string;
    readonly verdict: string;
    readonly coverage: string;
    readonly findingIds: readonly string[];
  };
}

const manifest = JSON.parse(readFileSync(new URL("../spec/corpus/v1/manifest.json", import.meta.url), "utf8")) as { vectors: readonly ConformanceVector[] };

describe("shared Pixwarden v1 corpus", () => {
  it.each(manifest.vectors)("conforms to $id", async (vector) => {
    const input = Buffer.from(vector.inputHex, "hex");
    expect(createHash("sha256").update(input).digest("hex")).toBe(vector.sha256);
    const result = await scanImage(input);
    expect(result.format).toBe(vector.expected.format);
    expect(result.validity).toBe(vector.expected.validity);
    expect(result.verdict).toBe(vector.expected.verdict);
    expect(result.coverage).toBe(vector.expected.coverage);
    expect([...new Set(result.findings.map((finding) => finding.id))].sort()).toEqual([...vector.expected.findingIds].sort());
  });
});
