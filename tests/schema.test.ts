import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { scanImage } from "../src/index.js";

const schema = JSON.parse(readFileSync(new URL("../spec/schemas/pixwarden-v1.schema.json", import.meta.url), "utf8")) as { $id: string };
const request = JSON.parse(readFileSync(new URL("../spec/examples/scan-request-v1.json", import.meta.url), "utf8")) as unknown;
const reviewResult = JSON.parse(readFileSync(new URL("../spec/examples/scan-result-review-v1.json", import.meta.url), "utf8")) as unknown;
const contractExamples = [
  ["ScanOptions", "scan-options-v1.json"], ["ScanHints", "scan-hints-v1.json"],
  ["ResourceLimits", "resource-limits-v1.json"], ["Evidence", "evidence-v1.json"],
  ["Finding", "finding-v1.json"], ["SecurityPolicy", "security-policy-v1.json"],
  ["SanitizationResult", "sanitization-result-v1.json"], ["BinaryInspectionResult", "binary-inspection-result-v1.json"],
  ["SteganographyResult", "steganography-result-v1.json"], ["AiInspectionResult", "ai-inspection-result-v1.json"],
  ["CapabilityReport", "capability-report-v1.json"], ["EngineError", "engine-error-v1.json"]
] as const;
const ajv = new Ajv2020({ allErrors: true, strict: true });
const addFormats = createRequire(import.meta.url)("ajv-formats") as (instance: InstanceType<typeof Ajv2020>) => void;
addFormats(ajv);
ajv.addSchema(schema);

function validator(name: string) {
  const result = ajv.getSchema(`${schema.$id}#/$defs/${name}`);
  if (!result) throw new Error(`Schema definition ${name} was not registered.`);
  return result;
}

function pngChunk(type: string, payload: number[]): number[] {
  const bytes = [...type].map((character) => character.charCodeAt(0)).concat(payload);
  let crc = 0xffff_ffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb8_8320 : 0);
  }
  crc = (crc ^ 0xffff_ffff) >>> 0;
  const length = payload.length;
  return [length >>> 24, (length >>> 16) & 255, (length >>> 8) & 255, length & 255, ...bytes, crc >>> 24, (crc >>> 16) & 255, (crc >>> 8) & 255, crc & 255];
}

describe("shared JSON contracts", () => {
  it("is a valid Draft 2020-12 schema and validates its golden request/result", () => {
    expect(ajv.validateSchema(schema)).toBe(true);
    expect(validator("ScanRequest")(request)).toBe(true);
    expect(validator("ScanResult")(reviewResult)).toBe(true);
  });

  it("accepts the current JavaScript runtime report shape", async () => {
    const input = new Uint8Array([
      137, 80, 78, 71, 13, 10, 26, 10,
      ...pngChunk("IHDR", [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
      ...pngChunk("IDAT", [0]),
      ...pngChunk("IEND", [])
    ]);
    const result = await scanImage(input);
    expect(result.binaryInspection).toMatchObject({ status: "passed", bytesScanned: 0, recursiveInspection: false });
    expect(validator("ScanResult")(result)).toBe(true);
  });

  it.each(contractExamples)("validates the %s golden example", (name, filename) => {
    const example = JSON.parse(readFileSync(new URL(`../spec/examples/${filename}`, import.meta.url), "utf8")) as unknown;
    expect(validator(name)(example)).toBe(true);
  });

  it("requires exactly one input variant and refuses remote input references", () => {
    const validate = validator("ScanRequest");
    expect(validate({ requestVersion: 1, input: { base64: "", inputRef: "local:upload-1" }, options: {} })).toBe(false);
    expect(validate({ requestVersion: 1, input: { inputRef: "https://internal.example/image" }, options: {} })).toBe(false);
  });

  it("rejects invalid ranges and unknown finding fields", () => {
    const validate = validator("Finding");
    const finding = {
      id: "BIN-009", severity: "medium", stage: "binary", title: "Indicator", description: "Not a verdict.",
      status: "suspected", controlStatus: "passed", evidence: [{ kind: "range", summary: "signature", offset: 8 }]
    };
    expect(validate(finding)).toBe(false);
    expect(validate({ ...finding, evidence: [{ kind: "offset", summary: "marker", offset: 8 }], extra: true })).toBe(false);
  });
});
