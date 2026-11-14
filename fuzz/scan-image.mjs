import assert from "node:assert/strict";
import { scanImage } from "../dist/index.js";

const MAX_FUZZ_INPUT_BYTES = 65_536;
const controlStatuses = new Set(["passed", "failed", "skipped", "unsupported", "error"]);

/**
 * Coverage-guided target. Inputs are synthetic bytes; the scanner never executes
 * file contents. Keep the target bounded so one mutation cannot allocate a large
 * image or induce work outside the byte-level profile.
 * @param {Buffer} input
 */
export async function fuzz(input) {
  if (input.byteLength > MAX_FUZZ_INPUT_BYTES) return;

  const original = Buffer.from(input);
  const report = await scanImage(input, { limits: { maxBytes: MAX_FUZZ_INPUT_BYTES } });

  assert.equal(report.inputBytes, input.byteLength, "report must preserve the input byte count");
  assert.deepEqual(input, original, "inspection must not mutate caller-owned bytes");
  assert.ok(["jpeg", "png", "gif", "webp", "svg", "unknown"].includes(report.format));
  assert.ok(["valid", "invalid", "unknown"].includes(report.validity));
  assert.ok(report.findings.length <= input.byteLength + 16, "finding count must remain bounded by input size");

  for (const control of Object.values(report.controls)) {
    assert.ok(controlStatuses.has(control.status), "control status must use the shared enum");
  }
  for (const finding of report.findings) {
    for (const evidence of finding.evidence) {
      if (evidence.offset !== undefined) {
        assert.ok(Number.isSafeInteger(evidence.offset) && evidence.offset >= 0 && evidence.offset <= input.byteLength);
      }
      if (evidence.length !== undefined) {
        assert.ok(Number.isSafeInteger(evidence.length) && evidence.length >= 0);
        assert.ok(evidence.offset !== undefined && evidence.offset + evidence.length <= input.byteLength);
      }
    }
  }
}
