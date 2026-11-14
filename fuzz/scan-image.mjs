import assert from "node:assert/strict";
import { PixwardenError, sanitizePngRgba8, sanitizeSvg, scanImage } from "../dist/index.js";

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

  if (report.format === "svg") {
    let sanitized;
    try {
      sanitized = sanitizeSvg(input);
    } catch (error) {
      if (!(error instanceof PixwardenError) || !["MALFORMED_INPUT", "INPUT_TOO_LARGE", "LIMIT_EXCEEDED"].includes(error.code)) {
        throw error;
      }
    }
    if (sanitized) {
      assert.equal(sanitized.inputBytes, input.byteLength);
      assert.equal(sanitized.outputBytes, sanitized.bytes.byteLength);
      assert.equal(sanitized.postCheckStatus, "passed");
      const repeated = sanitizeSvg(sanitized.bytes);
      assert.deepEqual(repeated.bytes, sanitized.bytes, "sanitized SVG must be idempotent");
      assert.deepEqual(repeated.removedElements, {});
      assert.equal(repeated.removedAttributes, 0);
    }
    assert.deepEqual(input, original, "SVG sanitization must not mutate caller-owned bytes");
  }

  if (report.format === "png") {
    let sanitized;
    try {
      sanitized = sanitizePngRgba8(input);
    } catch (error) {
      if (!(error instanceof PixwardenError) || !["MALFORMED_INPUT", "INPUT_TOO_LARGE", "LIMIT_EXCEEDED", "UNSUPPORTED_CAPABILITY", "SANITIZATION_FAILURE"].includes(error.code)) {
        throw error;
      }
    }
    if (sanitized) {
      assert.equal(sanitized.inputBytes, input.byteLength);
      assert.equal(sanitized.outputBytes, sanitized.bytes.byteLength);
      assert.equal(sanitized.postCheckStatus, "passed");
      const repeated = sanitizePngRgba8(sanitized.bytes);
      assert.deepEqual(repeated.bytes, sanitized.bytes, "sanitized RGBA8 PNG must be idempotent");
    }
    assert.deepEqual(input, original, "PNG raster sanitization must not mutate caller-owned bytes");
  }
}
