import { describe, expect, it } from "vitest";
import { sanitizeSvg, scanImage, scanImageStream } from "../src/index.js";

function pngChunk(type: string, payload: number[]): number[] {
  const bytes = [...type].map((char) => char.charCodeAt(0)).concat(payload);
  let crc = 0xffff_ffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb8_8320 : 0);
  }
  crc = (crc ^ 0xffff_ffff) >>> 0;
  const length = payload.length;
  return [length >>> 24, (length >>> 16) & 255, (length >>> 8) & 255, length & 255, ...bytes, crc >>> 24, (crc >>> 16) & 255, (crc >>> 8) & 255, crc & 255];
}

const validPng = new Uint8Array([
  137, 80, 78, 71, 13, 10, 26, 10,
  ...pngChunk("IHDR", [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
  ...pngChunk("IDAT", [0]),
  ...pngChunk("IEND", [])
]);

describe("scanImage structural core", () => {
  it("identifies and validates a structurally complete PNG without decoding it", async () => {
    const result = await scanImage(validPng);
    expect(result.format).toBe("png");
    expect(result.validity).toBe("valid");
    expect(result.decodability).toBe("not_attempted");
    expect(result.verdict).toBe("allow");
  });

  it("rejects a PNG chunk whose declared size exceeds the input", async () => {
    const malformed = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 50, 73, 72, 68, 82, 0, 0, 0, 0]);
    const result = await scanImage(malformed);
    expect(result.validity).toBe("invalid");
    expect(result.verdict).toBe("reject");
    expect(result.findings.some((finding) => finding.id === "IMG-004")).toBe(true);
  });

  it("reports unsupported formats as incomplete and review by default", async () => {
    const result = await scanImage(new Uint8Array([1, 2, 3]));
    expect(result.verdict).toBe("review");
    expect(result.coverage).toBe("partial");
    expect(result.controls.structural?.status).toBe("unsupported");
  });

  it("parses the RIFF length in a WebP container as little-endian", async () => {
    const webp = new Uint8Array([82, 73, 70, 70, 16, 0, 0, 0, 87, 69, 66, 80, 86, 80, 56, 32, 4, 0, 0, 0, 0, 0, 0, 0]);
    const result = await scanImage(webp);
    expect(result.format).toBe("webp");
    expect(result.validity).toBe("valid");
  });

  it("enforces the byte limit before structural processing", async () => {
    await expect(scanImage(new Uint8Array(9), { limits: { maxBytes: 8 } })).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });
  });

  it("does not claim complete policy compliance when a required control was skipped", async () => {
    const result = await scanImage(validPng, { binaryInspection: false, requiredControls: ["structural", "binary"] });
    expect(result.policyCompliant).toBe(false);
    expect(result.verdict).toBe("review");
  });

  it("returns review when a requested metadata control is not implemented", async () => {
    const result = await scanImage(validPng, { requiredControls: ["structural", "metadata"] });
    expect(result.controls.metadata?.status).toBe("unsupported");
    expect(result.verdict).toBe("review");
  });

  it("can cancel before synchronous inspection begins", async () => {
    const controller = new AbortController();
    const pending = scanImage(validPng, { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("scans bounded async byte chunks and snapshots them as they arrive", async () => {
    const source = (async function* () {
      const first = validPng.slice(0, 8);
      yield first;
      first.fill(0);
      yield validPng.slice(8);
    })();
    const result = await scanImageStream(source);
    expect(result.format).toBe("png");
    expect(result.validity).toBe("valid");
  });

  it("stops reading a stream as soon as the byte cap is exceeded", async () => {
    let yielded = 0;
    const source = (async function* () {
      yielded++;
      yield new Uint8Array(5);
      yielded++;
      yield new Uint8Array(4);
      yielded++;
      yield new Uint8Array(1);
    })();
    await expect(scanImageStream(source, { limits: { maxBytes: 8 } })).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });
    expect(yielded).toBe(2);
  });

  it("inspects SVG through the XML profile and reports active markup", async () => {
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>marker</script><rect width="8" onclick="marker"/></svg>');
    const result = await scanImage(svg);
    expect(result.format).toBe("svg");
    expect(result.validity).toBe("valid");
    expect(result.findings.map((finding) => finding.id)).toContain("SVG-001");
    expect(result.findings.map((finding) => finding.id)).toContain("SVG-002");
    expect(result.verdict).toBe("reject");
  });

  it("sanitizes SVG to a re-checked static allowlist output", () => {
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><rect width="8" fill="red" onclick="marker"/><script>marker</script></svg>');
    const result = sanitizeSvg(svg);
    const output = new TextDecoder().decode(result.bytes);
    expect(output).toContain("<rect width=\"8\" fill=\"red\">");
    expect(output).not.toContain("onclick");
    expect(output).not.toContain("script");
    expect(result.postCheckStatus).toBe("passed");
    expect(result.removedAttributes).toBe(1);
  });

  it("rejects SVG DTDs before accepting a sanitized result", () => {
    const svg = new TextEncoder().encode('<!DOCTYPE svg SYSTEM "file:///not-read"><svg xmlns="http://www.w3.org/2000/svg"/>');
    let caught: unknown;
    try {
      sanitizeSvg(svg);
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: "MALFORMED_INPUT" });
  });

  it("compares optional filename and MIME hints against byte-derived format without retaining them", async () => {
    const result = await scanImage(validPng, { hints: { filename: "/private/uploads/photo.jpg", mediaType: "image/jpeg" } });
    expect(result.findings.filter((finding) => finding.id === "IMG-010")).toHaveLength(1);
    expect(result.verdict).toBe("review");
    expect(JSON.stringify(result)).not.toContain("/private/uploads");
    expect(JSON.stringify(result)).not.toContain("photo.jpg");
  });

  it("passes recognized matching type hints", async () => {
    const result = await scanImage(validPng, { hints: { filename: "photo.PNG", mediaType: "image/png; charset=binary" } });
    expect(result.controls.hints?.status).toBe("passed");
    expect(result.findings.some((finding) => finding.id === "IMG-010")).toBe(false);
  });

  it("reports unknown type hints as unsupported when the policy requires comparison", async () => {
    const result = await scanImage(validPng, { hints: { filename: "photo.custom" }, requiredControls: ["structural", "hints"] });
    expect(result.controls.hints?.status).toBe("unsupported");
    expect(result.verdict).toBe("review");
  });
});
