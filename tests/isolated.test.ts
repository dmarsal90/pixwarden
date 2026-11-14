import { describe, expect, it } from "vitest";
import { scanImageIsolated } from "../dist/index.js";

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

const png = new Uint8Array([
  137, 80, 78, 71, 13, 10, 26, 10,
  ...pngChunk("IHDR", [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
  ...pngChunk("IDAT", [0]),
  ...pngChunk("IEND", [])
]);

describe("isolated worker scans", () => {
  it("returns a normal report and marks only the wall-clock limit as enforced", async () => {
    const result = await scanImageIsolated(png);
    expect(result.format).toBe("png");
    expect(result.capabilities.hardLimits.wallTime).toBe(true);
    expect(result.capabilities.hardLimits.memory).toBe(false);
    expect(result.capabilities.hardLimits.cpu).toBe(false);
  });

  it("terminates a worker when the caller aborts", async () => {
    const controller = new AbortController();
    const pending = scanImageIsolated(png, { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("rejects invalid worker resource settings before starting a worker", async () => {
    await expect(scanImageIsolated(png, {}, { timeoutMs: 1 })).rejects.toMatchObject({ code: "INVALID_OPTIONS" });
    await expect(scanImageIsolated(png, {}, { maxOldGenerationSizeMb: 8 })).rejects.toMatchObject({ code: "INVALID_OPTIONS" });
  });
});
