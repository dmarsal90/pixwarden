import { describe, expect, it } from "vitest";
import { scanImage } from "../src/index.js";

function seededBytes(seed: number, length: number): Uint8Array {
  let state = seed >>> 0 || 1;
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    bytes[index] = state >>> 24;
  }
  return bytes;
}

const formatPrefixes = [
  [137, 80, 78, 71, 13, 10, 26, 10],
  [0xff, 0xd8, 0xff],
  [...new TextEncoder().encode("GIF89a")],
  [...new TextEncoder().encode("RIFF"), 0, 0, 0, 0, ...new TextEncoder().encode("WEBP")],
  [...new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg">')]
] as const;

// Minimized by Jazzer.js 4.0.0 from the shared valid GIF seed on 2026-11-14.
// The descriptor advertises a local color table that is absent from the input.
const truncatedGifLocalColorTable = Buffer.from("R0lGODlhAQABAAAAACwAAAAAAQABAPo=", "base64");

describe("bounded parser fuzz smoke corpus", () => {
  it("bounds the evidence for a truncated GIF local color table", async () => {
    const result = await scanImage(truncatedGifLocalColorTable);
    const finding = result.findings.find((item) => item.id === "IMG-003");

    expect(result.format).toBe("gif");
    expect(finding).toBeDefined();
    expect(finding!.evidence[0]!.offset).toBe(truncatedGifLocalColorTable.byteLength);
  });

  it("keeps evidence ranges inside deterministic malformed inputs", async () => {
    for (let seed = 1; seed <= 24; seed++) {
      const tail = seededBytes(seed * 0x9e3779b1, (seed * 37) % 513);
      const inputs = [
        tail,
        ...formatPrefixes.map((prefix) => new Uint8Array([...prefix, ...tail]))
      ];

      for (const input of inputs) {
        const result = await scanImage(input);
        expect(result.inputBytes).toBe(input.byteLength);
        expect(result.findings.length).toBeLessThanOrEqual(input.byteLength + 16);
        for (const finding of result.findings) {
          for (const evidence of finding.evidence) {
            if (evidence.offset !== undefined) expect(evidence.offset).toBeLessThanOrEqual(input.byteLength);
            if (evidence.length !== undefined) {
              expect(evidence.offset).toBeDefined();
              expect(evidence.offset! + evidence.length).toBeLessThanOrEqual(input.byteLength);
            }
          }
        }
      }
    }
  });
});
