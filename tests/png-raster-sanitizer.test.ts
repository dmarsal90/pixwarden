import { readFileSync } from "node:fs";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { PixwardenError, sanitizePngRgba8, scanImage } from "../src/index.js";

describe("PNG RGBA8 raster sanitizer", () => {
  it("reconstructs pixels, removes ancillary chunks, and handles every PNG filter", async () => {
    const manifest = JSON.parse(readFileSync(new URL("../spec/corpus/v1/manifest.json", import.meta.url), "utf8"));
    for (const id of ["SAN-PNG-RGBA8-RECONSTRUCT-001", "SAN-PNG-RGBA8-FILTERS-001"]) {
      const vector = manifest.vectors.find((item: { id: string }) => item.id === id);
      expect(vector).toBeDefined();
      const input = Buffer.from(vector.inputHex, "hex");
      const snapshot = Buffer.from(input);
      const result = sanitizePngRgba8(input);
      expect(input).toEqual(snapshot);
      expect(result.width).toBe(vector.transform.width);
      expect(result.height).toBe(vector.transform.height);
      expect(result.removedChunks).toEqual(vector.transform.removedChunks);
      expect(result.postCheckStatus).toBe(vector.transform.postCheckStatus);

      const types: string[] = [];
      const idat: Buffer[] = [];
      let offset = 8;
      while (offset < result.bytes.byteLength) {
        const output = Buffer.from(result.bytes);
        const length = output.readUInt32BE(offset);
        const type = output.toString("ascii", offset + 4, offset + 8);
        types.push(type);
        if (type === "IDAT") idat.push(Buffer.from(result.bytes.subarray(offset + 8, offset + 8 + length)));
        offset += 12 + length;
      }
      expect(types).toEqual(vector.transform.outputChunkTypes);
      const scanline = inflateSync(Buffer.concat(idat));
      const pixelBytes = Buffer.concat(Array.from({ length: vector.transform.height }, (_, row) => scanline.subarray(row * (vector.transform.width * 4 + 1) + 1, (row + 1) * (vector.transform.width * 4 + 1))));
      expect(pixelBytes.toString("hex")).toBe(vector.transform.rgbaHex);
      expect((await scanImage(result.bytes)).validity).toBe("valid");
    }
  });

  it("rejects trailing zlib bytes and output beyond the expected scanline bound", async () => {
    const manifest = JSON.parse(readFileSync(new URL("../spec/corpus/v1/manifest.json", import.meta.url), "utf8"));
    for (const id of ["SAN-PNG-RGBA8-ZLIB-TRAILING-001", "SAN-PNG-RGBA8-EXPANSION-001"]) {
      const vector = manifest.vectors.find((item: { id: string }) => item.id === id);
      expect(vector).toBeDefined();
      const input = Buffer.from(vector.inputHex, "hex");
      expect((await scanImage(input)).validity).toBe("valid");
      let thrown: unknown;
      try { sanitizePngRgba8(input); } catch (error) { thrown = error; }
      expect(thrown).toBeInstanceOf(PixwardenError);
      expect((thrown as PixwardenError).code).toBe(vector.transform.expectedErrorCode);
    }
  });
});
