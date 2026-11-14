import { createRequire } from "node:module";
import { expect, it } from "vitest";
import type * as Pixwarden from "../src/index.js";

const require = createRequire(import.meta.url);
const commonjs = require("pixwarden-js") as typeof Pixwarden;

it("exposes the scan API through CommonJS", async () => {
  const result = await commonjs.scanImage(Buffer.from("opaque"));
  expect(result.format).toBe("unknown");
  expect(result.verdict).toBe("review");
});

it("runs isolated scans through the CommonJS worker entry", async () => {
  const result = await commonjs.scanImageIsolated(Buffer.from("opaque"));
  expect(result.format).toBe("unknown");
  expect(result.verdict).toBe("review");
});
