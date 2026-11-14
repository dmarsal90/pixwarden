#!/usr/bin/env node

import { createReadStream } from "node:fs";
import { scanImageStream } from "pixwarden-js";

const filename = process.argv[2];
if (!filename) {
  process.stderr.write("Usage: node examples/js/scan-file.mjs <image-path>\n");
  process.exitCode = 2;
} else {
  try {
    const result = await scanImageStream(createReadStream(filename), {
      limits: { maxBytes: 10 * 1024 * 1024, maxMetadataBytes: 1024 * 1024, maxPixels: 40_000_000 },
      binaryInspection: true
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.verdict !== "allow" || result.coverage !== "complete" || !result.policyCompliant) {
      process.stderr.write("Pixwarden did not establish complete policy coverage; keep the upload quarantined for review.\n");
    }
  } catch (error) {
    process.stderr.write(`Pixwarden scan failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  }
}
