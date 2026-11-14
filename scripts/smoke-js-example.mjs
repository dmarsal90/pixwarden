import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = JSON.parse(await readFile(join(root, "spec/corpus/v1/manifest.json"), "utf8"));
const vector = manifest.vectors.find((candidate) => candidate.id === "STEG-PNG-RGBA8-STATISTICS-001");
assert.ok(vector, "shared one-pixel PNG example fixture must exist");
const bytes = Buffer.from(vector.inputHex, "hex");
assert.equal(createHash("sha256").update(bytes).digest("hex"), vector.sha256);

const directory = await mkdtemp(join(tmpdir(), "pixwarden-js-example-"));
try {
  const imagePath = join(directory, "sample.png");
  await writeFile(imagePath, bytes, { flag: "wx", mode: 0o600 });
  const execution = spawnSync(process.execPath, ["examples/js/scan-file.mjs", imagePath], { cwd: root, encoding: "utf8", timeout: 15_000 });
  assert.equal(execution.error, undefined, execution.error?.message);
  assert.equal(execution.status, 0, execution.stderr);
  const report = JSON.parse(execution.stdout);
  assert.equal(report.format, "png");
  assert.equal(report.verdict, "allow");
  assert.equal(report.coverage, "partial");
  assert.match(execution.stderr, /keep the upload quarantined for review/i);
} finally {
  await rm(directory, { recursive: true, force: true });
}

process.stdout.write("Node file-ingress example runs and retains partial-coverage input.\n");
