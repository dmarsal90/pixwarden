import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const execution = spawnSync("npm", ["pack", "--dry-run", "--json"], { cwd: root, encoding: "utf8", timeout: 30_000 });
assert.equal(execution.error, undefined, execution.error?.message);
assert.equal(execution.status, 0, execution.stderr);

const [packageInfo] = JSON.parse(execution.stdout);
assert.equal(packageInfo.name, manifest.name);
assert.equal(packageInfo.version, manifest.version);
const files = new Set(packageInfo.files.map((file) => file.path));
for (const path of ["package.json", "README.md", "LICENSE", "SECURITY.md", "dist/index.js", "dist/index.d.ts", "dist/cjs/index.js", "dist/cjs/package.json"]) {
  assert.ok(files.has(path), `npm archive must contain ${path}`);
}
for (const path of files) {
  assert.ok(!/^(?:tests?|docs|fuzz|php|node_modules)\//.test(path), `npm archive must not contain development or sibling package files: ${path}`);
}

process.stdout.write(`npm archive check passed: ${packageInfo.entryCount} files, ${packageInfo.size} bytes.\n`);
