import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";

const outputDirectory = process.argv[2];
if (!outputDirectory) throw new Error("Provide an output directory for the temporary fuzz corpus.");

const manifestPath = new URL("../spec/corpus/v1/manifest.json", import.meta.url);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const resolvedOutput = resolve(outputDirectory);
await mkdir(resolvedOutput, { recursive: true });

for (const vector of manifest.vectors) {
  if (!/^[A-Z0-9-]{1,96}$/.test(vector.id) || typeof vector.inputHex !== "string" || vector.inputHex.length % 2 !== 0) {
    throw new Error("Shared corpus contains an invalid fuzz seed entry.");
  }
  const bytes = Buffer.from(vector.inputHex, "hex");
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== vector.sha256) throw new Error(`Shared corpus hash mismatch for ${vector.id}.`);
  await writeFile(join(resolvedOutput, `${vector.id}.bin`), bytes, { flag: "wx" });
}
