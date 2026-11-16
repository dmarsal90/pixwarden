import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanImage } from "../dist/index.js";

const manifest = JSON.parse(readFileSync(new URL("../spec/corpus/v1/manifest.json", import.meta.url), "utf8"));
const seedIds = [
  "STR-GIF-VALID-001",
  "STR-PNG-VALID-001",
  "STR-WEBP-VALID-001",
  "STR-WEBP-EXTENDED-VALID-001",
  "STR-JPEG-VALID-001",
  "META-PNG-EXIF-GPS-TAG-001"
];
const vectors = new Map(manifest.vectors.map((vector) => [vector.id, vector]));
const mutations = [];

for (const id of seedIds) {
  const vector = vectors.get(id);
  if (!vector) throw new Error(`Missing differential seed vector: ${id}`);
  const input = Buffer.from(vector.inputHex, "hex");
  for (let offset = 0; offset < input.length; offset++) {
    for (const bit of [1, 2, 4, 8, 16, 32, 64, 128]) {
      const changed = Buffer.from(input);
      changed[offset] ^= bit;
      mutations.push({ seed: id, offset, bit, hex: changed.toString("hex") });
    }
  }
}

const php = spawnSync("php", [fileURLToPath(new URL("./differential-mutation-worker.php", import.meta.url))], {
  input: `${mutations.map(({ hex }) => hex).join("\n")}\n`,
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
  timeout: Number(process.env.PIXWARDEN_DIFFERENTIAL_TIMEOUT_MS ?? 300_000)
});
if (php.error) throw php.error;
if (php.status !== 0) throw new Error(`PHP differential worker failed: ${php.stderr}`);

const phpResults = php.stdout.trim().split("\n").map((line) => JSON.parse(line));
if (phpResults.length !== mutations.length) {
  throw new Error(`PHP returned ${phpResults.length} results for ${mutations.length} mutations.`);
}

const mismatches = [];
for (let index = 0; index < mutations.length; index++) {
  const mutation = mutations[index];
  const phpResult = phpResults[index];
  if (phpResult.error) throw new Error(`PHP scanner threw on ${mutation.seed} at byte ${mutation.offset}.`);
  let result;
  try {
    result = await scanImage(Buffer.from(mutation.hex, "hex"));
  } catch (error) {
    throw new Error(`JS scanner threw on ${mutation.seed} at byte ${mutation.offset}: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  const ids = [...new Set(result.findings.map((finding) => finding.id))].sort();
  const jsResult = { format: result.format, validity: result.validity, verdict: result.verdict, findingIds: ids };
  if (JSON.stringify(jsResult) !== JSON.stringify(phpResult)) {
    mismatches.push({ seed: mutation.seed, offset: mutation.offset, bit: mutation.bit, js: jsResult, php: phpResult });
  }
}

if (mismatches.length > 0) {
  throw new Error(`JS/PHP differed on ${mismatches.length}/${mutations.length} single-bit mutations: ${JSON.stringify(mismatches.slice(0, 5))}`);
}
console.log(`JS/PHP differential mutation smoke passed: ${mutations.length} cases, ${seedIds.length} format/metadata seeds.`);
