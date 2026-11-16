import { readFile } from "node:fs/promises";
import { cpus, totalmem } from "node:os";
import { performance } from "node:perf_hooks";
import { ENGINE_VERSION, scanImage } from "../dist/index.js";

const iterations = Number(process.env.PIXWARDEN_BENCH_ITERATIONS ?? 500);
if (!Number.isSafeInteger(iterations) || iterations < 10 || iterations > 100_000) {
  throw new Error("PIXWARDEN_BENCH_ITERATIONS must be an integer from 10 to 100000.");
}

const manifest = JSON.parse(await readFile(new URL("../spec/corpus/v1/manifest.json", import.meta.url), "utf8"));
const ids = ["STR-PNG-VALID-001", "STR-GIF-VALID-001", "STR-JPEG-VALID-001", "STR-WEBP-VALID-001"];
const cases = ids.map((id) => {
  const vector = manifest.vectors.find((item) => item.id === id);
  if (!vector) throw new Error(`Benchmark vector ${id} is missing from corpus ${manifest.corpusVersion}.`);
  return { id, bytes: Buffer.from(vector.inputHex, "hex") };
});

function pngChunk(kind, payload) {
  const type = Buffer.from(kind, "ascii");
  const crcInput = Buffer.concat([type, payload]);
  let crc = 0xffff_ffff;
  for (const byte of crcInput) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb8_8320 : 0);
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE((crc ^ 0xffff_ffff) >>> 0);
  return Buffer.concat([header, crcInput, checksum]);
}

const basePng = cases.find((item) => item.id === "STR-PNG-VALID-001").bytes;
const largeText = Buffer.alloc(1024 * 1024, 0x61);
cases.push({
  id: "BENCH-PNG-1M-ANCILLARY",
  bytes: Buffer.concat([basePng.subarray(0, 33), pngChunk("tEXt", largeText), basePng.subarray(33)])
});
const baseJpeg = cases.find((item) => item.id === "STR-JPEG-VALID-001").bytes;
const jpegComments = [];
for (let index = 0; index < 16; index++) {
  const marker = Buffer.alloc(4);
  marker.set([0xff, 0xfe]);
  marker.writeUInt16BE(65_535, 2);
  jpegComments.push(marker, Buffer.alloc(65_533, 0x61));
}
cases.push({ id: "BENCH-JPEG-1M-COMMENT", bytes: Buffer.concat([baseJpeg.subarray(0, 2), ...jpegComments, baseJpeg.subarray(2)]) });

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

const results = [];
for (const item of cases) {
  const caseIterations = item.bytes.byteLength >= 100_000 ? Math.max(10, Math.floor(iterations / 5)) : iterations;
  for (let i = 0; i < 20; i++) await scanImage(item.bytes);
  const samples = [];
  const rssBefore = process.memoryUsage().rss;
  for (let i = 0; i < caseIterations; i++) {
    const started = performance.now();
    await scanImage(item.bytes);
    samples.push(performance.now() - started);
  }
  const rssAfter = process.memoryUsage().rss;
  samples.sort((a, b) => a - b);
  const meanMs = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  results.push({
    id: item.id,
    inputBytes: item.bytes.byteLength,
    iterations: caseIterations,
    medianMs: Number(percentile(samples, 0.5).toFixed(3)),
    p95Ms: Number(percentile(samples, 0.95).toFixed(3)),
    meanScansPerSecond: Number((1000 / meanMs).toFixed(1)),
    rssDeltaBytes: rssAfter - rssBefore
  });
}

console.log(JSON.stringify({
  benchmarkVersion: 1,
  engineVersion: ENGINE_VERSION,
  corpusVersion: manifest.corpusVersion,
  runtime: process.version,
  v8: process.versions.v8,
  platform: `${process.platform}-${process.arch}`,
  cpu: cpus()[0]?.model ?? "unknown",
  totalMemoryBytes: totalmem(),
  warmupScansPerCase: 20,
  results,
  note: "Synthetic shared-corpus microbenchmark; RSS delta is process-wide and not an allocation or peak-memory guarantee."
}, null, 2));
