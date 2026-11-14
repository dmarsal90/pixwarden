import { parentPort, workerData } from "node:worker_threads";
import { scanImage } from "./index.js";
import { PixwardenError, type ScanOptions } from "./types.js";

interface ScanWorkerData {
  readonly input: Uint8Array;
  readonly options: ScanOptions;
}

const port = parentPort;
if (!port) throw new Error("Pixwarden scan worker requires a parent port.");

const data = workerData as ScanWorkerData;
try {
  const result = await scanImage(data.input, data.options);
  port.postMessage({ ok: true, result });
} catch (error) {
  const code = error instanceof PixwardenError ? error.code : "IO_FAILURE";
  const message = error instanceof Error ? error.message : "Isolated scan failed.";
  port.postMessage({ ok: false, code, message });
}
