# Pixwarden JS

Pixwarden is an image security library. This initial package release provides bounded, read-only structural inspection for JPEG, PNG, GIF and WebP, a static SVG inspection/sanitization profile, and embedded-signature indicators scoped to format-defined metadata/extension regions and container trailers. Compressed raster payloads are excluded from signature scanning to reduce incidental matches. These indicators are not malware verdicts. Raster formats are not decoded or sanitized.

## Status

This package is an early implementation. Structural checks cover selected container and marker invariants and are not a full conformance validator. SVG uses a namespace-aware XML parser and a conservative static allowlist; unsupported nodes/attributes are removed by `sanitizeSvg`, DTDs and processing instructions are rejected, and this is not a general SVG renderer. Unknown formats produce an incomplete scan and `review` by default. No result means “safe” or “free of threats.”

## API

```ts
import { scanImage, scanImageIsolated } from "pixwarden-js";

const result = await scanImage(imageBytes, {
  hints: { filename: "upload.png", mediaType: "image/png" },
  limits: { maxBytes: 10 * 1024 * 1024, maxPixels: 40_000_000 },
  binaryInspection: true
});

// Use a killable worker when parsing attacker-controlled input.
const isolatedResult = await scanImageIsolated(imageBytes, {
  hints: { filename: "upload.png", mediaType: "image/png" },
  limits: { maxBytes: 10 * 1024 * 1024, maxPixels: 40_000_000 },
  binaryInspection: true
}, {
  timeoutMs: 10_000,
  maxOldGenerationSizeMb: 64
});

console.log(result.verdict, result.findings, result.controls);
console.log(result.binaryInspection?.bytesScanned, result.binaryInspection?.trailingData);
console.log(isolatedResult.capabilities.hardLimits);
```

`scanImageIsolated` terminates its worker on timeout or cancellation and applies a V8 old-generation heap ceiling. It is still a worker thread in the same process: this does not enforce an OS CPU quota or total RSS limit. Use a container or child process for hostile decoders and stronger isolation.

Hints are untrusted and are compared with the byte-derived format. Pixwarden does not store the supplied filename or media type in the report.

Input to `scanImage` and `scanImageIsolated` must be a `Uint8Array` or Node.js `Buffer`. `scanImageStream` accepts an `AsyncIterable<Uint8Array>`, copies each yielded chunk, and stops reading once the byte cap is exceeded. The stream is buffered up to that cap before inspection; memory/RSS and stalled-source timeouts are not enforced. `sanitizeSvg` handles only the documented static allowlist; there is no raster decoder/sanitizer, OCR, steganography detection, remote fetching, or telemetry. `AbortSignal` cancels pending stream reads and requests iterator cleanup, but the source must cooperate to stop its own work; it cannot interrupt synchronous parsing. Byte, dimension, and frame thresholds are checked before any decoder (none is invoked). `scanImage` has no hard CPU, memory, or wall-clock limits. `scanImageIsolated` adds worker timeout and V8 heap controls, but does not provide OS quotas or RSS isolation. Limits may be tightened but not raised above built-in maxima.

See [the product requirements](docs/01-PRD.md), [technical design](docs/02-TRD.md), [format matrix](docs/security/02-Format-Security-Matrix.md), [coverage limits](docs/security/04-Detection-Mitigation-Coverage.md), and [security policy](SECURITY.md).
