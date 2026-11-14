# Pixwarden JS

Pixwarden is an image security library. This initial package release provides bounded, read-only structural inspection for JPEG, PNG, GIF and WebP, a static SVG inspection/sanitization profile, and simple embedded-signature indicators. Raster formats are not decoded or sanitized.

## Status

This package is an early implementation. Structural checks cover selected container and marker invariants and are not a full conformance validator. SVG uses a namespace-aware XML parser and a conservative static allowlist; unsupported nodes/attributes are removed by `sanitizeSvg`, DTDs and processing instructions are rejected, and this is not a general SVG renderer. Unknown formats produce an incomplete scan and `review` by default. No result means “safe” or “free of threats.”

## API

```ts
import { scanImage } from "pixwarden-js";

const result = await scanImage(imageBytes, {
  hints: { filename: "upload.png", mediaType: "image/png" },
  limits: { maxBytes: 10 * 1024 * 1024, maxPixels: 40_000_000 },
  binaryInspection: true
});

console.log(result.verdict, result.findings, result.controls);
```

Hints are untrusted and are compared with the byte-derived format. Pixwarden does not store the supplied filename or media type in the report.

Input to `scanImage` must be a `Uint8Array` or Node.js `Buffer`. `scanImageStream` accepts an `AsyncIterable<Uint8Array>`, copies each yielded chunk, and stops reading once the byte cap is exceeded. The stream is buffered up to that cap before inspection; memory/RSS and stalled-source timeouts are not enforced. `sanitizeSvg` handles only the documented static allowlist; there is no raster decoder/sanitizer, OCR, steganography detection, remote fetching, or telemetry. `AbortSignal` is checked before parsing and between stream chunks; it cannot interrupt synchronous parsing or a source blocked while waiting to produce its next chunk. Byte, dimension, and frame thresholds are checked before any decoder (none is invoked). CPU, memory, and wall-clock limits are not enforced in process; run hostile workloads inside a killable worker/container. Limits may be tightened but not raised above built-in maxima.

See [the product requirements](docs/01-PRD.md), [technical design](docs/02-TRD.md), [format matrix](docs/security/02-Format-Security-Matrix.md), [coverage limits](docs/security/04-Detection-Mitigation-Coverage.md), and [security policy](SECURITY.md).
