# Pixwarden JS

Pixwarden is an image security library. This initial package release provides bounded, read-only structural inspection for JPEG, PNG, GIF and WebP plus simple embedded-signature indicators. It does not decode or sanitize images.

## Status

This package is an early implementation. Structural checks cover selected container and marker invariants and are not a full conformance validator. SVG is recognized as unsupported because no hardened XML parser/sanitizer has been selected. Unknown formats produce an incomplete scan and `review` by default. No result means “safe” or “free of threats.”

## API

```ts
import { scanImage } from "pixwarden-js";

const result = await scanImage(imageBytes, {
  limits: { maxBytes: 10 * 1024 * 1024, maxPixels: 40_000_000 },
  binaryInspection: true
});

console.log(result.verdict, result.findings, result.controls);
```

Input must be a `Uint8Array` or Node.js `Buffer`. The current implementation has no stream API, decoder, sanitizer, OCR, steganography detection, remote fetching, or telemetry. It takes a bounded snapshot before inspection so the reported analysis refers to stable bytes. `AbortSignal` can cancel before synchronous inspection starts; it cannot interrupt parsing after that point. Byte, dimension, and frame thresholds are checked before any decoder (none is invoked). CPU, memory, and wall-clock limits are not enforced in process; run hostile workloads inside a killable worker/container. Limits may be tightened but not raised above built-in maxima.

See [the product requirements](docs/01-PRD.md), [technical design](docs/02-TRD.md), [format matrix](docs/security/02-Format-Security-Matrix.md), [coverage limits](docs/security/04-Detection-Mitigation-Coverage.md), and [security policy](SECURITY.md).
