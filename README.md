# Pixwarden

Read the [documentation index](docs/README.md) for getting started, API details, format support, security policies, and explicit limitations.

This repository currently contains the `pixwarden-js` implementation and a native PHP package under [`php/`](php/). Shared contracts and versioned synthetic conformance fixtures live under [`spec/`](spec/).

## PHP package status

The initial Composer package in [`php/README.md`](php/README.md) is independent of Node.js and passes the shared v1 vectors. It has limited structural profiles, partial EXIF directory inspection, region-scoped signature indicators, a DOM-based static SVG sanitizer, a limited PNG metadata transform, and a restricted RGBA8 PNG raster transform; it does not yet have feature parity with JS. General raster formats, calibrated steganography detection, OCR, and enforceable process isolation remain unsupported. Optional static PNG RGBA8 statistics are descriptive only and cannot pass the steganography policy control. An opt-in local AI text rule checks a narrow set of PNG tEXt, zTXt and iTXt instruction-override phrases within the configured metadata budget; compressed text requires PHP `ext-zlib`. It does not inspect pixels or call a model. Do not interpret its `allow` verdict as a complete security assessment; its coverage remains `partial`.

Pixwarden is an image security library. This initial package release provides bounded, read-only structural inspection for JPEG, PNG, GIF and WebP, selective EXIF TIFF directory checks, a static SVG inspection/sanitization profile, and embedded-signature indicators scoped to format-defined metadata/extension regions and container trailers. Compressed raster payloads are excluded from signature scanning to reduce incidental matches. These indicators are not malware verdicts. A separate sanitizer reconstructs only static non-interlaced 8-bit RGBA PNGs up to one million pixels; it is not invoked by scans and is not a general raster decoder.

## Status

This package is an early implementation. Structural checks cover selected container and marker invariants and are not a full conformance validator. SVG uses a namespace-aware XML parser and a conservative static allowlist; unsupported nodes/attributes are removed by `sanitizeSvg`, DTDs and processing instructions are rejected, and this is not a general SVG renderer. `stripPngExifAndTextMetadata` removes only PNG `eXIf`, `tEXt`, `zTXt` and `iTXt` chunks without decoding pixels. It preserves ICC profiles and unknown ancillary chunks, so it is a limited privacy transform, not raster canonicalization. Unknown formats produce an incomplete scan and `review` by default. No result means “safe” or “free of threats.”

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
console.log(result.metadataInspection?.status, result.metadataInspection?.entriesInspected);
console.log(isolatedResult.capabilities.hardLimits);
```

`scanImageIsolated` terminates its worker on timeout or cancellation and applies a V8 old-generation heap ceiling. It is still a worker thread in the same process: this does not enforce an OS CPU quota or total RSS limit. Use a container or child process for hostile decoders and stronger isolation.

Hints are untrusted and are compared with the byte-derived format. Pixwarden does not store the supplied filename or media type in the report.

Input to `scanImage` and `scanImageIsolated` must be a `Uint8Array` or Node.js `Buffer`. `scanImageStream` accepts an `AsyncIterable<Uint8Array>`, copies each yielded chunk, and stops reading once the byte cap is exceeded. The stream is buffered up to that cap before inspection; memory/RSS and stalled-source timeouts are not enforced. `sanitizeSvg` handles only the documented static allowlist; `stripPngExifAndTextMetadata` removes only the PNG chunk types stated above; `sanitizePngRgba8` decodes/reconstructs only static, non-interlaced 8-bit RGBA PNGs up to one million pixels. That transform removes ancillary chunks and color profiles, so visual appearance may change; it does not remove pixel-level hidden data. The current metadata guard checks bounded EXIF TIFF directories and reports selected sensitive tag identifiers without extracting values. XMP and text metadata are not parsed during scan except when the opt-in AI text rule is enabled. No general raster decoder/re-encoder, OCR, calibrated steganography detection, remote fetching, or telemetry is bundled. Optional static PNG RGBA8 channel statistics remain inconclusive and do not identify hidden data. An opt-in local rule set checks PNG tEXt, zTXt and iTXt metadata for a narrow set of instruction-override phrases, subject to the configured metadata output bound; it does not inspect pixels or other formats. `AbortSignal` cancels pending stream reads and requests iterator cleanup, but the source must cooperate to stop its own work; it cannot interrupt synchronous parsing. Byte, dimension, and frame thresholds are checked before any decoder (none is invoked by scans). `scanImage` has no hard CPU, memory, or wall-clock limits. `scanImageIsolated` adds worker timeout and V8 heap controls, but does not provide OS quotas or RSS isolation. Limits may be tightened but not raised above built-in maxima.

See [the product requirements](docs/01-PRD.md), [technical design](docs/02-TRD.md), [format matrix](docs/security/02-Format-Security-Matrix.md), [coverage limits](docs/security/04-Detection-Mitigation-Coverage.md), and [security policy](SECURITY.md).

## Parser fuzzing

The development-only Jazzer.js target uses the hash-checked synthetic fixtures. To replay the seed corpus locally:

```sh
fuzz_corpus="$(mktemp -d)"
node scripts/prepare-fuzz-corpus.mjs "$fuzz_corpus"
npx jazzer fuzz/scan-image.mjs "$fuzz_corpus" --timeout=1000 --mode=regression
```

The scheduled workflow runs coverage-guided fuzzing for 90 seconds and uploads the evolving corpus and crash artifacts. This in-process target is not an OS CPU or memory boundary and covers the byte-level JS parser only.
