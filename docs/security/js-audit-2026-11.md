# JavaScript security and verification record

**Review date:** 2026-11-16  
**Scope:** JS byte inspectors, metadata inspection, sanitizer entry points, package checks, shared corpus/fuzz paths. This is an implementation audit record, not independent certification.

## Checks completed

| Check | Result |
|---|---|
| `npm test` | 158 tests passed after the WebP evidence-bound fix, CRC table change, adapter validation, strict configuration validation, and required-control coverage fix |
| `npm run typecheck` | Passed |
| `npm run test:differential` | 2,184 single-bit mutations across six seeds matched between JS and PHP (historical: run before the PHP package moved to its own repository; that harness was removed because each repository must be self-contained) |
| Jazzer.js, shared corpus v1.0.39 | 79,286 executions in 11 seconds; no failure after regression fix |
| `npm audit --audit-level=high` | Zero vulnerabilities reported |
| `npm run check:package` | Passed; 59 files, 68,348 bytes in the dry-run archive |
| `npm run benchmark` | Completed; see [the JS performance baseline](../performance-js.md) |

The checks requiring child-process execution or registry access were run outside the restricted sandbox. The local PHP suite, PHPStan, formatting check, and strict Composer validation passed after the shared regression was added.

## Finding fixed

Coverage-guided fuzzing found that a one-byte WebP `EXIF` chunk followed by bytes beginning with `Exif\0\0` could make both metadata parsers advance the TIFF start beyond the chunk end. The result contained a negative evidence length. The JS and PHP parsers now recognize that optional prefix only when all six bytes fit inside the chunk. Corpus vector `META-WEBP-SHORT-EXIF-CHUNK-001` and both runtime suites retain the regression.

## Residual risks

- Fuzzing is in-process and does not establish OS CPU/RSS isolation.
- The performance run uses synthetic data and does not establish production capacity or a memory ceiling.
- General raster decoding, calibrated steganography detection, OCR/VLM, full metadata extraction, and downstream renderer equivalence remain unsupported.
- The benchmark reports process RSS before/after sample loops, not peak memory.
- Native decoders are not invoked by scan; any future decoder or OCR engine needs its own versioned threat review, isolation design and held-out evaluation data.
