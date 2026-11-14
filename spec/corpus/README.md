# Pixwarden shared conformance corpus

The versioned fixtures in `v1/manifest.json` are synthetic, harmless byte sequences authored for Pixwarden. The manifest is the cross-runtime source of truth: implementations must verify each SHA-256 before scanning and compare the reported format, validity, verdict, coverage, and unique finding identifiers with the expected fields.

## Version 1

Corpus version `1.0.37` contains 85 vectors covering unknown and truncated inputs, structural regressions for PNG/GIF/JPEG/WebP, limits, synthetic EXIF and binary indicators, SVG allow/block cases, raster sanitation and steganography examples, and bounded metadata prompt-risk rules. The latest vectors include UTF-16 EXIF `UserComment` override cases in both TIFF byte orders and benign text. “Structurally valid” only means the enabled bounded structural profile accepts the container; it does not claim pixel decoding, full format conformance, or safety. Expected `partial` coverage makes that limitation explicit. EXIF samples contain no private values; signature samples are inert synthetic byte sequences; SVG instructions are never executed.

The fixtures and manifest are CC0-1.0. Each vector records its exact bytes as hex, digest, purpose, and expected outcome. New vectors are additive within a corpus version; changes to existing bytes or expectations require a new major corpus version and migration notes.

Both JS and PHP conformance suites should consume this manifest without copying expected outcomes into runtime-specific tests. Implementations may report additional findings only when the shared contract explicitly allows them; otherwise they must update the corpus and both implementations together.
