# Pixwarden shared conformance corpus

The versioned fixtures in `v1/manifest.json` are synthetic, harmless byte sequences authored for Pixwarden. The manifest is the cross-runtime source of truth: implementations must verify each SHA-256 before scanning and compare the reported format, validity, verdict, coverage, and unique finding identifiers with the expected fields.

## Version 1

Corpus version `1.0.0` currently contains twenty-two vectors: an unknown input, truncated PNG and GIF local color table, invalid PNG IHDR parameters and a PNG CRC mismatch, minimal PNG/GIF/JPEG/WebP containers, an extended WebP container and invalid RIFF padding/reserved flags, synthetic valid/malformed EXIF metadata, harmless signature indicators in defined ancillary regions, safe/active-content SVGs, and dimension/frame limit cases. “Structurally valid” only means the enabled bounded structural profile accepts the container; it does not claim pixel decoding, full format conformance, or safety. Expected `partial` coverage makes that limitation explicit. EXIF samples contain no private values; signature samples are inert synthetic byte sequences; SVG instructions are never executed.

The fixtures and manifest are CC0-1.0. Each vector records its exact bytes as hex, digest, purpose, and expected outcome. New vectors are additive within a corpus version; changes to existing bytes or expectations require a new major corpus version and migration notes.

Both JS and PHP conformance suites should consume this manifest without copying expected outcomes into runtime-specific tests. Implementations may report additional findings only when the shared contract explicitly allows them; otherwise they must update the corpus and both implementations together.
