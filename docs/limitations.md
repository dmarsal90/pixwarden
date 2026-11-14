# Limitations

- Structural profiles cover selected invariants; they are not complete format validators.
- No raster decoding or raster re-encoding is performed.
- No OCR, AI injection detection, or steganography analysis is implemented.
- Binary signatures cover selected regions, are indicator-only, and are not malware scanning.
- JS and PHP feature parity is incomplete; PHP SVG needs `ext-dom` and metadata/binary profiles differ.
- In-process checks do not enforce OS CPU/RSS quotas. JS worker limits do not equal OS isolation; PHP stream timeouts are caller-managed.
- SVG output is a static allowlist serialization, not a renderer, and downstream renderer differences remain.
- PNG metadata stripping removes only `eXIf`, `tEXt`, `zTXt`, `iTXt`; ICC, unknown ancillary data, and pixel content remain.
- Findings can be false positive or false negative. Unsupported, skipped, partial, or error controls cannot be interpreted as passing.
- Deployment controls, native downstream decoder patching, quarantine, auth, storage, and HTTP headers belong to the integrator.
