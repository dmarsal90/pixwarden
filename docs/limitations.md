# Limitations

- Structural profiles cover selected invariants; they are not complete format validators.
- Raster reconstruction exists only for static non-interlaced 8-bit RGBA PNGs up to one million pixels; it has no OS CPU/RSS quota and drops color profiles, which may change appearance. No general raster decoding/re-encoding is provided.
- The optional AI text rule inspects only a narrow set of uncompressed PNG metadata phrases. It does not provide OCR, pixel inspection, general prompt-injection detection, or steganography analysis. Reports return `aiInspection.status: "not_requested"` by default; steganography remains `unsupported`, and requiring it cannot result in `allow`.
- Binary signatures cover selected regions, are indicator-only, and are not malware scanning.
- JS and PHP feature parity is incomplete; PHP SVG needs `ext-dom` and metadata/binary profiles differ.
- In-process checks do not enforce OS CPU/RSS quotas. JS worker limits do not equal OS isolation; PHP stream timeouts are caller-managed.
- SVG output is a static allowlist serialization, not a renderer, and downstream renderer differences remain.
- PNG metadata stripping removes only `eXIf`, `tEXt`, `zTXt`, `iTXt`; ICC, unknown ancillary data, and pixel content remain.
- RGBA8 PNG reconstruction removes ancillary chunks but does not remove pixel-level hidden data or prove safe rendering.
- Findings can be false positive or false negative. Unsupported, skipped, partial, or error controls cannot be interpreted as passing.
- Deployment controls, native downstream decoder patching, quarantine, auth, storage, and HTTP headers belong to the integrator.
