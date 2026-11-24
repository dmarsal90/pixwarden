# API reference

This page documents the currently exported API surface. Generated declarations are authoritative for a particular release.

## JavaScript

- `scanImage(Uint8Array, ScanOptions): Promise<ScanResult>` performs in-process byte inspection.
- `scanImageIsolated(Uint8Array, ScanOptions, ScanIsolationOptions): Promise<ScanResult>` uses a terminable worker with timeout and V8 heap ceiling.
- `scanImageStream(AsyncIterable<Uint8Array>, ScanOptions): Promise<ScanResult>` buffers to the byte cap.
- `sanitizeSvg(Uint8Array): SvgSanitizationResult` applies the SVG static allowlist.
- `stripPngExifAndTextMetadata(Uint8Array): PngMetadataSanitizationResult` removes four PNG metadata chunk types.
- `sanitizePngRgba8(Uint8Array): PngRasterSanitizationResult` reconstructs static non-interlaced 8-bit RGBA PNGs up to one million pixels; it strips ancillary chunks and may alter color appearance.
- `ScanOptions.steganography: { enabled: true, mode: "statistical", maxSamples?: number }` requests bounded descriptive statistics for static PNG RGBA8 pixels (default 100,000 sampled pixels; maximum 1,000,000). The result remains inconclusive and its required policy control remains unsupported.
- `PixwardenError` carries a stable `code` such as `INVALID_OPTIONS`, `INPUT_TOO_LARGE`, `LIMIT_EXCEEDED`, `CANCELLED`, `MALFORMED_INPUT`, `SANITIZATION_FAILURE`, or `IO_FAILURE`.
