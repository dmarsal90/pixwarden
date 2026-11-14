# API reference

This page documents the currently exported API surface. Generated declarations and PHP signatures are authoritative for a particular release.

## JavaScript

- `scanImage(Uint8Array, ScanOptions): Promise<ScanResult>` performs in-process byte inspection.
- `scanImageIsolated(Uint8Array, ScanOptions, ScanIsolationOptions): Promise<ScanResult>` uses a terminable worker with timeout and V8 heap ceiling.
- `scanImageStream(AsyncIterable<Uint8Array>, ScanOptions): Promise<ScanResult>` buffers to the byte cap.
- `sanitizeSvg(Uint8Array): SvgSanitizationResult` applies the SVG static allowlist.
- `stripPngExifAndTextMetadata(Uint8Array): PngMetadataSanitizationResult` removes four PNG metadata chunk types.
- `PixwardenError` carries a stable `code` such as `INVALID_OPTIONS`, `INPUT_TOO_LARGE`, `LIMIT_EXCEEDED`, `CANCELLED`, `MALFORMED_INPUT`, `SANITIZATION_FAILURE`, or `IO_FAILURE`.

## PHP

- `Scanner::scan(string, ?ScanOptions): ScanResult`
- `Scanner::scanStream(mixed, ?ScanOptions): ScanResult`
- `Scanner::sanitizeSvg(string): array` (requires `ext-dom`)
- `Scanner::stripPngExifAndTextMetadata(string): array`

Failures use `PixwardenException` subclasses. PHP options and control parity are narrower than JS at this stage. See source PHPDoc and shared JSON Schema for detailed shapes.
