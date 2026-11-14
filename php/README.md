# Pixwarden PHP

Native PHP 8.2+ package (`dmarsal90/pixwarden-php`) with no Node.js runtime dependency and no network access. This initial package stage implements a conservative bounded byte-level profile for the shared v1 corpus; it is **not yet functionally equivalent** to Pixwarden JS.

## Status and limits

The current `Scanner::scan(string $bytes)` accepts already-buffered bytes; `scanStream($resource)` reads from the stream's current position and bounds buffering to the configured byte limit plus at most one overflow byte. The scanner does not rewind or close the caller-owned stream. Configure timeouts on blocking streams at the call site; this API does not enforce a wall-clock read timeout. Both methods enforce byte, metadata, dimension, pixel, and selected frame limits and return a typed `ScanResult` that serializes to the shared JSON report. It checks bounded EXIF TIFF directory structure and selected privacy-sensitive tag identifiers for JPEG, PNG, and WebP without extracting values. Binary signature indicators scan only format-defined metadata, extension, and trailer regions for JPEG, PNG, GIF, and WebP; they do not scan pixel bitstreams or prove complete embedded files. When PHP `ext-dom` is available, SVG uses a bounded DOM parser and a static allowlist sanitizer exposed separately as `Scanner::sanitizeSvg()`. `ScanOptions` accepts optional `ScanHints` to compare filename/media-type declarations against the byte-derived format; raw hint values are not included in the report. `Scanner::stripPngExifAndTextMetadata()` removes only PNG `eXIf`, `tEXt`, `zTXt` and `iTXt` chunks without decoding pixels. `Scanner::sanitizePngRgba8()` decodes/reconstructs static non-interlaced 8-bit RGBA PNGs up to one million pixels and requires `ext-zlib`; it removes ancillary chunks and color profiles, which may change appearance, and does not remove pixel-level hidden data. General raster decoding, steganography, OCR, and AI inspection are not implemented. Its container checks are intentionally narrow; `valid` means only that this PHP profile accepted its limited checks. Every report has partial coverage.

```php
use Pixwarden\ResourceLimits;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;

$result = (new Scanner())->scan($imageBytes);
if ($result->verdict === \Pixwarden\Verdict::Allow && $result->coverage === 'complete') {
    // This initial package never returns complete coverage.
}

$bounded = (new Scanner())->scan($imageBytes, new ScanOptions(
    limits: new ResourceLimits(maxBytes: 10_485_760, maxWidth: 40_000, maxPixels: 40_000_000, maxFrames: 200),
));
echo json_encode($bounded, JSON_THROW_ON_ERROR); // serializes to the shared report contract

$stream = fopen($path, 'rb');
try {
    $streamResult = (new Scanner())->scanStream($stream, new ScanOptions());
} finally {
    fclose($stream); // the scanner leaves caller-owned streams open
}
```

`sanitizeSvg()` returns a JSON-compatible result array containing the sanitized bytes and post-check status. It is available only when PHP `ext-dom` is installed.

Install with Composer once the package is released: `composer require dmarsal90/pixwarden-php`. The public registry currently returns no package record; account namespace ownership has not been checked and no release has been published.

## Development

From this directory run `composer install`, `composer test`, `composer analyse`, and `composer audit`. Shared vectors are loaded from `../spec/corpus/v1/manifest.json`, hash-checked, and every emitted report is validated against the shared Draft 2020-12 `ScanResult` contract. `opis/json-schema` and `nikic/php-fuzzer` are development-only dependencies; neither is required by applications using Pixwarden PHP. The weekly/manual PHP fuzz workflow runs the shared corpus and bounded mutations, and re-sanitizes SVG outputs to check idempotence; see [the corpus notes](../docs/security/03-Security-Test-Corpus.md).
