# Pixwarden PHP

Native PHP 8.2+ package (`dmarsal90/pixwarden-php`) with no Node.js runtime dependency and no network access. This initial package stage implements a conservative bounded byte-level profile for the shared v1 corpus; it is **not yet functionally equivalent** to Pixwarden JS.

## Status and limits

The current `Scanner::scan(string $bytes)` accepts already-buffered bytes, enforces a maximum input size, and emits a JSON-compatible report. It does not decode images, parse metadata, inspect embedded payloads, handle SVG, sanitize, or claim malware/steganography/AI detection. Its container checks are intentionally narrow; `valid` means only that this PHP profile accepted its limited checks. Every report has partial coverage.

```php
use Pixwarden\Scanner;

$result = (new Scanner())->scan($imageBytes);
if ($result['verdict'] === 'allow' && $result['coverage'] === 'complete') {
    // This initial package never returns complete coverage.
}
```

Install with Composer once the package is released: `composer require dmarsal90/pixwarden-php`. Package-name availability has not been verified; no release has been published.

## Development

From this directory run `composer install`, `composer test`, and `composer analyse`. Shared vectors are loaded from `../spec/corpus/v1/manifest.json` and hash-checked before the scan.
