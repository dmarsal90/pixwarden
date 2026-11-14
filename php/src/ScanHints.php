<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class ScanHints
{
    public function __construct(public ?string $filename = null, public ?string $mediaType = null)
    {
        if ($filename === null && $mediaType === null) {
            throw new InvalidScanOptionsException('At least one filename or media-type hint is required.');
        }
        if ($filename !== null && (strlen($filename) > 255 || preg_match('/[\x00-\x1f\x7f]/', $filename) === 1)) {
            throw new InvalidScanOptionsException('Filename hint must be a short string without control characters.');
        }
        if ($mediaType !== null && (strlen($mediaType) > 127 || preg_match('/[\x00-\x1f\x7f]/', $mediaType) === 1)) {
            throw new InvalidScanOptionsException('Media-type hint must be a short string without control characters.');
        }
    }
}
