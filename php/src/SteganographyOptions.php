<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class SteganographyOptions
{
    public function __construct(
        public bool $enabled = false,
        public string $mode = 'statistical',
        public int $maxSamples = 100_000,
    ) {
        if (!in_array($mode, ['statistical', 'targeted'], true)) {
            throw new InvalidScanOptionsException('Steganography mode must be statistical or targeted.');
        }
        if ($maxSamples < 1 || $maxSamples > 1_000_000) {
            throw new InvalidScanOptionsException('Steganography maxSamples must be from 1 to 1000000.');
        }
    }
}
