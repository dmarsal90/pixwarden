<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class ResourceLimits
{
    public function __construct(
        public int $maxBytes = 10_485_760,
        public int $maxMetadataBytes = 1_048_576,
        public int $maxWidth = 40_000,
        public int $maxHeight = 40_000,
        public int $maxPixels = 40_000_000,
        public int $maxFrames = 200,
    ) {
        $maxima = [
            'maxBytes' => [10_485_760, $maxBytes],
            'maxMetadataBytes' => [1_048_576, $maxMetadataBytes],
            'maxWidth' => [40_000, $maxWidth],
            'maxHeight' => [40_000, $maxHeight],
            'maxPixels' => [40_000_000, $maxPixels],
            'maxFrames' => [200, $maxFrames],
        ];
        foreach ($maxima as $name => [$maximum, $value]) {
            if ($value < 1 || $value > $maximum) {
                throw new InvalidScanOptionsException($name . ' must be positive and cannot exceed ' . $maximum . '.');
            }
        }
    }

    /** @return array<string, int> */
    public function toArray(): array
    {
        return [
            'maxBytes' => $this->maxBytes,
            'maxMetadataBytes' => $this->maxMetadataBytes,
            'maxWidth' => $this->maxWidth,
            'maxHeight' => $this->maxHeight,
            'maxPixels' => $this->maxPixels,
            'maxFrames' => $this->maxFrames,
        ];
    }
}
