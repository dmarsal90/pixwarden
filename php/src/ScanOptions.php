<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class ScanOptions
{
    public ResourceLimits $limits;
    public ?ScanHints $hints;

    public function __construct(?ResourceLimits $limits = null, ?ScanHints $hints = null)
    {
        $this->limits = $limits ?? new ResourceLimits();
        $this->hints = $hints;
    }
}
