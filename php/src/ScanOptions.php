<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class ScanOptions
{
    public ResourceLimits $limits;

    public function __construct(?ResourceLimits $limits = null)
    {
        $this->limits = $limits ?? new ResourceLimits();
    }
}
