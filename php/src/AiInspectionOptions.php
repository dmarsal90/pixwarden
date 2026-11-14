<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class AiInspectionOptions
{
    public function __construct(
        public bool $enabled = false,
        public bool $ocr = false,
    ) {
    }
}
