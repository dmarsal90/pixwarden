<?php

declare(strict_types=1);

namespace Pixwarden;

final readonly class ScanOptions
{
    public ResourceLimits $limits;
    public ?ScanHints $hints;
    public AiInspectionOptions $aiInspection;
    public SteganographyOptions $steganography;
    /** @var list<string> */
    public array $requiredControls;
    public string $unsupportedFormat;
    public string $incompleteAnalysis;

    /** @param list<string> $requiredControls */
    public function __construct(
        ?ResourceLimits $limits = null,
        ?ScanHints $hints = null,
        array $requiredControls = ['structural'],
        string $unsupportedFormat = 'review',
        string $incompleteAnalysis = 'review',
        ?AiInspectionOptions $aiInspection = null,
        ?SteganographyOptions $steganography = null,
    ) {
        $this->limits = $limits ?? new ResourceLimits();
        $this->hints = $hints;
        $this->aiInspection = $aiInspection ?? new AiInspectionOptions();
        $this->steganography = $steganography ?? new SteganographyOptions();
        $knownControls = ['hints', 'structural', 'metadata', 'binary', 'decode', 'sanitization', 'steganography', 'aiInspection'];
        if ($requiredControls === [] || array_diff($requiredControls, $knownControls) !== []) {
            throw new InvalidScanOptionsException('Required controls must be a non-empty list of known control identifiers.');
        }
        if (!in_array($unsupportedFormat, ['review', 'reject'], true)) {
            throw new InvalidScanOptionsException('Unsupported-format action must be review or reject.');
        }
        if (!in_array($incompleteAnalysis, ['review', 'reject'], true)) {
            throw new InvalidScanOptionsException('Incomplete-analysis action must be review or reject.');
        }
        if ($aiInspection?->enabled === true) {
            $requiredControls[] = 'aiInspection';
        }
        if ($steganography?->enabled === true) {
            $requiredControls[] = 'steganography';
        }
        $this->requiredControls = array_values(array_unique($requiredControls));
        $this->unsupportedFormat = $unsupportedFormat;
        $this->incompleteAnalysis = $incompleteAnalysis;
    }
}
