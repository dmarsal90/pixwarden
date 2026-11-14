<?php

declare(strict_types=1);

namespace Pixwarden;

use JsonSerializable;

/** Typed view of a scan report; serialization preserves the shared JSON contract. */
final readonly class ScanResult implements JsonSerializable
{
    public string $scanId;
    public ImageFormat $format;
    public string $validity;
    public Verdict $verdict;
    public string $coverage;
    /** @var list<array<string, mixed>> */
    public array $findings;
    /** @var array<string, mixed> */
    public array $controls;

    /** @param array<string, mixed> $report */
    private function __construct(private array $report)
    {
        $this->scanId = $report['scanId'];
        $this->format = ImageFormat::from($report['format']);
        $this->validity = $report['validity'];
        $this->verdict = Verdict::from($report['verdict']);
        $this->coverage = $report['coverage'];
        $this->findings = $report['findings'];
        $this->controls = $report['controls'];
    }

    /** @param array<string, mixed> $report */
    public static function fromReport(array $report): self
    {
        return new self($report);
    }

    public function scanId(): string
    {
        return $this->report['scanId'];
    }

    public function validity(): string
    {
        return $this->report['validity'];
    }

    public function coverage(): string
    {
        return $this->report['coverage'];
    }

    /** @return list<array<string, mixed>> */
    public function findings(): array
    {
        return $this->report['findings'];
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->report;
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->report;
    }
}
