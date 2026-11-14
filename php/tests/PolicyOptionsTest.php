<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\InvalidScanOptionsException;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;
use PHPUnit\Framework\TestCase;

final class PolicyOptionsTest extends TestCase
{
    public function testUnsupportedFormatCanBeRejectedByRequiredStructuralControl(): void
    {
        $result = (new Scanner())->scan('opaque', new ScanOptions(unsupportedFormat: 'reject'));
        self::assertSame('unknown', $result->format->value);
        self::assertSame('reject', $result->verdict->value);
        self::assertFalse($result->toArray()['policyCompliant']);
    }

    public function testRequiredUnsupportedControlUsesUnsupportedFormatAction(): void
    {
        $png = hex2bin('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c48900000001494441540028387de80000000049454e44ae426082');
        self::assertNotFalse($png);
        $result = (new Scanner())->scan($png, new ScanOptions(requiredControls: ['structural', 'decode'], unsupportedFormat: 'reject'));
        self::assertSame('reject', $result->verdict->value);
        self::assertSame('unsupported', $result->controls['decode']['status']);
    }

    public function testUnknownRequiredControlsAreRejectedAtConfigurationTime(): void
    {
        $this->expectException(InvalidScanOptionsException::class);
        new ScanOptions(requiredControls: ['steganography']);
    }
}
