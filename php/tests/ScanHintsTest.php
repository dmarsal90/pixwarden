<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\InvalidScanOptionsException;
use Pixwarden\ScanHints;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;
use PHPUnit\Framework\TestCase;

final class ScanHintsTest extends TestCase
{
    private const PNG = "\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x01IDAT\x00(8}\xe8\x00\x00\x00\x00IEND\xaeB`\x82";

    public function testMatchingFilenameAndMediaTypePassWithoutExposingHints(): void
    {
        $result = (new Scanner())->scan(self::PNG, new ScanOptions(hints: new ScanHints('private-name.png', 'image/png; charset=binary')));

        self::assertSame('passed', $result->controls['hints']['status']);
        self::assertSame([], array_values(array_filter($result->findings(), static fn (array $finding): bool => $finding['id'] === 'IMG-010')));
        self::assertStringNotContainsString('private-name', json_encode($result, JSON_THROW_ON_ERROR));
    }

    public function testMismatchedMediaTypeProducesParityFinding(): void
    {
        $result = (new Scanner())->scan(self::PNG, new ScanOptions(hints: new ScanHints(mediaType: 'image/jpeg')));
        $finding = array_values(array_filter($result->findings(), static fn (array $item): bool => $item['id'] === 'IMG-010'))[0] ?? null;

        self::assertSame('suspected', $finding['status'] ?? null);
        self::assertSame('passed', $result->controls['hints']['status']);
        self::assertStringNotContainsString('image/jpeg', json_encode($result, JSON_THROW_ON_ERROR));
    }

    public function testUnsupportedHintAndUnsafeHintFailClosed(): void
    {
        $result = (new Scanner())->scan(self::PNG, new ScanOptions(hints: new ScanHints(filename: 'image.bmp')));
        self::assertSame('unsupported', $result->controls['hints']['status']);

        $this->expectException(InvalidScanOptionsException::class);
        new ScanHints(filename: "bad\nname.png");
    }
}
