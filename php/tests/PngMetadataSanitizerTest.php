<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\Scanner;
use Pixwarden\SanitizationFailureException;
use PHPUnit\Framework\TestCase;

final class PngMetadataSanitizerTest extends TestCase
{
    public function testRemovesOnlyTextChunksAndChecksOutput(): void
    {
        $manifest = json_decode((string) file_get_contents(__DIR__ . '/../../spec/corpus/v1/manifest.json'), true, flags: JSON_THROW_ON_ERROR);
        $vector = array_values(array_filter($manifest['vectors'], static fn (array $item): bool => $item['id'] === 'SAN-PNG-TEXT-STRIP-001'))[0] ?? null;
        self::assertNotNull($vector);
        $source = hex2bin($vector['inputHex']);
        self::assertNotFalse($source);
        $snapshot = $source;

        $result = (new Scanner())->stripPngExifAndTextMetadata($source);

        self::assertSame($vector['transform']['removedChunks'], $result['removedChunks']);
        self::assertSame($vector['transform']['postCheckStatus'], $result['postCheckStatus']);
        self::assertSame($vector['transform']['expectedSha256'], hash('sha256', $result['bytes']));
        self::assertSame($snapshot, $source);
        self::assertStringNotContainsString('synthetic', $result['bytes']);
        self::assertSame('valid', (new Scanner())->scan($result['bytes'])->validity);
    }

    public function testRejectsMalformedPng(): void
    {
        $this->expectException(SanitizationFailureException::class);
        (new Scanner())->stripPngExifAndTextMetadata("\x89PNG\r\n\x1a\n");
    }
}
