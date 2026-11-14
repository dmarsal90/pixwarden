<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\Scanner;
use Pixwarden\InvalidInputException;
use Pixwarden\SanitizationFailureException;
use PHPUnit\Framework\TestCase;

final class PngMetadataSanitizerTest extends TestCase
{
    public function testRgba8RasterTransformMatchesSharedPixelVectorsAndFilters(): void
    {
        $manifest = json_decode((string) file_get_contents(__DIR__ . '/../../spec/corpus/v1/manifest.json'), true, flags: JSON_THROW_ON_ERROR);
        foreach (['SAN-PNG-RGBA8-RECONSTRUCT-001', 'SAN-PNG-RGBA8-FILTERS-001'] as $id) {
            $vector = array_values(array_filter($manifest['vectors'], static fn (array $item): bool => $item['id'] === $id))[0] ?? null;
            self::assertNotNull($vector);
            $input = hex2bin($vector['inputHex']);
            self::assertNotFalse($input);
            $snapshot = $input;

            $result = (new Scanner())->sanitizePngRgba8($input);

            self::assertSame($snapshot, $input);
            self::assertSame($vector['transform']['width'], $result['width']);
            self::assertSame($vector['transform']['height'], $result['height']);
            self::assertSame($vector['transform']['removedChunks'], $result['removedChunks']);
            self::assertSame($vector['transform']['postCheckStatus'], $result['postCheckStatus']);
            $types = [];
            $idat = '';
            for ($offset = 8, $length = strlen($result['bytes']); $offset < $length;) {
                $chunkLength = $this->readU32BE($result['bytes'], $offset);
                $type = substr($result['bytes'], $offset + 4, 4);
                $types[] = $type;
                if ($type === 'IDAT') {
                    $idat .= substr($result['bytes'], $offset + 8, $chunkLength);
                }
                $offset += 12 + $chunkLength;
            }
            self::assertSame($vector['transform']['outputChunkTypes'], $types);
            $scanlines = zlib_decode($idat);
            self::assertIsString($scanlines);
            $rowLength = $vector['transform']['width'] * 4 + 1;
            $pixels = '';
            for ($row = 0; $row < $vector['transform']['height']; $row++) {
                self::assertSame("\0", $scanlines[$row * $rowLength]);
                $pixels .= substr($scanlines, $row * $rowLength + 1, $rowLength - 1);
            }
            self::assertSame($vector['transform']['rgbaHex'], bin2hex($pixels));
        }
    }

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

    public function testRejectsTrailingZlibBytesAndExcessInflatedScanlineData(): void
    {
        $manifest = json_decode((string) file_get_contents(__DIR__ . '/../../spec/corpus/v1/manifest.json'), true, flags: JSON_THROW_ON_ERROR);
        foreach (['SAN-PNG-RGBA8-ZLIB-TRAILING-001', 'SAN-PNG-RGBA8-EXPANSION-001'] as $id) {
            $vector = array_values(array_filter($manifest['vectors'], static fn (array $item): bool => $item['id'] === $id))[0] ?? null;
            self::assertNotNull($vector);
            $input = hex2bin($vector['inputHex']);
            self::assertNotFalse($input);
            self::assertSame('valid', (new Scanner())->scan($input)->validity);
            $rejected = false;
            try {
                (new Scanner())->sanitizePngRgba8($input);
            } catch (InvalidInputException) {
                $rejected = true;
            }
            self::assertSame(true, $rejected, $id . ' should be rejected by raster sanitization.');
        }
    }

    public function testRejectsMalformedPng(): void
    {
        $this->expectException(SanitizationFailureException::class);
        (new Scanner())->stripPngExifAndTextMetadata("\x89PNG\r\n\x1a\n");
    }

    private function readU32BE(string $bytes, int $offset): int
    {
        $decoded = unpack('Nvalue', substr($bytes, $offset, 4));
        if (!is_array($decoded) || !isset($decoded['value'])) {
            self::fail('PNG output chunk length is truncated.');
        }

        return $decoded['value'];
    }
}
