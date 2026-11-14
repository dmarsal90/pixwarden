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
        $base = hex2bin('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c48900000001494441540028387de80000000049454e44ae426082');
        self::assertNotFalse($base);
        $text = $this->chunk('tEXt', "Comment\0private");
        $source = substr($base, 0, 33) . $text . substr($base, 33);
        $snapshot = $source;

        $result = (new Scanner())->stripPngExifAndTextMetadata($source);

        self::assertSame(['tEXt' => 1], $result['removedChunks']);
        self::assertSame('passed', $result['postCheckStatus']);
        self::assertSame($snapshot, $source);
        self::assertStringNotContainsString('private', $result['bytes']);
        self::assertSame(substr($base, -12), substr($result['bytes'], -12));
        self::assertSame('valid', (new Scanner())->scan($result['bytes'])->validity);
    }

    public function testRejectsMalformedPng(): void
    {
        $this->expectException(SanitizationFailureException::class);
        (new Scanner())->stripPngExifAndTextMetadata("\x89PNG\r\n\x1a\n");
    }

    private function chunk(string $type, string $payload): string
    {
        return pack('N', strlen($payload)) . $type . $payload . pack('N', crc32($type . $payload));
    }
}
