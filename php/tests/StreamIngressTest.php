<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\InvalidInputException;
use Pixwarden\ResourceLimitExceededException;
use Pixwarden\ResourceLimits;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;
use PHPUnit\Framework\TestCase;

final class StreamIngressTest extends TestCase
{
    public function testStreamReadsFromCurrentPositionAndLeavesResourceOpen(): void
    {
        $stream = fopen('php://memory', 'r+');
        self::assertIsResource($stream);
        fwrite($stream, 'prefix-image-bytes');
        fseek($stream, 7);

        $result = (new Scanner())->scanStream($stream);

        self::assertSame(11, $result->toArray()['inputBytes']);
        self::assertTrue(is_resource($stream));
        self::assertTrue(feof($stream));
        fclose($stream);
    }

    public function testStreamStopsAtTheConfiguredByteLimit(): void
    {
        $stream = fopen('php://memory', 'r+');
        self::assertIsResource($stream);
        fwrite($stream, 'four');
        rewind($stream);

        try {
            (new Scanner())->scanStream($stream, new ScanOptions(new ResourceLimits(maxBytes: 3)));
            self::fail('Expected the byte limit to be enforced while reading.');
        } catch (ResourceLimitExceededException) {
            self::assertSame(4, ftell($stream));
        } finally {
            fclose($stream);
        }
    }

    public function testRejectsNonStreamInputsWithTypedException(): void
    {
        $this->expectException(InvalidInputException::class);
        (new Scanner())->scanStream(null);
    }
}
