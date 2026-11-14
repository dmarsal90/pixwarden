<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\ErrorCode;
use Pixwarden\InvalidScanOptionsException;
use Pixwarden\ResourceLimitExceededException;
use Pixwarden\ResourceLimits;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;
use Pixwarden\Verdict;
use PHPUnit\Framework\TestCase;

final class TypedApiTest extends TestCase
{
    public function testOptionsAndResultUseTypedValuesAndRemainJsonCompatible(): void
    {
        $bytes = "\x89PNG\r\n\x1a\n" . pack('N', 13) . 'IHDR' . pack('NN', 1, 1) . "\x08\x02\x00\x00\x00" . pack('N', 0) . pack('N', 0) . 'IEND' . pack('N', 0);
        $result = (new Scanner())->scan($bytes, new ScanOptions(new ResourceLimits(maxPixels: 1)));

        self::assertSame('png', $result->format->value);
        self::assertInstanceOf(Verdict::class, $result->verdict);
        self::assertNotSame([], $result->controls);
        self::assertSame(json_encode($result->toArray(), JSON_THROW_ON_ERROR), json_encode($result, JSON_THROW_ON_ERROR));
    }

    public function testInvalidResourceConfigurationUsesPixwardenException(): void
    {
        try {
            new ResourceLimits(maxBytes: 10_485_761);
            self::fail('Expected invalid options to be rejected.');
        } catch (InvalidScanOptionsException $exception) {
            self::assertSame(ErrorCode::InvalidOptions, $exception->errorCode);
        }
    }

    public function testInputLimitUsesTypedPixwardenException(): void
    {
        $this->expectException(ResourceLimitExceededException::class);
        $this->expectExceptionMessage('Input exceeds the configured byte limit.');
        (new Scanner())->scan('1234', new ScanOptions(new ResourceLimits(maxBytes: 3)));
    }
}
