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

    public function testShortWebpExifChunkProducesBoundedEvidence(): void
    {
        $bytes = hex2bin('524946465400000057454250565038200400000000000000455849460100000045786966000049492aecececececececececececececececececececec0008000000010069870400010000001a00000000000000002e2e2f2e2e2f6a617a5f7a657200869207000a0000002c00000000000900000000000000450000d8');
        self::assertNotFalse($bytes);
        $report = (new Scanner())->scan($bytes)->toArray();
        foreach ($report['findings'] as $finding) {
            foreach ($finding['evidence'] as $evidence) {
                if (isset($evidence['length'])) {
                    self::assertGreaterThanOrEqual(0, $evidence['length']);
                    self::assertArrayHasKey('offset', $evidence);
                    self::assertLessThanOrEqual(strlen($bytes), $evidence['offset'] + $evidence['length']);
                }
            }
        }
    }
}
