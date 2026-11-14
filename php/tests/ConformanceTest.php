<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Opis\JsonSchema\CompliantValidator;
use Opis\JsonSchema\Errors\ErrorFormatter;
use Pixwarden\Scanner;
use Pixwarden\ResourceLimits;
use Pixwarden\ScanOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConformanceTest extends TestCase
{
    public function testSharedSchemaRejectsReportsWithMissingRequiredFields(): void
    {
        $invalidReport = json_decode(
            json_encode((new Scanner())->scan('opaque')->toArray(), JSON_THROW_ON_ERROR),
            false,
            flags: JSON_THROW_ON_ERROR,
        );
        unset($invalidReport->scanId);

        $validation = self::validator()->validate($invalidReport, 'urn:pixwarden:spec:0.1.0#/$defs/ScanResult');

        self::assertFalse($validation->isValid());
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function vectors(): iterable
    {
        $manifestJson = file_get_contents(__DIR__ . '/../../spec/corpus/v1/manifest.json');
        if ($manifestJson === false) {
            throw new \RuntimeException('Shared corpus manifest could not be read.');
        }
        $manifest = json_decode($manifestJson, true, flags: JSON_THROW_ON_ERROR);
        foreach ($manifest['vectors'] as $vector) {
            yield $vector['id'] => [$vector];
        }
    }

    /** @param array<string, mixed> $vector */
    #[DataProvider('vectors')]
    public function testSharedVector(array $vector): void
    {
        $bytes = hex2bin($vector['inputHex']);
        self::assertNotFalse($bytes);
        self::assertSame($vector['sha256'], hash('sha256', $bytes));
        $limitValues = $vector['scanOptions']['limits'] ?? [];
        $limits = new ResourceLimits(
            maxBytes: $limitValues['maxBytes'] ?? 10_485_760,
            maxMetadataBytes: $limitValues['maxMetadataBytes'] ?? 1_048_576,
            maxWidth: $limitValues['maxWidth'] ?? 40_000,
            maxHeight: $limitValues['maxHeight'] ?? 40_000,
            maxPixels: $limitValues['maxPixels'] ?? 40_000_000,
            maxFrames: $limitValues['maxFrames'] ?? 200,
        );
        $result = (new Scanner())->scan($bytes, new ScanOptions($limits));
        $report = $result->toArray();
        self::assertSame(json_encode($report, JSON_THROW_ON_ERROR), json_encode($result, JSON_THROW_ON_ERROR));
        $validation = self::validator()->validate(
            json_decode(json_encode($report, JSON_THROW_ON_ERROR), false, flags: JSON_THROW_ON_ERROR),
            'urn:pixwarden:spec:0.1.0#/$defs/ScanResult',
        );
        if (!$validation->isValid()) {
            $error = $validation->error();
            self::assertNotNull($error, $vector['id'] . ': schema validation failed without an error detail.');
            self::fail($vector['id'] . ': PHP report must satisfy the shared ScanResult schema: ' . json_encode((new ErrorFormatter())->format($error), JSON_THROW_ON_ERROR));
        }
        self::assertSame($report['format'], $result->format->value);
        self::assertSame($report['verdict'], $result->verdict->value);
        foreach (['format', 'validity', 'verdict', 'coverage'] as $key) {
            self::assertSame($vector['expected'][$key], $report[$key], $vector['id'] . ': ' . $key);
        }
        $ids = array_values(array_unique(array_column($result->findings(), 'id')));
        sort($ids);
        $expectedIds = $vector['expected']['findingIds'];
        sort($expectedIds);
        self::assertSame($expectedIds, $ids, $vector['id'] . ': findingIds');
        if (isset($vector['expected']['binaryStatus'])) {
            self::assertSame($vector['expected']['binaryStatus'], $report['binaryInspection']['status']);
            self::assertSame($vector['expected']['binaryBytesScanned'], $report['binaryInspection']['bytesScanned']);
        }
    }

    private static function validator(): CompliantValidator
    {
        static $validator = null;
        if ($validator === null) {
            $validator = new CompliantValidator();
            $resolver = $validator->resolver();
            if ($resolver === null) {
                throw new \RuntimeException('Opis schema resolver is unavailable.');
            }
            $resolver->registerFile(
                'urn:pixwarden:spec:0.1.0',
                __DIR__ . '/../../spec/schemas/pixwarden-v1.schema.json',
            );
        }

        return $validator;
    }
}
