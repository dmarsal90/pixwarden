<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\Scanner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConformanceTest extends TestCase
{
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
        $result = (new Scanner())->scan($bytes);
        foreach (['format', 'validity', 'verdict', 'coverage'] as $key) {
            self::assertSame($vector['expected'][$key], $result[$key], $vector['id'] . ': ' . $key);
        }
        $ids = array_values(array_unique(array_column($result['findings'], 'id')));
        sort($ids);
        $expectedIds = $vector['expected']['findingIds'];
        sort($expectedIds);
        self::assertSame($expectedIds, $ids, $vector['id'] . ': findingIds');
    }
}
