<?php

declare(strict_types=1);

use Pixwarden\AiInspectionOptions;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;

require dirname(__DIR__) . '/vendor/autoload.php';

if (function_exists('zlib_decode')) {
    fwrite(STDERR, "zlib_decode must be disabled for this smoke test.\n");
    exit(2);
}

$manifestPath = dirname(__DIR__, 2) . '/spec/corpus/v1/manifest.json';
$manifest = json_decode((string) file_get_contents($manifestPath), true, flags: JSON_THROW_ON_ERROR);
$targetIds = [
    'AI-PNG-ZTXT-COMPRESSED-OVERRIDE-001',
    'AI-PNG-ITXT-COMPRESSED-OVERRIDE-001',
    'AI-PNG-ITXT-COMPRESSED-BENIGN-001',
];
$vectors = [];
foreach ($manifest['vectors'] as $vector) {
    if (in_array($vector['id'], $targetIds, true)) {
        $vectors[$vector['id']] = $vector;
    }
}

if (count($vectors) !== count($targetIds)) {
    fwrite(STDERR, "A compressed PNG text corpus vector is missing.\n");
    exit(2);
}

foreach ($targetIds as $id) {
    $vector = $vectors[$id] ?? null;
    if (!is_array($vector)) {
        fwrite(STDERR, "The {$id} vector could not be indexed.\n");
        exit(2);
    }
    $bytes = hex2bin($vector['inputHex']);
    if ($bytes === false || hash('sha256', $bytes) !== $vector['sha256']) {
        fwrite(STDERR, "The {$id} fixture failed its hash check.\n");
        exit(2);
    }
    $result = (new Scanner())->scan($bytes, new ScanOptions(
        aiInspection: new AiInspectionOptions(enabled: true),
    ));
    $report = $result->toArray();
    if ($report['aiInspection']['status'] !== 'partial'
        || $report['controls']['aiInspection']['status'] !== 'unsupported'
        || $report['verdict'] !== 'review'
        || in_array('AI-002', array_column($result->findings(), 'id'), true)) {
        fwrite(STDERR, "The {$id} fixture was not safely reported as incomplete without zlib.\n");
        exit(1);
    }
}

fwrite(STDOUT, "PHP compressed PNG metadata without zlib remains partial and cannot pass policy.\n");
