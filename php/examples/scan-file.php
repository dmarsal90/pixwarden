<?php

declare(strict_types=1);

use Pixwarden\ResourceLimits;
use Pixwarden\ScanOptions;
use Pixwarden\Scanner;

require dirname(__DIR__) . '/vendor/autoload.php';

$path = $argv[1] ?? null;
if (!is_string($path) || $path === '') {
    fwrite(STDERR, "Usage: php php/examples/scan-file.php <image-path>\n");
    exit(2);
}

$stream = @fopen($path, 'rb');
if (!is_resource($stream)) {
    fwrite(STDERR, "Unable to open the input file.\n");
    exit(2);
}

try {
    $result = (new Scanner())->scanStream($stream, new ScanOptions(
        new ResourceLimits(maxBytes: 10_485_760, maxMetadataBytes: 1_048_576, maxPixels: 40_000_000),
    ));
} catch (Throwable $error) {
    fwrite(STDERR, 'Pixwarden scan failed: ' . $error->getMessage() . "\n");
    exit(1);
} finally {
    fclose($stream);
}

$report = json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
fwrite(STDOUT, $report . "\n");
$reportArray = $result->toArray();
if ($result->verdict !== \Pixwarden\Verdict::Allow || $result->coverage !== 'complete' || !($reportArray['policyCompliant'] ?? false)) {
    fwrite(STDERR, "Pixwarden did not establish complete policy coverage; keep the upload quarantined for review.\n");
}
