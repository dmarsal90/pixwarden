<?php

declare(strict_types=1);

use Pixwarden\CapabilityUnavailableException;
use Pixwarden\Scanner;

require dirname(__DIR__) . '/vendor/autoload.php';

if (class_exists(DOMDocument::class)) {
    fwrite(STDERR, "DOMDocument must be unavailable for this smoke test.\n");
    exit(2);
}

$manifestPath = dirname(__DIR__, 2) . '/spec/corpus/v1/manifest.json';
$manifest = json_decode((string) file_get_contents($manifestPath), true, flags: JSON_THROW_ON_ERROR);
$vector = null;
foreach ($manifest['vectors'] as $candidate) {
    if ($candidate['id'] === 'SVG-STATIC-SAFE-001') {
        $vector = $candidate;
        break;
    }
}

if (!is_array($vector)) {
    fwrite(STDERR, "The static SVG corpus vector is missing.\n");
    exit(2);
}
$bytes = hex2bin($vector['inputHex']);
if ($bytes === false || hash('sha256', $bytes) !== $vector['sha256']) {
    fwrite(STDERR, "The SVG fixture failed its hash check.\n");
    exit(2);
}

$scanner = new Scanner();
$report = $scanner->scan($bytes)->toArray();
if (($report['format'] ?? null) !== 'svg'
    || ($report['validity'] ?? null) !== 'unknown'
    || ($report['verdict'] ?? null) !== 'review'
    || ($report['controls']['sanitization']['status'] ?? null) !== 'unsupported') {
    fwrite(STDERR, "SVG without ext-dom was not reported as unsupported and incomplete.\n");
    exit(1);
}

try {
    $scanner->sanitizeSvg($bytes);
    fwrite(STDERR, "SVG sanitization unexpectedly ran without ext-dom.\n");
    exit(1);
} catch (CapabilityUnavailableException) {
    fwrite(STDOUT, "PHP SVG inspection and sanitization remain explicit without ext-dom.\n");
}
