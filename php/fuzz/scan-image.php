<?php

declare(strict_types=1);

use Pixwarden\PixwardenException;
use Pixwarden\Scanner;

require __DIR__ . '/../vendor/autoload.php';

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }

    throw new ErrorException($message, 0, $severity, $file, $line);
});

/** @var PhpFuzzer\Config $config */
$scanner = new Scanner();
$config->setTarget(static function (string $input) use ($scanner): void {
    $original = $input;
    try {
        $result = $scanner->scan($input);
    } catch (PixwardenException) {
        return;
    }

    if ($input !== $original) {
        throw new Error('Scanning modified the caller-owned input.');
    }

    $report = $result->toArray();
    $serialized = json_encode($result, JSON_THROW_ON_ERROR);
    if (!is_string($serialized)
        || !in_array($report['format'] ?? null, ['jpeg', 'png', 'gif', 'webp', 'svg', 'unknown'], true)
        || !in_array($report['validity'] ?? null, ['valid', 'invalid', 'unknown'], true)
        || !in_array($report['verdict'] ?? null, ['allow', 'sanitize', 'reject', 'review'], true)) {
        throw new Error('Scanner returned a report outside the shared enum contract.');
    }

    $inputLength = strlen($input);
    foreach ($report['findings'] ?? [] as $finding) {
        foreach ($finding['evidence'] ?? [] as $evidence) {
            if (!isset($evidence['offset'])) {
                continue;
            }
            $offset = $evidence['offset'];
            $length = $evidence['length'] ?? 0;
            if (!is_int($offset) || !is_int($length) || $offset < 0 || $length < 0
                || $offset > $inputLength || $length > $inputLength - $offset) {
                throw new Error('Scanner emitted evidence outside the input bounds.');
            }
        }
    }
});
$config->setMaxLen(65_536);
