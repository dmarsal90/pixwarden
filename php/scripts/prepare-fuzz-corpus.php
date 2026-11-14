<?php

declare(strict_types=1);

$outputDirectory = $argv[1] ?? null;
if (!is_string($outputDirectory) || $outputDirectory === '') {
    fwrite(STDERR, "Provide an output directory for the temporary fuzz corpus.\n");
    exit(2);
}

$manifestPath = dirname(__DIR__, 2) . '/spec/corpus/v1/manifest.json';
$manifestContents = file_get_contents($manifestPath);
if (!is_string($manifestContents)) {
    throw new RuntimeException('Shared corpus manifest could not be read.');
}
$manifest = json_decode($manifestContents, true, flags: JSON_THROW_ON_ERROR);
if (!is_array($manifest) || !is_array($manifest['vectors'] ?? null)) {
    throw new RuntimeException('Shared corpus manifest has no vector list.');
}
if (!is_dir($outputDirectory) && !mkdir($outputDirectory, 0700, true) && !is_dir($outputDirectory)) {
    throw new RuntimeException('Fuzz corpus output directory could not be created.');
}

foreach ($manifest['vectors'] as $vector) {
    if (!is_array($vector)
        || !is_string($vector['id'] ?? null)
        || !preg_match('/^[A-Z0-9-]{1,96}$/D', $vector['id'])
        || !is_string($vector['inputHex'] ?? null)
        || strlen($vector['inputHex']) % 2 !== 0
        || !is_string($vector['sha256'] ?? null)) {
        throw new RuntimeException('Shared corpus contains an invalid fuzz seed entry.');
    }

    $bytes = hex2bin($vector['inputHex']);
    if (!is_string($bytes) || !hash_equals($vector['sha256'], hash('sha256', $bytes))) {
        throw new RuntimeException('Shared corpus seed hash does not match for ' . $vector['id'] . '.');
    }

    $path = $outputDirectory . DIRECTORY_SEPARATOR . $vector['id'] . '.bin';
    $handle = fopen($path, 'xb');
    if (!is_resource($handle)) {
        throw new RuntimeException('Fuzz corpus seed could not be created: ' . $vector['id']);
    }
    try {
        if (fwrite($handle, $bytes) !== strlen($bytes)) {
            throw new RuntimeException('Fuzz corpus seed could not be fully written: ' . $vector['id']);
        }
    } finally {
        fclose($handle);
    }
}
