<?php

declare(strict_types=1);

require dirname(__DIR__) . '/php/vendor/autoload.php';

$scanner = new Pixwarden\Scanner();
while (($line = fgets(STDIN)) !== false) {
    $bytes = hex2bin(trim($line));
    if ($bytes === false) {
        echo json_encode(['error' => true], JSON_THROW_ON_ERROR), PHP_EOL;
        continue;
    }

    try {
        $report = $scanner->scan($bytes)->toArray();
        $findingIds = array_values(array_unique(array_column($report['findings'], 'id')));
        sort($findingIds);
        echo json_encode([
            'format' => $report['format'],
            'validity' => $report['validity'],
            'verdict' => $report['verdict'],
            'findingIds' => $findingIds,
        ], JSON_THROW_ON_ERROR), PHP_EOL;
    } catch (Throwable) {
        echo json_encode(['error' => true], JSON_THROW_ON_ERROR), PHP_EOL;
    }
}
