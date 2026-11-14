<?php

declare(strict_types=1);

$repositoryRoot = dirname(__DIR__, 2);
$manifestPath = $repositoryRoot . '/spec/corpus/v1/manifest.json';
$manifest = json_decode((string) file_get_contents($manifestPath), true, flags: JSON_THROW_ON_ERROR);
$vector = null;
foreach ($manifest['vectors'] as $candidate) {
    if ($candidate['id'] === 'STEG-PNG-RGBA8-STATISTICS-001') {
        $vector = $candidate;
        break;
    }
}

if (!is_array($vector)) {
    fwrite(STDERR, "The shared PNG example fixture is missing.\n");
    exit(2);
}
$bytes = hex2bin($vector['inputHex']);
if ($bytes === false || hash('sha256', $bytes) !== $vector['sha256']) {
    fwrite(STDERR, "The shared PNG example fixture failed its hash check.\n");
    exit(2);
}
$imagePath = tempnam(sys_get_temp_dir(), 'pixwarden-php-example-');
if (!is_string($imagePath) || file_put_contents($imagePath, $bytes, LOCK_EX) !== strlen($bytes)) {
    fwrite(STDERR, "Could not prepare the temporary image fixture.\n");
    exit(2);
}

$process = proc_open(
    [PHP_BINARY, $repositoryRoot . '/php/examples/scan-file.php', $imagePath],
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes,
    $repositoryRoot,
);
if (!is_resource($process)) {
    unlink($imagePath);
    fwrite(STDERR, "Could not start the PHP file-ingress example.\n");
    exit(2);
}
fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$exitCode = proc_close($process);
unlink($imagePath);

if ($exitCode !== 0 || !is_string($stdout) || !is_string($stderr)) {
    fwrite(STDERR, "The PHP file-ingress example returned an error.\n" . (string) $stderr);
    exit(1);
}
$report = json_decode($stdout, true, flags: JSON_THROW_ON_ERROR);
if (($report['format'] ?? null) !== 'png'
    || ($report['verdict'] ?? null) !== 'allow'
    || ($report['coverage'] ?? null) !== 'partial'
    || !str_contains($stderr, 'keep the upload quarantined for review')) {
    fwrite(STDERR, "The PHP file-ingress example did not preserve incomplete input for review.\n");
    exit(1);
}

fwrite(STDOUT, "PHP file-ingress example runs and retains partial-coverage input.\n");
