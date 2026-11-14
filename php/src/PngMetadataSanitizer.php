<?php

declare(strict_types=1);

namespace Pixwarden;

/** Removes a narrow set of PNG privacy metadata without decoding image data. */
final class PngMetadataSanitizer
{
    /** @return array{bytes: string, inputBytes: int, outputBytes: int, removedChunks: array<string, int>, postCheckStatus: string} */
    public function sanitize(string $input): array
    {
        if (strlen($input) > 10 * 1024 * 1024) {
            throw new ResourceLimitExceededException('PNG input exceeds the sanitizer byte limit.');
        }
        $snapshot = $input;
        $scanner = new Scanner();
        $before = $scanner->scan($snapshot);
        if ($before->format !== ImageFormat::Png || $before->validity !== 'valid' || array_filter(
            $before->findings,
            static fn (array $finding): bool => str_starts_with($finding['id'], 'IMG-') || $finding['id'] === 'DEC-007'
        ) !== []) {
            throw new SanitizationFailureException('Only structurally valid PNGs within built-in dimension limits can be transformed.');
        }

        $output = substr($snapshot, 0, 8);
        $removedChunks = [];
        $offset = 8;
        $length = strlen($snapshot);
        while ($offset < $length) {
            $chunkLength = $this->readChunkLength($snapshot, $offset);
            $chunkType = substr($snapshot, $offset + 4, 4);
            $chunkEnd = $offset + 12 + $chunkLength;
            if (in_array($chunkType, ['eXIf', 'tEXt', 'zTXt', 'iTXt'], true)) {
                $removedChunks[$chunkType] = ($removedChunks[$chunkType] ?? 0) + 1;
            } else {
                $output .= substr($snapshot, $offset, $chunkEnd - $offset);
            }
            $offset = $chunkEnd;
        }

        $after = $scanner->scan($output);
        if ($after->format !== ImageFormat::Png || $after->validity !== 'valid' || array_filter(
            $after->findings,
            static fn (array $finding): bool => str_starts_with($finding['id'], 'IMG-') || $finding['id'] === 'DEC-007'
        ) !== [] || $this->containsTargetChunk($output)) {
            throw new SanitizationFailureException('PNG output failed structural or metadata post-check.');
        }

        return [
            'bytes' => $output,
            'inputBytes' => strlen($snapshot),
            'outputBytes' => strlen($output),
            'removedChunks' => $removedChunks,
            'postCheckStatus' => 'passed',
        ];
    }

    private function containsTargetChunk(string $bytes): bool
    {
        $offset = 8;
        $length = strlen($bytes);
        while ($offset < $length) {
            $chunkLength = $this->readChunkLength($bytes, $offset);
            if (in_array(substr($bytes, $offset + 4, 4), ['eXIf', 'tEXt', 'zTXt', 'iTXt'], true)) {
                return true;
            }
            $offset += 12 + $chunkLength;
        }
        return false;
    }

    private function readChunkLength(string $bytes, int $offset): int
    {
        $decoded = unpack('Nlength', substr($bytes, $offset, 4));
        if (!is_array($decoded) || !isset($decoded['length'])) {
            throw new SanitizationFailureException('PNG chunk length could not be read during post-check.');
        }

        return $decoded['length'];
    }
}
