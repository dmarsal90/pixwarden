<?php

declare(strict_types=1);

namespace Pixwarden;

/** Reconstructs one narrow PNG raster profile and emits a minimal new PNG. */
final class PngRgba8Sanitizer
{
    private const MAX_BYTES = 10 * 1024 * 1024;
    private const MAX_PIXELS = 1_000_000;
    private const SIGNATURE = "\x89PNG\r\n\x1a\n";

    /** @return array{bytes: string, inputBytes: int, outputBytes: int, width: int, height: int, removedChunks: array<string, int>, postCheckStatus: string} */
    public function sanitize(string $input): array
    {
        if (strlen($input) > self::MAX_BYTES) {
            throw new ResourceLimitExceededException('PNG input exceeds the raster sanitizer byte limit.');
        }
        if (!function_exists('zlib_decode') || !function_exists('gzcompress')) {
            throw new CapabilityUnavailableException('The PHP zlib extension is required for PNG raster sanitization.');
        }
        $snapshot = $input;
        $scan = (new Scanner())->scan($snapshot);
        if ($scan->format !== ImageFormat::Png || $scan->validity !== 'valid' || array_filter(
            $scan->findings,
            static fn (array $finding): bool => str_starts_with($finding['id'], 'IMG-') || $finding['id'] === 'DEC-007'
        ) !== []) {
            throw new SanitizationFailureException('Only structurally valid PNGs within the raster sanitizer limits can be decoded.');
        }
        $width = $this->readU32BE($snapshot, 16);
        $height = $this->readU32BE($snapshot, 20);
        if ($width < 1 || $height < 1 || $width > intdiv(self::MAX_PIXELS, $height)) {
            throw new ResourceLimitExceededException('PNG dimensions exceed the one-million-pixel raster sanitizer limit.');
        }
        if (ord($snapshot[24]) !== 8 || ord($snapshot[25]) !== 6 || ord($snapshot[28]) !== 0) {
            throw new CapabilityUnavailableException('Raster sanitization supports only non-interlaced 8-bit RGBA PNG images.');
        }

        $compressed = '';
        $removedChunks = [];
        $offset = 8;
        $inputLength = strlen($snapshot);
        while ($offset < $inputLength) {
            $chunkLength = $this->readU32BE($snapshot, $offset);
            $type = substr($snapshot, $offset + 4, 4);
            $dataOffset = $offset + 8;
            if (in_array($type, ['acTL', 'fcTL', 'fdAT'], true)) {
                throw new CapabilityUnavailableException('Animated PNG is not supported by the raster sanitizer.');
            }
            if ($type === 'IDAT') {
                $compressed .= substr($snapshot, $dataOffset, $chunkLength);
            } elseif (!in_array($type, ['IHDR', 'IEND'], true)) {
                $removedChunks[$type] = ($removedChunks[$type] ?? 0) + 1;
            }
            $offset = $dataOffset + $chunkLength + 4;
        }

        $rowBytes = $width * 4;
        $expectedLength = $height * ($rowBytes + 1);
        set_error_handler(static fn (): bool => true, E_WARNING);
        try {
            $filtered = zlib_decode($compressed, $expectedLength);
        } finally {
            restore_error_handler();
        }
        if (!is_string($filtered) || strlen($filtered) !== $expectedLength) {
            throw new InvalidInputException('PNG image data could not be inflated to the bounded scanline size.');
        }
        $verified = $this->inflateWithInputAccounting($compressed, $expectedLength);
        if ($verified !== $filtered) {
            throw new InvalidInputException('PNG image data has trailing bytes or an invalid compressed stream.');
        }
        $pixels = $this->unfilter($filtered, $width, $height);
        $ihdr = pack('NNC5', $width, $height, 8, 6, 0, 0, 0);
        $scanlines = '';
        for ($y = 0; $y < $height; $y++) {
            $scanlines .= "\0" . substr($pixels, $y * $rowBytes, $rowBytes);
        }
        $deflated = gzcompress($scanlines);
        if ($deflated === false) {
            throw new SanitizationFailureException('PNG raster could not be recompressed.');
        }
        if (zlib_decode($deflated, $expectedLength) !== $scanlines) {
            throw new SanitizationFailureException('Recompressed PNG pixels failed post-check.');
        }
        $output = self::SIGNATURE . $this->chunk('IHDR', $ihdr) . $this->chunk('IDAT', $deflated) . $this->chunk('IEND', '');
        if (strlen($output) > self::MAX_BYTES) {
            throw new ResourceLimitExceededException('Sanitized PNG output exceeds the byte limit.');
        }
        $postCheck = (new Scanner())->scan($output);
        if ($postCheck->format !== ImageFormat::Png || $postCheck->validity !== 'valid' || array_filter(
            $postCheck->findings,
            static fn (array $finding): bool => str_starts_with($finding['id'], 'IMG-') || $finding['id'] === 'DEC-007'
        ) !== []) {
            throw new SanitizationFailureException('Reconstructed PNG did not pass structural post-check.');
        }

        return [
            'bytes' => $output,
            'inputBytes' => strlen($snapshot),
            'outputBytes' => strlen($output),
            'width' => $width,
            'height' => $height,
            'removedChunks' => $removedChunks,
            'postCheckStatus' => 'passed',
        ];
    }

    private function unfilter(string $filtered, int $width, int $height): string
    {
        $rowBytes = $width * 4;
        $pixels = str_repeat("\0", $rowBytes * $height);
        $sourceOffset = 0;
        for ($y = 0; $y < $height; $y++) {
            $filter = ord($filtered[$sourceOffset++]);
            if ($filter > 4) {
                throw new InvalidInputException('PNG scanline uses an unknown filter type.');
            }
            $rowStart = $y * $rowBytes;
            $previousStart = $rowStart - $rowBytes;
            for ($x = 0; $x < $rowBytes; $x++) {
                $raw = ord($filtered[$sourceOffset++]);
                $left = $x >= 4 ? ord($pixels[$rowStart + $x - 4]) : 0;
                $above = $y > 0 ? ord($pixels[$previousStart + $x]) : 0;
                $upperLeft = $y > 0 && $x >= 4 ? ord($pixels[$previousStart + $x - 4]) : 0;
                $predictor = match ($filter) {
                    1 => $left,
                    2 => $above,
                    3 => intdiv($left + $above, 2),
                    4 => $this->paeth($left, $above, $upperLeft),
                    default => 0,
                };
                $pixels[$rowStart + $x] = chr(($raw + $predictor) & 0xff);
            }
        }
        return $pixels;
    }

    /**
     * Recheck stream termination while keeping each inflater call's output bounded.
     * PHP's inflate_add() has no output-length argument, so feed small chunks and
     * stop as soon as accumulated output exceeds the already validated scanline size.
     */
    private function inflateWithInputAccounting(string $compressed, int $expectedLength): ?string
    {
        $context = inflate_init(ZLIB_ENCODING_DEFLATE);
        if ($context === false) {
            throw new CapabilityUnavailableException('A bounded zlib inflater could not be initialized.');
        }
        $output = '';
        $inputLength = strlen($compressed);
        for ($offset = 0; $offset < $inputLength; $offset += 4096) {
            $chunkLength = min(4096, $inputLength - $offset);
            $flush = $offset + $chunkLength === $inputLength ? ZLIB_FINISH : ZLIB_SYNC_FLUSH;
            $part = inflate_add($context, substr($compressed, $offset, $chunkLength), $flush);
            if (!is_string($part) || strlen($output) + strlen($part) > $expectedLength) {
                return null;
            }
            $output .= $part;
        }
        if (inflate_get_status($context) !== ZLIB_STREAM_END || inflate_get_read_len($context) !== $inputLength) {
            return null;
        }

        return $output;
    }

    private function paeth(int $a, int $b, int $c): int
    {
        $p = $a + $b - $c;
        $pa = abs($p - $a);
        $pb = abs($p - $b);
        $pc = abs($p - $c);
        return $pa <= $pb && $pa <= $pc ? $a : ($pb <= $pc ? $b : $c);
    }

    private function chunk(string $type, string $data): string
    {
        return pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
    }

    private function readU32BE(string $bytes, int $offset): int
    {
        $decoded = unpack('Nvalue', substr($bytes, $offset, 4));
        if (!is_array($decoded) || !isset($decoded['value'])) {
            throw new InvalidInputException('PNG chunk length could not be read.');
        }

        return $decoded['value'];
    }
}
