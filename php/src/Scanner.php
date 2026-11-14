<?php

declare(strict_types=1);

namespace Pixwarden;

/** Native PHP byte-level profile. It never invokes a decoder or external process. */
final class Scanner
{
    public function scan(string $bytes, ?ScanOptions $options = null): ScanResult
    {
        return ScanResult::fromReport($this->scanReport($bytes, $options ?? new ScanOptions()));
    }

    /**
     * Read a caller-owned stream from its current position without buffering beyond the byte limit.
     * The stream remains open and is not rewound. Configure timeouts on blocking streams yourself.
     *
     * @param resource|false|null $stream
     */
    public function scanStream(mixed $stream, ?ScanOptions $options = null): ScanResult
    {
        if (!is_resource($stream) || get_resource_type($stream) !== 'stream') {
            throw new InvalidInputException('scanStream expects an open PHP stream resource.');
        }

        $limits = ($options ?? new ScanOptions())->limits;
        $maximum = $limits->maxBytes;
        $bytes = '';
        while (true) {
            $remainingWithOverflowByte = $maximum - strlen($bytes) + 1;
            $chunkSize = $remainingWithOverflowByte > 65_536 ? 65_536 : max(1, $remainingWithOverflowByte);
            $chunk = fread($stream, $chunkSize);
            if ($chunk === false) {
                throw new StreamReadException('The input stream could not be read.');
            }
            if ($chunk === '') {
                $metadata = stream_get_meta_data($stream);
                if ($metadata['timed_out']) {
                    throw new StreamReadException('Reading the input stream timed out.');
                }
                if (feof($stream)) {
                    break;
                }
                throw new StreamReadException('The input stream returned no bytes before end-of-file.');
            }
            $bytes .= $chunk;
            if (strlen($bytes) > $maximum) {
                throw new ResourceLimitExceededException('Input exceeds the configured byte limit.');
            }
        }

        return $this->scan($bytes, $options);
    }

    /** @return array<string, mixed> */
    private function scanReport(string $bytes, ScanOptions $options): array
    {
        $resourceLimits = $options->limits->toArray();
        $maxBytes = $resourceLimits['maxBytes'];
        $maxMetadataBytes = $resourceLimits['maxMetadataBytes'];
        if (strlen($bytes) > $maxBytes) {
            throw new ResourceLimitExceededException('Input exceeds the configured byte limit.');
        }

        [$format, $validity, $findings] = $this->inspect($bytes, $maxBytes);
        $metadataInspection = (new MetadataGuard())->inspect($bytes, $format, $maxMetadataBytes);
        $findings = array_merge($findings, $metadataInspection['findings']);
        $binaryInspection = (new BinaryGuard())->inspect($bytes, $format);
        $findings = array_merge($findings, $binaryInspection['findings']);
        $findings = array_merge($findings, $this->resourceFindings($bytes, $format, $resourceLimits));
        $svgAvailable = class_exists(\DOMDocument::class);
        $controls = [
            'hints' => ['status' => 'skipped', 'summary' => 'No filename or media-type hints were supplied.'],
            'structural' => ['status' => $validity === 'valid' ? 'passed' : ($validity === 'invalid' ? 'failed' : 'unsupported'), 'summary' => 'A bounded byte-level profile ran; no decoder was invoked.'],
            'metadata' => ['status' => 'unsupported', 'summary' => 'Only bounded EXIF TIFF directory structure and selected sensitive tag identifiers are inspected; values, XMP and text metadata are not parsed.'],
            'binary' => [
                'status' => $binaryInspection['status'] === 'unsupported' ? 'unsupported' : 'passed',
                'summary' => $binaryInspection['status'] === 'unsupported'
                    ? 'No bounded binary-inspection regions are available for this format.'
                    : 'Read-only indicator signatures are checked only in bounded format-defined metadata, extension, and trailer regions; this is not malware scanning.',
            ],
            'decode' => ['status' => 'unsupported', 'summary' => 'No decoder is bundled or invoked.'],
            'sanitization' => $format === 'svg'
                ? ($svgAvailable
                    ? ['status' => 'skipped', 'summary' => 'The SVG sanitizer is available separately and was not invoked by scan().']
                    : ['status' => 'unsupported', 'summary' => 'PHP ext-dom is unavailable, so SVG inspection and sanitization cannot run.'])
                : ['status' => 'unsupported', 'summary' => 'No raster sanitizer is implemented; input bytes are unchanged.'],
        ];
        $hasBlockingFinding = array_filter($findings, static fn (array $finding): bool => in_array($finding['severity'], ['high', 'critical'], true) || $finding['controlStatus'] === 'failed') !== [];
        $hasReviewFinding = array_filter($findings, static fn (array $finding): bool => in_array($finding['status'], ['suspected', 'inconclusive'], true)) !== [];
        $verdict = $hasBlockingFinding ? 'reject' : ($validity !== 'valid' || $hasReviewFinding ? 'review' : 'allow');

        $scanIdBytes = random_bytes(16);
        $scanIdBytes[6] = chr((ord($scanIdBytes[6]) & 0x0f) | 0x40);
        $scanIdBytes[8] = chr((ord($scanIdBytes[8]) & 0x3f) | 0x80);
        $scanId = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($scanIdBytes), 4));
        $formatCapabilities = [];
        foreach (['jpeg', 'png', 'gif', 'webp', 'svg', 'unknown'] as $supportedFormat) {
            $formatCapabilities[$supportedFormat] = [
                'inspect' => in_array($supportedFormat, ['jpeg', 'png', 'gif', 'webp'], true) || ($supportedFormat === 'svg' && $svgAvailable),
                'decode' => false,
                'sanitize' => $supportedFormat === 'svg' && $svgAvailable,
                'reason' => $supportedFormat === 'svg'
                    ? ($svgAvailable ? 'A DOM-based static allowlist inspection/sanitizer is available separately; no general renderer is bundled.' : 'PHP ext-dom is unavailable.')
                    : (in_array($supportedFormat, ['jpeg', 'png', 'gif', 'webp'], true)
                        ? 'Limited byte-level container profile only; no decoder is bundled.'
                        : 'No structural profile is available.'),
            ];
        }
        return [
            'resultVersion' => 1,
            'scanId' => $scanId,
            'engineVersion' => '0.1.0',
            'specVersion' => '0.1.0',
            'startedAt' => gmdate('Y-m-d\TH:i:s\Z'),
            'completedAt' => gmdate('Y-m-d\TH:i:s\Z'),
            'format' => $format,
            'validity' => $validity,
            'decodability' => 'not_attempted',
            'sanitized' => false,
            'policyCompliant' => $verdict === 'allow',
            'coverage' => 'partial',
            'verdict' => $verdict,
            'controls' => $controls,
            'findings' => $findings,
            'capabilities' => [
                'runtime' => 'php', 'runtimeVersion' => PHP_VERSION,
                'engineVersion' => '0.1.0', 'specVersion' => '0.1.0',
                'networkAccess' => false,
                'formats' => $formatCapabilities,
                'optionalAdapters' => [],
                'hardLimits' => ['inputBytes' => true, 'dimensionsBeforeDecode' => true, 'framesBeforeDecode' => true, 'memory' => false, 'cpu' => false, 'wallTime' => false],
            ],
            'metadataInspection' => $metadataInspection,
            'binaryInspection' => $binaryInspection,
            'limitations' => ['The current PHP profile provides limited container checks for JPEG, PNG, GIF and WebP, bounded EXIF TIFF directory inspection for JPEG, PNG and WebP, indicator-only signatures in selected format-defined auxiliary regions, and a static SVG allowlist sanitizer when ext-dom is available. Metadata values, XMP and text are not parsed; no raster decoder/sanitizer, OCR, steganography, or process isolation is included. Binary signatures do not prove an embedded file or replace malware scanning. A valid result is not proof of safe decoding or rendering.'],
            'inputBytes' => strlen($bytes),
        ];
    }

    /**
     * Sanitize a standalone SVG into the documented static allowlist profile.
     * @return array<string, mixed>
     */
    public function sanitizeSvg(string $bytes): array
    {
        return (new SvgGuard())->sanitize($bytes);
    }

    /**
     * @param array<string, int> $limits
     * @return list<array<string, mixed>>
     */
    private function resourceFindings(string $bytes, string $format, array $limits): array
    {
        $metrics = $this->measure($bytes, $format);
        $findings = [];
        $width = $metrics['width'];
        $height = $metrics['height'];
        if ($width !== null && $height !== null && ($width < 1 || $height < 1 || $width > $limits['maxWidth'] || $height > $limits['maxHeight'] || $width > intdiv($limits['maxPixels'], max(1, $height)))) {
            $findings[] = [
                'id' => 'DEC-007', 'severity' => 'high', 'stage' => 'resource',
                'title' => 'Image dimensions exceed policy',
                'description' => 'Declared dimensions exceed configured image limits.',
                'status' => 'confirmed', 'controlStatus' => 'failed',
                'evidence' => [['kind' => 'statistic', 'summary' => 'width=' . $width . '; height=' . $height . '; configured width, height, or pixel maximum exceeded.']],
            ];
        }
        if ($metrics['frames'] !== null && $metrics['frames'] > $limits['maxFrames']) {
            $findings[] = [
                'id' => 'DEC-008', 'severity' => 'high', 'stage' => 'resource',
                'title' => 'Image frame limit exceeded',
                'description' => 'Frame count exceeds configured image limits.',
                'status' => 'confirmed', 'controlStatus' => 'failed',
                'evidence' => [[
                    'kind' => 'statistic',
                    'summary' => 'frames=' . $metrics['frames'] . '; maximum=' . $limits['maxFrames'],
                ]],
            ];
        }
        return $findings;
    }

    /** @return array{width: ?int, height: ?int, frames: ?int} */
    private function measure(string $bytes, string $format): array
    {
        $width = null;
        $height = null;
        $frames = null;
        $size = strlen($bytes);
        if ($format === 'png' && $size >= 24 && substr($bytes, 12, 4) === 'IHDR') {
            $width = $this->u32be($bytes, 16);
            $height = $this->u32be($bytes, 20);
        } elseif ($format === 'gif' && $size >= 13) {
            $width = $this->u16le($bytes, 6);
            $height = $this->u16le($bytes, 8);
            $frames = $this->countGifFrames($bytes);
        } elseif ($format === 'jpeg') {
            [$width, $height] = $this->jpegDimensions($bytes);
        } elseif ($format === 'webp' && $size >= 30) {
            [$width, $height, $frames] = $this->webpMetrics($bytes);
        }
        return ['width' => $width, 'height' => $height, 'frames' => $frames];
    }

    private function u16le(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) + ord($bytes[$offset + 1]) * 256;
    }

    private function u16be(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) * 256 + ord($bytes[$offset + 1]);
    }

    private function u32be(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) * 0x1000000 + ord($bytes[$offset + 1]) * 0x10000 + ord($bytes[$offset + 2]) * 0x100 + ord($bytes[$offset + 3]);
    }

    /** @return array{?int, ?int} */
    private function jpegDimensions(string $bytes): array
    {
        $size = strlen($bytes);
        $cursor = 2;
        $sof = [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf];
        while ($cursor + 4 <= $size && ord($bytes[$cursor]) === 0xff) {
            while ($cursor < $size && ord($bytes[$cursor]) === 0xff) {
                $cursor++;
            }
            if ($cursor >= $size) {
                break;
            }
            $marker = ord($bytes[$cursor++]);
            if ($marker === 0xda || $marker === 0xd9) {
                break;
            }
            if ($marker === 0xd8 || $marker === 0x01 || ($marker >= 0xd0 && $marker <= 0xd7)) {
                continue;
            }
            if ($cursor + 2 > $size) {
                break;
            }
            $length = $this->u16be($bytes, $cursor);
            if ($length < 2 || $length > $size - $cursor) {
                break;
            }
            if (in_array($marker, $sof, true) && $length >= 7) {
                $payload = $cursor + 2;
                return [$this->u16be($bytes, $payload + 3), $this->u16be($bytes, $payload + 1)];
            }
            $cursor += $length;
        }
        return [null, null];
    }

    private function countGifFrames(string $bytes): ?int
    {
        $size = strlen($bytes);
        $packed = ord($bytes[10]);
        $cursor = 13 + (($packed & 0x80) !== 0 ? 3 * (1 << (($packed & 7) + 1)) : 0);
        if ($cursor > $size) {
            return null;
        }
        $frames = 0;
        while ($cursor < $size) {
            $marker = ord($bytes[$cursor++]);
            if ($marker === 0x3b) {
                return $frames;
            }
            if ($marker === 0x2c) {
                if ($cursor + 9 > $size) {
                    return null;
                }
                $imagePacked = ord($bytes[$cursor + 8]);
                $cursor += 9;
                if (($imagePacked & 0x80) !== 0) {
                    $cursor += 3 * (1 << (($imagePacked & 7) + 1));
                }
                if ($cursor >= $size) {
                    return null;
                }
                $cursor++;
                $next = $this->skipGifSubBlocks($bytes, $cursor);
                if ($next === null) {
                    return null;
                }
                $cursor = $next;
                $frames++;
            } elseif ($marker === 0x21) {
                if ($cursor >= $size) {
                    return null;
                }
                $label = ord($bytes[$cursor++]);
                if ($label === 0xf9) {
                    if ($cursor + 6 > $size) {
                        return null;
                    }
                    $cursor += 6;
                } else {
                    $next = $this->skipGifSubBlocks($bytes, $cursor);
                    if ($next === null) {
                        return null;
                    }
                    $cursor = $next;
                }
            } else {
                return null;
            }
        }
        return null;
    }

    private function skipGifSubBlocks(string $bytes, int $cursor): ?int
    {
        $size = strlen($bytes);
        while ($cursor < $size) {
            $length = ord($bytes[$cursor++]);
            if ($length === 0) {
                return $cursor;
            }
            if ($length > $size - $cursor) {
                return null;
            }
            $cursor += $length;
        }
        return null;
    }

    /** @return array{?int, ?int, ?int} */
    private function webpMetrics(string $bytes): array
    {
        $size = strlen($bytes);
        $riff = unpack('Vlength', substr($bytes, 4, 4));
        if ($riff === false) {
            return [null, null, null];
        }
        $limit = min($size, $riff['length'] + 8);
        $cursor = 12;
        $width = null;
        $height = null;
        $frames = 0;
        while ($cursor + 8 <= $limit) {
            $kind = substr($bytes, $cursor, 4);
            $unpackedLength = unpack('Vlength', substr($bytes, $cursor + 4, 4));
            if ($unpackedLength === false) {
                break;
            }
            $length = $unpackedLength['length'];
            $payload = $cursor + 8;
            $end = $payload + $length;
            if ($end > $limit) {
                break;
            }
            if ($kind === 'VP8X' && $length === 10) {
                $width = 1 + $this->u24le($bytes, $payload + 4);
                $height = 1 + $this->u24le($bytes, $payload + 7);
            } elseif ($kind === 'ANMF') {
                $frames++;
            }
            $cursor = $end + ($length & 1);
        }
        return [$width, $height, $frames];
    }

    private function u24le(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) + ord($bytes[$offset + 1]) * 256 + ord($bytes[$offset + 2]) * 65_536;
    }

    /** @return array{string,string,list<array<string,mixed>>} */
    private function inspect(string $bytes, int $maxBytes): array
    {
        $format = match (true) {
            str_starts_with($bytes, "\x89PNG\r\n\x1a\n") => 'png',
            str_starts_with($bytes, "\xff\xd8\xff") => 'jpeg',
            str_starts_with($bytes, 'GIF87a'), str_starts_with($bytes, 'GIF89a') => 'gif',
            strlen($bytes) >= 12 && substr($bytes, 0, 4) === 'RIFF' && substr($bytes, 8, 4) === 'WEBP' => 'webp',
            default => 'unknown',
        };
        if ($format === 'unknown' && SvgGuard::looksLikeSvg($bytes)) {
            $svg = (new SvgGuard())->inspect($bytes, $maxBytes);
            return ['svg', $svg['validity'], $svg['findings']];
        }
        if ($format === 'unknown') {
            return [$format, 'unknown', []];
        }
        if ($format === 'png') {
            $valid = $this->validPng($bytes);
        } elseif ($format === 'gif') {
            $valid = strlen($bytes) >= 14 && str_ends_with($bytes, "\x3b");
        } elseif ($format === 'jpeg') {
            $valid = strlen($bytes) >= 4 && str_ends_with($bytes, "\xff\xd9") && str_contains(substr($bytes, 2), "\xff\xc0");
        } else {
            $valid = $this->validWebp($bytes);
        }
        if ($valid) {
            return [$format, 'valid', []];
        }
        return [$format, 'invalid', [[
            'id' => 'IMG-003', 'severity' => 'high', 'stage' => 'structural',
            'title' => 'Truncated or unsupported container structure',
            'description' => 'The bounded PHP profile could not validate the required terminal/container structure.',
            'status' => 'confirmed', 'controlStatus' => 'failed',
            'evidence' => [['kind' => 'policy', 'summary' => 'Input ended before the profile-required structure was complete.']],
        ]]];
    }

    private function validWebp(string $bytes): bool
    {
        if (strlen($bytes) < 20 || substr($bytes, 12, 4) !== 'VP8 ') {
            return false;
        }
        $length = unpack('Vlength', substr($bytes, 4, 4));
        return $length !== false && $length['length'] === strlen($bytes) - 8;
    }

    private function validPng(string $bytes): bool
    {
        if (strlen($bytes) < 45 || substr($bytes, 12, 4) !== 'IHDR') {
            return false;
        }
        $offset = 8;
        $seenHeader = false;
        $seenData = false;
        $seenEnd = false;
        while ($offset + 12 <= strlen($bytes)) {
            $unpackedLength = unpack('Nlength', substr($bytes, $offset, 4));
            if ($unpackedLength === false) {
                return false;
            }
            $length = $unpackedLength['length'];
            if ($length > strlen($bytes) - $offset - 12) {
                return false;
            }
            $type = substr($bytes, $offset + 4, 4);
            if (!$seenHeader && $type !== 'IHDR') {
                return false;
            }
            if ($type === 'IHDR') {
                if ($seenHeader || $length !== 13) {
                    return false;
                }
                $seenHeader = true;
            } elseif ($type === 'IDAT') {
                if (!$seenHeader) {
                    return false;
                }
                $seenData = true;
            } elseif ($type === 'IEND') {
                if ($length !== 0 || !$seenData) {
                    return false;
                }
                $seenEnd = true;
            }
            $offset += 12 + $length;
            if ($seenEnd) {
                break;
            }
        }
        return $seenHeader && $seenData && $seenEnd && $offset === strlen($bytes);
    }
}
