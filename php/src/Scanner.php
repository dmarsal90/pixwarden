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

        [$format, $validity, $findings] = $this->inspect($bytes, $maxBytes, $maxMetadataBytes);
        $metadataInspection = (new MetadataGuard())->inspect($bytes, $format, $maxMetadataBytes);
        $findings = array_merge($findings, $metadataInspection['findings']);
        $aiInspection = (new AiInjectionGuard())->inspect($bytes, $validity === 'valid' ? $format : 'unknown', $maxMetadataBytes, $options->aiInspection);
        $findings = array_merge($findings, $aiInspection['signals']);
        $resourceFindings = $this->resourceFindings($bytes, $format, $resourceLimits);
        $resourceLimitExceeded = array_filter(
            $resourceFindings,
            static fn (array $finding): bool => in_array($finding['id'], ['DEC-007', 'DEC-008'], true),
        ) !== [];
        $steganography = (new PngRgba8SteganographyAnalyzer())->inspect(
            $resourceLimitExceeded ? '' : $bytes,
            $resourceLimitExceeded ? 'unknown' : $format,
            $resourceLimitExceeded ? 'invalid' : $validity,
            $options->steganography,
        );
        $binaryInspection = (new BinaryGuard())->inspect($bytes, $format);
        $findings = array_merge($findings, $binaryInspection['findings']);
        $findings = array_merge($findings, $resourceFindings);
        $hintInspection = $this->inspectHints($format, $options->hints);
        $findings = array_merge($findings, $hintInspection['findings']);
        $svgAvailable = class_exists(\DOMDocument::class);
        $controls = [
            'hints' => $hintInspection['control'],
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
                : ['status' => 'unsupported', 'summary' => 'No sanitizer is invoked by scan(); input bytes are unchanged. A restricted PNG raster transform is available separately.'],
            'steganography' => $steganography['status'] === 'error'
                ? ['status' => 'error', 'summary' => 'The bounded PNG statistical pass could not complete.']
                : ['status' => 'unsupported', 'summary' => $steganography['status'] === 'inconclusive'
                    ? 'Descriptive PNG RGBA8 statistics ran, but no calibrated detector is available; this control cannot pass policy.'
                    : 'No applicable calibrated steganography detector is available for this profile.'],
            'aiInspection' => $aiInspection['status'] === 'not_requested'
                ? ['status' => 'skipped', 'summary' => 'AI/OCR inspection was not requested.']
                : ($aiInspection['status'] === 'error'
                    ? ['status' => 'error', 'summary' => 'PNG metadata instruction inspection could not safely read a chunk length.']
                : (in_array($aiInspection['status'], ['unsupported', 'partial'], true)
                    ? ['status' => 'unsupported', 'summary' => 'Only bounded PNG metadata text rules are available; requested OCR or format analysis is unsupported.']
                    : ['status' => 'passed', 'summary' => 'Bounded PNG text metadata rules ran locally; this is advisory and does not inspect pixels.'])),
        ];
        $evaluation = $this->evaluatePolicy($findings, $controls, $options);
        $verdict = $evaluation['verdict'];

        $scanIdBytes = random_bytes(16);
        $scanIdBytes[6] = chr((ord($scanIdBytes[6]) & 0x0f) | 0x40);
        $scanIdBytes[8] = chr((ord($scanIdBytes[8]) & 0x3f) | 0x80);
        $scanId = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($scanIdBytes), 4));
        $formatCapabilities = [];
        foreach (['jpeg', 'png', 'gif', 'webp', 'svg', 'unknown'] as $supportedFormat) {
            $formatCapabilities[$supportedFormat] = [
                'inspect' => in_array($supportedFormat, ['jpeg', 'png', 'gif', 'webp'], true) || ($supportedFormat === 'svg' && $svgAvailable),
                'decode' => $supportedFormat === 'png',
                'sanitize' => ($supportedFormat === 'svg' && $svgAvailable) || $supportedFormat === 'png',
                'reason' => $supportedFormat === 'svg'
                    ? ($svgAvailable ? 'A DOM-based static allowlist inspection/sanitizer is available separately; no general renderer is bundled.' : 'PHP ext-dom is unavailable.')
                    : ($supportedFormat === 'png'
                        ? 'Only the explicit sanitizer decodes static non-interlaced 8-bit RGBA PNGs up to one million pixels; other profiles are unsupported.'
                        : (in_array($supportedFormat, ['jpeg', 'png', 'gif', 'webp'], true)
                        ? 'Limited byte-level container profile only; no decoder is bundled.'
                        : 'No structural profile is available.')),
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
            'policyCompliant' => $evaluation['compliant'],
            'coverage' => 'partial',
            'verdict' => $verdict,
            'controls' => $controls,
            'findings' => $findings,
            'capabilities' => [
                'runtime' => 'php', 'runtimeVersion' => PHP_VERSION,
                'engineVersion' => '0.1.0', 'specVersion' => '0.1.0',
                'networkAccess' => false,
                'formats' => $formatCapabilities,
                'optionalAdapters' => (object) [],
                'hardLimits' => ['inputBytes' => true, 'dimensionsBeforeDecode' => true, 'framesBeforeDecode' => true, 'memory' => false, 'cpu' => false, 'wallTime' => false],
            ],
            'metadataInspection' => $metadataInspection,
            'binaryInspection' => $binaryInspection,
            'steganography' => $steganography,
            'aiInspection' => $aiInspection,
            'limitations' => ['The current PHP profile provides limited container checks for JPEG, PNG, GIF and WebP, bounded EXIF TIFF directory inspection for JPEG, PNG and WebP, indicator-only signatures in selected format-defined auxiliary regions, and a static SVG allowlist sanitizer when ext-dom is available. A separate PNG sanitizer decodes only static non-interlaced 8-bit RGBA inputs up to one million pixels; it drops ancillary chunks and color profiles, so visual appearance may change. Optional PNG RGBA8 steganography statistics are descriptive and uncalibrated, not a detector. No general raster decoder, OCR, or process isolation is included. Binary signatures do not prove an embedded file or replace malware scanning. A valid result is not proof of safe decoding or rendering.'],
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

    /** Remove PNG eXIf and textual metadata chunks without decoding image data.
     * @return array<string, mixed>
     */
    public function stripPngExifAndTextMetadata(string $bytes): array
    {
        return (new PngMetadataSanitizer())->sanitize($bytes);
    }

    /** Decode and reconstruct a static non-interlaced 8-bit RGBA PNG.
     * @return array<string, mixed>
     */
    public function sanitizePngRgba8(string $bytes): array
    {
        return (new PngRgba8Sanitizer())->sanitize($bytes);
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

    /** @return array{control: array{status: string, summary: string}, findings: list<array<string, mixed>>} */
    private function inspectHints(string $format, ?ScanHints $hints): array
    {
        if ($hints === null) {
            return ['control' => ['status' => 'skipped', 'summary' => 'No filename or media-type hints were supplied.'], 'findings' => []];
        }
        $types = ['jpg' => 'jpeg', 'jpeg' => 'jpeg', 'png' => 'png', 'gif' => 'gif', 'webp' => 'webp', 'svg' => 'svg'];
        $mediaTypes = [
            'image/jpeg' => 'jpeg', 'image/png' => 'png', 'image/gif' => 'gif',
            'image/webp' => 'webp', 'image/svg+xml' => 'svg',
        ];
        $candidates = [];
        $unsupported = false;
        if ($hints->filename !== null) {
            $basename = basename(str_replace('\\', '/', $hints->filename));
            $dot = strrpos($basename, '.');
            $extension = $dot === false ? '' : strtolower(substr($basename, $dot + 1));
            if (isset($types[$extension])) {
                $candidates[] = $types[$extension];
            } else {
                $unsupported = true;
            }
        }
        if ($hints->mediaType !== null) {
            $mediaType = strtolower(trim(explode(';', $hints->mediaType, 2)[0]));
            if (isset($mediaTypes[$mediaType])) {
                $candidates[] = $mediaTypes[$mediaType];
            } else {
                $unsupported = true;
            }
        }
        $findings = [];
        if ($format !== 'unknown') {
            foreach (array_unique($candidates) as $candidate) {
                if ($candidate !== $format) {
                    $findings[] = [
                        'id' => 'IMG-010', 'severity' => 'medium', 'stage' => 'identify',
                        'title' => 'Declared type disagrees with image bytes',
                        'description' => 'A recognized filename extension or media type does not match the format detected from the input bytes.',
                        'status' => 'suspected', 'controlStatus' => 'passed',
                        'evidence' => [['kind' => 'policy', 'summary' => 'Caller-provided type hint differs from byte-derived format.']],
                    ];
                }
            }
        }
        if ($format === 'unknown' || $unsupported) {
            return ['control' => ['status' => 'unsupported', 'summary' => 'One or more type hints or the detected format could not be compared using a supported profile.'], 'findings' => $findings];
        }

        return ['control' => ['status' => 'passed', 'summary' => 'Recognized caller hints were compared with the byte-derived format.'], 'findings' => $findings];
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

    /** @param array{offset: int, length: int}|null $metadataExceeded */
    private function countGifFrames(string $bytes, ?string &$errorId = null, int $maximumMetadataBytes = PHP_INT_MAX, ?array &$metadataExceeded = null): ?int
    {
        $errorId = null;
        $metadataExceeded = null;
        $metadataBytes = 0;
        $size = strlen($bytes);
        if ($size < 13) {
            return null;
        }
        $screenWidth = $this->u16le($bytes, 6);
        $screenHeight = $this->u16le($bytes, 8);
        if ($screenWidth < 1 || $screenHeight < 1) {
            $errorId = 'IMG-006';
            return null;
        }
        $packed = ord($bytes[10]);
        $cursor = 13 + (($packed & 0x80) !== 0 ? 3 * (1 << (($packed & 7) + 1)) : 0);
        if ($cursor > $size) {
            return null;
        }
        $frames = 0;
        while ($cursor < $size) {
            $markerOffset = $cursor;
            $marker = ord($bytes[$cursor++]);
            if ($marker === 0x3b) {
                if ($cursor !== $size) {
                    $errorId = 'IMG-008';
                    return null;
                }
                if ($frames === 0) {
                    $errorId = 'IMG-006';
                    return null;
                }
                return $frames;
            }
            if ($marker === 0x2c) {
                if ($cursor + 9 > $size) {
                    return null;
                }
                $left = $this->u16le($bytes, $cursor);
                $top = $this->u16le($bytes, $cursor + 2);
                $frameWidth = $this->u16le($bytes, $cursor + 4);
                $frameHeight = $this->u16le($bytes, $cursor + 6);
                if ($frameWidth < 1 || $frameHeight < 1 || $left + $frameWidth > $screenWidth || $top + $frameHeight > $screenHeight) {
                    $errorId = 'IMG-006';
                    return null;
                }
                $imagePacked = ord($bytes[$cursor + 8]);
                $cursor += 9;
                $localColorTableBytes = ($imagePacked & 0x80) !== 0 ? 3 * (1 << (($imagePacked & 7) + 1)) : 0;
                if ($localColorTableBytes > $size - $cursor) {
                    return null;
                }
                if (($imagePacked & 0x18) !== 0) {
                    $errorId = 'IMG-006';
                    return null;
                }
                $cursor += $localColorTableBytes;
                if ($cursor >= $size) {
                    return null;
                }
                $minimumCodeSize = ord($bytes[$cursor]);
                if ($minimumCodeSize < 2 || $minimumCodeSize > 8) {
                    $errorId = 'IMG-006';
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
                    if ($cursor + 6 > $size || ord($bytes[$cursor]) !== 4 || ord($bytes[$cursor + 5]) !== 0) {
                        return null;
                    }
                    if ((ord($bytes[$cursor + 1]) & 0xe0) !== 0) {
                        $errorId = 'IMG-006';
                        return null;
                    }
                    $cursor += 6;
                } else {
                    $fixedBlockSize = match ($label) {
                        0x01 => 12,
                        0xff => 11,
                        default => null,
                    };
                    if ($fixedBlockSize !== null && $cursor < $size && ord($bytes[$cursor]) !== $fixedBlockSize) {
                        $errorId = 'IMG-006';
                        return null;
                    }
                    if ($label === 0xff && $cursor + 12 <= $size) {
                        for ($index = $cursor + 1; $index < $cursor + 9; $index++) {
                            $identifierByte = ord($bytes[$index]);
                            if ($identifierByte < 0x20 || $identifierByte > 0x7e) {
                                $errorId = 'IMG-006';
                                return null;
                            }
                        }
                    }
                    $blocksStart = $cursor;
                    $next = $this->skipGifSubBlocks($bytes, $cursor);
                    if ($next === null) {
                        return null;
                    }
                    $blockBytes = $this->gifSubBlockPayloadBytes($bytes, $blocksStart, $next);
                    $metadataBytes += $blockBytes;
                    if ($metadataBytes > $maximumMetadataBytes && $metadataExceeded === null) {
                        $metadataExceeded = ['offset' => $markerOffset, 'length' => $blockBytes];
                    }
                    $cursor = $next;
                }
            } else {
                $errorId = 'IMG-001';
                return null;
            }
        }
        return null;
    }

    private function gifSubBlockPayloadBytes(string $bytes, int $start, int $end): int
    {
        $payloadBytes = 0;
        while ($start < $end) {
            $length = ord($bytes[$start++]);
            if ($length === 0) {
                break;
            }
            $payloadBytes += $length;
            $start += $length;
        }
        return $payloadBytes;
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
    private function inspect(string $bytes, int $maxBytes, int $maxMetadataBytes): array
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
        $pngCrcMismatchOffset = null;
        $pngTrailingDataOffset = null;
        $webpTrailingDataOffset = null;
        $pngErrorId = null;
        $webpErrorId = null;
        $jpegErrorId = null;
        $jpegMetadataExceededOffset = null;
        $gifErrorId = null;
        $gifMetadataExceededOffset = null;
        if ($format === 'png') {
            $valid = $this->validPng($bytes, $pngCrcMismatchOffset, $pngTrailingDataOffset, $pngErrorId);
        } elseif ($format === 'gif') {
            $frames = strlen($bytes) >= 14 ? $this->countGifFrames($bytes, $gifErrorId, $maxMetadataBytes, $gifMetadataExceededOffset) : null;
            $valid = $frames !== null && $frames > 0;
        } elseif ($format === 'jpeg') {
            $valid = $this->validJpeg($bytes, $jpegErrorId, $maxMetadataBytes, $jpegMetadataExceededOffset);
        } else {
            $valid = $this->validWebp($bytes, $webpTrailingDataOffset, $webpErrorId);
        }
        if ($valid) {
            $metadataExceeded = $format === 'gif' ? $gifMetadataExceededOffset : ($format === 'jpeg' ? $jpegMetadataExceededOffset : null);
            if ($metadataExceeded !== null) {
                $isGif = $format === 'gif';
                return [$format, 'valid', [[
                    'id' => 'META-006', 'severity' => 'medium', 'stage' => 'metadata',
                    'title' => $isGif ? 'GIF extension limit exceeded' : 'JPEG metadata limit exceeded',
                    'description' => $isGif ? 'Extension bytes exceed configured metadata limit.' : 'Metadata segment bytes exceed configured limit.',
                    'status' => 'confirmed', 'controlStatus' => 'failed',
                    'evidence' => [['kind' => 'range', 'summary' => $isGif ? 'GIF extension data exceeds configured metadata byte budget.' : 'JPEG metadata segment exceeds configured byte budget.', 'offset' => $metadataExceeded['offset'], 'length' => $metadataExceeded['length']]],
                ]]];
            }
            return [$format, 'valid', []];
        }
        if ($pngCrcMismatchOffset !== null) {
            return [$format, 'invalid', [[
                'id' => 'IMG-002', 'severity' => 'high', 'stage' => 'structural',
                'title' => 'PNG chunk CRC mismatch',
                'description' => 'A PNG chunk checksum does not match its type and payload bytes.',
                'status' => 'confirmed', 'controlStatus' => 'failed',
                'evidence' => [['kind' => 'range', 'summary' => 'Stored PNG chunk CRC differs from the computed checksum.', 'offset' => $pngCrcMismatchOffset, 'length' => 4]],
            ]]];
        }
        if ($pngTrailingDataOffset !== null) {
            return [$format, 'invalid', [[
                'id' => 'IMG-008', 'severity' => 'medium', 'stage' => 'structural',
                'title' => 'Data follows PNG IEND',
                'description' => 'Bytes remain after the PNG end chunk.',
                'status' => 'confirmed', 'controlStatus' => 'failed',
                'evidence' => [['kind' => 'range', 'summary' => 'Bytes remain after the PNG end chunk.', 'offset' => $pngTrailingDataOffset, 'length' => strlen($bytes) - $pngTrailingDataOffset]],
            ]]];
        }
        if ($webpTrailingDataOffset !== null) {
            return [$format, 'invalid', [[
                'id' => 'IMG-008', 'severity' => 'medium', 'stage' => 'structural',
                'title' => 'Data follows WebP RIFF container',
                'description' => 'Bytes remain after the declared RIFF container.',
                'status' => 'confirmed', 'controlStatus' => 'failed',
                'evidence' => [['kind' => 'range', 'summary' => 'Bytes remain after the declared RIFF container.', 'offset' => $webpTrailingDataOffset, 'length' => strlen($bytes) - $webpTrailingDataOffset]],
            ]]];
        }
        return [$format, 'invalid', [[
            'id' => $pngErrorId ?? $webpErrorId ?? $jpegErrorId ?? $gifErrorId ?? 'IMG-003', 'severity' => 'high', 'stage' => 'structural',
            'title' => 'Truncated or unsupported container structure',
            'description' => 'The bounded PHP profile could not validate the required terminal/container structure.',
            'status' => 'confirmed', 'controlStatus' => 'failed',
            'evidence' => [['kind' => 'policy', 'summary' => 'Input ended before the profile-required structure was complete.']],
        ]]];
    }

    private function validWebp(string $bytes, ?int &$trailingDataOffset = null, ?string &$errorId = null): bool
    {
        $trailingDataOffset = null;
        $errorId = null;
        $size = strlen($bytes);
        if ($size < 20 || substr($bytes, 0, 4) !== 'RIFF' || substr($bytes, 8, 4) !== 'WEBP') {
            $errorId = 'IMG-003';
            return false;
        }
        $riffLength = unpack('Vlength', substr($bytes, 4, 4));
        if ($riffLength === false || !is_int($riffLength['length'])) {
            $errorId = 'IMG-004';
            return false;
        }
        $declaredEnd = $riffLength['length'] + 8;
        if ($declaredEnd < 12 || $declaredEnd > $size) {
            $errorId = 'IMG-004';
            return false;
        }
        if ($declaredEnd < $size) {
            $trailingDataOffset = $declaredEnd;
            $errorId = 'IMG-008';
            return false;
        }

        $offset = 12;
        $seenVp8x = false;
        $seenImage = false;
        while ($offset < $size) {
            if ($size - $offset < 8) {
                $errorId = 'IMG-003';
                return false;
            }
            $kind = substr($bytes, $offset, 4);
            $chunkLength = unpack('Vlength', substr($bytes, $offset + 4, 4));
            if ($chunkLength === false || !is_int($chunkLength['length'])) {
                return false;
            }
            $length = $chunkLength['length'];
            $remaining = $size - $offset - 8;
            $padding = $length & 1;
            if ($length > $remaining || $padding > $remaining - $length) {
                $errorId = 'IMG-004';
                return false;
            }
            $payload = $offset + 8;
            $end = $payload + $length;
            if ($padding === 1 && $bytes[$end] !== "\0") {
                $errorId = 'IMG-003';
                return false;
            }

            if ($kind === 'VP8X') {
                if ($offset !== 12 || $seenVp8x || $length !== 10) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $flags = ord($bytes[$payload]);
                if (($flags & 0xc1) !== 0 || substr($bytes, $payload + 1, 3) !== "\0\0\0") {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenVp8x = true;
            } elseif ($kind === 'VP8 ' || $kind === 'VP8L') {
                if ($length === 0 || $seenImage) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenImage = true;
            } elseif ($kind === 'ANMF') {
                if ($length <= 16) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenImage = true;
            }

            $offset = $end + $padding;
        }

        if ($offset !== $size) {
            $errorId = 'IMG-004';
            return false;
        }
        if (!$seenImage) {
            $errorId = 'IMG-006';
            return false;
        }
        return true;
    }

    /** @param array{offset: int, length: int}|null $metadataExceeded */
    private function validJpeg(string $bytes, ?string &$errorId = null, int $maximumMetadataBytes = PHP_INT_MAX, ?array &$metadataExceeded = null): bool
    {
        $errorId = null;
        $metadataExceeded = null;
        $metadataBytes = 0;
        $size = strlen($bytes);
        if ($size < 4 || substr($bytes, 0, 2) !== "\xff\xd8") {
            return false;
        }

        $sofMarkers = [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf];
        $offset = 2;
        $inScan = false;
        $seenSof = false;
        $seenScan = false;
        while ($offset < $size) {
            if ($inScan) {
                while ($offset < $size && ord($bytes[$offset]) !== 0xff) {
                    $offset++;
                }
                if ($offset >= $size) {
                    $errorId = 'IMG-003';
                    return false;
                }
                $markerStart = $offset;
                while ($offset < $size && ord($bytes[$offset]) === 0xff) {
                    $offset++;
                }
                if ($offset >= $size) {
                    $errorId = 'IMG-003';
                    return false;
                }
                $marker = ord($bytes[$offset]);
                if ($marker === 0x00 || ($marker >= 0xd0 && $marker <= 0xd7)) {
                    $offset++;
                    continue;
                }
                $inScan = false;
                $offset = $markerStart;
            }

            if (ord($bytes[$offset]) !== 0xff) {
                $errorId = 'IMG-001';
                return false;
            }
            while ($offset < $size && ord($bytes[$offset]) === 0xff) {
                $offset++;
            }
            if ($offset >= $size) {
                $errorId = 'IMG-003';
                return false;
            }
            $marker = ord($bytes[$offset++]);
            if ($marker === 0xd9) {
                if (!$seenSof || !$seenScan) {
                    $errorId = 'IMG-006';
                    return false;
                }
                if ($offset !== $size) {
                    $errorId = 'IMG-008';
                    return false;
                }
                return true;
            }
            if ($marker === 0xd8 || $marker === 0x01 || ($marker >= 0xd0 && $marker <= 0xd7)) {
                continue;
            }
            if ($offset + 2 > $size) {
                $errorId = 'IMG-003';
                return false;
            }
            $segmentLength = $this->u16be($bytes, $offset);
            if ($segmentLength < 2 || $segmentLength > $size - $offset) {
                $errorId = 'IMG-004';
                return false;
            }
            $payloadLength = $segmentLength - 2;
            if (in_array($marker, [0xe1, 0xe2, 0xed, 0xfe], true)) {
                $metadataBytes += $payloadLength;
                if ($metadataBytes > $maximumMetadataBytes && $metadataExceeded === null) {
                    $metadataExceeded = ['offset' => $offset, 'length' => $segmentLength];
                }
            }
            if (in_array($marker, $sofMarkers, true)) {
                if ($payloadLength < 6) {
                    $errorId = 'IMG-003';
                    return false;
                }
                $seenSof = true;
            }
            if ($marker === 0xda) {
                $seenScan = true;
                $inScan = true;
            }
            $offset += $segmentLength;
        }

        $errorId = 'IMG-003';
        return false;
    }

    private function validPng(string $bytes, ?int &$crcMismatchOffset, ?int &$trailingDataOffset = null, ?string &$errorId = null): bool
    {
        $crcMismatchOffset = null;
        $trailingDataOffset = null;
        $errorId = null;
        if (strlen($bytes) < 45) {
            $errorId = 'IMG-003';
            return false;
        }
        $offset = 8;
        $seenHeader = false;
        $seenData = false;
        $dataSequenceEnded = false;
        $seenPalette = false;
        $seenEnd = false;
        $colorType = null;
        while ($offset + 12 <= strlen($bytes)) {
            $unpackedLength = unpack('Nlength', substr($bytes, $offset, 4));
            if ($unpackedLength === false) {
                return false;
            }
            $length = $unpackedLength['length'];
            if (!is_int($length) || $length > strlen($bytes) - $offset - 12) {
                $errorId = 'IMG-004';
                return false;
            }
            $type = substr($bytes, $offset + 4, 4);
            for ($typeIndex = 0; $typeIndex < 4; $typeIndex++) {
                $typeByte = ord($type[$typeIndex]);
                if (!(($typeByte >= 65 && $typeByte <= 90) || ($typeByte >= 97 && $typeByte <= 122))) {
                    $errorId = 'IMG-001';
                    return false;
                }
            }
            $reservedTypeByte = ord($type[2]);
            if ($reservedTypeByte >= 97 && $reservedTypeByte <= 122) {
                $errorId = 'IMG-001';
                return false;
            }
            $checksum = hash_init('crc32b');
            hash_update($checksum, $type);
            hash_update($checksum, substr($bytes, $offset + 8, $length));
            $computedCrc = hash_final($checksum, true);
            $storedCrc = substr($bytes, $offset + 8 + $length, 4);
            if (!hash_equals($storedCrc, $computedCrc)) {
                $crcMismatchOffset = $offset + 8 + $length;
                return false;
            }
            if (!$seenHeader && $type !== 'IHDR') {
                $errorId = 'IMG-005';
                return false;
            }
            if (ord($type[0]) >= 65 && ord($type[0]) <= 90 && !in_array($type, ['IHDR', 'PLTE', 'IDAT', 'IEND'], true)) {
                $errorId = 'IMG-006';
                return false;
            }
            if ($type === 'IHDR') {
                if ($seenHeader || $length !== 13) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $bitDepth = ord($bytes[$offset + 16]);
                $colorType = ord($bytes[$offset + 17]);
                $validBitDepths = match ($colorType) {
                    0 => [1, 2, 4, 8, 16],
                    2 => [8, 16],
                    3 => [1, 2, 4, 8],
                    4, 6 => [8, 16],
                    default => [],
                };
                if (!in_array($bitDepth, $validBitDepths, true)
                    || ord($bytes[$offset + 18]) !== 0
                    || ord($bytes[$offset + 19]) !== 0
                    || ord($bytes[$offset + 20]) > 1) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenHeader = true;
                $colorType = ord($bytes[$offset + 17]);
            } elseif ($type === 'PLTE') {
                if (!$seenHeader || $seenData || $seenPalette || in_array($colorType, [0, 4], true)
                    || $length === 0 || $length > 768 || $length % 3 !== 0) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenPalette = true;
            } elseif ($type === 'IDAT') {
                if (!$seenHeader || $dataSequenceEnded) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenData = true;
            } elseif ($type === 'IEND') {
                if ($length !== 0 || !$seenData) {
                    $errorId = 'IMG-006';
                    return false;
                }
                $seenEnd = true;
            }
            if ($seenData && $type !== 'IDAT' && $type !== 'IEND') {
                $dataSequenceEnded = true;
            }
            $offset += 12 + $length;
            if ($seenEnd) {
                break;
            }
        }
        if ($colorType === 3 && !$seenPalette) {
            $errorId = 'IMG-006';
            return false;
        }
        if ($seenEnd && $offset < strlen($bytes)) {
            $trailingDataOffset = $offset;
            $errorId = 'IMG-008';
            return false;
        }
        return $seenHeader && $seenData && $seenEnd && $offset === strlen($bytes);
    }

    /** @param list<array<string, mixed>> $findings
     * @param array<string, array{status: string, summary: string}> $controls
     * @return array{verdict: string, compliant: bool}
     */
    private function evaluatePolicy(array $findings, array $controls, ScanOptions $options): array
    {
        foreach ($findings as $finding) {
            if (in_array($finding['severity'], ['critical', 'high'], true) || $finding['controlStatus'] === 'failed') {
                return ['verdict' => 'reject', 'compliant' => false];
            }
        }
        $incomplete = false;
        $hasUnsupported = false;
        foreach ($options->requiredControls as $controlId) {
            $status = $controls[$controlId]['status'] ?? 'skipped';
            if ($status !== 'passed') {
                $incomplete = true;
                $hasUnsupported = $hasUnsupported || in_array($status, ['unsupported', 'skipped'], true);
            }
        }
        if ($incomplete) {
            return [
                'verdict' => $hasUnsupported ? $options->unsupportedFormat : $options->incompleteAnalysis,
                'compliant' => false,
            ];
        }
        foreach ($findings as $finding) {
            if (in_array($finding['status'], ['suspected', 'inconclusive'], true)) {
                return ['verdict' => 'review', 'compliant' => false];
            }
        }

        return ['verdict' => 'allow', 'compliant' => true];
    }
}
