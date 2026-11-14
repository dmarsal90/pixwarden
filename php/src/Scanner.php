<?php

declare(strict_types=1);

namespace Pixwarden;

use InvalidArgumentException;

/** Native PHP byte-level profile. It never invokes a decoder or external process. */
final class Scanner
{
    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function scan(string $bytes, array $options = []): array
    {
        $maxBytes = $options['maxBytes'] ?? 10_485_760;
        if (!is_int($maxBytes) || $maxBytes < 1 || $maxBytes > 10_485_760) {
            throw new InvalidArgumentException('maxBytes must be a positive integer no greater than the built-in maximum.');
        }
        $maxMetadataBytes = $options['maxMetadataBytes'] ?? 1_048_576;
        if (!is_int($maxMetadataBytes) || $maxMetadataBytes < 1 || $maxMetadataBytes > 1_048_576) {
            throw new InvalidArgumentException('maxMetadataBytes must be a positive integer no greater than the built-in maximum.');
        }
        if (strlen($bytes) > $maxBytes) {
            throw new InvalidArgumentException('Input exceeds the configured byte limit.');
        }

        [$format, $validity, $findings] = $this->inspect($bytes);
        $metadataInspection = (new MetadataGuard())->inspect($bytes, $format, $maxMetadataBytes);
        $findings = array_merge($findings, $metadataInspection['findings']);
        $binaryInspection = (new BinaryGuard())->inspect($bytes, $format);
        $findings = array_merge($findings, $binaryInspection['findings']);
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
            'sanitization' => ['status' => 'unsupported', 'summary' => 'No sanitizer is implemented; input bytes are unchanged.'],
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
                'inspect' => in_array($supportedFormat, ['jpeg', 'png', 'gif', 'webp'], true),
                'decode' => false,
                'sanitize' => false,
                'reason' => in_array($supportedFormat, ['jpeg', 'png', 'gif', 'webp'], true)
                    ? 'Limited byte-level container profile only; no decoder is bundled.'
                    : 'No structural profile is available.',
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
                'hardLimits' => ['inputBytes' => true, 'dimensionsBeforeDecode' => false, 'framesBeforeDecode' => false, 'memory' => false, 'cpu' => false, 'wallTime' => false],
            ],
            'metadataInspection' => $metadataInspection,
            'binaryInspection' => $binaryInspection,
            'limitations' => ['PHP v0.3.0 provides limited container checks for JPEG, PNG, GIF and WebP, bounded EXIF TIFF directory inspection for JPEG, PNG and WebP, and indicator-only signatures in selected format-defined ancillary regions. Metadata values, XMP and text are not parsed; no decoder, SVG handling, sanitizer, OCR, steganography, or process isolation is included. Binary signatures do not prove an embedded file or replace malware scanning. A valid result is not proof of safe decoding or rendering.'],
            'inputBytes' => strlen($bytes),
        ];
    }

    /** @return array{string,string,list<array<string,mixed>>} */
    private function inspect(string $bytes): array
    {
        $format = match (true) {
            str_starts_with($bytes, "\x89PNG\r\n\x1a\n") => 'png',
            str_starts_with($bytes, "\xff\xd8\xff") => 'jpeg',
            str_starts_with($bytes, 'GIF87a'), str_starts_with($bytes, 'GIF89a') => 'gif',
            strlen($bytes) >= 12 && substr($bytes, 0, 4) === 'RIFF' && substr($bytes, 8, 4) === 'WEBP' => 'webp',
            default => 'unknown',
        };
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
