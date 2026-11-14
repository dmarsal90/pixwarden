<?php

declare(strict_types=1);

namespace Pixwarden;

/** Advisory, bounded prompt-risk rules for selected image metadata. */
final class AiInjectionGuard
{
    private const SIGNATURE = "\x89PNG\r\n\x1a\n";
    private const PATTERNS = [
        '/ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i',
        '/disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions/i',
        '/(?:reveal|show|print)\s+(?:the\s+)?(?:system|developer)\s+prompt/i',
        '/ignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)/iu',
        '/(?:revela|muestra)\s+(?:el\s+)?prompt\s+del\s+sistema/iu',
    ];

    /** @return array{status: string, dataEgress: string, signals: list<array<string, mixed>>, limitations: list<string>} */
    public function inspect(string $bytes, string $format, int $maximum, AiInspectionOptions $options): array
    {
        $limitations = [
            'Rules inspect PNG tEXt, zTXt, iTXt and ASCII EXIF UserComment values; compressed output is capped by the metadata budget. Visible pixels, OCR output and other formats are not inspected.',
            'Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior.',
        ];
        if (!$options->enabled) {
            return ['status' => 'not_requested', 'dataEgress' => 'none', 'signals' => [], 'limitations' => $limitations];
        }
        if ($format === 'jpeg' && str_starts_with($bytes, "\xff\xd8")) {
            return $this->inspectJpegTextMetadata($bytes, $maximum, $options);
        }
        if ($format === 'webp' && str_starts_with($bytes, 'RIFF') && substr($bytes, 8, 4) === 'WEBP') {
            return $this->inspectWebpExif($bytes, $maximum, $options);
        }
        if ($format !== 'png' || !str_starts_with($bytes, self::SIGNATURE)) {
            return ['status' => 'unsupported', 'dataEgress' => 'none', 'signals' => [], 'limitations' => [...$limitations, 'The input is not a PNG text/EXIF, JPEG comment/EXIF, or WebP EXIF profile supported by this metadata rule set.']];
        }

        $signals = [];
        $offset = 8;
        $consumed = 0;
        $partial = false;
        $total = strlen($bytes);
        while ($offset + 12 <= $total) {
            $unpackedLength = unpack('Nvalue', substr($bytes, $offset, 4));
            if ($unpackedLength === false || !isset($unpackedLength['value']) || !is_int($unpackedLength['value'])) {
                return ['status' => 'error', 'dataEgress' => 'none', 'signals' => [], 'limitations' => [...$limitations, 'A PNG metadata chunk length could not be represented safely.']];
            }
            $length = $unpackedLength['value'];
            if ($length > $total - $offset - 12) {
                break;
            }
            $kind = substr($bytes, $offset + 4, 4);
            $payloadStart = $offset + 8;
            $payloadEnd = $payloadStart + $length;
            if ($kind === 'eXIf') {
                $allowed = max(0, $maximum - $consumed);
                $inspectedLength = min($length, $allowed);
                $comment = $this->inspectAsciiExifUserComment($bytes, $payloadStart, $payloadStart + $inspectedLength);
                if ($comment['text'] !== null && $comment['offset'] !== null && $comment['length'] !== null) {
                    $signal = $this->makePngExifSignal($comment['text'], $comment['offset'], $comment['length']);
                    if ($signal !== null) {
                        $signals[] = $signal;
                    }
                }
                $partial = $partial || $comment['partial'] || $inspectedLength < $length;
                $consumed += $inspectedLength;
            } elseif ($kind === 'tEXt' || $kind === 'zTXt' || $kind === 'iTXt') {
                $remaining = $maximum - $consumed;
                $allowed = $remaining > 0 ? $remaining : 0;
                $entry = $this->extractText($bytes, $payloadStart, $payloadEnd, $kind, $allowed);
                if ($entry !== null) {
                    if ($length + strlen($entry['text']) > $allowed || ($entry['compressed'] && strlen($entry['text']) >= $allowed)) {
                        $partial = true;
                    }
                    $consumed += min($length + strlen($entry['text']), $allowed);
                    foreach (self::PATTERNS as $pattern) {
                        $matched = preg_match($pattern, $entry['text']);
                        if ($matched === 1) {
                            $signals[] = [
                                'id' => 'AI-002', 'severity' => 'medium', 'stage' => 'ai',
                                'title' => 'Instruction-like text in PNG metadata',
                                'description' => ($entry['compressed'] ? 'Compressed' : 'Uncompressed') . ' PNG text metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.',
                                'status' => 'suspected', 'controlStatus' => 'passed',
                                'evidence' => [[
                                    'kind' => 'range', 'summary' => 'A bounded PNG text field matched a prompt-risk rule; field contents are redacted.',
                                    'offset' => $entry['start'], 'length' => $entry['length'],
                                ]],
                            ];
                            break;
                        }
                    }
                } else {
                    $partial = true;
                }
            }
            $offset = $payloadEnd + 4;
            if ($kind === 'IEND') {
                break;
            }
        }

        if ($options->ocr) {
            $limitations[] = 'OCR was requested but is not implemented; only metadata text rules ran.';
        }
        if ($partial) {
            $limitations[] = 'Some PNG text/EXIF metadata was malformed, used an unsupported UserComment encoding, or exceeded the configured metadata inspection bound.';
        }

        return ['status' => $options->ocr || $partial ? 'partial' : 'completed', 'dataEgress' => 'none', 'signals' => $signals, 'limitations' => $limitations];
    }

    /** @return array{status: string, dataEgress: string, signals: list<array<string, mixed>>, limitations: list<string>} */
    private function inspectWebpExif(string $bytes, int $maximum, AiInspectionOptions $options): array
    {
        $limitations = [
            'Rules inspect ASCII EXIF UserComment values in WebP EXIF chunks only; visible pixels, XMP text, OCR output and other metadata are not inspected.',
            'Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior.',
        ];
        $riff = unpack('Vlength', substr($bytes, 4, 4));
        if ($riff === false || !isset($riff['length']) || $riff['length'] + 8 !== strlen($bytes)) {
            return ['status' => 'partial', 'dataEgress' => 'none', 'signals' => [], 'limitations' => [...$limitations, 'WebP metadata container bounds could not be fully inspected.']];
        }
        $signals = [];
        $offset = 12;
        $total = strlen($bytes);
        $consumed = 0;
        $partial = false;
        while ($offset + 8 <= $total) {
            $kind = substr($bytes, $offset, 4);
            $unpacked = unpack('Vlength', substr($bytes, $offset + 4, 4));
            if ($unpacked === false || !isset($unpacked['length'])) {
                $partial = true;
                break;
            }
            $size = $unpacked['length'];
            $payloadStart = $offset + 8;
            $payloadEnd = $payloadStart + $size;
            $chunkEnd = $payloadEnd + ($size & 1);
            if ($chunkEnd > $total || (($size & 1) === 1 && $bytes[$payloadEnd] !== "\0")) {
                $partial = true;
                break;
            }
            if (in_array($kind, ['EXIF', 'XMP ', 'ICCP'], true)) {
                $allowed = max(0, $maximum - $consumed);
                $inspectedLength = min($size, $allowed);
                if ($kind === 'EXIF') {
                    $tiffStart = substr($bytes, $payloadStart, min(6, $inspectedLength)) === "Exif\0\0" ? $payloadStart + 6 : $payloadStart;
                    $comment = $this->inspectAsciiExifUserComment($bytes, $tiffStart, $payloadStart + $inspectedLength);
                    if ($comment['text'] !== null && $comment['offset'] !== null && $comment['length'] !== null) {
                        $signal = $this->makeWebpExifSignal($comment['text'], $comment['offset'], $comment['length']);
                        if ($signal !== null) {
                            $signals[] = $signal;
                        }
                    }
                    $partial = $partial || $comment['partial'];
                }
                $consumed += $inspectedLength;
                if ($inspectedLength < $size) {
                    $partial = true;
                    break;
                }
            }
            $offset = $chunkEnd;
        }
        if ($offset !== $total) {
            $partial = true;
        }
        if ($options->ocr) {
            $limitations[] = 'OCR was requested but is not implemented; only metadata text rules ran.';
        }
        if ($partial) {
            $limitations[] = 'WebP EXIF metadata was malformed, used an unsupported UserComment encoding, or exceeded the configured inspection bound.';
        }
        return ['status' => $options->ocr || $partial ? 'partial' : 'completed', 'dataEgress' => 'none', 'signals' => $signals, 'limitations' => $limitations];
    }

    /** @return array{status: string, dataEgress: string, signals: list<array<string, mixed>>, limitations: list<string>} */
    private function inspectJpegTextMetadata(string $bytes, int $maximum, AiInspectionOptions $options): array
    {
        $limitations = [
            'Rules inspect JPEG COM comment segments and ASCII-encoded EXIF UserComment values only; visible pixels, XMP text, OCR output and other formats are not inspected.',
            'Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior.',
        ];
        $signals = [];
        $offset = 2;
        $consumed = 0;
        $partial = false;
        $total = strlen($bytes);
        while ($offset < $total) {
            if (ord($bytes[$offset]) !== 0xff) {
                $partial = true;
                break;
            }
            while ($offset < $total && ord($bytes[$offset]) === 0xff) {
                $offset++;
            }
            if ($offset >= $total) {
                $partial = true;
                break;
            }
            $marker = ord($bytes[$offset++]);
            if ($marker === 0xda || $marker === 0xd9) {
                break;
            }
            if ($marker === 0xd8 || $marker === 0x01 || ($marker >= 0xd0 && $marker <= 0xd7)) {
                continue;
            }
            if ($offset + 2 > $total) {
                $partial = true;
                break;
            }
            $length = (ord($bytes[$offset]) << 8) | ord($bytes[$offset + 1]);
            if ($length < 2 || $length > $total - $offset) {
                $partial = true;
                break;
            }
            $start = $offset + 2;
            $payloadLength = $length - 2;
            if ($marker === 0xfe || $marker === 0xe1) {
                $allowed = max(0, $maximum - $consumed);
                $inspectedLength = min($payloadLength, $allowed);
                if ($marker === 0xfe) {
                    $text = substr($bytes, $start, $inspectedLength);
                    $signal = $this->makeJpegSignal($text, $start, $inspectedLength, 'JPEG COM comment');
                    if ($signal !== null) {
                        $signals[] = $signal;
                    }
                } elseif (substr($bytes, $start, min(6, $inspectedLength)) === "Exif\0\0") {
                    $comment = $this->inspectAsciiExifUserComment($bytes, $start + 6, $start + $inspectedLength);
                    if ($comment['text'] !== null && $comment['offset'] !== null && $comment['length'] !== null) {
                        $signal = $this->makeJpegSignal($comment['text'], $comment['offset'], $comment['length'], 'JPEG EXIF UserComment');
                        if ($signal !== null) {
                            $signals[] = $signal;
                        }
                    }
                    $partial = $partial || $comment['partial'];
                }
                $consumed += $inspectedLength;
                if ($inspectedLength < $payloadLength) {
                    $partial = true;
                    break;
                }
            }
            $offset += $length;
        }
        if ($options->ocr) {
            $limitations[] = 'OCR was requested but is not implemented; only metadata text rules ran.';
        }
        if ($partial) {
            $limitations[] = 'JPEG comment/EXIF metadata was malformed, used an unsupported UserComment encoding, or exceeded the configured inspection bound.';
        }
        return [
            'status' => $options->ocr || $partial ? 'partial' : 'completed',
            'dataEgress' => 'none', 'signals' => $signals, 'limitations' => $limitations,
        ];
    }

    /** @return array<string, mixed>|null */
    private function makeJpegSignal(string $text, int $offset, int $length, string $source): ?array
    {
        foreach (self::PATTERNS as $pattern) {
            if (preg_match($pattern, $text) === 1) {
                return [
                    'id' => 'AI-002', 'severity' => 'medium', 'stage' => 'ai',
                    'title' => 'Instruction-like text in JPEG metadata',
                    'description' => $source . ' metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.',
                    'status' => 'suspected', 'controlStatus' => 'passed',
                    'evidence' => [[
                        'kind' => 'range', 'summary' => 'A bounded ' . $source . ' field matched a prompt-risk rule; field contents are redacted.',
                        'offset' => $offset, 'length' => $length,
                    ]],
                ];
            }
        }
        return null;
    }

    /** @return array{text: ?string, offset: ?int, length: ?int, partial: bool} */
    private function inspectAsciiExifUserComment(string $bytes, int $tiff, int $app1End): array
    {
        if ($app1End - $tiff < 8) {
            return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
        }
        $little = substr($bytes, $tiff, 2) === 'II';
        if (!$little && substr($bytes, $tiff, 2) !== 'MM') {
            return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
        }
        $read16 = static function (int $offset) use ($bytes, $app1End, $little): ?int {
            if ($offset < 0 || $offset + 2 > $app1End) {
                return null;
            }
            $unpacked = unpack($little ? 'vvalue' : 'nvalue', substr($bytes, $offset, 2));
            return $unpacked === false ? null : $unpacked['value'];
        };
        $read32 = static function (int $offset) use ($bytes, $app1End, $little): ?int {
            if ($offset < 0 || $offset + 4 > $app1End) {
                return null;
            }
            $unpacked = unpack($little ? 'Vvalue' : 'Nvalue', substr($bytes, $offset, 4));
            return $unpacked === false ? null : $unpacked['value'];
        };
        if ($read16($tiff + 2) !== 42) {
            return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
        }
        $readIfd = static function (int $relative) use ($tiff, $app1End, $read16): ?array {
            if ($relative < 8 || $relative > $app1End - $tiff - 2) {
                return null;
            }
            $start = $tiff + $relative;
            $count = $read16($start);
            if ($count === null || $count > 1024 || $start + 2 + $count * 12 + 4 > $app1End) {
                return null;
            }
            return ['start' => $start + 2, 'count' => $count];
        };
        $ifd0Relative = $read32($tiff + 4);
        $ifd0 = $ifd0Relative === null ? null : $readIfd($ifd0Relative);
        if ($ifd0 === null) {
            return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
        }
        $exifRelative = null;
        for ($index = 0; $index < $ifd0['count']; $index++) {
            $entry = $ifd0['start'] + $index * 12;
            if ($read16($entry) === 0x8769 && $read16($entry + 2) === 4 && $read32($entry + 4) === 1) {
                $exifRelative = $read32($entry + 8);
                break;
            }
        }
        if ($exifRelative === null) {
            return ['text' => null, 'offset' => null, 'length' => null, 'partial' => false];
        }
        $exifIfd = $readIfd($exifRelative);
        if ($exifIfd === null) {
            return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
        }
        for ($index = 0; $index < $exifIfd['count']; $index++) {
            $entry = $exifIfd['start'] + $index * 12;
            if ($read16($entry) !== 0x9286) {
                continue;
            }
            $byteCount = $read32($entry + 4);
            if ($read16($entry + 2) !== 7 || $byteCount === null || $byteCount < 8) {
                return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
            }
            $relative = $read32($entry + 8);
            if ($relative === null || $relative < 8 || $relative > $app1End - $tiff || $byteCount > $app1End - ($tiff + $relative)) {
                return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
            }
            $valueStart = $tiff + $relative;
            if (substr($bytes, $valueStart, 8) !== "ASCII\0\0\0") {
                return ['text' => null, 'offset' => null, 'length' => null, 'partial' => true];
            }
            return [
                'text' => substr($bytes, $valueStart + 8, $byteCount - 8),
                'offset' => $valueStart + 8, 'length' => $byteCount - 8, 'partial' => false,
            ];
        }
        return ['text' => null, 'offset' => null, 'length' => null, 'partial' => false];
    }

    /** @return array<string, mixed>|null */
    private function makePngExifSignal(string $text, int $offset, int $length): ?array
    {
        foreach (self::PATTERNS as $pattern) {
            if (preg_match($pattern, $text) === 1) {
                return [
                    'id' => 'AI-002', 'severity' => 'medium', 'stage' => 'ai',
                    'title' => 'Instruction-like text in PNG EXIF metadata',
                    'description' => 'PNG EXIF UserComment metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.',
                    'status' => 'suspected', 'controlStatus' => 'passed',
                    'evidence' => [[
                        'kind' => 'range', 'summary' => 'A bounded PNG EXIF UserComment field matched a prompt-risk rule; field contents are redacted.',
                        'offset' => $offset, 'length' => $length,
                    ]],
                ];
            }
        }
        return null;
    }

    /** @return array<string, mixed>|null */
    private function makeWebpExifSignal(string $text, int $offset, int $length): ?array
    {
        foreach (self::PATTERNS as $pattern) {
            if (preg_match($pattern, $text) === 1) {
                return [
                    'id' => 'AI-002', 'severity' => 'medium', 'stage' => 'ai',
                    'title' => 'Instruction-like text in WebP EXIF metadata',
                    'description' => 'WebP EXIF UserComment metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.',
                    'status' => 'suspected', 'controlStatus' => 'passed',
                    'evidence' => [[
                        'kind' => 'range', 'summary' => 'A bounded WebP EXIF UserComment field matched a prompt-risk rule; field contents are redacted.',
                        'offset' => $offset, 'length' => $length,
                    ]],
                ];
            }
        }
        return null;
    }

    /** @return array{start: int, length: int, text: string, compressed: bool}|null */
    private function extractText(string $bytes, int $start, int $end, string $kind, int $maximumTextBytes): ?array
    {
        $keywordEnd = strpos($bytes, "\0", $start);
        if ($keywordEnd === false || $keywordEnd >= $end) {
            return null;
        }
        $compressed = false;
        if ($kind === 'tEXt') {
            $textStart = $keywordEnd + 1;
        } elseif ($kind === 'zTXt') {
            if ($keywordEnd + 2 > $end || ord($bytes[$keywordEnd + 1]) !== 0) {
                return null;
            }
            $textStart = $keywordEnd + 2;
            $compressed = true;
        } else {
            if ($keywordEnd + 3 > $end || ord($bytes[$keywordEnd + 1]) > 1 || ord($bytes[$keywordEnd + 2]) !== 0) {
                return null;
            }
            $compressed = ord($bytes[$keywordEnd + 1]) === 1;
            $languageEnd = strpos($bytes, "\0", $keywordEnd + 3);
            if ($languageEnd === false || $languageEnd >= $end) {
                return null;
            }
            $translatedEnd = strpos($bytes, "\0", $languageEnd + 1);
            if ($translatedEnd === false || $translatedEnd >= $end) {
                return null;
            }
            $textStart = $translatedEnd + 1;
        }
        $length = $end - $textStart;
        $text = substr($bytes, $textStart, min($length, $maximumTextBytes));
        if ($compressed) {
            if ($maximumTextBytes < 1 || $length > $maximumTextBytes || !function_exists('zlib_decode')) {
                return null;
            }
            $decoded = @zlib_decode($text, $maximumTextBytes);
            if (!is_string($decoded)) {
                return null;
            }
            $text = $decoded;
        }

        return ['start' => $textStart, 'length' => $length, 'text' => $text, 'compressed' => $compressed];
    }
}
