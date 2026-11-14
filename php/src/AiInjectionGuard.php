<?php

declare(strict_types=1);

namespace Pixwarden;

/** Advisory, bounded prompt-risk rules for uncompressed PNG text metadata. */
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
            'Rules inspect only uncompressed PNG tEXt and iTXt fields; visible pixels, OCR output, compressed metadata and other formats are not inspected.',
            'Text matching is advisory and can miss paraphrased, encoded, multilingual, or visually embedded instructions; it cannot determine downstream model behavior.',
        ];
        if (!$options->enabled) {
            return ['status' => 'not_requested', 'dataEgress' => 'none', 'signals' => [], 'limitations' => $limitations];
        }
        if ($format !== 'png' || !str_starts_with($bytes, self::SIGNATURE)) {
            return ['status' => 'unsupported', 'dataEgress' => 'none', 'signals' => [], 'limitations' => [...$limitations, 'The input is not a PNG profile supported by this metadata rule set.']];
        }

        $signals = [];
        $offset = 8;
        $consumed = 0;
        $partial = false;
        $total = strlen($bytes);
        while ($offset + 12 <= $total && $consumed < $maximum) {
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
            if ($kind === 'tEXt' || $kind === 'iTXt') {
                $remaining = $maximum - $consumed;
                $allowed = $remaining > 0 ? $remaining : 0;
                $entry = $this->extractText($bytes, $payloadStart, $payloadEnd, $kind, $allowed);
                if ($entry !== null) {
                    if ($length > $allowed) {
                        $partial = true;
                    }
                    $consumed += min($length, $allowed);
                    foreach (self::PATTERNS as $pattern) {
                        $matched = preg_match($pattern, $entry['text']);
                        if ($matched === 1) {
                            $signals[] = [
                                'id' => 'AI-002', 'severity' => 'medium', 'stage' => 'ai',
                                'title' => 'Instruction-like text in PNG metadata',
                                'description' => 'Uncompressed PNG text metadata matches a narrow rule for instruction override or system-prompt disclosure language. The text was not included in the report.',
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
            } elseif ($kind === 'zTXt') {
                $partial = true;
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
            $limitations[] = 'Some PNG text metadata was malformed or exceeded the configured metadata inspection bound.';
        }

        return ['status' => $options->ocr || $partial ? 'partial' : 'completed', 'dataEgress' => 'none', 'signals' => $signals, 'limitations' => $limitations];
    }

    /** @return array{start: int, length: int, text: string}|null */
    private function extractText(string $bytes, int $start, int $end, string $kind, int $maximumTextBytes): ?array
    {
        $keywordEnd = strpos($bytes, "\0", $start);
        if ($keywordEnd === false || $keywordEnd >= $end) {
            return null;
        }
        if ($kind === 'tEXt') {
            $textStart = $keywordEnd + 1;
        } else {
            if ($keywordEnd + 3 > $end || ord($bytes[$keywordEnd + 1]) !== 0 || ord($bytes[$keywordEnd + 2]) !== 0) {
                return null;
            }
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

        return ['start' => $textStart, 'length' => $length, 'text' => $text];
    }
}
