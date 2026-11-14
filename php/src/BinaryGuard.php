<?php

declare(strict_types=1);

namespace Pixwarden;

/** Read-only signature indicators restricted to bounded container regions. */
final class BinaryGuard
{
    /** @return array{status: string, bytesScanned: int, findings: list<array<string, mixed>>, trailingData: bool, recursiveInspection: false} */
    public function inspect(string $bytes, string $format): array
    {
        $regions = [];
        $trailingData = false;
        $supported = true;
        $size = strlen($bytes);
        if ($format === 'png') {
            $cursor = 8;
            while ($cursor + 12 <= $size) {
                $length = $this->u32be($bytes, $cursor);
                if ($length > $size - $cursor - 12) {
                    break;
                }
                $type = substr($bytes, $cursor + 4, 4);
                $start = $cursor + 8;
                $end = $start + $length;
                if (ord($type[0]) >= 0x61 && ord($type[0]) <= 0x7a && $type !== 'IDAT') {
                    $regions[] = [$start, $end];
                }
                $cursor = $end + 4;
                if ($type === 'IEND') {
                    if ($cursor < $size) {
                        $regions[] = [$cursor, $size];
                        $trailingData = true;
                    }
                    break;
                }
            }
        } elseif ($format === 'jpeg') {
            $cursor = 2;
            $inScan = false;
            while ($cursor < $size) {
                if ($inScan) {
                    while ($cursor < $size && ord($bytes[$cursor]) !== 0xff) {
                        $cursor++;
                    }
                    while ($cursor < $size && ord($bytes[$cursor]) === 0xff) {
                        $cursor++;
                    }
                    if ($cursor >= $size) {
                        break;
                    }
                    $marker = ord($bytes[$cursor]);
                    if ($marker === 0 || ($marker >= 0xd0 && $marker <= 0xd7)) {
                        $cursor++;
                        continue;
                    }
                    $inScan = false;
                    $cursor--;
                }
                if (ord($bytes[$cursor]) !== 0xff) {
                    break;
                }
                while ($cursor < $size && ord($bytes[$cursor]) === 0xff) {
                    $cursor++;
                }
                if ($cursor >= $size) {
                    break;
                }
                $marker = ord($bytes[$cursor++]);
                if ($marker === 0xd9) {
                    if ($cursor < $size) {
                        $regions[] = [$cursor, $size];
                        $trailingData = true;
                    }
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
                $payloadStart = $cursor + 2;
                $payloadEnd = $cursor + $length;
                if (($marker >= 0xe0 && $marker <= 0xef) || $marker === 0xfe) {
                    $regions[] = [$payloadStart, $payloadEnd];
                }
                $cursor = $payloadEnd;
                if ($marker === 0xda) {
                    $inScan = true;
                }
            }
        } elseif ($format === 'gif') {
            if ($size >= 13) {
                $packed = ord($bytes[10]);
                $cursor = 13 + (($packed & 0x80) !== 0 ? 3 * (1 << (($packed & 7) + 1)) : 0);
                while ($cursor < $size) {
                    $marker = ord($bytes[$cursor++]);
                    if ($marker === 0x3b) {
                        if ($cursor < $size) {
                            $regions[] = [$cursor, $size];
                            $trailingData = true;
                        }
                        break;
                    }
                    if ($marker === 0x2c) {
                        if ($cursor + 9 > $size) {
                            break;
                        }
                        $flags = ord($bytes[$cursor + 8]);
                        $cursor += 9;
                        if (($flags & 0x80) !== 0) {
                            $cursor += 3 * (1 << (($flags & 7) + 1));
                        }
                        if ($cursor >= $size) {
                            break;
                        }
                        $cursor++;
                        $cursor = $this->skipSubBlocks($bytes, $cursor, false, $regions);
                    } elseif ($marker === 0x21) {
                        if ($cursor >= $size) {
                            break;
                        }
                        $label = ord($bytes[$cursor++]);
                        if ($label === 0xf9) {
                            if ($cursor + 6 > $size) {
                                break;
                            }
                            $regions[] = [$cursor + 1, $cursor + 5];
                            $cursor += 6;
                        } else {
                            $cursor = $this->skipSubBlocks($bytes, $cursor, true, $regions);
                        }
                    } else {
                        break;
                    }
                    if ($cursor >= $size) {
                        break;
                    }
                }
            }
        } elseif ($format === 'webp') {
            $limit = min($size, $this->u32le($bytes, 4) + 8);
            $cursor = 12;
            while ($cursor + 8 <= $limit) {
                $kind = substr($bytes, $cursor, 4);
                $length = $this->u32le($bytes, $cursor + 4);
                $start = $cursor + 8;
                $end = $start + $length;
                if ($end > $limit) {
                    break;
                }
                if (in_array($kind, ['EXIF', 'XMP ', 'ICCP'], true)) {
                    $regions[] = [$start, $end];
                }
                $cursor = $end + ($length & 1);
            }
            if ($limit < $size) {
                $regions[] = [$limit, $size];
                $trailingData = true;
            }
        } else {
            $supported = false;
        }

        $patterns = [
            'ZIP local-file header' => "PK\x03\x04",
            'DOS/Windows executable signature' => 'MZ',
            'ELF executable signature' => "\x7fELF",
            'PDF header' => "%PDF-",
        ];
        $findings = [];
        $bytesScanned = 0;
        foreach ($regions as [$start, $end]) {
            $bytesScanned += $end - $start;
            foreach ($patterns as $name => $pattern) {
                $offset = strpos($bytes, $pattern, $start);
                if ($offset === false || $offset + strlen($pattern) > $end) {
                    continue;
                }
                $findings[] = [
                    'id' => 'BIN-009', 'severity' => 'medium', 'stage' => 'binary',
                    'title' => 'Embedded format signature',
                    'description' => 'A ' . $name . ' byte signature occurs in the image input. This is an indicator only and does not establish that a complete payload is present.',
                    'status' => 'suspected', 'controlStatus' => 'passed',
                    'evidence' => [['kind' => 'range', 'summary' => 'Indicator: ' . $name, 'offset' => $offset, 'length' => strlen($pattern)]],
                ];
                break;
            }
        }
        return [
            'status' => !$supported ? 'unsupported' : ($findings !== [] ? 'findings' : 'passed'),
            'bytesScanned' => $bytesScanned,
            'findings' => $findings,
            'trailingData' => $trailingData,
            'recursiveInspection' => false,
        ];
    }

    /** @param list<array{int, int}> $regions */
    private function skipSubBlocks(string $bytes, int $cursor, bool $collect, array &$regions): int
    {
        $size = strlen($bytes);
        while ($cursor < $size) {
            $length = ord($bytes[$cursor++]);
            if ($length === 0) {
                break;
            }
            if ($length > $size - $cursor) {
                return $size;
            }
            if ($collect) {
                $regions[] = [$cursor, $cursor + $length];
            }
            $cursor += $length;
        }
        return $cursor;
    }

    private function u16be(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) * 256 + ord($bytes[$offset + 1]);
    }
    private function u32be(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) * 0x1000000 + ord($bytes[$offset + 1]) * 0x10000 + ord($bytes[$offset + 2]) * 0x100 + ord($bytes[$offset + 3]);
    }
    private function u32le(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) + ord($bytes[$offset + 1]) * 0x100 + ord($bytes[$offset + 2]) * 0x10000 + ord($bytes[$offset + 3]) * 0x1000000;
    }
}
