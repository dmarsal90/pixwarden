<?php

declare(strict_types=1);

namespace Pixwarden;

/** Bounded EXIF/TIFF directory inspection; values are never extracted. */
final class MetadataGuard
{
    /** @return array{status: string, metadataBytes: int, entriesInspected: int, findings: list<array<string, mixed>>} */
    public function inspect(string $bytes, string $format, int $maxBytes): array
    {
        if (!in_array($format, ['jpeg', 'png', 'webp'], true)) {
            return ['status' => 'unsupported', 'metadataBytes' => 0, 'entriesInspected' => 0, 'findings' => []];
        }
        $findings = [];
        $metadataBytes = 0;
        $entriesInspected = 0;
        foreach ($this->exifRanges($bytes, $format) as [$start, $end]) {
            $permittedEnd = min($end, $start + max(0, $maxBytes - $metadataBytes));
            $metadataBytes += $permittedEnd - $start;
            $result = $this->inspectTiff($bytes, $start, $permittedEnd);
            $entriesInspected += $result['entries'];
            if ($result['malformed'] && $permittedEnd === $end) {
                $findings[] = $this->finding('META-001', 'high', 'Malformed EXIF TIFF structure', 'An EXIF TIFF header or IFD table is invalid or out of bounds.', $start, $end - $start);
            }
            $names = [0x8825 => 'GPSInfoIFDPointer', 0xa430 => 'OwnerName', 0xa431 => 'BodySerialNumber', 0xa435 => 'LensSerialNumber'];
            foreach ($result['sensitive'] as [$id, $offset]) {
                $findings[] = $this->finding('META-007', 'medium', 'Potentially sensitive EXIF tag', 'EXIF contains the ' . $names[$id] . ' tag; its value was not extracted.', $offset, 12);
            }
            if ($metadataBytes >= $maxBytes) {
                break;
            }
        }
        return ['status' => 'partial', 'metadataBytes' => $metadataBytes, 'entriesInspected' => $entriesInspected, 'findings' => $findings];
    }

    /** @return list<array{int, int}> */
    private function exifRanges(string $bytes, string $format): array
    {
        $ranges = [];
        $size = strlen($bytes);
        if ($format === 'jpeg') {
            $cursor = 2;
            while ($cursor + 4 <= $size && ord($bytes[$cursor]) === 0xff) {
                while ($cursor < $size && ord($bytes[$cursor]) === 0xff) {
                    $cursor++;
                }
                if ($cursor >= $size) {
                    break;
                }
                $marker = ord($bytes[$cursor++]);
                if ($marker === 0xd9 || $marker === 0xda) {
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
                $start = $cursor + 2;
                $end = $cursor + $length;
                if ($marker === 0xe1 && substr($bytes, $start, 6) === "Exif\0\0") {
                    $ranges[] = [$start + 6, $end];
                }
                $cursor = $end;
            }
        } elseif ($format === 'png' && $size >= 8) {
            $cursor = 8;
            while ($cursor + 12 <= $size) {
                $length = $this->u32be($bytes, $cursor);
                if ($length > $size - $cursor - 12) {
                    break;
                }
                $kind = substr($bytes, $cursor + 4, 4);
                $start = $cursor + 8;
                if ($kind === 'eXIf') {
                    $ranges[] = [$start, $start + $length];
                }
                $cursor += 12 + $length;
                if ($kind === 'IEND') {
                    break;
                }
            }
        } elseif ($format === 'webp' && $size >= 12 && substr($bytes, 0, 4) === 'RIFF' && substr($bytes, 8, 4) === 'WEBP') {
            $containerEnd = min($size, $this->u32le($bytes, 4) + 8);
            $cursor = 12;
            while ($cursor + 8 <= $containerEnd) {
                $kind = substr($bytes, $cursor, 4);
                $length = $this->u32le($bytes, $cursor + 4);
                $start = $cursor + 8;
                $end = $start + $length;
                if ($end > $containerEnd) {
                    break;
                }
                if ($kind === 'EXIF') {
                    $ranges[] = [$length >= 6 && substr($bytes, $start, 6) === "Exif\0\0" ? $start + 6 : $start, $end];
                }
                $cursor = $end + ($length & 1);
            }
        }
        return $ranges;
    }

    /** @return array{entries: int, malformed: bool, sensitive: list<array{int, int}>} */
    private function inspectTiff(string $bytes, int $start, int $end): array
    {
        if ($end - $start < 8) {
            return ['entries' => 0, 'malformed' => true, 'sensitive' => []];
        }
        $byteOrder = substr($bytes, $start, 2);
        if ($byteOrder !== 'II' && $byteOrder !== 'MM') {
            return ['entries' => 0, 'malformed' => true, 'sensitive' => []];
        }
        $little = $byteOrder === 'II';
        $read16 = fn (int $offset): int => $little ? $this->u16le($bytes, $offset) : $this->u16be($bytes, $offset);
        $read32 = fn (int $offset): int => $little ? $this->u32le($bytes, $offset) : $this->u32be($bytes, $offset);
        if ($read16($start + 2) !== 42) {
            return ['entries' => 0, 'malformed' => true, 'sensitive' => []];
        }
        $queue = [$read32($start + 4)];
        $visited = [];
        $sensitive = [];
        $entries = 0;
        while ($queue !== [] && count($visited) < 8 && $entries < 1024) {
            $relative = array_shift($queue);
            if (in_array($relative, $visited, true)) {
                continue;
            }
            $visited[] = $relative;
            $ifd = $start + $relative;
            if ($relative < 8 || $ifd + 2 > $end) {
                return ['entries' => $entries, 'malformed' => true, 'sensitive' => $sensitive];
            }
            $count = $read16($ifd);
            if ($count > 1024 || $ifd + 2 + $count * 12 + 4 > $end) {
                return ['entries' => $entries, 'malformed' => true, 'sensitive' => $sensitive];
            }
            for ($index = 0; $index < $count; $index++) {
                $entry = $ifd + 2 + $index * 12;
                $tag = $read16($entry);
                $type = $read16($entry + 2);
                $valueCount = $read32($entry + 4);
                $entries++;
                if (in_array($tag, [0x8825, 0xa430, 0xa431, 0xa435], true)) {
                    $sensitive[] = [$tag, $entry];
                }
                if (in_array($tag, [0x8769, 0x8825, 0xa005], true) && $type === 4 && $valueCount === 1) {
                    $pointer = $read32($entry + 8);
                    if ($pointer !== 0) {
                        $queue[] = $pointer;
                    }
                }
            }
            $next = $read32($ifd + 2 + $count * 12);
            if ($next !== 0) {
                $queue[] = $next;
            }
        }
        return ['entries' => $entries, 'malformed' => $queue !== [], 'sensitive' => $sensitive];
    }

    /** @return array<string, mixed> */
    private function finding(string $id, string $severity, string $title, string $description, int $offset, int $length): array
    {
        return [
            'id' => $id, 'severity' => $severity, 'stage' => 'metadata', 'title' => $title,
            'description' => $description, 'status' => $id === 'META-001' ? 'confirmed' : 'suspected',
            'controlStatus' => $id === 'META-001' ? 'failed' : 'passed',
            'evidence' => [['kind' => 'range', 'summary' => $description, 'offset' => $offset, 'length' => $length]],
        ];
    }

    private function u16be(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) * 256 + ord($bytes[$offset + 1]);
    }
    private function u16le(string $bytes, int $offset): int
    {
        return ord($bytes[$offset]) + ord($bytes[$offset + 1]) * 256;
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
