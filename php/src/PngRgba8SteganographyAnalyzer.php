<?php

declare(strict_types=1);

namespace Pixwarden;

/** Descriptive, uncalibrated PNG RGBA8 statistics; not a steganography detector. */
final class PngRgba8SteganographyAnalyzer
{
    private const MAX_PIXELS = 1_000_000;
    private const LIMITATIONS = [
        'This profile reports descriptive statistics for static, non-interlaced 8-bit RGBA PNG pixels only; it does not detect steganography or classify an image as anomalous.',
        'Scores are uncalibrated descriptive measurements. They must not be interpreted as probability, evidence of hidden data, or a safe/unsafe verdict.',
        'The profile does not inspect palette images, animation, JPEG coefficients, cross-image channels, or methods designed to resist these statistics. Pixel values are preserved and hidden data is not removed.',
    ];

    /** @return array{status: string, methods: list<array<string, mixed>>, limitations: list<string>} */
    public function inspect(string $bytes, string $format, string $validity, SteganographyOptions $options): array
    {
        if (!$options->enabled || $options->mode !== 'statistical') {
            return ['status' => 'unsupported', 'methods' => $this->emptyMethods(), 'limitations' => [...self::LIMITATIONS, 'Statistical mode was not enabled or the requested steganography mode is unsupported.']];
        }
        if ($format !== 'png' || $validity !== 'valid') {
            return ['status' => 'unsupported', 'methods' => $this->emptyMethods(), 'limitations' => [...self::LIMITATIONS, 'The input is not a valid PNG profile supported by this statistical analyzer.']];
        }
        if (!function_exists('zlib_decode')) {
            return ['status' => 'unsupported', 'methods' => $this->emptyMethods(), 'limitations' => [...self::LIMITATIONS, 'The PHP zlib extension is required for this PNG pixel profile.']];
        }

        try {
            $reconstructed = (new PngRgba8Sanitizer())->sanitize($bytes)['bytes'];
            $width = $this->readU32BE($reconstructed, 16);
            $height = $this->readU32BE($reconstructed, 20);
            if ($width < 1 || $height < 1 || $width > intdiv(self::MAX_PIXELS, $height)) {
                return ['status' => 'unsupported', 'methods' => $this->emptyMethods(), 'limitations' => [...self::LIMITATIONS, 'PNG dimensions exceed the one-million-pixel statistical profile.']];
            }
            $expectedLength = $height * ($width * 4 + 1);
            $compressed = $this->collectIdat($reconstructed);
            $scanlines = zlib_decode($compressed, $expectedLength);
            if (!is_string($scanlines) || strlen($scanlines) !== $expectedLength) {
                throw new SanitizationFailureException('Reconstructed PNG scanlines failed their bounded statistics check.');
            }

            $pixels = $width * $height;
            $requested = min($options->maxSamples, $pixels);
            $step = max(1, intdiv($pixels + $requested - 1, $requested));
            $sampledPixels = intdiv($pixels + $step - 1, $step);
            $zeroBits = [0, 0, 0, 0];
            $oneBits = [0, 0, 0, 0];
            $transparentSamples = 0;
            $transparentNonzeroRgb = 0;
            $rowBytes = $width * 4;
            for ($pixelIndex = 0; $pixelIndex < $pixels; $pixelIndex += $step) {
                $row = intdiv($pixelIndex, $width);
                $column = $pixelIndex % $width;
                $rowOffset = $row * ($rowBytes + 1);
                if ($scanlines[$rowOffset] !== "\0") {
                    throw new SanitizationFailureException('Reconstructed PNG did not use filter 0.');
                }
                $pixelOffset = $rowOffset + 1 + $column * 4;
                for ($channel = 0; $channel < 4; $channel++) {
                    if ((ord($scanlines[$pixelOffset + $channel]) & 1) === 0) {
                        $zeroBits[$channel]++;
                    } else {
                        $oneBits[$channel]++;
                    }
                }
                if (ord($scanlines[$pixelOffset + 3]) === 0) {
                    $transparentSamples++;
                    if (ord($scanlines[$pixelOffset]) !== 0 || ord($scanlines[$pixelOffset + 1]) !== 0 || ord($scanlines[$pixelOffset + 2]) !== 0) {
                        $transparentNonzeroRgb++;
                    }
                }
            }

            $methods = [];
            foreach (['R', 'G', 'B', 'A'] as $channel => $label) {
                $methods[] = [
                    'id' => 'PNG_RGBA8_LSB_' . $label . '_BALANCE_V1',
                    'applicable' => true,
                    'status' => 'passed',
                    'samples' => $sampledPixels,
                    'score' => abs($zeroBits[$channel] - $oneBits[$channel]) / $sampledPixels,
                ];
            }
            $methods[] = [
                'id' => 'PNG_RGBA8_TRANSPARENT_RGB_V1',
                'applicable' => $transparentSamples > 0,
                'status' => $transparentSamples > 0 ? 'passed' : 'skipped',
                'samples' => $transparentSamples,
                'score' => $transparentSamples > 0 ? $transparentNonzeroRgb / $transparentSamples : 0,
            ];

            return ['status' => 'inconclusive', 'methods' => $methods, 'limitations' => self::LIMITATIONS];
        } catch (CapabilityUnavailableException|ResourceLimitExceededException) {
            return ['status' => 'unsupported', 'methods' => $this->emptyMethods(), 'limitations' => [...self::LIMITATIONS, 'The input does not fit the supported PNG RGBA8 profile or its resource bounds.']];
        } catch (PixwardenException) {
            return ['status' => 'error', 'methods' => $this->emptyMethods(), 'limitations' => [...self::LIMITATIONS, 'The bounded pixel-statistics pass could not complete; no statistic is available.']];
        }
    }

    /** @return list<array{id: string, applicable: bool, status: string, samples: int}> */
    private function emptyMethods(): array
    {
        $methods = [];
        foreach (['R', 'G', 'B', 'A'] as $channel) {
            $methods[] = ['id' => 'PNG_RGBA8_LSB_' . $channel . '_BALANCE_V1', 'applicable' => false, 'status' => 'unsupported', 'samples' => 0];
        }
        $methods[] = ['id' => 'PNG_RGBA8_TRANSPARENT_RGB_V1', 'applicable' => false, 'status' => 'unsupported', 'samples' => 0];

        return $methods;
    }

    private function collectIdat(string $bytes): string
    {
        $chunks = '';
        for ($offset = 8, $total = strlen($bytes); $offset + 12 <= $total;) {
            $length = $this->readU32BE($bytes, $offset);
            if ($length > $total - $offset - 12) {
                throw new SanitizationFailureException('Reconstructed PNG chunk exceeds output bounds.');
            }
            $type = substr($bytes, $offset + 4, 4);
            if ($type === 'IDAT') {
                $chunks .= substr($bytes, $offset + 8, $length);
            }
            $offset += $length + 12;
            if ($type === 'IEND') {
                break;
            }
        }

        return $chunks;
    }

    private function readU32BE(string $bytes, int $offset): int
    {
        $unpacked = unpack('Nvalue', substr($bytes, $offset, 4));
        if ($unpacked === false || !isset($unpacked['value']) || !is_int($unpacked['value'])) {
            throw new SanitizationFailureException('PNG integer exceeds the supported runtime range.');
        }

        return $unpacked['value'];
    }
}
