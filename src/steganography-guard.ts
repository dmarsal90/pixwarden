import { inflateSync } from "node:zlib";
import { sanitizePngRgba8 } from "./png-raster-sanitizer.js";
import { PixwardenError, type SteganographyOptions, type SteganographyResult } from "./types.js";

const maxPixels = 1_000_000;
const maxSamples = 1_000_000;

export function inspectPngRgba8Steganography(input: Uint8Array, options: SteganographyOptions): SteganographyResult {
  const emptyMethods = [
    { id: "PNG_RGBA8_LSB_R_BALANCE_V1", applicable: false, status: "unsupported" as const, samples: 0 },
    { id: "PNG_RGBA8_LSB_G_BALANCE_V1", applicable: false, status: "unsupported" as const, samples: 0 },
    { id: "PNG_RGBA8_LSB_B_BALANCE_V1", applicable: false, status: "unsupported" as const, samples: 0 },
    { id: "PNG_RGBA8_LSB_A_BALANCE_V1", applicable: false, status: "unsupported" as const, samples: 0 },
    { id: "PNG_RGBA8_TRANSPARENT_RGB_V1", applicable: false, status: "unsupported" as const, samples: 0 }
  ];
  const limitations = [
    "This profile reports descriptive statistics for static, non-interlaced 8-bit RGBA PNG pixels only; it does not detect steganography or classify an image as anomalous.",
    "Scores are uncalibrated descriptive measurements. They must not be interpreted as probability, evidence of hidden data, or a safe/unsafe verdict.",
    "The profile does not inspect palette images, animation, JPEG coefficients, cross-image channels, or methods designed to resist these statistics. Pixel values are preserved and hidden data is not removed."
  ];
  if (!options.enabled || options.mode !== "statistical") {
    return { status: "unsupported", methods: emptyMethods, limitations: [...limitations, "Statistical mode was not enabled or the requested steganography mode is unsupported."] };
  }
  try {
    const reconstructed = sanitizePngRgba8(input).bytes;
    const width = readU32BE(reconstructed, 16);
    const height = readU32BE(reconstructed, 20);
    if (width < 1 || height < 1 || width > Math.floor(maxPixels / height)) {
      return { status: "unsupported", methods: emptyMethods, limitations: [...limitations, "PNG dimensions exceed the one-million-pixel statistical profile."] };
    }
    const expectedBytes = height * (width * 4 + 1);
    const compressed = collectIdat(reconstructed);
    const scanlines = inflateSync(compressed, { maxOutputLength: expectedBytes });
    if (scanlines.byteLength !== expectedBytes) throw new Error("Unexpected sanitized scanline size");

    const pixels = width * height;
    const requested = Math.min(options.maxSamples ?? 100_000, pixels);
    const step = Math.max(1, Math.ceil(pixels / requested));
    const sampledPixels = Math.ceil(pixels / step);
    const zeroBits = [0, 0, 0, 0];
    const oneBits = [0, 0, 0, 0];
    let transparentSamples = 0;
    let transparentNonzeroRgb = 0;
    const rowBytes = width * 4;
    for (let pixelIndex = 0; pixelIndex < pixels; pixelIndex += step) {
      const row = Math.floor(pixelIndex / width);
      const column = pixelIndex % width;
      const offset = row * (rowBytes + 1);
      if (scanlines[offset] !== 0) throw new Error("Sanitized PNG did not use filter 0");
      const pixelOffset = offset + 1 + column * 4;
      for (let channel = 0; channel < 4; channel++) {
        if ((scanlines[pixelOffset + channel]! & 1) === 0) zeroBits[channel]!++;
        else oneBits[channel]!++;
      }
      if (scanlines[pixelOffset + 3] === 0) {
        transparentSamples++;
        if (scanlines[pixelOffset] !== 0 || scanlines[pixelOffset + 1] !== 0 || scanlines[pixelOffset + 2] !== 0) transparentNonzeroRgb++;
      }
    }
    const channels = ["R", "G", "B", "A"];
    const methods: SteganographyResult["methods"][number][] = channels.map((channel, index) => ({
      id: `PNG_RGBA8_LSB_${channel}_BALANCE_V1`,
      applicable: true,
      status: "passed" as const,
      samples: sampledPixels,
      score: Math.abs(zeroBits[index]! - oneBits[index]!) / sampledPixels
    }));
    methods.push({
      id: "PNG_RGBA8_TRANSPARENT_RGB_V1",
      applicable: transparentSamples > 0,
      status: transparentSamples > 0 ? "passed" as const : "skipped" as const,
      samples: transparentSamples,
      score: transparentSamples > 0 ? transparentNonzeroRgb / transparentSamples : 0
    });
    return { status: "inconclusive", methods, limitations };
  } catch (error) {
    const unsupported = error instanceof PixwardenError && ["UNSUPPORTED_CAPABILITY", "LIMIT_EXCEEDED", "INPUT_TOO_LARGE"].includes(error.code);
    return {
      status: unsupported ? "unsupported" : "error",
      methods: emptyMethods,
      limitations: [...limitations, unsupported ? "The input does not fit the supported PNG RGBA8 profile or its resource bounds." : "The bounded pixel-statistics pass could not complete; no statistic is available."]
    };
  }
}

function collectIdat(bytes: Uint8Array): Buffer {
  const chunks: Buffer[] = [];
  let offset = 8;
  while (offset + 12 <= bytes.byteLength) {
    const length = readU32BE(bytes, offset);
    const type = String.fromCharCode(bytes[offset + 4]!, bytes[offset + 5]!, bytes[offset + 6]!, bytes[offset + 7]!);
    if (length > bytes.byteLength - offset - 12) throw new Error("Sanitized PNG chunk exceeds output bounds");
    if (type === "IDAT") chunks.push(Buffer.from(bytes.subarray(offset + 8, offset + 8 + length)));
    offset += length + 12;
    if (type === "IEND") break;
  }
  return Buffer.concat(chunks);
}

function readU32BE(bytes: Uint8Array, offset: number): number {
  return bytes[offset]! * 0x1000000 + bytes[offset + 1]! * 0x10000 + bytes[offset + 2]! * 0x100 + bytes[offset + 3]!;
}
