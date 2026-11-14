# Sanitization

## SVG

`sanitizeSvg` (JS) and `Scanner::sanitizeSvg` (PHP with `ext-dom`) serialize a conservative static allowlist and post-check the result. They reject malformed/DTD/processing-instruction input under the selected profile. This is not a renderer; renderer differences remain.

## PNG privacy transform

`stripPngExifAndTextMetadata` (JS) and `Scanner::stripPngExifAndTextMetadata` (PHP) remove `eXIf`, `tEXt`, `zTXt`, and `iTXt` chunks from structurally accepted PNGs up to 10 MiB and built-in dimension limits. They retain ICC profiles, unknown ancillary chunks, and all IDAT bytes. No decompression, pixel reconstruction, or complete metadata removal occurs. Input is not modified and output is structurally checked.

## Restricted RGBA8 raster reconstruction

`sanitizePngRgba8` (JS) and `Scanner::sanitizePngRgba8` (PHP) decode one restricted profile: static, non-interlaced, 8-bit RGBA PNG, no more than 1,000,000 pixels and 10 MiB input. They enforce a maximum inflated scanline size, reject malformed zlib streams/trailing compressed data, reconstruct filters, and emit only IHDR/IDAT/IEND before structural post-check. PHP requires `ext-zlib`. The input remains unchanged.

All ancillary chunks are removed, including ICC/gamma/color metadata. The RGBA sample bytes are reconstructed, but display color or appearance may change because color profiles and related interpretation chunks are discarded. Animation, grayscale, palette, RGB, interlaced, and other bit-depth profiles are unsupported. The limit bounds decompressed bytes but does not impose an OS CPU/RSS quota. Pixel steganography is not removed and output is not proof of benign pixels or safe downstream decoding. This is not a general-purpose raster sanitizer.
