# Sanitization

## SVG

`sanitizeSvg` (JS) and `Scanner::sanitizeSvg` (PHP with `ext-dom`) serialize a conservative static allowlist and post-check the result. They reject malformed/DTD/processing-instruction input under the selected profile. This is not a renderer; renderer differences remain.

## PNG privacy transform

`stripPngExifAndTextMetadata` (JS) and `Scanner::stripPngExifAndTextMetadata` (PHP) remove `eXIf`, `tEXt`, `zTXt`, and `iTXt` chunks from structurally accepted PNGs up to 10 MiB and built-in dimension limits. They retain ICC profiles, unknown ancillary chunks, and all IDAT bytes. No decompression, pixel reconstruction, or complete metadata removal occurs. Input is not modified and output is structurally checked.

## Raster canonicalization

**Not implemented.** There is no raster decoder/re-encoder. Neither operation proves that pixels are benign, removes pixel steganography, or neutralizes vulnerabilities in a downstream decoder. Do not call either operation a general-purpose raster sanitizer.
