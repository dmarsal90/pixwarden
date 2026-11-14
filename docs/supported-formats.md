# Supported formats

Support is intentionally narrower than the roadmap. “Inspect” means a bounded byte-level profile, not full standards validation or decodability.

| Format | Inspect | Decode | Transform | Current boundary |
|---|---:|---:|---|---|
| JPEG | Yes | No | None | Selected marker/segment profile; selective EXIF and auxiliary-region indicators |
| PNG | Yes | Restricted | Remove eXIf/tEXt/zTXt/iTXt; reconstruct RGBA8 | Raster transform supports static, non-interlaced 8-bit RGBA only, up to 1 million pixels and 10 MiB input; it drops all ancillary chunks including ICC and may change color appearance |
| GIF | Yes | No | None | Block/frame structure; compressed LZW data is not decoded |
| WebP | Yes | No | None | RIFF/chunk profile; no bitstream decode |
| SVG | Yes | No | Static allowlist serialization | JS Saxes; PHP requires `ext-dom`; not a general renderer |
| AVIF, HEIF/HEIC, JPEG XL, TIFF/BigTIFF, PSD/PSB, OpenEXR, EPS/AI, ICO/CUR/ICNS, APNG, DICOM, GeoTIFF, TGA, PCX, PDF, XPS | No | No | No | Unsupported; PDF/XPS are document containers, not raster images |

Capabilities can vary by runtime/build and are reported by the engine. Unknown or unsupported formats must follow an explicit review/reject policy. Do not infer support from a filename or MIME label.
