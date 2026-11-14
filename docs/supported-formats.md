# Supported formats

Support is intentionally narrower than the roadmap. “Inspect” means a bounded byte-level profile, not full standards validation or decodability.

| Format | Inspect | Decode | Transform | Current boundary |
|---|---:|---:|---|---|
| JPEG | Yes | No | None | Selected marker/segment profile; selective EXIF and auxiliary-region indicators |
| PNG | Yes | No | Remove eXIf/tEXt/zTXt/iTXt | Chunk order/bounds/CRC/dimension profile; preserves ICC/unknown ancillary and pixel stream |
| GIF | Yes | No | None | Block/frame structure; compressed LZW data is not decoded |
| WebP | Yes | No | None | RIFF/chunk profile; no bitstream decode |
| SVG | Yes | No | Static allowlist serialization | JS Saxes; PHP requires `ext-dom`; not a general renderer |
| AVIF, HEIF/HEIC, JPEG XL, TIFF/BigTIFF, PSD/PSB, OpenEXR, EPS/AI, ICO/CUR/ICNS, APNG, DICOM, GeoTIFF, TGA, PCX, PDF, XPS | No | No | No | Unsupported; PDF/XPS are document containers, not raster images |

Capabilities can vary by runtime/build and are reported by the engine. Unknown or unsupported formats must follow an explicit review/reject policy. Do not infer support from a filename or MIME label.
