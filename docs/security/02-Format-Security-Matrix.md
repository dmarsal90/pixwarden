# Format Security Matrix

**Document ID:** PW-FORMAT · **Version:** 0.1.0 · **Status:** Initial profile; no decoders enabled · **Reviewed:** 2026-11-13

This is a planning matrix, not a promise of support. Exact specifications and decoder versions must be researched and pinned before implementation. File signatures are partial identifiers and must be combined with structure parsing and policy. All formats default to no automatic native decoder enablement. `Core` means initial byte-inspection priority only.

| Format | Specification / signature family | Structure and metadata / active surface | Candidate libraries (not selected) | Risks and proposed inspection/sanitization | Default |
|---|---|---|---|---|---|
| JPEG | ISO/IEC 10918; SOI `FF D8`, marker stream, EOI | APP segments, EXIF/XMP/ICC, comments; trailing bytes | libjpeg-turbo, GD, libvips | Segment lengths/order, polyglot/tail, metadata; decode to new raster only in worker | Core inspect; decode opt-in |
| PNG | ISO/IEC 15948; 8-byte PNG signature, chunks/CRC/IEND | Ancillary/text/ICC chunks, animation extensions | libpng, GD, libvips | Chunk order/length/CRC, trailing data, text payload; strip unknown metadata/re-encode | Core inspect; decode opt-in |
| GIF | GIF89a/87a signatures, blocks/trailer | Comments, extensions, palettes, frame sequence | giflib, GD, libvips | Frame count, extension payload, disposal/timing; preserve/flatten explicitly | Core inspect; decode opt-in |
| WebP | RIFF/WEBP container | VP8/VP8L/VP8X, EXIF/XMP/ICC, ANIM/ANMF | libwebp, libvips | RIFF lengths, chunks, animation and metadata; worker decode | Core inspect; decode opt-in |
| SVG | W3C SVG XML vocabulary; XML root/namespace | Script, event attributes, CSS/URL refs, foreignObject, data URLs | hardened XML parser; sanitizer adapter | DTD/XXE, active document behavior, parser differentials; namespace allowlist serialization | Core secure inspect/sanitize |
| BMP | Microsoft/OS2 DIB headers; `BM` commonly | Header variants, palettes, masks, possible gaps | platform codecs, libvips | Header-size variants, offsets, overflow; optional raster conversion | Unsupported by default |
| AVIF | ISO BMFF / AV1 image item; `ftyp` brands | Item/property boxes, metadata, sequences | libavif, libheif, libvips | Box lengths, profiles, auxiliary images, native decoder exposure | Unsupported; adapter review |
| HEIF | ISO BMFF / HEIF brands | Items, sequences, EXIF/XMP, auxiliary content | libheif, platform frameworks | Complex box/item references, codec dependencies, resource use | Unsupported; adapter review |
| HEIC | HEIF with HEVC coding | HEIF boxes plus HEVC decoder | libheif + HEVC codec | Codec supply-chain/licensing and native parsing | Unsupported; adapter review |
| JPEG XL | ISO/IEC 18181; codestream/container signatures | Metadata, animation, boxes | libjxl | Container/codestream parser and resource consumption | Unsupported; adapter review |
| TIFF | TIFF 6.0 byte order + IFD offsets | Chains/graphs of IFDs, EXIF, pages, compression | libtiff, libvips | Offset graph, compression bombs, pages/tiles; strict depth/count | Unsupported; adapter review |
| BigTIFF | TIFF extension with 64-bit offsets | Large IFD offsets, tiled/pyramidal data | libtiff, libvips | Wide integer arithmetic/huge dimensions | Unsupported; adapter review |
| PSD | Adobe PSD format; `8BPS` | Layers, channels, previews, metadata | psd parsers, ImageMagick | Large layered structures, preview disagreement | Unsupported; no default decoder |
| PSB | Large-document PSD variant | 64-bit lengths/layers | ImageMagick/other specialized codecs | Large lengths and nested layer resources | Unsupported; no default decoder |
| OpenEXR | Academy OpenEXR spec; magic `76 2f 31 01` | Multipart/deep/tiled/channel data | OpenEXR | Deep data amplification, huge channels/tiles | Unsupported; no default decoder |
| SVGZ | Gzip-compressed SVG | Decompress then SVG/XML surfaces | gzip + hardened XML | Expansion ratio/size plus SVG risks; bounded decompression | Unsupported; separate adapter |
| EPS | Adobe PostScript encapsulation | PostScript language/delegates, previews | Ghostscript/ImageMagick | Active code/delegate execution and file/network access | Reject by default |
| AI | Adobe Illustrator often PDF/EPS-based | Compound/document semantics | vendor tools | PostScript/PDF surfaces, opaque variants | Reject/unsupported |
| ICO | Windows icon directory; `00 00 01 00` | Multiple embedded images/planes | platform codecs | Entry offsets/count and nested raster formats | Unsupported; adapter review |
| CUR | Cursor directory; `00 00 02 00` | Icon-like entries plus hotspot | platform codecs | Same as ICO plus hotspot consistency | Unsupported; adapter review |
| ICNS | Apple icon container; `icns` | Typed chunks, multiple resolutions | platform codecs | Chunk sizes and nested formats | Unsupported; adapter review |
| APNG | PNG plus animation control/frame chunks | PNG chunks, frame sequence | libpng-based tools/libvips | Frame count/order, fallback image mismatch | Inspect under PNG; animation decode opt-in |
| Animated GIF | GIF image descriptors/extensions | Per-frame palettes/timing/disposal | giflib/libvips | Frame explosion, timing/disposal differences | Inspect under GIF; bounded decode opt-in |
| Animated WebP | WebP ANIM/ANMF chunks | Frame sequence and metadata | libwebp/libvips | Frame counts and nested frame data | Inspect under WebP; bounded decode opt-in |
| Animated AVIF | ISO BMFF sequence | Sequence tracks/items | libavif/libheif | Complex sequence structures, native decoder | Unsupported |
| DICOM | DICOM PS3.10 and transfer syntax | Pixel data plus extensive sensitive patient metadata | DCMTK, GDCM | PHI/privacy, transfer syntaxes, encapsulated payloads | Reject/unsupported; medical profile needed |
| GeoTIFF | TIFF plus OGC geospatial tags | Coordinates, tiled/pyramidal data | libtiff, GDAL | TIFF risks plus sensitive geolocation | Unsupported; specialized adapter |
| TGA | Truevision TGA layout | Header, palette, optional RLE | specialized parsers | Length/packet bounds | Unsupported |
| PCX | ZSoft PCX header/RLE | Plane and row compression | specialized parsers | RLE expansion and malformed dimensions | Unsupported |
| PDF | ISO 32000 document container | Objects, streams, actions, attachments, JS | PDFium, MuPDF, Poppler | Document active content, decompression, object graph; not image parser | Reject as wrong category |
| XPS | ECMA-388 / Open Packaging Conventions ZIP-like package | XML, relationships, resources | platform document stacks | Package expansion, XML, relationships; not image parser | Reject as wrong category |

## Policy and adapter gate

An adapter proposal must name exact parser/decoder, versions and transitive native libraries; upstream security policy; supported subfeatures; format corpus; fuzz target; resource enforcement; license; platform/build matrix; sanitization fidelity; and whether its capability is equal in PHP and JS. A PHP GD decoder is build-dependent (PHP docs enumerate supported types conditionally); ImageMagick requires an explicit restrictive policy. These are candidates only, not dependencies selected by this baseline.

## References

[PNG specification](https://www.w3.org/TR/png-3/), [W3C SVG 2](https://www.w3.org/TR/SVG2/), [WebP RIFF container](https://developers.google.com/speed/webp/docs/riff_container), [JPEG XL](https://jpeg.org/jpegxl/), [TIFF 6.0 (Adobe PDF)](https://www.adobe.io/content/dam/udp/en/open/standards/tiff/TIFF6.pdf), [OpenEXR documentation](https://openexr.com/en/latest/), [DICOM standard](https://www.dicomstandard.org/current), [JSON Schema-independent file upload guidance](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [ImageMagick security policy](https://imagemagick.org/security-policy/), [PHP GD format variability](https://www.php.net/manual/en/book.image.php). Consulted 2026-11-13. Exact spec edition and applicable profile must be verified during each adapter phase.
