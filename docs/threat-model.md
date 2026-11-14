# Threat model

## Assets and principals

Assets include application availability, parser integrity, user privacy, stored uploads, and downstream model/tool decisions. Attackers can submit arbitrary bytes and caller-controlled names/media types. The integrating application owns authorization, storage, serving, queues, and model permissions.

## In scope

Malformed and ambiguous structures in enabled JPEG/PNG/GIF/WebP profiles; selected metadata and auxiliary regions; SVG active features under the sanitizer profile; resource declarations; and misuse of findings or capability status.

## Out of scope today

General malware detection, full format conformance, decoder exploitation (no raster decoder is invoked), universal polyglot detection, universal steganography detection, OCR/VLM prompt injection, adversarial model robustness, remote URL retrieval, and application deployment controls.

## Security assumptions

Inputs are copied or read into bounded memory. Parsers use checked boundaries in the declared profile. Transform output is independently rechecked. A caller does not treat partial coverage as a clean bill of health. Native decoders used downstream are separately isolated, patched, and resource constrained.

## Residual risk and response

False positives and false negatives remain possible; parser behavior may differ from downstream renderers. Keep uploads quarantined until application policy permits use. Report vulnerabilities using [SECURITY.md](../SECURITY.md), with harmless minimal reproductions and no private image data.
