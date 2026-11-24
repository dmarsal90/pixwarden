# Security Policy

Pixwarden is under active development. Do not rely on it as the only security control for untrusted uploads. Scan APIs inspect a limited set of container structures and do not invoke image decoders or fully scan image contents. Separate sanitizers include SVG allowlisting, PNG metadata removal, and restricted static RGBA8 PNG reconstruction.

## Reporting

Report suspected vulnerabilities privately through this repository's GitHub Security tab ("Report a vulnerability"). Include the affected commit/package version, runtime/platform, minimal harmless reproducer, expected and observed behavior, and any constraints. Do not include live malware or personal image data. A public disclosure timeline will be coordinated after a fix is available.

## Scope and limitations

This project is not an antivirus, and its signatures are not malware verdicts. Structural acceptance applies only to the documented profile. General raster decoders, OCR/model adapters, and steganography detection are not present. `sanitizePngRgba8`/`Scanner::sanitizePngRgba8` support only static non-interlaced RGBA8 PNGs up to one million pixels; they strip ancillary/color metadata, may change appearance, and do not remove pixel-level hidden content. PHP requires optional `ext-zlib`. The bounded output size does not enforce OS CPU/RSS quotas. `scanImageIsolated` runs the current pure-JS scan in a terminable worker with a wall-clock timeout and V8 old-generation heap ceiling; it does not enforce OS CPU quotas or total RSS. SVG sanitization is limited to a conservative allowlist. Deployments must retain upload authorization, quarantine, non-executable storage, response MIME controls, dependency patching, and process isolation with OS quotas for downstream decoders or stronger hostile-workload containment.
