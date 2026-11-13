# Security Policy

Pixwarden is under active development. Do not rely on it as the only security control for untrusted uploads. The current JS package inspects a limited set of container structures and does not decode, sanitize, execute, or fully scan image contents.

## Reporting

Report suspected vulnerabilities privately to the repository maintainers. Include the affected commit/package version, runtime/platform, minimal harmless reproducer, expected and observed behavior, and any constraints. Do not include live malware or personal image data. A public disclosure timeline will be coordinated after a fix is available.

## Scope and limitations

This project is not an antivirus, and its signatures are not malware verdicts. Structural acceptance applies only to the documented profile. Native decoders, OCR/model adapters, steganography detection, SVG sanitization, and hard CPU/memory isolation are not present in this first JS implementation. Deployments must retain upload authorization, quarantine, non-executable storage, response MIME controls, dependency patching, and process isolation where needed.
