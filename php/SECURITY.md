# Security policy

Report suspected vulnerabilities privately to the repository maintainers. Do not include untrusted image samples publicly when they contain private data. Until a security contact is configured, use GitHub's private vulnerability reporting for this repository.

This PHP package has narrow byte-level profiles. It does not decode raster images or detect malware. A `valid` result only means the limited structural checks passed; consumers must treat partial coverage and unsupported controls as unresolved risk. The optional `ext-dom` SVG path parses XML without external network access, applies a static allowlist, and post-checks the emitted bytes; it is not a general SVG renderer. The scanner does not execute input bytes or make network calls.
