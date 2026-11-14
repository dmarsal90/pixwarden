# Security policy

Report suspected vulnerabilities privately to the repository maintainers. Do not include untrusted image samples publicly when they contain private data. Until a security contact is configured, use GitHub's private vulnerability reporting for this repository.

This initial PHP package has a narrow byte-level profile. It does not decode, render, sanitize, or detect malware. A `valid` result only means the limited structural checks passed; consumers must treat partial coverage and unsupported controls as unresolved risk. The scanner does not execute input bytes or make network calls.
