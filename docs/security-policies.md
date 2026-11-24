# Security policies

Reports distinguish `validity`, `decodability`, `coverage`, `verdict`, controls, and findings. Current scans generally have partial coverage. `allow` describes the current engine decision; it does not mean threat-free or decoder-safe.

For public uploads, a conservative caller policy should quarantine results requiring review, reject malformed structures, fail closed when required controls are unsupported, and serve only a separately approved artifact with fixed content type and non-executable storage. Pixwarden does not provide a persisted policy engine or enforce your business decision.

The JS `requiredControls`, `unsupportedFormat`, and `incompleteAnalysis` options let callers tighten scan decisions. The PHP runtime has its own option set; see the `pixwarden-php` repository and do not assume JS options apply to it.
