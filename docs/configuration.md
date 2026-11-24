# Configuration

## JS scan options

`scanImage(bytes, options)` accepts optional `structural`, `binaryInspection`, and `metadata` booleans; `hints` with a filename and/or media type; `limits`; `requiredControls`; `unsupportedFormat`; `incompleteAnalysis`; and an `AbortSignal`. `scanImageIsolated` additionally accepts a worker timeout and V8 old-generation heap ceiling. The worker is not an OS process and its heap setting is not an RSS quota.

Default maxima are 10 MiB input, 40,000 width, 40,000 height, 40 million pixels, 200 frames, and 1 MiB metadata. Limits may be lowered, not raised above built-in maxima. `scanImageStream` buffers up to the byte limit and cannot impose a timeout on an uncooperative source.

Runtime validation rejects unknown option keys, wrong value types, duplicate or unknown required controls, unsupported policy actions, and unregistered `aiInspection.adapterId` values. Stream calls validate configuration before pulling the first chunk; isolated scans validate isolation options before starting a worker.

## Decision handling

Treat `allow`, `review`, `reject`, `coverage`, each control status, and findings as separate inputs to the application policy. `allow` is not proof of safety. Never upgrade `unsupported`, `skipped`, or `error` controls to `passed` in application code.
