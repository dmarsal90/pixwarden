# Pixwarden Shared Backend Schema Contracts

**Document ID:** PW-SCHEMA · **Version:** 0.1.0 · **Status:** Draft contract baseline · **Updated:** 2026-11-13

This is the normative semantic outline for JSON Schema Draft 2020-12 artifacts. A first combined schema is maintained at `spec/schemas/pixwarden-v1.schema.json` in this checkout; individual `$defs` are the public contract targets for the initial spec release. All objects use `additionalProperties: false` unless an explicitly extensible map says otherwise. All sizes are non-negative integers in bytes; timestamps are RFC 3339. Schema IDs use a local `urn:pixwarden:spec:0.1.0` namespace until the project controls a stable public schema domain.

## Shared enums

* `Verdict`: `allow | sanitize | reject | review`.
* `ControlStatus`: `passed | failed | skipped | unsupported | error`.
* `Severity`: `info | low | medium | high | critical`.
* `Confidence`: number 0..1 only for probabilistic detectors; absent for deterministic checks. It is not a probability of safety.
* `Format`: `jpeg | png | gif | webp | svg | bmp | avif | heif | heic | jxl | tiff | bigtiff | psd | psb | openexr | svgz | eps | ai | ico | cur | icns | apng | dicom | geotiff | tga | pcx | pdf | xps | unknown`.
* `Stage`: `receive | identify | structural | metadata | active_content | binary | steganography | resource | decode | sanitize | ai | postcheck | policy | report`.

## Contracts

### ScanRequest

Required: `requestVersion` (const `1`), `input` (exactly one of inline base64 bytes or caller-owned opaque `inputRef`; schema variants), `options` (`ScanOptions`), optional `hints` (`filename` max 255 Unicode scalar values; `mediaType` max 127 chars). Never accept remote URL fields. Example: `{"requestVersion":1,"input":{"base64":"iVBORw0KGgo="},"options":{"structural":true}}`.

### ScanOptions

Fields: booleans `structural`, `metadata`, `binaryInspection`, `sanitize`; optional JS convenience field `hints` (`ScanHints` below; serialized as `ScanRequest.hints`); object `steganography` `{enabled:boolean,mode:"statistical"|"targeted",maxSamples?:integer}`; `aiInspection` `{enabled:boolean,ocr:boolean,adapterId?:string}`; `limits` (`ResourceLimits`); `policyId` string; `requiredControls` array of control IDs. Defaults are explicit in versioned policy, not hidden in schema. Unknown adapter IDs fail configuration validation.

### ScanHints

Optional `filename` string (maximum 255 characters) and/or `mediaType` string (maximum 127 characters). These are untrusted hints only. Implementations compare recognized values to byte-derived formats, never use the filename as a path, and do not copy raw hint values into reports or logs. Unknown hint values produce an unsupported control state; a recognized mismatch is a review signal, not a malware verdict.

### ResourceLimits

Fields: `maxBytes`, `maxWidth`, `maxHeight`, `maxPixels`, `maxFrames`, `maxMetadataBytes`, `maxMetadataEntries`, `maxNestingDepth`, `maxWallTimeMs`, `maxMemoryBytes`, `maxConcurrency` as positive safe integers. `enforcement` can report `in_process | worker | container`; requesting CPU/RSS hard bounds without a capable worker is a configuration error. `maxWallTimeMs` alone does not imply interruption of blocked native code.

### Finding

Required `id` (catalog ID or registered extension ID), `severity`, `stage`, `title` (max 160), `description` (max 2000), `status` (`confirmed | suspected | inconclusive`), `controlStatus`, optional `confidence`, `evidence` array. Unknown IDs are permitted only in `EXT-<namespace>-<token>` form.

### Evidence

Required `kind` (`offset | range | signature | statistic | metadata_tag | text_signal | decoder | policy | digest`), `summary` (max 500), optional `offset`, `length`, `sha256`, `redactedValue`, `attributes` (small scalar map, max 16 keys). No raw payload or extracted full OCR text by default. Offsets must fit input length and evidence values are privacy-filtered.

### SanitizationResult

Required `status` (`not_requested | produced | failed | unsupported`), `sourceDigest` and, if produced, `artifactDigest`, `format`, `bytes`, `transformations` array and `postCheckStatus`. Original bytes are never represented as overwritten. If failed, artifact fields are absent.

The standalone byte-oriented sanitizer methods currently return runtime-native objects/arrays rather than this persisted JSON report: SVG reports element/attribute removals; PNG metadata stripping reports removed chunk counts; RGBA8 reconstruction reports dimensions, removed ancillary chunk counts, byte sizes, and post-check status. Callers should hash/store artifacts outside Pixwarden and must not serialize raw image bytes into routine logs.

### BinaryInspectionResult

Required `status` (`passed | findings | unsupported | error`), `bytesScanned`, `findings`, `trailingData` boolean, `recursiveInspection` fixed to `false` in core v1. Example evidence records offset/length and signature name without including bytes.

### MetadataInspectionResult

Required `status` (`partial | unsupported | error`), `metadataBytes`, `entriesInspected`, and `findings`. Partial results are explicit: the current JS profile bounds and walks selected EXIF TIFF IFD tables and reports selected sensitive tag identifiers without extracting values. It does not claim complete metadata coverage.

### SteganographyResult

Required `status` (`passed | anomalous | inconclusive | unsupported | error`), `methods` array of `{id, applicable, status, samples?, score?}`, `limitations` array. `score` is algorithm-specific and cannot be compared across methods.

### AiInspectionResult

Required `status` (`not_requested | completed | partial | unsupported | error`), `adapterId?`, `dataEgress` (`none | local | remote`), `signals` array of findings, `limitations`; extracted text omitted unless caller explicitly requests a protected output channel.

### CapabilityReport

Required `runtime`, `runtimeVersion`, `engineVersion`, `specVersion`, `formats` map where each format has `inspect`, `decode`, `sanitize` booleans and reason, `optionalAdapters` map, `hardLimits` map, `networkAccess` fixed `false` for core. Capability truth is runtime/build-specific.

### EngineError

Required `code`, `stage`, `message` (safe), `retryable`, `fatal`, `controlStatus`; optional `limitName`, `observed`, `maximum`, `correlationId`. Codes include `INVALID_OPTIONS`, `INPUT_TOO_LARGE`, `LIMIT_EXCEEDED`, `UNSUPPORTED_FORMAT`, `UNSUPPORTED_CAPABILITY`, `MALFORMED_INPUT`, `DECODER_FAILURE`, `TIMEOUT`, `CANCELLED`, `IO_FAILURE`, `POLICY_FAILURE`, `SANITIZATION_FAILURE`, `INTERNAL_ERROR`.

### SecurityPolicy

Required `policyVersion`, `id`, `requiredControls`, `unsupportedFormat` (`review|reject`), `incompleteAnalysis` (`review|reject`), `unknownFinding` (`review|reject`), severity thresholds per action, `metadataAction` (`preserve|strip|reject`), `svgAction` (`sanitize|reject`), `sanitizationFailure` (`review|reject`), `allowOnlyIfAllRequiredPassed` boolean (v1 default true). Policy ordering is deterministic; critical/high configured findings take precedence over allow. Policy can never turn mandatory `error/skipped/unsupported` into passed.

### ScanResult

Required `resultVersion`, `scanId` UUID, `engineVersion`, `specVersion`, `startedAt`, `completedAt`, `format`, `validity` (`valid|invalid|unknown`), `decodability` (`decoded|not_attempted|failed|unsupported`), `sanitized` boolean, `policyCompliant` boolean, `coverage` (`complete|partial|incomplete`), `verdict`, `controls` map, `findings`, `capabilities`, `limitations`, `sanitization?`, optional specialized results, and `inputDigest` only when configured. Example verdict `review` + coverage `partial` is valid and expected when optional checks were unavailable.

## Versioning, constraints and acceptance

Schema validators must enforce bounds, enum values, conditional fields and exactly-one input variant. Golden JSON examples in spec are shared by PHP/JS tests. Additive optional fields: minor spec version; changed required semantics/enums: major. `specVersion` and `resultVersion` are independent. JSON Schema cannot express all cross-field security invariants; both libraries must run semantic validation in addition to schema validation. Requirements: PRD-002/009/010; TRD-7.

The schema uses JSON Schema Draft 2020-12. Ajv validation imports the dedicated 2020-12 implementation because that draft is not interchangeable with the default draft-07 validator; see the [Ajv JSON Schema version guide](https://ajv.js.org/json-schema.html) and the [JSON Schema Draft 2020-12 specification](https://json-schema.org/draft/2020-12).
