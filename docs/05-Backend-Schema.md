# Pixwarden Shared Backend Schema Contracts

**Document ID:** PW-SCHEMA · **Version:** 0.1.0 · **Status:** Draft contract baseline · **Updated:** 2026-11-13

This is the normative semantic outline for JSON Schema Draft 2020-12 artifacts in `pixwarden-spec`. The repository is currently a single empty checkout, so these are specified contracts, not published schema files or runtime behavior. All objects use `additionalProperties: false` in the initial strict schemas unless an explicitly extensible evidence payload says otherwise. All sizes are non-negative integers in bytes; timestamps are RFC 3339 UTC. Schema `$id` convention: `https://pixwarden.dev/spec/v1/{Type}.schema.json` (domain ownership must be verified before publication).

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

Fields: booleans `structural`, `metadata`, `binaryInspection`, `sanitize`; object `steganography` `{enabled:boolean,mode:"statistical"|"targeted",maxSamples?:integer}`; `aiInspection` `{enabled:boolean,ocr:boolean,adapterId?:string}`; `limits` (`ResourceLimits`); `policyId` string; `requiredControls` array of control IDs. Defaults are explicit in versioned policy, not hidden in schema. Unknown adapter IDs fail configuration validation.

### ResourceLimits

Fields: `maxBytes`, `maxWidth`, `maxHeight`, `maxPixels`, `maxFrames`, `maxMetadataBytes`, `maxMetadataEntries`, `maxNestingDepth`, `maxWallTimeMs`, `maxMemoryBytes`, `maxConcurrency` as positive safe integers. `enforcement` can report `in_process | worker | container`; requesting CPU/RSS hard bounds without a capable worker is a configuration error. `maxWallTimeMs` alone does not imply interruption of blocked native code.

### Finding

Required `id` (catalog ID or registered extension ID), `severity`, `stage`, `title` (max 160), `description` (max 2000), `status` (`confirmed | suspected | inconclusive`), `controlStatus`, optional `confidence`, `evidence` array. Unknown IDs are permitted only in `EXT-<namespace>-<token>` form.

### Evidence

Required `kind` (`offset | range | signature | statistic | metadata_tag | text_signal | decoder | policy | digest`), `summary` (max 500), optional `offset`, `length`, `sha256`, `redactedValue`, `attributes` (small scalar map, max 16 keys). No raw payload or extracted full OCR text by default. Offsets must fit input length and evidence values are privacy-filtered.

### SanitizationResult

Required `status` (`not_requested | produced | failed | unsupported`), `sourceDigest` and, if produced, `artifactDigest`, `format`, `bytes`, `transformations` array and `postCheckStatus`. Original bytes are never represented as overwritten. If failed, artifact fields are absent.

### BinaryInspectionResult

Required `status` (`passed | findings | unsupported | error`), `bytesScanned`, `findings`, `trailingData` boolean, `recursiveInspection` fixed to `false` in core v1. Example evidence records offset/length and signature name without including bytes.

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
