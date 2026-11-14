# Pixwarden Implementation Plan

**Document ID:** PW-PLAN · **Version:** 0.1.7 · **Status:** Phases 2–5 in progress · **Updated:** 2026-11-14

## Phase gates and work items

| Phase | Priority / owner role | Work and dependencies | Deliverables / acceptance |
|---|---|---|---|
| 0 Research | P0 Security research, forensics, format specialists | Review authoritative standards/advisories, threat classes, licenses and available native libraries | Referenced threat register and format matrix; evidence dated; unknowns called out |
| 1 Documents | P0 Architect, security, QA, technical writer | Complete all ten docs; cross-link requirements, threats, controls and tests | Reviewable docs; no implementation claims; current phase complete when docs reviewed for coherence |
| 2 Spec | P0 Architect, QA | JSON schemas, taxonomy IDs, policy semantics, synthetic corpus manifests and vectors | Schema validation; deterministic expected outcomes; corpus hashes/license/provenance; conformance harness design |
| 3 JS Core | P1 TS engineer, appsec | Strict config, byte counting, format candidate detection, control model, report/policy | Node LTS; no decoder dependency; unit/property/conformance pass; real limits represented honestly |
| 4 PHP Core | P1 PHP engineer, appsec | Native Composer API equivalent to JS semantics | PHP 8.2+; static analysis/format/tests; shared vectors pass |
| 5 Advanced guards | P1 image security, forensics, QA | Structural parsers for initial formats, binary indicators, SVG secure sanitizer, resource worker contract, raster adapter | Adversarial regression corpus; sanitizer post-check; documented native decoder boundary |
| 6 AI/multimodal | P2 AI security, privacy, QA | OCR/context adapters, prompt-injection signal taxonomy and opt-in data flow | Disabled by default; local adapter first; remote adapter explicit; precision/recall/FPR on held-out corpus |
| 7 Integrations | P2 runtime engineers | Express/Fastify/Nest/Next server; Laravel/Symfony optional adapters | Executable examples, no core framework dependencies |
| 8 Audit | P0 security, performance, QA | Fuzz, dependency audit, performance, threat review, accessibility of docs/API | Reproducible reports; no unresolved critical known issue in shipped components; limitations updated |
| 9 Release prep | P0 release owner/legal review | Verify npm/Packagist names, license, SBOM, provenance, changelog, security contact | Manual release candidate and checklist; explicit user authorization before publish |

## Shared vs runtime work

**Shared (`pixwarden-spec`):** taxonomies, 82-vector initial catalog plus extensions, schemas, conformance definitions, corpus fixtures/manifests, expected outcomes, policy semantics, format profiles and versioning.

**JS (`pixwarden-js`):** Node stream/buffer APIs, AbortSignal, TypeScript declarations, adapter boundary, Node CI matrix and package build.

**PHP (`pixwarden-php`):** PSR-4/PSR-12, PHP 8.2 types/enums, stream/resource support, exception hierarchy, Composer metadata and static analysis.

Neither language task may publish a capability absent from the shared declared profile or its runtime capability report.

## Verification plan

Unit tests cover deterministic helpers and policy; integration tests cover adapters; conformance tests consume common fixture manifests; malformed-input regressions retain minimized synthetic cases; property tests assert no crashes, bounded offsets and stable error output; fuzz targets parsers in isolated CI workers; benchmarks report environment and limits. Probability-based detectors are measured on separated benign/synthetic attack sets for precision, recall, false-positive/negative rates, latency and memory. No claimed metric without a reproducible dataset and run.

## Definition of Done

For each phase: changes match requirements and threat IDs; docs and capability matrix updated; no skipped check is described as passed; PHP/JS parity checked; tests actually run with results recorded; dependency/license changes reviewed; errors and residual risks documented. Phase 1 is documentation only, so it does not imply code, schemas or tests exist.

## Risks and sequencing

Highest risks: decoder-native memory safety, format differentials, lack of enforceable in-process CPU/RSS controls, false positives in steganography/AI, testing-data bias, platform-dependent codec availability, and scope spanning two runtimes. Mitigation: narrow v1 formats, no automatic decoder enablement, external isolation, explicit capability reports, common vectors, release gating. Do not start OCR/VLM before core reporting and data-egress policy are stable.

## Current status

Initial repository inspection on 2026-11-13 found only `LICENSE` (MIT), no source code, package manifests, tests, CI or prior docs. Phase 1 documents were committed before implementation. JS increments now define a TypeScript ESM package; bounded structural inspection for JPEG/PNG/GIF/WebP; indicator-only binary signatures scoped to format-defined auxiliary regions and trailers; typed binary inspection status, bytes scanned and trailer reporting; selective EXIF TIFF directory validation and sensitive-tag presence reporting; policy/capability reporting; bounded async byte-stream ingress with abortable pending reads; a namespace-aware SVG static-profile inspector/sanitizer using Saxes 6.0.0; optional untrusted filename/MIME comparison; and a worker-isolated scan API with enforceable timeout and a V8 heap ceiling. Metadata values/XMP, raster decoding/sanitization, steganography/OCR, and OS-enforced CPU/RSS controls remain absent. CI passed Node 22/24/26 for the merged JS increments. The Saxes dependency audit reports zero vulnerabilities. Binary-region regression cases cover PNG ancillary versus pixel data, JPEG entropy/trailer boundaries, and synthetic GIF extension and WebP metadata regions. The code currently lives in this `pixwarden` repository; whether it is later split into the planned `pixwarden-js` repository is a repository-management decision, not implied by package metadata. This plan does not change or decide the existing license. Publication and the Apache-2.0 vs MIT decision remain open.

Package-name lookup for `pixwarden-js` and `dmarsal90/pixwarden-php` was attempted on 2026-11-13 through public search/direct listing pages, but registry records could not be retrieved reliably. Availability and namespace ownership are therefore **unverified**, not confirmed available. Repeat with the npm and Packagist registries immediately before repository/package creation and again before release; record timestamp and account ownership. Do not squat, transfer or publish a name as part of this check.

Phase 2 has a strict Draft 2020-12 contract artifact in `spec/schemas/pixwarden-v1.schema.json`. It defines the request, result, policy, finding/evidence, capability, resource, sanitization, binary, steganography, AI and error contracts in reusable `$defs`. JS validates versioned golden examples in CI. PHP validates each report generated by the shared conformance vectors against the same `ScanResult` definition using a Composer development-only validator.

The shared executable corpus is `spec/corpus/v1/manifest.json` (CC0-1.0, twenty-two hash-pinned synthetic vectors). JS and PHP conformance tests consume the same manifest and verify exact shared classifications; additional assertions check binary-inspection status and bytes scanned where applicable. Expected `partial` coverage is deliberate because codec decoding and broader controls are not asserted.

The native PHP package in `php/` consumes the same manifest. Its bounded PNG/GIF/JPEG/WebP container profile, typed scan options/results/errors, caller-owned bounded stream ingress, basic dimension/frame limits, EXIF TIFF directory scan, indicator-only binary scan of selected metadata/extension/trailer ranges, and optional ext-dom SVG allowlist sanitizer run natively. PHP now checks PNG chunk CRCs and IHDR parameter combinations, validates GIF block boundaries/local color-table lengths, and parses WebP RIFF chunk boundaries, zero padding and selected VP8X reserved fields; shared regressions cover malformed instances. Synthetic vectors cover privacy tags, malformed TIFF, inert signature bytes, SVG content, and resource limits; none includes executable payloads or private values. PHP conformance validates every emitted report against the shared Draft 2020-12 schema using a development-only validator. Raster decode/sanitization, steganography, OCR, stronger memory/CPU/depth limits, and independent repository packaging remain outstanding. The PHP package is not yet at functional parity with JS; its capability report and limitations must remain explicit.

The JS suite includes deterministic malformed-input regression coverage and a Jazzer.js coverage-guided target seeded from the shared synthetic corpus. Pull requests replay the seed corpus; a weekly scheduled run and manual dispatch fuzz the bounded byte parser, and retain the evolving corpus/crash artifacts for 14 days. A minimized GIF fixture discovered by an initial local run now covers a truncated local color table and guards evidence offsets in both runtimes. This is in-process JavaScript parser fuzzing only; PHP coverage-guided fuzzing, native-decoder fuzzing and OS-enforced CPU/RSS isolation remain planned.
