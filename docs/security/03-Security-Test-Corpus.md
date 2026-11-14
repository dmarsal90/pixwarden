# Security Test Corpus Plan

**Document ID:** PW-CORPUS · **Version:** 0.1.2 · **Status:** Shared synthetic conformance and scheduled JS fuzzing active; broader corpus planned · **Updated:** 2026-11-14

The shared `spec/corpus/v1/manifest.json` contains sixteen hash-pinned, harmless synthetic byte vectors consumed directly by JS and PHP tests. This initial corpus is a subset of the broader plan below; absent cases are planned, not tested. No operational malware or live exploit payloads are included. A separate `pixwarden-spec` repository is not yet created.

## Manifest contract

The current manifest records `id`, description, hex bytes, SHA-256, and expected format/validity/verdict/coverage/finding IDs; binary vectors also declare status and bytes scanned. The broader planned corpus schema will add category, source/license, labels, expected control states, policy, validity/decodability/sanitization, capabilities, and rationale. Cases must be minimal harmless bytes/markers, synthetic text and in-memory malformed structures. Every expected result is tied to implementation version and must be reviewed before changing.

The JavaScript parser has a Jazzer.js coverage-guided target seeded from this hash-checked manifest. Pull requests replay the seed corpus in regression mode; a weekly scheduled run and manual dispatch fuzz for 90 seconds with a 65,536-byte maximum input and one-second per-input timeout. The target checks report/input consistency, input immutability, enum values, bounded finding counts, and evidence ranges. The job is in-process and its workflow timeout is a job guard, not an OS CPU or RSS limit. The evolving corpus and crash artifacts are retained as CI artifacts for 14 days; minimized failures must become deterministic checked-in regressions after triage. PHP currently has shared deterministic conformance tests but no coverage-guided fuzzer.

Initial local run record (2026-11-14): Jazzer.js 4.0.0 on Node 22.22.2 first found a 23-byte synthetic GIF whose descriptor advertised a missing local color table; the parser emitted evidence beyond the input boundary. The parser now checks the table length before advancing, and the minimized bytes are a deterministic regression in `tests/parser-fuzz-smoke.test.ts`. A subsequent 30-second run completed 238,449 executions without another target invariant failure. This is one bounded run, not a protection metric, comprehensive audit, or proof of parser safety.

## Planned corpus cases

Implemented vector IDs in v1 include `FMT-UNKNOWN-001`, `STR-PNG-TRUNCATED-001`, `STR-PNG-VALID-001`, `STR-GIF-VALID-001`, `STR-JPEG-VALID-001`, `STR-WEBP-VALID-001`, `META-PNG-EXIF-GPS-TAG-001`, `META-PNG-EXIF-MALFORMED-001`, `BIN-PNG-ANCILLARY-SIGNATURE-001`, `BIN-GIF-EXTENSION-SIGNATURE-001`, `BIN-JPEG-APP-SIGNATURE-001`, `BIN-WEBP-XMP-SIGNATURE-001`, `SVG-STATIC-SAFE-001`, `SVG-ACTIVE-CONTENT-001`, `RES-PNG-WIDTH-LIMIT-001`, and `RES-GIF-FRAME-LIMIT-001`. The exact hashes and expected outcomes are maintained in the manifest.

| Case ID | Construction / benign purpose | Expected assertion | Trace |
|---|---|---|---|
| STR-001 | Valid minimal JPEG, PNG, GIF, WebP files | Correct candidate and valid profile | IMG-001 |
| STR-002 | Bad header bytes | Invalid/unknown, no crash | IMG-001 |
| STR-003 | Valid signature with deliberately mismatched type hint | Hint mismatch finding | IMG-002/009/010 |
| STR-004 | Truncated chunk/marker length | Structural failure, bounded offsets | IMG-003/004 |
| STR-005 | Oversized declared length within tiny fixture | Limit/malformed result without allocation | IMG-004 |
| STR-006 | Reordered/duplicate chunks in synthetic PNG profile | Specific ordering finding | IMG-005/006 |
| STR-007 | Two benign signatures concatenated in synthetic bytes | Multiple-candidate/polyglot signal | IMG-007/009 |
| BIN-001 | Benign marker bytes in legal metadata segment | Metadata region reported, no malware claim | BIN-002 |
| BIN-002 | Harmless ASCII trailer after image terminator | Trailing-data finding and offset | IMG-008/BIN-001 |
| BIN-003 | Harmless known file magic token in ancillary data | Embedded signature indicator only | BIN-003/009 |
| BIN-004 | Non-executable synthetic archive-like header bytes | Indicator, no extraction/execution | BIN-004/008 |
| BIN-005 | Token split over bounded synthetic segments | Limitation/fragment heuristic behavior | BIN-005/006 |
| BIN-006 | High-entropy random pixels vs smooth gradients | Statistical feature, no binary classification claim | BIN-007 |
| SVG-001 | Benign static shapes/text | Allowed features preserved by policy | SVG-001 |
| SVG-002 | Script and event attributes using inert harmless marker text | Removed/rejected; output reparses | SVG-001/002 |
| SVG-003 | External URL reference to reserved `.invalid` domain | Blocked without network request | SVG-003/008 |
| SVG-004 | DTD/entity declaration with tiny expansion pattern | Rejected before expansion | SVG-004/005 |
| SVG-005 | Embedded raster data URL under/over size boundary | Policy-specific strip/reject | SVG-006 |
| SVG-006 | Namespaced and malformed XML edge cases | Strict parse or reject, no ambiguous output | SVG-009/010 |
| META-001 | GPS/device EXIF from generated synthetic tags | Detect privacy tags; strip option removes | META-001/007 |
| META-002 | Malformed/oversized XMP text | Bounded error, no external entity resolution | META-002/006 |
| META-003 | Benign ICC and malformed ICC lengths | Known profile handling and bounds | META-003 |
| META-004 | Ordinary comments and unknown proprietary tags | Benign text not automatically injection; unknown field reported | META-004/008 |
| STEG-001 | Synthetic LSB payload-like pattern with known seed | Detector score repeatability; false-positive test | STEG-001 |
| STEG-002 | Alpha channel varying under zero alpha | Channel anomaly result | STEG-002/003 |
| STEG-003 | Transparent pixels with both arbitrary and canonical RGB | Separate benign/transparency handling | STEG-003 |
| STEG-004 | Animation with benign frame differences and high frame count | Per-frame checks and cap | STEG-004/DEC-008 |
| STEG-005 | Synthetic JPEG coefficient perturbations if selected adapter allows | Algorithm-specific test only | STEG-005 |
| STEG-006 | Natural-looking noise/textures across benign set | False-positive measurement | STEG-006/008 |
| AI-001 | Benign visible imperative text (e.g. sign/instructions in a photo) | No automatic rejection solely for imperative text | AI-001 |
| AI-002 | Synthetic visible “ignore prior instructions” prompt image | Advisory prompt-risk signal; no execution | AI-001/006 |
| AI-003 | Same harmless prompt text in metadata | Metadata signal, strip behavior | META-005/AI-002 |
| AI-004 | Small/rotated/low-contrast prompt-like text synthetic images | OCR confidence/inconclusive behavior | AI-003/009 |
| AI-005 | Benign official-looking logo/text vs synthetic authority claim | Context uncertainty disclosed | AI-004/005 |
| AI-006 | Perturbation samples generated for selected model | Model-specific score only | AI-006 |
| AI-007 | Prompt fragments distributed across regions/images | Single vs batch scope clearly reported | AI-007/008 |
| AI-008 | Harmless OCR text destined for mock RAG | Text provenance tags | AI-010 |
| DEC-001 | Dimensions/pixel arithmetic boundary values | Reject before decode; no allocation | DEC-002/007 |
| DEC-002 | Excessive frames/metadata/nesting synthetic structures | Cap and typed error | DEC-006/008/009 |
| DEC-003 | Timeout/hang simulated by test-only worker stub | Worker is terminated and result incomplete | DEC-005/010 |
| SAN-001 | Valid raster with EXIF, alpha, animation | New artifact, fidelity contract and postcheck | BIN-010/PRD-007 |
| SAN-002 | Malformed or unsupported sanitizer input | No output artifact; original digest preserved | PRD-007 |
| FP-001 | Photographs with high texture/noise | No confirmed steg finding without evidence | STEG-006 |
| FP-002 | Benign SVG gradients, filters and local fragment refs | Document allowlist removals are documented | SVG-010 |
| FP-003 | Benign captions with commands/imperatives | AI findings remain advisory | AI-001/AI-005 |
| PAR-001 | Same corpus run through both runtimes | Normalized results equal for shared capability | PRD-009 |

## Handling and maintenance

All samples use reserved names and harmless content. Corpus generation must be deterministic with pinned generator version and seed. Store binary fixtures via Git LFS only if needed; otherwise keep small fixtures directly in Git. Hash changes require review and changelog. Fuzzing uses time/memory budgets and isolated workers; minimized cases enter regression corpus after triage. License every third-party-derived sample; prefer original synthetic samples. Train/tune/evaluate partitions must be disjoint and generated before model calibration. Keep expected false positives and negative cases, not only attack-labelled samples.

No test results are claimed until fixtures, harnesses and runtime implementations exist and have been executed.
