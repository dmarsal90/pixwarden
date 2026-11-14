# Pixwarden Product Requirements Document

**Document ID:** PW-PRD · **Version:** 0.1.0 · **Status:** Phase 0/1 baseline · **Updated:** 2026-11-13

## 1. Vision and scope

Pixwarden is a family of independent PHP and JavaScript/TypeScript libraries for inspecting untrusted image-like files, applying explicit policy, and optionally producing a newly encoded derivative. It helps application teams reduce exposure in upload, document, API, and multimodal AI pipelines. It is not an antivirus, sandbox, forensic attribution system, or proof that an artifact is harmless.

Repos: `pixwarden-spec` owns the shared taxonomy, schemas, policy semantics, corpus and conformance suite; `pixwarden-js` and `pixwarden-php` implement native runtime integrations. Neither implementation depends on the other language. Candidate package identifiers are `pixwarden-js` and `dmarsal90/pixwarden-php`; availability, namespace ownership, license compatibility and publisher identity remain release gates (REL-001).

## 2. Users and use cases

Primary users are application/security engineers accepting images, API maintainers, platform teams handling document previews, and AI engineers supplying images to OCR/VLM/RAG/agent systems. Core use cases: classify a byte stream without trusting its filename; detect structural and policy findings; enforce bounded processing; strip metadata or produce a raster derivative; inspect text/binary payload indicators; report unsupported or skipped checks; integrate decisions into upload workflows.

## 3. Requirements

Requirements use stable IDs. `M` means required for declared core capability; `S` means optional adapter; `R` means release requirement.

| ID | Requirement | Acceptance |
|---|---|---|
| PRD-001 | Identify actual format from bytes and report extension/MIME disagreements | Conflicting signals appear as findings; caller metadata never overrides byte inspection |
| PRD-002 | Separate validity, decodability, sanitization, policy compliance and evaluation coverage | Result has independent fields and never collapses them into one “safe” boolean |
| PRD-003 | Bound input bytes, dimensions/pixels, frames, metadata, time, memory and concurrency | Each enforced limit is reported; hard CPU/memory/time claims require OS/process/container enforcement |
| PRD-004 | Inspect structural anomalies and trailing/embedded data for supported formats | Findings cite bounded evidence offsets/categories; no payload execution |
| PRD-005 | Apply SVG policy through a namespace-aware, hardened XML parser and allowlist sanitizer | External access/entity expansion disabled; sanitizer output reparses and is checked |
| PRD-006 | Inspect metadata and support strip/preserve/reject policy | Only parsed fields are exposed; privacy-preserving defaults are documented |
| PRD-007 | Provide controlled raster decode/re-encode as an optional sanitizer | New output is validated; source is never overwritten; unsupported frames/features are reported |
| PRD-008 | Offer optional statistical steganography and multimodal/OCR adapters | Results express uncertainty, confidence semantics, limitations and capability status |
| PRD-009 | Share JSON contracts and conformance cases across PHP/JS | Same schema version and test vectors; differences are documented by capability |
| PRD-010 | Produce reproducible typed reports with engine/spec versions | Report includes control states, evidence, policy decision and limitations |
| PRD-011 | No network access, telemetry, database, or framework requirement in core | Defaults work offline and store nothing persistently |
| PRD-012 | API supports cancellation and explicit errors | Abort/timeout/errors are distinguishable and never silently become allow |
| PRD-013 | Publish documented support by format, runtime and optional adapter | Capability report distinguishes inspect/decode/sanitize and runtime availability |
| RSK-001 | State residual risks and non-goals clearly | Every report can indicate unevaluated/unsupported surfaces |
| REL-001 | Verify npm/Packagist name, namespaces, licenses and release identity before publication | Release checklist evidence recorded; no automatic publication |

## 4. Meaning of analysis results

* **Valid**: the enabled structural checks found the byte layout consistent with the declared supported profile. This does not mean it is safe or decodable by every library.
* **Decodable**: a named decoder in the declared runtime/build successfully decoded under its configured limits. This does not attest to parser safety or benignness.
* **Sanitized**: a new output was generated under a named transformation and post-checked. It may alter appearance, animation, color profile, metadata, or semantics; it does not prove absence of hidden content.
* **Policy-compliant**: all mandatory checks have a terminal state accepted by the selected policy and no disallowed finding exists. `skipped`, `unsupported`, `error`, or timeout cannot satisfy mandatory checks.
* **Risks not evaluated**: any relevant control was disabled, unavailable, unsupported, inconclusive, or failed. This state is explicit in the report.

Verdicts are `allow`, `sanitize`, `reject`, `review`; coverage/completeness is separate. No “threat-free” claim is permitted. See TRD-001 and schema `CapabilityReport`.

## 5. Initial format scope

Initial policy prioritizes JPEG, PNG, GIF, WebP and SVG. Byte-level inspection should not imply decoder availability. SVG defaults to reject or sanitize-before-document-embedding; it is never loaded as an active document by the library. Other formats are unsupported until a justified adapter is selected, constrained, reviewed and tested. PDF/XPS are document containers and remain outside image parsing.

| Format family | Initial disposition |
|---|---|
| JPEG/PNG/GIF/WebP | Core inspection target; raster decode/sanitize only with available approved adapter |
| SVG | Secure XML inspection and allowlist sanitize; no general rasterization in core |
| APNG/animated GIF/WebP | Inspect frame count/limits; sanitization must preserve or explicitly flatten/reject |
| BMP | Optional structural recognition; no default decode promise |
| AVIF/HEIF/HEIC/JXL/TIFF/BigTIFF/PSD/PSB/OpenEXR | Unsupported by default; adapter proposal and resource review required |
| SVGZ/EPS/AI/ICO/CUR/ICNS/TGA/PCX/DICOM/GeoTIFF | Unsupported or inspection-only pending profile-specific threat review |
| PDF/XPS | Reject as wrong category unless a future document adapter is separately specified |

See `security/02-Format-Security-Matrix.md`.

## 6. Non-functional requirements and exclusions

PHP 8.2+ and Node.js LTS; strict public types; deterministic schema semantics; bounded memory proportional to configured input/output and decoder working set; no external services by default. Performance targets must be benchmarked against named hardware, formats and limits before publication (MET-001), not guessed here.

Out of scope: general malware scanning, behavioral execution, universal steganography detection, image provenance/authenticity, semantic truth, face/identity decisions, content moderation, remote URL fetching, and guaranteeing downstream browser/model behavior. OCR/VLM findings are advisory and may be wrong.

## 7. Privacy, risks and acceptance

Default report stores hashes/metadata only when caller requests it; never log image bytes, extracted text, paths or EXIF values by default. Risks include decoder CVEs, parser differentials, format ambiguity, hostile native extensions, resource exhaustion, false positives/negatives, model prompt injection not recognized, transformation damage, and dependency supply chain exposure. Isolation belongs to the host or an explicit worker adapter; in-process limits cannot enforce OS memory/CPU ceilings.

Acceptance aligns to project criteria: all ten phase documents; shared contracts/taxonomy/corpus; independent libraries; structural, binary and SVG controls; actual resource enforcement boundaries stated; sanitization post-validation; policy/report parity; tests and reproducible corpus; CI; integration examples; dependency/security review; published limitations. Phase status is tracked in `06-Implementation-Plan.md`; the current repo has no implementation, so these criteria are not yet met.

## 8. Roadmap

Phase 0 research and Phase 1 documentation; Phase 2 common schema/taxonomy/corpus; Phases 3–4 runtime cores and conformance; Phase 5 SVG/binary/steg/raster/pipeline controls; Phase 6 optional AI/OCR; Phase 7 adapters/examples; Phase 8 audit/performance; Phase 9 release readiness. No publication without explicit authorization.

## 9. References

Sources and consultation date are indexed in `security/01-Threat-Intelligence-Catalog.md` and `02-Format-Security-Matrix.md`. Key guidance: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [CWE-400](https://cwe.mitre.org/data/definitions/400.html), [CWE-409](https://cwe.mitre.org/data/definitions/409.html), [MDN SVG scripting](https://developer.mozilla.org/en-US/docs/Web/SVG/Guides/Scripting).
