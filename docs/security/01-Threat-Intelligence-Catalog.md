# Threat Intelligence Catalog

**Document ID:** PW-THREAT · **Version:** 0.1.0 · **Status:** Initial research baseline, not exhaustive · **Consulted:** 2026-11-13

This catalog treats the supplied 82 identifiers as threat scenarios, not 82 confirmed vulnerabilities. Detection is conditional on parsers, enabled controls and format applicability. Public evidence is class-level unless a direct advisory is linked; no CVE is asserted here without source verification. State `planned` means no implementation exists in this checkout.

## Evidence sources

* [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), consulted 2026-11-13: allowlist, don't trust MIME, signature not standalone, size limits, decode/re-encode with caveats, sandbox processor.
* [CWE-400](https://cwe.mitre.org/data/definitions/400.html) and [CWE-409](https://cwe.mitre.org/data/definitions/409.html), consulted 2026-11-13: uncontrolled resource consumption and compressed-data amplification.
* [MDN SVG scripting](https://developer.mozilla.org/en-US/docs/Web/SVG/Guides/Scripting) and [SVG linking](https://developer.mozilla.org/en-US/docs/Web/SVG/Guides/Linking), consulted 2026-11-13: standalone SVG can run script; image embedding mode differs; references exist.
* [ImageMagick Security Policy](https://imagemagick.org/security-policy/), consulted 2026-11-13: format coders, delegates and resource policies must be restricted per deployment.
* [JSON Schema 2020-12 specification](https://json-schema.org/specification), consulted 2026-11-13: proposed contract dialect.
* [PHP GD documentation](https://www.php.net/manual/en/book.image.php) and [imagecreatefromstring](https://www.php.net/manual/en/function.imagecreatefromstring.php), consulted 2026-11-13: available formats depend on build.

The source set is an initial baseline. Before implementation, research must be expanded against NVD, CERT/CC, GitHub advisories, decoder vendor advisories, format specifications and peer-reviewed multimodal security literature. Exact advisories and versions must be added per selected dependency; do not infer that a class-level reference proves a particular decoder is vulnerable.

## Threat register and coverage map

Columns: **Exposure** (typical condition), **Impact/severity** (potential, context-dependent), **Detection / mitigation** (proposed), **test** (synthetic corpus ID), **status** (planned unless marked otherwise). `CWE` references identify related weakness classes, not exact equivalence. The JS implementation is evolving; status does not mean CI or independent security review has completed.

| ID | Scenario / affected surface | Exposure; impact / severity | Detection, mitigation and limitation | Test / status |
|---|---|---|---|---|
| IMG-001 | Invalid headers; supported parser | Attacker-controlled bytes; parser error/ambiguity, med | Bounds/profile parser; reject malformed; unknown profiles remain unverified | STR-001 / planned |
| IMG-002 | Inconsistent signatures; multi-format sniffing | Conflicting parser selection; high | Multi-candidate detector and policy reject/review; signatures alone insufficient | STR-002 / planned |
| IMG-003 | Truncation; all | Partial parse or decoder crash; med-high | Checked end offsets and EOF checks; no partial pass | STR-003 / planned |
| IMG-004 | Invalid lengths; chunk/segment parsers | Overflow/OOB/DoS; high; CWE-190/125 | Checked arithmetic and bound assertions; fuzz | STR-004 / planned |
| IMG-005 | Out-of-order blocks; chunked formats | Parser disagreement/data loss; med | Per-format ordering rules; unknown extensions may vary | STR-005 / planned |
| IMG-006 | Incompatible blocks | Confused interpretation; med | Cross-field semantic checks | STR-006 / planned |
| IMG-007 | Polyglot file | Different consumers interpret different payload; high | Candidate signatures, strict allowlist, raster reconstruction; cannot prove no parser differential | BIN-001 / planned |
| IMG-008 | Appended data | Hidden payload or downstream mismatch; med-high | Format terminator/tail scan; allowable trailing bytes vary | BIN-002 / planned |
| IMG-009 | False declared format | Decoder selection confusion; med | Byte-derived format and hint mismatch finding | STR-007 / planned |
| IMG-010 | MIME/extension contradiction | Serving or decoder confusion; med | Treat hints as untrusted, report mismatch without retaining raw values | INT-001 / implemented-js, CI pending |
| IMG-011 | Unexpected nested structures | Recursive parsing/DoS; high | Depth/count bounds; no recursive extraction default | STR-008 / planned |
| IMG-012 | Parser differential | Different consumers disagree; high | Strict profile plus cross-parser checks where justified; cannot cover every consumer | STR-009 / planned |
| BIN-001 | Trailing binary content | Payload hidden after image terminator; high | Bounded tail scan/signatures; false positives possible | BIN-002 / planned |
| BIN-002 | Auxiliary segment payload | Content in metadata/ancillary segments; med-high | Parse known segment locations, report unknown blocks | BIN-003 / planned |
| BIN-003 | Executable-like bytes embedded | Execution by later unsafe tooling; critical potential | Signature and structure indicators only; never execute; not AV | BIN-004 / planned |
| BIN-004 | Compressed archive embedded | Expansion or secondary parser risk; high | Identify signatures, no automatic unpack; signatures incomplete | BIN-005 / planned |
| BIN-005 | Fragmented binary | Signature evasion; high | Structural region mapping and selected entropy heuristics; weak detection | BIN-006 / planned |
| BIN-006 | Encoded data | Obfuscated content; med | Limited known-encoding heuristics; no general decode search | BIN-007 / planned |
| BIN-007 | Anomalous entropy | Packed/encrypted content indicator; low-med | Local entropy windows; benign texture/compression produces false positives | BIN-008 / planned |
| BIN-008 | Additional container | Embedded document/container; high | Format-aware signatures in allowed regions; no nested execution | BIN-009 / planned |
| BIN-009 | Multiple format signatures | Polyglot/misrouting; high | Report candidate set and conflict | BIN-010 / planned |
| BIN-010 | Payload survives sanitize | Transform failed to remove detected data; high | Post-scan artifact and compare expected normalized structure | SAN-001 / planned |
| SVG-001 | Script/active element | SVG document embedding; high | XML element allowlist removes/rejects; render context still matters | SVG-001 / implemented-js, CI pending |
| SVG-002 | Event-handler attributes | Active behavior; high | Namespace-aware attribute allowlist | SVG-002 / implemented-js, CI pending |
| SVG-003 | External references | Network/privacy/SSRF when renderer resolves; high | No resolver, block external URLs; fragments policy | SVG-003 / implemented-js, CI pending |
| SVG-004 | External XML entities | File/network access; high; CWE-611 | Reject all DTDs; parser has no resolver or application entity loader | SVG-004 / implemented-js, CI pending |
| SVG-005 | Entity expansion | CPU/memory DoS; high; CWE-776/400 | Reject DTD, enforce byte/node/depth/output ceilings | SVG-005 / implemented-js, CI pending |
| SVG-006 | Embedded resources/data URLs | Payload and resource amplification; med-high | Remove resource-bearing elements/attributes; no data URLs allowed | SVG-006 / implemented-js, CI pending |
| SVG-007 | foreignObject/HTML | Scriptable foreign content; high | Reject/remove foreign content and subtree | SVG-007 / implemented-js, CI pending |
| SVG-008 | Dangerous URL scheme | Script/resource execution or fetch; high | Remove active/external URL values; allow local fragment references only | SVG-008 / implemented-js, CI pending |
| SVG-009 | Namespace/encoding ambiguity | Sanitizer/parser differential; high | Strict UTF-8 XML parse, namespace check, output reserialization | SVG-009 / implemented-js, CI pending |
| SVG-010 | Renderer differences | One consumer's active interpretation; med-high | Narrow output profile and browser integration guidance; no universal equivalence | SVG-010 / partial-js, CI pending |
| META-001 | Malformed EXIF | Parser crash/DoS; high | Bound tag count/offset/depth; strip or reject | META-001 / planned |
| META-002 | Malformed XMP | XML/parser exposure; high | Harden XML; cap bytes; strip/reject | META-002 / planned |
| META-003 | Inconsistent ICC profile | Decoder behavior/resource issues; med-high | Bound profile size and validate adapter support; strip option | META-003 / planned |
| META-004 | Active/comment payload | Downstream interpretation; med | Inspect bounded text/comment fields; strip policy | META-004 / planned |
| META-005 | AI instructions in text metadata | Prompt injection in downstream model; med-high | Extract bounded text and classify advisory; strip metadata; classifier misses/false positives | AI-001 / planned |
| META-006 | Excess metadata | Memory/CPU or privacy; med | Byte/count caps before parse; strip | META-005 / planned |
| META-007 | Private location/device data | Privacy breach; high context-dependent | Detect known sensitive fields; strip default for sanitized derivative; unknown fields remain | META-006 / planned |
| META-008 | Proprietary unknown fields | Unanticipated data; med | Report field IDs/counts, strip unknown under strict policy | META-007 / planned |
| STEG-001 | LSB anomaly | Hidden message; med | Named channel statistics; transforms mitigate some, detection incomplete | STEG-001 / planned |
| STEG-002 | Alpha-channel data | Hidden payload in alpha; med | Analyze alpha distribution; flattening changes appearance | STEG-002 / planned |
| STEG-003 | Transparent pixel RGB | Hidden data under transparent pixels; med | Inspect RGB where alpha zero; normalization may alter editing semantics | STEG-003 / planned |
| STEG-004 | Inter-frame data | Animation hidden signal; med | Per-frame checks and frame limits; no cross-image universal detection | STEG-004 / planned |
| STEG-005 | Transform coefficient anomaly | JPEG-domain hidden data; med | Optional coefficient tests with decoder-specific coverage | STEG-005 / planned |
| STEG-006 | Statistical anomaly | Potential hidden data; low-med | Calibrated detector and benign corpus; anomaly is not proof | STEG-006 / planned |
| STEG-007 | Palette data | Information encoded in palette/order; med | Palette analysis and canonicalization; fidelity may change | STEG-007 / planned |
| STEG-008 | Uniform-region data | Hidden changes in flat regions; low-med | Region statistics; texture can resemble anomaly | STEG-008 / planned |
| STEG-009 | Cross-image channel | Payload spread over images; high | Out of single-image scope; optional batch correlation API later | STEG-009 / planned |
| STEG-010 | Transform-resistant channel | Robust steganography; high | No universal detector; state unsupported/inconclusive | STEG-010 / planned |
| DEC-001 | Memory failure in decoder | Native parser on hostile input; critical potential | Isolated worker, OS RSS limit, updated decoder; in-process cannot guarantee containment | DEC-001 / planned |
| DEC-002 | Arithmetic overflow | Dimensions/offset arithmetic; critical potential; CWE-190 | Safe integer checked math; fuzz/property tests | DEC-002 / planned |
| DEC-003 | Out-of-bounds access | Native decoder/parser; critical potential; CWE-125/787 | Avoid custom unsafe parsing; isolate/pin/patch; black-box fuzz | DEC-003 / planned |
| DEC-004 | Bad structure lifetime/ownership | Native decoder corruption; high | Adapter isolation and versioned dependencies | DEC-004 / planned |
| DEC-005 | CPU exhaustion | Complex parsing/filtering; high; CWE-400 | Worker CPU/time quotas; in-process deadline is cooperative | DEC-005 / planned |
| DEC-006 | Memory exhaustion | Large expansion/pixel cache; high; CWE-400/409 | Pixels/frame limits plus worker RSS quota | DEC-006 / planned |
| DEC-007 | Extreme dimensions | Tiny input drives huge allocation; high | Overflow-safe width/height/pixel ceilings before decode | DEC-007 / planned |
| DEC-008 | Excess frames/pages | Animation workload; med-high | Frame/page ceiling, reject/flatten explicitly | DEC-008 / planned |
| DEC-009 | Unbounded recursion | Nested formats/metadata; high | No recursion default, depth budget | DEC-009 / planned |
| DEC-010 | Process hang | Native decoder deadlock; high | Killable worker deadline; library-only timeout insufficient | DEC-010 / planned |
| AI-001 | Visible instructions in image | Vision model follows image text; high context-dependent | OCR + advisory prompt-risk rules; cannot enforce downstream model | AI-002 / planned |
| AI-002 | Metadata instructions | Hidden text prompt injection; high | Metadata text scan/strip; detector incomplete | AI-003 / planned |
| AI-003 | OCR-recoverable instructions | Small/rotated/obfuscated text; high | Optional OCR variants and confidence; OCR errors remain | AI-004 / planned |
| AI-004 | Authority impersonation | Image claims system/admin status; high | Contextual rules/model advisory; no reliable binary signature | AI-005 / planned |
| AI-005 | Context manipulation | Instructions change task framing; high | Adapter flags suspicious directives; downstream prompt design remains necessary | AI-006 / planned |
| AI-006 | Adversarial visual content | Perturbation changes classifier output; high | Optional model-specific evaluation; no general defense | AI-007 / planned |
| AI-007 | Instructions split across regions | OCR segmentation misses relations; high | Region OCR and grouping; incomplete | AI-008 / planned |
| AI-008 | Instructions across images | Multi-image context attack; high | Batch-level optional analysis; single-image core cannot evaluate | AI-009 / planned |
| AI-009 | OCR manipulation | Confusable glyphs/overlays/noise; high | Multiple OCR/model checks advisory; false negatives remain | AI-010 / planned |
| AI-010 | RAG contamination | Injected image text enters index/retrieval; high | Extracted text provenance/taint metadata; downstream filtering needed | AI-011 / planned |
| AI-011 | Agent manipulation | Image instructions trigger tools/actions; critical potential | Detect/classify only; agent must treat image as untrusted data and gate tools | AI-012 / planned |
| AI-012 | Automated decision alteration | Visual adversarial/prompt content changes decision; critical context-dependent | Application-specific evaluation and human review; no universal defense | AI-013 / planned |
| INT-001 | Weak upload validation | Trusts user MIME/extension; high | Byte inspection, allowlist, app-layer auth/limits | INT-001 / planned |
| INT-002 | Dangerous filename | Path traversal/command confusion; high | Pixwarden ignores path for parsing; app uses generated basename | INT-002 / planned |
| INT-003 | Executable storage | Served/interpreted in web root; high | App stores quarantined/non-executable and serves fixed type | INT-003 / planned |
| INT-004 | Insecure permissions | Other processes/users read/write temp/artifact; high | Private exclusive temp and least privilege; deployment review | INT-004 / planned |
| INT-005 | MIME confusion | Browser/downstream parser mismatch; high | Report and set response MIME/nosniff at app layer | INT-005 / planned |
| INT-006 | Unsafe remote processing | URL fetch SSRF/egress; high; CWE-918 | Core has no fetch; caller controls hardened fetch | INT-006 / planned |
| INT-007 | Internal resource reference | SVG/delegate reference internal endpoint; high | Disable resolver/network/delegates; external fetch absent | INT-007 / planned |
| INT-008 | Later transform unverified | New artifact reintroduces risk; high | Pipeline guard and post-scan each transform output | INT-008 / planned |
| INT-009 | Predictable temp file | Symlink/race/disclosure; high | Exclusive random file, restrictive mode, cleanup | INT-009 / planned |
| INT-010 | Vulnerable dependency | Supply-chain/native decoder issue; critical potential | Lock, audit advisories/SBOM, patch cadence and release gate | INT-010 / planned |

## Threat to test traceability

`STR-*`, `BIN-*`, `SVG-*`, `META-*`, `STEG-*`, `DEC-*`, `AI-*`, `INT-*`, `SAN-*` identifiers are assigned to corpus cases in `03-Security-Test-Corpus.md`. Coverage and limits map to `04-Detection-Mitigation-Coverage.md`. A case marked planned has no implementation evidence yet.
