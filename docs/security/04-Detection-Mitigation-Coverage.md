# Detection and Mitigation Coverage

**Document ID:** PW-COVERAGE · **Version:** 0.1.0 · **Status:** Planned coverage baseline · **Updated:** 2026-11-13

Coverage labels: `D` direct deterministic inspection; `H` heuristic/probabilistic; `M` mitigation; `I` integration/deployment control; `—` no general capability. `Planned` is not implementation. A detector does not imply mitigation, and a mitigation does not prove detection.

| Threat IDs | Planned detection | Planned mitigation | Limitations / required status behavior | Test IDs |
|---|---|---|---|---|
| IMG-001–006, 009, 011 | D: bounded per-format profiles | M: reject/review; reconstruct only by approved sanitizer | Profiles cover only supported spec subset; incomplete parse => failed/error | STR-001–006 |
| IMG-007–008, 010, 012 | D/H: signature conflicts, terminator/tail, hint mismatch; limited differential checks | M: allowlisted output, fixed serving headers by caller | Arbitrary polyglot/parser differences not provable; unsupported => review | STR-003/007, BIN-002 |
| BIN-001–010 | D/H: region-aware signatures, structural gaps, bounded entropy | M: strip/reconstruct and post-scan | Signatures evadable; entropy noisy; no recursive unpack; report inconclusive | BIN-001–006, SAN-001 |
| SVG-001–010 | D: Saxes XML parse, namespace checks, static element/attribute allowlist, DTD rejection | M: canonical allowlist serialization and parse-again check | Renderer differences remain; CSS/style/filter/animation support is intentionally narrow; pending CI and security review | SVG-001–006 |
| META-001–008 | D: bounded known tag parsing and privacy tag map | M: strip/preserve/reject by policy | Unknown proprietary fields and parser coverage remain; never log raw values | META-001–004 |
| STEG-001–010 | H: named format-specific statistical methods | M: optional canonicalization/re-encode/flatten | No universal detection; false positives; cross-image and robust schemes out of scope; low-confidence => inconclusive | STEG-001–006 |
| DEC-001–010 | D: arithmetic, dimension, frame and nesting caps; worker exit state | M/I: isolate with CPU/RSS/wall-time quotas; pin/patch decoders | In-process code cannot enforce hard native limits; no worker => unsupported hard limit | DEC-001–003 |
| AI-001–005, 007–009 | H: optional OCR, region grouping, metadata text rules | M/I: mark untrusted, strip metadata, downstream prompt/tool policy | Legitimate text overlaps; OCR misses; advisory only; no execution | AI-001–007 |
| AI-006, 010–012 | H: model-specific optional red-team evaluation; provenance signals | I: application-specific model isolation, retrieval taint, human review | No general adversarial defense; cannot attest downstream model behavior | AI-006–008 |
| INT-001–005, 008–010 | D/I: report type mismatch, output postcheck and safe temp handling | I: app auth/rate limits/quarantine/non-executable storage; dependency audit | Application must enforce storage/HTTP controls; library cannot secure deployment alone | INT-001–005, SAN-001 |
| INT-006–007 | — in core; capability reports no network | I: caller-owned hardened fetch; no URL resolvers/delegates | Library does not fetch remote resources | INT-006 |

## What an “analysis passed” can mean

An individual deterministic control may be `passed` only for its documented profile and input. A scan can be `complete` only when all controls required by the selected policy ran successfully. `Unsupported`, `skipped`, `error`, timeout or inconclusive probabilistic outcomes are visible and make coverage partial/incomplete. `policyCompliant=true` means only “the selected policy accepted the declared controls/findings,” not “safe.” The public wording must say “no findings under checks X, Y, Z” and identify omitted checks.

## Metrics and validation gates

For `H` controls, evaluation must publish corpus version, label methodology, sample counts, split strategy, precision, recall, false-positive and false-negative rates, latency and peak memory, threshold, runtime/model/decoder versions and confidence intervals where meaningful. Do not tune and report on the same set. A detector without calibration is `experimental` and cannot be a mandatory allow gate. Sanitizer evaluation separately checks output validity, policy-control coverage, visual fidelity and privacy removal; visual similarity is not a security metric.

## Unresolved research before implementation

Add vendor advisories for each selected decoder/version; exact current CVEs and patch status; official detailed format specifications for each prioritized profile; empirical parser differential tests; peer-reviewed OCR/VLM prompt-injection and adversarial vision literature; deployment-specific isolation feasibility; and license review for every dependency/fixture. This baseline intentionally does not fabricate specific CVE mappings or efficacy claims.
