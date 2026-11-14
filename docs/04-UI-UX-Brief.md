# Pixwarden Developer Experience Brief

**Document ID:** PW-UX · **Version:** 0.1.0 · **Status:** Phase 0/1 baseline · **Updated:** 2026-11-13

Pixwarden is a library, so the interface is its API, types, errors, examples and reports. There is no dashboard requirement.

## Principles

1. **Explicit capability:** inspect, decode, sanitize and optional AI analysis are separate options and separately reported.
2. **Safe defaults:** no network, telemetry, implicit filesystem writes, framework dependency or remote model call.
3. **Predictable configuration:** one versioned options model with bounded resource limits; unknown keys fail validation where possible.
4. **Visible uncertainty:** result surfaces `unsupported`, `skipped`, `error`, confidence semantics and residual risk.
5. **Typed integration:** TypeScript discriminated unions and PHP enums/value objects; stable machine-readable error codes.
6. **Reviewable transformations:** sanitizer returns a new artifact and transformation summary; never mutates caller input.
7. **Privacy-safe hints:** filename and MIME hints can be compared with detected bytes, but raw values are not retained in scan reports.

## API shape

Expose a small top-level scan function in JS and an object API in PHP, with parity in meaning. Prefer byte buffers/streams and an explicit request object; do not use magic filename-based overloads. Cancellation is standard (`AbortSignal` / cancellation token where feasible). Results are immutable snapshots. Provide a capability query so applications can inspect installed optional adapters before accepting a policy.

Every error message should say which stage failed and offer a next action without exposing sensitive input, filesystem paths or native stack traces. Exception classes are stable; callers should branch on error code, not message text. Long-running integrations can emit progress events only if event order and cancellation semantics are specified.

## Documentation and examples

Docs are authored in English with a future localization structure. Quick start must state which formats are actually enabled in the package build. Separate guides cover installation, policy design, limits, SVG, binary payloads, steganography, AI adapter data flow, sanitization trade-offs, integration and troubleshooting. Executable examples require fixtures and commands and must not show aspirational options as released functionality.

Examples should include safe upload quarantine, explicit reject/review behavior, sanitation to new output, optional binary scan, optional steganography, opt-in OCR/AI, and Express/Fastify/Nest/Next server-side plus Laravel/Symfony adapters. Framework integrations remain optional packages.

CLI is deferred until a concrete use case exists. If added, it must emit JSON deterministically, return documented exit codes, avoid printing extracted private metadata by default, and require explicit output paths. No visual dashboard.

## Acceptance and migration

DX is accepted when each supported runtime has a minimal installation, typed quick start, configuration reference, error/decision example and working integration sample; PHP/JS names for equivalent concepts are documented; generated API docs match the shipped package; upgrade guides call out schema/report changes. Requirements: PRD-009–013 and TRD sections 6–7.
