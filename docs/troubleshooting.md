# Troubleshooting

| Symptom | Meaning / response |
|---|---|
| `review` with partial coverage | One or more controls or format features are unsupported, skipped, or incomplete. Inspect `controls`, `limitations`, and `capabilities`; do not treat as clean. |
| `reject` with `IMG-*` | A selected structural profile found malformed/inconsistent input. Preserve the original only in controlled quarantine and use the finding evidence offsets for diagnostics. |
| `DEC-007` or `DEC-008` | Declared dimensions, pixels, or frame count exceed configured thresholds. Do not decode downstream without a separately enforced policy. |
| JS worker timeout | Worker was terminated at the configured wall-time boundary. It does not imply OS memory or CPU containment. |
| PNG transform rejects input | The sanitizer requires structurally accepted PNG bytes, at most 10 MiB, and within built-in dimension bounds. It does not repair malformed inputs. |
| Registry install fails | The package may not yet be published. Check repository release status; do not substitute an unrelated package with a similar name. |

For bug reports, include runtime/package version, a minimal synthetic reproducer, observed report fields, and expected behavior. Do not attach private images or operational malware.
