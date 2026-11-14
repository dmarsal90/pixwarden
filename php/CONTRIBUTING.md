# Contributing

Keep changes aligned with `../spec/schemas/pixwarden-v1.schema.json` and the versioned shared corpus. Do not claim a capability unless code, tests, runtime capability reporting, and limitations agree. Use synthetic harmless fixtures; never execute or render extracted data in tests.

Run `composer install`, `composer analyse`, `composer format-check`, `composer test`, and `composer audit` from this directory. Add or update shared vectors when changing cross-runtime semantics.
