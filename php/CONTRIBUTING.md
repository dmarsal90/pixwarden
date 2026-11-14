# Contributing

Keep changes aligned with `../spec/schemas/pixwarden-v1.schema.json` and the versioned shared corpus. Do not claim a capability unless code, tests, runtime capability reporting, and limitations agree. Use synthetic harmless fixtures; never execute or render extracted data in tests.

Run `composer install`, `composer analyse`, `composer format-check`, `composer test`, `composer audit`, and `composer validate --strict` from this directory. To run the coverage-guided target locally, prepare an empty temporary seed directory with `php scripts/prepare-fuzz-corpus.php /tmp/pixwarden-php-fuzz` and run `php vendor/bin/php-fuzzer fuzz --max-runs 10000 --timeout 1 fuzz/scan-image.php /tmp/pixwarden-php-fuzz`. Add or update shared vectors when changing cross-runtime semantics. The fuzzer is an experimental development tool; minimize and reproduce any finding before adding a checked-in regression.
