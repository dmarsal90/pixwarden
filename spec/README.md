# Pixwarden shared specification

This directory is the in-repository seed for the planned `pixwarden-spec` source of truth. Contract IDs and report taxonomies are versioned independently from runtime packages. The JSON Schema file is normative for JSON shape; semantic rules such as `offset + length <= inputBytes` must also be enforced by implementations.

## Version 0.1.0

- Schema dialect: JSON Schema Draft 2020-12.
- Canonical artifact: `schemas/pixwarden-v1.schema.json`.
- Reusable contract names are under `$defs`; each main contract has a versioned golden example in `examples/`, and CI validates the examples.
- Object contracts reject unknown properties except explicitly open maps such as capabilities and scalar evidence attributes.
- `specVersion` and `resultVersion` change under separate compatibility rules in `docs/05-Backend-Schema.md`.
- Do not publish the local URN or package metadata as a public-domain commitment.

The JS CI validates the schema and examples with the Draft 2020-12 Ajv implementation. PHP must consume these same files and examples; it must not translate the contract into a runtime-specific shape.
