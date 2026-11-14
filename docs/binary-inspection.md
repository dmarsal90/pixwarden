# Binary inspection

The current Binary Guard performs read-only indicator checks in selected format-defined metadata, extension, or trailer regions for JPEG, PNG, GIF, and WebP. It excludes compressed pixel bitstreams in order to reduce incidental signature matches. It does not execute or recursively unpack bytes.

An indicator is not proof that a complete embedded file exists, and no indicator is not proof that data is absent. Encodings, fragmentation, unsupported containers, and signatures outside inspected regions can evade this profile. The JS detector currently has a broader indicator profile than PHP; consult the runtime capability notes before relying on equivalent coverage.

Use `binaryInspection` findings as one signal in quarantine policy. Do not execute or pass extracted content to a shell, archive utility, or decoder. See the shared [binary vectors](security/03-Security-Test-Corpus.md).
