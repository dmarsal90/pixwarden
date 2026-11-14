# Integration patterns

Pixwarden core has no framework dependencies, upload server, storage adapter, CLI, or automatic remote fetch. The application should authenticate and authorize uploads, enforce request-body limits before buffering, use quarantine/non-executable storage, invoke Pixwarden on bytes, inspect coverage/findings, and only then pass an approved artifact to downstream processing.

For Express, Fastify, NestJS, or Next.js, call `scanImage` in server-side code after the framework has applied request-size limits. For Laravel or Symfony, pass bounded bytes to `Scanner::scan()` or a caller-owned stream to `scanStream()`. These are usage patterns, not shipped framework adapters.

Do not construct shell commands from filenames. Do not serve an original SVG as an active document when policy requires a static transform. Fix response headers and storage permissions in the host application; Pixwarden does not set them.
