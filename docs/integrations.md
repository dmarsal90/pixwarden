# Integration patterns

Pixwarden core has no framework dependencies, upload server, storage adapter, CLI, or automatic remote fetch. The application should authenticate and authorize uploads, enforce request-body limits before buffering, use quarantine/non-executable storage, invoke Pixwarden on bytes, inspect coverage/findings, and only then pass an approved artifact to downstream processing.

For Express, Fastify, NestJS, or Next.js, call `scanImage` in server-side code after the framework has applied request-size limits. For Laravel or Symfony, pass bounded bytes to `Scanner::scan()` or a caller-owned stream to `scanStream()`. These are usage patterns, not shipped framework adapters.

Runnable file-ingress examples are available at [`examples/js/scan-file.mjs`](../examples/js/scan-file.mjs) and [`php/examples/scan-file.php`](../php/examples/scan-file.php). The JS example uses a bounded `AsyncIterable` stream; PHP uses `scanStream()` and leaves file ownership with the caller. Both print the typed report and explicitly keep input quarantined unless the verdict, policy compliance, and coverage all permit release. Current profiles report partial coverage, so these examples do not release files.

From the repository root, run the JS example after `npm install` and `npm run build`:

```sh
node examples/js/scan-file.mjs ./untrusted-image.png
```

Run the PHP example after `composer install --working-dir=php`:

```sh
php php/examples/scan-file.php ./untrusted-image.png
```

Do not construct shell commands from filenames. Do not serve an original SVG as an active document when policy requires a static transform. Fix response headers and storage permissions in the host application; Pixwarden does not set them.
