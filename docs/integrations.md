# Integration patterns

Pixwarden core has no framework dependencies, upload server, storage adapter, CLI, or automatic remote fetch. The application should authenticate and authorize uploads, enforce request-body limits before buffering, use quarantine/non-executable storage, invoke Pixwarden on bytes, inspect coverage/findings, and only then pass an approved artifact to downstream processing.

For Express, Fastify, NestJS, and Next.js, runnable server-side examples are provided below. For Laravel or Symfony, pass bounded bytes to `Scanner::scan()` or a caller-owned stream to `scanStream()`.

Runnable file-ingress examples are available at [`examples/js/scan-file.mjs`](../examples/js/scan-file.mjs) and [`php/examples/scan-file.php`](../php/examples/scan-file.php). The JS example uses a bounded `AsyncIterable` stream; PHP uses `scanStream()` and leaves file ownership with the caller. Both print the typed report and explicitly keep input quarantined unless the verdict, policy compliance, and coverage all permit release. Current profiles report partial coverage, so these examples do not release files.

From the repository root, run the JS example after `npm install` and `npm run build`:

```sh
node examples/js/scan-file.mjs ./untrusted-image.png
```

Run the PHP example after `composer install --working-dir=php`:

```sh
php php/examples/scan-file.php ./untrusted-image.png
```

The HTTP examples are optional and do not add framework dependencies to Pixwarden. From the repository root, install Express or Fastify in the application that will run the example, build Pixwarden, and start the chosen server:

```sh
npm install express
npm run build
node examples/js/express-upload.mjs
```

```sh
npm install fastify
npm run build
node examples/js/fastify-upload.mjs
```

Send raw image bytes to `POST /images/inspect`; the examples cap request bodies at 10 MiB and return the typed report. They bind to localhost by default. Add application authentication, rate limiting, logging controls and quarantine/storage decisions before exposing an endpoint to untrusted clients. Current inspection coverage is partial, so these examples do not release uploaded files.

For NestJS, copy [`nest-upload.ts`](../examples/js/nest-upload.ts) into a Nest application configured for the Express adapter and run it with the application's TypeScript runner. The host application needs `@nestjs/common`, `@nestjs/core`, `@nestjs/platform-express`, `express`, and `reflect-metadata`. The example disables Nest's default body parser and installs a bounded raw body parser for the inspection route. For Next.js App Router, copy [`next-route.ts`](../examples/js/next-route.ts) to `app/api/images/inspect/route.ts`; it uses the Node.js runtime and streams the request body through Pixwarden's byte cap. Both examples bind request handling to the same 10 MiB policy. Apply authentication and upstream request limits in the host application.

Do not construct shell commands from filenames. Do not serve an original SVG as an active document when policy requires a static transform. Fix response headers and storage permissions in the host application; Pixwarden does not set them.
