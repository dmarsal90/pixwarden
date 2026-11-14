# Getting started

Pixwarden currently provides bounded byte-level inspection for selected JPEG, PNG, GIF, and WebP profiles, a static SVG allowlist sanitizer, a limited PNG metadata transform, and a restricted RGBA8 PNG raster reconstruction. Read [limitations](limitations.md) before making an allow decision.

## JavaScript

Install the package in a Node.js 22.12+ application with `npm install pixwarden-js`. Supply bytes already obtained by the application:

```ts
import { readFile } from "node:fs/promises";
import { scanImage } from "pixwarden-js";

const bytes = await readFile("upload.bin");
const result = await scanImage(bytes, { hints: { filename: "upload.png", mediaType: "image/png" } });
if (result.verdict !== "allow" || result.coverage !== "complete") {
  throw new Error(`Image requires ${result.verdict} (coverage: ${result.coverage})`);
}
```

The current default profile reports partial coverage because decoder validation and several advanced controls are absent. Consequently the example's strict branch intentionally does not accept ordinary scans; define a reviewed policy in the application only after deciding which controls are mandatory.

## PHP

Install with Composer when the package is available. The PHP runtime has no Node.js dependency. Call `Scanner::scan()` with bytes or `scanStream()` with an open stream; caller-owned streams are not rewound or closed.

```php
$result = (new \Pixwarden\Scanner())->scan($bytes);
if ($result->coverage !== 'complete' || $result->verdict !== \Pixwarden\Verdict::Allow) {
    // Quarantine, reject, or route for review according to application policy.
}
```

All examples are illustrative integration patterns. Pixwarden does not authorize uploads, store files, or set response headers.
