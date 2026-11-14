# Installation

## JavaScript / TypeScript

Requirements: Node.js 22.12 or newer. Install from npm after a release exists:

```sh
npm install pixwarden-js
```

The package publishes ESM and CommonJS entry points with TypeScript declarations. Node.js selects the matching entry for `import` or `require`. The only runtime dependency is the XML parser used by the SVG profile. The library does not call external services.

## PHP

Requirements: PHP 8.2 or newer. The optional SVG parser requires `ext-dom`.

```sh
composer require dmarsal90/pixwarden-php
```

PHP is a native implementation and does not invoke Node.js. Framework integrations are caller-side examples; no Laravel or Symfony dependency is required by the core.

## Release status

Registry commands become usable only after an authorized release. Until then, clone the repository and follow its development instructions. Verify the package name, namespace ownership, license decision, dependency advisories, and release artifacts again immediately before publication.
