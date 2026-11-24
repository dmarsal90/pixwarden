# Installation

## JavaScript / TypeScript

Requirements: Node.js 22.12 or newer. Install from npm after a release exists:

```sh
npm install pixwarden-js
```

The package publishes ESM and CommonJS entry points with TypeScript declarations. Node.js selects the matching entry for `import` or `require`. The only runtime dependency is the XML parser used by the SVG profile. The library does not call external services.

## PHP

The PHP runtime is a separate package in its own repository, `pixwarden-php`.

## Release status

Registry commands become usable only after an authorized release. Until then, clone the repository and follow its development instructions. Verify the package name, namespace ownership, license decision, dependency advisories, and release artifacts again immediately before publication.
