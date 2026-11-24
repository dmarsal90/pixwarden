# Release Readiness: Names and Licensing

**Document ID:** PW-RELEASE-READINESS · **Version:** 0.1.0 · **Reviewed:** 2026-11-14 · **Status:** Not approved for publication

## Registry name checks

The following names were checked on 2026-11-14. Registry availability is a snapshot and must be checked again immediately before any package or repository creation.

| Target | Check | Result at review | Gate |
|---|---|---|---|
| npm `pixwarden-js` | `npm view pixwarden-js`; npm search | Registry returned 404; no exact search result | Recheck in npm before first publish |
| Packagist `dmarsal90/pixwarden-php` | Packagist package endpoint and search | Package endpoint returned 404; no exact search result | Recheck in Packagist before first publish |
| GitHub `dmarsal90/pixwarden-spec` | GitHub repository API | 404; repository not present | Recheck before creating the repository |
| GitHub `dmarsal90/pixwarden-js` | GitHub repository API | 404; repository not present | Recheck before creating the repository |
| GitHub `dmarsal90/pixwarden-php` | GitHub repository API | Repository created 2026-11-24 (private) | Make public before first Packagist publish |

`Pixwarden\\` is a PHP source namespace, not a centrally reserved registry identifier. Packagist has no exact `Pixwarden` package result as of this review, but Composer does not reserve PHP namespaces globally; maintainers must still check for conflicts when integrating dependencies and avoid claiming exclusive ownership of the namespace.

No packages or repositories were created or published as part of these checks.

## License choice

The repository, npm metadata, Composer metadata and current `LICENSE` file say MIT. This records the existing tree state; it does not resolve the product owner's requested license decision. Do not alter license files or publish until the owner explicitly selects a project license.

| Candidate | Practical tradeoff |
|---|---|
| MIT | Short and simple redistribution conditions. The OSI lists MIT as an approved open-source license. |
| Apache-2.0 | More detailed redistribution and NOTICE requirements; it includes an express contributor patent grant and patent-litigation termination clause. The OSI lists Apache-2.0 as approved. |

Primary texts: [OSI MIT license](https://opensource.org/license/mit), [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), and the [OSI approved-license list](https://opensource.org/licenses).

## Dependency-license snapshot

The runtime dependency surface is permissive and small:

- JS production tree: `saxes@6.0.0` (ISC) and `xmlchars@2.2.0` (MIT), from the CycloneDX SBOM generated on 2026-11-14.
- PHP (in `pixwarden-php`) runtime requirements: PHP 8.2 or newer; no Composer runtime packages are required.
- PHP development dependency licenses observed by `composer licenses`: MIT, BSD-3-Clause and Apache-2.0.
- The complete npm development SBOM also contains CC-BY-4.0, BlueOak-1.0.0 and MPL-2.0 components, in addition to MIT, ISC, Apache-2.0 and BSD-3-Clause. These are development/build dependencies; `package.json` limits the npm tarball to `dist`, README, SECURITY and LICENSE. Re-audit the exact release tarball and dependency tree before publishing.

The scan found no current license incompatibility for the declared runtime dependencies. It is not legal advice and does not replace review of the selected license, notices and exact release artifacts.

## Release gates

1. The owner makes an explicit MIT or Apache-2.0 decision before license metadata changes.
2. Recheck npm, Packagist, GitHub repository and namespace conflicts at release time.
3. Re-run dependency and license audits against the exact lockfiles and built artifacts.
4. Publish only after all project acceptance criteria and security review are complete and the owner authorizes release.
