# License evaluation

**Status:** decision pending; no license change is made by this document.

This is a project decision aid, not legal advice. The repository currently contains an MIT `LICENSE`, and package metadata currently declares MIT. The first public package release has not been made.

## Options

| License | Main fit | Patent terms | Reuse and obligations | Pixwarden trade-off |
|---|---|---|---|---|
| MIT | Minimal, permissive licensing | No comparable express patent grant in the short license text | Broad reuse, including closed-source products, with copyright and license notice retention | Lowest friction; contributors and adopters have less express patent language |
| Apache-2.0 | Permissive projects that want explicit patent terms | Express contributor patent grant with a patent-litigation termination clause | Broad reuse, including closed-source products; preserve notices and comply with redistribution conditions | Better fit for a security library distributed into varied commercial stacks; longer license and notice handling |
| MPL-2.0 | File-level copyleft with permissive larger-work integration | Express contributor patent grant and patent-litigation termination clause | Modified MPL-covered files remain under MPL when distributed; larger works may use other terms if MPL conditions are met | Offers reciprocal sharing of changes to covered files, with more compliance work for adopters |

MIT and Apache-2.0 are OSI-approved permissive licenses; MPL-2.0 is OSI-approved and file-level copyleft. Apache-2.0's grant and termination terms are in sections 3 and 3–5 respectively; MIT's principal conditions are retaining its copyright and permission notice. MPL-2.0 specifies patent grants and distribution responsibilities for covered source and executable forms.

## Project-specific recommendation

**Apache-2.0 is the recommended candidate** if the project wants a permissive license while making contributor patent terms explicit. MIT is a sound choice if keeping adoption and compliance as simple as possible is the priority. MPL-2.0 is the alternative if the project wants distributed modifications to covered files to remain available under the same license.

All three permit reuse under their terms. A condition intended to prohibit reuse, commercial use, or redistribution is not compatible with an OSI-approved open-source license. A custom source-available restriction would be a different licensing model and would require a separate product decision.

No candidate is selected here. The current MIT license remains in place until the rights holder explicitly chooses a change. If changing it before first package publication, review contribution ownership and third-party dependency terms, replace the root `LICENSE`, update both package manifests and license documentation, and record the decision in the changelog. A license change does not retroactively revoke permissions already granted under MIT.

## References

- [OSI: MIT License](https://opensource.org/license/mit)
- [Apache Software Foundation: Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)
- [OSI: Mozilla Public License 2.0](https://opensource.org/license/mpl-2.0)
- [OSI: Open Source Definition](https://opensource.org/osd)
