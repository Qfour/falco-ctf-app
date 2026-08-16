# cybercore-css — vendored, self-hosted (P23-6)

**Source**: https://github.com/sebyx07/cybercore-css (MIT, JS-free CSS component/utility library)

## Pin

| field | value |
|---|---|
| npm package | `cybercore-css` |
| npm version (pinned) | `0.3.0` |
| npm dist-tag at fetch time | `latest` (== `0.3.0`) |
| **npm tarball integrity (registry `dist.integrity`, SHA-512 — PRIMARY check)** | `sha512-ZvNFKcTKB86ehnHBzzcTO7SnOT6P0BTFr/szGYdz4G6qhylkRoL58dvk7yfL2O+Y7I/1dmHeIDykrZnS6C8wcg==` |
| local re-verify (`openssl dgst -sha512 -binary cybercore-css-0.3.0.tgz \| base64`) | `ZvNFKcTKB86ehnHBzzcTO7SnOT6P0BTFr/szGYdz4G6qhylkRoL58dvk7yfL2O+Y7I/1dmHeIDykrZnS6C8wcg==` (match) |
| npm tarball shasum (registry `dist.shasum`, SHA-1 — secondary/legacy check) | `b28e21ad8bab73bb72a06524fa487b6e20debb0f` |
| local re-verify (`shasum -a 1 cybercore-css-0.3.0.tgz`) | `b28e21ad8bab73bb72a06524fa487b6e20debb0f` (match) |
| upstream git tag | `v0.3.0` (`repos/sebyx07/cybercore-css/tags`) |
| upstream commit (npm `gitHead` field, `0.3.0`) | `ce1e55ec01c3fd3f780999e62851747012af7f6b` |
| license | MIT (`LICENSE`, copied verbatim alongside this file) |

SHA-512 `integrity` is the PRIMARY provenance check (2026-08-16 /review-5x
R3 nit fixup — matches P12's digest-pin discipline elsewhere in this repo,
e.g. base-image `@sha256:...` pins: prefer the stronger, collision-resistant
hash as the check that actually gates a pin bump). The npm registry's
`dist.shasum` (SHA-1) is kept as a secondary/legacy cross-check only — SHA-1
is not itself relied upon to detect a tampered tarball here, npm just still
publishes it alongside `integrity` for backward compatibility with older
tooling.

`dist/cybercore.min.css` from the `0.3.0` npm tarball is copied verbatim into
`cybercore.min.css` in this directory (byte-for-byte; not re-built from SCSS —
this repo does not run node/sass, so vendoring the npm-published, pre-built
artifact keeps the pin verifiable by shasum rather than by "trust the build
output"). `dist/cybercore.css` (unminified) and the `.map` sourcemaps are
NOT vendored — the app only ever serves the minified file, and the maps are
dev-only artifacts with no runtime value here.

## Why self-host (go:embed) instead of CDN

P12 (supply chain / egress lockdown) treats the prod workspace's outbound
network surface as a hard boundary — see REFACTORING.md P23-6: "CDN 不可 =
egress/P12". Loading this CSS from a third-party CDN would add an
uncontrolled runtime dependency (availability + supply-chain: a CDN swap-out
could serve different bytes at any time) that a git-SHA-pinned, go:embed'd
file does not have. `internal/scoreboard/view/vendorassets.go` embeds this
exact file into the scoreboard binary and serves it from `/vendor/cybercore.min.css`
(same-origin, no external HTTP request the browser needs to make for this
asset).

## External references inside the file (audited)

`grep -oE "https?://[^\"')]+"` against the vendored file matches exactly one
string: `http://www.w3.org/2000/svg` — the XML namespace declared inside
several `url("data:image/svg+xml,...")` inline data URIs (icon glyphs / a
noise-filter SVG). This is a namespace identifier, not a network fetch: the
browser never dereferences it, and every `url(...)` in the file is a
`data:` URI (verified: zero non-`data:` `url(...)` occurrences, zero
`@import`). Egress-zero holds.

## Bump procedure

1. Pick a new npm version (or re-verify `latest` is still what's expected).
2. `curl -sL -o cybercore-css-<ver>.tgz https://registry.npmjs.org/cybercore-css/-/cybercore-css-<ver>.tgz`
3. **Primary check**: compare `openssl dgst -sha512 -binary cybercore-css-<ver>.tgz | base64`
   against the registry's `dist.integrity` (strip the `sha512-` prefix) for
   that version (`curl -s https://registry.npmjs.org/cybercore-css/<ver> | jq -r .dist.integrity`).
   Secondary/legacy cross-check: `shasum -a 1` against `dist.shasum` from the
   same response.
4. `tar xzf ... package/dist/cybercore.min.css package/LICENSE` and overwrite
   the two files in this directory.
5. Re-run the external-reference audit above (`grep -oE 'https?://[^"'\'')]+'`
   and `grep -c '@import'`) before committing — a future upstream release
   could introduce an external font/CDN reference that must not land here.
6. Update this file's pin table (npm version / integrity / shasum / gitHead /
   git tag) and re-measure gzip size in the PR description.
7. `make test` (embed + CSP tests) and a colima smoke check
   (`make dev` / `make load-colima` → open `/portal`, confirm no console
   errors and the visual theme still resolves — a component/variable rename
   upstream could silently drop styling `internal/scoreboard/view/templates/portal.html`'s
   Falco-brand override block depends on).
