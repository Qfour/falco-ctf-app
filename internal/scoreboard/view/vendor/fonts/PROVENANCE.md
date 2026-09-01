# Google Fonts — vendored, self-hosted (app#96 / P12 follow-up)

Replaces the portal's external `<link href="https://fonts.googleapis.com/css2?...">`
(pre-existing since before P23-6; see csp.go's old portalCSP doc) with the
exact same 10 family+weight combinations, served same-origin. Follows the
same go:embed self-host pattern as `../cybercore/` (P23-6) — see that
directory's `PROVENANCE.md` for the general "why self-host" rationale
(P12 egress-zero / supply-chain), not repeated here.

## Fetch

Source stylesheet: Google Fonts' css2 API, the EXACT URL
`templates/portal.html`'s pre-existing `<link>` used to request:

```
https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap
```

Fetched 2026-09-01 with a modern-desktop-Chrome `User-Agent` (Google's css2
endpoint varies the response — format (woff2 vs woff/ttf) and unicode-range
subset count — by the requester's `User-Agent`; a modern UA is what yields
woff2 + the per-script-subset split below, matching what every participant's
actual browser receives).

## Subset scope: `latin` only

The full response splits each family+weight into 7-10 `@font-face` blocks
(cyrillic, cyrillic-ext, greek, greek-ext, latin, latin-ext, thai,
vietnamese — Google serves one file per unicode-range subset so a browser
only downloads the glyphs it needs). This CTF's portal content, catalog
text, and participant-supplied display names are English/Latin-script only
— vendoring every subset would 5-10x the embedded binary size for glyph
coverage nothing in this app renders. Only the `/* latin */` block per
family+weight is vendored (`unicode-range: U+0000-00FF, U+0131, ...` — see
`fonts.css`, identical range on every rule copied verbatim from Google's
response). If a future change needs non-Latin glyph coverage (e.g.
internationalized display names), that is a deliberate follow-up (add the
needed subset's block + font file), not an oversight here.

## Variable fonts: fewer files than @font-face rules

Inter and JetBrains Mono are published by Google Fonts as variable fonts —
requesting several static weights returns several `@font-face` blocks that
all point at the SAME woff2 URL (a single variable-axis file); a modern
browser instantiates the declared `font-weight` along the file's `wght` axis
per rule. Chakra Petch is not a variable font upstream, so its 3 weights are
3 distinct files. Net: **10 `@font-face` rules, 5 vendored files.**

## Pin table

| file | family / weight(s) | upstream URL (fonts.gstatic.com) | sha256 (this repo's copy) |
|---|---|---|---|
| `chakrapetch-500.woff2` | Chakra Petch 500 | `https://fonts.gstatic.com/s/chakrapetch/v13/cIflMapbsEk7TDLdtEz1BwkebIl1R5_F.woff2` | `36ad966cb653de70ba37355c41003b02de8940b2df6cbcd46480a6ad8cadd65d` |
| `chakrapetch-600.woff2` | Chakra Petch 600 | `https://fonts.gstatic.com/s/chakrapetch/v13/cIflMapbsEk7TDLdtEz1BwkeQI51R5_F.woff2` | `a5888696e9eb1b4bbbecc8eb3922b8369f49d4bddb72263e033cbd17f399be76` |
| `chakrapetch-700.woff2` | Chakra Petch 700 | `https://fonts.gstatic.com/s/chakrapetch/v13/cIflMapbsEk7TDLdtEz1BwkeJI91R5_F.woff2` | `ce5095dc1cb200aaa939e38067a0677018d10e9f26ec38cdcf1557ac524fc775` |
| `inter-var.woff2` | Inter 400/500/600/700 (variable, one file) | `https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1ZL7.woff2` | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| `jetbrainsmono-var.woff2` | JetBrains Mono 400/500/700 (variable, one file) | `https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxDcwg.woff2` | `83c005d49d8a6a50474c73a5a36ac0468076e9c4a29da7bdb14995d80560a5be` |

`fonts.gstatic.com`'s file URLs are themselves content-addressed (the path
segment encodes a content hash Google's own infra uses for cache-busting on
any byte change), so the URL + a locally re-computed sha256 together give
the same "primary strong-hash, re-verify locally" discipline
`vendor/cybercore/PROVENANCE.md` documents for its npm tarball — there is no
`dist.integrity`-style registry field for a raw gstatic asset the way npm
publishes one, so the URL's own content-addressing plus this table's sha256
is the equivalent check here.

## License

All three families ship under the **SIL Open Font License, Version 1.1**
(OFL), copied verbatim into this directory:

| file | family | upstream OFL.txt (google/fonts repo) | commit fetched |
|---|---|---|---|
| `LICENSE-chakrapetch.txt` | Chakra Petch | `ofl/chakrapetch/OFL.txt` | `a4c8c2a0f77efa06765d596d64d077af1d7f0dae` (2026-02-26) |
| `LICENSE-inter.txt` | Inter | `ofl/inter/OFL.txt` | `0b58fb370093f9a9f4ff785d94405710b79de67c` (2026-03-03) |
| `LICENSE-jetbrainsmono.txt` | JetBrains Mono | `ofl/jetbrainsmono/OFL.txt` | `6e4b84c976cadb3c49a40fd9a1c203e4f7fcf2da` (2026-03-03) |

OFL §1 permits bundling/embedding the font in a larger software distribution
(here: a go:embed'd file served by the scoreboard binary) without triggering
the "Reserved Font Name" restrictions, provided the license text travels
with the font — hence the three `LICENSE-*.txt` files kept alongside the
`.woff2` files rather than a single repo-wide notice.

## External references inside `fonts.css` (audited)

`grep -oE "https?://[^)]+" fonts.css` matches zero results — every `src:
url(...)` in the vendored stylesheet is a same-origin `/vendor/fonts/*.woff2`
path (`grep -c '@import'` is also zero). Egress-zero holds, mirroring
`vendor/cybercore/PROVENANCE.md`'s equivalent audit.

## Bump procedure

1. Re-fetch the SAME css2 URL above with a modern-desktop-Chrome
   `User-Agent` (`curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)
   AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<N>.0.0.0 Safari/537.36"
   "<url>"`).
2. Extract only the `/* latin */`-commented `@font-face` blocks.
3. Dedup by `src: url(...)` (variable-font families collapse to one file —
   see above) and download each unique URL.
4. `shasum -a 256` every downloaded file and update this table.
5. Re-run the external-reference audit (`grep -oE 'https?://[^)]+'` and
   `grep -c '@import'` over the new `fonts.css`) before committing.
6. Re-fetch each family's `OFL.txt` from
   `https://raw.githubusercontent.com/google/fonts/main/ofl/<family>/OFL.txt`
   only if the license text itself changed (rare — OFL text is near-static
   across font updates); update the commit-sha table above either way to
   record the check was re-done.
7. `make test` (embed + CSP tests) and a colima smoke check (`make dev` /
   `make load-colima` → open `/portal` and `/`, confirm no console
   errors/network requests to `fonts.googleapis.com`/`fonts.gstatic.com`,
   and every heading/mono text still renders in the intended typeface).
