# Avatar glyphs — first-party, hand-drawn (ADR-0034 D9, S1)

The 8 pictograms a participant picks from for their profile picture. They are
served by the `/static/` registry (ADR-0028) under the logical names
`avatars/<glyph>.svg`, which the registry turns into
`/static/avatars-<glyph>.<hash>.svg`. The picture's id is `<glyph>-<color>`; the
color is NOT in these files (see "Color" below).

## Origin

**Self-authored** by the design-engineer role of this project (an AI agent
working for the repository owner), 2026-10-13, for this repository. Each glyph
was written directly as SVG path data from simple geometry (circles, arcs,
rectangles, straight segments) on a 24 x 24 grid and checked by rendering it on
the six avatar colors. **No path data was copied or traced from an icon set, a
font, a logo or any other third-party artwork**, so there is no upstream, no
version pin and no third-party license to carry. Subjects are generic
pictograms (a shield, a key, a padlock, a terminal prompt); any resemblance to
the common way such icons are drawn is the resemblance of the subject, not of
the file.

**License**: the same as the repository, Apache-2.0 (`/LICENSE`). If a glyph is
ever replaced by third-party artwork, record here, per file: the upstream URL,
the version or commit, the sha256 of the file as fetched, and the license, and
take only artwork under OFL, CC0 or a compatible permissive license.

## Files

| file | subject | bytes | sha256 |
|---|---|---|---|
| `falcon.svg` | a bird front-on, wings swept up (the falcon of Falco CTF) | 205 | `86c596d0b09e2ab9551a19170afab2bc75daaf5cf62c84cbc38786e9abb1feaa` |
| `shield.svg` | a shield with a check cut out | 216 | `cea26beffea86d047465f49b4e7d0f0916cd8bef252c3844cd06c0e8c72a8be1` |
| `key.svg` | a key: ring bow, shaft, two teeth | 328 | `877048d338ab05a2d097dec0ee914a082c6287905c94149a62b0cfe3b55f0588` |
| `terminal.svg` | a terminal window with a `>_` prompt cut out | 250 | `21e743ce624b797019223a1665526e0bb6531c071ff9ea2244d52b16970ea780` |
| `radar.svg` | two rings, a center dot and a sweep line | 402 | `171727ba3bdc9cdc58ef36b29dd2fc359c88b26cdbc4db52698850097081ea70` |
| `lock.svg` | a padlock with a keyhole cut out | 301 | `4ab684dd0fe40fe9a74285976dfb42d3689966aed6cc2b8f7ba0e8149feff034` |
| `bug.svg` | a beetle seen from above: body, head, six legs, two antennae | 394 | `0d01bef9d66f041568f9cd518a085eb4e7a735fca2092436f41ba36087804e6b` |
| `flame.svg` | a flame with a small flame cut out | 303 | `47709de8d461b1b4eec43f7a8ac24b932bb69a4429715a3a06357b34a41ef5d8` |

`falcon` is the one glyph that stands for the project; the rest are the CTF
vocabulary (defend, secret, shell, detect, lock, vulnerability, incident).

## Format rules (enforced at start-up, not by this prose)

`svgsanitize.go` parses every `.svg` when the registry is built and refuses the
scoreboard's start-up on anything outside its allow-list: elements `svg`, `g`,
`path`, `circle`, `ellipse`, `rect`; attributes `xmlns`, `viewBox` (fixed
`0 0 24 24`), `fill` (`#fff` or `none`), `fill-rule`, `d`, and plain numeric
geometry; no `href` of any kind, no `style`, no text, no comment, no
processing instruction, no DOCTYPE/ENTITY, at most 4 KB. A new glyph that needs
anything else is a change to that allow-list, which needs a security-engineer
review. The `.svg` response also carries
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`
and `X-Content-Type-Options: nosniff` (ADR-0034 D9 (b)).

## Color

Each glyph is a single white (`#fff`) fill with transparent surroundings. The
background color is applied by the page, on the `<img>` element, from the
`--avatar-<color>` variables in `../tokens.css` (`css-avatar.tmpl`:
`.avatar-<color>`). A CSS variable does not resolve inside an SVG loaded through
`<img>`, and the glyph is never inlined into the page (ADR-0034 D9 (c)), so the
colors cannot live in these files.

## Adding or changing a glyph

1. Draw it on the 24 x 24 grid, white fill, keep it under 3 KB.
2. Add it to `avatarAssetGlyphs` in `staticassets.go` and to `wantLogicalNames`
   and `wantAvatarGlyphs` in the tests (the registry pin: security-engineer
   review).
3. Update the table above (bytes, sha256: `shasum -a 256 <file>`).
