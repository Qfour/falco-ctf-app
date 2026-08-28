#!/usr/bin/env python3
"""Design-token single-source gate (app#116, 3-digit extension: review-5x
follow-up on the original PR).

Fails (exit 1) if a raw hex color literal — 6-digit (#RRGGBB) OR 3-digit
shorthand (#RGB) — appears anywhere in
internal/scoreboard/view/templates/*.html outside a comment.
internal/scoreboard/view/static/tokens.css is the ONE place a hex literal
for the Falco CTF palette is written down (app#116); the two templates only
reference it via `var(--...)`.

Why 3-digit needed its own pass, and why this script parses comments
instead of just widening the regex naively:
  - The original app#116 PR's regex only matched 6-digit hex
    (`#[0-9a-fA-F]{6}`), which happened to never false-positive on this
    file's `app#<issue-number>` / `Issue #<issue-number>` comment
    references purely because GitHub issue numbers here are 3-4 digits —
    never 6. That was luck of the numbers, not a real exclusion mechanism.
  - review-5x found 4 pre-existing LEGITIMATE 3-digit hex literals the
    6-digit-only regex had missed (`#000` — mask-image gradient stops in
    both templates' body/.p-shell ::before rules, the terminal
    .term-frame background, and the terminal iframe's inline style). All
    4 are now `var(--ink-black)` (static/tokens.css).
  - Naively widening the regex to 3-OR-6-digit reintroduces a REAL
    false-positive risk this time: this file's comments reference GitHub
    issues as `app#116`, `#125`, `Issue #167`, etc. — 3-digit, hex-shaped
    (decimal digits are valid hex digits too), and NOT inside a string
    format ("app#" / "Issue #") narrow enough to exclude with a prefix
    allowlist (some references are mid-prose: "before #167).",
    "for #124's persistent", "review-5x of #165)" — no single fixed
    prefix covers all of them).
  - The robust fix is to not treat comment TEXT as scannable in the first
    place: a genuine CSS hex color can only ever appear in actual
    CSS/markup, never inside an HTML `<!-- -->` comment or a JS/CSS
    `//`/`/* */` comment in this file (verified: no template comment
    documents an example hex value in `#RRGGBB`/`#RGB` form — the one
    historical case, app#116's own #pane-me doc, was deliberately
    reworded to "hex BDF78B" without the `#` prefix). Blanking comment
    bodies (replacing non-newline characters with spaces, so line/column
    numbers stay accurate for the FAIL report) before running the hex
    regex closes the false-positive hole structurally, for ANY future
    issue-number mention, not just today's 5 known ones.
"""
import re
import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "internal" / "scoreboard" / "view" / "templates"

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")

# Exactly 3 or 6 hex digits, with a trailing word boundary so a longer run
# (e.g. an 8-digit #RRGGBBAA, not used in this codebase today) can't be
# partial-matched as a false 3- or 6-digit hit — see module doc.
HEX_RE = re.compile(r"#(?:[0-9a-fA-F]{3}){1,2}\b")


def _blank(match: "re.Match[str]") -> str:
    """Replace every non-newline character in match with a space, so
    downstream line/column numbers are unaffected by the substitution."""
    return re.sub(r"[^\n]", " ", match.group(0))


def strip_comments(src: str) -> str:
    src = _HTML_COMMENT.sub(_blank, src)
    src = _BLOCK_COMMENT.sub(_blank, src)
    src = _LINE_COMMENT.sub(_blank, src)
    return src


def main() -> int:
    if not TEMPLATES_DIR.is_dir():
        print(f"FAIL: templates dir not found: {TEMPLATES_DIR}", file=sys.stderr)
        return 1

    print("==> scanning templates/*.html for raw hex color literals (3- and 6-digit, comments excluded)")
    hits: list[str] = []
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        original = path.read_text(encoding="utf-8")
        scannable = strip_comments(original)
        rel = path.relative_to(REPO_ROOT)
        for lineno, line in enumerate(scannable.splitlines(), start=1):
            for m in HEX_RE.finditer(line):
                hits.append(f"{rel}:{lineno}: {m.group(0)}")

    if hits:
        print("FAIL: raw hex color literal(s) found in internal/scoreboard/view/templates/*.html:", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        print(
            "  → templates must reference design tokens via var(--...); add a new\n"
            "    token to internal/scoreboard/view/static/tokens.css (single hex\n"
            "    source, app#116) instead of hand-typing a hex literal here.",
            file=sys.stderr,
        )
        return 1

    print("  ok: no raw hex literals in templates/*.html (outside comments) — tokens.css is the single source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
