#!/usr/bin/env bash
# Design-token single-source gate (app#116).
#
# Fails (non-zero) if a raw hex color literal (`#RRGGBB`) appears anywhere in
# internal/scoreboard/view/templates/*.html. Before app#116, the SAME hex
# codes were hand-duplicated across index.html and portal.html in three
# separate `:root` namespaces with nothing stopping them from silently
# drifting apart. internal/scoreboard/view/static/tokens.css is now the ONE
# place a hex literal for the Falco CTF palette is written down; the two
# templates only reference it via `var(--...)`. This script makes that
# mechanical rather than a convention someone can forget.
#
# Only templates/*.html are in scope — NOT static/tokens.css itself (the
# single source is SUPPOSED to hold the literals) and NOT the vendored
# cybercore.min.css (a pinned third-party file, not hand-authored here; see
# vendor/cybercore/PROVENANCE.md).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "==> scanning templates/*.html for raw hex color literals"
hits=$(grep -noE '#[0-9a-fA-F]{6}' internal/scoreboard/view/templates/*.html 2>/dev/null || true)
if [ -n "$hits" ]; then
  echo "FAIL: raw hex color literal(s) found in internal/scoreboard/view/templates/*.html:" >&2
  echo "$hits" | sed 's/^/  /' >&2
  echo "  → templates must reference design tokens via var(--...); add a new" >&2
  echo "    token to internal/scoreboard/view/static/tokens.css (single hex" >&2
  echo "    source, app#116) instead of hand-typing a hex literal here." >&2
  exit 1
fi
echo "  ok: no raw hex literals in templates/*.html — tokens.css is the single source"
