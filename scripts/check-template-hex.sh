#!/usr/bin/env bash
# Design-token single-source gate (app#116).
#
# Fails (non-zero) if a raw hex color literal — 6-digit (#RRGGBB) or 3-digit
# shorthand (#RGB) — appears anywhere in
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
#
# The actual match/exclude logic (including comment-stripping so
# `app#125`-style GitHub issue references in HTML/JS/CSS comments don't
# false-positive as 3-digit hex — see that script's module doc for why a
# naive regex-only widening to 3-digit isn't safe) lives in
# check-template-hex.py; this is a thin, `make`-friendly entry point.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec python3 scripts/check-template-hex.py
