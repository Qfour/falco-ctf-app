#!/usr/bin/env bash
# Flag-hygiene gate for the PUBLIC repo. Fails (non-zero) if:
#   1. any tracked file carries a real FALCO{...} flag literal, or
#   2. generated challenge values are out of sync with plant.sh.
#
# Allowed flag forms (these are not secrets):
#   FALCO{dev-<slug>}   local-dev / test placeholders
#   FALCO{...}          literal ellipsis used in docs/help text
# Go unit tests (*_test.go) may use arbitrary fixtures and are exempt.
#
# Real per-event flags live only in falco-ctf-platform events/<date>/flags.sops.yaml
# and are injected at deploy time (FLAGS_FILE for scoring, CTF_FLAG_* for planting).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

rc=0

echo "==> scanning tracked files for real flag literals"
bad=$(git grep -hoE 'FALCO\{[^}]*\}' -- . ':(exclude)*_test.go' 2>/dev/null \
  | sort -u \
  | grep -vE '^FALCO\{dev-.*\}$' \
  | grep -vE '^FALCO\{\.\.\.\}$' || true)
if [ -n "$bad" ]; then
  echo "FAIL: non-placeholder flag literal(s) found in tracked files:" >&2
  echo "$bad" | sed 's/^/  /' >&2
  echo "  locations:" >&2
  while IFS= read -r tok; do
    git grep -nF "$tok" -- . ':(exclude)*_test.go' | sed 's/^/    /' >&2
  done <<< "$bad"
  echo "  → move the real flag to platform events/<date>/flags.sops.yaml; use FALCO{dev-...} here." >&2
  rc=1
else
  echo "  ok: only FALCO{dev-...} / FALCO{...} placeholders present"
fi

echo "==> checking generated challenge values are in sync"
if ! ./challenges/gen-values.sh --check; then
  echo "  → run 'make gen-values' and commit the result" >&2
  rc=1
fi

exit "$rc"
