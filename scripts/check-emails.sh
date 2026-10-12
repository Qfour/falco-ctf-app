#!/usr/bin/env bash
# Public-repo hygiene gate (ADR-0034 V17, 条件 14): no tracked file carries an
# email address whose domain does not end in a RESERVED label
# (local, test, invalid, example, localhost). The event roster's external
# identities are personal data and live outside both repos; a real address
# committed here — in a test fixture, a doc, a values file — is a leak that git
# history cannot take back.
#
# One address is allowed by exact string: the no-reply co-author trailer
# documented in .claude/agents/committer.md. The allow-list is deliberately a
# fixed literal in this file, not a configurable list.
#
# The scan reports local-part-at-domain shapes with an alphabetic final label only: `tool@v1.2.3`, `image@sha256:…`
# and `module@v1.7.12` are version pins, not addresses (the final label must be
# alphabetic).
#
# Usage: ./scripts/check-emails.sh [pathspec...]
#   CHECK_EMAILS_ROOT=<dir>  scan that git work tree instead of the current one
#                            (scripts/check-emails-selftest.sh uses a scratch repo)
# Exit: 0 clean, 1 violation(s), 2 the scan itself failed (fail-closed: a broken
# `git grep` is not "no emails found").
set -euo pipefail

root="${CHECK_EMAILS_ROOT:-$(git rev-parse --show-toplevel)}"
cd "$root"

EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*'
ALLOWED_LITERAL='noreply@anthropic.com'

if [ "$#" -eq 0 ]; then
  set -- .
fi

echo "==> scanning tracked files for email addresses outside the reserved domains"

# git grep: 0 = matches, 1 = none, >1 = error. Only 1 means "clean".
set +e
found="$(git grep -hoIE "$EMAIL_RE" -- "$@" 2>/dev/null)"
rc=$?
set -e
if [ "$rc" -gt 1 ]; then
  echo "FAIL: git grep failed (exit $rc) — the scan did not run; refusing to call that clean" >&2
  exit 2
fi

bad=""
if [ "$rc" -eq 0 ]; then
  while IFS= read -r addr; do
    [ -n "$addr" ] || continue
    last="${addr##*.}"
    last="$(printf '%s' "$last" | tr '[:upper:]' '[:lower:]')"
    case "$last" in
      local|test|invalid|example|localhost) continue ;;
    esac
    if [ "$addr" = "$ALLOWED_LITERAL" ]; then
      continue
    fi
    bad="${bad}${addr}"$'\n'
  done < <(printf '%s\n' "$found" | sort -u)
fi

if [ -n "$bad" ]; then
  echo "FAIL: email address(es) outside the reserved domains in tracked files:" >&2
  printf '%s' "$bad" | sed 's/^/  /' >&2
  echo "  locations:" >&2
  while IFS= read -r addr; do
    [ -n "$addr" ] || continue
    git grep -nIF -- "$addr" -- "$@" | sed 's/^/    /' >&2 || true
  done <<< "$bad"
  echo "  → use a reserved domain (user@ctf.local, someone@partner.example); real addresses belong outside git (ADR-0034 D11)." >&2
  exit 1
fi
echo "  ok: every email address in tracked files is on a reserved domain"
