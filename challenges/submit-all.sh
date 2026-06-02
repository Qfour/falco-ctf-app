#!/bin/sh
# Shared submit helper for all-missions mode.
#
# Usage:
#   source /opt/ctf/submit.sh
#   submit <mission-id> '<flag>'
#
# Examples:
#   submit 03-stealth-read 'FALCO{...}'
#   submit 10-final-exfil  'FALCO{...}'
#
# Identity is read from $FALCO_CTF_USER (set by the chart). Challenge id is
# explicit so all 10 missions can be solved from a single workspace pod.

submit() {
  if [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
    echo "usage: submit <mission-id> <flag>" >&2
    echo "  e.g.  submit 03-stealth-read 'FALCO{...}'" >&2
    return 1
  fi
  local cid="$1"
  local flag="$2"
  local sb="${FALCO_CTF_SCOREBOARD:-http://scoreboard.scoreboard.svc:80}"
  local user="${FALCO_CTF_USER:?FALCO_CTF_USER not set}"
  curl -s -X POST "${sb}/api/challenges/${cid}/submit" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"user":"%s","flag":"%s"}' "${user}" "${flag}")"
  echo
}
