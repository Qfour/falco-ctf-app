#!/bin/sh
# Source this file to define the `submit` shell function.
# (Identical to challenge 02's submit.sh — copy-pasted for self-contained
# fixtures per challenge.)

submit() {
  if [ -z "${1:-}" ]; then
    echo "usage: submit <flag>" >&2
    return 1
  fi
  local sb="${FALCO_CTF_SCOREBOARD:-http://scoreboard.scoreboard.svc:80}"
  local cid="${FALCO_CTF_CHALLENGE:?FALCO_CTF_CHALLENGE not set}"
  local user="${FALCO_CTF_USER:?FALCO_CTF_USER not set}"
  curl -s -X POST "${sb}/api/challenges/${cid}/submit" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"user":"%s","flag":"%s"}' "${user}" "$1")"
  echo
}
