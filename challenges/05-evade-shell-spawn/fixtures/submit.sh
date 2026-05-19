#!/bin/sh
# Source this file to define the `submit` shell function:
#   source /opt/ctf/fixtures/05-evade-shell-spawn/submit.sh
#   submit 'FALCO{...}'

submit() {
  if [ -z "${1:-}" ]; then
    echo "usage: submit <flag>" >&2
    return 1
  fi
  local sb="${FALCO_CTF_SCOREBOARD:-http://scoreboard.scoreboard.svc:80}"
  local user="${FALCO_CTF_USER:?FALCO_CTF_USER not set}"
  curl -s -X POST "${sb}/api/challenges/05-evade-shell-spawn/submit" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"user":"%s","flag":"%s"}' "${user}" "$1")"
  echo
}
