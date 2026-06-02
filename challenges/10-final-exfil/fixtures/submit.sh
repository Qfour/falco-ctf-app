#!/bin/sh
# Source this file to define `submit` and `set_display_name`:
#   source /opt/ctf/fixtures/submit.sh
#   set_display_name 'Alice'           # ← cosmetic name on the scoreboard
#   submit 'FALCO{...}'                # ← (evade challenges only)

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

# set_display_name <name>
#
# Picks the *cosmetic* name shown on the scoreboard / /me page for this
# user. Identity (`$FALCO_CTF_USER`) is the stable key — solves and the
# auth-policy host↔email check still use that. Re-runnable any time.
#
# Underscore-named for POSIX sh compatibility (busybox sh rejects hyphens
# in function names; bash accepts both).
set_display_name() {
  if [ -z "${1:-}" ]; then
    echo "usage: set_display_name <name>   (1..32 chars, no < > & \" ' or control chars)" >&2
    return 1
  fi
  local sb="${FALCO_CTF_SCOREBOARD:-http://scoreboard.scoreboard.svc:80}"
  local user="${FALCO_CTF_USER:?FALCO_CTF_USER not set}"
  curl -s -X POST "${sb}/api/users/${user}/display-name" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"name":"%s"}' "$1")"
  echo
}
