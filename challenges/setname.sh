#!/bin/sh
# Set (or change) your own name on the scoreboard.
#
# Usage:
#   source /opt/ctf/setname.sh
#   setname 'Alice'
#
# Default name is your username ($FALCO_CTF_USER). Re-run anytime to change it.
# 1-32 chars, no < > & " ' or control characters.
setname() {
  if [ -z "${1:-}" ]; then
    echo "usage: setname '<name>'" >&2
    return 1
  fi
  name="$1"
  # P11.5: reach the scoreboard only through the collector front.
  sb="${FALCO_CTF_COLLECTOR:-${FALCO_CTF_SCOREBOARD:-http://collector.collector.svc:80}}"
  user="${FALCO_CTF_USER:?FALCO_CTF_USER not set}"
  curl -s -X POST "${sb}/api/users/${user}/display-name" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"name":"%s"}' "${name}")"
  echo
}
