#!/bin/sh
# Batch-submit EVADE-challenge flags from a YAML answers file.
#
#   sh /opt/ctf/submit-yaml.sh                 # uses /opt/ctf/answers.yaml
#   sh /opt/ctf/submit-yaml.sh /path/to.yaml
#
# Edit /opt/ctf/answers.yaml first — one line per mission you've cleared:
#
#   03-stealth-read: FALCO{...}
#   05-silent-search: FALCO{...}
#
# Each non-empty line is submitted via the same scoreboard endpoint as
# `submit` (flag must match AND the forbidden rule must not have fired in the
# last windowSeconds). trigger challenges need no submission — Falco firing is
# the solve. Comments (#) and empty flags are skipped.
set -u

FILE="${1:-/opt/ctf/answers.yaml}"
[ -f "$FILE" ] || { echo "answers file not found: $FILE" >&2; exit 1; }

# Reuse submit() (reads $FALCO_CTF_USER, POSTs to the scoreboard).
. /opt/ctf/submit.sh

any=0
while IFS= read -r line; do
  case "$line" in \#*|"") continue ;; esac
  cid=$(printf '%s' "$line" | sed -n 's/^\([0-9][0-9]-[a-z0-9-]*\)[[:space:]]*:.*/\1/p')
  [ -n "$cid" ] || continue
  flag=$(printf '%s' "$line" | sed 's/^[^:]*:[[:space:]]*//; s/^["'\'']//; s/["'\'']*[[:space:]]*$//')
  if [ -z "$flag" ]; then
    echo "skip ${cid} (no flag yet)"
    continue
  fi
  printf '== %s ==\n' "$cid"
  submit "$cid" "$flag"
  any=1
done < "$FILE"

[ "$any" = 1 ] || echo "No flags filled in ${FILE}. Edit it first: '<mission-id>: FALCO{...}'."
