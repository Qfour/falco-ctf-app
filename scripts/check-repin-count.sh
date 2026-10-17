#!/usr/bin/env bash
# Count commits on a ref's first-parent history where an EXISTING apk pin's version changed
# (ADR-0002 Signpost 4: "exact pin の再解決"). Read-only.
set -uo pipefail
ref="${1:-origin/main}"; since="${2:-2026-09-01}"
pins() { # $1=rev $2=file -> "file name=version" lines
  git show "$1:$2" 2>/dev/null | awk '{ if (sub(/\\$/, "")) { buf = buf $0 " "; next } print buf $0; buf = "" } END { if (buf != "") print buf }' \
   | grep -E '^RUN .*apk add' | tr -s ' \t' '\n\n' | tr -d '"' | grep -E '^[a-z0-9][a-z0-9._+-]*=[0-9][^ ]*$' | sed "s|^|$2 |" | sort -u
}
# shellcheck disable=SC2046  # word-splitting of the file list is intended
git log --first-parent "$ref" --since="$since" --reverse --format='%H %ad %s' --date=short -- $(git ls-tree -r --name-only "$ref" | grep -i dockerfile) | while read -r c d s; do
  files=$(git diff --name-only "$c^" "$c" | grep -i dockerfile)
  changed=""; added=""
  for f in $files; do
    before=$(pins "$c^" "$f"); after=$(pins "$c" "$f")
    while read -r _ nv; do [ -z "$nv" ] && continue; n=${nv%%=*}; v=${nv#*=}
      ov=$(printf '%s\n' "$before" | awk -v n="$n" '{split($2,a,"="); if (a[1]==n) print a[2]}' | head -1)
      if [ -n "$ov" ] && [ "$ov" != "$v" ]; then changed="$changed ${f##*/}:$n:$ov->$v"; elif [ -z "$ov" ]; then added="$added ${f##*/}:$n"; fi
    done <<<"$after"
  done
  [ -n "$changed$added" ] && echo "$d ${c:0:7} | changed:${changed:- none} | added:${added:- none} | ${s:0:70}"
done
