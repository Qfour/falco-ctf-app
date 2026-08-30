#!/usr/bin/env bash
# ADR number / index hygiene gate (Issue #181).
#
# WHY THIS EXISTS
# ----------------
# ADR number collisions have recurred: an Issue self-assigns "the next free
# ADR number", lands out of order relative to another ADR PR that also
# claimed it, and a human has to notice and renumber after the fact (see
# docs/adr/README.md's "規律" section — the ADR-0008/ADR-0009 collision is
# the one confirmed instance, called out there as a recurring failure mode).
# Separately, docs/adr/README.md ("ADR を新設したらこの索引に 1 行追加する")
# has silently drifted out of sync with the files on disk before (ADR-0024
# shipped without ever being added to the index). Both are the same root
# problem — a hand-maintained convention nobody re-checks — so one hermetic
# script covers both:
#
#   (a) two docs/adr/NNNN-*.md files claiming the same 4-digit number.
#   (b) a file's `# ADR-NNNN` header disagreeing with its own filename
#       number (copy-paste-derived drift when authoring a new ADR from an
#       existing one).
#   (c) a docs/adr/NNNN-*.md file that isn't referenced from
#       docs/adr/README.md (by filename or by a `[NNNN]` index link) — the
#       ADR-0024 gap.
#
# Hermetic: no network, no `gh`, no git history walk. Reads only
# docs/adr/*.md. docs/adr/README.md itself is the index, not an ADR, and is
# excluded from the NNNN-*.md scan by construction (it doesn't match the
# 4-digit-prefix glob).
#
# On success (no violations), prints the next free ADR number (existing max
# + 1) to stdout as a numbering helper for whoever cuts the next ADR — a
# convenience value, not an authoritative reservation. Historical ADRs leave
# gaps on purpose (ADR-0009 is reserved-but-fileless per the README), so
# max+1 does not need to account for reserved-but-unfiled numbers; it only
# needs to not collide with a number already in use, which is what this
# check enforces.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

adr_dir="docs/adr"
index="${adr_dir}/README.md"
rc=0

if [ ! -f "$index" ]; then
  echo "FAIL: ${index} not found — expected the ADR index at this path." >&2
  exit 1
fi

shopt -s nullglob
files=("${adr_dir}"/[0-9][0-9][0-9][0-9]-*.md)
shopt -u nullglob

if [ "${#files[@]}" -eq 0 ]; then
  echo "FAIL: no ${adr_dir}/NNNN-*.md files found — treating a zero-ADR" \
       "extraction as a failure, not a vacuous pass (glob/path likely wrong)." >&2
  exit 1
fi

echo "==> scanning ${#files[@]} ADR file(s) under ${adr_dir}/"

echo "==> (a) checking for duplicate ADR numbers"
# Note: deliberately avoids `declare -A` (bash 4+ only) — macOS ships bash
# 3.2 by default, and this script is also invoked directly (not just via a
# container) in local dev. sort | uniq -d works on 3.2.
dup_rc=0
all_nums=""
for f in "${files[@]}"; do
  base="$(basename "$f")"
  all_nums="${all_nums}${base%%-*}
"
done
dup_nums="$(printf '%s' "$all_nums" | sort | uniq -d)"
if [ -n "$dup_nums" ]; then
  while IFS= read -r dnum; do
    [ -n "$dnum" ] || continue
    echo "FAIL: ADR number ${dnum} is claimed by more than one file:" >&2
    for f in "${files[@]}"; do
      base="$(basename "$f")"
      if [ "${base%%-*}" = "$dnum" ]; then
        echo "  ${f}" >&2
      fi
    done
    echo "  → renumber one of them to the next free number (this script" \
         "prints it on a clean run) before landing either." >&2
    dup_rc=1
  done <<<"$dup_nums"
fi
if [ "$dup_rc" -eq 0 ]; then
  echo "  ok: every ADR number is claimed by exactly one file"
else
  rc=1
fi

echo "==> (b) checking filename number matches the '# ADR-NNNN' header"
header_rc=0
for f in "${files[@]}"; do
  base="$(basename "$f")"
  num="${base%%-*}"
  header_line="$(grep -m1 -E '^# ADR-[0-9]{4}' "$f" || true)"
  if [ -z "$header_line" ]; then
    echo "FAIL: ${f} has no '# ADR-NNNN' header (expected on line 1)." >&2
    header_rc=1
    continue
  fi
  header_num="$(printf '%s\n' "$header_line" | grep -oE 'ADR-[0-9]{4}' | head -n1 | cut -d- -f2)"
  if [ "$header_num" != "$num" ]; then
    echo "FAIL: ${f} filename number ${num} != header number ${header_num}" >&2
    echo "  header: ${header_line}" >&2
    header_rc=1
  fi
done
if [ "$header_rc" -eq 0 ]; then
  echo "  ok: every filename number matches its own header"
else
  rc=1
fi

echo "==> (c) checking every ADR is referenced from ${index}"
index_rc=0
for f in "${files[@]}"; do
  base="$(basename "$f")"
  num="${base%%-*}"
  if grep -qF -- "$base" "$index"; then
    continue
  fi
  if grep -qE -- "\[${num}\]" "$index"; then
    continue
  fi
  echo "FAIL: ${f} is not referenced from ${index}" \
       "(no '${base}' filename match and no '[${num}]' link)." >&2
  echo "  → add a row to the index table (see README.md's own instruction:" \
       "'ADR を新設したらこの索引に 1 行追加する')." >&2
  index_rc=1
done
if [ "$index_rc" -eq 0 ]; then
  echo "  ok: every ADR is referenced from the index"
else
  rc=1
fi

if [ "$rc" -ne 0 ]; then
  echo >&2
  echo "FAIL: ADR number/index hygiene violated — see FAIL lines above." >&2
  exit 1
fi

max=0
for f in "${files[@]}"; do
  base="$(basename "$f")"
  num="${base%%-*}"
  # Force base-10: a leading zero (e.g. "0008") would otherwise be
  # interpreted as octal by bash arithmetic and fail on "0008"/"0009".
  n=$((10#$num))
  if [ "$n" -gt "$max" ]; then
    max=$n
  fi
done
next=$((max + 1))

echo
echo "OK: no ADR number collisions, no header/filename drift, no index gaps."
printf 'Next free ADR number: %04d\n' "$next"
