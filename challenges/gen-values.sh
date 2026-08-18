#!/usr/bin/env bash
# Generate per-challenge values.yaml and the combined values-all.yaml from each
# evade challenge's plant.sh (the single source of truth for flag planting).
#
#   ./gen-values.sh           regenerate the files in place
#   ./gen-values.sh --check   fail if the committed files are out of sync (CI),
#                             or if any plant.sh / generated seed script
#                             violates ADR-0001 Verification 2 (2-1..2-7)
#
# ADR-0001 (Option B, Accepted): plant.sh no longer runs in the challenge
# container and no longer writes to the real sensitive path. It runs in the
# `plant` initContainer (charts/ctf-user/templates/pod.yaml) and writes into
# a seed emptyDir. This script renders, per scope (a single challenge, or
# all-missions):
#   - plant.seedScript: the initContainer's `sh -c` script, built from the
#     declared plant.sh bodies in mission-id sort order. For any plant-target
#     that needs base data restored first (declared via
#     `# plant-seed-source:`), the *first* mission (sort order) to touch that
#     target gets a `cp -a` from the build-time snapshot baked into the
#     challenge image at /opt/ctf/plant-seed/ (ADR-0001 S-a) — never from the
#     real path. Every subsequent mission just appends (2-2/2-4).
#   - plant.mounts: the deduped list of declared plant-target absolute paths
#     (charts/ctf-user/templates/pod.yaml turns each into a read-only subPath
#     mount from the seed volume onto the real path in `challenge`).
#
# plant.sh references CTF_FLAG_* env vars only — no flag literals — so flags
# live in exactly one place at runtime (the ctf-flags Secret, seen only by
# the `plant` initContainer, never by `challenge` — I12).
set -euo pipefail

cd "$(dirname "$0")"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

# The `plant` initContainer's own view of the seed volume (emptyDir mountPath
# in charts/ctf-user/templates/pod.yaml) and the build-time snapshot root
# baked into the challenge image (images/challenge/Dockerfile, ADR-0001 S-a).
SEED_ROOT='/plant-seed'
SNAPSHOT_ROOT='/opt/ctf/plant-seed'

# Sensitive path list the *generated* seed script must never read from
# directly (Verification 2-7(b)). Derived from the same catalog file the
# docs site renders (challenges/03-stealth-read/rule.yaml's
# `sensitive_file_names` list) rather than hardcoded here a second time, so
# a future edit to that list can't silently drift out of sync with this
# check.
SENSITIVE_RULE_FILE="03-stealth-read/rule.yaml"
sensitive_paths() {
  awk '
    /^- list: sensitive_file_names$/ { f=1; next }
    f && /^  items:/ { print; exit }
  ' "${SENSITIVE_RULE_FILE}" \
    | sed -E 's/^  items: \[(.*)\]$/\1/' \
    | tr ',' '\n' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | grep -v '^$'
}
SENSITIVE_DIR_PREFIXES="/etc/sudoers.d /etc/pam.d"

# Evade challenges = directories that carry a plant.sh, in NN order.
# (portable to bash 3.2 / macOS — no mapfile / no associative arrays)
MISSIONS=()
while IFS= read -r m; do
  MISSIONS+=("$m")
done < <(find . -maxdepth 2 -name plant.sh | sed 's|^\./||;s|/plant.sh$||' | sort)

# ---------------------------------------------------------------------------
# plant.sh header parsing
# ---------------------------------------------------------------------------

plant_targets() { # <plant.sh> -> one absolute path per line (may be empty — 2-1 catches that)
  grep -E '^# plant-target: ' "$1" | sed -E 's/^# plant-target: *//' || true
}

plant_seed_source() { # <plant.sh> -> the snapshot source path, or nothing (declaration is optional)
  { grep -E '^# plant-seed-source: ' "$1" | sed -E 's/^# plant-seed-source: *//' | head -1; } || true
}

plant_body() { # <plant.sh> -> the file with the two header directive lines stripped
  grep -vE '^# plant-target: |^# plant-seed-source: ' "$1"
}

relpath() { printf '%s' "${1#/}"; }               # "/etc/shadow" -> "etc/shadow"
indent()  { awk '{ if ($0 == "") print ""; else print "      " $0 }'; }  # reads stdin

# ---------------------------------------------------------------------------
# Verification 2-1 / 2-3: header validation (both modes — generation itself
# depends on these being true, not just --check).
# ---------------------------------------------------------------------------

HEADER_ERRORS=""
for id in "${MISSIONS[@]}"; do
  targets="$(plant_targets "${id}/plant.sh")"
  if [ -z "${targets}" ]; then
    HEADER_ERRORS="${HEADER_ERRORS}2-1 VIOLATION: ${id}/plant.sh has no '# plant-target:' declaration\n"
    continue
  fi
  ntargets="$(printf '%s\n' "${targets}" | grep -c .)"
  source="$(plant_seed_source "${id}/plant.sh")"
  if [ -n "${source}" ]; then
    if [ "${ntargets}" -ne 1 ]; then
      HEADER_ERRORS="${HEADER_ERRORS}${id}/plant.sh: plant-seed-source requires exactly one plant-target (has ${ntargets})\n"
    fi
    case "${source}" in
      "${SNAPSHOT_ROOT}"/*) : ;;
      *)
        HEADER_ERRORS="${HEADER_ERRORS}2-3 VIOLATION: ${id}/plant.sh declares plant-seed-source '${source}' outside ${SNAPSHOT_ROOT}/ (must be a build-time snapshot path, never the real sensitive path)\n"
        ;;
    esac
  fi
done
if [ -n "${HEADER_ERRORS}" ]; then
  printf '%b' "${HEADER_ERRORS}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Target -> seed-source resolution, with a consistency check across missions
# that share a plant-target (03 and 10 both declare /etc/shadow — 2-2).
# ---------------------------------------------------------------------------

TARGET_KEYS=()
TARGET_VALS=()

target_source_get() { # $1=target ; prints the recorded source (may be ""); rc 1 if unseen
  local i
  if [ "${#TARGET_KEYS[@]}" -gt 0 ]; then
    for i in "${!TARGET_KEYS[@]}"; do
      if [ "${TARGET_KEYS[$i]}" = "$1" ]; then
        printf '%s' "${TARGET_VALS[$i]}"
        return 0
      fi
    done
  fi
  return 1
}

for id in "${MISSIONS[@]}"; do
  s="$(plant_seed_source "${id}/plant.sh")"
  while IFS= read -r target; do
    [ -z "${target}" ] && continue
    if existing="$(target_source_get "${target}")"; then
      if [ "${existing}" != "${s}" ]; then
        echo "gen-values: ${id}/plant.sh declares plant-target ${target} with seed-source '${s}', but an earlier mission recorded '${existing}' for the same target" >&2
        exit 1
      fi
    else
      TARGET_KEYS+=("${target}")
      TARGET_VALS+=("${s}")
    fi
  done < <(plant_targets "${id}/plant.sh")
done

# ---------------------------------------------------------------------------
# Rendering (per scope = a list of mission ids, always MISSIONS sort order —
# 2-4)
# ---------------------------------------------------------------------------

unique_targets_for() { # $@ = mission ids -> unique plant-target list, first-appearance order (2-2)
  local seen=() id target found x
  for id in "$@"; do
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      found=0
      if [ "${#seen[@]}" -gt 0 ]; then
        for x in "${seen[@]}"; do
          [ "${x}" = "${target}" ] && found=1 && break
        done
      fi
      if [ "${found}" -eq 0 ]; then
        seen+=("${target}")
        printf '%s\n' "${target}"
      fi
    done < <(plant_targets "${id}/plant.sh")
  done
}

# render_seed_body <mission-id>... -> the *unindented* initContainer script
# body (the ADR-0001 Option B seed script — this is exactly the text
# Verification 2-7 statically checks).
render_seed_body() {
  local seeded=() id target source found x rel dir
  printf 'set -eu\n'
  printf 'PLANT_SEED_ROOT=%s\n' "${SEED_ROOT}"
  for id in "$@"; do
    printf '\n# ---- %s ----\n' "${id}"
    source="$(plant_seed_source "${id}/plant.sh")"
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      found=0
      if [ "${#seeded[@]}" -gt 0 ]; then
        for x in "${seeded[@]}"; do
          [ "${x}" = "${target}" ] && found=1 && break
        done
      fi
      if [ "${found}" -eq 0 ]; then
        seeded+=("${target}")
        if [ -n "${source}" ]; then
          rel="$(relpath "${target}")"
          dir="$(dirname "${rel}")"
          printf '# seed %s from the build-time snapshot (ADR-0001 S-a) — runs once\n' "${target}"
          printf 'mkdir -p "${PLANT_SEED_ROOT}/%s"\n' "${dir}"
          printf 'cp -a "%s" "${PLANT_SEED_ROOT}/%s"\n' "${source}" "${rel}"
        fi
      fi
    done < <(plant_targets "${id}/plant.sh")
    plant_body "${id}/plant.sh"
  done
}

render_plant_block() { # $@ = mission ids
  cat <<'HDR'
plant:
  seedScript:
    - sh
    - -c
    - |
HDR
  render_seed_body "$@" | indent
  echo '  mounts:'
  unique_targets_for "$@" | while IFS= read -r t; do
    printf '    - %s\n' "${t}"
  done
}

render_one() {
  local id="$1"
  cat <<HEADER
# GENERATED from ${id}/plant.sh by gen-values.sh — DO NOT EDIT.
# Run \`make gen-values\` after editing plant.sh.
HEADER
  render_plant_block "${id}"
}

render_all() {
  cat <<'HEADER'
# GENERATED by gen-values.sh — DO NOT EDIT. Run `make gen-values`.
#
# All-missions mode (deploy-user.sh <user> all): the `plant` initContainer
# runs every evade mission's plant.sh in one seed script (ADR-0001 Option B).
# Flag values come from the ctf-flags Secret (CTF_FLAG_* keys), injected into
# `plant` only — never into the challenge container; no flag literals live
# here.
HEADER
  render_plant_block "${MISSIONS[@]}"
}

# ---------------------------------------------------------------------------
# Verification 2-5 (best-effort heuristic, on the raw plant.sh source): every
# write destination must be anchored at ${PLANT_SEED_ROOT}, never a bare
# absolute path (which would silently miss the mount and vanish, or worse,
# hit the real sensitive path).
# ---------------------------------------------------------------------------

check_2_5() {
  local id rc=0 hits
  for id in "${MISSIONS[@]}"; do
    hits="$(plant_body "${id}/plant.sh" \
      | grep -vE '^[[:space:]]*#|^[[:space:]]*$' \
      | grep -Ev 'PLANT_SEED_ROOT' \
      | grep -E '(>>?|mkdir -p|chmod [0-7]+) *"?/' || true)"
    if [ -n "${hits}" ]; then
      echo "2-5 VIOLATION: ${id}/plant.sh writes to a path outside \${PLANT_SEED_ROOT} (best-effort static check on \`>\`/\`>>\`/mkdir -p/chmod destinations):" >&2
      printf '%s\n' "${hits}" | sed 's/^/    /' >&2
      rc=1
    fi
  done
  return "${rc}"
}

# ---------------------------------------------------------------------------
# Verification 2-7 (I13b machine enforcement, on the *generated* seed
# script): the deploy path must never read a sensitive path at runtime.
# Best-effort static heuristic, documented as such.
#   (a) every `cp` copy-source is anchored under ${SNAPSHOT_ROOT}
#   (b) none of catalog's sensitive_file_names / sensitive dirs appear
#       outside of a ${PLANT_SEED_ROOT}... or ${SNAPSHOT_ROOT}... token
#   (c) grep / egrep / fgrep / find / ln are never invoked
#   (d) nothing under ${PLANT_SEED_ROOT} is executed
# ---------------------------------------------------------------------------

check_2_7() { # $1 = generated seed script text (unindented), $2 = label
  local script="$1" label="$2" rc=0 hits p residue code

  # All 4 sub-checks below look at CODE only — full-comment lines (this
  # script's own documentation, and the prose plant.sh authors write above
  # their commands) are excluded, since they legitimately mention sensitive
  # paths / tool names in prose without ever reading/execing anything.
  # Best-effort heuristic: this only strips a comment that occupies a whole
  # line; it does not parse shell syntax.
  code="$(printf '%s\n' "${script}" | grep -vE '^[[:space:]]*#')"

  # (a) copy-source allowlist.
  hits="$(printf '%s\n' "${code}" | grep -oE 'cp -a "[^"]+"' | sed -E 's/^cp -a "//; s/"$//' \
    | grep -vE "^${SNAPSHOT_ROOT}/" || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(a) VIOLATION [${label}]: cp copy-source outside ${SNAPSHOT_ROOT}/:" >&2
    printf '%s\n' "${hits}" | sed 's/^/    /' >&2
    rc=1
  fi

  # (b) sensitive paths must not appear outside a safe (seed-relative)
  # prefix. Strip every safe occurrence, then check whether the bare
  # sensitive literal still remains anywhere in the residue.
  residue="${code}"
  while IFS= read -r p; do
    [ -z "${p}" ] && continue
    residue="$(printf '%s' "${residue}" \
      | sed -E "s#\\\$\\{PLANT_SEED_ROOT\\}${p}##g; s#${SNAPSHOT_ROOT}${p}##g")"
  done < <(sensitive_paths)
  for p in $(sensitive_paths) ${SENSITIVE_DIR_PREFIXES}; do
    if printf '%s' "${residue}" | grep -qF "${p}"; then
      echo "2-7(b) VIOLATION [${label}]: sensitive path '${p}' appears outside a \${PLANT_SEED_ROOT}/${SNAPSHOT_ROOT} prefix:" >&2
      printf '%s\n' "${code}" | grep -F "${p}" | sed 's/^/    /' >&2
      rc=1
    fi
  done

  # (c) forbidden binaries (word-boundary match).
  hits="$(printf '%s\n' "${code}" \
    | grep -nE '(^|[^A-Za-z0-9_])(grep|egrep|fgrep|find|ln)([^A-Za-z0-9_]|$)' || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(c) VIOLATION [${label}]: forbidden binary (grep/egrep/fgrep/find/ln) in generated seed script:" >&2
    printf '%s\n' "${hits}" | sed 's/^/    /' >&2
    rc=1
  fi

  # (d) nothing under the seed volume is executed (i.e. never the first
  # token of a (sub)statement).
  hits="$(printf '%s\n' "${code}" \
    | grep -nE '(^|[;&|]) *"?\$\{?PLANT_SEED_ROOT' || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(d) VIOLATION [${label}]: \${PLANT_SEED_ROOT} path used as a command (exec of seed-written content):" >&2
    printf '%s\n' "${hits}" | sed 's/^/    /' >&2
    rc=1
  fi

  return "${rc}"
}

run_2_7_all_scopes() {
  local rc=0 id
  check_2_7 "$(render_seed_body "${MISSIONS[@]}")" "values-all" || rc=1
  for id in "${MISSIONS[@]}"; do
    check_2_7 "$(render_seed_body "${id}")" "${id}" || rc=1
  done
  return "${rc}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [ "${CHECK}" -eq 1 ]; then
  rc=0
  check_2_5 || rc=1
  run_2_7_all_scopes || rc=1
  for id in "${MISSIONS[@]}"; do
    if ! diff -u "${id}/values.yaml" <(render_one "${id}") >/dev/null 2>&1; then
      echo "DRIFT: ${id}/values.yaml is out of sync with ${id}/plant.sh" >&2
      rc=1
    fi
  done
  if ! diff -u values-all.yaml <(render_all) >/dev/null 2>&1; then
    echo "DRIFT: values-all.yaml is out of sync with plant.sh files" >&2
    rc=1
  fi
  [ "${rc}" -eq 0 ] && echo "gen-values: in sync (2-1..2-7 clean)"
  exit "${rc}"
fi

check_2_5
run_2_7_all_scopes

for id in "${MISSIONS[@]}"; do
  render_one "${id}" > "${id}/values.yaml"
  echo "wrote ${id}/values.yaml"
done
render_all > values-all.yaml
echo "wrote values-all.yaml"
