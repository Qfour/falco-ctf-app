#!/usr/bin/env bash
# Generate per-challenge values.yaml and the combined values-all.yaml from each
# evade challenge's plant.sh (the single source of truth for flag planting).
#
#   ./gen-values.sh           regenerate the files in place
#   ./gen-values.sh --check   fail if the committed files are out of sync (CI),
#                             or if any plant.sh / generated seed script
#                             (the plant is derived from the type: an evade
#                             challenge's plant.sh, or an investigate
#                             challenge's evidence.mountDir, ADR-0056 D11)
#                             violates ADR-0001 Verification 2 (2-1..2-7) or
#                             ADR-0007 Verification 1 (mount directory
#                             granularity), or if an `investigate`
#                             challenge's evidence.mountDir sits in a
#                             sensitive directory / overlaps another
#                             plant-target, or two plant.sh write the same
#                             file (ADR-0056 D1 + ADR-0055 C4 (ii);
#                             check_claims() below)
#   ./gen-values.sh --check-seed-script | --render-evidence-copy |
#       --list-evidence-mount-dirs | --emit-evidence-fixture ...
#                             entry points for scripts/check-flag-isolation.sh
#                             (ADR-0056 A5b): the definitions of the evidence
#                             copy line and of its 2-7(a) rule live here only
#                             (see "Entry points" before Main)
#
# ADR-0001 (Option B, Accepted): plant.sh no longer runs in the challenge
# container and no longer writes to the real sensitive path. It runs in the
# `plant` initContainer (charts/ctf-user/templates/pod.yaml) and writes into
# a seed emptyDir.
#
# ADR-0007 (Option 1, Accepted, supersedes ADR-0001's derived decision (1) =
# B1 mount granularity): a plant-target that is a FILE is never bind-mounted
# by itself — only its **enclosing directory** is. Mounting a single
# sensitive file (subPath or hostPath, doesn't matter) makes the container
# runtime's own mount-setup machinery trigger the `open_read`-family Falco
# rules on every deploy (docs/adr/0007-plant-mount-directory-granularity.md
# §C2); a directory destination structurally cannot, because those rules
# require `fd.typechar='f'`. This script now renders, per scope (a single
# challenge, or all-missions):
#   - plant.seedScript: the initContainer's `sh -c` script, built from the
#     declared plant.sh bodies in mission-id sort order. For any *mount
#     directory* that needs base data restored first (declared via
#     `# plant-seed-source:`, now a DIRECTORY path), the *first* mission
#     (sort order) to touch that directory gets a directory-wide
#     `cp -a SRC/. DST/` from the build-time snapshot baked into the
#     challenge image at /opt/ctf/plant-seed/ (ADR-0001 S-a / ADR-0007) —
#     never from the real path. Every subsequent mission just appends
#     (2-2/2-4), same as before.
#   - plant.mounts: the deduped list of {path, readOnly} mount directories
#     (charts/ctf-user/templates/pod.yaml turns each into a subPath mount
#     from the seed volume onto the real path in `challenge`). `path` is the
#     plant-target itself when `# plant-target-type: dir`, or its dirname
#     when `# plant-target-type: file`. `readOnly` is `false` only for mount
#     directories whose plant.sh declares `# plant-mount-readonly: false`
#     (resolved by plant_mount_readonly_override()/is_mount_writable() below) —
#     everything else defaults to `true` (fail-closed side).
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
# baked into the challenge image (images/challenge/Dockerfile, ADR-0001 S-a /
# ADR-0007).
SEED_ROOT='/plant-seed'
SNAPSHOT_ROOT='/opt/ctf/plant-seed'

# ADR-0007 Consequences ("諦めたもの"): per-mount readOnly is derived from
# each plant.sh's optional `# plant-mount-readonly: false` header (see
# is_mount_writable() below, defined once the MOUNTDIR_* arrays exist).
# Everything NOT explicitly declared `false` by some plant.sh defaults to
# readOnly:true (fail-closed side). Today only 03-stealth-read declares
# `plant-mount-readonly: false` for the /etc mount dir — required by
# mission 09 (challenges/09-hidden-cache, which has NO plant.sh of its own;
# its plant-target /etc/sudoers is baked directly into the image, not
# planted) needing `ln /etc/sudoers /etc/.cache.bak` to succeed. Mission
# 05's /root/.ssh mount declares no override and stays readOnly:true.

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

# security-engineer A6: this used to be a hardcoded literal
# ("/etc/sudoers.d /etc/pam.d"). Derived instead from the same
# `sensitive_files` macro's `fd.directory in (...)` clause in
# SENSITIVE_RULE_FILE, so it can't silently drift from N6's "derive from
# catalog, don't hardcode" requirement either.
sensitive_dir_prefixes() {
  awk '
    /^- macro: sensitive_files$/ { f=1 }
    f && /fd\.directory in \(/ { print; exit }
  ' "${SENSITIVE_RULE_FILE}" \
    | sed -E 's/.*fd\.directory in \(([^)]*)\).*/\1/' \
    | tr ',' '\n' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | grep -v '^$'
}

# Evade challenges = directories that carry a plant.sh, in NN order.
# (portable to bash 3.2 / macOS — no mapfile / no associative arrays)
# MISSIONS is the plant.sh-only list: the plant.sh header checks below and the
# plant.sh-specific checks use it. What the `plant` initContainer plants for is
# derived from the TYPE instead (PLANT_IDS = evade plant.sh, or a challenge
# whose falco-rule.yaml says `type: investigate`; init_plant_ids() below,
# ADR-0056 D11 / A5a-2), which is what the rendering and the generated-script
# checks iterate.
MISSIONS=()
while IFS= read -r m; do
  MISSIONS+=("$m")
done < <(find . -maxdepth 2 -name plant.sh | sed 's|^\./||;s|/plant.sh$||' | sort)
PLANT_IDS=()
INVESTIGATE_IDS=()

# ADR-0056 D11: the `plant` initContainer sees the per-seat Secret `ctf-evidence`
# here (readOnly, plant only). The bundle's file names are unknown to this
# script (the event edition supplies them at deploy time), so a real run
# generates no copy line; the chart enumerates .Values.evidence.challenges.<cid>.names in
# the shape render_evidence_copy() defines. EVIDENCE_FILES is set only by the
# internal fixtures, to show the generated shape and to feed check_2_7 (2-7(a)).
# The Secret is one PER CHALLENGE (ctf-evidence-<cid>, ADR-0056 D11): a flat
# key set could not say which mountDir a file belongs to when a scope has two
# investigate challenges. So the source of a copy is
# ${EVIDENCE_SRC_ROOT}/<cid>/<name>, <cid> being a challenge id (CHALLENGE_ID_RE,
# defined with the scenario checks below, the one existing grammar here) and
# <name> matching EVIDENCE_NAME_RE: ADR-0056 B2's file-name grammar (lower-case,
# at most 63 characters, never starting with `.` or `-`), the same as the chart's
# `fail` in charts/ctf-user/templates/_helpers.tpl (ctf-user.evidence.check). The Go
# definition is edition.NamePattern (internal/edition/bundle.go), and
# internal/edition/evidence_grammar_test.go (ADR-0056 V52) holds this line, CHALLENGE_ID_RE
# and the chart's three literals equal to the Go definitions.
EVIDENCE_SRC_ROOT='/opt/ctf/evidence-src'
EVIDENCE_NAME_RE='^[a-z0-9][a-z0-9._-]{0,62}$'
EVIDENCE_FILES=()

# The grammar of an investigate challenge's evidence.mountDir, as THIS script
# requires it before the value reaches the generated `sh -c` script and
# plant.mounts (init_plant_ids). It is the Go catalog's (validateMountDir:
# absolute, clean, elements of [A-Za-z0-9._-], not "/"), checked here on its own
# so that a drift between Go's reading and the awk extraction cannot put a
# `$(...)`, a backtick, a quote or a `;` into a script.
MOUNTDIR_RE='^(/[A-Za-z0-9._-]+)+$'

# ---------------------------------------------------------------------------
# plant.sh header parsing
# ---------------------------------------------------------------------------

plant_targets() { # <plant.sh> -> one absolute path per line (may be empty — 2-1 catches that)
  grep -E '^# plant-target: ' "$1" | sed -E 's/^# plant-target: *//' || true
}

plant_target_type() { # <plant.sh> -> "file" or "dir" (may be empty — ADR-0007 header validation catches that)
  { grep -E '^# plant-target-type: ' "$1" | sed -E 's/^# plant-target-type: *//' | head -1; } || true
}

plant_seed_source() { # <plant.sh> -> the snapshot DIRECTORY source path, or nothing (declaration is optional)
  { grep -E '^# plant-seed-source: ' "$1" | sed -E 's/^# plant-seed-source: *//' | head -1; } || true
}

plant_mount_readonly_override() { # <plant.sh> -> "true"/"false" if declared, else nothing
  { grep -E '^# plant-mount-readonly: ' "$1" | sed -E 's/^# plant-mount-readonly: *//' | head -1; } || true
}

plant_body() { # <plant.sh> -> the file with the header directive lines stripped
  grep -vE '^# plant-target: |^# plant-target-type: |^# plant-seed-source: |^# plant-mount-readonly: ' "$1"
}

relpath() { printf '%s' "${1#/}"; }               # "/etc/shadow" -> "etc/shadow"
indent()  { awk '{ if ($0 == "") print ""; else print "      " $0 }'; }  # reads stdin

mount_dir_for() { # $1=target $2=type -> the directory that must be bind-mounted (ADR-0007)
  if [ "$2" = "dir" ]; then
    printf '%s' "$1"
  else
    dirname "$1"
  fi
}

# ---------------------------------------------------------------------------
# Verification 2-1 / 2-3 / 2-3b (ADR-0001) + ADR-0007 header validation (both
# modes — generation itself depends on these being true, not just --check).
# ---------------------------------------------------------------------------

HEADER_ERRORS=""
for id in "${MISSIONS[@]}"; do
  targets="$(plant_targets "${id}/plant.sh")"
  if [ -z "${targets}" ]; then
    HEADER_ERRORS="${HEADER_ERRORS}2-1 VIOLATION: ${id}/plant.sh has no '# plant-target:' declaration\n"
    continue
  fi
  ntargets="$(printf '%s\n' "${targets}" | grep -c .)"

  type="$(plant_target_type "${id}/plant.sh")"
  case "${type}" in
    file|dir) : ;;
    "")
      HEADER_ERRORS="${HEADER_ERRORS}ADR-0007 VIOLATION: ${id}/plant.sh has no '# plant-target-type:' declaration (must be 'file' or 'dir')\n"
      ;;
    *)
      HEADER_ERRORS="${HEADER_ERRORS}ADR-0007 VIOLATION: ${id}/plant.sh declares plant-target-type '${type}', want 'file' or 'dir'\n"
      ;;
  esac
  if [ "${ntargets}" -ne 1 ] && [ -n "${type}" ]; then
    HEADER_ERRORS="${HEADER_ERRORS}ADR-0007 VIOLATION: ${id}/plant.sh declares ${ntargets} plant-targets but exactly one plant-target-type (this script assumes a 1:1 mapping) — split into separate plant.sh-style declarations or extend this script before adding a second target\n"
  fi

  source="$(plant_seed_source "${id}/plant.sh")"
  if [ -n "${source}" ]; then
    if [ "${ntargets}" -ne 1 ]; then
      HEADER_ERRORS="${HEADER_ERRORS}${id}/plant.sh: plant-seed-source requires exactly one plant-target (has ${ntargets})\n"
    elif [ -n "${type}" ]; then
      target="$(printf '%s\n' "${targets}" | head -1)"
      mountdir="$(mount_dir_for "${target}" "${type}")"
      expected="${SNAPSHOT_ROOT}/$(relpath "${mountdir}")"
      case "${source}" in
        "${SNAPSHOT_ROOT}"/*) : ;;
        *)
          HEADER_ERRORS="${HEADER_ERRORS}2-3 VIOLATION: ${id}/plant.sh declares plant-seed-source '${source}' outside ${SNAPSHOT_ROOT}/ (must be a build-time snapshot path, never the real sensitive path)\n"
          ;;
      esac
      if [ "${source}" != "${expected}" ]; then
        HEADER_ERRORS="${HEADER_ERRORS}ADR-0007 VIOLATION: ${id}/plant.sh declares plant-seed-source '${source}', want '${expected}' (must be the snapshot of the MOUNT DIRECTORY '${mountdir}', not the plant-target file itself — ADR-0007 restores the whole enclosing directory, not a single file)\n"
      fi
    fi
  else
    # 2-3b (security-engineer A3): `>>` presupposes the destination already
    # has content. Without a plant-seed-source, the seed file starts empty
    # (emptyDir), so an append-only plant.sh would silently produce a
    # flag-only file instead of the pre-existing content the mission brief
    # assumes — exactly the bug 2-3 was written to close, just reached via
    # "forgot the header" instead of "pointed it at the real path".
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      rel="$(relpath "${target}")"
      if plant_body "${id}/plant.sh" | grep -qE '>>[[:space:]]*"?\$\{PLANT_SEED_ROOT\}/'"${rel}"'"?'; then
        HEADER_ERRORS="${HEADER_ERRORS}2-3b VIOLATION: ${id}/plant.sh appends (>>) to plant-target ${target} without declaring plant-seed-source — the seed file starts empty (emptyDir), so this would silently replace any pre-existing content the mission brief assumes instead of appending to it\n"
      fi
    done < <(printf '%s\n' "${targets}")
  fi
done
if [ -n "${HEADER_ERRORS}" ]; then
  printf '%b' "${HEADER_ERRORS}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Scenario-scope mode (P27-1, REFACTORING.md): scenarios/<name>/scenario.yaml
# (same shape as internal/catalog.Scenario — `id`, `title`, an ordered
# `challenges:` list — parsed independently here since this script has no Go
# runtime) selects an ordered subset of challenge ids for one event
# composition. Until now that file only scoped scoring/display (SCENARIO_FILE
# env, catalog.Restrict()) — the participant WORKSPACE still got every
# challenge's fixtures/README/flag regardless (P27-1's gap). This section
# renders, per scenario, values-scenario-<name>.yaml with:
#   - plant.seedScript/plant.mounts restricted to the scenario's own evade
#     missions (render_plant_block() below, same function values-all.yaml /
#     per-challenge values.yaml use, just given a filtered id list) — a
#     mission NOT in the scenario never has its flag planted here, regardless
#     of what "all"-mode or another scenario plants.
#   - scenario.missions: the scenario's full ordered challenge-id list
#     (including trigger-only ids with no plant.sh) — consumed by
#     charts/ctf-user/templates/pod.yaml's `missions-scope` initContainer to
#     restrict the participant-visible /opt/ctf/missions/ tree to exactly
#     this list (fixtures/README isolation, not just flags).
# Fail-closed (same discipline as catalog.Restrict(), Go side): a scenario
# manifest referencing an id with no matching challenges/ directory is a
# hard error, not a silently-dropped mission.
# ---------------------------------------------------------------------------

SCENARIOS_DIR='../scenarios'   # this script cd'd into challenges/ above

scenario_dirs() { # -> one scenario directory per line, sorted
  [ -d "${SCENARIOS_DIR}" ] || return 0
  find "${SCENARIOS_DIR}" -mindepth 1 -maxdepth 1 -type d | sort
}

# scenario_challenge_ids <scenario.yaml> -> one challenge id per line, in
# declared order (mirrors internal/catalog.Scenario.Challenges' yaml shape:
# a top-level `challenges:` key, then `  - <id>` list items — same
# restrained awk style already used above for FLAGS_FILE / sensitive_paths()
# rather than a second hardcoded copy of the Go struct's field names).
scenario_challenge_ids() {
  awk '
    /^challenges:/ { inblock=1; next }
    inblock && /^[^[:space:]]/ { inblock=0 }
    inblock && /^[[:space:]]*-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      sub(/[[:space:]]*#.*$/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$1"
}

# app#207 (P27-1 review-5x R1 finding, MEDIUM): charts/ctf-user/templates/
# pod.yaml's `missions-scope` initContainer interpolates each
# .Values.scenario.missions element straight into a `sh -c` script
# (`mkdir -p "/missions-seed/{{ . }}"` / `cp -a "/opt/ctf/missions/{{ . }}/."
# ...`) with no escaping. scenario.missions is exactly the ordered id list
# scenario_challenge_ids() below extracts from scenario.yaml's `challenges:`,
# so a challenge id containing a `"` (or other shell metacharacter) reaching
# that far would let an entry in a content-editor-authored scenario.yaml
# break out of the generated script's quoting. The existing check below only
# verifies "is this an id with a matching challenges/<id> directory" — it
# does not constrain the id's character set. Reject anything outside the
# challenge-id grammar here, fail-closed, BEFORE the directory-existence check
# (which would otherwise also need to double as a de-facto charset gate).
# app#437: the grammar is the one internal/catalog/challengeid.Pattern (a
# challenge's id is its directory name, `<NN>-<slug>`); this is a shell copy of
# it (no test pins it equal to the Go pattern yet; it is
# listed in app#472 with the Helm ones). The rejected id is NOT echoed.
# Mirrored, independently, by a Helm `regexMatch`+`fail` render-time guard in
# charts/ctf-user/templates/pod.yaml (defense-in-depth for callers that
# `helm template`/`helm upgrade` directly, bypassing this script).
CHALLENGE_ID_RE='^[0-9]{2}-[a-z0-9-]{1,60}$'

SCENARIO_ERRORS=""
while IFS= read -r sdir; do
  [ -z "${sdir}" ] && continue
  sid="$(basename "${sdir}")"
  sfile="${sdir}/scenario.yaml"
  if [ ! -f "${sfile}" ]; then
    SCENARIO_ERRORS="${SCENARIO_ERRORS}scenario '${sid}' has no scenario.yaml at ${sfile}\n"
    continue
  fi
  scount=0
  while IFS= read -r cid; do
    [ -z "${cid}" ] && continue
    scount=$((scount + 1))
    if ! [[ "${cid}" =~ ${CHALLENGE_ID_RE} ]]; then
      SCENARIO_ERRORS="${SCENARIO_ERRORS}scenario '${sid}': challenge #${scount} is not a valid challenge id (${CHALLENGE_ID_RE}; the value is not echoed — app#207 shell-metacharacter guard, app#437 grammar)\n"
      continue
    fi
    if [ ! -d "${cid}" ]; then
      SCENARIO_ERRORS="${SCENARIO_ERRORS}scenario '${sid}' references unknown challenge '${cid}' (no such directory under challenges/)\n"
    fi
  done < <(scenario_challenge_ids "${sfile}")
  if [ "${scount}" -eq 0 ]; then
    SCENARIO_ERRORS="${SCENARIO_ERRORS}scenario '${sid}': no challenges listed in ${sfile}\n"
  fi
done < <(scenario_dirs)
if [ -n "${SCENARIO_ERRORS}" ]; then
  printf '%b' "${SCENARIO_ERRORS}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Mount-directory -> seed-source / readOnly resolution, with a consistency
# check across missions that share a mount directory (03 and 10 both plant
# into /opt/nimbus/vault — each writes its OWN file there, creds.recover and
# master.key; before the 2026-09-01 vault separation they shared /etc —
# 2-2, keyed by mount dir rather than raw plant-target). Sharing a DIRECTORY is
# allowed; sharing a FILE is not (ADR-0055 C4 (ii), check_claims() below).
# ---------------------------------------------------------------------------

MOUNTDIR_KEYS=()
MOUNTDIR_SOURCE_VALS=()
MOUNTDIR_RO_VALS=()

mountdir_index() { # $1=mountdir -> prints index; rc 1 if unseen
  local i
  if [ "${#MOUNTDIR_KEYS[@]}" -gt 0 ]; then
    for i in "${!MOUNTDIR_KEYS[@]}"; do
      if [ "${MOUNTDIR_KEYS[$i]}" = "$1" ]; then
        printf '%s' "$i"
        return 0
      fi
    done
  fi
  return 1
}

for id in "${MISSIONS[@]}"; do
  type="$(plant_target_type "${id}/plant.sh")"
  source="$(plant_seed_source "${id}/plant.sh")"
  ro_override="$(plant_mount_readonly_override "${id}/plant.sh")"
  while IFS= read -r target; do
    [ -z "${target}" ] && continue
    mountdir="$(mount_dir_for "${target}" "${type}")"
    if idx="$(mountdir_index "${mountdir}")"; then
      if [ "${MOUNTDIR_SOURCE_VALS[$idx]}" != "${source}" ]; then
        echo "gen-values: ${id}/plant.sh maps plant-target ${target} to mount dir ${mountdir} with seed-source '${source}', but an earlier mission recorded '${MOUNTDIR_SOURCE_VALS[$idx]}' for the same mount dir" >&2
        exit 1
      fi
      if [ -n "${ro_override}" ] && [ -n "${MOUNTDIR_RO_VALS[$idx]}" ] && [ "${ro_override}" != "${MOUNTDIR_RO_VALS[$idx]}" ]; then
        echo "gen-values: ${id}/plant.sh declares plant-mount-readonly '${ro_override}' for mount dir ${mountdir}, but an earlier mission recorded '${MOUNTDIR_RO_VALS[$idx]}' for the same mount dir" >&2
        exit 1
      fi
      if [ -n "${ro_override}" ] && [ -z "${MOUNTDIR_RO_VALS[$idx]}" ]; then
        MOUNTDIR_RO_VALS[$idx]="${ro_override}"
      fi
    else
      MOUNTDIR_KEYS+=("${mountdir}")
      MOUNTDIR_SOURCE_VALS+=("${source}")
      MOUNTDIR_RO_VALS+=("${ro_override}")
    fi
  done < <(plant_targets "${id}/plant.sh")
done

is_mount_writable() { # $1=mount dir -> rc 0 iff some plant.sh declared plant-mount-readonly: false for it
  local idx
  if idx="$(mountdir_index "$1")"; then
    [ "${MOUNTDIR_RO_VALS[$idx]}" = "false" ] && return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Rendering (per scope = a list of plant ids (PLANT_IDS: evade plant.sh or
# investigate, derived from the type), always sorted by id —
# 2-4)
# ---------------------------------------------------------------------------

is_investigate_id() { # $1=id -> rc 0 iff init_plant_ids() found it to be an investigate challenge
  local x
  if [ "${#INVESTIGATE_IDS[@]}" -gt 0 ]; then
    for x in "${INVESTIGATE_IDS[@]}"; do
      [ "${x}" = "$1" ] && return 0
    done
  fi
  return 1
}

# init_plant_ids: derive, from the cwd tree, what the `plant` initContainer
# plants for — the evade challenges (a plant.sh) AND the investigate
# challenges (falco-rule.yaml `type: investigate`, no plant.sh: their evidence
# bundle is copied in, ADR-0056 D11). Sorted by id (so, with no investigate
# challenge, exactly MISSIONS). Fail-closed: an investigate challenge whose
# mountDir cannot be read, or that also carries a plant.sh (two sources for
# one challenge), stops the run.
init_plant_ids() {
  local f id mdir
  PLANT_IDS=()
  INVESTIGATE_IDS=()
  while IFS= read -r f; do
    [ -z "${f}" ] && continue
    id="$(basename "$(dirname "${f}")")"
    is_investigate_file "${f}" || continue
    mdir="$(investigate_mount_dir "${f}")"
    if [ -z "${mdir}" ]; then
      echo "ADR-0056 A5a-2 VIOLATION: ${id} is 'type: ${INVESTIGATE_TYPE}' but no investigate.evidence.mountDir could be read from its falco-rule.yaml, so what to plant cannot be derived" >&2
      exit 1
    fi
    # fail-closed on the grammar, here, because this value is written into the
    # initContainer's sh script and into plant.mounts verbatim
    if ! claims_path_clean "${mdir}" || ! [[ "${mdir}" =~ ${MOUNTDIR_RE} ]]; then
      printf 'ADR-0056 A5a-2 VIOLATION: %s evidence.mountDir %q does not match %s (an absolute, clean path of [A-Za-z0-9._-] elements; it is written into the generated sh script)\n' "${id}" "${mdir}" "${MOUNTDIR_RE}" >&2
      exit 1
    fi
    if [ -f "$(dirname "${f}")/plant.sh" ]; then
      echo "ADR-0056 A5a-2 VIOLATION: ${id} is 'type: ${INVESTIGATE_TYPE}' and also carries a plant.sh (an investigate challenge plants its evidence bundle only; the plant is derived from the type)" >&2
      exit 1
    fi
    INVESTIGATE_IDS+=("${id}")
  done < <(find . -maxdepth 2 -name falco-rule.yaml | sort)
  while IFS= read -r id; do
    [ -z "${id}" ] && continue
    PLANT_IDS+=("${id}")
  done < <({
    find . -maxdepth 2 -name plant.sh | sed 's|^\./||;s|/plant.sh$||'
    if [ "${#INVESTIGATE_IDS[@]}" -gt 0 ]; then printf '%s\n' "${INVESTIGATE_IDS[@]}"; fi
  } | sort -u)
}

mount_dirs_of_id() { # $1=id -> the directory(ies) this id mounts into `challenge`, one per line (evade: from its plant-targets; investigate: evidence.mountDir)
  local type target
  if is_investigate_id "$1"; then
    investigate_mount_dir "$1/falco-rule.yaml"
    return 0
  fi
  type="$(plant_target_type "$1/plant.sh")"
  while IFS= read -r target; do
    [ -z "${target}" ] && continue
    printf '%s\n' "$(mount_dir_for "${target}" "${type}")"
  done < <(plant_targets "$1/plant.sh")
}

evidence_map_for() { # $@ = ids -> "<mountDir> TAB <challenge id>" for each investigate id among them, one per line
  local id
  for id in "$@"; do
    if is_investigate_id "${id}"; then
      printf '%s\t%s\n' "$(investigate_mount_dir "${id}/falco-rule.yaml")" "${id}"
    fi
  done
}

unique_mount_dirs_for() { # $@ = ids -> unique mount-directory list, first-appearance order (2-2, ADR-0007)
  local seen=() id mountdir found x
  for id in "$@"; do
    while IFS= read -r mountdir; do
      [ -z "${mountdir}" ] && continue
      found=0
      if [ "${#seen[@]}" -gt 0 ]; then
        for x in "${seen[@]}"; do
          [ "${x}" = "${mountdir}" ] && found=1 && break
        done
      fi
      if [ "${found}" -eq 0 ]; then
        seen+=("${mountdir}")
        printf '%s\n' "${mountdir}"
      fi
    done < <(mount_dirs_of_id "${id}")
  done
}

# render_evidence_copy <challenge id> <mount dir> <bundle file name>... ->
# ADR-0056 D11's copy lines: the Secret is one per challenge (ctf-evidence-<cid>,
# mounted at ${EVIDENCE_SRC_ROOT}/<cid>); each file by NAME (never `-a`, `.` or a
# glob), a plain file, then read-only. Deliberately does not validate the
# names: check_2_7 (2-7(a)) is the gate, so a bad name must reach it.
render_evidence_copy() {
  local cid="$1" rel f
  rel="$(relpath "$2")"
  shift 2
  for f in "$@"; do
    printf 'cp "%s/%s/%s" "${PLANT_SEED_ROOT}/%s/%s"\n' "${EVIDENCE_SRC_ROOT}" "${cid}" "${f}" "${rel}" "${f}"
    printf 'chmod 0444 "${PLANT_SEED_ROOT}/%s/%s"\n' "${rel}" "${f}"
  done
}

# render_seed_body <id>... -> the *unindented* initContainer script
# body (the ADR-0001/ADR-0007 seed script — this is exactly the text
# Verification 2-7 statically checks).
render_seed_body() {
  local seeded=() id mountdir source found x rel
  printf 'set -eu\n'
  printf 'PLANT_SEED_ROOT=%s\n' "${SEED_ROOT}"
  for id in "$@"; do
    printf '\n# ---- %s ----\n' "${id}"
    if is_investigate_id "${id}"; then
      mountdir="$(investigate_mount_dir "${id}/falco-rule.yaml")"
      rel="$(relpath "${mountdir}")"
      printf '# evidence bundle (ADR-0056 D11): %s is where the bundle files are copied by name from %s/%s/ (the ctf-evidence-%s Secret, mounted in this initContainer only)\n' "${mountdir}" "${EVIDENCE_SRC_ROOT}" "${id}" "${id}"
      printf 'mkdir -p "${PLANT_SEED_ROOT}/%s"\n' "${rel}"
      if [ "${#EVIDENCE_FILES[@]}" -gt 0 ]; then
        render_evidence_copy "${id}" "${mountdir}" "${EVIDENCE_FILES[@]}"
      fi
      continue
    fi
    source="$(plant_seed_source "${id}/plant.sh")"
    while IFS= read -r mountdir; do
      [ -z "${mountdir}" ] && continue
      found=0
      if [ "${#seeded[@]}" -gt 0 ]; then
        for x in "${seeded[@]}"; do
          [ "${x}" = "${mountdir}" ] && found=1 && break
        done
      fi
      if [ "${found}" -eq 0 ]; then
        seeded+=("${mountdir}")
        if [ -n "${source}" ]; then
          rel="$(relpath "${mountdir}")"
          printf '# seed %s from the build-time snapshot (ADR-0001 S-a / ADR-0007) — runs once, directory-wide\n' "${mountdir}"
          printf 'mkdir -p "${PLANT_SEED_ROOT}/%s"\n' "${rel}"
          printf 'cp -a "%s/." "${PLANT_SEED_ROOT}/%s/"\n' "${source}" "${rel}"
        fi
      fi
    done < <(mount_dirs_of_id "${id}")
    plant_body "${id}/plant.sh"
  done
}

# An investigate challenge's mount carries `evidence: true` and
# `challenge: <cid>` (after readOnly): the chart (A5b) copies the bundle files
# of the Secret ctf-evidence-<cid>, by name, into exactly those directories, and
# `fail`s unless this set of cids equals the keys of .Values.evidence.challenges.
# Evade mounts are rendered as before. An evade mount that shares its directory
# with an investigate challenge (it would also be marked) cannot get here:
# check_claims() rule (b) rejects an evidence dir equal to / inside / above
# another challenge's mount dir (fixtures b1 / b2 in verify_claims_negative_tests).
render_plant_block() { # $@ = ids
  local ev
  ev="$(evidence_map_for "$@")"
  cat <<'HDR'
plant:
  seedScript:
    - sh
    - -c
    - |
HDR
  render_seed_body "$@" | indent
  echo '  mounts:'
  unique_mount_dirs_for "$@" | while IFS= read -r d; do
    if is_mount_writable "${d}"; then
      printf '    - path: %s\n      readOnly: false\n' "${d}"
    else
      printf '    - path: %s\n      readOnly: true\n' "${d}"
    fi
    cid="$(printf '%s\n' "${ev}" | awk -F'\t' -v d="${d}" '$1 == d { print $2; exit }')"
    if [ -n "${cid}" ]; then
      printf '      evidence: true\n      challenge: %s\n' "${cid}"
    fi
  done
}

render_one() {
  local id="$1"
  if is_investigate_id "${id}"; then
    cat <<HEADER
# GENERATED from ${id}/falco-rule.yaml (type: ${INVESTIGATE_TYPE}) by gen-values.sh — DO NOT EDIT.
# Run \`make gen-values\` after editing falco-rule.yaml.
HEADER
  else
    cat <<HEADER
# GENERATED from ${id}/plant.sh by gen-values.sh — DO NOT EDIT.
# Run \`make gen-values\` after editing plant.sh.
HEADER
  fi
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
# here. Mount directories (ADR-0007) are the enclosing directory of each
# plant-target, not the plant-target itself when it is a file.
HEADER
  render_plant_block "${PLANT_IDS[@]}"
}

# scenario_all_ids <scenario dir> -> that scenario's full ordered
# challenge-id list (scenario.yaml already validated above).
scenario_all_ids() { scenario_challenge_ids "$1/scenario.yaml"; }

# scenario_plant_ids <scenario dir> -> the subset of PLANT_IDS (global,
# sorted — same "always sort order" discipline as render_all()/
# render_one(), 2-4) that this scenario's challenges: list also names. A
# scenario listing ids out of PLANT_IDS order still renders a deterministic
# seed script; an id with no plant.sh (trigger-only) simply never matches
# and plants nothing, same as it would in "all" mode.
scenario_plant_ids() {
  local dir="$1" m x found ids=()
  while IFS= read -r x; do
    [ -z "${x}" ] && continue
    ids+=("${x}")
  done < <(scenario_all_ids "${dir}")
  for m in "${PLANT_IDS[@]}"; do
    found=0
    for x in "${ids[@]}"; do
      [ "${x}" = "${m}" ] && found=1 && break
    done
    [ "${found}" -eq 1 ] && printf '%s\n' "${m}"
  done
}

render_scenario() { # $1 = scenario dir (e.g. ../scenarios/tutorial-intro)
  local dir="$1" id m
  id="$(basename "${dir}")"
  local plant_ids=()
  while IFS= read -r m; do
    [ -z "${m}" ] && continue
    plant_ids+=("${m}")
  done < <(scenario_plant_ids "${dir}")

  cat <<HEADER
# GENERATED by gen-values.sh from scenarios/${id}/scenario.yaml — DO NOT EDIT.
# Run \`make gen-values\`.
#
# Scenario-scope mode (deploy-user.sh <user> scenario:${id}, P27-1 /
# REFACTORING.md): the \`plant\` initContainer below runs ONLY this
# scenario's own evade missions' plant.sh — a challenge id outside
# scenarios/${id}/scenario.yaml's \`challenges:\` list never has its flag
# planted or its mount directory bound here, regardless of what "all" mode
# or another scenario plants. \`scenario.missions\` additionally scopes
# charts/ctf-user's \`missions-scope\` initContainer, which restricts the
# participant-visible /opt/ctf/missions/ tree to exactly this list
# (fixtures/README isolation, not just flags).
HEADER
  render_plant_block ${plant_ids:+"${plant_ids[@]}"}
  echo 'scenario:'
  echo '  missions:'
  while IFS= read -r m; do
    [ -z "${m}" ] && continue
    printf '    - %s\n' "${m}"
  done < <(scenario_all_ids "${dir}")
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
# script): the deploy path must never read a sensitive path, and must never
# talk to anything, at runtime. Best-effort static heuristic, documented as
# such — see the (f) comment below for the one sub-check that is closer to
# a real allowlist and the limits of the rest.
#   (a) every `cp` copy-source (all operands but the destination) is anchored
#       under ${SNAPSHOT_ROOT}, or is ${EVIDENCE_SRC_ROOT}/<challenge id>/<plain
#       file name> with no flag (ADR-0056 D11 / A5a-2: the one added root; never
#       `-a`, `.`, a glob, `..`, `-t`), and the copy's challenge id is the one
#       of the plant.mounts entry it copies into
#   (b) none of catalog's sensitive_file_names / sensitive dirs appear
#       outside of a ${PLANT_SEED_ROOT}... or ${SNAPSHOT_ROOT}... token
#   (c) grep / egrep / fgrep / find / ln are never invoked (enumerated —
#       see (f))
#   (d) nothing under ${PLANT_SEED_ROOT} is executed
#   (e) no network tool is invoked, and the k8s apiserver's in-cluster DNS
#       name never appears (enumerated — see (f); security-engineer C2)
#   (f) every command actually invoked is in a fixed allowlist — this is
#       the general-purpose backstop for (c)/(e): those two are enumerated
#       (list a name, catch that name) and were exactly how `curl` and
#       `install` slipped through in the security-engineer's audit (C2).
#       (f) instead declares the small, fixed set of commands the
#       initContainer's seed script is allowed to run at all
#       (mkdir/cp/echo/cat/chmod/umask/set/printf/true/:/sh) and fails on
#       anything else — including binaries with no name-based check yet,
#       and bare-path "exec a file we just wrote" forms like
#       `/dev/shm/x` that (c)/(e) don't parse for. It is still a
#       heuristic: it tokenizes each `;`/`&&`/`||`/`|`-separated segment by
#       whitespace and treats the first token as "the command", skipping
#       heredoc bodies and `NAME=value` assignments — it does not parse
#       shell quoting/substitution, so a sufficiently adversarial one-liner
#       (e.g. hiding a command inside `$(...)` or a quoted string that
#       *becomes* a command some other way) could still evade it. A bare
#       `(` or `)` segment (subshell grouping — ADR-0008 Decision (1a)'s
#       `( umask NNN; cat > ... <<EOF ... EOF )` pattern) is exempted, since
#       grouping syntax is not itself a command. Extend the allowlist
#       deliberately when a new plant.sh legitimately needs another
#       command — don't work around a (f) failure by rewording the line.
# ---------------------------------------------------------------------------

check_2_7() { # $1 = generated seed script text (unindented), $2 = label, $3 = evidence map ("<mountDir> TAB <challenge id>" lines of the scope; may be empty)
  local script="$1" label="$2" map="${3:-}" rc=0 hits p residue code offending ln
  local cpout kind nr a b c rest cid name hitsu hitsf hitsm seedpre

  # All sub-checks below look at CODE only — full-comment lines (this
  # script's own documentation, and the prose plant.sh authors write above
  # their commands) are excluded, since they legitimately mention sensitive
  # paths / tool names in prose without ever reading/execing anything.
  # Best-effort heuristic: this only strips a comment that occupies a whole
  # line; it does not parse shell syntax.
  code="$(printf '%s\n' "${script}" | grep -vE '^[[:space:]]*#')"

  # (a) copy-source allowlist: every `cp` (any flags, quoted or not; heredoc
  # bodies skipped; the command of a segment, or the command of a segment's
  # `sh -c "cp ..."`) has EVERY operand but the last (the destination) under
  # ${SNAPSHOT_ROOT}/ (the build-time snapshot), or equal to
  # ${EVIDENCE_SRC_ROOT}/<challenge id>/<plain file name> (ADR-0056 D11: the
  # ctf-evidence-<cid> Secret, the ONE added root; <challenge id> is
  # CHALLENGE_ID_RE, the name is EVIDENCE_NAME_RE: no `.`, `..`, `/`, glob, `$`,
  # space) with NO flag (so never `-a`). A source with a `..` element or a
  # glob / `$` / backtick, a `-t` / `--target-directory`, or a cp with fewer than
  # two operands is rejected.
  # Fail-closed on what the parser does not read: every word `cp` in the code
  # (a heredoc body with an unquoted delimiter included, a quoted one excluded:
  # it is not executed) is counted, and so is every `cp` the parser read in a
  # command position (a segment's first word, or after `sh -c "`). A line with
  # more of the first than the second (`x=$(cp ...)`, `echo $(cp ...)`, a
  # backtick, `a & cp ...`, `then cp`, a `cp` in an unquoted heredoc) is a
  # violation: a `cp` the parser did not see is never "allowed".
  # An evidence-root source (a non-last operand under ${EVIDENCE_SRC_ROOT}/) is
  # allowed in ONE shape only, and always judged against the mounts:
  #   cp "<root>/<cid>/<name>" "${PLANT_SEED_ROOT}<mountDir>/<name>"
  # (two double-quoted operands, no flag, no trailing slash); any other cp with
  # an evidence source is a violation (F). One parser: awk reads the whole
  # command, bash only judges the fields awk prints (no second regex over the
  # line). awk has no interval expressions on every platform, so none is used.
  #   X TAB <line no> TAB <line>                      cp copy-source rule
  #   U TAB <line no> TAB <line>                      a cp the parser did not read
  #   F TAB <line no> TAB <line>                      evidence source, not D11's shape
  #   E TAB <line no> TAB <source> TAB <destination> TAB <line>   D11's shape, judged below
  cpout="$(printf '%s\n' "${code}" | awk -v snap="${SNAPSHOT_ROOT}" -v evs="${EVIDENCE_SRC_ROOT}" '
    function cpwords(s,   n) {
      n = 0
      while (match(s, /(^|[^A-Za-z0-9_-])cp([ \t]|$)/)) { n++; s = substr(s, RSTART + RLENGTH) }
      return n
    }
    BEGIN { heredoc = 0; hq = 0 }
    {
      line = $0
      if (heredoc) {
        chk = line; sub(/^[ \t]+/, "", chk)
        if (chk == delim) heredoc = 0
        else if (!hq && cpwords(line) > 0) printf "U\t%d\t%s\n", NR, line
        next
      }
      t = line
      sub(/^[ \t]+/, "", t); sub(/[ \t]+$/, "", t)
      if (t == "") next
      if (match(t, /<<-?[ \t]*['\''"]?[A-Za-z_][A-Za-z0-9_]*['\''"]?[ \t]*$/)) {
        d = substr(t, RSTART, RLENGTH)
        hq = (d ~ /['\''"]/)
        gsub(/^<<-?[ \t]*['\''"]?/, "", d); gsub(/['\''"]?[ \t]*$/, "", d)
        delim = d; heredoc = 1
      }
      tot = cpwords(t); parsed = 0
      nseg = split(t, segs, /(;|&&|\|\||\|)/)
      for (i = 1; i <= nseg; i++) {
        seg = segs[i]
        gsub(/^[ \t]+/, "", seg); gsub(/[ \t]+$/, "", seg)
        if (seg ~ /^sh[ \t]+-[A-Za-z]+[ \t]+["\047]/) {
          sub(/^sh[ \t]+-[A-Za-z]+[ \t]+["\047]/, "", seg)
          sub(/["\047]$/, "", seg)
        }
        if (seg !~ /^cp([ \t]|$)/) continue
        parsed++
        rest = substr(seg, 3)
        nops = 0; flags = ""; tflag = 0; endopt = 0
        while (match(rest, /^[ \t]+("[^"]*"|\047[^\047]*\047|[^ \t"\047]+)/)) {
          tok = substr(rest, RSTART, RLENGTH)
          rest = substr(rest, RSTART + RLENGTH)
          gsub(/^[ \t]+/, "", tok)
          if (!endopt && substr(tok, 1, 1) == "-") {
            if (tok == "--") endopt = 1
            flags = flags tok
            if (tok ~ /^-[A-Za-z]*t/ || tok ~ /^--target/) tflag = 1
            continue
          }
          nops++
          q[nops] = substr(tok, 1, 1)
          gsub(/^["\047]|["\047]$/, "", tok)
          ops[nops] = tok
        }
        bad = 0
        if (rest !~ /^[ \t]*$/ || tflag || nops < 2) bad = 1
        hasev = 0
        for (k = 1; !bad && k < nops; k++) {
          if (ops[k] == evs || index(ops[k], evs "/") == 1) hasev = 1
        }
        if (!bad && hasev) {
          dest = ops[nops]; drel = substr(dest, 19)
          if (flags == "" && nops == 2 && q[1] == "\"" && q[2] == "\"" \
              && index(dest, "${PLANT_SEED_ROOT}/") == 1 \
              && drel ~ /^(\/[A-Za-z0-9._-]+)+$/ && drel !~ /(^|\/)\.\.(\/|$)/) {
            printf "E\t%d\t%s\t%s\t%s\n", NR, ops[1], dest, line
          } else printf "F\t%d\t%s\n", NR, line
        } else if (!bad) {
          for (k = 1; !bad && k < nops; k++) {
            src = ops[k]
            if (src ~ /(^|\/)\.\.(\/|$)/ || src ~ /[*?$`]/ || index(src, "[") > 0) bad = 1
            else if (index(src, snap "/") != 1) bad = 1
          }
        }
        if (bad) printf "X\t%d\t%s\n", NR, line
      }
      if (tot > parsed) printf "U\t%d\t%s\n", NR, line
    }
  ' || true)"
  hits=""
  hitsu=""
  hitsf=""
  hitsm=""
  while IFS=$'\t' read -r kind nr a b c; do
    [ -z "${kind}" ] && continue
    case "${kind}" in
      X) hits="${hits}${nr}:${a}"$'\n' ;;
      U) hitsu="${hitsu}${nr}:${a}"$'\n' ;;
      F) hitsf="${hitsf}${nr}:${a}"$'\n' ;;
      E)
        # a = source, b = destination, c = the line
        rest="${a#"${EVIDENCE_SRC_ROOT}"/}"
        cid="${rest%%/*}"
        name="${rest#*/}"
        if [ "${rest}" = "${cid}" ] || ! [[ "${cid}" =~ ${CHALLENGE_ID_RE} ]] || ! [[ "${name}" =~ ${EVIDENCE_NAME_RE} ]]; then
          hits="${hits}${nr}:${c}"$'\n'
        else
          # D11: the destination directory is the mountDir of the challenge the
          # source directory belongs to, and the file keeps its name
          seedpre='${PLANT_SEED_ROOT}'
          rest="${b#"${seedpre}"}"
          if [ "${rest##*/}" != "${name}" ] || ! printf '%s\n' "${map}" | grep -qxF "${rest%/*}"$'\t'"${cid}"; then
            hitsm="${hitsm}${nr}:${c}"$'\n'
          fi
        fi
        ;;
    esac
  done <<< "${cpout}"
  if [ -n "${hits}" ]; then
    echo "2-7(a) VIOLATION [${label}]: cp copy-source is not ${SNAPSHOT_ROOT}/... or ${EVIDENCE_SRC_ROOT}/<challenge id>/<plain file name> (every operand but the last; no flag on an evidence copy, no '-a', no '.', no glob, no '..', no -t / --target-directory):" >&2
    printf '%s' "${hits}" | sed 's/^/    /' >&2
    rc=1
  fi
  if [ -n "${hitsu}" ]; then
    echo "2-7(a) VIOLATION [${label}]: a word cp the 2-7(a) parser did not read as a command (a cp in a substitution, a backtick, after a lone '&', in an unquoted heredoc, in an argument):" >&2
    printf '%s' "${hitsu}" | sed 's/^/    /' >&2
    rc=1
  fi
  if [ -n "${hitsf}" ]; then
    echo "2-7(a) VIOLATION [${label}]: a cp from ${EVIDENCE_SRC_ROOT}/ is not exactly: cp \"${EVIDENCE_SRC_ROOT}/<cid>/<name>\" \"\${PLANT_SEED_ROOT}<mountDir>/<name>\" (one source, two double-quoted operands, no flag, no trailing slash, inside the seed root):" >&2
    printf '%s' "${hitsf}" | sed 's/^/    /' >&2
    rc=1
  fi
  if [ -n "${hitsm}" ]; then
    echo "2-7(a) VIOLATION [${label}]: evidence copy does not match a plant.mounts entry {path: <destination directory>, challenge: <the source's challenge id>} with the same file name:" >&2
    printf '%s' "${hitsm}" | sed 's/^/    /' >&2
    rc=1
  fi

  # (b) sensitive paths must not appear outside a safe (seed-relative)
  # prefix. Strip every safe occurrence from a copy of the text, then
  # report only the ORIGINAL lines whose stripped counterpart still
  # contains the bare sensitive literal (not every line that merely
  # mentions it safely — security-engineer A7).
  for p in $(sensitive_paths) $(sensitive_dir_prefixes); do
    [ -z "${p}" ] && continue
    residue="$(printf '%s\n' "${code}" \
      | sed -E "s#\\\$\\{PLANT_SEED_ROOT\\}${p}##g; s#${SNAPSHOT_ROOT}${p}##g")"
    offending="$(printf '%s\n' "${residue}" | grep -nF "${p}" | cut -d: -f1 || true)"
    if [ -n "${offending}" ]; then
      echo "2-7(b) VIOLATION [${label}]: sensitive path '${p}' appears outside \${PLANT_SEED_ROOT}/... or ${SNAPSHOT_ROOT}/... in the generated script:" >&2
      while IFS= read -r ln; do
        [ -z "${ln}" ] && continue
        printf '%s\n' "${code}" | sed -n "${ln}p" | sed 's/^/    /' >&2
      done <<< "${offending}"
      rc=1
    fi
  done

  # (c) forbidden binaries (word-boundary match). Enumerated — see (f).
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

  # (e) network tools + the in-cluster apiserver DNS name (security-engineer
  # C2: mission 01's expectedRule is "Contact K8S API Server From
  # Container" — a deploy-path `curl`/`wget` to it would auto-solve 01 for
  # every participant on every deploy, the same class of bug S-a closed for
  # mission 02). Enumerated — see (f).
  hits="$(printf '%s\n' "${code}" \
    | grep -nE '(^|[^A-Za-z0-9_])(curl|wget|nc|ncat|netcat|nslookup|dig|getent)([^A-Za-z0-9_]|$)' || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(e) VIOLATION [${label}]: forbidden network tool in generated seed script:" >&2
    printf '%s\n' "${hits}" | sed 's/^/    /' >&2
    rc=1
  fi
  hits="$(printf '%s\n' "${code}" | grep -nF 'kubernetes.default' || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(e) VIOLATION [${label}]: in-cluster apiserver DNS name in generated seed script:" >&2
    printf '%s\n' "${hits}" | sed 's/^/    /' >&2
    rc=1
  fi

  # (f) allowlist backstop — see the block comment above this function.
  #
  # ADR-0008 Decision (1a): `umask` was added to the allowlist and bare `(`
  # / `)` grouping lines are explicitly skipped (not treated as an
  # unrecognized "command") so a plant.sh can scope a `umask` override to a
  # `( umask NNN; cat > ... <<EOF ... EOF )` subshell — the mechanism that
  # replaced mission 05's standalone `chmod 600 ...` exec (removing that
  # exec's "id_rsa" argv literal from the deploy path once "Search Private
  # Keys or Passwords" was generalized to fire on ANY proc, not just
  # proc.name=find). `(`/`)` are shell grouping syntax, never a command
  # name, so skipping them exactly-matched (not stripped from a glued
  # token) keeps this heuristic from silently accepting `(rm -rf /)` as
  # "just grouping" — only a segment that IS `(` or `)` on its own is
  # exempted.
  hits="$(printf '%s\n' "${code}" | awk '
    BEGIN {
      n = split("sh set mkdir cp echo cat chmod umask printf true :", allowed, " ")
      for (i = 1; i <= n; i++) allow[allowed[i]] = 1
      heredoc = 0
    }
    {
      line = $0
      if (heredoc) {
        chk = line; sub(/^[ \t]+/, "", chk)
        if (chk == delim) heredoc = 0
        next
      }
      t = line
      sub(/^[ \t]+/, "", t); sub(/[ \t]+$/, "", t)
      if (t == "") next
      if (match(t, /<<-?[ \t]*['\''"]?[A-Za-z_][A-Za-z0-9_]*['\''"]?[ \t]*$/)) {
        d = substr(t, RSTART, RLENGTH)
        gsub(/^<<-?[ \t]*['\''"]?/, "", d); gsub(/['\''"]?[ \t]*$/, "", d)
        delim = d; heredoc = 1
      }
      nseg = split(t, segs, /(;|&&|\|\||\|)/)
      for (i = 1; i <= nseg; i++) {
        seg = segs[i]
        gsub(/^[ \t]+/, "", seg); gsub(/[ \t]+$/, "", seg)
        if (seg == "") continue
        if (seg == "(" || seg == ")") continue
        if (seg ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue
        split(seg, w, /[ \t]+/)
        if (w[1] != "" && !(w[1] in allow)) printf "%d:%s\n", NR, line
      }
    }
  ' || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(f) VIOLATION [${label}]: command not in the seed-script allowlist (mkdir/cp/echo/cat/chmod/umask/set/printf/true/:/sh, or a bare '(' / ')' grouping line):" >&2
    printf '%s\n' "${hits}" | sort -t: -k1,1 -u | sed 's/^/    /' >&2
    rc=1
  fi

  return "${rc}"
}

run_2_7_all_scopes() {
  local rc=0 id sdir sid m plant_ids
  check_2_7 "$(render_seed_body "${PLANT_IDS[@]}")" "values-all" "$(evidence_map_for "${PLANT_IDS[@]}")" || rc=1
  for id in "${PLANT_IDS[@]}"; do
    check_2_7 "$(render_seed_body "${id}")" "${id}" "$(evidence_map_for "${id}")" || rc=1
  done
  # P27-1: scenario-scoped seed scripts get the exact same ADR-0001
  # Verification 2-7 treatment as values-all / per-mission — a filtered
  # mission-id list must still pass every allowlist/sensitive-path check.
  while IFS= read -r sdir; do
    [ -z "${sdir}" ] && continue
    sid="$(basename "${sdir}")"
    plant_ids=()
    while IFS= read -r m; do
      [ -z "${m}" ] && continue
      plant_ids+=("${m}")
    done < <(scenario_plant_ids "${sdir}")
    check_2_7 "$(render_seed_body ${plant_ids:+"${plant_ids[@]}"})" "scenario:${sid}" "$(evidence_map_for ${plant_ids:+"${plant_ids[@]}"})" || rc=1
  done < <(scenario_dirs)
  return "${rc}"
}

# ---------------------------------------------------------------------------
# ADR-0007 Verification 1: plant.mounts directory-granularity static assert.
#
#   - every plant.mounts entry must be a directory (structural check: it
#     must never be literally one of the declared FILE-type plant-targets —
#     a file-type target's mount is always its dirname, by construction, so
#     if a mount ever equals the raw file target itself, generation
#     regressed to file granularity). As of the 2026-09-01 vault-separation
#     change (03/10 retargeted from `/etc/shadow` (type: file) to
#     `/opt/nimbus/vault` (type: dir, mission-05-shaped), no challenge in
#     the catalog currently declares `plant-target-type: file` —
#     file_type_mount_targets() below is legitimately empty in real runs.
#     This branch is not dead code: it stays load-bearing the moment any
#     future plant.sh declares a file-type target again, and its rejection
#     logic itself is regression-tested independent of live catalog data —
#     see check_mount_granularity()'s $4 override and verify_negative_test()
#     below.
#   - plant.mounts must never contain "/" or the seed root itself (ADR-0001
#     F5's "never mount the whole seed tree" continued into this dimension)
#   - the extracted mount set must be non-empty in the all-missions scope
#     (an empty result must never read as "no violations")
#   - judged entirely by exit status (no string-matching on stdout)
# ---------------------------------------------------------------------------

file_type_mount_targets() { # -> every declared plant-target whose type is "file", one per line
  local id target type
  for id in "${MISSIONS[@]}"; do
    type="$(plant_target_type "${id}/plant.sh")"
    [ "${type}" = "file" ] || continue
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      printf '%s\n' "${target}"
    done < <(plant_targets "${id}/plant.sh")
  done
}

# extract_mount_paths <file>: pull the bare path out of every `mounts:` list
# entry, whichever shape it's in — the current {path, readOnly} map form
# ("    - path: /etc") AND the pre-ADR-0007 bare-string form
# ("    - /etc/shadow"), the latter INTENTIONALLY still recognized so a
# fixture using the old shape (ADR-0007 Verification 2's negative test) is
# actually seen by this extractor rather than silently skipped.
extract_mount_paths() { # $1=file
  awk '
    /^  mounts:$/ { f=1; next }
    f && /^    - / {
      line = $0
      sub(/^    - /, "", line)
      sub(/^path: */, "", line)
      gsub(/^"|"$/, "", line)
      print line
      next
    }
    f && /^[^ ]/ { f=0 }
  ' "$1"
}

check_mount_granularity() { # $1=values file $2=label $3=allow_empty(0/1, default 0) $4=file_type_targets_override(optional, newline-separated; defaults to the live file_type_mount_targets() when omitted) -> rc 0 iff every mount is a directory
  local file="$1" label="$2" allow_empty="${3:-0}" file_type_override="${4:-}" rc=0 mounts n m ft
  mounts="$(extract_mount_paths "${file}")"
  n="$(printf '%s\n' "${mounts}" | grep -c . || true)"
  if [ "${n}" -eq 0 ]; then
    if [ "${allow_empty}" -eq 1 ]; then
      echo "  ok: [${label}] 0 plant.mounts entries (scenario has no evade missions in scope)"
      return 0
    fi
    echo "ADR-0007 V1 VIOLATION [${label}]: extracted 0 plant.mounts entries from ${file} (extraction is broken, or this scope genuinely plants nothing — the all-missions/per-mission scopes checked below must always have >=1)" >&2
    return 1
  fi
  while IFS= read -r m; do
    [ -z "${m}" ] && continue
    case "${m}" in
      /|"${SEED_ROOT}"|"${SEED_ROOT}"/*)
        echo "ADR-0007 V1 VIOLATION [${label}]: plant.mounts entry '${m}' is '/' or the seed root itself" >&2
        rc=1
        ;;
    esac
    while IFS= read -r ft; do
      [ -z "${ft}" ] && continue
      if [ "${m}" = "${ft}" ]; then
        echo "ADR-0007 V1 VIOLATION [${label}]: plant.mounts entry '${m}' is a FILE-granularity plant-target — it must be mounted at its enclosing directory instead (this is exactly the defect ADR-0007 closes: a file-destination bind mount makes the runtime's own mount-setup trigger open_read-family Falco rules on every deploy)" >&2
        rc=1
      fi
    done < <(if [ -n "${file_type_override}" ]; then printf '%s\n' "${file_type_override}"; else file_type_mount_targets; fi)
  done <<< "${mounts}"
  return "${rc}"
}

run_verification_1_all_scopes() {
  local rc=0 id sdir sid plant_ids m allow_empty
  check_mount_granularity <(render_all) "values-all (generated)" || rc=1
  for id in "${PLANT_IDS[@]}"; do
    check_mount_granularity <(render_one "${id}") "${id} (generated)" || rc=1
  done
  # P27-1: scenario-scoped plant.mounts get the same directory-granularity
  # assert. allow_empty=1 only when this scenario has zero evade missions in
  # scope (a legitimately empty plant.mounts, not a broken extraction).
  while IFS= read -r sdir; do
    [ -z "${sdir}" ] && continue
    sid="$(basename "${sdir}")"
    plant_ids=()
    while IFS= read -r m; do
      [ -z "${m}" ] && continue
      plant_ids+=("${m}")
    done < <(scenario_plant_ids "${sdir}")
    allow_empty=0
    [ "${#plant_ids[@]}" -eq 0 ] && allow_empty=1
    check_mount_granularity <(render_scenario "${sdir}") "scenario:${sid} (generated)" "${allow_empty}" || rc=1
  done < <(scenario_dirs)
  return "${rc}"
}

# ---------------------------------------------------------------------------
# ADR-0007 Verification 2: negative test (self-check that Verification 1 is
# not vacuous). Feeds check_mount_granularity a fixture whose plant.mounts
# lists a FILE-granularity entry and asserts it is REJECTED. If this ever
# passes (i.e. the fixture is accepted), Verification 1's own assert has
# regressed to a no-op and this function itself fails closed.
#
# 2026-09-01 vault-separation update: `/etc/shadow` is no longer a live,
# catalog-declared file-type plant-target (03/10 moved to
# `/opt/nimbus/vault`, type: dir — see file_type_mount_targets()'s comment
# above). The historical `/etc/shadow` literal is kept here as an explicit
# $4 OVERRIDE passed to check_mount_granularity (not read from live catalog
# data via file_type_mount_targets()), so this test still exercises the
# REJECTION LOGIC ITSELF (an entry equal to a declared file-type target must
# be flagged) even though no real plant.sh currently supplies that data.
# This is weaker than the pre-vault-separation form in one sense (it no
# longer also proves file_type_mount_targets() extraction is wired
# correctly against a live example) — see ADR-0007 Verification 2's
# "judged entirely by exit status" discipline note above; the exit-status
# check itself is unchanged, only its input provenance is.
# ---------------------------------------------------------------------------

verify_negative_test() {
  local fixture out
  fixture="$(mktemp)"
  out="$(mktemp)"
  trap 'rm -f "${fixture}" "${out}"' RETURN
  cat > "${fixture}" <<'FIXTURE'
# ADR-0007 Verification 2 fixture — INTENTIONALLY violates Verification 1
# (file-granularity plant.mounts entry). Never committed as a real
# values.yaml; generated in a tempfile by gen-values.sh --check and deleted
# immediately after use.
plant:
  seedScript:
    - sh
    - -c
    - "true"
  mounts:
    - /etc/shadow
FIXTURE
  if check_mount_granularity "${fixture}" "ADR-0007-V2-fixture" 0 "/etc/shadow" >"${out}" 2>&1; then
    echo "ADR-0007 V2 VIOLATION: the deliberately-bad fixture (plant.mounts: [/etc/shadow], file granularity) was ACCEPTED against the synthetic file-type-target override '/etc/shadow' — Verification 1's rejection logic is vacuous" >&2
    cat "${out}" >&2
    return 1
  fi
  echo "  ok: ADR-0007 Verification 2 — the file-granularity fixture is correctly rejected (synthetic override, no live catalog file-type target as of 2026-09-01 vault separation)"
  return 0
}

# ---------------------------------------------------------------------------
# ADR-0056 D1 (`investigate` challenge's evidence.mountDir) + ADR-0055 C4 (ii)
# (plant write destinations are disjoint across the whole challenge pool).
#
# Everything is judged over one table of "claims", one line per fact:
#
#   <challenge id> TAB <kind> TAB <absolute path>
#
#   mount     the directory a plant.sh's plant-target is bind-mounted at
#   write     a FILE a plant.sh writes: the destination of a `>` / `>>`
#             redirect or a `cp` anchored at ${PLANT_SEED_ROOT}, plus a
#             `plant-target-type: file` target itself (this is the one list
#             2-5 only half-checked: it asks "is the destination under the
#             seed root", never "does another plant.sh write the same file")
#   evidence  an `investigate` challenge's evidence.mountDir (falco-rule.yaml:
#             `type: investigate`, `investigate.evidence.mountDir`)
#
# collect_claims() reads the tree, check_claims() judges the table, so the
# negative fixtures below run the SAME two functions over a synthetic tree
# (ADR-0007 V2's shape: a check that cannot be seen to fail is vacuous).
#
# Rules (check_claims):
#   (a) an evidence dir is neither inside nor above a sensitive_dir_prefixes()
#       entry (so a deploy cannot trip the catalog's own rule, I13b). The list
#       is gen-values' own; it is NOT copied into Go. (a2) Likewise for the
#       directory of each sensitive FILE (sensitive_paths()): not equal to it
#       and not above it. Both rules are for investigate evidence only; the
#       evade plant-targets (03/05/10) plant into sensitive places on purpose.
#   (b) an evidence dir does not overlap (equal / inside / above) any OTHER
#       challenge's mount dir, write file or evidence dir. A bundle's file
#       names are not known here, so any shared directory is treated as a
#       shared file.
#   (c) no file is written by two different plant.sh. Sharing a DIRECTORY is
#       fine (03 and 10 write creds.recover and master.key into one dir).
#   plus fail-closed guards: every plant.sh LINE that mentions PLANT_SEED_ROOT
#   must be one of the enumerated forms (plant_unrecognized_lines()), a
#   falco-rule.yaml with an `investigate:` block / mountDir whose type is not
#   INVESTIGATE_TYPE is rejected, every compared path is absolute and clean, a
#   write destination with a shell expansion cannot be compared and is
#   rejected, a plant.sh with no recognized write destination is rejected
#   (an unrecognized write form must not read as "disjoint"), a `type:
#   investigate` file with no extractable mountDir is rejected, and an empty
#   table / empty sensitive list is a failure, never "clean".
# The investigate type has no plant.sh and no challenge in the tree uses it
# yet (ADR-0056 A5a-1): until one does, (a) and (b) are exercised only by the
# fixtures in verify_claims_negative_tests(); (c) runs on the real plant.sh.
# ---------------------------------------------------------------------------

plant_write_files() { # <plant.sh> -> absolute FILE paths it writes via redirect / cp, one per line
  local code
  code="$(plant_body "$1" | grep -vE '^[[:space:]]*#' || true)"
  {
    printf '%s\n' "${code}" \
      | sed -nE 's#.*>>?[[:space:]]*"?\$\{PLANT_SEED_ROOT\}(/[^"[:space:]]+).*#\1#p'
    printf '%s\n' "${code}" \
      | sed -nE 's#^[[:space:]]*cp[[:space:]].*[[:space:]]"?\$\{PLANT_SEED_ROOT\}(/[^"[:space:]]+)"?[[:space:]]*$#\1#p'
  } | sort -u
}

# plant_unrecognized_lines <plant.sh> -> every non-comment line that mentions
# PLANT_SEED_ROOT in a form NOT enumerated here, one per line. Fail-closed per
# LINE (not per file): a recognized write elsewhere in the same plant.sh must
# not let an unrecognized one (two redirects on one line, a brace-less
# $PLANT_SEED_ROOT, a quote in another place, a cp into a directory, tee, ...)
# slip through unseen. The forms are exactly the ones the plant.sh files use,
# each with ONE "${PLANT_SEED_ROOT}/path" operand (path chars [A-Za-z0-9._/-],
# no trailing slash):
#   mkdir -p "${PLANT_SEED_ROOT}/dir"
#   chmod MODE "${PLANT_SEED_ROOT}/path"
#   <anything> > "${PLANT_SEED_ROOT}/file"   (also >>; also `cat > f <<EOF`)
#   cp SRC "${PLANT_SEED_ROOT}/file"          (SRC without a variable, no flags)
# Not detectable here: a cp whose destination is a directory with no trailing
# slash (the shell decides at run time).
plant_unrecognized_lines() {
  local f="$1" line n
  local re_path='"\$\{PLANT_SEED_ROOT\}/[A-Za-z0-9._/-]*[A-Za-z0-9._-]"'
  local re_mkdir="^[[:space:]]*mkdir -p ${re_path}[[:space:]]*\$"
  local re_chmod="^[[:space:]]*chmod [0-7]+ ${re_path}[[:space:]]*\$"
  local re_redir=">>?[[:space:]]*${re_path}([[:space:]]|\$)"
  local re_cp="^[[:space:]]*cp ([^[:space:]\"\$]+|\"[^\"\$]+\") ${re_path}[[:space:]]*\$"
  while IFS= read -r line; do
    case "${line}" in
      *PLANT_SEED_ROOT*) ;;
      *) continue ;;
    esac
    n="$(printf '%s\n' "${line}" | grep -o 'PLANT_SEED_ROOT' | grep -c . || true)"
    if [ "${n}" -eq 1 ]; then
      if [[ "${line}" =~ ${re_mkdir} ]] || [[ "${line}" =~ ${re_chmod} ]] \
        || [[ "${line}" =~ ${re_redir} ]] || [[ "${line}" =~ ${re_cp} ]]; then
        continue
      fi
    fi
    printf '%s\n' "${line}"
  done < <(plant_body "${f}" | grep -vE '^[[:space:]]*#' || true)
}

# The `type:` value of the 4th challenge type, as the catalog spells it
# (catalog.TypeInvestigate). internal/catalog/investigate_type_parity_test.go
# reads this assignment and holds it equal to the Go constant, so a rename in
# Go that is missed here is red instead of silently dropping real investigate
# challenges out of the rules above.
INVESTIGATE_TYPE='investigate'

is_investigate_file() { # <falco-rule.yaml> -> rc 0 iff its top-level type is INVESTIGATE_TYPE
  grep -qE "^type:[[:space:]]*[\"']?${INVESTIGATE_TYPE}[\"']?[[:space:]]*(#.*)?\$" "$1"
}

# <falco-rule.yaml> -> investigate.evidence.mountDir (nothing if it cannot be
# read). Same restrained awk style as scenario_challenge_ids(): the block form
# (`  evidence:` then `    mountDir: X`) and the flow form that the catalog
# tests use (`  evidence: {mountDir: X}`). Anything else extracts nothing,
# which check_claims() turns into a violation.
investigate_mount_dir() {
  awk '
    function clean(v) {
      sub(/[ \t]*[,}#].*$/, "", v)
      gsub(/^["\047]|["\047]$/, "", v)
      return v
    }
    /^[^ \t#]/ { ininv = ($0 ~ /^investigate:/); inev = 0; next }
    ininv && /^  [^ \t#]/ {
      inev = ($0 ~ /^  evidence:/)
      if (inev && $0 ~ /mountDir:/) {
        v = $0; sub(/.*mountDir:[ \t]*/, "", v); print clean(v); exit
      }
      next
    }
    ininv && inev && /^    mountDir:/ {
      v = $0; sub(/^    mountDir:[ \t]*/, "", v); print clean(v); exit
    }
  ' "$1"
}

collect_claims() { # $1=challenges root -> the claims table (see above)
  local root="$1" f id type target w mdir
  while IFS= read -r f; do
    [ -z "${f}" ] && continue
    id="$(basename "$(dirname "${f}")")"
    type="$(plant_target_type "${f}")"
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      printf '%s\tmount\t%s\n' "${id}" "$(mount_dir_for "${target}" "${type}")"
      if [ "${type}" = "file" ]; then
        printf '%s\twrite\t%s\n' "${id}" "${target}"
      fi
    done < <(plant_targets "${f}")
    while IFS= read -r w; do
      [ -z "${w}" ] && continue
      printf '%s\twrite\t%s\n' "${id}" "${w}"
    done < <(plant_write_files "${f}")
    while IFS= read -r w; do
      [ -z "${w}" ] && continue
      printf '%s\tunparsed\t%s\n' "${id}" "$(printf '%s' "${w}" | tr '\t' ' ')"
    done < <(plant_unrecognized_lines "${f}")
  done < <(find "${root}" -maxdepth 2 -name plant.sh | sort)
  while IFS= read -r f; do
    [ -z "${f}" ] && continue
    id="$(basename "$(dirname "${f}")")"
    if is_investigate_file "${f}"; then
      mdir="$(investigate_mount_dir "${f}")"
      printf '%s\tevidence\t%s\n' "${id}" "${mdir}"
    elif grep -qE '^investigate:|^[^#]*mountDir:' "${f}"; then
      # an investigate block / mountDir under a type this script does not
      # recognize: it would silently escape rules (a)/(b) (fail-closed)
      printf '%s\ttypemiss\t\n' "${id}"
    fi
  done < <(find "${root}" -maxdepth 2 -name falco-rule.yaml | sort)
}

claims_path_clean() { # $1 -> rc 0 iff an absolute path, not "/", no doubled or trailing slash, no . / .. element
  case "$1" in
    /) return 1 ;;
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *//*|*/|*/.|*/..|*/./*|*/../*) return 1 ;;
  esac
  return 0
}

claims_path_overlaps() { # $1 $2 -> rc 0 iff equal, or one is inside the other (whole elements)
  [ "$1" = "$2" ] && return 0
  case "$1" in "$2"/*) return 0 ;; esac
  case "$2" in "$1"/*) return 0 ;; esac
  return 1
}

check_claims() { # $1=claims table $2=sensitive dir prefixes $3=sensitive file paths (one per line each) -> rc 0 iff every rule holds
  local claims="$1" prefixes="$2" sfiles="$3" rc=0 d
  local ids=() kinds=() paths=() n=0 nwrite=0 id kind p i j s k reported="|"
  while IFS=$'\t' read -r id kind p; do
    [ -z "${id}" ] && continue
    ids+=("${id}")
    kinds+=("${kind}")
    paths+=("${p}")
    n=$((n + 1))
    if [ "${kind}" = "write" ]; then
      nwrite=$((nwrite + 1))
    fi
  done <<< "${claims}"
  if [ "${n}" -eq 0 ] || [ "${nwrite}" -eq 0 ]; then
    echo "ADR-0055 C4 (ii) VIOLATION: no plant write destination was recognized in any plant.sh (the extraction is broken; an empty table must never read as 'disjoint')" >&2
    return 1
  fi
  if [ -z "${prefixes}" ]; then
    echo "ADR-0056 D1 VIOLATION: sensitive_dir_prefixes() is empty (the extraction from ${SENSITIVE_RULE_FILE} is broken; an empty list must never read as 'outside')" >&2
    return 1
  fi
  if [ -z "${sfiles}" ]; then
    echo "ADR-0056 D1 VIOLATION: sensitive_paths() is empty (the extraction from ${SENSITIVE_RULE_FILE} is broken; an empty list must never read as 'outside')" >&2
    return 1
  fi

  i=0
  while [ "${i}" -lt "${n}" ]; do
    id="${ids[$i]}"
    kind="${kinds[$i]}"
    p="${paths[$i]}"

    if [ "${kind}" = "unparsed" ]; then
      echo "ADR-0055 C4 (ii) VIOLATION: ${id}/plant.sh line '${p}' mentions \${PLANT_SEED_ROOT} in a form that is not one of the enumerated plant.sh forms (mkdir -p / chmod MODE / one '>' or '>>' redirect / cp SRC FILE, each with exactly one \"\${PLANT_SEED_ROOT}/path\" operand), so its write destination cannot be compared" >&2
      rc=1
      i=$((i + 1))
      continue
    fi
    if [ "${kind}" = "typemiss" ]; then
      echo "ADR-0056 D1 VIOLATION: ${id}/falco-rule.yaml has an 'investigate:' block or a 'mountDir:' but its top-level type is not '${INVESTIGATE_TYPE}' (this script's INVESTIGATE_TYPE; a mismatch would drop the challenge out of rules (a) and (b))" >&2
      rc=1
      i=$((i + 1))
      continue
    fi
    if [ "${kind}" = "evidence" ] && [ -z "${p}" ]; then
      echo "ADR-0056 D1 VIOLATION: ${id} is 'type: investigate' but no investigate.evidence.mountDir could be read from its falco-rule.yaml" >&2
      rc=1
      i=$((i + 1))
      continue
    fi
    if ! claims_path_clean "${p}"; then
      echo "ADR-0056 D1 VIOLATION: ${id} ${kind} path '${p}' is not an absolute, clean path (no '/', doubled or trailing slash, '.' or '..' element); it cannot be compared reliably" >&2
      rc=1
      i=$((i + 1))
      continue
    fi
    if [ "${kind}" = "write" ]; then
      case "${p}" in
        *'$'*|*'`'*|*'*'*|*'?'*|*'['*)
          echo "ADR-0055 C4 (ii) VIOLATION: ${id}/plant.sh writes to '${p}', which contains a shell expansion or glob and cannot be compared with other write destinations" >&2
          rc=1
          ;;
      esac
    fi

    if [ "${kind}" = "mount" ]; then
      # every plant.sh must have at least one recognized write destination
      s=0
      j=0
      while [ "${j}" -lt "${n}" ]; do
        if [ "${ids[$j]}" = "${id}" ] && [ "${kinds[$j]}" = "write" ]; then
          s=1
          break
        fi
        j=$((j + 1))
      done
      case "${reported}" in
        *"|${id}|"*) s=1 ;;
      esac
      if [ "${s}" -eq 0 ]; then
        echo "ADR-0055 C4 (ii) VIOLATION: ${id}/plant.sh has no recognized write destination (a '>' / '>>' redirect or a 'cp' anchored at \${PLANT_SEED_ROOT}); its files cannot be checked for overlap" >&2
        reported="${reported}${id}|"
        rc=1
      fi
    fi

    if [ "${kind}" = "write" ]; then
      j=$((i + 1))
      while [ "${j}" -lt "${n}" ]; do
        if [ "${kinds[$j]}" = "write" ] && [ "${ids[$j]}" != "${id}" ] && [ "${paths[$j]}" = "${p}" ]; then
          echo "ADR-0055 C4 (ii) VIOLATION: ${id}/plant.sh and ${ids[$j]}/plant.sh both write the file '${p}' (plant write destinations must be disjoint across the whole challenge pool; sharing a directory is fine, sharing a file is not)" >&2
          rc=1
        fi
        j=$((j + 1))
      done
    fi

    if [ "${kind}" = "evidence" ]; then
      # (R) ADR-0056 D11 / V44: not equal to, inside or above the three roots this
      # script owns. internal/catalog's reservedMountRoots has four: these three
      # (mountroots_parity_test.go ties them to the constants here) and
      # /opt/ctf/missions (I16), which only the Go side refuses. A mountDir under EVIDENCE_SRC_ROOT would
      # make 2-7(a)'s judgement of a copy source ambiguous, one over the seed root or
      # the snapshot would mount an evidence directory over the plant's own.
      for s in "${SEED_ROOT}" "${SNAPSHOT_ROOT}" "${EVIDENCE_SRC_ROOT}"; do
        if claims_path_overlaps "${p}" "${s}"; then
          echo "ADR-0056 D11 (R) VIOLATION: ${id} evidence.mountDir '${p}' is equal to, inside or above the reserved root '${s}' (the seed root, the build-time snapshot, or where the evidence Secrets are mounted in the plant initContainer)" >&2
          rc=1
        fi
      done
      while IFS= read -r s; do
        [ -z "${s}" ] && continue
        if claims_path_overlaps "${p}" "${s}"; then
          echo "ADR-0056 D1 (a) VIOLATION: ${id} evidence.mountDir '${p}' is inside or above the sensitive directory '${s}' (the deploy would trip the catalog's own rule, I13b)" >&2
          rc=1
        fi
      done <<< "${prefixes}"
      # (a2) the directory of every sensitive FILE (sensitive_paths(), from the
      # same rule.yaml): the rule fires on fd.name in that list, so a bundle in
      # the file's own directory (or in an ancestor, which mounts over it) is
      # what the sensitive-file rule is about. Not applied to plant-targets:
      # 03/05/10 are evade challenges that plant INTO sensitive places on purpose.
      while IFS= read -r s; do
        [ -z "${s}" ] && continue
        d="$(dirname "${s}")"
        if [ "${p}" = "${s}" ] || [ "${p}" = "${d}" ]; then
          echo "ADR-0056 D1 (a2) VIOLATION: ${id} evidence.mountDir '${p}' is the sensitive file '${s}' or its directory (the deploy would trip the catalog's sensitive-file rule, I13b)" >&2
          rc=1
        else
          case "${d}" in
            "${p}"/*)
              echo "ADR-0056 D1 (a2) VIOLATION: ${id} evidence.mountDir '${p}' is above the directory '${d}' of the sensitive file '${s}' (it would mount over it)" >&2
              rc=1
              ;;
          esac
        fi
      done <<< "${sfiles}"
      j=0
      while [ "${j}" -lt "${n}" ]; do
        k="${kinds[$j]}"
        if [ "${ids[$j]}" != "${id}" ] && [ -n "${paths[$j]}" ] \
          && { [ "${k}" = "mount" ] || [ "${k}" = "write" ] || { [ "${k}" = "evidence" ] && [ "${j}" -gt "${i}" ]; }; } \
          && claims_path_overlaps "${p}" "${paths[$j]}"; then
          echo "ADR-0056 D1 (b) VIOLATION: ${id} evidence.mountDir '${p}' overlaps the ${k} '${paths[$j]}' of ${ids[$j]} (ADR-0055 C4 (ii): evidence and plant destinations must be disjoint)" >&2
          rc=1
        fi
        j=$((j + 1))
      done
    fi
    i=$((i + 1))
  done
  return "${rc}"
}

run_claims_check() { # the live tree (the cwd is challenges/)
  local claims
  claims="$(collect_claims .)"
  check_claims "${claims}" "$(sensitive_dir_prefixes)" "$(sensitive_paths)"
}

fx_check() { # $1=root -> check_claims over a synthetic tree with the live sensitive lists
  check_claims "$(collect_claims "$1")" "$(sensitive_dir_prefixes)" "$(sensitive_paths)"
}

# Synthetic-tree builders for the fixtures below.
fx_plant() { # $1=root $2=id $3=plant-target $4=type $5=one line of plant.sh body (verbatim)
  mkdir -p "$1/$2"
  {
    printf '# plant-target: %s\n# plant-target-type: %s\n' "$3" "$4"
    printf '%s\n' "$5"
  } > "$1/$2/plant.sh"
}

fx_inv() { # $1=root $2=id $3=the investigate.evidence lines, verbatim ("  evidence: ..." or block form)
  mkdir -p "$1/$2"
  printf 'challengeId: %s\ntype: investigate\ninvestigate:\n%s\n  questions:\n    - id: q1\n      format: hexid\n      params: {length: 16}\n' "$2" "$3" > "$1/$2/falco-rule.yaml"
}

# $1=label $2=root $3=expected marker text -> rc 0 iff check_claims() rejects the
# tree AND says why with the marker (a fixture rejected for some other reason
# proves nothing about the rule it is meant to exercise).
fx_expect_rejected() {
  local label="$1" root="$2" marker="$3" out rc=0
  out="$(mktemp)"
  if fx_check "${root}" >"${out}" 2>&1; then
    echo "ADR-0056 A5a VIOLATION: the deliberately-bad fixture '${label}' was ACCEPTED — the check is vacuous" >&2
    rc=1
  elif ! grep -qF "${marker}" "${out}"; then
    echo "ADR-0056 A5a VIOLATION: the fixture '${label}' was rejected, but not for the expected reason '${marker}':" >&2
    sed 's/^/    /' "${out}" >&2
    rc=1
  fi
  rm -f "${out}"
  return "${rc}"
}

# ADR-0007 V2's shape for the two rules above: positive trees pass, each
# deliberately-bad tree is rejected with its own message. Judged by exit
# status; the marker only pins WHY.
verify_claims_negative_tests() {
  local root rc=0 sens sfdir="" f
  sens="$(sensitive_dir_prefixes)"
  sens="${sens%%$'\n'*}"   # the first entry (no `| head`: SIGPIPE under pipefail)
  if [ -z "${sens}" ]; then
    echo "ADR-0056 A5a VIOLATION: sensitive_dir_prefixes() is empty, so the sensitive-directory fixture cannot be built" >&2
    return 1
  fi
  # the directory of the first sensitive file that is not directly under /
  # element 1 (e.g. /etc/security), so its parent is a real directory too
  while IFS= read -r f; do
    [ -z "${f}" ] && continue
    case "$(dirname "${f}")" in
      /*/*)
        sfdir="$(dirname "${f}")"
        break
        ;;
    esac
  done <<< "$(sensitive_paths)"
  if [ -z "${sfdir}" ]; then
    echo "ADR-0056 A5a VIOLATION: no sensitive file in sensitive_paths() lives two levels deep, so the sensitive-file-directory fixture cannot be built" >&2
    return 1
  fi
  root="$(mktemp -d)"

  # positive: two plants sharing a DIRECTORY (distinct files, one via cp), a
  # block-form and a flow-form investigate challenge in disjoint directories
  fx_plant "${root}/ok" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_plant "${root}/ok" 31-b /opt/fx/vault dir 'cp /opt/ctf/plant-seed/x "${PLANT_SEED_ROOT}/opt/fx/vault/b"'
  fx_inv "${root}/ok" 40-ev '  evidence:
    mountDir: /opt/fx/evidence-a'
  fx_inv "${root}/ok" 41-ev '  evidence: {mountDir: /opt/fx/evidence-b}'
  # a sibling of EVIDENCE_SRC_ROOT that shares its prefix but not its path element
  fx_inv "${root}/ok" 42-ev '  evidence: {mountDir: /opt/ctf/evidence-srcx}'
  if ! fx_check "${root}/ok" >/dev/null 2>&1; then
    echo "ADR-0056 A5a VIOLATION: the disjoint positive fixture was REJECTED — the check is too strict or the extraction is broken:" >&2
    fx_check "${root}/ok" 2>&1 | sed 's/^/    /' >&2 || true
    rc=1
  fi

  # (a) mountDir inside a sensitive directory; and above one
  fx_plant "${root}/a1" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/a1" 40-ev "  evidence: {mountDir: ${sens}/bundle}"
  fx_expect_rejected "mountDir inside a sensitive dir" "${root}/a1" "ADR-0056 D1 (a) VIOLATION" || rc=1
  fx_plant "${root}/a2" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/a2" 40-ev "  evidence: {mountDir: $(dirname "${sens}")}"
  fx_expect_rejected "mountDir above a sensitive dir" "${root}/a2" "ADR-0056 D1 (a) VIOLATION" || rc=1
  # (a2) the directory of a sensitive FILE (a name from sensitive_paths(), not a
  # dir prefix: sfdir does not overlap any sensitive_dir_prefixes entry); and above it
  fx_plant "${root}/a3" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/a3" 40-ev "  evidence: {mountDir: ${sfdir}}"
  fx_expect_rejected "mountDir is the directory of a sensitive file" "${root}/a3" "ADR-0056 D1 (a2) VIOLATION" || rc=1
  fx_plant "${root}/a4" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/a4" 40-ev "  evidence: {mountDir: $(dirname "${sfdir}")}"
  fx_expect_rejected "mountDir above the directory of a sensitive file" "${root}/a4" "ADR-0056 D1 (a2) VIOLATION" || rc=1

  # (b) mountDir overlaps another challenge's write file / mount dir / evidence dir
  fx_plant "${root}/b1" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/b1" 40-ev '  evidence: {mountDir: /opt/fx/vault}'
  fx_expect_rejected "mountDir over another plant's directory and file" "${root}/b1" "ADR-0056 D1 (b) VIOLATION" || rc=1
  fx_plant "${root}/b2" 30-a /opt/fx/vault/deep dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/deep/a"'
  fx_inv "${root}/b2" 40-ev '  evidence: {mountDir: /opt/fx/vault}'
  fx_expect_rejected "mountDir above another plant's mount dir" "${root}/b2" "ADR-0056 D1 (b) VIOLATION" || rc=1
  fx_plant "${root}/b3" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/b3" 40-ev '  evidence: {mountDir: /opt/fx/ev}'
  fx_inv "${root}/b3" 41-ev '  evidence: {mountDir: /opt/fx/ev/inner}'
  fx_expect_rejected "two investigate challenges nested" "${root}/b3" "ADR-0056 D1 (b) VIOLATION" || rc=1

  # (R) mountDir equal to / inside / above a reserved root (ADR-0056 D11, V44: the
  # catalog's reservedMountRoots refuses these three, and /opt/ctf/missions, in Go)
  fx_plant "${root}/r1" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/r1" 40-ev "  evidence: {mountDir: ${EVIDENCE_SRC_ROOT}/40-ev}"
  # The marker names the root that was hit, so each case pins WHICH root's rule fired
  # (a mountDir above two roots is checked against both).
  fx_expect_rejected "mountDir under the evidence source root" "${root}/r1" "(R) VIOLATION: 40-ev evidence.mountDir '${EVIDENCE_SRC_ROOT}/40-ev' is equal to, inside or above the reserved root '${EVIDENCE_SRC_ROOT}'" || rc=1
  fx_plant "${root}/r2" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/r2" 40-ev "  evidence: {mountDir: ${EVIDENCE_SRC_ROOT}}"
  fx_expect_rejected "mountDir is the evidence source root" "${root}/r2" "above the reserved root '${EVIDENCE_SRC_ROOT}'" || rc=1
  fx_plant "${root}/r3" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/r3" 40-ev "  evidence: {mountDir: $(dirname "${EVIDENCE_SRC_ROOT}")}"
  fx_expect_rejected "mountDir above the evidence source root" "${root}/r3" "above the reserved root '${EVIDENCE_SRC_ROOT}'" || rc=1
  fx_expect_rejected "the same mountDir above the snapshot root" "${root}/r3" "above the reserved root '${SNAPSHOT_ROOT}'" || rc=1
  fx_plant "${root}/r4" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/r4" 40-ev "  evidence: {mountDir: ${SEED_ROOT}}"
  fx_expect_rejected "mountDir is the seed root" "${root}/r4" "above the reserved root '${SEED_ROOT}'" || rc=1
  fx_plant "${root}/r5" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/r5" 40-ev "  evidence: {mountDir: ${SEED_ROOT}/x}"
  fx_expect_rejected "mountDir under the seed root" "${root}/r5" "above the reserved root '${SEED_ROOT}'" || rc=1
  fx_plant "${root}/r6" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/r6" 40-ev "  evidence: {mountDir: ${SNAPSHOT_ROOT}/x}"
  fx_expect_rejected "mountDir under the snapshot root" "${root}/r6" "above the reserved root '${SNAPSHOT_ROOT}'" || rc=1

  # (c) two plant.sh write the same file (redirect + redirect, redirect + cp)
  fx_plant "${root}/c1" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_plant "${root}/c1" 31-b /opt/fx/vault dir 'printf y >> "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_expect_rejected "two plant.sh write one file" "${root}/c1" "both write the file" || rc=1
  fx_plant "${root}/c2" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_plant "${root}/c2" 31-b /opt/fx/vault dir 'cp /opt/ctf/plant-seed/x "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_expect_rejected "a plant.sh redirects to a file another plant.sh cp's to" "${root}/c2" "both write the file" || rc=1
  fx_plant "${root}/c3" 30-a /opt/fx/f file 'printf x > "${PLANT_SEED_ROOT}/opt/fx/f"'
  fx_plant "${root}/c3" 31-b /opt/fx/other dir 'printf y > "${PLANT_SEED_ROOT}/opt/fx/f"'
  fx_expect_rejected "a file-type target is another plant.sh's write destination" "${root}/c3" "both write the file" || rc=1

  # fail-closed guards
  fx_plant "${root}/g1" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/g1" 40-ev '  evidence: {mountDir: /opt//fx/ev}'
  fx_expect_rejected "mountDir with a doubled slash" "${root}/g1" "not an absolute, clean path" || rc=1
  fx_plant "${root}/g2" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/g2" 40-ev '  evidence: [/opt/fx/ev]'
  fx_expect_rejected "investigate with no readable mountDir" "${root}/g2" "no investigate.evidence.mountDir could be read" || rc=1
  fx_plant "${root}/g3" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_plant "${root}/g3" 31-b /opt/fx/other dir 'tee "${PLANT_SEED_ROOT}/opt/fx/other/b" < /dev/null'
  fx_expect_rejected "a plant.sh whose write form is not recognized" "${root}/g3" "has no recognized write destination" || rc=1
  fx_plant "${root}/g4" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/$NAME"'
  fx_expect_rejected "a write destination with a shell expansion" "${root}/g4" "shell expansion or glob" || rc=1
  # an investigate block under a type this script does not recognize
  mkdir -p "${root}/g5/40-ev"
  fx_plant "${root}/g5" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  printf 'challengeId: 40-ev\ntype: inspect\ninvestigate:\n  evidence: {mountDir: /opt/fx/ev}\n' > "${root}/g5/40-ev/falco-rule.yaml"
  fx_expect_rejected "an investigate block under another type name" "${root}/g5" "its top-level type is not" || rc=1

  # per-LINE fail-closed: a recognized write in the same plant.sh must not hide
  # an unrecognized one
  local u="is not one of the enumerated plant.sh forms"
  fx_plant "${root}/u1" 30-a /opt/fx/other dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/other/a"
printf y | tee "${PLANT_SEED_ROOT}/opt/fx/other/b"'
  fx_expect_rejected "a recognized write beside a tee" "${root}/u1" "${u}" || rc=1
  fx_plant "${root}/u2" 30-a /opt/fx/other dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/other/a" > "${PLANT_SEED_ROOT}/opt/fx/other/b"'
  fx_expect_rejected "two redirects on one line" "${root}/u2" "${u}" || rc=1
  fx_plant "${root}/u3" 30-a /opt/fx/other dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/other/a"
printf y > "$PLANT_SEED_ROOT/opt/fx/other/b"'
  fx_expect_rejected "a recognized write beside a brace-less PLANT_SEED_ROOT" "${root}/u3" "${u}" || rc=1
  fx_plant "${root}/u4" 30-a /opt/fx/other dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/other/a"
printf y > "${PLANT_SEED_ROOT}"/opt/fx/other/b'
  fx_expect_rejected "a recognized write beside a quote in another place" "${root}/u4" "${u}" || rc=1
  fx_plant "${root}/u5" 30-a /opt/fx/other dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/other/a"
cp /opt/ctf/plant-seed/x "${PLANT_SEED_ROOT}/opt/fx/other/"'
  fx_expect_rejected "a recognized write beside a cp into a directory" "${root}/u5" "${u}" || rc=1

  rm -rf "${root}"
  if [ "${rc}" -eq 0 ]; then
    echo "  ok: ADR-0056 A5a — mountDir / plant-write disjointness: the positive tree passes and each of the 26 deliberately-bad trees is rejected for its own reason"
  fi
  return "${rc}"
}

# ---------------------------------------------------------------------------
# ADR-0056 A5a-2: the plant is derived from the TYPE (evade plant.sh, or
# investigate), the investigate mount and copy shapes are generated, and 2-7(a)
# accepts ${EVIDENCE_SRC_ROOT}/<challenge id>/<plain file name> (the Secret is
# one per challenge) and nothing else new.
# ADR-0007 V2's shape again: a positive tree passes and shows the generated
# shape; each deliberately-bad input is rejected, for its own reason (the
# marker), by the SAME functions the live run uses. No investigate challenge
# exists in the tree yet, so this is where the shapes are exercised.
# ---------------------------------------------------------------------------

# $1=label $2=script text $3=expected marker (text only the intended check
# prints) $4=evidence map (optional) -> rc 0 iff check_2_7() rejects the text AND
# says why with the marker
fx_expect_2_7() {
  local label="$1" text="$2" marker="$3" map="${4:-}" out rc=0
  out="$(mktemp)"
  if check_2_7 "${text}" "fx" "${map}" >"${out}" 2>&1; then
    echo "ADR-0056 A5a-2 VIOLATION: the deliberately-bad script '${label}' was ACCEPTED by 2-7 — the check is vacuous" >&2
    rc=1
  elif ! grep -qF "${marker}" "${out}"; then
    echo "ADR-0056 A5a-2 VIOLATION: the script '${label}' was rejected, but not for the expected reason '${marker}':" >&2
    sed 's/^/    /' "${out}" >&2
    rc=1
  fi
  rm -f "${out}"
  return "${rc}"
}

# $1=label $2=root (a tree) $3=marker -> rc 0 iff init_plant_ids() stops on it with the marker
fx_expect_derive_rejected() {
  local label="$1" root="$2" marker="$3" out rc=0
  out="$(mktemp)"
  if ( cd "${root}" && init_plant_ids ) >"${out}" 2>&1; then
    echo "ADR-0056 A5a-2 VIOLATION: the deliberately-bad tree '${label}' was ACCEPTED by init_plant_ids" >&2
    rc=1
  elif ! grep -qF "${marker}" "${out}"; then
    echo "ADR-0056 A5a-2 VIOLATION: the tree '${label}' was rejected, but not for the expected reason '${marker}':" >&2
    sed 's/^/    /' "${out}" >&2
    rc=1
  fi
  rm -f "${out}"
  return "${rc}"
}

verify_plant_derivation_tests() {
  local root rc=0 got seed block want want_ids wantev one scen
  local dst='"${PLANT_SEED_ROOT}/opt/fx/evidence-a/x"'
  local src="${EVIDENCE_SRC_ROOT}"
  local cs="${EVIDENCE_SRC_ROOT}/40-ev"
  local map
  map="$(printf '/opt/fx/evidence-a\t40-ev')"
  root="$(mktemp -d)"

  # positive: an evade plant.sh, an investigate challenge with NO plant.sh, and a
  # challenge that is neither (type: inspect) which must not be planted for
  fx_plant "${root}/p" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/p" 40-ev '  evidence: {mountDir: /opt/fx/evidence-a}'
  mkdir -p "${root}/p/20-t"
  printf 'challengeId: 20-t\ntype: inspect\n' > "${root}/p/20-t/falco-rule.yaml"
  want_ids='30-a
40-ev'
  if ! got="$( cd "${root}/p" && init_plant_ids && printf '%s\n' "${PLANT_IDS[@]}" )" || [ "${got}" != "${want_ids}" ]; then
    echo "ADR-0056 A5a-2 VIOLATION: the plant ids derived from the positive tree are '${got}', want '${want_ids}' (evade plant.sh + investigate; not a challenge of another type)" >&2
    rc=1
  fi
  # the mounts: the investigate one is readOnly and marked evidence, the evade one is not
  block="$( cd "${root}/p" && init_plant_ids && render_plant_block "${PLANT_IDS[@]}" )" || rc=1
  wantev='    - path: /opt/fx/evidence-a
      readOnly: true
      evidence: true
      challenge: 40-ev'
  want='    - path: /opt/fx/vault
      readOnly: true
'"${wantev}"
  case "${block}" in
    *"${want}") : ;;
    *)
      echo "ADR-0056 A5a-2 VIOLATION: the generated plant.mounts of the positive tree does not end with the expected mounts:" >&2
      printf '%s\n' "${block}" | sed 's/^/    /' >&2
      rc=1
      ;;
  esac
  # the per-id values (render_one: its investigate branch) and the scenario
  # scope (scenario_plant_ids over PLANT_IDS): the investigate mount is there when
  # the challenge is in scope, and only then
  one="$( cd "${root}/p" && init_plant_ids && render_one 40-ev )" || rc=1
  case "${one}" in
    "# GENERATED from 40-ev/falco-rule.yaml (type: ${INVESTIGATE_TYPE})"*"${wantev}") : ;;
    *)
      echo "ADR-0056 A5a-2 VIOLATION: render_one of an investigate challenge does not name its falco-rule.yaml as the source and carry its evidence mount:" >&2
      printf '%s\n' "${one}" | sed 's/^/    /' >&2
      rc=1
      ;;
  esac
  mkdir -p "${root}/sin" "${root}/sout"
  printf 'id: sin\ntitle: in\nchallenges:\n  - 30-a\n  - 40-ev\n' > "${root}/sin/scenario.yaml"
  printf 'id: sout\ntitle: out\nchallenges:\n  - 30-a\n' > "${root}/sout/scenario.yaml"
  scen="$( cd "${root}/p" && init_plant_ids && render_scenario "${root}/sin" )" || rc=1
  case "${scen}" in
    *"${want}"*) : ;;
    *)
      echo "ADR-0056 A5a-2 VIOLATION: the scenario scope that lists an investigate challenge has no evidence mount for it:" >&2
      printf '%s\n' "${scen}" | sed 's/^/    /' >&2
      rc=1
      ;;
  esac
  scen="$( cd "${root}/p" && init_plant_ids && render_scenario "${root}/sout" )" || rc=1
  case "${scen}" in
    *evidence*|*40-ev*)
      echo "ADR-0056 A5a-2 VIOLATION: the scenario scope that does NOT list the investigate challenge still carries it:" >&2
      printf '%s\n' "${scen}" | sed 's/^/    /' >&2
      rc=1
      ;;
  esac
  # a real run knows no file name: mkdir only, no copy line
  case "${block}" in
    *'mkdir -p "${PLANT_SEED_ROOT}/opt/fx/evidence-a"'*) : ;;
    *) echo "ADR-0056 A5a-2 VIOLATION: the generated seed script has no mkdir for the evidence directory" >&2; rc=1 ;;
  esac
  case "${block}" in
    *"cp \"${src}/"*) echo "ADR-0056 A5a-2 VIOLATION: a copy line was generated although no bundle file name is known to gen-values" >&2; rc=1 ;;
  esac
  # with names (fixture only): D11's shape, and 2-7 accepts it
  seed="$( cd "${root}/p" && init_plant_ids && EVIDENCE_FILES=(a.log b-2.txt) && render_seed_body "${PLANT_IDS[@]}" )" || rc=1
  case "${seed}" in
    *"cp \"${cs}/a.log\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"
chmod 0444 \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"
cp \"${cs}/b-2.txt\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/b-2.txt\"
chmod 0444 \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/b-2.txt\""*) : ;;
    *)
      echo "ADR-0056 A5a-2 VIOLATION: the generated copy lines are not D11's shape (cp by name, no -a, then chmod 0444):" >&2
      printf '%s\n' "${seed}" | sed 's/^/    /' >&2
      rc=1
      ;;
  esac
  if ! check_2_7 "${seed}" "fx-positive" "${map}" >/dev/null 2>&1; then
    echo "ADR-0056 A5a-2 VIOLATION: 2-7 rejected the generated evidence copy lines (the allowlist is too strict):" >&2
    check_2_7 "${seed}" "fx-positive" "${map}" 2>&1 | sed 's/^/    /' >&2 || true
    rc=1
  fi
  # the existing snapshot restore stays accepted
  if ! check_2_7 'cp -a "/opt/ctf/plant-seed/etc/." "${PLANT_SEED_ROOT}/etc/"' "fx-snapshot" >/dev/null 2>&1; then
    echo "ADR-0056 A5a-2 VIOLATION: 2-7 rejected the existing snapshot restore line" >&2
    rc=1
  fi

  # negative: 2-7(a), by hand-written lines
  local m='cp copy-source is not'
  local mf='is not exactly'
  local mu='a word cp the 2-7(a) parser did not read'
  local de='"${PLANT_SEED_ROOT}/opt/fx/evidence-a/"'
  fx_expect_2_7 "a copy-source outside both roots" "cp \"/etc/hostname\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "cp -a from outside both roots" "cp -a \"/etc/hostname\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "cp -a from the evidence root" "cp -a \"${cs}/a.log\" ${dst}" "${mf}" || rc=1
  fx_expect_2_7 "cp -a of the evidence directory (.)" "cp -a \"${cs}/.\" ${de}" "${mf}" || rc=1
  fx_expect_2_7 "the evidence directory (.) without -a" "cp \"${cs}/.\" ${de}" "${mf}" || rc=1
  fx_expect_2_7 "a glob in the evidence directory" "cp \"${cs}/*\" ${de}" "${mf}" || rc=1
  fx_expect_2_7 "a '..' element" "cp \"${cs}/../../plant-seed/x\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "a file name with a space" "cp \"${cs}/a b\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "a sibling root (prefix without the slash)" "cp \"${src}x/40-ev/a\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "a flag on a plain evidence copy" "cp -r \"${cs}/a.log\" ${dst}" "${mf}" || rc=1
  fx_expect_2_7 "a source with no challenge id level" "cp \"${src}/a.log\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "a challenge id level that is not a challenge id" "cp \"${src}/BAD/a.log\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "a nested name below the challenge id" "cp \"${cs}/sub/a.log\" ${dst}" "${m}" || rc=1
  fx_expect_2_7 "a second source that is outside both roots" "cp \"${cs}/a.log\" \"/etc/hostname\" ${de}" "${mf}" || rc=1
  fx_expect_2_7 "a snapshot source then an evidence glob" "cp \"/opt/ctf/plant-seed/x\" \"${cs}/*\" ${de}" "${mf}" || rc=1
  fx_expect_2_7 "-t (the destination first)" "cp -t ${de} \"/etc/hostname\"" "${m}" || rc=1
  # only the --target-directory rule rejects this: the first operand is a snapshot
  # path, and the "last operand" would otherwise be taken for the destination
  fx_expect_2_7 "--target-directory (the last operand is a source)" "cp --target-directory=/plant-seed/opt/fx/evidence-a \"/opt/ctf/plant-seed/x\" \"/etc/hostname\"" "${m}" || rc=1
  fx_expect_2_7 "the cp inside sh -c" "sh -c 'cp -a \"/etc/hostname\" ${dst}'" "${m}" || rc=1
  # negative: bad names reaching 2-7 through the real renderer (the renderer is not the gate)
  seed="$( cd "${root}/p" && init_plant_ids && EVIDENCE_FILES=('../x') && render_seed_body "${PLANT_IDS[@]}" )" || rc=1
  fx_expect_2_7 "a bundle file named '../x' through the renderer" "${seed}" "${mf}" "${map}" || rc=1
  seed="$( cd "${root}/p" && init_plant_ids && EVIDENCE_FILES=('*') && render_seed_body "${PLANT_IDS[@]}" )" || rc=1
  fx_expect_2_7 "a bundle file named '*' through the renderer" "${seed}" "${mf}" "${map}" || rc=1
  # B2's grammar is lower-case and at most 63 characters (the chart's `fail` says the same)
  seed="$( cd "${root}/p" && init_plant_ids && EVIDENCE_FILES=('A.log') && render_seed_body "${PLANT_IDS[@]}" )" || rc=1
  fx_expect_2_7 "a bundle file with an upper-case name through the renderer" "${seed}" "${m}" "${map}" || rc=1
  seed="$( cd "${root}/p" && init_plant_ids && EVIDENCE_FILES=("$(printf '%064d' 0 | tr 0 a)") && render_seed_body "${PLANT_IDS[@]}" )" || rc=1
  fx_expect_2_7 "a bundle file name of 64 characters through the renderer" "${seed}" "${m}" "${map}" || rc=1
  # positive: the top of the grammar, 63 characters, is accepted
  seed="$( cd "${root}/p" && init_plant_ids && EVIDENCE_FILES=("$(printf '%063d' 0 | tr 0 a)") && render_seed_body "${PLANT_IDS[@]}" )" || rc=1
  if ! check_2_7 "${seed}" "fx-name63" "${map}" >/dev/null 2>&1; then
    echo "ADR-0056 A5b VIOLATION: 2-7 rejected a bundle file name of 63 characters (the top of B2's grammar: the allowlist is too strict)" >&2
    rc=1
  fi
  # negative: a copy of the right SHAPE that does not match the mount's challenge
  # (the shape is allowed; whether this cid belongs to this directory is judged
  # against plant.mounts, here with the map)
  local mm='evidence copy'
  fx_expect_2_7 "another challenge's directory copied into this mount" "cp \"${src}/41-xx/a.log\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"" "${mm}" "${map}" || rc=1
  fx_expect_2_7 "a copy into a directory no mount names" "cp \"${cs}/a.log\" \"\${PLANT_SEED_ROOT}/opt/fx/other/a.log\"" "${mm}" "${map}" || rc=1
  fx_expect_2_7 "a copy with no mount at all (empty map)" "cp \"${cs}/a.log\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"" "${mm}" || rc=1
  fx_expect_2_7 "a copy that renames the file" "cp \"${cs}/a.log\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/b.log\"" "${mm}" "${map}" || rc=1
  # negative: a cp the parser does not read as a command is never "allowed"
  # (each of these was caught by the old line-wide grep)
  fx_expect_2_7 "a cp in an assignment's substitution" "x=\$(cp -a \"/etc/hostname\" ${dst})" "${mu}" || rc=1
  fx_expect_2_7 "a cp in the argument of an allowlisted command" "echo \$(cp -a \"/etc/hostname\" ${dst})" "${mu}" || rc=1
  fx_expect_2_7 "a cp in backticks" "echo \`cp -a \"/etc/hostname\" ${dst}\`" "${mu}" || rc=1
  fx_expect_2_7 "a cp after a lone &" "true & cp -a \"/etc/hostname\" ${dst}" "${mu}" || rc=1
  fx_expect_2_7 "a cp in the body of an unquoted heredoc" "cat > \"\${PLANT_SEED_ROOT}/opt/fx/a\" <<EOF
\$(cp -a \"/etc/hostname\" ${dst})
EOF" "${mu}" || rc=1
  # negative: an evidence copy of any other shape than D11's (judged by the one
  # parser, so none of these can skip the match against plant.mounts)
  fx_expect_2_7 "an unquoted source" "cp ${cs}/a.log \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"" "${mf}" "${map}" || rc=1
  fx_expect_2_7 "an unquoted destination" "cp \"${cs}/a.log\" \${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log" "${mf}" "${map}" || rc=1
  fx_expect_2_7 "two evidence sources" "cp \"${cs}/a.log\" \"${cs}/b.log\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"" "${mf}" "${map}" || rc=1
  fx_expect_2_7 "a destination directory with a trailing slash" "cp \"${cs}/a.log\" \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/\"" "${mf}" "${map}" || rc=1
  fx_expect_2_7 "a destination outside the seed root" "cp \"${cs}/a.log\" \"/opt/fx/evidence-a/a.log\"" "${mf}" "${map}" || rc=1
  # positive: extra blanks are fine (one parser reads tokens), and a cp word in a
  # QUOTED heredoc body (never executed) is not a violation
  if ! check_2_7 "  cp   \"${cs}/a.log\"     \"\${PLANT_SEED_ROOT}/opt/fx/evidence-a/a.log\"   " "fx-blanks" "${map}" >/dev/null 2>&1; then
    echo "ADR-0056 A5a-2 VIOLATION: 2-7 rejected a D11 copy with extra blanks (the parser is too strict)" >&2
    rc=1
  fi
  if ! check_2_7 "cat > \"\${PLANT_SEED_ROOT}/opt/fx/a\" <<'EOF'
then cp the file
EOF" "fx-quoted-heredoc" >/dev/null 2>&1; then
    echo "ADR-0056 A5a-2 VIOLATION: 2-7 rejected a cp word in a quoted heredoc body (never executed)" >&2
    rc=1
  fi

  # negative: the derivation itself
  fx_plant "${root}/e1" 30-a /opt/fx/vault dir 'printf x > "${PLANT_SEED_ROOT}/opt/fx/vault/a"'
  fx_inv "${root}/e1" 40-ev '  evidence: [/opt/fx/evidence-a]'
  fx_expect_derive_rejected "an investigate challenge with no mountDir" "${root}/e1" "no investigate.evidence.mountDir could be read" || rc=1
  fx_inv "${root}/e2" 40-ev '  evidence: {mountDir: /opt/fx/evidence-a}'
  printf '# plant-target: /opt/fx/other\n# plant-target-type: dir\ntrue\n' > "${root}/e2/40-ev/plant.sh"
  fx_expect_derive_rejected "an investigate challenge that also has a plant.sh" "${root}/e2" "also carries a plant.sh" || rc=1
  # negative: the mountDir grammar, here, before the value is written into a script
  fx_inv "${root}/m1" 40-ev '  evidence: {mountDir: /opt/fx/$(id)}'
  fx_expect_derive_rejected "a mountDir with a command substitution" "${root}/m1" "does not match" || rc=1
  fx_inv "${root}/m2" 40-ev '  evidence: {mountDir: /opt/fx/`id`}'
  fx_expect_derive_rejected "a mountDir with a backtick" "${root}/m2" "does not match" || rc=1
  fx_inv "${root}/m3" 40-ev '  evidence: {mountDir: /opt/fx/a"b}'
  fx_expect_derive_rejected "a mountDir with a double quote" "${root}/m3" "does not match" || rc=1
  fx_inv "${root}/m4" 40-ev '  evidence: {mountDir: /opt/fx/a;id}'
  fx_expect_derive_rejected "a mountDir with a semicolon" "${root}/m4" "does not match" || rc=1
  fx_inv "${root}/m5" 40-ev '  evidence: {mountDir: /opt/fx/a b}'
  fx_expect_derive_rejected "a mountDir with a space" "${root}/m5" "does not match" || rc=1
  fx_inv "${root}/m6" 40-ev '  evidence:
    mountDir: /opt/fx/ev '
  fx_expect_derive_rejected "a mountDir with a trailing space" "${root}/m6" "does not match" || rc=1
  fx_inv "${root}/m7" 40-ev '  evidence: {mountDir: /opt/fx/../etc}'
  fx_expect_derive_rejected "a mountDir with a '..' element" "${root}/m7" "does not match" || rc=1

  rm -rf "${root}"
  if [ "${rc}" -eq 0 ]; then
    echo "  ok: ADR-0056 A5a-2 — plant derived from type (evade + investigate), investigate mount / copy shapes generated (per-challenge Secret ${EVIDENCE_SRC_ROOT}/<cid>), 2-7(a) accepts only ${EVIDENCE_SRC_ROOT}/<challenge id>/<plain file name>: the positive tree passes and each of the 45 deliberately-bad inputs is rejected for its own reason"
  fi
  return "${rc}"
}

# ---------------------------------------------------------------------------
# Entry points for scripts/check-flag-isolation.sh (ADR-0056 A5b, V43).
#
# This script is not sourceable (it runs its checks at the top level), so the
# chart check cannot import the definitions below; it asks this script for them
# instead, and does not write them a second time: the SHAPE of an evidence copy
# line (render_evidence_copy), the rule that judges it (check_2_7, 2-7(a)), what an
# investigate challenge's mount directory is (investigate_mount_dir), and the tree
# the two-challenge fixture is rendered from. Every mode takes ABSOLUTE paths (this
# script cd's to its own directory first), and an unusable argument is exit 2,
# never "ok".
#   --check-seed-script <label> <script file> <map file>
#       rc 0 iff check_2_7 accepts the script text; the map is the "<mountDir> TAB
#       <challenge id>" lines of the scope (the same text evidence_map_for prints).
#       An empty script file is a usage error: nothing was judged.
#   --render-evidence-copy <cid> <mountDir> <file name>...
#       the lines render_evidence_copy prints
#   --list-evidence-mount-dirs [<tree>]
#       the evidence.mountDir of every investigate challenge under <tree> (default:
#       this directory), one per line, by the same derivation init_plant_ids uses
#   --emit-evidence-fixture <existing dir>
#       writes <dir>/tree (two investigate challenges, 40-ev and 41-ev, no plant.sh),
#       <dir>/values.yaml (the `plant:` block this script generates for them) and
#       <dir>/map (their evidence map)
# ---------------------------------------------------------------------------

entry_usage() {
  echo "gen-values.sh $1: $2" >&2
  exit 2
}

case "${1:-}" in
  --check-seed-script)
    [ "$#" -eq 4 ] || entry_usage "$1" "want <label> <script file> <map file>"
    case "$3" in /*) : ;; *) entry_usage "$1" "the script file must be an absolute path" ;; esac
    case "$4" in /*) : ;; *) entry_usage "$1" "the map file must be an absolute path" ;; esac
    [ -s "$3" ] || entry_usage "$1" "the script file is missing or empty (nothing to judge)"
    [ -f "$4" ] || entry_usage "$1" "the map file is missing"
    if check_2_7 "$(cat "$3")" "$2" "$(cat "$4")"; then exit 0; else exit 1; fi
    ;;
  --render-evidence-copy)
    [ "$#" -ge 4 ] || entry_usage "$1" "want <cid> <mountDir> <file name>..."
    render_evidence_copy "${@:2}"
    exit 0
    ;;
  --list-evidence-mount-dirs)
    [ "$#" -le 2 ] || entry_usage "$1" "want [<tree>]"
    cd "${2:-.}" || entry_usage "$1" "cannot enter the tree"
    init_plant_ids
    if [ "${#INVESTIGATE_IDS[@]}" -gt 0 ]; then
      for id in "${INVESTIGATE_IDS[@]}"; do
        investigate_mount_dir "${id}/falco-rule.yaml"
      done
    fi
    exit 0
    ;;
  --emit-evidence-fixture)
    [ "$#" -eq 2 ] || entry_usage "$1" "want <existing dir>"
    case "$2" in /*) : ;; *) entry_usage "$1" "the directory must be an absolute path" ;; esac
    [ -d "$2" ] || entry_usage "$1" "the directory does not exist"
    fx_inv "$2/tree" 40-ev '  evidence: {mountDir: /opt/fx/evidence-a}'
    fx_inv "$2/tree" 41-ev '  evidence: {mountDir: /opt/fx/evidence-b}'
    cd "$2/tree"
    init_plant_ids
    render_plant_block "${PLANT_IDS[@]}" > "$2/values.yaml"
    evidence_map_for "${PLANT_IDS[@]}" > "$2/map"
    exit 0
    ;;
esac

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

init_plant_ids

if [ "${CHECK}" -eq 1 ]; then
  rc=0
  check_2_5 || rc=1
  run_2_7_all_scopes || rc=1
  run_verification_1_all_scopes || rc=1
  verify_negative_test || rc=1
  run_claims_check || rc=1
  verify_claims_negative_tests || rc=1
  verify_plant_derivation_tests || rc=1
  for id in "${PLANT_IDS[@]}"; do
    if ! diff -u "${id}/values.yaml" <(render_one "${id}") >/dev/null 2>&1; then
      echo "DRIFT: ${id}/values.yaml is out of sync with its plant source (${id}/plant.sh, or ${id}/falco-rule.yaml for type: ${INVESTIGATE_TYPE})" >&2
      rc=1
    fi
  done
  if ! diff -u values-all.yaml <(render_all) >/dev/null 2>&1; then
    echo "DRIFT: values-all.yaml is out of sync with the plant sources (plant.sh files, and falco-rule.yaml of type: ${INVESTIGATE_TYPE})" >&2
    rc=1
  fi
  while IFS= read -r sdir; do
    [ -z "${sdir}" ] && continue
    sid="$(basename "${sdir}")"
    if ! diff -u "values-scenario-${sid}.yaml" <(render_scenario "${sdir}") >/dev/null 2>&1; then
      echo "DRIFT: values-scenario-${sid}.yaml is out of sync with scenarios/${sid}/scenario.yaml or the plant sources (plant.sh files, falco-rule.yaml of type: ${INVESTIGATE_TYPE})" >&2
      rc=1
    fi
  done < <(scenario_dirs)
  [ "${rc}" -eq 0 ] && echo "gen-values: in sync (ADR-0001 2-1..2-7 + ADR-0007 V1/V2 + P27-1 scenario scope clean)"
  exit "${rc}"
fi

check_2_5
run_2_7_all_scopes
run_verification_1_all_scopes
verify_negative_test
run_claims_check
verify_claims_negative_tests
verify_plant_derivation_tests

for id in "${PLANT_IDS[@]}"; do
  render_one "${id}" > "${id}/values.yaml"
  echo "wrote ${id}/values.yaml"
done
render_all > values-all.yaml
echo "wrote values-all.yaml"

while IFS= read -r sdir; do
  [ -z "${sdir}" ] && continue
  sid="$(basename "${sdir}")"
  render_scenario "${sdir}" > "values-scenario-${sid}.yaml"
  echo "wrote values-scenario-${sid}.yaml"
done < <(scenario_dirs)
