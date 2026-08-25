#!/usr/bin/env bash
# Generate per-challenge values.yaml and the combined values-all.yaml from each
# evade challenge's plant.sh (the single source of truth for flag planting).
#
#   ./gen-values.sh           regenerate the files in place
#   ./gen-values.sh --check   fail if the committed files are out of sync (CI),
#                             or if any plant.sh / generated seed script
#                             violates ADR-0001 Verification 2 (2-1..2-7) or
#                             ADR-0007 Verification 1 (mount directory
#                             granularity)
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
#     directories listed in WRITABLE_MOUNT_DIRS below (see that comment) —
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
# Mount-directory -> seed-source / readOnly resolution, with a consistency
# check across missions that share a mount directory (03 and 10 both map
# /etc/shadow to the /etc mount directory — 2-2, now keyed by mount dir
# rather than raw plant-target).
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
# Rendering (per scope = a list of mission ids, always MISSIONS sort order —
# 2-4)
# ---------------------------------------------------------------------------

unique_mount_dirs_for() { # $@ = mission ids -> unique mount-directory list, first-appearance order (2-2, ADR-0007)
  local seen=() id type target mountdir found x
  for id in "$@"; do
    type="$(plant_target_type "${id}/plant.sh")"
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      mountdir="$(mount_dir_for "${target}" "${type}")"
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
    done < <(plant_targets "${id}/plant.sh")
  done
}

# render_seed_body <mission-id>... -> the *unindented* initContainer script
# body (the ADR-0001/ADR-0007 seed script — this is exactly the text
# Verification 2-7 statically checks).
render_seed_body() {
  local seeded=() id type target mountdir source found x rel
  printf 'set -eu\n'
  printf 'PLANT_SEED_ROOT=%s\n' "${SEED_ROOT}"
  for id in "$@"; do
    printf '\n# ---- %s ----\n' "${id}"
    type="$(plant_target_type "${id}/plant.sh")"
    source="$(plant_seed_source "${id}/plant.sh")"
    while IFS= read -r target; do
      [ -z "${target}" ] && continue
      mountdir="$(mount_dir_for "${target}" "${type}")"
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
  unique_mount_dirs_for "$@" | while IFS= read -r d; do
    if is_mount_writable "${d}"; then
      printf '    - path: %s\n      readOnly: false\n' "${d}"
    else
      printf '    - path: %s\n      readOnly: true\n' "${d}"
    fi
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
# here. Mount directories (ADR-0007) are the enclosing directory of each
# plant-target, not the plant-target itself when it is a file.
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
# script): the deploy path must never read a sensitive path, and must never
# talk to anything, at runtime. Best-effort static heuristic, documented as
# such — see the (f) comment below for the one sub-check that is closer to
# a real allowlist and the limits of the rest.
#   (a) every `cp` copy-source is anchored under ${SNAPSHOT_ROOT}
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
#       (mkdir/cp/echo/cat/chmod/set/printf/true/:/sh) and fails on
#       anything else — including binaries with no name-based check yet,
#       and bare-path "exec a file we just wrote" forms like
#       `/dev/shm/x` that (c)/(e) don't parse for. It is still a
#       heuristic: it tokenizes each `;`/`&&`/`||`/`|`-separated segment by
#       whitespace and treats the first token as "the command", skipping
#       heredoc bodies and `NAME=value` assignments — it does not parse
#       shell quoting/substitution, so a sufficiently adversarial one-liner
#       (e.g. hiding a command inside `$(...)` or a quoted string that
#       *becomes* a command some other way) could still evade it. Extend
#       the allowlist deliberately when a new plant.sh legitimately needs
#       another command — don't work around a (f) failure by rewording the
#       line.
# ---------------------------------------------------------------------------

check_2_7() { # $1 = generated seed script text (unindented), $2 = label
  local script="$1" label="$2" rc=0 hits p residue code offending ln

  # All sub-checks below look at CODE only — full-comment lines (this
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
  hits="$(printf '%s\n' "${code}" | awk '
    BEGIN {
      n = split("sh set mkdir cp echo cat chmod printf true :", allowed, " ")
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
        if (seg ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue
        split(seg, w, /[ \t]+/)
        if (w[1] != "" && !(w[1] in allow)) printf "%d:%s\n", NR, line
      }
    }
  ' || true)"
  if [ -n "${hits}" ]; then
    echo "2-7(f) VIOLATION [${label}]: command not in the seed-script allowlist (mkdir/cp/echo/cat/chmod/set/printf/true/:/sh):" >&2
    printf '%s\n' "${hits}" | sort -t: -k1,1 -u | sed 's/^/    /' >&2
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
# ADR-0007 Verification 1: plant.mounts directory-granularity static assert.
#
#   - every plant.mounts entry must be a directory (structural check: it
#     must never be literally one of the declared FILE-type plant-targets —
#     a file-type target's mount is always its dirname, by construction, so
#     if a mount ever equals the raw file target itself, generation
#     regressed to file granularity)
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

check_mount_granularity() { # $1=values file $2=label -> rc 0 iff every mount is a directory
  local file="$1" label="$2" rc=0 mounts n m ft
  mounts="$(extract_mount_paths "${file}")"
  n="$(printf '%s\n' "${mounts}" | grep -c . || true)"
  if [ "${n}" -eq 0 ]; then
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
    done < <(file_type_mount_targets)
  done <<< "${mounts}"
  return "${rc}"
}

run_verification_1_all_scopes() {
  local rc=0 id
  check_mount_granularity <(render_all) "values-all (generated)" || rc=1
  for id in "${MISSIONS[@]}"; do
    check_mount_granularity <(render_one "${id}") "${id} (generated)" || rc=1
  done
  return "${rc}"
}

# ---------------------------------------------------------------------------
# ADR-0007 Verification 2: negative test (self-check that Verification 1 is
# not vacuous). Feeds check_mount_granularity a fixture whose plant.mounts
# lists a FILE-granularity entry (the real, catalog-declared /etc/shadow
# plant-target, verbatim — not a synthetic path) and asserts it is REJECTED.
# If this ever passes (i.e. the fixture is accepted), Verification 1's own
# assert has regressed to a no-op and this function itself fails closed.
# ---------------------------------------------------------------------------

verify_negative_test() {
  local fixture
  fixture="$(mktemp)"
  trap 'rm -f "${fixture}"' RETURN
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
  if check_mount_granularity "${fixture}" "ADR-0007-V2-fixture" >/tmp/adr0007-v2-negative.out 2>&1; then
    echo "ADR-0007 V2 VIOLATION: the deliberately-bad fixture (plant.mounts: [/etc/shadow], file granularity) was ACCEPTED — Verification 1's assert is vacuous" >&2
    cat /tmp/adr0007-v2-negative.out >&2
    rm -f /tmp/adr0007-v2-negative.out
    return 1
  fi
  echo "  ok: ADR-0007 Verification 2 — the file-granularity fixture is correctly rejected"
  rm -f /tmp/adr0007-v2-negative.out
  return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [ "${CHECK}" -eq 1 ]; then
  rc=0
  check_2_5 || rc=1
  run_2_7_all_scopes || rc=1
  run_verification_1_all_scopes || rc=1
  verify_negative_test || rc=1
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
  [ "${rc}" -eq 0 ] && echo "gen-values: in sync (ADR-0001 2-1..2-7 + ADR-0007 V1/V2 clean)"
  exit "${rc}"
fi

check_2_5
run_2_7_all_scopes
run_verification_1_all_scopes
verify_negative_test

for id in "${MISSIONS[@]}"; do
  render_one "${id}" > "${id}/values.yaml"
  echo "wrote ${id}/values.yaml"
done
render_all > values-all.yaml
echo "wrote values-all.yaml"
