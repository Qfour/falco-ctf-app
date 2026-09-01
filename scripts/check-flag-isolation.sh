#!/usr/bin/env bash
# ADR-0001 (Option B, Accepted) Verification 1: allowlist-type static
# assertions over `helm template charts/ctf-user` output.
#
# WHY ALLOWLIST, NOT A DENYLIST OF ENV NAMES (ADR-0001 explicit requirement):
# a denylist ("no env named ^CTF_FLAG_") is bypassable via `envFrom` or a
# volumeMount that lands the flag at a path the challenge container reads —
# neither introduces a matching env *name*. Every check below instead
# enumerates the small set of things the `challenge` container (and the
# `plant` initContainer, and the Role bound to the workspace SA) is allowed
# to have, and fails on anything outside that set.
#
# This script only ever runs `helm template` (no cluster, no real image) and
# only ever reads repo-tracked files (challenges/*/plant.sh headers,
# charts/ctf-user/values.yaml) to derive its allowlists — it never touches
# challenges/values-all.yaml or any other generated/shared artifact.
#
# Usage:
#   ./scripts/check-flag-isolation.sh
#       Renders and checks every scope in the ADR-0001 Verification 1 render
#       matrix (Makefile: `make check-flag-isolation`; CI: chart-lint job).
#
#   ./scripts/check-flag-isolation.sh --scope <label> -- <helm template args...>
#       Renders exactly one ad-hoc scope and runs the same assertions against
#       it. Used to demonstrate the deliberate-violation patches in the
#       ADR-0001 PR body (see the PR description for the exact invocations) —
#       every patch is expressed as `helm template` input (--set / a
#       temporary values file), never as an edit to a committed chart or
#       challenges/ file.
#
# Exit status: 0 iff every assertion passes in every scope checked. Never
# fail-open: every check below branches explicitly on a captured exit status
# or string comparison, never on the exit status of a pipeline's non-final
# stage.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Override only used to point the *same* assertions at a scratch copy of
# the chart when demonstrating a deliberate-violation patch (ADR-0001 PR
# body) — never set in `make check-flag-isolation` / CI, which always check
# the real, committed chart.
CHART_DIR="${CHECK_FLAG_ISOLATION_CHART_DIR:-charts/ctf-user}"
PROBE_FLAG='FALCO{dev-probe}'
RC=0
# P27-1: set by the scenario-scope loop below, immediately before each
# run_scope() call, to the scenario's own space-joined challenge-id list.
# Read by assert_missions_scope() inside run_scope(); empty (the default)
# in every non-scenario scope, which makes that assert a no-op there.
EXPECTED_SCENARIO_MISSIONS=""

# ---------------------------------------------------------------------------
# output helpers — every violation is printed AND recorded (RC=1); nothing
# here can silently downgrade a violation to a pass.
# ---------------------------------------------------------------------------
violation() { # $1=assert-id $2=message
  echo "  FAIL [$1]: $2" >&2
  RC=1
}
ok() { # $1=assert-id $2=message
  echo "  ok   [$1]: $2"
}

# ---------------------------------------------------------------------------
# Allowlists derived from repo-tracked sources (never hardcoded a second
# time here — same "derive from catalog" discipline as gen-values.sh's
# sensitive_paths()/sensitive_dir_prefixes()).
# ---------------------------------------------------------------------------

# 1-1: the only env names the challenge container may ever carry.
CHALLENGE_ENV_ALLOWLIST=(FALCO_CTF_USER FALCO_CTF_CHALLENGE FALCO_CTF_COLLECTOR FALCO_CTF_SCOREBOARD FALCO_CTF_DNS_SUFFIX)

# 1-4 / 1-18 (ADR-0007 — granularity-neutral rewrite): the universe of
# directories that may be bind-mounted, derived from every plant.sh's
# `# plant-target:` + `# plant-target-type:` header pair (the same headers
# challenges/gen-values.sh reads to build `plant.mounts`) — the mount
# directory is the plant-target itself when `plant-target-type: dir`, or
# its dirname when `plant-target-type: file`. A challenge container may
# only ever bind-mount one of these off the plant-seed volume, and NEVER a
# bare plant-target FILE path itself (that regression is exactly what
# ADR-0007 closes — see docs/adr/0007-plant-mount-directory-granularity.md).
plant_mount_dir_allowlist() {
  local f target type
  for f in challenges/*/plant.sh; do
    [ -e "$f" ] || continue
    target="$(grep -E '^# plant-target: ' "$f" | sed -E 's/^# plant-target: *//' | head -1)"
    type="$(grep -E '^# plant-target-type: ' "$f" | sed -E 's/^# plant-target-type: *//' | head -1)"
    [ -z "$target" ] && continue
    if [ "$type" = "dir" ]; then
      printf '%s\n' "$target"
    else
      dirname "$target"
    fi
  done | sort -u
}

# The set of raw plant-target FILE paths (never a valid mountPath under
# ADR-0007 — a mountPath equal to one of these is exactly the file-
# granularity regression Verification 1-4 must catch).
plant_target_file_allowlist() {
  local f target type
  for f in challenges/*/plant.sh; do
    [ -e "$f" ] || continue
    target="$(grep -E '^# plant-target: ' "$f" | sed -E 's/^# plant-target: *//' | head -1)"
    type="$(grep -E '^# plant-target-type: ' "$f" | sed -E 's/^# plant-target-type: *//' | head -1)"
    [ -z "$target" ] && continue
    [ "$type" = "file" ] && printf '%s\n' "$target"
  done | sort -u
}

# ADR-0007: mount directories whose bind mount must NOT be readOnly:true.
# Kept as an independently-maintained literal here (not sourced from
# gen-values.sh / plant.sh headers) so this script can catch a drift
# between the two rather than blindly inheriting gen-values.sh's own
# reasoning — mirrors gen-values.sh's WRITABLE_MOUNT_DIRS derivation
# (mission 09's `/etc/sudoers` hardlink target; see
# challenges/03-stealth-read/plant.sh's `plant-mount-readonly` header).
#
# 2026-09-01 (ADR-0025 vault-separation): no plant.sh currently declares
# `plant-mount-readonly: false` for /etc or anywhere else (mission 03/10
# moved off /etc/shadow to /opt/nimbus/vault, which nothing writes into at
# runtime; mission 09 no longer has /etc separately mounted at all, so its
# hardlink target needs no readOnly:false override). This entry is
# VACUOUS as of today — it never matches a rendered mountPath in any
# render-matrix scope, so `mount_dir_is_writable` always returns false and
# every mount is asserted readOnly:true. Left in place (not emptied) as a
# ready allowlist slot for if /etc (or another mount) needs write access
# again in the future.
WRITABLE_MOUNT_DIR_ALLOWLIST=(/etc)

mount_dir_is_writable() { # $1=mount dir -> rc 0 iff it is allowed readOnly:false
  local d="$1" x
  for x in "${WRITABLE_MOUNT_DIR_ALLOWLIST[@]}"; do
    [ "$x" = "$d" ] && return 0
  done
  return 1
}

is_in_allowlist() { # $1=needle  $2...=haystack array elements
  local needle="$1"; shift
  local x
  for x in "$@"; do [ "$x" = "$needle" ] && return 0; done
  return 1
}

# ---------------------------------------------------------------------------
# Manifest-document extraction. `helm template` emits `---`-separated docs;
# split once per scope, then pick the doc(s) each assert needs by kind (+
# metadata.name where more than one object of that kind could exist).
# ---------------------------------------------------------------------------

# Populates the global array DOCS[] with one element per rendered document
# (leading/trailing blank docs from the `---` separators are dropped).
#
# NOTE: deliberately does not use `${var//pattern/}`-style glob substitution
# on accumulated multi-line content — bash 3.2 (macOS's shipped /bin/bash,
# which this repo targets for locally-run scripts, see
# challenges/gen-values.sh's "portable to bash 3.2 / macOS" note) has a
# severe performance pathology with global pattern substitution over
# multi-byte UTF-8 text (this repo's rendered charts are full of em dashes /
# arrows in comments) — it turns an O(n) split into what looks like a hang.
# `saw_content` tracks non-emptiness directly instead.
split_docs() { # $1=full manifest text
  DOCS=()
  local cur="" line saw_content=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "---" ]; then
      [ "$saw_content" -eq 1 ] && DOCS+=("$cur")
      cur=""; saw_content=0
    else
      cur+="$line"$'\n'
      [ -n "$line" ] && saw_content=1
    fi
  done <<<"$1"
  [ "$saw_content" -eq 1 ] && DOCS+=("$cur")
}

find_doc() { # $1=kind $2=name(optional) -> prints the matching doc from DOCS[], rc=1 if none
  local kind="$1" name="${2:-}" d
  for d in "${DOCS[@]}"; do
    if grep -qx "kind: ${kind}" <<<"$d"; then
      if [ -z "$name" ] || grep -qx "  name: ${name}" <<<"$d"; then
        printf '%s' "$d"
        return 0
      fi
    fi
  done
  return 1
}

# extract_named_block: pull one container/initContainer's full text out of a
# Pod doc, from its `- name: X` line up to (but not including) either the
# next sibling list item at the same indent (another `- name:`) or the next
# spec-level key (2-space indent) — i.e. the point where we've left the
# containers/initContainers list entirely. Comments are preserved (needed by
# 1-6's plain-string search).
extract_named_block() { # $1=doc text $2="    - name: X" (exact, 4-space indent)
  awk -v start="$2" '
    BEGIN{on=0}
    index($0, start) == 1 && !on { on=1; print; next }
    on && index($0, "    - name: ") == 1 { exit }
    on && $0 ~ /^  [A-Za-z]/ { exit }
    on { print }
  ' <<<"$1"
}

# block_of: pull the children of an exact "key:" line (e.g. "      env:")
# out of already-extracted text, stopping at the first line whose indent is
# <= the key line's indent.
block_of() { # $1=text $2="<indent-spaces>key:" exact line
  local text="$1" keyline="$2"
  local kind=0
  # count leading spaces of the key line
  while [ "${keyline:$kind:1}" = " " ]; do kind=$((kind + 1)); done
  awk -v key="$keyline" -v kind="$kind" '
    BEGIN{on=0}
    $0==key && !on {on=1; next}
    on {
      n=0
      while (substr($0, n+1, 1) == " ") n++
      if (n <= kind) exit
      print
    }
  ' <<<"$text"
}

# ---------------------------------------------------------------------------
# Verification 1-1 .. 1-11, 1-14 .. 1-21 (per-scope). Each takes the
# already-split docs for one rendered scope.
# ---------------------------------------------------------------------------

assert_challenge_env() { # 1-1, 1-2, 1-3
  local block="$1" env_block names name valuefrom_lines
  if grep -q '^      envFrom:' <<<"$block"; then
    violation 1-2 "challenge container has an envFrom key"
  else
    ok 1-2 "challenge container has no envFrom key"
  fi

  env_block="$(block_of "$block" "      env:")"
  names="$(grep -oE '^        - name: .*' <<<"$env_block" | sed -E 's/^        - name: //')"
  local bad=0
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    if ! is_in_allowlist "$name" "${CHALLENGE_ENV_ALLOWLIST[@]}"; then
      violation 1-1 "challenge env name '${name}' is not in the allowlist (${CHALLENGE_ENV_ALLOWLIST[*]})"
      bad=1
    fi
  done <<<"$names"
  [ "$bad" -eq 0 ] && ok 1-1 "every challenge env[].name is in the allowlist"

  valuefrom_lines="$(grep -n 'valueFrom:' <<<"$env_block" || true)"
  if [ -n "$valuefrom_lines" ]; then
    violation 1-3 "challenge env entry has a valueFrom (secretKeyRef/configMapKeyRef path):"$'\n'"$valuefrom_lines"
  else
    ok 1-3 "no challenge env entry has valueFrom (value: only)"
  fi
}

assert_challenge_mounts() { # 1-4, 1-5, 1-18 (challenge side) — ADR-0007 granularity-neutral rewrite
  local block="$1"
  local -a allowlist=() file_targets=()
  while IFS= read -r t; do [ -n "$t" ] && allowlist+=("$t"); done < <(plant_mount_dir_allowlist)
  while IFS= read -r t; do [ -n "$t" ] && file_targets+=("$t"); done < <(plant_target_file_allowlist)

  if grep -qF '/var/run/secrets/kubernetes.io/serviceaccount' <<<"$block"; then
    violation 1-5 "challenge container mounts the serviceaccount token path"
  else
    ok 1-5 "challenge container has no serviceaccount token mount"
  fi

  local vm_block
  vm_block="$(block_of "$block" "      volumeMounts:")"
  if [ -z "$vm_block" ]; then
    ok 1-4 "challenge has no volumeMounts key (no plant-target mounted — matches empty plant.mounts)"
    ok 1-18 "no seed mounts to check (challenge has no volumeMounts key)"
    return
  fi

  # Each entry is a "- name: plant-seed" line followed by mountPath/subPath/
  # readOnly siblings at the same 8-space indent. Walk them one at a time.
  local mountpath="" subpath="" readonly_val="" volname="" bad4=0 bad18=0
  flush_entry() {
    [ -z "$volname" ] && return
    if [ "$volname" = "plant-seed" ]; then
      if [ -z "$subpath" ]; then
        violation F5 "challenge mounts the plant-seed volume WITHOUT subPath at mountPath=${mountpath} (seed-root mount — mission 03 bypass)"
        bad4=1; bad18=1
      else
        local mp_bare="${mountpath%\"}"; mp_bare="${mp_bare#\"}"
        # ADR-0007 Verification 1 (mirrored here): mountPath must be a
        # declared MOUNT DIRECTORY (plant-target's enclosing dir, or the
        # plant-target itself when it's already a dir) — and must NEVER be
        # a bare plant-target FILE path. The file-path check runs first and
        # is the sharper of the two failure messages (it names exactly the
        # regression class ADR-0007 exists to catch).
        # bash 3.2 (macOS default) note: file_targets[] is legitimately
        # empty as of the 2026-09-01 vault-separation change (no challenge
        # currently declares plant-target-type: file — see
        # challenges/gen-values.sh's file_type_mount_targets() comment for
        # the same fact on the gen-values side). Under `set -u`, expanding
        # "${file_targets[@]}" when the array has zero elements raises
        # "unbound variable" in bash 3.2 (a known pre-4.4 quirk — empty
        # arrays are NOT the same as unset scalars for this purpose). The
        # ${file_targets[@]+"${file_targets[@]}"} form guards that: it only
        # expands the inner "${file_targets[@]}" when the array has at least
        # one element (or is otherwise "set"), and produces nothing (not an
        # error) when it is empty — is_in_allowlist then just never matches.
        if is_in_allowlist "$mp_bare" ${file_targets[@]+"${file_targets[@]}"}; then
          violation 1-4 "challenge volumeMount mountPath '${mp_bare}' is a FILE-granularity plant-target, not its enclosing directory (ADR-0007 requires directory granularity — a file destination makes the runtime's own mount-setup trigger open_read-family Falco rules on every deploy)"
          bad4=1
        elif ! is_in_allowlist "$mp_bare" "${allowlist[@]}"; then
          violation 1-4 "challenge volumeMount mountPath '${mp_bare}' is not a declared plant-target mount directory (${allowlist[*]})"
          bad4=1
        fi
        local sp_bare="${subpath%\"}"; sp_bare="${sp_bare#\"}"
        local want_sp="${mp_bare#/}"
        if [ "$sp_bare" != "$want_sp" ]; then
          violation 1-18 "challenge volumeMount mountPath=${mp_bare} has subPath='${sp_bare}', want '${want_sp}' (subPath must exactly trace the declared mount directory)"
          bad18=1
        fi
        # ADR-0007: readOnly is per-mount now. Exactly the mount dirs in
        # WRITABLE_MOUNT_DIR_ALLOWLIST may render readOnly:false; every
        # other mount must still be readOnly:true (fail-closed default —
        # mission 05's /root/.ssh must never silently become writable just
        # because /etc needed to be).
        if mount_dir_is_writable "$mp_bare"; then
          if [ "$readonly_val" != "false" ]; then
            violation 1-18 "challenge volumeMount mountPath=${mp_bare} is in the writable-mount allowlist but is not readOnly: false"
            bad18=1
          fi
        else
          if [ "$readonly_val" != "true" ]; then
            violation 1-18 "challenge volumeMount mountPath=${mp_bare} is not readOnly: true (only ${WRITABLE_MOUNT_DIR_ALLOWLIST[*]} may be readOnly: false)"
            bad18=1
          fi
        fi
      fi
    fi
    mountpath=""; subpath=""; readonly_val=""; volname=""
  }
  while IFS= read -r line; do
    case "$line" in
      "        - name: "*) flush_entry; volname="${line#        - name: }" ;;
      "          mountPath: "*) mountpath="${line#          mountPath: }" ;;
      "          subPath: "*) subpath="${line#          subPath: }" ;;
      "          readOnly: "*) readonly_val="${line#          readOnly: }" ;;
    esac
  done <<<"$vm_block"
  flush_entry
  [ "$bad4" -eq 0 ] && ok 1-4 "every challenge volumeMount mountPath is a declared plant-target mount directory (never a bare file)"
  [ "$bad18" -eq 0 ] && ok 1-18 "every challenge seed volumeMount has subPath tracing its mount directory, and readOnly matching the writable-mount allowlist (${WRITABLE_MOUNT_DIR_ALLOWLIST[*]})"
}

assert_challenge_no_flag_string() { # 1-6, 1-7 (1-7 is a subset of 1-6 — postStart lives in the same block)
  local block="$1"
  if grep -qF 'CTF_FLAG' <<<"$block"; then
    violation 1-6 "the literal string 'CTF_FLAG' appears in the challenge container block"
    violation 1-7 "(subsumed by 1-6) postStart/lifecycle in the challenge block may reference a flag"
  else
    ok 1-6 "no 'CTF_FLAG' string anywhere in the challenge container block"
    ok 1-7 "(subsumed by 1-6) no lifecycle.postStart flag reference"
  fi
}

assert_secret_scope() { # 1-8 (i) + (ii)
  local full="$1" secret_doc="$2" non_secret="$3"
  if grep -qF "$PROBE_FLAG" <<<"$non_secret"; then
    violation 1-8i "plaintext probe flag '${PROBE_FLAG}' appears outside the ctf-flags Secret document"
  else
    ok 1-8i "plaintext probe flag appears only inside the ctf-flags Secret document (or not at all)"
  fi

  local b64 secret_data total_hits data_hits
  b64="$(printf '%s' "$PROBE_FLAG" | base64 | tr -d '\n')"
  total_hits=$(grep -c -- "$b64" <<<"$full" 2>/dev/null || true)
  secret_data="$(block_of "${secret_doc:-}" "data:" 2>/dev/null || true)"
  data_hits=$(grep -c -- "$b64" <<<"$secret_data" 2>/dev/null || true)
  : "${total_hits:=0}" "${data_hits:=0}"
  if [ "$total_hits" -gt "$data_hits" ]; then
    violation 1-8ii "base64 form of the probe flag appears outside kind:Secret ctf-flags' data: block"
  else
    ok 1-8ii "base64 form of the probe flag never appears outside ctf-flags' data: block"
  fi
}

assert_pod_level() { # 1-9, 1-15
  local pod_doc="$1"
  if grep -qx '  automountServiceAccountToken: false' <<<"$pod_doc"; then
    ok 1-9 "spec.automountServiceAccountToken == false"
  else
    violation 1-9 "spec.automountServiceAccountToken is not 'false'"
  fi

  local bad=0
  if grep -qx '  shareProcessNamespace: true' <<<"$pod_doc"; then
    violation 1-15 "spec.shareProcessNamespace: true"
    bad=1
  fi
  if grep -qx '  hostPID: true' <<<"$pod_doc"; then
    violation 1-15 "spec.hostPID: true"
    bad=1
  fi
  [ "$bad" -eq 0 ] && ok 1-15 "shareProcessNamespace and hostPID are unset/false"
}

assert_plant_block() { # 1-10, 1-14, 1-19 (plant side), 1-21
  local block="$1" pod_doc="$2"

  if grep -q '^      restartPolicy:' <<<"$block"; then
    violation 1-14 "plant initContainer has a restartPolicy key (would make it a native sidecar)"
  else
    ok 1-14 "plant initContainer has no restartPolicy key"
  fi

  local env_block value_lines
  if grep -q '^      envFrom:' <<<"$block" && grep -q 'name: ctf-flags' <<<"$block"; then
    ok 1-10 "plant has envFrom.secretRef referencing ctf-flags"
  else
    violation 1-10 "plant does not have an envFrom.secretRef to ctf-flags"
  fi
  env_block="$(block_of "$block" "      env:")"
  value_lines="$(grep -nE '^ {10}value: ' <<<"$env_block" || true)"
  if [ -n "$value_lines" ]; then
    violation 1-10 "plant has a plaintext env value: entry:"$'\n'"$value_lines"
  else
    ok 1-10 "plant has no plaintext env value: entries"
  fi

  # 1-19 counts STRUCTURAL occurrences only (the actual secretRef.name
  # field) — comment-only lines (this template's own prose, or a mission's
  # plant.sh header prose carried through into the seed script's comments)
  # legitimately say "ctf-flags" without being a second reference. Strip
  # any line whose first non-blank character is '#' before counting.
  local pod_code block_code ctf_flags_total ctf_flags_in_plant
  pod_code="$(grep -vE '^[[:space:]]*#' <<<"$pod_doc" || true)"
  block_code="$(grep -vE '^[[:space:]]*#' <<<"$block" || true)"
  ctf_flags_total=$(grep -c -- 'ctf-flags' <<<"$pod_code" 2>/dev/null || true)
  ctf_flags_in_plant=$(grep -c -- 'ctf-flags' <<<"$block_code" 2>/dev/null || true)
  : "${ctf_flags_total:=0}" "${ctf_flags_in_plant:=0}"
  if [ "$ctf_flags_total" -eq 1 ] && [ "$ctf_flags_in_plant" -eq 1 ]; then
    ok 1-19 "'ctf-flags' appears exactly once in the Pod, inside plant's envFrom"
  else
    violation 1-19 "'ctf-flags' appears ${ctf_flags_total} time(s) in the Pod (want exactly 1, inside plant's envFrom; plant block has ${ctf_flags_in_plant})"
  fi
  if grep -q 'optional: true' <<<"$block"; then
    violation 1-19 "plant's ctf-flags envFrom has optional: true (fail-open on missing Secret)"
  else
    ok 1-19 "plant's ctf-flags envFrom has no optional: true"
  fi

  local bad21=0
  if grep -qE 'privileged: *true' <<<"$block"; then
    violation 1-21 "plant sets securityContext.privileged: true"
    bad21=1
  fi
  if grep -A3 '^      securityContext:' <<<"$block" | grep -q '^ *add:' ; then
    violation 1-21 "plant securityContext adds capabilities"
    bad21=1
  fi
  if grep -q 'hostPath:' <<<"$pod_doc"; then
    violation 1-21 "Pod defines a hostPath volume"
    bad21=1
  fi
  [ "$bad21" -eq 0 ] && ok 1-21 "plant has no privileged/added-capabilities/hostPath"
}

assert_plant_seed_root_only() { # 1-18 (plant side): plant's own volumeMounts == exactly one entry, the seed root, no subPath
  local block="$1"
  local vm_block n
  vm_block="$(block_of "$block" "      volumeMounts:")"
  n=$(grep -c '^        - name: ' <<<"$vm_block" 2>/dev/null || true)
  : "${n:=0}"
  if [ "$n" -ne 1 ]; then
    violation 1-18 "plant has ${n} volumeMounts entries (want exactly 1: the plant-seed root)"
    return
  fi
  if grep -q '^          subPath: ' <<<"$vm_block"; then
    violation 1-18 "plant's single volumeMount has a subPath (it must mount the seed root, unpinned)"
    return
  fi
  ok 1-18 "plant mounts exactly one volume: the plant-seed root, no subPath"
}

assert_ttyd_argv() { # 1-17 (recommended)
  local block="$1"
  if grep -qx '        - name: TTYD_TARGET_CONTAINER' <<<"$block" && grep -q '^          value: "challenge"' <<<"$block"; then
    ok 1-17 "TTYD_TARGET_CONTAINER renders to 'challenge'"
  else
    violation 1-17 "TTYD_TARGET_CONTAINER is missing or not pinned to 'challenge'"
  fi
  if grep -qE '^      (command|args):' <<<"$block"; then
    violation 1-17 "ttyd container has a command/args key — a chart-controlled argv injection door"
  else
    ok 1-17 "ttyd container has no command/args key (no argv injection door in the chart)"
  fi
}

assert_no_overlay_noop() { # 1-20 (recommended). Only "bites" when challenge
  # has no volumeMounts key at all (i.e. the no-overlay / trigger-only
  # scope) — in every other scope this is a vacuous "not applicable" pass,
  # by property rather than by hardcoding which scope is "the" scope 5.
  local plant_block="$1" challenge_block="$2"
  if grep -q '^      volumeMounts:' <<<"$challenge_block"; then
    ok 1-20 "not applicable in this scope (challenge has declared plant-target mounts)"
    return
  fi
  local cmd_block want
  cmd_block="$(block_of "$plant_block" "      command:")"
  # No trailing \n: $(block_of ...) is a command substitution, which always
  # strips trailing newlines from its output, however many `block_of`'s awk
  # actually printed.
  want=$'        - sh\n        - -c\n        - "true"'
  if [ "$cmd_block" = "$want" ]; then
    ok 1-20 "challenge has no volumeMounts key AND plant's seedScript is a genuine no-op"
  else
    violation 1-20 "challenge has no volumeMounts key but plant's seedScript is NOT the no-op ('sh -c true'):"$'\n'"$cmd_block"
  fi
}

assert_missions_scope() { # P27-1, render-time equivalent of assert-flag-isolation.sh's
  # cluster-side 3-8. Reads the global EXPECTED_SCENARIO_MISSIONS (set by the
  # scenario-scope loop below, immediately before each run_scope() call that
  # needs it) — a no-op in every scope where that's empty (the 5 fixed
  # scopes above never set it). Found missing by 5x review R2: this script
  # asserted flag isolation (1-1..1-21) for scenario scope but had NOTHING
  # checking that the `missions-scope` initContainer / `missions-seed`
  # mount charts/ctf-user/templates/pod.yaml renders for content isolation
  # (see that file's P27-1 comments) actually exist — a `{{- if false }}`
  # mutation over the challenge volumeMount rendered clean here while
  # failing cluster-side 3-8. This closes that CI-visible gap.
  local pod_doc="$1" challenge_block="$2"
  [ -n "${EXPECTED_SCENARIO_MISSIONS}" ] || return 0

  local scope_block
  scope_block="$(extract_named_block "$pod_doc" "    - name: missions-scope")"
  if [ -z "$scope_block" ]; then
    violation P27-1a "scenario.missions is set but no 'missions-scope' initContainer is in the rendered Pod (content isolation is not applied — /opt/ctf/missions/ stays the full image-baked tree)"
    return
  fi
  ok P27-1a "'missions-scope' initContainer is present"

  local id missing=()
  for id in ${EXPECTED_SCENARIO_MISSIONS}; do
    if ! grep -qF "mkdir -p \"/missions-seed/${id}\"" <<<"$scope_block" \
      || ! grep -qF "cp -a \"/opt/ctf/missions/${id}/.\"" <<<"$scope_block"
    then
      missing+=("$id")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    violation P27-1b "'missions-scope' initContainer command has no mkdir/cp for: ${missing[*]} (expected: ${EXPECTED_SCENARIO_MISSIONS})"
  else
    ok P27-1b "'missions-scope' initContainer command covers every expected mission id (${EXPECTED_SCENARIO_MISSIONS})"
  fi

  # The challenge container's volumeMounts entry that actually shadows
  # /opt/ctf/missions/ — checked as an adjacent {name, mountPath} pair
  # (mountPath must be the very next line after the name line, matching
  # exactly how pod.yaml renders it), not just "both substrings appear
  # somewhere in the block".
  local vm_block
  vm_block="$(block_of "$challenge_block" "      volumeMounts:")"
  if grep -A1 -F -- '- name: missions-seed' <<<"$vm_block" | grep -qF -- 'mountPath: /opt/ctf/missions'; then
    ok P27-1c "challenge container mounts missions-seed at /opt/ctf/missions"
  else
    violation P27-1c "challenge container has no missions-seed volumeMount at /opt/ctf/missions (scenario.missions is set but /opt/ctf/missions/ is not shadowed in the challenge container)"
  fi
}

assert_role() { # 1-16 (required)
  local role_doc="$1"
  if [ -z "$role_doc" ]; then
    violation 1-16 "no Role document found to check"
    return
  fi
  local pairs bad=0
  pairs="$(awk '
    /^  - apiGroups:/ { if (res != "") print res "\x01" verbs; res=""; verbs="" }
    /resources:/ { res=$0 }
    /verbs:/ { verbs=$0 }
    END { if (res != "") print res "\x01" verbs }
  ' <<<"$role_doc")"
  while IFS=$'\x01' read -r res verbs; do
    [ -z "$res" ] && continue
    if grep -qE '"secrets"|"configmaps"' <<<"$res"; then
      violation 1-16 "Role rule grants a verb on secrets/configmaps: ${res} / ${verbs}"
      bad=1
    fi
    if grep -qF '"pods/ephemeralcontainers"' <<<"$res" && grep -qF 'patch' <<<"$verbs"; then
      violation 1-16 "Role rule grants patch on pods/ephemeralcontainers: ${res} / ${verbs}"
      bad=1
    fi
    if grep -qF '"pods"' <<<"$res" && ! grep -qF '"pods/' <<<"$res"; then
      if grep -qE 'create|patch' <<<"$verbs"; then
        violation 1-16 "Role rule grants create/patch on pods: ${res} / ${verbs}"
        bad=1
      fi
    fi
  done <<<"$pairs"
  [ "$bad" -eq 0 ] && ok 1-16 "ttyd-exec Role has no secrets/configmaps verb and no pods/ephemeralcontainers-patch or pods-create/patch"
}

# ---------------------------------------------------------------------------
# negative tests (template must FAIL): 1-12
# ---------------------------------------------------------------------------
assert_1_12() {
  if helm template "$CHART_DIR" \
      --set 'challenge.extraEnv[0].name=CTF_FLAG_03_STEALTH_READ' \
      --set 'challenge.extraEnv[0].value=x' >/dev/null 2>/tmp/check-flag-isolation-1-12.err; then
    violation 1-12 "helm template with challenge.extraEnv[0].name=CTF_FLAG_03_STEALTH_READ succeeded (want: template-time fail)"
  else
    ok 1-12 "helm template rejects challenge.extraEnv[*].name starting with CTF_FLAG_ ($(tr -d '\n' </tmp/check-flag-isolation-1-12.err | head -c 120))"
  fi
  rm -f /tmp/check-flag-isolation-1-12.err
}

# 1-13: no extraEnvFrom-shaped door exists in the chart's own values schema
# (a static repo-content check, not a per-scope render check).
assert_1_13() {
  if grep -q 'extraEnvFrom' "$CHART_DIR/values.yaml"; then
    violation 1-13 "charts/ctf-user/values.yaml declares an extraEnvFrom field (a new injection door — needs architect sign-off + I12 amendment)"
  else
    ok 1-13 "charts/ctf-user/values.yaml has no extraEnvFrom field"
  fi
}

# ---------------------------------------------------------------------------
# One full scope: render, split into docs, run every per-scope assertion.
# ---------------------------------------------------------------------------
run_scope() { # $1=label, remaining args = helm template args (after $CHART_DIR)
  local label="$1"; shift
  echo "== scope: ${label} =="
  echo "   helm template ${CHART_DIR} $*"
  local manifest
  if ! manifest="$(helm template "$CHART_DIR" "$@" 2>&1)"; then
    violation RENDER "helm template failed for scope '${label}':"$'\n'"$manifest"
    return
  fi

  split_docs "$manifest"
  local pod_doc secret_doc role_doc non_secret_manifest="" d
  pod_doc="$(find_doc Pod || true)"
  secret_doc="$(find_doc Secret ctf-flags || true)"
  role_doc="$(find_doc Role ttyd-exec || true)"
  # Built from DOCS[] directly, matched by kind+name rather than by
  # string-comparing against $secret_doc: command substitution
  # ("secret_doc=$(...)") strips trailing newlines, so $secret_doc is never
  # byte-identical to its counterpart still sitting in DOCS[] — comparing
  # them would silently fail to exclude anything.
  for d in "${DOCS[@]}"; do
    if grep -qx 'kind: Secret' <<<"$d" && grep -qx '  name: ctf-flags' <<<"$d"; then
      continue
    fi
    non_secret_manifest+="$d"
  done

  if [ -z "$pod_doc" ]; then
    violation RENDER "scope '${label}': no Pod document in rendered output"
    return
  fi

  local plant_block challenge_block ttyd_block
  plant_block="$(extract_named_block "$pod_doc" "    - name: plant")"
  challenge_block="$(extract_named_block "$pod_doc" "    - name: challenge")"
  ttyd_block="$(extract_named_block "$pod_doc" "    - name: ttyd")"

  if [ -z "$plant_block" ]; then
    violation RENDER "scope '${label}': no 'plant' initContainer in rendered Pod"
  fi
  if [ -z "$challenge_block" ]; then
    violation RENDER "scope '${label}': no 'challenge' container in rendered Pod"
  fi
  [ -z "$plant_block" ] || [ -z "$challenge_block" ] && return

  assert_challenge_env "$challenge_block"
  assert_challenge_mounts "$challenge_block"
  assert_challenge_no_flag_string "$challenge_block"
  assert_secret_scope "$manifest" "${secret_doc:-}" "$non_secret_manifest"
  assert_pod_level "$pod_doc"
  assert_plant_block "$plant_block" "$pod_doc"
  assert_plant_seed_root_only "$plant_block"
  assert_ttyd_argv "$ttyd_block"
  assert_no_overlay_noop "$plant_block" "$challenge_block"
  assert_role "${role_doc:-}"
  assert_missions_scope "$pod_doc" "$challenge_block"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

if [ "${1:-}" = "--scope" ]; then
  label="$2"; shift 3 2>/dev/null || shift $#
  # remaining args ($@) are the helm template args for this one ad-hoc scope
  # (the `--` separator, if present, is only for readability at the call
  # site — helm ignores stray `--` tokens it doesn't recognize as its own).
  run_scope "$label" "$@"
  exit "$RC"
fi

echo "ADR-0001 Verification 1 — render matrix (5 fixed scopes + P27-1 scenario scopes)"
echo

# 1. all-missions (production default)
run_scope "values-all (challengeId=all)" \
  -f challenges/values-all.yaml --set challengeId=all \
  --set-string challenge.flags.03-stealth-read="$PROBE_FLAG" \
  --set-string challenge.flags.05-silent-search="$PROBE_FLAG" \
  --set-string challenge.flags.10-final-exfil="$PROBE_FLAG"
echo

# 2-4. single-mission overlays for every evade mission
for id in 03-stealth-read 05-silent-search 10-final-exfil; do
  run_scope "single-mission (challengeId=${id})" \
    -f "challenges/${id}/values.yaml" --set "challengeId=${id}" \
    --set-string "challenge.flags.${id}=${PROBE_FLAG}"
  echo
done

# 5. no overlay at all — a trigger-only challengeId with no plant.sh, so
# deploy-user.sh's `[[ -f "${CHALLENGE_VALUES}" ]]` guard never adds a `-f`
# and the chart's own defaults apply (plant.seedScript: [sh,-c,"true"],
# plant.mounts: [], no volumeMounts key on challenge at all).
run_scope "no overlay (challengeId=02-credential-files, trigger-only)" \
  --set challengeId=02-credential-files
echo

# 6+. scenario-scope mode (P27-1): one scope per scenarios/<name>/scenario.yaml,
# fed the GENERATED challenges/values-scenario-<name>.yaml
# (challenges/gen-values.sh) — same ADR-0001 assertions must hold for a
# filtered mission-id list, not just "all"/single-mission. challengeId is
# "scenario:<name>" (charts/ctf-user/templates/ctf-flags-secret.yaml's
# hasPrefix "scenario:" branch / deploy-user.sh). Discovered dynamically
# (not hardcoded to today's 2 scenarios) so a new scenarios/<name>/ directory
# is covered automatically once `make gen-values` has generated its values
# file — same "derive from repo content, don't hardcode a second copy"
# discipline as plant_mount_dir_allowlist() above.
for sfile in scenarios/*/scenario.yaml; do
  [ -e "$sfile" ] || continue
  sname="$(basename "$(dirname "$sfile")")"
  svalues="challenges/values-scenario-${sname}.yaml"
  if [ ! -f "$svalues" ]; then
    violation RENDER "scenario '${sname}': ${svalues} not generated (run 'make gen-values')"
    continue
  fi
  # Parse the scenario's own `challenges:` list once (same restrained awk
  # shape challenges/gen-values.sh's scenario_challenge_ids() uses) — this
  # feeds BOTH the PROBE_FLAG overrides below (evade ids only) AND
  # EXPECTED_SCENARIO_MISSIONS (every id, read by assert_missions_scope()).
  all_ids=()
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    all_ids+=("$cid")
  done < <(awk '
    /^challenges:/ { inblock=1; next }
    inblock && /^[^[:space:]]/ { inblock=0 }
    inblock && /^[[:space:]]*-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      sub(/[[:space:]]*#.*$/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$sfile")

  # PROBE_FLAG overrides only for evade ids THIS scenario actually lists
  # (same "don't leak an unrelated mission's probe flag into this Secret"
  # discipline the single-mission scopes above use).
  flag_args=()
  for cid in "${all_ids[@]}"; do
    [ -f "challenges/${cid}/plant.sh" ] || continue
    flag_args+=(--set-string "challenge.flags.${cid}=${PROBE_FLAG}")
  done

  # EXPECTED_SCENARIO_MISSIONS (global, read by assert_missions_scope() via
  # run_scope): every id this scenario lists, space-joined. A challenge id
  # never contains whitespace (see assert-flag-isolation.sh's own probe),
  # so this is a safe wire format.
  EXPECTED_SCENARIO_MISSIONS="${all_ids[*]}"
  run_scope "scenario (challengeId=scenario:${sname})" \
    -f "$svalues" --set "challengeId=scenario:${sname}" \
    ${flag_args:+"${flag_args[@]}"}
  EXPECTED_SCENARIO_MISSIONS=""
  echo
done

assert_1_12
assert_1_13

echo
if [ "$RC" -eq 0 ]; then
  echo "OK: Verification 1 (1-1..1-21) passes for all render-matrix scopes (5 fixed + P27-1 scenario scopes)."
else
  echo "FAIL: Verification 1 violated — see FAIL lines above." >&2
fi
exit "$RC"
