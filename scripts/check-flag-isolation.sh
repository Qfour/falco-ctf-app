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
# ADR-0056 D11 / V2 / V43 (A5b): the evidence bundles' Secrets
# `ctf-evidence-<cid>` (one per investigate challenge). Two things are checked
# beyond the flag assertions above:
#   - every scope: the chart renders NO `ctf-evidence-*` Secret (deploy-user.sh
#     creates them before helm: addendum 6, so a bundle never reaches the Helm
#     release record); the Pod references them by name without `optional`, and a
#     referenced one is volume-mounted by `plant` only, readOnly, at
#     /opt/ctf/evidence-src/<cid>, and named nowhere else (assert_evidence_scope).
#     The repo's scopes reference none (no investigate challenge exists yet), so
#     there it is "no such Secret, no such mount". Once a real scope (values-all, a
#     scenario) holds an investigate challenge (A5d), it is rendered with the names of
#     that challenge's public practice bundle and the Secrets it must reference are
#     ctf-evidence-<cid> of exactly the scope's investigate challenges
#     (scope_practice_evidence). V50 (a bundle's content never
#     reaches the Helm release record): a values file that carries content is
#     refused without echoing it (the chart takes names only); a sentinel check on
#     the fixture's own values and output is only a guard of how it is built.
#   - the evidence fixture (run_evidence_fixtures): two investigate challenges'
#     bundles are rendered, and the copy lines the CHART writes into the plant
#     script are held to challenges/gen-values.sh's definitions by ASKING that
#     script (it is not sourceable): they must end with exactly what
#     `gen-values.sh --render-evidence-copy` prints (the shape, byte for byte), and
#     the script passes `--check-seed-script` (check_2_7 = rule 2-7(a)). The shape
#     and the rule are defined there and not written a second time here. The
#     fixture's `plant.mounts` and seed script come from gen-values.sh
#     (`--emit-evidence-fixture`), so the contract between the two is exercised
#     too. The mount allowlist of 1-4 / 1-18 gets the investigate challenges'
#     directories from the same script (`--list-evidence-mount-dirs`: one
#     derivation of what a mountDir is). Negative cases: the `fail`s of the
#     chart, and mutated renders that must come out red.
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
# ADR-0056 A5b. challenges/gen-values.sh is asked, not sourced (see above).
GEN_VALUES="challenges/gen-values.sh"
# ADR-0056 A5d: the reader of a values file's investigate scope (evidence_scope_cids) and
# the lister of a bundle's names (evidence_sorted_names) are deploy-user.sh's own, from the
# helpers it sources; scope_practice_evidence below uses them and writes neither rule again.
# shellcheck source=charts/ctf-user/evidence-bundle.sh
source charts/ctf-user/evidence-bundle.sh
# The practice edition's layout (internal/edition/practicelayout.go: EditionDirName,
# PracticeDirName, PracticeEvidenceDirName, PracticeAnswersFileName, PracticeDigestsFileName).
# internal/edition/practice_flagisolation_layout_test.go (V85) holds these five literals to
# the Go definitions, the lines that build the paths from them, and that no other line of
# this script spells one of the names as a path.
EVIDENCE_EDITION_DIR='edition'
EVIDENCE_PRACTICE_DIR='practice'
EVIDENCE_PRACTICE_EVIDENCE_DIR='evidence'
EVIDENCE_PRACTICE_ANSWERS='answers.tsv'
EVIDENCE_PRACTICE_DIGESTS='digests.tsv'
# Set by run_evidence_fixtures() around its scopes, empty (the default) everywhere
# else, which makes the checks they feed a "no evidence expected" check:
#   EXPECTED_EVIDENCE_SECRETS  the Secret names the Pod must reference, space-joined
#   EVIDENCE_FIXTURE_DIR       the dir `--emit-evidence-fixture` filled (its `map`)
#   EVIDENCE_FIXTURE_FILES     "<cid> TAB <file names, space-joined>" per challenge:
#                              the bundle the scope was rendered with
#   EVIDENCE_TREE              the fixture's tree of investigate challenges, whose
#                              mount directories join the 1-4 allowlist
EXPECTED_EVIDENCE_SECRETS=""
# V50 (A5b): the content every file of the fixture's bundle holds; a placeholder that
# must appear in no values file given to helm and not in the rendered manifest
EVIDENCE_SENTINEL='SENTINEL-evidence-bundle-content-7f3a9c'
EVIDENCE_FIXTURE_DIR=""
EVIDENCE_FIXTURE_FILES=""
EVIDENCE_TREE=""

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

# ADR-0056 D11 (A5b): the mount directories of the investigate challenges (their
# `evidence.mountDir`, which has no plant.sh header to read). Asked of
# challenges/gen-values.sh (`--list-evidence-mount-dirs`, the derivation its own
# init_plant_ids uses): the type rule is not written a third time here. Over
# $EVIDENCE_TREE when a fixture sets it, else over challenges/. Prints nothing when
# there is no investigate challenge; a failure of the script is the caller's to see.
evidence_mount_dir_allowlist() {
  "$GEN_VALUES" --list-evidence-mount-dirs ${EVIDENCE_TREE:+"$EVIDENCE_TREE"}
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
  local ev_dirs
  while IFS= read -r t; do [ -n "$t" ] && allowlist+=("$t"); done < <(plant_mount_dir_allowlist)
  # ADR-0056 A5b: an investigate challenge's mountDir is a declared mount directory too.
  # Captured first (not inside the process substitution) so a failure is seen.
  if ev_dirs="$(evidence_mount_dir_allowlist)"; then
    while IFS= read -r t; do [ -n "$t" ] && allowlist+=("$t"); done <<<"$ev_dirs"
  else
    violation 1-4 "${GEN_VALUES} --list-evidence-mount-dirs failed, so the investigate challenges' mount directories are unknown"
  fi
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

assert_plant_seed_root_only() { # 1-18 (plant side): plant's own volumeMounts == exactly one entry, the seed root, no subPath (+ the evidence Secret volumes, which assert_evidence_scope judges)
  local block="$1" pod_doc="$2"
  local vm_block n evv name
  vm_block="$(block_of "$block" "      volumeMounts:")"
  evv="$(evidence_volumes "$pod_doc")"
  n=0
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    # a mount of a ctf-evidence-<cid> Secret's volume is not the seed root
    if ! grep -qxF -- "$name" <<<"$evv"; then n=$((n + 1)); fi
  done <<<"$(grep '^        - name: ' <<<"$vm_block" | sed -E 's/^        - name: //' || true)"
  if [ "$n" -ne 1 ]; then
    violation 1-18 "plant has ${n} volumeMounts entries besides its ctf-evidence-* Secret volumes (want exactly 1: the plant-seed root)"
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
# ADR-0056 D11 / V2 / V43 (A5b): the evidence Secrets `ctf-evidence-<cid>`.
# ---------------------------------------------------------------------------

# pod_records <Pod doc>: the Secret-backed volumes and the volumeMounts of every
# container and initContainer, tab separated ("-" for an absent field: a tab is IFS
# whitespace, so an empty field would collapse when read back).
#   V <volume> <secretName> <optional>
#   M <container> <volume> <mountPath> <readOnly>
#   X <container> <list>   an item of containers / initContainers / a container's
#       volumeMounts / volumes that does not start with `- name:` (or such a list
#       written inline): the reader would skip it, so it is reported and
#       assert_evidence_scope fails closed on it (a mountPath-first volumeMount
#       must not slip past the checks)
pod_records() {
  awk '
    function flush() {
      if (mname != "") printf "M\t%s\t%s\t%s\t%s\n", cont, mname, (mp == "" ? "-" : mp), (ro == "" ? "-" : ro)
      mname = ""; mp = ""; ro = ""
    }
    function vflush() {
      if (sn != "") printf "V\t%s\t%s\t%s\n", vname, sn, (vopt == "" ? "-" : vopt)
      sn = ""; vopt = ""
    }
    /^  [A-Za-z]/ {
      vflush(); flush(); sec = $0; sub(/^  /, "", sec); sub(/:.*$/, "", sec); invm = 0
      if ($0 ~ /^  (volumes|containers|initContainers): *[^ ]/) printf "X\t-\t%s\n", sec
      next
    }
    sec == "initContainers" || sec == "containers" {
      if ($0 ~ /^    - name: /) { flush(); cont = $0; sub(/^    - name: /, "", cont); invm = 0; next }
      if ($0 ~ /^    - /) { flush(); invm = 0; printf "X\t%s\t%s\n", (cont == "" ? "-" : cont), sec; next }
      if ($0 ~ /^      [A-Za-z]/) {
        flush(); invm = ($0 ~ /^      volumeMounts:/)
        if ($0 ~ /^      volumeMounts: *[^ ]/) printf "X\t%s\tvolumeMounts\n", cont
        next
      }
      if (invm && $0 ~ /^        - name: /) { flush(); mname = $0; sub(/^        - name: /, "", mname); next }
      if (invm && $0 ~ /^        - /) { flush(); printf "X\t%s\tvolumeMounts\n", cont; next }
      if (invm && $0 ~ /^          mountPath: /) { mp = $0; sub(/^          mountPath: /, "", mp); gsub(/"/, "", mp); next }
      if (invm && $0 ~ /^          readOnly: /) { ro = $0; sub(/^          readOnly: /, "", ro); next }
      next
    }
    sec == "volumes" {
      if ($0 ~ /^    - name: /) { vflush(); vname = $0; sub(/^    - name: /, "", vname); next }
      if ($0 ~ /^    - /) { vflush(); printf "X\t-\tvolumes\n"; next }
      if ($0 ~ /^        secretName: /) { sn = $0; sub(/^        secretName: /, "", sn); next }
      if ($0 ~ /^        optional: /) { vopt = $0; sub(/^        optional: /, "", vopt) }
    }
    END { flush(); vflush() }
  ' <<<"$1"
}

evidence_volumes() { # $1=Pod doc -> the names of the volumes backed by a ctf-evidence-* Secret, one per line
  pod_records "$1" | awk -F'\t' '$1 == "V" && index($3, "ctf-evidence-") == 1 { print $2 }'
}

norm_set() { printf '%s\n' "$@" | LC_ALL=C sort | tr '\n' ' '; }

# V2 (A5b, addendum 6), every scope: the chart renders no ctf-evidence-* Secret (it
# only references the ones deploy-user.sh made); the Secrets the Pod references are
# exactly EXPECTED_EVIDENCE_SECRETS (none outside the fixture), each is the secretName
# of one volume without `optional`, and that volume is mounted by `plant` only,
# readOnly, at
# /opt/ctf/evidence-src/<cid>. No container but `plant` mounts anything under
# /opt/ctf/evidence-src, and the string `ctf-evidence-` appears in the Pod's code
# only as those secretName lines (so no envFrom / secretKeyRef / env reaches one).
# The containers are read from the Pod (every initContainer and container), not
# from a list of names: a container added later is judged too.
assert_evidence_scope() { # $1=Pod doc (DOCS[] holds the scope's documents)
  local pod_doc="$1" recs d nm have="" refs="" evv="" kind a b c e sn mcount="" n stray bad=0
  recs="$(pod_records "$pod_doc")"
  # the parser must have read plant's seed mount, or it read nothing and "no evidence mount" means nothing
  if ! grep -qxF $'M\tplant\tplant-seed\t/plant-seed\t-' <<<"$recs"; then
    violation E-scope "the Pod reader found no plant-seed mount in the plant initContainer (it read nothing: 'no evidence mount' would be vacuous)"
    return
  fi
  while IFS=$'\t' read -r kind a b c e; do
    [ "$kind" = "X" ] || continue
    violation E-scope "an item of '${b}' (container '${a}') does not start with \`- name:\` or the list is inline, which the Pod reader cannot read: a volume mount written that way would escape the evidence checks"
    bad=1
  done <<<"$recs"
  for d in "${DOCS[@]}"; do
    if grep -qx 'kind: Secret' <<<"$d"; then
      nm="$(awk '/^  name: / { sub(/^  name: /, ""); print; exit }' <<<"$d")"
      case "$nm" in ctf-evidence-*) have="${have} ${nm}" ;; esac
    fi
  done
  # (a) the chart renders NO ctf-evidence-* Secret (addendum 6: deploy-user.sh creates
  # them before helm, so the Helm release record never holds a bundle)
  if [ -n "$have" ]; then
    violation E-scope "the chart renders the Secret(s) [${have# }]: a ctf-evidence-* Secret is created by deploy-user.sh before helm and only referenced here (a rendered one would put the bundle into the Helm release record)"
    bad=1
  fi
  while IFS=$'\t' read -r kind a b c e; do
    [ "$kind" = "V" ] || continue
    case "$b" in
      ctf-evidence-*)
        evv="${evv} ${a}=${b}"
        refs="${refs} ${b}"
        # (b) no `optional` on the reference: a missing Secret must keep the Pod from starting
        if [ "$c" != "-" ]; then
          violation E-scope "volume '${a}' (${b}) has optional: ${c} (a missing evidence Secret must stop the Pod from starting, not plant an empty directory)"
          bad=1
        fi
        ;;
    esac
  done <<<"$recs"
  # the Secrets the Pod references are exactly the expected ones (none outside the fixture)
  # shellcheck disable=SC2086  # the names hold no blanks; split on purpose
  if [ "$(norm_set $refs)" != "$(norm_set $EXPECTED_EVIDENCE_SECRETS)" ]; then
    violation E-scope "the ctf-evidence-* Secrets the Pod references [${refs# }] are not the expected [${EXPECTED_EVIDENCE_SECRETS}]"
    bad=1
  fi
  for nm in $refs; do
    n="$(awk -F'\t' -v s="$nm" '$1 == "V" && $3 == s { n++ } END { print n + 0 }' <<<"$recs")"
    if [ "$n" != "1" ]; then
      violation E-scope "the Secret '${nm}' is the secretName of ${n} volumes (want exactly 1)"
      bad=1
    fi
  done
  while IFS=$'\t' read -r kind a b c e; do
    [ "$kind" = "M" ] || continue
    # a=container b=volume c=mountPath e=readOnly
    case "$c" in
      /opt/ctf/evidence-src|/opt/ctf/evidence-src/*)
        if [ "$a" != "plant" ]; then
          violation E-scope "container '${a}' mounts ${c} (the evidence Secrets are mounted in the plant initContainer only)"
          bad=1
        fi
        ;;
    esac
    case " ${evv} " in
      *" ${b}="*)
        sn="${evv#* ${b}=}"
        sn="${sn%% *}"
        mcount="${mcount} ${b}"
        if [ "$a" != "plant" ]; then
          violation E-scope "container '${a}' mounts the evidence volume '${b}' (${sn}); only the plant initContainer may"
          bad=1
        else
          if [ "$c" != "/opt/ctf/evidence-src/${sn#ctf-evidence-}" ]; then
            violation E-scope "plant mounts '${b}' (${sn}) at '${c}', want /opt/ctf/evidence-src/${sn#ctf-evidence-}"
            bad=1
          fi
          if [ "$e" != "true" ]; then
            violation E-scope "plant mounts '${b}' (${sn}) with readOnly '${e}', want true"
            bad=1
          fi
        fi
        ;;
    esac
  done <<<"$recs"
  for nm in $evv; do
    b="${nm%%=*}"
    # shellcheck disable=SC2086  # the volume names hold no blanks; split on purpose
    n="$(printf '%s\n' $mcount | grep -cxF -- "$b" || true)"
    if [ "$n" != "1" ]; then
      violation E-scope "the evidence volume '${b}' is mounted ${n} times (want exactly 1, by plant)"
      bad=1
    fi
  done
  stray="$(grep -vE '^[[:space:]]*#' <<<"$pod_doc" | grep -n 'ctf-evidence-' | grep -vE '^[0-9]+:        secretName: ctf-evidence-' || true)"
  if [ -n "$stray" ]; then
    violation E-scope "ctf-evidence- appears in the Pod outside a volume's secretName (an envFrom / secretKeyRef / env door):"$'\n'"$stray"
    bad=1
  fi
  [ "$bad" -eq 0 ] && ok E-scope "no ctf-evidence-* Secret is rendered; the referenced [${refs# }] are mounted in plant only, readOnly, at /opt/ctf/evidence-src/<cid>, with no optional, and named nowhere else in the Pod"
  return 0
}

# The `sh -c` script of the plant initContainer, unindented. Empty when its command is
# not the literal-block form pod.yaml renders when there is evidence.
plant_script_text() { # $1=the plant container's block
  awk '
    on && /^          / { sub(/^          /, ""); print; next }
    on && /^ *$/ { print ""; next }
    on { exit }
    $0 == "        - |" { on = 1 }
  ' <<<"$(block_of "$1" "      command:")"
}

# V43 (A5b), only in a scope that set EVIDENCE_FIXTURE_DIR: the copy lines the CHART
# rendered. (1) the plant script passes gen-values.sh's check_2_7 (rule 2-7(a)) against
# the scope's evidence map; (2) it ENDS with exactly the lines
# `gen-values.sh --render-evidence-copy` prints for each challenge in id order, files in
# byte order (LC_ALL=C sort here, the chart's sortAlpha there): the shape, the chmod and
# the order, byte for byte. The expected text is never built here from a format string.
assert_evidence_copy() { # $1=label $2=the plant container's block
  [ -n "$EVIDENCE_FIXTURE_DIR" ] || return 0
  local label="$1" script f out expected="" cid names sorted mdir piece
  script="$(plant_script_text "$2")"
  if [ -z "$script" ]; then
    violation E-copy "no sh -c script (command: - sh / - -c / - |) could be read from the plant initContainer, so its copy lines were not judged"
    return
  fi
  f="$(mktemp "${EVIDENCE_FIXTURE_DIR}/script.XXXXXX")"
  printf '%s\n' "$script" >"$f"
  if out="$("$GEN_VALUES" --check-seed-script "$label" "$f" "${EVIDENCE_FIXTURE_DIR}/map" 2>&1)"; then
    ok E-2-7 "the plant script passes gen-values.sh's 2-7 (a copy source is /opt/ctf/evidence-src/<cid>/<plain file name>, no flag, into the mount of that challenge)"
  else
    violation E-2-7 "the plant script is rejected by ${GEN_VALUES} --check-seed-script:"$'\n'"$out"
  fi
  while IFS=$'\t' read -r cid names; do
    [ -z "$cid" ] && continue
    mdir="$(awk -F'\t' -v c="$cid" '$2 == c { print $1; exit }' "${EVIDENCE_FIXTURE_DIR}/map")"
    # shellcheck disable=SC2086  # the names hold no blanks; split on purpose
    sorted="$(printf '%s\n' $names | LC_ALL=C sort | tr '\n' ' ')"
    # shellcheck disable=SC2086
    if ! piece="$("$GEN_VALUES" --render-evidence-copy "$cid" "$mdir" $sorted)"; then
      violation E-copy "${GEN_VALUES} --render-evidence-copy failed for ${cid} (mountDir '${mdir}')"
      return
    fi
    expected="${expected}${piece}"$'\n'
  done <<<"$EVIDENCE_FIXTURE_FILES"
  expected="${expected%$'\n'}"
  if [ -z "$expected" ]; then
    violation E-copy "no expected copy line was built (EVIDENCE_FIXTURE_FILES is empty: the comparison would be vacuous)"
    return
  fi
  case "$script" in
    *$'\n'"$expected") ok E-copy "the plant script ends with exactly the copy lines render_evidence_copy prints for each challenge (byte order of ids and names)" ;;
    *) violation E-copy "the plant script does not end with exactly the copy lines render_evidence_copy prints (expected tail, then the script's own tail):"$'\n'"$expected"$'\n'"-----"$'\n'"$(tail -n 8 <<<"$script")" ;;
  esac
}

# ADR-0056 A5d: a real scope (values-all, a scenario) whose values file marks an
# investigate challenge is rendered with the names of that challenge's PUBLIC practice
# bundle, the bundle deploy-user.sh's practice path deploys:
# <root>/<cid>/<edition>/<practice>/<evidence>/ (the literals above; answers.tsv and
# digests.tsv beside that directory are not the bundle, so they are never a name). Neither
# rule is written here again: the scope is read by evidence_scope_cids and the names are
# listed (byte order) by evidence_sorted_names, the two functions deploy-user.sh uses, and
# the names reach the chart in the form deploy-user.sh passes them
# (--set-string evidence.challenges.<cid>.names[<i>]). The Secrets the Pod must reference
# are then ctf-evidence-<cid> for exactly those challenges (assert_evidence_scope). Which
# challenges ARE investigate is gen-values.sh's derivation, written into the values file;
# V53 (internal/catalog/evidence_mount_parity_test.go) holds it to the Go catalog.
# Sets SCOPE_EVIDENCE_ARGS and EXPECTED_EVIDENCE_SECRETS (both empty for a scope without an
# investigate challenge); rc 1 after a violation (the scope is then not rendered).
SCOPE_EVIDENCE_ARGS=()
scope_practice_evidence() { # $1=values file $2=challenges root
  local values="$1" root="$2" cids cid bundle names n i
  local -a nm=()
  SCOPE_EVIDENCE_ARGS=()
  EXPECTED_EVIDENCE_SECRETS=""
  if ! cids="$(evidence_scope_cids "$values")"; then
    violation A5d-names "an evidence entry of ${values} is not in the form gen-values.sh writes, so the investigate challenges of the scope cannot be read"
    return 1
  fi
  while IFS= read -r cid; do
    [ -n "$cid" ] || continue
    bundle="${root}/${cid}/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}"
    if [ -L "$bundle" ]; then
      violation A5d-names "the practice bundle of ${cid} (${bundle}) is a link (refused)"
      return 1
    fi
    if [ ! -d "$bundle" ]; then
      violation A5d-names "the investigate challenge ${cid} of this scope has no practice bundle (${bundle} is not a directory)"
      return 1
    fi
    if ! names="$(evidence_sorted_names "$bundle")"; then
      violation A5d-names "the practice bundle of ${cid} cannot be listed (a name holds a TAB or a LF)"
      return 1
    fi
    if [ -z "$names" ]; then
      violation A5d-names "the practice bundle of ${cid} holds no file"
      return 1
    fi
    # Before a name becomes a helm argument (a `,` or `=` in it would set another value):
    # every entry is a regular file, not a link or a directory (evidence_bundle_digest,
    # the definition deploy-user.sh's digest check uses, refuses anything else), and every
    # name is of B2's grammar (asked of gen-values.sh: EVIDENCE_NAME_RE, which V52 holds to
    # edition.NamePattern, the definition deploy-user.sh's EVIDENCE_NAME_PATTERN is held to
    # by V58). Neither rule is written here.
    if ! evidence_bundle_digest "$bundle" >/dev/null; then
      violation A5d-names "the practice bundle of ${cid} holds an entry that is not a regular file (a link or a directory)"
      return 1
    fi
    nm=()
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      nm+=("$n")
    done <<<"$names"
    if ! "$GEN_VALUES" --check-evidence-names "${nm[@]}"; then
      violation A5d-names "the practice bundle of ${cid} holds a file name outside ADR-0056 B2's grammar (see above)"
      return 1
    fi
    i=0
    for n in "${nm[@]}"; do
      SCOPE_EVIDENCE_ARGS+=(--set-string "evidence.challenges.${cid}.names[${i}]=${n}")
      i=$((i + 1))
    done
    EXPECTED_EVIDENCE_SECRETS="${EXPECTED_EVIDENCE_SECRETS:+${EXPECTED_EVIDENCE_SECRETS} }ctf-evidence-${cid}"
  done <<<"$cids"
  return 0
}

# ev_practice_tree <cid> <root> <file name>...: a practice edition of <cid> under <root>, the
# bundle files under its evidence directory and the two files beside it that are not the
# bundle (placeholders only)
ev_practice_tree() {
  local f pd
  pd="${2}/${1}/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}"
  mkdir -p "${pd}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}"
  shift 2
  for f in "$@"; do printf 'placeholder %s\n' "$f" >"${pd}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}/${f}"; done
  printf 'placeholder, not the bundle\n' >"${pd}/${EVIDENCE_PRACTICE_ANSWERS}"
  printf 'placeholder, not the bundle\n' >"${pd}/${EVIDENCE_PRACTICE_DIGESTS}"
}

# expect_names_refused <label> <marker> <values file> <practice root>: scope_practice_evidence
# refuses, with a FAIL line that says <marker>; the RC of the run is left as it was
expect_names_refused() {
  local label="$1" marker="$2" saved="$RC" out line found=0
  out="$(mktemp "${EVF_TMP}/names.XXXXXX")"
  RC=0
  if scope_practice_evidence "$3" "$4" 2>"$out"; then
    RC="$saved"
    violation A5d "${label}: the names were derived (want a refusal saying '${marker}')"
    return 0
  fi
  while IFS= read -r line; do
    case "$line" in *'FAIL ['*"$marker"*) found=1 ;; esac
  done <"$out"
  if [ "$RC" -eq 0 ] || [ "$found" -eq 0 ]; then
    RC="$saved"
    violation A5d "${label}: refused, but not with a FAIL line saying '${marker}':"$'\n'"$(head -5 "$out")"
  else
    RC="$saved"
    ok A5d "${label}: refused (${marker})"
  fi
  SCOPE_EVIDENCE_ARGS=()
  EXPECTED_EVIDENCE_SECRETS=""
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
  check_scope_manifest "$label" "$manifest"
}

# Every per-scope assertion over an already-rendered manifest (run_scope renders;
# the evidence fixture also feeds it deliberately mutated renders, which must come
# out red: expect_red below).
check_scope_manifest() { # $1=label, $2=the rendered manifest text
  local label="$1" manifest="$2"
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
  # Container names `plant` / `challenge` are also referenced by platform's Falco customRules (contract table, "Falco custom rule override" row in .claude/rules/falco-ctf-app-conventions.md): rename only in a both-repos PR.
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
  assert_plant_seed_root_only "$plant_block" "$pod_doc"
  assert_ttyd_argv "$ttyd_block"
  assert_no_overlay_noop "$plant_block" "$challenge_block"
  assert_role "${role_doc:-}"
  assert_missions_scope "$pod_doc" "$challenge_block"
  assert_evidence_scope "$pod_doc"
  assert_evidence_copy "$label" "$plant_block"
}

# ---------------------------------------------------------------------------
# ADR-0056 V43 / V50 (A5b): the evidence fixture. Two investigate challenges (40-ev,
# 41-ev; gen-values.sh generates their plant.mounts and seed script), bundled with
# file names whose byte order is not the order of a locale's collation, rendered by
# the chart, which is given the NAMES only (addendum 6: the Secrets are created by
# deploy-user.sh, never rendered here). Positive: the Secret references, the mounts
# and the copy lines (check_scope_manifest with EVIDENCE_*), and no bundle content in
# anything helm sees (V50). Negative: the chart's `fail`s, and mutated renders that
# the same assertions must turn red (a check that cannot fail proves nothing).
# ---------------------------------------------------------------------------

ev_header() { printf 'evidence:\n  challenges:\n'; }

ev_block() { # <cid> <file name>... -> evidence.challenges.<cid> of a values file: the NAMES only (the chart never sees a content)
  local cid="$1" f
  shift
  printf '    "%s":\n      names:\n' "$cid"
  for f in "$@"; do printf '        - "%s"\n' "$f"; done
}

ev_mounts() { # <NN>... -> a values file whose plant.mounts has one evidence mount per challenge <NN>-ev (a minimal seedScript)
  local n
  printf 'plant:\n  seedScript: [sh, -c, "set -eu\\n"]\n  mounts:\n'
  for n in "$@"; do
    printf '    - path: /opt/fx/ev%s\n      readOnly: true\n      evidence: true\n      challenge: %s-ev\n' "$n" "$n"
  done
}

ev_plant_head() { # <seedScript, as YAML> -> the start of a values file's plant: block; ev_entry lines follow
  printf 'plant:\n  seedScript: %s\n  mounts:\n' "$1"
}

ev_entry() { # <path> <evidence YAML value> <challenge YAML value> -> one plant.mounts entry, values verbatim
  printf '    - path: %s\n      readOnly: true\n      evidence: %s\n      challenge: %s\n' "$1" "$2" "$3"
}

expect_render_fail() { # <label> <marker> <helm template args...>
  local label="$1" marker="$2" out
  shift 2
  if out="$(helm template "$CHART_DIR" "$@" 2>&1)"; then
    violation V43 "${label}: helm template ACCEPTED this input (want a template-time fail saying '${marker}')"
  elif ! grep -qF -- "$marker" <<<"$out"; then
    violation V43 "${label}: helm template failed, but not with '${marker}':"$'\n'"$(head -c 400 <<<"$out")"
  else
    ok V43 "${label}: refused (${marker})"
  fi
}

expect_render_ok() { # <label> <helm template args...>
  local label="$1" out
  shift
  if out="$(helm template "$CHART_DIR" "$@" 2>&1)"; then
    ok V43 "${label}: renders"
  else
    violation V43 "${label}: helm template failed:"$'\n'"$(head -c 400 <<<"$out")"
  fi
}

# <label> <marker> <awk program> <rendered manifest>: the program mutates the manifest
# (a mutation that changes nothing is a failure of this case, not a pass), and
# check_scope_manifest must then raise a violation that says <marker>.
expect_red() {
  local label="$1" marker="$2" prog="$3" manifest="$4" mutated saved out
  mutated="$(awk "$prog" <<<"$manifest")"
  if [ "$mutated" = "$manifest" ]; then
    violation V43 "mutant '${label}': the mutation changed nothing (the render has no such line, so this case proves nothing)"
    return
  fi
  saved="$RC"
  RC=0
  out="$(mktemp "${EVIDENCE_FIXTURE_DIR}/red.XXXXXX")"
  # `|| true`: an assert that ends with a non-zero status (a `[ ... ] && ...` on its
  # last line, say) must not stop the whole script under `set -e` with no diagnosis;
  # the verdict is RC, which violation() sets. (Inside a `||` list `set -e` is off for
  # the function body, so a failing command in it does not abort it either.)
  check_scope_manifest "mutant: ${label}" "$mutated" >"$out" 2>&1 || true
  if [ "$RC" -eq 0 ]; then
    RC="$saved"
    violation V43 "mutant '${label}' was ACCEPTED by every assertion (the check cannot fail)"
  elif ! grep -F 'FAIL [' "$out" | grep -qF -- "$marker"; then
    # only a `FAIL [` line counts: an `ok` line (always printed) must never satisfy a marker
    RC="$saved"
    violation V43 "mutant '${label}' was refused, but not for '${marker}':"$'\n'"$(grep -F 'FAIL' "$out" | head -5)"
  else
    RC="$saved"
    ok V43 "mutant '${label}' is refused (${marker})"
  fi
}

run_evidence_fixtures() {
  local -a base many
  local manifest i long bad out
  EVF_TMP="$(mktemp -d)"
  trap 'rm -rf "${EVF_TMP}"' EXIT
  echo "== evidence fixture (ADR-0056 V43): two investigate challenges =="
  if ! "$GEN_VALUES" --emit-evidence-fixture "$EVF_TMP"; then
    violation V43 "${GEN_VALUES} --emit-evidence-fixture failed: no fixture to render"
    return
  fi
  if [ "$(grep -c 'evidence: true' "${EVF_TMP}/values.yaml" || true)" != "2" ] || [ "$(grep -c . "${EVF_TMP}/map" || true)" != "2" ]; then
    violation V43 "the generated fixture does not hold two evidence mounts and a two-line map (the contract with gen-values.sh changed, or the emit is broken)"
    return
  fi
  base=(-f "${EVF_TMP}/values.yaml" --set challengeId=40-ev)

  # positive. a_b.log / a.log / a-b.log / a1.log: byte order is a-b.log a.log a1.log a_b.log
  {
    ev_header
    ev_block 40-ev a_b.log a.log a-b.log a1.log
    ev_block 41-ev b.txt a.txt
  } >"${EVF_TMP}/files.yaml"
  # V50: the bundle's CONTENT exists only in a directory helm is never given
  # (deploy-user.sh makes the Secrets from it); every file holds the sentinel
  mkdir -p "${EVF_TMP}/bundle/40-ev" "${EVF_TMP}/bundle/41-ev"
  for i in a_b.log a.log a-b.log a1.log; do printf '%s\n' "$EVIDENCE_SENTINEL" >"${EVF_TMP}/bundle/40-ev/${i}"; done
  for i in b.txt a.txt; do printf '%s\n' "$EVIDENCE_SENTINEL" >"${EVF_TMP}/bundle/41-ev/${i}"; done
  EXPECTED_EVIDENCE_SECRETS="ctf-evidence-40-ev ctf-evidence-41-ev"
  EVIDENCE_FIXTURE_DIR="$EVF_TMP"
  EVIDENCE_FIXTURE_FILES="40-ev"$'\t'"a_b.log a.log a-b.log a1.log"$'\n'"41-ev"$'\t'"b.txt a.txt"
  EVIDENCE_TREE="${EVF_TMP}/tree"
  echo "   helm template ${CHART_DIR} ${base[*]} -f files.yaml"
  if ! manifest="$(helm template "$CHART_DIR" "${base[@]}" -f "${EVF_TMP}/files.yaml" 2>&1)"; then
    violation RENDER "helm template failed for the evidence fixture:"$'\n'"$manifest"
  else
    check_scope_manifest "evidence fixture (two investigate challenges)" "$manifest"
    # A regression guard of how this fixture is built, NOT the evidence for V50: the
    # bundle's files are never handed to helm, so this cannot fail by itself. V50's
    # evidence is the case below (a values file that carries content is refused, and the
    # refusal does not echo it) and deploy-user.sh's V49 (A5c).
    if grep -rqF -- "$EVIDENCE_SENTINEL" "${EVF_TMP}/values.yaml" "${EVF_TMP}/files.yaml" || grep -qF -- "$EVIDENCE_SENTINEL" <<<"$manifest"; then
      violation V50 "fixture guard: the bundle's sentinel appears in a values file given to helm or in the rendered manifest (the fixture was built wrongly, or a bundle's content reached the chart)"
    else
      ok V50 "fixture guard (not the V50 evidence): the bundle sentinel is in no values file given to helm and not in the rendered manifest"
    fi
    expect_red "the chart renders an evidence Secret" "the chart renders the Secret" \
      'BEGIN { d = 0 } { print } END { print "---"; print "apiVersion: v1"; print "kind: Secret"; print "metadata:"; print "  name: ctf-evidence-40-ev"; print "type: Opaque" }' "$manifest"
    expect_red "an evidence volume is optional" "has optional: " \
      '/^        secretName: ctf-evidence-/ && !d { print; print "        optional: true"; d = 1; next } { print }' "$manifest"
    # mutated renders: each must be refused, for its own reason
    expect_red "a plain cp becomes cp -a" "FAIL [E-2-7]: the plant script is rejected by" \
      '!d && /^ *cp "\/opt\/ctf\/evidence-src\// { sub(/cp "/, "cp -a \""); d = 1 } { print }' "$manifest"
    expect_red "a chmod mode changes" "does not end with exactly" \
      '!d && /^ *chmod 0444 / { sub(/0444/, "0777"); d = 1 } { print }' "$manifest"
    expect_red "the first chmod line is dropped (its cp stays)" "does not end with exactly" \
      '!d && /^ *chmod 0444 / { d = 1; next } { print }' "$manifest"
    expect_red "the first cp line is dropped (its chmod stays)" "does not end with exactly" \
      '!d && /^ *cp "\/opt\/ctf\/evidence-src\// { d = 1; next } { print }' "$manifest"
    expect_red "challenge mounts an evidence Secret volume, mountPath first" "does not start with \`- name:\`" \
      '/^    - name: / { cont = $0 } cont ~ /name: challenge$/ && !d && /^      volumeMounts:$/ { print; print "        - mountPath: /opt/ctf/evidence-src/40-ev"; print "          name: evidence-0"; print "          readOnly: true"; d = 1; next } { print }' "$manifest"
    expect_red "challenge mounts an evidence Secret volume" "mounts the evidence volume" \
      '/^    - name: / { cont = $0 } cont ~ /name: challenge$/ && !d && /^      volumeMounts:$/ { print; print "        - name: evidence-0"; print "          mountPath: /opt/ctf/evidence-src/40-ev"; print "          readOnly: true"; d = 1; next } { print }' "$manifest"
    expect_red "challenge takes an evidence Secret through envFrom" "outside a volume's secretName" \
      '/^    - name: challenge$/ && !d { print; print "      envFrom:"; print "        - secretRef:"; print "            name: ctf-evidence-40-ev"; d = 1; next } { print }' "$manifest"
    expect_red "plant mounts an evidence Secret without readOnly" "with readOnly" \
      '!d && /^          mountPath: \/opt\/ctf\/evidence-src\// { print; getline; if ($0 ~ /readOnly: true/) { d = 1; next } } { print }' "$manifest"
  fi
  EXPECTED_EVIDENCE_SECRETS=""
  EVIDENCE_FIXTURE_DIR=""
  EVIDENCE_FIXTURE_FILES=""
  EVIDENCE_TREE=""

  # A5d: the names of a real scope come from the practice bundles (scope_practice_evidence),
  # exercised here over the generated fixture's values (no investigate challenge is in the
  # repo yet, so the real scopes above derive nothing). The bundle's names are passed, in
  # byte order, and the two files beside the bundle are not; the Secrets expected are
  # exactly the scope's; the render with those names passes every assertion above,
  # including the copy lines.
  local want_args a leaked=0
  ev_practice_tree 40-ev "${EVF_TMP}/pr" a_b.log a.log a-b.log a1.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr" b.txt a.txt
  want_args="--set-string evidence.challenges.40-ev.names[0]=a-b.log --set-string evidence.challenges.40-ev.names[1]=a.log --set-string evidence.challenges.40-ev.names[2]=a1.log --set-string evidence.challenges.40-ev.names[3]=a_b.log --set-string evidence.challenges.41-ev.names[0]=a.txt --set-string evidence.challenges.41-ev.names[1]=b.txt"
  if scope_practice_evidence "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr"; then
    for a in ${SCOPE_EVIDENCE_ARGS[@]+"${SCOPE_EVIDENCE_ARGS[@]}"}; do
      case "$a" in *"=${EVIDENCE_PRACTICE_ANSWERS}" | *"=${EVIDENCE_PRACTICE_DIGESTS}") leaked=1 ;; esac
    done
    if [ "$leaked" -ne 0 ]; then
      violation A5d "a file beside the practice bundle (${EVIDENCE_PRACTICE_ANSWERS} / ${EVIDENCE_PRACTICE_DIGESTS}) became a name"
    elif [ "${SCOPE_EVIDENCE_ARGS[*]+${SCOPE_EVIDENCE_ARGS[*]}}" != "$want_args" ]; then
      violation A5d "the names derived from the practice bundles are not the bundles' files in byte order:"$'\n'"got:  ${SCOPE_EVIDENCE_ARGS[*]+${SCOPE_EVIDENCE_ARGS[*]}}"$'\n'"want: ${want_args}"
    else
      ok A5d "the names are the practice bundles' files in byte order, the files beside the bundle are not among them"
    fi
    # shellcheck disable=SC2086  # the names hold no blanks; split on purpose
    if [ "$(norm_set $EXPECTED_EVIDENCE_SECRETS)" != "$(norm_set ctf-evidence-40-ev ctf-evidence-41-ev)" ]; then
      violation A5d "the Secrets expected of the scope are [${EXPECTED_EVIDENCE_SECRETS}], want exactly ctf-evidence-40-ev ctf-evidence-41-ev"
    else
      ok A5d "the Secrets expected of the scope are ctf-evidence-<cid> of exactly its investigate challenges"
    fi
    EVIDENCE_FIXTURE_DIR="$EVF_TMP"
    EVIDENCE_FIXTURE_FILES="40-ev"$'\t'"a_b.log a.log a-b.log a1.log"$'\n'"41-ev"$'\t'"b.txt a.txt"
    EVIDENCE_TREE="${EVF_TMP}/tree"
    if ! manifest="$(helm template "$CHART_DIR" "${base[@]}" ${SCOPE_EVIDENCE_ARGS[@]+"${SCOPE_EVIDENCE_ARGS[@]}"} 2>&1)"; then
      violation RENDER "helm template failed for the practice names of the evidence fixture:"$'\n'"$manifest"
    else
      check_scope_manifest "evidence fixture, names from the practice bundles (A5d)" "$manifest"
    fi
  fi
  SCOPE_EVIDENCE_ARGS=()
  EXPECTED_EVIDENCE_SECRETS=""
  EVIDENCE_FIXTURE_DIR=""
  EVIDENCE_FIXTURE_FILES=""
  EVIDENCE_TREE=""
  # and it refuses, for its own reason each: a challenge of the scope with no practice
  # bundle, a bundle that is a link, an empty bundle, a values file it cannot read
  ev_practice_tree 40-ev "${EVF_TMP}/pr-one" a.log
  expect_names_refused "a challenge of the scope with no practice bundle" "has no practice bundle" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-one"
  ev_practice_tree 40-ev "${EVF_TMP}/pr-link" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-link" b.txt
  rm -rf "${EVF_TMP}/pr-link/41-ev/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}"
  ln -s "${EVF_TMP}/pr-link/40-ev/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}" "${EVF_TMP}/pr-link/41-ev/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}"
  expect_names_refused "a practice bundle that is a link" "is a link" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-link"
  ev_practice_tree 40-ev "${EVF_TMP}/pr-empty" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-empty"
  expect_names_refused "an empty practice bundle" "holds no file" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-empty"
  printf 'plant:\n  mounts:\n    - path: /opt/fx/evidence-a\n      readOnly: true\n      evidence: "true"\n      challenge: 40-ev\n' >"${EVF_TMP}/badscope.yaml"
  expect_names_refused "a values file whose evidence entry is not in gen-values.sh's form" "is not in the form gen-values.sh writes" "${EVF_TMP}/badscope.yaml" "${EVF_TMP}/pr"
  # a name that would set another helm value, or is outside B2; an entry that is not a
  # regular file: refused before any name becomes an argument
  ev_practice_tree 40-ev "${EVF_TMP}/pr-comma" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-comma" 'b.txt,plant.seedScript[2]=x'
  expect_names_refused "a practice file name with a comma" "outside ADR-0056 B2's grammar" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-comma"
  ev_practice_tree 40-ev "${EVF_TMP}/pr-equals" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-equals" 'b=x.txt'
  expect_names_refused "a practice file name with an equals sign" "outside ADR-0056 B2's grammar" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-equals"
  ev_practice_tree 40-ev "${EVF_TMP}/pr-upper" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-upper" B.txt
  expect_names_refused "a practice file name outside B2 (upper case)" "outside ADR-0056 B2's grammar" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-upper"
  ev_practice_tree 40-ev "${EVF_TMP}/pr-symlink" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-symlink" b.txt
  ln -s b.txt "${EVF_TMP}/pr-symlink/41-ev/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}/c.txt"
  expect_names_refused "a symlink in a practice bundle" "is not a regular file" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-symlink"
  ev_practice_tree 40-ev "${EVF_TMP}/pr-subdir" a.log
  ev_practice_tree 41-ev "${EVF_TMP}/pr-subdir" b.txt
  mkdir -p "${EVF_TMP}/pr-subdir/41-ev/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}/sub"
  expect_names_refused "a directory in a practice bundle" "is not a regular file" "${EVF_TMP}/values.yaml" "${EVF_TMP}/pr-subdir"

  # negative: the chart's `fail`s (V8, V43)
  { ev_header; ev_block 40-ev x.log; ev_block 42-xx y.log; } >"${EVF_TMP}/shifted.yaml"
  expect_render_fail "a values key moved off its mount's challenge (41-ev -> 42-xx)" "are not the same set" "${base[@]}" -f "${EVF_TMP}/shifted.yaml"
  { ev_header; ev_block 40-ev x.log; } >"${EVF_TMP}/one.yaml"
  expect_render_fail "a mount with no bundle" "are not the same set" "${base[@]}" -f "${EVF_TMP}/one.yaml"
  expect_render_fail "a bundle with no mount (plant.mounts empty)" "are not the same set" --set challengeId=02-credential-files -f "${EVF_TMP}/files.yaml"
  many=()
  for i in $(seq 1 65); do many+=("f${i}.log"); done
  { ev_header; ev_block 40-ev "${many[@]:0:64}"; ev_block 41-ev b.txt; } >"${EVF_TMP}/n64.yaml"
  { ev_header; ev_block 40-ev "${many[@]}"; ev_block 41-ev b.txt; } >"${EVF_TMP}/n65.yaml"
  expect_render_ok "64 names in one challenge" "${base[@]}" -f "${EVF_TMP}/n64.yaml"
  expect_render_fail "65 names in one challenge" "has 65 names" "${base[@]}" -f "${EVF_TMP}/n65.yaml"
  long="$(printf '%064d' 0 | tr 0 a)"
  for bad in 'A.log' '-a' '.a' '..' 'a b' 'a$b' 'a/b' "$long"; do
    { ev_header; ev_block 40-ev "$bad"; ev_block 41-ev b.txt; } >"${EVF_TMP}/badname.yaml"
    expect_render_fail "the file name '${bad}'" "has the file name" "${base[@]}" -f "${EVF_TMP}/badname.yaml"
  done
  # the top of the name grammar: 63 characters render
  { ev_header; ev_block 40-ev "${long%a}"; ev_block 41-ev b.txt; } >"${EVF_TMP}/name63.yaml"
  expect_render_ok "a file name of 63 characters" "${base[@]}" -f "${EVF_TMP}/name63.yaml"
  { ev_header; ev_block 40-ev a.log a.log; ev_block 41-ev b.txt; } >"${EVF_TMP}/dupname.yaml"
  expect_render_fail "a file name listed twice" "lists the file name" "${base[@]}" -f "${EVF_TMP}/dupname.yaml"
  printf 'evidence:\n  challenges:\n    "40-ev":\n      names: [123]\n    "41-ev":\n      names: ["b.txt"]\n' >"${EVF_TMP}/num.yaml"
  expect_render_fail "a name that is not a string" "has an entry that is not a string" "${base[@]}" -f "${EVF_TMP}/num.yaml"
  printf 'evidence:\n  challenges:\n    "40-ev":\n      names: ["a.log"]\n      mode: "0777"\n    "41-ev":\n      names: ["b.txt"]\n' >"${EVF_TMP}/extra.yaml"
  expect_render_fail "a key beside names" "must have the single key" "${base[@]}" -f "${EVF_TMP}/extra.yaml"
  # V50: a bundle's CONTENT handed to the chart (the old `files` shape) is refused, and
  # the refusal does not echo it
  printf 'evidence:\n  challenges:\n    "40-ev":\n      names: ["a.log"]\n      files: {"a.log": "%s"}\n    "41-ev":\n      names: ["b.txt"]\n' "$EVIDENCE_SENTINEL" >"${EVF_TMP}/content.yaml"
  if out="$(helm template "$CHART_DIR" "${base[@]}" -f "${EVF_TMP}/content.yaml" 2>&1)"; then
    violation V50 "helm template ACCEPTED a values file that carries a bundle's content (evidence.challenges.<cid>.files)"
  elif grep -qF -- "$EVIDENCE_SENTINEL" <<<"$out"; then
    violation V50 "helm template refused a values file that carries a bundle's content, but its message echoes the content"
  elif ! grep -qF -- "must have the single key" <<<"$out"; then
    violation V50 "helm template failed on a values file that carries a bundle's content, but not with 'must have the single key'"
  else
    ok V50 "a values file that carries a bundle's content is refused, and the message does not echo it"
  fi

  # One case per reachable `fail` of ctf-user.evidence.check (20 `fail`s), each by a
  # marker only that `fail` prints. The id-grammar `fail` on an evidence.challenges KEY
  # has no case: the key set must equal the mounts' challenge ids, which the mount loop
  # has already held to the same grammar, so it cannot be reached (defence in depth).
  local ss='[sh, -c, "set -eu\n"]' one="${EVF_TMP}/one.yaml" cf
  cf="${EVF_TMP}/case.yaml"
  { ev_plant_head "$ss"; ev_entry /opt/fx/ev40 '"true"' 40-ev; } >"$cf"
  expect_render_fail "plant.mounts evidence is the string \"true\"" "that is not the boolean true" --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head "$ss"; ev_entry /opt/fx/ev40 true 40; } >"$cf"
  expect_render_fail "plant.mounts challenge is a number" "but has no string" --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head "$ss"; ev_entry /opt/fx/ev40 true BAD; } >"$cf"
  expect_render_fail "plant.mounts challenge is not an id" 'challenge "BAD" is not a challenge id' --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head "$ss"; ev_entry /opt/fx/ev40 true 40-ev; ev_entry /opt/fx/ev41 true 40-ev; } >"$cf"
  expect_render_fail "two evidence mounts for one challenge" "more than one evidence entry" --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head "$ss"; ev_entry 123 true 40-ev; } >"$cf"
  expect_render_fail "plant.mounts path is a number" "has no string path" --set challengeId=40-ev -f "$cf" -f "$one"
  ev_mounts 40 >"${EVF_TMP}/mounts1.yaml"
  printf 'evidence:\n  challenges: "x"\n' >"$cf"
  expect_render_fail "evidence.challenges is not a map" "must be a map of challenge id" --set challengeId=40-ev -f "${EVF_TMP}/mounts1.yaml" -f "$cf"
  printf 'evidence:\n  challenges:\n    "40-ev": "x"\n' >"$cf"
  expect_render_fail "a challenge's bundle is not a map" "must be a map with the single key" --set challengeId=40-ev -f "${EVF_TMP}/mounts1.yaml" -f "$cf"
  printf 'evidence:\n  challenges:\n    "40-ev":\n      names: {"a.log": "x"}\n' >"$cf"
  expect_render_fail "names is not a list" "names must be a list of file names" --set challengeId=40-ev -f "${EVF_TMP}/mounts1.yaml" -f "$cf"
  printf 'evidence:\n  challenges:\n    "40-ev":\n      names: []\n' >"$cf"
  expect_render_fail "a challenge with no names" "has 0 names" --set challengeId=40-ev -f "${EVF_TMP}/mounts1.yaml" -f "$cf"
  { ev_plant_head '"set -eu"'; ev_entry /opt/fx/ev40 true 40-ev; } >"$cf"
  expect_render_fail "seedScript is not a list" "plant.seedScript must be a list" --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head '[sh, -c]'; ev_entry /opt/fx/ev40 true 40-ev; } >"$cf"
  expect_render_fail "seedScript has two elements" "must have 3 elements" --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head '[bash, -c, "set -eu\n"]'; ev_entry /opt/fx/ev40 true 40-ev; } >"$cf"
  expect_render_fail "seedScript does not start with sh" "elements must be sh, -c and a string" --set challengeId=40-ev -f "$cf" -f "$one"
  printf 'plant:\n  seedScript: [sh, -c, "set -eu\\n"]\n  mounts:\n    - path: "/opt/x$(id)"\n      readOnly: true\n      evidence: true\n      challenge: 40-ev\n' >"${EVF_TMP}/badpath.yaml"
  { ev_plant_head "$ss"; ev_entry /opt/fx/../ev true 40-ev; } >"$cf"
  expect_render_fail "an evidence mount path with a .. element" "is not an absolute path of" --set challengeId=40-ev -f "$cf" -f "$one"
  { ev_plant_head "$ss"; ev_entry /opt/fx/./ev true 40-ev; } >"$cf"
  expect_render_fail "an evidence mount path with a . element" "is not an absolute path of" --set challengeId=40-ev -f "$cf" -f "$one"
  expect_render_fail "an evidence mount path with a command substitution" "is not an absolute path of" --set challengeId=40-ev -f "${EVF_TMP}/badpath.yaml" -f "${EVF_TMP}/one.yaml"
  printf 'plant:\n  seedScript: [sh, -c, "true"]\n  mounts:\n    - path: /opt/fx/ev\n      readOnly: true\n      evidence: true\n      challenge: 40-ev\n' >"${EVF_TMP}/badscript.yaml"
  expect_render_fail "a seedScript that is not the generated one" "must start with" --set challengeId=40-ev -f "${EVF_TMP}/badscript.yaml" -f "${EVF_TMP}/one.yaml"
  # The size limits (512 KiB per challenge, 2 MiB in all) are not the chart's: it sees
  # names only. They are deploy-user.sh's (A5c, V49) and the validator's (B2).
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

# 1. all-missions (production default). ADR-0056 A5d: an investigate challenge of the
# scope is rendered with its practice bundle's names, and its Secret is expected
# (scope_practice_evidence; nothing while the repo has no investigate challenge).
if scope_practice_evidence challenges/values-all.yaml challenges; then
  run_scope "values-all (challengeId=all)" \
    -f challenges/values-all.yaml --set challengeId=all \
    --set-string challenge.flags.03-stealth-read="$PROBE_FLAG" \
    --set-string challenge.flags.05-silent-search="$PROBE_FLAG" \
    --set-string challenge.flags.10-final-exfil="$PROBE_FLAG" \
    ${SCOPE_EVIDENCE_ARGS[@]+"${SCOPE_EVIDENCE_ARGS[@]}"}
fi
SCOPE_EVIDENCE_ARGS=()
EXPECTED_EVIDENCE_SECRETS=""
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
  # ADR-0056 A5d: the scenario's investigate challenges, as for values-all above
  if scope_practice_evidence "$svalues" challenges; then
    run_scope "scenario (challengeId=scenario:${sname})" \
      -f "$svalues" --set "challengeId=scenario:${sname}" \
      ${flag_args:+"${flag_args[@]}"} \
      ${SCOPE_EVIDENCE_ARGS[@]+"${SCOPE_EVIDENCE_ARGS[@]}"}
  fi
  SCOPE_EVIDENCE_ARGS=()
  EXPECTED_EVIDENCE_SECRETS=""
  EXPECTED_SCENARIO_MISSIONS=""
  echo
done

run_evidence_fixtures
echo

assert_1_12
assert_1_13

echo
if [ "$RC" -eq 0 ]; then
  echo "OK: Verification 1 (1-1..1-21) passes for all render-matrix scopes (5 fixed + P27-1 scenario scopes)."
else
  echo "FAIL: Verification 1 violated — see FAIL lines above." >&2
fi
exit "$RC"
