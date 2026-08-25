#!/usr/bin/env bash
# ADR-0001 (Option B, Accepted) Verification 2-8 / DoD 15 + ADR-0007
# (Option 1) Verification 3: re-verify, at every build, that the build-time
# flag-plant snapshot baked into the challenge image (/opt/ctf/plant-seed/,
# images/challenge/Dockerfile, S-a) introduces zero new material and is
# byte-identical (mode/owner included) to the real directory it shadows —
# and, since ADR-0007 widened the snapshot from a single file
# (/etc/shadow) to the whole enclosing directory (/etc), that the ENTRY SET
# matches in both directions (not just "every snapshotted file has a real
# counterpart" — also "every real file has a snapshotted counterpart",
# which catches a `RUN` step landing AFTER the snapshot line and silently
# drifting the two apart).
#
# WHY THIS IS ITS OWN MAKE TARGET CALLED FROM `make build`, NOT JUST A CI
# STEP: prod is CI-free (operators run `make build` by hand — see
# Makefile:50-58, which is a plain list of `docker build`s with no
# post-build hook). A check that only lives in CI would leave prod
# ungated the same way F2 did before `assert-flag-isolation.sh` closed it.
# So this also runs from `make build` (fail-closed: a nonzero exit here
# fails `make build` itself) in addition to CI's build job.
#
# What "hygiene" means here, on the already-built `challenge` image
# (docker run, no cluster, no Falco, no scoring surface touched):
#   (i)   no crypt-hash-shaped string (":$<n>$...") anywhere under the
#         snapshot tree
#   (ii)  no `FALCO{` literal anywhere under the snapshot tree
#   (iii) every snapshotted file's mode+owner+content matches its real
#         counterpart byte-for-byte
#   (iv)  `find /etc -type f -links +1` is empty (a hardlinked file under
#         /etc would mean a future `cp -a` variant stopped being link-safe)
#   (v)   (ADR-0007 Verification 3) every REAL file under a snapshotted
#         top-level directory has a snapshot counterpart too — the reverse
#         of (iii), closing the entry-set gap a post-snapshot `RUN` could
#         otherwise open silently
#
# Usage:
#   ./scripts/check-image-hygiene.sh <image-ref>
#   (Makefile: `make check-image-hygiene` — builds the ref from
#   REGISTRY/TAG the same way `make build` does)
set -euo pipefail

IMAGE="${1:?usage: check-image-hygiene.sh <image-ref>}"

# The inspection script runs INSIDE the already-built image via `docker run`
# — this is a local, offline supply-chain check (no cluster, no k8s, no
# Falco monitoring context whatsoever), so using grep/find/stat freely here
# carries none of the deploy-path / assert-script restrictions in
# ADR-0001 §F3′ (those are about what runs inside a live workspace Pod).
INSPECT='
set -eu
rc=0
fail_file=/tmp/hygiene-fail
rm -f "$fail_file"

SNAP=/opt/ctf/plant-seed

# ADR-0007: these 3 paths are ALWAYS overwritten by the container runtime at
# every container start (docker run bind-mounts a fresh /etc/hosts,
# /etc/hostname, /etc/resolv.conf into every container regardless of image
# content; Kubernetes does the same, then further overlays kubelet-managed
# content on top when the directory itself is bind-mounted from an emptyDir
# at deploy time -- confirmed at the real workspace-Pod layer in
# docs/adr/0007-plant-mount-directory-granularity.md Section C3). Comparing
# a build-time snapshot against a live container means comparing the
# runtime-injected content from two DIFFERENT container instantiations, not
# a drift introduced by this Dockerfile -- it will always mismatch, in
# every image, forever, and carries no hash/flag material either way. Skip
# them entirely (not just skip content comparison -- mode and owner can
# differ too).
is_runtime_managed_etc_file() { # $1=absolute real path -> rc0 iff excluded
  case "$1" in
    /etc/hosts|/etc/hostname|/etc/resolv.conf) return 0 ;;
    *) return 1 ;;
  esac
}

if [ ! -d "$SNAP" ]; then
  echo "HYGIENE VIOLATION: $SNAP does not exist in this image" >&2
  touch "$fail_file"
fi

# (i) crypt-hash-shaped string anywhere under the snapshot tree
if [ -d "$SNAP" ] && grep -RE ":\\\$[0-9A-Za-z]+\\\$" "$SNAP" >/tmp/hygiene-hash-hits 2>/dev/null; then
  echo "HYGIENE VIOLATION (i): crypt-hash-shaped string found under $SNAP:" >&2
  cat /tmp/hygiene-hash-hits >&2
  touch "$fail_file"
fi

# (ii) FALCO{ literal anywhere under the snapshot tree
if [ -d "$SNAP" ] && grep -RF "FALCO{" "$SNAP" >/tmp/hygiene-flag-hits 2>/dev/null; then
  echo "HYGIENE VIOLATION (ii): FALCO{ literal found under $SNAP:" >&2
  cat /tmp/hygiene-flag-hits >&2
  touch "$fail_file"
fi

# (iii) mode+owner match between every snapshotted file and its real
# counterpart (the path with the $SNAP prefix stripped). Avoid a
# `find | while read` pipeline (the while-loop would run in a subshell in
# some shells, silently losing the fail_file write on `exit`) — iterate via
# a plain for-loop over find output instead (fixture tree is tiny, no
# filenames with spaces).
if [ -d "$SNAP" ]; then
  for f in $(find "$SNAP" -type f); do
    orig="${f#"$SNAP"}"
    if is_runtime_managed_etc_file "$orig"; then
      continue
    fi
    if [ ! -e "$orig" ]; then
      echo "HYGIENE VIOLATION (iii): snapshot file $f has no real counterpart at $orig" >&2
      touch "$fail_file"
      continue
    fi
    sm=$(stat -c "%a %U %G" "$f" 2>/dev/null || stat -f "%Lp %Su %Sg" "$f")
    om=$(stat -c "%a %U %G" "$orig" 2>/dev/null || stat -f "%Lp %Su %Sg" "$orig")
    if [ "$sm" != "$om" ]; then
      echo "HYGIENE VIOLATION (iii): mode/owner mismatch: $f ($sm) vs $orig ($om)" >&2
      touch "$fail_file"
    fi
    if ! cmp -s "$f" "$orig"; then
      echo "HYGIENE VIOLATION (iii): content mismatch: $f vs $orig (snapshot must be byte-identical)" >&2
      touch "$fail_file"
    fi
  done
fi

# (iv) no hardlinked file under /etc (a `cp -a` variant that started
# preserving links instead of copying content would create one)
links="$(find /etc -type f -links +1 2>/dev/null || true)"
if [ -n "$links" ]; then
  echo "HYGIENE VIOLATION (iv): /etc contains hardlinked file(s) (links>1):" >&2
  echo "$links" >&2
  touch "$fail_file"
fi

# (v) ADR-0007 Verification 3: entry-set parity in the OTHER direction —
# every REAL file under a directory this image snapshots must have a
# snapshot counterpart too. (iii) above only walks $SNAP and checks the
# real side exists; that alone cannot catch a `RUN` step added AFTER the
# snapshot line in the Dockerfile that adds/changes a file under the real
# directory without the snapshot ever seeing it. Scoped to the top-level
# directory names actually present under $SNAP (currently just "etc") so
# this generalizes to any future plant-target enclosing directory without
# a hardcoded list.
if [ -d "$SNAP" ]; then
  for d in "$SNAP"/*/; do
    [ -d "$d" ] || continue
    realdir="/${d#"$SNAP"/}"
    realdir="${realdir%/}"
    [ -d "$realdir" ] || continue
    for f in $(find "$realdir" -type f); do
      if is_runtime_managed_etc_file "$f"; then
        continue
      fi
      snap="$SNAP$f"
      if [ ! -e "$snap" ]; then
        echo "HYGIENE VIOLATION (v): real file $f has no snapshot counterpart at $snap (a RUN step after the snapshot line added/changed $realdir without updating the snapshot — entry-set drift)" >&2
        touch "$fail_file"
      fi
    done
  done
fi

[ -f "$fail_file" ] && rc=1
exit "$rc"
'

echo "==> check-image-hygiene: ${IMAGE}"
if docker run --rm --entrypoint sh "${IMAGE}" -c "${INSPECT}"; then
  echo "OK: ${IMAGE} — /opt/ctf/plant-seed/ hygiene verified (no hash/flag material, mode/owner/content/entry-set match in both directions, no hardlinks under /etc)."
  exit 0
else
  echo "FAIL: ${IMAGE} failed the image-hygiene check (ADR-0001 Verification 2-8 / ADR-0007 Verification 3) — see violations above." >&2
  exit 1
fi
