#!/usr/bin/env bash
# ADR-0001 (Option B, Accepted) Verification 2-8 / DoD 15: re-verify, at
# every build, that the build-time flag-plant snapshot baked into the
# challenge image (/opt/ctf/plant-seed/, images/challenge/Dockerfile, S-a)
# introduces zero new material and is byte-identical (mode/owner included)
# to the real path it shadows.
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
#   (iii) every snapshotted file's mode+owner matches its real counterpart
#         byte-for-byte
#   (iv)  `find /etc -type f -links +1` is empty (a hardlinked file under
#         /etc would mean a future `cp -a` variant stopped being link-safe)
#   (v)   ADR-0007 Verification 3: entry-SET completeness, both directions,
#         for every top-level directory under the snapshot (currently just
#         "etc" — images/challenge/Dockerfile now snapshots the whole /etc
#         tree, not a single file, per ADR-0007 Option 1). (iii) above only
#         ever walks files THE SNAPSHOT has and checks their real
#         counterpart — it can't see a file that exists in the real
#         directory but is MISSING from the snapshot. That's exactly what a
#         future `RUN` line added after the snapshot instruction (or the
#         snapshot instruction being moved earlier by a careless edit) would
#         produce: real /etc gains a file the snapshot never captured, so
#         every participant's mounted /etc silently lacks it at runtime.
#         (v) catches that by comparing the full recursive file list (not
#         just names — reuses cmp/mode checks per-file too) of snapshot vs.
#         real in both directions.
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

# ADR-0007: /etc/hosts, /etc/hostname, /etc/resolv.conf are excluded from
# the mode/owner/content comparisons below (but NOT from the entry-set
# comparison in (v) — they still have to be PRESENT). Every container
# runtime (this scripts own `docker run` inspection AND the real kubelet at
# deploy time — architect probe i, docs/adr/0007 SC3) unconditionally
# bind-mounts its OWN generated content over these 3 exact paths,
# regardless of what the image bakes there. So this check would see a
# "content mismatch" for them on every single run, forever, no matter how
# faithfully images/challenge/Dockerfile snapshots /etc — that is not
# snapshot drift, it is how every container runtime already treats these
# paths, confirmed safe to layer the runtime overlay UNDER (docs/adr/0007
# probe i: "kubelet の /etc/hosts overlay は /etc volume mount の上に正しく
# 重なる").
RUNTIME_MANAGED_RELPATHS="etc/hosts etc/hostname etc/resolv.conf"
is_runtime_managed() {
  case " $RUNTIME_MANAGED_RELPATHS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

# (iii) mode+owner+content match between every snapshotted file and its
# real counterpart (the path with the $SNAP prefix stripped, minus the
# runtime-managed exclusions above). Avoid a `find | while read` pipeline
# (the while-loop would run in a subshell in some shells, silently losing
# the fail_file write on `exit`) — iterate via a plain for-loop over find
# output instead (fixture tree is small, no filenames with spaces).
if [ -d "$SNAP" ]; then
  for f in $(find "$SNAP" -type f); do
    orig="${f#"$SNAP"}"
    relpath="${orig#/}"
    if is_runtime_managed "$relpath"; then
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

# (v) ADR-0007 Verification 3: entry-set completeness, both directions, for
# every top-level directory under the snapshot. A `RUN` line that touches
# /etc AFTER the build-time snapshot instruction (images/challenge/Dockerfile)
# — including one added by a future, careless edit — would leave a file
# present in the real directory but absent from the snapshot; (iii) above
# cannot see that (it only walks files the snapshot HAS). Compare the full
# recursive relative-path listing of snapshot vs. real, in both directions.
if [ -d "$SNAP" ]; then
  for topdir in "$SNAP"/*/; do
    [ -d "$topdir" ] || continue
    name="$(basename "$topdir")"
    real="/$name"
    if [ ! -d "$real" ]; then
      echo "HYGIENE VIOLATION (v): snapshot top-level dir $topdir has no real counterpart at $real" >&2
      touch "$fail_file"
      continue
    fi
    snap_list="$(cd "$topdir" && find . -type f | sort)"
    real_list="$(cd "$real" && find . -type f | sort)"
    if [ "$snap_list" != "$real_list" ]; then
      echo "HYGIENE VIOLATION (v): entry-set mismatch between $topdir and $real — a file was added to (or removed from) $real after the build-time snapshot was taken (snapshot drift):" >&2
      diff <(printf "%s\n" "$snap_list") <(printf "%s\n" "$real_list") >&2 || true
      touch "$fail_file"
    fi
  done
fi

[ -f "$fail_file" ] && rc=1
exit "$rc"
'

echo "==> check-image-hygiene: ${IMAGE}"
if docker run --rm --entrypoint sh "${IMAGE}" -c "${INSPECT}"; then
  echo "OK: ${IMAGE} — /opt/ctf/plant-seed/ hygiene verified (no hash/flag material, mode/owner/content match, entry-set complete, no hardlinks under /etc)."
  exit 0
else
  echo "FAIL: ${IMAGE} failed the image-hygiene check (ADR-0001 Verification 2-8) — see violations above." >&2
  exit 1
fi
