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
# ADR-0026 (I16) adds three host-driven checks on the same image — the
# /opt/ctf/missions/ allowlist (V1), answers.yaml (V2) and flag-literal
# absence (V3). They are driven from the HOST (git + the build context are
# the reference) and inspect the image with `docker run` only:
#   V1  /opt/ctf/missions/ holds exactly `<id>(/fixtures(/.*)?)?` for every
#       catalog id; every tracked `challenges/*/fixtures/**` file is there
#       with the same sha256 + mode and nothing else is (no untracked/ignored
#       file, no symlink/special file); no tracked non-fixture file under
#       challenges/ (except the 4 individually COPY'd tools) has a sha256
#       found anywhere in the image; the entry set directly under /opt/ctf
#       is pinned.
#   V2  the keys of /opt/ctf/answers.yaml == the catalog's evade ids.
#   V3  no repo `expectedFlag` literal anywhere in the image; no flag-shaped
#       marker other than the placeholder notation under /opt/ctf.
# scripts/test-check-image-hygiene.sh proves each of these actually fails on
# a deliberately broken derived image (mutation test).
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
if [ -d "$SNAP" ] && grep -RlE ":\\\$[0-9A-Za-z]+\\\$" "$SNAP" >/tmp/hygiene-hash-hits 2>/dev/null; then
  echo "HYGIENE VIOLATION (i): crypt-hash-shaped string found under $SNAP (file(s) only, the matched text is deliberately not printed):" >&2
  cat /tmp/hygiene-hash-hits >&2
  touch "$fail_file"
fi

# (ii) FALCO{ literal anywhere under the snapshot tree
if [ -d "$SNAP" ] && grep -RlF "FALCO{" "$SNAP" >/tmp/hygiene-flag-hits 2>/dev/null; then
  echo "HYGIENE VIOLATION (ii): FALCO{ literal found under $SNAP (file(s) only, the matched text is deliberately not printed):" >&2
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
if ! docker run --rm --entrypoint sh "${IMAGE}" -c "${INSPECT}"; then
  echo "FAIL: ${IMAGE} failed the image-hygiene check (ADR-0001 Verification 2-8 / ADR-0007 Verification 3) — see violations above." >&2
  exit 1
fi
echo "OK: ${IMAGE} — /opt/ctf/plant-seed/ hygiene verified (no hash/flag material, mode/owner/content/entry-set match in both directions, no hardlinks under /etc)."

# ---------------------------------------------------------------------------
# ADR-0026 V1-V3 (host side). bash 3.2 compatible (macOS): temp files + awk,
# no associative arrays / mapfile.
# ---------------------------------------------------------------------------
cd "$(dirname "$0")/.."
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fails=0
fail() { echo "HYGIENE VIOLATION (ADR-0026 $1): $2" >&2; fails=$((fails + 1)); }
die() { echo "FAIL: check-image-hygiene (ADR-0026): $*" >&2; exit 1; }

sha256_of() { # $1=file -> hex digest (macOS has shasum, Linux sha256sum)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum <"$1" | awk '{print $1}'; else shasum -a 256 <"$1" | awk '{print $1}'; fi
}
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# The 4 tools COPY'd individually by images/challenge/Dockerfile (ADR-0026 D2:
# unchanged). Pinned HERE, not derived from the Dockerfile, so adding a COPY
# of another challenges/ file cannot silently exempt it from the sha256 scan.
TOOLS="challenges/submit-all.sh challenges/setname.sh challenges/submit-yaml.sh challenges/banner.sh"

# --- reference sets from git (fail-closed on any error / empty set) ---------
git -c core.quotepath=off ls-files 'challenges/*/falco-rule.yaml' >"$T/rules" || die "git ls-files (falco-rule.yaml) failed"
awk -F/ 'NF == 3 { print $2 }' "$T/rules" | sort -u >"$T/ids"
[ -s "$T/ids" ] || die "V1: no catalog id (challenges/*/falco-rule.yaml) found"

git -c core.quotepath=off ls-files 'challenges/*/fixtures/**' >"$T/fixtures" || die "git ls-files (fixtures) failed"
[ -s "$T/fixtures" ] || die "V1: no tracked challenges/*/fixtures/** file found (0 fixtures)"
if grep -vE '^challenges/[^/]+/fixtures/.+' "$T/fixtures" >"$T/fixtures-odd"; then
  die "V1: unexpected path(s) from git ls-files 'challenges/*/fixtures/**': $(cat "$T/fixtures-odd")"
fi

git -c core.quotepath=off ls-files challenges >"$T/all" || die "git ls-files (challenges) failed"

# --- the build context must equal the index (A1-2) ----------------------------------
# ADR-0026 V1's reference is `git ls-files`, but sha256/mode are read from the
# working tree (the build context). They only mean "the committed content" if
# the fixtures have no uncommitted change, untracked file or ignored file.
git status --porcelain --untracked-files=all --ignored -- 'challenges/*/fixtures/**' >"$T/dirty" || die "git status failed"
if [ -s "$T/dirty" ]; then
  fail V1 "challenges/*/fixtures has uncommitted / untracked / ignored changes (V1 compares against git; commit or clean them): $(awk '{ printf "%s ", $0 }' "$T/dirty")"
fi

# --- untracked / ignored files in the working-tree fixtures --------------------
# (the builder would copy them: the build context is the working tree)
find challenges -path 'challenges/*/fixtures/*' \( -type f -o -type l \) | sort >"$T/wt-fixtures"
sort "$T/fixtures" >"$T/fixtures-sorted"
if ! cmp -s "$T/wt-fixtures" "$T/fixtures-sorted"; then
  fail V1 "working-tree fixtures differ from \`git ls-files\` (untracked/ignored file or tracked file missing): $(comm -3 "$T/fixtures-sorted" "$T/wt-fixtures" | tr -s '\t\n' '  ')"
fi

# expected: "<sha256> <mode> <id>/fixtures/<rel>" per tracked fixture file
: >"$T/exp-fixtures"
while IFS= read -r f; do
  [ -f "$f" ] && [ ! -L "$f" ] || { fail V1 "tracked fixture $f is not a regular file in the build context"; continue; }
  printf '%s %s %s\n' "$(sha256_of "$f")" "$(mode_of "$f")" "${f#challenges/}" >>"$T/exp-fixtures"
done <"$T/fixtures"

# --- inspect the image (docker run, read-only) -----------------------------------
docker run --rm --entrypoint sh "${IMAGE}" -c '
set -eu
cd /opt/ctf/missions
find . -mindepth 1 -printf "E\t%y\t%m\t%P\n"
find . -mindepth 1 -type f -exec sha256sum {} + >/tmp/sums
sed "s/^/S\t/" /tmp/sums
find /opt/ctf -mindepth 1 -maxdepth 1 -printf "T\t%y\t%f\n"
' >"$T/img-missions" || die "V1: inspecting /opt/ctf in ${IMAGE} failed"
[ -s "$T/img-missions" ] || die "V1: /opt/ctf/missions in ${IMAGE} is empty"

# directories below <id>/fixtures that are an ancestor of a tracked file (anything else is a stray dir)
awk -F/ '{ p = $2 "/" $3; for (i = 4; i < NF; i++) { p = p "/" $i; print p } }' "$T/fixtures" | sort -u >"$T/exp-dirs"

# V1a: every path is <id>(/fixtures(/.*)?)? ; level-1 = dirs named by ids ; level-2 = "fixtures" dir ; only f/d below
awk -F'\t' -v idfile="$T/ids" -v dirfile="$T/exp-dirs" '
  BEGIN { while ((getline l < idfile) > 0) ids[l] = 1; while ((getline l < dirfile) > 0) okdir[l] = 1 }
  $1 == "E" {
    type = $2; path = $4; n = split(path, p, "/")
    if (n == 1) {
      if (!(path in ids)) print "entry " path " is not a catalog id"
      else if (type != "d") print path " is not a directory (type " type ")"
      seen[path] = 1
    } else if (n == 2) {
      if (p[2] != "fixtures") print path ": only \"fixtures\" is allowed directly under an id"
      else if (type != "d") print path " is not a directory (type " type ")"
      else hasfx[p[1]] = 1
    } else {
      if (!(p[1] in ids) || p[2] != "fixtures") print path ": outside <id>/fixtures/"
      if (type != "f" && type != "d") print path ": unexpected file type " type " (symlink/special file)"
      else if (type == "d" && !(path in okdir)) print path ": directory is not an ancestor of any tracked fixture"
    }
  }
  END {
    for (i in ids) { if (!(i in seen)) print "id " i " has no directory"; else if (!(i in hasfx)) print "id " i " has no fixtures/ directory" }
  }' "$T/img-missions" >"$T/v1a" || die "V1: awk failed"
if [ -s "$T/v1a" ]; then fail V1 "$(tr '\n' ';' <"$T/v1a")"; fi

# V1b: tracked fixture files == image regular files under fixtures (sha256 + mode)
awk -F'\t' '$1 == "E" && $2 == "f" { print $4 }' "$T/img-missions" | sort >"$T/img-files"
awk '{ print $3 }' "$T/exp-fixtures" | sort >"$T/exp-files"
if ! cmp -s "$T/img-files" "$T/exp-files"; then
  fail V1 "fixture file set differs (< expected only / > image only): $(diff "$T/exp-files" "$T/img-files" | grep '^[<>]' | tr '\n' ';')"
fi
awk -F'\t' '$1 == "E" && $2 == "f" { print $3, $4 }' "$T/img-missions" >"$T/img-modes"   # "<mode> <path>"
awk -F'\t' '$1 == "S" { s = $2; sub(/^[0-9a-f]+  \.\//, "", s); h = $2; sub(/  .*/, "", h); print h, s }' "$T/img-missions" >"$T/img-sha"   # "<sha> <path>"
while read -r sha mode path; do
  img_sha="$(awk -v p="$path" 'substr($0, index($0, " ") + 1) == p { print $1 }' "$T/img-sha")"
  img_mode="$(awk -v p="$path" 'substr($0, index($0, " ") + 1) == p { print $1 }' "$T/img-modes")"
  if [ -z "$img_sha" ]; then fail V1 "$path: no sha256 from the image (file missing or hashing failed)"; continue; fi
  [ "$img_sha" = "$sha" ] || fail V1 "$path: sha256 differs from the build context"
  [ "$img_mode" = "$mode" ] || fail V1 "$path: mode $img_mode != build context $mode"
done <"$T/exp-fixtures"

# V1c: /opt/ctf top-level entry set is pinned
awk -F'\t' '$1 == "T" { print $2, $3 }' "$T/img-missions" | sort >"$T/top"
printf '%s\n' 'd missions' 'd plant-seed' 'f answers.yaml' 'f banner.sh' 'f setname.sh' 'f submit-yaml.sh' 'f submit.sh' | sort >"$T/top-exp"
if ! cmp -s "$T/top" "$T/top-exp"; then
  fail V1 "/opt/ctf entry set differs (< expected only / > image only): $(diff "$T/top-exp" "$T/top" | grep '^[<>]' | tr '\n' ';')"
fi

# V1d: no tracked non-fixture challenges/ file (minus the 4 tools; empty files carry no content)
# has a sha256 found anywhere in the image (whole filesystem, -xdev).
docker run --rm --entrypoint sh "${IMAGE}" -c 'set -eu; find / -xdev -type f -exec sha256sum {} + >/tmp/sums; cut -d" " -f1 /tmp/sums' >"$T/img-all-sha.raw" \
  || die "V1: hashing the image filesystem failed"
sort -u "$T/img-all-sha.raw" >"$T/img-all-sha"
[ -s "$T/img-all-sha" ] || die "V1: image filesystem hash list is empty"
grep -vxFf "$T/fixtures" "$T/all" | grep -vxF -e "$(printf '%s\n' $TOOLS)" >"$T/nonfixtures" || die "V1: no tracked non-fixture file under challenges/ (reference set empty)"
checked=0
while IFS= read -r f; do
  [ -f "$f" ] && [ -s "$f" ] || continue
  checked=$((checked + 1))
  if grep -qxF "$(sha256_of "$f")" "$T/img-all-sha"; then
    fail V1 "tracked non-fixture file $f (sha256) is present in the image"
  fi
done <"$T/nonfixtures"
[ "$checked" -gt 0 ] || die "V1: sha256 scan of non-fixture files checked 0 files"

# --- V2: answers.yaml keys == evade ids -------------------------------------------
: >"$T/evade-ids"
while IFS= read -r rf; do
  # Same rule as the Dockerfile's missions-builder: exactly one top-level `type:`
  # line, exactly `type: trigger|evade|detect`; anything else is a failure.
  tcount="$(grep -c '^type:' "$rf" || true)"
  tline="$(grep '^type:' "$rf" | head -n 1 || true)"
  if [ "$tcount" != 1 ]; then fail V2 "$rf: needs exactly one top-level type: line (found $tcount)"
  else
    case "$tline" in
      'type: trigger'|'type: detect') ;;
      'type: evade') basename "$(dirname "$rf")" >>"$T/evade-ids" ;;
      *) fail V2 "$rf: top-level type: must be exactly 'type: trigger|evade|detect'" ;;
    esac
  fi
done <"$T/rules"
sort -o "$T/evade-ids" "$T/evade-ids"
docker run --rm --entrypoint sh "${IMAGE}" -c 'cat /opt/ctf/answers.yaml' >"$T/answers" || die "V2: reading /opt/ctf/answers.yaml failed"
grep -E '^[^#[:space:]][^:]*:' "$T/answers" | sed 's/:.*//' | sort >"$T/answers-keys" || true
if [ ! -s "$T/evade-ids" ]; then fail V2 "catalog has no evade id (reference set empty)"
elif ! cmp -s "$T/answers-keys" "$T/evade-ids"; then
  fail V2 "answers.yaml keys != catalog evade ids (< catalog only / > answers.yaml only): $(diff "$T/evade-ids" "$T/answers-keys" | grep '^[<>]' | tr '\n' ';')"
fi

# --- V3: flag literals ----------------------------------------------------------------
: >"$T/flags"
while IFS= read -r rf; do
  sed -n 's/^expectedFlag:[[:space:]]*//p' "$rf" | tr -d "\"' " >>"$T/flags"
done <"$T/rules"
[ -s "$T/flags" ] || die "V3: no expectedFlag found in challenges/*/falco-rule.yaml (reference set empty)"
if grep -vE '^FALCO\{[A-Za-z0-9_-]+\}$' "$T/flags" >"$T/flags-odd"; then die "V3: malformed expectedFlag: $(cat "$T/flags-odd")"; fi
# (a) whole image: no expectedFlag literal. Patterns go in via the environment, not
# stdin (a `docker run -i` pipe hung once on a shared Colima daemon). They are the
# repo's own expectedFlag values (placeholders in this public repo).
# A positive control (a probe string that is also a pattern, planted in
# /tmp/hygiene-probe) must come back, or the scan itself is broken (fail-closed).
PROBE="hygiene-probe-$$-$(date +%s)"
docker run --rm -e "HYGIENE_PATTERNS=$(cat "$T/flags"; echo "$PROBE")" --entrypoint sh "${IMAGE}" -c '
set -eu
printf "%s\n" "$HYGIENE_PATTERNS" >/tmp/hygiene-patterns
probe=$(tail -n 1 /tmp/hygiene-patterns); echo "$probe" >/tmp/hygiene-probe
find / -xdev -type f ! -path /tmp/hygiene-patterns -exec grep -Fal -f /tmp/hygiene-patterns {} + || true
' >"$T/flag-hits" || die "V3: scanning the image for flag literals failed"
if ! grep -qxF /tmp/hygiene-probe "$T/flag-hits"; then die "V3: positive control not found — the flag-literal scan is not working"; fi
grep -vxF /tmp/hygiene-probe "$T/flag-hits" >"$T/flag-hits-real" || true
if [ -s "$T/flag-hits-real" ]; then fail V3 "an expectedFlag literal is present in the image: $(tr '\n' ' ' <"$T/flag-hits-real")"; fi
# (b) /opt/ctf: no flag-shaped marker other than the placeholder notation FALCO{...}
# (MARK is built at run time: scripts/check-flags.sh flags any literal marker
# followed by a closing brace on one source line, which this script must not contain).
MARK="FALCO""{"
docker run --rm --entrypoint sh "${IMAGE}" -c 'grep -raoE "FALCO\{.{0,64}" /opt/ctf || [ $? -eq 1 ]' >"$T/falco-hits" \
  || die "V3: scanning /opt/ctf for FALCO{ failed"
if sed "s/${MARK}\.\.\.}//g" "$T/falco-hits" | grep -qF "$MARK"; then
  # path(s) and count only: never echo the matched text (it may be a real flag).
  sed "s/${MARK}\.\.\.}//g" "$T/falco-hits" | grep -F "$MARK" | cut -d: -f1 | sort -u >"$T/falco-hit-files" || true
  fail V3 "a flag-shaped marker other than the placeholder notation was found under /opt/ctf in $(wc -l <"$T/falco-hit-files" | tr -d ' ') file(s) (value not printed): $(tr '\n' ' ' <"$T/falco-hit-files")"
fi

if [ "$fails" -gt 0 ]; then
  echo "FAIL: ${IMAGE} failed ADR-0026 V1-V3 (${fails} violation(s)) — see above." >&2
  exit 1
fi
echo "OK: ${IMAGE} — ADR-0026 V1-V3 verified (missions allowlist = <id>/fixtures/** only, fixtures bytes+mode match the build context, ${checked} non-fixture challenges/ files absent from the image, answers.yaml keys = evade ids, no flag literal)."
exit 0
