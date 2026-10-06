#!/usr/bin/env bash
# Mutation test for scripts/check-image-hygiene.sh (ADR-0026 V1-V3, V6).
# (A few cases temporarily edit the working tree and restore it with git checkout;
# run it on a tree whose challenges/ has no uncommitted work.)
#
# A check that never fails is indistinguishable from one that works, so this
# builds derived images (`FROM <image>` + one deliberate violation each) and
# asserts that check-image-hygiene.sh exits NON-ZERO with the message that
# names that violation (not merely "something failed"). The unmodified image
# must pass first. Build context = repo root, so mutations can COPY the real
# README.md / plant.sh / journey.yaml.
#
# Usage: ./scripts/test-check-image-hygiene.sh <image-ref>   (make check-image-hygiene-selftest)
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="${1:?usage: test-check-image-hygiene.sh <image-ref>}"
# Some cases below edit challenges/ temporarily and restore it with `git checkout`:
# refuse to start unless challenges/ is clean (nothing of ours to lose, nothing to confuse).
if ! git diff --quiet -- challenges || ! git diff --cached --quiet -- challenges || [ -n "$(git ls-files --others -- challenges)" ]; then
  echo "SELFTEST: challenges/ has uncommitted or untracked changes; refusing to run (it edits and restores challenges/)." >&2
  exit 2
fi
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
imgs=""; cleanup() { for i in $imgs; do docker rmi -f "$i" >/dev/null 2>&1 || true; done; rm -f "$out"; }; trap cleanup EXIT
failures=0; n=0

# expect_fail <name> <expected stderr substring> <Dockerfile body after FROM>
expect_fail() {
  local name="$1" want="$2" body="$3" tag rc=0
  n=$((n + 1)); tag="falco-ctf-hygiene-selftest:$$-$n"; imgs="$imgs $tag"
  printf 'FROM %s\n%s\n' "$BASE" "$body" | docker build -q -t "$tag" -f - . >/dev/null \
    || { echo "SELFTEST ERROR: could not build mutation '$name'" >&2; failures=$((failures + 1)); return; }
  ./scripts/check-image-hygiene.sh "$tag" >"$out" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: mutation '$name' was NOT detected (exit 0)"; failures=$((failures + 1))
  elif ! grep -qF -- "$want" "$out"; then
    echo "SELFTEST FAIL: mutation '$name' exited $rc but without the expected message [$want]:"; sed 's/^/    /' "$out"; failures=$((failures + 1))
  else
    echo "ok   (exit $rc): $name  ->  $(grep -F -- "$want" "$out" | head -n 1 | cut -c1-150)"
  fi
}

echo "== baseline: the unmodified image must pass"
./scripts/check-image-hygiene.sh "$BASE" >/dev/null 2>&1 || { echo "SELFTEST FAIL: baseline image does not pass" >&2; exit 1; }
echo "ok   (exit 0): baseline"

echo "== mutations: each must fail with its own message"
M=/opt/ctf/missions
expect_fail "README.md added next to fixtures/ (the ADR-0026 V6 negative test)" 'only "fixtures" is allowed directly under an id' \
  "COPY challenges/02-credential-files/README.md $M/02-credential-files/README.md"
expect_fail "journey.yaml added next to fixtures/" 'only "fixtures" is allowed directly under an id' \
  "COPY challenges/02-credential-files/journey.yaml $M/02-credential-files/journey.yaml"
expect_fail "README.md smuggled into fixtures/" 'fixture file set differs' \
  "COPY challenges/02-credential-files/README.md $M/02-credential-files/fixtures/README.md"
expect_fail "tracked non-fixture file (plant.sh) copied elsewhere in the image" 'challenges/03-stealth-read/plant.sh (sha256) is present in the image' \
  "COPY challenges/03-stealth-read/plant.sh /usr/local/share/plant.sh"
expect_fail "extra file directly under /opt/ctf" '/opt/ctf entry set differs' \
  "RUN echo x > /opt/ctf/extra.txt"
expect_fail "fixture mode changed (exec bit of 11/aws dropped)" 'fixtures/aws: mode 644' \
  "RUN chmod 0644 $M/11-cloud-cred-hunt/fixtures/aws"
expect_fail "fixture bytes changed" 'welcome.txt: sha256 differs from the build context' \
  "RUN echo x >> $M/00-tutorial/fixtures/welcome.txt"
expect_fail "symlink inside fixtures/" 'unexpected file type l' \
  "RUN ln -s /etc/passwd $M/00-tutorial/fixtures/link"
expect_fail "id without fixtures/" 'has no fixtures/ directory' \
  "RUN rm -r $M/00-tutorial/fixtures"
expect_fail "unknown id directory" 'is not a catalog id' \
  "RUN mkdir -p $M/99-extra/fixtures"
expect_fail "answers.yaml missing an evade id" 'answers.yaml keys != catalog evade ids' \
  "RUN sed -i '/^10-final-exfil/d' /opt/ctf/answers.yaml"
expect_fail "expectedFlag literal somewhere in the image" 'an expectedFlag literal is present in the image' \
  "RUN echo 'FALCO{dev-stealth-read}' > /usr/local/share/leak.txt"
# (the marker is split in the source so scripts/check-flags.sh does not see a literal)
expect_fail "non-placeholder flag-shaped marker under /opt/ctf" 'a flag-shaped marker other than the placeholder notation' \
  "RUN echo 'FALCO''{something-else}' >> /opt/ctf/banner.sh"

expect_fail "ignored/untracked file (.DS_Store) inside fixtures/" 'fixture file set differs' \
  "RUN touch $M/00-tutorial/fixtures/.DS_Store"
expect_fail "empty stray directory inside fixtures/" 'directory is not an ancestor of any tracked fixture' \
  "RUN mkdir $M/00-tutorial/fixtures/stray"
expect_fail "one fixture file missing (deletion direction)" 'fixture file set differs' \
  "RUN rm $M/00-tutorial/fixtures/welcome.txt"
expect_fail "id directory missing" 'id 00-tutorial has no directory' \
  "RUN rm -r $M/00-tutorial"

# --- build-context (working tree) mutations: the image is the unmodified base; the
# tree is changed temporarily and restored by the trap/restore command. The
# baseline above passed, so challenges/*/fixtures is clean before each of these.
# expect_fail_tree <name> <expected message> <setup cmd> <restore cmd>
expect_fail_tree() {
  local name="$1" want="$2" rc=0
  n=$((n + 1))
  trap 'eval "$4"; cleanup' EXIT
  eval "$3"
  ./scripts/check-image-hygiene.sh "$BASE" >"$out" 2>&1 || rc=$?
  eval "$4"
  trap cleanup EXIT
  if [ "$rc" -eq 0 ]; then echo "SELFTEST FAIL: tree mutation '$name' was NOT detected (exit 0)"; failures=$((failures + 1))
  elif ! grep -qF -- "$want" "$out"; then echo "SELFTEST FAIL: tree mutation '$name' exited $rc without [$want]:"; sed 's/^/    /' "$out"; failures=$((failures + 1))
  else echo "ok   (exit $rc): $name  ->  $(grep -F -- "$want" "$out" | head -n 1 | cut -c1-150)"; fi
}
F=challenges/00-tutorial/fixtures
expect_fail_tree "tracked fixture edited in the working tree (dirty tree)" 'has uncommitted / untracked / ignored changes' \
  "echo x >> $F/welcome.txt" "git checkout -q -- $F/welcome.txt"
expect_fail_tree "exec bit of 11/aws dropped in the working tree" 'has uncommitted / untracked / ignored changes' \
  "chmod 0644 challenges/11-cloud-cred-hunt/fixtures/aws" "chmod 0755 challenges/11-cloud-cred-hunt/fixtures/aws"
expect_fail_tree "untracked file in the working-tree fixtures" 'has uncommitted / untracked / ignored changes' \
  "touch $F/untracked.tmp" "rm -f $F/untracked.tmp"
expect_fail_tree "quoted evade type (type: \"evade\") is not silently accepted" 'top-level type: must be exactly' \
  "sed -i.bak 's/^type: evade/type: \"evade\"/' challenges/03-stealth-read/falco-rule.yaml; rm -f challenges/03-stealth-read/falco-rule.yaml.bak" \
  "git checkout -q -- challenges/03-stealth-read/falco-rule.yaml"
expect_fail_tree "trailing comment on the type line" 'top-level type: must be exactly' \
  "sed -i.bak 's/^type: evade/type: evade # c/' challenges/03-stealth-read/falco-rule.yaml; rm -f challenges/03-stealth-read/falco-rule.yaml.bak" \
  "git checkout -q -- challenges/03-stealth-read/falco-rule.yaml"

# --- empty reference set must die, not pass: a fresh empty git repo with a copy of the script
n=$((n + 1))
E="$(mktemp -d)"; mkdir "$E/scripts"; cp scripts/check-image-hygiene.sh "$E/scripts/"; git -C "$E" init -q
rc=0; "$E/scripts/check-image-hygiene.sh" "$BASE" >"$out" 2>&1 || rc=$?; rm -rf "$E"
if [ "$rc" -ne 0 ] && grep -qF 'no catalog id' "$out"; then echo "ok   (exit $rc): empty reference set (no catalog id) dies  ->  $(grep -F 'no catalog id' "$out" | head -n 1 | cut -c1-120)"
else echo "SELFTEST FAIL: empty reference set did not die (exit $rc)"; failures=$((failures + 1)); fi

echo "== $n mutations, $failures failure(s)"
[ "$failures" -eq 0 ]
