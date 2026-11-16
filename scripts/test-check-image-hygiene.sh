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
# The first block below is docker-free (ADR-0056 V22: the `type:` rule and the V1
# reference set, run from the real Dockerfile / check-image-hygiene.sh text against
# synthetic trees). `--type-rule-only` runs that block alone, with no image.
#
# Usage: ./scripts/test-check-image-hygiene.sh <image-ref>   (make check-image-hygiene-selftest)
#        ./scripts/test-check-image-hygiene.sh --type-rule-only   (no docker)
set -euo pipefail
cd "$(dirname "$0")/.."
TYPE_ONLY=0
if [ "${1:-}" = "--type-rule-only" ]; then
  TYPE_ONLY=1; BASE=""
else
  BASE="${1:?usage: test-check-image-hygiene.sh <image-ref> | --type-rule-only}"
fi

# ---------------------------------------------------------------------------
# ADR-0056 V22 — docker-free. The `type:` rule is written twice as shell: the
# Dockerfile's missions-builder (answers.yaml) and check-image-hygiene.sh V2. Both
# are EXTRACTED from the real files here (a copy in this test could drift from what
# ships) and run against synthetic trees under a temp dir; the real challenges/ is
# not read. The V1 reference-set lines are extracted the same way and run in a
# throwaway git repo. What needs docker (the image actually built from a tree that
# has an investigate challenge, V1b-V1d on it) is left to CI and the baseline below.
# ---------------------------------------------------------------------------
TR="$(mktemp -d)"
tr_total=0; tr_failures=0
tr_pass() { tr_total=$((tr_total + 1)); echo "ok   : $1"; }
tr_fail() { tr_total=$((tr_total + 1)); tr_failures=$((tr_failures + 1)); echo "SELFTEST FAIL: $1"; }
tr_die() { echo "SELFTEST ERROR (type rule): $*" >&2; rm -rf "$TR"; exit 1; }

# the builder's answers.yaml block: from `{ echo '# EVADE ...` to `} > /out/answers.yaml`
awk 'index($0, "{ echo ") && index($0, "# EVADE") { p = 1 } p { print } index($0, "} > /out/answers.yaml") { p = 0 }' \
  images/challenge/Dockerfile >"$TR/builder-body.txt"
[ -s "$TR/builder-body.txt" ] || tr_die "could not extract the answers.yaml block from images/challenge/Dockerfile (the file was reshaped: update this extraction)"
grep -qF "'type: evade')" "$TR/builder-body.txt" || tr_die "the extracted Dockerfile block has no 'type: evade') case"
{ echo 'set -eu'
  sed -e "s#/src/challenges#${TR}/src/challenges#g" -e "s#> /out/answers.yaml#> ${TR}/out/answers.yaml#" "$TR/builder-body.txt"
} >"$TR/builder.sh"
grep -qF "${TR}/out/answers.yaml" "$TR/builder.sh" || tr_die "the output path of the builder block was not redirected"

# V2's type loop, its `fail` helper and its answers-keys line, from check-image-hygiene.sh
awk 'index($0, ": >\"$T/evade-ids\"") == 1 { p = 1 } p { print } index($0, "sort -o \"$T/evade-ids\" \"$T/evade-ids\"") == 1 { p = 0 }' \
  scripts/check-image-hygiene.sh >"$TR/v2-body.txt"
grep -m1 '^fail() ' scripts/check-image-hygiene.sh >"$TR/v2-fail.txt" || true
grep -m1 -F '>"$T/answers-keys"' scripts/check-image-hygiene.sh >"$TR/v2-keys.txt" || true
[ -s "$TR/v2-body.txt" ] && [ -s "$TR/v2-fail.txt" ] && [ -s "$TR/v2-keys.txt" ] \
  || tr_die "could not extract the V2 type loop / fail helper / answers-keys line from scripts/check-image-hygiene.sh"
{ echo 'set -euo pipefail'
  echo "T='${TR}/v2'"
  echo 'fails=0'
  cat "$TR/v2-fail.txt" "$TR/v2-body.txt" "$TR/v2-keys.txt"
  echo '[ "$fails" -eq 0 ] || exit 1'
  echo 'cmp -s "$T/answers-keys" "$T/evade-ids"'
} >"$TR/v2.sh"

tr_mk() { # <id> <top-level type line>
  mkdir -p "$TR/src/challenges/$1"
  printf 'challengeId: %s\n%s\nexpectedRules: [r]\n' "$1" "$2" >"$TR/src/challenges/$1/falco-rule.yaml"
}
tr_run() { # <builder script> <v2 script>: sets B_RC and V_RC; stderr in $TR/b.err and $TR/v2.err
  rm -rf "$TR/out" "$TR/v2"; mkdir -p "$TR/out" "$TR/v2"
  B_RC=0; sh "$1" >/dev/null 2>"$TR/b.err" || B_RC=$?
  ls "$TR/src/challenges"/*/falco-rule.yaml >"$TR/v2/rules"
  if [ -f "$TR/out/answers.yaml" ]; then cp "$TR/out/answers.yaml" "$TR/v2/answers"; else : >"$TR/v2/answers"; fi
  V_RC=0; bash "$2" >/dev/null 2>"$TR/v2.err" || V_RC=$?
}
tr_refused() { # <label> <who> <rc> <stderr file>
  if [ "$3" -ne 0 ] && grep -qF 'top-level type: must be exactly' "$4" && grep -qF 'trigger|evade|detect|investigate' "$4"; then
    tr_pass "$1: $2 refuses it with the type message"
  else
    tr_fail "$1: $2 did not refuse it with the type message (rc $3): $(head -n 3 "$4" | tr '\n' ' ')"
  fi
}

echo "== type rule (docker-free): a tree with one challenge of each of trigger / evade / investigate"
tr_mk 90-demo-evade 'type: evade'
tr_mk 91-demo-trigger 'type: trigger'
tr_mk 92-demo-invest 'type: investigate'
tr_run "$TR/builder.sh" "$TR/v2.sh"
if [ "$B_RC" -eq 0 ]; then tr_pass "builder accepts type: investigate"; else tr_fail "builder refused a valid tree (rc $B_RC): $(head -n 3 "$TR/b.err" | tr '\n' ' ')"; fi
if [ "$V_RC" -eq 0 ]; then tr_pass "V2 accepts type: investigate and answers.yaml keys == evade ids"; else tr_fail "V2 refused a valid tree (rc $V_RC): $(head -n 3 "$TR/v2.err" | tr '\n' ' ')"; fi
if grep -q '^90-demo-evade:' "$TR/out/answers.yaml" && ! grep -q '92-demo-invest' "$TR/out/answers.yaml" && ! grep -q '91-demo-trigger' "$TR/out/answers.yaml"; then
  tr_pass "answers.yaml has the evade id and no investigate / trigger id"
else
  tr_fail "answers.yaml keys are wrong: $(grep -v '^#' "$TR/out/answers.yaml" | tr '\n' ' ')"
fi
if grep -q '調査型' "$TR/out/answers.yaml"; then tr_pass "answers.yaml carries the note that an investigate challenge is answered in the portal"; else tr_fail "answers.yaml has no note for investigate challenges"; fi
if [ "$(cat "$TR/v2/evade-ids")" = "90-demo-evade" ]; then tr_pass "V2 evade ids = the evade challenge only"; else tr_fail "V2 evade ids: $(tr '\n' ' ' <"$TR/v2/evade-ids")"; fi

echo "== type rule (docker-free): near-misses of the type line are refused by BOTH"
for line in 'type: investigat' 'type: "investigate"' 'type: investigate # c' 'type:  investigate' 'type: Investigate'; do
  tr_mk 92-demo-invest "$line"
  tr_run "$TR/builder.sh" "$TR/v2.sh"
  tr_refused "[$line]" builder "$B_RC" "$TR/b.err"
  tr_refused "[$line]" V2 "$V_RC" "$TR/v2.err"
done

echo "== type rule (docker-free): the check can fail — the same tree against a copy that lost 'type: investigate'"
tr_mk 92-demo-invest 'type: investigate'
sed "s/|'type: investigate'//" "$TR/builder.sh" >"$TR/builder-noinv.sh"
sed "s/|'type: investigate'//" "$TR/v2.sh" >"$TR/v2-noinv.sh"
cmp -s "$TR/builder.sh" "$TR/builder-noinv.sh" && tr_die "the Dockerfile block has no |'type: investigate' to remove (the case line was reshaped: update this test)"
cmp -s "$TR/v2.sh" "$TR/v2-noinv.sh" && tr_die "V2 has no |'type: investigate' to remove (the case line was reshaped: update this test)"
tr_run "$TR/builder-noinv.sh" "$TR/v2-noinv.sh"
if [ "$B_RC" -ne 0 ]; then tr_pass "a builder without investigate refuses the tree (the positive case above is not vacuous)"; else tr_fail "a builder without investigate still accepted the tree"; fi
if [ "$V_RC" -ne 0 ]; then tr_pass "a V2 without investigate refuses the tree (the positive case above is not vacuous)"; else tr_fail "a V2 without investigate still accepted the tree"; fi

echo "== V1 reference set (docker-free): challenges/<id>/edition/** is a tracked non-fixture file, so V1d scans the image for it"
G="$TR/repo"; E="$G/challenges/92-demo-invest"
mkdir -p "$E/fixtures" "$E/edition"
printf 'type: investigate\n' >"$E/falco-rule.yaml"
printf 'title: t\n' >"$E/journey.yaml"
printf 'x\n' >"$E/fixtures/note.txt"
printf 'x\n' >"$E/edition/table.tsv"
for tool in submit-all.sh submit-yaml.sh banner.sh; do printf 'x\n' >"$G/challenges/$tool"; done
git -C "$G" init -q
git -C "$G" add challenges
awk 'index($0, "git -c core.quotepath=off ls-files") == 1 || index($0, "TOOLS=\"") == 1 || index($0, "grep -vxFf \"$T/fixtures\" \"$T/all\"") == 1 { print }' \
  scripts/check-image-hygiene.sh >"$TR/v1-body.txt"
grep -m1 '^die() ' scripts/check-image-hygiene.sh >"$TR/v1-die.txt" || true
[ -s "$TR/v1-die.txt" ] && [ "$(wc -l <"$TR/v1-body.txt" | tr -d ' ')" = 5 ] \
  || tr_die "could not extract the 5 V1 reference-set lines (3 git ls-files, TOOLS, nonfixtures) from scripts/check-image-hygiene.sh"
{ echo 'set -euo pipefail'
  echo "cd '${G}'"
  echo "T='${TR}/v1'; mkdir -p \"\$T\""
  cat "$TR/v1-die.txt" "$TR/v1-body.txt"
} >"$TR/v1.sh"
V1_RC=0; bash "$TR/v1.sh" >/dev/null 2>"$TR/v1.err" || V1_RC=$?
if [ "$V1_RC" -ne 0 ]; then
  tr_fail "the V1 reference-set lines failed (rc $V1_RC): $(head -n 3 "$TR/v1.err" | tr '\n' ' ')"
else
  nf="$TR/v1/nonfixtures"
  if grep -qxF 'challenges/92-demo-invest/edition/table.tsv' "$nf" \
     && grep -qxF 'challenges/92-demo-invest/falco-rule.yaml' "$nf" \
     && grep -qxF 'challenges/92-demo-invest/journey.yaml' "$nf" \
     && ! grep -qF 'fixtures/' "$nf" && ! grep -qF 'submit-' "$nf" && ! grep -qF 'banner.sh' "$nf"; then
    tr_pass "edition/** (with falco-rule.yaml and journey.yaml) is in the non-fixture reference set; fixtures and the 3 tools are not"
  else
    tr_fail "the non-fixture reference set is wrong: $(tr '\n' ' ' <"$nf")"
  fi
  if [ "$(cat "$TR/v1/fixtures")" = 'challenges/92-demo-invest/fixtures/note.txt' ]; then
    tr_pass "the fixtures reference set holds the fixture only (edition/** is not a fixture)"
  else
    tr_fail "the fixtures reference set is wrong: $(tr '\n' ' ' <"$TR/v1/fixtures")"
  fi
fi

echo "== type rule + V1 reference set: $tr_total checks, $tr_failures failure(s)"
rm -rf "$TR"
[ "$tr_failures" -eq 0 ] || exit 1
[ "$TYPE_ONLY" -eq 0 ] || exit 0

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
