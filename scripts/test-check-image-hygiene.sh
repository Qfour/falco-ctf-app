#!/usr/bin/env bash
# Mutation test for scripts/check-image-hygiene.sh (ADR-0026 V1-V3, V6).
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

echo "== $n mutations, $failures failure(s)"
[ "$failures" -eq 0 ]
