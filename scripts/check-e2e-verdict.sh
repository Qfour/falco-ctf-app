#!/usr/bin/env bash
# Self-test of scripts/e2e-verdict.py (ADR-0031 V6): builds a verdict directory
# the way Dockerfile.e2e's run stage would, then plants one defect at a time and
# requires the verdict to refuse it. The good directory must pass, so a verdict
# that refuses everything is caught too. Needs only bash and python3; no Docker.
# Runs in CI's required `flag-guard` job.
set -u
cd "$(dirname "$0")/.." || exit 1

verdict=scripts/e2e-verdict.py
run_id=run-123
sha=0123456789abcdef
pkg=github.com/Qfour/falco-ctf-app/internal/e2e
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf '%s\n' '# comment' 'TestA' 'TestB' >"$tmp/expected.txt"

# good DIR: a passing run of TestA and TestB.
good() {
  mkdir -p "$1"
  {
    for t in TestA TestB; do
      printf '{"Action":"run","Package":"%s","Test":"%s"}\n' "$pkg" "$t"
      printf '{"Action":"pass","Package":"%s","Test":"%s"}\n' "$pkg" "$t"
    done
    printf '{"Action":"pass","Package":"%s"}\n' "$pkg"
  } >"$1/test.json"
  printf '0\n' >"$1/exit"
  printf '%s\n' "$run_id" >"$1/run_id"
  printf '%s\n' "$sha" >"$1/sha"
}

status=0
check() { # check NAME WANT(pass|fail) DIR [EXPECTED_FILE]
  local name=$1 want=$2 dir=$3 exp=${4:-$tmp/expected.txt} out rc
  out="$(python3 "$verdict" --dir "$dir" --expected "$exp" --run-id "$run_id" --sha "$sha" 2>&1)"
  rc=$?
  if { [ "$want" = pass ] && [ "$rc" -ne 0 ]; } || { [ "$want" = fail ] && [ "$rc" -eq 0 ]; }; then
    echo "FAIL: $name: wanted $want, exit $rc: $out"
    status=1
  else
    echo "ok:   $name ($want)"
  fi
}

good "$tmp/ok";                                          check "a good run" pass "$tmp/ok"
good "$tmp/exit";  printf '1\n' >"$tmp/exit/exit";       check "go test exit code not 0" fail "$tmp/exit"
good "$tmp/miss";  sed -i.bak '/"TestB"/d' "$tmp/miss/test.json"
                                                         check "a listed test did not pass" fail "$tmp/miss"
good "$tmp/extra"; printf '{"Action":"pass","Package":"%s","Test":"TestC"}\n' "$pkg" >>"$tmp/extra/test.json"
                                                         check "a passing test that is not listed" fail "$tmp/extra"
good "$tmp/skip";  printf '{"Action":"skip","Package":"%s","Test":"TestA/sub"}\n' "$pkg" >>"$tmp/skip/test.json"
                                                         check "a skipped subtest" fail "$tmp/skip"
good "$tmp/fail";  printf '{"Action":"fail","Package":"%s","Test":"TestA/sub"}\n' "$pkg" >>"$tmp/fail/test.json"
                                                         check "a failed subtest" fail "$tmp/fail"
good "$tmp/stale"; printf 'run-OLD\n' >"$tmp/stale/run_id"
                                                         check "run id of an earlier run (stale or cached verdict)" fail "$tmp/stale"
good "$tmp/sha";   printf 'ffffffffffff\n' >"$tmp/sha/sha"
                                                         check "sha of another commit" fail "$tmp/sha"
good "$tmp/nofile"; rm "$tmp/nofile/test.json";          check "test.json missing" fail "$tmp/nofile"
good "$tmp/noexit"; rm "$tmp/noexit/exit";               check "exit file missing" fail "$tmp/noexit"
good "$tmp/empty"; : >"$tmp/empty/test.json";            check "test.json empty" fail "$tmp/empty"
good "$tmp/junk";  printf 'not json\n' >>"$tmp/junk/test.json"
                                                         check "an unreadable line" fail "$tmp/junk"
good "$tmp/nopkg"; sed -i.bak '/^{"Action":"pass","Package":"[^"]*"}$/d' "$tmp/nopkg/test.json"
                                                         check "no passing package result" fail "$tmp/nopkg"
good "$tmp/zero";  printf '{"Action":"pass","Package":"%s"}\n' "$pkg" >"$tmp/zero/test.json"
                                                         check "zero tests ran" fail "$tmp/zero"
good "$tmp/nobrowser"
{ printf '{"Action":"run","Package":"%s","Test":"TestA"}\n' "$pkg"
  printf '{"Action":"fail","Package":"%s","Test":"TestA"}\n' "$pkg"
  printf '{"Action":"fail","Package":"%s"}\n' "$pkg"; } >"$tmp/nobrowser/test.json"
printf '1\n' >"$tmp/nobrowser/exit"
                                                         check "browser missing (tests fail, not skip)" fail "$tmp/nobrowser"
: >"$tmp/noexpected.txt"; good "$tmp/noexp";             check "an empty expected list" fail "$tmp/noexp" "$tmp/noexpected.txt"
printf 'TestA\nTestA\nTestB\n' >"$tmp/dup.txt";          check "a test listed twice" fail "$tmp/ok" "$tmp/dup.txt"

exit "$status"
