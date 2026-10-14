#!/bin/sh
# Runs the browser E2E scenarios inside Dockerfile.e2e's `run` stage and leaves
# the evidence in /verdict. It ALWAYS exits 0: BuildKit exports nothing from a
# failed RUN, so the result travels as files and scripts/e2e-verdict.py decides
# (ADR-0031 D1 (b)). A missing or empty file there is itself a failure.
set -u

out=/verdict
mkdir -p "$out/diag"
rm -f "$out/test.json" "$out/test.stderr" "$out/exit" "$out/run_id" "$out/sha"

E2E_SCOREBOARD_BIN=/out/scoreboard E2E_DIAG_DIR="$out/diag" \
  go test -tags e2e -count=1 -json -timeout 15m ./internal/e2e \
  >"$out/test.json" 2>"$out/test.stderr"
rc=$?

printf '%s\n' "$rc" >"$out/exit"
printf '%s\n' "${E2E_RUN_ID:-}" >"$out/run_id"
printf '%s\n' "${E2E_GIT_SHA:-}" >"$out/sha"
exit 0
