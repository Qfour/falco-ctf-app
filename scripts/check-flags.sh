#!/usr/bin/env bash
# Flag-hygiene gate for the PUBLIC repo. Fails (non-zero) if:
#   1. any tracked file carries a real FALCO{...} flag literal,
#   2. generated challenge values are out of sync with plant.sh, or
#   3. any tracked file carries a "DO NOT COMMIT" tripwire marker
#      (scratch/PoC files accidentally staged and committed), or
#   4. any tracked file carries the header of an EVENT's render output (an answers
#      table or a digests file whose run id is not the practice one, or a render
#      record), or any tracked path has the layout of an event's evidence bundle
#      (evidence/<seat>/<cid>/<file>): scripts/check-edition-headers.sh (ADR-0056
#      V84 / V93), whose self-test runs here too, so the guard is shown able to fail
#      on every run, or
#   5. the scenario checks of challenges/gen-values.sh (an id that is not its directory's
#      name, a challenge listed twice; ADR-0055 V1) cannot be shown to fail:
#      scripts/test-gen-values-scenarios.sh.
#
# Allowed flag forms (these are not secrets):
#   FALCO{dev-<slug>}   local-dev / test placeholders
#   FALCO{...}          literal ellipsis used in docs/help text
# Go unit tests (*_test.go) may use arbitrary fixtures and are exempt.
#
# Real per-event flags live only in falco-ctf-platform events/<date>/flags.sops.yaml
# and are injected at deploy time (FLAGS_FILE for scoring, CTF_FLAG_* for planting).
#
# P23-2b tripwire: "DO NOT COMMIT" (and DO-NOT-COMMIT / DONOTCOMMIT / any case)
# is the convention for marking scratch/PoC edits that must never be staged.
# Excluded from the scan (self-reference only, not real markers):
#   - this script (documents/matches the marker literal to implement the check)
#   - .claude/rules/falco-ctf-app-conventions.md (documents the convention)
# Everything else tracked is in scope.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

rc=0
tripwire_excludes=(
  ':(exclude)scripts/check-flags.sh'
  ':(exclude).claude/rules/falco-ctf-app-conventions.md'
)

echo "==> scanning tracked files for DO NOT COMMIT tripwire markers"
tripwire=$(git grep -inE 'DO[ _-]*NOT[ _-]*COMMIT' -- . "${tripwire_excludes[@]}" 2>/dev/null || true)
if [ -n "$tripwire" ]; then
  echo "FAIL: 'DO NOT COMMIT' tripwire marker found in tracked file(s):" >&2
  echo "$tripwire" | sed 's/^/  /' >&2
  echo "  → this marks scratch/PoC content that must not be committed; remove it or drop the marker before committing." >&2
  rc=1
else
  echo "  ok: no DO NOT COMMIT markers in tracked files"
fi

echo "==> scanning tracked files for real flag literals"
bad=$(git grep -hoE 'FALCO\{[^}]*\}' -- . ':(exclude)*_test.go' 2>/dev/null \
  | sort -u \
  | grep -vE '^FALCO\{dev-.*\}$' \
  | grep -vE '^FALCO\{\.\.\.\}$' || true)
if [ -n "$bad" ]; then
  echo "FAIL: non-placeholder flag literal(s) found in tracked files:" >&2
  echo "$bad" | sed 's/^/  /' >&2
  echo "  locations:" >&2
  while IFS= read -r tok; do
    git grep -nF "$tok" -- . ':(exclude)*_test.go' | sed 's/^/    /' >&2
  done <<< "$bad"
  echo "  → move the real flag to platform events/<date>/flags.sops.yaml; use FALCO{dev-...} here." >&2
  rc=1
else
  echo "  ok: only FALCO{dev-...} / FALCO{...} placeholders present"
fi

# ADR-0056 V84: an event's render output never enters the public repository. The script is
# run through bash so that its file mode does not decide whether the guard runs.
if ! bash ./scripts/check-edition-headers.sh; then
  rc=1
fi
if ! bash ./scripts/check-edition-headers.sh --selftest; then
  echo "FAIL: the self-test of check-edition-headers.sh: the guard is not shown able to fail" >&2
  rc=1
fi

echo "==> checking generated challenge values are in sync"
if ! ./challenges/gen-values.sh --check; then
  echo "  → run 'make gen-values' and commit the result" >&2
  rc=1
fi

# ADR-0055 V1: gen-values.sh refuses a scenario whose id is not its directory's name and a
# challenge listed twice in one scenario. This runs each refusal (and its control) on a
# copy of the tree, so the checks are shown able to fail on every run. Run through bash so
# that the file mode does not decide whether it runs.
echo "==> gen-values.sh scenario checks can fail (ADR-0055 V1 self-test)"
if ! bash ./scripts/test-gen-values-scenarios.sh; then
  echo "FAIL: the self-test of gen-values.sh's scenario checks (scripts/test-gen-values-scenarios.sh)" >&2
  rc=1
fi

exit "$rc"
