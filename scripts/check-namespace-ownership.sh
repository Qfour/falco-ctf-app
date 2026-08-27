#!/usr/bin/env bash
# ADR-0011 (Accepted) follow-up (platform#111): fail-closed static guard that
# no chart under charts/ renders a `kind: Namespace` object.
#
# WHY THIS EXISTS
# ----------------
# ADR-0011 moved Namespace ownership for auth-policy/collector/scoreboard/docs
# from "each chart templates its own Namespace" to a single platform-side
# bootstrap release (`helmfile/releases/namespaces`, falco-ctf-platform). The
# whole point of that ADR was to make "two Helm releases claim the same
# Namespace object" structurally impossible. `helm lint` / `helm template
# >/dev/null` (the chart-lint job, pre-existing) never inspect rendered
# *content* — so re-adding `templates/namespace.yaml` to one of those charts
# (or to a brand-new chart added later) would go undetected and silently
# reintroduce the exact ownership conflict ADR-0011 closed. See
# docs/adr/0011-namespace-bootstrap-single-owner.md, Consequences
# ("新たに守る前提") and the org's 2026-08-18 self-diagnosis: rules that
# aren't machine-enforced get ~0% compliance.
#
# WHY RENDER (helm template), NOT A SOURCE GREP
# -----------------------------------------------
# This checks `helm template` *output*, not template source text, for the
# same reason scripts/check-seccomp.py does: a chart could in principle
# assemble `kind: Namespace` indirectly (via an included helper, or split
# across `{{- if }}` branches) in a way a literal source grep would miss.
# Rendering and inspecting the actual manifest catches that regardless of
# how the chart's templates are structured.
#
# THE MATCH ITSELF MUST TOLERATE INDENTATION AND QUOTING (5x R2, MEDIUM,
# mutation-tested 2026-08): an exact full-line match (`grep -qx 'kind:
# Namespace'`, no leading-whitespace tolerance) misses a Namespace object
# nested inside a `kind: List` `items:` array — YAML that `helm template`
# happily renders, where the `kind: Namespace` line is indented, not
# flush-left. That's a live way to (accidentally or not) reintroduce the
# exact ADR-0011 violation this script exists to catch, and it slipped past
# the "verified once by hand" check when this script was first written —
# the fixture chart scripts/testdata/namespace-ownership-FIXTURE/charts/list-chart
# reproduces it (mutation-tested: reverting to the exact-match grep
# reproduces a false PASS on that fixture). The regex below
# (`^[[:space:]]*kind:[[:space:]]*"?Namespace"?[[:space:]]*$`) matches
# `kind: Namespace` at any indentation and tolerates an optional quoted
# value (`kind: "Namespace"`), while still anchoring on the full value so it
# does not false-positive on `kind: NamespaceList` or similar — same pattern
# falco-ctf-platform's check-namespace-guard.sh already uses.
#
# SCOPE: charts/ctf-user is no longer excluded (Issue #198, follow-up to
# platform#75 / ADR-0011). ADR-0011's Context section explains why folding
# ctf-user's namespace into the platform bootstrap release isn't structurally
# straightforward (dynamic per-participant namespaces vs. a static
# `.Values.namespaces` list). platform#75 (deploy-user.sh's missing `-n`) was
# instead fixed by applying ADR-0011's single-owner *principle* directly in
# deploy-user.sh: that script now creates/labels the `ctf-<user>` Namespace
# itself with plain `kubectl` before ever calling helm, and
# charts/ctf-user/templates/namespace.yaml has been removed — so the real
# chart no longer renders a Namespace object at all and passes this guard
# with no exclusion needed. An unconditional by-name exclusion left in place
# after that fix would itself become the exact kind of unenforced regression
# this guard exists to prevent: if a future PR reintroduced
# charts/ctf-user/templates/namespace.yaml, an exclusion would let it pass
# silently. So the exclusion has been lifted; ctf-user is checked exactly
# like every other chart under charts/.
#
# Exit status: 0 iff no in-scope chart renders a Namespace object and every
# in-scope chart renders successfully. Never fail-open: a `helm template`
# failure is itself a violation (fail-closed), and the chart-directory
# extraction asserts non-empty before looping (an empty extraction must never
# read as "nothing to check, so pass").
#
# Usage:
#   ./scripts/check-namespace-ownership.sh                   # checks charts/ (repo-relative)
#   ./scripts/check-namespace-ownership.sh --charts-dir DIR   # checks DIR instead
#     (--charts-dir is used by the CI negative test (5x R3 follow-up) to point
#      this same script at scripts/testdata/namespace-ownership-FIXTURE/charts,
#      a tree with a deliberately-violating chart, without touching the real
#      charts/ directory. Mirrors falco-ctf-platform's
#      check-namespace-guard.sh --releases-dir.)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

CHARTS_DIR="charts"
RC=0

if [ "${1:-}" = "--charts-dir" ]; then
  CHARTS_DIR="${2:?--charts-dir requires a directory}"
fi

shopt -s nullglob
chart_dirs=("$CHARTS_DIR"/*/)
shopt -u nullglob

if [ "${#chart_dirs[@]}" -eq 0 ]; then
  echo "FAIL: no chart directories found under ${CHARTS_DIR}/ — treating a" \
       "zero-chart extraction as a failure, not a vacuous pass" >&2
  exit 1
fi

for chart_dir in "${chart_dirs[@]}"; do
  chart="$(basename "$chart_dir")"

  # P21 item 5 (falco-ctf-common): a `type: library` chart cannot be
  # `helm template`-d on its own ("library charts are not installable",
  # regardless of content). Its named templates only ever render once
  # `include`d by a real chart, and every such caller
  # (scoreboard/auth-policy/collector) is still checked below with the
  # library's templates expanded inline — so skipping the library chart
  # itself here is not a coverage gap.
  if grep -qE '^type:[[:space:]]*library[[:space:]]*$' "${chart_dir}Chart.yaml" 2>/dev/null; then
    echo "== ${chart} == (type: library — not installable, skipping)"
    continue
  fi

  echo "== ${chart} =="
  manifest=""
  if ! manifest="$(helm template "$chart_dir" 2>&1)"; then
    echo "  FAIL: helm template failed for ${chart}:" >&2
    echo "$manifest" >&2
    RC=1
    continue
  fi

  if grep -qE '^[[:space:]]*kind:[[:space:]]*"?Namespace"?[[:space:]]*$' <<<"$manifest"; then
    echo "  FAIL: ${chart} renders a document with kind: Namespace" \
         "(ADR-0011: Namespace ownership belongs solely to the platform-side" \
         "'namespaces' bootstrap release — this chart must not template its own)" >&2
    RC=1
  else
    echo "  ok: no kind: Namespace in rendered output"
  fi
done

echo
if [ "$RC" -ne 0 ]; then
  echo "FAIL: namespace ownership invariant violated (ADR-0011) — see FAIL lines above." >&2
  exit 1
fi

echo "OK: no chart under charts/ renders a Namespace object."
