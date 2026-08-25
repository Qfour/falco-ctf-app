#!/usr/bin/env bash
# ADR-0011 (Accepted) follow-up (platform#111): fail-closed static guard that
# no chart under charts/ (except charts/ctf-user, which ADR-0011 explicitly
# excludes) renders a `kind: Namespace` object.
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
# SCOPE: charts/ctf-user is excluded. ADR-0011's Context section explains why
# ("ctf-user は対象外") — deploy-user.sh doesn't pass -n/--create-namespace to
# `helm upgrade --install`, so ctf-user doesn't hit the same failure modes
# today, and folding it into the platform bootstrap release isn't structurally
# straightforward (dynamic per-participant namespaces vs. a static
# `.Values.namespaces` list). Revisit only alongside platform#75.
#
# Exit status: 0 iff no in-scope chart renders a Namespace object and every
# in-scope chart renders successfully. Never fail-open: a `helm template`
# failure is itself a violation (fail-closed), and the chart-directory
# extraction asserts non-empty before looping (an empty extraction must never
# read as "nothing to check, so pass").
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

CHARTS_DIR="charts"
EXCLUDE_CHART="ctf-user"
RC=0

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

  if [ "$chart" = "$EXCLUDE_CHART" ]; then
    echo "== ${chart} (skipped — ADR-0011 excludes ctf-user from this guard) =="
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

  if grep -qx 'kind: Namespace' <<<"$manifest"; then
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

echo "OK: no chart under charts/ (excluding ${EXCLUDE_CHART}) renders a Namespace object."
