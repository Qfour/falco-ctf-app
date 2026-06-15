#!/usr/bin/env bash
# Challenge rule eval: every expectedRules / forbiddenRules entry across
# challenges/ must reference a rule name that actually EXISTS in the Falco
# ruleset the event deploys. A typo'd rule name is a silent failure — the rule
# never fires, so a trigger challenge is unsolvable / an evade gate is toothless.
#
# This is the CI-able layer of challenge validation. The live-fire layer ("does
# the rule actually fire when the intended action runs") needs a cluster — see
# falco-ctf-platform scripts/verify.sh for the Falco→scoreboard pipeline check.
#
# Pin matches the falco chart's bundled rules (helmfile falco release). Bump
# both together. Override the source with FALCO_RULES_URL for a local file.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

FALCO_RULES_REF="${FALCO_RULES_REF:-falco-rules-3.0.1}"
FALCO_RULES_URL="${FALCO_RULES_URL:-https://raw.githubusercontent.com/falcosecurity/rules/${FALCO_RULES_REF}/rules/falco_rules.yaml}"

rules_file="$(mktemp)"
trap 'rm -f "$rules_file"' EXIT
echo "==> fetching Falco ruleset (${FALCO_RULES_REF})"
curl -fsSL "$FALCO_RULES_URL" -o "$rules_file"

# Referenced rule names = uppercase-leading list items in falco-rule.yaml
# (only expectedRules / forbiddenRules use lists there).
refs="$(grep -rhoE '^[[:space:]]+- "?[A-Z][^"]+"?$' challenges/*/falco-rule.yaml \
  | sed 's/^[[:space:]]*- //; s/"//g' | sort -u)"

rc=0
while IFS= read -r r; do
  [ -z "$r" ] && continue
  if grep -qF "rule: $r" "$rules_file"; then
    echo "  ✓ $r"
  else
    echo "  ✗ MISSING from Falco ruleset: \"$r\"" >&2
    rc=1
  fi
done <<< "$refs"

if [ "$rc" -ne 0 ]; then
  echo "FAIL: a challenge references a Falco rule that does not exist in ${FALCO_RULES_REF}." >&2
  echo "  Fix the rule name, or bump FALCO_RULES_REF if the ruleset version changed." >&2
else
  echo "challenge rules: all referenced Falco rules exist"
fi
exit "$rc"
