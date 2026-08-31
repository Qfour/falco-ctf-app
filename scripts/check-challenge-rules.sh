#!/usr/bin/env bash
# Challenge rule eval: every expectedRules / forbiddenRules entry across
# challenges/ must reference a rule name that actually EXISTS in the KNOWN
# rule set — the upstream Falco ruleset the event deploys, UNION the project's
# own customRules manifest (ADR-0008 Decision (5)). A typo'd rule name is a
# silent failure — the rule never fires, so a trigger challenge is unsolvable
# / an evade gate is toothless.
#
# This is the CI-able layer of challenge validation. The live-fire layer ("does
# the rule actually fire when the intended action runs") needs a cluster — see
# falco-ctf-platform scripts/verify.sh for the Falco→scoreboard pipeline check.
#
# Pin matches the falco chart's bundled rules (helmfile falco release). Bump
# both together. Override the source with FALCO_RULES_URL for a local file.
#
# ADR-0008 Decision (5): the platform's Falco deployment now also loads
# project-specific `customRules` (falco-ctf-platform/helmfile/releases/falco/
# values.yaml.gotmpl) — rule names that are genuinely new and DO NOT exist
# upstream. Comparing against upstream alone would make this required check
# (`challenge-rules`) fail permanently for any challenge that references one.
# CUSTOM_RULES_FILE is the single app-side manifest of those rule names (an
# ALLOWLIST of intentionally-added customRules, not a typo escape hatch — a
# name must ALSO not be in this file to be flagged).
#
# Second, independent check (issue #122): RULE_YAML_SYNC_GROUPS enforces that
# challenges/<NN>/rule.yaml (the participant-facing display excerpt, NOT this
# script's falco-rule.yaml rule-name check above) stays byte-identical across
# challenges that are built around the same underlying Falco rule.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

FALCO_RULES_REF="${FALCO_RULES_REF:-falco-rules-3.0.1}"
FALCO_RULES_URL="${FALCO_RULES_URL:-https://raw.githubusercontent.com/falcosecurity/rules/${FALCO_RULES_REF}/rules/falco_rules.yaml}"
CUSTOM_RULES_FILE="${CUSTOM_RULES_FILE:-challenges/custom-falco-rules.txt}"

rules_file="$(mktemp)"
trap 'rm -f "$rules_file"' EXIT
echo "==> fetching Falco ruleset (${FALCO_RULES_REF})"
curl -fsSL "$FALCO_RULES_URL" -o "$rules_file"

echo "==> loading project custom rule manifest (${CUSTOM_RULES_FILE})"
custom_rules=""
if [ -f "${CUSTOM_RULES_FILE}" ]; then
  custom_rules="$(grep -vE '^[[:space:]]*(#|$)' "${CUSTOM_RULES_FILE}" | sed -E 's/[[:space:]]+$//' || true)"
fi

# Referenced rule names = uppercase-leading list items in falco-rule.yaml
# (only expectedRules / forbiddenRules use lists there).
refs="$(grep -rhoE '^[[:space:]]+- "?[A-Z][^"]+"?$' challenges/*/falco-rule.yaml \
  | sed 's/^[[:space:]]*- //; s/"//g' | sort -u)"

rc=0
while IFS= read -r r; do
  [ -z "$r" ] && continue
  if grep -qF "rule: $r" "$rules_file"; then
    echo "  ✓ $r (upstream)"
  elif printf '%s\n' "$custom_rules" | grep -qxF "$r"; then
    echo "  ✓ $r (custom, ${CUSTOM_RULES_FILE})"
  else
    echo "  ✗ MISSING from the Falco ruleset AND from ${CUSTOM_RULES_FILE}: \"$r\"" >&2
    rc=1
  fi
done <<< "$refs"

if [ "$rc" -ne 0 ]; then
  echo "FAIL: a challenge references a Falco rule that does not exist in ${FALCO_RULES_REF} and is not declared in ${CUSTOM_RULES_FILE}." >&2
  echo "  Fix the rule name, bump FALCO_RULES_REF if the ruleset version changed, or add the rule name to ${CUSTOM_RULES_FILE} if it is a genuinely new customRule (ADR-0008 Decision (5))." >&2
else
  echo "challenge rules: all referenced Falco rules exist (upstream or declared custom)"
fi

# --- rule.yaml sync groups (issue #122) -----------------------------------
# challenges/<NN>/rule.yaml is the participant-facing DISPLAY excerpt of a
# Falco rule (docs site "background" section) — distinct from falco-rule.yaml
# (scoring metadata: expectedRules/forbiddenRules). Some challenges are
# deliberately built around the SAME underlying Falco rule shown from two
# angles, so their rule.yaml excerpts must stay byte-identical or
# participants see the rule's condition described differently depending on
# which mission they're on.
#
# Declare one group per shared rule as a single array element: a
# space-separated list of `challenges/<name>` dirs whose rule.yaml must be
# byte-identical. Adding a group is a 1-line edit.
#
# 02-credential-files (trigger) and 03-stealth-read (evade) both display the
# "Read sensitive file untrusted" upstream rule — 02 shows the trigger path,
# 03 shows the evade path, but it's the same rule text either way.
RULE_YAML_SYNC_GROUPS=(
  "02-credential-files 03-stealth-read"
)

echo "==> checking rule.yaml sync groups (byte-identical display excerpts)"
sync_rc=0
for group in "${RULE_YAML_SYNC_GROUPS[@]}"; do
  read -ra members <<< "$group"
  first="${members[0]}"
  first_file="challenges/${first}/rule.yaml"
  if [ ! -f "$first_file" ]; then
    echo "  ✗ sync group [$group]: missing $first_file" >&2
    sync_rc=1
    continue
  fi
  for member in "${members[@]:1}"; do
    member_file="challenges/${member}/rule.yaml"
    if [ ! -f "$member_file" ]; then
      echo "  ✗ sync group [$group]: missing $member_file" >&2
      sync_rc=1
      continue
    fi
    if cmp -s "$first_file" "$member_file"; then
      echo "  ✓ $first_file == $member_file"
    else
      echo "  ✗ sync group [$group]: $first_file and $member_file diverge (must be byte-identical) — diff:" >&2
      diff -u "$first_file" "$member_file" | head -20 >&2 || true
      sync_rc=1
    fi
  done
done

if [ "$sync_rc" -ne 0 ]; then
  echo "FAIL: a rule.yaml sync group has members that are not byte-identical (issue #122)." >&2
  echo "  These challenges deliberately display the same underlying Falco rule. When re-extracting rule.yaml after a Falco version bump, update ALL members of the group together (see RULE_YAML_SYNC_GROUPS in this script)." >&2
else
  echo "challenge rules: all rule.yaml sync groups are byte-identical"
fi

if [ "$sync_rc" -ne 0 ]; then
  rc=1
fi

exit "$rc"
