#!/usr/bin/env bash
# Render check for the participant portal's evade card (ADR-0027 D6, V7).
#
# Extracts esc() (core-util.tmpl) and the evade render functions
# (pane-story.tmpl: evalPending / evadeSection / dirtySection /
# autoSolveStatus / submitForm) from the SOURCE, runs them under jsc
# (JavaScriptCore) for every status x dirty x requireExfil x exfilReceived
# combination and asserts on the produced HTML:
#   (a) a non-current, non-dirty evade never says the attempt is clean /
#       submittable / will auto-clear on a clean attempt
#   (b) a dirty evade shows the dirty card (and its reset button) in EVERY status
#   (c) the current evade keeps the existing copy
#   (d) a dirtyRules entry containing markup is escaped, never emitted raw
#
# Optional target (`make check-portal-render`), NOT part of `make test` / CI:
# jsc ships with macOS (no node in this repo's toolchain). It runs the real
# functions, but it is not a browser: layout, CSS and the click handlers are
# out of scope (that is the E2E harness, ADR-0031, not yet built).
set -euo pipefail
cd "$(dirname "$0")/.."

JSC="${JSC:-}"
if [ -z "$JSC" ]; then
  if command -v jsc >/dev/null 2>&1; then
    JSC="$(command -v jsc)"
  else
    JSC=/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc
  fi
fi
if [ ! -x "$JSC" ]; then
  echo "check-portal-render: jsc not found (macOS only; set JSC=/path/to/jsc)" >&2
  exit 2
fi

P=internal/scoreboard/view/templates/portal
out="$(mktemp -t portal-render.XXXXXX)"
trap 'rm -f "$out"' EXIT

python3 - "$P" > "$out" <<'PY'
import re, sys
p = sys.argv[1]
util = open(p + '/core-util.tmpl', encoding='utf-8').read()
m = re.search(r'^const esc = .*$', util, re.M)
assert m, 'esc definition not found in core-util.tmpl'
story = open(p + '/pane-story.tmpl', encoding='utf-8').read()

def fn(name):
    start = story.find('\n  function ' + name + '(')
    assert start >= 0, 'function ' + name + ' not found in pane-story.tmpl'
    nxt = story.find('\n  function ', start + 2)
    return story[start:nxt if nxt >= 0 else len(story)]

print(m.group(0))
for n in ('evalPending', 'submitForm', 'dirtySection', 'autoSolveStatus', 'evadeSection'):
    print(fn(n))
print(open('scripts/check-portal-render.js', encoding='utf-8').read())
PY

"$JSC" "$out"
