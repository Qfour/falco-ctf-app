#!/usr/bin/env bash
# check-freshness.sh — fail if any Dockerfile base-image OS/runtime cycle is
# past its EOL date (data: endoflife.date). Warn when EOL is within 90 days.
#
# 起因 (REFACTORING.md P8): alpine 3.20 の EOL (2026-04) を見逃し、CVE 修正が
# 来ないままイベント準備に入りかけた。イベント前チェックリスト
# (platform 側 preflight-event.sh) と定期実行から呼ぶ。
#
# Requires network access to endoflife.date.
# Exit codes: 0 = all OK, 1 = EOL/unknown cycle detected, 2 = network/data error.
# SKIP_FRESHNESS=1 は offline 開発時のみ使用可。イベント前チェックでは不可。
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${SKIP_FRESHNESS:-0}" = "1" ]; then
  echo "check-freshness: skipped (SKIP_FRESHNESS=1)"
  exit 0
fi

# 対象 Dockerfile は git 管理下の全 Dockerfile を自動発見 (新規追加のすり抜け防止)。
# heredoc が stdin を占有するため、FROM 行は env 変数で渡す。
FROM_LINES="$(git ls-files '*Dockerfile*' | xargs grep -h '^FROM ')"
export FROM_LINES

python3 - <<'PY'
import json, os, re, sys, urllib.request
from datetime import date, timedelta

# regex on the FROM line -> endoflife.date product slug
PRODUCTS = {
    r'(?:^|[/ ])alpine:(\d+\.\d+)':     'alpine-linux',
    r'golang:(\d+\.\d+)':               'go',
    r'nginx-unprivileged:(\d+\.\d+)':   'nginx',
    r'(?:^|[/ ])python:(\d+\.\d+)':     'python',
    r'static-debian(\d+)':              'debian',
}
WARN_WINDOW = timedelta(days=90)

cache = {}
def eol_of(product, cycle):
    if product not in cache:
        url = f'https://endoflife.date/api/{product}.json'
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                cache[product] = {row['cycle']: row.get('eol') for row in json.load(r)}
        except OSError as e:
            print(f'check-freshness: cannot reach {url} ({e}); '
                  'SKIP_FRESHNESS=1 は offline 開発時のみ。'
                  'イベント前チェックでは不可', file=sys.stderr)
            sys.exit(2)
        except json.JSONDecodeError as e:
            print(f'check-freshness: invalid JSON from {url} ({e}); '
                  'SKIP_FRESHNESS=1 は offline 開発時のみ。'
                  'イベント前チェックでは不可', file=sys.stderr)
            sys.exit(2)
    return cache[product].get(cycle)

seen, failed = set(), False
for line in os.environ['FROM_LINES'].splitlines():
    for pattern, product in PRODUCTS.items():
        m = re.search(pattern, line)
        if not m or (product, m.group(1)) in seen:
            continue
        cycle = m.group(1)
        seen.add((product, cycle))
        eol = eol_of(product, cycle)
        if eol is False:
            print(f'OK    {product} {cycle} (supported, no EOL date yet)')
        elif eol is None:
            # fail-closed: 未知の cycle は typo か EOL 済みで一覧から消えた可能性
            print(f'FAIL  {product} {cycle}: cycle not found on endoflife.date')
            failed = True
        elif eol is True:
            print(f'FAIL  {product} {cycle}: already EOL (no date)')
            failed = True
        else:
            d = date.fromisoformat(eol)
            if d <= date.today():
                print(f'FAIL  {product} {cycle}: EOL since {eol}')
                failed = True
            elif d - date.today() <= WARN_WINDOW:
                print(f'WARN  {product} {cycle}: EOL {eol} is within 90 days')
            else:
                print(f'OK    {product} {cycle} (EOL {eol})')

sys.exit(1 if failed else 0)
PY
