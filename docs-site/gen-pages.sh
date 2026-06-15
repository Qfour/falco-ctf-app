#!/usr/bin/env bash
# Generate MkDocs pages per challenge from the canonical challenges/ tree.
# Single source of truth: challenges/<NN>-<slug>/{fixtures/welcome.txt,README.md}.
# Images (optional): docs/assets/missions/<NN>-<slug>/*.
#
# Two modes control what each page contains:
#   participant — mission brief only (welcome.txt). NO 想定解 / 解説 (no spoilers).
#   admin       — brief + 攻略と解説 (README body). 運営専用。
#
# Run from docs-site/ with repo root as $1 (default ..) and mode as $2.
#   ./gen-pages.sh .. participant
#   ./gen-pages.sh .. admin
set -euo pipefail

ROOT="${1:-..}"
MODE="${2:-participant}"
case "$MODE" in participant|admin) ;; *) echo "mode must be participant|admin" >&2; exit 2;; esac
MISS="docs/missions"
rm -rf "$MISS"
mkdir -p "$MISS"
shopt -s nullglob

{
  echo "# ミッション一覧"
  echo
  if [ "$MODE" = admin ]; then
    echo '!!! warning "運営専用ビュー"'
    echo "    各ページに **想定解・解説** を含みます。参加者には配布しないこと。"
    echo
    echo "Operation NimbusBreach の全ミッション。ミッションブリーフ + 攻略・解説、"
    echo "ページ上部から PDF をダウンロードできます。"
  else
    echo "Operation NimbusBreach の全ミッション。各ページにミッションブリーフ、"
    echo "ページ上部から PDF をダウンロードできます。"
  fi
} > "$MISS/index.md"

for d in "$ROOT"/challenges/[0-9][0-9]-*/; do
  [ -d "$d" ] || continue
  nn="$(basename "$d")"
  readme="$d/README.md"
  [ -f "$readme" ] || { echo "skip $nn (no README.md)"; continue; }
  title="$(sed -n '1s/^#[[:space:]]*//p' "$readme")"
  [ -n "$title" ] || title="Mission ${nn%%-*}"
  page="$MISS/${nn}.md"

  {
    echo "# ${title}"
    echo
    if [ "$MODE" = admin ]; then
      echo '!!! warning "運営専用 — 想定解・解説を含む"'
      echo
    fi
    echo "[PDF をダウンロード](/pdf/${nn}.pdf){ .md-button .md-button--primary }"
    echo
    for img in docs/assets/missions/"$nn"/*; do
      [ -f "$img" ] || continue
      case "$img" in *.md) continue;; esac
      echo "![${nn}](../assets/missions/${nn}/$(basename "$img"))"
      echo
    done
    if [ -f "$d/fixtures/welcome.txt" ]; then
      echo "## ミッションブリーフ"
      echo
      echo '```text'
      cat "$d/fixtures/welcome.txt"
      echo '```'
      echo
    fi
    if [ "$MODE" = admin ]; then
      echo "## 攻略と解説"
      echo
      tail -n +2 "$readme"
    fi
  } > "$page"
  echo "generated [$MODE] $page"
done
