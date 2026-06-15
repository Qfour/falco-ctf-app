#!/usr/bin/env bash
# Generate one MkDocs page per challenge from the canonical challenges/ tree.
# Single source of truth: challenges/<NN>-<slug>/{fixtures/welcome.txt,README.md}.
# Images (optional) come from docs/assets/missions/<NN>-<slug>/*.
#
# Run from docs-site/ with the repo root as $1 (default ..). Idempotent.
#   ./gen-pages.sh ..
set -euo pipefail

ROOT="${1:-..}"
MISS="docs/missions"
mkdir -p "$MISS"
shopt -s nullglob

cat > "$MISS/index.md" <<'EOF'
# ミッション一覧

Operation NimbusBreach の全ミッション。各ページに **ミッションブリーフ** と
**攻略・解説**、ページ上部から **PDF ダウンロード** が利用できます。
EOF

for d in "$ROOT"/challenges/[0-9][0-9]-*/; do
  [ -d "$d" ] || continue
  nn="$(basename "$d")"                 # e.g. 01-initial-recon
  readme="$d/README.md"
  [ -f "$readme" ] || { echo "skip $nn (no README.md)"; continue; }
  title="$(sed -n '1s/^#[[:space:]]*//p' "$readme")"
  [ -n "$title" ] || title="Mission ${nn%%-*}"
  page="$MISS/${nn}.md"

  {
    echo "# ${title}"
    echo
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
    echo "## 攻略と解説"
    echo
    tail -n +2 "$readme"
  } > "$page"
  echo "generated $page"
done
