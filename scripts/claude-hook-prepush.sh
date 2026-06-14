#!/usr/bin/env bash
# PreToolUse hook: block git commit if secrets are staged.
# Receives tool input JSON on stdin. Exit 1 blocks the tool use.

set -euo pipefail

INPUT=$(cat)
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null || true)

# Only intercept git commit commands
if ! echo "$CMD" | grep -qE '^git commit'; then
    exit 0
fi

# Check staged files for secrets
STAGED=$(git diff --cached --name-only 2>/dev/null || true)
SECRET_FILES=$(echo "$STAGED" | grep -E '(^|/)(\.env(\.[^.]+)?|[^/]+\.key|[^/]+\.pem|[^/]+\.crt|[^/]+\.db|kubeconfig[^/]*)$' || true)

if [[ -n "$SECRET_FILES" ]]; then
    echo "⛔ blocked: シークレットファイルが staged に含まれています:" >&2
    echo "$SECRET_FILES" >&2
    echo "git restore --staged <file> でアンステージしてください" >&2
    exit 1
fi

# Block real CTF flag literals leaking into the public repo (allow FALCO{dev-...}
# and FALCO{...}). Scope to staged content only for speed.
if echo "$STAGED" | grep -qE '(^|/)challenges/'; then
    BAD_FLAGS=$(git diff --cached -U0 -- challenges/ \
        | grep -E '^\+' \
        | grep -oE 'FALCO\{[^}]*\}' \
        | sort -u \
        | grep -vE '^FALCO\{dev-.*\}$' \
        | grep -vE '^FALCO\{\.\.\.\}$' || true)
    if [[ -n "$BAD_FLAGS" ]]; then
        echo "⛔ blocked: 実フラグらしき文字列が staged に含まれています (public repo):" >&2
        echo "$BAD_FLAGS" | sed 's/^/  /' >&2
        echo "実フラグは platform events/<date>/flags.sops.yaml に置き、ここは FALCO{dev-...} を使ってください" >&2
        exit 1
    fi
fi

exit 0
