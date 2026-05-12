---
description: Challenge レビュー — reviewer + challenge-author を並列実行。パターン C 向け。
argument-hint: [challenge ID or path, e.g. 06-new-challenge]
---

Run BOTH subagents in a **single message with two parallel Agent tool calls** so they execute concurrently.

1. **`reviewer` subagent** — Schema correctness:
   - `falco-rule.yaml` の `type:` 必須フィールド、`FALCO{...}` flag 形式
   - `challengeId` の uniqueness (既存 challenges/ との重複なし)
   - `catalog.Load` が通るか (`internal/catalog/catalog.go` の validation 通過)
   - README の完結性 (ゴール・ヒント・想定手順)
   - Focus: $ARGUMENTS

2. **`challenge-author` subagent** — Design quality:
   - Falco ルールの実現可能性 (デフォルトルールセットで発火するか)
   - CTF 難易度のバランス
   - evade challenge の場合: 抜け穴・別解の想定
   - flag 文字列の強度 (推測困難か、他 challenge と重複しないか)
   - Focus: $ARGUMENTS

After BOTH complete, merge the verdicts:

```
## Overall Verdict
APPROVE / APPROVE WITH NITS / REQUEST CHANGES

## Blocking
<prefixed with [schema] or [design]>

## Non-blocking

## Nits
```

Do NOT implement fixes. Surface findings only. Match the user's language.
