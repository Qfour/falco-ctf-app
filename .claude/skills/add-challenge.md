---
name: add-challenge
description: Step-by-step procedure for adding a new CTF challenge to challenges/<NN>-<slug>/
type: skill
---

# Challenge 追加手順

## 1. 番号とスラグを決める

```bash
ls challenges/ | sort | tail -1   # 現在の最大番号を確認
# 次の NN = 最大 + 1 (ゼロ埋め 2 桁)
# slug = falco ルール名をケバブケースに変換した略称
```

## 2. ディレクトリを作る

```bash
NN=06
SLUG=my-challenge
mkdir -p challenges/${NN}-${SLUG}/fixtures
```

## 3. `falco-rule.yaml` を書く

**trigger 型**（ユーザがルールを発火させる課題）:
```yaml
challengeId: "${NN}-${SLUG}"
type: trigger
expectedRules:
  - "Exact Falco Rule Name Here"
```

**evade 型**（ルールを発火させずにフラグを取る課題）:
```yaml
challengeId: "${NN}-${SLUG}"
type: evade
forbiddenRules:
  - "Exact Falco Rule Name Here"
expectedFlag: "FALCO{descriptive_l33tspeak_2026}"
windowSeconds: 10
```

フラグ重複確認:
```bash
grep -r "expectedFlag" challenges/   # 重複がないこと
grep -r "challengeId" challenges/    # ID 重複がないこと
```

## 4. `values.yaml` を書く（evade 型のみ）

```yaml
challenge:
  extraEnv:
    - name: CTF${NN}_FLAG
      value: "FALCO{...}"
  postStart:
    - sh
    - -c
    - >-
      printf '# falco-ctf flag: %s\n' "${CTF${NN}_FLAG}" >> /etc/shadow
```

## 5. `fixtures/welcome.txt` を書く

```
ようこそ！
この課題の目標: <一文でゴールを説明>
ヒント: <最初のとっかかり>
```

evade 型は `fixtures/submit.sh` も作る:
```bash
#!/bin/sh
# フラグを scoreboard に提出する
FLAG=${1:-$CTF${NN}_FLAG}
curl -s -X POST http://scoreboard.scoreboard.svc.cluster.local:8000/falco/submit \
  -H "Content-Type: application/json" \
  -d "{\"challengeId\":\"${NN}-${SLUG}\",\"flag\":\"${FLAG}\"}"
```

## 6. `README.md` を書く

必須セクション:
- `## 出題文` — ユーザへの指示
- `## クリア条件` — 何が起きたらクリアか
- `## 想定解` — コマンド例 + 解説
- `## 仕組みの解説` — Falco 観測層、ルール条件の内訳
- `## ヒント (難易度別)` — 易/中/難

## 7. scoreboard に認識させる

```bash
make dev   # scoreboard を再起動 (catalog は起動時 1 回ロード)
# または
docker compose restart scoreboard
```

## 8. 動作確認

```bash
# scoreboard の challenge 一覧に新課題が出ること
curl -s http://localhost:8000/api/state | jq '.challenges[] | select(.id == "${NN}-${SLUG}")'
```

## チェックリスト

- [ ] `challengeId` が一意
- [ ] `expectedFlag` が一意（evade のみ）
- [ ] Falco ルール名が公式と完全一致
- [ ] `fixtures/welcome.txt` が存在
- [ ] `README.md` が全セクションを持つ
- [ ] scoreboard 再起動後に `/api/state` に表示される
