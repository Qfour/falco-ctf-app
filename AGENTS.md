# AGENTS.md — falco-ctf-app

<!-- AI agent 共通指示。ツール固有機能は書かない。 -->

## Project Overview

- **Stack**: Python 3.12 (FastAPI) + Alpine Dockerfile + Kustomize
- **Purpose**: Falco CTF のアプリ層(scoreboard / auth-policy / user-facing images / challenges)
- **Project label**: `falco-ctf`
- **Cross-repo**: 基盤は `falco-ctf-platform`

## Commands

```bash
# ローカル dev (hot-reload)
make dev                                  # docker compose up
make dev-down

# image build / push
make build                                # 全イメージを REGISTRY=$REGISTRY TAG=$TAG で build
make push
make load-colima                          # colima k3s containerd に取込 (local only)

# colima にデプロイ
make deploy-local                         # kubectl apply -k deploy/*/overlays/local

# Kustomize 整合性チェック
make lint

# scoreboard 動作確認
curl -X POST http://localhost:8000/falco/events -H 'content-type: application/json' \
  -d '{"rule":"Read sensitive file untrusted","priority":"Warning",
       "output_fields":{"k8s.ns.name":"ctf-user1",
                        "container.image.repository":"falco-ctf/challenge"}}'
curl http://localhost:8000/api/state | jq
```

## Code Style

### File naming

- Python app: `<app>/{Dockerfile, requirements.txt, app/main.py}`
- イメージのみ: `images/<name>/Dockerfile`
- 課題: `challenges/<NN>-<slug>/` (NN は 2 桁ゼロパディング、slug は kebab-case)
- Kustomize: `deploy/<app>/{base,overlays/<env>}/kustomization.yaml`
- スクリプト: `scripts/<name>.sh` (kebab-case)

### Challenge ディレクトリ規約

```
challenges/<NN>-<slug>/
├── README.md            # 出題文 + ヒント + 想定解
├── fixtures/            # challenge コンテナへ仕込むファイル (ConfigMap 経由 mount)
├── falco-rule.yaml      # challengeId + type + expected/forbiddenRules (scoreboard が読む)
└── values.yaml          # (任意) ctf-user chart に重ねる Helm values overlay
```

`falco-rule.yaml` 必須フィールド:

```yaml
# trigger 型 (ルール発火で solved)
challengeId: "01-read-shadow"
type: trigger
expectedRules: ["Read sensitive file untrusted"]

# evade 型 (flag submit + 直近 windowSeconds 秒に forbidden 発火なしで solved)
challengeId: "02-evade-shadow-read"
type: evade
forbiddenRules: ["Read sensitive file untrusted"]
expectedFlag: "FALCO{...}"
windowSeconds: 10
```

### Dockerfile 規約

- 全イメージ Alpine ベース (`python:3.12-alpine` / `alpine:3.20`)
- 最終 USER は **非 root (1000)**。例外: `images/challenge/` は CTF realism のため root
- scoreboard / auth-policy は build context = repo root (`COPY <app>/...` 形式)
- ttyd / challenge は build context = `images/<name>/`

### Kustomize 規約

- `base/` は環境非依存。host / domain は placeholder (`example.invalid`)
- `overlays/<env>/` で実値をパッチ
- `images:` field で tag を上書き(`newTag: <git-sha>`)

## Boundaries

- **Do NOT** challenges/ を別 repo に分離する
  → scoreboard が `expectedRules` を読むので密結合。リリースサイクルが一致する必要
- **Do NOT** Dockerfile に機微情報を焼き込む
  → Secret + envFrom を使う
- **Do NOT** challenge コンテナの Dockerfile に Service / Ingress を追加する想定で書く
  → private 接続要件。ttyd の `kubectl exec` のみが入口(platform 側 chart で強制)
- **Do NOT** scoreboard を replica >1 で動かす
  → SQLite。並行書込不可。本番でも `strategy: Recreate` + replica 1
- **Do NOT** auth-policy の `X-Auth-Request-Email` 解釈を緩める
  → `<username>@` で始まることを必ず照合。緩めると別ユーザの workspace に到達できる
- **Do NOT** `git add .` / `git add -A`
  → 明示パス指定。`.env` や `.db` の混入を防ぐ
- **Do NOT** image tag を `latest` で本番 deploy
  → git SHA pin 必須。platform 側 PR で bump

## Always

- ✅ scoreboard / auth-policy / ttyd / challenge の image tag は **同一 git SHA**
  (CI で一括 push)
- ✅ challenge 追加時は scoreboard に動作確認(`POST /falco/events` で expected
  ルール → `/api/state` に solved 反映)
- ✅ Kustomize 編集後は `make lint` で全 overlay を `kustomize build`
- ✅ 機微情報は環境変数で渡す。Dockerfile / yaml にハードコードしない

## Falco event JSON フィールド早見表

| フィールド | 例 | 用途 |
|---|---|---|
| `output_fields["k8s.ns.name"]` | `ctf-user1` | ユーザ識別 |
| `output_fields["k8s.pod.name"]` | `workspace` | Pod 名 |
| `output_fields["container.image.repository"]` | `falco-ctf/challenge` | 課題種別 |
| `rule` | `Read sensitive file untrusted` | クリア判定キー |
| `priority` | `Warning` | フィルタ用 (notice 以上を採点対象) |
| `time` | `2026-05-08T07:15:32Z` | 重複イベント排除 |

## 関連リポジトリ

| Repo | 関係 |
|---|---|
| `falco-ctf-platform` | 基盤 (Falco / ingress / Dex / oauth2-proxy / cert-manager) + ctf-user chart + Terraform (EKS) |

## Git

- Commit messages: Conventional Commits
  例: `feat(scoreboard): add evade-type windowing`,
      `fix(auth-policy): tighten email prefix match`,
      `feat(challenge): add 06-pty-spawn`
- ブランチ戦略: `main` ← `feature/<ticket-id>-<slug>`
- PR スコープ: 1 サービス変更を 1 PR
