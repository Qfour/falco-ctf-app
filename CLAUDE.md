# CLAUDE.md — falco-ctf-app

## プロジェクト概要

Falco CTF のアプリケーション層。scoreboard / auth-policy / ttyd / challenge image
と、出題コンテンツ (challenges/) を持つ。基盤(Falco, ingress, Dex, oauth2-proxy)
と ctf-user chart は別リポジトリ **`falco-ctf-platform`** にある。

## アーキテクチャ

```
falco-ctf-app/
├── scoreboard/         FastAPI (Falco webhook → SQLite)
├── auth-policy/        FastAPI (oauth2-proxy 経由で host↔email 認可)
├── images/{ttyd,challenge}/   Dockerfile のみ
├── challenges/<NN>-<slug>/    README + falco-rule.yaml + fixtures + values.yaml
├── deploy/<app>/{base,overlays/<env>}/   Kustomize
├── scripts/            build-and-load.sh (colima 用), mock-oauth2.conf
├── docker-compose.yml  ローカル dev (scoreboard + auth-policy + mock-oauth2)
└── Makefile            dev / build / push / load-colima / deploy-local
```

## 設計判断 (why, not what)

- **scoreboard と challenges/ は同一 repo** — 採点ロジック(`expectedRules`)が
  challenge メタデータを直接読むので、リリースサイクルが完全一致。別 repo にすると
  scoreboard が古い challenge スキーマで動く事故が起きる。

- **scoreboard Dockerfile は repo root を context にする** — `COPY challenges/`
  でカタログをイメージに焼き込む。runtime で `/app/challenges` を volume mount
  すれば overlay 可能(local dev では compose で実体 mount)。

- **auth-policy は別サービス** — oauth2-proxy 単体では「認証済ユーザ = 全 workspace
  到達可」になる問題を解消するため。`X-Auth-Request-Email` を読んで
  `<username>@` 一致を確認する小さな FastAPI。

- **ttyd / challenge イメージはここに置く** — ユーザの体験面はアプリ層の責務。
  platform 側の ctf-user chart は image tag を values で pin するだけ。

- **Kustomize は base = 環境非依存** — `host` や `EXPECTED_EMAIL_DOMAIN` は
  overlay でパッチ。base には placeholder (`example.invalid`) を入れる。

- **docker-compose に mock-oauth2 を含める** — auth-policy 単体テストのため。
  本物の Dex を立てるコストを払わずに /check 経路が動く。

## クロスリポ契約 (falco-ctf-platform 側との接点)

| 接点 | 契約 |
|---|---|
| Image | `${REGISTRY}/falco-ctf-{ttyd,challenge,scoreboard,auth-policy}:<tag>`。tag は git SHA。platform 側 chart/manifest が values で pin |
| Challenges path | platform の `deploy-user.sh --challenges-dir <path>` が当 repo の `challenges/` を指す。CI では sparse checkout |
| Webhook payload | `POST /falco/events` の JSON は falcosidekick 標準形。フィールドキー変更は両 repo 同時 PR |
| Cookie domain | `.<ctf-domain>` は platform が決定。app 側は前提とする |

## Claude Code Workflow

- **イメージビルド + colima 取込** → `make load-colima`
- **ローカル全層起動** → `make dev` (compose) または `make deploy-local` (colima)
- **新しい challenge 追加** → `challenges/<NN>-<slug>/` を作って falco-rule.yaml と
  README を書く。scoreboard を再起動して認識させる
- 規約・境界は AGENTS.md と `.claude/rules/` を参照
