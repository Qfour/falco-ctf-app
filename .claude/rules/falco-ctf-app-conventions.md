# Falco CTF App Conventions — Source of Truth

このファイルが **唯一の正典**。CLAUDE.md / AGENTS.md は概要のみ持ち、
詳細な制約はここを参照する。

## UID 一覧 (runtime user)

| サービス | UID | 根拠 |
|---|---|---|
| scoreboard | **65532** | distroless/static-debian12:nonroot |
| auth-policy | **65532** | distroless/static-debian12:nonroot |
| ttyd | **1000** | alpine adduser -D -u 1000 ttyd |
| challenge | **root (0)** | CTF realism — ユーザが体験するシェル環境 |

## Hard Invariants (違反は即 blocking)

| # | ルール |
|---|---|
| I1 | scoreboard は `replicas: 1` + `strategy: Recreate` 固定 (SQLite 並行書込不可) |
| I2 | scoreboard / auth-policy のコンテナ `runAsUser: 65532` |
| I3 | scoreboard PVC `fsGroup: 65532` |
| I4 | image tag は **git SHA** で push。`latest` で本番 deploy 禁止 |
| I5 | 全 4 イメージ (scoreboard / auth-policy / ttyd / challenge) を **同一 git SHA** でビルド・push |
| I6 | challenges/ は scoreboard と同一 repo に置く (falco-rule.yaml が scoreboard の一次消費) |
| I7 | `base/` は環境非依存。hostname / domain は placeholder (`example.invalid`) |
| I8 | auth-policy は `X-Auth-Request-Email` を **prefix-exact** (`<username>@`) で照合。緩めない |
| I9 | challenge コンテナ Dockerfile に Service / Ingress を追加しない |
| I10 | Dockerfile / yaml にトークン・実シークレットを焼き込まない |

## Dockerfile 規約

| サービス | builder | final |
|---|---|---|
| scoreboard | `golang:1.23-alpine` | `gcr.io/distroless/static-debian12:nonroot` |
| auth-policy | `golang:1.23-alpine` | `gcr.io/distroless/static-debian12:nonroot` |
| ttyd | (single-stage) | `alpine:3.20` |
| challenge | (single-stage) | `alpine:3.20` |

- Go ビルドは `CGO_ENABLED=0 -ldflags="-s -w" -trimpath` で static binary
- scoreboard / auth-policy の build context = repo root

## SecurityContext (コンテナレベル)

scoreboard / auth-policy に必須:
```yaml
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

## Security

- `.env` / kubeconfig / `*.key` / `*.pem` / `*.db` はコミットしない
- 課題用ダミー値 (`P@ssw0rd`, `flag{...}`) は LOW 扱い、明確にダミーと示す
- `git add .` / `git add -A` 禁止 (明示パス指定のみ)

## Scope / 影響範囲

| 変更箇所 | 影響 |
|---|---|
| `scoreboard/` | 採点ロジック直結。`POST /falco/events` payload を変えるなら platform 側も同時 PR |
| `auth-policy/` | セキュリティ境界。`X-Auth-Request-Email` 解釈は絶対に緩めない |
| `challenges/<NN>-<slug>/` | その課題のみ |
| `images/{ttyd,challenge}/` | 全ユーザ環境に影響 |
| `deploy/<app>/base/` | 全環境。`overlays/<env>/` は当該環境のみ |

## Cross-repo 契約 (falco-ctf-platform との接点)

| 接点 | 詳細 |
|---|---|
| Image tag | `${REGISTRY}/falco-ctf-{scoreboard,auth-policy,ttyd,challenge}:<git-sha>` |
| Challenges path | platform の `deploy-user.sh --challenges-dir` が当 repo `challenges/` を指す |
| Webhook payload | `POST /falco/events` は falcosidekick 標準形。フィールドキー変更は両 repo 同時 PR |
| Cookie domain | `.<ctf-domain>` は platform が決定。app 側は前提とする |
