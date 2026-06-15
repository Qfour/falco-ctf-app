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
| I7 | chart の `values.yaml` default は環境非依存。host/domain/registry は placeholder (`example.invalid` / `docker.io/falco-ctf`)。環境値は platform helmfile が供給 |
| I8 | auth-policy は `X-Auth-Request-Email` を **prefix-exact** (`<username>@`) で照合。緩めない |
| I9 | challenge コンテナ Dockerfile に Service / Ingress を追加しない |
| I10 | Dockerfile / yaml にトークン・実シークレットを焼き込まない |

## Dockerfile 規約

| サービス | builder | final |
|---|---|---|
| scoreboard | `golang:1.25-alpine` | `gcr.io/distroless/static-debian12:nonroot` |
| auth-policy | `golang:1.25-alpine` | `gcr.io/distroless/static-debian12:nonroot` |
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
- **実フラグをコミットしない (public repo)**。`falco-rule.yaml` は `FALCO{dev-<slug>}`
  placeholder のみ。実フラグは platform `events/<date>/flags.sops.yaml`。
  `make check-flags` (CI: `flag-guard`、PreCommit hook) が混入を block。
- 課題用ダミー値 (`P@ssw0rd`) は LOW 扱い、明確にダミーと示す
- `git add .` / `git add -A` 禁止 (明示パス指定のみ)

## フラグ注入 (flag injection) — 単一ソース

- 採点側: scoreboard が `FLAGS_FILE` (yaml `{flags: {id: FALCO{...}}}`) を読み、
  evade challenge の `expectedFlag` を起動時に上書き (`catalog.ApplyFlagOverrides`、
  fail-closed)。空なら placeholder のまま (local/test)。
- 仕込み側: `challenges/<NN>/plant.sh` が唯一の正典。フラグ実値は書かず
  `${CTF_FLAG_<ID>}` env を参照 (`<ID>` = challengeId 大文字・`-`→`_`)。
- `values.yaml` / `values-all.yaml` は `make gen-values` で plant.sh から生成。
  **手書き禁止**。CI `flag-guard` が同期を検証。
- 採点フラグ (FLAGS_FILE) と仕込みフラグ (CTF_FLAG_*) は platform の
  同一 `flags.sops.yaml` から render され、必ず一致する。

## Scope / 影響範囲

| 変更箇所 | 影響 |
|---|---|
| `scoreboard/` | 採点ロジック直結。`POST /falco/events` payload を変えるなら platform 側も同時 PR |
| `auth-policy/` | セキュリティ境界。`X-Auth-Request-Email` 解釈は絶対に緩めない |
| `challenges/<NN>-<slug>/` | その課題のみ |
| `images/{ttyd,challenge}/` | 全ユーザ環境に影響 |
| `charts/<name>/` | 全環境。default は環境非依存、環境値は platform helmfile が供給 |

## Cross-repo 契約 (falco-ctf-platform との接点)

| 接点 | 詳細 |
|---|---|
| Image tag | `${REGISTRY}/falco-ctf-{scoreboard,auth-policy,ttyd,challenge}:<git-sha>` (registry の repo 名は `falco-ctf/X` slash 推奨; `falco-ctf-X` dash も ingest 受理) |
| Charts | `charts/{scoreboard,auth-policy,ctf-user}` を CI が `oci://<ECR>/charts` へ `0.1.0-<sha>` で publish。platform helmfile が local=path / prod=OCI で参照 |
| Challenges path | `deploy-user.sh --challenges-dir` (ctf-user chart 同梱、当 repo `challenges/` を default 参照) |
| Webhook payload | `POST /falco/events` は falcosidekick 標準形。フィールドキー変更は両 repo 同時 PR |
| Cookie domain | `.<ctf-domain>` は platform が決定。app 側は前提とする |
| Flags | platform `events/<date>/flags.sops.yaml` が正典。scoreboard へ `FLAGS_FILE`、challenge コンテナへ `CTF_FLAG_<ID>` env として注入。app は `FALCO{dev-<slug>}` placeholder のみ保持。dev default 値は両 repo で一致させる |

## scoreboard ingest フィルタ (defense-in-depth)

`internal/scoreboard/ingest/ingest.go` の image substring check は
`falco-ctf/challenge` **または** `falco-ctf-challenge` を受理する。
ECR が repo 名で `/` を許すので slash 命名が正式だが、containerd の
image dedup で push 名と Falco 報告名が乖離するケース (同一 digest を
別 repo にも push したケース) に対応するため dash 形も許容。

新しい registry を追加する場合は image string が `falco-ctf/challenge` /
`falco-ctf-challenge` のどちらかを含むよう repo 命名する。

## Prod 値の供給 (chart には焼き込まない)

scoreboard / auth-policy / ctf-user chart の `values.yaml` は placeholder default
のみ (`example.invalid` / `docker.io/falco-ctf` / `FALCO{dev-...}` / `ADMIN_EMAILS=""`)。
本番値 (実 host・ECR registry・image tag・EXPECTED_EMAIL_DOMAIN・ADMIN_EMAILS) は
**platform helmfile の prod 環境値**が供給する (`falco-ctf-platform/helmfile/environments/prod.yaml.gotmpl`
+ `releases/{scoreboard,auth-policy}/values*.gotmpl`)。chart に実値をコミットしない。

> kustomize `deploy/` は P2 で廃止。k8s マニフェストの正典は `charts/`。
