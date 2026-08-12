# Falco CTF App Conventions — Source of Truth

このファイルが **唯一の正典**。CLAUDE.md / AGENTS.md は概要のみ持ち、
詳細な制約はここを参照する。

## UID 一覧 (runtime user)

| サービス | UID | 根拠 |
|---|---|---|
| scoreboard | **65532** | distroless/static-debian13:nonroot |
| auth-policy | **65532** | distroless/static-debian13:nonroot |
| collector | **65532** | distroless/static-debian13:nonroot |
| ttyd | **1000** | alpine adduser -D -u 1000 ttyd |
| challenge | **root (0)** | CTF realism — ユーザが体験するシェル環境 |
| docs | **101** | nginxinc/nginx-unprivileged (静的サイト配信) |

## Hard Invariants (違反は即 blocking)

| # | ルール |
|---|---|
| I1 | scoreboard は `replicas: 1` + `strategy: Recreate` 固定 (SQLite 並行書込不可) |
| I2 | scoreboard / auth-policy / collector のコンテナ `runAsUser: 65532` |
| I3 | scoreboard PVC `fsGroup: 65532` |
| I4 | image tag は **git SHA** で push。`latest` で本番 deploy 禁止 |
| I5 | 全 6 イメージ (scoreboard / auth-policy / collector / ttyd / challenge / docs) を **同一 git SHA** でビルド・push |
| I6 | challenges/ は scoreboard と同一 repo に置く (falco-rule.yaml が scoreboard の一次消費) |
| I7 | chart の `values.yaml` default は環境非依存。host/domain/registry は placeholder (`example.invalid` / `docker.io/falco-ctf`)。環境値は platform helmfile が供給 |
| I8 | auth-policy `/check` は `X-Auth-Request-Email` を **prefix-exact** (`<username>@`) で照合。**唯一の例外**: email が `ADMIN_EMAILS` に含まれる場合は任意の workspace を許可 (運営の全 workspace アクセス)。それ以外で prefix 一致を緩めない |
| I9 | challenge コンテナ Dockerfile に Service / Ingress を追加しない |
| I10 | Dockerfile / yaml にトークン・実シークレットを焼き込まない |

## Dockerfile 規約

| サービス | builder | final |
|---|---|---|
| scoreboard | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| auth-policy | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| collector | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| ttyd | (single-stage) | `alpine:3.22` |
| challenge | (single-stage) | `alpine:3.22` |
| docs | `python:3.12-slim` (mkdocs-material + pandoc + weasyprint) | `nginxinc/nginx-unprivileged:1.30-alpine` |

- alpine は最新 cycle ではなく「リリース後 ~1 年経過した supported cycle」を選ぶ
  (apk pin の安定性と EOL 余裕のバランス。2026-07 時点: 3.22)。
  cycle 鮮度は `make check-freshness`、パッケージ鮮度は CVE scan (PR CI) の二層でカバー。

- docs イメージの build context = repo root (`challenges/` を読んで gen-pages.sh が
  ミッションページを生成。`README.md` の H1 をタイトル、`fixtures/welcome.txt` を
  ブリーフ、本文を「攻略と解説」に流し込む。単一ソース = challenges/)

- Go ビルドは `CGO_ENABLED=0 -ldflags="-s -w" -trimpath` で static binary
- scoreboard / auth-policy の build context = repo root

## サプライチェーン: base image の digest pin (P12)

全 Dockerfile の外部 base image は **digest pin** する
(`image:tag@sha256:...`)。tag も可読性のため残す (`golang:1.26-alpine@sha256:...`)。
`scratch` は digest を持たないので対象外。

- **なぜ**: mutable tag は再取得で中身が変わりうる。digest 固定で「同一 SHA build =
  bit-identical な base」を保証し、供給元置換 (tag 乗っ取り) を封じる。
- **check-freshness (P8) との併用**: `scripts/check-freshness.sh` は FROM 行を
  `re.search` で cycle 抽出するため `@sha256:...` 付きでも動く (tag 部分を先に拾う)。
  digest pin しても EOL/鮮度検知は壊れない (script 変更不要)。cycle 鮮度 =
  check-freshness、パッケージ/base の CVE = PR CI scan の二層は従来どおり。
- **I5 (全イメージ同一 SHA build)** は不変。digest は base の pin であって app の
  build SHA とは独立。

### digest の bump 手順

新しい base digest に更新するとき (cycle 据え置きで CVE 修正版へ、または cycle bump 時):

```sh
# 1. 対象 image の現行 tag が指す manifest digest を実解決する
#    (multi-platform の index digest を取る。buildx が build 時に platform を選ぶ)
docker buildx imagetools inspect golang:1.26-alpine --format '{{.Manifest.Digest}}'
#    確認: index であること (単一 arch を掴まないため)
docker buildx imagetools inspect golang:1.26-alpine --format '{{.Manifest.MediaType}}'
#    → application/vnd.oci.image.index.v1+json (または docker manifest.list) であること

# 2. 該当 Dockerfile の FROM を `image:tag@sha256:<新digest>` に差し替える
#    (同一 image を使う複数 Dockerfile は同じ digest に揃える。現状:
#     golang:1.26-alpine              = scoreboard/auth-policy/Dockerfile.{test,gen,tidy}、
#     distroless static-debian13:nonroot = scoreboard/auth-policy、
#     alpine:3.22                     = images/{ttyd,challenge}、
#     python:3.12-slim                = images/docs (build stage)、
#     nginx-unprivileged:1.30-alpine  = images/docs (serve stage))

# 3. 検証: 実ビルド + 鮮度 + テスト
make build TAG=local      # digest が pull でき build が通ること
make check-freshness      # cycle が EOL でないこと
make test                 # Go build/test (Dockerfile.test) が通ること
```

cycle 自体を上げる場合 (例: alpine 3.22→3.23) は tag も一緒に変え、apk pin と
`## Dockerfile 規約` 表・UID 表も見直す (P8 の bump 手順と同じ)。

## サプライチェーン: CI workflow / action 参照の pin (P12)

- **reusable workflow の `@main` 参照は禁止**。commit SHA に pin する
  (`...@<40-hex> # main as of <date>`)。mutable ブランチ参照は上流の任意 commit を
  そのまま実行してしまうため。現状 `Qfour/homelab-workflows` の go-test /
  image-pipeline を `10583360...` (main as of 2026-05-12) に pin。
  bump 時は `gh api repos/Qfour/homelab-workflows/commits/main --jq .sha` で
  新 SHA を取り、動作確認の上で差し替える。
- **platform が本リポの reusable workflow (`shellcheck.yaml` / `actionlint.yaml`) を
  consume する際も同 SHA-pin ポリシーを適用する** (app が reusable の一次配布元。
  `Qfour/falco-ctf-app/.github/workflows/<name>.yaml@<40-hex>` で pin し `@main` 禁止)。
- **サードパーティ action の `@vN` メジャータグは許容例外**。SHA pin しない。
  根拠: (1) いずれも広く使われる信頼済み提供元 (GitHub 公式 `actions/*`・
  `azure/*`・`aws-actions/*`・`anthropics/*)、(2) メジャータグは提供元が
  セキュリティ修正を配る移動先で、SHA pin すると修正が届かず手動 bump 負債になる、
  (3) **バージョン追随は Dependabot 自動 PR (weekly・`dependencies` ラベル・grouping) +
  人間レビュー → CEO merge で行う (G3 で導入)。CI-free prod 方針 (image 手動 build/push)
  とは直交** — Dependabot は依存更新 PR を開くだけで、prod deploy 経路には触れない。
  auto-merge は使わない (更新は必ず人間レビュー → CEO merge を経る)。platform `SUPPLY-CHAIN.md`
  と同一方針。**例外リスト (mutable で許容する参照)**:
  | action | 用途 |
  |---|---|
  | `actions/checkout@v4` | repo チェックアウト (GitHub 公式) |
  | `azure/setup-helm@v4` | helm セットアップ (chart-lint / publish) |
  | `aws-actions/configure-aws-credentials@v4` | OIDC creds (publish-charts、publish gate 時のみ) |
  | `anthropics/claude-code-action@v1` | PR コードレビュー (claude-review.yml) |

  この 4 つ以外の action / `@main` reusable workflow を追加する場合は SHA pin するか、
  上記例外表に根拠付きで追記すること (完了条件: mutable 参照ゼロ or 例外表に記載)。
- **この例外表は各リポの実 workflow に固有** (共通なのは pin ポリシーであって
  action 集合ではない。集合は各リポの `uses:` に従属する)。platform 表と件数/内容が
  一致する必要はない。
- **`github/codeql-action/*` は SHA pin (例外表に載せない)。bump は Dependabot
  github-actions group が担う** (codeql.yml の init/autobuild/analyze を同一 SHA に揃える)。
- **G5-2 検査 job (`checks.yaml` / `freshness.yaml`) の方針**: 新規サードパーティ
  action を増やさないため、静的検査ツールは action ではなく golang container 内で
  `go install <module>@<version>` する (module version pin = reproducible。mutable な
  git ref ではない)。現状 install するツール: `rhysd/actionlint@v1.7.7`・
  `golang.org/x/vuln/cmd/govulncheck@v1.1.4`・`oapi-codegen/v2@v2.3.0`
  (oapi は Dockerfile.gen と同 version)。使う `uses:` は上記例外表の
  `actions/checkout@v4` のみ (新規 action ゼロ)。bump は手動レビューで実施。

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

## 課題ドキュメント用 rule.yaml (challenges/<NN>/rule.yaml)

- docs サイトが「背景の後」に描画する **表示用 Falco ルール抜粋**。`falco-rule.yaml`
  (scoreboard metadata: expectedRules/forbiddenRules) とは別物。
- **デプロイ中の実ルールセットから抽出**して精度を担保(本番 Falco と一致):
  `kubectl -n falco exec <falco-pod> -c falco -- cat /etc/falco/falco_rules.yaml` から
  各課題の expectedRules + forbiddenRules の rule ブロックを抽出 → `challenges/<NN>/rule.yaml`。
- **Falco バージョンを上げたら再抽出**(condition/output が変わるため)。docs の
  gen-pages.py は存在すれば描画、無ければスキップ(必須ではない)。

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
| Image naming (**正典**) | `${REGISTRY}/falco-ctf-{scoreboard,auth-policy,ttyd,challenge,docs}:<git-sha>`。registry の repo 名は **`falco-ctf/X` slash が正式**、`falco-ctf-X` dash も ingest 受理。tag は git SHA (I4/I5)。**この行が slash/dash 命名契約の単一定義** — 他所 (ingest フィルタ節・platform docs) はここを参照する |
| Charts | `charts/{scoreboard,auth-policy,ctf-user,docs}` を platform helmfile が local=path / prod=OCI で参照 (CI publish は現状停止 → prod も local clone path。`project_ci_free_prod` 参照) |
| Challenges path | `deploy-user.sh --challenges-dir` (ctf-user chart 同梱、当 repo `challenges/` を default 参照) |
| Webhook payload | `POST /falco/events` は falcosidekick 標準形。フィールドキー変更は両 repo 同時 PR |
| Cookie domain | `.<ctf-domain>` は platform が決定。app 側は前提とする |
| Flags | platform `events/<date>/flags.sops.yaml` が正典。scoreboard へ `FLAGS_FILE`、challenge コンテナへ `CTF_FLAG_<ID>` env として注入。app は `FALCO{dev-<slug>}` placeholder のみ保持。dev default 値は両 repo で一致させる |

## scoreboard ingest フィルタ (defense-in-depth)

> slash/dash 命名契約の**正典は上記「Cross-repo 契約」表の Image naming 行**。
> この節はその契約を ingest が **なぜ両形受理するか** を説明する (二重定義しない)。

`internal/scoreboard/ingest/ingest.go` の image substring check は
`falco-ctf/challenge` **または** `falco-ctf-challenge` を受理する。
slash が正式命名 (契約表参照) だが、containerd の image dedup で push 名と
Falco 報告名が乖離するケース (同一 digest を別 repo にも push したケース) に
対応するため dash 形も許容している。

新しい registry を追加する場合は image string が `falco-ctf/challenge` /
`falco-ctf-challenge` のどちらかを含むよう repo 命名する (契約表の命名に従う)。

## Prod 値の供給 (chart には焼き込まない)

scoreboard / auth-policy / ctf-user chart の `values.yaml` は placeholder default
のみ (`example.invalid` / `docker.io/falco-ctf` / `FALCO{dev-...}` / `ADMIN_EMAILS=""`)。
本番値 (実 host・ECR registry・image tag・EXPECTED_EMAIL_DOMAIN・ADMIN_EMAILS) は
**platform helmfile の prod 環境値**が供給する (`falco-ctf-platform/helmfile/environments/prod.yaml.gotmpl`
+ `releases/{scoreboard,auth-policy}/values*.gotmpl`)。chart に実値をコミットしない。

> kustomize `deploy/` は P2 で廃止。k8s マニフェストの正典は `charts/`。
