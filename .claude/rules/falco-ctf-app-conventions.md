# Falco CTF App Conventions — Source of Truth

このファイルが **唯一の正典**。CLAUDE.md / AGENTS.md は概要のみ持ち、
詳細な制約はここを参照する。

## UID 一覧 (runtime user)

| サービス | UID | 根拠 |
|---|---|---|
| scoreboard | **65532** | distroless/static-debian13:nonroot |
| auth-policy | **65532** | distroless/static-debian13:nonroot |
| collector | **65532** | distroless/static-debian13:nonroot |
| detect-grader | **65532** | falco base に足した非 root grader ユーザ (I2 と揃える。replay は driverless で無権限) |
| ttyd | **1000** | alpine adduser -D -u 1000 ttyd |
| ttyd-proxy | **65532** | distroless/static-debian13:nonroot (P23-3。ttyd 前段の CSP frame-ancestors リバースプロキシ) |
| challenge | **root (0)** | CTF realism — ユーザが体験するシェル環境 |
| docs | **101** | nginxinc/nginx-unprivileged (静的サイト配信) |

## Hard Invariants (違反は即 blocking)

| # | ルール |
|---|---|
| I1 | scoreboard は `replicas: 1` + `strategy: Recreate` 固定 (SQLite 並行書込不可) |
| I2 | scoreboard / auth-policy / collector のコンテナ `runAsUser: 65532` |
| I3 | scoreboard PVC `fsGroup: 65532` |
| I4 | image tag は **git SHA** で push。`latest` で本番 deploy 禁止 |
| I5 | 全 8 イメージ (scoreboard / auth-policy / collector / ttyd / ttyd-proxy / challenge / docs / detect-grader) を **同一 git SHA** でビルド・push。detect-grader は `type: detect` 課題の capture-replay 採点 (falco base + grade.sh)。ttyd-proxy は P23-3 の CSP frame-ancestors リバースプロキシ。#44 で CEO 批准済 (6→7)、7→8 は本 PR で提案・CEO 承認待ち (merge 時) |
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
| ttyd-proxy | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| challenge | (single-stage) | `alpine:3.22` |
| docs | `python:3.12-slim` (mkdocs-material + pandoc + weasyprint) | `nginxinc/nginx-unprivileged:1.30-alpine` |
| detect-grader | (single-stage) | `falcosecurity/falco:0.43.1` (wolfi/apko base; digest pin。非 root 65532 ユーザを build 時に追加) |

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
#     nginx-unprivileged:1.30-alpine  = images/docs (serve stage)、
#     falcosecurity/falco:0.43.1      = images/detect-grader (Falco 版 bump 時は
#                                       digest 再解決 + capture 再録画をセットで。§5))

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

## SecurityContext

scoreboard / auth-policy に必須:
```yaml
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

### challenge コンテナ (`charts/ctf-user`) — root だが seccompProfile は必須

challenge コンテナは UID 表のとおり **root (0) が意図的** (CTF realism)。
但し **`runAsNonRoot: false` は seccomp を含まない** — root 化は「Pod 内で
何ができるか」の話であって、「Pod の外に出られるか」の境界とは別物。
`seccompProfile: {type: RuntimeDefault}` は root/non-root と独立に必須。

- `charts/ctf-user/templates/pod.yaml` は **Pod レベル** `securityContext` に
  `seccompProfile: {type: RuntimeDefault}` を置く。**k8s の継承はブロック単位
  ではなくフィールド単位** — container 側が `seccompProfile` を明示的に
  set しない限り Pod レベルの値が effective になる。ttyd / ttyd-proxy は
  コンテナレベルで既に明示済みなので無影響、challenge はコンテナレベルの
  `securityContext` を一切持たないため、これが唯一の適用経路になる。
- **実際に unconfined 化しうる経路は次の 3 つだけ**。フィールド単位継承のため
  「container-level `securityContext` を追加するだけ」では起きない
  (追加したコンテナが `seccompProfile` を明示しない限り Pod レベルの値を
  素通しで受け継ぐ):
  1. container-level で **`seccompProfile: Unconfined` を明示**する
  2. **`privileged: true`** を付ける (seccomp そのものを無効化する)
  3. **Pod レベルの `seccompProfile` 2 行を削除**する
     (機械強制: `make check-seccomp` / `scripts/check-seccomp.py`、
     CI `chart-lint` job から呼ばれる)
- **Pod レベルに置くのが最も堅牢な理由**: フィールド単位継承なので、現行
  3 コンテナだけでなく **将来の initContainer / ephemeralContainer
  (`kubectl debug` が追加するものを含む) にも自動適用され fail-closed**
  になる。逆にコンテナごとに `seccompProfile` を列挙する方式は、新しい
  コンテナを追加したときに書き忘れると unconfined のまま通ってしまう
  (= 厳密に弱い方式)。
- 新しい chart / コンテナを書くときも同じ穴を空けない: **root 許可
  (`runAsNonRoot: false`) は seccompProfile 免除の理由にならない**。
  root が必要な場合でも `seccompProfile: RuntimeDefault` は付ける
  (unconfined は個別に明示的な理由と ADR が無い限り不可)。

## Security

- `.env` / kubeconfig / `*.key` / `*.pem` / `*.db` はコミットしない
- **実フラグをコミットしない (public repo)**。`falco-rule.yaml` は `FALCO{dev-<slug>}`
  placeholder のみ。実フラグは platform `events/<date>/flags.sops.yaml`。
  `make check-flags` (CI: `flag-guard`、PreCommit hook) が混入を block。
- **scratch/PoC を誤ってコミットしない (P23-2b)**。作業中の一時ファイルには
  `DO` + `NOT` + `COMMIT` マーカー (大小文字・`-`/`_` variant 可) を付ける運用。
  `make check-flags` がこのマーカーを含む tracked file を検出し fail-closed で block
  (このスクリプト自身と本ファイルは自己言及のため除外)。
- 課題用ダミー値 (`P@ssw0rd`) は LOW 扱い、明確にダミーと示す
- `git add .` / `git add -A` 禁止 (明示パス指定のみ)

## フラグ注入 (flag injection) — 単一ソース

- 採点側: scoreboard が `FLAGS_FILE` (yaml `{flags: {id: FALCO{...}}}`) を読み、
  evade challenge の `expectedFlag` を起動時に上書き (`catalog.ApplyFlagOverrides`、
  fail-closed)。空なら placeholder のまま (local/test)。
- 仕込み側: `challenges/<NN>/plant.sh` が唯一の正典。フラグ実値は書かず
  `${CTF_FLAG_<ID>}` env を参照 (`<ID>` = challengeId 大文字・`-`→`_`)。
  **ADR-0001 (Option B, Accepted)**: `plant.sh` は `challenge` コンテナでは
  実行されない。`plant` initContainer (image は challenge と同一、I5 に触れない)
  が `ctf-flags` Secret から `CTF_FLAG_<ID>` を受け取り、seed emptyDir
  (`$PLANT_SEED_ROOT`) に書く。`challenge` は宣言済み `# plant-target:` に
  対応する subPath mount だけを見る (seed root は mount しない — I12)。
  `challenge` の env には `CTF_FLAG_*` は一切出現しない。
- `values.yaml` / `values-all.yaml` は `make gen-values`
  (`challenges/gen-values.sh`) で plant.sh から生成。**手書き禁止**。
  生成物は `plant.seedScript` (initContainer が実行する `sh -c` script。
  同一 plant-target を複数の plant.sh が共有する場合は 1 回だけ
  build-time snapshot (`/opt/ctf/plant-seed/`, ADR-0001 S-a) から復元して
  dedupe する) と `plant.mounts` (宣言済み plant-target の重複無しリスト)。
  CI `flag-guard` (`gen-values.sh --check`) が同期 + ADR-0001 Verification
  2-1〜2-7 (禁じ手集合の静的検査含む) を検証する。
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
| Image naming (**正典**) | `${REGISTRY}/falco-ctf-{scoreboard,auth-policy,collector,ttyd,ttyd-proxy,challenge,docs,detect-grader}:<git-sha>`。registry の repo 名は **`falco-ctf/X` slash が正式**、`falco-ctf-X` dash も ingest 受理。tag は git SHA (I4/I5, 全 8 イメージ同一 SHA)。**この行が slash/dash 命名契約の単一定義** — 他所 (ingest フィルタ節・platform docs) はここを参照する |
| ttyd-proxy 配線 (P23-3, **正典・実装済**) | `charts/ctf-user` の workspace Pod に ttyd-proxy サイドカーを追加 (本 repo 内、chart 配線まで app-lead が完結)。契約: (1) image = `falco-ctf/ttyd-proxy:<git-sha>` (I4/I5)、(2) ttyd-proxy が Ingress 到達ポート (`LISTEN_ADDR` env、`.Values.ttyd.port` 既定 `:7681` = 現行 ttyd ポート) を listen し Service.targetPort/NetworkPolicy はこのポートのみ許可、ttyd 自体は `.Values.ttyd.upstreamPort` 既定 `7682` へ退避して `TTYD_PORT=7682` + `TTYD_INTERFACE=127.0.0.1` を chart から明示注入 (image 側の `TTYD_INTERFACE` 既定は後方互換のため `0.0.0.0` のまま — オプトインは chart 側の責務)、(3) `FRAME_ANCESTORS` env = `.Values.ttyd.frameAncestors` 既定 `'none'` (fail-safe。`deploy-user.sh --frame-ancestors <value>` で上書き可) — **ctf-user は helmfile 管理外** (platform helmfile の release ではない) なので、P23-4 でポータル origin を注入する経路は platform の `deploy-event-workspaces.sh` から `deploy-user.sh --frame-ancestors <value>` への passthrough を追加する形になる (この passthrough は未実装・P23-4 で追加予定。今のところ運用者が `deploy-user.sh --frame-ancestors` を直接叩く手動経路のみ)。ttyd の readinessProbe は `tcpSocket` ではなく `exec curl 127.0.0.1:<upstreamPort>` (tcpSocket/httpGet probe は kubelet が Pod IP に dial するため loopback-only コンテナには使えない)。契約変更 (ポート番号・env 名) は両 repo 同時 PR |
| detect-grader Job (**正典**) | scoreboard は `DETECT_RUNNER=k8s` のとき per-submission Job を作る。**app が確定し platform が一致させる契約**: (1) namespace = `DETECT_GRADER_NAMESPACE` env (専用 grader ns。platform が作成)、(2) grader image = `DETECT_GRADER_IMAGE` env (digest-pinned `.../detect-grader@sha256:...`。platform helmfile が供給、chart に焼かない I7)、(3) scoreboard SA に **Job + Secret + Pod の RBAC** (下記動詞)、(4) grader ns に **deny-all NetworkPolicy** (replay は無ネットワーク)。Job/Secret/Pod は label `app.kubernetes.io/name=detect-grader`・`app.kubernetes.io/component=grader-job`・`falco-ctf/challenge=<id>` を持つ。Job/Secret 名 = `detect-<challengeId>-<nonce>` / `<jobname>-cond`。契約変更は両 repo 同時 PR |
| Charts | `charts/{scoreboard,auth-policy,ctf-user,docs}` を platform helmfile が local=path / prod=OCI で参照 (CI publish は現状停止 → prod も local clone path。`project_ci_free_prod` 参照) |
| `deploy-user.sh` の exit status (**正典**・ADR-0001 DoD 8) | **`deploy-user.sh` の非ゼロ exit は fail-closed 契約。呼び出し側は伝播する。** ADR-0001 Verification 3 の deploy 時 assert (`charts/ctf-user/assert-flag-isolation.sh`) は violation で `deploy-user.sh` を非ゼロ終了させるので、**呼び出し側が exit status を捨てると assert 自体が無意味になる** (security-engineer の F2)。platform 側 `scripts/deploy-event-workspaces.sh` は per-user の exit status を収集し、**1 件でも失敗したら `✓ done` を出さず非ゼロ終了する** (bare `wait` は子の失敗を伝播せず exit 0 を返すので使わない)。契約変更は両 repo 同時 PR |
| Challenges path | `deploy-user.sh --challenges-dir` (ctf-user chart 同梱、当 repo `challenges/` を default 参照) |
| Webhook payload | `POST /falco/events` は falcosidekick 標準形。フィールドキー変更は両 repo 同時 PR |
| Cookie domain | `.<ctf-domain>` は platform が決定。app 側は前提とする |
| Flags (**ADR-0001 Option B で更新**) | platform `events/<date>/flags.sops.yaml` が正典。scoreboard へは変わらず `FLAGS_FILE`。仕込み側は **`ctf-flags` Secret (`CTF_FLAG_<ID>` キー) → `plant` initContainer にのみ `envFrom`/`secretKeyRef` で到達** — `challenge` コンテナの env には CTF_FLAG_* は一切出現しない (I12)。`deploy-user.sh --flags-file` の `--set-string challenge.flags.<id>=...` という *引数* 面は不変 (C6)、到達経路だけが変わった。app は `FALCO{dev-<slug>}` placeholder のみ保持。dev default 値は両 repo で一致させる |
| `ALLOWED_ORIGINS` (P23-2, **platform 側 P19-2a で landing 済**) | scoreboard の origin-guard middleware (`internal/scoreboard/originguard`) が読む CSRF 対策アローリスト env。chart 側は `charts/scoreboard/values.yaml` の `env.allowedOrigins` (default `""` = fail-closed = 全ガード対象ルートが拒否) と `templates/deployment.yaml` で受け皿を用意済み。**platform helmfile (`releases/scoreboard/values*.gotmpl` 等) が P19-2a (platform#54) でこの値の供給を landing 済み**。P19-2b の単一 origin 化後は値がさらに単一化: `https://app.<dnsSuffix>` の一値 (旧・host分離時代の `https://journey.<dnsSuffix>` 等の複数値は不要になった)。`userN.<dnsSuffix>` の ttyd origin は含めない (CSRF 踏み台化を防ぐため意図的に対象外)。値の実供給・検証は platform-lead 側 |

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
