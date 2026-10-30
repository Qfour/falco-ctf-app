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
| I8 | 認証済み identity (oauth2-proxy が検証した `email_verified` の email を ADR-0034 D2 で正規化したもの) から seat (workspace 名) への対応は、auth-policy が読む**ロスター 1 表**だけが決める。auth-policy は表で解決できた identity に限り、後段へ正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` だけを渡し、`/check-workspace?host=<h>` は seat == h の完全一致でのみ 200。表に無い identity は参加者と workspace の全 route で 403 (表の欠落・空は起動拒否)。scoreboard の self 判定は `<user>@<EXPECTED_EMAIL_DOMAIN>` との完全一致 (`EXPECTED_EMAIL_DOMAIN` が空なら誰も self にならない)。`EXPECTED_EMAIL_DOMAIN` の最後のラベルは予約名 (`local` `test` `invalid` `example` `localhost`) で、外部 IdP はこのドメインの email を検証済みで出せない。**唯一の例外**は `ADMIN_EMAILS` (任意の workspace と運営 route。要素は予約ドメインの静的アカウントだけ)。IdP の email の local-part を seat と読む経路を持たない (prefix・suffix・部分一致を使わない)。**前提 (ヘッダの完全性)**: app の chart の全 Ingress の auth-url が auth-policy を指して `X-Auth-Request-{User,Email,Preferred-Username}` を上書きし (参加者 = `/check-participant`、workspace = `/check-workspace?host=<username>`、運営 = `/check-admin`。template に固定、値で差し替えない)、collector が workspace からの `X-Auth-Request-*` を消し、scoreboard は ingress-nginx・collector・falco からしか受けない (`charts/scoreboard/templates/networkpolicy.yaml`)。機械強制 (すべて `make test` = required check、ADR-0034): **V9** `internal/authpolicy/identity_v9_test.go` (解決・正規形の上書き・403 本文に identity が出ない)、**V10** `internal/authpolicy/roster_test.go` + `internal/authpolicy/roster_parity_test.go` (正規化と予約名の共通ケース表 `internal/authpolicy/testdata/roster-parity/{cases,reserved-domains}.tsv`。platform の shell 実装 `scripts/lib/roster.sh` が同じ表を読む) + `internal/identity/identity_test.go` + `cmd/{auth-policy,scoreboard}` の起動検査 (1 ケース 1 欠陥)、**V11** `internal/scoreboard/identity_v11_test.go` (self は正規形の完全一致)、**V12** `internal/apispec/ingressparity/authurl_test.go` (全 chart を `helm template` し、Ingress ごとに役割 → endpoint・件数・identity header を pin。helm が無ければ fail)、**V13** `internal/collector/auth_header_strip_test.go` (転送 route すべてで strip)。出所: ADR-0034。旧文言 (`/check` の prefix-exact `<username>@` 照合) はここで置き換え済み |
| I9 | challenge コンテナ Dockerfile に Service / Ingress を追加しない |
| I10 | Dockerfile / yaml にトークン・実シークレットを焼き込まない |
| I11 | evade challenge の clean 判定 (`evaluateClean`) は **attempt スコープ**で評価する: forbidden rule の taint は「先行 trigger 課題の必須発火 (`ExpectedRules`) との交差」を持つ場合にのみ生じ、成立した `dirty` は時刻に依存せず恒久的 (`POST .../reset-dirty` の明示呼び出しのみが解除)、`ResetDirty` は `exfil` レコード削除を `evade_dirty` 解除より**先**に行う (fail-closed 順序、A2-2)。機械強制: `internal/catalog/catalog_test.go` の `TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules` (実 catalog + 実 scenario で先行trigger↔後続evadeの交差ペアを pin) + `internal/scoreboard/scoring/scoring_test.go` の `TestOnRuleFire_RealCatalog_AttemptScope_TwinMissionsStayClean` / `TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance` / `TestDirtyFlag_SurvivesStoreRestart` + `internal/scoreboard/server_test.go` の `TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved` (clock 非依存の回帰) + `internal/store/store_internal_test.go` の `TestResetDirty_TransactionRollsBackOnPartialFailure` (`exfil` テーブルを故意に破壊し削除順序の fail-closed を区別)。すべて `make test` = required check。出所: ADR-0003。2026-08-31 昇格 (Verification (a)+(b)+(e) landing 確認、#145) |
| I12 | workspace Pod の `challenge` コンテナには、フラグ実値を到達させる経路を一切設けない (env / `envFrom` / volume (`volumeMount`) / seed root の mount / ServiceAccount token を含むが、これらに限らない)。evade フラグの仕込みは `plant` initContainer + emptyDir seed 経由のみ。challenge 側の seed 参照は宣言済み `# plant-target:` に対応する mount だけとし、seed volume の root mount を禁止する。`/opt/ctf/plant-seed/` (S-a snapshot) はフラグ実値・資格情報を一切含まない。機械強制: `scripts/check-flag-isolation.sh` (静的、CI `flag-guard` required check) + `charts/ctf-user/assert-flag-isolation.sh` (実機、`deploy-user.sh` から fail-closed 呼び出し)。出所: ADR-0001。2026-08-25 昇格 (ADR-0007 が課した3条件 [到達可能性表現・granularity中立なassert・I13a/I13b非依存] を ADR-0010 が実測確認) |
| I14 | `http.ServeMux` を組み立てる全バイナリ (scoreboard/collector/auth-policy) について、mux に登録されたルート集合 = 対応する `docs/openapi-*.yaml` の operation 集合であり、origin-guard の有無と collector forward の集合も spec の宣言と一致する。**例外・除外リストを持たない** (ADR-0005)。機構: `internal/apispec` (ルートテーブルと `Register`) + 各サービスの `apispec_parity_test.go` (宣言 ↔ spec) + **`internal/scoreboard/origin_guard_test.go` の `TestOriginGuard_AllProtectedRoutesEnforced`** (宣言 ↔ **強制**。`Routes()` から導出。これを削ると I14 は宣言の一致しか保証しなくなる) — すべて `make test` = required check。対象バイナリは**列挙ではなく機械判定** (`http.ServeMux` を組み立てるものすべて。現在は scoreboard / collector / auth-policy の 3 本) |
| I15 | scoreboard の `AudienceParticipant` な mux Route (`scoreboard.Handler.Routes()`) は**すべて** `charts/scoreboard/templates/ingress-journey.yaml` がレンダリングする本番単一起点 ingress の participant allow-list に含まれる。逆に、同 allow-list の**各エントリ (Prefix/Exact 問わず)** が到達させる mux Route (audience 不問) は**すべて** `Audience == AudienceParticipant` である (非 participant = admin/operator/internal/infra route の allow-list 混入を、エントリの pathType に関わらず禁止する。検査は `Audience != AudienceParticipant` 全 audience が対象 — R2 実測確認)。**例外・除外リストを持たない** (ADR-0021、reverse 検査の Exact 拡張は ADR-0022)。I14 (mux↔spec) とは別レイヤ・別主張 — mux/spec 両方が正しくても ingress allow-list への登録漏れは検出できなかった実障害 (#95/#235、うち #235 は本番到達) の再発防止。機構: test-only `internal/apispec/ingressparity` (`specparity` と同型の production-import 禁止規律) が `helm template charts/scoreboard --show-only templates/ingress-journey.yaml --set ingress.journeyHost=<non-empty>` の出力を双方向比較 (`internal/scoreboard/ingress_journey_parity_test.go`) — `make test` = required check に相乗り (`Dockerfile.test` が helm を `go install helm.sh/helm/v3/cmd/helm@<pin>` で同梱)。対象は scoreboard の journey ingress のみ (admin ingress は catch-all Prefix で allow-list ではないため構造的に対象外、collector/auth-policy は Ingress オブジェクト自体を持たない、ADR-0021 C3) |
| I16 | challenge image の `/opt/ctf/missions/` は、catalog の各 id について `<id>/fixtures/**` だけを持つ (他の entry を持たず、全 id に `<id>/fixtures/` がある)。`challenges/*/fixtures/**` は、ADR-0026 D5 の規則で違反となる n-gram (`hints[]` にあって無料表示に無い 10 rune) を含まない。**例外・除外リストを持たない** (ADR-0026)。**I16 は「ヒントの経路が 1 つである」とは主張しない** (検査できない): 主張するのは image の entry 集合と fixtures の文面だけで、公開リポ・配布文書・n-gram が捕まえない言い換えは I16 の外 (ADR-0026 残余 1〜3)。残余 4: `/opt/ctf/missions/` **以外**への COPY は I16 の文言の外 (V1 の sha256 照合が「そのまま置く」場合を落とす。内容を変えて置く場合は Dockerfile 変更の security-engineer レビューに残る)。deploy 時の 3-8 は deploy の瞬間の検査で、参加者が触った後の再実行は image の証跡にならない (監査は `check-image-hygiene.sh <digest>`)。表題は「missions の fixtures allowlist と fixtures のヒント非同梱」とし、「ヒント単一経路」は使わない。機構 (4 層): (1) **build 時** `scripts/check-image-hygiene.sh` V1〜V3 (entry 集合・fixtures の sha256+mode・`expectedFlag` 逐語の不在) — `make build` / `make push` の fail-closed 経路、`scripts/test-check-image-hygiene.sh` が mutation test。(2) **deploy 時** `charts/ctf-user/assert-flag-isolation.sh` の **3-8** (V4: scenario / `all` / 単一課題の 3 モードで `/opt/ctf/missions/` 直下 = 期待 id 集合・すべて実ディレクトリ・各 `<id>/` は実ディレクトリの `fixtures` だけ。dot entry も列挙、fixtures の中身は開かない。`deploy-user.sh` の非ゼロ exit = fail-closed 契約) — 期待 id 集合は operator の checkout の `challenges/` から作る (**checkout と image の ref の一致が deploy の条件**)。`scripts/check-missions-allowlist-assert.sh` が実 probe を偽 FS に当てる selftest (`make check-flags` / CI `flag-guard`)。(3) **文面** `internal/hintleak` の `TestFixtures_CarryNoHintOnlyNgrams` (V5) + `TestHintLeakChecker_Mutation` (V6) — `make test` = required check。(4) **レビュー** (V8): `challenges/*/fixtures/**` と `journey.yaml` の `hints[]` を変える PR は security-engineer レビュー必須 (n-gram は逐語一致しか捕まえず、言い換えは文面レビューだけが防ぐ)。加えて `internal/hintleak/**` と `internal/sourcehygiene/**` (test と testdata を含む) を変える PR も必須 (n-gram 検査の本体とその述語で、test を消す PR も I16 を弱める。ADR-0043)。**`image-hygiene` CI job は required check ではない** (一次ゲートは `make build` / `make push`。required に上げるかは VP / CEO 判断) |

> **I13 は欠番ではなく予約済み (未昇格)。** 番号は 2026-08-18 に VP が批准済で再利用しない。
> **I16 は 2026-10-14 に昇格済み** (上記表。ADR-0026 の V1〜V6・V8 が main に揃った P28-0d 3/3 で。
> 実機検証 V7 は本番投入の前に満たす条件として残る)。
> **I12 は 2026-08-25 に昇格済み** (上記表に移動。ADR-0010 参照)。
> **I11 は 2026-08-31 に昇格済み** (上記表に移動。ADR-0003 Verification (a)+(b)+(e) landing 確認、#145)。
> **未昇格として残るのは I13a/I13b のみ** (2026-08-19 に 5x R3 が実測して判明。理由は実機 cluster 実測が未実施であること):
>
> | # | 主張 | 出所 | 状態 |
> |---|---|---|---|
> | I13a | deploy の前後で当該 user の `solved` / `evade_dirty` / `exfil` に**差分が生じない** (delta 表現) | ADR-0001 rev.5 | **実機 cluster 実測が残 gate** |
> | I13b | deploy 経路は catalog の `expectedRules` ∪ `forbiddenRules` に現れるルール名を**1 本も発火させない** (性質表現。対象は本数で持たず、その時点の catalog から導く) | ADR-0001 rev.5 | **実機 cluster 実測が残 gate** |
>
> ⚠ **I13 を「Falco イベントを 1 件も出さない」と要約してはいけない。** それは rev.3 の文言で、
> ADR-0001 が「根拠が事実に反し、字義どおりには検証不能」として **rev.4 で撤回**している
> (非 catalog ルールの発火は I13b の対象外)。I14 がこの表に居るのは、検査 (`internal/apispec`) が
> 同じ PR で landing しているため。

## Dockerfile 規約

| サービス | builder | final |
|---|---|---|
| scoreboard | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| auth-policy | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| collector | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| ttyd | `alpine:3.24` (`kubectl` stage: busybox wget で取得し、焼き込んだ sha256 と照合する。`apk add` 無し = pin 無し。app#504) | `alpine:3.24` (builder と同一 digest。検証済みの kubectl を `COPY --from` で受ける。curl / bash は置かない: build 時の assert) |
| ttyd-proxy | `golang:1.26-alpine` | `gcr.io/distroless/static-debian13:nonroot` |
| challenge | `alpine:3.24` (`missions-builder`: `challenges/` 全体を読み、`<id>/fixtures/**` と `answers.yaml` だけを組み立てる。ADR-0026) | `alpine:3.24` (builder と同一 digest。`/opt/ctf/missions/` は `<id>/fixtures/**` だけ。`make check-image-hygiene` が V1-V3 で機械検査) |
| docs | `python:3.12-slim` (mkdocs-material) | `nginxinc/nginx-unprivileged:1.30-alpine-slim` (動的 module / curl 無し。app#442) |
| detect-grader | (single-stage) | `falcosecurity/falco:0.44.1` (wolfi/apko base; digest pin。非 root 65532 ユーザを build 時に追加) |

- alpine の cycle は次の 3 条件を満たす **最古の supported cycle** を選ぶ
  (「リリース後 ~1 年経過」という月数基準は 2026-08 に廃止 — ADR-0002, Accepted):
  1. **安定性実績**: patch release が 3 回以上出ている (= `x.y.3` 以降)
  2. **EOL runway**: EOL まで 12 ヶ月以上ある (`make check-freshness` が検証)
  3. **CVE fix 到達性**: 現在 open な High/Critical の fix version が
     その cycle の main/community に存在する (`apk policy <pkg>` で実測)

  条件 1-3 を満たす cycle が複数あるときは最古を選ぶ (apk exact pin の再解決コストは
  bump 毎に発生するため、無用に新しい cycle を追わない)。条件 3 を満たさない場合に限り
  1 cycle 新しい側へ上げ、PR 本文に `apk policy` の実測出力と bump 後の残存 CVE を明記する。

  **CVE 緊急 bump の例外パス (正式な例外として明記)**: 選定済み cycle の運用中に scan の
  CVE フィードが drift し、新規 High/Critical の fix 版が現行 cycle に存在しないと
  判明した場合、条件 1 (patch 実績 3 回) の到達を待たずに 1 cycle 上へ即日 re-bump してよい
  — 条件 3 (fix 到達性) は CVE urgency の前では月数・patch 回数より優先する。PR 本文に
  「何が緊急 bump を要求したか (CVE ID・fix 版番号)」を明記すること。
  前例 (#227/workspace#31 → app#266): 3.22→3.23 で curl 等の High を解消した同日中に
  curl/libcurl の CVE フィードが drift し 3.23 に fix apk が無いと判明、条件 3 の
  緊急パスで即日 3.23→3.24 へ再 bump (3.24 は 2026-06-09 リリース・EOL 2028-06-01 で
  条件 1 の patch 実績には遠く及ばないが、緊急パスは条件 1 を要求しない)。

  fix が全 cycle・edge に存在しない場合は cycle bump では解決しない —— パッケージ自体の
  除去を第一候補とする (前例: wget を busybox wget に置換, images/challenge/Dockerfile:12-17)。

  2026-09 時点の適合解: **3.24** (app#266 の緊急パス bump 後の到達点)。
  EOL は `make check-freshness` で機械確認。
  cycle 鮮度は `make check-freshness`、パッケージ鮮度は CVE scan (PR CI) の二層でカバー。

- **apk の版の書き方と drift 検知 (ADR-0036 D1・D5、機械強制)**: `apk add` の版の指定は exact
  (`name=version`) だけ。範囲 (`>=` `>` `<` `~`)・`@edge` の tag・`--repository` / `-X`・
  `--keys-dir`・`--allow-untrusted`・`/etc/apk` 以下への書き込み (RUN の読み取り以外・COPY / ADD・`--mount`)
  は使わない (ADR-0031 D5 を全 Dockerfile に広げた。後ろ 4 つは版を書かない package の出所と署名検証を
  守る、security の条件 4 = app#382 F4。版を書かない `apk add name` は可)。Alpine の index は
  各 package の最新 1 版しか持たないので、upstream の security release の日に base に無い版の pin は
  index から消え、次の build が止まる (受理から 53 日で 5 回、ADR-0036 C1)。
  **`scripts/check-apk-pins.sh` (`make check-apk-pins`、docker + network 要)** が
  `git ls-files '*Dockerfile*'` から導いた全 Dockerfile の pin を、その `RUN` が属する stage の
  base image (`FROM x@sha256:...`、`FROM <stage>` は継承を辿る) の中の `apk policy` と突き合わせ、
  index にも base の installed にも無い版を列挙して落ちる (対象を列挙しない。0 件は fail、docker 無しは
  skip でなく exit 2)。**毎日 `.github/workflows/apk-pins.yaml` が回し**、赤 (exit 1) なら label
  `apk-pin-drift` の Issue を 1 本だけ開く / 更新する (PR では回さない: PR の build が drift を
  捕まえる)。実ツリーの文法 (D1 + 条件 4)・pin 0 件・parser の coverage は offline の `--lint`
  (`make check-apk-pins-lint`、required の flag-guard の独立 step) が、checker 自身が赤くなれること
  (planted fixture と parse table) は `--selftest` が固定する。毎日の index 照合 (`apk-pins.yaml`) と
  合わせて 3 層。`check-e2e-pins.sh` は `Dockerfile.e2e` 用の wrapper。pin の版を上げる PR は、
  `make check-apk-pins` の出力を貼る。**どの package に exact pin を許すか (D2〜D4) は D2 の実装 PR まで
  未適用** (今の pin は ADR-0002 の運用のまま)。

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
#     golang:1.26.N-alpine            = 検査 `scripts/check-go-base-digest.sh` (`make
#                                       check-go-base-digest`、flag-guard job) が全箇所を
#                                       `git ls-files '*Dockerfile*'` と `.github/workflows/*.y*ml`
#                                       から導出して照合する。一覧は持たない。異なる値が 2 つ以上、
#                                       digest 無し、一致 0 件は fail (checks.yaml の container.image
#                                       だけ旧 digest で残ると go-vulncheck が別の Go で回る。
#                                       app#78/#87/#88/#499 で発覚)、
#     distroless static-debian13:nonroot = scoreboard/auth-policy、
#                                       Dockerfile.e2e (serve stage。`make e2e-serve` のイメージ)、
#     alpine:3.24                     = images/{ttyd,challenge} (どちらの Dockerfile も FROM が 2 本。
#                                       2 本とも同じ digest に揃える)、
#     python:3.12-slim                = images/docs (build stage)、
#     nginx-unprivileged:1.30-alpine-slim = images/docs (serve stage)、
#     falcosecurity/falco:0.44.1      = images/detect-grader (Falco 版 bump 時は
#                                       digest 再解決 + capture 再録画をセットで。§5))

# 3. 検証: 実ビルド + 鮮度 + テスト
make build TAG=local      # digest が pull でき build が通ること
make check-freshness      # cycle が EOL でないこと
make check-go-base-digest # golang の tag@digest が全箇所で同一であること
make check-apk-pins       # 新しい digest の base に対して、全 Dockerfile の apk pin が index にあること
make test                 # Go build/test (Dockerfile.test) が通ること
```

cycle 自体を上げる場合 (例: alpine 3.23→3.24) は tag も一緒に変え、apk pin と
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
  platform は 2026-10-19 から self-hosted 切替のため一時的に inline (platform #267)。終状態 = 本 repo の再利用 workflow に `runs-on` input を足す (platform#268)。
- **サードパーティ action の `@vN` メジャータグは許容例外**。SHA pin しない。
  根拠: (1) いずれも広く使われる信頼済み提供元 (GitHub 公式 `actions/*`・
  `azure/*`・`aws-actions/*`・`anthropics/*)、(2) メジャータグは提供元が
  セキュリティ修正を配る移動先で、SHA pin すると修正が届かず手動 bump 負債になる、
  (3) **バージョン追随は Dependabot 自動 PR (weekly・`dependencies` ラベル・grouping) +
  人間レビュー → CEO merge で行う (G3 で導入)。CI-free prod 方針 (image 手動 build/push)
  とは直交** — Dependabot は依存更新 PR を開くだけで、prod deploy 経路には触れない。
  auto-merge は使わない (更新は必ず人間レビュー → CEO merge を経る)。platform `SUPPLY-CHAIN.md`
  と同じ例外表の規則。ただし SHA pin の範囲は非対称 (下の箇条)。**例外リスト (mutable で許容する参照)**:
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
- **platform との非対称 (意図的、platform `SUPPLY-CHAIN.md` と同文)**: self-hosted runner に載りうる workflow は全 action を SHA pin + 版コメント (platform の ci.yaml / smoke)。app には self-hosted に載る workflow が無いので例外表のみ。platform と「同じ方針」ではなく、この非対称を両 repo の正典に同文で置く (platform #267 / #268)。
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
- **tracked file (Docker 経路では build context の全 file) に生の bidi 制御文字 (U+202A〜U+202E / U+2066〜U+2069) を置かない (Trojan Source、app#501)。** 攻撃データは escape で書く (Go の `"` + 4 桁 hex の u escape、case 表の `{U+202E}`、散文の `U+202E`)。`internal/sourcehygiene` の test (`make test` = required check `test`) が、拡張子の閉集合 (`binaryExt` = `internal/sourcehygiene/testdata/binary-ext.tsv`。今は `.woff2`・untracked の `.tgz`・`.pdf` (app は tracked しない。platform の deck 用、ADR-0045)。**拡張子に加えて先頭 bytes が形式の signature (`%PDF-` / `wOF2` / gzip の `1F 8B`) に合う file だけ**を飛ばす。`*.pdf` と名付けた text は走査する。ただし先頭が signature の偽造は、置き場の閉集合の外でしか止まらない、#537 / ADR-0051。binary と判定した file は `internal/sourcehygiene/testdata/binary-paths.tsv` の path (`.woff2` = `internal/scoreboard/view/vendor/fonts/`、`.tgz` = `charts/*/charts/`) の下にあるときだけ飛ばし、外なら problem で、app の binary は `appBinaryFiles` の `.woff2` 5 file に固定する) 以外の全 file を byte で走査して落とす (NUL を含む file は binary 扱いにせず、閉集合の外なら problem)。build context が tracked file を欠かないことは `scripts/check-build-context.sh` (`make check-build-context`、flag-guard) が `git ls-files` と突き合わせる。手元で untracked の file に落ちたら、その file を消すか `.dockerignore` で除く。例外は `internal/sourcehygiene/testdata/bidi-allowlist.txt` の閉集合 (1 行 = 完全一致の path + TAB + 理由、追加は security レビュー、生の文字が無い行は dead として落ちる)。今は 0 行。許容の判断を test の側に書き足さない。
- **tracked file に生の不可視文字 (`internal/sourcehygiene/invisible.go` の `invisibleRanges` = Cf ∪ Default_Ignorable ∪ C0 / C1 制御文字 ∪ U+2028 / U+2029 ∪ 単独の CR。Tag 文字、ZWSP、変体セレクタなど) を置かず、tracked path は印字可能 ASCII (U+0021〜U+007E) だけにする (app#511)。** escape で書く。文脈で正当な出現 (非 ASCII の So の直後の U+FE0F、非 ASCII の So の並びの内側の U+200D、先頭の BOM、CRLF) だけは通る。同じ walk・同じ gate (`make test`) で bidi と一緒に検査し、例外は `internal/sourcehygiene/testdata/invisible-allowlist.txt` の閉集合 (path + code point の列 + 理由、列にある code point だけ許す、dead は FAIL、追加は security review)。表と文脈規則は `Hidden` / `Invisible` で import できる (写しを作らない)。hintleak (ADR-0026 D5、I16 の n-gram) も同じ `Hidden` で判定する (ADR-0043。escape を解釈した後のヒント文と fixtures の文に適用し、source gate の allowlist は hintleak に効かない)。このため `internal/sourcehygiene/**`・`internal/hintleak/**`・`scripts/sourcehygiene-scan.py`・`scripts/test-sourcehygiene-scan.sh` (ADR-0045 の参照 scanner と mutant harness) を変える PR は、採点境界 (V8 / I16) の変更として security-engineer レビュー必須 (I16 の機構 (4)、dev-flow のパターン A の表)。 workspace と platform にも、app の参照 scanner (`scripts/sourcehygiene-scan.py`) で同じ規則を当てる (ADR-0045、Cross-repo 契約表の行)。workspace は ws#90 で実装済み (binary 0 件。`--binary-paths` は未使用で、渡さない走査は空の閉集合なので緑。自リポの閉集合は ws#92)。platform は platform#294 で展開予定で、今は未実装 (`--binary-paths` を渡すことが受け入れ条件、ADR-0051 D5)。
- 課題用ダミー値 (`P@ssw0rd`) は LOW 扱い、明確にダミーと示す
- `git add .` / `git add -A` 禁止 (明示パス指定のみ)

## フラグ注入 (flag injection) — 単一ソース

- 採点側: scoreboard が `FLAGS_FILE` (yaml `{flags: {id: FALCO{...}}}`) を読み、
  evade challenge の `expectedFlag` を起動時に上書き (`catalog.LoadScored`、
  fail-closed)。空なら placeholder のまま (local/test)。
- **flags ファイルを指定したときの検査 (両側 fail-closed)**。1 つでも破れば採点側は
  起動を拒否し (ログ `flag overrides failed`)、仕込み側は cluster に触れる前に非ゼロ終了する
  (既定値のまま黙って動く経路を作らない)。エラー文言は行番号と検証済みの id のみで、
  flag 値や解釈できなかった行の内容を出さない。
  1. スコープ内の全 evade 課題に flag が供給されている
  2. どの値も、**いずれかの課題の**リポ既定値 (`falco-rule.yaml` の `expectedFlag` /
     `charts/ctf-user/values.yaml` の `challenge.flags`) と同値でない
  3. 課題間で同じ値を使い回していない
  4. 値は `^FALCO\{[A-Za-z0-9_-]+\}$` (`catalog.flagRE`。`expectedFlag` にも同じ制約)。
     この文字集合の外は、YAML の引用・エスケープの解釈差や `helm --set-string` の
     `,` 分割で、採点値と仕込み値が食い違い得るため受け付けない
  5. 未知 id・非 evade・重複 id が無く、`flags:` 直下に 1 行 1 エントリで値が同じ行に
     リテラルで書かれている (ブロック/フロー/複数行/エイリアス/タグ/アンカー/
     インラインコメント/複数ドキュメント不可)
  6. **ファイルにあるのは `flags:` 1 つ・その下のエントリ・空行・行コメントだけ**
     (他のトップレベルキーは両側で拒否。`sops -d` の出力はこの形)
     コメントを含めどの行にも、制御文字 (タブ・CR を含む)・NEL / LS / PS
     (YAML では改行)・BOM・不正な UTF-8 を置かない (仕込み側はバイト単位で拒否。
     コメント中の通常の非 ASCII 文字は可)
  - **この検査が保証しないこと**: 値の強度や、**過去イベントで使った値の再利用**は
    検出しない (検査しているのは「既定値と違う」「課題間で重複しない」ことだけ)。
    イベント毎の新規生成は platform 側の運用で担保する。
  - **スコープ**: 採点側 = scenario で絞った後の catalog。仕込み側 = deploy モードが
    plant する evade 課題 (`all` = 全 evade / `scenario:<name>` = その scenario の evade /
    `<NN-slug>` = その課題が evade なら 1 件)。スコープ外の evade id が載っているのは可
    (1 つのイベント用ファイルを全モード・全 scenario で使い回せる)。スコープ外の
    エントリも検査はするが、採点側は適用せず、仕込み側は helm に渡さない。
  - **採点側 (Go, `internal/catalog/flags.go`) が真正性の正。** 仕込み側
    (`charts/ctf-user/validate-flags-file.sh`、`deploy-user.sh --flags-file` が呼ぶ) は
    cluster に触れる前の早期検出であり、**食い違ったら Go に従う** (直すのは shell 側)。
    一致は parity テストで機械的に確かめる: 共通入力
    `internal/catalog/testdata/flags-parity/` を `flags_test.go` (`make test`) と
    `scripts/check-flags-file-validation.sh` (`make check-flags` / CI `flag-guard`) の
    両方が読み、(a) 受理した側は必ず `expected.tsv` どおりに解釈する、(b) 判定が
    分かれる入力は `cases.tsv` に固定 (現状すべて「Go 受理・shell 拒否」。
    「shell だけ受理」は 0 件であることを両テストが assert)。
  - `main()` は catalog を **`scoredFromEnv(serverutil.Env)` 1 回の呼び出しだけ**で得る
    (`cmd/scoreboard/catalog.go`。env の読み取りと `catalog.LoadScored` =
    読込 → scenario の絞り込み → flag 上書き、を 1 関数に閉じ、別々の catalog 値を
    取り違える余地を無くす)。`cmd/scoreboard/main_test.go` の
    `TestScoredFromEnv` (振る舞い) と `TestMainTakesCatalogOnlyFromScoredFromEnv`
    (`main()` がその結果以外から catalog を得ない・差し替えない) が固定。
  - follow-up (この変更では未実施): 検査の単一ソース化 — `charts/ctf-user/templates/
    ctf-flags-secret.yaml` の描画に寄せて `helm template` でオフライン判定する案、
    または Go 実装を CLI 化して shell から呼ぶ案。現状は 2 実装 + parity テスト。
- 仕込み側: `challenges/<NN>/plant.sh` が唯一の正典。フラグ実値は書かず
  `${CTF_FLAG_<ID>}` env を参照 (`<ID>` = challengeId 大文字・`-`→`_`)。
  **ADR-0001 (Option B, Accepted)**: `plant.sh` は `challenge` コンテナでは
  実行されない。`plant` initContainer (image は challenge と同一、I5 に触れない)
  が `ctf-flags` Secret から `CTF_FLAG_<ID>` を受け取り、seed emptyDir
  (`$PLANT_SEED_ROOT`) に書く。**`challenge` が見るのは plant-target の
  ENCLOSING DIRECTORY だけ** (ADR-0007, Accepted, ADR-0001 の派生決定 (1)
  = B1 を supersede) — plant-target が `dir` なら宣言そのもの
  (mission 05 の `/root/.ssh`)、`file` ならその親ディレクトリ
  (mission 03/10 の `/etc/shadow` → `/etc`)。plant-target ファイルそのものを
  単独で bind mount することは never (ファイル destination の mount は
  コンテナランタイム自身の mount-setup が `open_read` 系 Falco ルールを
  deploy ごとに発火させるため — `open_read` は `fd.typechar='f'` を要求し、
  ディレクトリ destination は構造的にこれを満たせない)。seed root は
  mount しない (F5・ADR-0001 提案 I12 は不変)。`challenge` の env には
  `CTF_FLAG_*` は一切出現しない。
- `values.yaml` / `values-all.yaml` は `make gen-values`
  (`challenges/gen-values.sh`) で plant.sh から生成。**手書き禁止**。
  生成物は `plant.seedScript` (initContainer が実行する `sh -c` script。
  同一マウントディレクトリを複数の plant.sh が共有する場合は 1 回だけ
  build-time snapshot (`/opt/ctf/plant-seed/`, ADR-0001 S-a) から
  ディレクトリごと復元して dedupe する) と `plant.mounts` (マウントディレクトリの
  重複無しリスト。各要素は `{path, readOnly}` — `readOnly` は **per-mount**
  で決まり (`plant.sh` の `# plant-mount-readonly: false` header 宣言、
  `gen-values.sh` の `plant_mount_readonly_override()`)、宣言が無ければ
  fail-closed 側の `true` になる。現状 `/etc` マウントのみ `readOnly: false`
  (mission 09 の `ln /etc/sudoers /etc/.cache.bak` が `/etc` への書込を要する
  ため)。mission 05 の `/root/.ssh` マウントは宣言なし = `readOnly: true` 維持)。
  CI `flag-guard` (`gen-values.sh --check`) が同期 + ADR-0001 Verification
  2-1〜2-7 + ADR-0007 Verification 1/2 (mount ディレクトリ granularity の
  静的検査・故意違反の negative test) を検証する。
- 採点フラグ (FLAGS_FILE) と仕込みフラグ (CTF_FLAG_*) は platform の
  同一 `flags.sops.yaml` から render され、必ず一致する。

## 課題ドキュメント用 rule.yaml (challenges/<NN>/rule.yaml)

- docs サイトが「背景の後」に描画する **表示用 Falco ルール抜粋**。`falco-rule.yaml`
  (scoreboard metadata: expectedRules/forbiddenRules) とは別物。
- **デプロイ中の実ルールセットから抽出**して精度を担保(本番 Falco と一致):
  `kubectl -n falco exec <falco-pod> -c falco -- cat /etc/falco/falco_rules.yaml` から
  各課題の expectedRules + forbiddenRules の rule ブロックを抽出 → `challenges/<NN>/rule.yaml`。
  **ただし 10 の証明の rule (`Nimbus Vault Master Key Read`) は抽出しない** (ADR-0032 D9 (i)。condition の開示になる)。10 の `rule.yaml` は禁止ルール 7 本だけを載せ、`internal/catalog/rules_test.go` の `TestMission10DisplayRuleExcerptExcludesProof` が「証明の rule 名と `master.key` を含む rule が無く、`rule.yaml` 自体はある」ことを pin する。
- **Falco バージョンを上げたら再抽出**(condition/output が変わるため)。docs の
  gen-pages.py は存在すれば描画、無ければスキップ(必須ではない)。
- **同一 Falco ルールを表示する課題は sync group として同時更新する** — 例:
  `02-credential-files`(trigger)と `03-stealth-read`(evade)はどちらも
  `Read sensitive file untrusted` を表示するため、両者の `rule.yaml` は
  byte-identical でなければならない。再抽出時に片方だけ更新すると drift し、
  参加者に見せるルール条件が課題間で食い違う(採点には非影響、issue #122)。
  `scripts/check-challenge-rules.sh` の `RULE_YAML_SYNC_GROUPS` がこれを
  機械強制する(必須 CI check `challenge-rules` に相乗り)。新しい sync group は
  同スクリプトの配列に 1 行追記する。

## Scope / 影響範囲

| 変更箇所 | 影響 |
|---|---|
| `scoreboard/` | 採点ロジック直結。`POST /falco/events` payload を変えるなら platform 側も同時 PR |
| `auth-policy/` | セキュリティ境界。ロスター (I8) と `X-Auth-Request-Email` の正規形は絶対に緩めない |
| `challenges/<NN>-<slug>/` | その課題のみ |
| `images/{ttyd,challenge}/` | 全ユーザ環境に影響 |
| `charts/<name>/` | 全環境。default は環境非依存、環境値は platform helmfile が供給 |

## Cross-repo 契約 (falco-ctf-platform との接点)

この表で `<family>{<label>, …}` の形で書いた metric family は、所有 binary の起動直後から存在する。family が無いことは改名か旧い image で、0 とは読まない (ADR-0040。表の code span と所有 binary の起動直後の `/metrics` の一致は `internal/contractmetrics` の test 1 本が確かめる)。契約でない名前 (旧い名前など) はこの形で書かない。

| 接点 | 詳細 |
|---|---|
| Image naming (**正典**) | `${REGISTRY}/falco-ctf-{scoreboard,auth-policy,collector,ttyd,ttyd-proxy,challenge,docs,detect-grader}:<git-sha>`。registry の repo 名は **`falco-ctf/X` slash が正式**、`falco-ctf-X` dash も ingest 受理。tag は git SHA (I4/I5, 全 8 イメージ同一 SHA)。**この行が slash/dash 命名契約の単一定義** — 他所 (ingest フィルタ節・platform docs) はここを参照する。**release の image 集合 (ADR-WS-0010 D8)**: platform の release scan gate は `Makefile` の `IMAGES :=` の 1 行 (継続行・行末コメント無し) を release の image 集合として読む (platform `scripts/lib/release-scan.sh`)。形式や意味を変える PR は両リポ同時。`IMAGES :=` が I5 の 8 image と一致することと 1 行の形は `internal/contracttable` の test が固定する |
| ttyd-proxy 配線 (P23-3, **正典・実装済**) | `charts/ctf-user` の workspace Pod に ttyd-proxy サイドカーを追加 (本 repo 内、chart 配線まで app-lead が完結)。契約: (1) image = `falco-ctf/ttyd-proxy:<git-sha>` (I4/I5)、(2) ttyd-proxy が Ingress 到達ポート (`LISTEN_ADDR` env、`.Values.ttyd.port` 既定 `:7681` = 現行 ttyd ポート) を listen し Service.targetPort/NetworkPolicy はこのポートのみ許可、ttyd 自体は `.Values.ttyd.upstreamPort` 既定 `7682` へ退避して `TTYD_PORT=7682` + `TTYD_INTERFACE=127.0.0.1` を chart から明示注入 (image 側の `TTYD_INTERFACE` 既定は後方互換のため `0.0.0.0` のまま — オプトインは chart 側の責務)、(3) `FRAME_ANCESTORS` env = `.Values.ttyd.frameAncestors` 既定 `'none'` (fail-safe。`deploy-user.sh --frame-ancestors <value>` で上書き可) — **ctf-user は helmfile 管理外** (platform helmfile の release ではない) なので、ポータル origin を注入する経路は platform の `deploy-event-workspaces.sh --frame-ancestors <origin>` からロースター全員分 `deploy-user.sh --frame-ancestors` へ passthrough する形。**実装済み** (platform issue#52 → PR platform#54, P19-2a。文法は app の 1 定義 (ADR-0044、「`--frame-ancestors` / `--app-host` の文法」行) で、platform は値を組み立てて forward するだけ。P19-2a の旧検査は ADR-0044 D6 の対 issue platform#290 で消す予定 (未 merge)。残っている間も app の検査より広い側なので、受理集合は app が決める)。**platform の名簿の経路の値の出所** (ADR-0046、Proposed。**platform 側は未実装**: platform#292 (未 merge)。それまでの stand-up と runbook の名簿は 3 値を渡さず、ttyd-proxy は chart 既定の `'none'` を返す): platform#292 が入ると、`deploy-event-workspaces.sh` は、2 フラグが省かれたとき `--env` の env file の `appHost` から `--frame-ancestors https://<appHost>` と `--app-host <appHost>` を導いて、全 seat に渡す予定。明示の値は `'none'` (意図した無効化) か導出値と同じ値だけを受け、違えば seat に進まず exit 2。env が local なのに kube context が local 系でない (`TARGET_IS_LOCAL=0`) ときも exit 2。local 以外で `appHost` が空 (env file が読めないときも同じ) なら exit 2、local で空なら導出しない (省略なら chart 既定、明示値はそのまま渡る)。導出値は名簿の前に文法を検査し、文法外なら exit 2。ADR-0046 が Accepted になれば scoreboard の `allowedOrigins` と同じ出所になり、手で揃える運用規律は platform の経路から無くなる。app の `deploy-user.sh` は導出しない (passthrough のまま。直接使うときは運用者が 2 値を渡し、一致は ADR-0044 D3 が検査する)。platform#292 が merge されなければこの記述を戻す。**WebSocket Upgrade は `Origin` = `https://<Host>` の 1 origin だけを通す** (ADR-0048。ttyd-proxy が、`Connection` に token `upgrade` + `Upgrade` が空でない request で、Origin 無し・複数・別 origin・http・port 違い・大文字小文字違いを 403 にする。非 upgrade は不変。Host の前提 = platform の義務: workspace Ingress の前段 (ingress controller・Cloudflare・LB) はクライアントの Host を変えずに ttyd-proxy へ渡す。Host の扱いを変える変更 (upstream-vhost 相当、controller の置き換え、Gateway API) は両リポ同時 PR とし ADR-0048 V3 をやり直す。実機は ADR-0048 V3 で、platform の event pin にこの SHA 以降を載せる前に通す。platform#297)。ttyd の readinessProbe は `tcpSocket` ではなく `exec wget -q -O /dev/null http://127.0.0.1:<upstreamPort>/` (busybox wget。ttyd image に curl / bash は無い。app#504) (tcpSocket/httpGet probe は kubelet が Pod IP に dial するため loopback-only コンテナには使えない)。契約変更 (ポート番号・env 名) は両 repo 同時 PR |
| detect-grader Job (**正典**) | scoreboard は `DETECT_RUNNER=k8s` のとき per-submission Job を作る。**app が確定し platform が一致させる契約**: (1) namespace = `DETECT_GRADER_NAMESPACE` env (専用 grader ns。platform が作成)、(2) grader image = `DETECT_GRADER_IMAGE` env (digest-pinned `.../detect-grader@sha256:...`。platform helmfile が供給、chart に焼かない I7)、(3) scoreboard SA に **Job + Secret + Pod の RBAC** (下記動詞)、(4) grader ns に **deny-all NetworkPolicy** (replay は無ネットワーク)。Job/Secret/Pod は label `app.kubernetes.io/name=detect-grader`・`app.kubernetes.io/component=grader-job`・`falco-ctf/challenge=<id>` を持つ。Job/Secret 名 = `detect-<challengeId>-<nonce>` / `<jobname>-cond`。契約変更は両 repo 同時 PR |
| Charts | `charts/{scoreboard,auth-policy,ctf-user,docs}` を platform helmfile が local=path / prod=OCI で参照 (CI publish は現状停止 → prod も local clone path。`project_ci_free_prod` 参照) |
| Participant path 集合 (ADR-0028 D6, **正典**) | 参加者 (any-login) に開く path の集合は **`charts/scoreboard/templates/ingress-journey.yaml` が正典** (本 repo)。`AudienceParticipant` の mux Route との一致は **I15** が機械照合する (`internal/scoreboard/ingress_journey_parity_test.go`)。**platform は文書で参照するだけ** (文書の一覧と食い違ったらこの file が正)。静的アセットは `/static/` (Prefix) 1 本なので、アセットを足しても platform の変更は要らない。**path / pathType を変える PR は両 repo 同時 PR + 相互リンク**。chart (platform から見た app clone の checkout) と image (`appImageTag`) は**同じ SHA で同時に**入れる — 片方だけだと portal が無スタイルになる (ADR-0028 Consequences) |
| `deploy-user.sh` の exit status (**正典**・ADR-0001 DoD 8) | **`deploy-user.sh` の非ゼロ exit は fail-closed 契約。呼び出し側は伝播する。** ADR-0001 Verification 3 の deploy 時 assert (`charts/ctf-user/assert-flag-isolation.sh`) は violation で `deploy-user.sh` を非ゼロ終了させるので、**呼び出し側が exit status を捨てると assert 自体が無意味になる** (security-engineer の F2)。platform 側 `scripts/deploy-event-workspaces.sh` は per-user の exit status を収集し、**1 件でも失敗したら `✓ done` を出さず非ゼロ終了する** (bare `wait` は子の失敗を伝播せず exit 0 を返すので使わない)。契約変更は両 repo 同時 PR |
| Challenges path | `deploy-user.sh --challenges-dir` (ctf-user chart 同梱、当 repo `challenges/` を default 参照)。`--scenarios-dir` (P27-1) は同様に当 repo `scenarios/` を default 参照 — `<username> scenario:<name>` モードでのみ使う。**platform 側 `deploy-event-workspaces.sh` (platform#130 で実装) は `--challenge` 未指定時、現在の環境の `scoreboardScenario` (採点スコープ) を helmfile 経由で読み取り `scenario:<name>` へ自動導出する** (`--challenge` 明示指定は自動導出より優先。`--env` で対象環境を選ぶ — `scripts/standup.sh` は `$HELM_ENV` を渡す) | 
| fixtures の絶対パス (ADR-0026 D3, **正典**・platform#203 と対) | workspace 内 `/opt/ctf/missions/<challengeId>/fixtures/**` = 本 repo の `challenges/<challengeId>/fixtures/**`。challenge image の `/opt/ctf/missions/` が持つのは `<id>/fixtures/**` だけ (**I16**。README / `journey.yaml` / `falco-rule.yaml` は端末から読めない)。platform の Falco `customRules` (`helmfile/releases/falco/values.yaml.gotmpl` の `13-archive-loot` の `fixtures/loot/`) がこの絶対パスに依存するので、**パスを変えると該当 trigger 課題が無検知 (= 解けない) になる。変更は両 repo 同時 PR + 相互リンク**。deploy 時 (V4): `deploy-user.sh` が呼ぶ `assert-flag-isolation.sh` の 3-8 が、scenario / `all` / 単一課題の 全モードで running Pod の `/opt/ctf/missions/` を検査し (`all` / 単一課題では image 自身、**scenario モードで見るのは `missions-scope` の copy** = 参加者から見える面)、一致しなければ**非ゼロ exit** (fail-closed 契約。呼び出し側は伝播する)。**allowlist 前の image に新しい ctf-user chart を deploy すると 3-8 で止まる → image を先に更新する**。期待 id 集合は operator の checkout の `challenges/` から作るので、**app の checkout は image と同じ pin ref にあること** (ずれると `all` / 単一課題でも止まる)。**platform が使う app の面**: `scripts/check-image-hygiene.sh <image>` (app の root で実行。引数は image 参照 1 つ。exit 0 = 合格、非 0 = push しない。fixtures が git clean であることが前提。検査は image 自身の `find -printf` と `sha256sum` を使う) — platform の `docs/prod-deploy.md` の build ループが push 前に呼ぶ。`make build` を使わない platform の経路ではこれが一次ゲート |
| Webhook payload | `POST /falco/events` は falcosidekick 標準形。フィールドキー変更は両 repo 同時 PR |
| Webhook 流量制限 (app#359) | `POST /falco/events` の流量制限のキーは**参加者 (event の `ctf-<user>` ns)** であり、送り手 (falcosidekick の 1 IP) ではない。採点に効く rule (いずれかの challenge の forbidden / expected) は**落とさない**: 参加者の scoring bucket を超えても通常の taint 述語 (現在の evade が forbid する rule) は適用し、実 rule 名で fail-closed に taint (`Grader.TaintOnOverflow`。述語を広げない = ADR-0003 A1 / I11)、200 で返す。それ以外の採点 rule は処理を skip (outcome `overflow_skipped`)。ns は username slug として検証し、合わなければ ignored。採点に効かない rule は observation bucket 超過で 429。ctf 以外の ns / 非 challenge コンテナ / 下限未満の priority は制限しない。観測: `scoreboard_ingest_falco_events_scoring_overflow_total{ns}` (verify は 0 を要求する) / `scoreboard_ingest_falco_events_rate_limited_total{ns}`。**2 つの family は起動直後から存在する** (`ns="_other"` の 0 を事前生成。family 無し = 改名か旧 image であり、「0」とは読まない)。sidekick は 429 を再送しない。metric 名・label 名 `ns`・起動時の事前生成を変える変更は両リポ同時。契約変更 (bucket のキーを送り手へ戻す、採点 rule を drop に戻す) は security-engineer レビュー必須 |
| identity 拒否の観測 (app#404、ADR-0038) | scoreboard の identity gate が identity を理由に拒否した要求 (identity-keyed bucket の strict middleware・`selfOrAdmin`・`requireAuthenticated` の 403) と、識別できない呼び手に返した portal の shell (`GET /portal`、200 のまま) を、**metric `scoreboard_identity_denials_total{gate, reason}` の 1 本**で数える (1 要求につき、拒否した gate で 1 回)。**`reason`**: `no_identity` (`X-Auth-Request-Email` が無いか空) / `non_canonical` (header はあるが、正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` でも、その gate が通す `ADMIN_EMAILS` でもない) / `mismatch` (正規形の別 seat。参加者の操作で 0 にならない)。**app の保証**: (1) 健全な本番では `no_identity` と `non_canonical` は 0 (header 無しや非正規形で identity gate に届く経路が無い = I8 の前提と「Identity 表と正規形」行の (2))、(2) **全 gate の `reason="no_identity"` の系列が起動時に 0 で存在する** (系列が無い = 契約違反。platform は「0 件」ではなく判定不能と扱う)、(3) 値は Pod の起動からの累計 (in-memory、Recreate で 0)。`gate` は表示用で、値の集合を固定しない (gate と reason の値を足すのは app 単独でよい)。**platform** の verify は `reason="no_identity"` の**前回の verify (または stand-up 時の baseline) からの増分**が非 0 なら WARN として読む (FAIL にしない。累計の非 0 を読むと、一度の事故で以後ずっと WARN になる。counter は Pod の起動からの累計なので、Pod UID が前回と違えば baseline を取り直す。`non_canonical` を読み始めても契約の変更は要らない)。triage は log `identity gate denied` の `remote_addr` を見る (loopback = 運営の port-forward)。metric 名、label 名 `reason`、`no_identity` と `non_canonical` の意味、事前生成を変える PR は両リポ同時。gate を外す・reason を畳む変更は security-engineer のレビュー必須 |
| Cookie domain | `.<ctf-domain>` は platform が決定。app 側は前提とする |
| Identity 表と正規形 (ADR-0034 S2, **正典・両リポ同時 PR**) | auth-policy の identity 表 (ロスター)・正規形・endpoint の契約。**platform** は: (1) seat の集合 (Dex の静的ユーザの生成元と同じ値) と外部 identity (git の外のファイル) から、`ROSTER_FILE` の YAML (`seats:` の下に `{seat, external?}`。`external` は seat あたり高々 1 つ・省略は key ごと省く) を描画して **Secret (既定名 `auth-policy-roster`、key `roster.yaml`、auth-policy の namespace)** に入れる (chart は `/etc/auth-policy/roster/roster.yaml` に mount して `ROSTER_FILE` を渡す。Secret が無ければ Pod は起動しない = fail-closed。表の変更で rolling restart するよう `roster.checksum` に内容の digest を渡す)、(2) `EXPECTED_EMAIL_DOMAIN` に予約名 (最後のラベルが `local` `test` `invalid` `example` `localhost`) を渡し、**auth-policy (`env.expectedEmailDomain`) と scoreboard (`env.expectedEmailDomain`) に同じ値**を供給する、(3) oauth2-proxy を `insecure_oidc_allow_unverified_email=false`・既定の email claim・`email_domains` は表から描画にする、(4) `ADMIN_EMAILS` には予約ドメインの静的アカウントだけを渡し、roster の seat の正規形・external と重ねない (重なる設定は **auth-policy だけ**が起動拒否する。scoreboard はロスターを持たないので seat との重なりを検出できない)。**`ADMIN_EMAILS` は同じ 1 値を auth-policy と scoreboard の両 release に渡す (platform の義務)**: 2 release でずれる (例えば scoreboard だけに `user1@<domain>` が入る) と、auth-policy が正規形に書き換えた seat が journey 経由で scoreboard の admin になる。**app** は: D2 の形と起動検査 (欠落・空・重複 [正規化の後]・予約名・非 ASCII)、D3 の正規形と endpoint (`GET /check-workspace?host=<h>` / `GET /check-participant` / `GET /check-admin`。**旧 `GET /check` は削除** — 新 chart + 旧 binary、旧 chart + 新 binary のどちらも 404 → ingress 500 で閉じる)、`/healthz` の `roster_seats` / `roster_external` (件数のみ。preflight は `roster_seats > 0` を見る)、D4 の auth-url の固定 (**`journeyAuthUrl` / `adminAuthUrl` / `auth.authUrl` / `auth.enabled` は廃止** — 渡されたら描画 fail。Ingress の annotation passthrough 3 つ (scoreboard の `ingress.annotations` / `ingress.journeyAnnotations`、docs の `ingress.annotations`。ctf-user には passthrough が無い) は **許可 key の allowlist** (`nginx.ingress.kubernetes.io/ssl-redirect` / `nginx.ingress.kubernetes.io/proxy-body-size` / `cert-manager.io/cluster-issuer` の 3 つ。`falco-ctf-common.ingressPassthrough` に 1 定義) で、それ以外の key は描画 fail: `auth-*` だけでなく `satisfy` (`any` と source-range の組は auth subrequest を飛ばす) や `whitelist-source-range` / `allowlist-source-range` も入らない。key を足すのは理由のある PR で、V12 のケースと同時)、D6 の collector の `X-Auth-Request-*` strip を保証する。**platform が literal で pin している固定値** (rego の AUTH boundary・preflight-identity・apply-roster-secret。app の V12 `internal/apispec/ingressparity` が描画結果で同じ値を pin する。変えるなら両リポ同時): auth-policy の Service DNS = `auth-policy.auth-policy.svc.cluster.local:80`、各 Ingress の namespace/name と役割 = `scoreboard/scoreboard` → `/check-admin`、`scoreboard/scoreboard-journey` → `/check-participant`、`<docs release の namespace>/docs-admin` → `/check-admin`、`ctf-<seat>/ttyd` → `/check-workspace?host=<seat>`、`auth-response-headers` = `X-Auth-Request-User,X-Auth-Request-Email,X-Auth-Request-Preferred-Username` の 3 本 (全 Ingress)。どれかを変えるときは両リポ同時 PR |
| seat の文法と共有 case 表 (ADR-0042、ADR-0034 D2 の 1 文を置き換え、**両リポ同時 PR**, app#480) | seat (workspace 名、Helm の release 名、`ctf-<seat>`、workspace host の先頭 label) の文法は **`^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$` (1〜53 文字、両端が英数字)** = deploy できる集合。Go の定義は `identity.SeatPattern` の 1 つ (spec 3 本の `pattern` と、その pattern を持つ全 site の `maxLength` (= 53、`ValidSeat` に尋ねた値) は `specparity` が固定。spec の description に regex の写しは置かない)。**写しを全部照合する正典は `internal/identity/testdata/seat-cases.tsv`**: **1 行目は header `# pattern: ` + 正典 literal の regex** (`# pattern: ^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$`、書式は固定。**platform の parity test はこの行を読む。app の Go ソースの字面は契約の面にしない**。Go 側は `TestSeatCaseTable_HeaderIsTheGoPattern` が `identity.SeatPattern` との一致を固定し、header は row reader には comment として読まれる)、行は 2 列 `input<TAB>accept|reject` (最初の tab で分割、input は空でもよい、`#` と空行は無視)、placeholder の閉集合 `{LF}` `{U+202E}` `{U+00FC}` `{U+00EF}` (decode 後に `{` `}` が残った行は reader の誤りとして fail。表自体は ASCII)。**読み手** (表を読む実装は 1 つずつ): Go = `internal/casetable` (`TestValidSeat_SharedCaseTable`)、shell = `scripts/lib/casetable.sh`、platform = `scripts/test-seat-grammar-parity.sh` (platform#282 で main 入り)。この表を使う検査は次のとおり: `charts/ctf-user/deploy-user.sh` の `SEAT_PATTERN` (`scripts/check-seat-grammar.sh`。`TestDeployUserShellPatternIsTheGoPattern` が text を `SeatPattern` に固定。`make check-flags` と CI `flag-guard`)、platform の `scripts/lib/roster.sh`・`policy/key-guards.rego`・`scripts/preflight-identity.sh` (対の PR)。`make e2e-serve AS=` の検査は近似で表には登録しない。**deploy が seat から作る名前** (release 名・namespace・label の値・host) との一致は 2 段で固定する: release 名 (= seat) と namespace (`ctf-<seat>`) の導出は `scripts/check-seat-grammar.sh` が `deploy-user.sh` の実呼び出し (記録した `helm upgrade --install <seat> … -n ctf-<seat>` と `kubectl create namespace ctf-<seat>`) を完全一致で比べて固定し、chart が seat から作る名前 (namespace・label の値・host) は `internal/apispec/ingressparity/seat_render_test.go` が `helm template` で固定する (`deploy-user.sh` は `--set-string username=`、chart は label の値を `quote`)。**chart 自身も username が string でない (`--set username=0` / `true` / `null`、values file の数値) か空なら描画で fail する** (`ctf-user.username` の 1 箇所を namespace・label・host・auth-url・Pod env の全てが通る。`--set-string` で渡す。ADR-0042 C4、app#503)。**表の path の rename・移動、書式 (1 行目の header・2 列・placeholder の集合)、文法の変更はいずれも両リポ同時 PR** (行は落とさない。食い違う側が bug)。順序 app → platform。出所: ADR-0042 |
| Flags (**ADR-0001 Option B で更新**) | platform `events/<date>/flags.sops.yaml` が正典。scoreboard へは変わらず `FLAGS_FILE`。仕込み側は **`ctf-flags` Secret (`CTF_FLAG_<ID>` キー) → `plant` initContainer にのみ `envFrom`/`secretKeyRef` で到達** — `challenge` コンテナの env には CTF_FLAG_* は一切出現しない (ADR-0001 提案 I12)。`deploy-user.sh --flags-file` の `--set-string challenge.flags.<id>=...` という *引数* 面は不変 (C6)、到達経路だけが変わった。app は `FALCO{dev-<slug>}` placeholder のみ保持。dev default 値は両 repo で一致させる。**flags ファイルの要件 (fail-closed)**: 指定時は、スコープ内の全 evade 課題の id を含み、値は `FALCO{...} (only A-Za-z0-9_- inside the braces)` の形で、どの課題の dev default とも同値でなく、課題間で重複しないこと。`flags:` 直下に `<id>: <値>` を 1 行 1 エントリで書く — 満たさないファイルは scoreboard が起動を拒否し、`deploy-user.sh` が非ゼロ終了する (「フラグ注入」節参照)。platform はイベント用ファイルを全 evade id について生成する。**platform が使う app の面 (変えるときは両 repo 同時 PR)**: `charts/ctf-user/validate-flags-file.sh` の CLI (引数 `<flags-file> <challenges-dir> <challenge-id> [<scenarios-dir>]`、終了 0 = 受理 / 1 = 拒否 / 2 = 使い方の誤り・読めない入力。stdout は成功時にスコープ内の `<id><TAB><flag>` 行で**値を含む**ので、検査だけの呼び出しは捨てる。stderr の診断は値を含まない)、`deploy-user.sh --flags-file`、`challenges/*/falco-rule.yaml` の top-level `type: evade` と `challengeId` (platform が evade id の集合を導く元)。platform 側の決定 (flags を指定しない経路の遮断・課金前の gate・適用の順序) は ADR-0033 Decision 9 |
| `ALLOWED_ORIGINS` (P23-2, **platform 側 P19-2a で landing 済**) | scoreboard の origin-guard middleware (`internal/scoreboard/originguard`) が読む CSRF 対策アローリスト env。chart 側は `charts/scoreboard/values.yaml` の `env.allowedOrigins` (default `""` = fail-closed = 全ガード対象ルートが拒否) と `templates/deployment.yaml` で受け皿を用意済み。**platform helmfile (`releases/scoreboard/values*.gotmpl` 等) が P19-2a (platform#54) でこの値の供給を landing 済み**。P19-2b の単一 origin 化後は値がさらに単一化: `https://app.<dnsSuffix>` の一値 (旧・host分離時代の `https://journey.<dnsSuffix>` 等の複数値は不要になった)。`userN.<dnsSuffix>` の ttyd origin は含めない (CSRF 踏み台化を防ぐため意図的に対象外)。値の実供給・検証は platform-lead 側 |
| `PORTAL_TTYD_SUFFIX`⇔`ctf-user.dnsSuffix` 一致制約 (P23-4, **正典**。scoreboard 側 = 実装済、ctf-user 側の導出 = 未実装: platform#292 (未 merge)) | scoreboard の portal Terminal タブは呼び手自身の ttyd iframe src を `https://<derived-username>.<PORTAL_TTYD_SUFFIX>` で構築する (`cmd/scoreboard/main.go` の `portalTtydSuffix := serverutil.Env("PORTAL_TTYD_SUFFIX", "")` (L115) → `WithTtydSuffix` → `internal/scoreboard/view/view.go` の `ttydSuffix` (L96-102) → `internal/scoreboard/view/portal.go` の `ttydURLFor`)。**この値は `charts/ctf-user` chart の `dnsSuffix` (per-user ttyd Ingress host `<username>.<dnsSuffix>` の分) と文字列完全一致していなければならない** — 不一致は fail-safe (iframe が 404 する、または auth-policy `/check` の host 照合で弾かれ 403。**参加者間の隔離自体 (I8) は破れない**が Terminal タブの UX が壊れる)。platform 側は `helmfile/releases/scoreboard/values.yaml.gotmpl` の `portalTtydSuffix: {{ .Values.dnsSuffix \| quote }}` が env file の `dnsSuffix` から派生させ、ctf-user 側は、platform#292 が入ると名簿の経路 (`deploy-event-workspaces.sh`) が同じ env file の `dnsSuffix` から `--dns-suffix` を導く予定 (ADR-0046 D5、Proposed。`appHost` の有無と独立に導く。**platform 側は未実装**: platform#292 (未 merge))。ADR-0046 が Accepted になれば、両側を同じ値から作ることでこの一致を保証する。それまでは名簿が `--dns-suffix` を渡さず、ctf-user 側は chart 既定の `dnsSuffix` (`ctf-event.dev`) との偶然の一致で成り立つ (prod / vm-prod。local の nip.io では成り立たない: ADR-0046 C6、仮説)。platform#292 が merge されなければこの記述を戻す。scoreboard は起動時に `dnsname.Valid` で検査し、文法外 (大文字・末尾 `.`・port・scheme・空白・制御文字・長さ超過) なら起動しない (ADR-0047 D6、app#532。platform の `dnsSuffix` は同じ `dnsname.Pattern` を受理する値なので新しい契約面は無い)。空 (default) = Terminal ペインは「未構成」プレースホルダに fail-safe (`view.go` L96-102、`portal.go` L34)。契約変更 (env 名・派生元) は両 repo 同時 PR |
| Cookie `SameSite=None`+Secure embed 契約 (P23-4, **正典・実装済**) | portal Terminal タブが ttyd を **cross-origin `<iframe>`** で埋め込む (appHost origin のページに `userN.<dnsSuffix>` origin を埋め込み) ため、oauth2-proxy の session/CSRF cookie は `SameSite=Lax` のままだと iframe 内のサブリクエストに付与されず認証が壊れる。platform 側 `helmfile/releases/oauth2-proxy/values.yaml.gotmpl` の `cookie_samesite = "none"` (L60、`cookie_secure = true` は既設 L48) が緩和し、`cookie_csrf_samesite` は空継承で CSRF cookie も同時に `None` になる (L53-55 コメント参照)。**この緩和は単独では安全に成立しない** — (1) `internal/scoreboard/originguard` (P23-2) が状態変更 API の Origin/Referer を明示 allowlist (`ALLOWED_ORIGINS`、上記行) で fail-closed 検証し、SameSite=Lax が今まで閉じていた classic cross-site form-POST CSRF の穴を埋める (ガード対象は `h.og()` でラップされたルートに限る — submit / display-name (非 admin) / internal-exfil の 3 ルートは collector forward 経路のため意図的に対象外。`api.go` 側コメントに accepted residual risk として明記済みで、本緩和による新規悪化ではない)、(2) ttyd-proxy の `FRAME_ANCESTORS` (P23-3、上記「ttyd-proxy 配線」行) が iframe として許可する親 origin を制限する、(3) ttyd-proxy の WebSocket Upgrade の Origin 検査 (ADR-0048) が seat host 以外の Origin を 403 にする (platform#297。platform CLAUDE.md の前提条件の要約は platform#297 で揃える)。**この 3 つが main に landing 済みであることが cookie 緩和の前提条件** (`internal/scoreboard/originguard/originguard.go` の package doc L1-15 に同じ依存関係の説明あり)。**merge 順序**: platform (cookie 緩和) を同時 or わずかに先行させる。app-first で merge すると iframe に cookie が届かず Terminal タブが login ループ/403 になり不可 (経緯は platform#53 / app#91 の PR 本文)。契約変更は両 repo 同時 PR |
| collector の forward 集合 (ADR-0034 D12 S1) | collector が scoreboard へ転送するのは **`submit` / `exfil` の 2 本だけ** (default-deny)。参加者用 `POST /api/users/{user}/display-name` (旧 forward、端末の `setname` が使っていた) は route ごと撤去し、`setname` も challenge image から外した (forward は 3 本 → 2 本。`docs/openapi-collector.yaml` は 5 → 4 operation)。表示名と絵柄は portal の `POST /api/users/{user}/profile` (origin-guard 付き・self-or-admin・認証ヘッダー必須・collector 非 forward)。forward を足す・戻す変更は ADR が要る。architect の同意は ADR-0034 D12 |
| challenge id の文法と collector の 404 (ADR-0041 Accepted, **両リポ同時 PR**) | challenge id の文法 `^[0-9]{2}-[a-z0-9-]{1,60}$` (`NN-slug`) は、**Go と両 spec で 1 定義** (`internal/catalog/challengeid.Pattern`。両 spec の `Cid.pattern` が等しいことは `internal/apispec/specparity` の `identifier_patterns_test` が固定)。**platform は文法を持たない**。shell 側の写しのうち **`charts/ctf-user/deploy-user.sh` の単一課題モードの id (`CHALLENGE_ID_PATTERN`) は pin 済み** (app#494: 共有 case 表 `internal/catalog/challengeid/testdata/challenge-id-cases.tsv` を Go (`challengeid` の `TestValid_SharedCaseTable`、`TestDeployUserShellPatternIsThePattern` が text を `Pattern` に固定) と `scripts/check-deploy-user-ids.sh` (`make check-flags`・CI `flag-guard`) が読み、文法外は kubectl / helm の前に exit 2 `invalid challenge id`。`--set-string challengeId=` で渡す)。`scenario:<name>` の name も同じ経路で検査する (`SCENARIO_PATTERN` `^[a-z0-9]([a-z0-9-]{0,52}[a-z0-9])?$`、`internal/catalog/testdata/scenario-name-cases.tsv`、Go の定義は無く header と shell の literal の一致を `internal/catalog/scenario_name_test.go` が固定、実在の scenario は全て受理)。**残りの写し (`gen-values.sh`・他の検証 script・chart の `regexMatch` guard) は未 pin (app#472)**。collector は `{cid}` を**構文でだけ**検査し (catalog / flags / DB は持たない)、文法外なら `submit` も `exfil` も collector 自身が `404 {"error":"unknown challenge"}` を返して転送しない (exfil の旧 `400 invalid challenge id` は ADR-0041 で 404 に変更)。文法内なら catalog に有るかを問わず転送する (`submit` は verbatim)。catalog に無い id は scoreboard が同じ 404 `{"error":"unknown challenge"}` (id は echo しない) で答える。**platform の消費者** = `scripts/verify.sh` (a-2) の probe `POST /api/challenges/99-verify-probe/submit`: 文法内で catalog に無いので collector が転送し、scoreboard の 404 + body の prefix `{"error":"unknown challenge` が green。collector の局所 404 は scoreboard の 404 と同じ bytes なので、gate が答えた側を区別するのは「probe が文法内」という事実で、app の `make test` が固定する (V2: 文法内 / V3: 実 catalog に無い・scoreboard の 404 / V5: collector を実 scoreboard の前に置いた合成 test で、文法外の 404 と転送された 404 の status・Content-Type・body が一致)。**両リポ同時の対象**: probe の id、文法 (`Cid.pattern`)、collector の局所 404、**scoreboard の unknown challenge 404 の body prefix `{"error":"unknown challenge`**。順序: platform #264 (済) → app #484 → platform pin bump (#271) |
| DNS 名の文法 (ADR-0047、**クロスリポ契約**: 文法は app に 1 つ、platform は表の 1 行目だけを読む) | **1 定義** = Go の `internal/dnsname` (標準ライブラリだけの葉。module 内の package を import しない)。literal は `dnsname.Label` = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` の 1 つだけで、残りは合成: `dnsname.Body` (Label を `\.` で連ねる。anchor 無しで、host を埋め込む文法が使う)・`dnsname.Pattern` (`^` + Body + `$`)・`dnsname.MaxLen` (253。label の上限 63 は Label の `{0,61}` が決める)・`dnsname.Valid` (長さ ≤ MaxLen かつ Pattern に一致。空は false)。小文字だけで、scheme・port・path・userinfo・末尾の `.`・IPv6 literal は受けない。**消費者** (どれも同じ受理集合): `deploy-user.sh --dns-suffix` と `--app-host` (shell の写し `DNS_SUFFIX_PATTERN` / `DNS_SUFFIX_MAX_LEN`。literal = Pattern / MaxLen、`dns-suffix-cases.tsv` の header = Pattern、表の全行 = Valid、chart の default の `dnsSuffix` の受理を `internal/dnsname/dnsname_test.go` が固定する)・`FRAME_ANCESTORS` の host 部分 (`ttydproxy.FrameAncestorsPattern` が `dnsname.Body` を合成し、`FrameAncestorsMaxLen` = 8 + MaxLen。「`deploy-user.sh --frame-ancestors` / `--app-host` の文法」行)・scoreboard の `PORTAL_TTYD_SUFFIX` (`view.ValidateTtydSuffix` が `cmd/scoreboard` の起動時に `dnsname.Valid`。空は「未構成」として許し、文法外は起動しない: app#532)。新しい消費者は import し、写しを作らない (`internal/identity` の seat 形の検出器が、cmd/ と internal/ の test 以外の .go にある Label の 2 つ目の literal を赤にする)。**platform が読む面** = `internal/catalog/testdata/dns-suffix-cases.tsv` の **1 行目** (`# pattern: ` + `dnsname.Pattern`。書式は seat の表の header と同じ)。Go / shell の字面と 2 行目以降は面にしない。**変更の規則**: dnsname を変えると `--dns-suffix`・`--app-host`・`--frame-ancestors` (`PORTAL_TTYD_SUFFIX` も: app#532) が同時に変わるので、**狭める変更も両リポ同時 PR** (「`deploy-user.sh` の運用者入力の文法」行の「app 単独 PR でよい」は `--dns-suffix` に適用しない)。広げる変更は `--frame-ancestors` も広げるので ADR が要る (port は dnsname を変えずに合成する。ADR-0047 Signpost 1)。`dns-suffix-cases.tsv` / `frame-ancestors-cases.tsv` の path と 1 行目の byte を変える変更は、**同値の書き換えでも両リポ同時 PR** (表の `internal/dnsname/testdata` への移動も同じ。ADR-0044 D7)。`internal/dnsname/**` (test を含む) の変更は security-engineer レビュー必須 (`.claude/rules/dev-flow.md` のゲート表)。出所: app#533 (#543)、review-5x 81 R4#2 / R4#4、review-5x 90 R4#4 |
| `deploy-user.sh` の運用者入力の文法 (app#510。`--dns-suffix` 以外の 3 値は **app 単独で狭められる**。`--dns-suffix` は「DNS 名の文法 (ADR-0047)」行。ADR-0041 / ADR-0042 の行とは別) | `charts/ctf-user/deploy-user.sh` の運用者入力のうち 4 値は、kubectl / helm の前に閉じた文法で検査し (exit 2 `invalid <name>: ...`)、`--set-string` で渡す: `--dns-suffix` (`DNS_SUFFIX_PATTERN` = RFC 1123 subdomain・小文字・≤ `DNS_SUFFIX_MAX_LEN` 253。253 は suffix 単体の上限で、host `<seat>.<suffix>` の長さは helm / apiserver が判定する)・`FALCO_CTF_REGISTRY` (`REGISTRY_PATTERN` = OCI `host[:port]/path` **かつ末尾の成分が `falco-ctf`**。`${REGISTRY}/challenge` が scoreboard ingest の filter (`internal/scoreboard/ingest/ingest.go` の `falco-ctf/challenge` の substring) を満たさないと採点イベントが黙って捨てられるため、fail-closed にする)・`FALCO_CTF_IMAGE_TAG` (`IMAGE_TAG_PATTERN` = OCI tag 1〜128)・`--api-server-cidr` (`API_SERVER_CIDR_PATTERN` = IPv4 `a.b.c.d/n`)。**値の出所は platform** (`--dns-suffix` / `--api-server-cidr` は運用者の引数と terraform output、registry / tag は platform#285 (open) が env file から導く予定。merge されなければこの記述を戻す)、**文法は app に 1 つ**で platform は持たない。`--dns-suffix` の定義・固定・platform が読む面・変更の規則は「DNS 名の文法 (ADR-0047)」行 (`DNS_SUFFIX_PATTERN` / `DNS_SUFFIX_MAX_LEN` は `dnsname.Pattern` / `dnsname.MaxLen` の写し)。残る 3 値は Go に定義が無く、shell literal が定義: case 表 3 本 `internal/catalog/testdata/{image-registry,image-tag,api-server-cidr}-cases.tsv` の header と literal の一致・全行・chart の default 値の受理を `internal/catalog/deploy_operator_inputs_test.go` が固定し、`scripts/check-deploy-user-ids.sh` (`make check-flags`・CI `flag-guard`) が表の全行と変異を `deploy-user.sh` の実呼び出しに通す (accept は helm の呼び出しに ` --set ` が `networkPolicy.egress.enabled=true` (script 自身が書く boolean) 以外に無いことも固定)。`--set-string` は型付け (`null` が key の削除になる等) を止めるだけで `,` の分割は止めない: 文法検査と `--set-string` は両方要る。**変更の規則** (`--dns-suffix` を除く 3 値): 文法を**狭める**変更は、platform の出所の値 (prod の ECR registry・release scan の tag・VPC CIDR) が accept 行にあることを確かめた上で **app 単独 PR でよい** (platform は文法を持たない)。値の**形式そのもの** (出所の形: registry の `falco-ctf` 末尾、tag の SHA 形式等) を変えるときだけ両リポ同時 PR。`--frame-ancestors` と `--app-host` は次の行 (ADR-0044。クロスリポ契約なので、狭めるときも両リポ同時 PR)。出所: app#510、#507 review-5x R1#1 |
| `deploy-user.sh --frame-ancestors` / `--app-host` の文法 (app#520、ADR-0044、**クロスリポ契約**: 値の出所は platform、文法は app に 1 つ) | `--app-host` = DNS 名の文法 (`dnsname.Pattern` + `dnsname.MaxLen`。定義・写し・固定・変更の規則は「DNS 名の文法 (ADR-0047)」行。scheme・port・path・userinfo なし)。`--frame-ancestors` = ちょうど 1 つの source で、`'none'` か `https://<app-host の文法>` (≤ 261。`'self'`・`*`・`*.`・scheme だけ・`http:`・port・path・複数・素の `none` は不可)。両方を渡し、`'none'` でなければ `--frame-ancestors` = `https://<app-host>` (不一致は exit 2。片方だけならその値の文法だけを検査する。platform の名簿の経路では、ADR-0046 (Proposed。**platform 側は未実装**: platform#292 (未 merge)) が Accepted になれば、local で `appHost` が空の場合を除き 2 値は常に両方渡る。platform#292 が merge されなければこの記述を戻す)。どれも kubectl / helm の前に exit 2 で止め、`--set-string` (`ttyd.frameAncestors` / `auth.appHost`) で渡す。**1 定義** = Go の `ttydproxy.FrameAncestorsPattern` (`^('none'|https://` + `dnsname.Body` + `)$` の合成。host 部分の権威は「DNS 名の文法 (ADR-0047)」行)。ttyd-proxy も起動時に同じ文法で拒否するので、chart を直接使う経路でも **frame-ancestors だけは**閉じる。app-host と一致の検査は `deploy-user.sh` だけで、scoreboard の `PORTAL_TTYD_SUFFIX` は起動時に `dnsname.Valid` で検査される (ADR-0047 D6、app#532)。`deploy-user.sh` の literal と `internal/ttydproxy/testdata/frame-ancestors-cases.tsv` の header がこれと一致することを `internal/ttydproxy/frame_ancestors_grammar_test.go` が固定する (host 部分は合成なので、構造上 `dnsname.Body` と一致する)。`scripts/check-deploy-user-ids.sh` が表の全行を実呼び出しに通す。chart の `FRAME_ANCESTORS` env は `quote` で描画する (`internal/apispec/ingressparity/frame_ancestors_render_test.go`)。**platform 側は未実装**: platform#290 (open issue。実装 PR は未 merge) で、APP_PIN の bump、V4 の test、版の gate を足す。版の gate は、名簿の前に 1 回 sibling app clone に `frame-ancestors-cases.tsv` があることを確かめ、無ければ local 以外を止める (ADR-0033 Decision 9 (b) の形)。そのあと deploy の pin が ADR-0044 の commit 以降になってから、旧 2 検査 (`deploy-event-workspaces.sh` の 2 つの正規表現) を消す。merge されなければこの記述を戻す。それまでは platform の旧検査が残るが、app の検査より広い側なので、受理集合は app が決める。**platform が読む面** = `internal/ttydproxy/testdata/frame-ancestors-cases.tsv` と `internal/catalog/testdata/dns-suffix-cases.tsv` の **1 行目** (`# pattern: ` + 正典 literal の regex。書式は seat の表の header と同じ)。app の Go / shell ソースの字面は契約の面にしない。順序: app → platform#290 (APP_PIN を app の squash SHA に) → 旧 2 検査の削除 (deploy の pin が上がってから。tag は CEO)。適用時は image tag と chart pin を同時に上げ、同時に戻す (ADR-0044 Consequences)。**変更の規則**: 狭めるのも広げるのも両リポ同時 PR。広げる (port・2 つ目の origin・http) には ADR が要る。**表の path の rename・移動、header の書式の変更も両リポ同時 PR** |
| 不可視文字の表の書き出しと参照 scanner (ADR-0045 / ADR-0051、app#511 F2 / app#542、**クロスリポ契約**: app が正典、platform / workspace は scanner を走らせるだけ) | app は `internal/sourcehygiene` の表 (`invisibleRanges` ∪ `bidiControls`) と、走査しない拡張子 (`binaryExt`) を `internal/sourcehygiene/testdata/` の 3 file に書き出す: `hidden-ranges.tsv` (header 3 行 = `# unicode: <Go の unicode.Version>` / `# skin-tone: U+1F3FB-U+1F3FF` / `# variation-selector: U+FE00-U+FE0F,U+E0100-U+E01EF`。行 = `U+LLLL<TAB>U+HHHH<TAB><rule><TAB><name>`。`<rule>` は Go の `ruleKind` の識別子 `always` / `vsAfterSymbol` / `zwjInEmoji` / `bomAtStart` / `loneCR` と、`bidiControls` の行を表す `bidi` の閉集合)、`hidden-cases.tsv` (`<name><TAB><input><TAB><expected>`。input は印字可能 ASCII で、それ以外は `{U+XXXX}` (4〜6 桁の大文字 hex) と不正バイトの `{xHH}` (80〜FF) で書き、placeholder を除いて `{` `}` が残る行は reader の誤り = FAIL。expected は `none` か `<line>:<col> U+XXXX` の `,` 区切りで、`Hidden` の結果)、`binary-ext.tsv` (`<.ext><TAB><reason><TAB><signature>`。signature は先頭 bytes の大文字 hex で、拡張子と signature の両方が合うときだけ走査しない、#537)。`internal/sourcehygiene/exported_table_test.go` が 3 file = Go の値 (双方向・順序・名前・rule)、header = `unicode.Version` と文脈規則の定数、cases の全行 = `Hidden` を固定する。sourcehygiene の非 test package は述語だけのまま (ADR-0043 Signpost 3)。参照 scanner `scripts/sourcehygiene-scan.py` (Python 標準ライブラリだけ。data は自分と同じ checkout の 3 file だけを読み (`--selftest` は `testdata/negatives/` も読む)、引数で受けない) は述語を `Hidden` と同じにし (共有 cases で機械が parity を見る)、walk と allowlist (file 集合・`binary-ext.tsv`・binary の置き場の閉集合・NUL・path・allowlist の閉集合と dead entry) は scanner の `--selftest` が固定する。walk・allowlist・reader の parity は、**共有の否定例にある例について**だけ、`internal/sourcehygiene/testdata/negatives/` (1 dir = 1 否定例。`expect.txt` + 入力 1 つ。Go の `TestSharedNegatives` と scanner の `--selftest` が同じ dir 群を同じに判定する、#537) が機械で見る。**両実装が持つ挙動の否定例は `testdata/negatives/` に置く** (Go の表に残すのは共有しないものと、Go の文言の確認だけ)。共有しない挙動 (ranges の reader、bidi の allowlist、git mode、symlink、binary だけの tree、`--also-untracked`) は各実装が別々に固定する (scanner は `--selftest`、Go は自分の test。allowlist は bidi の code point も書けるので意味自体が同じではない)。signature は誤命名への対策で偽造への対策ではない (先頭が signature に一致する text は、拡張子が表にあれば binary と判定される)。**binary の置き場は閉集合** (ADR-0051): binary と判定した file は、`--binary-paths <file>` の閉集合のうち自分の拡張子の行の prefix の下にあるときだけ走査しない。外にあれば problem (exit 1) で、text としても走査しない。**`--binary-paths` を渡さない走査は空の閉集合 (strict)** で、binary を 1 つでも持つ tree は FAIL になる (binary の無い tree は影響を受けない)。残る残余は閉集合の中の偽造だけ (共有否定例 `walk-binpaths-forged-woff2-inside-is-the-residual` が固定する)。app は自分の閉集合 `internal/sourcehygiene/testdata/binary-paths.tsv` (`.tgz` = `charts/*/charts/`、`.woff2` = `internal/scoreboard/view/vendor/fonts/`。`.pdf` の行は無い) を Go の gate と flag-guard の走査の両方に当て、Go の test が app の binary を file 単位で固定する (`appBinaryFiles` = `.woff2` の 5 file。tracked の `.tgz` = 0 件)。file の中身は出力しない。app の `flag-guard` が `--selftest` と app tree の走査で回す。**消費者が読む面** = bundle の配置 (`scripts/sourcehygiene-scan.py` と、ディレクトリ `internal/sourcehygiene/testdata/` の全体の repo 相対の path。`--selftest` は `testdata/negatives/` も読み、通常の走査 (`<dir>`) は `hidden-ranges.tsv` / `hidden-cases.tsv` / `binary-ext.tsv` の 3 file だけで足りる。**bundle を部分コピーする消費者を作らない**。file / dir の移動・rename は面の変更で、追加は許す。面の単位を file 3 本から `testdata/` 全体に変えたのは VP 承認 2026-10-27、review-5x 88)・scanner の CLI (`--selftest` / `<dir>` / `--allowlist <file>` / `--also-untracked <rel>` / `--binary-paths <file>`。最後は ADR-0051 で足した。渡さなければ空の閉集合)・終了コード (0 = 違反なし / 1 = 違反・読めない・0 件 / 2 = 使い方の誤り)・allowlist の書式 (`invisible-allowlist.txt` と同じ。bidi の code point も書ける)・**`--binary-paths` の file の書式** (消費者が書くので allowlist の書式と同じ扱いの面。行 = `<.ext><TAB><directory prefix>`。ext は `binary-ext.tsv` にある小文字の拡張子で、無い ext の行は FAIL。prefix は `/` で終わる segment の列で、segment は `[A-Za-z0-9._+@-]` の literal (`.` / `..` は不可) か単独の `*` (ちょうど 1 segment)。file は prefix の下に任意の深さで置ける (prefix と同じ深さの file は覆わない)。行は (ext, prefix) の昇順で重複なし。印字可能 ASCII・TAB・LF だけで、`# ` で始まる行と空行は comment。comment だけの file = 空の閉集合。名前を付けた file が無い・読めない・書式違いは FAIL)・出力の接頭辞。**判定に使うのは終了コードだけ**で、安定を約束する出力は finding 行の接頭辞 `<path>:<line>:<col> U+XXXX` と要約行の接頭辞 `OK sourcehygiene-scan:` / `FAIL` だけ (他の文言は保証しない。消費者の selftest は終了コードと接頭辞だけで判定する)。data file (`hidden-ranges.tsv` / `hidden-cases.tsv` / `binary-ext.tsv`) の書式は面にしない (app の `binary-paths.tsv` は app 自身の閉集合で、書式は上の面)。**消費者の状態** (ADR-0051 D5): **platform = 未実装** (platform#294 は open。実装 PR は未 merge。merge されなければこの記述を戻す)。予定は、`scripts/check-source-hygiene.sh` が CI `identity-selftest` の APP_PIN の sibling app clone の scanner を自リポの tree に当て、自リポの allowlist と自リポの閉集合 (`--binary-paths`。deck の PDF 2 本の dir に限る) を渡す (どちらも閉集合で、追加は security review。閉集合の file が無ければ FAIL。selftest は閉集合の外の signature 付き binary が exit 1 になることを観測する。#294 の受け入れ条件)。この契約の対象は面と、pin する消費者の platform。**workspace = 実装済み** (ws#90 = 62dbc6e、`scripts/claude/check-hidden-chars.sh`)。`--binary-paths` は未使用 (tracked の binary は 0 件なので strict の既定で緑)。自リポの閉集合と、`.claude/worktrees/*/` に置いた checkout (app の checkout は `.woff2` を持つ) の扱いは ws#92 (ws の follow-up issue)。配線は ADR-0045 D7 (VP の手元の衛生検査で、deploy の契約ではないので app を pin せず、使った app の SHA を出力する)。表・文脈規則・scanner を写さない。scanner が無い・data が読めない・0 件の走査は FAIL (SKIP にしない)。`unicodedata` の版が header と違えば WARN (終了コードは変えない)。**変更の規則**: 表の行・case 行の追加 (= 狭める) は app 単独 PR + security。行の削除・文脈規則の緩和は app 単独 PR + security + ADR。`binary-ext.tsv` の行の追加と、data の書式・rule の語彙の変更は app 単独 PR + security (scanner・Go の test・data を同じ PR で)。**`binary-ext.tsv` の行の削除と signature の変更**は、その ext を書いた消費者の `--binary-paths` の file を FAIL にする (ext の存在検査) ので、ADR を要し、消費者の対応を先にする (platform は APP_PIN をその SHA に上げる対の PR で自分の file を同時に直す。pin しない workspace は app の merge の前に直す)。**app の `binary-paths.tsv` の行の追加** (app の閉集合を広げる = 偽造の置き場を足す) は app 単独 PR + security で、Go の `appBinaryPaths` と同じ diff で変える。app に binary file を足すのは `appBinaryFiles` の行の追加で、app 単独 PR + security。**`--binary-paths` の書式**: 受理を広げる追加 (今ある file がすべて有効なまま) は app 単独 PR + security。狭める変更・既存の行の意味を変える変更 (`*` の深さ・prefix の照合の単位など) と、flag を渡さない走査の既定 (空の閉集合) を緩める変更は、新しい flag か、app と platform の同時 PR + ADR (workspace は app の merge と同じセッションで追随)。scanner と mutant harness (`scripts/sourcehygiene-scan.py` / `scripts/test-sourcehygiene-scan.sh`) のコードの変更も app 単独 PR + security。**消費者が読む面は追加だけ** (既存の意味を変えるなら新しい path。追加だけなので両リポ同時 PR は不要で、消費者 PR は後続)。意味を変えるときは app と platform の同時 PR (workspace の配線は ADR-0045 D7。pin しないので app の merge に追随する)。platform の APP_PIN の bump は対の PR。出所: app#511 F2 (#536)、#537 (#541)、app#542 (#554)、review-5x 83 / 88 / 93 |
| scoreboard の起動ログ (platform `scripts/verify.sh` [flags] が読む。**両リポ同時 PR**, app#487 / platform#266) | scoreboard が起動時に出す次の 3 種の log record は、platform の `scripts/verify.sh` の `[flags]` block が**生の slog JSONHandler の 1 行を部分文字列で**読む契約である。(1) `msg="flag overrides failed"` (level **ERROR**。flags file が使えず起動を拒否するとき、`os.Exit(1)` の直前に 1 回。verify.sh は JSON の key を見ず msg の文字列だけで grep し、あれば FAIL)。(2) `msg="stored user slug check"` の属性 `solved_violations` / `exfil_violations` (app#439 / #459)。(3) `msg="stored display name check"` の属性 `violations` (app#403 / #419)。(2)(3) は 1 起動に 1 record ずつで、**level が結果を表す**: **INFO = 0 件** (属性は整数 `0`)、**WARN = 違反あり** (件数は属性、operator 向けの `remedy` ・(3) の `seats` / `seats_truncated` は読み手が読まない補助)。どちらも件数だけで値は出さない。読み手は `"msg":"…"`、`"level":"INFO"`、`"solved_violations":0` のような **JSONHandler の直列化 (key の綴り・`:` の後に空白なし・数値は裸)** に依存するので、handler を TextHandler などに替える・属性を rename する・INFO の record に key を足し引きする変更は契約変更になる。record が無いことは「0 件」ではなく**未検証**で、読み手はそう扱う (`VERIFY_STORED`)。**読み手**: platform `scripts/verify.sh` の `[flags]` block、`docs/operations.md` §3.1、`docs/P13-RUNBOOK.md` §2。**機械で固定するもの**: `cmd/scoreboard/bootlog_contract_test.go` が msg・level・属性名と、logger の handler とその options (`slog.NewJSONHandler(os.Stdout, nil)`) を**定数を使わず文字列 literal で**固定する (定数経由の既存 test は rename に追従して緑のままなので、これが rename の唯一の赤)。**変更は msg・属性名・level の意味・直列化のいずれも両リポ同時 PR** (platform の reader と同時に直す)。順序: 消費側 (platform #266、済) が先行し、この記載は後追い。読み手が依存するのは msg / level / 属性名で、key の完全一致と ERROR level は app 側が追加で守っている。reader が 2 本以上に増える、または record の欠落で stand-up が 未検証 / FAIL になったら、起動時の gauge (名前は未決。契約表の metric family の形では書かない) へ移す (architect 合意)。 |
| `deploy-user.sh --display-name` の廃止 (ADR-0034 D10・D12 S1) | `--display-name` を渡すと理由を stderr に出して **exit 2** で止まる (kubectl / helm には触れない。deploy は表示名を書かない)。platform の `deploy-event-workspaces.sh --names-file` (内部で `--display-name` を渡す) も同時に廃止する (platform 側の変更)。**merge 順: platform の `--names-file` 廃止を先に merge し、その後に events の `app.ref` (pin) を進める。** platform は app を `versions.yaml` の ref で pin するので app を先に merge しても本番には届かないが、platform 未 merge のまま re-pin して `--names-file` を使うと全 user の deploy が exit 2 になる。契約変更は両 repo 同時 PR |
| Falco custom rule override (ADR-0008, **project 初の default ruleset override**) | `falco-ctf-platform/helmfile/releases/falco/values.yaml.gotmpl` の `customRules` block が正典。app 側は `challenges/custom-falco-rules.txt` (customRules として追加されたルール名の allowlist manifest。1行1ルール名) を持ち、`scripts/check-challenge-rules.sh` (必須 CI check `challenge-rules`) が「upstream `falcosecurity/rules` ∪ このマニフェスト」を既知集合として `challenges/*/falco-rule.yaml` の `expectedRules`/`forbiddenRules` を検証する。**ルール名は両リポで文字列完全一致させる手動規律** (自動整合機構は無い — `challenges/*/rule.yaml` の「デプロイ中の実ルールセットから再抽出する」既存運用と同種)。**デプロイ順序依存**: `requireExpectedRuleFire: true` を持つ evade challenge (現状 05・10) は、platform 側の対応する customRules が実クラスタで稼働していない限り永久に unsolvable になる (`internal/scoreboard/scoring` の `evaluateClean` が該当ゲートを無条件に評価するため、feature flag 等の緩和は無い)。**platform の customRules landing → app 側の `requireExpectedRuleFire: true` 有効化、の順を守ること** (逆順で本番投入すると mission が softlock する)。契約変更は両 repo 同時 PR + 相互リンク必須。**[ADR-0025](../../docs/adr/0025-evade-flag-placement-separation.md) (`customRules` 3 件目)**: mission03 (`03-stealth-read`)/mission10 (`10-final-exfil`) の evade flag を `/opt/nimbus/vault/{creds.recover,master.key}` へ retarget し、`Read sensitive file untrusted` へ **dir-prefix match** (`fd.name startswith "/opt/nimbus/vault/" and container.name != "plant"`) を append (`rules-nimbus-vault-sensitive-file.yaml`) — mission05 の exact-match append とは条件の形が異なる (1 エントリで 2 課題を同時カバーする設計、ADR-0025 §Context)。**デプロイ順序依存 (mission05 とは逆方向の失敗モード)**: mission05 は customRules 未 landing だと `requireExpectedRuleFire` で **softlock** (恒久 unsolvable) するのに対し、mission03/10 は逆に customRules 未 landing のまま app 側の新 plant-target (`/opt/nimbus/vault`) が先に有効化されると `cat /opt/nimbus/vault/...` が無検知になり **free-win** (evasion 技法なしで自明に solve) する。**platform → app の順を守ること**は同じだが、逆順で壊れる方向が softlock/free-win で真逆である点に注意。**[ADR-0032](../../docs/adr/0032-evade-attempt-epoch-and-capstone-positive-proof.md) S1/S2 (`Nimbus Vault Master Key Read`)**: mission10 (`10-final-exfil`) の capstone「読む段」に positive-proof rule を 1 本足し、app 側 `challenges/10-final-exfil/falco-rule.yaml` が `expectedRules: [Nimbus Vault Master Key Read]` + `requireExpectedRuleFire: true` で要求する (mission05 と同型)。rule 本体の condition は public の app に書かず platform 側の private 正典が持つ (ADR-0032 冒頭の公開境界と D9 (i)) — allowlist (`challenges/custom-falco-rules.txt`) には condition を表さない rule 名だけを載せ、`challenges/10-final-exfil/rule.yaml` (参加者表示用抜粋) にも proof rule は**載せない** (mission05 の表示用抜粋とは非対称。載せると condition の開示になるため。載せてよいかの基準は D9 (i) の 1 つ)。**デプロイ順序依存 (mission05 と同じ softlock 方向)**: platform の S1 customRule が実クラスタで稼働してから app 側の `requireExpectedRuleFire` を有効化する (platform → app、**同じ stand-up**。S2 を含まない app の回には platform の 4 件目を載せない = D9 (g))。逆順だと proof が永久に鳴らず mission が softlock する。**`rule_matching: first` の前提 (ADR-0032 D9 (k))**: customRules が新設する rule (05・10 の proof、13 の trigger) は upstream の rule より後に読み込まれるので、先に読み込まれる rule が想定解の event に一致すると鳴らない (05・10 は softlock、13 は solve できない)。この前提は upstream の ruleset の版ごとの性質で、実機の fire / no-fire はその stand-up の版についてだけ確かめる。**ctf-user chart の container 名も platform の customRules が参照する契約面 (ADR-0032 D9 (j))**: 名前で参照される container は **2 つ** — initContainer `plant` (05 の proof `Shell Redirected Private Key Read` と ADR-0025 append が除外する) と、参加者 shell の container `challenge` (10 の proof `Nimbus Vault Master Key Read` が許可する唯一の container。`TTYD_TARGET_CONTAINER=challenge` と同じ値) である。initContainer `missions-scope` は名前では参照されないが、3 つとも同じ challenge image を使うため ingest の image フィルタ (`falco-ctf/challenge` を含む repo) を通る — だから gate は image でなく container 名で絞る必要があり、10 の proof は `challenge` の allowlist になっている。`challenge` / `plant` の改名は platform と同時 PR (`challenge` の改名は 10 を softlock させ、`plant` の改名は 05 の proof と ADR-0025 append の除外を外して deploy 経路の発火 = I13b になりうる。flag-guard の名前を一緒に直すと app の CI は緑のまま壊れる) |
| Rate-limit client-IP ヘッダ (ADR-0023) | `internal/scoreboard/ratelimit.ClientIP` は `CF-Connecting-IP` (非空・valid IP) を最優先し、無ければ `X-Forwarded-For` leftmost、無ければ `RemoteAddr` にフォールバックする。`CF-Connecting-IP` は `falco-ctf-platform` の `cloudflareEnabled` な環境 (prod/vm-prod) で Cloudflare が上書き設定する値であり、ingress-nginx はこれを加工せず透過する (`forwarded-for-header` 設定は ingress-nginx 自身の `$remote_addr` 解決にのみ影響し、ヘッダの透過そのものには影響しない)。local (colima) は対象外。`POST /falco/events` は Cloudflare を経由しない内部呼び出しのため対象外。**`internal/collector` は Cloudflare を経由しない workspace 直叩きの forward proxy であるため、`CF-Connecting-IP` を含む参加者制御下のあらゆる client-IP 系ヘッダを無条件に strip する義務を負う** (`collector.go` の `Director` — 既存の `X-Forwarded-For`/`X-Real-IP` strip と同格) — この義務は将来 `ratelimit.ClientIP` が新しい信頼ヘッダを追加するたびに `collector.go` の `Director` も追随して strip 対象を拡張しなければならないことを意味する (対応漏れは ADR-0023 が是正した regression と同型の穴を再度開く)。観測: scoreboard の `ratelimit_client_ip_source_total{caller, source}` counter (`source` は `cf_connecting_ip`/`x_forwarded_for`/`remote_addr`、`caller` は route family で表示用 = 値の集合は契約にしない) が CF-Connecting-IP 不在時のフォールバック発生を可視化する。**scoreboard の起動直後から存在する** (組み立てた caller ごとに source 3 つを 0 で事前生成する。caller の値の集合は契約でない。collector は `ClientIPKeyed` を呼ばないのでこの family を出さない)。metric 名・label 名・事前生成を変える変更は両リポ同時。契約変更は両 repo 同時 PR |

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
本番値 (実 host・ECR registry・image tag・EXPECTED_EMAIL_DOMAIN・ADMIN_EMAILS・identity 表 = ロスターの Secret) は
**platform helmfile の prod 環境値**が供給する (`falco-ctf-platform/helmfile/environments/prod.yaml.gotmpl`
+ `releases/{scoreboard,auth-policy}/values*.gotmpl`)。chart に実値をコミットしない。

> kustomize `deploy/` は P2 で廃止。k8s マニフェストの正典は `charts/`。
