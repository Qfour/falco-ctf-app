# ADR-0021: scoreboard 単一起点 ingress の participant allow-list を機械検査する新規 Hard Invariant (I15)

- Status: **Accepted** (2026-08-29。architect 起案 → security-engineer advisory で
  D3 の HIGH (k8s Prefix pathType のトレーリングスラッシュ正規化との不一致 = false
  negative) + MED/LOW を差し戻し → architect 全件是正 → security-engineer 再確認で
  「穴なし・Accepted 化してよい」→ objection なしにつき VP 時限自動承認)
- Date / Deciders: 2026-08-29 / architect (起案)、security-engineer (advisory・条件充足)、
  VP (承認)。origin-guard/ingress 境界に触れるため security-engineer レビューを
  Accepted の条件とした (充足済み)
- **2026-08-29 追記 (Status のみ。Decision/Verification 本文は凍結・未編集— ADR-0005 と
  同じ規律)**: Issue #240 (review-5x R4, architect 本人による self-catch) で D2 の
  reverse 検査が Exact エントリの audience 混入 (「一致するが audience が違う」) を
  一切見ていない gap を発見。**ADR-0022 が D2 のこの部分のみを限定 supersede** し、
  V(I15)-6 (blocking) を追加する。本 ADR の O1/D1/D3/D4 および V(I15)-1/2/3/4/5 は
  無傷のまま有効。
- 関連: Issue #238 (本 ADR の発注元) / #95 (`POST /csp-report`, review-5x が着地前に検出) /
  #235 (`/vendor/cybercore.min.css` + `/static/tokens.css`, **本番で参加者 portal が
  無スタイル表示**のまま着地した実障害) / ADR-0005 (I14, mux↔spec parity。本 ADR はこれを
  supersede しない — 別レイヤの別不変条件を新設する)
- フェーズ: P## 非該当

## Context

### C1. 実測した defect class (2 回発生、うち 1 回は本番到達)

participant 向け mux route が **(a) `internal/apispec` の Route テーブルに正しく宣言され
(b) `docs/openapi-scoreboard.yaml` にも正しく記載されている** (= ADR-0005 の I14 は
green) のに、**(c) 本番 single-origin ingress の participant allow-list
(`charts/scoreboard/templates/ingress-journey.yaml`) にだけ登録され忘れる**、という
3 段目の欠落が 2 回起きた:

- **#95** (`POST /csp-report`): review-5x が着地前に指摘し、修正が同じ PR に入って
  ノーインシデントで着地 (`ingress-journey.yaml:78-106` の長大なコメントが経緯を記録)
- **#235** (`/vendor/cybercore.min.css` + `/static/tokens.css`): **修正前に本番へ着地し、
  参加者の portal が無スタイル表示のまま稼働した** (`ingress-journey.yaml:107-144`)

I14 (ADR-0005) の Verification は明示的に「mux 登録 ↔ spec の operation 集合」の 2 者間
一致だけを検査対象と定義しており (`0005-openapi-canon-and-parity-gate.md` V1-V6)、
ingress 層は範囲外 — 実測 (`internal/apispec/*_test.go` を精読) でも ingress を読む
コードは存在しない。**I14 は仕様どおり green のまま、この defect class を通す。**

### C2. なぜ I14 の拡張ではなく新規不変条件か

ADR-0005 は「Decision / Verification 節は以後編集しない — 変更は後継 ADR で行う」と
自ら定めている (`0005-openapi-canon-and-parity-gate.md:7-8`)。ingress allow-list は
mux でも spec でもない**第 3 の artifact**であり、I14 の主張文
(「mux に登録されたルート集合 = spec の operation 集合」) はそのままでは ingress を
指せない。I14 の文言を書き換えて範囲を広げる (「I14 を拡張」と呼ぶ) のは、上記の
凍結規律を実質的に破ることになるので採らない。**新しい主張 (I15) を新設し、I14 は
無傷のまま残す。**

### C3. スコープの実測 (対象を過不足なく決めるため)

3 バイナリのうち、この defect class が**構造的に起こり得るのは scoreboard の
`ingress-journey.yaml` だけ**:

| ingress オブジェクト | 方式 | この defect class が起きるか |
|---|---|---|
| `charts/scoreboard/templates/ingress-journey.yaml` | **allow-list** (Exact/Prefix を列挙、他は default backend で 404) | **起きる** (#95/#235 の実測) |
| `charts/scoreboard/templates/ingress.yaml` (admin host) | **`path: / pathType: Prefix` の catch-all** (`ingress.yaml:56-57`) | **起きない** — allow-list が無いので「登録し忘れる」余地が構造的に無い。admin 側の懸念は逆方向 (過剰露出) であり、それは I8 (`/check-admin`) と server-side `isAdmin` ゲートが担う別の不変条件 |
| collector | **Ingress オブジェクト自体が存在しない** (`charts/collector/templates/` に ingress template 無し。workspace からは NetworkPolicy 経由のみ到達) | 対象外 (allow-list が無い) |
| auth-policy | 同上 (`/check` は ingress の `auth-url` サブリクエストとして呼ばれるのみ、path 経由で晒されない) | 対象外 |

**よって I15 は「scoreboard の `AudienceParticipant` Route 集合 ⊆
`ingress-journey.yaml` の participant allow-list」に限定してよい。** 他サービス・
他 Ingress を含める理由が無い (含めると除外リストの温床になる — ADR-0005 Decision 1 と
同じ論点)。

### C4. helm レンダリングが必須である理由 (文字列 grep では足りない)

`ingress-journey.yaml` の `paths:` ブロックは現状すべて static literal だが、これは
**現状の事実であって保証ではない**。ADR-0005 V2 が `mux.HandleFunc("GET "+path, ...)`
という文字列連結で literal-grep 抽出が破れた実例を残しているのと同型のリスクが
ここにもある (将来 `{{ range .Values.ingress.extraJourneyPaths }}` のような
values 駆動の path list が入れば、静的 grep は黙って追従できなくなる)。
**`helm template` を実際に実行してレンダリング結果を見る**のが唯一正しい抽出方法。

`ingress.journeyHost` の default は空文字 (`charts/scoreboard/values.yaml:166`) であり、
`ingress-journey.yaml:1` の `{{- if and .Values.ingress.enabled .Values.ingress.journeyHost }}`
は空文字を falsy として扱うため、**`--set ingress.journeyHost=<non-empty>` を明示しない
限り `helm template` の出力は空になる**。これは V8 スタイルの「抽出の非空 assert」を
持たない検査だと**永久に緑になる** (paths 0 件 = 「未カバーなし」に誤読される) —
この ADR の Verification で明示的に釘を刺す。

## Options

### O1 (推奨). 新規 Hard Invariant I15 を新設し、既存の required `test` に相乗りさせる

- **変更点**: (a) `internal/apispec` の姉妹に test-only 専用パッケージ
  `internal/apispec/ingressparity` を新設 (`specparity` と同じ「production 非import」
  規律を `dependency_boundary_test.go` に 1 行追加して機械強制)。yaml.v3 で
  `helm template` の出力をパースし、`scoreboard.Handler.Routes()`
  (`internal/scoreboard/server.go:252`。api/view/ingest を横断済み) から
  `Audience == AudienceParticipant` を抽出して双方向比較する。
  (b) `Dockerfile.test` に `RUN go install helm.sh/helm/v3/cmd/helm@v<pinned>` を 1 行足し、
  helm バイナリをテストコンテナに同梱する。これは本リポ既存の「CI ツールは
  `go install <module>@<version>` で pin する」慣行
  (govulncheck/oapi-codegen/actionlint、`.claude/rules/falco-ctf-app-conventions.md`
  「G5-2 検査 job の方針」) の延長で、新しい GitHub Action も curl 経由のバイナリ取得も
  増やさない。(c) 新テストは `make test` = 既存の required check `test` にそのまま入る。
- **コスト**: `Dockerfile.test` のビルド時間が伸びる (helm を `go install` でソースから
  ビルドするため、PR ごとに数十秒〜1 分程度増える見込み — 実測して Signpost 3 で監視)。
  **既存の required check 名を 1 つも増やさない** — `scripts/change-mgmt/setup-rulesets.sh`
  (workspace-local) の `CHECKS` 配列変更が不要 (release-engineer 作業ゼロ)。
- **リスクと可逆性**: 「required `test` job が Go 標準ライブラリだけで完結する」という
  これまでの前提を初めて破る (govulncheck 等は全て **advisory** job だった — G5-2 が
  明示的に「advisory と required は別ポリシー」としていた境界を、本 ADR で意図的に越える)。
  越える理由は #235 の実害 (本番到達) — advisory の遵守率が実質ゼロという組織診断の結論
  (ADR-0005 C3) を踏まえ、この defect class は required 以外の選択肢を採らない。
  可逆性: `Dockerfile.test` の 1 行 revert で完全に戻せる。
- **効き始める閾値**: 1 本目の新規 participant route から (I14 と同型)。

### O2. software-engineer 提案 (b): chart-lint job に `actions/setup-go` を追加し、helm 既設のそちら側で完結させる

- **変更点**: `chart-lint` job (既に `azure/setup-helm@v5` を持つ) に
  `actions/setup-go@vN` を足し、`go test -run TestIngressJourneyCoversParticipant ./internal/apispec/ingressparity/...`
  のような**限定実行**を chart-lint の 1 ステップとして追加する。
- **コスト**: **新しい GitHub Action 依存が 1 つ増える** (`actions/setup-go` は
  `.claude/rules/falco-ctf-app-conventions.md` の例外表に無い — GitHub 公式なので
  例外表への追記自体は妥当だが、「新規サードパーティ action は増やさない」という
  G5-2 の明示方針とは逆行する)。**required check 名が割れる**: この検査が `test` とは
  別の `chart-lint` job の 1 ステップに住むため、`chart-lint` が fail した場合の原因が
  「chart 構文」なのか「ingress parity」なのか PR 上で見分けにくくなる。**開発者体験**:
  `make test` (パターン A の日常フロー) を回しても検出できず、`make lint`
  (パターン B のフロー) 側でしか光らない — Go source の変更 (`internal/apispec`) が
  chart 側の CI でしか検出されないというレイヤの逆転が起きる。
- **リスクと可逆性**: 可逆性は高い (job 定義の削除で戻る) が、「Go の変更を検出する検査は
  Go の required check に置く」という ADR-0005 の設計原則 (「走る場所はすべて go test」)
  から外れる先例を作る。
- **効き始める閾値**: O1 と同じ。

### O3. 専用の新規 required job (`Dockerfile.chart-test` を新設し、O1/O2 いずれの既存 job にも同居させない)

- **変更点**: `test` とも `chart-lint` とも別の 3 本目の Dockerfile (`Dockerfile.test`/
  `Dockerfile.tidy`/`Dockerfile.gen` と並ぶ 4 本目) を新設し、go + helm 両方を持つ
  専用コンテナで実行する新規 required check を追加する。
- **コスト**: 最も高い。**新しい required check 名が増える**ため
  `scripts/change-mgmt/setup-rulesets.sh` の変更が必須 (release-engineer 作業発生、
  ADR-0005 が V7 を required 化できずに止まっている実例が示すとおりこの一手間は
  現に detach しやすい)。CI job 数も増える。
- **リスクと可逆性**: 高い可逆性 (job まるごと削除で戻る) だが、コストに見合う追加の
  分離価値が無い — O1 で `Dockerfile.test` に 1 行足すだけで同じ検査対象・同じ
  fail-closed 性質が手に入るのに、job を割る理由が「Dockerfile.test を汚したくない」
  という美観以外に無い。
- **効き始める閾値**: `Dockerfile.test` のビルド時間が実際に問題化したとき
  (Signpost 3 が発火したら O3 へ切替を検討)。

## Decision

**O1 を採る。** 理由: (1) `test` は唯一 100% 遵守が実測されている required check であり
(advisory の遵守率ゼロは ADR-0005 C3 の実測結論)、この defect class は 2 回中 1 回が
本番到達という実害を持つので non-required の選択肢を最初から排除する。(2) O1 は
既存 required check 名を増やさないため release-engineer 側の ruleset 変更が不要
(ADR-0005 の V7 が「昇格判断待ち」のまま止まっている先例を繰り返さない)。(3) helm を
`go install <module>@<version>` で入れる手段は本リポに既に定着した慣行の直接延長であり、
新しい GitHub Action も新しいバイナリ取得経路も増やさない。

**Decision 詳細:**

### D1. 新 Hard Invariant I15 (提案文)

> **I15 (提案)**: scoreboard の `AudienceParticipant` な mux Route (`scoreboard.Handler.Routes()`
> が返す集合のうち `Audience == AudienceParticipant`) は、**すべて**
> `charts/scoreboard/templates/ingress-journey.yaml` がレンダリングする participant
> allow-list に含まれる。逆に、同 allow-list の各 Prefix エントリが到達させる mux Route
> (audience 不問) は、**すべて** `Audience == AudienceParticipant` である
> (admin/operator/internal route を allow-list に紛れ込ませない)。例外・除外リストを持たない。

I14 と同じ「例外を持たない」規律を踏襲するが、**I14 とは別の主張・別の Verification**
であり、I14 の文言・番号は変更しない。

### D2. 検査方向は双方向 (issue の「一方向で足りる」提案を採らない)

issue の設計骨子は forward 方向 (participant ⊆ ingress) のみを提案しているが、
**reverse 方向にも実害がある**ため双方向にする:

- **Forward (blocking)**: #95/#235 が実際に起きた欠落方向。参加者が使う機能が
  本番で壊れる (可用性の事故)。
- **Reverse — Prefix エントリのみ、audience 混入検査 (blocking)**: `ingress-journey.yaml`
  の Prefix エントリ (`/api/users/`, `/api/challenges/`) が到達させる mux Route
  **すべて**が `Audience == AudienceParticipant` であることを assert する。これは
  ADR-0005 Decision 4 が origin-guard について既に確立した「両方向に事故がある = 契約」と
  **同型の非対称**: 将来誰かが `/api/users/admin-summary` のような operator 向け route を
  この prefix 配下に足せば、single-origin ingress の allow-list が admin/operator 面を
  意図せず参加者に晒す。ingress.yaml 自身のコメント
  (`ingress.yaml:17-26`: 「journey Ingress の allow-list が admin path を絶対に晒さない」)
  が既に述べている不変条件を、これまで検査していなかっただけ。
  **⚠ この reverse 検査は defense-in-depth であり、認可境界の主防御ではない
  (security-engineer advisory, 2026-08-29 MED)。** 実際の認可境界はサーバサイドの
  `isAdmin()` / `selfOrAdmin()` / `selfOrAdminWrite` (`internal/scoreboard/api/api.go`) で
  あり、そのランタイム enforcement は `internal/scoreboard/authz_test.go` の
  `TestAuthz_AllDeclaredGatesEnforced` (`authzCheck`、I14/ADR-0005 の範囲) と
  `internal/scoreboard/origin_guard_test.go` の
  `TestOriginGuard_AllProtectedRoutesEnforced` が既に独立して検証している。I15 の
  reverse 検査が見るのは「single-origin ingress の allow-list が意図せず広がって
  いないか」という**アーキテクチャ drift の早期検出**であって、**「I15 が green だから
  `isAdmin()`/`selfOrAdmin()` のサーバサイドチェックを省略してよい」と読んではならない**
  — ingress は可用性/UX レイヤであり、認可はサーバサイドで独立に再検証される設計のまま
  変わらない (`ingress-journey.yaml:54` 自身のコメント「Server-side gates still apply on
  top of this」がこの前提を既に明記している)。
- **Reverse — Exact エントリの死んだ登録 (advisory)**: Exact path が現存する mux Route と
  一致しない場合 (rename/削除後の残骸)。これはハイジーン (drift) であって
  セキュリティ事故ではないため blocking にしない — blocking にすると
  「ingress を先に消す/renameする PR」と「mux を消す/rename する PR」の着地順序次第で
  無関係な PR が赤くなり、defect class と無関係な摩擦を生む。

### D3. Pattern ↔ path のマッチング規則 (issue の点 2b への回答。**2026-08-29 security-engineer advisory 反映、HIGH 修正**)

`{param}` は Go 1.22+ mux 構文上**必ず 1 セグメント全体を占める**ため、param を持つ
Pattern の最初の `{` の直前は必ず `/` で終わる。これを **staticPrefix** と呼ぶ
(param が無ければ Pattern 全体。この場合 staticPrefix は Pattern そのものであり、
末尾 `/` が付くとは限らない)。

**⚠ 初版の Prefix 判定規則は k8s `pathType: Prefix` の実挙動と不一致だった
(security-engineer advisory, 2026-08-29 HIGH)。** k8s の Prefix マッチは
**宣言側 `path` の末尾 `/` を無視する** (公式挙動: 宣言 `path: /aaa/bbb/` は
リクエスト `/aaa/bbb` にもマッチする — 末尾 `/` の有無は宣言側では意味を持たない)。
初版は「`path` の末尾に `/` を足してから `staticPrefix` と文字列 prefix 比較する」
規則だったため、**staticPrefix 側に末尾 `/` が無い bare exact route (param 無しで
`Pattern == "/api/users"` のような literal route) を、末尾 `/` 付き Prefix エントリ
(`path: /api/users/`) が実際にはカバーしているのに、検査は非被覆と誤判定していた**
(staticPrefix `/api/users` (11 文字) が正規化後の ingress path `/api/users/`
(12 文字) より短いため、文字列 prefix 判定が成立しない)。

forward 方向ではこの誤判定は安全側 (無関係な participant route が誤って赤くなるだけ)
だが、**reverse 方向 (V(I15)-2, admin/operator route の allow-list 混入検知) では
致命的な false negative になる**: 将来 `GET /api/users` (bare, param 無し,
`Audience: Operator`) のような route が登録された場合、実際には `path: /api/users/`
の Prefix エントリ経由で single-origin ingress から到達可能 (k8s の trailing-slash
無視挙動による) なのに、初版の規則は「非被覆 (=到達しない)」と誤判定し reverse 検査を
発火させない — **これは I15 が防ぎたい defect class そのもの (admin route が
single-origin ingress 経由で参加者に到達可能なのに検知されない) を素通りさせる**。
V(I15)-2 の対象エントリは現状 `/api/users/` `/api/challenges/` の 2 本のみで、
bare exact な非 participant route も今日時点では存在しないため**現時点で実害は無い**
が、この false negative を持つ規則のまま実装 PR に発注するのは fail-open な仕様を
そのまま landing させることになるため、ここで修正する。

**修正後の規則 (以下を正典とし、初版の記述は破棄する):**

- `normalize(path)` := `path` の末尾 `/` を 1 つ除去した文字列 (無ければそのまま)。
- **Exact エントリ**: `path` が `Pattern` に literal 一致し、かつ Pattern が
  param を 1 つも持たない場合のみ被覆と判定する (変更なし)。Exact は 1 つの具体 URL
  しか通さないため、任意の param 値に対する到達性を証明できない — 1 つの param 値だけ
  通ることを「カバー」と呼ぶのは過大な主張になる。**k8s の Exact は Prefix と異なり
  末尾 `/` を正規化しない**ため、実チャートの Exact エントリ (いずれも末尾 `/` を
  持たない) はこの非対称の影響を受けない。
- **Prefix エントリ**: `P2 := normalize(path) + "/"` (path の末尾 `/` を必ず 1 個に
  正規化した形) を基準にする。
  - **param を持たない Pattern**: `Pattern == normalize(path) || strings.HasPrefix(Pattern, P2)`
    なら被覆 (bare route が ingress path 自身、またはその配下の literal サブパスに
    ある場合 — 修正前は判定できなかったケース)。
  - **param を持つ Pattern**: `staticPrefix == P2 || strings.HasPrefix(staticPrefix, P2)`
    なら被覆 (staticPrefix は常に `/` 終端なので `P2` と同じ正規化形で比較できる —
    修正前の判定と実質同値、こちらは元々正しかった)。
  - **言い換えれば「Pattern が生成しうる全ての具象パス R について
    `R == normalize(path) || R.startswith(P2)` が成り立つか」を判定する** — これが
    k8s 公式ドキュメントの Prefix マッチ例 (末尾 `/` 有無の両方) と一致することを、
    実装時に両方のケースを固定した table test で示す。
- **実装は `staticPrefix`/`covers()` を計算するテスト用ヘルパ 1 関数に閉じ、
  mutation test はこのヘルパに直接、合成した (route, ingress-paths) 入力を渡して
  赤化を確認する形にする** — 実チャートファイルを一時的に書き換える形の mutation は
  壊れやすい (D4 参照)。

### D4. mutation test は「合成入力」で行う (実チャートの一時改変はしない)

抽出ロジック (`helm template` → yaml.v3 パース) と比較ロジック (staticPrefix 計算 →
被覆判定) を関数境界で分離し、比較ロジック側の関数に synthetic な
`([]apispec.Route, []ingressEntry)` を直接渡して mutation test を書く
(1 route を落とす / 1 entry を落とす / Prefix を Exact に変える、の 3 ケース最低限)。
抽出ロジック側 (`helm template` の実行) は「非空である」ことだけを実チャートに対して
assert する (C4 の空文字 journeyHost の罠を閉じる)。

## Consequences

### 諦めたもの

- **required `test` job が Go 標準ライブラリだけで完結する、という前提が崩れる。**
  `Dockerfile.test` に外部ツール (helm) の `go install` が初めて入る。advisory job
  (govulncheck 等) では既に前例があるが、required job では初。
- **CI 時間が伸びる** (helm を `go install` でソースからビルドする分)。
  Signpost 3 で監視し、閾値超過なら O3 (checksum-pinned バイナリ配布) へ切替える。
- **`internal/apispec` の周辺にもう 1 つ test-only サブパッケージ
  (`internal/apispec/ingressparity`) が増える** — `specparity` と同じ
  production-import 禁止規律を machine で強制する追加コストを払う
  (`dependency_boundary_test.go` に 1 assert 追加)。

### 新たに守る不変条件 (提案 = I15。今は conventions の表に書かない — 実装 PR と同じ PR で追記する、ADR-0005 と同じ規律)

D1 の文言のとおり。**昇格の条件**: 下記 Verification が landing し、その実装 PR と
同じ PR で `.claude/rules/falco-ctf-app-conventions.md` の Hard Invariants 表に I15 を
追記する。

### runbook / 他ロールへの影響

- **software-engineer**: 本 ADR が確定仕様。実装は Verification 節に従う。
- **release-engineer**: **作業ゼロ** (O1 は既存 required check 名 `test` に相乗りするため
  branch protection / `setup-rulesets.sh` の変更が不要) — これが O1 を選んだ理由の一部。
- **security-engineer**: D2 の reverse 方向 (admin/operator route の allow-list 混入検知)
  はセキュリティ境界に隣接する新しい blocking assert なので、実装 PR のレビューを
  必ず通すこと (Accepted への条件、下記)。
- **VP**: Accepted への昇格は、本 ADR に対する security-engineer の advisory コメント
  (D2 reverse 方向の妥当性) を得てから行うこと。1 往復以内に objection が無ければ
  時限自動承認可 (ORGANIZATION.md §7 の既定運用)。

## Signposts (この決定を覆す観測可能な信号)

1. **参加者向け mux route が `{name...}` 形式のワイルドカードセグメントを使い始めたら**
   — D3 の「param は必ず 1 セグメント全体」という staticPrefix 前提が崩れるので、
   マッチング規則を再設計する。
2. **ingress-journey.yaml 以外の Ingress が参加者向け allow-list 方式を採用したら**
   (今日 collector/auth-policy には Ingress オブジェクト自体が無い) — C3 のスコープを
   広げる。現状ゼロ本なので広げない。
3. **`Dockerfile.test` のビルド時間が O1 導入前後で有意に (目安: 中央値 +60s 超) 伸びたら**
   — O3 (checksum-pinned バイナリ) へ切替える。
4. **本 ADR 実装後に同型の defect が 1 回でも本番へ到達したら** — D3 のマッチング規則
   自体に穴があるので、規則を疑う (不変条件そのものの棄却ではなく規則の精密化)。

## Verification (= software-engineer への発注仕様。全て fail-closed)

> **走る場所**: `internal/apispec/ingressparity` (新設、test-only。`specparity` と同じ
> `dependency_boundary_test.go` の production-import 禁止規律を追加で受ける) を
> import する `internal/scoreboard/*_test.go` の Go テストとして `make test` に載る。
> **`Dockerfile.test` に `RUN go install helm.sh/helm/v3/cmd/helm@v<pinned>` を追加**
> (バージョンは実装時点の最新安定版を pin。`golang:1.26-alpine` builder 内で完結、
> 新規 apk パッケージ・新規 curl ダウンロードは追加しない)。

**V(I15)-1. Forward 被覆 (blocking)**
`scoreboard.Handler.Routes()` (`internal/scoreboard/server.go:252`) の
`Audience == AudienceParticipant` な Route **すべて**が、
`helm template charts/scoreboard --show-only templates/ingress-journey.yaml
--set ingress.enabled=true --set ingress.journeyHost=<non-empty>` の出力の
`spec.rules[].http.paths[]` エントリのいずれかに D3 の規則で被覆されること。
未被覆の route 名を全件 fail メッセージに含める (最初の 1 件で止めない)。

**V(I15)-2. Reverse audience 混入検査 (blocking)**
`ingress-journey.yaml` の各 **Prefix** エントリについて、その prefix が到達させうる
scoreboard mux Route (audience 不問、全パッケージ合算) が**すべて**
`Audience == AudienceParticipant` であること。1 件でも他 audience が混入していれば fail。

**V(I15)-3. Reverse 死んだ Exact エントリ (advisory、非 blocking)**
`ingress-journey.yaml` の各 **Exact** エントリについて、literal 一致する mux Route が
存在しない場合に warning ログを出す (テスト自体は fail させない — `t.Log`、
`t.Error`/`t.Fatal` は使わない)。

**V(I15)-4. 抽出の非空 assert (blocking)**
`helm template` の出力 (`paths[]`) が空、または `scoreboard.Handler.Routes()` の
`AudienceParticipant` 抽出が空になった場合は**即 fail** (C4 の `journeyHost` 空文字の罠を
閉じる。既定値のまま `--set` を忘れると本検査自体が永久に緑になる、という
ADR-0005 と同じ轍を踏まないための必須ガード)。

**V(I15)-5. mutation test (blocking / PR 提出物、D4 の合成入力方式)**
比較ロジック本体を `CoverageDiff(routes []apispec.Route, paths []IngressEntry) (uncovered, foreign []string)`
のような純粋関数に切り出し、以下をテーブル駆動テストとして実出力付きで示す:
1. 実チャートの現況スナップショットで `uncovered`/`foreign` が空 (green baseline)
2. participant route を 1 本落とした合成入力で `uncovered` に該当 route 名が現れる (V(I15)-1 の赤化)
3. Prefix エントリの届く範囲に operator route を 1 本混ぜた合成入力で `foreign` に現れる (V(I15)-2 の赤化)
4. Prefix エントリを Exact に変えた合成入力で、param を持つ route が非被覆に落ちる
   (D3 の Exact/Prefix 非対称の赤化)
5. **bare exact route の境界ケース (D3 の HIGH 修正の regression guard)**: param を
   持たない合成 route (例: `GET /api/users`) を、末尾 `/` 付き Prefix エントリ
   (`path: /api/users/`) に対して被覆判定させ、**修正後の規則では被覆と判定され、
   初版の (バグを再現した) 規則を使えば非被覆と誤判定される**ことを両方 assert する —
   D3 の修正が実際に効いていること、および将来のリグレッションを固定する。

**この検査が見ないもの**

- ingress-nginx の実際の path マッチング挙動そのもの (kubectl 実機での到達性検証は
  対象外 — 本検査は chart のレンダリング結果に対する静的検査)
- Method ごとの区別 (ingress-nginx は path のみでルーティングし method は見ないため、
  本検査も Method 不問で Pattern のみを比較する — これは ingress-nginx の実仕様に
  合わせた意図的な設計であり、見落としではない)
- admin `ingress.yaml` (catch-all Prefix のため対象外、C3 参照)
- collector / auth-policy (Ingress オブジェクト自体が無いため対象外、C3 参照)
- **I8 の self-scope 逸脱** (`{user}` param と呼び出し元 identity のバインディング、
  `selfOrAdmin`/`selfOrAdminWrite` ゲート実装そのもののバグ) は対象外
  (security-engineer advisory, 2026-08-29 LOW)。I15 は ingress allow-list という
  **別レイヤ**の被覆/混入だけを見る。ランタイム enforcement は
  `internal/scoreboard/authz_test.go` の `authzCheck`
  (`TestAuthz_AllDeclaredGatesEnforced`) と
  `internal/scoreboard/origin_guard_test.go` の
  `TestOriginGuard_AllProtectedRoutesEnforced` が担う (ADR-0005 / I14 の範囲)。

## Advice (受けた助言と出所)

- **VP (2026-08-29、本タスクの委任文)**: Issue #238 で 4 点 (ADR 要否 / 検査設計妥当性 /
  CI 配線 / スコープ) を委任。「実装は software-engineer に発注する」前提で
  確定仕様を求められた。→ 全節に反映。
- **software-engineer (Issue #238 起票文, 2026-08-29)**: forward 一方向で足りるという
  提案、CI 配線 2 択 (Dockerfile.test への helm pin 追加 / chart-lint への setup-go 追加)、
  mutation test 必須という要求。→ O1/O2 の骨格として採用したが、**一方向で足りるという
  1 点は採らなかった** (D2 で reverse を blocking として追加) — 理由は ADR-0005
  Decision 4 が origin-guard について既に確立した「両方向に事故がある」という
  同型パターンがここにも当てはまると判断したため。CI 配線は**どちらも採らず** O1
  (Dockerfile.test への `go install helm` pin) を新たに導出した — 理由は
  release-engineer 側の ruleset 変更コストがゼロになる点が O2 (chart-lint + setup-go)
  に対して decisive だったため。
- **security-engineer (VP 経由の差し戻し, 2026-08-29)**: 3 点の advisory。
  **[HIGH] D3 の Prefix 判定規則が k8s `pathType: Prefix` の実挙動 (宣言側末尾 `/` を
  無視する) と不一致で、bare exact route に対する reverse 検査 (V(I15)-2) が
  false negative になる**、**[MED] D2 の reverse 方向の説明がサーバサイド認可の
  主防御を代替するかのように読める**、**[LOW] Verification の「見ないもの」節に
  I8 self-scope 逸脱の対象外を明記すべき**。→ D3 を修正 (正規化規則の導出・
  V(I15)-5 に境界ケースを追加)、D2 に defense-in-depth の明記を追加、
  「見ないもの」に I8 の bullet を追加。**HIGH は Verification の正典精度に
  直結するため、そのまま実装 PR に発注していれば I15 自身が防ぎたい defect class を
  reverse 方向で再生産するところだった** — 非拘束の助言ではなく実質的な修正必須事項
  として扱った。この修正版を再度 security-engineer が確認し、objection が無ければ
  VP が Accepted へ昇格させる。
