# ADR-0031: ブラウザでの確認を二層にする — 開発時は Claude が専用ブラウザで確かめて証跡を残し、CI は Go のテストが実バイナリと実 Chromium を動かす E2E (`make e2e`) で固定する

- Status: **Proposed** (Accepted 化の期限 = P28-1 の着手前: workspace `REFACTORING.md:1902`。ハーネスの実装は受け入れ判定まで。時限自動承認の対象: workspace `ORGANIZATION.md:472`)
- Date / Deciders: 2026-10-06 / CEO (ADR-WS-0009 の H「検証できないものは出荷しない」を承認。CI は Playwright 相当を `make test` の層に) + VP (発注) + architect (起草・同意権) /
  独立レビュー: qa-engineer (ハーネスのオーナー)・security-engineer (どちらも未実施)
- 関連: ADR-0027 V6・V7 (`0027:152-154`)、ADR-0032 D8・⑩ (`0032:111-113,239`)、app#316 / #317 (P28-0b、draft)、workspace `REFACTORING.md` P28 (受け入れ条件 2・4・6・7 = `:1619-1629`、
  `:1657,1801`)、workspace `DEV-METHOD-REVIEW.md` H (`:22,49,128-130`) と CEO 判断 8 (`:171`)、workspace `GITHUB-OPS.md` G5 (`:242-254`)
- 行番号は c5e0761。`0027:N` などは `docs/adr/` の各 ADR の行番号、`pane-story` は `internal/scoreboard/view/templates/portal/pane-story.tmpl`。Claude Code の docs は 2026-10-06 に取得した
  `https://code.claude.com/docs/en/<page>` を「docs: <page>」と書く。docs に書かれていないことは「未確認」と書く

## Context

- **C1 確認の欠落は起きている。** portal の変更が画面を見ずに merge され (`DEV-METHOD-REVIEW.md:49,130`)、TDZ の欠陥はレビューで JS を jsc で動かして初めて見つかった (`:130`)。
  ADR-0027 V6 / V7・ADR-0032 ⑩・P28 条件 2・4・6・7 は「ハーネスができるまで qa の手動検証」として本 ADR を前方参照している (`0027:154`、`0032:239`、`REFACTORING.md:1657`)。
- **C2 現状の手段。** CI に JS の実行系が無い (`REFACTORING.md:1801`)。#316 の `make check-portal-render` は macOS の jsc で描画関数を評価する任意の target で、`make test` にも CI にも入らず、
  レイアウト・クリック・ポーリングを見ない (#316 の `scripts/check-portal-render.sh:15-18`)。`make test` は `Dockerfile.test` の中の `go vet` と `go test` (`Dockerfile.test:57-58`)。
  CI の `test / go-test` は main で 2 分 52 秒 (2026-10-06、run 37426304714)。
- **C3 素のブラウザでは portal が開かない。** identity は `X-Auth-Request-Email` からだけ導かれ、`?user=` は無い (`internal/scoreboard/api/api.go:370-386`)。ヘッダが無いと Story は
  ポーリングを始めない (`pane-story:55,76-84`)。`make dev` の compose は scoreboard を素で出し (`docker-compose.yml:10-27`)、mock-oauth2 は auth-policy の subrequest に固定ヘッダを返すだけで、
  cookie も iframe も持たない (`scripts/mock-oauth2.conf:6-9`)。
- **C4 ブラウザでだけ壊れる面。** 2 秒ポーリング (`pane-story:84`)、`?mission=` による閲覧 (`:115`)、ネイティブ `confirm()` を挟むヒント開封と reset (`:782,819`)、nonce つき CSP の下での実行、
  ページ自身が出す要求の集合 (ADR-0032 D8 が「クリックからだけ」を要求する: `0032:111-113`。テンプレートの静的検査は `0032:232`)。
- **C5 Claude 側の手段 (docs)。** Claude in Chrome は CLI から使え (docs: chrome)、MCP の tool として subagent に継承され、background の subagent も MCP の tool はすべて持つ
  (docs: sub-agents「Available tools」)。拡張はブラウザのログイン状態を共有し、auto mode では classifier が承認した呼び出しについて拡張側のサイト確認が省かれる (docs: chrome
  「Manage site permissions」)。ネイティブ dialog が出ている間は操作できない (同「Browser not responding」)。screenshot は disk に保存できる (同「Save screenshots to disk」)。
  Desktop の Browser pane は個人のブラウザと別の clean profile で、localhost は承認不要、`.claude/launch.json` の `url` だけで既に動いているサーバに付く (docs: desktop
  「Preview your app」「Configure preview servers」)。Browser pane の tool が subagent に届くか、画像を disk に保存できるか、dialog を閉じられるか、任意の要求ヘッダを付けられるかは
  docs に記載が無い (未確認)。`/run-skill-generator` は起動手順を project skill に記録する (docs: skills)。
- **C6 制約。** 公開リポ。base image の digest pin と action の pin (`.claude/rules/falco-ctf-app-conventions.md:101-114,152-192`)。Colima は host の path を共有しないので bind mount を
  使わない (`CLAUDE.md:104-108`)。新しい check は advisory で入れ、required への昇格は CEO の admin 操作 (`GITHUB-OPS.md:242-254`、workspace `scripts/change-mgmt/setup-rulesets.sh:54`)。
  qa / software の skill は Go と shell だけ (workspace `ORGANIZATION.md:133,152`)。

## Options (CI で固定する層の作り方)

1. **Go のテストから実バイナリと実 Chromium を動かす【推奨】** — `internal/e2e/` (build tag `e2e`) が `cmd/scoreboard` を子プロセスで起動し、手前にテスト側の reverse proxy を置き、
   chromedp で Alpine の Chromium を headless で動かす。`Dockerfile.e2e`・`make e2e`・CI の別 job。
   コスト: test 専用の Go 依存 1 系統 (chromedp。2026-10-05 に v0.20.0、Go 1.25 以降。go.mod と Dependabot gomod に乗る)。image は `Dockerfile.test` と同じ base に Chromium 一式
   (Alpine 3.24 の chromium 152.0.7977.82-r0 は download 139.7MiB / installed 305.5MiB。依存込みで +0.4〜0.5GiB の見積)。待ち合わせの helper を自前で持つ。
   リスク: Chromium だけ。CDP を直に使うので自動待機が無い (D3 と V3 で補う)。可逆: 最初の 3 本なら Option 2 への書き直しは数百行。閾値: 次の portal PR から (C1 は既に起きている)。
2. **Playwright (TypeScript)** — `Dockerfile.e2e` を公式 image (digest pin) か node + chromium で作り、同じ container で実バイナリを起動し、seed は HTTP で入れる。
   コスト: 2 つ目の言語と依存の系統 (npm・lockfile・Dependabot npm・P12 の pin 規則の追記)。qa / software の skill に無い (C6)。3 browser 入りの公式 image は約 2.2GB (二次情報、未確認)。
   利点: 自動待機・trace・WebKit / Firefox・時計の制御・役割による locator。リスク: 判定がクライアント側の event になる (同じ proxy を TS で書けば揃う)。可逆: 同上。閾値: Signpost 1 か 2。
3. **`Dockerfile.test` を拡張して `make test` の中で回す** — 不採用。初日から required の `test` と Stop hook (`.claude/rules/dev-flow.md:27,45`) がブラウザに依存し、advisory で入れて
   観測してから昇格する規律 (`GITHUB-OPS.md:242-254`) に反し、全 Go 変更のセッション終了が遅くなる。閾値: Option 1 が required になり、所要が `test` と同程度になったら target の統合だけを
   再検討する (check の名前は分けたまま)。

方向として採らないもの: **jsc の拡張だけ** (DOM・要求・dialog・CSP を持たず macOS 専用: #316 の `scripts/check-portal-render.sh:22-33`)。**Claude in Chrome だけ** (回帰の gate にならず、
dialog で止まり、要求の網羅を見られず、作り手の自己申告になる)。**Cypress** (Node の費用は Option 2 と同じで、Option 2 に無い利点が無い)。**playwright-go** (Go のまま Playwright を
使えるが、Node の driver を同梱し、browser を Playwright の CDN から build 時に取る。apk の署名と digest pin の外になる)。

## Decision

**二層にし、CI は Option 1。** 理由: この portal で E2E でしか言えない性質 (要求の集合・CSP の下での実行・ポーリングの収束) は、サーバの手前の proxy の記録と実バイナリで判定するのが
最も漏れが無く、それを製品と同じ言語・同じ供給網の規則のまま持てるのが Option 1 だけだから。

- **D1 二層。**
  - **(a) 開発時 = Claude がブラウザで確かめる。主は Claude in Chrome。** subagent の Engineer にまで届くと docs で確かめられるのは Chrome だけだから (C5。VP のセッションが CLI である前提。Desktop のセッションから Chrome を使えるかは未確認)。
    条件 (組織の設定。CEO): 拡張はログインの無い専用ブラウザにだけ入れる (別の Chromium 系ブラウザ。同じ Chrome の別 profile を `/chrome` で選び分けられるかは未確認)。サイト許可は
    localhost だけにするが、auto mode では classifier の承認でこの確認が省かれる (C5) ので、境界は「ログインの無いブラウザ」の側に置く。subagent は親セッションの接続を継承するので、UI の仕事を出す VP のセッションで有効にする (`--chrome`。既定で有効にすると tool の説明が常に context を使う: docs: chrome)。
    直接契約のプランと `/login` が前提 (API key では無効: docs: chrome)。Desktop の Browser pane は Desktop のセッションで使ってよい副の経路 (clean profile なので専用ブラウザは要らない)。
  - 起動は **`make e2e-serve SEED=<名前> [AS=user1]`** — (b) と同じ image・seed・proxy で、identity を注入した portal を `127.0.0.1` にだけ出す。compose と `ALLOWED_ORIGINS` の dev 値は
    変えない。Desktop は `launch.json` の `url` でこれに付ける。手順は project skill に記録し、Engineer と `/run`・`/verify` が同じ手順を使う (docs: skills)。auth・ttyd・iframe に触れる
    変更は platform の local stack で確かめ、ログインだけ人が行う (Claude はログイン画面で止まって人に渡す: docs: chrome)。
  - 確かめられること: 見た目・DOM・console・クリックで進む流れ・ポーリングでの変化 (GIF も可)。確かめられないこと: ネイティブ dialog の先 (人が閉じるか CI に任せる)、ページが出した
    要求の網羅 (Chrome から要求の一覧を読めるかは未確認)、cross-origin の ttyd iframe と cookie (D2)、回帰の継続。
  - **(b) CI = `make e2e`。** `internal/e2e/` (build tag `e2e`) の Go テストが、`cmd/scoreboard` の実バイナリ (`scoreboard/Dockerfile` と同じ build flag) を env だけで子プロセスとして
    起動する (`LISTEN_ADDR`・`SCOREBOARD_DB`・`ALLOWED_ORIGINS`: `cmd/scoreboard/main.go:31-32,75`。webhook の secret は既定 off: `:140`)。テスト専用の時計 (`scoreboard.WithNow`:
    `internal/scoreboard/server.go:86`) と store への直書きは使わない — main の組み立て (`main.go:286-299`) を写すと drift の元になる。手前の proxy は (1) `X-Auth-Request-Email` を
    上書きで注入する (ingress と同じ向き) (2) 全要求を順序つきで記録する (3) 障害を注入できる (P28 条件 2 の 404)。ブラウザは chromedp で Chromium を headless で動かす。
  - `Dockerfile.e2e`: base は `Dockerfile.test:8` と同じ digest、chromium は apk の exact pin、テストを回す `RUN` は `--network=none` (外部への要求を構造的に持たない。loopback は使える)。
    push しない — `Makefile:12` の `IMAGES` と CI の build matrix (`.github/workflows/ci.yaml:282-340`) に入れないので I5 の 8 image ではない。build step の Chromium は root なので
    `--no-sandbox` になるが、読み込むのは loopback の first-party の頁だけで、step は offline で秘密を持たない (security-engineer の確認事項)。
  - `make e2e` は **`make test` と別の target**。判定は exit status と実行シナリオ数で、0 件・ブラウザ不在は fail (`t.Skip` で黙って緑にしない: `dev-flow.md:167-176` の I15 の前例)。
    失敗時の診断 (要求ログ・console・DOM の抜粋・画像) は `--target export -o` の形 (`Makefile:151-152`) で取り出し、判定ファイルが無ければ fail。`make test` は E2E を実行せず、
    `go vet -tags e2e ./...` でコンパイルだけを確かめる。Stop hook は変えない。
  - CI: job `e2e` を advisory の workflow (`.github/workflows/checks.yaml:3-9`) に置き、path filter を付けずに全 PR で回す (昇格したときに永久 pending を作らない)。`continue-on-error` は
    使わない。起動は ubuntu の runner で `actions/checkout` の後に `make e2e` を実行するだけ (BuildKit の build の中でテストが回る。services も port の公開も使わず、Colima と同じ経路)。新しい third-party action を足さない — 画像を artifact にするなら `actions/upload-artifact` を P12 の例外表に足す判断と同じ PR で行う。
  - 見積 (未計測。V5 で実測する): image は `Dockerfile.test` の image + 0.4〜0.5GiB。job は `test / go-test` の 2 分 52 秒 + 1〜2 分 (apk、バイナリの build、3 シナリオ。各 10〜20 秒で、
    2 秒ポーリングの待ちが支配的)。
  - **(c) required への昇格**: 次をすべて満たしたら、CEO が `setup-rulesets.sh` の CHECKS に `e2e` を足す — V1 の E1〜E3 と V2 の自己テストが main で green / 2 週間以上かつ 20 run 以上で
    flake 0 (同じ SHA の再実行で赤から緑になったもの。切り分けは qa-engineer) / job の p95 が 10 分以下 / chromium の pin が index から消えたことを main が赤くなる前に検知できる。
- **D2 対象の固定。**
  - **入れる規則**: ブラウザが出荷物の JS を出荷物の CSP の下で動かすこと、ポーリングとサーバ状態の収束、ページ自身が出す要求の集合、ネイティブ dialog を挟む操作、のどれかに依存する
    性質だけ。HTTP 応答への assert (Go テスト) か、描画関数の出力への assert (jsc・template の静的テスト) で言えるものは入れない。
  - **全シナリオ共通の assert**: uncaught error 0 / CSP 違反 0 (document の開始から集める。`POST /csp-report` は届く時刻が保証されないので主の判定にしない) / proxy 以外の origin への要求 0 /
    **書き込み要求 (GET 以外) の集合 = そのステップで利用者が行った操作の集合**。集合の一致なので、自動の呼び出しも、将来足される route (ADR-0032 の開始ルート) も同じ規則で落ちる。
  - **最初の対象**: V1 の E1〜E3 (ADR-0027 V6 / V7 と ADR-0032 ⑩)。**次の候補**: P28 条件 2 (asset の 404 を注入しても「発火 → CLEARED」)・4 (ingest から 1 ポーリング以内)・
    6 (skip と演出中の Terminal への切替)・7 (reduced-motion とキーボード操作)。その UI を入れる P28-1 以降の PR が足す (D4)。
  - **対象外**: (i) **I8 の browser 経路** (cross-origin の ttyd iframe に oauth2-proxy の cookie が届くこと)。local に oauth2-proxy・ttyd・TLS の registrable domain が無く、mock-oauth2 は
    固定ヘッダを返すだけ (C3) なので代替できない。platform の実 stack (`verify-auth.sh` と stand-up のリハーサル。PoC は `REFACTORING.md:594` と同じ経路) に残す。prefix-exact の判定
    そのものは auth-policy の Go テスト。(ii) 画素の比較は持たない (開発時の画像と design のレビューに置く)。(iii) API の status・self-scope・投影の値は Go テスト、描画の組み合わせは
    jsc と template の検査。
- **D3 決定論。**
  - シナリオごとに新しいバイナリと一時 DB、直列。seed はバイナリの HTTP 面だけ (`POST /falco/events`、`POST /api/challenges/{cid}/submit`) で入れ、proxy を通さない (要求ログに混ぜない)。
    seed の手順は 1 箇所に置いて `make e2e-serve` と共有する。ADR-0032 で開始操作が要るようになったら、そこだけを直す。
  - 待ち合わせに sleep を使わない (V3)。サーバ側: 状態を変えた後に始まった journey の GET を proxy の記録で 1 回以上待つ。クライアント側: DOM の述語を締切つきで待つ (締切は失敗までの
    上限で、成功の条件ではない)。否定の assert は、同じ描画の肯定の同期点 (`#pane-journey-detail` の `data-mission` が期待の id: `pane-story:188`) の後にだけ置く。
  - 時刻: サーバの時計は本物のまま。時刻を含む表示 (`updated …`・相対時刻) は assert しない。rate-limit の bucket は 1 req/s・burst 10 (`api.go:299`) なので、1 シナリオの書き込みは
    10 秒に 10 回未満に保つ。ポーリングの間隔は変えない。乱数: CSP の nonce は応答ごとに変わるが assert しない。
  - ブラウザ: viewport 1280×800、`ja-JP`、`Asia/Tokyo`、`prefers-reduced-motion: reduce` (P28 条件 7 と、演出の時間を判定から外すため)。
  - fixtures: 実の `challenges/` と `scenarios/nimbusbreach-full` (主題が実の順序なので。ADR-0027 V2 と同じ)。flag は公開の dev placeholder だけで、FLAGS_FILE を渡さない。content 由来の
    期待値 (ヒントの本文) は実行時に catalog から読み、テストに書き写さない。文言そのものが主題のとき (E2 の 3 文) だけ文言で assert し、範囲を `#pane-journey-detail` に絞る。
  - セレクタ: portal の JS 自身が依存している id と data 属性 (`pane-journey-open-hint`・`pane-journey-reset-dirty`・`data-mission`・`data-next`・`data-penalty`・`data-cid`:
    `pane-story:188,258,274,775-812`) を使う。足りないときだけ `data-testid` を同じ PR で足す (application-engineer)。製品の JS と CSS は `data-testid` を読まない (V3)。class 名と位置では
    掴まない。最初の 3 本は template を変えずに書ける見込み (未確認。H1 で確定)。
- **D4 DoD の変更 (提案。app の `.claude/rules/dev-flow.md` は H2 で直し、本 ADR では触れない)。** パターン A の表 (`dev-flow.md:42-48`) と CI の表 (`:154-165`) に次の 2 行を、
  パターン D の判定 (`:14`) に `Dockerfile.e2e` を、表の後に注意を 1 文足す:
  > | ブラウザ確認 | PR 直前 | portal が描く面 (`internal/scoreboard/view/templates/portal/**`・`internal/scoreboard/view/static/**`) か、portal が読む応答 (`Journey`・`MissionDetail`・`Me`) の形や値を変えた時 | ADR-0031 D1 の経路で確かめ、PR 本文の「ブラウザ確認」節に ADR-0031 D4 の最小形を書く。ADR-0031 D2 の対象の振る舞いを変えたら、同じ PR でシナリオを足すか直し、`make e2e` の結果を添える |
  >
  > | browser E2E | `make e2e` (PR 前に推奨) | advisory (`e2e`)。ADR-0031 D1 (c) を満たしたら blocking |
  >
  > 注意: `make test` は E2E を実行しない (コンパイルだけ)。「`make test` が緑」を「ブラウザで確かめた」と読み替えない。
  - **証跡の最小形** (PR 本文。画像は確かめた状態ごとに 1 枚):
    ```
    ### ブラウザ確認 (ADR-0031 D4)
    - 経路: Claude in Chrome (専用ブラウザ) | Desktop Browser | make e2e / SHA: <sha> / 起動: make e2e-serve SEED=<名前> AS=<user>
    - 1. <操作> → 期待: <…> → 観測: <DOM の該当テキスト> [画像: <ファイル名>]
    - console error: <件数> / CSP 違反: <件数>
    - 確かめていないこと: <dialog の先・iframe など。無ければ「無し」>
    ```
  - `gh` から PR 本文に画像を添付する手段は確認できていない (未確認)。添付は PR を作る VP が Web UI で行い、添付できない場合も操作ログは必須 (再現手順を兼ねる)。D2 の対象の振る舞いは、
    シナリオ名と `e2e` job の結果で証跡に代える。ORGANIZATION §7 の DoD の 1 行は VP が workspace で直す。

## Consequences

- **諦めたもの**: WebKit と Firefox (Chromium だけ)。Playwright の自動待機・trace・時計の制御。画素の比較。開発時に dialog の先まで自動で確かめること。
- **新しい不変条件は足さない。** `e2e` が required になるまで機械強制が blocking でないので、Hard Invariant は提案しない (`docs/adr/README.md` の規律)。
- **影響**: go.mod に test 専用の依存が入る (本番の binary に入らないことを V4 で検査)。CI の job が 1 つ増える。`Dockerfile.e2e` は Class-2 (Dockerfile: workspace `ORGANIZATION.md:277`) で、
  security-engineer のレビューと CEO の merge が要る。ADR-0027 V6 / V7 と ADR-0032 ⑩ の「qa の手動検証」は、E1〜E3 が main に入った時点でシナリオ名に置き換わる。
- **architect の判定 (同意権)**: `Dockerfile.e2e` は I5 の image ではない — **yes, if** push しない・`IMAGES` と build matrix に入れない・base の digest と chromium の exact pin・テストの
  step が offline。契約 (`ALLOWED_ORIGINS`・cookie domain・compose の dev 値) と API (spec) は変えない。
- **助言 (非拘束)**: (1) application-engineer へ — ネイティブ `confirm()` は Claude in Chrome を止める (C5)。P28-1 でページ内の確認に置き換えるなら、開発時にも dialog の先まで確かめられる
  (ADR-0032 D8 は確認の形を指定していない)。(2) e2e の image は CI に JS の実行系を持ち込むので、#316 の描画行列を同じ image の Chromium (サーバ無し) で回せば macOS の jsc への依存を外せる。
  どちらも E2E の対象を広げる話ではない。

## 段階と期限

| 段階 | 内容 | 担当 | Class | security |
|---|---|---|---|---|
| H0 | 本 ADR を Accepted にする (期限 = P28-1 の着手前) | architect → VP | 0 | 不要 |
| H1 | `Dockerfile.e2e`・`internal/e2e` (proxy・helper・自己テスト・E1〜E3)・`make e2e` / `e2e-serve`・`Dockerfile.test` の `go vet -tags e2e`・job `e2e` (advisory)・V4 の境界テスト | qa-engineer (オーナー。シナリオと helper)、software-engineer (Dockerfile・Makefile・CI) | 2 | 必須 |
| H2 | dev-flow の文 (D4)・`e2e-serve` の手順の project skill・ORGANIZATION §7 の DoD | application-engineer・VP | 0 | 不要 |
| H3 | `e2e` を required にする (D1 (c) の記録を添える) | CEO (admin) | — | — |

- **H1 は P28-0b (#316 / #317) の merge の後に出す** (E1 / E2 はその挙動を固定する)。0b が遅れるなら H1 は E3 と自己テストだけで出し、E1 / E2 は 0b の merge 後の PR で足す。
- **H1 までの間**: ADR-0027 V6 / V7 と ADR-0032 ⑩ は qa の手動検証のまま。`e2e-serve` がまだ無いので、platform の local stack で人がログインした専用ブラウザを Claude が操作し、D4 の最小形で残す。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・3 は CI の run 履歴から、2 はイベント後の問い合わせとリハーサルの記録から測る。

1. **待ち合わせ由来の flake**: 2 週間で `e2e` の flake が 2 件を超える、または run の 2% を超え、原因が待ち合わせ → D3 の同期点を見直し、直らなければ Option 2 (自動待機) に移す。
2. **ブラウザ固有の欠陥**: 参加者の申告かリハーサルで、WebKit か Firefox でだけ再現する portal の欠陥が 1 件出る → 該当シナリオに Option 2 で WebKit / Firefox を足す。
3. **費用**: `e2e` の job の p50 が 10 分を超える、image が 2GiB を超える、またはシナリオが 15 本を超える → 並列化か分割。時計の制御が要るなら in-process の server を再検討する。
4. **開発時の経路**: Desktop の Browser pane の tool が subagent に届き、画像を disk に保存できると docs に書かれる → D1 (a) の主を Desktop に替える (専用ブラウザの設定が要らなくなる)。

## Verification

すべて**未実装** (H1 で入れる)。

- **V1 最初の 3 シナリオ** (実 catalog + `nimbusbreach-full`、user1。各シナリオは守る性質を故意に壊した変更で赤になることを PR 本文に出力で示す):
  - **E1 (ADR-0027 V6)**: 01〜04 を solve して current = 05。地図で 06 を開くと、`?mission=06` の詳細が `locked` のまま「ヒント 1」の開封と減点 10 を出す。押すと dialog の文に 10 点が出る。
    取消なら書き込み 0、承認なら `POST …/06-web-rce-shell/hints/1` が 1 回で、本文 (catalog から読む) と次の減点 30 が出る。
  - **E2 (ADR-0027 V7 = D6。ADR-0032 の後は `alert` 基準に読み替える: `0032:156`)**: current の evade (05) では従来の「クリーン」の文が出る。current でない evade (10) では V7 の 3 文が出ず、
    中立の表示になる。05 の禁止ルールの発火を ingest に送ると、2 ポーリング以内に dirty の表示と reset ボタンに変わる。
  - **E3 (ADR-0032 ⑩ と reset)**: 閲覧 (ポーリング 3 回以上・地図の node 3 つ・current へ戻る・タブの切替・再読込) の間、書き込み要求の集合が空。dirty の 05 で reset を押して dialog を
    取消すと空のまま、承認すると `POST …/05-silent-search/reset-dirty` が 1 回だけ。dialog の文が消えるものを名指しする (現行 `pane-story:814-818`。ADR-0032 S4 の後は receipt と証明も)。
- **V2 判定の自己テスト (恒久)**: `internal/e2e/testdata` の小さな頁で、(a) 読み込み時に POST する (b) CSP に違反する (c) uncaught error を出す (d) 外部の origin を取りに行く、の
  それぞれを共通 assert が赤にすることを assert する。
- **V3 静的検査**: `internal/e2e` に `time.Sleep` が無い。製品の template と JS が `data-testid` を読まない。
- **V4 境界**: 本番の binary (`cmd/*`) の import の閉包に chromedp と `internal/e2e` が無い (`internal/apispec/dependency_boundary_test.go:125` と同じ形)。`Dockerfile.test` の
  `go vet -tags e2e ./...` で E2E のコードがコンパイルされ続ける。どちらも `make test` = required。
- **V5 image と所要**: `Dockerfile.e2e` の base の digest pin・chromium の exact pin・テストの `RUN --network=none`。`IMAGES` と build matrix に無い。image の大きさと job の所要を実測して
  PR に貼る (見積を超えたら Signpost 3 で扱う)。
- **V6 判定の fail-closed**: 実行シナリオ数が期待未満、ブラウザ不在、判定ファイルの欠落のどれでも `make e2e` が非ゼロで終わることを、故意の build tag の誤りとファイルの削除で示す。
- **V7 昇格の記録**: CHECKS を変える PR に、期間・run 数・flake 数・p95 を貼る (D1 (c))。

## Advice

- VP (2026-10-06、発注): D1〜D4 の論点、最初の 3 シナリオを ADR-0027 V6 / V7 と ADR-0032 ⑩ にすること、jsc の拡張だけ・Chrome だけ・Cypress を代替として評価すること。
- qa-engineer・security-engineer: 未実施 (H0 の間に受ける)。security の確認事項: `--no-sandbox`、offline の step、新しい依存と action、`e2e-serve` の identity 注入が `127.0.0.1` にだけ出ること。
- architect の判断 (発注の外): 開発時の起動を compose ではなく `e2e-serve` にした (seed を CI と共有し、identity の注入をテスト側に閉じるため)。CI のサーバを in-process ではなく実バイナリに
  した (main の組み立ての写しを作らないため)。CEO の「`make test` の層に足す」を「コンテナで回す自動テストの層に、別 target・別 check で足す」と読んだ (理由は Option 3。CEO の確認事項)。
