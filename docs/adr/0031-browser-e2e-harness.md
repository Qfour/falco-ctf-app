# ADR-0031: ブラウザでの確認を二層にする — 開発時は Claude が専用ブラウザで確かめて証跡を残し、CI は Go のテストが実バイナリと実 Chromium を動かす E2E (`make e2e`) で固定する

- Status: **Proposed** (Accepted 化の期限 = P28-1 の着手前: workspace `REFACTORING.md:1902`。ハーネスの実装は受け入れ判定まで。時限自動承認の対象: workspace `ORGANIZATION.md:472`)
- Date / Deciders: 2026-10-06 起草・2026-10-07 改訂 / CEO (ADR-WS-0009 の H「検証できないものは出荷しない」を承認。CI は Playwright 相当を `make test` の層に) + VP (発注・査定) + architect (起草・同意権) /
  独立レビュー: qa-engineer R2・security-engineer R1 (2026-10-07、app#321。両者とも方向を承認して REQUEST CHANGES。指摘の反映先は Advice)
- 関連: ADR-0027 V6・V7 (`0027:152-154`)、ADR-0032 D8・⑩ (`0032:111-113,239`)、app#316 / #317 (P28-0b、draft)、workspace `REFACTORING.md` P28 (受け入れ条件 2・4・6・7 = `:1619-1629`、
  `:1657,1801`)、workspace `DEV-METHOD-REVIEW.md` H (`:22,49,128-130`) と CEO 判断 8 (`:171`)、workspace `GITHUB-OPS.md` G5 (`:242-254`)
- 行番号は c5e0761 (platform は 873eed2)。`0027:N` などは `docs/adr/` の各 ADR、`pane-<名>` は `internal/scoreboard/view/templates/portal/pane-<名>.tmpl`、`conventions` は
  `.claude/rules/falco-ctf-app-conventions.md`。Claude Code の docs は 2026-10-06 / 07 に取得した `https://code.claude.com/docs/en/<page>` を「docs: <page>」と書く。docs に無いことは「未確認」と書く

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
  ページ自身が出す要求の集合 (ADR-0032 D8 が「クリックからだけ」を要求する: `0032:111-113`。テンプレートの静的検査は `0032:232`)。描画の例外は `refresh()` の try に捕まって「connection error」
  の表示に変わり、uncaught にならない (`pane-story:112-123`、`pane-me:57-66`)。**I8 の browser 経路は 2 面ある**: portal の CSP の `frame-src` は `PORTAL_TTYD_SUFFIX` から組まれ
  (`internal/scoreboard/view/csp.go:173-177`)、それが欠けていた欠陥は suffix が空の local の smoke を素通りした (`:35-41`)。もう 1 面は cross-origin の ttyd iframe に oauth2-proxy の cookie が
  `SameSite=None` で届くこと (`conventions:378`) で、platform の `scripts/verify-auth.sh:45-105` は cookie jar で host と email の束縛を見るだけで、iframe への到達を見ない。
- **C5 Claude 側の手段 (docs)。** Claude in Chrome は CLI から使え (docs: chrome)、MCP (server `claude-in-chrome`) の tool として subagent に継承され、background の subagent も MCP の tool は
  すべて持つ (docs: sub-agents「Available tools」)。拡張はブラウザのログイン状態を共有する。auto mode では classifier が承認した呼び出しについて拡張の site 確認が省かれる — ただし permission
  rules が Claude in Chrome に site を 1 つでも deny していれば省かれない (docs: chrome「Manage site permissions」)。拡張は sandbox の外で動き (sandbox が効くのは Bash・PowerShell・Monitor だけ:
  docs: permissions「How permissions interact with sandboxing」)、session が Read できるファイルを upload でき、Read の deny は upload も止める (docs: chrome「Upload files to web pages」)。
  ネイティブ dialog が出ている間は操作できない (同「Browser not responding」)。screenshot は disk に保存でき、GIF はブラウザに見えるものをすべて写す (同「Save screenshots to disk」「Record a demo GIF」)。
  Desktop の Browser pane は個人のブラウザと別の clean profile で、localhost は承認不要、`.claude/launch.json` の `url` で既に動いているサーバに付き、managed 設定 `disableBrowserExternalNavigation: true`
  で外部への遷移を利用者と Claude の両方について止められる (docs: desktop「Preview your app」「Restrict external browsing for your organization」)。Browser pane の tool が subagent に届くか、画像を
  disk に保存できるか、dialog を閉じられるか、任意の要求ヘッダを付けられるかは docs に無い (未確認)。`/run-skill-generator` は起動手順を project skill に記録する (docs: skills)。
- **C6 制約。** 公開リポ。base image の digest pin と action の pin (`conventions:101-114,152-192`)。Colima は host の path を共有しないので bind mount を使わない (`CLAUDE.md:104-108`)。新しい check は
  advisory で入れ、required への昇格は CEO の admin 操作 (`GITHUB-OPS.md:242-254`、workspace `scripts/change-mgmt/setup-rulesets.sh:54`)。qa / software の skill は Go と shell だけ (workspace
  `ORGANIZATION.md:133,152`)。Alpine の index は各 package の最新の 1 版だけを載せる (2026-10-07 の v3.24 community の APKINDEX: chromium は x86_64・aarch64 とも 152.0.7977.82-r0 の 1 件)。

## Options (CI で固定する層の作り方)

1. **Go のテストから実バイナリと実 Chromium を動かす【推奨】** — `internal/e2e/` (build tag `e2e`) が `cmd/scoreboard` を子プロセスで起動し、手前にテスト側の reverse proxy を置き、
   chromedp で Alpine の Chromium を headless で動かす。`Dockerfile.e2e`・`make e2e`・CI の別 job。
   コスト: test 専用の Go 依存 1 系統 (chromedp。2026-10-05 に v0.20.0、v0.20.1 も出ている: security-engineer。Go 1.25 以降。go.mod と Dependabot gomod に乗る)。image は `Dockerfile.test` と同じ
   base に Chromium 一式 (chromium 152.0.7977.82-r0 は x86_64 で download 139.7MiB / installed 305.5MiB。依存込みで +0.4〜0.5GiB の見積)。待ち合わせの helper を自前で持つ。pin の保守 (D5)。
   リスク: Chromium だけ。CDP を直に使うので自動待機が無い (D3 と H1 の受け入れ条件で補う)。可逆: 最初の 4 本なら Option 2 への書き直しは数百行。閾値: 次の portal PR から (C1 は既に起きている)。
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

**二層にし、CI は Option 1。** 理由: この portal で E2E でしか言えない性質 (要求の列・CSP の下での実行・ポーリングの収束) は、サーバの手前の proxy の記録と実バイナリで判定するのが
最も漏れが無く、それを製品と同じ言語・同じ供給網の規則のまま持てるのが Option 1 だけだから。

- **D1 二層。**
  - **(a) 開発時 = Claude がブラウザで確かめる。主は Claude in Chrome。** subagent の Engineer にまで届くと docs で確かめられるのは Chrome だけだから (C5。VP のセッションが CLI である前提。
    Desktop のセッションから Chrome を使えるかは未確認)。subagent は親の接続を継承するので、UI の仕事を出す VP のセッションに `--chrome` を付ける (既定で有効にすると tool の説明が常に
    context を使う)。直接契約のプランと `/login` が前提 (API key では無効: docs: chrome)。
  - **境界は permission の設定に置き、ブラウザの選び方には置かない。** 拡張は sandbox の外で動き、Read できるファイルはどれも upload でき、off-origin への送出を止めるのは確率的な classifier
    だけなので (C5)、「ログインの無いブラウザ」だけでは開発機にあり得る鍵や `events/` の持ち出しを防げない。**使い始める前提 (CEO の設定。Chrome 連携を入れる前に行う)**:
    - (i) user settings に Read の deny: 鍵 (SOPS の鍵・`~/.ssh`)・`~/.aws`・kubeconfig・platform の `events/**`・`*.dec.yaml`・`*.secret.*` (`~/` か `//` で書く: docs: permissions「Read and Edit」)。
    - (ii) `--chrome` の session では flags・secrets・prod を扱わない。それらの仕事は `--chrome` の無い別の session で行う。
    - (iii) Claude in Chrome に site を deny する permission rule を 1 つ置き、auto mode でも拡張の site 確認を残す (C5)。その書式は docs に無い (未確認。settings は括弧つきの `mcp__` の規則を
      読み飛ばし、MCP の引数の一致は `--disallowedTools` でだけ書ける: docs: permissions「Match by input parameter」)。書式を確かめて記録するまでは、auto mode の site の制限は classifier だけが担う
      ものとして境界に数えない。拡張の site 許可は localhost 全体でなく `e2e-serve` の origin だけにする (host:port 単位で絞れるかは未確認)。
    - (iv) 専用ブラウザ = 普段使わない別の Chromium 系ブラウザ (docs: chrome。同じ Chrome の別 profile を選べるかは未確認)。どのアカウントにもサインインせず、同期・パスワード管理・自動入力を
      切る。cookie を持ってよいのは local Dex の合成ユーザだけ。
    - (v) UI を確かめる 3 職 (application-engineer・design-engineer・qa-engineer) 以外で `tools:` を持たない 6 職の frontmatter に `disallowedTools: mcp__claude-in-chrome` を付け (server 単位の
      形は docs: sub-agents)、workspace の `scripts/claude/check-agent-skills.sh` で検査する (workspace の別 PR。VP)。architect と security-engineer は `tools:` の allowlist に MCP が無い。
  - 起動は **`make e2e-serve SEED=<名前> [AS=user1]`** — (b) と同じ image・seed・proxy で、identity を注入した portal を `127.0.0.1` にだけ出す (V8)。compose と `ALLOWED_ORIGINS` の dev 値は
    変えない。Desktop は副の経路で、`launch.json` の `url` でこれに付ける (clean profile なので専用ブラウザは要らない)。手順は project skill に記録し、Engineer と `/run`・`/verify` が同じ手順を使う
    (docs: skills)。auth・ttyd・iframe に触れる変更は platform の local stack で確かめ、ログインだけ人が行う (Claude はログイン画面で止まって人に渡す: docs: chrome)。
  - **画像の規律**: 証跡用の local stack は `events/` の flags と names を渡さずに立てる (platform の `scripts/deploy-event-workspaces.sh:11-13` は `--env local` でも `--flags-file` と
    `--names-file` を受ける)。VP は PR に添付する前に各画像を確かめる。GIF は `e2e-serve` で撮ったものだけ (GIF は見えるものをすべて写す: C5)。
  - 確かめられること: 見た目・DOM・console・クリックで進む流れ・ポーリングでの変化 (GIF も可)。確かめられないこと: ネイティブ dialog の先 (人が閉じるか CI に任せる)、ページが出した
    要求の網羅 (Chrome から要求の一覧を読めるかは未確認)、cross-origin の ttyd iframe の cookie (D2)、回帰の継続。
  - **(b) CI = `make e2e`。** `internal/e2e/` (build tag `e2e`) の Go テストが、`cmd/scoreboard` の実バイナリ (`scoreboard/Dockerfile` と同じ build flag) を子プロセスとして起動する。子の env は
    allowlist から組んで親の env を継がない: `LISTEN_ADDR` (loopback)・`SCOREBOARD_DB` (一時)・`ALLOWED_ORIGINS` (proxy の origin) (`cmd/scoreboard/main.go:31-32,75`)・`CHALLENGES_DIR`・
    `SCENARIO_FILE` (`cmd/scoreboard/catalog.go:28-29`)・`PORTAL_TTYD_SUFFIX` (予約 TLD のテスト値 `<名>.test`: `main.go:122`)。`FLAGS_FILE`・`ADMIN_EMAILS`・webhook の secret (既定 off: `:140`)
    は渡さず、無いことを起動時に assert する。テスト専用の時計 (`scoreboard.WithNow`: `internal/scoreboard/server.go:86`) と store への直書きは使わない — main の組み立て (`main.go:286-299`) を写すと drift の元になる。
  - 手前の proxy は (1) `X-Auth-Request-Email` を上書きで注入する (ingress と同じ向き) (2) 全要求を順序つきで記録する (3) 障害 (404・500・応答の停止) を注入できる (4) 応答のヘッダ (CSP を
    含む) を書き換えない。upstream は自分が起動した子だけで、env や引数で差し替えられない。ブラウザは chromedp で Chromium を headless で動かし、`--host-resolver-rules` で `user1.<suffix>` を
    loopback の TLS stub に向ける (iframe は頁の読み込みで作られる: `pane-terminal:69-79,93`。信頼させるのは stub の鍵だけで、`--ignore-certificate-errors-spki-list` が候補 (未確認)。証明書の検査を全体で切る flag は使わない)。
  - `Dockerfile.e2e`: base は `Dockerfile.test:8` と同じ digest、Chromium と font は apk の exact pin (D5)、テストを回す `RUN` は `--network=none` (外部への要求を構造的に持たない。loopback は
    使える見込み: V5 で実測)。push しない — `Makefile:12` の `IMAGES` と CI の build matrix (`.github/workflows/ci.yaml:282-340`) に入れないので I5 の 8 image ではない。build step の Chromium は
    root なので `--no-sandbox` になるが、読み込むのは loopback の first-party の頁だけで、step は offline で秘密を持たない (security-engineer が既存の `go test` と同じ信頼範囲と確認した: Advice)。
  - **判定は fail-closed で、host 側で行う。** BuildKit は失敗した `RUN` の後を export しないので、test の `RUN` は `go test -json` の出力と終了コードをファイルに書いて常に 0 で終わる。
    `make e2e` は (1) export 先の専用 dir (`.gitignore` と `.dockerignore` の両方に載せる) を空にしてから build する (2) 毎回生成する `E2E_RUN_ID` と HEAD の SHA を build ARG で渡し (test の層の
    cache を外す)、判定ファイルに書かせる (3) build の後で、RUN_ID と SHA の一致・終了コード 0・pass したテスト名の集合 = `internal/e2e` に置く名前の表・skip 0 をすべて確かめ、1 つでも欠ければ
    非ゼロで終わる (ファイルの欠落・空・読めない行も fail。`t.Skip` で黙って緑にしない: `dev-flow.md:167-176` の I15 の前例)。診断 (要求ログ・console・DOM の抜粋・画像) も同じ export に入る (`Makefile:151-152` の形)。
  - `make e2e` は **`make test` と別の target**。`make test` は E2E を実行せず、`go vet -tags e2e ./...` でコンパイルだけを確かめる。Stop hook は変えない。
  - CI: job `e2e` を advisory の workflow (`.github/workflows/checks.yaml:3-9`) に置き、path filter を付けずに全 PR で回す (昇格したときに永久 pending を作らない)。`continue-on-error` と
    `container:` は使わない。runner の上で `actions/checkout` の後に `make e2e` を実行するだけ (BuildKit の build の中でテストが回る。services も port の公開も使わず、Colima と同じ経路)。新しい
    third-party action を足さない — 診断を artifact にするなら `actions/upload-artifact` を P12 の例外表 (`conventions:172-177`) に足し、同じ PR で表を実態 (`actions/checkout@v7` ほか: `checks.yaml:20-22`) に直す。
  - 見積 (未計測。V5 で実測する): image は `Dockerfile.test` の image + 0.4〜0.5GiB。job は `test / go-test` の 2 分 52 秒 + 1〜2 分 (apk、バイナリの build、4 シナリオ。各 10〜20 秒で、2 秒ポーリングの待ちが支配的)。
  - **(c) required への昇格**: 次をすべて満たしたら、CEO が `setup-rulesets.sh` の CHECKS に `e2e` を足す — V1 の E1〜E4 と V2 の自己テストが main で green / 2 週間以上かつ 20 run 以上で
    flake 0 / job の p95 が 10 分以下 / D5 の検知 job が main で動き、期間中の bump がすべて検知から 2 日以内に main に入った (bump が無ければ V9 で検知を示す)。**flake** = test stage の失敗で、
    同じ SHA の再実行で緑になったもの。build stage の失敗 (apk・base image・Go module の取得、index の更新) は flake に数えず、原因つきで別に記録する (取得の失敗が run の 2% を超えたら昇格
    しない)。cancel された run は数えない。赤の run の再実行と分類は qa-engineer。
- **D2 対象の固定。**
  - **入れる規則**: ブラウザが出荷物の JS を出荷物の CSP の下で動かすこと、ポーリングとサーバ状態の収束、ページ自身が出す要求の列、ネイティブ dialog を挟む操作、のどれかに依存する
    性質だけ。HTTP 応答への assert (Go テスト) か、描画関数の出力への assert (jsc・template の静的テスト) で言えるものは入れない。
  - **全シナリオ共通の assert** (集め方は H1 の受け入れ条件 (d)): uncaught error 0 / console の error 0 / **どの pane の更新表示も「connection error」にならない** (描画の例外はこれでしか
    見えない: C4。`pane-board:145-146` も同じ形) / CSP 違反 0 (document の開始から集める。`POST /csp-report` は届く時刻が保証されないので主の判定にしない) / proxy と ttyd の stub 以外の origin
    への要求 0 / **書き込み要求 (GET 以外) の (method, path) の列 = そのステップで利用者が行った操作の列** (順序と回数まで一致させるので、listener の積み重なりによる二重 POST も、自動の
    呼び出しも、将来足される route (ADR-0032 の開始ルート) も同じ規則で落ちる)。障害を注入するシナリオは、期待する error と表示をシナリオの中で列挙し、それ以外は 0。0 にできない雑音は
    assert を緩めずに製品の側を直す (除外リストを持たない)。
  - **最初の対象**: V1 の E1〜E4 (ADR-0027 V6 / V7、ADR-0032 ⑩、I8 の frame-src)。**次の候補**: P28 条件 2 (asset の 404 を注入しても「発火 → CLEARED」)・4 (ingest から 1 ポーリング以内)・
    6 (skip と演出中の Terminal への切替)・7 (reduced-motion とキーボード操作)。その UI を入れる P28-1 以降の PR が足す (D4)。
  - **対象外**: (i) **I8 の cookie 側** (cross-origin の ttyd iframe に oauth2-proxy の cookie が届くこと)。local に oauth2-proxy・ttyd・TLS の registrable domain が無く、mock-oauth2 は固定
    ヘッダを返すだけ (C3) なので代替できない。platform の実 stack に残し、`verify-auth.sh` は見ていない (C4) ので stand-up のリハーサルの手動項目に明記する (platform の runbook、sre-engineer)。
    frame-src 側は E4 で固定する。prefix-exact の判定そのものは auth-policy の Go テスト。(ii) 画素の比較は持たない (開発時の画像と design のレビューに置く)。(iii) API の status・self-scope・
    投影の値は Go テスト、描画の組み合わせは jsc と template の検査。
- **D3 決定論。**
  - シナリオごとに新しいバイナリ・一時 DB・browser context、直列。seed はバイナリの HTTP 面だけ (`POST /falco/events`、`POST /api/challenges/{cid}/submit`) で入れ、proxy を通さない (要求ログに
    混ぜない)。seed の手順は 1 箇所に置いて `make e2e-serve` と共有する。ADR-0032 で開始操作が要るようになったら、そこだけを直す。
  - 待ち合わせに sleep を使わない (V3)。同期点はサーバ側が proxy の記録、クライアント側が DOM の述語 (締切つき。締切は失敗までの上限で、成功の条件ではない) で、規則は H1 の受け入れ条件 (b)。
    否定の assert は、同じ描画の肯定の同期点の後にだけ置く。
  - 時刻: サーバの時計は本物のまま。時刻を含む表示 (`updated …`・相対時刻) は assert しない。rate-limit の bucket は 1 req/s・burst 10 (`api.go:299`) なので、1 シナリオの書き込みは
    10 秒に 10 回未満に保つ。ポーリングの間隔は変えない。乱数: CSP の nonce は応答ごとに変わるが assert しない。
  - ブラウザ: viewport 1280×800、`ja-JP`、`Asia/Tokyo`。media はシナリオごとに指定する (`prefers-reduced-motion` の既定は `reduce` で、演出の時間を判定から外す。P28 条件 6 の skip は `no-preference` で試す)。
  - fixtures: 実の `challenges/` と `scenarios/nimbusbreach-full` (主題が実の順序なので。ADR-0027 V2 と同じ)。flag は公開の dev placeholder だけで、FLAGS_FILE を渡さない。content 由来の
    期待値 (ヒントの本文) は実行時に catalog から読み、テストに書き写さない。文言そのものが主題のとき (E2 の 3 文) だけ文言で assert し、範囲を `#pane-journey-detail` に絞る。
  - セレクタ: portal の JS 自身が依存している id と data 属性 (`pane-journey-open-hint`・`pane-journey-reset-dirty`・`data-mission`・`data-next`・`data-penalty`・`data-cid`:
    `pane-story:188,258,274,775-812`) を使う。足りないときだけ `data-testid` (静的な文字列だけ) を同じ PR で足す (application-engineer)。製品の JS と CSS は `data-testid` を読まない (V3)。
    class 名と位置では掴まない。最初の 4 本は template を変えずに書ける見込み (未確認。H1 で確定)。
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
    - console error: <件数> / CSP 違反: <件数> / 画像: D1 (a) の規律で VP が確認済み
    - 確かめていないこと: <dialog の先・iframe の cookie など。無ければ「無し」>
    ```
  - `gh` から PR 本文に画像を添付する手段は確認できていない (未確認)。添付は PR を作る VP が Web UI で行い、添付できない場合も操作ログは必須 (再現手順を兼ねる)。D2 の対象の振る舞いは、
    シナリオ名と `e2e` job の結果で証跡に代える。ORGANIZATION §7 の DoD の 1 行は VP が workspace で直す。
- **D5 Chromium の pin の保守。** index は 1 版だけを載せる (C6) ので、exact pin は Chromium の更新のたびに index から消え、`Dockerfile.e2e` の build が止まる (fail-closed)。
  - 直すのは pin の更新だけ。unpin・版の範囲指定・別の repository への切替で緑に戻さない。
  - 検知: freshness 型の定期 job (`.github/workflows/freshness.yaml:3-16` と同じ形。network を使うので PR では回さず、advisory) を毎日と `workflow_dispatch` で回し、pin した base image の中で
    `apk policy` を引いて、`Dockerfile.e2e` の apk の pin のどれかが index の版と違えば赤にする。
  - bump: 担当は software-engineer (Dockerfile の担当)。Chromium を上げる PR では chromedp と cdproto の版も見直し、上げるなら同じ PR で上げる。Dependabot は apk を上げないので、Dependabot の
    chromedp の PR は `e2e` が緑のときだけ merge する。PR に `apk policy` の出力と `make e2e` の判定を貼る。
  - `Dockerfile.e2e` を digest の bump の一覧 (`conventions:129-141` の `golang:1.26-alpine` の行) に足す (H1)。package は `chromium` を使い、同じ版の `chromium-headless-shell` (旧 headless の
    別実装。x86_64 で installed 188.9MiB) は使わない — 小さいが、参加者のブラウザとの差を増やすため。

## Consequences

- **諦めたもの**: WebKit と Firefox (Chromium だけ)。Playwright の自動待機・trace・時計の制御。画素の比較。開発時に dialog の先まで自動で確かめること。I8 の cookie 側の自動化 (D2)。
- **新しい不変条件は足さない。** `e2e` が required になるまで機械強制が blocking でないので、Hard Invariant は提案しない (`docs/adr/README.md` の規律)。
- **影響**: go.mod に test 専用の依存が入る (本番の binary に入らないことを V4 で検査)。CI の job と定期 job が 1 つずつ増え、Chromium の bump が定常の作業になる (D5)。`Dockerfile.e2e` は
  Class-2 (Dockerfile: workspace `ORGANIZATION.md:277`) で、security-engineer のレビューと CEO の merge が要る。ADR-0027 V6 / V7 と ADR-0032 ⑩ の「qa の手動検証」は、E1〜E3 が main に入った
  時点でシナリオ名に置き換わる。platform の stand-up のリハーサルに iframe の cookie の手動項目が 1 つ増える (sre-engineer)。D1 (a) (i) の Read の deny は Claude のどの session にも効くので、
  `events/` を読む作業 (event の pin の更新など) も Claude に頼めなくなる — 困るなら `events/**` を `--chrome` の session にだけ効かせる方法を CEO が選ぶ (方法は未確認)。
- **architect の判定 (同意権)**: `Dockerfile.e2e` は I5 の image ではない — **yes, if** push しない・`IMAGES` と build matrix に入れない・base の digest と Chromium の exact pin・テストの
  step が offline・pin の保守 (D5) を持つ。契約 (`ALLOWED_ORIGINS`・cookie domain・compose の dev 値・`PORTAL_TTYD_SUFFIX` の派生規則 `conventions:377`) と API (spec) は変えない — E4 はテスト値を子の env に渡すだけ。
- **助言 (非拘束)**: (1) application-engineer へ — ネイティブ `confirm()` は Claude in Chrome を止める (C5)。P28-1 でページ内の確認に置き換えるなら、開発時にも dialog の先まで確かめられる
  (ADR-0032 D8 は確認の形を指定していない)。(2) e2e の image は CI に JS の実行系を持ち込むので、#316 の描画行列を同じ image の Chromium (サーバ無し) で回せば macOS の jsc への依存を外せる。
  どちらも E2E の対象を広げる話ではない。

## 段階と期限

| 段階 | 内容 | 担当 | Class | security |
|---|---|---|---|---|
| H0 | 本 ADR を Accepted にする (期限 = P28-1 の着手前) | architect → VP | 0 | 不要 |
| P | D1 (a) の前提: (i)〜(iv) の設定と、(v) の `disallowedTools` + `check-agent-skills.sh` の検査 (workspace の PR)。**揃うまで Claude にブラウザを操作させない** | CEO (設定)・VP (PR) | — | 必須 |
| H1 | `Dockerfile.e2e`・`internal/e2e` (proxy・TLS stub・helper・判定器・自己テスト・E1〜E4)・`make e2e` / `e2e-serve`・`Dockerfile.test` の `go vet -tags e2e`・job `e2e` (advisory)・D5 の定期 job・V4 / V8 の境界テスト | qa-engineer (オーナー。シナリオ・helper・判定器)、software-engineer (Dockerfile・Makefile・CI・D5) | 2 | 必須 |
| H2 | dev-flow の文 (D4)・`e2e-serve` の手順の project skill・ORGANIZATION §7 の DoD・platform のリハーサルの手動項目 (iframe の cookie) | application-engineer・VP・sre-engineer | 0 | 不要 |
| H3 | `e2e` を required にする (D1 (c) の記録を添える) | CEO (admin) | — | — |

- **H1 は P28-0b (#316 / #317) の merge の後に出す** (E1 / E2 はその挙動を固定する)。0b が遅れるなら H1 は E3・E4 と自己テストだけで出し、E1 / E2 は 0b の merge 後の PR で足す。
- **H1 までの間**: ADR-0027 V6 / V7 と ADR-0032 ⑩ は qa の手動検証のまま。P が揃っていれば platform の local stack で人がログインした専用ブラウザを Claude が操作し、揃うまでは qa が手で確かめ、どちらも D4 の最小形で残す。
- **H1 の受け入れ条件** (qa-engineer が確かめ、VP が査定する):
  - (a) 書き込みが無いことを確かめる窓は、最長のポーリング (board の 5 秒: `pane-board:135,584`) 以上をとる。`#pane-story` は描き直されない (`pane-story:87-93`) ので、listener の積み重なりは二重 POST として現れる。
  - (b) 同期点: (1) 状態を変えたら、変更の前に始まった journey の GET がすべて完了し、変更の後に始まった GET が 1 回以上完了するまで待つ (`setInterval` の GET は重なり、応答は逆転し得る。
    Me は busy で止めない: `pane-me:53-54`) (2) 同じ課題の中の変化では `data-mission` が変わらず、detail は signature が変わったときだけ描き直す (`pane-story:332-347`) ので、変わった内容そのもの
    の DOM の述語で待つ (3) Sweeper (5 秒: `internal/scoreboard/scoring/scoring.go:939`) による変化は、API を HTTP で読み返して期待の状態になってから (1) を待つ (4)「N ポーリング以内」は変更の
    後に始まった journey の GET の回数で数える。
  - (c) E3 は 05 が dirty の間に閲覧し、detail の描き直し (`wireDetail` は signature の変化時だけ走る: `pane-story:335-340`) を含める。閲覧の前後に journey を HTTP で読み、`hints.opened` と `dirty` が変わらないことも確かめる。
  - (d) 集め方: 外部 origin への要求は proxy に届かない (名前が引けない) ので `Network.requestWillBeSent` で集める。CSP 違反と console は最初の navigate の前に有効にする (`Audits` か `Log`、
    または `Page.addScriptToEvaluateOnNewDocument` + `Runtime.addBinding` で `securitypolicyviolation` を拾う)。`Page.setBypassCSP` は使わない。dialog は `Page.javascriptDialogOpening` を goroutine で受ける。
  - (e) 障害注入は 404・500・応答の停止の 3 種。前提: seed の event は ns `ctf-`・pod `workspace`・image に `falco-ctf/challenge`・priority が notice 以上 (`internal/scoreboard/ingest/ingest.go:216-248`)。
    `make e2e` では seed の submit とブラウザの書き込みが同じ rate-limit の bucket (127.0.0.1) に入る (D3)。
  - (f) Chromium: 起動 flag は allowlist で持ち、`--disable-dev-shm-usage` を明示し、`--disable-web-security` と証明書の検査を全体で切る flag を入れない。CJK の font は診断画像を読むため
    だけに入れる (候補 `font-wqy-zenhei` installed 16.3MiB。`font-noto-cjk` は 88.8MiB)。Colima の VM に要るメモリを実測して PR に書く。chromedp の版を決め直す。
  - (g) 未確認を確かめて PR に書く: chromedp の既定の flag (`--no-sandbox`・`/dev/shm`)・`golang:1.26.6-alpine` の digest の Alpine の版・`# syntax=` 無しの `RUN --network=none` と loopback・
    BuildKit の `/dev/shm`・Reporting API の report が proxy に届くか・Chrome の Local Network Access。
  - (h) 既存の穴 (本 ADR の外。別 issue で扱う): `.dockerignore` に `*.dec.yaml` と `kubeconfig*` が無い (`.dockerignore:45-50`。`.gitignore:23` には `kubeconfig*` がある)。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・3 は CI の run 履歴から、2 はイベント後の問い合わせとリハーサルの記録から、4 は docs から測る。

1. **待ち合わせ由来の flake**: 2 週間で `e2e` の flake が 2 件を超える、または run の 2% を超え、原因が待ち合わせ → D3 の同期点を見直し、直らなければ Option 2 (自動待機) に移す。
2. **ブラウザ固有の欠陥**: 参加者の申告かリハーサルで、WebKit か Firefox でだけ再現する portal の欠陥が 1 件出る → 該当シナリオに Option 2 で WebKit / Firefox を足す。
3. **費用**: `e2e` の p50 が 10 分を超える、image が 2GiB を超える、またはシナリオが 15 本を超える → 並列化か分割 (時計の制御が要るなら in-process の server を再検討)。Chromium の bump が
   月 4 回を超えるか、index の更新で `e2e` が 2 日を超えて赤だったことが 2 回ある → 版が消えない配布 (Debian の snapshot か、digest で pin した Chromium 入りの base image) を再検討する。
4. **開発時の経路**: Desktop の Browser pane の tool が subagent に届き、画像を disk に保存できると docs に書かれる → D1 (a) の主を Desktop に替える。専用ブラウザの設定が要らず、managed 設定
   `disableBrowserExternalNavigation: true` で外部への遷移を構造的に止められる (C5) ので、拡張の site 許可と classifier より強い境界になる。

## Verification

すべて**未実装** (H1 で入れる)。

- **V1 最初の 4 シナリオ** (実 catalog + `nimbusbreach-full`、user1。各シナリオは守る性質を故意に壊した変更で赤になることを PR 本文に出力で示す):
  - **E1 (ADR-0027 V6)**: 01〜04 を solve して current = 05。地図で 06 を開くと、`?mission=06` の詳細が `locked` のまま「ヒント 1」の開封と減点 10 を出す。押すと dialog の文に 10 点が出る。
    取消なら書き込み 0、承認なら `POST …/06-web-rce-shell/hints/1` が 1 回で、本文 (catalog から読む) と次の減点 30 が出る。
  - **E2 (ADR-0027 V7 = D6。ADR-0032 の後は `alert` 基準に読み替える: `0032:156`)**: current の evade (05) では従来の「クリーン」の文が出る。current でない evade (10) では V7 の 3 文が出ず、
    中立の表示になる。05 の禁止ルールの発火を ingest に送ると、2 ポーリング以内に dirty の表示と reset ボタンに変わる。
  - **E3 (ADR-0032 ⑩ と reset)**: 05 が dirty の間の閲覧 (ポーリング 3 回以上・地図の node 3 つ・current へ戻る・タブの切替・再読込: H1 (c)) で書き込み要求の列が空。dirty の 05 で reset を
    押して dialog を取消すと空のまま、承認すると `POST …/05-silent-search/reset-dirty` が 1 回だけ。dialog の文が消えるものを名指しする (現行 `pane-story:814-818`。ADR-0032 S4 の後は receipt と証明も)。
  - **E4 (I8 の frame-src 側)**: portal を開くと iframe の src が `https://user1.<suffix>` で、TLS stub がその要求を受け、CSP 違反が 0 (D1 (b))。`frame-src` を壊した変更 (`csp.go:173-177`) と
    suffix を空にした変更 (iframe が作られない) で赤になる。
- **V2 判定の自己テスト (恒久)**: `internal/e2e/testdata` の小さな頁で、(a) 読み込み時に POST する (b) CSP に違反する (`<head>` の中を含む) (c) uncaught error を出す (d) 外部の origin を取りに
  行く (e) 描画の例外を try で捕まえて「connection error」を出す (f) 読み込みの 2 秒後に自動で POST する (g) 1 回のクリックで同じ POST を 2 回出す、のそれぞれを共通 assert が赤にする。
- **V3 静的検査**: `internal/e2e` に `time.Sleep`・`chromedp.Sleep`・`time.After` が無い。製品の template と JS が `data-testid` を読まない。Chromium の起動 flag が allowlist の外に無く、
  `--disable-web-security` と `Page.setBypassCSP` を使わない。
- **V4 境界**: `cmd/*` の 6 本すべて (auth-policy・collector・scoreboard・ttyd-proxy・gen-home-fragments・gen-tutorial-fragments) の、module 内の import の閉包にある package の import (標準・外部を
  含む) に `github.com/chromedp/` と `internal/e2e` が無い。`importsOf` は module 内の import だけを返す (`internal/apispec/mux_ownership_test.go:66-85`) ので、`allImportsOf`
  (`internal/apispec/dependency_boundary_test.go:183-189`) の形で外部も集め、parse は今と同じく build tag を無視する。`//go:build e2e` を持つファイルは `internal/e2e/` の下にだけある。どれも故意の
  破りの fixture で赤になることをテストに持つ。`Dockerfile.test` の `go vet -tags e2e ./...` で E2E のコードがコンパイルされ続ける。すべて `make test` = required。
- **V5 image と所要**: base の digest pin・Chromium と font の exact pin・テストの `RUN --network=none` (loopback が使え、外部に出られないことを実測)。`IMAGES` と build matrix に無い。image の
  大きさと job の所要を実測して PR に貼る (見積を超えたら Signpost 3 で扱う)。
- **V6 判定の fail-closed**: 判定器に次のどれを与えても `make e2e` が非ゼロで終わる — 終了コードが 0 でない / pass の名前が表より少ない・多い / skip が 1 件 / RUN_ID が今回のものでない (前回の
  判定ファイル・cache された層の判定ファイル) / SHA の不一致 / ファイルの欠落・空・読めない行 / ブラウザ不在。各ケースを fixture として恒久化し、required の check (`make test` か `flag-guard`) で回す。
- **V7 昇格の記録**: CHECKS を変える PR に、期間・run 数・flake 数・build stage の失敗の内訳・p95・bump の所要を貼る (D1 (c))。
- **V8 `e2e-serve` の境界**: publish は `-p 127.0.0.1:` だけで、子は loopback で listen する / proxy の upstream は自分が起動した子だけ / `AS` は `validUser` (`api.go:57`) を満たす名前だけを受け、
  email は予約 TLD `.test` の合成ドメインで組む / 子の env に `ADMIN_EMAILS` と `FLAGS_FILE` が無いことを起動時に assert する / proxy の応答の CSP ヘッダは子の応答と同じ / 起動時に出す URL は
  1 つで、拡張の site 許可はその origin だけ (D1 (a) (iii))。設定値の検査は故意の破りの fixture で赤になることをテストに持つ。
- **V9 pin の検知**: D5 の定期 job が、index と違う pin を与えると赤になることを `workflow_dispatch` で示し、PR に貼る。

## Advice

- VP (2026-10-06、発注): D1〜D4 の論点、最初の 3 シナリオを ADR-0027 V6 / V7 と ADR-0032 ⑩ にすること、jsc の拡張だけ・Chrome だけ・Cypress を代替として評価すること。
- qa-engineer R2 (2026-10-07、app#321。HIGH 4・MED 6・LOW 3): HIGH-1 → D2 の共通 assert・V2 (e)。HIGH-2 → D1 (b) の判定・V6。HIGH-3 → D5・D1 (c)・V9。HIGH-4 → D2 の対象外の縮小・E4。
  MED・LOW → H1 の受け入れ条件 (MED-5 の列は D2 の定義に、MED-10 は D3 に、LOW-11 は D1 (b) の env と D3 にも、LOW-12 は V3・V6・D1 (c) にも)。
- security-engineer R1 (2026-10-07、app#321。HIGH 2・MED 4・LOW 2): HIGH-1 → C5 の訂正と D1 (a) (i)〜(iv)。HIGH-2 → D1 (a) (v) と段階 P。MED → V8・V4・D1 (a) の画像の規律・D1 (b) の判定と V6。
  LOW → C6・D5・D1 (b) の CI・D3・V3・H1 (f) (h)。勧め → Signpost 4。妥当と確認: root + `--no-sandbox` の Chromium は既存の `go test` と同じ信頼範囲、I5 の外、identity 注入を製品の外に置くこと。
- VP の査定 (2026-10-07): 採用 10 項目を本文 (Accepted の前提) に、MED・LOW を H1 の受け入れ条件に振り分けた。
- architect の判断 (発注の外): 開発時の起動を compose でなく `e2e-serve` にした (seed を CI と共有し、identity の注入をテスト側に閉じるため)。CI のサーバを in-process でなく実バイナリにした
  (main の組み立ての写しを作らないため)。CEO の「`make test` の層に足す」を「コンテナで回す自動テストの層に、別 target・別 check で足す」と読んだ (理由は Option 3。CEO の確認事項)。改訂で:
  書き込み要求の比較を集合から列に改めた (共通 assert の定義なので D2 に置いた)。全シナリオで `PORTAL_TTYD_SUFFIX` を渡す (iframe は読み込み時に作られるので E4 の外でも stub が要る)。初版の
  昇格条件「pin が index から消えたことを main が赤くなる前に検知できる」は、index が 1 版だけで消える時と赤くなる時が同じなので満たせず、検知から main までの日数に替えた。D1 (a) (v) の対象は、
  `tools:` を持たない 9 職から UI を確かめる 3 職を除いた 6 職と読んだ。
