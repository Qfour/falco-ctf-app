# ADR-0038: identity を理由にした拒否は 4 つの gate (strict・self_or_admin・authenticated・portal) で 1 つの metric `scoreboard_identity_denials_total{gate, reason}` と 1 種類の間引きログに記録し、`no_identity` の事前生成と「健全な本番で 0」を platform との契約にする

- Status: **Proposed** (2026-10-17 起草)。Accepted 化は VP が実装 PR (PR-B) の merge と同じセッションの docs PR で行う (workspace `ORGANIZATION.md` §4 の Class-2 条件 (f))。クロスリポ契約表に行を 1 つ新設するので architect 合意 + VP 承認 (ORGANIZATION.md §4)。新 image・新サービス・Hard Invariant の変更は無いので CEO 判断を要さない。
- Date / Deciders: 2026-10-17 / VP (承認) + architect (起草・契約表の新設行への同意) + security-engineer (D4 の field 規則・log 流量のレビュー) / 実装: software-engineer (PR-B)、qa-engineer (V1〜V8 の derived test と変異 test)、sre-engineer (platform#244 の verify)
- 関連: Issue #404 (#398 review-5x R4#3)、PR #398 (`c7ac02c`、app#387)、platform#244 (sre の判断 2026-10-17)・platform#231、#397 (board の 2 bucket)、#393 / PR #409 (Authz の identity 出所の表、open)、ADR-0023、ADR-0034 (I8)、ADR-0037 (Proposed)。フェーズ: 非該当
- 読み方: app は origin/main `eb76f22` (#405 を含む。`d118788` から api.go の行が +12 ずれている)、platform は origin/main `e126fff`。`conventions` は `.claude/rules/falco-ctf-app-conventions.md`、`api.go` は `internal/scoreboard/api/api.go`、`0037:N` は `docs/adr/0037-*.md` の行。

## Context

- **C1 拒否は 4 か所で起きるのに、metric・alert・間引きは 1 か所 (#398 の strict) にしか無い。**

  | gate | 実装 | 拒否と観測の今 |
  |---|---|---|
  | strict (identity-keyed bucket) | `ratelimit.MiddlewareStrict` (`internal/scoreboard/ratelimit/ratelimit.go:276-302`) | header が無いか空なら 403、token を使わない。`ratelimit_identity_requests_total{bucket, outcome="no_identity"}` (`ratelimit/metrics.go:42-62`) を数え、wrap 時に 0 で事前生成 (`ratelimit.go:278-283`)。bucket ごとに 10 秒 1 行の Warn (`ratelimit.go:304-346`。absent / blank は log の `reason` にだけ出る `:327-330`) |
  | self_or_admin | `selfOrAdmin` (`api.go:1023-1040`) | header 無しで 403 + **間引かない** Warn に `user` (path の値) (`:1027`)。不一致は 403 + Warn に `user` と **`email` (identity の値)** (`:1037`)。metric 無し。GET /me・/journey (`api.go:557,563`。bucket 無し) と POST 5 本 (`api.go:1422,1624,1680,1789`、`internal/scoreboard/api/profile.go:116`) が呼ぶ (POST は strict が先に動く `api.go:535-536`) |
  | authenticated | `requireAuthenticated` (`api.go:910-918`) / `boardIdentity` (`:930-942`) | header 無し 403 + 間引かない Warn (`:913`)。header はあるが seat の正規形でない 403 + Warn (`:937`)。metric 無し。board の 6 route |
  | portal | `GET /portal` (`internal/scoreboard/view/view.go:229-238`、Authz `none`) / `renderPortal` (`view/portal.go:196-204`) | 200 で shell を返す。識別できなければ user = `""`。log も metric も無い |

- **C2 header 欠落の主症状と、新規の読み込みの盲点。** 開いたままの portal は Me 2 秒 (`view/templates/portal/pane-me.tmpl:323`)・Story 2 秒 (`pane-story.tmpl:84`)・Board 5 秒 (`pane-board.tmpl:135`) で poll するので、header が落ちると self_or_admin と authenticated が 1 タブあたり毎秒約 1.2 件の 403 を出す (間引かない Warn がそのまま流れる)。**header 無しで新しく開いた portal では 3 つの pane がどれも止まる** (`pane-me.tmpl:314-324`、`pane-story.tmpl:76-84`、`pane-board.tmpl:85-92`) ので、それ以降の要求は無い。**新規の読み込みで header 欠落を示すのは portal の描画 1 件だけ**で、今はそこに観測が無い。
- **C3 alert。** `ScoreboardNoIdentityDenials` (`charts/scoreboard/templates/prometheusrule.yaml:80-88`) は strict の bucket ごとに「5 分で 10 件超」(`:82`)。read gate は対象外と自分で書いている (`:68-70`)。platform は全環境 `appMonitoringEnabled: false` (platform `helmfile/environments/default.yaml.gotmpl:93`・`prod.yaml.gotmpl:205`・`vm-prod.yaml.gotmpl:114`) なので、どこでも描画されない。sre は当面 false のまま、pull 側の verify を代わりにすると決めた (platform#244)。
- **C4 契約の時機。** metric 名が出てくるのは app だけ (`docs/openapi-scoreboard.yaml:603`、`docs/detect-challenge-design.md:122`、`prometheusrule.yaml:82`、`CHANGELOG.md:90`)。platform main には 0 件 (`e126fff` を git grep)。sre は「#404 で形が決まって契約表に行が入ってから読む」と条件を付け、platform が依存するのは metric 名・label・値 `no_identity`・0 起点の事前生成の 3 点、`bucket` は表示用とした (platform#244)。**改名できるのは今が最後**で、platform が読み始めた後の改名は両リポ同時 PR になる。
- **C5 健全な本番での下限は、構造上 0。** scoreboard に届く送り手は falco・ingress-nginx・collector の 3 namespace だけ (`charts/scoreboard/templates/networkpolicy.yaml:19-47`)。falcosidekick が叩くのは `/falco/events` だけ。collector が転送するのは submit と exfil だけで (`internal/collector/collector.go:162-180`)、どちらも identity gate ではない。ingress は auth-url と identity header の上書きを必ず通る (I8 の前提 (1)、`conventions:30`、V12)。参加者の portal は auth-policy が正規形を付けた要求しか届かない。よって、**健全な本番では header 無しや非正規形の要求は identity gate に届かない**。届いたら I8 の前提が崩れたか、誰かが手で叩いたかのどちらか。
- **C6 制約。**
  - (a) **collector は `ratelimit` と `httpx` を link し** (`collector.go:62`)、image に名前で COPY する (`collector/Dockerfile:13-15`)。collector の image build は required check ではない (`0037:37`)。`ratelimit` に新しい import を足すと、CI は緑のまま collector の image だけが壊れる。
  - (b) `internal/identity` は stdlib だけで、auth-policy の image に COPY される (`internal/identity/identity.go:7-8`)。collector には COPY されない。
  - (c) metric に per-user の label を置かない (`internal/scoreboard/metrics/metrics.go:3-6`)。route ごとの 403 の件数は既に `scoreboard_http_request_duration_seconds{route, method, status}` にある (`internal/scoreboard/server.go:334-340`、`metrics.go:156-169`)。
  - (d) scoreboard の log は JSON (`cmd/scoreboard/main.go:29`)。auth-policy は seat 単位の拒否に msg `identity denied` を使い、seat だけを出す。生の email を出すのはロスターに無い identity のときだけ (`internal/authpolicy/server.go:274-285`)。
  - (e) ADR-0037 (Proposed) は bucket の label 値を動かさない (`0037:41`)。名前は metric label と同じ (`0037:85`)。V5 (d) は「`no_identity` の counter が送った数だけ動く」を見る (`0037:181`)。D8 は #397 を (a)、つまり board も strict にする方向で助言している (`0037:152`)。
- **C7 `EXPECTED_EMAIL_DOMAIN` のずれは、今は実行時に誰にも見えない。** scoreboard は空の domain でも起動する (`internal/identity/identity.go:142-149`、`cmd/scoreboard/identity.go:25` の `true`)。chart は空なら env を省き、その結果どの email も参加者本人にならない (`charts/scoreboard/templates/deployment.yaml:94-100`)。参加者は全員 403 になり、空の portal が出るが、operator には何も届かない。platform main はこの値を auth-policy にしか渡していない (platform `helmfile/releases/auth-policy/values.yaml.gotmpl:12`)。S2 ブランチは 2 つの release に 1 つの値から渡す (platform `feat/adr-0034-s2-identity-platform`: `helmfile/releases/scoreboard/values.yaml.gotmpl:31`)。契約表の「Identity 表と正規形」行 (2) は同じ値を要求している (`conventions:383`)。pin の順序を誤ったときや将来の手書きのずれを、実行時に知らせるものが無い。

## Options

### O1 (推奨). 新しい metric `scoreboard_identity_denials_total{gate, reason}` を scoreboard 専用の package に置き、4 gate がそこへ記録する。`ratelimit_identity_requests_total` は `allowed|limited` だけにする
- 変更点: 観測点 (metric・語彙・事前生成・間引き・log の形) を 1 つの package にまとめ、strict は組み立て時に受け取る observer 経由でそこに記録する。
- コスト: 運用 = platform が読み始める名前は新しいもの 1 つだけ (今はまだ何も読んでいない)。認知 = 語彙 1 組 (gate 4 × reason 3、宣言する組は 8) と log の msg 1 つ。依存 = module 内に package が 1 つ増える (prometheus は既存の依存)。image size は変わらない。collector の閉包には入らない (V7)。
- リスクと可逆性: 今の改名は無償 (C4)。platform が読み始めた後に戻すと両リポ同時 PR。将来、通過も含めた「判定」の counter が要っても、別の metric として足せばよく、この契約には触れない。
- 効き始める閾値: deploy した最初の起動から。起動時に 0 の系列があるので、最初の 1 件から `increase()` と verify に見える。

### O2. `ratelimit_identity_requests_total{bucket, outcome}` を保ち、`gate` label を足して、read gate と portal を `bucket=""` / `outcome="no_identity"` で数える
- 変更点: 既存の metric に label を 1 つ足す。
- コスト: platform は影響を受けない (platform#244 の「(a)(b) は変わらない」)。認知 = label の組み合わせで意味が変わる metric になる。
- リスクと可逆性: strict は要求をすべて (allowed・limited も) 数えるのに、他の 3 gate は拒否しか数えないので、metric 全体の `sum()` が意味を失う。4 gate のうち 3 つで `bucket` が空になる。`ratelimit_` の接頭辞が、triage の目を rate-limit の設定へ向けてしまう。platform が読み始めると、この誤った名前が恒久のクロスリポ契約になる。戻せるのは今だけ。
- 効き始める閾値: 検出の速さは O1 と同じ。代償は、誰かが sum を取るか alert を書いた時点ですぐに現れる (alert は outcome と gate の両方で絞る必要がある)。

### O3. 判定をすべて数える `scoreboard_identity_checks_total{gate, result}` (`ok`・`ok_admin` を含む。`auth_policy_checks_total{endpoint, result}` と同じ型、`internal/authpolicy/metrics.go:8-21`)
- 変更点: identity gate を通過した要求も記録する。
- コスト: 識別できた要求 (1 要求で最大 2 gate) のたびに counter を 1 つ増やす。CPU は無視できるが、通過経路の呼び出し箇所が拒否経路と同じ数だけ増え、それを揃えておく必要がある。系列は約 14 本。
- リスクと可逆性: 通過の記録を 1 か所忘れると、比率が黙って歪む。分母は `scoreboard_http_request_duration_seconds_count{route}` (`server.go:334-340`) と重複する。O1 に後から別の metric として足せる。
- 効き始める閾値: alert か verify に比率が要るとき。つまり、ある gate の `no_identity` / `non_canonical` の下限が構造上 0 でなくなったとき (Signpost 1)。

## Decision

**O1 を採る。** 理由: platform が読み始める前の今だけ、名前・label・意味を一致させて 1 つの観測点にできる。sum が意味を持ち、label の値が空にならない形は O1 にしか無い。

### D1. metric の形
- `scoreboard_identity_denials_total{gate, reason}` (counter。Namespace `scoreboard`、Subsystem `identity`)。
- **1 要求につき 1 回、拒否した gate で数える。** strict が拒否すると handler が動かないので、self_or_admin や authenticated で二重に数えることは無い。strict を通って self_or_admin で不一致になった要求も 1 回だけ。
- **label は 2 つだけ。** `bucket`・`route`・user は置かない。bucket は route から導けて、表示用でしかない (platform#244)。route ごとの 403 は C6 (c) の HTTP histogram にあり、per-user は C6 (c) の規則に反する。
- `ratelimit_identity_requests_total{bucket, outcome}` の outcome は `allowed|limited` だけにする (事前生成も 2 つ)。「bucket に届いた要求」という意味がこれで正確になり、strict の 403 を 2 つの metric で数えることも無くなる。旧名と旧い outcome は契約表に書かない。
- Help (例): "Requests an identity gate refused for lack of a usable proven identity, by gate and reason. gate=portal counts portal shells served without a usable identity (the identity panes stay empty). In healthy production reason=no_identity and reason=non_canonical stay 0."

### D2. 語彙 (閉じた集合。どの宣言も使わない語は置かない = ADR-0037 D1 と同じ規律)
- `gate`: `strict` (identity-keyed bucket の fail-closed な前段) / `self_or_admin` / `authenticated` / `portal`。
  - VP の案 `read` は `self_or_admin` にした。この gate は POST 5 本 (C1) も守るので、`read` では書き込みの不一致を誤って名付けてしまう。
  - VP の案 `board` は `authenticated` にした。gate は route の家族ではなく Authz の分類 (`internal/apispec/route.go:98`) で、#397 (a) の後は board の POST の header 欠落を strict が先に拒否する。
- `reason`: `no_identity` / `non_canonical` / `mismatch`。
  - `no_identity`: `X-Auth-Request-Email` が無いか、trim すると空。**VP の案の `empty_identity` は `no_identity` に畳む。** #398 の metric は既に両方を `no_identity` と数えている (`ratelimit.go:286-287`)。分けると、platform は 2 つの値を読まない限り、空 header の事故を黙って取りこぼす。absent と blank の区別は log の `header` field に残す。
    - 仮説 (この判断を支える根拠ではない): ingress-nginx は値が空の header を upstream に渡さないので、ingress 経由の欠落は absent になり、blank は手作りの要求でしか起きない。
  - `non_canonical`: header はあるが、正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` でも、その gate が通す `ADMIN_EMAILS` でもない。原因は設定にある (C7、または auth-policy が正規形を付けていない = I8)。
  - `mismatch`: 正規形の、別の seat (self_or_admin だけ)。原因は参加者の行動 (URL の書き換え) にあり、0 にならない。
  - **`non_canonical` を `mismatch` から分ける理由**: 原因が「設定」と「行動」で違い、alert と verify が見るのは前者だけ。
- **宣言する組 (起動時に 0 で事前生成。8 本)**:

  | gate | reason |
  |---|---|
  | strict | no_identity |
  | self_or_admin | no_identity, non_canonical, mismatch |
  | authenticated | no_identity, non_canonical |
  | portal | no_identity, non_canonical |

  - strict × non_canonical は届かない。strict は空でないかしか見ず、通った後で self_or_admin が判定する。
  - 全 gate に `reason="no_identity"` の系列があるので、platform の「系列が 1 本も無い = 判定不能」の検査が、どの gate についても成り立つ。
- **判定は gate が持ち、helper は記録だけをする。** self_or_admin の拒否は `UsernameFromEmail(email, domain) == ""` (`api.go:450`) なら `non_canonical`、そうでなければ `mismatch`。boardIdentity が使えない identity として返す拒否 (`api.go:937`) は `non_canonical`。portal は `!isAdmin && user == ""` のとき、header が absent か blank なら `no_identity`、そうでなければ `non_canonical`。応答は今と同じ 200 の shell。admin・正規形の参加者・本人の要求は記録しない。
- **admin gate (`isAdmin`、11 箇所) は範囲外。** 語彙に `admin` を置くのは、配線する PR のときだけにする (Signpost 4)。

### D3. helper の置き場と依存の向き
- **新しい package `internal/scoreboard/identityobs`** に置く。中身は metric・語彙 (型付き定数)・宣言する組と事前生成 (init)・間引き・log の形・入口 1 つ (`Record(r, gate, reason)` のような形。名前は software-engineer が決める)。計数は package レベルの metric で無条件に行う。間引きの clock と logger だけを test から差し替えられるようにする (nil なら `time.Now` / `slog.Default()`)。
- **`ratelimit` は `identityobs` を import しない (C6 (a))。** `MiddlewareStrict` (ADR-0037 D2 では宣言から middleware を組み立てる関数) は、組み立て時に **必須の observer** を受け取り (nil なら組み立て時に失敗)、header 無しの 403 を返す直前に呼ぶ。scoreboard の api が `identityobs` の strict 用 observer を渡す (`api.go:535-536`)。こうすると collector は `identityobs` を link せず、その metric の系列も出さない。
- `ratelimit` に置かない理由: portal と read gate は rate-limit の関心ではない。置けば `ratelimit_` の名前と同じく境界が曖昧になる。`internal/identity` に置かない理由: stdlib だけの package で auth-policy の image に入り、collector には COPY されない (C6 (b))。
- identity header の名前の定義は 1 つにする。置き場は collector の閉包に既にあって新しい import 辺を作らない `internal/scoreboard/httpx` か、`identityobs` が `ratelimit.IdentityHeader` (`ratelimit.go:247`) を import する形。`ratelimit` から `internal/identity` は使えない。

### D4. log の形と間引き (1 種類)
- msg は定数 **`identity gate denied`**。reason を msg に埋めると JSON log で絞り込めない。auth-policy の `identity denied` (C6 (d)) とは別の出来事なので、同じ文字列にしない。
- **field はちょうど 6 つ**:
  - `gate`
  - `reason`
  - `route`: `r.Pattern`。mux の pattern で、path ではない。
  - `remote_addr`: TCP の相手の host、port 無し。triage の鍵で、ingress-nginx の Pod IP か、collector の Pod IP か、それ以外かを見る (`prometheusrule.yaml:72-79` の表)。XFF / CF-Connecting-IP は参加者が影響できるので使わない。
  - `header`: `absent` | `blank` | `present`
  - `suppressed`
- **出さないもの**: header の値、URL の path と path parameter (`user` を含む)、query。`mismatch` でも呼び手の seat は出さない (Consequences の「諦めたもの」)。
- **間引きの key は (gate, reason)**、10 秒に 1 行。最初の 1 件はすぐ出し、残りは `suppressed` として次の行に載せる (今の `ratelimit.go:304-325` と同じ)。VP の案の「gate ごと」を (gate, reason) にしたのは、ある reason の大量の流れ (2 秒の poll の `no_identity`) が、同じ gate の別の reason (`mismatch`) の最初の 1 行を隠さないため。
- key は宣言した 8 つの定数で、要求から作らない。だから map は伸びず、行の上限は流量に関係なく 0.8 行/秒。間引き用の lock は limiter の lock と分ける (`ratelimit.go:38-41` と同じ理由)。
- 間引かない今の行 (`api.go:913, 937, 1027, 1037`) と `logNoIdentity` (`ratelimit.go:304-346`) は、この 1 種類に置き換える。

### D5. alert (1 本)
```yaml
- alert: ScoreboardIdentityDenials
  expr: |
    sum by (gate, reason) (increase(scoreboard_identity_denials_total{reason=~"no_identity|non_canonical"}[5m])) > 0
  labels: {severity: warning, component: scoreboard}
```
- **gate ごとの閾値は持たず、全 gate で `> 0` にする。** C5 のとおり、健全な本番での下限が構造上 0 なので、0 より上の閾値は検出を遅らせるだけ。しかも遅れが最も大きいのは portal で、ページ読み込み 1 回につき 1 件しか出ず、新規の読み込みではそれが唯一の信号 (C2)。`> 10` のままにすると、portal だけで発火させるには 5 分で 11 回の読み込みが要る。
- `mismatch` は alert に含めない (参加者の行動)。
- 描画されると、手での `kubectl port-forward` + curl でも発火する。identity gate に identity 無しで届いたという意味では正しい。warning で、5 分で解消する。
- `ScoreboardNoIdentityDenials` (`prometheusrule.yaml:65-88`) は置き換える。description は reason 別の triage:
  - `no_identity`: `remote_addr` を見る。ingress-nginx の Pod IP なら auth-url / auth-response-headers が壊れた (I8 前提 (1))。collector の Pod IP なら転送表が identity route に伸びた (ADR-0034 D12、ADR-0037 V7)。それ以外なら NetworkPolicy が効いていない。
  - `non_canonical`: auth-policy と scoreboard の `EXPECTED_EMAIL_DOMAIN` が違うか空、または auth-policy が正規形を付けていない。
- `monitoring.enabled` は false のまま (sre)。push 側はこの rule を成果物として描画検査 (V5) で守る。pull 側の検出器は platform#244 の verify。

### D6. クロスリポ契約表に新設する行 (`conventions:381`「Webhook 流量制限 (app#359)」の次。実装 PR に同梱)

| 接点 | 詳細 |
|---|---|
| identity 拒否の観測 (app#404、ADR-0038) | scoreboard の identity gate が identity を理由に拒否した要求 (identity-keyed bucket の strict middleware・`selfOrAdmin`・`requireAuthenticated` の 403) と、識別できない呼び手に返した portal の shell (`GET /portal`、200 のまま) を、**metric `scoreboard_identity_denials_total{gate, reason}` の 1 本**で数える (1 要求につき、拒否した gate で 1 回)。**`reason`**: `no_identity` (`X-Auth-Request-Email` が無いか空) / `non_canonical` (header はあるが、正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` でも、その gate が通す `ADMIN_EMAILS` でもない) / `mismatch` (正規形の別 seat。参加者の操作で 0 にならない)。**app の保証**: (1) 健全な本番では `no_identity` と `non_canonical` は 0 (header 無しや非正規形で identity gate に届く経路が無い = I8 の前提と「Identity 表と正規形」行の (2))、(2) **全 gate の `reason="no_identity"` の系列が起動時に 0 で存在する** (系列が無い = 契約違反。platform は「0 件」ではなく判定不能と扱う)、(3) 値は Pod の起動からの累計 (in-memory、Recreate で 0)。`gate` は表示用で、値の集合を固定しない (gate と reason の値を足すのは app 単独でよい)。**platform** の verify は `reason="no_identity"` の非 0 を WARN として読む (FAIL にしない。`non_canonical` を読み始めても契約の変更は要らない)。metric 名、label 名 `reason`、`no_identity` と `non_canonical` の意味、事前生成を変える PR は両リポ同時。gate を外す・reason を畳む変更は security-engineer のレビュー必須 |

### D7. #398 からの移行と順序 (HTTP の status と body は変えない。portal は 200 のまま)
- **PR-A (docs、Class-0)**: 本 ADR (Proposed) と `docs/adr/README.md` の索引の 1 行。
- **PR-B (実装、Class-2 = クロスリポ契約 + auth の gate の経路。security-engineer のレビュー必須)**:
  1. `identityobs` を新設する (D1〜D4)。
  2. `ratelimit` を変える。
     - `logger`・`denyMu`・`denyLog`・`denyState`・`denyLogInterval`・`WithLogger` を消す (`ratelimit.go:35-53, 79-86`)。
     - `logNoIdentity` を消す (`:304-346`)。
     - `MiddlewareStrict` に必須の observer を足す (`:276-302`)。
     - `identityOutcomes` を `allowed|limited` にする (`:258-260`)。
     - `metrics.go:42-62` の doc と Help を直す。
  3. api を変える。
     - `selfOrAdmin` (`api.go:1023-1040`)、`requireAuthenticated` (`:910-918`)、`boardIdentity` (`:930-942`) を `identityobs` に記録する形にし、間引かない Warn 4 行を消す。
     - `api.go:372-373` の `.WithLogger(logger)` を外す。
     - `:535-536` で strict の observer を渡す。
  4. view: `portal` (`view.go:360-378` / `portal.go:196-204`) に D2 の条件で記録を足す。
  5. chart: `prometheusrule.yaml:65-88` を D5 に置き換える。
  6. 文書を直す。
     - `docs/openapi-scoreboard.yaml:599-608` の description。spec は実装の記述なので同じ PR で直す。
     - `docs/detect-challenge-design.md:121-130`。
     - CHANGELOG に新しい項を足す (`:90` は履歴として残す)。
     - 契約表に D6 の行を足す。
  7. test: `ratelimit_test.go:407-428, 450-464, 578-604` と `identity_bucket_test.go:185` の `no_identity` を新しい metric に移す。V1〜V8 は**新しい file** に置き、PR #409 が触る `authz_test.go` などとはぶつけない。
- 大きさ (1 PR 400 行 / 15 file) を超えるなら、V5 (alert と code の検査。test だけ) を後続の test PR に回す。どこでも描画されない rule なので先送りの害が最も小さい。契約表の行と spec の記述は PR-B から外さない。
- **順序**:
  1. PR-B は ADR-0037 S1a より先にする。どちらも `ratelimit.go` と `api.go` を触る (同じ file の PR は 1 本)。#404 の方が小さく、platform#244 を止めている。S1a の V5 (d) も最終形の counter を最初から読める。
  2. #397 は前後どちらでもよい。(a) なら board の POST の `no_identity` が gate=strict に移るだけで、契約は変わらない。#397 は #404 の「急ぐ合図 (c) 3 本目の identity-keyed bucket」に当たるので、#397 を先に入れるなら #404 も同じ週に入れる。
  3. PR #409 が先に入れば、V1 の route の選び方は `IdentitySource == proven` かつ Authz ≠ admin に変える。
  4. platform#244 の PR は、PR-B が main に入り、platform の pin がこの metric を出す image になってから merge する (sre の順序)。PR 本文で相互にリンクする。

## Consequences

- **諦めたもの**
  - **`mismatch` の帰属。** 今の `api.go:1037` は呼び手の `email` (正規形の seat) を全件出しているが、それを消す。新しい行は間引くので帰属が部分的になり、「誰が覗いたか」の台帳にはならない。log は「起きている、counter を見よ」という指し示し (`ratelimit.go:44-47` の考え方) にとどめ、帰属が要るなら別の仕組みにする (Signpost 2)。
  - metric の上で、`no_identity` を bucket 別には見られなくなる (log の `route` から導く)。absent と blank の区別も log にしか残らない。
  - admin gate (`isAdmin`) の拒否は観測の外に残る (V1 は Authz = admin を語彙で除く。route の列挙はしない)。
  - **既知の穴 (#397 が (b) のままの間)**: board の 2 bucket は header 無しを client IP で数えるので (`api.go:547-548, 887-895`)、IP の burst を越えた header 無しは limiter の 429 になり、`requireAuthenticated` に届かず記録されない (ADR-0037 C5 `0037:34-35`)。HTTP histogram の 429 にしか残らない。#397 (a) (strict に揃える) で閉じる。本 ADR は #397 (a) を支持する理由を 1 つ足す。
- **新たに守るもの**
  - D2 の語彙の規律 (V6)。
  - 「1 要求につき 1 回、拒否した gate で」(V1)。
  - 全 gate の `no_identity` を事前生成すること (V3)。
  - log の field 集合 (V4)。
  - collector の閉包に `identityobs` を入れないこと (V7)。
  - 契約表の D6 の行 (Hard Invariant にはしない。観測であって強制ではない)。
- **ADR との関係**
  - ADR-0037 V5 (d) の「`no_identity` の counter」は、以後 `scoreboard_identity_denials_total{gate="strict",reason="no_identity"}` を指す。ADR-0037 の本文は書き換えない (Accepted 化の PR で Status に導線を足す。`docs/adr/README.md:71-79` の例外)。
  - ADR-0034 の I8 の前提 (1) と「Identity 表と正規形」行 (2) には、実行時の検出器ができる (I8 の文言は変えない)。
- **他ロールへの影響**
  - software-engineer: PR-B。
  - qa-engineer: V1〜V8。
  - security-engineer: PR-B の D4 (PII・流量) と「mismatch の帰属を諦めること」。
  - sre-engineer: platform#244 の verify (名前は D6 の 1 つだけ)。platform `docs/operations.md` §6.2 の手動 1 行も新しい名前で書く。
- **runbook**
  - 監視は pull だけなので、開催中の検出の遅れは「次に verify を回すまで」になる (sre の判断として受け入れる。Signpost 3)。
  - triage は D5 の description をそのまま使う。

## Signposts (この決定を覆す観測可能な信号)

1. **健全な本番で、identity gate に header 無しか非正規形で届く正当な呼び手が現れる** (新しい内部サービス。または ADR-0037 V7 / ADR-0034 D12 を覆して collector が identity route を転送する) → 下限が 0 でなくなる。gate ごとの閾値か比率に移り、分母のために O3 を**別の metric として**足す。この metric の名前と契約は変えない。
2. **開催中に `mismatch` の呼び手を特定する必要が生じたのに、間引いた行からは特定できなかった** (security・運営の記録) → `mismatch` 専用の監査経路を別に設計する (seat 単位の label にはしない。C6 (c))。この行に identity を足して済ませない。
3. **platform が `monitoring.enabled` を Alertmanager の受け手付きで true にする** (sre の次の段)、または **pull だけの検出遅れが原因で、開催中の header 欠落に気づくのが 15 分以上遅れた** → severity と `for` を見直し、新規の読み込みの唯一の信号である `gate="portal"` の通知の経路を決める。
4. **5 つ目の identity gate を足す** (admin gate を載せる、ttyd-proxy や collector が identity を読むようになる)、または **間引いた後でも 1 開催の `identity gate denied` が 1,000 行を超える** → 語彙を足す (足すのは app 単独でよい、D6) か、間引き (間隔・key) を見直す。

## Verification (すべて `make test` = required の `test / go-test` に載せ、exit status で判定する)

- **V1 被覆と 1 回 (`Routes()` から導出)**:
  - Authz が `self-or-admin` か `authenticated` の route を、すべて production の配線で試す (PR #409 の後は `IdentitySource == proven` かつ Authz ≠ admin)。origin-guard のある route には許可された Origin を付け、header を absent と blank の 2 通りで送る。**要求ごとに新しい handler を使う** (board の bucket は 2 route で共有され、burst 3 を越えると 429 になる。Consequences の既知の穴)。
  - 期待: 応答は今と同じ 403。`sum(scoreboard_identity_denials_total{reason="no_identity"})` が 1 要求ちょうど 1 増える。動いた系列の gate は、route が identity-strict の bucket を宣言していれば `strict` (ADR-0037 S1a の宣言。それまでは `identity_bucket_test.go` の表)、そうでなければ Authz の gate。
  - 試した route の数は、導出した対象の数と等しく、1 以上。
  - `GET /portal` は名前で 1 件足す。identity を導けない Authz `none` の route として、表示を持つのはこれだけ。
- **V2 header の状態ごとの reason**:
  - self_or_admin の route: 本人 → 0 件、admin → 0 件、正規形の別 seat → `mismatch` +1、非正規形 → `non_canonical` +1。
  - authenticated の route: 正規形 → 0 件、非正規形 → `non_canonical` +1。
  - portal: admin → 0 件、正規形 → 0 件、absent / blank → `no_identity` +1、admin でない非正規形 → `non_canonical` +1。どの場合も応答は 200 で、`__PORTAL_USER__` は今と同じ。
  - `EXPECTED_EMAIL_DOMAIN` を空にして配線すると、参加者の portal は `non_canonical` になる (C7 の検出器)。
- **V3 事前生成**: production の handler を組み立てた直後、要求を送る前に gather した `scoreboard_identity_denials_total` の label の組が、D2 の 8 本ちょうどである。`reason="no_identity"` は全 gate にある。`ratelimit_identity_requests_total` には `no_identity` の系列が無い。
- **V4 log の規則** (clock と JSON logger を差し替えて確かめる):
  - (a) (gate, reason) ごとの最初の 1 件で、ちょうど 1 行が出る。key は time・level・msg とその 6 field だけ。msg は `identity gate denied`。
  - (b) 10 秒の間は同じ key の行が出ない。10 秒後の行は `suppressed = N` を持つ。
  - (c) ある reason が大量に流れても、同じ gate の別の reason の最初の 1 行は出る。
  - (d) header の値と path に一意の sentinel を入れて送ると、出力のどこにも sentinel が現れない (`user` の path parameter も同じ)。
  - (e) `remote_addr` に port が付かない。
- **V5 alert と code の一致**: `helm template charts/scoreboard --set monitoring.enabled=true` を描画し (V12 と同じく、helm が無ければ fail)、PrometheusRule の expr に出てくる `scoreboard_*` と `ratelimit_*` の metric 名が、すべて scoreboard の process に登録されていることを確かめる。identity の rule が選ぶ `reason` の値は、宣言した語彙の中にあり、`no_identity` と `non_canonical` を含み、`mismatch` を含まない。
- **V6 語彙**: `gate` と `reason` の定数は、すべて non-test code で 1 回以上使われる。宣言した組は gate × reason の部分集合である。V1 と V2 の driver が、宣言していない組を記録しない。
- **V7 collector の閉包**: `cmd/collector` の module 内の import 閉包 (`internal/apispec/dependency_boundary_test.go:72-90` の `transitiveModuleImports`) に、`internal/scoreboard/identityobs` が無い。あわせて、閉包の各 package の directory を `collector/Dockerfile` が COPY している (`internal/apispec` は ADR-0037 V4 の file 集合の検査に任せる)。
- **V8 検査が嘘でないこと** (変異を常設の test にする)。次のそれぞれで赤になる:
  - selfOrAdmin の `no_identity` の記録を消す (V1)。
  - portal で gate を self_or_admin と記録する (V2)。
  - `mismatch` と `non_canonical` を入れ替える (V2)。
  - 事前生成を消す (V3)。
  - log に `email` field を足す (V4 (a)(d))。
  - 間引きの key を gate だけにする (V4 (c))。
  - rule の metric 名を 1 文字変える (V5)。
  - 使わない gate の定数を足す (V6)。
  - `ratelimit` から `identityobs` を import する (V7)。
  - `MiddlewareStrict` に nil の observer を渡す (組み立て時の失敗)。
- **この検査が見ないもの**: 実クラスタで ingress が header を落としたときに本当に数が増えるか (実機でのみ確認可。platform#244 の verify と次の stand-up で見る)、Prometheus の評価、Alertmanager。

## Advice (受けた助言。非拘束でも記録する)

- **Issue #404 (#398 review-5x R4#3、2026-10-17)**: 3 gate と portal が同じ metric・間引き・field 規則を使う。gate = strict | read | board、reason、portal は canary、platform が読む前に形を決める。→ すべて採用し、語の名前だけ D2 で改めた。
- **VP (2026-10-17、本 ADR の発注)**: 名前を保つか改名するか (今が最後の機会)、`gate` = strict | read | board | portal、`reason` = no_identity | empty_identity | mismatch、bucket は strict 以外では空か省略、全 gate で 0 起点の事前生成、`identity denied: <reason>` + gate / route pattern / remote_addr / suppressed、identity の値と path は出さない、gate ごとに 10 秒 1 行、helper は `ratelimit` か `identityobs`、alert の gate 別の閾値、契約表に「Webhook 流量制限」行と同形の 1 行、ADR の要否、CEO の要否。→ 次のように扱った。
  - 改名する (O1)。
  - `read` は `self_or_admin`、`board` は `authenticated` にする (D2)。
  - `empty_identity` は `no_identity` に畳み、`non_canonical` を新設する (D2)。
  - bucket は metric から外す (D1)。
  - msg は定数、reason は field にする (D4)。
  - 間引きの key は (gate, reason) にする (D4)。
  - helper は `identityobs` に置き、strict は observer を受け取る (D3)。理由は collector の制約 C6 (a)。
  - 閾値は全 gate で `> 0` にする (D5)。
  - 行の文面は D6。
  - ADR を新設し、CEO の判断は不要とする (Status)。
- **sre-engineer (platform#244、2026-10-17)**: platform が依存するのは名前・label・`no_identity`・0 起点の事前生成の 3 点で、bucket は表示用。WARN で読み FAIL にはしない。系列が無ければ判定不能として扱い、これが改名の検出器にもなる。行は最終形の PR に同梱する。platform の PR は app の main と pin の後。`monitoring.enabled` は false のまま。→ D6 と D7 にそのまま入れた。label 名は `outcome` から `reason` に変わるが、platform はまだ実装していない。`non_canonical` を読むかどうかは sre が判断する (契約の変更は要らない)。
- **ADR-0037 D8 (architect、#397)**: board を strict に揃える。→ 本 ADR はどちらの結論でも成り立つ (D7)。
- **security-engineer**: 未受領。PR-B のレビューで次を受け、ここに追記する。
  - D4 の field の集合。
  - `mismatch` の帰属を諦めることの可否。
  - 間引き key が固定であること。
  - `/metrics` が参加者の allow-list に無いこと (I15) の再確認。
