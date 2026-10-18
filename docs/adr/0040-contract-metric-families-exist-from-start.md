# ADR-0040: 契約表で名指しした metric family は所有 binary の起動直後から存在させる (family が無いことは「改名か旧 image」で、0 とは読まない)。事前生成の置き場は package を link する binary の数で決め、契約表から導いた表駆動の test 1 本で確かめる

- Status: **Proposed** (2026-10-19 起草)。
  - Accepted 化は VP が行う (時限承認: workspace `ORGANIZATION.md:470-472`。S1 の merge より前)。
  - クロスリポ契約表に、全行に効く一般則 (D1) と metric の名指し方 (D3) を足し、「Rate-limit client-IP ヘッダ」の行の metric 名を訂正する (D5)。だから architect 合意 + VP 承認が要る (`ORGANIZATION.md` §4)。
  - HTTP の status と body は変えない。`/metrics` に 0 の系列が 6 本増えるだけ (D5)。
  - 新 image・新サービス・Dockerfile・Hard Invariant に触れないので、CEO 判断を要さない。
  - 実装は Proposed のまま始めてよい。
- Date / Deciders: 2026-10-19 / VP (承認) + architect (起草・契約表の規則と行の訂正への同意) / 実装: software-engineer (S1)、qa-engineer (V3 の変異)、sre-engineer (platform#245 / #247 の「family 無し = rc 2」への切替と、platform の文書の metric 名の訂正)
- 関連:
  - Issue #450 (発注元。#448 review-5x R4#1 / R3#2 / R4#2)
  - #412 / PR #448 (`e64d5ae`。ingest の 2 family の事前生成)、#463 / PR #469 (`b7a37cb`。`NSCounter` の内側の `_other`)
  - #404 / PR #424 (identity。ADR-0038)
  - app#387 (`MiddlewareStrict` の組み立て時の事前生成。D2 の先例)
  - PR #467 (Limiter の上限。方針は ADR-0037 rev2 で記録する予定)
  - ADR-0023 (client-IP の観測)、ADR-0037 (Proposed。rate-limit の宣言)、ADR-0038 (D2 / D6 / V3 / Accepted 時の追補 (b) = V9)
  - platform#244・#245・#247
  - フェーズ: 非該当
- 読み方:
  - app は origin/main `b7a37cb` (#469 を含む)。
  - platform は origin/main `e126fff` と branch `feat/verify-scoring-overflow` (`2f77d04`、platform#245)。
  - `conventions` は `.claude/rules/falco-ctf-app-conventions.md`、`0038:N` は `docs/adr/0038-*.md` の行。
  - platform#247 の本文は、この起草では読めていない (GitHub API の rate limit)。中身は VP の発注にある「family 無し = rc 2 の切替」に拠る。

## Context

- **C1 「起動直後から存在する」は、契約行ごとの個別の判断として 2 回書かれた。一般則が無い。**
  - identity: `scoreboard_identity_denials_total{gate, reason}` は、宣言した 8 組を package の初期化で 0 から作る (`internal/scoreboard/identityobs/identityobs.go:125,141-146`。ADR-0038 D2 `0038:72-82`、V3 `0038:201`)。契約行は「全 gate の `reason="no_identity"` の系列が起動時に 0 で存在する (系列が無い = 契約違反。platform は「0 件」ではなく判定不能と扱う)」と書く (`conventions:382`)。
  - ingest: `scoreboard_ingest_falco_events_scoring_overflow_total{ns}` と `scoreboard_ingest_falco_events_rate_limited_total{ns}` は、`ns="_other"` を package の初期化で 0 から作る (`internal/scoreboard/metrics/metrics.go:68-80,140,157`)。#448 で入り、#469 で `NSCounter` の内側に移った。契約行は「2 つの family は起動直後から存在する … family 無し = 改名か旧 image であり、「0」とは読まない」と書く (`conventions:381`)。
  - 3 つ目の候補 (`conventions:392` の client-IP の行) には、事前生成も契約の test も無い (C3)。
- **C2 なぜ事前生成が要るか。理由は 2 つある。**
  - (a) label の付いた family は、子の系列が 1 本も無いと `/metrics` に現れない (`# TYPE` の行も出ない)。platform の verify は今これを「0」でなく「未検証」と読み、app#412 が image に入ったら「読めない (rc 2)」に切り替える (platform `docs/operations.md:895-898`、branch `feat/verify-scoring-overflow`。その切替が #247)。family が無いことを 0 と読めば、改名と旧い image を「異常なし」と読む。
  - (b) 1 から生まれた系列は、Prometheus の `increase()` に増分を残さない。最初の 1 件を数えるには、先に 0 の sample が要る (`internal/scoreboard/ratelimit/ratelimit.go:335-337` の comment、app#387)。
- **C3 契約表の client-IP の行の metric 名は、出ている family と合っていない。**
  - 行は `client_ip_source_total{source}` と書く (`conventions:392`)。実際の family は namespace が `ratelimit`、label が `caller` と `source` の `ratelimit_client_ip_source_total{caller, source}` (`internal/scoreboard/ratelimit/metrics.go:33-40`)。
  - 事前生成も無い。系列は、`ClientIPKeyed` の keyFn が最初の要求を数えたときにできる (`ratelimit.go:269-275`)。だから起動直後の scoreboard に、この family は無い。
  - platform の main には、短い名前の PromQL の文例が文書に 1 つあるだけで (platform `docs/verification-gates-2026-08.md:757-760`)、読む script は無い (`e126fff` を git grep)。
- **C4 package を link する binary の数で、事前生成の置き場の意味が変わる。**
  - `identityobs` と `scoreboard/metrics` は、scoreboard の binary だけが link する (identityobs が collector の閉包に入らないことは ADR-0038 V7 が固定している)。
  - `ratelimit` は、scoreboard と collector が link する (`collector/Dockerfile:15`、ADR-0038 C6 (a) `0038:24`)。
  - package-level の metric は、link したすべての binary の default registry に登録される。`ratelimit` が package の初期化で事前生成すると、`ClientIPKeyed` を一度も呼ばない collector も、この family を 0 で出す。その 0 は「数えていない」ではなく「fallback が起きていない」と読まれる。`ratelimit/metrics.go:28-32` は「collector では 0 のまま」と書くが、事前生成の無い今の正しい記述は「family が無い」。
  - 組み立て時の事前生成の先例は、既に `ratelimit` にある。`MiddlewareStrict` は wrap するときに、bucket ごとの outcome を 0 で作る (`ratelimit.go:330-340`)。
- **C5 契約行と exposed metric を比べる test は、行ごとに 2 本あり、足場が複製されている。**
  - `internal/scoreboard/identityobs/contract_test.go` (154 行) と `internal/scoreboard/metrics/contract_test.go` (199 行) が、それぞれ moduleRoot・行の抽出・gather・変異の表を持つ。
  - 判定も分かれ始めている: label の集め方、「起動直後から存在する」の文の要否、旧い名前の扱い。
  - 3 つ目の契約 metric を足す PR は、3 本目の test を書かない限り検査に入らない (opt-in)。
  - どちらも、その package の test の process の default registry を見る。同じ process で先に走った test が counter を動かしうるので、「起動直後の 0」を default registry で見る test には限りがある (`internal/scoreboard/identity_denials_test.go:341-346` がそう書く)。
- **C6 制約。**
  - 契約表は `.dockerignore` の例外で test の context に入る (`.dockerignore:7-17`)。file が無ければ FAIL で、skip しない。
  - metric に per-user の label を置かない (`internal/scoreboard/metrics/metrics.go:3-8`)。だから事前生成するのは宣言した値と sentinel (`_other`) だけで、要求から作らない。
  - 契約行の metric 名・label 名・事前生成を変える変更は、両リポ同時 (`conventions:381,382`)。

## Options (Alternatives)

### O1 (推奨). 一般則を ADR にし、事前生成の置き場を link する binary の数で決め、契約表から family を導く表駆動の test 1 本で確かめる
- 変更点: 契約表に `name{labels}` と書いた family を test が抜き出し、所有 binary を組み立てた直後の registry にあることを確かめる。行ごとの test 2 本は畳む。
- コスト:
  - 運用 = 契約表に metric を足す PR は、test の所有の表に 1 行 (所有 binary・置き場・事前生成する子) を足す。所有の表は契約表と双方向に比べるので、足し忘れは赤になる。
  - 認知 = 規則 3 つ (D1〜D3)。
  - 依存・image = 増えない (test だけ)。`/metrics` に 0 の系列が 6 本増える。
- リスクと可逆性: 低。test を戻せば元に戻る。client-IP の行の名前の訂正は、出ている名前を変えない (表の文を実際に合わせるだけ)。
- 効き始める閾値: S1 から。契約表に `name{labels}` の metric を足して事前生成を忘れた PR が、赤になる。

### O2. 一般則は書かず、行ごとの test の足場だけを共通の helper にする (#450 のやること 2 だけ)
- 変更点: moduleRoot・行の抽出・gather を `internal/testutil` に 1 つ置き、2 本の test がそれを使う。
- コスト: 最小。
- リスクと可逆性: 新しい契約 metric は、その PR が 3 本目の test を書かない限り検査に入らない (opt-in。C5)。client-IP の行は検査されないまま残る。ADR-0039 C1 と同じ失敗様式。
- 効き始める閾値: 無し (足し忘れには構造的に効かない)。

### O3. 契約 metric を Go の宣言 (family・所有 binary・label・事前生成する子) にし、契約表の metric の部分をその宣言から描画する (ADR-0037 D2 の向き)
- 変更点: metric の契約の権威を Go に移し、表は描画の結果にする。
- コスト: 契約表の行は、platform の読み方や triage の手順などの散文が大半で、metric 名はその一部にすぎない。行の一部だけを生成すると、手で書く部分と機械が書く部分が 1 行に混ざる。Docker の中で回す writer も要る。
- リスクと可逆性: 強制が構造になる (宣言から事前生成まで作れる)。一方で、規則 3 つと test 1 本に比べて、可動部が多い。
- 効き始める閾値: 契約 metric が増え、散文から名前を抜き出すのが脆くなったとき (Signpost 2)。

## Decision

**O1 を採る。** 理由: 「起動直後から存在する」は契約 metric すべてに要る性質 (C2) だが、行ごとに書いて test を手で足す形だと足し忘れた行 (C3 の client-IP) が黙って残る。だから契約表そのものから family を導き、所有 binary の組み立ての直後に確かめる 1 本の test にする。

### D1. 一般則
- 契約表 (`conventions` の「Cross-repo 契約」) で名指しした metric family は、所有 binary の起動直後から存在する。
  - 「起動直後」は、production の組み立て (scoreboard なら `cmd/scoreboard/main.go:302` の `scoreboard.NewHandler`) を終え、最初の要求を受ける前。Recreate の後も同じ。
  - 「存在する」は、所有 binary の `/metrics` にその family の子の系列が 1 本以上あり、起動直後はどの子も 0 であること。label の付いた family は子が無いと現れないので (C2 (a))、子を 0 で作る (事前生成)。
- **family が無いことは「改名か旧い image」であって、0 とは読まない。** platform が「無い = 読めない (rc 2)」と読めるのは、この保証があるから (C2 (a)。platform#245 / #247)。
- 事前生成する子は、宣言した値と sentinel だけで、要求からは作らない (C6)。今の 4 family では次のとおり。
  - identity: 宣言した 8 組 (`0038:72-79`)
  - ingest の 2 つ: `ns="_other"`
  - client-IP: 組み立てた caller ごとの source 3 つ (D5)
- 所有 binary は、その family を数える binary で、family ごとに 1 つ。今の 4 family は、どれも scoreboard。

### D2. 事前生成の置き場
- **package を link する binary が 1 つだけなら、package の初期化** (package-level の var の初期化か `init`)。組み立ての順序や handler の配線の変更に依らず、family が存在する。例: `identityobs.go:125,141-146`、`metrics.go:68-80`。
- **2 つ以上の binary が link する package (今は `ratelimit`) なら、組み立て時。**
  - 所有 binary が、その family を数える部品を作るときに作る。package の初期化で作ると、数えない binary も 0 を出し、その 0 が「起きていない」と読まれる (C4)。
  - 例: `MiddlewareStrict` (`ratelimit.go:335-340`、app#387)、`ClientIPKeyed` (D5)。
- 「link する binary の数」は、`cmd/*` の module 内の import の閉包で数える (`internal/apispec/dependency_boundary_test.go:72` の `transitiveModuleImports`)。V2 が機械で確かめる。package の初期化で事前生成する package を 2 つ目の binary が link し始めると、その PR が赤になる。

### D3. 契約表で metric を名指す書き方
- metric を契約として名指すときは、code span を `<family>{<label>, …}` の形で書く。
  - family は exposed の完全な名前 (namespace と subsystem を含む)。
  - label は label 名の集合で、順序は問わない。label が無ければ `{}`。
- 契約ではない名前 (旧い名前、比べるために出す名前) は、この形で書かない。test は、この形の code span をすべて契約の family と読むため。
- 契約表の前置き (`conventions:368-369` の、見出しと表の間) に、D1 を 1 文で書く。
  - 文案: 「この表で `name{labels}` と書いた metric family は、所有 binary の起動直後から存在する。family が無いことは改名か旧い image で、0 とは読まない (ADR-0040)」
  - 行ごとに「起動直後から存在する」と書き直さなくてよい。今の行の文は消さなくてよい。

### D4. 検査の形 (S1)
- **test は 1 本で、専用の package に置く** (例: `_test.go` だけの `internal/contractmetrics`。置き場は software-engineer が決める)。専用にするのは、その process で他の test が counter を動かさないので、起動直後の 0 を default registry でそのまま見られるから (C5)。
- 手順:
  1. `conventions` の「Cross-repo 契約」の表の行から、D3 の形の code span をすべて抜き出す。0 件なら赤。
  2. test の中の所有の表 (family → 所有 binary の組み立て・置き場 (init か組み立て時)・事前生成する子) と、1 の集合を双方向に比べる (`specparity.CoverageDiff` と同じ形)。契約表にあって所有の表に無いもの、またはその逆は赤。
  3. 置き場が組み立て時の family は、組み立ての前に gather して、子が無いことを確かめる。
  4. 所有 binary ごとに、production の組み立てを要求の前まで行い (scoreboard は `scoreboard.NewHandler`)、default registry を gather する。各 family について次を確かめる: family がある / label 名の集合が code span と等しい / 所有の表の事前生成する子がすべてある / どの子も 0。
  5. 置き場が init の family は、定義する package が所有 binary の閉包にだけあることを確かめる (V2)。
- 行ごとの 2 本 (`identityobs/contract_test.go`・`metrics/contract_test.go`) は、この test に畳んで消す。行に固有の検査は、所有の表の欄として持つ。
  - identity: reason の値 `no_identity` / `non_canonical` / `mismatch` が、行に code span としてある。
  - 旧い `ratelimit_identity_requests_total` を契約として名指さない。D3 の形で書けば、2 の比較で赤になる。
- 契約の行を読む helper (moduleRoot・`conventions` の読み込み・表の行と code span の抽出) は 1 つにする。label 名は集合で集める (#450 のやること 2)。
- `.dockerignore:7-16` の comment は、この test を指す形に直す。
- 各 package の事前生成の unit test は残す (fresh registry で事前生成を外す変異を持つもの: `identityobs`、`metrics` の nscap 系)。この test は契約の面を見て、unit test は実装を見る。

### D5. 今の 4 family への適用

| 契約行 (`conventions`) | family (D3 の形) | 所有 binary | package (link する binary) | 置き場 | 事前生成する子 | 状態 |
|---|---|---|---|---|---|---|
| identity 拒否の観測 (:382) | `scoreboard_identity_denials_total{gate, reason}` | scoreboard | `identityobs` (scoreboard) | init | 宣言した 8 組 | 済 (ADR-0038、#424) |
| Webhook 流量制限 (:381) | `scoreboard_ingest_falco_events_scoring_overflow_total{ns}` | scoreboard | `scoreboard/metrics` (scoreboard) | init | `ns="_other"` | 済 (#448、#469) |
| 同上 | `scoreboard_ingest_falco_events_rate_limited_total{ns}` | scoreboard | 同上 | init | `ns="_other"` | 済 (同上) |
| Rate-limit client-IP ヘッダ (:392) | `ratelimit_client_ip_source_total{caller, source}` | scoreboard | `ratelimit` (scoreboard、collector) | 組み立て時 | 組み立てた caller (`submit`・`csp_report`) × source 3 つ = 6 本 | **S1 で直す** |

- client-IP の行は S1 で直す。
  - (a) code span を、出ている family の名前と label に訂正する (`client_ip_source_total{source}` → `ratelimit_client_ip_source_total{caller, source}`)。出ている名前は ADR-0023 から変わっていないので、表の文を実際に合わせるだけ。
  - (b) `ClientIPKeyed(caller)` は keyFn を作るとき (組み立て時: `internal/scoreboard/api/api.go:580`、`internal/scoreboard/view/view.go:293`) に、その caller の source 3 つを 0 で作る。collector は `ClientIPKeyed` を呼ばないので、この family を出さない。`ratelimit/metrics.go:28-32` の comment も直す。
  - (c) `caller` の値は表示用で、値の集合は契約にしない (identity の `gate` と同じ)。label 名の `caller` と `source` は契約。
  - (d) platform の文書の文例の短い名前 (platform `docs/verification-gates-2026-08.md:757-760`) は、同じ時期に platform の文書の PR で直す (sre-engineer、Class-0)。読む script は無いので、両リポの順序は問わない。

### D6. 段と順序
- **S1** (Class-1、software-engineer・qa-engineer。HTTP の挙動は変えない)
  - D4 の test と helper、行ごとの 2 本の削除、`.dockerignore` の comment
  - D5 の client-IP の (a)(b)
  - D3 の前置きの 1 文
  - 見込みは追加 約 300 行・削除 約 350 行 (行ごとの 2 本)、7 file 前後。
  - 契約表に触れる (D3 の前置き、D5 の (a)) ので architect 合意と VP 承認が要るが、この ADR の Accepted で代える。
- platform: #245 / #247 の「family 無し = rc 2」への切替は、その family の事前生成を含む image に pin が上がってから。
  - ingest の 2 family は #448 (`e64d5ae`) から起動直後に存在するので、S1 を待たない。
  - client-IP は、platform が読み始めるときに S1 を含む image が要る (Signpost 1)。
- ADR-0038 は書き換えない。Status block に導線を 1 行足す (「契約表の metric の一般則と、V9 の test を 1 本の test に置き換えることは ADR-0040」)。
- ADR-0037 は、rev2 で Limiter の上限 (#467) を記録するときに、「`ratelimit` の契約 family の事前生成は組み立て時 (ADR-0040 D2)」と 1 文で指す。

## Verification (すべて `make test` = required の `test / go-test` に載せ、exit status で判定する)

- **V1 契約表・所有の表・registry**: D4 の 1〜4。
  - 抽出は 1 件以上 (今は 4)。所有の表と双方向に一致する。
  - 所有 binary の組み立ての直後に、各 family がある。label 名の集合が code span と等しく、事前生成する子がすべてあり、どれも 0。
- **V2 置き場**:
  - 置き場が init の family の package は、所有 binary の閉包にだけある (`transitiveModuleImports`)。
  - 置き場が組み立て時の family は、組み立ての前の gather に子が無い。process の中では「所有でない binary が 0 を出さない」を直接見られないので、その代わりにする。
- **V3 検査が嘘でないこと** (常設の変異。次のそれぞれで赤になる)
  - 契約表の family 名を 1 文字変える。
  - code span から `{…}` を外す (抽出から消え、所有の表と食い違う)。
  - label を 1 つ足す、または名前を変える。
  - 事前生成を外す (合成の registry で、子の無い family)。
  - 子を 1 で作る (0 でない)。
  - 所有の表に、契約表に無い family を足す。
  - 置き場が init の package を、もう 1 つの binary の閉包に入れる (合成の閉包)。
  - 組み立て時の family を init で作る (組み立ての前の gather に子がある)。
  - 契約表の抽出が 0 件になる。
- **この検査が見ないもの**
  - 実 cluster の scrape と、platform の rc の扱い (platform#245 / #247 の verify)。
  - Prometheus の `increase()` の評価。C2 (b) は、先例の comment と Prometheus の仕様に拠る。
  - 契約表の散文の中身 (platform の読み方や triage)。
  - 契約行の label の値のうち、所有の表に書かないもの。
  - platform が読む `process_start_time_seconds` (client の process collector が出す。契約表に無い。platform は無ければ `unknown` と出す: platform `docs/operations.md:891`)。

## Consequences

- **諦めたもの**
  - `/metrics` に、起動直後から 0 の系列が増える (client-IP で 6 本)。どれも宣言した値で、要求から作らない。
  - 契約表で metric を名指す書き方が 1 つに決まる (D3)。契約でない名前を同じ形では書けない。
  - 所有の表は test の中の小さな手書きの表になる。契約表と双方向に比べるので、足し忘れは赤になる。
  - 所有でない binary が family を出さないことは、process の中では確かめない (default registry は process で共有される)。閉包と、組み立ての前に子が無いこと (V2) で代える。
- **新たに守るもの**
  - D1 の一般則、D2 の置き場、D3 の書き方、D4 の test が 1 本であること。
  - 契約表に metric を足す PR は、所有の表に 1 行を足す。
- **他ロールへの影響**
  - software-engineer = S1。qa-engineer = V3 の変異。
  - sre-engineer = platform#245 / #247 の切替は D1 を app の保証として読む。platform の文書の client-IP の名前の訂正 (D5 (d))。
  - security-engineer のレビューは要らない (auth・flags・採点・Dockerfile に触れない)。
- **runbook**: platform の verify が「family 無し = 読めない (rc 2)」と読めるのは、pin した image がその family について D1 を満たすときだけ。旧い image の pin では、今と同じく「未検証」と読む (platform `docs/operations.md:895-898`)。

## Signposts (この決定を覆す観測可能な信号)

1. **platform が `ratelimit_client_ip_source_total` を読み始める** (verify・alert。ADR-0023 Signpost 2 の drift の検出)
   - → `caller` の値の集合を契約に入れるかを決める (今は表示用。入れるなら、caller を足す・外す PR は両リポ同時)。
   - あわせて、「組み立てた caller だけが出る」を読む側が前提にしてよいかを、契約行に書く。
2. **契約表で名指す family が 5 本目に増える (今は 4 本)、または 1 つの行が 3 本以上を名指す**
   - → 散文から名前を抜き出す形をやめ、契約 metric を Go の宣言にして、表の metric の部分をそこから描画する (O3、ADR-0037 D2 の向き)。
3. **2 つ目の binary が、同じ family を所有する必要が生じる** (例: collector が `ratelimit` の契約 family を数える)
   - → 「所有 binary は 1 つ」という D1 の前提が崩れる。契約に binary の区別 (scrape の job か、行を分ける) を入れ、D2 の置き場を見直す。
   - 2 つ目の binary が誤って link するだけなら V2 が赤にするので、それは signpost ではない。
4. **S1 を含む image で、platform の verify が開催中に「family 無し (rc 2)」を出す**
   - → 起動直後の保証が実機で破れた。所有 binary が組み立ての直後に契約 family を自分で確かめ、無ければ起動を止める (start-up self-check) ことを検討する。

## Advice (受けた助言。非拘束でも記録する)

- **VP (2026-10-19、本 ADR の発注。Issue #450)**: 一般則 (1)、事前生成の置き場 (2)、表駆動の test 1 本 (3)、適用例 = ADR-0038 と #448 (`NSCounter` の `_other` = #469)、Signposts 3 つ、関連 = ADR-0037 と platform#245 / #247。→ D1〜D6 と Signposts。Signposts は次のように具体化した。
  - 「4 つ目の metric」: client-IP を今の 4 本目として D5 で入れたので、「5 本目」にした。
  - 「2 つ目の binary が link」: 誤って link する場合は V2 の機械の検査にし、意図して所有する場合を Signpost 3 にした。
- **review-5x (app#448、2026-10-18) R4#1 / R3#2 / R4#2 (#450 の事実)**: 一般則が無い / 3 例目の client-IP に事前生成も契約 test も無い / 契約行の test の足場が複製され、挙動が分かれ始めた。→ D1・D4・D5。
- **sre-engineer (platform#244、2026-10-17。ADR-0038 の Advice から)**: 系列が無ければ判定不能として扱い、これが改名の検出器にもなる。→ D1 の「0 とは読まない」を、すべての契約 family の一般則にした。
- **architect (起草の中)**
  - client-IP の行の名前と label が、出ている family と合っていないことを見つけた (C3)。D1 の例外にせず、S1 で直す (例外を置くと、除外の一覧が 1 つ増える)。
  - 事前生成の理由に、`increase()` の 0 の起点 (C2 (b)、app#387) を加えた。
  - default registry を共有する test の限界 (C5) から、test を専用の package に置いた。
