# ADR-0039: spec の string の schema node ごとに、誰がそのバイトを選べるかと見せ方を省略できない `x-ctf-text-origin` で宣言し、portal の bidi gate・route の文字の拒否・応答への流れをその宣言から導いたテストで確かめる

- Status: **Proposed** (2026-10-18 起草)。Accepted 化は VP (時限承認: workspace `ORGANIZATION.md:470-472`。S1 の merge より前)。spec に必須の extension を新設する (= API 契約の新設) ので architect 合意 + VP 承認 (`ORGANIZATION.md` §4)。HTTP の挙動を変えるのは S3a だけで、Class-2 (security-engineer の APPROVE)。クロスリポ契約・新 image・新サービス・Dockerfile に触れないので CEO 判断を要さない。D9 の I18 は提案だけで、昇格は S4。実装は Proposed のまま始めてよい。
- Date / Deciders: 2026-10-18 / VP (承認) + architect (起草・API 契約と I18 提案への同意) + security-engineer (S3a の APPROVE、S2 のレビュー、C2 (b) の triage) / 実装: software-engineer (S1・S3a)、application-engineer (S2)、qa-engineer (S3b・S4)
- 関連: Issue #407 (発注元。app#405 review-5x R4#1)、#343 / #375 / #383 (表示名の隔離と gate)、#377 / #405 (件名)、#408 / #420 (件名の client 事前検査)、#401 / #411 (sharedHelpers)、#419 (保存済み表示名の warn)、#115 F2 (生成型の採用)、#113 (`err.Error()`)、ADR-0005・ADR-0009 (spec の parity と V5)、ADR-0028 (Signpost 2′)、ADR-0034 (表示名・絵柄)、ADR-0035 (goja・form は server より厳しくならない)、ADR-0037・ADR-0038 (閉じた語彙と構造からの導出)、I14。フェーズ: 非該当
- 読み方: app は origin/main `295e8af` (#420 を含む。3 spec は `6cc91bc` から変わっていない)、platform は origin/main。`0005:N` などは `docs/adr/` の各 ADR の行、`api.go` は `internal/scoreboard/api/api.go`、`board.go` は `internal/scoreboard/api/board.go`、`spec` は `docs/openapi-scoreboard.yaml`、`bidi_test` は `internal/scoreboard/view/portal_bidi_test.go`、template は `internal/scoreboard/view/templates/portal/` の partial。

## Context

- **C1 「参加者が書いた inline の文字列」の field の集合が 2 つの側に別々にあり、どちらも宣言から導かれていない。**
  - portal: `inlineTextFields = {display_name, authorDisplay, subject}` と `inlineTextLocals = {displayName}` は手書き (`bidi_test:33,37`)。gate は走査型 (#375) で、下限 (`bidiFloors`、`bidi_test:165-170`) と変異 test (#383) を持つが、走査する「名前」は人が足す。
  - server: field の集合そのものが無い。あるのは handler が validator を呼ぶこと (`validDisplayName` `api.go:1121` を admin rename `api.go:1157` と profile `internal/scoreboard/api/profile.go:138` が呼ぶ、`validBoardSubject` `board.go:73-85`)、関数を叩く表 (`internal/scoreboard/api/testdata/display-name-parity/cases.yaml`、`testdata/board-subject/cases.yaml`)、全 code point の走査 (`testdata/display-name-parity/rule.yaml:22-24` と比べる) の 3 つで、「この request field にこの規則が route で当たる」「この request field の値をこの response field が返し、portal が読む」を結ぶものは無い。
  - 同じ bug class が 2 回起きた: 表示名 (#343 → #375) と件名 (#377。#375 の review で見つかり、#405 が両側に手で足した)。opt-in の印 (`x-ctf-participant-text: true` の類) や両側が読む共有表は、新しい field を足す PR が印も表も触らなければ黙って外れる。これは 2 回の失敗様式そのものなので採らない (Issue #407)。

- **C2 181 本を分類すると、紙に書かれた前提のうち 3 つが実装と合わない (`295e8af` で実測)。**
  - (a) body: 「A message body is a block of its own (a <div>), so it is not in this set」(`bidi_test:19`)。今は真 (`pane-board.tmpl:509,790` は `<div class="thread-msg-body">` の中の `esc(m.body)`、`css.tmpl:769` が `pre-wrap`) だが、誰も検査しない。body を一覧の行に inline で出す変更は gate を通る。server の `validBoardBody` は trim と長さしか見ず (`board.go:90-99`)、U+202E・U+200B・C1・NUL・CR をそのまま保存する。
  - (b) `user`: 「first_solver is a username slug, not a name」(`bidi_test:32`)、spec も「first solver's username」(`spec:2709-2712`)。だが `POST /api/challenges/{cid}/submit` は `user` が空でないことしか見ず (`api.go:1219-1227`)、`Grader.SubmitEvade` (`internal/scoreboard/scoring/scoring.go:689-705`) も `Store.MarkSolved` (`internal/store/store.go:590-605`) も検査しない。`POST /internal/exfil/{cid}` も同じ (`api.go:1562-1574`)。`submit-detect` だけが `validUser` (`api.go:61`) を当てる (`api.go:1390-1401`)。collector は body を解釈せずに転送する (`docs/openapi-collector.yaml:94-96`)。よって plain な evade の flag を知る参加者は、workspace の curl で任意のバイト列を `user` にした solve を作れ、それは State の `leaderboard[].user` と `first_solver` に載る (`api.go:2451-2466,2584-2600`)。`first_solver` は bare `esc()` で inline に出る (`pane-scoreboard.tmpl:242`、`templates/index.html:378`)。見えるのは運営の画面 (State は admin) で、U+202E を含む `user` はその行の並びを崩す。claimed identity で他の seat に solve を付けられることは既知の設計 (`api.go:1180-1182`、`spec:2037`) だが、seat の形をしないバイト列を保存できることは別の欠陥。security-engineer の triage が要る (D6)。
  - (c) `SubmitFlagVerdict.reason` は claimed `user` を `%q` で埋め (`api.go:1268-1274,1288-1292`)、`Error.error` は `{cid}` を返す (`api.go:1201`)。どちらも要求した本人の応答にだけ出る (self-echo) ので、別の人の画面への流れではない。本 ADR の分類は「書いた人と読む人が違う」流れについて言う。
- **C3 string の schema node は 181 本** (scoreboard 159 / collector 4 / auth-policy 18)。数え方: `type` が `string` (または `string` を含む列) の Schema Object を、`components.schemas`・`components.parameters.*.schema`・operation の inline の parameter / requestBody / response / response header の schema から、`properties`・`items`・`additionalProperties`・`allOf|anyOf|oneOf` を辿って数える。`$ref` の節点は数えない (参照先で 1 回)。内訳は JSON の property 157 (配列の `items` を含む)、parameter 15、response header 9。書式は flow 形式 (`{type: string}`) が 127、block 形式が 54。
- **C4 既存の `x-ctf-*` は operation に付き、Go の `Routes()` と比べる** (必須: `0005:153-157`、既定値なし: `0005:236-237`、実装: `internal/apispec/specparity/parity.go:58-133`)。ADR-0037 は rate-limit の宣言の権威を Go に置いた。理由は limiter をその宣言から組み立てるから (`0037:90-93` の (b))。文字列の出所には runtime で組み立てる者が無い: validator は field ごとの関数 (32 rune と 120 rune、metacharacter の有無、trim)、描画は portal の JS で、どちらも class から組み立てられない。field の正典は spec (`0005:294`)。
- **C5 読み手。** 消費するのは app の test の 3 package (`internal/scoreboard/api`・`internal/scoreboard/view`・`internal/scoreboard` の parity) と、`internal/apispec` の spec の検査だけになる。platform に `x-ctf-` は 0 件 (`git grep`、platform origin/main)、docs site は spec を描画しない (`git grep -i openapi -- images/` は 0 件)。クロスリポ契約ではない。
- **C6 制約。** ADR-0005: 除外リストを持たない、欠落は fail、Decision / Verification は凍結 (`0005:7`、`docs/adr/README.md:72-80`)。ADR-0037 D1 / ADR-0038 D2: 語彙は閉じた集合で、使わない語を置かない。ADR-0035: form は server より厳しくならない。拘束力があるのは `make test` だけ (`gen-diff-check` は required でない: `0005:9-12`)。`internal/apispec/specparity` は test 専用 (`internal/apispec/dependency_boundary_test.go`)。`specparity` の `resolve` は components の外の `$ref` を黙って nil にする (`internal/apispec/specparity/spec.go:197-207`)。oapi-codegen v2.3.0 は schema の未知の `x-` key を無視する (仮説。S1 の V3 で確かめる)。

## Options (Alternatives)

### O1 (推奨). string の schema node に必須の `x-ctf-text-origin` を置き (権威は spec、Go に写しを持たない)、portal の gate・route の probe・応答への流れの検査をそこから導く
- 変更点: 181 node に閉じた 6 語のどれか 1 つを書く。test が spec を読んで、portal が走査する名前、route ごとに叩く field、応答のどの node に参加者のバイトが出てよいかを導く。
- コスト: 運用 = string を足す PR は 1 語を選ぶ。認知 = 6 語の表 1 枚 (D2)。依存・image = 増えない (walker と語彙は test 専用の `specparity`)。spec は約 70 行増える (flow 形式は同じ行、block 形式は 1 行ずつ)。
- リスクと可逆性: 低。HTTP の挙動を変えるのは S3a だけ。読み手が app の test だけなので、key の形は 1 PR で戻せる。O2 へは「class を生成型に写す」を足せば移れる (spec の宣言はそのまま使える)。
- 効き始める閾値: S1 から。新しい string を分類無しで足した PR が赤になる。

### O2. class を生成型の struct tag に写し、request の decode の層が class ごとの述語を自動で当てる
- 変更点: oapi-codegen の `x-oapi-codegen-extra-tags` で class を生成型の field tag にし、全 handler が生成型に decode して、tag を読む共通の検査を通す。portal は O1 と同じく spec から導く。
- コスト: request の decode を生成型に揃える (今、生成型で decode するのは submit・submit-detect・falco/events (`0005:124-129`) と board (`board.go:136`) で、admin rename と internal exfil は手書きの struct: `api.go:1149-1151,1553-1556`)。全 handler の変更で、Class-2 が handler の数だけ要る。field ごとの規則 (長さ・metacharacter・trim) は class では決まらないので関数の validator は残り、述語が 2 か所になる。生成物の鮮度は required でない `gen-diff-check` に頼る。
- リスクと可逆性: 強制が構造になる (validator の呼び忘れが起きない)。一方で spec の 1 語が runtime の 400 を増減させ、spec の review が runtime の review になる。戻すには decode の層を外す。
- 効き始める閾値: request の decode がすべて生成型を通るようになったとき (#115 F2)、または Signpost 3。

### O3. participant の field を並べた共有の表 (YAML 1 つ) を、server の test と portal の gate が読む
- 変更点: `inlineTextFields` と route の field の一覧を 1 file にまとめる。
- コスト: 最小。
- リスクと可逆性: 新しい field を足す PR が表を触らなければ、どちらの検査にも入らない。C1 の失敗様式が残る (opt-in)。
- 効き始める閾値: 無し (付け忘れに構造的に効かない)。

## Decision

**O1 を採る。** 理由: 出所は spec が既に定義している値の属性で、runtime に組み立てる者が無いので、写しを持たずに宣言を 1 つにできる場所は schema の node だけであり、そこに省略できない key を置くと「新しい field の付け忘れ」は parity の赤になり、3 つの導出 (D4・D5・D7) が各 class を検査された主張にする。

### D1. 宣言の形
- key は `x-ctf-text-origin`、値は D2 の 6 語のどれか 1 つ (文字列)。必須で既定値を持たない (`0005:236-237` と同じ規律)。
- **置き場は `type: string` を書く Schema Object そのもの。** component の property、配列の `items`、`additionalProperties`、parameter の `schema`、response header の `schema` を含む。`$ref` の節点には書かない (参照先の定義に 1 回)。
  - operation に置かない: 出所は値の属性で、route の属性ではない。`BoardThread` は 6 route の 200 で、`display_name` は 9 schema にある。route ごとに書くと、同じ値の宣言が route の数だけでき、食い違える。
  - 親 object の map (`x-ctf-text-origins: {name: class}`) にしない: property を足す PR が map を触らなくても property は増える。property の隣に書けば diff の同じ hunk に出る。
  - request と response で分けない: 1 つの schema は両側で同じ値を運ぶ。側で変わる規則は D3 が使われ方から決める。
- **権威は spec。Go に写し (Route の field や生成型の tag) を持たない。** (1) 組み立てる消費者が無い (C4)。ADR-0037 が Go に権威を置いた理由 (`0037:90-93`) はここに当てはまらない。(2) field の正典は spec で (`0005:294`)、消費者の test は既に `specparity` で spec を読む。(3) 写すと写しと spec の parity がもう 1 つ要る。
- **保存先の規則**: 値の class は、それを保存する場所の class に従い、保存先の class は書き手のうち最も信頼できない者で決まる。admin の rename の `DisplayNameRequest.name` は参加者も書く表示名の保存先に入るので `participant-inline`、運営の返信の `PostReplyRequest.body` は `participant-block`。1 つの保存先に 1 つの規則と 1 つの描画を当てるため。D7 が機械で確かめる。
- 3 spec の `info.description` の extension の節 (`spec:28-50` ほか) に語彙と規則の要約を足す (collector と auth-policy は scoreboard の節を指す 1 行でよい)。

### D2. 語彙 (閉じた集合。定義は `specparity` の 1 表だけ。どの node も使わない語は置かない = ADR-0037 D1 / ADR-0038 D2 と同じ規律)

| 値 | 意味 (誰がバイトを選ぶか × どう見せるか) | 静的規則 (S1) | request の検査 (S3b) | response の検査 (S2・S4) |
|---|---|---|---|---|
| `participant-inline` | 参加者が選べる自由文 (保存先の規則を含む)。他の文字列の隣に inline で出る | response では名前の付いた object property にだけ置く。その property 名を response の他の class の string に使わない | route が class の規則の probe をすべて 400 で拒否 | portal は `nameHTML()` / `textHTML()` でだけ markup に入れる (S2)。受けてよい marker: inline (S4) |
| `participant-block` | 同上。自分の block (複数行) に出る | 同上 | 同上。ただし LF と TAB は受理 | 同上 (isolate を要求。S2)。受けてよい marker: inline・block (S4) |
| `participant-opaque` | 参加者が選ぶが、どの応答にも載らない (flag、Falco の condition、credential の header、CSP report、強制変換される選択子) | response から到達する node に置かない | 無し (文字の規則を持たない) | その marker がどの応答にも出ない (S4) |
| `operator` | 運営側だけが選ぶ自由文 (repo の content と catalog、運営の設定、server の文、falcosidekick の event) | request では `x-ctf-audience: operator` か「`internal` かつ `x-ctf-collector-forward: false`」の operation にだけ置く | 無し | 受けてよい marker: operator (S4) |
| `token` | 閉じた文法の値 (seat・challenge の slug、hex の id、RFC 3339 の時刻)。印字可能 ASCII (U+0021–U+007E) だけ | `enum` / `const` を持たない | 文法外の 1 値 (`"a\u202Eb"`) が非 2xx | 実値が印字可能 ASCII で、`pattern` / `format: date-time` があればそれにも合う。marker を受けない (S4) |
| `enum` | 閉じた集合 | `enum` か `const` を持つ (逆に、それらを持つ node は必ず `enum`) | 集合外の 1 値が非 2xx | 実値が集合に入る。marker を受けない (S4) |

- issue の仮の語との違い: `slug` → `token` (hex の id と時刻は slug でないが、どの検査でも同じに扱う)。`participant-opaque` を足した (flag と condition に文字の規則を当てると提出が壊れ、`operator` と書くと参加者のバイトを運営のものと偽る)。`enum` は issue の `enum/constant`。
- 暫定の分類 (S1 で確定): inline 17 (response 14 = `display_name` ×9・`authorDisplay` ×3・`subject` ×2、request 3 = `DisplayNameRequest.name`・`ProfileRequest.display_name`・`CreateThreadRequest.subject`)、block 4 (`BoardMessage.body` と request の `body` ×3)、opaque 26 (flag ×3・condition・CSP report ×14・`CreateThreadRequest.audience`・`?mission`・auth-policy の `Cookie` / `Authorization` ×6)、operator 50、token 66、enum 18。
- slug / enum を Cc / Cf の category の表から外す理由: 規則が「自由文から category を引く」ではなく「閉じた文法への所属」で、そちらの方が厳しい。ただし検査の外には置かない。文法外の 1 値で十分に区別でき、C2 (b) のとおり slug という宣言は実装で偽になり得るから。

### D3. 宣言の検査 (S1。`internal/apispec` の `TestAPISpec_TextOriginDeclared`)
`specNameForCmd` (`internal/apispec/mux_ownership_test.go:236-240`。V6 が mux を持つ binary の走査と照合する表) の全 spec を回す。service ごとの配線は要らない (spec が増えれば V6 が表を増やさせる)。
- (a) C3 の数え方で見つけた全 string node が key を持ち、値が語彙にある。失敗文は JSON pointer を名指す。
- (b) string でない node は key を持たない。
- (c) walk で解決できない `$ref` (components の外・存在しない名前) は fail。spec を分割 (ADR-0028 Signpost 2′) して外部 `$ref` になったとき、node が黙って検査から消えないように。
- (d) D2 の静的規則: response から到達する opaque / 参加者の届く operation (D2 の `operator` の行の条件を満たさないもの) の request にある operator / `enum` ⇔ `enum`・`const` / participant-* は response では名前付きの property だけ (`items`・`additionalProperties` に置かない。portal の走査が名前で値を見るため) / participant-* の property 名を response の他の class の string に使わない。request か response かは operation から `$ref` を辿って決め、両側で使う component は両方の規則を受ける。
- (e) collector の forward の operation が request の schema を書くなら、その string node の (pointer, class) は `x-ctf-forward-target` の request と一致する (今は exfil の inline の `{user, flag}` と scoreboard の `ExfilRequest`: `docs/openapi-collector.yaml:114-124`)。
- (f) 語彙の各語が少なくとも 1 node で使われる。
- (g) spec ごとに string node が 1 本以上。participant-inline・participant-block・participant-opaque の本数を pin する (足す・外す・付け替える PR が pin の行を触る。review の目印で、ADR-0009 の件数 pin と同じ)。
- walker と語彙は `internal/apispec/specparity/textorigin.go` に置く (test 専用。production に入らない)。

### D4. 導出 1: portal の gate (S2。`bidi_test`)
- `inlineTextFields` を消し、spec の response から到達する `participant-inline` と `participant-block` の property 名の集合を導く (今は `{display_name, authorDisplay, subject, body}`。前の 3 つが今の手書きと同じで、`body` が増える)。`inlineTextLocals` も消し、「宣言の初期化式がその名前を読む local は参加者の文字列」を 1 段だけの走査で導く (`pane-me.tmpl:364` の `const displayName = d.display_name || user;` から `displayName`)。
- 規則は 1 つ: その名前を bare の `esc()` に渡さない (0 件)。`nameHTML()` / `textHTML()` (`core-util.tmpl:44,54`) を通す。
- **block にも isolate を要求する。** body の 2 か所 (`pane-board.tmpl:509,790`) を `textHTML(m.body)` にする。block 要素の中にあることは layout の事実で、template の走査では確かめられない (三項演算子、連結、後から足す preview)。`<bdi>` は inline でも block の中でも漏れを止めるので、検査できる性質 (helper を通ったか) を要求する。新しい `blockHTML()` は作らない (block であることは安全に寄与しない)。`textHTML` の doc (`core-util.tmpl:46-53` の「Not for a block of text」) を「参加者の文 (inline でも block でも)」に直す。見える変化: 最初の強い文字が RTL の body は、その向きで並ぶ (`<bdi>` の向きは中身で決まる)。
- `bidiFloors` は下限として残し、`pane-board.tmpl` を 11 → 13 にする。`sharedHelpers` (`bidi_test:69`) は helper の 1 定義の検査で、field の分類とは直交するので残す。
- view の test は `specparity` を import して spec を読む (test から test 専用 package への import で、境界の検査は production の import だけを見る)。

### D5. 導出 2: route の文字の検査 (S3b。`TestAPISpec_TextOriginProbes`)
- **導出集合**: operation の JSON request body を `$ref` を辿って歩き、class が `participant-inline` / `participant-block` / `token` / `enum` の (operation, JSON pointer, class)。collector の forward は target で叩く (D3 (e) で class は同じ)。今は scoreboard の 10 operation / 12 組: inline 3 (profile の `display_name`、admin rename の `name`、thread の `subject`)、block 3 (thread・message・admin reply の `body`)、token 3 (submit・internal exfil・submit-detect の `user`)、enum 3 (profile の `avatar` (`profile.go:149-150`)、admin の thread と message の `state` (`board.go:529,575`))。
- **driver の表**: operation の鍵 → 有効な要求の組み立て (path、identity、Origin、前提の状態、全 field に有効な値)。鍵の集合を導出集合と双方向に比べる (`specparity.CoverageDiff` と同じ形: `internal/apispec/specparity/coverage.go:93-109`)。導出にあって表に無い = 赤、表にあって導出に無い = 赤。D7 と 1 つの表を共有する (鍵の集合 = 2 つの導出集合の和)。
- **判定**: driver ごとに (1) baseline (有効な値のまま) が 2xx であること (でなければ 400 が field のせいだと言えない)。(2) probe ごとに新しい handler で (bucket が status を決めないように)、対象の field だけを `"a" + probe + "b"` (端の trim を避ける) に替えて送る。class が拒否する probe → 400 で body が `Error` の形。block が受理する probe (LF・TAB) → 2xx。token / enum → 文法外の 1 値が非 2xx。
- **規則と probe の file**: `internal/scoreboard/api/testdata/text-rule.yaml` (S3a で今の `display-name-parity/rule.yaml` を組み替える)。class ごとの `categories` (`Cc`・`Cf`)・`exempt` (U+200D。emoji の間だけ)・`allow` (block だけ LF と TAB)、表示名だけの `meta`、`probes` (U+202E・U+2066・U+200B・U+FEFF・U+00AD・U+0085・U+0000・U+0009・U+000A・U+007F)。検査: class の鍵の集合 = 語彙の `participant-inline`・`participant-block` (双方向)、各 probe はどれかの category に入る、各 category に `allow` でない probe が 1 つ以上ある。
- **probe しないもの (理由)**: path / query / header の parameter は lookup key か選択子で、route が catalog・ロスター・store・登録表と照合し、外れは spec が書く 404 / 400 か既定値になる (保存されるのは照合した側の値)。D3 の静的規則だけを受ける。`participant-opaque` と `operator` は文字の規則を持たない (opaque は D7 が流れで見る)。field ごとの規則 (32 rune・120 rune・metacharacter・trim・ZWJ) は関数の表 (`cases.yaml` 2 本) と全 code point の走査が持つ。route の probe が言うのは「その route がその field に class の下限を当てる」ことだけ。
- 3 service に同じ名前の test を置き、`requiredParityTestFuncs` (`internal/apispec/parity_coverage_test.go:66-70`) に足す。collector と auth-policy は導出が 0 件 (collector の body は forward で target が持ち、auth-policy に body は無い) で、0 件を許す (`TestAPISpec_IdentitySourceProperty` と同じ形: `parity_coverage_test.go:37-46`)。body を持つ operation が足されたらその場で導出に入る。
- 今の main で赤になる組 (S3a が直す): block 3 (C2 (a))、token 2 (submit と internal exfil の `user`、C2 (b))。

### D6. validator の変更 (S3a。Class-2)
- `validBoardBody` (`board.go:90-99`) に participant-block の規則を当てる: Cc / Cf を拒否し、LF と TAB を許す。U+200D は表示名と同じく emoji の間だけ (`hasForbiddenRune`、`api.go:1087-1101`)。CR は拒否 (portal の textarea の値は LF に正規化され、board の書き込みは origin-guard 付きで workspace の curl から届かない)。flag の形の拒否は残す。400 の文は固定で、入力を返さない。
- `submit` と `internal/exfil` の `user` に trim の後で `validUser` (`api.go:61`) を当て、外れは 400 `invalid user` (`submit-detect` と同じ: `api.go:1398-1401`)。spec の `SubmitFlagRequest.user` / `ExfilRequest.user` に `pattern` (`User` parameter と同じ: `spec:1868`) と 400 を書く。workspace の curl は seat を送るので、正しい提出は変わらない (大文字などの打ち間違いは、今は別の user の solve になり seat に付かないが、400 で分かるようになる)。
- `rule.yaml` を D5 の `text-rule.yaml` に組み替え、読み手 4 つ (`display_name_parity_test.go`・`board_subject_rule_test.go`・`portal_nameproblem_test.go`・`portal_subjectproblem_test.go`) を直す。block の全 code point の走査を足す (`TestBoardSubject_SweepEveryCodePoint` と同じ形)。
- 保存済みの値は消さない。body は D4 で isolate される。slug でない `user` の solve が残っていた場合に起動時に件数を Warn するか (#419 と同じ型、値は出さない) は security-engineer が決める。
- security-engineer の APPROVE が要る (採点の経路の claimed identity と board の書き込みに拒否が増える)。CHANGELOG に書く。C2 (b) は D1〜D5 に依存しないので、S3a は S1 より先に (hotfix として) 出してよい。

### D7. 応答への流れの検査 (S4。`TestAPISpec_TextOriginFlow`)
- 1 つの fixture に、自由文の request node (`participant-inline` / `participant-block` / `participant-opaque` / `operator`) ごとに、その field の規則を通る固有の marker (例 `TF ✓i3`。空白と U+2713 を含むので token と enum の文法に決して合わない) を driver で送る。query の `participant-opaque` (`?mission=`) にも送る。
- 送った要求の応答と、JSON object の応答を持つ GET の全 operation (`specparity.ResponseObjectOperations` (`coverage.go:25-34`) から導く) の応答を、schema を辿って string の葉ごとに見る。GET の path parameter は名前ごとの表 (`{user}` → seat、`{tid}` → 作った thread) から埋め、表は使われる名前の集合と双方向に比べる。identity は `x-ctf-authz` から決める。
- 流れの規則:

  | marker の出所 (request の class) | 出てよい応答の node の class |
  |---|---|
  | `participant-inline` | `participant-inline`・`participant-block` |
  | `participant-block` | `participant-block` |
  | `operator` | `operator` |
  | `participant-opaque` | どこにも出ない |

  加えて (i) `participant-inline` / `participant-block` の request node の marker は少なくとも 1 か所に出る (出ないなら `participant-opaque` の誤りか、読む GET が足りない)。(ii) token / enum の葉は D2 の文法に合う (marker が入れば必ず外れる)。
- これで response の側の分類 (別の人に参加者のバイトを見せる node が participant-* を名乗っているか) と、保存先の規則 (admin の request を `operator` と書いて参加者の保存先に入れれば赤) が機械で確かめられる。届くのは driver が通す流れだけ (Signpost 1)。
- 文法の検査は `CompareResponse` (ADR-0009 Decision B) を変えず、別の walker にする。ADR-0005 V5 の「型と値域は見ない」(`0005:419`) は V5 について真のまま残る (supersede しない)。

### D8. 移行と段階 (各段は単独で緑)

| 段 | 中身 | 大きさ (見込み) | Class | 前提 |
|---|---|---|---|---|
| S1 | walker と語彙、D3 の test と変異、181 node への付与、3 spec の `info.description`、CHANGELOG、`regen-openapi` skill の手順 0 | 約 450 行 / 8 file (400 行を越える理由: gate を spec の一部にだけ当てると除外リストになる。分けるなら walker と合成 spec の test を先に) | Class-1 (HTTP の挙動は変えない。spec は I14 の正典なので Class-0 にしない) | ADR の Accepted |
| S2 | D4 | 約 150 行 / 4 file | Class-1 (参加者の描画なので security-engineer のレビューを推奨) | S1 |
| S3a | D6 | 約 300 行 / 10 file | **Class-2** (security の APPROVE) | 無し (S1 より先でもよい) |
| S3b | D5 | 約 380 行 / 5 file | Class-1 | S1・S3a |
| S4 | D7、D9 の I18 の昇格 | 約 400 行 / 4 file | Class-1 (I18 の追記は architect 合意 + VP 承認) | S3b |

- 手書きの表との関係: `inlineTextFields` / `inlineTextLocals` (#375・#405) は S2 で消える。`cases.yaml` 2 本 (#381・#420) は field ごとの accept / reject の表として残る (class の下限は `text-rule.yaml`、field の上乗せは cases)。`rule.yaml` は S3a で `text-rule.yaml` になる。`sharedHelpers` (#411・#420) と `bidiFloors` (#383) は残る。
- S2 と S3a は触る file が重ならないので並行できる (WIP の上限の中で)。
- 文書: ADR-0005 の Status block と `docs/adr/README.md` の索引に導線を足す (`README.md:72-80` の例外)。workspace の `falco-api` skill の「`x-ctf-*` 5 つ」の節に schema の key を足す (skill の所有者、S1 と同時)。
- spec の行数: scoreboard の spec は約 3,040 行になり 3,000 を越えるが、ADR-0028 Signpost 2′ は分割を許すだけ (`0028:104-108`)。本 ADR は分割しない。

### D9. I18 (提案。未昇格)
> **I18 (参加者の文字列の出所)**: `http.ServeMux` を組み立てる全バイナリの spec で、string の schema node はすべて `x-ctf-text-origin` を持ち (欠落・語彙の外は fail、既定値なし、除外リストなし)、その宣言どおりに、(a) `participant-inline` / `participant-block` の request の値は route が class の規則で拒否し、(b) その response の値を portal は isolate する helper でだけ markup に入れ、(c) 参加者が選んだバイトは宣言が許す class の node にだけ現れる。機構: `TestAPISpec_TextOriginDeclared` (宣言) + `TestAPISpec_TextOriginProbes` (request。3 service に required) + `TestDisplayNames_AreBidiIsolated` (portal。spec から導出) + `TestAPISpec_TextOriginFlow` (流れ)。すべて `make test` = required check。

- 番号: I13 は予約済み、I17 は ADR-0029 が提案済み (未昇格) なので I18。
- 昇格の条件: V1〜V8 が `make test` に入った PR (S4) と同じ PR で conventions の表に足す。それより前に書かない (`docs/adr/README.md:81-83`)。

## Consequences

- **諦めたもの**
  - string を足すたびに 1 語を選ぶ手間。6 語のどれも選べない値は、まだ誰のバイトか決まっていない (設計を問う信号)。
  - body の描画の向き (D4)。最初の強い文字が RTL の body は RTL で並ぶ。
  - S3a の後、Cc / Cf (LF・TAB を除く) を含む body と、slug でない `user` の submit / exfil は 400 になる。
  - route の probe は field ごとの規則を言わない (関数の表に残す)。流れの検査は driver が通す流れだけを見る。
- **新たに守るもの**: D2 の語彙の規律と保存先の規則。participant-* を足す・外す・付け替える spec の PR は security-engineer のレビューを通す (`x-ctf-origin-guard` と同じ扱い。D3 (g) の pin がその PR を目に見えるようにする)。I18 (提案)。
- **他ロールへの影響**: software-engineer = S1・S3a。application-engineer = S2 (body の描画の確認を含む)。qa-engineer = S3b・S4 (driver の表と変異)。security-engineer = S3a の APPROVE、S2 のレビュー、C2 (b) の triage。skill の所有者 = `falco-api` と `regen-openapi`。
- **runbook**: 無し (platform は `x-ctf-*` を読まない: C5)。参加者の手順書の curl (`user` は seat) は変わらない。

## Signposts (この決定を覆す観測可能な信号)

1. **参加者が選んだ文字列が、流れの検査の外の経路で participant-* でない node から別の人の画面に出た** (review-5x・e2e・security の監査・本番で見つかった) → driver の流れでは足りない。seed を spec の `example` から生成するか、server の側で値に出所を持たせる (O2 の方向) に進む。
2. **class の規則に field ごとの例外が要る** (inline で TAB を許したい、block で LF を拒みたい等) → 語を 1 つ足して表に規則を書く。例外のリストは作らない。
3. **route が class の規則より弱い述語を当てているのに probe を通った** (review で見つかった)、または **request の decode がすべて生成型を通るようになった** (#115 F2) → class を生成型に載せ、decode の層で述語を当てる O2 に進む。
4. **`x-ctf-text-origin` を app の test 以外が読み始めた** (docs site、platform、外の道具) → extension の JSON Schema と版を定める (ADR-0005 Signpost 5、ADR-0037 Signpost 1)。

## Verification (V3 を除き `make test` = required の `test / go-test` に載せ、exit status で判定する)

- **V1 宣言 (S1)**: `TestAPISpec_TextOriginDeclared` が D3 (a)〜(g) を満たす。spec ごとに 1 本以上、participant-* の件数の pin。
- **V2 静的規則の変異 (S1、常設の表)**: 次のそれぞれで赤になり、失敗文が JSON pointer を名指す — key の無い `{type: string}` を足す / 語彙の外の値 / object の node に key / 解決できない `$ref` / response から到達する node に `participant-opaque` / participant の到達する request に `operator` / `enum` を持つ node を `token` / `participant-inline` を配列の `items` に / participant-* の property 名を response の `operator` の string に流用 / collector の forward の class を target と変える / 使われない語を語彙に足す。
- **V3 生成物 (S1)**: `make gen` の後、`internal/{scoreboard,authpolicy}/oapi/types.gen.go` に差分が無い (`gen-diff-check`。advisory なので PR 本文に出力を貼る)。
- **V4 portal (S2)**: `TestDisplayNames_AreBidiIsolated` が spec から名前を導き (導出が空なら赤)、bare `esc()` 0 件、下限を満たす。変異: spec の写しに `participant-inline` の `nick` を足し、partial に `esc(x.nick)` → 赤 / `esc(m.body)` に戻す → 赤 / local の alias を `dn` に改名して bare `esc(dn)` → 赤 (今の手書きでは下限だけが気づく)。
- **V5 route (S3b)**: `TestAPISpec_TextOriginProbes` が 3 service にあり (`requiredParityTestFuncs`)、scoreboard の導出は 12 組 (pin)、driver の表と導出が双方向に一致し、baseline が 2xx、probe が D5 のとおり。変異: `validBoardSubject` から `inlineTextHasForbidden` を外す → 赤 / `submit` の `validUser` を外す → 赤 / spec の写しに driver の無い `participant-inline` の request field を足す → 赤 / 表に余分な driver → 赤 / baseline が 4xx になる driver → 赤 / `text-rule.yaml` に probe の無い category を足す → 赤。
- **V6 規則 (S3a)**: `text-rule.yaml` の class の鍵 = 語彙 (双方向)。`validBoardBody` の全 code point の走査が block の規則と一致 (LF・TAB は受理、U+200D は emoji の間だけ)。submit と internal exfil に slug でない `user` → 400 の handler test。
- **V7 流れ (S4)**: `TestAPISpec_TextOriginFlow` が D7 を満たす。変異: spec の写しで `BoardSummary.subject` を `operator` に → 赤 / 応答の `reason` に flag を埋める test 用の handler → 赤 / token の node に marker → 赤 / marker が 1 つも観測されない → 赤 / GET の parameter の表に無い名前 → 赤 / `DisplayNameRequest.name` を `operator` にした spec の写し → 赤 (保存先の規則)。
- **V8 検査が嘘でないこと**: V2・V4・V5・V7 の変異は常設の table-driven test にする (ADR-0005 V8)。抽出 0 件は赤。
- **この検査が見ないもの**: 見た目の似た文字・空白に見える文字 (U+3164 など。表示名の偽装は admin の reset: ADR-0034)、inline の中の U+2028 / U+2029 (Zl / Zp。`categories` の外)、属性の中の参加者の文字列 (gate は bare `esc()` を一律に拒否する。属性に要るなら helper を足す)、ブラウザの Unicode の表 (ADR-0035 C4)、`operator` の content の中の bidi、要求した本人への echo (C2 (c))、parameter への route の probe (D5)、driver が通さない流れ (Signpost 1)。

## Advice (受けた助言。非拘束でも記録する)

- **VP (2026-10-18、本 ADR の発注)**: 宣言の形 (名前・値・置き場、ADR-0037 との関係)、portal の gate と request 側の表駆動 test の導出、fail-closed、移行 (本数と PR 数、Class)、追補か新 ADR か、slug / enum を検査対象外にする理由の明記。→ D1〜D8。追補にせず新 ADR にした (ADR-0005 の Decision / Verification は凍結: `0005:7`。ADR-0037 も新 ADR だった)。slug / enum は Cc / Cf の表からは外し、文法外の 1 値の probe を当てた (D2 末尾。C2 (b) で slug の宣言が実装で偽だったため)。
- **Issue #407 (app#405 review-5x R4#1、2026-10-17)**: 必須の extension、2 つの導出、opt-in の印と共有表を採らない。→ D1・D3・D4・D5。語を `slug` → `token` にし、`participant-opaque` を足した (D2)。
- **ADR-0037 (2026-10-17)**: 構造化した宣言から性質を導く流儀と、権威は組み立てる側に置く規則。→ D1 で「組み立てる者が無いので spec」と読んだ。
- **security-engineer**: 未受領。S3a・S2 のレビューと C2 (b) の triage で受けて追記する。
- **qa-engineer / application-engineer**: 未受領 (S3b・S4 の driver の表の形、S2 の body の描画)。
- **architect (発注の外)**: C2 の 3 件は分類の途中の実測。body に新しい `blockHTML()` を作らず `textHTML()` を要求した (検査できる性質だけを要求する)。流れの規則 (D7) で response の側の誤分類と保存先の規則を機械にした。
