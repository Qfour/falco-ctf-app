# ADR-0039: spec の string の schema node ごとに、誰がそのバイトを選べるかと見せ方を省略できない `x-ctf-text-origin` で宣言し、portal の bidi gate・route の文字の拒否・応答への流れをその宣言から導いたテストで確かめる

- Status: **Accepted** (2026-10-18、VP 承認。S1 = app #452 の merge 前に昇格、D1〜D9 は rev2 のまま)。Accepted 化は VP (時限承認: workspace `ORGANIZATION.md:470-472`。S1 の merge より前)。spec に必須の extension を新設する (= API 契約の新設) ので architect 合意 + VP 承認 (`ORGANIZATION.md` §4)。HTTP の挙動を変えるのは S3a だけで、Class-2 (security-engineer の APPROVE)。S3a は rev2 で 2 つに分けた: S3a-1 (seat の `user`) は app#433 で merge 済み、S3a-2 (board の body) は未着手 (D6・D8)。クロスリポ契約・新 image・新サービス・Dockerfile に触れないので CEO 判断を要さない。D9 の I18 は提案だけで、昇格は S4。実装は Proposed のまま始めてよい。
- Date / Deciders: 2026-10-18 (rev2 も同日) / VP (承認) + architect (起草・API 契約と I18 提案への同意) + security-engineer (S3a の APPROVE、S2 のレビュー、C2 (b) の triage と body の規則の判断。後の 2 つは 2026-10-18 に受領) / 実装: software-engineer (S1・S3a)、application-engineer (S2)、qa-engineer (S3b・S4)
- 関連: Issue #407 (発注元。app#405 review-5x R4#1)、#428 / #433 (S3a-1。2026-10-18 merge)、#429 (S3a-2 の body の規則)、#439 / platform#257 (保存済みの slug でない `user`)、#440 (seat の文法を 1 か所に)、#437 (challenge id の文法を 1 か所に)、#421 (保存済みの件名と body)、#343 / #375 / #383 (表示名の隔離と gate)、#377 / #405 (件名)、#408 / #420 (件名の client 事前検査)、#401 / #411 (sharedHelpers)、#419 (保存済み表示名の warn)、#115 F2 (生成型の採用)、#113 (`err.Error()`)、ADR-0005・ADR-0009 (spec の parity と V5)、ADR-0028 (Signpost 2′)、ADR-0034 (表示名・絵柄)、ADR-0035 (goja・form は server より厳しくならない)、ADR-0037・ADR-0038 (閉じた語彙と構造からの導出)、I8・I14。フェーズ: 非該当
- 読み方: rev2 は app の origin/main `6adb77a` (#433 の squash merge。tree は PR の tip `135356b` と同じ。#424・#425・#435 も含む) で全行を引き直した (rev1 の `295e8af` から `api.go`・`pane-board.tmpl`・`bidi_test`・spec の行がずれた)。platform は origin/main `e126fff`。`0005:N` などは `docs/adr/` の各 ADR の行、`api.go` は `internal/scoreboard/api/api.go`、`board.go` は `internal/scoreboard/api/board.go`、`spec` は `docs/openapi-scoreboard.yaml`、`bidi_test` は `internal/scoreboard/view/portal_bidi_test.go`、template は `internal/scoreboard/view/templates/portal/` の partial (`index.html` は `internal/scoreboard/view/templates/index.html`)。
- 改訂: rev2 (2026-10-18) は app#433 の review-5x (30 回目) の R4#1〜R4#4 と、security-engineer の 2 つの判断 (#429、#433 の review) の反映。変えた節: Status・関連・読み方・C1〜C3・C5・C6 と O2 (行のみ)・D2 (seat の値は token)・D3 (e) (受理の keyword まで比べる)・D4 (first_solver の扱いと floor の数え方)・D5 (規則の file・probe・赤の組)・D6 (S3a-1 / S3a-2、保存済みの値)・D7 (ii) の注記・D8 (表と段の外の follow-up)・D9 (行のみ)・Consequences・Signpost 2 / 3・V2 / V4 / V5 / V6 / V8・見ないもの・Advice。Decision (O1) と D1 は変えていない。

## Context

- **C1 「参加者が書いた inline の文字列」の field の集合が 2 つの側に別々にあり、どちらも宣言から導かれていない。**
  - portal: `inlineTextFields = {display_name, authorDisplay, subject, first_solver}` と `inlineTextLocals = {displayName}` は手書き (`bidi_test:34,38`)。gate は走査型 (#375) で、下限 (`bidiFloors`、`bidi_test:167-172`) と変異 test (#383) を持つが、走査する「名前」は人が足す。
  - server: field の集合そのものが無い。あるのは handler が validator を呼ぶこと (`validDisplayName` `api.go:1136` を admin rename `api.go:1172` と profile `internal/scoreboard/api/profile.go:138` が呼ぶ、`validBoardSubject` `board.go:73-85`)、関数を叩く表 (`internal/scoreboard/api/testdata/display-name-parity/cases.yaml`、`testdata/board-subject/cases.yaml`)、全 code point の走査 (`testdata/display-name-parity/rule.yaml:22-24` と比べる) の 3 つで、「この request field にこの規則が route で当たる」「この request field の値をこの response field が返し、portal が読む」を結ぶものは無い。
  - 同じ bug class が 3 回起きた: 表示名 (#343 → #375)、件名 (#377。#375 の review で見つかり、#405 が両側に手で足した)、seat の `user` (#428。本 ADR の分類の途中で見つかり、#433 が server の検査と `inlineTextFields` の両方に手で足した: C2 (b))。opt-in の印 (`x-ctf-participant-text: true` の類) や両側が読む共有表は、新しい field を足す PR が印も表も触らなければ黙って外れる。これは 3 回の失敗様式そのものなので採らない (Issue #407)。

- **C2 181 本を分類すると、紙に書かれた前提のうち 3 つが実装と合わなかった** (rev1 が `295e8af` で実測。(b) は S3a-1 で直った。(a) は S2 と S3a-2 が直す)。
  - (a) body: 「A message body is a block of its own (a <div>), so it is not in this set」(`bidi_test:19`)。今も真 (`pane-board.tmpl:538,835` は `<div class="thread-msg-body">` の中の `esc(m.body)`、`css.tmpl:769` が `pre-wrap`) だが、誰も検査しない。body を一覧の行に inline で出す変更は gate を通る。server の `validBoardBody` は trim と長さしか見ず (`board.go:90-99`)、U+202E・U+200B・C1・NUL・CR をそのまま保存する (`6adb77a` でも同じ)。
  - (b) seat の `user` (**S3a-1 = #433 で修正済み**)。rev1 の時点では、`bidi_test` が「first_solver is a username slug, not a name」と書き、spec も「first solver's username」と書く (`spec:2719-2722`) が、`POST /api/challenges/{cid}/submit` と `POST /internal/exfil/{cid}` は `user` が空でないことしか見ていなかった。`submit-detect` だけが `validUser` (`api.go:62`) を当てていた (`api.go:1422-1426`)。`Grader.SubmitEvade` (`internal/scoreboard/scoring/scoring.go:689-705`) と `Store.MarkSolved` (`internal/store/store.go:590-605`) は今も検査しない。collector は body を解釈せずに転送する (`docs/openapi-collector.yaml:94-96`)。よって plain な evade の flag を知る参加者は、workspace の curl で任意のバイト列を `user` にした solve を作れ、それは State の `leaderboard[].user`・`first_solver` などに載り (`api.go:2489-2497,2614-2635,2666-2683`)、`first_solver` は bare `esc()` で inline に出ていた。見えるのは運営の画面 (State は admin) で、U+202E を含む `user` はその行の並びを崩す。claimed identity で他の seat に solve を付けられることは既知の設計 (`api.go:1195-1197`、`spec:2036-2040`) だが、seat の形をしないバイト列を保存できることは別の欠陥だった。#428 で起票し、#433 が両 route の server の検査 (`api.go:1243-1251,1593-1599`)、spec の `pattern`、`first_solver` の `nameHTML` (`pane-scoreboard.tmpl:242`、`index.html:378`) を入れた (D6)。本 ADR に残る教訓: slug という宣言は実装で偽になり得る (D2 末尾で token を検査の外に置かない理由)。
  - (c) `SubmitFlagVerdict.reason` は claimed `user` を `%q` で埋め (`api.go:1292-1298,1312-1317,1326-1330`)、`Error.error` は `{cid}` を返す (`api.go:1216`)。どちらも要求した本人の応答にだけ出る (self-echo) ので、別の人の画面への流れではない。本 ADR の分類は「書いた人と読む人が違う」流れについて言う (S3a-1 の後、`reason` に入る `user` は slug だけ)。
- **C3 string の schema node は 181 本** (scoreboard 159 / collector 4 / auth-policy 18。`6adb77a` でも同じ: #433 は既存の node に `pattern` などを足しただけ)。数え方: `type` が `string` (または `string` を含む列) の Schema Object を、`components.schemas`・`components.parameters.*.schema`・operation の inline の parameter / requestBody / response / response header の schema から、`properties`・`items`・`additionalProperties`・`allOf|anyOf|oneOf` を辿って数える。`$ref` の節点は数えない (参照先で 1 回)。内訳は JSON の property 157 (配列の `items` を含む)、parameter 15、response header 9。書式は flow 形式 (`{type: string}`) が 124、block 形式が 57 (rev1 は 127 / 54。#433 が seat の `user` の 3 node を block 形式にした)。
- **C4 既存の `x-ctf-*` は operation に付き、Go の `Routes()` と比べる** (必須: `0005:153-157`、既定値なし: `0005:236-237`、実装: `internal/apispec/specparity/parity.go:58-133`)。ADR-0037 は rate-limit の宣言の権威を Go に置いた。理由は limiter をその宣言から組み立てるから (`0037:90-93` の (b))。文字列の出所には runtime で組み立てる者が無い: validator は field ごとの関数 (32 rune と 120 rune、metacharacter の有無、trim)、描画は portal の JS で、どちらも class から組み立てられない。field の正典は spec (`0005:294`)。
- **C5 読み手。** 消費するのは app の test の 3 package (`internal/scoreboard/api`・`internal/scoreboard/view`・`internal/scoreboard` の parity) と、`internal/apispec` の spec の検査だけになる。platform に `x-ctf-` は 0 件 (`git grep`、platform origin/main `e126fff`)、docs site は spec を描画しない (`git grep -i openapi -- images/` は 0 件)。クロスリポ契約ではない。
- **C6 制約。** ADR-0005: 除外リストを持たない、欠落は fail、Decision / Verification は凍結 (`0005:7`、`docs/adr/README.md:73-81`)。ADR-0037 D1 / ADR-0038 D2: 語彙は閉じた集合で、使わない語を置かない。ADR-0035: form は server より厳しくならない。拘束力があるのは `make test` だけ (`gen-diff-check` は required でない: `0005:9-12`)。`internal/apispec/specparity` は test 専用 (`internal/apispec/dependency_boundary_test.go`)。`specparity` の `resolve` は components の外の `$ref` を黙って nil にする (`internal/apispec/specparity/spec.go:197-207`)。oapi-codegen v2.3.0 は schema の未知の `x-` key を無視する (仮説。S1 の V3 で確かめる)。

## Options (Alternatives)

### O1 (推奨). string の schema node に必須の `x-ctf-text-origin` を置き (権威は spec、Go に写しを持たない)、portal の gate・route の probe・応答への流れの検査をそこから導く
- 変更点: 181 node に閉じた 6 語のどれか 1 つを書く。test が spec を読んで、portal が走査する名前、route ごとに叩く field、応答のどの node に参加者のバイトが出てよいかを導く。
- コスト: 運用 = string を足す PR は 1 語を選ぶ。認知 = 6 語の表 1 枚 (D2)。依存・image = 増えない (walker と語彙は test 専用の `specparity`)。spec は約 70 行増える (flow 形式は同じ行、block 形式は 1 行ずつ)。
- リスクと可逆性: 低。HTTP の挙動を変えるのは S3a だけ (S3a-1 は済)。読み手が app の test だけなので、key の形は 1 PR で戻せる。O2 へは「class を生成型に写す」を足せば移れる (spec の宣言はそのまま使える)。
- 効き始める閾値: S1 から。新しい string を分類無しで足した PR が赤になる。

### O2. class を生成型の struct tag に写し、request の decode の層が class ごとの述語を自動で当てる
- 変更点: oapi-codegen の `x-oapi-codegen-extra-tags` で class を生成型の field tag にし、全 handler が生成型に decode して、tag を読む共通の検査を通す。portal は O1 と同じく spec から導く。
- コスト: request の decode を生成型に揃える (今、生成型で decode するのは submit・submit-detect・falco/events (`0005:124-129`) と board (`board.go:136`) で、admin rename と internal exfil は手書きの struct: `api.go:1164-1166,1577-1580`)。全 handler の変更で、Class-2 が handler の数だけ要る。field ごとの規則 (長さ・metacharacter・trim) は class では決まらないので関数の validator は残り、述語が 2 か所になる。生成物の鮮度は required でない `gen-diff-check` に頼る。
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
| `participant-block` | 同上。自分の block (複数行) に出る | 同上 | 同上。ただし LF と TAB は受理 (語の中の U+200C / U+200D と emoji の間の U+200D も受理するが、文脈つきなので probe にせず表で固定する: D5・D6) | 同上 (isolate を要求。S2)。受けてよい marker: inline・block (S4) |
| `participant-opaque` | 参加者が選ぶが、どの応答にも載らない (flag、Falco の condition、credential の header、CSP report、強制変換される選択子) | response から到達する node に置かない | 無し (文字の規則を持たない) | その marker がどの応答にも出ない (S4) |
| `operator` | 運営側だけが選ぶ自由文 (repo の content と catalog、運営の設定、server の文、falcosidekick の event) | request では `x-ctf-audience: operator` か「`internal` かつ `x-ctf-collector-forward: false`」の operation にだけ置く | 無し | 受けてよい marker: operator (S4) |
| `token` | 閉じた文法の値 (seat・challenge の slug、hex の id、RFC 3339 の時刻)。印字可能 ASCII (U+0021–U+007E) だけ。誰が選ぶかを問わない (下の seat の項) | `enum` / `const` を持たない | 文法外の 1 値 (`"a\u202Eb"`) が非 2xx | 実値が印字可能 ASCII で、`pattern` / `format: date-time` があればそれにも合う。marker を受けない (S4) |
| `enum` | 閉じた集合 | `enum` か `const` を持つ (逆に、それらを持つ node は必ず `enum`) | 集合外の 1 値が非 2xx | 実値が集合に入る。marker を受けない (S4) |

- issue の仮の語との違い: `slug` → `token` (hex の id と時刻は slug でないが、どの検査でも同じに扱う)。`participant-opaque` を足した (flag と condition に文字の規則を当てると提出が壊れ、`operator` と書くと参加者のバイトを運営のものと偽る)。`enum` は issue の `enum/constant`。
- **seat の値は `token`** (rev2。app#433 review-5x R4#1)。request の `user` (submit・internal exfil・submit-detect)、path の `{user}`、response の seat の値 (`ChallengeStat.first_solver`・`ChallengeStat.solvers[]`・`ChallengeSolver.user`・`LeaderboardEntry.user`・`SolveRecord.user` ほか) はすべて `token`。参加者は claimed identity でどの seat を名乗るかを選べるが、選べるのは文法の中の値だけで (S3a-1 以後。ingest の ns も同じ文法: `internal/scoreboard/ingest/ingest.go:127,323`)、見せ方の危険 (bidi・不可視の文字) を運ばない。token を「誰が選ぶか」でなく文法で決めるのはこのため。帰結として D4 の導出は seat を走査しない (今の手書きの表にある `first_solver` は S2 で外れる)。その代わりに何が受け持つかと、participant-inline にしない理由は D4。
- 実測の分類 (S1 = app #452、2026-10-18): inline 17 (response 14 = `display_name` ×9・`authorDisplay` ×3・`subject` ×2、request 3 = `DisplayNameRequest.name`・`ProfileRequest.display_name`・`CreateThreadRequest.subject`)、block 4 (`BoardMessage.body` と request の `body` ×3)、opaque 26 (flag ×3・condition・CSP report ×14・`CreateThreadRequest.audience`・`?mission`・auth-policy の `Cookie` / `Authorization` ×6)、operator 49、token 67 (seat の値を含む)、enum 18。
- slug / enum を Cc / Cf の category の表から外す理由: 規則が「自由文から category を引く」ではなく「閉じた文法への所属」で、そちらの方が厳しい。ただし検査の外には置かない。文法外の 1 値で十分に区別でき、C2 (b) のとおり slug という宣言は実装で偽になり得るから (rev1 の時点で実際に偽だった: #428)。

### D3. 宣言の検査 (S1。`internal/apispec` の `TestAPISpec_TextOriginDeclared`)
`specNameForCmd` (`internal/apispec/mux_ownership_test.go:236-240`。V6 が mux を持つ binary の走査と照合する表) の全 spec を回す。service ごとの配線は要らない (spec が増えれば V6 が表を増やさせる)。
- (a) C3 の数え方で見つけた全 string node が key を持ち、値が語彙にある。失敗文は JSON pointer を名指す。
- (b) string でない node は key を持たない。
- (c) walk で解決できない `$ref` (components の外・存在しない名前) は fail。spec を分割 (ADR-0028 Signpost 2′) して外部 `$ref` になったとき、node が黙って検査から消えないように。
- (d) D2 の静的規則: response から到達する opaque / 参加者の届く operation (D2 の `operator` の行の条件を満たさないもの) の request にある operator / `enum` ⇔ `enum`・`const` / participant-* は response では名前付きの property だけ (`items`・`additionalProperties` に置かない。portal の走査が名前で値を見るため) / participant-* の property 名を response の他の class の string に使わない。request か response かは operation から `$ref` を辿って決め、両側で使う component は両方の規則を受ける。
- (e) collector の forward の operation が request の schema を書くなら、その string node は `x-ctf-forward-target` の request の同じ pointer の node と次が一致する (pointer の集合も双方向に一致する): class、受理を決める keyword (`type`・`pattern`・`maxLength`・`minLength`・`format`・`enum`・`const`。`$ref` は解決してから比べ、`description` は比べない)、親 object の `required` に入るかどうか。今の対は exfil の inline の `{user, flag}` (`docs/openapi-collector.yaml:114-127`) と scoreboard の `ExfilRequest` (`spec:2112-2121`) で、`6adb77a` では一致する。parameter は比べない (collector は `{cid}` を自分で検査するので写しではない: `docs/openapi-collector.yaml:104-105,256-263`)。rev2 で比較を class から受理の keyword まで広げた (app#433 review-5x R4#4。選択肢と理由は D8 の末尾)。
- (f) 語彙の各語が少なくとも 1 node で使われる。
- (g) spec ごとに string node が 1 本以上。participant-inline・participant-block・participant-opaque の本数を pin する (足す・外す・付け替える PR が pin の行を触る。review の目印で、ADR-0009 の件数 pin と同じ)。
- walker と語彙は `internal/apispec/specparity/textorigin.go` に置く (test 専用。production に入らない)。

### D4. 導出 1: portal の gate (S2。`bidi_test`)
- `inlineTextFields` を消し、spec の response から到達する `participant-inline` と `participant-block` の property 名の集合を導く。導出は `{display_name, authorDisplay, subject, body}` で、今の手書き (`bidi_test:34` = `{display_name, authorDisplay, subject, first_solver}`) と比べると **`body` が増え、`first_solver` が減る**。`inlineTextLocals` も消し、「宣言の初期化式がその名前を読む local は参加者の文字列」を 1 段だけの走査で導く (`pane-me.tmpl:364` の `const displayName = d.display_name || user;` から `displayName`)。
- **`first_solver` が減るのは意図した変化で、黙って起こさない** (rev2。rev1 はこの減少を書いておらず、rev1 の D4 のとおりに作ると first_solver が走査から黙って外れた: app#433 review-5x R4#1)。first_solver は seat の値で `token` (D2)。手書きの表に入ったのは #433 (S3a-1) の多層防御で、出所の宣言ではない (`bidi_test:32-33` の comment も、server が slug の文法に保つ値だが保存された claimed な値なので gate する、という理由を書く)。S2 は first_solver を走査から外し、その site を次の 3 つに委ねる。S2 の PR 本文にこの減少と 3 つを書く。
  - **描画 = floor**。S2 は floor の数え方を「参加者の名前を引数にとる helper の呼び出し」から「helper (`nameHTML` / `textHTML`) の呼び出しすべて (引数を問わない)」に変える。今の数え方 (`isolatedUseRe` は `inlineTextArg` から作る: `bidi_test:42,134`) のままだと、first_solver が導出から外れた時点で `nameHTML(c.first_solver)` (`pane-scoreboard.tmpl:242`、`index.html:378`) が数えられなくなり、pane-scoreboard と index.html の floor を 6 → 5 に下げることになって、この site を bare `esc()` に戻しても何も赤くならない。数え方を変えても floor の値は変わらない (`6adb77a` の helper の呼び出しは pane-scoreboard 6・pane-board 11・pane-me 1・index.html 6 で、今の floor と同じ)。この site の isolate を機械で保つのは、security-engineer の #428 step 3 の判断 (D6) が「古い行が残っても first_solver は bdi で隔離される」を根拠の 1 つにしているから。数え方は分類から独立になるが、分類の変更は D3 (g) の pin が目に見えるようにする。
  - **文法 = server と導出の検査**。書き込みは S3a-1 の server の検査 (`api.go:1246,1595`。submit-detect は `:1422`) と、S3b の D5 の token probe (文法外の 1 値が非 2xx。probe する field は spec から導くので、seat を書く route が増えればその場で入る)。読み出しは S4 の D7 (ii) (応答の token の葉が印字可能 ASCII で、`pattern` があればそれにも合う)。応答の seat の node には今 `pattern` が無いので (`spec:2665,2691,2714,2719-2722,2728`)、D7 (ii) が見るのは印字可能 ASCII までだが、bidi 制御・不可視の文字・C0 / C1 はすべてその外にあるので、描画の安全にはそれで足りる。
  - **古い行 = 運用と起動時の検査**。S3a-1 より前に保存された slug でない `user` は、開場前の DB を新規 PVC か admin reset にする前提 (platform#257) と、起動時に件数だけを Warn し Sweep が飛ばす follow-up (app#439) が受け持つ (D6)。
- **seat を `participant-inline` にして走査に残す案は採らない**。(1) D2 の意味と合わない: participant-inline は参加者が選ぶ自由文の語で、閉じた文法の値ではない。(2) D7 (ii) の文法検査を失う: (ii) は token / enum の葉だけを文法で見るので、first_solver が participant-inline なら応答の側で誰も slug の形を見ない。(3) 保存先の規則 (D1) と D3 (d) で広がる: 同じ `solved.user` を `LeaderboardEntry.user`・`ChallengeSolver.user`・`SolveRecord.user`・`ChallengeStat.solvers[]` も返す (`api.go:2489-2497,2614-2635,2666-2683`) のでそれらも participant-inline になり、D3 (d) により `Journey.user`・`Me.user` など他の `user` も participant-* にすることになる。すると gate は属性の中の `data-user="${esc(p.user)}"` (`pane-scoreboard.tmpl:208`、`index.html:344`。`<bdi>` を置けない) を拒否する。
- 規則は 1 つ: 導出した名前を bare の `esc()` に渡さない (0 件)。`nameHTML()` / `textHTML()` (`core-util.tmpl:44,54`) を通す。
- **block にも isolate を要求する。** body の 2 か所 (`pane-board.tmpl:538,835`) を `textHTML(m.body)` にする。block 要素の中にあることは layout の事実で、template の走査では確かめられない (三項演算子、連結、後から足す preview)。`<bdi>` は inline でも block の中でも漏れを止めるので、検査できる性質 (helper を通ったか) を要求する。新しい `blockHTML()` は作らない (block であることは安全に寄与しない)。`textHTML` の doc (`core-util.tmpl:46-53` の「Not for a block of text」) を「参加者の文 (inline でも block でも)」に直す。見える変化: 最初の強い文字が RTL の body は、その向きで並ぶ (`<bdi>` の向きは中身で決まる)。
- `bidiFloors` は下限として残し (数え方は上のとおり)、`pane-board.tmpl` を 11 → 13 にする (pane-scoreboard 6・pane-me 1・index.html 6 は変わらない)。`sharedHelpers` (`bidi_test:70`) は helper の 1 定義の検査で、field の分類とは直交するので残す。`6adb77a` の変異の表 (`bidi_test:262-372` の 32 件) は、数え方を変えた後も同じ誤りで赤になる (1 件ずつ読んで確かめた。S2 が実行で確かめる)。
- view の test は `specparity` を import して spec を読む (test から test 専用 package への import で、境界の検査は production の import だけを見る)。

### D5. 導出 2: route の文字の検査 (S3b。`TestAPISpec_TextOriginProbes`)
- **導出集合**: operation の JSON request body を `$ref` を辿って歩き、class が `participant-inline` / `participant-block` / `token` / `enum` の (operation, JSON pointer, class)。collector の forward は target で叩く (D3 (e) で class は同じ)。今は scoreboard の 10 operation / 12 組: inline 3 (profile の `display_name`、admin rename の `name`、thread の `subject`)、block 3 (thread・message・admin reply の `body`)、token 3 (submit・internal exfil・submit-detect の `user`)、enum 3 (profile の `avatar` (`profile.go:149-150`)、admin の thread と message の `state` (`board.go:529,575`))。
- **driver の表**: operation の鍵 → 有効な要求の組み立て (path、identity、Origin、前提の状態、全 field に有効な値)。鍵の集合を導出集合と双方向に比べる (`specparity.CoverageDiff` と同じ形: `internal/apispec/specparity/coverage.go:93-109`)。導出にあって表に無い = 赤、表にあって導出に無い = 赤。D7 と 1 つの表を共有する (鍵の集合 = 2 つの導出集合の和)。
- **判定**: driver ごとに (1) baseline (有効な値のまま) が 2xx であること (でなければ 400 が field のせいだと言えない)。(2) probe ごとに新しい handler で (bucket が status を決めないように)、対象の field だけを `"a" + probe + "b"` (端の trim を避ける) に替えて送る。class が拒否する probe → 400 で body が `Error` の形。block が受理する probe (LF・TAB) → 2xx。token / enum → 文法外の 1 値が非 2xx。文脈つきの例外 (D6 の語の中の U+200C / U+200D、emoji の間の U+200D) は probe にしない (`"a" + U+200C + "b"` は語の中なので受理になる。文脈は D6 の表が固定する)。
- **規則と probe の file**: `internal/scoreboard/api/testdata/text-rule.yaml` (S3a-2 で今の `display-name-parity/rule.yaml` を組み替える。形は security-engineer が #429 の判断で示した案)。`classes` の下に class ごとの `categories` (どちらも `Cc`・`Cf`)・`allow` (block だけ U+0009 と U+000A)・`exempt` (code point → 文脈の語の列。inline は U+200D → `between-emoji`。block は U+200C → `inside-word`、U+200D → `inside-word`・`between-emoji`)。表示名だけの `meta`。`probes` (U+202E・U+2066・U+200F・U+200B・U+FEFF・U+00AD・U+2060・U+E0041・U+0085・U+009B・U+0000・U+000D・U+007F・U+0009・U+000A)。文脈の語は閉じた集合で、各語は Go の述語 1 つ (`between-emoji` = 直前が emoji の前置 (So、U+1F3FB–1F3FF、U+FE0F) で直後が So。今の `isEmojiPrefix` / `isEmojiBase`: `api.go:1070-1075`。`inside-word` = 直前と直後がともに L か M)。検査: class の鍵の集合 = 語彙の `participant-inline`・`participant-block` (双方向)、文脈の語の集合 = Go の述語の表 (双方向)、各 probe はどれかの category に入る、`exempt` の code point は probe にない、各 category に `allow` でない probe が 1 つ以上ある。`participant-inline` の中身は今の `categories` / `exempt` と同じ (表示名と件名の規則は変わらない)。
- **probe しないもの (理由)**: path / query / header の parameter は lookup key か選択子で、route が catalog・ロスター・store・登録表と照合し、外れは spec が書く 404 / 400 か既定値になる (保存されるのは照合した側の値)。D3 の静的規則だけを受ける。`participant-opaque` と `operator` は文字の規則を持たない (opaque は D7 が流れで見る)。field ごとの規則 (32 rune・120 rune・metacharacter・trim・ZWNJ / ZWJ の文脈) は関数の表 (`cases.yaml`。S3a-2 の後は 3 本) と全 code point の走査が持つ。route の probe が言うのは「その route がその field に class の下限を当てる」ことだけ。
- 3 service に同じ名前の test を置き、`requiredParityTestFuncs` (`internal/apispec/parity_coverage_test.go:66-70`) に足す。collector と auth-policy は導出が 0 件 (collector の body は forward で target が持ち、auth-policy に body は無い) で、0 件を許す (`TestAPISpec_IdentitySourceProperty` と同じ形: `parity_coverage_test.go:37-46`)。body を持つ operation が足されたらその場で導出に入る。
- `6adb77a` で赤になる組 (S3a-2 が直す): block 3 (C2 (a))。token の 3 組は S3a-1 の後なので緑 (`api.go:1246,1595,1422`)。rev1 が赤に数えた token 2 (submit と internal exfil の `user`) は #433 で直った。

### D6. validator の変更 (S3a。Class-2。rev2 で S3a-1 (済) と S3a-2 に分けた)
- **S3a-1 = seat の `user` (#428 / #433、2026-10-18 merge、`6adb77a`)**。C2 (b) は D1〜D5 に依存しないので、S1 より先に hotfix として出した。
  - `submit` と `internal/exfil` の `user` に trim の後で `validUser` (`api.go:62`) を当て、外れは 400 `{"error":"invalid user"}` (固定文で入力を返さない。`submit-detect` (`api.go:1422-1426`) と同じ形)。Grader を呼ぶ前なので solve も receipt も保存せず、flag の正否で応答が変わらない (`api.go:1243-1251,1593-1599`)。
  - spec: `SubmitFlagRequest.user`・`SubmitDetectRequest.user`・`ExfilRequest.user` と collector の inline の写しに `pattern` (`User` parameter と同じ: `spec:1869`) と `maxLength: 63` (`spec:2036-2040,2084-2087,2116-2120`、`docs/openapi-collector.yaml:123-126`)。2 route の 400 の説明に文法を書いた。
  - 描画: `first_solver` を `nameHTML` に (`pane-scoreboard.tmpl:242`、`index.html:378`)。手書きの `inlineTextFields` に `first_solver` を足し、floor を 6 / 6 にした (`bidi_test:34,167-172`)。この手書きは S2 で D4 の導出に置き換わる (first_solver の扱いは D4)。
  - test は `internal/scoreboard/user_slug_test.go` (V6)。CHANGELOG の Security に upgrade note と区分 (minor) を書いた (`CHANGELOG.md:116-118`)。workspace の curl は seat を送るので、正しい提出は変わらない (大文字などの打ち間違いは、以前は別の user の solve になって seat に付かなかったが、今は 400 で分かる)。
  - security-engineer: APPROVE with comments (LOW 5 は #433 で反映)。
- **S3a-2 = board の body (#429、未着手)**。security-engineer の判断 (#429、2026-10-18) は (a) に語の中の例外を足した形で、(b) (#377 の「body は検査しない」の維持) は採らない (理由は Advice)。
  - `validBoardBody` (`board.go:90-99`) に participant-block の規則を当てる。LF と TAB を受理し、他の Cc (C0・DEL・C1・CR) と Cf をすべて拒否する。例外は 2 つ: U+200C ZWNJ と U+200D ZWJ は直前と直後がともに文字か結合記号 (L か M) のとき受理し (ペルシア語の語形、インド系の文字の virama の隣)、ZWJ はこれに加えて表示名と同じく emoji の間で受理する。U+200B・U+2060・U+00AD・語の中の U+FEFF・U+200E / U+200F / U+061C・tag 文字は拒否する (U+FEFF だけの本文も 400 になる: #429 の追記、app#425 R2#5)。CR は拒否 (portal の textarea の値は LF に正規化され、board の書き込みは origin-guard 付きで workspace の curl から届かない)。
  - 文脈の判定は Go の 1 か所 (`hasForbiddenRune` (`api.go:1102-1116`) を一般化したもの) に置き、`text-rule.yaml` の文脈の語 (D5) とその表を双方向に比べる。
  - 運営の返信 (`PostReplyRequest.body`) にも同じ規則を当てる (D1 の保存先の規則)。
  - flag の形の拒否は残す。照合を U+200C / U+200D を除いた文字列で行うのは任意 (#429 (ii)。この gate はもともと意図的な漏えいを止めない)。
  - 400 の文は固定で入力を返さず、利用者がすることを書く。2 種類 (制御文字か見えない書式文字がある / 語の外に ZWNJ・ZWJ がある)。
  - `rule.yaml` を D5 の `text-rule.yaml` に組み替え、読み手 4 つ (`display_name_parity_test.go`・`board_subject_rule_test.go`・`portal_nameproblem_test.go`・`portal_subjectproblem_test.go`) を直す。block の全 code point の走査を足す (`TestBoardSubject_SweepEveryCodePoint` と同じ形。exempt の 2 code point は走査から外し、表で固定する)。body の `cases.yaml` に #429 (ii) の表の全行と (iii) の各 code point の行を置く。
  - security の APPROVE の条件 (#429 の 5 つ): 走査が participant-block と一致し、inline の走査と既存の `cases.yaml` 2 本は変えずに緑 (表示名と件名の規則が動いていない) / body の `cases.yaml` / 固定文 / 返信にも同じ規則 / 文脈の判定が Go の 1 か所にあり、語の集合と双方向に一致。
  - body の form の事前検査 (見えない文字の位置と code point を示す。application-engineer) は merge 条件ではない。ADR-0035 のとおり form は U+200C / U+200D を常に通し、文脈は server が決める。`pane-board.tmpl` を触るので S2 の後にする。
  - CHANGELOG に、拒否が増えることと保存済みの body を書き換えないことを書く。
- **保存済みの値** (rev2。security-engineer の #428 step 3 の判断、#433 の review、2026-10-18)
  - `user`: claimed な `user` が届く table は `solved` と `exfil` だけで (user を key にする他の table は検査済みの経路からしか書かれない: ingest の ns、path の `{user}`、profile、admin)、`Store.Reset()` (admin reset、`internal/store/store.go:1015-1050`) は両方を全行消す。イベントは新規 DB で始める前提。古い行が残っても描画の影響は小さい (first_solver は S3a-1 で isolate され、他の名前の表示は既に `nameHTML` を通る)。**判断: 起動時の check は S3a-1 の merge 条件にしない。** 前提「開場前の DB は新規 PVC か admin reset」は sre-engineer が stand-up の必須手順に書く (platform#257)。follow-up (LOW、推奨) は app#439: 起動時に `solved` / `exfil` のうち `validUser` に合わない `user` の件数だけを Warn し (値も一覧も出さない。#419 と同じ型)、`Grader.Sweep` が slug でない receipt を飛ばす (今は `PendingExfilSolves` の receipt を user を見ずに `evaluateClean` → `MarkSolved` に流す: `scoring.go:947-958`)。
  - body: #421 の決定に同じ形で含め、独立の仕組みは作らない (#429 (iv))。body は D4 で isolate される。

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

  加えて (i) `participant-inline` / `participant-block` の request node の marker は少なくとも 1 か所に出る (出ないなら `participant-opaque` の誤りか、読む GET が足りない)。(ii) token / enum の葉は D2 の文法に合う (marker が入れば必ず外れる。応答の seat の node は今 `pattern` を持たないので、seat について見るのは印字可能 ASCII まで: D4)。
- これで response の側の分類 (別の人に参加者のバイトを見せる node が participant-* を名乗っているか) と、保存先の規則 (admin の request を `operator` と書いて参加者の保存先に入れれば赤) が機械で確かめられる。届くのは driver が通す流れだけ (Signpost 1)。
- 文法の検査は `CompareResponse` (ADR-0009 Decision B) を変えず、別の walker にする。ADR-0005 V5 の「型と値域は見ない」(`0005:419`) は V5 について真のまま残る (supersede しない)。

### D8. 移行と段階 (各段は単独で緑)

| 段 | 中身 | 大きさ (見込み) | Class | 前提 |
|---|---|---|---|---|
| S1 | walker と語彙、D3 の test と変異 (rev2 の (e) を含む)、181 node への付与、3 spec の `info.description`、CHANGELOG、`regen-openapi` skill の手順 0 | 約 460 行 / 8 file (400 行を越える理由: gate を spec の一部にだけ当てると除外リストになる。分けるなら walker と合成 spec の test を先に) | Class-1 (HTTP の挙動は変えない。spec は I14 の正典なので Class-0 にしない) | ADR の Accepted |
| S2 | D4 (seat を走査から外すこと、floor の数え方を含む) | 約 160 行 / 4 file | Class-1 (参加者の描画なので security-engineer のレビューを推奨) | S1 |
| S3a-1 | D6 の seat の `user` | 実績 +223 / −19 行、9 file (#433) | **Class-2** (security APPROVE with comments) | **済** (2026-10-18、`6adb77a`) |
| S3a-2 | D6 の board の body | 約 380 行 / 12 file | **Class-2** (security の APPROVE。#429 の 5 条件) | 無し (S1 より先でもよい。そのときは `text-rule.yaml` の class の鍵を 2 語の literal で pin し、S1 で語彙の表に繋ぐ) |
| S3b | D5 | 約 380 行 / 5 file | Class-1 | S1・S3a-2 |
| S4 | D7、D9 の I18 の昇格 | 約 400 行 / 4 file | Class-1 (I18 の追記は architect 合意 + VP 承認) | S3b |

- 手書きの表との関係: `inlineTextFields` / `inlineTextLocals` (#375・#405・#433) は S2 で消える (`first_solver` は導出に入らない: D4)。`cases.yaml` 2 本 (#381・#420) は field ごとの accept / reject の表として残り、S3a-2 で body の表が 1 本増える (class の下限は `text-rule.yaml`、field の上乗せと文脈つきの例外は cases)。`rule.yaml` は S3a-2 で `text-rule.yaml` になる。`sharedHelpers` (#411・#420) と `bidiFloors` (#383) は残る。
- S2 と S3a-2 は CHANGELOG を除いて触る file が重ならないので並行できる (WIP の上限の中で)。body の form の事前検査 (D6) は `pane-board.tmpl` を触るので S2 の後。
- 文書: ADR-0005 の Status block と `docs/adr/README.md` の索引に導線を足す (`README.md:73-81` の例外)。workspace の `falco-api` skill の「`x-ctf-*` 5 つ」の節に schema の key を足す (skill の所有者、S1 と同時)。
- spec の行数: scoreboard の spec は約 3,050 行になり 3,000 を越える (`6adb77a` で 2,981 行) が、ADR-0028 Signpost 2′ は分割を許すだけ (`0028:104-108`)。本 ADR は分割しない。
- **段の外の follow-up と判断 (rev2 で記録。本 ADR の段と順序の依存は無い)**
  - **seat の文法の 1 定義化 (app#440。#433 review-5x R4#3 / R4#4、security の F-1)**。Go の写しは 4 つ (`internal/scoreboard/api/api.go:62`、`internal/scoreboard/ingest/ingest.go:127`、`internal/authpolicy/server.go:45`、`internal/e2e/harness/seed.go:22`。ほかに `Makefile:207` の shell の検査)、spec の `pattern` は 6 node (`spec:1869,2038,2086,2118`、`docs/openapi-collector.yaml:125`、`docs/openapi-auth-policy.yaml:207`) にあり、一致を見る test は api と harness の 1 組だけ (`internal/e2e/harness/seed_test.go:21-35`)。#433 の後、1 つの seat の store の key を api の写し (submit・exfil) と ingest の写し (event) が別々に決めるので、写しの一致が採点の前提になった。提案は (i) `internal/identity` (I8 で両 binary が合意する部品の stdlib だけの置き場: `internal/identity/identity.go:1-10`。api と authpolicy は既に import し、auth-policy の Dockerfile は名前で copy する: `auth-policy/Dockerfile:19`) に pattern の定数と述語を 1 つ置き、写しを import にする、(ii) spec の seat の文法を `components.schemas` の 1 node にして `User` parameter と body の `user` 3 つから `$ref` する (oapi-codegen v2.3.0 が生成型の field の型を変えるなら inline のまま揃える。仮説で、app#440 の `make gen` の差分で確かめる)、(iii) spec の `pattern` と Go の文法の一致を test で固定する。本 ADR との関係: (ii) の後、seat の文法の node は component の 1 本になり、`x-ctf-text-origin: token` はそこに 1 回だけ書く (D1 の「`$ref` の節点には書かない」)。C3 の数と D2 の暫定の token の本数は少なくとも 3 減るが、D3 (g) の pin は participant-* だけなので動かない。応答の seat の node (D4) まで `$ref` にすれば D7 (ii) が slug の文法まで見るが、`first_solver` は `nullable` を持つので (`spec:2721`) 形が変わる。app#440 で決めてよい。(iii) への architect の助言 (非拘束): node の一覧を持たず、spec の全 `pattern` の値の集合と Go の文法の定義 (seat と、#437 の challenge id: `docs/openapi-collector.yaml:262`) の集合を双方向に比べる。一覧を持つと C1 の失敗様式に戻る。
  - **D3 (e) を受理の keyword まで広げるか (R4#4 が architect に求めた判断)**。選択肢: (A) rev1 のまま class だけ / (B) `pattern` を足す / (C) 受理を決める keyword (`type`・`pattern`・`maxLength`・`minLength`・`format`・`enum`・`const`) と `required` まで。コストはどれも D3 (e) が既に作る対の上で比べる key を足すだけ ((C) で約 10 行)。**(C) を採った (D3 (e))**。理由: forward の body を受理するのは target だけで、collector の写しの keyword に独立の意味は無く、違えばどちらかの spec が嘘になる。(B) は `pattern` の欠落 (#433 の review の時点で実際に起きた: scoreboard の `ExfilRequest.user` に `pattern` が入り、collector の写しには無かった。R4#4 が見つけ、#433 の中で揃えた) は捕まえるが、`maxLength` の欠落や `required` の食い違いを残す。collector の spec は scoreboard の component を `$ref` できない (外部 `$ref` は `resolve` が nil にし (`spec.go:197-207`)、D3 (c) が赤にする) ので、app#440 の (ii) の後も写しは inline に残り、この比較が写しを target に縛るただ 1 つの検査になる。app#440 の (iii) (spec ↔ Go: 各 `pattern` が実在の文法か) とは向きが違い (D3 (e) は spec ↔ spec)、重ならない。可逆性: 高 (比べる key を減らすだけ)。効き始める閾値: S1 から。
  - **保存済みの slug でない `user`**: app#439 (起動時の Warn と Sweep の skip、software-engineer) と platform#257 (stand-up の前提、sre-engineer)。D6。
  - **保存済みの件名と body**: #421 (#429 (iv))。

### D9. I18 (提案。未昇格)
> **I18 (参加者の文字列の出所)**: `http.ServeMux` を組み立てる全バイナリの spec で、string の schema node はすべて `x-ctf-text-origin` を持ち (欠落・語彙の外は fail、既定値なし、除外リストなし)、その宣言どおりに、(a) `participant-inline` / `participant-block` の request の値は route が class の規則で拒否し、(b) その response の値を portal は isolate する helper でだけ markup に入れ、(c) 参加者が選んだバイトは宣言が許す class の node にだけ現れる。機構: `TestAPISpec_TextOriginDeclared` (宣言) + `TestAPISpec_TextOriginProbes` (request。3 service に required) + `TestDisplayNames_AreBidiIsolated` (portal。spec から導出) + `TestAPISpec_TextOriginFlow` (流れ)。すべて `make test` = required check。

- 番号: I13 は予約済み、I17 は ADR-0029 が提案済み (未昇格) なので I18。
- 昇格の条件: V1〜V8 が `make test` に入った PR (S4) と同じ PR で conventions の表に足す。それより前に書かない (`docs/adr/README.md:82-84`)。

## Consequences

- **諦めたもの**
  - string を足すたびに 1 語を選ぶ手間。6 語のどれも選べない値は、まだ誰のバイトか決まっていない (設計を問う信号)。
  - body の描画の向き (D4)。最初の強い文字が RTL の body は RTL で並ぶ。
  - S3a-1 の後 (済)、slug でない `user` の submit / exfil は 400。S3a-2 の後、Cc / Cf (LF・TAB と、語の中の ZWNJ / ZWJ・emoji の間の ZWJ を除く) を含む body は 400。マラヤーラム語の旧式 chillu (語末の ZWJ) など、文脈の外の joiner も 400 (#429 が受け入れた妥協)。
  - S2 の後、seat の値 (`first_solver` ほか) は portal の bare `esc()` の規則の外になる。描画の isolate は floor が、値の形は文法の検査が受け持つ (D4)。
  - route の probe は field ごとの規則を言わない (関数の表に残す)。流れの検査は driver が通す流れだけを見る。
- **新たに守るもの**: D2 の語彙の規律と保存先の規則。seat の値は token (D2)。collector の forward の写しは target と class・受理の keyword・`required` まで一致する (D3 (e))。participant-* を足す・外す・付け替える spec の PR は security-engineer のレビューを通す (`x-ctf-origin-guard` と同じ扱い。D3 (g) の pin がその PR を目に見えるようにする)。I18 (提案)。
- **記録した follow-up (rev2。本 ADR の決定ではない)**: seat の文法の 1 定義化と spec の `$ref` (app#440。R4#3 / R4#4)、保存済みの slug でない `user` (app#439・platform#257)、保存済みの件名と body (#421)。中身は D8 の末尾。
- **他ロールへの影響**: software-engineer = S1・S3a-2 (S3a-1 は済)、app#439・app#440。application-engineer = S2 (body の描画の確認と、seat を走査から外すことを PR 本文に書くことを含む)、body の form の事前検査。qa-engineer = S3b・S4 (driver の表と変異)、app#440 の parity test。security-engineer = S3a-2 の APPROVE、S2 のレビュー (C2 (b) の triage と body の規則の判断は済)。sre-engineer = platform#257。skill の所有者 = `falco-api` と `regen-openapi`。
- **runbook**: platform の stand-up の手順に「scoreboard の DB は新規 PVC か、開場前に admin reset」を必須として足す (platform#257。D6 の保存済みの値の前提)。それ以外は無し (platform は `x-ctf-*` を読まない: C5)。参加者の手順書の curl (`user` は seat) は変わらない。

## Signposts (この決定を覆す観測可能な信号)

1. **参加者が選んだ文字列が、流れの検査の外の経路で participant-* でない node から別の人の画面に出た** (review-5x・e2e・security の監査・本番で見つかった) → driver の流れでは足りない。seed を spec の `example` から生成するか、server の側で値に出所を持たせる (O2 の方向) に進む。
2. **class の規則に field ごとの例外が要る** (inline で TAB を許したい、block で LF を拒みたい等)、または **block の規則で正当な投稿が 400 になった** (RTL の言語の U+200E / U+200F / U+061C、マラヤーラム語の旧式 chillu など。#429 が見直しのきっかけに挙げた) → 語を 1 つ足すか、class の `allow` / `exempt` を変えて表に規則を書く。field の例外のリストは作らない。
3. **route が class の規則より弱い述語を当てているのに probe を通った** (review で見つかった)、**request の decode がすべて生成型を通るようになった** (#115 F2)、**文法の外の seat の値が保存されていた** (app#439 の起動時 Warn が開場前の DB で非 0)、または **seat を保存する経路が route (body と path) と ingest の ns の外に増えた** → 述語を route の外へ移す。class は生成型に載せて decode の層で当てる (O2)。seat の文法は Grader / Store の入口で当てる (#433 review-5x R1#2 (b))。
4. **`x-ctf-text-origin` を app の test 以外が読み始めた** (docs site、platform、外の道具) → extension の JSON Schema と版を定める (ADR-0005 Signpost 5、ADR-0037 Signpost 1)。

## Verification (V3 を除き `make test` = required の `test / go-test` に載せ、exit status で判定する)

- **V1 宣言 (S1)**: `TestAPISpec_TextOriginDeclared` が D3 (a)〜(g) を満たす。spec ごとに 1 本以上、participant-* の件数の pin。
- **V2 静的規則の変異 (S1、常設の表)**: 次のそれぞれで赤になり、失敗文が JSON pointer を名指す — key の無い `{type: string}` を足す / 語彙の外の値 / object の node に key / 解決できない `$ref` / response から到達する node に `participant-opaque` / participant の到達する request に `operator` / `enum` を持つ node を `token` / `participant-inline` を配列の `items` に / participant-* の property 名を response の `operator` の string に流用 / collector の forward の class を target と変える / collector の写しの `pattern` を 1 文字変える / 写しの `maxLength` を消す / 写しの `required` から `flag` を外す / 使われない語を語彙に足す。
- **V3 生成物 (S1)**: `make gen` の後、`internal/{scoreboard,authpolicy}/oapi/types.gen.go` に差分が無い (`gen-diff-check`。advisory なので PR 本文に出力を貼る)。
- **V4 portal (S2)**: `TestDisplayNames_AreBidiIsolated` が spec から名前を導き (導出が空なら赤)、bare `esc()` 0 件、floor (helper の呼び出しを引数を問わず数える: D4) を満たす。変異: spec の写しに `participant-inline` の `nick` を足し、partial に `esc(x.nick)` → 赤 / `esc(m.body)` に戻す → 赤 / local の alias を `dn` に改名して bare `esc(dn)` → 赤 (今の手書きでは下限だけが気づく) / `nameHTML(c.first_solver)` を `esc(c.first_solver)` に戻す → floor だけで赤 (token なので bare `esc()` の規則は当たらない。今の数え方のままなら緑で抜ける)。
- **V5 route (S3b)**: `TestAPISpec_TextOriginProbes` が 3 service にあり (`requiredParityTestFuncs`)、scoreboard の導出は 12 組 (pin)、driver の表と導出が双方向に一致し、baseline が 2xx、probe が D5 のとおり。変異: `validBoardSubject` から `inlineTextHasForbidden` を外す → 赤 / `submit` の `validUser` (S3a-1 の検査) を外す → 赤 / spec の写しに driver の無い `participant-inline` の request field を足す → 赤 / 表に余分な driver → 赤 / baseline が 4xx になる driver → 赤 / `text-rule.yaml` に probe の無い category を足す → 赤。
- **V6 規則 (S3a)**
  - **S3a-1 (#433 で満たした)**: `internal/scoreboard/user_slug_test.go` が submit と internal exfil の両方で、slug でない 10 値 (大文字・内部の空白・U+202E・U+200B・markup・64 文字・先頭の `-`・`_`・改行・email の形) → 400 と固定文と保存 0 (exfil は receipt が 1 つも無いこと)、slug の 4 値 (63 文字を含む) → 200 で保存、flag の採点より前に弾く (正しい flag と誤った flag で応答のバイト列が同じ)、trim してから検査する (`" user1 "` → `user1` で保存、空白だけ → 400 `user required`) を固定する (`TestSubmit_*` / `TestExfil_*` の 7 本: `user_slug_test.go:35-169`)。security-engineer が 2 つの `validUser` の検査を外すと subtest が落ちることを確かめた (#433 の review)。
  - **S3a-2**: `text-rule.yaml` の class の鍵 = 語彙 (双方向。S3a-2 が S1 より先なら 2 語の literal、D8)、文脈の語の集合 = Go の述語の表 (双方向)、`exempt` の code point は probe にない。`validBoardBody` の全 code point の走査が block の規則と一致 (LF・TAB は受理、U+200C / U+200D は走査から外し表で固定)。inline の走査と既存の `cases.yaml` 2 本は変えずに緑。body の `cases.yaml` が #429 (ii) の表の全行と (iii) の各 code point を持つ。返信 (`PostReplyRequest.body`) にも同じ規則が当たる handler test。400 は固定文で入力を含まない。変異: 文脈の語を Go の表から 1 つ消す → 赤 / `exempt` の code point を probe に足す → 赤。
- **V7 流れ (S4)**: `TestAPISpec_TextOriginFlow` が D7 を満たす。変異: spec の写しで `BoardSummary.subject` を `operator` に → 赤 / 応答の `reason` に flag を埋める test 用の handler → 赤 / token の node に marker → 赤 / marker が 1 つも観測されない → 赤 / GET の parameter の表に無い名前 → 赤 / `DisplayNameRequest.name` を `operator` にした spec の写し → 赤 (保存先の規則)。
- **V8 検査が嘘でないこと**: V2・V4・V5・V6 (S3a-2)・V7 の変異は常設の table-driven test にする (ADR-0005 V8)。抽出 0 件は赤。
- **この検査が見ないもの**: 見た目の似た文字・空白に見える文字と、Cf でない見えない文字 (U+3164 などの Lo、異体字セレクタ U+FE00–FE0F・U+E0100–E01EF と U+034F の Mn。表示名の偽装は admin の reset: ADR-0034。#429 (iii) も範囲外とした)、inline の中の U+2028 / U+2029 (Zl / Zp。`categories` の外)、属性の中の参加者の文字列 (gate は bare `esc()` を一律に拒否する。属性に要るなら helper を足す)、ブラウザの Unicode の表 (ADR-0035 C4)、`operator` の content の中の bidi、要求した本人への echo (C2 (c))、parameter への route の probe (D5)、driver が通さない流れ (Signpost 1)、応答の seat の値の slug の文法そのもの (応答の node に `pattern` が無いので D7 (ii) は印字可能 ASCII までを見る: D4)、spec の `pattern` と Go の文法の一致 (app#440)。

## Advice (受けた助言。非拘束でも記録する)

- **VP (2026-10-18、本 ADR の発注)**: 宣言の形 (名前・値・置き場、ADR-0037 との関係)、portal の gate と request 側の表駆動 test の導出、fail-closed、移行 (本数と PR 数、Class)、追補か新 ADR か、slug / enum を検査対象外にする理由の明記。→ D1〜D8。追補にせず新 ADR にした (ADR-0005 の Decision / Verification は凍結: `0005:7`。ADR-0037 も新 ADR だった)。slug / enum は Cc / Cf の表からは外し、文法外の 1 値の probe を当てた (D2 末尾。C2 (b) で slug の宣言が実装で偽だったため)。
- **VP (2026-10-18、rev2 の発注)**: app#433 の review-5x (30 回目) の R4#1 (MED)・R4#2 / R4#3 / R4#4 (LOW) に従って更新する。first_solver など response の seat の値は token とし、S2 の走査から外れることを D2 / D4 に書く (描画の backstop は floor、文法は server の検査 + D5 の token probe + D7 (ii)、古い行は起動時の Warn)。S3a を S3a-1 / S3a-2 に分け、security の C2 (b) の triage を転記する。R4#3 / R4#4 は記録し、D3 (e) を広げるかを決める。→ D2・D3 (e)・D4・D5・D6・D8・Consequences・Signposts・V2 / V4 / V6。floor の backstop は数え方を変えて成り立たせた (下の architect (rev2))。
- **review-5x (app#433、30 回目、2026-10-18)**: R4#1 → D2・D4。R4#2 → D5・D6・D8・V6・この節。R4#3 (seat の文法の Go の写しを `internal/identity` の 1 定義に) と R4#4 (spec の seat の文法を component の 1 node にして `$ref`、spec の `pattern` と Go の照合) → D8 の末尾に記録 (app#440)。R4#4 が求めた D3 (e) の判断 → (C) を採った。R1#1 / R2#3 (保存済みの slug でない行、Sweep) → D6 と app#439・platform#257。R1#2 / R2#2 / R3#4 → app#440。
- **Issue #407 (app#405 review-5x R4#1、2026-10-17)**: 必須の extension、2 つの導出、opt-in の印と共有表を採らない。→ D1・D3・D4・D5。語を `slug` → `token` にし、`participant-opaque` を足した (D2)。
- **ADR-0037 (2026-10-17)**: 構造化した宣言から性質を導く流儀と、権威は組み立てる側に置く規則。→ D1 で「組み立てる者が無いので spec」と読んだ。
- **security-engineer**
  - **#429 の判断 (2026-10-18)**: body (participant-block) は LF と TAB を受理し、他の Cc (C0・DEL・C1・CR) と Cf を拒否する。例外は語の中 (前後が L か M) の U+200C / U+200D と、emoji の間の U+200D。(b) (#377 の「body は検査しない」の維持) は採らない。理由: bidi の効果は block の外へは漏れないが、block の中で画面に見える文字と保存されたバイトが食い違い、コピーする読み手 (とくに全スレッドを読む運営) に見た目と違うバイトを渡せる (Trojan Source と同類)。C1 の U+009B / U+009D は端末で制御列として働きうる。block に規則が無いと D5 が body を書く 3 route を検査の外に残す。ほかに `text-rule.yaml` の class 別の形と probe の一覧、文脈の語を Go の 1 か所の述語と双方向に比べること、S3a-2 の APPROVE の 5 条件、保存済みの body は #421 に含めること、form の事前検査は merge 条件にしないこと。→ D2・D5・D6・D8・V6・Signpost 2。
  - **#433 の review (2026-10-18、APPROVE with comments。LOW 5 は #433 で反映)** と #428 step 3 の判断: claimed な `user` が届く table は `solved` と `exfil` だけで `Store.Reset()` が両方を消し、イベントは新規 DB で始まるので、起動時の check は merge 条件にしない。前提は sre-engineer が runbook に書き (platform#257)、件数だけの Warn は follow-up (app#439)。F-1 (seat の文法を 1 か所に) → app#440。LOW-3 (spec の request の `pattern`) は #433 で反映。→ C2 (b)・D4・D6・D8。
- **qa-engineer / application-engineer**: 未受領 (S3b・S4 の driver の表の形、S2 の body の描画と floor の数え方)。
- **architect (発注の外)**: C2 の 3 件は分類の途中の実測。body に新しい `blockHTML()` を作らず `textHTML()` を要求した (検査できる性質だけを要求する)。流れの規則 (D7) で response の側の誤分類と保存先の規則を機械にした。
- **architect (rev2)**: R4#1 の推奨のうち「描画の backstop は floor (pane-scoreboard 6 / index.html 6)」は、今の floor の数え方 (`isolatedUseRe` は `inlineTextArg` から作る: `bidi_test:42,134`) のままでは S2 の後に成り立たない (first_solver が導出から外れると floor の数から消え、floor を 5 に下げることになる)。そこで S2 で floor を helper の呼び出しすべてで数えることにした (D4)。数えた値は今の floor と同じで、32 件の変異も同じ誤りで赤になる (読解による。S2 が実行で確かめる)。seat を participant-inline にしない理由に、保存先の規則と D3 (d) で `user` の全 node に広がり、属性の中の `esc(p.user)` を拒否することになる点を足した。
