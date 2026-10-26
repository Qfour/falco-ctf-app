# ADR-0043: hintleak の不可視文字の判定を unicode.Cf から sourcehygiene.Hidden (表と文脈規則) に替え、ADR-0026 D5-1 の Cf の一文を限定 supersede する
- Status: Proposed (実装 PR の merge と同じセッションの docs PR で Accepted)
- Date / Deciders: 2026-10-26 / VP + architect (起草) + security-engineer (R1)
- 関連: app#526、#511 (security 仕様 F1)、#382 F1、#525 (9291799)、ADR-0026 D5 / V6 / 残余 3、ADR-0029 D1 / I17 (a) / V1、ADR-0030 C8 / D4、#511 F2 (ADR-0045 として起票予定)
## Context
- C1. (以下の file:line は origin/main 1d4d014 の版) hintleak.go:89-97 はヒント項目と対象項目を unicode.Cf だけで落とし、正規化は IsSpace だけ (:137-148)。Cf でも空白でもない不可視の rune (U+034F CGJ = Mn、U+FE00-FE0D = Mn、U+3164 / U+115F / U+FFA0 = Lo、U+E0100 以降 = Mn) を 1 つ挟むと、それをまたぐ窓がすべて変わり、逐語のコピーが黙って通る (#511 / #382 F1)。IsSpace でない C0 / C1 制御 (ESC / DEL 等) も同じ穴だった (今は閉じる)。0026:89 は異体字セレクタ等を「捕まえない (残余 3)」と明記していた。
- C2. #525 が表と scanner を sourcehygiene の非 test package に置いた: invisible.go:56-98 (表)、:136-141 (Invisible / Hidden)、chars.go:8-18 (bidi 9 文字)。package doc (:4-9) は「写しでなく import する」と書き、#526 を名指ししている。非 test の import は標準ライブラリだけ (:37-42)。
- C3. ヒント項目は YAML 解釈後の文字列 (0026:80-82)。escape は ASCII なので source gate を通り (invisible.go:20-21)、解釈後に生の rune になる。ヒントでは hintleak が唯一の防衛線、fixtures (0026:87、生バイト) では二線目になる。
- C4. ADR-0029 D1 (:60-61) は quest の閉包を quest + hintleak とし、「hintleak は module 内 import を持たない」と注記している。V1 は未実装 (ADR-0029:187)。
- C5. ADR-0030 C8 (:41-42) と D4 (1) (:137) も Cf と書いている。述語がずれると、entry 1 つの不可視文字で Quest が全体無効 (D4 (3)) になる。
## Options
1. hintleak が sourcehygiene.Hidden を import する。変更点: Cf のループを Hidden に替える。コスト: 閉包が +1 package、sourcehygiene の変更が V5 / I16 の仕組みの変更になる (security レビュー)。リスク: Hidden は必要より厳しい所がある (VT / FF / NEL / LS / PS / 単独 CR は IsSpace なので窓を切れないが error になる) が、厳しい側 = fail-closed。可逆 (ループ 1 つを戻す)。効き始め: 即時 (今ある穴)。
2. 表を hintleak に写す。表が 2 つになり、網羅の meta test (invisible_test.go:256-273) は片方しか守らない。drift は緩い側に無音で起きる。conventions:279 に反する。
3. 述語を新しい葉 package に切り出す。今は効果が無い (gate は *_test.go 側にあり、非 test は既に述語だけ)。sourcehygiene の非 test に述語以外が入る時に効く。
## Decision
Option 1。表・文脈規則・bidi を 1 定義のまま、採点境界の n-gram 検査が同じ集合を見るため。
- D1 (D5-1 の Cf の一文を置き換える): ヒント項目と fixtures 項目に sourcehygiene.Hidden が報告する rune があれば fail。対象は表 invisibleRanges (Cf ∪ Default_Ignorable ∪ C0/C1 ∪ U+2028/2029 ∪ 単独 CR) と bidi 制御 9 文字。文脈で正当な出現は除く: 非 ASCII の So の直後に 1 つの U+FE0E / U+FE0F、非 ASCII の So の並びの内側の U+200D (直前が So・肌色修飾・許された U+FE0F、直後が So。So は絵文字に限らない)、項目の先頭の U+FEFF、LF の直前の CR。適用先はヒントの YAML 解釈後の文字列と、fixtures の生バイトを UTF-8 として読んだ文字列。項目 1 つを Hidden の「file」1 つとして渡す (BOM は項目の先頭で判定する)。escape で書いた文字は解釈後に生の rune になるので、ここで落ちる。source gate の allowlist (invisible-allowlist.txt) は hintleak に効かない (D5-6: 除外リストを持たない)。無料表示項目は対象外のまま (厳しい側)。正規化 (D5-2) は変えない。
- D2 (残余 3 の後半を置き換える): 文脈で許される U+FE0E / U+FE0F / U+200D は可視の記号 (非 ASCII の So。絵文字に限らない) 1 つにつき 1 つしか載らない。窓を切れるのは記号を含む並びだけで、これは source gate と同じ受容である。
- D3 (V6 の Cf の一文を置き換える): Verification の V-a〜V-c。
- D4: ErrFormatChar の識別子は残す (errors.Is の呼び手と test の安定のため。改名は閉包 test (ADR-0029 V1) と一緒に P28-1 で検討)。文言は code point・名前・文脈規則の理由を出す。
- D5: quest の事前検査 (ADR-0030 D4 (1)) は、hintleak が公開する 1 関数で同じ述語を使う (P28-1 で足す。quest は表を写さない)。
## Consequences
- 受理集合は狭まる。例外は 2 点で、2 つの非 ASCII So の間の U+200D と項目先頭の U+FEFF は Cf では error だったが今は通る (D2 の残余。So は絵文字に限らない)。既存の hint / fixture は全部通る (V-e)。
- 諦めたもの: hintleak が IsSpace 系の C0/C1 / LS / PS / 単独 CR を許していた寛容さ (今の tree には無い)。
- 新たに守るもの: sourcehygiene の非 test file の変更 = I16 の仕組みの変更 (security 必須)。I16 の文言は変わらない (D5 を参照するだけ)。
- ADR-0029 D1 / I17 / V1 と ADR-0030 C8 / D4 (1) / V2 / V8 を同じ PR で改訂する。conventions:279 と I16 の機構 (4)、dev-flow のゲート表、sourcehygiene の package doc (:7-9) も直す。
- 追跡 (P28-1 の DoD): D5 (hintleak が公開する 1 関数) と、ADR-0029 V1 の追記分 (許可リストの葉の dead 検査・公開 var の型検査・直接 import の検査) は P28-1 で実装する。本 PR は文面だけ。
- security の必須対象は `internal/sourcehygiene/**` と `internal/hintleak/**` (test と testdata を含む。test を消す PR も I16 を弱める。dev-flow のパターン A の表)。
- runbook への影響: 無し。
## Signposts
1. 正当なヒントや fixture が Hidden で 1 回でも落ちる (例: keycap の `#` + U+FE0F + U+20E3) → 文脈規則を sourcehygiene の 1 か所で広げる。hintleak 側に例外を作らない。
2. Go の更新で Unicode が上がり TestInvisibleTable_CoversCfAndDICP が赤になる → その表の更新 PR は V5 の変更として security R1 を通す。
3. sourcehygiene の非 test package に述語以外 (walker・allowlist reader・CLI) が入る PR が出る → 先に Option 3 で切り出す。
4. 表に無い可視の空白状の rune (例: U+2800) で窓を切った fixture が見つかる → 表か正規化を補強する。
## Verification
- V-a: unicode.Cf ∪ Variation_Selector ∪ Other_Default_Ignorable_Code_Point ∪ bidi 9 文字 ∪ TAB・LF 以外の Cc (CR は単独で置く) ∪ Zl / Zp (U+2028 / U+2029) の全 rune について、"abcde"+r+"fghijklm" をヒント側と対象側に入れると errors.Is(ErrFormatChar) になり、文言が U+XXXX を名指す。検査した件数が 0 より大きいことも assert する。
- V-b: #511 で名指しされた U+034F、U+FE00、文字の直後の U+FE0F、U+3164、U+115F、U+FFA0、U+E0041、U+E0100、U+202E、U+2066 と、C0 / C1 制御の U+0001・U+001B (ESC)・U+007F (DEL)・U+009B (CSI) が error になる。
- V-c: 文脈で正当なもの。U+26A0 U+FE0F を含むヒントと同じ文の fixture は error にならず、違反として報告される (窓が読み飛ばされない)。先頭が U+FEFF の fixture と CRLF の fixture も error にならない。非 ASCII So + U+200D + 非 ASCII So を含むヒントと同文の fixture は error にならず、違反の n-gram のどれかに U+200D が入る。先頭が U+FEFF のヒント項目は error にならず、コピーされた並びが報告される。
- V-d: 無料表示項目に U+034F があっても error にならない (hintleak_test.go:176-180 の形)。
- V-e: 実 tree の V5 (TestFixtures_CarryNoHintOnlyNgrams) が全スコープで緑。出力を PR 本文に貼る。
- V-f (P28-1): ADR-0029 V1 の改訂どおり。
## Advice
- security-engineer (#511 / #382 F1): Mn の異体字セレクタ、CGJ、Hangul filler (Lo) が Cf の判定を素通りする。
- VP brief (2026-10-26): 採点境界 V8 として Class-2 で扱い、security R1 を通す。
