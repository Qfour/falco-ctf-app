# ADR-0030: Quest content を 3 ファイルに置き、開示はサーバが solve の事実だけで決める — 公開抜粋に無い rule の中身・evade の盲点・解法の文を、solve 前に見える文と他課題の とくぎ に出さない

- Status: **Proposed** (Accepted 化は CEO の確認時。期限 = P28-1 の content の merge 前: workspace `REFACTORING.md:1901`)
- Date / Deciders: 2026-10-12 / architect (起草・同意権) + VP (発注)。独立レビューは未実施 (Advice)
- 関連: workspace `REFACTORING.md` P28 (受け入れ条件 3・4・5・11・14〜16、architect §1・§4・§5・§8、VP 裁定 2・3・7)、P22 (2026-08-14 CEO 決定:
  ヒントの唯一経路は journey の減点つきの開封、docs-admin は維持)、ADR-0014 (overlay の形)、ADR-0026 (D5 の n-gram 規則と V8)、ADR-0027 (どの課題の
  ヒントも減点つきで開ける)、ADR-0028 D5 (`/static/` に Quest content を置かない)、ADR-0029 (D2 の分け方・D7 の印の条件)、ADR-0032 rev2.1 (D9 (h)(i)・
  残余 4。branch `feat/adr-0032-s2-capstone-proof` の a005012)
- 行番号は c5e0761。C4 の測定は architect の probe (ADR-0026 D5 の再実装。e74d871 で ADR-0026 の公表値 364 / 275 / 281 / 42 と全スコープで一致する
  ことを確かめてから使った)。**公開境界**: 解法・回避の条件・private の検知条件をここに書かない。測定は件数と種類だけを書く

## Context

- **C1 置き場は決まっている (REFACTORING §1)。** 新設 3 ファイル。理由は、journey・narrative の読み込みの失敗が起動を止める (`cmd/scoreboard/main.go:179-209`)
  ので、Quest の誤記が採点を止めないよう別ファイルで隔離するため。起動時は warn と entry の破棄、CI は fail。表示の母集合は Restrict 後の catalog。
  overlay は ADR-0014 と同じ形で flavor だけを置き換える。Quest content は ja だけ。
- **C2 ヒントの経路。** ヒントは journey で減点つきで開くものだけ (P22)。どの課題でも開ける (ADR-0027)。端末には fixtures だけを置く (ADR-0026 D1)。
  n-gram 規則は 1 実装 (`internal/hintleak` の `Check`。app#318、未 merge。n = `GramRunes` = 10) で ADR-0030 と共有する (`0026:75`)。Quest への閾値と
  故意違反の例は本 ADR で固定する (`REFACTORING.md:1822-1825`)。
- **C3 rule の集合。** c5e0761 では 14 課題の expected ∪ forbidden が 12 rule で、どれもいずれかの `rule.yaml` (表示用抜粋) に載っている。範囲ごとに
  nimbusbreach-full 8・nimbusbreach-with-tutorial 9・tutorial-intro 3。ADR-0032 の S2 (未 merge) で 10 に証明の rule `Nimbus Vault Master Key Read` が入り
  13 rule になる。この rule は表示用抜粋に載せない (condition の公開になる: rev2.1 D9 (i)、`TestMission10DisplayRuleExcerptExcludesProof`)。10 の証明は
  技法の実演そのものを保証しないので、10 について「技法を実演した」と書かない (rev2.1 の残余 4 と「禁止を解除できる条件」)。
- **C4 解法を運ぶ文は hints[] の外にもある (probe、nimbusbreach-full の範囲、n = 10)。**
  - `scenarios/nimbusbreach-full/debrief.md` (とくぎと防御の素材: `REFACTORING.md:1705`) は、hints[] にだけある 10 rune の並びを 20 組 (3 か所) 持つ。
    どれも他課題の想定解の断片である。`challenges/*/rule-explain.md` の 4 本は 9 組 (3 か所。03 の回避の原理と 04 の想定解のコマンド)。
  - debrief の「防御」「学び」の行を とくぎ に写したと仮定すると、守る文を hints[] だけにした場合に引っかかる行は 2、hints[] ∪ `README.md` ∪
    `rule-explain.md` にした場合は 6。evade の防御の行 (回避の経路を名指しする) は後者でだけ捕まる (同じ並びが rule-explain.md にしか無い)。
  - n の膝: 同じ文書で n = 9 は 2 か所、n = 8 は 13 か所増え、増えた分はすべて一般的な日本語の言い回し (雑音)。n = 14 では rule-explain の 9 組が
    3 組に減る (真の一致を落とす)。fixtures (ADR-0026 D5) と同じく、10 が膝の直上である。
- **C5 rule-explain.md。** 4/14 本 (01・03・04・05)。描画するのは docs-site で、届くのは docs-admin だけ (`docs-site/gen-pages.py:104-115,161`)。portal の
  Home には出ないが、HTML は scoreboard の binary に埋め込まれている (`internal/scoreboard/view/homefragments_gen.go:37-40`)。除外は表示側の 1 分岐
  (`internal/scoreboard/view/home.go:67-75`、test は `home_test.go:90-100`)。中身は rule が「何を見ていないか」を含む (`challenges/03-stealth-read/rule-explain.md:19-27`、
  `challenges/04-key-search/rule-explain.md:27`)。
- **C6 公開リポ。** Quest content は GitHub で読める (順位の真正性の上限: product brief)。端末には入らない (ADR-0026 D1 の allowlist が自動で除く)。
  scoreboard の image には入る (`scoreboard/Dockerfile:24-25`)。本 ADR の開示境界は「portal がいつ何を出すか」であって、秘密の保持ではない。
- **C7 prod は CI-free** (image は手で build する: `REFACTORING.md:24-27`)。required check を通っていない tree からも image を作れる。

## Options

1. **全文を返して UI が隠す** — コスト: 最小。リスク: 応答を読めば未 solve の解法に届く。公平性の gate を UI に置くことになる (ADR-0027 も投影は server で
   作る: `0027:54-55`)。可逆。閾値: 効かない (既定が露出側)。
2. **server が solve の事実で開示を決め、文の中身を「公開抜粋」「n-gram」「文面レビュー」の 3 段で縛る【推奨】** — コスト: loader と検証、検査 2 種
   (CI と起動時)、レビューの規律。リスク: 逐語でない言い換えは機械で捕まらない (残余 3)。可逆。閾値: P28-1 の最初の content から。
3. **図鑑に盲点を持たせ、その rule を禁止する evade を 1 つ solve したら開示する (初版の tier 2)** — リスク: ボスを先に solve すると、未 solve の 03・05 の
   解法が減点なしで読める (R2 HIGH で廃止: `REFACTORING.md:1812-1815`)。閾値: 採らない。

## Decision

**Option 2。** 理由: 開示の判断を server の 1 箇所に置き、見せてよい由来 (公開抜粋) を構造で縛ったうえで、逐語の写しを機械で、言い換えを人で止める
以外に、solve 前の文と solve 後の文を分けて守る方法が無い。

- **D1 3 ファイルと schema。** 厳格に decode する (未知の key と型の誤りは CI で fail、起動時はその entry を破棄)。
  ```
  # challenges/<id>/quest.yaml (課題単位。scenario に中立)
  challengeId: <ディレクトリ名と一致>
  encounter:
    role: <短いラベル。open string>            # 例: あばく / しのぶ
    intro: <solve 前に見える導入>
    phases: [{label: <段の名前>, signal: <下の語彙>}]
    retreatNote: <evade だけ。やり直しの文。attempt に中立>
  skill:                                       # solve の後にだけ返る
    name: <とくぎ名>
    defense: <防御 1 行>
    counter: <evade だけ。その課題自身の技法の盲点と補強>
  # challenges/codex.yaml (rule 単位。中立)
  rules: {<rule 名>: {axis: <判定軸>, sight: <見破りポイント 1 行>, story: <実案件>}}
  labels: {fired, cleared, noHint, noReset, boss, undisclosed}   # 印・称号・非公開の固定文。key の集合は固定
  # scenarios/<name>/quest.yaml (世界観の overlay。flavor だけ)
  guardians: {<rule 名>: {alias: <副題>}}
  encounters: {<challengeId>: {intro: <置き換える導入>}}
  ```
  - `signal` の語彙は Go の閉じた集合: trigger = `rule-fired`・`solved`、evade = `attempt-started` (ADR-0032 S3b-1 の後)・`proof-fired`
    (`requireExpectedRuleFire` の課題だけ)・`exfil-received` (`requireExfil` の課題だけ)・`solved`。`phases[].state` は server がこの signal からだけ計算する
    (REFACTORING §8)。
  - overlay は ADR-0014 と同じ entry 単位の全置換で、key はその scenario の範囲の rule と課題だけ。rule 名・フィールド名・コマンドを置き換えない
    (alias は副題: VP 裁定 2)。
  - 物語の文はこの 3 ファイルと journey.yaml・narrative.yaml にだけ置く (受け入れ条件 11)。`internal/quest` の Go コードに表示文を書かない。
  - 看破 (P28-5) の key はまだ無い (今入れると strict decode で落ちる)。新しい文のフィールドは、D2 の開示の段を本 ADR の改訂で宣言してから足す。
- **D2 開示 (server が決め、条件を満たさない文は応答に含めない)。**

  | 文 | 返す条件 | 段 |
  |---|---|---|
  | `encounter` の `role`・`intro`・`phases[].label`・`retreatNote`、overlay の `alias`・`intro`、図鑑の rule 名 | 常に (status を問わない) | solve 前 |
  | 図鑑の `axis`・`sight`・`story` | その rule に発火印か突破印が付いた (ADR-0029 D7) | solve 前 (他課題から見て) |
  | battleLog の `sights` | 自分の発火の行の rule について、印に関わらず (受け入れ条件 4) | solve 前 |
  | `skill` の `name`・`defense`・`counter` | その課題を solve した (経路を問わない) | 自課題の solve 後 |
  | `labels` | 印・称号の条件が成り立った | — |

  - 図鑑の範囲は Restrict 後の catalog の rule。QuestBook は self-scope で、他者の要求は 403 (I8、受け入れ条件 3)。
  - **公開抜粋に無い rule は文を持たない**: `axis`・`sight`・`story` を書けるのは、full catalog のどれかの `rule.yaml` に載っている rule だけ。載って
    いない rule (S2 の後の 10 の証明の rule) の entry は文を持たず、server は `labels.undisclosed` を出す。scenario S では、文を持つ rule は S の課題の
    どれかの `rule.yaml` に載っていなければならない。
  - 図鑑は盲点を持たない (REFACTORING §5): 「見ないもの」・回避の手段・補強は、その rule を禁止する evade 自身の `skill.counter` にだけ置く。
- **D3 内容規則** (機械で守る部分と、文面レビュー = content と security に残す部分)。
  - (a) trigger の `skill.defense` は「この検知が鳴ったら何をするか」だけ。同じ rule の盲点と補強を書かない (04 の防御が 05 の、02 の防御が 03 の解法を
    渡すため)。機械: trigger に `counter` を置けない (schema)、D4。人: 言い換え。
  - (b) 印・称号の文は事実の記述 (「この挑戦中、検知の記録なし」) にする。順番・完全制覇・独力と読める語を入れない (受け入れ条件 15)。突破印は 03・05・10
    で同じ形にする (受け入れ条件 16)。「技法を実演した」と読める文は、積極証明があり、その証明が技法の実演と同値な課題 (現状 05 だけ) の図鑑の説明文
    にだけ置く。10 は証明を持つが残余 4 があるので断定しない。機械: `labels` の key と文を test で pin する (変える PR は security レビュー必須)。禁止語の
    逐語の検査 (完全制覇・独力・順番どおり・実演) を `labels` と 03・10 の quest.yaml にかける (床であって防衛線ではない)。人: 言い換え。
  - (c) ボス 10 の `skill` は合成の学びだけにし、他の evade の技法を書かない。機械: D4 と V3。人: 言い換え。
  - (d) 公開抜粋に無い rule の条件を表す語を、どの Quest の文にも書かない (ADR-0032 rev2.1 D9 (i))。機械: D2 の「文を持たない」。人: 残りの文を security が
    private の正典と突き合わせる。
  - (e) 実イベントの output と観測値を出さない (VP 裁定 7)。構造: battleLog は rule・時刻・relation だけ (ADR-0029 D8)。
  - (f) IP の境界 (VP 裁定 3) と、比喩は文法まで・語彙は実物 (VP 裁定 2)。人: content と design。
  - (g) `FALCO{` を含めない (受け入れ条件 5)。機械。
- **D4 n-gram 検査** (REFACTORING §5 の検査を固定する)。
  - 規則は ADR-0026 D5 と同じ実装を使う (`hintleak.Check`。n = `GramRunes` = 10、空白だけを除く正規化、項目ごとに切る、Cf と非 UTF-8 と 0 件は error)。
    n を据え置く根拠は C4。
  - ADR-0026 との違いは入力だけである (呼び手が組む)。
    - 守る文 (`Input.Hints`): 範囲の課題の `hints[]` に加え、`README.md` (想定解) と `rule-explain.md` (盲点の説明) の全文。理由は C4 — 解法は hints[] の
      外の文書にもあり、content はそれらを素材にする。
    - 無料表示 (`Input.Free`): ADR-0026 D5-1 と同じ (briefing は narrative の override で置き換え、steps、`rule.yaml` の表示用フィールド)。title・tagline・
      bridge は数えない。
    - 対象 (`Input.Targets`): (i) D2 の段が「solve 前」の文 (overlay と `labels` を含む) は、範囲の全課題の守る文に対して (ii) `skill` は、自課題以外の
      守る文に対して (自課題の解法は、solve した本人には開示済み)。
  - 範囲は full catalog と各 `scenarios/*/scenario.yaml`。図鑑はその範囲の rule だけ、overlay はその scenario だけを対象にする。報告の単位は
    (対象の項目, 異なる n-gram)。除外リストを作らず、Quest 側の言い換えで消す。
  - **起動時も同じ検査を回し、違反した entry を破棄する** (C7: 検査を通っていない tree から作った image でも、未 solve の解法を出さない)。無料表示の
    項目を組む関数は 1 つにし、起動時と CI が同じものを使う。
- **D5 CI と起動時の分担。** CI (`make test`、full catalog と全 scenario) では fail、起動時は warn と entry の破棄 (ADR-0029 D3)。(1) quest.yaml の
  `challengeId` = ディレクトリ ∈ catalog (2) codex の rule の集合 = full catalog の expected ∪ forbidden (双方向) (3) `signal` が課題の type と flag に
  適合する (4) overlay の orphan (5) D4 (6) 公開抜粋に無い rule の entry が文を持たない、scenario ごとの抜粋の範囲 (7) 未知の key と型 (8) `FALCO{` が
  無い (9) evade だけのフィールド (`retreatNote`・`skill.counter`) が trigger に無い (10) `labels` の key の集合。(1)〜(5) は REFACTORING §1 の 5 点。
- **D6 rule-explain.md の扱い。**
  - 参加者向けの源にしない。参加者向けのルール解説の正は codex.yaml。docs-admin での描画は変えない (P22 の決定 (iv))。
  - D4 の守る文に入れる (Quest に写せば CI と起動時の検査が落とす)。
  - **portal の binary から外す**: `docs-site/home-fragments.yaml:43-48` の `rule-explain` の entry を消して生成物を作り直し (`make gen-home-fragments`)、
    `HomeFragments` に課題ごとの entry (`ChalNN` が空でないもの) が 0 件であることを test で固定する。今は表示側の 1 分岐 (C5) を消すだけで、03 の
    回避の原理が全員の Home に出る。docs-admin は `gen-pages.py:161` が直接読むので影響しない。担当は content (yaml) と software (生成物と test)。
  - REFACTORING §1 の「portal Home からも除外 (`docs-site/gen-pages.py:104-115,161`)」は、除外の場所の記述が誤りである (実体は C5 の `home.go`)。
- **D7 所有とレビュー。** 3 ファイルの中身は content-engineer、loader と検査は software-engineer。3 ファイルを変える PR は security-engineer のレビューを
  必須にする (ADR-0026 V8 の対象 = fixtures と `hints[]` に足す)。schema の変更は architect の同意と VP の承認 (journey.yaml と同じ:
  `internal/catalog/journey.go:8`)。

**Hard Invariant は提案しない。** 中心の主張 (言い換えを含めて解法が漏れない) は機械で検査できず、検査できる部分 (V1〜V5) は `make test` の required に
乗る。HI にすると「Quest の文がヒントの経路を守っている」と読めてしまう (ADR-0026 D4 と同じ理由。主張していないことを名前に主張させない)。

## Consequences

- **諦めたもの**: debrief.md・README・rule-explain の文をそのまま Quest に写すこと (言い換えが要る)。10 の証明の rule の図鑑の解説。図鑑で盲点を
  教えること (evade の とくぎ でだけ教える)。
- **残余 (隠さない)**:
  1. evade の `skill` は経路を問わず開くので、順序外や W1 で 03 を抜けた人にも、10 の部分解が減点なしで届く (「本人は解いた」原則で許容: REFACTORING §5)。
  2. 範囲外の solve も Score に乗る (表示では直らない。ADR-0032 が閉じる)。
  3. n-gram は逐語しか捕まえない。言い換えに対する最後の防衛線は content と security の文面レビュー (ADR-0026 の残余 3 と同じ)。
  4. 公開リポ: Quest content は GitHub で読める。
  5. 10 の証明は技法の実演を保証しない (ADR-0032 rev2.1 の残余 4)。05 と 10 の差は、事実としてだけ書く。
  6. 図鑑の tier 1 は trigger の solve でも開く (02 の後に「Read sensitive file untrusted」の見るものが見える)。rule.yaml の言い換えなら無料表示と同格だが、
     言い換えを越えた記述はレビューでしか止まらない。
  7. private の検知条件 (証明と観測の rule) と Quest の文の突き合わせは機械にできない (条件を公開リポに置けない)。security が private の正典で確かめる。
- **他 ADR への影響**: ADR-0026 の n-gram の実装を、入力の違う 2 つ目の呼び手が使う (n と正規化は共有し、守る文の集合は ADR ごとに決める)。
- **REFACTORING との差** (VP へ報告): §5 の守る文を hints[] から hints[] ∪ README ∪ rule-explain に広げた (厳しい側)。起動時の検査、公開抜粋の規則
  (D2)、`labels`・`undisclosed`、D6 を足した。§1 の rule-explain の除外の記述を訂正した。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・3 は PR と起動 log、2 は `hint_views` と `solved` から事後に測る。

1. n-gram の誤検知による言い換えが 1 PR に 3 件以上、が 2 PR 続く → 守る文から README を外して hints と rule-explain で足りるかを測る、または n を
   上げる (上限 14)。逆に、検査を通った Quest の文から解法が 1 件見つかる → その文の段を「solve 後」に移すか、規則を補強する。
2. 次回イベントで、03 か 05 のヒント 3 の開示率が前回の半分未満になり、solve 率が上がる → Quest の文が解法を運んでいる疑い。図鑑と encounter を監査する。
3. content から「1 課題に 4 ファイルで編集を誤った」申告が 2 回、または本番で Quest content の破棄の warn が出る (REFACTORING §1) → 配置か tooling を
   見直す。
4. 公開抜粋に無い rule が 2 本以上になる (03 の証明を gate にするなど) → 「文を持たず固定の 1 行」の扱いを product-engineer と見直す。

## Verification

すべて**未実装**。V1〜V5・V7 は P28-1 の content の前提になる software の PR、V6 は D6 の PR、V8 は最初の content の PR で満たす。

- **V1 schema と CI の検証** (D5 の (1)〜(10)): 各項に、壊した複製の tree で赤になる case を持つ (`make test`)。走査 0 件は fail。
- **V2 n-gram** (D4): `TestQuestContent_CarriesNoProtectedOnlyNgrams` (full と全 scenario)。故意違反: 03 の hints の文を 02 の skill に混ぜると赤
  (REFACTORING §5 の名指し) / 03 の rule-explain の文を「Read sensitive file untrusted」の sight に混ぜると赤 / 03 の README の文を 10 の skill に混ぜると
  赤 / 自課題の hints の文を自課題の skill に置くと緑 / 無料表示にある文は緑 / 範囲で結果が変わる例がその範囲でだけ赤。起動時: 違反した entry だけが
  破棄され、他は残る。
- **V3 E2E の否定** (受け入れ条件 5): 実 catalog と nimbusbreach-full で、10 だけを solve した状態の QuestBook と全課題の MissionDetail から Quest の文を
  集め、03・05 の守る文に対する違反が 0。10 の skill に 03 のヒントを混ぜた複製で赤。
- **V4 開示** (server): skill は solve の後だけ / 図鑑の文は印の後だけ / battleLog の sights は印に関わらず / 他者の QuestBook は 403 / 公開抜粋に無い
  rule は文を持たず `labels.undisclosed` を返す。
- **V5 固定の文と床**: `labels` の key と文の pin、禁止語の逐語の検査、`FALCO{` の不在、`internal/quest` の非 test の Go の文字列リテラルに日本語
  (ひらがな・カタカナ・漢字) が無い (文は content に置く)。
- **V6 rule-explain**: `HomeFragments` に `ChalNN` が空でない entry が 0 件 (生成物を作り直した PR で)。
- **V7 単一実装**: 無料表示の項目を組む関数は 1 つで、ADR-0026 の fixtures の検査と同じ入力から同じ項目の集合を作る (test)。
- **V8 レビューの規律**: dev-flow のゲート表に 3 ファイルを security 必須として載せる (ADR-0026 V8 の行に足す)。
- **機械で守れないもの**: 言い換えによる漏えい、IP の境界、private の条件との突き合わせ (D3 の「人」の欄)。

## Advice

- architect (2026-10-04、REFACTORING P28 §1・§5) と、その R2 (qa-engineer)・R4 (architect の別インスタンス) のレビュー (tier 2 の廃止など) が出発点。
  本 ADR は守る文を広げ (C4)、起動時の検査・公開抜粋の規則 (D2)・D6 を足した。
- content-engineer (2026-10-04): 素材は debrief.md、作業量は約 60〜70 単位・約 25 ファイル。C4 は、その素材が解法の断片を持つことを示す。
- product-engineer (2026-10-05): 受け入れ条件 14〜16 (印は事実の記述、03・05・10 で同じ形)。10 の断定しない文言は確認待ち (ADR-0032)。
- ADR-0032 rev2.1 (2026-10-10): D9 (h)(i) と残余 4。
- VP (2026-10-10 / 12、発注): 決めることの一覧と ADR の型。
- 独立レビューは未実施。security-engineer (守る文の範囲・起動時の破棄・D6・private の条件との突き合わせ)、qa-engineer (V2・V3 の組み方)、
  content-engineer の助言 (schema の使いやすさ) を求める。
