# ADR-0030: Quest content を 3 ファイルに置き、開示はサーバが solve の事実だけで決める — 公開抜粋に無い rule の中身・evade の盲点・解法の文を、solve 前に見える文と他課題の とくぎ に出さない

- Status: **Proposed** (Accepted 化は CEO の確認時。期限 = P28-1 の content の merge 前: workspace `REFACTORING.md:1901`)
- Date / Deciders: 2026-10-12 / architect (起草・同意権) + VP (発注と裁定 = D5 の PR の順序・D7 の security 必須の範囲、2026-10-12)。独立レビュー: qa-engineer R2・
  security-engineer R1 (どちらも 2026-10-12、本版に反映)
- 関連: workspace `REFACTORING.md` P28 (受け入れ条件 3・4・5・11・14〜16、architect §1・§4・§5・§8、VP 裁定 2・3・7)、P22 (2026-08-14 CEO 決定:
  ヒントの唯一経路は journey の減点つきの開封、docs-admin は維持)、ADR-0014 (overlay の形)、ADR-0026 (D5 の n-gram 規則と V8)、ADR-0027 (どの課題の
  ヒントも減点つきで開ける)、ADR-0028 D5 (`/static/` に Quest content を置かない)、ADR-0029 (D1 の許可リスト・D2 の入力型・D7 の印の条件)、ADR-0031 (D2: HTTP の
  性質は `make test`)、ADR-0032 rev2.1 (D9 (h)(i)・残余 4。branch `feat/adr-0032-s2-capstone-proof` の a005012)
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
- **C6 公開リポ。** Quest content は GitHub で読める (順位の真正性の上限: product brief)。端末に入らないのは ADR-0026 D1 の allowlist が landing した後で、c5e0761 では
  challenge image が `challenges/` を丸ごと `/opt/ctf/missions/` に COPY する (`images/challenge/Dockerfile:103`) ので、codex.yaml と quest.yaml の `skill.counter` が
  端末から読める。scoreboard の image には `challenges/` が丸ごと入る (`scoreboard/Dockerfile:24-25`。起動時の検査は README.md と rule-explain.md を読める)。本 ADR の
  開示境界は「portal がいつ何を出すか」であって、秘密の保持ではない。
- **C7 prod は CI-free** (image は手で build する: `REFACTORING.md:24-27`)。required check を通っていない tree からも image を作れる。
- **C8 `hintleak.Check` は範囲全体で error を返す。** 守る文か対象に Cf (不可視の書式文字) が 1 つある、どれかの項目が非 UTF-8、守る文か対象が 0 件、のどれでも、
  違反の一覧ではなく範囲全体の error を返す (`internal/hintleak/hintleak.go:77-97`、branch `feat/hintleak-ngram-check` の 6f52615)。
- **C9 yaml.v3 (v3.0.1: `go.mod:9`) の挙動。** `Node.Decode` は新しい decoder を作り、`KnownFields` を引き継がない (`yaml.go` の `Node.Decode`)。string のフィールドには
  数値と真偽値の scalar を文字列にして入れる (`decode.go` の `scalar` の `reflect.String`)。repo に `KnownFields` の前例は無い (c5e0761)。entry ごとの厳格な decode は、
  decoder の設定だけでは作れない。

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

- **D1 3 ファイルと schema。** 厳格に decode する。単位は entry (課題の quest.yaml は 1 ファイルで 1 entry、codex は rule ごとと `labels`、overlay は rule・課題ごと)。
  entry に未知の key がある・mapping か list の位置に scalar がある (逆も)・文のフィールドが `!!str` 以外の scalar (`123`・`true`) である、のどれかで、その entry を
  起動時は破棄し、CI は fail にする。YAML として読めないファイルは、ファイルごと同じ扱い。判定は decoder の設定に任せず、node の key と tag で行う (C9)。
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

  - `sight` は battleLog の `sights` で、発火しただけで見える (受け入れ条件 4)。印の gate が実際に効くのは図鑑の `axis` と `story` だけである。
  - `skill` を返す面は 2 つ (MissionDetail の `encounter.skill` と QuestBook の `skills`) で、条件は同じ。battleLog の `sights` の key は、同じ応答の battleLog に出た
    rule だけ。
  - 図鑑の範囲は Restrict 後の catalog の rule。QuestBook は self-scope で、他者の要求は 403 (I8、受け入れ条件 3)。admin (ADMIN_EMAILS) は他者の QuestBook を読めるが、
    返るのはその user 本人に返るものと同じ。
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
  - (g) `FALCO{` を含めない (受け入れ条件 5)。機械: content のファイル (V5) と API の出力 (V3) の両方。
- **D4 n-gram 検査** (REFACTORING §5 の検査を固定する)。
  - 規則は ADR-0026 D5 と同じ実装を使う (`hintleak.Check`。n = `GramRunes` = 10、空白だけを除く正規化、項目ごとに切る)。n を据え置く根拠は C4。
  - ADR-0026 との違いは入力だけである (呼び手が組む)。
    - 守る文 (`Input.Hints`): 範囲の課題の `hints[]` に加え、`README.md` (想定解) と `rule-explain.md` (盲点の説明) の全文。理由は C4 — 解法は hints[] の
      外の文書にもあり、content はそれらを素材にする。
    - 無料表示 (`Input.Free`): ADR-0026 D5-1 と同じ (briefing は narrative の override で置き換え、steps、`rule.yaml` の表示用フィールド)。title・tagline・
      bridge は数えない。
    - 対象 (`Input.Targets`): (i) D2 の段が「solve 前」の文 (overlay と `labels` を含む) は、範囲の全課題の守る文に対して (ii) `skill` は、自課題以外の
      守る文に対して (自課題の解法は、solve した本人には開示済み)。
  - 無料表示と守る文の項目を組む関数は `internal/catalog` に 1 つ置く (catalog の型から string の項目を作り、hintleak も quest も import しない)。quest は catalog を
    import できない (ADR-0029 D1) ので、合成層が `hintleak.Item` に詰めて渡す。ADR-0026 の検査・起動時・CI が同じ関数を使う (V7)。
  - 範囲は full catalog と各 `scenarios/*/scenario.yaml`。図鑑はその範囲の rule だけ、overlay はその scenario だけを対象にする。報告の単位は
    (対象の項目, 異なる n-gram)。除外リストを作らず、Quest 側の言い換えで消す。
  - **起動時も同じ検査を回す** (C7: 検査を通っていない tree から作った image でも、未 solve の解法を出さない)。入力が欠けると守る文が縮んで緩む側に倒れ、Check は
    範囲全体で error を返す (C8) ので、起動時は次の順にする。(0) 範囲の各課題に `README.md` と journey があることを確かめる (rule-explain.md は 4 本だけなので要求しない)
    (1) Quest の各 entry を先に UTF-8 と Cf で検査し、駄目な entry を破棄する (2) Check の違反に当たった entry を破棄し、他は残す (3) (0) が欠けているか Check が error
    なら (守る文か無料表示の側の Cf・非 UTF-8、守る文が 0 件)、Quest の文をすべて破棄して Quest を無効にする (`quest_enabled` = 0)。log を出して文を残すことはしない
    (開示が fail-open になる) (4) 対象が 0 件なら何もしない。(2)・(3) の破棄は counter の kind `ngram` に数え、preflight は 1 件以上を no-go 相当の信号として扱う
    (ADR-0029 D9)。CI では (0)・(1)・(3)・(4) も fail。
- **D5 CI と起動時の分担。** CI (`make test`、full catalog と全 scenario) では fail、起動時は warn と entry の破棄 (ADR-0029 D3)。(1) quest.yaml の
  `challengeId` = ディレクトリ ∈ catalog (2) codex の rule の集合 = full catalog の expected ∪ forbidden (双方向) (3) `signal` が課題の type と `requireExfil`・
  `requireExpectedRuleFire` に適合する (4) overlay の orphan (5) D4 (6) 公開抜粋に無い rule の entry が文を持たない、scenario ごとの抜粋の範囲 (7) D1 の厳格な decode
  (8) `FALCO{` が無い (9) evade だけのフィールド (`retreatNote`・`skill.counter`) が trigger に無い (10) `labels` の key の集合。(1)〜(5) は REFACTORING §1 の 5 点。
  - **PR の順序 (VP 裁定 2026-10-12)**: 実 tree に対する検査は、codex.yaml を入れる content の PR (security レビュー必須) と同じ PR に載せる。software の先行 PR は検査の
    本体と、合成 fixture に対する検査だけを持つ。実 tree を走査する test 関数 (数行。本体は software の関数) は content の PR で足し、ファイルが無ければ fail にする
    (`t.Skip` しない。先に入れると赤になり、skip は黙って緑になるので、ファイルと検査を同じ PR に置く)。ADR-0032 S2 (10 の証明 rule) は codex の rule 集合を変えるので、
    S2 を先に merge し、codex.yaml は S2 の後の集合で書く。最初の content の PR の merge は ADR-0026 V1 (challenge image の entry-set の build 時検査: `0026:138`) の
    landing の後に置く (それまでは C6 のとおり端末から読める)。CEO が F1 の維持に覆した回 (P28-0d') は、quest.yaml と codex.yaml を challenge image から除く変更
    (REFACTORING §7: `REFACTORING.md:1854`) を同じ前提にする。
- **D6 rule-explain.md の扱い。**
  - 参加者向けの源にしない。参加者向けのルール解説の正は codex.yaml。docs-admin での描画は変えない (P22 の決定 (iv))。
  - D4 の守る文に入れる (Quest に写せば CI と起動時の検査が落とす)。
  - **portal の binary から外す**: `docs-site/home-fragments.yaml:43-48` の `rule-explain` の entry を消して生成物を作り直し (`make gen-home-fragments`)、
    `HomeFragments` に課題ごとの entry (`ChalNN` が空でないもの) が 0 件であることを test で固定する。今は表示側の 1 分岐 (C5) を消すだけで、03 の
    回避の原理が全員の Home に出る。docs-admin は `gen-pages.py:161` が直接読むので影響しない。担当は content (yaml) と software (生成物と test)。
  - REFACTORING §1 の「portal Home からも除外 (`docs-site/gen-pages.py:104-115,161`)」は、除外の場所の記述が誤りである (実体は C5 の `home.go`)。
- **D7 所有とレビュー。** 3 ファイルの中身は content-engineer、loader と検査は software-engineer (実 tree の test 関数も software か qa が書き、content の PR に同梱する)。
  security-engineer のレビューを必須にするのは、3 ファイルを変える PR と、開示を決めるコード (`internal/quest`・`internal/scoreboard/api/quest.go`・n-gram の検査の
  テスト・`internal/hintleak`) を変える PR (ADR-0026 V8 の対象 = fixtures と `hints[]` に足す)。REFACTORING の段階表で security を「不要」としている P28-3 (overlay =
  solve 前の文、ボスの phases) と P28-4 は「必須」に直す (`REFACTORING.md:1922-1923`。VP 決定 2026-10-12。表は workspace の文書なので VP が直す)。schema の変更は
  architect の同意と VP の承認 (journey.yaml と同じ: `internal/catalog/journey.go:8`)。

**Hard Invariant は提案しない。** 中心の主張 (言い換えを含めて解法が漏れない) は機械で検査できず、検査できる部分 (V1〜V5) は `make test` の required に
乗る。HI にすると「Quest の文がヒントの経路を守っている」と読めてしまう (ADR-0026 D4 と同じ理由。主張していないことを名前に主張させない)。

## Consequences

- **諦めたもの**: debrief.md・README・rule-explain の文をそのまま Quest に写すこと (言い換えが要る)。10 の証明の rule の図鑑の解説。図鑑で盲点を
  教えること (evade の とくぎ でだけ教える)。content を software・ADR-0026 V1 より先に入れること (D5)。
- **残余 (隠さない)**:
  1. evade の `skill` は経路を問わず開くので、順序外や W1 で 03 を抜けた人にも、10 の部分解が減点なしで届く (「本人は解いた」原則で許容: REFACTORING §5)。
  2. 範囲外の solve も Score に乗る (表示では直らない。ADR-0032 が閉じる)。
  3. n-gram は逐語しか捕まえない。言い換えに対する最後の防衛線は content と security の文面レビュー (ADR-0026 の残余 3 と同じ)。
  4. 公開リポ: Quest content は GitHub で読める。
  5. 10 の証明は技法の実演を保証しない (ADR-0032 rev2.1 の残余 4)。05 と 10 の差は、事実としてだけ書く。
  6. 図鑑の tier 1 は trigger の solve でも開く (02 の後に「Read sensitive file untrusted」の見るものが見える)。rule.yaml の言い換えなら無料表示と同格だが、
     言い換えを越えた記述はレビューでしか止まらない。
  7. private の検知条件 (証明と観測の rule) と Quest の文の突き合わせは、公開側の CI では機械にできない (条件を公開リポに置けない)。security が private の正典で
     確かめる。platform の preflight は app の pin を読むので、private の deny-list を stand-up 時に quest.yaml と codex.yaml へ当てられる (platform の follow-up)。
- **他 ADR への影響**: ADR-0026 の n-gram の実装を、入力の違う 2 つ目の呼び手が使う (n と正規化は共有し、守る文の集合は ADR ごとに決める)。ADR-0026 の検査は、無料表示の
  項目を `internal/catalog` の関数から得るように変わる (V7)。
- **REFACTORING との差** (VP へ報告): §5 の守る文を hints[] から hints[] ∪ README ∪ rule-explain に広げた (厳しい側。受け入れ条件 5 は厳しくなるだけで、9 は不変)。
  起動時の検査と破棄の順 (D4)、公開抜粋の規則 (D2)、`labels`・`undisclosed`、D6、PR の順序 (D5) を足した。§1 の rule-explain の除外の記述を訂正した (受け入れ条件 5)。
  段階表の P28-3・P28-4 の security を「必須」にした (D7)。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・3 は PR と起動 log、2 は `hint_views` と `solved` から事後に測る。

1. n-gram の誤検知による言い換えが 1 PR に 3 件以上、が 2 PR 続く → 守る文から README を外して hints と rule-explain で足りるかを測る、または n を
   上げる (上限 14)。逆に、検査を通った Quest の文から解法が 1 件見つかる → その文の段を「solve 後」に移すか、規則を補強する。
2. 次回イベントで、03 か 05 のヒント 3 の開示率が前回の半分未満になり、solve 率が上がる → Quest の文が解法を運んでいる疑い。図鑑と encounter を監査する。
3. content から「1 課題に 4 ファイルで編集を誤った」申告が 2 回、または本番で Quest content の破棄の warn が出る (REFACTORING §1) → 配置か tooling を
   見直す。
4. 公開抜粋に無い rule が 2 本以上になる (03 の証明を gate にするなど) → 「文を持たず固定の 1 行」の扱いを product-engineer と見直す。

## Verification

すべて**未実装**。「software」= P28-1 の content の前提になる software の PR、「content」= 最初の content の PR (D5 の順序。ADR-0026 V1 の後)。V6 は D6 の PR。
counter は前後の差分で assert する (metric はプロセスで共有される)。

- **V1 schema と CI の検証** (D5 の (1)〜(10)、`make test`)。
  - software: 各項に、壊した複製の tree で赤になる case を持つ。D1 の decode: 1 entry に未知の key → その entry だけ破棄 (起動時) / fail (CI)、mapping か list の位置に
    scalar → 同じ、文のフィールドに `123`・`true` → 同じ、YAML として読めないファイル → ファイルごと。
  - content: 実 tree で `codex.yaml` が無い、または課題の quest.yaml が 0 件なら fail (skip しない)。codex の rule 集合は S2 の後の集合と双方向に一致する。
- **V2 n-gram** (D4): `TestQuestContent_CarriesNoProtectedOnlyNgrams` (full と全 scenario)。故意違反: 03 の hints の文を 02 の skill に混ぜると赤
  (REFACTORING §5 の名指し) / 03 の rule-explain の文を「Read sensitive file untrusted」の sight に混ぜると赤 / 03 の README の文を 10 の skill に混ぜると
  赤 / 自課題の hints の文を自課題の skill に置くと、他課題の守る文に同じ並びが無ければ緑 / 自課題の想定解の文でも、他課題の守る文にだけある並びを含めば赤 (03 の
  skill に、10 の守る文と重なる 03 の想定解の行を書く) / 無料表示にある文は緑 / 範囲で結果が変わる例がその範囲でだけ赤。起動時: 違反した entry だけが破棄され
  他は残る / Cf を含む entry は破棄され他は残る / 守る文の側の Cf で Check が error → Quest の文がすべて破棄され `quest_enabled` = 0 / 範囲の課題の README.md か
  journey を消した tree → 同じ (fail-closed) / 対象 0 件 → 起動時は何もしない、CI は fail / 破棄が kind `ngram` に数えられる。合成 fixture は software、実 tree は content。
- **V3 否定** (受け入れ条件 5。HTTP の性質なので `make test` = required に置き、ADR-0031 D2 により `make e2e` には置かない): `TestQuest_NegativeDisclosure_AllBodies`。
  実 catalog と nimbusbreach-full で、状態 = 10 だけ solve / 1 課題だけ solve (課題ごと) / X 以外を全部 solve (X = 03・05・10)。QuestBook・journey (全課題の
  `?mission=`)・me の body 全体の文字列を集め、未 solve の課題の守る文に対する違反が 0、`FALCO{` が 0。故意違反: 10 の skill に 03 のヒントを混ぜた複製で赤。
  仕組みは software (合成 content)、実 tree は content。
- **V4 開示** (server、httptest。ingest は同期なので開示の時点を固定できる: `internal/scoreboard/ingest/ingest.go:258-273`): skill は solve の後だけで、MissionDetail と
  QuestBook の両方 / 図鑑の文は印の後だけ / battleLog の `sights` は印に関わらず返り、key は battleLog の rule の部分集合 / 他者の QuestBook は 403、admin はその user
  本人と同じものを読む / 公開抜粋に無い rule は文を持たず `labels.undisclosed` を返す / admin reset で印と skill が消える。ブラウザ (ADR-0031) に回すのは、描画と
  「1 ポーリング以内」だけ。
- **V5 固定の文と床**: software = `internal/quest` の非 test の Go の文字列リテラルに日本語 (ひらがな・カタカナ・漢字) が無い (文は content に置く)。content = `labels` の
  key と文の pin、禁止語の逐語の検査、content のファイルに `FALCO{` が無い。
- **V6 rule-explain**: `HomeFragments` に `ChalNN` が空でない entry が 0 件 (生成物を作り直した PR で)。
- **V7 単一実装**: 無料表示と守る文の項目を組む関数は `internal/catalog` の 1 つで、ADR-0026 の検査・起動時・CI がそれを呼ぶ (3 者が同じ集合を得ることを test で確かめる)。
- **V8 レビューの規律**: dev-flow のゲート表に、3 ファイルと D7 のコードの経路を security 必須として載せる (ADR-0026 V8 の行に足す)。
- **機械で守れないもの**: 言い換えによる漏えい、IP の境界、private の条件との突き合わせ (D3 の「人」の欄)。

## Advice

- architect (2026-10-04、REFACTORING P28 §1・§5) と、その R2 (qa-engineer)・R4 (architect の別インスタンス) のレビュー (tier 2 の廃止など) が出発点。
  本 ADR は守る文を広げ (C4)、起動時の検査・公開抜粋の規則 (D2)・D6 を足した。
- content-engineer (2026-10-04): 素材は debrief.md、作業量は約 60〜70 単位・約 25 ファイル。C4 は、その素材が解法の断片を持つことを示す。
- product-engineer (2026-10-05): 受け入れ条件 14〜16 (印は事実の記述、03・05・10 で同じ形)。10 の断定しない文言は確認待ち (ADR-0032)。
- ADR-0032 rev2.1 (2026-10-10): D9 (h)(i) と残余 4。
- VP (2026-10-10 / 12、発注): 決めることの一覧と ADR の型。VP 裁定 (2026-10-12): 実 tree の検査は codex.yaml を入れる content の PR に載せ、S2 を先に merge する (D5)。
- **qa-engineer R2 (2026-10-12、REQUEST CHANGES。方向には同意)**。VP が全件を採用し、本版に反映した: 起動時の Check の error の扱い (D4・V2)・PR の順序と skip の禁止
  (D5・V1)・V3 を `make test` に置き、body 全体と状態を広げる (V3)・V4 の追加 (2 つの面・`sights` の key・admin・admin reset)・厳格な decode のテストの形 (D1・V1)・API の
  出力の `FALCO{` (D3 (g)・V3)・counter の差分。yaml.v3 の 2 つの挙動 (qa は未確認としていた) は architect が v3.0.1 のソースで確かめた (C9)。
- **security-engineer R1 (2026-10-12、REQUEST CHANGES。BLOCKING なし)**。VP が全件を採用し、本版に反映した: C6 の訂正と ADR-0026 V1 を content の前提にする
  (C6・D5)・起動時の入力の欠けを fail-closed にし、`ngram` の破棄を preflight の信号にする (D4)・security 必須の範囲にコードの経路を足し、段階表を直す (D7・V8)・
  `sight` は発火で見えると書く (D2)・自課題の文が他課題の守る文に当たる例 (V2)・private の deny-list の follow-up (残余 7)。D6 の binary からの撤去は、security が
  実コードで妥当と確認した。
- content-engineer の助言 (schema の使いやすさ) を求める。
