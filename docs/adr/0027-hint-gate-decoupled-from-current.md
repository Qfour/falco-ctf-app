# ADR-0027: ヒントと steps の gate を読み投影の `current` から切り離し、どの課題でも減点つきで開けるようにする

- Status: **Proposed** (Accepted 化は CEO merge 時。期限 = P28-0b の merge 前)
- Date / Deciders: 2026-10-05 / CEO (2026-10-04 判断 3「開ける」) + VP + architect (起草) + security-engineer・qa-engineer
  (独立レビュー 2026-10-05。指摘は本版に反映済み)
- 関連: workspace `REFACTORING.md` P28-0b、app#105 (2026-08-17 CEO 決定)、ADR-0003 (A1・Option 1 / 2・Signpost 1 / 4 / 5)、
  ADR-0008、ADR-0005 / 0009 (spec parity)、I11、app#306 (portal のソース分割)。**他 ADR の Decision は supersede しない。**
  改めるのは 2026-08-17 の CEO 決定 (ADR ではなく、コード・テスト・spec の記述として存在する)
- 行番号は e74d871。`portal.html` = `internal/scoreboard/view/templates/portal.html` で、app#306 が入った後は
  `templates/portal/pane-story.tmpl` の同名関数を指す。`0003:N` / `0008:N` は `docs/adr/` の ADR-0003 / ADR-0008 の行番号

## Context

**C1. 現状の gate は読み投影にだけある。** journey は「order の先頭の未 solve」を `current`、それより後の未 solve を `locked` とし
(`internal/scoreboard/api/api.go:1883-1886,1913-1922`)、`missionDetail` は `locked` のとき store を見ずに、hints を全て未開封・
steps を全て未チェックで返す (`api.go:2041,2051-2056,2073-2100`)。根拠は 2026-08-17 の CEO 決定「locked mission hints 秘匿は
公平性の不可侵」で、テスト (`internal/scoreboard/journey_api_test.go:695-711`) と spec (`docs/openapi-scoreboard.yaml:2254-2257`
ほか 5 箇所) に固定されている。

**C2. 書き込み側には lock が無い。** `openHint` (`api.go:1483-1547`) と `stepCheck` (`:1427-1470`) は status も `current` も
参照しない。qa-engineer の実行 (2026-10-04、実 catalog + nimbusbreach-full、未コミットの再現テスト): 01〜04 を solve して
current = 05 のとき、`?mission=06` / `08` は `status=locked`・`nextIndex=0`・`opened=[]`。同じ状態で
`POST …/06-web-rce-shell/hints/1` は 200 で本文を返し、`hint_views` に記録され、score は 400 → 390。直後の投影は
`nextIndex=0`・`opened=[]` のまま。**減点は付くのに画面には出ない。**

**C3. 運用は既に非線形である。** 2h 版はハンズオンを 01・02・03・04・06・08 とし、05・07 を飛ばす
(`scenarios/nimbusbreach-full/playbook-2h.md:13,47`)。04 の後は current が 05 に留まり、06 / 08 のヒントは UI から開けない。
ヒントを必要とする初学者に偏って不利になる。trigger の solve は順序を問わない (`internal/scoreboard/scoring/scoring.go:359-363`)
ので、順序外に解くこと自体は元から許されている。lock が止めているのは「順序外に解くこと」ではなく「順序外に助けを買うこと」だけ
である。

**C4. CEO 決定 2026-10-04 (判断 3): 開ける。** どの課題でも減点つきでヒントを開けるようにする。採点 (Score・taint・`current`) は
変えない (P28 VP 裁定 1)。

## Options

1. **維持し、書き込み側にも lock を足す** — `openHint` / `stepCheck` が locked の課題を 4xx で拒否する。
   コスト: 書き込み経路が `current` の新しい消費者になる (ADR-0003 が `Sweep` への同種の追加を却下したのと同じ理由 = 単一定義の
   希薄化、`0003:780-784`)。`POST …/hints/{idx}` に 4xx が増える (API 契約の変更)。
   リスク: 投影と書き込みの食い違いは閉じるが、2h 版では 06 / 08 のヒントが使えないまま残る。運営が口頭で補えば「operator の
   無償救済は無し」(P22 決定) に反する。可逆。効き始める閾値: 全員が順番どおりに解く運用のとき。
2. **読み投影を `current` から切り離す【推奨・CEO 決定】** — hints と steps の投影を常に store から作る。`status` の値は残す。
   コスト: `missionDetail` の分岐、テストの反転と新設、spec の description 6 箇所 + `make gen`、portal の文言。
   書き込み側と採点は無変更。リスク: 先の課題のヒントを先に買える (Consequences の残余)。可逆だが、戻すなら Option 1 と同時で
   なければ C2 の「減点は付くのに見えない」が再発する。閾値: 順序外に解かせる運用が 1 つでもある時点 (2h 版で既に該当)。
3. **scenario にハンズオン経路を持たせる / skip を状態にする** — `current` の進み方を変える。
   コスト・リスク: `current` は taint の錨 (ADR-0003 A1) なので採点が変わる (I11 の supersede、Class-2)。経路上の 03 で詰まった人は
   救えない。閾値: attempt を明示操作にする設計 (CEO 判断 4 の別 ADR) と一体でのみ成立する。P28-0b (採点不変) では採れない。

## Decision

**Option 2。** 理由: 食い違いを「買ったものは見える」側に揃える案だけが、採点に触れずに 2h 版の不利を消せる。

- **D1 投影**: `hints` (`opened` / `lockedCount` / `nextIndex` / `penalty`) と `steps[].checked` は store だけの関数とし、`status` に
  依存させない。
- **D2 `status`**: 値 `solved | current | locked` は残す (response の enum を変えない)。`locked` の意味を「案内上の未到達」に改め、
  読み取りの制限を含意させない。`hints.lockedCount` は「未開封の数」のまま改名しない。
- **D3 書き込み側は無変更**: self-or-admin-write・origin-guard・順序開封 (前の番号が未開封なら 409)・冪等な再開封・rate-limit は
  そのまま。新しい status code は増えない。`openHint` / `stepCheck` / `resetDirty` の関数本体には触れない。
- **D4 無接触**: `scoring.CurrentMission`・taint (`scoring.go:427-441`)・`evaluateClean`・`Sweep`・Score
  (`internal/scoreboard/scoring/points.go`)・スキーマ。
- **D5 記述の更新**: 旧不変条件を主張している doc comment (`api.go:152-155,1827-1843,2027-2037,2043-2050,2069-2072,2101-2104`、
  同 `:2172-2173,2190-2191,2232-2233`、`journey_api_test.go:645-648,665-669,852-855`)、spec の 6 箇所
  (`docs/openapi-scoreboard.yaml:846-854,2254-2257,2277,2306-2311,2321,2376-2379`)、portal の `PREVIEW · LOCKED` 表示
  (`portal.html:1366`)。完了条件は `git grep -n 'unlocked prefix\|unlike hints\|or locked' -- internal docs/openapi-scoreboard.yaml` が
  0 件 (e74d871 では 17 件。うち portal の「solved or locked mission」2 件は真のままの記述だが、言い回しを変えて 0 件にする。grep は
  緩めない)。減点の先出し表示 (10 / 30 / 50) は変えない。
- **D6 非 current の evade の表示を中立にする (P28-0b の PR に含める。拘束)**: portal は status に関係なく全 evade に検知状態カードを
  描き、dirty でなければ「この attempt はクリーンです…このまま提出できます」と出す (`renderDetail` → `evadeSection` → `dirtySection`:
  `portal.html:1423,1493,1623,1650-1655`。`autoSolveStatus` の「クリーンな attempt を確認」`:1689-1695` も同種)。非 current の evade は
  dirty にならない (ADR-0003 A1) ので、評価していない gate を「通過」と見せている (`0003:461-464` に抵触。既存)。D1 で locked の
  課題が操作対象になると、これが標準の進め方に入る。P28-0b では、非 current の evade に上記の文言を出さず、「未開始」に当たる中立の
  表示にする (文言は product / content)。P28-1 が `alert` を入れるまでは `status` による分岐でよい。

### ADR-0003 への影響 (評価)

ADR-0003 は Option 2 (attempt を `current` から導出) を採り、有効条件を「進行が線形かつ `current` が単一である限り正しい」と
書いた (`0003:149`)。本 ADR は採点を変えないので I11 は破らない。ただし、この有効条件が成り立っていないことをここに記録する。

- **Option 1 (attempt epoch) の閾値** (`0003:133-134`「attempt の開始が進行順から導出できなくなった瞬間 — … 任意順 …」): **到達した。**
  順序外に試みる evade は、その課題が `current` になる前に attempt が始まって終わる。qa の実行でも、非 current の evade は禁止
  ルールを発火しても dirty にならなかった (ADR-0003 A1 の定義どおりの挙動)。
- **Signpost 1** (`0003:523-526`): **発火したものとして扱う。** 字義の観測形 2 つ (scenario.yaml が線形リストでなくなる / `?mission=` が
  attempt 開始の意味を持つ) はどちらも未充足である。だが見出しの条件「任意順が入る」は 2h 版の運用で成立しており、本 ADR は
  それを製品の標準動作にする。帰結「`current` が attempt の錨として機能しなくなる」は上の実行で観測済み。
- **Signpost 4** (`0003:532-534` submit できない申告 / reset が 3 回超): **未計測。** reset の痕跡はログ 1 行だけで (`api.go:1621`)
  metric が無く、2026-09-03 の実測値は見当たらない。本 ADR はこの評価を動かさない。計測手段は V8 で用意する。
- **Signpost 5** (`0003:535-541` capstone gate の inert 化): **前提が運用上つねに成立する。**「先行の evade が未 solve のまま後続が
  solve 済」は 2h 版の設計そのものである。qa の実行で、current = 03 でも current = 05 (2h 版の形) でも W2 が再現した。
  ADR-0003 が公開済みの W2 (`0003:221-244`、`scoring.go:84-135`) の再現であり、本 ADR が新しく作る経路ではない。
- **接続**: ADR-0003 自身の基準では Option 1 が目標形になる。CEO 判断 4 のうち、錨 (エンカウント開始を明示的な attempt にする) は
  推奨案で確定している。「10 の積極証明」の軸は、入れる方向で実現性の調査を先に行う (CEO 決定 2026-10-05)。この 2 点を扱う ADR は I11 と
  ADR-0003 Decision の supersede (Class-2) になり、ADR-0008 の「epoch は課題個別に」という立場 (`0008:401-404,442-445`) との整合も
  決める。それまで ADR-0003 の禁止 (`0003:461-464`「gate が実効的に存在する」と読める記述を書かない) は有効である。
- **期間の扱い (CEO 決定 2026-10-05: 前倒し)**: P28-0b が本番に出てからその ADR が landing するまで、W2 は標準の進め方の中にある
  (security-engineer R1 の指摘)。この期間を受容せず、ADR の期限を「P28-3 の前」から「**次回イベントの前**」へ前倒しする
  (露出が生じるのは開発段階ではなくイベントなので、期限もイベント基準で置く)。間に合わない回があれば、その回の受容を
  CEO が明示する。

**architect の判定: yes, if** — (a) 上の ADR を次回イベントの前に Accepted にする (CEO 決定 2026-10-05。当初案は P28-3 の前)、
(b) 間に合わない回は、その回の受容を CEO が明示する、(c) D6 を P28-0b に含める。

## Consequences

- **諦めたもの**: 「到達前の課題のヒントは見えない」という順序の統制 (2026-08-17 決定)。
- **残余 (読み飛ばし)**: current より先の課題のヒントを買える。値段は全員同じで、順位への効果は current で買う場合と変わらない
  (既定の配点で 1 solve = 100 点、ヒント 3 本で計 90 点)。ただし順序外の evade には禁止ルールの taint が付かない (ADR-0003 A1。
  公開済みの W1 / W2) ので、そこでヒントを買えば、gate の効かない道に有料の案内が付く。新しい経路ではないが、標準の進め方の
  中に入る。閉じるのは上の「接続」に書いた別 ADR である。
- **rate-limit の共有 (P28-0b の merge 前に Issue 化)**: hints / steps / reset-dirty は submit と同じ IP 単位の bucket を共有している
  (`api.go:299,438`。1 req/s・burst 10)。会場 NAT の下では、ヒントの開封が他人の submit を 429 にしうる (solve の時刻は
  タイブレークに効く)。開封数を最初に増やすのは P28-0b なので、Issue 化と対処方針の決定を 0b の merge 前に行う。
- **新たに守る不変条件**: 増やさない。「投影は store の関数」は下のテストで pin する (Hard Invariant にはしない)。
- **他ロール**: application は `status` から開封の可否を推論しない (portal は既に `nextIndex` だけで判断している:
  `portal.html:1458`)。P28-1 も同じ `missionDetail` を触るので直列化する。

## Signposts (この決定を覆す観測可能な信号)

計測は `hint_views.at` と `solved.at` から事後に導出できる。数値は仮 (基準データ未取得)。

1. **読み飛ばしの常態化**: 開封時点の current から order 上で 4 つ以上先 (2h 版の正規経路の最大距離 = 05 → 08 の 3 を超える) の
   課題のヒント 3 が、ヒント 3 の全開封の 20% を超える → ヒント 3 だけを近接条件で絞るか、明示的な attempt (別 ADR) に移す。
2. **順序外 evade への有料の案内**: evade の solve のうち、solve 時点で先行課題が未 solve で、かつその課題のヒントを事前に
   開いていたものが、1 イベントで 5 件を超える → 別 ADR の landing まで、evade のヒントに限って Option 1 を適用する。
3. **attempt epoch の ADR が Accepted になる** → `current` の意味が変わる。D1・D2・D6 はその ADR が上書きする前提で読み直す。
4. **開いたのに使われないヒント**: locked の課題で開かれ、その課題が最後まで未 solve だったヒントが全開封の 30% を超える →
   減点の確認 UI が先買いを誘っている。文言と導線を product / application で見直す。

## Verification

V1〜V7 は P28-0b の PR で満たす (**未実装**)。V8 は次回イベントの前に満たす (未着手)。**P28-0b の PR は security-engineer レビュー必須。**

- **V1 反転 (消さずに改名)**: `TestJourney_FreeBrowsing_LockedMissionHintsAlwaysHidden` →
  `TestJourney_FreeBrowsing_LockedMissionHints_FollowStore`、`TestJourney_FreeBrowsing_LockedMissionStepsAlwaysUnchecked` →
  `TestJourney_FreeBrowsing_LockedMissionSteps_FollowStore` (`journey_api_test.go:711,761`)。旧名と反転の理由を doc comment に残す。
- **V2 新設**: `TestJourney_RealOrder_SkippedMissionHints` — 実 catalog + nimbusbreach-full、current = 05 で `?mission=06` / `08` が
  `status == "locked"` のまま (D2)、開封前は `lockedCount == total`・`opened == []`・`nextIndex == 1`・`penalty == 10`。開封後は
  `opened` に本文が出て `nextIndex == 2`・`penalty == 30`。V1・V2 が変更前に red になることを PR 本文に貼る (qa の red-before で確認済み)。
- **V3 守る挙動を名指しで commit する (変更前も変更後も緑)**。locked の課題についての検査は qa の未コミットのテストにしか無い
  (既存の `TestJourney_HintInOrderReveal` と `TestJourneyWriteGate_OpenHint_CrossUserOracleBlocked` は current の課題だけを見て、
  記録の有無も assert しない)。次の名前で新設する:
  `TestJourney_LockedMission_OutOfOrderRevealIs409` / `TestJourneyWriteGate_OpenHint_LockedMission_CrossUserIs403AndRecordsNothing`
  (`hint_views` に行が残らないことまで assert) / `TestJourney_SolvedMission_KeepsOpenedHints` /
  `TestJourney_OpenHint_UnknownChallengeIs404` / `TestJourney_OutOfScenarioMission_FallsBackAndRevealIs404` (実 catalog)。
  既存の `TestJourney_FreeBrowsing_InvalidMissionFallsBackToCurrent`・`TestJourney_NoHintsForMissionWithoutJourney`・
  `TestReadGate_OtherUserForbidden` (読み取り側の self-scope) も無変更で緑。
- **V4 採点非接触**: `internal/scoreboard/scoring/` と `internal/store/` の diff がゼロ。`openHint` / `stepCheck` / `resetDirty` の
  関数本体も diff ゼロ。I11 の機械強制テスト (conventions の I11 行に列挙) が無変更で green。同じ `solved` + `hint_views` に対する
  Score が前後で一致する。
- **V5 spec と記述**: 6 箇所の description を更新し、`make gen` の生成物を同じ commit に含める。`gen-diff-check` は required check
  ではないので、実行結果を PR 本文に貼る。response のキー集合は変わらない (ADR-0009 の V5 は無変更で green)。D5 の `git grep` が 0 件。
- **V6 UI**: locked の課題でヒントを開けて本文が出ること、減点の先出し表示が出ること。
- **V7 D6**: `status` が `current` でない evade の画面に「クリーンです」「このまま提出できます」「クリーンな attempt を確認」が
  出ないこと。current の evade では従来どおり出ること。V6・V7 はブラウザでの確認で、E2E ハーネス (ADR-0031、予約) ができるまでは qa の手動検証 (画面を PR に貼る)。
- **V8 計測の準備**: Signposts 1 / 2 / 4 の集計手順を runbook に置く。reset 回数 (ADR-0003 Signpost 4) の計測手段も同時に決める。

## Advice

- security-engineer R1 (2026-10-05、APPROVE with comments → 本版に反映): D6 を拘束にする、W2 が標準の進め方に入る期間の受容は
  CEO 判断、rate-limit の共有を 0b の前に Issue 化、D5 の列挙漏れ。
- qa-engineer R2 (2026-10-05、APPROVE with comments → 本版に反映): V3 のテストを名指しで commit する、V2 / V4 の assert の追加、
  D5 の完了条件を grep にする。前段の実行結果 (C2、ADR-0003 評価、red-before と guard) も qa。
- product-engineer / VP (2026-10-04): F2 を公平性の検査で検出し、CEO 判断 3 として提示。Option 3 を却下する理由。
- R2 / R4 レビュー (P28 節、2026-10-04): ADR-0003 の有効条件の評価を本 ADR の必須項目にすること。
