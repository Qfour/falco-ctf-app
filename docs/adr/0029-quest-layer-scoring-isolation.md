# ADR-0029: Quest 層を採点から切り離す — `internal/quest` は採点の事実を値で受け取る派生層にし、採点非干渉 (I17) を import 閉包・leaderboard の一致・障害注入で機械検査する

- Status: **Proposed** (Accepted 化は CEO の確認時。期限 = P28-1 の software の merge 前: workspace `REFACTORING.md:1900`)
- Date / Deciders: 2026-10-12 / architect (起草・同意権) + VP (発注)。前提の CEO 決定: P28 判断 1〜6 (2026-10-04)、判断 4 の錨 = 明示的な attempt
  (2026-10-04 / 05)。独立レビューは未実施 (Advice)
- 関連: workspace `REFACTORING.md` P28 (VP 裁定 1・5・6、受け入れ条件 1〜3・14〜16、architect §2〜§4・§8・§10)、ADR-0006 / app#292 (別ファイル・
  物理分離の先例)、ADR-0020 (migration)、ADR-0028 (Signpost 2′ が I17 を処方に使う: `0028:102-104`)、ADR-0030 (content 契約と開示境界)、
  ADR-0031 (ブラウザ側の確認)、ADR-0032 (attempt epoch。Consequences の P28 の段落 `0032:177-180` が本 ADR を拘束する)
- 行番号は c5e0761。`0032:N` は main の ADR-0032 (a71fb20)。他 ADR の Decision は supersede しない。ADR-0032 には改訂を提案する (D7)

## Context

- **C1 前提 (再議論しない)。** 採点不変 (VP 裁定 1)。Lv は main quest の solve 数の別表示で、第 2 の数値経済を作らない (VP 裁定 5、CEO 判断 2 (a))。
  演出は従で、全部無くても全課題が解ける (product brief 柱 5)。他者の Lv・称号を出さない (VP 裁定 6)。マイクロサービス化しない (`REFACTORING.md:22-23`)。
- **C2 依存の向き (c5e0761 の非 test の import を集計)。** `store` → なし。`scoring` → {catalog, store} (`internal/scoreboard/scoring/scoring.go:146-147`)。
  `ingest` → {scoring, store, …}。`board`・`catalog` → なし。store・scoring・ingest をまとめて import するのは合成層 (`internal/scoreboard/api`・
  `internal/scoreboard`・`cmd/scoreboard`) だけ。board の境界は「board の閉包が store・scoring を含まない」片方向だけが検査されている
  (`internal/apispec/board_boundary_test.go:36-45`)。逆向き (core の閉包が board を含まない) は今は成り立つが、検査が無い。
- **C3 起動は fail-loud。** journey・narrative・rule 抜粋の読み込みの失敗は起動を止める (`cmd/scoreboard/main.go:179-209`)。board.db も開けなければ
  止める (`:237-241`) — board は必須機能だからで、Quest (C1 の柱 5) とは事情が違う。core の DB は migration に失敗すると開かない
  (`internal/store/store.go:183-186`)。
- **C4 順位の単一の源は `computeLeaderboard`** (`internal/scoreboard/api/api.go:2343-2444`)。入力は store の Snapshot・HIDDEN_USERS・`Grader.UserScore`
  (solve 数と hint_views: `scoring.go:330-343`) だけ。`/api/state` の body は `now` (`api.go:2571`) と、同時刻の solve の並びが map の走査順に依存する
  `recent_solves` (`:2533-2548`) を含むので、body 全体は byte で再現しない。`leaderboard` は user を整列してから安定 sort する (`:2373,2423-2428`) ので再現する。
- **C5 Quest に要る事実はすべて core にある。** solved・hint_views・catalog・order、交戦ログの素材の in-memory の発火 (300 秒。件数の上限は無い:
  `internal/store/store.go:93-101,457-474,607-619`)、taint と証明の記録。ingest は発火を記録して Grader を呼ぶだけ (`internal/scoreboard/ingest/ingest.go:261-273`)。
- **C6 ADR-0032 の拘束。** やり直しと切り替えは core のトランザクションで新しい epoch を払い出す (`0032:54-59,101-103`)。`evade_attempt` は上書きされ、
  履歴を持たない (`0032:125`)。印・称号は「gate を通った solve」を server の solve の記録から導き、時刻の比較や claimed identity の経路 (collector 経由の
  submit・exfil) から導かない。ADR-0032 の landing より前の evade の solve には出さない (`0032:177-180`)。
- **C7 REFACTORING §3 の案。** 「reset なし突破」だけを quest.db の `retreats` に記録し、記録開始時刻 (Quest が有効だった区間) より後に始まった attempt
  にだけ付与する。書き込みに失敗したときの扱いを本 ADR で決める (`REFACTORING.md:1782,1789-1791`)。

## Options

1. **core に直接足す** — Quest の計算を api に、永続を scoreboard.db に置く。コスト: 最小。リスク: Quest の表が core の migration に混ざり、その失敗が
   core の起動拒否になる (C3)。Quest の panic が journey の応答を 500 にする。I17 を機械で言えない。可逆性: 低 (core の migration は additive-only:
   ADR-0020)。閾値: 無し (採らない)。
2. **`internal/quest` を派生層に分け、合成層が組み立てる【推奨】** — quest は catalog にだけ依存し、core の事実を値で受け取って表示を返す。永続が要る
   ときだけ別ファイル quest.db。コスト: package 1・境界テスト・障害注入テスト・nil を許す配線・metric 3 本。リスク: 合成点の api が太る (`api.go` は
   2,573 行。Quest の handler は `api/quest.go` に分ける)。可逆: Quest を外しても core は無変更。閾値: P28-1 から。
3. **Quest を別プロセスにする** — 障害の分離は最も強い。コスト: image 追加 (I5、CEO 承認)、spec・ingress・identity 照合の写しが 1 組増える。リスク:
   「gate を通った solve」のような core の内部の事実を HTTP で外に出す API が要る (攻撃面と公開境界が広がる)。閾値: Signpost 2 が 2 回続き、D3 の
   in-process の隔離で直らないとき。

## Decision

**Option 2。** 理由: core を 1 行も Quest に依存させずに済み、Quest の障害の伝播を「import の向き・値渡し・recover」の 3 層で止められ、新しい image も
HTTP 境界も増やさない。

- **D1 依存の向き (I17 (a))。**
  - `internal/quest` (配下の package を含む) の module 内 import 閉包は、`internal/store`・`internal/scoreboard/{scoring,ingest,api,view}`・`internal/board`
    を含まない。設計上、依存してよい module 内 package は `internal/catalog` と `internal/hintleak` (ADR-0030 D4) だけとする (こちらは review で守る)。
  - 逆向き: `internal/store`・`internal/scoreboard/scoring`・`internal/scoreboard/ingest` の閉包は `internal/quest` (配下を含む) と `internal/board` を含まない
    (board の逆向きを吸収する: REFACTORING §4)。catalog は scoring の閉包の中にあるので、catalog が quest を import すれば同じ検査で落ちる。
    Quest content の型と loader は catalog ではなく quest に置く。
  - store・scoring・ingest と quest の両方を import してよいのは合成層だけ。
- **D2 Quest は事実を値で受け取る。**
  - api が core から読んだ事実を quest の入力型 (例: `Facts{Order, Solved, HintsOpened, GatePassed, AttemptStarts}`) に詰めて渡す。quest は store の
    handle も Grader も持たず、core に書かない。
  - core の事実だけで作れる表示は core の projection に置く: MissionDetail の `forbiddenRules`・`battleLog`・`alert` (alert の定義は ADR-0032 D8)。
    battleLog は `store.RecentRuleFires(user, now, 300)` を当該課題の expected ∪ forbidden で絞り、新しい順に上限 (仮 20 件) で切る。`relation` は ADR-0032
    D8 の定義に従う。Quest content が要る `sights`・`encounter` と `GET /api/users/{user}/quest` (QuestBook) だけが quest を通る。
  - ingest・Sweep・submit・exfil の経路に Quest の呼び出しと書き込みを足さない。
- **D3 fail-soft。**
  - Quest content の読み込みと検証の失敗は、その entry の破棄と warn だけにして起動を止めない (CI では fail にする: ADR-0030 D5)。quest.db の open・
    migrate の失敗と、DB が binary より新しい場合も、Quest の永続を無効にするだけで起動を続ける (board・core と逆の向き)。
  - 実行時: 合成層は quest の呼び出しを recover で囲み、error と panic を「その応答の Quest のキーを空にする」に変える (`encounter: null`・`sights: {}`、
    QuestBook は 503 `{"error": "quest unavailable"}`。文言は定数)。core のキーと status code は変えない。quest は goroutine を作らない (recover が届かない)。
  - kill switch は env `QUEST_ENABLED` (chart の既定は `true`)。`false` と未知の値は Quest 無効 (未知の値は error log。Quest のために起動を止めない)。
  - ブラウザ側 (Quest の script の例外が core の pane を止めない) は ADR-0031 の E2E と application の規律に置く (`REFACTORING.md:1801`)。
- **D4 採点非干渉 (I17 (b))。** Quest の状態 (有効・kill switch・content なし・content 破損・quest.db を開けない) にかかわらず、同じ core の状態に対して
  `GET /api/state` の `leaderboard` の JSON と、`GET /api/users/{user}/me` の `rank`・`score` が byte で一致する (body 全体ではない: C4)。`/api/state` に
  Quest のデータを足さない (他者の Lv・称号を構造的に出さない。key 集合は ADR-0009 の V5 が pin している)。Score・タイブレーク・
  `internal/scoreboard/scoring/points.go` を Quest の PR で変えない。
- **D5 障害注入 (I17 (c))。** quest を nil にしても、すべての呼び出しが error か panic になる実装に差し替えても、journey・submit (trigger と evade)・
  hints・steps・reset-dirty・`POST /falco/events`・admin reset・Sweep の status と core のキーは変わらない。
- **D6 永続と寿命。**
  - Quest の永続状態は別ファイル **`quest.db`** (`SCOREBOARD_DB` と同じディレクトリ = 同じ PVC。board.db と同じ置き方: `cmd/scoreboard/main.go:237`)。
    同じプロセスがファイルごとに唯一の writer なので I1 は変わらない。scoreboard.db を ATTACH せず、ファイルをまたぐトランザクションを作らない。
    migration は ADR-0020 と同じ形の独立した写し (board と同じ理由: `internal/board/migrations.go:7-14`)。
  - quest.db に置くのは **Quest だけが真実を持つもの** (P28-5 の看破の回答)。core に真実がある事実 (solve・ヒント・attempt・やり直し) を写さない。
    flag と提出値を置かない。
  - **作るのは最初の利用者の PR (P28-5)。** P28-1・P28-2 の表示はすべて派生で、永続を要らない。
  - admin reset: core の reset が成功した後で quest.db を閉じ、本体と `-wal`・`-shm` を消して作り直す。Quest 側が失敗しても応答は 200 のままで、
    `quest` に結果 (`reset` | `unavailable`) を添える (additive。spec はその PR で足す)。
  - 寿命: 交戦ログは in-memory の 300 秒で再起動で消える (core の既存の性質)。QuestBook は派生なので core と同じ。quest.db はイベント 1 回分
    (admin reset と teardown で消える)。バックアップの対象にしない。
- **D7 印・称号は core の記録から導き、Quest は記録しない** (REFACTORING §3 の必須項目への回答)。
  - Lv・とくぎ・称号「ノーヒント」 = solved と hint_views。図鑑の発火印 (rule r) = r を expected に持つ課題 (trigger、または積極証明つきの evade) を
    solve した。証明の記録 (`expected_rule_fire`) は読まない (ADR-0032 で attempt スコープになり、attempt の外では見えない: `0032:67-69`)。
  - 突破印 (rule r)・称号「ボス突破」 = r を forbidden に持つ evade を **`GatePassed`** で solve した。`GatePassed(u, c)` は core 側 (scoring) の 1 関数が
    決め、合成層が bool で渡す。ADR-0032 の下では「`c` の attempt 開始の記録があり、`c` が solve 済み」。退避 (i') の回は REFACTORING §8 の inScope
    (core の記録の比較。Quest は関与しない)。どちらも landing していない間は常に `false`。
  - 称号「reset なし突破」 = `GatePassed`、かつ (u, c) の attempt 開始が 1 回だけ (やり直しと、切り替えて戻ることを、どちらも新しい開始と数える)。
  - **前提 (未確定)。** ADR-0032 の現案には attempt 開始の履歴が無い (C6)。**ADR-0032 の改訂として、S3a に append-only の表
    (epoch, user, challenge, started_at) を足し、開始・切り替え・やり直しと同じトランザクションで書くことを提案する** (admin reset はこの表も消す。
    ADR-0032 の Signposts 3・4 を stdout ではなく DB から測れる利点もある)。採否は VP / CEO (Class-2)。入るまで、突破印・「ボス突破」・「reset なし突破」
    は出さない。
  - この形では §3 の「記録開始時刻」と「書き込み失敗時の扱い」が要らない: 記録は epoch の払い出しと同じトランザクションにあり、記録の無い attempt は
    存在できない。表ができる前の attempt には記録が無いので付与されない (fail-closed が構造で成り立つ)。退避 (i') の回の「reset なし突破」は出さない
    (やり直しの履歴が core に無い)。
- **D8 HTTP 面 (REFACTORING §2 の確認)。** `GET /api/users/{user}/quest` は self-or-admin (I8)、route table + spec + `x-ctf-*` (I14)、response の key 集合の
  検査 (ADR-0009)。ingress は既存の `/api/users/` Prefix で足りる (I15。変更なし)。エラーは `{"error": 定数}` の 1 形で `err.Error()` を出さない。
  MissionDetail の additive は `forbiddenRules`・`battleLog`・`alert`・`sights`・`encounter` の 5 つ。`relation`・`alert`・`role` は open string で、未知値の
  扱いを spec に書く。看破 (P28-5) の route は origin-guard と identity キーの rate-limit を持ち、その PR で spec を決める。
- **D9 観測と運用。** gauge `quest_enabled` (0 / 1)、counter `quest_content_discarded_total{kind}` と `quest_errors_total{op}` (user を label にしない)。log は破棄
  した file と entry の id だけを出し、文面を出さない。sre の preflight と verify は `quest_enabled == 1` を warn で見る (no-go にしない)。kill switch を
  runbook に載せる (platform の文書。sre)。
- **D10 移行と rollback。** P28-1・P28-2 はどちらの DB にも schema を足さないので、前の image に戻すだけで戻る。quest.db (P28-5 以降) を前の image で
  開くと「DB が新しい」で Quest の永続が無効になるだけで、core は動く (core の DB は ADR-0032 の migration の後は前の image で開けない: `0032:176`)。
  D7 の改訂は core の migration なので、ADR-0032 の切り戻しの規律に従う。

### I17 (提案。未昇格)

> **I17 (採点非干渉)**: (a) `internal/store`・`internal/scoreboard/scoring`・`internal/scoreboard/ingest` の module 内 import 閉包は `internal/quest` (配下を
> 含む) と `internal/board` を含まない。`internal/quest` (配下を含む) の閉包は store・scoring・ingest・api・view・board を含まない。(b) Quest の状態に
> かかわらず、同じ core の状態に対する `GET /api/state` の `leaderboard` と `GET /api/users/{user}/me` の `rank`・`score` は byte で一致する。(c) Quest を
> nil にしても常に失敗させても、journey・submit・hints・steps・reset-dirty・`POST /falco/events`・admin reset・Sweep の振る舞いは変わらない。
> 例外・除外リストを持たない。

- 機械強制は V1〜V3 (すべて `make test` = required check)。**昇格は V1〜V3 が landing する PR (`internal/quest` を作る P28-1 の software の PR) と
  同じ PR で行う** (`docs/adr/README.md` の規律)。先に表へ載せない。
- I17 は「Quest が採点を変えない」とだけ主張し、「Quest の文がヒントを漏らさない」は主張しない (ADR-0030 の領分。表題に混ぜない)。

**architect の判定 (同意権)**: I17 の新設は **yes, if** — (i) V1〜V3 と同じ PR で表に載せる (ii) 故意違反で赤になる出力を PR 本文に貼る (iii) D7 の前提が
決まるまで、突破印と 2 つの称号を出さない実装にする。

## Consequences

- **諦めたもの**: Quest が自分の判断で判定を足すこと (core の事実が要る判定は、core 側の機能として提案する経路を通る)。突破印と「reset なし突破」を
  P28-2 の初日から出すこと (D7 の前提が入るまで出ない)。独立 XP (CEO 判断 2)。
- **新たに守る不変条件**: I17 (提案)。既存の board の境界テスト (`board_boundary_test.go`) は残し、I17 (a) が逆向きを足す。
- **他 ADR への影響**: ADR-0032 に表 1 つの改訂を提案する (D7)。ADR-0028 Signpost 2′ の処方 (境界を import 閉包で点検する) は V1 を使う。
- **REFACTORING との差** (VP へ報告): §3 の `retreats` と記録開始時刻を D7 で置き換えた。§3 の発火印の「または `expected_rule_fire` に行がある」を
  外した (証明の rule の印が付くのは発火の時点ではなく solve の時点になる。product-engineer の確認が要る)。quest.db を作る時期を P28-5 に移した。I17 (a) に quest 側の向き (api・view・board も含まない) を、(b) に me の `rank`・`score` を足した。
- **runbook**: kill switch・`quest_enabled`・admin reset の応答の `quest` (platform の文書、sre)。
- **残余**: (1) Quest の CPU とメモリは core と同じプロセスにある (Signpost 2) (2) recover は quest が goroutine を作らない前提で効く (review で守る)
  (3) 交戦ログは再起動で消える (既存の性質で、Quest が増やすものではない)。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・2 は scoreboard の metric と `scoreboard_http_request_duration_seconds`、3・4 は PR と ADR の記録から測る。

1. イベント中に `quest_errors_total` が 0 を超える、または journey・me の 5xx が Quest に起因する例が 1 件 → 計算を request の外 (起動時と solve の変化時の
   事前計算) に移す。
2. journey の p99 が P28-1 の前のイベントより 50ms 以上悪化する、または QuestBook の p95 が 200ms を超えるか 32KB を超える (REFACTORING §2) → Quest の
   projection を別の poll か cache に分ける。2 回続き D3 で直らなければ Option 3 を再検討する (image の追加は CEO)。
3. Quest の要件が ingest の経路か core の DB への書き込みを求める (例: 交戦ログの永続の要求が 2 回: REFACTORING §3) → 例外で通さず、core 側の機能
   として ADR を書く。
4. D7 の前提 (attempt 開始の記録) の採否が P28-2 の software の merge までに決まらない、または不採用 → 「reset なし突破」を外すか、quest.db に記録して
   残余を明記する設計を新 ADR で比べる (product-engineer の判断を添える)。

## Verification

すべて**未実装**。V1〜V5 は P28-1 の software の PR、V6 は D7 の前提が入る PR で満たす。

- **V1 (I17 (a))**: `internal/apispec/quest_boundary_test.go` の `TestCoreClosure_ExcludesQuestAndBoard` と `TestQuestClosure_ExcludesCore`。既存の
  `transitiveModuleImports` (`internal/apispec/dependency_boundary_test.go:72-90`) を使う。`internal/quest` 配下の package はディレクトリを歩いて列挙し、
  0 件 (non-test の .go が 1 本も無い) は fail。非空の検査として scoring の閉包が store と catalog を含むことを確かめる (歩けていない検査を緑にしない)。
  故意違反: t.TempDir() の 2 段の鎖 (core → fixture → quest、quest → fixture → store) がそれぞれ赤になる (`:163-181` と同じ形)。
- **V2 (I17 (b))**: `internal/scoreboard` の `TestLeaderboard_ByteIdenticalRegardlessOfQuest`。同じ手順 (HTTP で発火・submit・ヒントの開封) を 4 状態
  (有効・kill switch・content なし・content 破損。quest.db を作る P28-5 の PR で「quest.db の位置にディレクトリ」を足す) の handler に流し、`leaderboard` の JSON と me の `rank`・`score` を byte で
  比べる。Quest の値を lbEntry に混ぜた故意の変更で赤になる出力を PR 本文に貼る。
- **V3 (I17 (c))**: (i) Quest を入れる PR で、既存のテストの変更を response の key 集合・件数と route 数の pin (ADR-0005 / 0009) に限り、
  それ以外は無変更で green (既存のテストは Quest を配線しない = nil の場合そのもの) (ii) `TestQuestFailing_CoreRoutesUnchanged`: 常に error を返す Quest と
  常に panic する Quest で、D5 の route の status と core のキーが nil の場合と同じ (iii) Quest 無効時の形: `encounter: null`・`sights: {}`・QuestBook は 503
  と定数の文言。
- **V4 起動**: `cmd/scoreboard` の `TestMain_QuestBroken_BootsAndScores`。壊した content と未知の `QUEST_ENABLED` (P28-5 以降は開けない quest.db も) のそれぞれで起動し、
  `quest_enabled` が 0、破棄の counter が増え、trigger の solve が通る。
- **V5 (D7 の fail-closed)**: `GatePassed` が false の間 (core の記録が無い evade の solve。ADR-0032 より前の行を含む) は、突破印・「ボス突破」・
  「reset なし突破」が QuestBook に出ない。発火印は solved だけから出る (`expected_rule_fire` に行があっても solve の前は出ない)。
- **V6 (前提が入ったら)**: 実 store で、最初の attempt で solve → 付与 / やり直した後の solve → 付与しない / 切り替えて戻った後の solve → 付与しない /
  admin reset の後は数え直す。
- **機械で守れないもの**: quest が goroutine を作らないこと、Quest の PR が `points.go` を変えないこと (どちらも PR の review)。

## Advice

- architect (2026-10-04、REFACTORING P28 §2〜§4・§8・§10) と、その R2 (qa-engineer)・R4 (architect の別インスタンス) のレビューが出発点。本 ADR は
  D2 (core の projection と Quest の分け方)・D4 の比較対象・D7 を改めた。
- ADR-0032 の Consequences (2026-10-05、product-engineer の条件つき合意) の拘束を D7 で受けた。
- VP (2026-10-10 / 12、発注): 決めることの一覧と ADR の型。
- 独立レビューは未実施。security-engineer (fail-soft・admin reset・kill switch の既定・D7 の提案) と qa-engineer (V1〜V3 の組み方と故意違反) に依頼する。
