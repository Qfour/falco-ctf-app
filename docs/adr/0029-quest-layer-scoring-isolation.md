# ADR-0029: Quest 層を採点から切り離す — `internal/quest` は採点の事実を値で受け取る派生層にし、採点非干渉 (I17) を import 閉包・leaderboard の一致・障害注入で機械検査する

- Status: **Proposed** (Accepted 化は CEO の確認時。期限 = P28-1 の software の merge 前: workspace `REFACTORING.md:1900`)
- Date / Deciders: 2026-10-12 / architect (起草・同意権) + VP (発注と裁定 2 件 = D7 の判定の定義・ADR-0030 の content の PR の順序、2026-10-12)。前提の CEO 決定:
  P28 判断 1〜6 (2026-10-04)、判断 4 の錨 = 明示的な attempt (2026-10-04 / 05)。独立レビュー: qa-engineer R2・security-engineer R1 (どちらも 2026-10-12、本版に反映)
- 関連: workspace `REFACTORING.md` P28 (VP 裁定 1・5・6、受け入れ条件 1〜3・14〜16、architect §2〜§4・§8・§10)、ADR-0006 / app#292 (別ファイル・
  物理分離の先例)、ADR-0020 (migration)、ADR-0028 (Signpost 2′ が I17 を処方に使う: `0028:102-104`)、ADR-0030 (content 契約と開示境界)、
  ADR-0031 (ブラウザ側の確認。D2 = HTTP の性質は `make test` に置く)、ADR-0032 (attempt epoch。Consequences の P28 の段落 `0032:177-180` が本 ADR を拘束する)
- 行番号は c5e0761。`0032:N` は main の ADR-0032 (a71fb20)。他 ADR の Decision は supersede しない。ADR-0032 には改訂を 2 つ提案する (D7)

## Context

- **C1 前提 (再議論しない)。** 採点不変 (VP 裁定 1)。Lv は main quest の solve 数の別表示で、第 2 の数値経済を作らない (VP 裁定 5、CEO 判断 2 (a))。
  演出は従で、全部無くても全課題が解ける (product brief 柱 5)。他者の Lv・称号を出さない (VP 裁定 6)。マイクロサービス化しない (`REFACTORING.md:22-23`)。
- **C2 依存の向き (c5e0761 の非 test の import を集計)。** `store`・`catalog`・`board` → module 内の import なし。`scoring` → {catalog, store}
  (`internal/scoreboard/scoring/scoring.go:146-147`)。`detect` → {catalog}。`ingest` → {scoring, store, …}。store・scoring・ingest をまとめて import するのは合成層
  (`internal/scoreboard/api`・`internal/scoreboard`・`cmd/scoreboard`) だけ。board の境界は「board の閉包が store・scoring を含まない」片方向だけが検査されている
  (`internal/apispec/board_boundary_test.go:36-45`)。閉包を歩く `transitiveModuleImports` はディレクトリの無い package を葉として扱う
  (`internal/apispec/dependency_boundary_test.go:83-86`) ので、出発点の package が移動すると閉包が出発点だけになり、検査は黙って緑になる。
- **C3 起動は fail-loud。** journey・narrative・rule 抜粋の読み込みの失敗は起動を止める (`cmd/scoreboard/main.go:179-209`)。board.db も開けなければ
  止める (`:237-241`) — board は必須機能だからで、Quest (C1 の柱 5) とは事情が違う。core の DB は migration に失敗すると開かない (`internal/store/store.go:183-186`)。
  main() は os.Exit を含む 1 つの関数で (`main.go:28-325`)、既存のテストは切り出した関数とソースの文字列の pin しか見ない (`cmd/scoreboard/main_test.go:221-278`)。
  `serverutil.Env` は空文字を未設定と同じに扱う (`internal/serverutil/serverutil.go:21-26`)。
- **C4 順位の単一の源は `computeLeaderboard`** (`internal/scoreboard/api/api.go:2343-2444`)。入力は store の Snapshot・HIDDEN_USERS・`Grader.UserScore`
  (solve 数と hint_views: `scoring.go:330-343`) だけ。同点を割る `earliest` は最新の solve の時刻 (`api.go:2396-2404`) で、solve の時刻は handler の時計
  (`scoreboard.WithNow`: `internal/scoreboard/server.go:86`) から来る。`/api/state` の `recent_solves` は、同時刻の solve の並びが map の走査順に依存する (`api.go:2533-2548`)。
- **C5 Quest に要る事実はすべて core にある。** solved・hint_views・catalog・order、交戦ログの素材の in-memory の発火 (300 秒。件数の上限は無い:
  `internal/store/store.go:93-101,457-474,607-619`)、taint と証明の記録。ingest は発火を記録して Grader を同期で呼ぶだけ (`internal/scoreboard/ingest/ingest.go:258-273`)。
- **C6 ADR-0032 の拘束。** やり直しと切り替えは core のトランザクションで新しい epoch を払い出す (`0032:54-59,101-103`)。`evade_attempt` は user が主キーで、次の開始で
  上書きされ、履歴を持たない (`0032:54,125`)。S3b-1 (開始ルート) から S3b-2 (gate の強制) までの間は、開始の記録があっても gate を通らずに solve できる (`0032:62,196`)。
  印・称号は「gate を通った solve」を server の solve の記録から導き、時刻の比較や claimed identity の経路 (collector 経由の submit・exfil) から導かない。ADR-0032 の
  landing より前の evade の solve には出さない (`0032:177-180`)。
- **C7 Quest に渡すと core を壊しうるもの。** `catalog.Catalog` は `map[string]Challenge` で、`ExpectedRules` と `ExpectedFlag` を持つ (`internal/catalog/catalog.go:82-114`)。
  scoring と api は同じ `cat` と同じ order の slice を持ち (`internal/scoreboard/server.go:220,232-236`)、採点はそれを `slices.Contains` と走査で読む
  (`scoring.go:300,381,436,479`)。Go の値渡しは浅いコピーなので、quest が受け取った slice を in-place で filter (`s[:0]`) か sort すると、禁止ルールの taint が黙って
  外れる (fail-open)。これは import の閉包にも、Quest を呼ばない手順の比較にも映らない。`httpx.WriteJSON` は header を書いた後に Encode の error を捨てる
  (`internal/scoreboard/httpx/httpx.go:10-14`) ので、encode できない値が core の応答に混ざると、recover の外で 200 の空 (か途中までの) body になる。recover は runtime の
  fatal error (並行の map 書き込み・stack overflow・OOM) を止めず、プロセスごと落ちる。replica は 1 つ (I1) なので、その間の Falco イベントを取りこぼしうる (taint の空白)。
- **C8 REFACTORING §3 の案。** 「reset なし突破」だけを quest.db の `retreats` に記録し、記録開始時刻 (Quest が有効だった区間) より後に始まった attempt
  にだけ付与する。書き込みに失敗したときの扱いを本 ADR で決める (`REFACTORING.md:1782,1789-1791`)。

## Options

1. **core に直接足す** — Quest の計算を api に、永続を scoreboard.db に置く。コスト: 最小。リスク: Quest の表が core の migration に混ざり、その失敗が
   core の起動拒否になる (C3)。Quest の panic が journey の応答を 500 にする。I17 を機械で言えない。可逆性: 低 (core の migration は additive-only:
   ADR-0020)。閾値: 無し (採らない)。
2. **`internal/quest` を派生層に分け、合成層が組み立てる【推奨】** — quest は core の事実を値で受け取って表示を返す。永続が要るときだけ別ファイル quest.db。
   コスト: package 1・境界テスト・障害注入テスト・nil を許す配線・metric 3 本・入力型への詰め替え。リスク: 合成点の api が太る (`api.go` は 2,573 行。
   Quest の handler は `api/quest.go` に分ける)。可逆: Quest を外しても core は無変更。閾値: P28-1 から。
3. **Quest を別プロセスにする** — 障害の分離は最も強い。コスト: image 追加 (I5、CEO 承認)、spec・ingress・identity 照合の写しが 1 組増える。リスク:
   「gate を通った solve」のような core の内部の事実を HTTP で外に出す API が要る (攻撃面と公開境界が広がる)。閾値: Signpost 2 が 2 回続き D3 の
   in-process の隔離で直らないとき、または Quest に起因するプロセスの停止 (fatal error) が 1 件起きたとき。

## Decision

**Option 2。** 理由: core を 1 行も Quest に依存させずに済み、Quest の障害の伝播を「import の向き・複製による値渡し・recover」の 3 層で止められ、新しい image も
HTTP 境界も増やさない。

- **D1 依存の向き (I17 (a))。**
  - quest 側は**許可リスト**で決める: `internal/quest` (配下を含む) の module 内 import 閉包は、`internal/quest` 配下・`internal/hintleak` (ADR-0030 D4)・`internal/sourcehygiene` (hintleak が import する不可視文字の表と文脈規則: ADR-0043 D1。hintleak の module 内
    import は sourcehygiene だけ、sourcehygiene は持たない。起草時の注記「hintleak は module 内の import を持たない」は ADR-0043 で訂正) の外を含まない。許可リストの葉 2 つは、公開の package レベル var を error 型以外に持たない (quest が書ける共有状態を作らない)。catalog も許さない (catalog の型を持てば C7 の参照を持ちうる)。catalog 由来の事実は D2 の入力型で受け取る。Quest content の型と
    loader は quest に置く。
  - core 側: `internal/store`・`internal/scoreboard/{scoring,ingest,detect}` の閉包は `internal/quest` (配下を含む) と `internal/board` を含まない (board の逆向きを
    吸収する: REFACTORING §4)。catalog は scoring の閉包の中にあるので、catalog が quest を import すれば同じ検査で落ちる。
  - store・scoring・ingest と quest の両方を import してよいのは合成層だけ。
- **D2 Quest は事実を複製で受け取り、状態を共有しない** (qa R2 HIGH-2 と security R1 HIGH を 1 つにした)。
  - 入力型は quest が定義し、合成層が core から読んで組み立てる (例: 呼び出しごとの `Facts{Order, Solved, HintsOpened, GatePassed, StartCounts}`、構築時の課題ごとの
    type・expected・forbidden・`requireExfil`・`requireExpectedRuleFire` と、n-gram 検査の文 = `hintleak.Item`)。入力型が持てるのは bool・数値・string と、それらから成る
    slice・map・struct (quest か hintleak が定義した型) だけ。pointer・interface・func・chan・他 package の型 (`catalog.Catalog`・`time.Time` を含む) と、名前に flag を
    含むフィールドを持たない。**slice と map は呼び出しごと・構築時ともに新しく作る** (catalog と order の slice は複製し、backing array を共有しない: C7)。quest が入力を
    書き換えても core に届かない。quest は store の handle も Grader も持たず、core に書かない。
  - quest は goroutine を作らず (recover が届かない)、request をまたぐ可変状態を持たない (package レベルの var を持たず、読み込んだ content を起動後に変えない)。cache を
    入れるときは user をキーにし、admin reset で捨てる。fatal error (C7) は recover で止まらないので、構造で起こさない。
  - core の事実だけで作れる表示は core の projection に置く: MissionDetail の `forbiddenRules`・`battleLog`・`alert` (alert の定義は ADR-0032 D8)。
    battleLog は `store.RecentRuleFires(user, now, 300)` を当該課題の expected ∪ forbidden で絞り、新しい順に上限 (仮 20 件) で切る。`relation` は ADR-0032
    D8 の定義に従う。Quest content が要る `sights`・`encounter` と `GET /api/users/{user}/quest` (QuestBook) だけが quest を通る。
  - ingest・Sweep・submit・exfil の経路に Quest の呼び出しと書き込みを足さない。
- **D3 fail-soft。**
  - 起動時: 合成層の seam `questFromEnv` (error を返さない) が env・Quest content・(P28-5 以降) quest.db を読み、失敗はすべて「その entry の破棄」か「Quest の無効化」に
    する (CI では fail: ADR-0030 D5)。main はその結果で exit しない。quest.db の open・migrate の失敗と、DB が binary より新しい場合は、Quest の永続を無効にするだけで
    起動を続ける (board・core と逆の向き)。破棄と error は quest が一覧で返し、metric と log は合成層が出す。
  - 実行時: 合成層は quest の呼び出しと、**その出力の JSON 化** (`json.RawMessage` にしてから core の応答に埋める) を recover の内側で行い、error・panic・encode の失敗を
    「その応答の Quest のキーを無効の形にする」に変える (`encounter: null`・`sights: {}`、QuestBook は 503 `{"error": "quest unavailable"}`。文言は定数)。core のキー・
    status code・Content-Type は変えない (C7 の空 body を作らない)。
  - kill switch は env `QUEST_ENABLED` (chart と compose は `true` を明示する)。`strconv.ParseBool` が true = 有効。未設定・空文字 (C3)・false = 無効 (info log)、それ以外
    = 無効 (error log。Quest のために起動を止めない)。未設定を未知の値と同じ安全側に倒す (security R1)。ADR-0031 の E2E は子の env を allowlist で組むので、そこに
    `QUEST_ENABLED=true` を足す (依頼)。切り替えは Pod の作り直しで、その間は ingest が止まる (開催中の切り替えは採点に空白を作る。runbook に書く)。
  - ブラウザ側 (Quest の script の例外が core の pane を止めない) は ADR-0031 の E2E と application の規律に置く (`REFACTORING.md:1801`)。
- **D4 採点非干渉 (I17 (b))。** Quest の状態 (有効・kill switch・content なし・content 破損・常に error・常に panic。P28-5 以降は quest.db を開けない) にかかわらず、
  同じ core の状態に対して `GET /api/state` の `leaderboard` の JSON と、`GET /api/users/{user}/me` の `rank`・`score` が byte で一致し、P28 の前に固定した期待値とも一致
  する (body 全体ではない: C4)。`/api/state` に Quest のデータを足さない (他者の Lv・称号を構造的に出さない。key 集合は ADR-0009 の V5 が pin している:
  `internal/scoreboard/apispec_parity_test.go:424`)。Score・タイブレーク・`internal/scoreboard/scoring/points.go` を Quest の PR で変えない。
- **D5 障害注入 (I17 (c))。** quest を nil にしても、すべての呼び出しが error・panic・encode に失敗する値の返却・入力の書き換えをする実装に替えても、
  `scoreboard.Handler.Routes()` (`internal/scoreboard/server.go:296`) の**全 route** の status・Content-Type・JSON の body と、Sweep の結果は変わらない (route を手で列挙
  しない。新しい route は自動で対象になる)。Quest を有効にしても、Quest の面 (`sights`・`encounter`・QuestBook) の外は nil の場合と同じ。
- **D6 永続と寿命。**
  - Quest の永続状態は別ファイル **`quest.db`** (`SCOREBOARD_DB` と同じディレクトリ = 同じ PVC。board.db と同じ置き方: `cmd/scoreboard/main.go:237`)。
    同じプロセスがファイルごとに唯一の writer なので I1 は変わらない。scoreboard.db を ATTACH せず、ファイルをまたぐトランザクションを作らない。
    migration は ADR-0020 と同じ形の独立した写し (board と同じ理由: `internal/board/migrations.go:7-14`)。
  - quest.db に置くのは **Quest だけが真実を持つもの** (P28-5 の看破の回答)。core に真実がある事実 (solve・ヒント・attempt・やり直し) を写さない。
    flag と提出値を置かない。**作るのは最初の利用者の PR (P28-5)。** P28-1・P28-2 の表示はすべて派生で、永続を要らない。
  - admin reset: core の reset が成功した後で quest.db を閉じ、`-wal`・`-shm` を本体より先に消してから本体を消して作り直す (残った WAL が新しい本体に再生されうる)。
    削除に失敗したら旧ファイルを開き直さず、Quest の永続を無効にする。Quest 側が失敗しても応答は 200 のままで、`quest` に結果 (`reset` | `unavailable`) を添える
    (additive。spec はその PR で足す)。quest.db の行は (user, 問) の upsert にし、件数を user 数 × 問の数で有界にする (同じ PVC を使い切ると core の書き込みが失敗する)。
  - 寿命: 交戦ログは in-memory の 300 秒で再起動で消える (core の既存の性質)。QuestBook は派生なので core と同じ。quest.db はイベント 1 回分
    (admin reset と teardown で消える)。バックアップの対象にしない。
- **D7 印・称号は core の記録から導き、Quest は記録しない** (REFACTORING §3 の必須項目への回答)。
  - Lv・とくぎ・称号「ノーヒント」 = solved と hint_views。図鑑の発火印 (rule r) = r を expected に持つ課題 (trigger、または積極証明つきの evade) を
    solve した。証明の記録 (`expected_rule_fire`) は読まない (ADR-0032 で attempt スコープになり、attempt の外では見えない: `0032:67-69`)。
  - 突破印 (rule r)・称号「ボス突破」 = r を forbidden に持つ evade `c` を **`GatePassed(u, c)`** で solve した。**`GatePassed(u, c)` := (u, c) の solve の記録が 0 でない
    epoch を持つ** (VP 裁定 2026-10-12)。solve の epoch は、ADR-0032 の gate (active な attempt の確認を含む: `0032` D5) を通った evade の solve だけが、store の同じ臨界
    区間で active な attempt と照合して書く (食い違えば 0)。trigger の solve、S3b-2 より前の solve (S3b-1 からの間に開始の記録があっても)、退避 (i') の回の solve は 0 =
    印なし。**gate を強制していない solve には印を付けない。** 開始の記録 (`evade_attempt`) からは判定しない (C6: 05 を開始すると 03 の印が消える)。判定は core 側
    (store・scoring) の 1 関数で、合成層が bool で渡す。
  - 称号「reset なし突破」 = `GatePassed`、かつ (u, c) の開始が 1 回だけ (やり直しと、切り替えて戻ることを、どちらも新しい開始と数える。`already_active` は数えない)。
  - **前提 = ADR-0032 への改訂 2 つ** (ADR-0032 は Proposed。どちらも core の migration なので Class-2):
    - (a) S3a の migration で `solved` に `epoch INTEGER NOT NULL DEFAULT 0` を足し (書き込みは 0 のまま)、S3b-2 で上の規律で書く。VP 裁定で採る定義。**入るまで
      突破印と「ボス突破」を出さない。**
    - (b) S3a に append-only の表 (epoch, user, challenge, started_at, 操作者の種別 = 本人 | 運営) を足し、開始・切り替え・やり直しと同じトランザクションで書く
      (ADR-0032 D11 の監査は stdout だけで Pod の作り直しで消えるが、これは DB に残り、Signposts 2〜4 も DB から測れる)。admin reset はこの表も消す
      (`TestAdminReset_IsAtomic` の対象に入れる)。Quest に渡すのは (u, c) ごとの開始の件数だけで、epoch の値を出さない (DB 全体の連番なので、値から他の参加者の開始数が
      読める)。採否は CEO 判断 (security は条件つきで可)。**入るまで「reset なし突破」を出さない。**
  - この形では §3 の「記録開始時刻」と「書き込み失敗時の扱い」が要らない: epoch は solve の記録そのものにあり、記録の無い gate 通過は存在できない (fail-closed が構造で
    成り立つ)。§8 の「退避 (i') の回は inScope のまま」は採らない (時刻の比較で印を出す経路を作らない。受け入れ条件 14 = ADR-0032 より前の solve には出さない、と整合)。
- **D8 HTTP 面 (REFACTORING §2 の確認)。** `GET /api/users/{user}/quest` は self-or-admin (I8)、route table + spec + `x-ctf-*` (I14)、response の key 集合の
  検査 (ADR-0009)。ingress は既存の `/api/users/` Prefix で足りる (I15。変更なし)。エラーは `{"error": 定数}` の 1 形で `err.Error()` を出さない。
  MissionDetail の additive は `forbiddenRules`・`battleLog`・`alert`・`sights`・`encounter` の 5 つ。`relation`・`alert`・`role` は open string で、未知値の
  扱いを spec に書く。看破 (P28-5) の route は今の段階で `x-ctf-authz: self-or-admin` (認証ヘッダー必須。`self-or-admin-write` は
  ヘッダーの無い要求を claimed identity として通す: `api.go:933-939`)・`x-ctf-collector-forward: false`・origin-guard・identity キーの rate-limit に固定する。
- **D9 観測と運用。** gauge `quest_enabled` (0 / 1)、counter `quest_content_discarded_total{kind}` (kind は少なくとも `decode` と `ngram` を分ける: ADR-0030 D4) と
  `quest_errors_total{op}` (user を label にしない。出すのは合成層: D3)。log は破棄した file と entry の id だけを出し、文面を出さない。sre の preflight と verify は
  `quest_enabled == 1` を warn で見る (no-go にしない) が、`kind="ngram"` の破棄が 1 件以上なら no-go 相当の信号として扱う (未 solve の解法を運ぶ文か、守る文の欠けた
  tree が image に入っている)。kill switch と切り替えの空白 (D3) を runbook に載せる (platform の文書。sre)。
- **D10 移行と rollback。** P28-1・P28-2 はどちらの DB にも schema を足さないので、前の image に戻すだけで戻る。quest.db (P28-5 以降) を前の image で
  開くと「DB が新しい」で Quest の永続が無効になるだけで、core は動く (core の DB は ADR-0032 の migration の後は前の image で開けない: `0032:176`)。
  D7 の改訂は ADR-0032 の migration に入るので、ADR-0032 の切り戻しの規律に従う。

### I17 (提案。未昇格)

> **I17 (採点非干渉)**: (a) `internal/store`・`internal/scoreboard/{scoring,ingest,detect}` の module 内 import 閉包は `internal/quest` (配下を含む) と `internal/board` を
> 含まない。`internal/quest` (配下を含む) の閉包は、`internal/quest` 配下・`internal/hintleak`・`internal/sourcehygiene` の外を含まない。(b) Quest の状態にかかわらず、同じ core の状態に対する
> `GET /api/state` の `leaderboard` と `GET /api/users/{user}/me` の `rank`・`score` は byte で一致し、P28 の前に固定した期待値と一致する。(c) Quest を nil にしても、常に
> error・panic・encode に失敗する値の返却・入力の書き換えをする実装に替えても、`scoreboard.Handler.Routes()` の全 route の status・Content-Type・JSON の body と Sweep の
> 結果は変わらない。Quest を有効にしても、Quest の面 (D8) の外は変わらない。例外・除外リストを持たない。

- 機械強制は V1〜V3 (すべて `make test` = required check)。**昇格は V1〜V3 が landing する PR (`internal/quest` を作る P28-1 の software の PR。V4・V5 も同じ PR) と
  同じ PR で行う** (`docs/adr/README.md` の規律)。先に表へ載せない。
- I17 は「Quest が採点を変えない」とだけ主張し、「Quest の文がヒントを漏らさない」は主張しない (ADR-0030 の領分。表題に混ぜない)。

**architect の判定 (同意権)**: I17 の新設は **yes, if** — (i) V1〜V3 と同じ PR で表に載せる (ii) 故意違反で赤になることをテストとして恒久化する (PR 本文に貼るだけに
しない) (iii) D7 の改訂 (a) が入るまで突破印と「ボス突破」を、(b) が入るまで「reset なし突破」を出さない実装にする (iv) V2・V3 を `-race` で回す経路を
同じ PR で足す。

## Consequences

- **諦めたもの**: Quest が自分の判断で判定を足すこと (core の事実が要る判定は、core 側の機能として提案する経路を通る)。quest が catalog の型を直接使うこと (D2 の
  入力型への詰め替えが要る)。突破印と称号を P28-2 の初日から出すこと (D7 の改訂が入るまで出ない)。退避 (i') の回の印。独立 XP (CEO 判断 2)。
- **新たに守る不変条件**: I17 (提案)。既存の board の境界テスト (`board_boundary_test.go`) は残し、I17 (a) が逆向きを足す。
- **他 ADR への影響**: ADR-0032 に改訂 2 つを提案する (D7)。ADR-0031 の E2E は、子の env の allowlist に `QUEST_ENABLED=true` を足し、起動した実バイナリで
  `quest_enabled` = 1 を assert する (未設定 = 無効なので、足さないと Quest の無い状態だけを確かめる)。ADR-0028 Signpost 2′ の処方 (境界を import 閉包で点検する) は V1 を使う。
- **REFACTORING との差** (VP へ報告): §3 の `retreats` と記録開始時刻を D7 で置き換えた。§3 の発火印の「または `expected_rule_fire` に行がある」を外した (証明の rule の印が
  付くのは発火の時点ではなく solve の時点になる: 受け入れ条件 14 に影響、4 には影響しない。product-engineer の確認が要る)。§8 の「退避 (i') の回は inScope のまま」を
  外した。quest.db を作る時期を P28-5 に移した (受け入れ条件 2 の quest.db の部分も P28-5 に移る)。I17 (a) を許可リストにし detect を足し、(b) に me の `rank`・`score` と
  P28 前の期待値を、(c) に全 route と障害の型を足した。§2 の看破の認可を self-or-admin に固定した (§2 は selfOrAdminWrite も再利用の候補にしていた)。称号名
  「reset なし」と「切り替えも新しい開始と数える」のずれは product-engineer の確認が要る (受け入れ条件 12・14・15)。
- **runbook**: kill switch (未設定は無効。chart は `true`)・切り替えは Pod の作り直しで ingest が止まること・`quest_enabled`・`kind="ngram"` の破棄・admin reset の応答の
  `quest` (platform の文書、sre)。
- **残余**: (1) Quest の CPU とメモリは core と同じプロセスにある (Signpost 2) (2) recover が止めるのは panic だけ。fatal error (C7) はプロセスを落とし、無限ループや
  block は journey の応答を止める (D2 の形と V1 の AST・V2 / V3 の `-race` で起こしにくくする。quest は request の中で I/O をせず、P28-5 の quest.db は QuestBook と看破の
  経路だけで使う) (3) 交戦ログは再起動で消える (既存の性質で、Quest が増やすものではない)。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・2 は scoreboard の metric と `scoreboard_http_request_duration_seconds`、3・4 は PR と ADR の記録から測る。

1. イベント中に `quest_errors_total` が 0 を超える、または journey・me の 5xx が Quest に起因する例が 1 件 → 計算を request の外 (起動時と solve の変化時の
   事前計算) に移す。Quest に起因するプロセスの停止 (fatal error) が 1 件 → kill switch で止め、Option 3 を再検討する。
2. journey の p99 が P28-1 の前のイベントより 50ms 以上悪化する、または QuestBook の p95 が 200ms を超えるか 32KB を超える (REFACTORING §2) → Quest の
   projection を別の poll か cache に分ける。2 回続き D3 で直らなければ Option 3 を再検討する (image の追加は CEO)。
3. Quest の要件が ingest の経路か core の DB への書き込みを求める (例: 交戦ログの永続の要求が 2 回: REFACTORING §3) → 例外で通さず、core 側の機能
   として ADR を書く。
4. D7 の改訂 (a) が P28-2 の software の merge までに ADR-0032 に入らない、または (b) が不採用 → 突破印を P28-2 から外すか、「reset なし突破」を外すか quest.db に記録して
   残余を明記する設計を新 ADR で比べる (product-engineer の判断を添える)。

## Verification

すべて**未実装**。V2 (i) は P28-1 より前の qa の PR、V1〜V5 は P28-1 の software の PR、V6 は P28-2、V7 は D7 の改訂が入る PR、V8 は P28-5 の PR で満たす。
metric はプロセスで共有されるので、counter は前後の差分で assert する。故意違反は PR 本文に貼るだけでなくテストとして残す。V2・V3 は `-race` でも回す
(`make test` の経路は今 `go test ./... -count=1` だけ: `Dockerfile.test:58`。software の PR で足し、alpine の base で `-race` が動くことを実測する。未確認)。

- **V1 (I17 (a))**: `internal/apispec/quest_boundary_test.go`。既存の `transitiveModuleImports` (`internal/apispec/dependency_boundary_test.go:72-90`) を使う。
  - `TestCoreClosure_ExcludesQuestAndBoard`: 出発点 (store・scoring・ingest・detect) ごとに、ディレクトリがあり非 test の .go が 1 本以上あることを先に確かめる (C2 の
    葉の扱いで黙って緑にしない)。
  - `TestQuestClosure_WithinAllowlist`: `internal/quest` 配下をディレクトリで歩いて列挙し (`testdata` と、`_`・`.` で始まるディレクトリは除く。build tag は無視して多めに
    拾う)、0 件は fail。各 package の閉包が D1 の許可リストの外を含まない。許可リストの各葉が実際に閉包に入っていること (`internal/sourcehygiene` ∈ hintleak の閉包。dead な許可を残さない) と、葉 2 つの公開 package レベル var が error 型だけであること (go/ast + 型情報) も確かめる。
  - `TestQuest_NoGoroutinesNoPackageState`: `internal/quest` の非 test の .go に、`go` 文、名前が `AfterFunc`・`Go` の selector の呼び出し (`time.AfterFunc`・
    `sync.WaitGroup.Go`)、package レベルの var (型が `error` のものと `_` を除く。型情報で判定) が無い (go/ast。床であって完全ではない)。
  - 故意違反: t.TempDir() の 2 段の鎖 (core → fixture → quest、quest → fixture → store、quest → catalog、quest → hintleak の写し → sourcehygiene の写し → catalog)、出発点のディレクトリを消した tree、`go` 文か package レベルの
    map の var を足したファイルが、それぞれ赤になる (`:163-181` と同じ形)。
- **V2 (I17 (b))**:
  - (i) **P28 前の期待値**: P28-1 より前に main で入れる `TestLeaderboard_Golden_PreP28` (qa)。期待値はリテラルで持つ (ファイルの golden と再生成の仕組みは使わない。
    ADR-0032 の ⑨ `TestLeaderboard_CanonicalOrder_Unchanged` と同じ方式で、先に入った方を共有してよい)。手順は HTTP (発火・submit・ヒントの開封) で、時計 (`WithNow`) は
    テストが手順の間で進める (呼び出しの回数に依存させない)。表示される user は 3 人以上で、Score が同点で `earliest` で割れる組・ヒントの減点・solve 0 件・HIDDEN_USERS の
    user を含む。Quest の PR はこの期待値を変えない。
  - (ii) `TestLeaderboard_ByteIdenticalRegardlessOfQuest`: (i) と同じ手順を D4 の 6 状態 (P28-5 の PR で「quest.db の位置にディレクトリ」を足す) の handler に流し、
    `leaderboard` の JSON と me の `rank`・`score` を状態どうしと (i) の期待値の両方と byte で比べる。手順は採点の操作 (発火・submit・ヒントの開封) の前ごとに全課題の
    journey と QuestBook を呼び (Quest のコードを採点の間に走らせる)、同じ手順を journey と QuestBook を並行に呼び続けながら行う版を `-race` で回す。「有効」は
    本番と同じ loader で読んだ合成 content で作り、`encounter` が null でないことと QuestBook が 200 であることを assert する (P28-1 の software の時点では実 content が
    無いので、これが無いと緑でも何も確かめていない)。
  - 比較器の unit テスト (Quest の値を `lbEntry` に混ぜた変更・同点の並びを変えた変更で赤) を置く。
- **V3 (I17 (c))**: `TestQuestFailing_AllRoutesUnchanged`。
  - route ごとの要求の作り方 (path の値・body・認証ヘッダ・Origin) を表に持ち、`Handler.Routes()` にあって表に無い route があれば fail (除外を作らない。
    `TestOriginGuard_AllProtectedRoutesEnforced` と同じく `Routes()` から導くので、ADR-0032 の `…/attempt` も入った時点で対象になる)。全 route を
    1 回以上含む同じ手順と Sweep の 1 回を、時計を固定した handler に流し、応答の列を比べる。JSON の応答は body を JSON として比べ、それ以外 (HTML・`/metrics`・静的
    アセット) は status と Content-Type を比べる (body は CSP の nonce と計測値で毎回変わる)。
  - 先に nil を 2 回流して一致することを確かめる (比較器が不安定なら fail)。nil と、常に error・常に panic・encode に失敗する値を返す・**受け取った slice と map を
    すべて書き換えてから正常に返す**、の 4 実装が一致する (Quest のキーも無効の形で一致する)。nil と「有効」は、Quest の面 (`sights`・`encounter`・QuestBook) の外が一致する。
  - Quest を入れる PR では、既存のテストの変更を response の key 集合・件数と route 数の pin (ADR-0005 / 0009) に限る (既存のテストは Quest を配線しない = nil の場合)。
- **V4 起動 (D3)**: seam `questFromEnv` の表テスト — `QUEST_ENABLED` の {未設定, 空文字, `true`, `false`, `TRUE`, `1`, 不正値} で、有効・無効と log の level が D3 どおり。
  壊した content (P28-5 以降は開けない quest.db も) で、seam が無効か一部を破棄した Quest を返し (panic も exit もしない)、`quest_enabled` と破棄の counter が D3 どおりに
  動き、その Quest を配線した handler で trigger の solve が通る。ソースの pin (`cmd/scoreboard/main_test.go:221-278` と同じ形): `questFromEnv(` の呼び出しが 1 回で、
  そこから `scoreboard.NewHandler(` までに `os.Exit` が無い。
- **V5 入力型 (D2)**: quest の exported な関数・メソッドの引数の型を型情報で再帰的に歩き (列挙を手で持たない)、D2 が許す kind と型の外 (pointer・interface・func・chan・
  他 package の型) と、名前に flag を含むフィールド (大文字小文字を問わない) が 0。故意違反: `catalog.Catalog` を引数に取る関数を足した複製で赤。API の出力に `FALCO{` が
  無いことは ADR-0030 V3 で確かめる。
- **V6 (D7 の fail-closed。P28-2)**: 改訂 (a) が入る前は、evade を solve しても突破印・「ボス突破」・「reset なし突破」が QuestBook に出ない。発火印は solved だけから
  出る (`expected_rule_fire` に行があっても solve の前は出ない)。
- **V7 (改訂が入ったら。実 store で、live と再起動の後の両方)**: (a) c を solve → d を開始 → c の印が残る / S3b-2 より前に記録された solve は、開始の記録があっても印が
  付かない / trigger の solve に突破印が付かない / admin reset で消える。(b) 最初の attempt で solve → 付与 / やり直した後の solve → 付与しない / 切り替えて戻った後の
  solve → 付与しない / admin reset の後は数え直す。記録の行が操作者の種別を持ち、Quest の入力に epoch の値が出ない (件数だけ。V5 の型で確かめる)。admin reset は
  この表も 1 トランザクションで消す (`TestAdminReset_IsAtomic`)。
- **V8 quest.db (P28-5 の DoD)**: quest.db が binary より新しい・中身が壊れている・開けない (位置にディレクトリ) のそれぞれで、起動が続き、V3 の core の応答が変わらず、
  admin reset は 200 と `quest: unavailable` を返し、counter が増える。admin reset は `-wal`・`-shm` を本体より先に消し、削除に失敗したら旧ファイルを開き直さない
  (削除の順と失敗を差し替えられる形で確かめる)。(user, 問) の upsert で、行数が user 数 × 問の数を超えない。
- **機械で守れないもの**: Quest の PR が `points.go` を変えないこと (PR の review。結果は V2 (i) が見る)。quest の無限ループと block (残余 2)。

## Advice

- architect (2026-10-04、REFACTORING P28 §2〜§4・§8・§10) と、その R2 (qa-engineer)・R4 (architect の別インスタンス) のレビューが出発点。本 ADR は
  D2 (core の projection と Quest の分け方)・D4 の比較対象・D7 を改めた。
- ADR-0032 の Consequences (2026-10-05、product-engineer の条件つき合意) の拘束を D7 で受けた。
- VP (2026-10-10 / 12、発注): 決めることの一覧と ADR の型。
- **qa-engineer R2 (2026-10-12、REQUEST CHANGES = HIGH 5・MEDIUM 5・LOW 1。方向には同意)**。VP が全件を採用し、本版に反映した: 検査を全 route と値の比較にする
  (D5・V3)・入力型と出力の JSON 化 (D2・D3・V5)・P28 前の期待値と「有効」の非空 (V2)・import の許可リストと出発点の非空と goroutine の床 (D1・D2・V1)・seam と env の表
  (D3・V4)・印の判定を開始の記録から solve の epoch に移す (D7・V7)・quest.db の障害 (V8)・counter の差分と比較器の恒久テスト。qa の提案と違えた点: quest の許可リストから
  catalog も外した (C7 の参照を構造で持たせない)、os.Exit の pin は `questFromEnv(` から `NewHandler(` までの区間に限った (Serve の後の exit = `main.go:325` は Quest と無関係)、
  nil と失敗する実装の比較では Quest のキーも外さない (どちらも無効の形になる)。
- VP 裁定 (2026-10-12): `GatePassed` は solve の記録の epoch で判定し、gate を強制していない solve には印を付けない。開始の履歴の表 (D7 (b)) は CEO 判断として残す。
- **security-engineer R1 (2026-10-12、REQUEST CHANGES = HIGH 1・MEDIUM 5・LOW 4。BLOCKING なし)**。VP が全件を採用し、本版に反映した: slice・map と構築時の値の
  複製・書き換えてから正常に返す fake・採点の間に Quest を呼ぶ手順と `-race` (D2・V2・V3)・request をまたぐ可変状態の禁止と package レベルの var の AST 検査 (D2・V1)・
  route の導出 (V3)・`QUEST_ENABLED` の未設定は無効と切り替えの空白 (D3)・admin reset の削除の順と quest.db の有界 (D6・V8)・看破の認可の固定 (D8)・開始の記録の操作者の
  種別と件数だけの受け渡し (D7 (b))・`ngram` の破棄を preflight の信号にする (D9)。security の許可リスト案 (catalog・hintleak) は、qa R2 の「catalog の型を入力に持たない」と
  合わせて hintleak だけに狭めた (catalog 由来の値は D2 の入力型で渡すので、catalog を import する用途が残らない)。
