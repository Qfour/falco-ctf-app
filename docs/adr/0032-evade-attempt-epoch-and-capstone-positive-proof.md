# ADR-0032: evade の attempt を明示的な開始操作 (epoch) にし、solve を「その attempt の中で記録された証跡」だけで判定する — 10-final-exfil に attempt スコープの積極証明を入れる

- Status: **Proposed** (Accepted 化は CEO merge 時。期限 = 次回イベントの前、CEO 決定 2026-10-05。rev2 = 2026-10-10: S1 の実装と R4 を反映。追加は末尾の「Decision の追加 (rev2)」)
- Date / Deciders: 2026-10-05 / CEO (2026-10-04 錨は明示的な attempt。2026-10-05 10 の積極証明は入れる方向で調査を先に・期限の前倒し・残余 1 / 2 の受容・05 も揃える。
  Class-2 の merge) + VP (承認、レビュー指摘の全件採用) + architect (起草・同意権) + content-engineer (実現性調査) + product-engineer (P28 の印・称号の合意) +
  security-engineer・qa-engineer (独立レビュー 2 巡、2026-10-05。本版に反映済み) / rev2 (2026-10-10): architect (起草・D12 の同意権) + VP (発注)
- 関連: ADR-0003 (Decision を supersede。I11 の起源)、ADR-0004・0008・0027 (限定 supersede。「supersede の範囲」の表)、ADR-0017 (custom rule の先例)、ADR-0020 (migration)、
  ADR-0025 (10 の flag の置き場)、ADR-0033 (flags ファイルの完全性。Accepted)、Issue #121、workspace `REFACTORING.md` P28 architect §8 / §10、ADR-0031 (Proposed、app#321)、platform#207・#208・#209
- 行番号は e74d871 (rev2 で足した参照は c5e0761。platform は S1 ブランチの 3aaf11f)。`0003:N` などは `docs/adr/` の各 ADR の行番号。**公開境界**: flag 実値・未公開の回避条件・rule の condition は書かない (condition の正典は
  private の platform `docs/falco-detection-conditions.md`)。弱点は公開済みの範囲で、手順ではなく性質として書く

## Context

- **C1 現行の錨は進行順から導いた `current`。** ADR-0003 は Option 2 を採り、taint を「その課題が `current` (order の先頭の未 solve) のときだけ」書く (`0003:162-167`、
  `internal/scoreboard/scoring/scoring.go:283-293,427-441`)。有効条件は「進行が線形かつ `current` が単一」(`0003:149`)。receipt (`exfil`) と証明 (`expected_rule_fire`) は
  attempt を知らず、reset は行の削除で表している (`internal/store/store.go:825-857`)。
- **C2 公開済みの弱点。** W1: `current` になる前の発火は数えない (`0003:217-219`)。W2: 先行の evade を未 solve のまま置くと `current` が進まず、10 の禁止 7 本は 10 を taint しない。
  `Sweep` は `current` を見ないので、receipt があれば auto-solve する (`0003:221-244`、`scoring.go:84-136,886-910`)。ADR-0003 は「capstone gate が実効的に存在する」と読める
  記述を禁じ (`0003:461-464`)、閉じるのは attempt ごとの積極証明だけだとした (`0003:99-100,243-244`)。
- **C3 qa-engineer の実行 (2026-10-04 / 05、実 catalog + nimbusbreach-full、未コミットの再現テスト)。** current = 03 でも current = 05 (2h 版の形) でも、10 の禁止 7 本が発火した後に receipt が届くと
  Sweeper の 1 回で 10 が solve された (10 が current のときは taint になり solve しない)。非 current の evade は禁止ルールが発火しても dirty にならず、後で current になっても「クリーン」のままだった。
- **C4 順序外は標準の進め方になる。** 2h 版のハンズオンは 01・02・03・04・06・08 で、05・07 を飛ばす (`scenarios/nimbusbreach-full/playbook-2h.md:13,47`)。ADR-0027 がどの課題でも
  ヒントを開けるようにし、Option 1 の閾値 (`0003:133-134`) への到達と Signpost 1・5 の発火を記録した (`0027:80-90`)。Signpost 2 (evade が積極証明を得る、`0003:527-528`) は
  05 で発火して「実害なし」と判定されたが (`0008:348-368`)、10 に証明を足すと再び発火する。Signpost 4 は未計測である。
- **C5 10 の gate は技法の使用を証明しない (content-engineer 2026-10-05)。** 現行の gate は「禁止 7 本の不発火」+「正しい flag の receipt」(`challenges/10-final-exfil/falco-rule.yaml:3-10,17`)。
  flag はイベントごと・課題ごとに 1 つの静的な値で (`internal/catalog/flags.go:44-57`、契約表 Flags 行、ADR-0033)、receipt はどの attempt にも紐づかない。したがって epoch を入れても
  「値がその attempt の中で得られた」ことは保証できない。保証できるのは「開始後に、読む段の技法が使われた」という記録だけである。
- **C6 制約。** identity が証明されるのはブラウザ経路 (`X-Auth-Request-Email`) と Falco の発火 (namespace から導く: `internal/scoreboard/ingest/ingest.go:251`) だけで、collector 経由の
  submit / exfil は claimed identity である (`internal/scoreboard/api/api.go:505-510,541-546`、`internal/collector/collector.go:156-196`)。I1・I8・I14・I15 と ADR-0020 を守る。
- **C7 CEO 決定 (再議論しない)。** 2026-10-04: 錨は「エンカウント開始を明示的な attempt にする」(ADR-0003 の Option 1)。2026-10-05: 10 の積極証明は入れる (調査の結論は「実現可能・推奨あり」)。期限は
  次回イベントの前 (`0027:95-98`)。残余 1・2 は、03 に証明を足せるかの調査の結果が出るまで受容する。05 の証明も attempt スコープに揃える。

## Options

- **錨 (i) 明示的な attempt epoch【CEO 決定・推奨】** — 開始操作で attempt を始め、taint・receipt・証明をその epoch に属するものだけ数える。コスト: 表 2 + 列 3 の migration、route 1、
  portal の開始導線、参加者に「開始」を教える認知コスト。リスク: 開始を忘れた操作は数えられない (最頻の問い合わせになりうる)。積極証明の無い evade では gate が保証する範囲が
  狭い (Consequences)。可逆性: migration 適用後の DB は旧イメージで開けない (`internal/store/migrations.go:147-171`)。閾値: 順序外の進行が 1 つでも標準にある時点 (到達済み)。
- **錨 (i') `current` のまま、evade の solve を先行課題がすべて solve 済みのときだけ許し、`current` になる前の receipt を数えない** — schema 変更なし。コスト: `evaluateClean` と `Sweep` が
  `current` の消費者になり (`0003:780-784` が単独では却下した追加)、solve 時刻の比較が gate に入る。リスク: 2h 版では 05・07・09 を解かないと 10 を solve できない。値の由来は
  (i) と同じく保証できない。可逆。閾値: (i) が期限に間に合わない回の退避。
- **錨 現状維持** — コストなし。W2 が標準の進め方の中に残り、範囲外の solve が Score に乗り続け、`0003:461-464` の禁止が続く。
- **証明 A 読む段の custom rule 1 本【推奨】** — 10 の flag ファイル (ADR-0025) を読む段の技法に専用の rule を足し、`requireExpectedRuleFire` で要求する。コスト: allowlist 1 行 +
  platform customRules 1 本 + 両リポ同時 PR (ADR-0017 と同型)。gate と `Sweep` は既にこの条件を通る (`scoring.go:677-679`)。リスク: 証明の発火と届いた値は結び付かない。
  可逆 (catalog の 1 行)。閾値: epoch とセットのときだけ「開始後に実演された」と言える。
- **証明 B 持ち出す段の rule** — 不採用。「騒がしい道具を使わなかった」という負の性質は rule で証明できず、submit も collector を通るのでノイズが大きい。持ち出す段は禁止ルールに任せる。
- **証明 C 既存の expected rule の流用** — 不採用。対象ファイルが違い、記録が attempt に依存しないので効果が無い。
- **証明 D receipt 側の nonce** — 不採用 (D10)。collector は body を素通しするので無改修で通る (`collector.go:227-242`) が、実体は epoch の実装形の 1 つである。

## Decision

**錨は (i)、証明は A。証明の記録は全 evade で attempt スコープにする (05 も揃える)。nonce は採らない。** 理由: 「attempt = 参加者が明示的に始めた 1 回の交戦」を証跡の唯一の単位にすれば、
順序・`current`・時間のどれにも依存せずに gate を定義でき、不変条件を例外なしで書ける。

- **D1 attempt は参加者ごとに高々 1 つ。epoch は DB 全体の連番。** 新表 `evade_attempt (user PRIMARY KEY, challenge, epoch, started_at)`。主キーが user なので「同時に active な attempt は 1 つ」は
  schema の事実になる。`active(u)` := 行があり、その `challenge` が catalog の evade で未 solve (solve は attempt を終える。追加の書き込みは要らない)。epoch は 1 行の採番表
  `attempt_epoch_seq` から払い出す DB 全体で一意の連番で、**admin の `Reset` でも巻き戻さない** (採番表は `Reset` の対象外)。したがって epoch は切り替え・やり直し・admin reset を
  またいで再利用されない。**開始・切り替え・やり直しは、採番表の更新と `evade_attempt` の書き込みを 1 トランザクションで行い、in-memory は commit の後に更新する。** 課題ごとに独立した
  attempt は採らない: soundness は同等だが、放置された attempt が別の作業で taint され続け、「active = いま取り組んでいる相手」が崩れる (ADR-0003 Signpost 4 が問題にした
  作業単位とのずれ)。順序外に複数の evade を進める人は切り替えのたびに開始し直す。ヒントの開封 (ADR-0027) は attempt と無関係である。
- **D2 証跡 3 表に epoch を持たせる。** `exfil`・`evade_dirty`・`expected_rule_fire` に `epoch INTEGER NOT NULL DEFAULT 0` を足す (`PRAGMA user_version` = 2 の additive な migration。
  `migrations.go:43-47,62-125`、ADR-0020。`docs/db-schema.md:318-325` の版ラベル v2 / v2.1 とは別の番号なので、履歴表には user_version を併記して行を足す)。有効な epoch は 1 から。
  **採点を切り替える PR (S3b-2) で次の規律を入れる。それより前 (S3a) は列と表を足すだけで、既存の証跡の書き込み (epoch 0) と読み込み (全行) を変えない** (先に入れると、開始ルートが
  無いので taint が記録されないか、再起動で taint が消える)。
  (a) 証跡の書き込みメソッドは epoch を引数に取らない。store が**同じ臨界区間で** active な attempt を解決して epoch を押し、その課題が active でなければ行を書かずに「記録しなかった」を
  返す。切り替え後に epoch 0 の行を書く経路は無い。Grader は active な課題を読んで catalog と照合するが、epoch は扱わない
  (b) 3 表とも epoch を更新する upsert にする。`evade_dirty`・`expected_rule_fire` の `INSERT OR IGNORE` (`store.go:696,756`) と `exfil` の `DO UPDATE SET flag, at` (`store.go:515-518`) は、
  前の epoch の行が残っていると新しい epoch の記録にならない (c) in-memory の各行に epoch を持たせ、**store の読み出しメソッドの中で**現 attempt の (challenge, epoch) と照合する
  (gate のスナップショット、`PendingExfilSolves` = `store.go:571-594`、投影用の 3 つ = `api.go:2118,2127,2196`)。照合を呼び手に任せず、切り替え時の in-memory の掃除を正しさの根拠に
  しない。gate 用の個別の読み出し (`DirtyRules`・`HasExpectedRuleFire`・`HasExfil`) は `ScoreStore` の port から外し、スナップショット 1 つにする
  (d) スナップショットは、solved・attempt の (challenge, epoch)・3 表を 1 つの臨界区間で読む (e) epoch 0 の行は数えない。既存の taint も数えないが、開始しない限り solve しないので
  緩まない (f) admin の `Reset` (`store.go:899-933`) を 1 トランザクションにし、**同じトランザクションで `evade_attempt` も消す (採番表だけを残す)**。in-memory は commit の後に消す。
  現行は DELETE を順に実行するので、途中で失敗すると「attempt は active のまま taint だけ消えた」状態が残りうる。また `evade_attempt` を残して solved だけを消すと、solve 済みだった
  最後の attempt が開始操作なしで active に戻る (S3a で入れる) (g) 同じ epoch の中で ExpectedFlag と一致した receipt は、一致しない値で置き換えない (判定は 1 つの臨界区間)。
- **D3 開始ルート `POST /api/users/{user}/challenges/{cid}/attempt`。** `x-ctf-audience: participant` / **`x-ctf-authz: self-or-admin`** (認証ヘッダー必須。無ければ 403: `api.go:888-905`。
  `self-or-admin-write` はヘッダーの無い要求を claimed identity として通す (`api.go:933-939`) ので使わない。reset-dirty も同じ gate に揃える) / `x-ctf-origin-guard: true` /
  `x-ctf-collector-forward: false` (claimed identity で他人の attempt を切り替えられる。reset-dirty と同じ理由: `api.go:580-590`) / `x-ctf-rate-limit`: identity キーの bucket (reset-dirty も
  per-IP の共有 bucket からこちらへ移す。空キーを返さない board の形: `api.go:754-771`。会場 NAT 下で他人のヒント開封に開始を止めさせない: `0027:110-112`)。ingress は `/api/users/` Prefix で
  到達済み (`charts/scoreboard/templates/ingress-journey.yaml:183-184`)。**運営 (ADMIN_EMAILS) が代わりに開始・切り替え・やり直しできる例外は残す** (I8 と同じ例外)。理由: 運営は既に
  全消去 (`POST /api/admin/reset`) の権限を持ち、禁じても守れるものが増えない / taint と証明は Falco 由来で、運営が開始しても作れない / 既存の gate をそのまま使え、authz の語彙を
  増やさない。操作者は監査ログに残す (D11)。body は任意の `{"abandon": "<cid>"}` (比較にだけ使う)。**状態の衝突は 4xx にせず、200 + `result` で返す**: 応答
  `AttemptResult {user, cid, result, active, abandoned}`。`result` は open string (未知値は「何も変わっていない」として journey を読み直す)、`active` は呼び出し後に active な課題 (無ければ
  空文字)、`abandoned` は今回終わらせた課題 (`switched` のときだけ非空)。4xx の判定は既存の reset-dirty と同じ順で、下の表より先に行う: 400 (user の書式) → 403 (origin・認証なし・
  他人) → 404 (未知の課題) → 400 (evade でない。solve 済みの trigger もここ) → 400 (body・`abandon` の書式)。429。500 は定数文言。

  | `cid` の状態 | 呼び出し前の active | `abandon` | `result` | 変わるもの |
  |---|---|---|---|---|
  | solve 済みの evade | 何でも | 何でも | `solved` | なし |
  | 未 solve の evade | 無い | 何でも (無視) | `started` | 新しい epoch |
  | 未 solve の evade | `cid` 自身 | 何でも (無視) | `already_active` | なし (**二重開始は冪等で、証跡は残る**) |
  | 未 solve の evade | 別の課題 X | X を名指し | `switched` (`abandoned` = X) | X の証跡が無効になり、新しい epoch |
  | 未 solve の evade | 別の課題 X | 無し、または X 以外 (`cid` 自身・active でない課題・未知の id を含む) | `conflict` (`active` = X) | なし (古い画面の誤操作で他の課題の証跡を消さない) |
- **D4 数えるのは active な attempt の間に記録されたものだけ。** `OnRuleFire(u, r)`: `a := active(u)`。`r` が `a.challenge` の `forbiddenRules` にあれば taint を、`requireExpectedRuleFire` の
  `expectedRules` にあれば証明を、epoch `a.epoch` で記録し、その後に trigger を評価する。**trigger の solve は attempt の外のまま** (`scoring.go:359-363,372-392`)。単一の公開入口は維持する
  (ADR-0003 A4)。「taint → trigger の順」は `current` が錨でなくなるので規範から外す。receipt は `active(u).challenge == cid` のときだけ数える。**exfil の応答は、対象 user の attempt の
  状態に関係なく一定にする** (status・キー・文言とも同じ。collector 経路は claimed identity なので、状態で応答を変えると他人の attempt の状態が読める)。数えられたかは self-scope の
  投影 (`exfilReceived`) で示す。**開始前の発火・証明・receipt は数えない。**
- **D5 gate は 1 箇所のまま (`evaluateClean`)。** gate 3 (flag 一致) の後: solve 済みなら `EvadeSolved{Newly: false}` (solved は終端) → `active(u).challenge != c` なら **`EvadeNotStarted`**
  (新設。宣言順 = gate 順の慣行に従い `EvadeWrongFlag` の次: `scoring.go:582-585`) → taint → 証明 → receipt → `MarkSolved`。`Sweep` と手動 submit は同じ関数を通るので判定は一致する
  (`scoring.go:642-647,900`)。submit の応答は 200 `{"correct": true, "started": false, "reason": …}` (`SubmitFlagVerdict` に `started` を additive、metrics の outcome に `not_started`)。
  `started` は gate 3 の後にだけ返るので、正しい flag を持つ者には他人の分も見える (既存の `evaded`・`proven` と同じ性質)。
- **D6 reset = 新しい epoch。** `reset-dirty` の path は変えない。その課題が active なら新しい epoch を払い出し (taint・receipt・証明が一括で無効になる)、active のまま続ける。active で
  なければ何もせず (200、冪等)、別の課題の attempt にも触れない。書き込みは D1 の 1 トランザクション (採番表と `evade_attempt`) だけで、証跡 3 表には触れないので、ADR-0003 F1 の
  「片方だけ消える」状態は構造上起きない。時間経過・再読込・再接続は reset 条件にせず、猶予窓も入れない (`0003:279-282`)。
- **D7 採点は order を消費しなくなる。** `Grader.WithOrder` / `currentMission` (`scoring.go:265-268,299-307`、`internal/scoreboard/server.go:220`) を撤去し、`CurrentMission` は journey の投影だけが使う。
  `status` (`solved | current | locked`) は案内であり、採点上の意味を持たない (ADR-0027 D2 と整合)。
- **D8 投影と P28-1 の UI 契約。** `Journey` に `attempt` (active な課題の id。無ければ空文字。null にしない — 既存の `current` は 3.0 の `nullable: true` で書かれており
  (`docs/openapi-scoreboard.yaml:2470-2472`)、3.1.0 の spec では踏襲しない)、`MissionDetail` に `alert` (open string。`idle` = この課題に active な attempt が無い / `clean` = active で禁止発火の
  記録なし / `spotted` = active で記録あり。未知値は `idle` として描く) を additive で足す (P28 architect §2 の `alert` の前倒し)。**段階**: `attempt` と `alert` は S3b-1 で入れ、その時点の
  `alert` は「active でなければ `idle`、active なら現行の `dirty` (全行) から `clean` / `spotted`」で算出する。`dirty`・`dirtyRules`・`exfilReceived`・`expectedRuleFired` を「active な attempt の」
  値に切り替えるのは S3b-2 (先に切り替えると、epoch 0 の行を数えないので投影が常に空になる)。portal は戦闘状態を `status` から推論せず `alert` / `attempt` だけを使い、`idle` の evade に
  「クリーン」を出さない。**portal が開始ルートと reset-dirty を呼ぶのは利用者のクリックからだけ** (閲覧・ポーリング・`?mission=` の解決では呼ばない。リンクを開いただけで証跡が無効に
  なる経路を作らないための security 上の性質)。切り替え (`abandon`) とやり直しは、「taint だけでなく receipt と証明も消える」と示した確認を経たクリックだけが送る (現行の確認文 =
  `internal/scoreboard/view/templates/portal.html:1793-1797` は taint と exfil しか書いていない)。`relation` は「その発火が attempt の taint / 証明として記録されたか」から導く。
- **D9 積極証明。** (a) **10**: 読む段の rule を `expectedRules` に置き `requireExpectedRuleFire: true` にする。rule 名は `challenges/custom-falco-rules.txt` に 1 行で、**condition を表さない名前**に
  する。condition は platform の `customRules` (設計と「どの読み方で成立 / 不成立か」は private 正典)。持ち出す段は証明の対象にしない。(b) **記録は attempt スコープ**: D4 のとおり
  active な attempt にだけ記録し、reset と切り替えで無効になる。(c) **05 も揃える** (CEO 2026-10-05): ADR-0008 は「reset 後に再証明させる利益は無い」とした (`0008:355-363`) が、錨が
  `current` だった時の判断である。開始が明示操作になると、証明が attempt の外で成立する限り、禁止ルールの gate は技法の実演を観測しないまま通過を許しうる。揃えれば全 evade で
  「1 回の attempt の中で技法が実演された」と同じ文で言え、課題ごとの指定 (`0008:442-445`) を持たずに済む。(d) **deploy は platform が先・app が後** (逆順は 10 が解けなくなる。
  05 と同じ softlock: 契約表 Falco custom rule 行)。(e) 実機の fire / no-fire が済むまで「検証済み」と書かない。(f) rule 名は他課題と共有しない。(g)〜(j) (同じ stand-up・Me pane・表示抜粋・container 名) は末尾の「Decision の追加 (rev2)」。
- **D10 nonce は採らない。** attempt への帰属は、サーバが受信時に押す epoch で足りる。nonce が加えるのは「receipt の送り主が portal を見られる本人である」ことの証明で、これは claimed
  identity の問題であり attempt の問題ではない。値が静的である限り、値の由来は nonce でも保証できず、参加者に手で写させる手順と exfil の body 契約の変更に見合わない。
  attempt ごとに値を変える案は、flag を 1 イベント 1 ファイルで 2 つの消費者に配る契約 (ADR-0033) と plant の経路 (ADR-0001 / I12) の作り直しになるので、本 ADR では扱わない (Signpost 3)。
- **D11 観測。** counter (label は challenge と種別だけ。user を label にしない): attempt の開始 / やり直し / 切り替え、数えなかった receipt、`SubmissionsTotal{outcome="not_started"}`。
  **監査ログ**: 開始・切り替え・やり直しごとに操作者 (認証ヘッダーの identity)・user・cid・種別・旧 epoch → 新 epoch・終わらせた課題を、数えなかった receipt ごとに user・cid を 1 行で出す
  (`dirty_reset` の行 = `api.go:1621` を置き換える)。`evade_attempt` は上書きされ履歴を持たないので、Signposts 2〜4 はこのログから測る。数えなかった receipt と `not_started` は
  claimed identity の入力で、誰でも水増しできる。集計は (user, cid) で重複を除く。

### I11 の新しい文言 (案。表の書き換えは採点を切り替える PR = S3b-2 と同じ PR で行い、それまで現行の行が有効)

> **I11**: evade 課題の solve は、明示的に開始された attempt の証跡だけで判定する。(a) attempt の開始とやり直し (`…/attempt`・`…/reset-dirty`) は、origin-guard と認証ヘッダー必須の
> self-or-admin を通った要求だけが行える (本人、または I8 と同じ例外の ADMIN_EMAILS。操作者は監査ログに残す)。collector はどちらも forward しない。参加者ごとに同時に active なのは
> 高々 1 つ。(b) 禁止ルールの taint・`requireExpectedRuleFire` の証明・`requireExfil` の receipt は、active な attempt の epoch で記録されたものだけを数える。attempt が active でない間の
> 記録と、epoch を持たない既存行は数えない。(c) active な attempt の無い evade は solve しない。`Sweep` と手動 submit は同じ `evaluateClean` を通る。(d) やり直しと別課題の開始は新しい
> epoch を始め、taint・証明・receipt を一括で無効にする。epoch は admin reset をまたいでも再利用しない。(e) 判定に経過時間を用いない (窓・猶予・期限・タイムアウトを導入しない)。
> (f) 全ての rule fire は単一の Grader 入口を通る。trigger の solve は attempt にも順序にも依存しない。

- **機械強制 (現行の 6 本 → 書き換え後)**: `TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules` → 維持 (交差は「双子の罠」の根拠として pin) + `TestAttempt_TwinTrap_StartBeforePredecessor_Taints` /
  `TestOnRuleFire_RealCatalog_AttemptScope_TwinMissionsStayClean` → 書き換えて維持 + `TestOnRuleFire_RealCatalog_WithoutStart_NoEvadeSolves` / `TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance`・
  `TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved` → 維持 + `TestAttempt_VerdictIgnoresClock` / `TestDirtyFlag_SurvivesStoreRestart` → 維持 + `TestAttempt_SurvivesStoreRestart` /
  `TestResetDirty_TransactionRollsBackOnPartialFailure` → `TestAttemptWrite_FailureLeavesStateIntact` + `TestAdminReset_IsAtomic` + `TestAdminReset_ClearsAttempt_KeepsSequence`。
- **追加**: (a) = `TestAttemptStart_NoAuthHeader_403`・`TestJourneyWriteGate_ResetDirty_NoHeader` (反転後)・`TestAuthz_SelfOrAdminGate_MissingHeaderDenied`・`TestAPISpec_V4_AttemptNeverForwarded`・
  `TestAPISpec_V4_ResetDirtyNeverForwarded`・`TestPortal_AttemptAndResetOnlyFromClickHandlers` / (b) = W2 の 2 本・`TestAttempt_ReceiptBeforeStart_NotCounted`・`TestAttempt_Proof_FiredBeforeStart_NotCounted`・
  `TestMigrate_UserVersion2_LegacyEvidenceRows_NeverCount`・`TestEvidence_ReDeliveredInNewEpoch_CountsAfterRestart` / (d) = `TestAttempt_SwitchAwayAndBack_OldEpochEvidenceNotCounted`・
  `TestStoreReads_OldEpochEvidenceNeverVisible`・`TestAttempt_EpochNeverReused`。汎用の `TestAuthz_AllDeclaredGatesEnforced` は不一致のヘッダーしか送らず、self-or-admin と
  self-or-admin-write を区別しない (`internal/scoreboard/authz_test.go:191,196`) ので、(a) の根拠にしない。
- 現行の行 (`.claude/rules/falco-ctf-app-conventions.md:33`) の「taint は先行 trigger の必須発火との交差を持つ場合にのみ生じ」は ADR-0003 A1 の規則と一致していない (交差は attempt スコープが
  要る理由であって、taint の条件ではない)。上の文言で置き換える。

### supersede の範囲 (既存 ADR の本文は書き換えない)

| ADR | 本 ADR が置き換えるもの | そのまま有効なもの |
|---|---|---|
| 0003 | Decision の Option 2 と A1 の錨・判定規則 (`:162-213`)、A2-1 / A2-2 の「行を消す」機構と F1 の削除順 (要件「reset 後の solve は新しい証跡を伴う」は残し、証明にも広げる)、I11 の候補文言 (`:475-480`)、Verification (a) の scoring 側・(c)・(e) の具体形、Signpost 1・2・4・5 (本 ADR が応答) | C1〜C6、A2-4 / A2-5、A3、A4 (単一入口と `RuleFireOutcome`)、A5、A6 (新しい錨で書き直す)、A8、Verification (b)・(d)、Signpost 3・6、`:461-464` の禁止 (解除条件は Consequences) |
| 0004 | C2 の事実 5 (`:53`。solve 済みの submit は gate 3 の後で solved を返す) と Signpost 2 の処方 (`:226-228`。「短絡が gate 3 より前に入ったら」と読み替える) | Decision (d′) と V1〜V7 の期待値 (手順の先頭に開始操作が加わる)、目的 (i)(ii)(iii)、前提の unit 2 本 (`:279-283`。改名・削除しない) |
| 0008 | Decision (3) の「attempt スコープを適用しない」(`:279-285`) と Decision (4) (`:348-368`)、Verification (b)(v) (`:508`) | Decision (1)(2)(5)、(3) の catalog field・gate・status・API 2 キー・type ガード・`ExpectedFireErr` の扱い、Verification (a)(c)(d)(e)、Signposts |
| 0027 | D6 の暫定規則「`status` による分岐でよい」(`:68-73`)。V7 は `alert` 基準に読み替える | D1〜D5、V1〜V6・V8 |

## Consequences

- **諦めたもの**: 開始操作なしで進められる手軽さ。課題をまたいで証跡を持ち越すこと。05 の「一度証明すれば reset 後も有効」。
- **残余 1 — 値の由来は保証しない**: 値は静的で課題ごとに 1 つなので、gate は「届いた値がその attempt の中で得られた」ことを保証しない。証明が保証するのは「開始後に証明の rule が
  鳴った」ことだけで (05 では技法の実演と同じ。10 は残余 4)、**証明の発火と届いた値は結び付かない**。技法は実演されているので受容する、が content-engineer の判断だった (受容の扱いは残余 2 の末尾。10 は残余 4)。
- **残余 2 — 積極証明を持たない evade (現状 03)**: gate が保証するのは「開始から solve までに禁止ルールの記録が無い」ことだけで、技法が使われたことも値の由来も保証しない
  (W1 の一般化。ADR-0003 C5 = `0003:86-102`)。現行は 03 が `current` になった時点から禁止発火が taint になるが、本 ADR では開始操作より前の発火は taint にならない。閉じるのは積極証明だけである。
  **調査の結果 (content-engineer 2026-10-05、静的読解): 03 に証明は足せるが条件つき** — 証明が付くのは想定している読み方の一部だけ (具体は private の正典と issue)。**VP 裁定 (product-engineer が支持): 今は gate にしない。**
  観測用の rule を S1' (採点に使わず、見せない: D12) で載せ、次回イベントで実測して Signpost 2 の条件で再判断する。CEO の受容 (2026-10-05、残余 1・2) は「調査の結果が出るまで」だったので、次の再判断までの延長は本 ADR の merge で確定する。
- **残余 3 — 到着順**: 判定はイベントの到着順で行う。開始の直前に起きた発火が開始の後に届くと taint になる (厳格側。やり直しで回復する)。solve の後に届いた発火は効かない (既存: `0003:212`)。
- **残余 4 — 10 の証明は技法の実演そのものを保証しない** (rev2): 技法を使わずに 10 の証明の rule を点灯させる操作がある (具体と受容の根拠は private 正典 §7-4。静的読解、未実測)。残余 1 とは別の残余で、
  両方が重なると gate が保証するのは「開始後に禁止ルールの記録が無く、証明の rule が鳴り、正しい値が届いた」ことだけになる。**受容は CEO** (S2 の PR 本文で明示し、merge で確定する)。
- **双子の罠**: 02 / 04 を解く前に 03 / 05 を開始すると、先行課題の必須発火 (同じ rule) が taint になる。定義どおりの挙動で、やり直しで回復する。参加者向けの文面と guard テストで扱う。
- **`0003:461-464` の禁止を解除できる条件 (課題ごと)**: ① D1〜D8 が main に入り、Verification の表のテストが green ② その課題が attempt スコープの積極証明を持ち、rule の fire / no-fire が実機で
  確認済み ③ 開始操作つきの E2E (d′) が green ④ 残余 1 (残余 2 の末尾) と、10 は残余 4 (CEO) の受容が有効である。満たした課題に限り「1 回の attempt の中で、禁止ルールが発火せず、証明の rule が鳴り、
  (requireExfil なら) 値が届いた」と書ける。「その値を技法で読んだ」「独力で解いた」と、10 の「技法を実演した」は書かない。03 は ② を満たさないので解除しない。10 の証明だけを epoch より先に入れた状態は部分的な縮小で、解除しない。
- **参加者向けの文面** (content。ADR-0003 F2 の再発防止): 03・05・10 の README / journey / welcome、HANDBOOK、submit と exfil の応答文 (`api.go:1120-1126,1412-1413`) が「開始してから
  操作する。開始前の操作・receipt・証明は数えない」を言うこと。
- **切り戻し**: migration 適用後の DB は旧イメージで開けない。migration をイベント中の hotfix として適用しない (段階と期限)。適用前の DB のバックアップを go / no-go の記録に含め、切り戻しは「旧イメージ + バックアップの復元」で行う。
- **P28 の印・称号** (product-engineer と合意済み 2026-10-05。workspace `REFACTORING.md` P28 受け入れ条件 14〜18): architect §8 の条件 inScope (先行課題がすべて solve 済み) を
  「attempt の gate を通って solve した」に置き換える (順序は問わない。inScope と同義ではない)。条件: 文面は「この挑戦中、検知の記録なし」という事実の記述に限り、順番・完全制覇・
  独力と読める語を入れない。突破印は 03・05・10 で同じ形にし、「指定の技法を実演した」という差は図鑑の説明文にだけ置く (10 は残余 4 があるので断定しない文言にする。product-engineer の確認待ち)。ADR-0029 は「gate を通った solve」をサーバ側の solve の
  記録から導き、時刻の比較や claimed identity の経路から導かない。本 ADR の landing より前の evade の solve には印・称号を出さない。

## 段階と期限

| 段階 | 内容 | 担当 | Class | security |
|---|---|---|---|---|
| S1 | platform: 10 の証明 rule `Nimbus Vault Master Key Read` を `customRules` の 4 件目に足す (standalone、container は `challenge` だけの allowlist。condition は private 正典 §7)。前提 = vault の free-win ゲートを ADR-0025 の append 固有の一致にする修正 (platform#209)。**載せるのは S2 を含む app の ref と同じ stand-up だけ** (D9 (g)) | content (condition) → platform | 2 (クロスリポ) | 必須 |
| S1' | platform だけ: 03 の観測用の rule を D12 の条件で載せる (`INFO`・tag `ctf_observation`・最後に読み込むファイル・Falco の `priority` を `info`・upstream の INFO の rule を無効化)。採点に使わず app にも届かないので S2 と独立に載せてよい。Signpost 2 の計測は Falco ログの回収 (platform#208) が前提 | content (condition) → platform | 2 (採点の入力 = Falco の設定) | 必須 |
| S2 | app: allowlist 1 行 (condition を表さない rule 名)、10 の `expectedRules` + `requireExpectedRuleFire`、参加者向けの文面 (D9 (h))、契約表 (Falco custom rule の行に container 名 = D9 (j)、Webhook payload の行に priority の層 = D12)、Verification の「Me pane の表示」と「機械で守るもの」の app 側。**merge の前提 = platform#207 (全 Falco pod での rule 名の読み込みと fire / no-fire のゲート) が stand-up で green** | content、software (テスト)、architect (契約表) | 2 | 必須 (`hints[]` を変えるので ADR-0026 V8 も) |
| S3a | migration と store の追加 (表 2・列 3・attempt の読み書き・`Reset` の 1 トランザクション化)。**既存の証跡の書き込み (epoch 0) と読み込み (全行) は変えない** | software | 2 | 必須 (ADR-0020) |
| S3c | collector の Director で `X-Auth-Request-*` を落とす (S3b-1 の前提。現状は穴ではないが、「認証ヘッダーがある = 証明済み」を collector を通る経路でも成り立たせる: `internal/collector/collector.go:118-124`) | software | 2 | 必須 |
| S3b-1 | 開始ルート・投影 (`attempt`・`alert`)・監査ログと counter、reset-dirty の authz と rate-limit の変更。**開始ルートは証跡 3 表に触れず、採点に効かない**。spec: 新 path と `AttemptResult`、`Journey.attempt`、`MissionDetail.alert`、reset-dirty の `x-ctf-authz` / `x-ctf-rate-limit` (+ `make gen`) | software、architect (spec) | 2 | 必須 |
| S3b-0 | 既存テストに開始ヘルパを挿入する (green のまま)。正規順の leaderboard の期待値を固定する | qa、software | 0 | 不要 |
| S4 | portal の開始導線・`alert` 表示・確認 (切り替えとやり直し) | application (文言は product / content) | 1 | 必須 |
| S3b-2 | 採点の切り替え (D2 の規律、D4〜D7、投影の 4 フィールド)。spec: `SubmitFlagVerdict.started` と、意味が変わるフィールド・reset-dirty・exfil の description (+ `make gen`)。反転・新規テスト、I11 の表の書き換え | software、architect (spec・I11) | 2 | 必須 |
| S5 | 実機: rule の読み込みと fire / no-fire (platform#207)、E2E (d′)、stand-up 前の DB バックアップ、teardown 前の Falco ログの回収 (platform#208)。platform の `docs/PROD-GATE-E2E-PLAN.md` を更新する (Origin だけを付けた reset-dirty の呼び出しは 403 になるので、認証つきの手順に直す) | qa、platform、sre | — (stand-up は CEO 承認) | private 正典の fire / no-fire 表を確認 |

- **S3b-1 から S3b-2 までの間は release tag を切らない** (表示は attempt、採点は `current` で食い違う)。S3b-2 は S4 より後に入れる (開始導線の無いまま採点だけ切り替わると、どの evade も解けなくなる。ADR-0003 F3 と同じ失敗)。
- **S3a 以降の tag は migration を含む。** イベント中の hotfix は、stand-up で使った tag から branch を切って出す (main の先頭を当てない)。
- **期限**: 次回イベントの stand-up で使う app の SHA を固定する時点までに S1〜S3b-2 (S1' を除く。S1' が入らない回は Signpost 2 を測らない) が merge 済みで、S5 がリハーサルで green。
- **間に合わない回の退避** (CEO が go / no-go で選ぶ): 退避 a = 受容する (何も入れない) / 退避 b = (i') を入れる / 退避 c = 10 の証明だけを ADR-0008 の意味論で入れる (部分的な縮小)。
  architect の推奨: P28-0b がその回のリリースに入るなら b + c、入らないなら a でよい。(i') は `current` を gate の消費者にするので、(i) の landing と同時に撤去する。**手順**: VP が対象
  イベントを名指しした受容の Issue を起票 → CEO が Issue 上で受容または退避を明示 → platform のそのイベントの go / no-go 記録からリンク → その回は `0003:461-464` を維持 → 次の期限を置き直す。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1 は D11 の counter (claimed identity の入力なので (user, cid) で重複を除き、問い合わせの件数と突き合わせる)、3・4 は D11 の監査ログと solve 時点の証跡行の `at`、
2 は teardown の前に回収した Falco の stdout (platform#208) と D11 の監査ログから事後に測る (観測用の rule は D12 で app に届かない)。D12 を覆す信号は D12 に置く。

1. **開始を忘れた操作の常態化**: `not_started` の submit と数えなかった receipt が 1 イベントで evade の提出全体の 20% を超える、または運営への同種の問い合わせが 5 件を超える →
   開始の導線を作り直す。自動開始に戻すなら錨が二重になるので新 ADR。
2. **03 の gate が名目だけになる**: 次回イベントで、03 の solve のうち、開始から solve までに観測用の rule (採点に使わず、見せない: S1'・D12) の発火が無いものが半数を超える → 03 の証明を gate にするかを
   再判断する。gate にする条件: この閾値を超える + 実機の fire / no-fire と、全ノードでの rule の読み込み・rule 名の一致が確認済み + 60 分のハンズオンで 03 の solve 時間の中央値が悪化しない見込み。gate にするときは rule を `NOTICE` に上げて証明にし、文面を D9 (h) の形にする。
3. **値の由来**: 10 の solve のうち、その attempt で receipt が証明の発火より先に届いたものが 3 割を超える、または値の共有が運営で観測される → 値を attempt か参加者に結び付ける
   設計 (flags 契約と plant 経路の変更。別 ADR)。
4. **1 つだけの active が実害になる**: 同じ参加者が 2 つの evade の間を 3 往復以上する例が 1 イベントで 5 人を超える → 課題ごとの attempt に変える (`evade_attempt` の主キーを変える migration)。

## Verification

すべて**未実装**。`make test` = required check。attempt の性質 (①〜⑨ = qa-engineer の骨子) は実 store で回す (`internal/scoreboard` の HTTP 経由か、実 `store.Open`。fakeStore は epoch の照合を
持たないので根拠にしない)。区分: **[R]** = S3b-2 で入れ、S3b-2 の直前の tree で compile でき fail する (PR 本文に fail の出力を貼る) / **[S]** = 導入した段階で入れ、その段階で green。実装を
故意に壊して赤になることを PR 本文に示す / **[G]** = 既存。無変更か、開始ヘルパを足すだけで全段階 green / **[I]** = 既存を反転・書き換える (旧名と理由を doc comment に残す)。

| 段階 | 区分 | テスト |
|---|---|---|
| S3a | [G] | I11 の既存 6 本と `internal/store/store_test.go` の証跡系が無変更で green |
| S3a | [S] | `TestMigrate_UserVersion2_AddsEpochColumnsAndAttemptTables` / `TestAttempt_EpochNeverReused` (切り替え・やり直し・admin reset をまたぐ) / `TestAttemptWrite_FailureLeavesStateIntact` (開始・切り替え・やり直しのそれぞれで、採番表か `evade_attempt` の書き込みを失敗させる) / `TestAttempt_SurvivesStoreRestart` / `TestAdminReset_IsAtomic` (途中の DELETE を失敗させても何も消えない) / `TestAdminReset_ClearsAttempt_KeepsSequence` (Reset の後、最後の attempt が active に戻らず、次の epoch は続きから) |
| S3c | [S] | collector の `TestForward_StripsAuthRequestHeaders` |
| S3b-1 | [S] | ⑧ `TestAttemptStart_ResultTable` (D3 の表の全行、`abandon` の各値、4xx の判定順) / `TestAttemptStart_DoesNotTouchEvidenceTables` / `TestAttemptStart_OtherUser403_RecordsNothing` / `TestAttemptStart_NoAuthHeader_403` / `TestAuthz_SelfOrAdminGate_MissingHeaderDenied` (`TestAuthz_AuthenticatedGate_MissingHeaderDenied` = `internal/scoreboard/authz_test.go:288` と同じ形。開始と reset-dirty) / `TestAPISpec_V4_AttemptNeverForwarded` / `TestAPISpec_V5_AttemptResultFieldsMatchSpec` / `TestResetDirty_RateLimit_KeyedByIdentity` / ⑨ `TestJourney_Alert_UnstartedEvadeIsIdle` / `TestAttempt_AuditLogAndCounters` (D11) |
| S3b-1 | [I] | `TestJourneyWriteGate_ResetDirty_NoHeader` (`internal/scoreboard/journey_api_test.go:1054`。200 → 403) / `TestResetDirty_NonEvadeChallenge_Rejected` (`:1071`)・`TestResetDirty_UnknownChallenge_404` (`:1079`) は認証ヘッダーを付ける (gate が catalog の照合より前: `api.go:1603`) / 件数の pin を各 +1: `wantOriginGuardedRouteCount` 13 → 14 (`origin_guard_test.go:98`)、`selfGated` 7 → 8 (`authz_test.go:269`)、ルート数 37 → 38 (`apispec_parity_test.go:213`)、response の件数 25 → 26 (`:610`) / `TestAPISpec_V5_JourneyFieldsMatchSpec` (`attempt`・`alert` のキー) / collector の `TestDefaultDeny_BlockedRoutes` (手書きの表に attempt と reset-dirty の行を足す) |
| S3b-1 | [G] | `TestAPISpec_V1_RouteSetMatchesSpec`・`TestOriginGuard_AllProtectedRoutesEnforced`・`TestAuthz_AllDeclaredGatesEnforced`・`TestAPISpec_V3b_StringExtParity`・`TestAPISpec_V4_ResetDirtyNeverForwarded` |
| S3b-0 | [G] | 開始ヘルパを足すだけの既存テスト (採点は `current` のまま green)。⑨ `TestLeaderboard_CanonicalOrder_Unchanged` を足す: 正規順 (開始を挟む) の固定シナリオの leaderboard を、期待値のリテラルで持つ (ファイルの golden と再生成の仕組みは使わない。`make test` は host に書き戻さない) |
| S4 | [S] | ⑩ `TestPortal_AttemptAndResetOnlyFromClickHandlers` (`internal/scoreboard/view` のテンプレートの静的検査: 開始ルートと reset-dirty を呼ぶ箇所がクリックのハンドラだけで、`abandon` とやり直しが確認を経ること) |
| S3b-2 | [R] | ① `TestAttempt_W2_BossNotSolved_CurrentPinnedAt03` / `…_CurrentPinnedAt05` (10 の禁止発火と receipt があっても Sweep も手動 submit も solve しない) ② `TestAttempt_ReceiptBeforeStart_NotCounted` ③ `TestAttempt_ForbiddenFireDuringAttempt_Taints` / `TestAttempt_Restart_InvalidatesTaintReceiptAndProof` / `TestAttempt_SweepAndSubmit_SameVerdictInEveryState` (idle・clean・spotted・証明なし・receipt なし・完了) / `TestAttempt_SwitchAwayAndBack_OldEpochEvidenceNotCounted` (A → B → A。gate・Sweep・投影の 3 フィールドで、live でも再起動後でも) / `TestResetDirty_NotActive_NoOp_OtherAttemptUntouched` / `TestAttempt_TwinTrap_StartBeforePredecessor_Taints` ④ `TestOnRuleFire_RealCatalog_WithoutStart_NoEvadeSolves` ⑤ `TestAttempt_Proof_FiredBeforeStart_NotCounted` ⑦ `TestMigrate_UserVersion2_LegacyEvidenceRows_NeverCount` ⑨ `TestLeaderboard_OutOfScopeSolve_NotScored` (明示的な assert。golden にしない) |
| S3b-2 | [S] | ② `TestAttempt_ReceiptAfterStart_Counts` / `TestAttempt_Receipt_MatchingValueNotReplacedByMismatch` (D2 (g)) / `TestExfil_ResponseIndependentOfState` (active の有無・D2 (g) の置き換え拒否・solve 済み・別の課題が active のどれでも status・キー・文言が同じ) ③ `TestStoreReads_OldEpochEvidenceNeverVisible` (store の読み出しメソッド全部の表 × live / 再起動後) / `TestAttemptStart_SameChallengeTwice_KeepsEvidence` ⑤ `TestAttempt_Proof_CleanButNoProofFire_NotSolved` / `…FiredAfterStart_Counts` / `TestExpectedRuleFire_NewRuleNameUniqueToMission10` ⑥ `TestAttempt_VerdictIgnoresClock` ⑦ `TestEvidence_ReDeliveredInNewEpoch_CountsAfterRestart` (3 表それぞれ。D2 (b)) / `TestStore_EvidenceWrite_WithoutActiveAttempt_WritesNothing` (D2 (a)) / `TestAttempt_UncountedReceipt_AuditLogAndCounter` (D11) |
| S3b-2 | [I] | 反転: `TestOnRuleFire_ExpectedRuleFire_NotAttemptScoped` → `…_AttemptScoped`、`TestResetDirty_NeverClearsExpectedRuleFire` → `TestResetDirty_InvalidatesExpectedRuleFire`。書き換え: `TestOnRuleFire_RealCatalog_AttemptScope_TwinMissionsStayClean` (④。`internal/scoreboard/scoring/scoring_test.go:1361` の `WithOrder` が D7 で無くなる)、`TestOnRuleFire_AttemptScope_OnlyTaintsCurrentChallenge` (`:445` → `…_OnlyTaintsActiveAttempt`)、`…_IsIdempotent` (`:518`)、`TestSubmitEvade_SevenForbiddenRules_ResetRequiresFreshExfil`、`TestResetDirty_TransactionRollsBackOnPartialFailure`、`internal/scoreboard/server_test.go:573,644,686,739` (`current` への依存と行削除の reset)、`internal/scoreboard/ingest/ingest_test.go:120` (開始が無いと taint の書き込みが起きない)、`journey_api_test.go:295,363` (store に直接書いて投影を見る)、`internal/store/store_test.go` の証跡系 (特に `:464`)、`TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec` (和集合に `started`) |
| S3b-2 | [G] | ⑥ `TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance`・`TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved`・trigger の既存テスト (attempt なしで solve する) / `TestDirtyFlag_SurvivesStoreRestart` / `TestSweep_ManualAndSweeperShareVerdict`・`TestSweep_AlreadySolved_Idempotent` / ⑨ `TestLeaderboard_CanonicalOrder_Unchanged` (期待値を変えない) / `TestAPISpec_V5_ExfilReceiptFieldsMatchSpec` |

- **[I] の洗い出しの正典**は、S3b-2 の作業ブランチで `make test` を回した fail の一覧である。上に無いものが出たら PR 本文に載せる。
- **ブラウザでだけ確認できるもの (⑩)**: 閲覧・ポーリング・`?mission=` で開始ルートと reset-dirty が呼ばれないこと、確認の文面。ブラウザ E2E (ADR-0031) で固定し、ハーネスができるまでは qa の手動検証。
- **Me pane の表示 (D9 (h)・D12)**: S2 で `TestFalcoEvents_IgnoresBelowMinimumPriority` (`internal/scoreboard/server_test.go:397-410`) を、Informational の発火が `GET …/me` の `recent_rule_fires` にも出ないことまで
  見る形にし (D12 の app 側の層。doc comment に本 ADR を書く)、10 の証明の rule の発火は出ることを足す。描画は ADR-0031 (Proposed、app#321) の E3 を拡張して固定する (10 の証明の rule 名が Me pane の一覧に出て、
  Informational の event は出ない)。ハーネスができるまでは qa の手動検証。
- **実機でだけ確認できるもの**: (a) 全 Falco pod で rule 名 `Nimbus Vault Master Key Read` が読み込まれていること (ファイルではなく名前で) と fire / no-fire = platform#207 のゲート。**S2 の merge の前に stand-up で green**
  (ADR-0008 (a-1)・ADR-0017 (a-2)(a-3) と同型。結果は private 正典に記録し、security-engineer が確認する) (b) 開始 → auto-solve の観測 → 手動 submit の E2E (d′) (c) deploy 経路が新しい rule を発火させないこと
  (I13b の対象 +1。S1' の観測用の rule は catalog の外だが、Signpost 2 の分子を汚すので同じく 0 件を見る) (d) Falco の `priority` を `info` にした後も catalog の rule の fire / no-fire (platform#207 と vault のゲート) が変わらないこと (D12)。
- **機械で守るもの (rev2)**: (1) D9 (g) [推奨、platform の preflight]: platform の customRules が新設する rule 名の集合 (`ctf_observation` を除く) と、stand-up で使う app の pin の `challenges/custom-falco-rules.txt` が
  一致しなければ no-go (S2 の無い回に 4 件目を載せることと、S1 の無い回に S2 を当てる softlock の両方を止める。無い間は private 正典 §9 の手順) (2) D9 (i): S2 で `challenges/10-final-exfil/rule.yaml` に証明の rule 名が無いことをテストで pin する
  (3) D9 (j): `flag-guard` (`scripts/check-flag-isolation.sh:663-670`) は `plant` / `challenge` の不在で既に赤になる。S2 でその箇所に「platform の customRules が参照する。契約表」の 1 文を足す (4) D12 [platform の CI]: customRules のうち
  tag `ctf_observation` の rule は `INFO` で最後に読み込まれるファイルにあり、それ以外に `INFO` 以下の rule が無い。Falco の `priority` が `info` なら upstream の INFO の rule が無効化され、sidekick の webhook の `minimumpriority` は `notice`。
  stand-up では全 Falco pod の rule ファイル (falcoctl が入れたものを含む) の INFO の rule ⊆ 無効化リスト ∪ `ctf_observation` を検査する (upstream で catalog の rule が INFO に下がった場合もここで止まる)。
- **I11 の表を書き換える条件**: 上の表の S3a〜S3b-2 のテスト (S4 の静的検査を含む) が main に入り、本 ADR が Accepted。(a)(b) が済むまで「検証済み」「実効的」と書かない。

## Decision の追加 (rev2、2026-10-10)

S1 (platform `feat/adr-0032-s1-proof-rules`。private 正典 `docs/falco-detection-conditions.md` §7〜§10) の実装と architect の R4 (2026-10-07) で分かった事実に合わせて足す。D1〜D11 と同格の決定で、
行番号を保つためにここに置く (ADR-0031 が `0032:111-113,156,232,239` を参照している)。前提の事実: ingest は image フィルタを通った全 rule の発火を rule 名で絞らずに記録し (`internal/scoreboard/ingest/ingest.go:261`、
`internal/store/store.go:603-619`)、Me pane が「Falco rules you triggered (last 60s)」と events 数に出す (`internal/scoreboard/api/api.go:1760`、`internal/scoreboard/view/templates/portal/pane-me.tmpl:146`)。

- **D9 (g) 10 の証明の rule は、S2 を含む app の ref と同じ stand-up でだけ載せる。** rule 名は `Nimbus Vault Master Key Read` (S1 で確定)。S2 の無い回に載せると、想定解の読み方で rule 名が Me pane に
  「triggered」と出て、文面の「発火させず読む」(`challenges/10-final-exfil/journey.yaml:6,14,33,54`) と矛盾する (03 の観測用の rule を S1 から外したのと同じ理由)。(d) の「platform が先・app が後」は同じ stand-up の中の
  順序で、別の回に分けてよいという意味ではない。S2 の無い回は platform の entry を外す (1 commit)。機械化は Verification の「機械で守るもの」(1)。
- **D9 (h) 証明は Me pane に見える前提で文面を揃える (05 と同型)。** D12 の隠し方は証明に使えない (INFO は app に届かず、採点もできない)。10 の文面は 05 (`challenges/05-silent-search/journey.yaml:20-22,31-35`) と
  同じく「禁止ルールは鳴らさない / 証明の rule は鳴ることが CLEARED の条件」と書き、condition の形は書かない。上の 4 箇所と README (`challenges/10-final-exfil/README.md:3,48`) を S2 で直す。
- **D9 (i) 表示用の抜粋に載せない (公開境界)。** `challenges/10-final-exfil/rule.yaml` に証明の rule を載せない。載せると condition が公開される。05 が載せているのは、05 の condition が回避の経路を含まないため (private 正典 §10 (b))。
- **D9 (j) ctf-user の container 名は契約。** 証明の rule は container 名を参照する (`charts/ctf-user/templates/pod.yaml:275` の `challenge` だけを許可する。initContainer の `plant` = `:102`・`missions-scope` = `:131` は同じ image で、
  ingest の image フィルタを通る)。app 側で名前を変えると、flag-guard の名前を一緒に直せば app の CI は緑のまま、S2 の後に 10 が softlock する。契約表の Falco custom rule の行に「`challenge` / `plant` / `missions-scope` の
  container 名は platform の customRules が参照する (condition は書かない)。変更は両リポ同時 PR」を S2 で足す。
- **D12 採点に使わない観測用の rule は priority で隠す (案 B)。** 03 の観測用の rule (残余 2・Signpost 2) は、鳴っても参加者に見えてはならない (上の前提の経路で Me pane に出る)。
  - 案 A: app の ingest に rule 名の drop-list を置く。入れ忘れると見える側に倒れ (fail-open)、観測用の rule 名が公開リポに載り、採点の入口に分岐が増える
  - 案 B: 観測用の rule を `INFO` にし、Falco の `priority` (platform `helmfile/releases/falco/values.yaml.gotmpl:28`、今 `notice`) を `info` に下げる。Falco の stdout には出るが、falcosidekick の webhook は
    `minimumpriority: notice` (`:47`) で転送せず、app も Debug / Info を無視する (`ingest.go:240-249`、`docs/openapi-scoreboard.yaml:1946-1951`)。隠す層は既存の 2 つ (platform と app に 1 つずつ) で、app は変えない
  - 案 C: app が falcosidekick の payload の `tags` を読み、`ctf_observation` を落とす (additive な payload 契約 = 両リポ同時 PR)。app で観測の発火を数えられるが、tag の入れ忘れと両リポの版のずれで見える側に倒れ、採点の入口に分岐が増える
  - **決定: B。** 理由: 隠す層が既存で 2 つあり、採点の入口に分岐を足さず、観測用の rule 名が公開リポに出ない。**architect の同意の条件** (B の新しい代償への対処): Falco は `rule_matching: first`
    (Falco 0.43.1 の `falco.yaml:692-713`。platform の描画も `first`) で、同じイベントに一致する rule のうち先に読み込まれたものだけを出す。priority を下げると upstream の INFO の rule (falco-rules-5.0.0 では
    1 本: `falco_rules.yaml:685-701`) も読み込まれ、後に読み込まれる catalog の rule を鳴らさなくしうる (具体は private 正典に置く)。したがって (1) upstream の INFO の rule は Falco の設定で名前を指定して無効にする
    (`rules:` = `falco.yaml:246-275`。今は `notice` なので読み込まれておらず、稼働する rule の集合は観測用の rule の分しか変わらない) (2) 観測用の rule は `INFO`・tag `ctf_observation` で、customRules の中で最後に
    読み込まれるファイルに置く (rules.d はアルファベット順: `falco.yaml:205-206`。後に catalog の rule が無いので、それを鳴らさなくすることがない) (3) upstream の rule は falcoctl が `falco-rules:5` を追って入れる
    (platform の描画) ので、無効化の漏れは stand-up で全 Falco pod の実ファイルと突き合わせて止める (Verification の「機械で守るもの」(4)) (4) 契約表の Webhook payload の行に「Debug / Informational の event は
    採点にも表示にも使わない。platform の観測用の rule の非表示はこれと sidekick の `minimumpriority` の 2 層に依存する」を S1' より前か同時に足す (S2 か docs だけの PR) (5) `priority` を `info` にするのは観測用の
    rule と同じ PR で行い、観測用の rule が無くなれば戻す
  - **覆す信号**: (i) catalog の rule が INFO の rule に打ち消された例が実機か Falco ログで 1 件でも見つかる → priority を `notice` に戻して観測用の rule を外し、C を新 ADR で (ii) Signpost 2 を Falco ログから
    測れない (次回イベントまでに platform#208 の回収が入らない、または回収に欠けがある) → C (app で観測の発火を数える) (iii) P28 で観測の発火を app で表示・集計したくなる → C (iv) Falco pod 1 つあたりの
    INFO の行が 1 イベントで 03 の開始回数の 10 倍を超える (観測用の rule 以外の INFO が読み込まれている) → 無効化を直し、2 回続くなら C

## Advice

- content-engineer (2026-10-05): 10 の証明は A を推奨 (B・C は不採用、D は epoch の実装形の 1 つ)。記録は「10 に限り」attempt スコープ、が推奨だった。architect は 05 も揃える案を出し、CEO が採った。
  03 の証明の調査 (静的読解) は「足せるが条件つき」(残余 2)。未確認: 10 と 03 の rule の実機 fire / no-fire。
- security-engineer R1 (2026-10-05、2 巡。REQUEST CHANGES → APPROVE with comments。反映済み): admin `Reset` と epoch の採番、読み出し側での epoch 照合、claimed identity の経路の応答と receipt の保護、
  認証ヘッダー必須、portal が自動で呼ばないこと、監査ログ、公開境界、切り戻し。2 巡目: I11 の機械強制の穴 2 つ、attempt の書き込みの原子性、I11 冒頭と運営の例外、やり直しの確認文、読み出し
  メソッドの網羅、counter の水増し、collector のヘッダー、静的検査の名前、段階の注記。
- qa-engineer R2 (同、2 巡とも REQUEST CHANGES・BLOCKING なし。反映済み): S3a が挙動を変えない条件、開始ルートの応答表、既存テストの名指し、段階の分割、Signposts を測るログ、P28 の inScope。
  2 巡目: S3b-1 で赤になる件数の pin と spec 変更の割り当て、admin `Reset` と `evade_attempt`、区分 [S] と段階の明記、golden をやめて期待値のリテラルにすること、名指し漏れ、投影 4 フィールドの
  切り替え段階。W2 の再現と骨子 9 点 (2026-10-04 / 05) も qa。
- product-engineer (2026-10-05): P28 の印・称号の条件の置き換えに条件つきで同意。03 の証明を今は gate にしない VP 裁定を支持。
- architect の判断 (指摘の外、または委ねられたもの): reset-dirty も認証ヘッダー必須に揃えた。epoch を DB 全体の連番にした。I11 は運営の例外を文言に書く側にした (理由は D3)。
- VP (2026-10-05): 指摘の全件採用、exfil の応答を一定にする裁定、03 を今は gate にしない裁定。未検証の前提: 開始直前の発火が開始後に届く頻度、開始を忘れる頻度、次回イベントの日付、
  03 の観測用の rule の実機での挙動と solve 時間への影響。
- architect R4 (2026-10-07、platform S1 の手動レビュー): #1 同じ stand-up でだけ載せる (D9 (g))、#2 隠す機構は本 ADR に無い新しい設計 (D12)、#3 container 名のクロスリポ依存 (D9 (j))。
- platform-engineer・content-engineer (S1、2026-10-06〜07) と review-5x (platform S1、2026-10-07): 03 を S1 から外す判断、container の allowlist、技法なしの点灯 (残余 4)、ゲートの偽 PASS (platform#209)、
  verify のゲート (#207)、ログの回収 (#208)。
- VP (2026-10-10): D12 は B を推奨。覆す信号 3 つ (Falco の stdout の増加・P28 で app に出したい・`System user interactive` が noisy)。architect の判断: B を採り、`rule_matching: first` による打ち消しを同意の条件
  (1)〜(3) で塞いだ。3 つ目の信号は (1) の無効化で起きなくなるので (iv) に置き換えた。0.43.1 が同梱する ruleset は falco-rules-5.0.0 (Falco の `cmake/modules/rules.cmake:21` @0.43.1) で INFO は 1 本だが、cluster は
  falcoctl が入れる `falco-rules:5` の最新版を読む。未確認 (rev2): 打ち消しが実機で起きるか (静的読解のみ)、stand-up 時点の `falco-rules:5` の INFO の rule、残余 4 の点灯 (private 正典 §7-7)。
