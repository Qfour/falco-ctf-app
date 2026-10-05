# ADR-0032: evade の attempt を明示的な開始操作 (epoch) にし、solve を「その attempt の中で記録された証跡」だけで判定する — 10-final-exfil に attempt スコープの積極証明を入れる

- Status: **Proposed** (Accepted 化は CEO merge 時。期限 = 次回イベントの前、CEO 決定 2026-10-05)
- Date / Deciders: 2026-10-05 / CEO (2026-10-04 錨は明示的な attempt、2026-10-05 10 の積極証明は入れる方向で調査を先に・期限の前倒し。Class-2 の merge) + VP (承認) +
  architect (起草・同意権) + content-engineer (実現性調査) + qa-engineer (再現と回帰テストの骨子)。security-engineer・qa-engineer の独立レビューは未実施
- 関連: ADR-0003 (Decision を supersede。I11 の起源)、ADR-0004・0008・0027 (限定 supersede。「supersede の範囲」の表)、ADR-0017 (custom rule の先例)、ADR-0020 (migration)、
  ADR-0025 (10 の flag の置き場)、ADR-0033 (flags ファイルの完全性。未 merge)、Issue #121、workspace `REFACTORING.md` P28 architect §8 / §10
- 行番号は e74d871。`0003:N` などは `docs/adr/` の各 ADR の行番号。**公開境界**: flag 実値・未公開の回避条件・rule の condition は書かない (condition の正典は
  private の platform `docs/falco-detection-conditions.md`)。弱点の記述は公開済みの範囲に留める

## Context

- **C1 現行の錨は進行順から導いた `current`。** ADR-0003 は Option 2 を採り、taint を「その課題が `current` (order の先頭の未 solve) のときだけ」書く (`0003:162-167`、
  `internal/scoreboard/scoring/scoring.go:283-293,427-441`)。有効条件は「進行が線形かつ `current` が単一」(`0003:149`)。receipt (`exfil`) と証明 (`expected_rule_fire`) は
  attempt を知らず、reset は行の削除で表している (`internal/store/store.go:825-857`)。
- **C2 公開済みの弱点。** W1: `current` になる前の発火は数えない (`0003:217-219`)。W2: 先行の evade を未 solve のまま置くと `current` が進まず、10 の禁止 7 本は 10 を taint しない。
  `Sweep` は `current` を見ないので、receipt があれば auto-solve する (`0003:221-244`、`scoring.go:84-136,886-910`)。ADR-0003 は「capstone gate が実効的に存在する」と読める
  記述を禁じ (`0003:461-464`)、閉じるのは attempt ごとの積極証明だけだとした (`0003:99-100,243-244`)。
- **C3 qa-engineer の実行 (2026-10-04 / 05、実 catalog + nimbusbreach-full、未コミットの再現テスト)。** current = 03 でも current = 05 (2h 版の形) でも、10 の禁止 7 本を発火させた後に
  receipt を届けると、Sweeper の 1 回で 10 が solve された (10 の dirty は空のまま)。10 が current のときは同じ発火が taint になり solve しない (対照)。非 current の evade は
  禁止ルールが発火しても dirty にならず、後で current になった時点でも「クリーン」のままだった。
- **C4 順序外は標準の進め方になる。** 2h 版のハンズオンは 01・02・03・04・06・08 で、05・07 を飛ばす (`scenarios/nimbusbreach-full/playbook-2h.md:13,47`)。ADR-0027 がどの課題でも
  ヒントを開けるようにし、Option 1 の閾値 (`0003:133-134`) への到達と Signpost 1・5 の発火を記録した (`0027:80-90`)。Signpost 2 (evade が積極証明を得る、`0003:527-528`) は
  05 で発火して「実害なし」と判定されたが (`0008:348-368`)、10 に証明を足すと再び発火する。Signpost 4 は未計測である。
- **C5 10 の gate は技法の使用を証明しない (content-engineer 2026-10-05)。** 現行の gate は「禁止 7 本の不発火」+「正しい flag の receipt」(`challenges/10-final-exfil/falco-rule.yaml:3-10,17`)。
  flag はイベントごと・課題ごとに 1 つの静的な値で (`internal/catalog/flags.go:44-57`、契約表 Flags 行、ADR-0033)、receipt はどの attempt にも紐づかない。したがって epoch を入れても
  「事前に得た値を開始後に持ち出す」ことは区別できない。区別できるのは「開始後に、読む段の技法が使われた」という記録だけである。
- **C6 制約。** identity が証明されるのはブラウザ経路 (`X-Auth-Request-Email`) と Falco の発火 (namespace から導く: `internal/scoreboard/ingest/ingest.go:251`) だけで、collector 経由の
  submit / exfil は claimed identity である (`internal/scoreboard/api/api.go:505-510,541-546`、`internal/collector/collector.go:156-196`)。I1・I8・I14・I15 と ADR-0020 を守る。
- **C7 CEO 決定 (再議論しない)。** 2026-10-04: 錨は「エンカウント開始を明示的な attempt にする」(ADR-0003 の Option 1)。2026-10-05: 10 の積極証明は入れる方向で実現性の調査を
  先に行う → 結論は「実現可能・推奨あり」。2026-10-05: 本 ADR の期限は次回イベントの前 (`0027:95-98`)。

## Options

- **錨 (i) 明示的な attempt epoch【CEO 決定・推奨】** — 開始操作で attempt を始め、taint・receipt・証明をその epoch に属するものだけ数える。コスト: 表 1 + 列 3 の migration、route 1、
  portal の開始導線、参加者に「開始」を教える認知コスト。リスク: 開始を忘れた操作は数えられない (最頻の問い合わせになりうる)。積極証明の無い evade では開始前の取得を
  区別できない (Consequences)。可逆性: migration 適用後の DB は旧イメージで開けない (`internal/store/migrations.go:147-171`)。閾値: 順序外の進行が 1 つでも標準にある時点 (到達済み)。
- **錨 (i') `current` のまま、evade の solve を先行課題がすべて solve 済みのときだけ許し、`current` になる前の receipt を数えない** — schema 変更なし。コスト: `evaluateClean` と `Sweep` が
  `current` の消費者になり (`0003:780-784` が単独では却下した追加)、solve 時刻の比較が gate に入る。リスク: 2h 版では 05・07・09 を解かないと 10 を solve できない。開始前の取得は
  (i) と同じく区別できない。可逆。閾値: (i) が期限に間に合わない回の退避。
- **錨 現状維持** — コストなし。W2 が標準の進め方の中に残り、範囲外の solve が Score に乗り続け、`0003:461-464` の禁止が続く。
- **証明 A 読む段の custom rule 1 本【推奨】** — 10 の flag ファイル (master.key、完全一致) を読む段の技法に専用の rule を足し、`requireExpectedRuleFire` で要求する。コスト: allowlist 1 行 +
  platform customRules 1 本 + 両リポ同時 PR (ADR-0017 と同型)。gate と `Sweep` は既にこの条件を通る (`scoring.go:677-679`)。リスク: 証明の発火と届いた値は結び付かない。
  可逆 (catalog の 1 行)。閾値: epoch とセットのときだけ「開始後に実演された」と言える。
- **証明 B 持ち出す段の rule** — 不採用。「騒がしい道具を使わなかった」という負の性質は rule で証明できず、submit も collector を通るのでノイズが大きい。持ち出す段は禁止ルールに任せる。
- **証明 C 既存の expected rule の流用** — 不採用。対象ファイルが違い、記録が attempt に依存しないので効果が無い。
- **証明 D receipt 側の nonce** — 不採用 (D10)。collector は body を素通しするので無改修で通る (`collector.go:227-242`) が、実体は epoch の実装形の 1 つである。

## Decision

**錨は (i)、証明は A。証明の記録は全 evade で attempt スコープにする (05 も揃える)。nonce は採らない。** 理由: 「attempt = 参加者が明示的に始めた 1 回の交戦」を証跡の唯一の単位にすれば、
順序・`current`・時間のどれにも依存せずに gate を定義でき、不変条件を例外なしで書ける。

- **D1 attempt は参加者ごとに高々 1 つ。** 新表 `evade_attempt (user PRIMARY KEY, challenge, epoch, started_at)`。主キーが user なので「同時に active な attempt は 1 つ」は schema の事実になる。
  `active(u)` := 行があり、その `challenge` が catalog の evade で未 solve (solve は attempt を終える。追加の書き込みは要らない)。**epoch は user 単位で単調増加し、再利用しない**
  (新しい epoch = その user の `evade_attempt` と証跡 3 表の最大 epoch + 1)。課題ごとに独立した attempt は採らない: soundness は同等だが、放置された attempt が別の作業で taint され続け、
  「active = いま取り組んでいる相手」が崩れる (ADR-0003 Signpost 4 が問題にした作業単位とのずれ)。順序外に複数の evade を進める人は切り替えのたびに開始し直す。失うのは切り替え前の
  証跡だけで、ヒントの開封 (ADR-0027) は attempt を要求せず、attempt に影響しない。
- **D2 証跡 3 表に epoch を持たせる (migration #2、additive)。** `exfil`・`evade_dirty`・`expected_rule_fire` に `epoch INTEGER NOT NULL DEFAULT 0` を足す (`migrations.go:43-47,62-125`、ADR-0020。
  `docs/db-schema.md:318-325` に行を足す)。有効な epoch は 1 から。**既存行は epoch 0 のまま、どの attempt にも属さない (数えない)。** 既存の taint も数えないが、開始しない限り solve
  しないので緩まない。規律: (a) epoch の解決と行の書き込みは store の 1 つの臨界区間で行う (b) `evade_dirty` と `expected_rule_fire` の `INSERT OR IGNORE` (`store.go:696,756`) は、同じ rule が
  前の epoch に残っていると新しい epoch の発火を捨てる (false-clean) ので、epoch を更新する upsert に変える (c) in-memory の写しは現 epoch の行だけを持ち (`loadFromDB` が
  `evade_attempt` と突き合わせる)、読み手ごとに epoch を比べない (d) gate は taint・証明・receipt を 1 回のスナップショットで読む (e) admin の `Reset` は証跡 3 表を先に、`evade_attempt` を最後に消す。
- **D3 開始ルート `POST /api/users/{user}/challenges/{cid}/attempt`。** `x-ctf-audience: participant` / `x-ctf-authz: self-or-admin-write` / `x-ctf-origin-guard: true` / `x-ctf-collector-forward: false` /
  `x-ctf-rate-limit`: identity キーの bucket (reset-dirty も per-IP の共有 bucket からこちらへ移す。空キーを返さない board の形: `api.go:754-771`。会場 NAT 下で他人のヒント開封に開始を
  止めさせない: `0027:110-112`)。ingress は `/api/users/` Prefix で到達済み (`charts/scoreboard/templates/ingress-journey.yaml:183-184`)。**collector の forward に足さない** (claimed identity で
  他人の attempt を切り替えられる。reset-dirty と同じ理由: `api.go:580-590`)。body は任意の `{"abandon": "<cid>"}`、応答は 200 `AttemptResult {ok, user, cid, started, abandoned}`。
  同じ課題が active → 何も変えず `started: false` (**二重開始は冪等で、証跡は残る**)。active が無い → 新しい epoch で `started: true`。別の課題が active → `abandon` がその課題を名指しして
  いれば切り替え、そうでなければ **409** (古い画面の誤操作で他の課題の証跡を消さない)。400 = evade でない・不正な user / body、403 = origin・他人、404 = 未知の課題、409 = solve 済み、
  500 は定数文言。閲覧 (`?mission=`) は attempt を始めない。
- **D4 数えるのは active な attempt の間に記録されたものだけ。** `OnRuleFire(u, r)`: `a := active(u)`。`r` が `a.challenge` の `forbiddenRules` にあれば taint を、`requireExpectedRuleFire` の
  `expectedRules` にあれば証明を、epoch `a.epoch` で記録し、その後に trigger を評価する。**trigger の solve は attempt の外のまま** (`scoring.go:359-363,372-392`)。単一の公開入口は維持する
  (ADR-0003 A4)。「taint → trigger の順」は `current` が錨でなくなるので規範から外す。receipt は `active(u).challenge == cid` のときだけ保存し、そうでなければ保存せず
  200 `{"received": false, …}` を返す (`ExfilStatus` に `ExfilNoActiveAttempt`。応答のキー集合は不変)。**開始前の発火・証明・receipt は数えない。**
- **D5 gate は 1 箇所のまま (`evaluateClean`)。** gate 3 (flag 一致) の後: solve 済みなら `EvadeSolved{Newly: false}` (solved は終端) → `active(u).challenge != c` なら **`EvadeNotStarted`**
  (新設。宣言順 = gate 順の慣行に従い `EvadeWrongFlag` の次: `scoring.go:582-585`) → taint → 証明 → receipt → `MarkSolved`。`Sweep` と手動 submit は同じ関数を通るので判定は一致する
  (`scoring.go:642-647,900`)。submit の応答は 200 `{"correct": true, "started": false, "reason": …}` (`SubmitFlagVerdict` に `started` を additive、metrics の outcome に `not_started`)。
- **D6 reset = 新しい epoch。** `reset-dirty` の path は変えない。その課題が active なら epoch を進め (taint・receipt・証明が一括で無効になる)、active のまま続ける。active でなければ何もしない
  (200、冪等)。別の課題の attempt には触れない。epoch の更新は 1 行の更新なので、ADR-0003 F1 の「片方だけ消える」状態は構造上起きない。時間経過・再読込・再接続は reset 条件にせず、
  猶予窓も入れない (`0003:279-282`)。
- **D7 採点は order を消費しなくなる。** `Grader.WithOrder` / `currentMission` (`scoring.go:265-268,299-307`、`internal/scoreboard/server.go:220`) を撤去し、`CurrentMission` は journey の投影だけが使う。
  `status` (`solved | current | locked`) は案内であり、採点上の意味を持たない (ADR-0027 D2 と整合)。
- **D8 投影と P28-1 の UI 契約。** `Journey` に `attempt` (active な課題の id または null。`current` と同じ形: `docs/openapi-scoreboard.yaml:2470`)、`MissionDetail` に `alert` (open string。`idle` = この課題に
  active な attempt が無い / `clean` = active で禁止発火の記録なし / `spotted` = active で記録あり。未知値は `idle` として描く) を additive で足す (P28 architect §2 の `alert` の前倒し)。`dirty`・
  `dirtyRules`・`exfilReceived`・`expectedRuleFired` は「active な attempt の」値になる。portal は戦闘状態を `status` から推論せず `alert` / `attempt` だけを使い、`idle` の evade に「クリーン」を
  出さない。開始操作 (P28 の「たたかう」) はこの route そのもので、装飾としても自動でも呼ばない。やり直しと切り替えは確認を挟み「receipt と証明も消える」と明示する。
  `relation` は「その発火が attempt の taint / 証明として記録されたか」から導く。
- **D9 積極証明。** (a) **10**: 読む段の rule を `expectedRules` に置き `requireExpectedRuleFire: true` にする。rule 名は `challenges/custom-falco-rules.txt` に 1 行、condition は platform の
  `customRules` (設計と「どの読み方で成立 / 不成立か」は private 正典)。持ち出す段は証明の対象にしない。(b) **記録は attempt スコープ**: D4 のとおり active な attempt にだけ記録し、
  reset と切り替えで無効になる。(c) **05 も揃える**: ADR-0008 は「reset 後に再証明させる利益は無い」とした (`0008:355-363`) が、錨が `current` だった時の判断である。開始が明示操作に
  なると、証明が attempt の外で成立する限り「開始 → 覚えていた値を提出」で、禁止ルールの gate に一度も試されずに通る。揃えれば全 evade で「1 回の attempt の中で技法が実演された」と
  同じ文で言え、課題ごとの指定 (`0008:442-445`) を持たずに済む。content-engineer の推奨は「10 だけ」(Advice)。(d) **deploy は platform が先・app が後** (逆順は 10 が解けなくなる。
  05 と同じ softlock: 契約表 Falco custom rule 行)。(e) 実機の fire / no-fire が済むまで「検証済み」と書かない。(f) rule 名は他課題と共有しない
  (`TestExpectedRuleFire_NewRuleNameUniqueToMission05` と同型を 10 に足す)。
- **D10 nonce は採らない。** attempt への帰属は、サーバが受信時に押す epoch で足りる。nonce が加えるのは「receipt の送り主が portal を見られる本人である」ことの証明で、これは claimed
  identity の問題であり attempt の問題ではない。値が静的である限り「事前に得た値」は nonce でも区別できず、参加者に手で写させる手順と exfil の body 契約の変更に見合わない。
  attempt ごとに値を変える案は、flag を 1 イベント 1 ファイルで 2 つの消費者に配る契約 (ADR-0033) と plant の経路 (ADR-0001 / I12) の作り直しになるので、本 ADR では扱わない (Signpost 3)。
- **D11 観測。** counter (label は challenge と種別だけ。user を label にしない): attempt の開始 / やり直し / 切り替え、数えなかった receipt、`SubmissionsTotal{outcome="not_started"}`。
  `dirty_reset` の監査ログ (`api.go:1621`) に epoch を足す。

### I11 の新しい文言 (案。表の書き換えは採点の実装 PR と同じ PR で行い、それまで現行の行が有効)

> **I11**: evade 課題の solve は、参加者本人が明示的に開始した attempt の証跡だけで判定する。(a) attempt は開始ルート (origin-guard + self-or-admin-write、collector は forward しない) で
> だけ始まり、参加者ごとに同時に active なのは高々 1 つ。(b) 禁止ルールの taint・`requireExpectedRuleFire` の証明・`requireExfil` の receipt は、active な attempt の epoch で記録された
> ものだけを数える。attempt が active でない間の記録と、epoch を持たない既存行は数えない。(c) active な attempt の無い evade は solve しない。`Sweep` と手動 submit は同じ
> `evaluateClean` を通る。(d) reset と別課題の開始は新しい epoch を始め、taint・証明・receipt を一括で無効にする。epoch は再利用しない。(e) 判定に経過時間を用いない (窓・猶予・期限・
> タイムアウトを導入しない)。(f) 全ての rule fire は単一の Grader 入口を通る。trigger の solve は attempt にも順序にも依存しない。

現行の行 (`.claude/rules/falco-ctf-app-conventions.md:33`) の「taint は先行 trigger の必須発火との交差を持つ場合にのみ生じ」は ADR-0003 A1 の規則と一致していない (交差は attempt スコープが
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
- **残余 1 — 事前に得た値を開始後に持ち出す**: 値は静的で課題ごとに 1 つなので、開始前に得た値や他の参加者から得た値を開始後に届けることは区別できない。証明が言うのは
  「開始後に技法が実演された」ことだけで、**証明の発火と届いた値は結び付かない** (技法を 1 回実演し、覚えていた値を送れる)。技法は実演されているので受容する、が
  content-engineer の判断。受容そのものは CEO 判断。
- **残余 2 — 積極証明を持たない evade (現状 03)**: 開始前の発火は回数を問わず数えない (W1 の一般化)。開始後に値を提出するだけで gate を通る。正規順で 02 の後に 03 が `current` になると
  禁止発火が taint になる、という現行の実務上の効き目は、開始前の操作には働かなくなる。ADR-0003 C5 (`0003:86-102`) のとおり、閉じるのは積極証明だけである。03 に証明を足せるかの
  調査 (content + security) を別件として要求する。
- **残余 3 — 到着順**: 判定はイベントの到着順で行う。開始の直前に起きた発火が開始の後に届くと taint になる (厳格側。やり直しで回復する)。solve の後に届いた発火は効かない
  (既存。`0003:542-546` と同じ扱い)。
- **`0003:461-464` の禁止を解除できる条件 (課題ごと)**: ① D1〜D8 が main に入り、Verification ①〜⑨ が required check で green ② その課題が attempt スコープの積極証明を持ち、rule の
  fire / no-fire が実機で確認済み ③ 開始操作つきの E2E (d′) が green ④ 残余 1 を CEO が受容。満たした課題に限り「1 回の attempt の中で、禁止ルールが発火せず、技法が実演され、
  (requireExfil なら) 値が届いた」と書ける。「その値を技法で読んだ」「独力で解いた」とは書かない。03 は ② を満たさないので解除しない。10 の証明だけを epoch より先に入れた状態は
  部分的な縮小で、解除しない。
- **参加者向けの文面** (content。ADR-0003 F2 の再発防止): 03・05・10 の README / journey / welcome、HANDBOOK、submit と exfil の応答文 (`api.go:1120-1126,1412-1413`) が「開始してから
  操作する。開始前の操作・receipt・証明は数えない」を言うこと。
- **切り戻しは無い**: migration #2 を適用した DB は旧イメージで開けない。go / no-go は stand-up の前に、リハーサルの結果で決める。
- **P28**: architect §8 の `inScope` は、本 ADR の landing 後は「attempt の gate を通った solve」と同義になる。ADR-0029 / 0030 はこの定義で書く。

## 段階と期限

| 段階 | 内容 | 担当 | Class | security |
|---|---|---|---|---|
| S1 | 10 の証明 rule を platform の `customRules` に足す (app より先に deploy) | content (condition) → platform | 2 (クロスリポ) | 必須 |
| S2 | allowlist 1 行、10 の `expectedRules` + `requireExpectedRuleFire`、契約表の行、参加者向けの文面 | content、architect (契約表) | 2 | 必須 |
| S3a | migration #2 と store (表・列・upsert・スナップショット・`Reset` の順)。挙動は変えない | software | 2 | 必須 (ADR-0020) |
| S3b | scoring・api・spec・`make gen`・I11 の表の書き換え・テスト | software、architect (spec・I11) | 2 | 必須 |
| S4 | portal の開始導線・`alert` 表示・確認 | application (文言は product / content) | 1 (S3b と同じリリース) | 必須 |
| S5 | 実機: rule の fire / no-fire、E2E (d′)、platform の E2E 計画の更新 | qa、platform、sre | — (stand-up は CEO 承認) | — |

- **S3b と S4 は同じイメージで出す** (I5)。開始導線の無いまま S3b だけが出ると、どの evade も解けなくなる (ADR-0003 F3 と同じ失敗)。
- **期限**: 次回イベントの stand-up で使う app の SHA を固定する時点までに S1〜S4 が merge 済みで、S5 がリハーサルで green。
- **間に合わない回の退避** (CEO が go / no-go で選ぶ): F1 = 受容する (何も入れない) / F2 = (i') を入れる / F3 = 10 の証明だけを ADR-0008 の意味論で入れる (部分的な縮小)。architect の推奨:
  P28-0b がその回のリリースに入るなら F2 + F3、入らないなら F1 でよい。(i') は `current` を gate の消費者にするので、(i) の landing と同時に撤去する。**手順**: VP が対象イベントを
  名指しした受容の Issue を起票 → CEO が Issue 上で受容または退避を明示 → platform のそのイベントの go / no-go 記録からリンク → その回は `0003:461-464` を維持 → 次の期限を置き直す。

## Signposts (この決定を覆す観測可能な信号)

数値は仮 (基準データ未取得)。1・3・4 は D11 の counter と監査ログ、2 は `evade_attempt.started_at` と発火の履歴から事後に測る。
1. **開始を忘れた操作の常態化**: `not_started` の submit と数えなかった receipt が 1 イベントで evade の提出全体の 20% を超える、または運営への同種の問い合わせが 5 件を超える →
   開始の導線を作り直す。自動開始に戻すなら錨が二重になるので新 ADR。
2. **証明のない evade が名目だけになる**: 03 の solve のうち、開始から solve までに本人の発火が 1 件も無いものが半数を超える → 03 に積極証明を足すか、03 を「gate のない導入」と明示する。
3. **値の持ち込み**: 10 の solve のうち、その attempt で receipt が証明の発火より先に届いたものが 3 割を超える、または値の共有が運営で観測される → 値を attempt か参加者に結び付ける
   設計 (flags 契約と plant 経路の変更。別 ADR)。
4. **1 つだけの active が実害になる**: 同じ参加者が 2 つの evade の間を 3 往復以上する例が 1 イベントで 5 人を超える → 課題ごとの attempt に変える (`evade_attempt` の主キーを変える migration)。

## Verification

すべて**未実装**。①〜⑨ は qa-engineer の骨子に対応する。採点の実装 PR は、各テストが変更前の tree で red になる出力を本文に貼る (`make test` = required check)。

- ① W2 の閉塞 (実 catalog): `TestAttempt_W2_BossNotSolved_CurrentPinnedAt03` / `…_CurrentPinnedAt05` — 10 の禁止発火と receipt があっても Sweep も手動 submit も solve しない。
  開始してから同じことをすると taint で止まる。② receipt: `TestAttempt_ReceiptBeforeStart_NotCounted` / `TestAttempt_ReceiptAfterStart_Counts`。
- ③ taint と reset: `TestAttempt_ForbiddenFireDuringAttempt_Taints` / `TestAttempt_Restart_InvalidatesTaintReceiptAndProof` / `TestAttempt_SweepAndSubmit_SameVerdictInEveryState`
  (idle・clean・spotted・証明なし・receipt なし・完了の各状態で両経路の判定が一致)。
- ④ 正規の 01 → 10: `TestOnRuleFire_RealCatalog_AttemptScope_TwinMissionsStayClean` (名前を保ち、各 evade の前に開始を挟む) / `TestOnRuleFire_RealCatalog_WithoutStart_NoEvadeSolves`。
- ⑤ 証明: `TestAttempt_Proof_CleanButNoProofFire_NotSolved` / `TestAttempt_Proof_FiredBeforeStart_NotCounted` / `TestAttempt_Proof_FiredAfterStart_Counts`。ADR-0008 のテストは消さずに反転する:
  `TestOnRuleFire_ExpectedRuleFire_NotAttemptScoped` → `…_AttemptScoped`、`TestResetDirty_NeverClearsExpectedRuleFire` → `TestResetDirty_InvalidatesExpectedRuleFire` (旧名と理由を doc comment に残す)。
- ⑥ 時間と trigger: `TestAttempt_VerdictIgnoresClock` (各操作の間で時計を任意に進めても判定が同じ) / `TestOnRuleFire_TriggerSolves_WithoutAttempt`。既存の
  `TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance`・`TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved` を維持する。
- ⑦ 永続化: `TestAttempt_SurvivesStoreRestart` / `TestMigrate_V2_LegacyEvidenceRows_NeverCount` (epoch の無い exfil・dirty・証明の行は開始後も数えない) / `TestMarkDirty_SameRuleInNewEpoch_TaintsAgain`
  (D2 (b)) / `TestAttempt_EpochNeverReused` (切り替え・やり直し・admin reset をまたぐ) / `TestAttemptRestart_FailureLeavesEvidenceIntact` (`TestResetDirty_TransactionRollsBackOnPartialFailure` の後継)。
- ⑧ 開始ルート: `TestAttemptStart_OtherUser403_RecordsNothing` / `TestAttemptStart_SameChallengeTwice_KeepsEvidence` / `TestAttemptStart_OtherActive_409UnlessAbandonNamed` /
  `TestAttemptStart_SolvedChallenge_409` / `TestAPISpec_V4_AttemptNeverForwarded`。既存の `TestOriginGuard_AllProtectedRoutesEnforced`・`TestAuthz_AllDeclaredGatesEnforced`・
  `TestAPISpec_V1_RouteSetMatchesSpec`・collector の `TestDefaultDeny_BlockedRoutes` が新 route を含めて green (I14)。応答のキー集合は ADR-0009 の V5 に登録する。
- ⑨ 投影: `TestJourney_Alert_UnstartedEvadeIsIdle` / `TestLeaderboard_Golden_CanonicalOrder_SameAsBefore` (正規順は前後で一致) / `TestLeaderboard_Golden_OutOfScopeSolve_Dropped`
  (範囲外 solve が載らなくなる差分を golden に明示)。
- **実機でだけ確認できるもの**: (a) 10 の証明 rule の fire / no-fire と DaemonSet の読み込み (ADR-0008 (a-1)・ADR-0017 (a-2)(a-3) と同型。結果は private 正典に記録) (b) 開始 → auto-solve の
  観測 → 手動 submit の E2E (d′) (c) deploy 経路が新しい rule を発火させないこと (I13b の対象 +1)。
- **I11 の表を書き換える条件**: ①〜⑨ が main に入り、本 ADR が Accepted。(a)(b) が済むまで「検証済み」「実効的」と書かない。

## Advice

- content-engineer (2026-10-05、実現性調査): A を推奨。B・C は不採用、D は epoch の実装形の 1 つ。記録は「10 に限り」attempt スコープとし、ADR-0008 の「課題個別に」に従う、が推奨だった。
  **architect は 05 も揃えた** (D9 (c))。VP / CEO の判断に付す。未確認: A の condition の実機 fire / no-fire。
- qa-engineer (2026-10-04 / 05): W2 と、非 current の evade が taint されない件の再現。回帰テストの骨子 9 点 (Verification ①〜⑨)。
- VP / 前回の architect 契約設計 (workspace `REFACTORING.md` P28 §8・§10): 「開始前の receipt は無効」「同時に active な attempt は 1 つ」、P28-1 で先に守る契約。
- security-engineer: **未取得**。必ず見せる箇所 — migration #2 と epoch の非再利用 (D1・D2)、開始ルートの origin-guard・非 forward・identity キーの rate-limit (D3)、claimed identity の経路の
  応答 (`received: false`・`started: false`) が他人の attempt 状態を返す点 (D4・D5)、custom rule と deploy 順序 (D9)。
- 未検証の前提: 開始直前の発火が開始後に届く頻度、開始を忘れる頻度、次回イベントの日付、flag を参加者別にする予定の有無 (現状は課題ごとに 1 つ)。
