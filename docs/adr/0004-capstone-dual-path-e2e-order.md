# ADR-0004: capstone (mission 10) の両経路は「auto-solve を観測してから手動 submit」の順で E2E 検証する

- Status: Proposed
- Date / Deciders: 2026-08-19 / architect (起草・解釈判定) + VP (承認) + qa-engineer (E2E 計画側) + CEO (merge)
- 関連: **ADR-0003 (Accepted) の `## Verification (d)` を部分 supersede する** (下記「supersede の範囲」)、
  ADR-0001 (Accepted。`## Verification` layer 4 が (d) と同一 E2E run に相乗りする)、
  qa-engineer の E2E 計画 `falco-ctf-platform` branch `docs/adr-e2e-plan` = `83c2940`
  (`docs/PROD-GATE-E2E-PLAN.md` §4 Phase 5 step 9 / §11)、Issue #121 (evade の積極証明)
- フェーズ: 本番投入前 gate (P## 非該当)

## supersede の範囲 (先に明示する)

**本 ADR は ADR-0003 の `## Verification (d)` の但し書き 1 項目のみを置き換える。**
ADR-0003 の Decision (attempt スコープ = Option 2)・A1-A8・Consequences・Signposts・
Verification (a)(b)(c)(e)・I11 昇格条件は **すべてそのまま有効**である。

**ADR-0003 の本文は 1 文字も変更しない** —— 同 ADR は Accepted であり、
自身が「以後の変更は本 ADR を書き換えず、supersede する新 ADR で行う」と定めている
(`docs/adr/0003-evade-clean-gate-attempt-scope.md:12-13`)。ADR-0001 も Accepted である
(`docs/adr/0001-flag-plant-initcontainer-not-challenge-env.md:3`) ため同様に編集しない。

> **読者への導線 (VP へ申し送り)**: ADR-0003 (d) を読んだ人が本 ADR に到達する導線が
> **現状は無い** (両リポに ADR 索引が無い)。理想は ADR-0003 に 1 行の相互参照を足すことだが、
> **Accepted ADR の編集は VP / CEO の判断**なので本 ADR では行わない。
> 代替として **(i) E2E 計画 (`docs/PROD-GATE-E2E-PLAN.md`) が本 ADR を引く**、
> **(ii) PR 本文で相互リンクする**、の 2 本で担保する。

## Context

### C1. 争点

ADR-0003 (d) の現物 (`docs/adr/0003-evade-clean-gate-attempt-scope.md:610-619`):

> **正規順に 01, 02, 04, 06, 07, 08, 09 をクリアした後、手動 reset なしで 03 / 05 / 10 が
> submit / auto-solve 可能であること。**
> - **10 は auto-solve 経路 (exfil → Sweeper) と手動 submit の両方**を確認する
>   (両者は `evaluateClean` を共有するが、**共有が壊れていないことを確認するのが目的**)

qa-engineer の E2E 計画は、**手動 submit を 03 / 05 で代替**し **10 では auto-solve のみ**を
確認する判断を採り、qa / architect の同意待ちに置いた。理由は「10 で 2 回起こすのを避ける」。

VP の見立ては「**要求を満たしていない**」。architect も同じ結論に至ったが、
**却下の理由と、代わりに採るべき手順は VP の候補 (α)(γ) とは違う** —— reset は 1 回も要らない。

### C2. 実コードで確認した事実 (すべて `main` = `0aa634e` 基準)

| # | 事実 | 根拠 |
|---|---|---|
| 1 | **gates 4-6 (dirty → exfil → MarkSolved) は 1 関数に集約**され、呼び出しは 2 箇所だけ | `internal/scoreboard/scoring/scoring.go:572` (`evaluateClean`)、呼び出しは `:552` (`SubmitEvade`) と `:797` (`Sweep`) |
| 2 | **gate 3 (flag 一致) は共有されていない。2 箇所に *二重実装* されている** | `SubmitEvade` = `scoring.go:545` (`flag != ch.ExpectedFlag`)、`Sweep` = 同 `:794` (`r.Flag != ch.ExpectedFlag`) |
| 3 | **`Sweep` は `RequireExfil` でない evade を skip する** → **03 / 05 は原理的に Sweeper 経路に入らない** | 同 `:791-793`。`requireExfil` を持つのは **10 だけ** (`challenges/10-final-exfil/falco-rule.yaml:17`。03 / 05 の `falco-rule.yaml` に該当行なし = architect 実測) |
| 4 | **`PendingExfilSolves` は solved 済ペアを skip する** → **手動 submit を先にやると Sweeper は以後何も enqueue しない** | `internal/store/store.go:611-613` |
| 5 | **`submit` ハンドラに「既に solved」の短絡は無い。** auto-solve 済でも gates 1-6 を全通過し `EvadeSolved` / `Newly=false` を返す | `internal/scoreboard/api/api.go:598-724` (early return は unknown challenge / not evade / bad body / user 空 / store error のみ)。`MarkSolved` は first-write-wins (`internal/store/store.go:513`) |
| 6 | その応答は **HTTP 200 + `{"correct":true,"evaded":true,"solved":true,…}`**、audit は `outcome=solved newly=false`、metrics は **`SubmissionsTotal{solved}` のみ +1 で `SolvesTotal` は増えない** | `internal/scoreboard/api/api.go:711-723` |
| 7 | **`reset-dirty` では `solved` は戻らない** (`evade_dirty` と `exfil` のみ削除) | `internal/store/store.go:800-832` |
| 8 | **`solved` を消せるのは `POST /api/admin/reset` = `Store.Reset()` だけで、`WHERE` 句が無い = 全 user 一括** | `internal/scoreboard/api/api.go:274` → `internal/store/store.go:877-891` |
| 9 | Sweeper の cadence は **5 秒**、`Run` は **入場時に即 1 回 sweep する** | `scoring.go:836` (`DefaultSweepCadence`)、`:843-` (`Run`) |
| 10 | **【最重要】「共有が壊れていないこと」は既に unit test が両順序で pin している** | `TestSweep_ManualAndSweeperShareVerdict` (`internal/scoreboard/scoring/scoring_test.go:764-803`): sweeper 先行 → 手動が `EvadeSolved && !Newly` / 手動先行 → sweeper が何も拾わない、を assert。加えて `TestSweep_AlreadySolved_Idempotent` (同 `:911`) |

### C3. したがって (d) の但し書きは「理由」を間違えている

事実 10 のとおり、**`evaluateClean` の共有健全性は in-process の unit test で既に pin 済**である。
実クラスタで 2 回動かして確認する対象ではない (単一プロセス内の関数共有は
**Go の呼び出しグラフとして静的に決まる**ので、クラスタでしか壊れる余地が無い)。

**一方で、クラスタでしか確認できないものは別に 3 つある**:

1. **配送パイプラインが 2 本あり、共有点より *前* が完全に別物である** ——
   手動 = participant → collector `POST /api/challenges/{cid}/submit` → scoreboard `/submit`。
   auto = participant → collector `POST /api/challenges/{cid}/exfil` → collector が
   scoreboard 内部 sink に書き換え → `RecordExfil` → `exfil` テーブル → **Sweeper goroutine**。
   egress lockdown (P11.5) / collector の route 集合 / origin-guard / NetworkPolicy は
   **この 2 本で別々に効く**。
2. **二重実装された gate 3 が両方で一致すること** (事実 2)。ここは C2 (仕込み側 `CTF_FLAG_*` と
   採点側 `FLAGS_FILE` が同一 `flags.sops.yaml` から render される)
   が**独立に 2 回**効く場所であり、片方だけ食い違う事故は実配線でしか出ない。
3. **Sweeper が prod で実際に回っていること** (goroutine の起動漏れ / SIGTERM で止まったまま /
   cadence 設定ミス)。unit test は `Sweep()` を直接呼ぶので、**配線の有無を見ない**。

→ **(d) の要求 (10 で両経路) は維持すべきだが、理由は書き換えるべきである。**

### C4. 「10 で 2 回起こす」は高くない —— reset は 1 回も要らない

事実 4 + 5 の組み合わせが答えである:

- **手動 → auto の順は不可能** (事実 4: solved 済は enqueue されない)。
- **auto → 手動の順は可能で、しかも手動側は gates 1-6 を全通過する** (事実 5)。
  `Newly=false` になるだけで、**gate 3 (flag 一致) / gate 4 (taint) / gate 5 (`HasExfil`) /
  gate 6 (`MarkSolved`) はすべて実行される**。receipt は solve 時に削除されないので
  gate 5 も通る (`HasExfil` = `internal/store/store.go:563-568`)。
- したがって **順序を固定するだけで両経路が 1 回の進行で観測でき、reset は不要**。
  これは事実 10 の unit test が期待動作として encode している挙動そのものである
  (`scoring_test.go:775-786`)。

**ただし自然な参加者フロー (exfil → 即 submit) は race である**: cadence 5 秒 (事実 9) の間に
submit が届けば手動が先に solved を書き、**以後 Sweeper は何も拾わない** (事実 4)。
→ **順序を固定しない E2E は「どちらかの経路を観測しないまま green になる」** ので、
計画は**待って順序を確定させる**必要がある。ここが本 ADR の実務上の中身である。

## Options

### Option 1 — qa 案: 手動 submit を 03 / 05 で代替し、10 は auto-solve のみ

- 変更点: (d) の但し書きを実質的に「10 は auto のみ」に読み替える。
- コスト: **ゼロ** (計画は既にこの形)。
- リスクと可逆性: 可逆。ただし **10 の 2 本目のパイプライン (手動 submit) を
  capstone に対して 1 度も通さない**。事実 3 より 03 / 05 は Sweeper 経路に入らないので、
  **「同じ verdict に 2 経路から到達する」ことは *どの mission でも* 確認されない**。
  さらに事実 2 の二重 gate 3 のうち **`Sweep` 側しか通らない** ため、
  「参加者が打った flag 文字列」と「収集器に届いた flag」の一致は capstone で未検証のまま残る。
- 効き始める閾値: 「10 の手動 submit が別の試験で毎回通る」なら許容できる。
  **現状そういう試験は無い** (計画は capstone を auto のみで閉じる)。

→ **却下。** 理由は「(d) にそう書いてあるから」ではなく、**上記の 2 つの穴が実配線由来で、
`test1` 1 本の E2E がそれを見る唯一の機会だから**である。

### Option 2 — VP (α): Phase 5 を手動 submit まで進め、global reset して 10 だけ auto-solve をやり直す

- 変更点: Phase 5 の途中に `POST /api/admin/reset` を 1 回追加。
- コスト: **高い。** 事実 8 のとおり reset は全 user 一括なので、**その時点までに測った
  すべての採点状態が消える** (ADR-0001 layer 4 の delta 観測、Phase 2-4 の測定値を含む)。
  計画の phase 順を組み替える必要がある。
- リスクと可逆性: 可逆だが、**「E2E の途中で採点状態を全消しする」手順は再実行時に
  順序依存のバグを埋める** (どの測定がどの reset の前後かを人間が追う必要がある)。
- 効き始める閾値: 事実 5 が変わったとき (submit に「既に solved」の短絡が入ったとき) のみ必要になる。

→ **却下。** C4 のとおり **reset そのものが不要**なので、コストを払う理由が無い。

### Option 3 — VP (γ): `Store.ResetUser` (ADR-0001 DoD 17) を先に実装して per-user で 10 を戻す

- 変更点: 実装 1 本 (per-user reset) + E2E に reset 呼び出し。
- コスト: 中。ADR-0001 DoD 17 は **「4-7 を本番開始後に実行する必要が生じた時点」の条件付き**で
  起票されており、**本番前に走る E2E のためには条件が成立しない**。
  merge 前に実装を前倒しする根拠にならない。
- リスクと可逆性: 実装が増える = gate が伸びる。
- 効き始める閾値: **本番中に `test1` を汚す probe を打つ必要が出たとき** (= DoD 17 の本来の条件)。

→ **却下 (今は不要)。** DoD 17 の位置づけは変えない。

### Option 4 — (β): 両経路の確認を (d) から外し、unit / 統合テストに委ねる

- 変更点: (d) の但し書きを削除し、`TestSweep_ManualAndSweeperShareVerdict` を「消さないこと」と規定。
- コスト: ゼロ。
- リスクと可逆性: **C3 の 3 点 (2 本のパイプライン / 二重 gate 3 / Sweeper の prod 稼働) が
  どの層にも残らない。** とくに 3 は「Sweeper が動いていない prod」を green で通すので
  **capstone が誰にも auto-solve されないまま本番に入る**。
- 効き始める閾値: Sweeper の稼働を別の手段 (readiness / metrics / ログ) で常時監視できるなら、
  (d) から外してよい。**現状その監視は無い** (`SolvesTotal{…,"evade"}` は solve が起きた後にしか動かない)。

→ **却下。ただし「共有の pin は unit で足りる」という指摘自体は正しい**ので、
**(d) の *理由* の書き換えとして取り込む** (Decision)。

### Option 5 — 順序固定: exfil → **auto-solve を観測** → 同一 flag で手動 submit 【採用】

- 変更点: **E2E の手順だけ。** reset なし・phase 追加なし・実装なし。
- コスト: **待ち時間のみ** (cadence 5 秒 = 事実 9。上限は下記 Verification で 3 tick 相当)。
- リスクと可逆性: 完全に可逆 (手順の 1 行)。
- 効き始める閾値: 事実 4 または事実 5 が変わったら破綻する → Signpost 3 / 4。

## Decision

**Option 5 を採る。ADR-0003 (d) の但し書きを次の (d′) に置き換える。**

> **(d′) mission 10 は、次の順序で *両経路* を 1 回の正規進行の中で確認する
> (手動 reset・admin reset は使わない)**:
>
> 1. 10 の flag を取得し、**collector へ exfil する**
> 2. **auto-solve が記録されるのを待って観測する** (Sweeper 経路。`solved` に入ったことを確認)
> 3. **同じ flag を手動 submit する** → `solved:true` かつ **`newly=false`** を確認
>
> **逆順 (手動 submit → exfil) は禁止**。`PendingExfilSolves` が solved 済ペアを skip するため
> (`internal/store/store.go:611-613`)、**auto 経路が一度も走らないまま green になる**。
> **自然な参加者フロー (exfil → 即 submit) も race なので、E2E は 2 を待って順序を確定させる。**
>
> **目的 (ADR-0003 の但し書きから差し替える)**: `evaluateClean` の共有確認**ではない**
> (それは `TestSweep_ManualAndSweeperShareVerdict` = `internal/scoreboard/scoring/scoring_test.go:764-803`
> が両順序で pin 済)。実機で確認するのは次の 3 つである:
> **(i) 共有点より前が完全に別物である 2 本の配送パイプライン** (collector の 2 route /
> 内部 sink / Sweeper goroutine / egress lockdown・origin-guard が別々に効く)、
> **(ii) `evaluateClean` の外に二重実装された gate 3 (flag 一致) が両経路で一致すること**
> (`scoring.go:545` と `:794`。C2 = フラグ単一ソースが独立に 2 回効く点)、
> **(iii) Sweeper が prod で実際に回っていること** (unit test は `Sweep()` を直接呼ぶので配線を見ない)。

**03 / 05 は (d) のまま「手動 submit で solve すること」を確認する** ——
ただし **10 の手動経路の代替にはならない** (事実 3: `requireExfil` を持たないので
Sweeper 経路に入らず、二重 gate 3 の `Sweep` 側も通らない)。

## Consequences

### 諦めたもの

- **10 の手動 submit 側で `newly=true` を観測することは諦める。** `newly` は
  `MarkSolved` の first-write-wins (`internal/store/store.go:513`) であり、
  **同一 run の auto 側で `newly=true` として観測される**。03 / 05 でも手動 `newly=true` を観測する。
  → **どの経路でも一度も観測されない値は無い。**
- **「両経路が独立に solve を *記録* できる」ことは実機では確認しない** (記録は先着 1 回だけ)。
  これは単一 writer の設計 (I1: replicas 1) の帰結であり、unit test が担当する領域。

### 新たに守る不変条件

**無し。** 本 ADR は Verification の手順規範のみを変える。
**I11 (attempt スコープ) / I12 (フラグ隔離) / I13a・I13b (deploy 経路の無汚染) に影響しない。**

### E2E 計画 (platform `docs/PROD-GATE-E2E-PLAN.md`) への影響

- **§4 Phase 5 step 9 を (d′) の 3 ステップに置き換える** (auto-solve 観測 → 手動 submit)。
- **§11 の「手動 submit は 03/05 で代替」の判断を撤回**し、本 ADR を根拠として引く。
- **no-go 条件に 2 件追加**:
  - **auto-solve が待ち上限内に記録されない** → Sweeper が prod で回っていない (C3 の iii)。
  - **auto-solve 後の手動 submit が `solved:true` を返さない**
    (`wrong_flag` / `not_evaded` / `not_exfiltrated` / 5xx のいずれか) →
    二重 gate 3 の不一致、または taint / receipt の実配線の齟齬 (C3 の i・ii)。
- **reset の追加は不要** (Option 2 / 3 を却下したので phase 順の組み替えも不要)。

### runbook への影響

無し。

## Signposts

この決定を覆す / 見直す**観測可能な信号**:

1. **03 または 05 に `requireExfil` が付く** (Issue #121 の積極証明が exfil 証跡を採る形になった場合)。
   → その mission が Sweeper 経路に入るので **capstone 以外で両経路を観測できるようになる**。
   (d′) の「10 で両方」を緩められるか再訪する。
2. **`submit` に「既に solved なら短絡」が入る** (事実 5 の否定)。
   → **順序固定案が壊れる**。その時点で Option 2 (global reset) か Option 3 (`ResetUser`) に戻る。
   本 ADR を supersede する。
3. **`PendingExfilSolves` が solved 済を skip しなくなる** (事実 4 の否定) →
   逆順も可能になるので順序の禁止規定を撤回できる。
4. **`Sweep` が `evaluateClean` を呼ばなくなる / gate 3 が `evaluateClean` に移る** →
   目的 (ii) が消えるので (d′) の理由を再定義する。
5. **`DefaultSweepCadence` が変わる、または Sweeper が leader election / 複数 replica になる**
   (I1 の変更) → 待ち上限の再計算と、単一 writer 前提の再検証が必要。

## Verification

**(d′) を機械で確認する形。実行主体 = qa-engineer、対象 = `test1` のみ。**

| # | 観測点 | 期待値 | 取得元 |
|---|---|---|---|
| V1 | exfil 受領 | receipt が記録される | `exfil` テーブル / journey detail の exfil 表示 (`HasExfilAny` = `internal/store/store.go:576`) |
| V2 | **auto-solve** | **待ち上限 15 秒 (cadence 5 秒 × 3 tick) 以内に 10 が solved** | admin state の `solved` / leaderboard。ポーリング間隔は 2 秒で足る (Journey UI と同じ) |
| V3 | auto-solve が **Sweeper 由来**であること | scoreboard ログに **`auto_solve user=test1 cid=10-final-exfil`** の行が出る | `internal/scoreboard/scoring/scoring.go:863` (`sweepOnce`) |
| V4 | **手動 submit (V2 の後)** | HTTP 200 + `{"correct":true,"evaded":true,"solved":true}` | collector 経由の submit 応答 |
| V5 | 同 submit が **2 重計上しない** | run 全体で **`SolvesTotal{10-final-exfil,"evade"}` の増分が 1 のまま** (手動側は `Newly=false` なので bump しない) / **`SubmissionsTotal{10-final-exfil,"solved"}` が +1** | metrics (`internal/scoreboard/api/api.go:712-715`) |
| V6 | 同 submit の audit | `outcome=solved` **`newly=false`** | scoreboard ログ (`api.go:717`) |
| V7 | 順序の逸脱検知 | **V2 より前に手動 submit を打っていない**ことを手順で保証する (打ってしまったら auto 経路は観測不能なので、その run は (d′) 未達として扱う) | 計画の手順書き |

> **⚠️ 経路の帰属は metrics では取れない。** `SolvesTotal{cid,"evade"}` は
> **Sweeper の `onSolved` フックと手動 submit が同じラベルを bump する**設計で
> (`internal/scoreboard/server.go:170-174` の doc が「an auto-solve is indistinguishable from a
> manual one on the dashboard」と明言、手動側は `api.go:712-714`)、**どちらが solve したかを
> 区別しない**。したがって **V3 の帰属判定はログ行が唯一の一次ソース**である
> (ADR-0001 rev.5 の N8 と同型の「取得元を 1 つに確定する」規律)。

**待ち上限 15 秒の根拠**: cadence 5 秒 (`scoring.go:836`) + `Run` が入場時に即 1 回 sweep する
(`scoring.go:843-`) ので、正常系は **最悪 1 tick (5 秒) + 配送遅延**。3 tick を上限に置けば
「遅い」と「動いていない」を区別できる。**15 秒を超えたら V2 は no-go** (Sweeper 未稼働の疑い)。

**unit 側 (本 ADR の前提。消すと (d′) の理由が崩れる)**:

- `TestSweep_ManualAndSweeperShareVerdict` (`internal/scoreboard/scoring/scoring_test.go:764-803`)
- `TestSweep_AlreadySolved_Idempotent` (同 `:911`)
- **この 2 本を削除・改名する変更は、本 ADR の Decision を変える変更である。**

## 付随判定: ADR-0001 Verification 4-7 (ii) を **N/A** とする (VP 裁定に同意)

**4-7 (ii)** =「emptyDir 上の実行体が `proc.is_exe_upper_layer` と判定されるか」。
qa-engineer は「現行ミッション集合に probe 対象が無い」として **N/A / ADR-0001 Signpost 8 送り**とし、
VP が妥当と裁定した。**architect も同意する。** 根拠を 3 点記録する:

1. **問いが成立する対象が存在しない** —— seed に実行可能物を置くミッションは無い
   (plant-target は `/etc/shadow` と `/root/.ssh/id_rsa` の 2 つだけで、どちらも実行体ではない)。
   **無い対象について実機で測った値は、将来の対象について何も保証しない**
   (upper-layer 判定は overlay の構成に依存するので、置き方が決まってから測るのが正しい)。
2. **その間、リスクは静的検査で閉じている** —— ADR-0001 Verification **2-7 (d)** が
   「**seed (emptyDir) 上に書いたファイルを exec しない**」を静的に禁止している
   (`docs/adr/0001-flag-plant-initcontainer-not-challenge-env.md:1138`)。
   したがって「deploy 経路が mission 07 (`Drop and execute new binary in container`) を
   auto-solve する」経路は **実測の有無に関わらず塞がっている**。
   **N/A は穴を開けない。**
3. **問いを失わない置き場所がある** —— ADR-0001 **Signpost 8**
   (「新しい plant-target が build 時 snapshot で表現できない」) が発火する場面は、
   まさに「seed に実行時生成物を置く」場面と重なる。**Signpost 8 送りは適切**である。

**条件**: E2E 計画には **「N/A」ではなく「対象不在のため未実施。ADR-0001 Signpost 8 で再訪」**と
理由付きで書くこと。**空欄や無印の N/A にしない** —— 「測っていない」ことが
「測って問題なかった」と読める台帳を作らないため (ADR-0001 rev.5 の N9 と同じ失敗モード)。

## Advice

- **VP (2026-08-19)**: 争点の提示と (α)(β)(γ) の候補提示。制約として
  「**stand-up は課金を伴う CEO 承認事項なので『実機で見れば分かる』で終わらせず、
  計画に何を書くべきかを決めること**」を指示。
  「submit 自体は `current` を要求しないはず (未確認)」という見立ては **実コードで正しいと確認した**
  (`SubmitEvade` = `scoring.go:537-553` のゲートは catalog 存在 / evade 型 / flag 一致のみで
  `current` を参照しない)。
- **qa-engineer (2026-08-19, E2E 計画 `83c2940` 経由)**: 全 7 phase / `test1` 限定 / no-go 7 件の計画。
  争点を「判断で決めた」と明示して同意待ちに置いた運用は正しい
  (**正典と計画の乖離を作らずに架橋した**)。本 ADR は §4 Phase 5 step 9 と §11 の変更を要求する。
- **architect (2026-08-19, 本 ADR 起草)**: VP の「要求を満たしていない」に**同意**。
  ただし **却下理由を差し替えた** —— (d) の但し書きが挙げる目的
  (`evaluateClean` の共有確認) は **既に unit test が pin 済**なので理由として成立しない。
  実機の価値は **2 本の配送パイプライン / 二重実装された gate 3 / Sweeper の prod 稼働**にある。
  また **(α)(γ) を却下** —— 事実 4 + 5 より **reset は 1 回も要らない**。
- **未取得の助言**: sre-engineer (計画 §10 を同時編集中。**V3 の「Sweeper 由来であることをログで見る」
  取得手順**は sre のログ導線に依存する)、security-engineer
  (**本 ADR は採点の入口を緩めないが、手順が `test1` 以外を汚さないことの独立確認**は
  ADR-0001 の 4-7 と同じ枠で受けるのが自然)。**実行前に取得すること。**
