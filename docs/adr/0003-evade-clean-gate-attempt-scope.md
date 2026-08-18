# ADR-0003: evade の clean 判定は「その課題の attempt が始まって以降の禁止ルール発火」で評価する (attempt スコープ)

- Status: **Accepted**
- Date / Deciders: 2026-08-18 / VP (承認) + **CEO (§A2 = enforce を決定、2026-08-18)** + security-engineer (境界認定) + architect (起草・Accepted 化)
- 関連: Issue #120 (App-H2 sliding window)、Issue #121 (mission 05 の実効ゲート不在)、**実装 PR #124 = <https://github.com/Qfour/falco-ctf-app/pull/124> (`fix/evade-persistent-dirty-flag`, draft。attempt スコープ実装 = commit `04c217a`)**、ADR-0001 (flag isolation)。フェーズ: リハ後 hygiene (P## 非該当)
- 参照コミット (`origin/fix/evade-persistent-dirty-flag`。`main` と異なる箇所は明記する):
  - **`d24fe02` (attempt スコープ導入*前*) 基準** = Context (C2-C6) / A3 の撤去対象表 /
    各節が「現状」「現行」として**問題を記述している** `file:line` (= 直そうとしている状態のスナップショット)
  - **`04c217a` (実装 commit) 基準** = **Accepted 化で追記・訂正した箇所** —
    A1 の強制手段表 / A2 の F1 要件 / A4 の signature / A5 の metric label と struct 理由 /
    Verification (e) / Advice の R4 再レビュー表と R1・R2 閉止状況表
- **Accepted 化 (2026-08-18)**: 次の 3 つを本文に確定させた (詳細は `## Advice`)。
  **以後の変更は本 ADR を書き換えず、supersede する新 ADR で行う。**
  1. **実装との食い違いの訂正 (C-1〜C-4。実装が正)** — A4 の signature / A5 の「単一 error では区別不能」/
     A1 の強制手段の書き分け / metric label
  2. **R4 再レビュー findings (F1-F7)** — **F1 = merge gate** (§A2 + Verification (e))、
     **F2 / F3 = prod 前必須** (Consequences)、F4 → §A5 要件 6、F5 → Signpost 6、F6 / F7 → §A8-3/4
  3. **R1 の追加 findings C2** — `current` を進ませないことで **capstone gate が実質 inert** になる経路
     (§A1 の **W2** / Signpost 5 / Consequences)。**R1 の緩和案は architect 判定で却下**し、
     **受容 + Issue #121 (mission 10 を scope に含める) で閉じる**方針を記録した
     (**残存リスクの受容そのものは CEO 未承認**)

---

## Context

### C1. 直接の動機 — 設計要素が「口伝」で運ばれて落ちた

PR #124 は evade 採点の clean 判定を「直近 `windowSeconds` 秒の禁止ルール発火」から
**恒久 dirty フラグ**へ置換した。実装自体は指示に忠実で、狙った 2 つの穴
(「発火 → 待つ → submit」と「再起動で発火履歴が消えて偽 auto-solve」) を実コードとテストの
両方で閉じている。

しかし **product-engineer の受け入れ条件は「初期値: `dirty = false` (課題を開始した時点)」** と
attempt スコープを含んでいたのに、**VP が software-engineer への発注文に転記する際、括弧内の限定を
落とした** (出典: PR #124 の VP 査定コメント「VP の過失」節, 2026-08-18T02:39:53Z)。
結果は後述 C3 のとおり **正規参加者が 10 問中 3 問を永久に解けなくなる**リグレッションである。

**この事故の教訓は「実装が悪かった」ではなく「設計要素を会話で運ぶと落ちる」**であり、
ORGANIZATION.md §0-3 が明言する「権威を運べる媒体は正典ドキュメントと意思決定マトリクスの 2 つだけ。
**会話文脈は媒体にならない**」の実証である。よって attempt スコープの意味論を本 ADR に固定する。

### C2. 現行カタログの実データ (実ファイル検証済)

| challenge | type | rules | 出典 |
|---|---|---|---|
| 02-credential-files | trigger | expected: `Read sensitive file untrusted` | `challenges/02-credential-files/falco-rule.yaml:3-4` |
| 03-stealth-read | evade | forbidden: `Read sensitive file untrusted` (**同一**) | `challenges/03-stealth-read/falco-rule.yaml:3-4` |
| 04-key-search | trigger | expected: `Search Private Keys or Passwords` | `challenges/04-key-search/falco-rule.yaml:3-4` |
| 05-silent-search | evade | forbidden: `Search Private Keys or Passwords` (**同一**) | `challenges/05-silent-search/falco-rule.yaml:3-4` |
| 10-final-exfil | evade | forbidden: **7 本** (01/02/04/06/07/08/09 の expectedRules 全部) + `requireExfil: true` | `challenges/10-final-exfil/falco-rule.yaml:3-10,18` |

進行順序は `scenarios/nimbusbreach-full/scenario.yaml:8-18` で `01 → 02 → … → 10` に固定
(scoreboard は `SCENARIO_FILE` で Restrict、`internal/catalog/catalog_test.go:300-322` が 10 問に pin)。

> **訂正**: レビュー時に「10 は 5 rules」と記録されたが、実ファイルは **7 rules**
> (`challenges/10-final-exfil/falco-rule.yaml:4-10`)。以後 7 を正とする。

### C3. なぜ恒久 dirty 単体では壊れるか

`MarkDirtyOnRuleFire` (`internal/scoreboard/scoring/scoring.go:232-246`) は
**その user の全 evade 課題**に対して無条件に taint を書く。ingest は 1 event ごとにこれを呼ぶ
(`internal/scoreboard/ingest/ingest.go:136-138`)。したがって:

- 02 をクリアするには `Read sensitive file untrusted` を**発火させることが必須** (`README.md:8-12`)
  → その瞬間 **03 が恒久 dirty**
- 04 → 05 も同型
- 01/02/04/06/07/08/09 を正当にクリアした時点で **10 が 7 重に dirty**

`evaluateClean` (`scoring.go:341-352`) は `DirtyRules` が空でなければ必ず `EvadeForbiddenFired` を返し、
解除経路は `ResetDirty` (`internal/store/store.go:728-739`) のみ。
→ **正規進行した全参加者が 03 / 05 / 10 を submit できない。** 元の穴 (不正者に不当な solve) より
**運用影響が大きい** (正規参加者の 30% のミッションが詰む)。

**旧 `windowSeconds` (10/30 秒) は弱い gate だったが、同時に load-bearing な暗黙の attempt スコープでもあった**
— 「先行ミッションの必須発火は窓から抜けている」ことを前提に設計されていた。
窓を外すなら、**窓が兼務していたスコープ機能を明示的に置き換えなければならない**。これが本 ADR の本体。

### C4. 「時間非依存」は誤った命題である

#124 のコメントは「clean 判定は時間に依存しない」を成果として繰り返し記述している
(`scoring.go:31-45`, `:341-352`, `internal/store/store.go:670-701`)。
これは **必要条件を不変条件と誤認**している。時間依存の除去は正しいが、それだけでは C3 を招く。
**正しい不変条件は「attempt スコープ」であり、時間非依存はその帰結として得られる。**

### C5. より深い制約 — 負の条件だけの gate は原理的に不健全

02 の想定解 `cat /etc/shadow` は **03 の flag をそのまま画面に出す**
(`challenges/03-stealth-read/README.md:13-16`: flag は `/etc/shadow` 末尾に追記される)。
つまり **02 をクリアする発火そのものが 03 の flag を参加者に渡す**。
どの attempt スコープを採っても、その発火は「02 の attempt 中」なので 03 を taint しない
= **参加者は回避技法を一度も使わずに 03 を solve できる**。

これは新しい欠陥ではなく **現状 (`windowSeconds: 10`) でも「11 秒待って submit」で成立している**。
Issue #121 が 05 について指摘したのと同じ構造で、**03 / 05 は `requireExfil` を持たないため
原理的に「技法を使った証跡」が存在しない** (`03-stealth-read/falco-rule.yaml` / `05-silent-search/falco-rule.yaml`
に `requireExfil` が無い)。

→ **attempt スコープはゲームを成立させるために必要だが、負の条件だけの gate を健全にはできない。
健全化は attempt ごとの積極証明 (`requireExfil` / `expectedRules`) しかない = Issue #121 の主題。**
本 ADR はこの限界を**受容した残存リスクとして明記**し、`scoring.go` の package doc が
「穴を閉じた」と読める記述 (`scoring.go:31-45`) を是正する要件を含める。

### C6. 既存の不変条件・決定事項との関係

- **I1** (`replicas: 1` + `Recreate`, `.claude/rules/falco-ctf-app-conventions.md:23`): taint は永続でなければならない。
  in-memory 化への後退は不可 (#120 の経路 2 がそれ)
- **I5** (全 8 イメージを同一 git SHA, 同 :27): scoreboard の JSON 応答と `portal.html` は同一イメージに同居するため、
  journey detail のフィールド追加・削除で **版skew は発生しない**。よって `windowSeconds` の応答フィールド撤去は安全
- **I8** (`prefix-exact` 照合, 同 :30): reset エンドポイントは `selfOrAdminWrite` に委譲し**自前照合を書かない** (#124 は準拠済)
- **I10** (シークレットを焼き込まない, 同 :32): dirty 応答は**ルール名のみ**を返し flag 値を含めない
- **ADR-0001** (flag isolation): 「フラグの取得元は閉じるが、取得手段が技法であることは保証しない」と既に明記。
  本 ADR の C5 はその系
- **クロスリポ契約**: `/falco/events` の payload 形状は変更しない (`docs/openapi-scoreboard.yaml:74`)。
  本 ADR は app 内部の採点意味論であり、platform 側の falcosidekick 設定に影響しない

---

## Options

### Option 1 — attempt epoch を一級市民にする (目標形)

**変更点**: `evade_attempt (user, challenge, epoch, started_at)` テーブルを追加し、`exfil` と `evade_dirty` に
`epoch` 列を持たせる。clean 判定 = 「現 epoch 以降に禁止ルール発火が無い」。reset = `epoch++`
(旧 receipt / 旧 taint は現 epoch と一致しなくなるので自動的に無効化)。

- **コスト**: 新テーブル 1 + 既存 2 テーブルのスキーマ変更。migration 機構は未整備 (app#117 未着手、
  現状は `CREATE TABLE IF NOT EXISTS` のみ = `internal/store/store.go:163`)。`docs/db-schema.md` の
  Migration history (`:147-151`) に v2 を追加する必要。認知コスト: 「epoch」概念を運用者・
  challenge-author 双方に説明する必要
- **リスクと可逆性**: 既存 PVC データ (`exfil` 行) に epoch を後付けする必要があり、
  **リハ中の hotfix としては不可逆度が高い**。設計としては最も素直で、後から Option 2 → 1 への移行は可能
- **効き始める閾値**: **attempt の開始が「進行順」から導出できなくなった瞬間** —
  並行ミッション / 任意順 / 同一課題の複数同時 attempt / 「attempt 開始」ボタンの導入

### Option 2 — attempt スコープを進行順から導出する (新テーブル不要) 【推奨】

**変更点**: taint 書き込みを **「その cid がその参加者の `current` (進行順で最初の未 solve) であるときだけ」** に限定する。
`current` の導出は journey 投影が既に持っている (`internal/scoreboard/api/api.go:1376-1382`;
順序は `api.go:82,157` の `Order` = scenario 順、無指定時は sorted catalog IDs = `internal/catalog/catalog.go:95`)。

- **コスト**: スキーマ変更ゼロ。ただし **`Grader` は現在 order を持たない**
  (`scoring.go:98-103` は `cat/store/now/points` のみ、`server.go:160` の `scoring.New(cat, s, h.now)` に
  order を渡していない。order は `server.go:92-94` の `WithOrder` から api.Handler にしか流れていない)
  → **Grader に順序を注入する必要があり、これが唯一の構造変更**。放置すると
  「journey が表示する current」と「採点が使う current」の 2 つの定義が生まれ drift する
- **リスクと可逆性**: 完全に可逆 (書き込み条件を外せば #124 の挙動に戻る)。
  リスクは C5 の残存 honor system と、下記「exempt 発火」の意味論を明示しないと再度取り違えられること
- **効き始める閾値**: 進行が線形かつ `current` が単一である限り正しい。scenario に並行/任意順が入ると破綻する

### Option 3 — admin-only reset (attempt スコープを導入しない)

**変更点**: taint は無条件恒久のまま、解除を運営限定にする。C3 は「運営が 40 名 × 3 問を手で reset する」で回避。

- **コスト**: 運用コストが O(参加者 × evade 問数)。2 時間のイベントで **最低 120 回の手作業**
  (`scenarios/nimbusbreach-full/playbook-2h.md` の枠内で不可能)
- **リスクと可逆性**: 可逆だが、当日の運営を単一障害点にする。参加者は待たされる
- **効き始める閾値**: 参加者数が 1 桁かつ 1 対 1 メンタリング形式のとき

---

## Decision

**Option 2 を採る** — attempt の開始を「その課題が進行順で `current` になった時点」と定義し、
それ以降の禁止ルール発火だけを taint とする。理由: **スキーマ変更ゼロで C3 を閉じ、
`current` の導出は既に参加者に見えている概念 (journey の current mission) なので、
参加者への説明可能性と実装が一致する。**

以下 A1-A8 を **本 ADR が要求する規範 (実装 PR の完了条件)** とする。

### A1. attempt スコープの意味論 (判定アルゴリズム)

以下を **`Grader` の内部で 1 箇所**に実装する。用語を正典化する:

```
order(u)        := 進行順 (SCENARIO_FILE 指定時は scenario 順、未指定時は sorted catalog IDs)
                   ★ journey 投影と同一のリストでなければならない (api.go:82,157 と単一ソース)
solved(u)       := store の solved 集合 (catalog に存在する id のみ)
current(u)      := order(u) のうち solved(u) に含まれない最初の id ("" = 全 solve 済)
attemptStart(u,c) := c が current(u) になった時点、または (u,c) の最後の reset 成功時点の
                     いずれか遅い方  ※ 状態としては保持せず、下記 taint 規則で表現する

on ruleFire(u, r):                       # ingest から 1 event 1 回
    cur := current(u)                    # ★ この event の trigger solve を適用する **前** の状態で評価
    for c in evade challenges where r ∈ c.forbiddenRules:
        if c == cur: MarkDirty(u, c, r)  # ← attempt スコープ。これが唯一の taint 書き込み条件
    applyTriggerSolves(u, r)             # ← その後に trigger 判定

clean(u,c) := DirtyRules(u,c) が空
```

**評価順序 (`cur` を event 適用前の状態で取る) は規範であり、実装詳細ではない。**
これにより「mission N をクリアするための必須発火は mission N+1 を taint しない」が成立する
(C2 の 02→03 / 04→05 の双子構造がこの 1 点に依存している)。逆順にすると C3 が再発する。

**この不変条件を「何が」強制するのか (強制手段を層ごとに書き分ける)** —
結論 (「不変条件は機械強制されている」) は変わらないが、強制の実体は **2 層**であり強度が違う。
「型で順序を強制する」という書き方は不正確なので採らない:

| 対象 | 強制手段 | 強度 | 実体 |
|---|---|---|---|
| **「全ての rule fire が taint 評価を受ける」** | **パッケージ境界 (Go の export 規則)** | **コンパイル時** — パッケージ外の call-site は「片方だけ呼ぶ」「逆順で呼ぶ」を*書けない* | `markDirtyOnRuleFire` (`scoring.go:361`) / `evaluateTrigger` (`scoring.go:306`) が unexported、公開入口は `OnRuleFire` (`scoring.go:421`) の 1 本のみ |
| **「taint → trigger の順序そのもの」** | **テスト** | **実行時** — 順序は `OnRuleFire` 本体の 2 行 (`scoring.go:422-423`) で、**パッケージ内編集で反転可能。型では守れない** | 反転すると `TestOnRuleFire_AttemptScope_OnlyTaintsCurrentChallenge` の第 1 段 (`internal/scoreboard/scoring/scoring_test.go:401`) と `TestSubmit_RequiredTriggerFire_DoesNotDirtyFollowingEvade` (`internal/scoreboard/server_test.go:543`) が即 FAIL する |

→ よって A4 の要件は「型で順序を強制する」ではなく
**「パッケージ境界 + 単一入口で構造化し、順序はテストで pin する」**である。
**この 2 本のテストを消すことは順序の機械強制を消すことと等価**であり、Verification (a)(b) の対象に含める。

**明示する帰結 (これが attempt スコープの定義そのもの)**:
- `c` が `current` になる**前**の発火は taint しない (= 先行ミッションの必須発火は exempt)
- `c` が `current` である**間**の発火は taint する (= 騒がしい再試行は捕まる)
- `c` が solve 済になった後の発火は無関係 (solve は first-write-wins = `store.go:505-516`)

**既知の弱点を明記する (隠さない)。attempt スコープは負の条件だけの gate を健全にはしない** —
`current` を進ませないことが taint を回避する手段になる。弱点は 2 つあり、**強度が違う**:

**W1 (03 / 05 — 限定的)**: `c` が `current` になる前の発火は exempt なので、
参加者は「1 発で抜ける」ことができる。ただし C2 の双子構造では**騒がしい実施が先行 trigger を即 solve させ、
`current` が `c` に進む**ため、**2 回目以降の発火は必ず taint される** (この緩和は 03 / 05 に限る)。

**W2 (10-final-exfil — capstone gate が実質 inert になる。緩和は効かない)**:
**`current` は「進行順で最初の未 solve」であり、03 / 05 は evade = 手動 submit しか solve 経路が無い**
(`CurrentMission` = `scoring.go:221-231`)。よって参加者が **03 を submit しないだけで `current` は 03 に固定される**。
その状態では:

- **10 の禁止 7 本 (`challenges/10-final-exfil/falco-rule.yaml:4-10`) のうち、03 が禁止する 1 本
  (`Read sensitive file untrusted` = `challenges/03-stealth-read/falco-rule.yaml:4`) 以外は一切 taint されない**
  (taint 先は `current` = 03 のみ)
- **trigger 側は attempt スコープ外**なので、04 / 06 / 07 / 08 / 09 は**騒がしく発火させても solve が進む**
  (`evaluateTrigger` の doc が「Deliberately NOT attempt-scoped」と明記 = `scoring.go:293-297`)
- **`Sweep` は `current` を参照しない** (`scoring.go:729-752` → `PendingExfilSolves` → `evaluateClean`)。
  したがって騒がしく取得した flag の receipt が残っていれば **capstone は auto-solve される**
- しかも `challenges/submit-yaml.sh` は **evade flag の一括提出フロー** (「one line per mission you've cleared」
  = `submit-yaml.sh:2-16`) であり、**「全部やってから最後にまとめて提出」が自然な進め方**になる。
  → **W2 は意図的な悪用に限らず、既定経路で成立する**

**W2 は退行ではない (merge を阻害しない)**: `main` の窓ベース gate でも同じことができた —
`evaluateClean` は `RecentFiresMatching(..., ch.WindowSeconds)` で判定し
(`origin/main:internal/scoreboard/scoring/scoring.go:282`)、10 の窓は 30 秒
(`origin/main:challenges/10-final-exfil/falco-rule.yaml:13`) なので **「全部騒がしくやって 31 秒待って exfil」** で
同じ結果になる。本 ADR は W2 を**新たに作っていないし、閉じてもいない**。

**W1 / W2 を閉じるのは attempt ごとの積極証明のみ (Issue #121)。** C5 の結論の系であり、
**`#121` の scope に mission 10 を含めなければ capstone gate は inert のまま**である (Consequences 参照)。

### A2. reset の意味論

1. **reset は attempt の再開始である。** `(u,c)` の taint を全削除する
   (`store.ResetDirty` = `internal/store/store.go:779-798` (`04c217a`)、既存実装で足りる)
2. **【enforce — CEO 決定 2026-08-18・確定】** reset は **同 `(u,c)` の exfil receipt も削除**しなければならない。
   根拠 (**以下 3 つの `file:line` は決定時点の `d24fe02` 基準** = A2-2 実装前の状態):
   当時の `ResetDirty` は `evade_dirty` のみ削除し `exfil` 行を残していた
   (`store.go:732-733`)。`PendingExfilSolves` (`store.go:581`) は未 solve の receipt を列挙し、
   Sweeper (`scoring.go:552`, `:626`) が 5 秒周期で `evaluateClean` に通すため、
   **reset を 1 回叩くだけで capstone が auto-solve される**。
   exploit が「発火 → 待つ → solve」から「発火 → reset → solve」に**別の扉から再生産**されている。
   → 要件: **「reset 後の solve は必ず新しい証跡を伴う」**。`requireExfil` 課題では
   reset 後に **再度 exfil を届けなければ solve しない**こと
   → **【F1・追加要件 (2026-08-18 R4 再レビュー。merge blocker)】削除順は `exfil` 先・`evade_dirty` 後とする。**
   実装 `store.ResetDirty` (`internal/store/store.go:779-798`) は現在 **`evade_dirty` → `exfil` の順**で、
   `DELETE FROM evade_dirty` 成功 → `delete(s.dirtyRules, key)` (`:789`) の**後**に
   `DELETE FROM exfil` (`:791-796`) が失敗すると `return err` して `delete(s.exfil, key)` (`:797`) に到達しない。
   結果は **「taint が消えて古い receipt が残る」**状態であり、
   **A2-2 が閉じたはずの「発火 → reset → Sweeper が 5 秒で auto-solve」がエラー経路から再生する fail-open** になる
   (Sweeper は `PendingExfilSolves` を回して `evaluateClean` に通す = `scoring.go:729-732` /
   `internal/store/store.go:606`、cadence は 5 秒 = `scoring.go:782`。taint が無ければ clean と判定される)。
   **順序を逆 (`exfil` 先) にすれば、失敗時は dirty が残って submit が閉じる = fail-closed に倒れる。**
   in-memory 側の `delete` も、対応する `DELETE` が成功した後に行う。
   **理想は 2 つの `DELETE` を 1 トランザクション (`database/sql` の `Tx`) にまとめること** —
   その場合は「どちらも成功 / どちらも未実行」となり順序依存そのものが消える (推奨形)。
   **Verification (e) がこの順序を機械で pin する。**
3. **【honor — 却下 (2026-08-18 CEO 判断により不採用)】** 以下は採らない。記録として残す。
   receipt を残すなら、
   (a) `challenges/10-final-exfil/README.md` と journey に **「reset しても exfil 証跡は再取得不要」** を明記し、
   (b) `scoring.go` の package doc と `store.ResetDirty` の doc に
   **「reset は capstone の auto-solve を誘発しうる = 意図的な honor system」** を明記し、
   (c) `docs/adr/` に本 ADR を supersede する ADR でその選択を記録する。
   **黙って残すことは認めない** (紙の上で「閉じた」と読める状態を作らない)
4. **時間経過・ページ再読込・ttyd 再接続・セッションタイムアウトは reset 条件にしない**
   (#124 のこの判断は正しい。新しい「待つだけ」経路を作らないため)
5. **reset 直後の猶予窓 (取り込み遅延バッファ) は入れない** (#124 の判断を継承。
   攻撃 → 即 reset → 即 submit で同種の脆弱性を再生産するため)

### A3. `windowSeconds` は **field ごと撤去**する

「informational」として残さない (`internal/catalog/catalog.go:15-17` の現行記述はこの選択肢を採っている)。
理由: 参加者向け表示に残ると必ず誤情報になり (`portal.html:1525` が実例)、
challenge-author が新規課題で設定し続ける (`.claude/agents/challenge-author.md:83` が
「>= 5、通常 10」と指導している)。**採点に効かないフィールドを schema に残すのは規約の腐敗源。**

撤去対象 (d24fe02 基準・実測):

| # | path:line | 内容 |
|---|---|---|
| 1 | `internal/catalog/catalog.go:15-17` | schema doc の「informational only」記述 |
| 2 | `internal/catalog/catalog.go:77` | `WindowSeconds int` field |
| 3 | `internal/catalog/catalog.go:153-154` | default 10 の代入 |
| 4 | `internal/scoreboard/api/api.go:1681` | journey detail 応答の `"windowSeconds"` |
| 5 | `internal/scoreboard/view/templates/portal.html:1525` | 「禁止ルールが N 秒 静かになれば自動クリア」= **虚偽の案内** |
| 6 | `AGENTS.md:81,86,175` | evade 型の説明・例・mermaid の `block submit for windowSeconds` |
| 7 | `challenges/03-stealth-read/README.md:10` / `challenges/10-final-exfil/README.md:10` | 参加者向け採点条件 |
| 8 | `challenges/submit-yaml.sh:14` | コメント |
| 9 | `.claude/agents/challenge-author.md:42,83` / `.claude/skills/add-challenge.md:43` | 生成テンプレと検証指示 |
| 10 | `challenges/{03,05,10}/falco-rule.yaml` (`:9` / `:7` / `:13`) | 実カタログの値 |
| 11 | `internal/store/store.go:15,54` の doc / `docs/db-schema.md:31-55,101-116,127-129` | 旧モデル記述 |
| 12 | 各 `*_test.go` の fixture (`WindowSeconds: 10` 等 20 箇所超) | field 削除に伴い機械的に消える |

**撤去しないもの (別概念。混同禁止)**: `triggerDetectWindowSeconds = 60`
(`internal/scoreboard/api/api.go:57-66,1637`) は trigger 課題の**表示専用**ルックバックであり
採点に効かない。`store.RecentFiresMatching` (`store.go:644`) はその表示のために残る。

**journey detail (`GET /api/users/{user}/journey?mission=<cid>`) が返すべきもの**:
`"windowSeconds"` を削除し、代わりに

- `"dirty": bool` — その attempt が taint されているか
- `"dirtyRules": []string` — taint したルール名 (sorted, 常に非 nil。**flag 値は含めない = I10**)

を返す。**これは API 契約の変更であり、architect 合意 + VP 承認が必要な事項** (ORGANIZATION.md §4)。
本 ADR がその合意を構成する。I5 により応答とテンプレは同一イメージに同居するため版 skew は無い。

### A4. `Grader.OnRuleFire` へ統合する — call-site 規律を構造的事実にする

現状 1 event に対し Grader の入口が **2 本**ある:
`ingest.go:136` (`MarkDirtyOnRuleFire`) と `ingest.go:143` (`EvaluateTrigger`)。
将来 replay ツール / 別 source / テストが `EvaluateTrigger` だけを呼ぶと **taint が書かれず、
#120 の穴が無言で再オープンする**。しかも A1 は両者の**評価順序**を規範としているので、
順序を呼び出し側の作法に委ねてはならない。

要件: **`Grader.OnRuleFire(user, rule) RuleFireOutcome` を唯一の公開入口**とし、
A1 の順序 (taint → trigger) を内部に閉じ込める。`MarkDirtyOnRuleFire` と `EvaluateTrigger` は
**unexported** にする (パッケージ外から呼べないようにする = 「全ての rule fire は taint 評価される」を
規律ではなく **パッケージ境界による静的な事実**にする。**順序そのものの強制はテスト** —
強制手段の内訳は A1 の表を見よ)。ingest handler は `OnRuleFire` のみを呼ぶ。

**戻り値は単一 `error` ではなく struct にする** (実装 = `internal/scoreboard/scoring/scoring.go:394`):

```go
type RuleFireOutcome struct {
    Results    []TriggerResult
    TaintErr   error
    TriggerErr error
}
```

**理由 (A5 との整合)**: A5 は taint 失敗と trigger 失敗に**異なる反応**を要求する —
taint 失敗は **5xx + `FalcoEventsReceived{outcome="taint_error"}`**、trigger 失敗は **log + 200** (A5 の要件 1-3)。
両者を `errors.Join` した**単一 `error`** で返すと、handler には
**(i) エラー文字列の照合 (脆く、メッセージ変更で無言に壊れる)**、
**(ii) 区別の放棄 (両方 5xx = 表示専用の失敗でイベントを落とす / 両方 200 = false-clean を隠す)**
しか残らない。**struct にすることで criticality の非対称が型に現れ**、呼び出し側が
「どちらのエラーなのか」を推測しなくてよくなる。
これは A4 の趣旨 (**採点の重要判断を call-site の作法に委ねない**) と同型の要求であり、
`([]TriggerResult, error)` は A4 自身の趣旨に反する。handler 側の分岐は
`internal/scoreboard/ingest/ingest.go:143-158`。

### A5. ingest の criticality 逆転を是正する

現状の非対称 (実測):

| 書き込み | 失敗時の挙動 | 出典 |
|---|---|---|
| `RecordRuleFire` (**表示専用**) | 500 + `FalcoEventsReceived{store_error}` メトリクス | `ingest.go:121-126` |
| `MarkDirty` (**採点権威**) | **200 + ログのみ**。メトリクス無し | `ingest.go:136-138` |

falcosidekick customWebhook は再送しないため、**取りこぼした taint は恒久 false-clean になる**。
さらに `store.MarkDirty` は SQLite の Exec が失敗すると **in-memory の `dirtyRules` も更新せずに return する**
(`store.go:685-700`: `if _, err := s.db.Exec(...); err != nil { return err }` が in-memory 更新より前)
→ **DB エラー時は in-memory taint すら立たない。**

**この非対称は Grader の戻り値の形に跳ね返る (A4 と一体の要件)**: 同一 event の中で
**taint 失敗は false-clean を作る (回復不能)** が、**trigger 失敗は次の一致発火まで solve が遅れるだけ (回復する)**。
したがって Grader が両者を `errors.Join` した **単一 `error` として返すと handler は区別できず**、
残るのは**エラー文字列の照合 (脆い)** か **区別の放棄 (どちらかを必ず誤る)** だけになる。
**これが A4 の戻り値を `RuleFireOutcome{Results, TaintErr, TriggerErr}` struct にしている理由である**
(将来「なぜ struct なのか」を失わないために A5 側にも明記する)。

要件:

1. **fail-closed 方向**: 永続化が失敗しても **in-memory taint は必ず立てる**
   (over-taint は参加者が reset で回復できる。**taint の見逃しは回復不能**)
2. **メトリクスを追加**: **`FalcoEventsReceived{outcome="taint_error"}`** (既存 CounterVec を再利用、
   `internal/scoreboard/metrics/metrics.go:26-34`。**label 名は `outcome` であり `result` ではない** —
   Proposed 段階の本 ADR は `result=` と書いていたが、実装・既存 label 集合ともに `outcome=` が正
   = `metrics.go:16-17,33` / `ingest.go:145`)。または専用カウンタ。
   **0 でないことが観測可能でなければ fail-open を許さない**
3. **HTTP ステータス**: taint 書き込み失敗時は **5xx を返す** (falcosidekick が再送しないことは事実だが、
   「採点権威が event を完全に記録できなかった」を 200 で隠さない)
4. **fail-open を残す判断をした場合は、その理由を本 ADR を supersede する ADR に明記する**
   (「再送されないので 5xx に意味が無い」という理由は成立するが、**書かずに残すのは認めない**)
5. **残存リスクとして明記**: 永続化失敗直後に pod が再起動すると in-memory taint は失われる。
   緩和は (2) のメトリクスと runbook の確認手順のみ。これを `scoring.go` の package doc に書く
6. **【F4・LOW】5xx を返す前に、その event で既に確定した観測量を計上する。** 実装は
   `TaintErr` で即 `return` するため (`internal/scoreboard/ingest/ingest.go:143-147`)、
   **同一イベントで永続化に成功した trigger solve の `SolvesTotal` (`:160-162`) が計上されない**。
   さらに `accepted` (`:128`) と `taint_error` (`:145`) の**二重計上**により
   `FalcoEventsReceived` の label 合計が受信総数と一致しなくなる (label 集合を「排他的な結果」として
   読む前提が壊れる = `metrics.go:3-6` の cardinality 規律の意図に反する)。
   → 要件: **metric の bump と `SolvesTotal` の計上を 5xx 応答より前に行い、
   `accepted` と `taint_error` を排他にする** (どちらを排他の代表にするかは実装者判断)

### A6. `scoring.go` package doc の是正

`scoring.go:31-45` は「穴を閉じた」と読めるが、C4 (時間非依存は不変条件ではない) と
C5 (負の条件だけの gate は不健全) が抜けている。要件:

- 不変条件を **「attempt スコープ」** と書く (「時間に依存しない」を不変条件として書かない)
- **03 / 05 は `requireExfil` を持たないため技法の証跡が無く honor system が残る**ことを明記し、
  Issue #121 を参照する
- A5 (5) の残存リスクを明記する
- **A1 の W2 (capstone gate の inert 化) を明記する。** `04c217a` の package doc
  (`internal/scoreboard/scoring/scoring.go:69-82`) は残存リスクを **03 / 05 の honor system に限って**書いており、
  **`requireExfil` を持つ 10 についても `current` を進めなければ taint されない**ことに触れていない。
  → **「`requireExfil` があるから 10 は守られている」と読める状態を作らない**
  (`Sweep` が `current` を参照しないことを `Sweep` の doc にも書く)。**LOW / merge gate ではない**が、
  A6 の趣旨 (「穴を閉じた」と読める記述を残さない) の対象である

### A7. Issue #121 との依存関係

`05-silent-search` に `requireExfil` を足す修正は **本 ADR の実装を前提とする**。
理由: attempt スコープ無しに `requireExfil` を足すと、05 は 10 と**同一の理由で恒久 dirty** になる
(04 の必須発火 = 05 の禁止ルール) 上に、receipt が永続するため
**A2-2 を満たさない reset は capstone と同じ auto-solve 経路を 05 にも作る**。
→ **#121 の実装は本 ADR の実装 PR が merge された後に着手する** (逆順は禁止)。

**#121 の scope に mission 10 を含めることを本 ADR から要求する** (R1 の追加 findings C2 = A1 の W2)。
理由: 10 は `requireExfil` を**既に持っている**が、receipt は「flag を届けた」ことの証跡であって
**「回避技法を使った」ことの証跡ではない**。`current` を 03 に固定したまま騒がしく取得しても
receipt は同じ形で届くので、**10 の gate は負の条件 (`forbiddenRules`) だけで守られている状態のまま**である。
→ **03 / 05 だけを積極証明化しても capstone は inert のまま。最高配点のミッションが実質 honor system で残る。**

### A8. spec / schema doc の追随 (architect 所管)

1. `docs/openapi-scoreboard.yaml` に **`POST /api/users/{user}/challenges/{cid}/reset-dirty` を追記**する。
   現在の spec は 9 path のみ (`:27,52,74,115,155,211,238,277,289`) で、#124 が追加した
   route (`internal/scoreboard/api/api.go:326`) が**入っていない**。採点権威への参加者可能な書き込みが
   spec 外にあるのは許容しない
2. `docs/db-schema.md` を **evade_dirty / exfil を含む現行スキーマに更新**する。
   現状は `solved` / `events_per_user` しか記載が無く (`:57-100`)、
   さらに `:101-116` は消えた in-memory sliding window を仕様として説明し、
   **`:127-129` は「Evade-windowing still keys off Falco's time」と記述しているが、
   実装は `ingest.go:112-119` で server 側 `now()` を使っており事実誤り** (#124 以前から誤り)。
   Migration history (`:147-151`) に本変更の行を追加する
3. **【F6・LOW — 本 ADR の完了条件には含めない。follow-up issue とする】**
   `docs/openapi-scoreboard.yaml` は **`/api/users/{user}/journey` 自体を未記載**である
   (`04c217a` 時点の path は `:27,52,74,120,160,216,269,296,335,347` の 10 本のみ)。
   したがって A3 が新設した参加者向けフィールド (`dirty` / `dirtyRules`) の**契約はコードにしか存在しない**。
   これは本 ADR が作ったギャップではなく既存ギャップなので A8 の必須要件にはしないが、
   **「採点権威の参加者向け読み取り契約が spec 外」という A8-1 と同じ問題**であり、issue 化して閉じる
4. **【F7・NIT — 運用メモ】** `docs/db-schema.md:317-318` は **未 merge の PR #124 / 本 ADR を
   v2 / v2.1 として日付付きで確定形で記載**している。**merge 時に日付と状態を実際の merge 日に確定させる**
   (未 merge の変更を「済」と読める台帳は MERGE-DRAIN の趣旨に反する)

---

## Consequences

### 諦めたもの

- **完全な attempt 分離を諦めた** (Option 1)。`current` は進行順の関数なので、
  「同一課題の複数 attempt を区別する」ことはできない。reset は「現在の attempt をやり直す」意味しか持たない
- **A1 の既知の弱点 W1 / W2 を残した。** W1 (03 / 05 の「1 発で抜ける」経路) は双子構造で部分的に緩和されるが、
  **W2 (`current` を 03 に固定して 10 の禁止 7 本を騒がしく踏んでも capstone が auto-solve される) は緩和が効かない**
  — `Sweep` が `current` を見ないため。**`main` の 30 秒窓でも同じことができたので退行ではないが、
  「capstone gate が実効的に存在する」と読める記述を本 ADR / コード / 参加者向け文書に書いてはならない**
- **閉じるのは attempt ごとの積極証明 (Issue #121) のみである。**
  → **要求: #121 の scope に mission 10 を含める。** 03 / 05 だけを積極証明化しても
  **capstone gate は inert のまま**であり、最高配点のミッションが実質 honor system で残る
  (A7 の依存関係はそのまま: #121 は本 ADR の実装 merge 後に着手する)
- **C5 の残存リスクを受容した**: 03 / 05 は「回避技法を使ったこと」の証跡を持たない。
  02 の必須発火が 03 の flag を露出する構造 (`03-stealth-read/README.md:13-16`) はカタログ設計の問題であり、
  採点機構では閉じられない

### 新たに守る不変条件 (候補)

> **I11 (候補・昇格は Verification (a)+(b)+(e) の landing + 実装 PR / 本 ADR の main merge が条件。末尾「I11 昇格の条件」参照)**
> **evade 課題の clean 判定は attempt スコープで評価する。**
> 参加者がその課題の attempt を開始する (= その課題が進行順で `current` になる、または reset する)
> **前**に発火した禁止ルールは taint しない。**判定に経過時間を用いない**
> (窓・猶予・期限・タイムアウトを導入しない)。**全ての rule fire は単一の Grader 入口を通り、
> taint 評価と trigger 評価をこの順で受ける。**

ORGANIZATION.md:347 の歯止め (「`Verification` が無い ADR は Hard Invariant に昇格させない」) に従い、
**機械強制が landing するまで I11 は候補のままとし、`.claude/rules/falco-ctf-app-conventions.md` には追記しない。**

### runbook / 運用への影響

- **【F3・HIGH・prod 前必須 / application-engineer】reset エンドポイントが参加者から到達可能でなければならない**
  (R1 の HIGH)。現状は origin-guard により workspace からの `curl` が 403 になり、portal に導線が無い。
  さらに **`04c217a` は「reset-dirty でやり直すまで自動クリアされません」という表示を新たに追加した**
  (`internal/scoreboard/view/templates/portal.html:1529`) ため、
  **手段の無い指示を参加者に見せている状態**になっている (実装前より悪い)
  → **portal に dirty 表示 + やり直しボタン**が必要。
  **ボタンの文言は A2-2 を反映しなければならない** — `requireExfil` 課題では
  **reset すると exfil receipt も消える = flag の再配送が必要**である旨を明示する
  (黙って receipt を消すと「reset したら capstone が solve されなくなった」という問い合わせになる)。
  ⚠️ **collector allowlist への追加で解決してはならない** — collector 経路はヘッダ無し =
  claimed identity を許すため、**任意の workspace が他人の taint を消し他人に capstone solve を付与できる
  帰属改竄経路**になる (R1)
- **リハ前に E2E (Verification (d)) を実行しない限り本番投入しない。** #124 の欠陥は
  ユニットテスト全 green で通過している = 単体テストではこのクラスの回帰を検出できない
- **【F2・MEDIUM・prod 前必須 / content-engineer】参加者向け記述が撤去済みモデル (`windowSeconds`) を
  教え続けている。** `04c217a` 時点の実測インベントリ:

  | path:line | 内容 | 危険度 |
  |---|---|---|
  | `challenges/PARTICIPANT-HANDBOOK.md:171-173` | 「**10 秒待つ か、Pod を再起動 (運営に依頼) でリセット**」 | **最悪** — taint は永続化済みなので**再起動では消えない**。**運営工数を誤誘導する** (当日「再起動してください」の列ができる) |
  | `challenges/PARTICIPANT-HANDBOOK.md:84` | 「提出直前 10 秒に該当ルールが発火していないこと」 | 採点条件の虚偽 |
  | `challenges/PARTICIPANT-HANDBOOK.md:119` | 「`evaded:false` が出たら 10 秒待ってから もう一度 submit」 | 存在しない回復手段の案内 |
  | `challenges/10-final-exfil/journey.yaml:11,22,27` | 「直前 30 秒に 1 つでも発火していると弾かれる」「**30 秒静かに待って提出**」(step label) / 想定解の骨子 | **portal に描画される最高露出面** |
  | `challenges/10-final-exfil/README.md:50,63-64` | 「30 秒静かに待ってから提出」「その後 30 秒は弾かれる」 | 採点条件の虚偽 |
  | `challenges/{03-stealth-read,05-silent-search,10-final-exfil}/fixtures/welcome.txt` (`:17,41` / `:16` / `:29`) | 同種の「直前 10/30 秒」記述 | **workspace 内で最初に読まれる面** (architect が F2 のインベントリに追加) |

  → **これらは A3 の撤去対象表 (項目 7) の未完了分である。** 参加者に見える面の虚偽は
  「採点条件が分からない」という当日の最大の摩擦源になる
- 参加者向け記述の更新が必要 (上記に加えて): `challenges/03-stealth-read/README.md`・`AGENTS.md` (content-engineer)

---

## Signposts

この決定 (Option 2) を覆す**観測可能な信号**:

1. **scenario に並行ミッション / 任意順 / 分岐が入る** — `scenarios/*/scenario.yaml` の
   `challenges:` が線形リストでなくなる、または journey の `?mission=` 自由閲覧
   (`internal/scoreboard/api/api.go:1351`) が「attempt 開始」の意味を持つ変更が入る。
   → **`current` が attempt の錨として機能しなくなる = Option 1 (epoch) が唯一解になる**
2. **evade 課題が 2 つ目の `requireExfil` を持つ、または `expectedRules` (積極証明) を得る** (#121 の帰結)。
   → 「receipt が**どの attempt の**証跡か」を区別する必要が生じ、`exfil.epoch` 列 = Option 1 が必要になる
3. **`FalcoEventsReceived{outcome="taint_error"} > 0` がイベント中に観測される** —
   A5 の fail-open 残存リスクが実在化した証拠。→ taint 書き込みを ingest の同期パスから外し、
   永続化保証のあるキューに載せる設計 (別 ADR) が必要
4. **リハ / 本番で「03 / 05 / 10 を submit できない」申告、または 1 参加者あたり reset 呼び出しが 3 回を超える** —
   attempt スコープの定義が参加者の実際の作業単位と合っていない証拠。
   → attempt を明示操作 (「この課題を開始する」ボタン) に変更 = Option 1
5. **capstone gate の inert 化が観測される (A1 の W2)** — 具体的な観測形:
   **10 を auto-solve した参加者のうち、solve 時刻より前に 10 の禁止ルールを発火させていた者の割合**
   (`store.RecentFiresMatching` の表示用履歴 / Falco イベントログで事後に測れる)、
   または **03 / 05 が未 solve のまま 04-09 が solve 済**という状態が参加者の多数で観測される
   (= `current` が 03 に固定されたまま進行している = W2 の前提が成立している)。
   → **負の条件だけの gate では capstone を守れないことの実証**。#121 の積極証明を 10 まで広げる
   (mission 10 に `expectedRules` 相当の「回避技法を使った証跡」を導入する) 以外に手が無くなる
6. **`scoreboard_ingest_falco_events_received_total` が持続的に高い (A5 の F5 = OnRuleFire の直列化欠如)** —
   `OnRuleFire` は user 単位の直列化を持たないので、trigger solve 確定の直後に到着した発火が
   **古い `current` で評価される窓 (ms)** がある。判定は**寛容側 (taint しない側) に倒れる**ので A1 と矛盾しないが、
   イベント率が上がるとこの窓に入る確率が上がる。→ **per-user mutex を `OnRuleFire` に入れる**
   (ロック粒度が上がるので、必要になるまで入れない)

---

## Verification

**機械で確認する方法。以下 (a)+(b)+(e) が landing した時点で I11 を Hard Invariant に昇格できる**
(昇格の手続き条件は末尾「I11 昇格の条件」を見よ)。

### (a) 実 catalog に対する交差テスト 【I11 昇格の必須条件・最優先】

`internal/catalog/catalog_test.go` の「実 `../../challenges` を読む契約テスト」枠
(`TestLoad_RealChallenges` = `:253-297` / `TestScoredScenario_ExcludesTutorial` = `:300-322`) に追加する:

- 実カタログ + 実 scenario (`scenarios/nimbusbreach-full/scenario.yaml`) を読み、
  **各 evade 課題 `c` について `c.ForbiddenRules ∩ (c より前の全 trigger 課題の ExpectedRules)`** を計算する
- この交差が**空でないこと自体は正常**である (03/05/10 で必ず非空 = C2)。
  テストの役割は **「非空である」という事実を明示的に pin し、attempt スコープ実装の存在を要求する**こと
- 具体形: 交差が非空な `(先行 trigger, 後続 evade)` ペアの集合を期待値として列挙し、
  **期待値と一致しなければ FAIL** させる。新しい課題を追加して交差が増えたら、
  作者は attempt スコープが自分の課題に効くことを確認した上で期待値を更新せざるを得ない
- 併せて **scoring 側の交差テスト**: 上記ペアについて
  「先行 trigger の expectedRule を発火 → 後続 evade が dirty でない」を実カタログで assert する

> **根拠: 今回の BLOCK はこれ 1 本で捕まった。** そして理由は「fixture の形が足りない」ではない —
> **合成 fixture は既にこの交差を持っている**:
> `scoring_test.go:154-175` は `01-trigger` の `ExpectedRules` と `02-evade`/`03-exfil` の
> `ForbiddenRules` を**同一のルール名 (`Read sensitive file untrusted`) で定義**しており、
> `server_test.go:30-51` と `journey_api_test.go:32-34` も同型である。
> 欠けているのは **fixture ではなく「正規進行を通す property assertion」**:
>
> - `TestEvaluateTrigger_SolvesMatchingChallenge` (`scoring_test.go:209-231`) はルールを発火させて
>   `01-trigger` の solve を assert するが、**その後 `02-evade` を submit しない**
> - `TestSubmitEvade_ForbiddenFired_NotSolved` (`:313-342`) と
>   `TestMarkDirtyOnRuleFire_TaintsOnlyMatchingEvadeChallenges` (`:372-398`) は
>   **「そのルールが発火したら 02/03 が taint される」を期待動作として positively assert している**
>   = BLOCKING-1 そのものを仕様として encode している
>
> **R2 が指摘した「旧テスト名が exploit を期待動作として assert していた」のと完全に同じ失敗形**であり、
> 個別の assertion では検出できない。検出できるのは
> **「先行 trigger をその必須発火でクリアしたあと、後続 evade が submit 可能である」**という
> 進行 property を、**実カタログのペア集合に対して**回す形だけである。

### (b) clock 非依存の回帰 【I11 昇格の必須条件】

#124 で追加された以下を維持する (attempt スコープ導入後も pass しなければならない):

- `TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance` (`internal/scoreboard/scoring/scoring_test.go`)
- `TestDirtyFlag_SurvivesStoreRestart` (実 SQLite の `Close()` → 同一ファイル `Open()` で
  pod 再起動を模し、Sweeper が誤って auto-solve しないことを検出) — **#120 経路 2 の回帰本体**
- `TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved` (旧 `..._AfterWindow_Solves` の反転)

> 旧テスト名 `TestSubmit_CorrectFlag_AfterWindow_Solves` は **exploit を「期待動作」として
> assert していた** (R2)。脆弱性がテストスイートに仕様として encode されていたことが穴の生存要因の 1 つ。
> **反転したテストを消さないこと自体が verification である。**

### (c) 最高リスク形状の fixture

**複数 `ForbiddenRules` + `requireExfil`** の evade fixture を `scoring_test.go` / `server_test.go` に追加する。
実カタログの `10-final-exfil` は **7 forbidden rules + `requireExfil: true`**
(`challenges/10-final-exfil/falco-rule.yaml:4-10,18`) で **本番で最もリスクが高い形**なのに、
既存 fixture は単一 forbidden rule しか持たない (R2 指摘。件数は 7 に訂正)。
少なくとも: 7 本のうち 1 本だけ発火 → dirty / reset → A2-2 に従い receipt 無効化 → 再 exfil 無しでは solve しない。

### (d) E2E 受け入れ条件 【本番投入の gate】

**正規順に 01, 02, 04, 06, 07, 08, 09 をクリアした後、手動 reset なしで 03 / 05 / 10 が
submit / auto-solve 可能であること。**

- 実行主体: qa-engineer。`scripts/` の既存 E2E / `verify*.sh` 枠に載せる
- **10 は auto-solve 経路 (exfil → Sweeper) と手動 submit の両方**を確認する
  (両者は `evaluateClean` を共有するが、共有が壊れていないことを確認するのが目的)
- **この (d) が green でない限り本番 stand-up に載せない。** #124 の欠陥はユニットテスト全 green で
  通過しており、**参加者の正規進行を通す試験がなければ検出できないクラスの回帰**である

### (e) reset の削除順 (fail-closed) の回帰 【I11 昇格の必須条件・F1】

A2-2 の追加要件 (**`exfil` 先 / `evade_dirty` 後**、理想は 1 トランザクション) を pin する。

- **「両方成功した場合」を見るテストでは順序を区別できない。** 既存の
  `TestResetDirty_ClearsExfilReceiptToo` (`internal/store/store_test.go:434-454`) は
  reset 後に taint も receipt も消えていることを assert するが、
  **どちらの `DELETE` が先かに依存しない**ので F1 の fail-open を通してしまう。
  区別できるのは **2 番目の `DELETE` だけを失敗させたとき**だけである
- 具体形: `package store` の in-package テスト (例 `internal/store/reset_order_internal_test.go`) で
  **`exfil` テーブルだけを使用不能**にし (in-package なら未 export の `s.db` に到達できる。例:
  `s.db.Exec("DROP TABLE exfil")`)、**dirty + receipt を両方持つ pair** に対し `ResetDirty` を呼ぶ
- assert: **(1)** error が返る **(2) `DirtyRules` が空でない** (in-memory と、再 `Open()` 後の永続行の両方)
  **(3)** その pair の evade submit が `EvadeForbiddenFired` のまま (= submit が閉じている)
- 判別性: **1 トランザクション実装なら原子性で pass**、**`exfil` 先の順序実装なら 1 本目が失敗するので pass**、
  **現行の `evade_dirty` 先実装では (2) が FAIL する**
- ⚠️ **既存の `TestMarkDirty_FailClosed_InMemoryTaintSurvivesPersistenceFailure` (`store_test.go:456-476`) が
  使う「`Close()` して Exec を失敗させる」手法を流用してはならない** — この手法では
  **1 本目の `DELETE` から失敗する**ので、`evade_dirty` 先 / `exfil` 先のどちらでも pass してしまい
  順序を区別できない (F1 を検出しないテストは Verification にならない)

### I11 昇格の条件 (再掲)

**architect の判定 (2026-08-18, Accepted 化時) = 「yes, if」。** 条件は次の 2 つを**両方**満たすこと:

1. **(a) + (b) + (e) が main に landing している** ((e) は F1 の fail-open を捕まえる唯一の機械的検査なので、
   これを欠いた昇格は「紙のルール」を増やすだけになる)
2. **実装 PR #124 と本 ADR ブランチ (`origin/docs/adr-0001-0002`) の両方が main に merge されている** —
   ADR が main に無い状態で `.claude/rules/falco-ctf-app-conventions.md` に I11 を書くと
   **参照先の無いルール**が生まれる。ORGANIZATION.md:347 の歯止め (Verification 無き ADR を昇格させない) の趣旨は
   「機械で確認できる根拠が main 上に存在すること」であり、ADR 本体も含む

→ **本 ADR の Accepted 化と同時に I11 を追記することはしない。`.claude/rules/` への追記は merge 後の別作業**
(architect が起票、VP 承認、ORGANIZATION.md §4)。

(c) は昇格の必須条件ではない。**(d) が未実施のまま prod 投入することは認めない** — この gate は
Accepted 化によっても緩めない (#124 の欠陥はユニットテスト全 green で通過した実績がある)。

---

## Advice

受けた助言の記録 (ORGANIZATION.md §4 / architect.md の ADR 書式に従い、非拘束でも記録する)。

### security-engineer (R1) — 2026-08-18

出典: PR #124 の VP 査定コメント (`gh api repos/Qfour/falco-ctf-app/issues/124/comments`, 2026-08-18T02:39:53Z)。
R1 判定 = **BLOCK**。architect (R4) と**独立に同じ BLOCKING に到達**。

1. **BLOCKING-1**: 正規進行で 03/05/10 が恒久 dirty になる (→ 本 ADR の C3・A1)
2. **BLOCKING-2**: `ResetDirty` が exfil receipt を残すため **reset 1 回で capstone が auto-solve** される。
   exploit が「発火 → 待つ → solve」から「発火 → reset → solve」に置換されただけ。
   しかも `TestSweep_ForbiddenFired_NotSolved` がこの挙動を「意図どおり」として固定している (→ A2-2)
3. **HIGH**: reset API が参加者から到達不能 (origin-guard で `curl` 403 + portal に導線無し)。
   ⚠️ **collector allowlist 追加で解決してはならない** — ヘッダ無し = claimed identity を許すため、
   **他人の taint を消し他人に capstone solve を付与できる帰属改竄経路**になる (→ Consequences)
4. **HIGH**: criticality の逆転 + fail-open (`MarkDirty` 失敗が 200 + ログのみ、
   DB エラー時は in-memory taint すら立たない) (→ A5)
5. **認定した前進**: #120 経路 2 (再起動 → 偽 solve) は実コードとテストの両方で閉じた
   (`loadFromDB` が起動時に taint を復元、ゲートから時刻引数が完全に消えた)
6. **Issue #121 (2026-08-18, ADR-0001 の脅威モデル監査中に発見)**: mission 05 は素の `cat` で
   無検知に solve できる (forbidden rule が `proc.cmdline` しか見ていない)。
   **#120 と同根 = 負の条件だけで採点している** (→ C5・A7)

### qa-engineer (R2) — 2026-08-18

出典: 同上。R2 判定 = **APPROVE with comments**。

1. **複数 `ForbiddenRules` + `requireExfil` の fixture が無い** — 実カタログの 10 が
   **本番で最もリスクが高い形**なのにテストされていない (→ Verification (c))。
   ※ R2 は「5 rules」と記録したが、実ファイル検証の結果 **7 rules** (`falco-rule.yaml:4-10`)。本 ADR で訂正
2. `TestDirtyFlag_SurvivesStoreRestart` は実 SQLite の `Close()` → `Open()` で pod 再起動を忠実に模しており、
   **R2 が自ら gate を無効化して FAIL を再現**した = 本物の回帰テストと認定 (→ Verification (b))
3. **旧テスト名 `TestSubmit_CorrectFlag_AfterWindow_Solves` は exploit を「期待動作」として assert していた。**
   脆弱性がテストスイートに仕様として encode されており、これが穴の生存要因の 1 つ。
   反転は正当な改変と判定 (→ Verification (b) の注記)

### product-engineer — 2026-08-18 (経由: PR #124 受け入れ条件)

**「初期値: `dirty = false` (課題を開始した時点)」** — attempt スコープはここで既に定義されていた。
本 ADR は**この助言を正典化するために存在する** (C1)。
併せて: 03/05 の学習目標は「静かに操作する態度」ではなく
**「ルールが `fd.name` / `proc.cmdline` の何を見て何を見ていないかの理解」**であり、
騒がしく取って待つ (または 1 発で抜ける) のは**学習目標の完全な未達**。

### architect (R4) — 初回レビュー 2026-08-18 (対象 `d24fe02`)

本 ADR の起草者自身のレビュー。BLOCKING-1 に独立到達、`windowSeconds` 全撤去 (A3)、
`Grader.OnRuleFire` 統合 (A4)、Option 1/2/3 の分析、
**「evade の clean 判定は時間に依存しない」は誤った命題である** (C4) を提示。
また「両リポに `docs/adr` は無い」と報告したが、これは **`main` 基準では正**
(0001/0002 は `origin/docs/adr-0001-0002` に commit 済 = `0ee7899`、main 未 merge)。
本 ADR は 0003 から採番している。

### architect (R4) — 再レビュー 2026-08-18 (対象 `04c217a` = attempt スコープ実装)

実装 commit に対する findings。**F1 が merge blocker、F2 / F3 が prod 前必須**、F4-F7 は LOW / NIT。
`file:line` は architect が `04c217a` で再検証済。

| # | 重大度 | findings | 出典 | 反映先 |
|---|---|---|---|---|
| **F1** | **MEDIUM・merge 前修正要求** | `ResetDirty` が**非トランザクション**かつ **`evade_dirty` 先削除**。`DELETE FROM evade_dirty` 成功 + `delete(s.dirtyRules)` の後に `DELETE FROM exfil` が失敗すると **「taint 無し + 古い receipt」**が残り、**A2-2 が閉じたはずの「発火 → reset → Sweeper が 5 秒で auto-solve」がエラー経路から再生する fail-open** | `internal/store/store.go:779-798` (`:783-789` evade_dirty / `:791-797` exfil)、auto-solve 経路 = `scoring.go:729-732,782` + `internal/store/store.go:606` | **§A2 の追加要件** (`exfil` 先 / 理想は 1 Tx) + **Verification (e)** |
| **F2** | **MEDIUM・prod 前必須 (content-engineer)** | 参加者向け記述が撤去済みモデルを教え続けている。特に **`PARTICIPANT-HANDBOOK.md:171-173` の「10 秒待つ か、Pod を再起動 (運営に依頼) でリセット」は、taint が永続化済みで再起動では消えないため運営工数を誤誘導する** | `challenges/PARTICIPANT-HANDBOOK.md:84,119,171-173`、`challenges/10-final-exfil/journey.yaml:11,22,27` (portal 描画 = 最高露出)、`challenges/10-final-exfil/README.md:50,63-64`、+ architect 追加分 `challenges/{03-stealth-read,05-silent-search,10-final-exfil}/fixtures/welcome.txt:17,41 / :16 / :29` | **Consequences の runbook 節にインベントリ表として明記** (A3 項目 7 の未完了分) |
| **F3** | **HIGH・prod 前必須 (application-engineer)** | 参加者から reset が到達不能なまま (portal に導線なし / workspace `curl` は origin-guard で 403)。**`portal.html:1529` が「reset-dirty でやり直すまで自動クリアされません」と手段のない指示を新たに表示**している。A2-2 によりボタンには**「再 exfil が必要」の明示**が要る。⚠️ **collector allowlist 追加で解決してはならない** (R1: 帰属改竄経路) | `internal/scoreboard/view/templates/portal.html:1523-1531` | **Consequences の runbook 節** (文言要件を含む) |
| **F4** | LOW | `TaintErr` で即 500 `return` するため、**同一イベントで永続化に成功した trigger solve の `SolvesTotal` が計上されない**。また `accepted` と `taint_error` の**二重計上**で `FalcoEventsReceived` の label 合計が受信総数と一致しない | `internal/scoreboard/ingest/ingest.go:143-147` (return) / `:160-162` (`SolvesTotal`) / `:128` (`accepted`) / `:145` (`taint_error`) | **§A5 要件 6** (metric bump と solve 計上を 5xx の前へ、label を排他に) |
| **F5** | LOW | `OnRuleFire` に **user 単位の直列化が無い**。trigger solve 確定直後に到着した発火が**古い `current` で評価される窓 (ms)** がある。**寛容側 (taint しない側) に倒れる**ので A1 と矛盾しないが、イベント率が上がると窓に入る確率が上がる | `scoring.go:421-425` (mutex 無し)、`currentMission` = `:237-245` | **Signpost 6** (per-user mutex は必要になるまで入れない) |
| **F6** | LOW | `docs/openapi-scoreboard.yaml` は **`/api/users/{user}/journey` 自体を未記載**なので、A3 が新設した `dirty` / `dirtyRules` の**参加者向け契約がコードにしか存在しない**。A8 が要求していない**既存**ギャップ | `04c217a` の path 一覧 = `:27,52,74,120,160,216,269,296,335,347` (journey が無い) | **§A8-3 に follow-up issue として記録** (本 ADR の完了条件には含めない) |
| **F7** | NIT | `docs/db-schema.md` が **未 merge の PR #124 / 本 ADR を v2 / v2.1 として日付付き確定形で記載** | `docs/db-schema.md:317-318` | **§A8-4 に運用メモ** (merge 時に日付と状態を確定) |

### Accepted 化に伴う ADR 側の訂正 (C-1〜C-4。実装は正、ADR が誤っていた分)

R4 再レビューで判明した **「ADR 本文 vs 実装」の食い違い**。いずれも**実装が正しい**ので ADR を訂正した
(findings F1-F7 とは別枠。実装への要求ではない):

| # | 訂正内容 | 実装 (`04c217a`) | 訂正先 |
|---|---|---|---|
| **C-1** | A4 の signature を `([]TriggerResult, error)` → **`RuleFireOutcome{Results, TaintErr, TriggerErr}`** | `scoring.go:394-398`、handler 分岐 `ingest.go:143-158` | **§A4** (struct にする理由も明記) |
| **C-2** | 「なぜ struct なのか」= **A5 が taint 失敗と trigger 失敗に異なる反応を要求する**ため。`errors.Join` した単一 `error` では handler は文字列照合か区別放棄しか選べない | 同上 | **§A5** (要件側にも明記して将来失われないようにした) |
| **C-3** | A4 の「**型システムが保証する事実**」は過大。**export 規則 = コンパイル時**に強制されるのは「両方を必ず通る」であり、**順序そのものは `OnRuleFire` 本体の 2 行でパッケージ内編集で反転可能** = 強制はテスト | 順序 `scoring.go:422-423`、反転検出 `scoring_test.go:401` 第 1 段 / `internal/scoreboard/server_test.go:543` | **§A1 に強制手段の表を追加**、§A4 の文言修正 |
| **C-4** | metric label は `result` ではなく **`outcome`** | `metrics.go:16-17,26-34`、`ingest.go:145` | **§A5 要件 2 / Signpost 3** |

**Accepted 化の判定**: **F1 の修正が実装 PR #124 の完了条件** (merge gate)、**F2 / F3 が prod 投入前の必須条件**。
C-1〜C-4 は本 ADR 側の訂正で解消済。
**I11 の `.claude/rules/` 追記は「yes, if — 実装 PR #124 と本 ADR ブランチの両方が main に merge されること」**
(Verification 末尾を見よ)。

### security-engineer (R1) — 追加 findings C2 (2026-08-18。VP が実コードで確認)

**`current` を進ませないことが taint 回避手段になる**。特に **10-final-exfil では capstone gate が実質 inert** になる
(→ **§A1 の W2**、**Signpost 5**、**Consequences**)。VP の実コード確認:
`CurrentMission` = 最初の未 solve (`scoring.go:221-231`) / `evaluateTrigger` は
「Deliberately NOT attempt-scoped」(`scoring.go:293-297`) / `Sweep` は `PendingExfilSolves` → `evaluateClean` で
`current` 非参照 (`scoring.go:729-752`) / 10 の禁止 7 本 ∩ 03 の禁止 1 本 = 1
(`challenges/10-final-exfil/falco-rule.yaml:4-10` ∩ `challenges/03-stealth-read/falco-rule.yaml:4`)。
architect 追加検証: `challenges/submit-yaml.sh:2-16` の一括提出フローにより **W2 は既定経路で成立する**。

#### R1 の非拘束緩和案に対する architect 判定 — **却下 (2026-08-18)**

R1 案: **「receipt が存在する `requireExfil` 課題は attempt 開始済とみなし、`current` でなくても taint 対象に含める」**
(taint 錨 = `current(u) ∪ { c : c.RequireExfil ∧ receipt(u,c) ∧ ¬solved(u,c) }`)。

**却下する。規模を理由にしない、3 つの構造的な理由:**

1. **W2 の記述された経路を閉じない (効果が非対称に誤っている)。** 錨は **receipt が存在してから**効き始めるので、
   **「先に全部騒がしくやってから最後に exfil する」順序では taint がゼロのまま**である。
   閉じるのは「exfil を先に届けてから騒がしくする」順序だけで、これは**悪用として自然な順序ではない**
2. **正規参加者にだけコストが出る。** flag を早めに届けて 07-09 を続ける進め方 (推奨手順に沿う)は
   **必須発火で再 taint** され、**reset + 再 exfil (A2-2 により receipt も消える) を強いられる**。
   = **偽陽性は honest path に、偽陰性は exploit path に**という最悪の非対称
3. **A1 の錨を二重化し、境界を曖昧にする。** 本 ADR の全体は
   **「attempt スコープ = `current` 1 本」**という単一定義に乗っている (A1 / F5 / Signpost 1 がこれに依存)。
   2 本目の錨 (receipt) を足すと、**「receipt はどの attempt の証跡か」という Option 1 (epoch) の問いを
   スキーマ無しで答えることになり**、Signpost 2 が予告した破綻を先取りして引き受ける

**代替案として検討し、これも却下**: **`Sweep` に `current` 参照を入れる**
(auto-solve を `c == current(u)` のときだけ許す)。理由: **これも W2 を閉じない** —
参加者が 03 / 05 を submit して `current` を 10 まで進めれば、**それ以前の騒がしい発火は依然 exempt** なので
receipt はそのまま通る。得られるのは「10 まで歩かせる」だけで、代償として
**`current` の消費者が `Sweep` にも増える** (単一ソース原則の希薄化)。

**採る道 = 受容 + Issue #121 の積極証明で閉じる (VP 推奨と同じ)。** 本 ADR は W2 を
**受容した残存リスクとして明記**し (A1 の W2 / Consequences / Signpost 5)、
**#121 の scope に mission 10 を含めることを要求する**。
これを覆す信号は **Signpost 5**。**残存リスクの受容そのもの (採点公平性の受容) は CEO 判断事項であり、
本 ADR 時点では未承認** — CEO が受容しない場合の唯一の実行可能な選択肢は
**#121 (mission 10 の積極証明) をリハ前に前倒しすること**であり、緩和案 1 / 2 ではない。

### R1 / R2 findings の閉止状況 (2026-08-18 再レビュー時点、`04c217a` 基準)

初回レビュー (上記 R1 / R2 節) の findings が実装でどう閉じたかの対応表。**未閉止を隠さないために記録する。**

| findings | 状態 | 根拠 |
|---|---|---|
| R1 BLOCKING-1 (正規進行で 03/05/10 が恒久 dirty) | **閉止** | attempt スコープ = `scoring.go:361-375`。回帰 = `scoring_test.go:401`、`scoring_test.go:1191` (実カタログ)、`internal/catalog/catalog_test.go:343` (交差 pin)、`server_test.go:543` (HTTP) |
| R1 BLOCKING-2 (reset 1 回で capstone auto-solve) | **成功経路は閉止 / エラー経路は F1 で未閉止** | `store.go:766-799` が exfil も削除。ただし削除順が fail-open = **F1** |
| R1 HIGH (reset API が参加者から到達不能) | **未閉止 = F3 (prod 前必須)** | portal は dirty 表示のみで reset 導線が無い。`portal.html:1529` は手段の無い指示を新たに表示 (実装前より悪化)。⚠️ collector allowlist で解決してはならない (帰属改竄経路) |
| R1 HIGH (criticality 逆転 / fail-open) | **閉止** (fail-closed 化 + 5xx + `taint_error` metric)。**metric / solve 計上の順序に F4 が残る** | `internal/store/store.go:721-728`、`ingest.go:143-146`、`internal/store/store_test.go:456-476` |
| R1 #121 (05 は素の `cat` で無検知 solve 可) | **受容 (別 Issue)** | package doc に honor system として明記 (`scoring.go:69-82`)。閉じるのは #121 = A7 (本 ADR merge 後) |
| R1 C2 (`current` 固定で capstone gate が inert) | **受容 (緩和案は却下)** | A1 の W2 / Signpost 5 / Consequences。`main` の 30 秒窓でも成立したので退行ではない。閉じるのは #121 に mission 10 を含めること |
| R2-1 (複数 forbiddenRules + requireExfil の fixture 不在) | **充足** | `TestSubmitEvade_SevenForbiddenRules_ResetRequiresFreshExfil` (`scoring_test.go:1261`) = Verification (c) |
| R2-2 (`TestDirtyFlag_SurvivesStoreRestart` は本物の回帰テスト) | **維持** | `scoring_test.go:543`、store 側は `internal/store/store_test.go:486` |
| R2-3 (旧テスト名が exploit を期待動作として assert していた) | **反転で維持** | `TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved` (`server_test.go:577`) = Verification (b) |
