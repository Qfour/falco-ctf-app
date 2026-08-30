# ADR-0009: V5 のレスポンス欠陥検査を機械列挙・fail-closed 化し、Decision-Verification 不整合を正典化する (ADR-0005 の限定 supersede)

- Status: **Proposed**
- Date / Deciders: 2026-08-31 / architect (起案)。承認は VP・CEO (後日、review-5x 後)
- 関連:
  - **supersede 対象**: [ADR-0005](0005-openapi-canon-and-parity-gate.md) の `## Verification` 節のうち
    **V5 の「最低限カバーすべき4つ」という floor 記述**、および **V3 に対応する named Verification 項目が
    x-ctf-audience/authz/rate-limit の string parity を欠いていた点**の 2 箇所を**限定 supersede** する。
    ADR-0005 の他の節 (Decision 1-5 / V1-V2 / V4 / V6-V8 / I14 提案 / Consequences) は無傷のまま存続する。
    **ADR-0005 本文ファイルは直接編集しない** (Accepted ADR の規律、ADR-0022 と同じ論法)。
  - Issue #144 (本 ADR の発注元。2026-08-19 review-5x R2/R3/R4 が発見した ADR-0005 の設計欠陥 3 件)
  - I14 (`.claude/rules/falco-ctf-app-conventions.md`、ADR-0005 提案・ADR-0021/0022 が別レイヤで拡張) —
    **本 ADR は I14 の文言を変更しない**。I14 の主張はルート集合・origin-guard・collector-forward の
    3 点のみで、レスポンスの field-set parity (V5) や x-ctf-audience/authz/rate-limit の string parity
    (V3b) はそもそも I14 の対象外 (ADR-0005 の Consequences 節の I14 提案文自体がこの 3 点しか主張していない)。
    したがって本 ADR は新規 Hard Invariant を提案しない (下記 Consequences 参照)。
  - Issue #181 (ADR 番号衝突の再発 3 件と機械検出の要望。CLOSED — `docs/adr/README.md` の
    `check-adr-numbers.sh` 導入で対処済み。本 ADR 自体が「ADR-0009 予約」の当初目的を果たす)
  - ADR-0021 / ADR-0022 (限定 supersede の書式手本。同型の論法を踏襲)
- フェーズ: P## 非該当 (2026-08-19 組織診断の「機構化されていない規約は 0% 遵守」への継続対処)

## Context

### C1. ADR-0005 は Accepted・本文凍結済みで、5x review (2026-08-19) が3件の設計欠陥を発見した

ADR-0005 (`docs/adr/0005-openapi-canon-and-parity-gate.md:7`) は「Decision / Verification 節は
以後編集しない」と自己宣言している。Issue #144 は 2026-08-19 の review-5x R2/R3/R4 が発見した
3 件の欠陥を記録し、ADR-0005 自身の Status ブロック (`0005:36-50`) もこの 3 件を「#149 で closed」
「後継 ADR-0007/Issue #144 で条文化」と明示している。本 ADR は 2026-08-31 時点の main で
**各欠陥を実コードから再検証**した上で書く (2026-08-19 時点の findings をそのまま信用しない)。

### C2. 欠陥1 (V5 floor の列挙機構欠如) は**現在も実在**する

ADR-0005 V5 (`0005:366-381`) は「最低限カバーすべき 4 つ: Journey / Me / State / SubmitFlagVerdict」
と書き、実装 (`internal/scoreboard/apispec_parity_test.go:339-380` の `TestAPISpec_V5_*`、
`:442-514` の `TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec`) はこの 4 つだけを検査する。

3 spec を実測すると、200/201 `application/json` の object (または oneOf-of-object) schema を
宣言する operation は **16 本** — scoreboard 14 本 (`Health` `SubmitFlagVerdict` `SubmitDetectVerdict`
`IngestAccepted`/`IngestIgnored` (`POST /falco/events` の oneOf、`docs/openapi-scoreboard.yaml:406-408`)
`ExfilReceipt` `Me` `Journey` `StepCheckResult` `OpenHintResult` `ResetDirtyResult`
`DisplayNameResult`×2 `State` `AdminResetResult`) + collector `GET /healthz` (inline) 1 本 +
auth-policy `GET /healthz` (inline) 1 本。**カバレッジは 4/16 = 25%**、2026-08-19 の R4 実測
(「16本中4本」) と**一致し、変化なし**。

未覆の `StepCheckResult` (`docs/openapi-scoreboard.yaml:1683`) / `OpenHintResult` (`:1693`) /
`ResetDirtyResult` (`:1707`) は falco-api skill が明記するとおり **portal が 2 秒ポーリングで読む
フィールド**を持つ (`journey` detail 経路とは別の書き込み系レスポンス)。フィールド drift が
本番に出ても、この 3 スキーマに対しては現状 V5 は何も検査していない。

P25 で追加された `QuestionList`/`QuestionThread` 系 7 operation
(`docs/openapi-scoreboard.yaml:976,1071,1118,1291,1323,1361`) はいずれのスキーマも
固定キー集合の通常の object schema (variant 形ではない — `QuestionThread.messages[]` は
`$ref: QuestionMessage` の配列で、V5 の既存の再帰規則 (`properties` 宣言箇所のみ再帰・配列は
先頭要素判定) でそのまま検査可能)。にもかかわらず `falco-api` skill (`.claude/skills/falco-api/SKILL.md`)
は「V5 の対象外 (Issue #144参照)」とだけ書いており、**コード上の除外機構は無い** — 単に
誰も書いていないだけである。この「対象外」という記述自体が、本 ADR が閉じるべき紙と実装の
乖離の一部である。

これは ADR-0005 が O1 (advisory カバレッジ率) を却下した理由 (`0005:149`「カバレッジ率は
下がっても merge できるので指標にならない」) と**同型の欠陥**: V5 の「4 つ」という floor は
事実上の固定 allowlist であり、新規 operation が spec に足されても検査対象に自動で入らない。

### C3. 欠陥2 (`CompareResponse` の節点 fail-open) は**現在も実在**し、実機検証で再現できた

`internal/apispec/specparity/compare.go:49-60`:

```go
props, hasProps := resolved["properties"].(map[string]any)
if !hasProps {
    // Known limitation (ADR-0005 "見ないもの", intentionally NOT
    // scheduled for this PR — see ADR-0006 for the F3 discussion of
    // strengthening V5) ...
    return
}
```

(コメントが指す「ADR-0006」は 2026-08-21 の番号衝突より前の旧採番で、現在の本 ADR-0009 を指す
— つまりこのコード自体が「後で ADR で閉じる」ことを見込んで書かれている。)

`internal/apispec/specparity/spec.go:171-199` の `resolve()` は `$ref` と単層 `allOf` のみを
解決し、`oneOf`/`anyOf` には未対応。`docs/openapi-scoreboard.yaml:406-408` の
`POST /falco/events` 200 応答は既に `oneOf: [IngestAccepted, IngestIgnored]`。

**実機検証** (一時テストを `internal/apispec/specparity/` に追加・実行・削除。リポジトリに
差分は残していない):

1. `CompareResponse(spec, /falco/events の 200 schema, actual={"totally_wrong_key": true}, "root")`
   → `mismatches = []` (0件)。IngestAccepted (`accepted/user/rule`) にも IngestIgnored
   (`ignored/reason`) にも一致しない任意の actual を渡しても fail-open。
2. `properties` キーを持たない schema ノード (`{"type": "object"}` のみ) に任意の `actual` map を
   渡しても `mismatches = []`。

V8-2 の非空 assert (`0005:409-411`、および `apispec_parity_test.go:366-379` の
「missions[]/detail/steps[] が空でないこと」guard) は**実 JSON 側の非空**のみを保証し、
**schema 側が properties/oneOf を持っていたか**は保証しない — 欠陥2の指摘は正確。

`0005` の「この検査が見ないもの」列挙 (`0005:415-420`) は「型/値域」「認可挙動」「`text/plain`
文言」「`additionalProperties` map の中身」の 4 点のみを意図的スコープ外と書いており、
**「properties を持たない object 節点」「oneOf 節点」「解決不能な `$ref`」はそこに含まれていない**
— つまり現在の fail-open は ADR-0005 が意図した境界ではなく、単純に**未実装**である。

### C4. 欠陥3 (Decision 2(b) ↔ Verification 不整合) は**機能的には main で既に解消済み**

`specparity.StringExtParity` (`internal/apispec/specparity/parity.go:111-133`) が
scoreboard/collector/auth-policy **全 3 サービス**の `apispec_parity_test.go` に配線済み
(`internal/scoreboard/apispec_parity_test.go:278-301`、
`internal/collector/apispec_parity_test.go:117-146`、
`internal/authpolicy/apispec_parity_test.go:85-111`)。`x-ctf-audience`/`x-ctf-authz`/
`x-ctf-rate-limit` の 3 つを欠落 fail-closed・値不一致 fail-closed で検査する。

Issue #144 が指摘した「`Route.Authz` 反転で green になる穴」は
`internal/scoreboard/apispec_parity_test.go:579-599` の `authz_reversed_in_spec` サブテストが
mutation test として閉止を証明している (spec 側 `x-ctf-authz` を `"none"→"admin"` に書き換え、
`StringExtParity` の `mismatched` に検出されることを assert)。

**しかし** ADR-0005 の凍結された `## Verification` 節本文 (`0005:333-421`) には、この検査に
対応する **named な V-item が存在しない**。V3 (`0005:353-356`) は origin-guard の bool parity
のみを要求し、V4 (`0005:358-364`) は collector forward の bijection のみを要求する。
`x-ctf-audience`/`x-ctf-authz`/`x-ctf-rate-limit` の string parity は ADR-0005 の Status ブロック
(`0005:23-24`、凍結対象外の状態記述)にのみ「#149 で closed」と後から書き足された事実記述として
存在し、**Decision 2(b) (`0005:155` の O2(b)、Decision で採用: `0005:182`) が要求した契約が
Verification 節という正典に条文化されないまま**、実装だけが先行して閉じている。

「機構化されていない規約は 0% 遵守」(2026-08-18 組織診断) の裏側 — **今回は機構は既にあるが、
それを要求する条文が正典 (`## Verification`) に無い**ため、将来の refactor がこの検査を
弱める/削除しても、ADR-0005 のどの条文にも違反しない。これが欠陥3の本質であり、今も未解消。

## Decision

### Decision A — V5 を機械列挙化する (欠陥1の supersede。**実装は別 PR**)

ADR-0005 V5 の「最低限カバーすべき4つ」という floor 記述 (`0005:378-381`) を、
以下の**列挙機構**で置き換える (ADR-0005 の他の V5 記述 — 分岐比較の単位・`nullable`+`required`
の扱い・再帰の深さ規則 — は無傷のまま存続する):

1. 新規 `specparity.ResponseObjectOperations(*Spec) []string` を追加する。3 spec すべてを
   走査し、**200 または 201 の `application/json` schema が `properties` を持つ object、または
   (Decision B で resolve に oneOf 対応を追加した後の) object-only の `oneOf` に解決できる**
   operation を `"METHOD /path"` の集合として機械導出する。除外リストは持たない
   (ADR-0005 Decision 1 と同じ規律)。
2. 各サービスの `apispec_parity_test.go` は、その operation ごとに「フィールド比較テストが
   存在する」ことを宣言する `var v5Coverage = map[string]bool{...}` テーブルを持つ。
3. 新規 blocking test が `ResponseObjectOperations()` の結果と `v5Coverage` のキー集合を
   **双方向比較**する: 導出集合にあってテーブルに無い → 「documented operation, no V5 coverage」
   で fail。テーブルにあって導出集合に無い → 「stale coverage entry」で fail (V1 の
   `RouteSetDiff` と同型の双方向 fail-closed。テーブル自体が新しい drift 源にならないよう、
   欠落側だけでなく過剰側も検査する)。
4. **QuestionList/QuestionThread 系 7 operation は対象に含める** (C2 の判定どおり、これらは
   構造的に通常の固定キー object schema であり、除外の技術的根拠が無い)。`falco-api` skill の
   「V5 の対象外」という記述は本 ADR の実装 PR 着地と同時に訂正すること (application-engineer/
   qa-engineer への申し送り)。
5. 実際のフィールド比較テスト本体 (16 本 → 実装 PR 時点の実測値に更新、うち 4 本は既存流用)
   の**追加作業自体**は、機械列挙が要求する「テストが無ければ fail」という圧力の下で、
   実装 PR (software-engineer + qa-engineer) が行う。本 ADR は機構を spec するのみ。

### Decision B — `CompareResponse` を fail-closed 化する (欠陥2の supersede。**実装は別 PR**)

ADR-0005 の「この検査が見ないもの」列挙 (`0005:415-420`) に暗黙に含まれていなかった
2 つの穴を閉じる (列挙自体の 4 項目 — 型/値域・認可挙動・`text/plain`文言・
`additionalProperties`中身 — は無傷のまま存続する):

1. `compareInto` の map 分岐: `resolved` が `properties` も (Decision B-2 の) `oneOf`/`anyOf`
   も持たない場合、現在の無言 `return` を**廃止**し、`actual` が map である以上これを
   parity failure として報告する (「schema declares neither properties nor oneOf/anyOf but
   actual is an object at this path」)。`properties` の typo・宣言漏れ・解決不能な `$ref`
   のクラスをまとめて閉じる。
2. `resolve()`/`compareInto()` に **oneOf (および anyOf、同一コード経路)** の分岐比較を追加する:
   各ブランチ ($ref 経由が前提。docs/openapi-*.yaml の現行使用パターンに限定 — 汎用 JSON Schema
   resolver にはしない) の `properties` キー集合に対し、`actual` のキー集合が**厳密に一致する
   ブランチが1つだけ**存在することを要求する。0 個一致 (どのブランチにも合わない) または
   2 個以上一致 (ブランチ同士が overlap している spec 側のバグ) はどちらも fail。
   これは `SubmitFlagVerdict`/`SubmitDetectVerdict` に対して既に人手で書かれている
   variant-branch テストパターン (`apispec_parity_test.go:442-514`) を `compare.go` 自身に
   一般化するもので、以後は新しい oneOf schema が増えても Decision A の列挙機構経由で
   自動的にこの分岐比較の対象になる。
3. `$ref` が指す schema 名が `components.schemas` に存在しない場合、`SchemaByName` の
   `nil` 伝播に頼らず明示的な fail (「dangling $ref」) にする。

### Decision C — Decision 2(b) と Verification を正典で一致させる (欠陥3の supersede。**実装は無し。本 ADR の merge が完了条件**)

ADR-0005 の Verification 節に、V3 を拡張する新項目 **V3b** を追加する
(V3 本文はそのまま存続。V3b は additive):

> **V3b. x-ctf-audience / x-ctf-authz / x-ctf-rate-limit の string parity (blocking)**
> 3 spec の全 operation について、`x-ctf-audience` / `x-ctf-authz` / `x-ctf-rate-limit` の
> 各 string extension が (a) 存在すること (欠落は fail-closed、V3 と同じ「既定値を持たない」規律)、
> かつ (b) 対応する `Route` の文字列値と完全一致すること。**この項目は本 ADR 執筆時点の main で
> 既に完全に満たされている** — `specparity.StringExtParity` (`internal/apispec/specparity/parity.go:111-133`)
> が 3 サービス全ての `apispec_parity_test.go` に配線済みで、`Route.Authz` を反転させる mutation
> test (`internal/scoreboard/apispec_parity_test.go:579-599`) で検出されることを確認済み。
> **本項目のための追加実装 PR は不要** — 本 ADR がこの既存の機構を正典の条文として書き込む
> ことそのものが完了条件。

## Consequences

### 諦めたもの / 新たに引き受けるもの

- **Decision A/B は実装 PR を要求する** (software-engineer 主体、qa-engineer が V5 の
  フィールド比較テスト本体を分担)。Decision A だけでも 12 operation 分の新規テストが要る
  ため、PR サイズが 1PR400行制約を超える可能性が高い — **Decision A (列挙機構 + 既存4本の
  移行) と、残り 12 operation のテスト追加は分割 PR にしてよい** (列挙機構が先に着地すれば、
  未着手の operation は「documented, no coverage」で即座に赤くなるので、分割しても
  fail-open のまま放置される期間はゼロ)。
- **`falco-api` skill の「QuestionThread/QuestionList は V5 対象外」記述は本 ADR の実装着地と
  同時に訂正が必要** — 訂正を怠ると skill が再び「紙の記述と実装の乖離」を生む。
- **本 ADR は新規 Hard Invariant を提案しない**。I14 (ADR-0005 提案、ADR-0021/0022 が
  ingress 面で拡張) はルート集合・origin-guard・collector-forward の 3 点のみを主張しており、
  V5 (レスポンス field-set parity) と V3b (string ext parity) はそもそも I14 の主張対象外
  — Decision A/B が実装・landing した後であっても、これらを I14 に**追加**することは
  本 ADR の範囲外の別判断とする (I14 の主張範囲を広げるかどうかは別途 Signpost で判断)。
- **Decision C は landing 済みの機構を追認するだけ**なので、実装コストはゼロ。ただし
  「ADR 本文と実装が事実として一致していない期間」が (少なくとも) 2026-08-21 (#149 merge) から
  本 ADR merge までの約 10 日間存在していたことは記録として残す — 将来同様の「実装が ADR 条文を
  追い越す」ケースでは、実装 PR と同じ PR で Verification 条文を追記する運用を推奨する
  (ADR-0005 自身が I14 の昇格条件でこの規律を既に定めている: `0005:276-279`)。

### runbook / 他ロールへの影響

- **qa-engineer**: Decision A の実装 PR で、未覆 12 operation 分のフィールド比較テストを
  追加する主担当になる。
- **software-engineer**: Decision B (`compare.go`/`spec.go` の oneOf 対応・fail-closed 化)
  の実装主体。既存の `SubmitFlagVerdict` variant-branch テストパターンを一般化する形で
  実装できる (再発明不要)。
- **application-engineer**: `falco-api` skill のうち「QuestionThread/QuestionList は V5 の
  対象外」の記述を、実装 PR 着地後に訂正すること。
- **release-engineer / VP**: Decision A/B の実装 PR は `make test` (required check) に
  相乗りするため、CI 配線の追加変更は不要。

## Signposts (この決定を覆す観測可能な信号)

1. **(Issue #144 R4 提示、継続監視)** V5 未カバーの operation (Decision A 実装前は 12 本、
   実装後もテーブルへの登録漏れが `stale coverage entry` チェックをすり抜けた場合)
   のいずれかでフィールド drift が本番に出たら — Decision A の双方向比較ロジック自体に
   バグがあると判定し、即座に再監査する。
2. **(Issue #144 R4 提示、継続監視)** parity test に「例外」要求が 1 件でも出たら —
   ADR-0005 Decision 1 の「除外リストゼロ」という前提が崩れる。⚠ 除外リストは
   `registrationTargets`(#149で機械化済み)と V5 の 4 schema 選択(本 ADR で機械化)の
   **2 箇所に既に潜在していた**という R4 の指摘を忘れないこと — 3 箇所目が今後見つかったら
   同じパターンを疑う。
3. **Decision B の oneOf 分岐比較が、実際の spec で「ブランチが 2 個以上一致」を報告したら** —
   `IngestAccepted`/`IngestIgnored` のような disjoint 設計の前提が崩れている (spec 側のバグ、
   またはブランチの overlap を許容する新しい oneOf 設計が必要になったことを意味する)。
4. **V3b/V5 の string/field parity を I14 (Hard Invariant) に統合すべきという要求が 2 回以上
   別々の 5x review で挙がったら** — Consequences で見送った「I14 拡張」を再検討する。

## Verification (= 実装 PR への発注仕様。Decision C を除き fail-closed)

**V(A)-1. 列挙の非空・双方向性 (blocking)**
`ResponseObjectOperations()` は 3 spec 合計で 16 本以上を返すこと (P25 の Q* 7 本を含む — 含まない
実装は本 Decision 未達)。`v5Coverage` との双方向比較テストは、(a) 導出集合にのみ存在する
operation を注入した変異と (b) テーブルにのみ存在するエントリを注入した変異の**両方**で
red になることを、テストケースとして実出力付きで示すこと (ADR-0005 V8 と同じ規律)。

**V(A)-2. 抽出の非空 assert (blocking)**
`ResponseObjectOperations()` が 0 件を返したら即 fail (spec 読み込み自体の壊れを検出不能に
しない)。

**V(B)-1. fail-closed 化の mutation 証明 (blocking)**
`properties` を持たない schema ノード (typo 相当) に対する actual map を渡すと現在
`mismatches=[]` になる (本 ADR 執筆時点で実測済み) — 修正後は非空の mismatch を返すことを
テストケースで示す。

**V(B)-2. oneOf 分岐比較の mutation 証明 (blocking)**
`POST /falco/events` の 200 応答 (`IngestAccepted`/`IngestIgnored`) に対し、(a) 両ブランチの
どちらにも一致しない actual、(b) 正しい actual、の両方でテストし、(a) が非空 mismatch を、
(b) が空 mismatch を返すことを示す。

**V(C)-1. Decision C は無し**
実装なし。この ADR ファイル自体が merge されることが完了条件。継続監視は既存の
`TestAPISpec_V3b_StringExtParity` (3 サービス) + `authz_reversed_in_spec` mutation subtest
(いずれも `make test` = required check) がそのまま担う — 新しい機械強制は追加しない。

**この ADR が見ないもの (ADR-0005 の「見ないもの」に追加する新項目は無い)**

Decision A/B は ADR-0005 V5 が元々主張していたスコープ (properties 宣言箇所のみの再帰・
配列は先頭要素判定・型/値域は対象外) を狭めも広げもしない。変わるのは「どの operation が
検査対象になるか (機械列挙)」と「未対応スキーマ構造に遭遇したときの既定動作 (fail-open → fail-closed)」
の 2 点のみ。

## Advice (受けた助言と出所)

- **VP (task #144 発注文、2026-08-31)**: 「各欠陥が現行 main に実在するかを実コードで再確認し、
  解消済みの部分は『解消済み・対象外』と明記すること」→ 欠陥3 が機能的に解消済みであることを
  実コード grep + mutation test の存在確認で裏付け、Decision C を「文書のみ・実装ゼロ」に
  縮小する判断につながった。「V5 の列挙機構(200+json object を宣言する全 operation を機械導出)
  を Decision として spec すること」→ Decision A の骨子そのもの。
- **Issue #144 (2026-08-19 review-5x R2/R3/R4)**: 欠陥 1-3 の発見そのもの。R4 の「16本中4本」
  実測値・2 つの Signpost・「除外リストは既に2箇所に潜在していた」という警句 → Context C2 /
  Signposts 1-2 にそのまま反映。
- **ADR-0005 自身 (`compare.go:51-53` のコメント)**: 「ADR-0006 (現ADR-0009) の F3 discussion」
  として fail-open の解消を name-drop していた → Decision B がその予告を回収する形になった。
