# ADR-0022: I15 の reverse audience 混入検査を Exact エントリにも拡張する (ADR-0021 D2 の限定 supersede)

- Status: **Accepted** (2026-08-29。architect 起案 (ADR-0021 起草者本人による self-catch,
  review-5x R4) → security-engineer 再確認 (ADR-0021 と同じ origin-guard/ingress 境界の
  Accepted 条件) で「穴なし — param 付き route への誤マッチ不能・3 分岐の相互排他性・blocking
  妥当性・narrow supersede の一貫性・mutation 検出力をすべて手計算で確認」→ objection なしに
  つき VP 時限自動承認)
- Date / Deciders: 2026-08-29 / architect (起案)、security-engineer (再確認・条件充足)、
  VP (承認)
- 関連: Issue #240 (本 ADR の発注元) / ADR-0021 (I15 新設、本 ADR が**限定 supersede**
  するのは D2 の Exact エントリに関する記述のみ — O1/D1/D3/D4・CI 配線・Verification
  V(I15)-1/4/5 は無傷のまま存続) / #95・#235 (I15 が防ぐ元の defect class)
- フェーズ: P## 非該当

## Context

### C1. ADR-0021 が Accepted 済み・実装済み・main に landing 済みであること

`docs/adr/0021-ingress-participant-route-coverage-gate.md` は Status: Accepted
(2026-08-29)、実装は `internal/apispec/ingressparity/*` + I15 として
`.claude/rules/falco-ctf-app-conventions.md` の Hard Invariants 表に既に昇格済み
(PR #241, `main` に landing 済み)。architect の自己規律 (ADR フォーマットの
「既存 ADR は書き換えず新 ADR で supersede する」、ORGANIZATION.md §8 と同一の規律) を
自分自身の直近の成果物に対しても例外なく適用する — **ADR-0021 の Decision/Verification
本文は直接編集しない**。ADR-0021 自身が C2 節で「ADR-0005 は自ら Decision/Verification を
凍結しており、それを書き換えるのではなく新しい主張 (I15) を新設した」という論法で
I14 を無傷のまま残した。同じ論法を、今度は ADR-0021 自身に適用する。

### C2. 見つかったギャップの実測 (Issue #240、review-5x R4)

`internal/apispec/ingressparity/ingressparity.go` の `CoverageDiff` (ADR-0021 D2/D4):

```go
for _, e := range paths {
    if e.PathType != "Prefix" {   // ← Exact エントリを reverse 検査から完全に除外
        continue
    }
    ...
}
```

`DeadExact` (V(I15)-3, advisory) は「literal 一致する mux Route が**存在しない**」
ことだけを見て、一致した Route の audience は一切見ない。結果として:

**Exact エントリが実在する非 participant (admin/operator) route に literal 一致する
ケースは、forward 検査にも reverse 検査にも DeadExact にも引っかからず green のまま
通過する。** 例: `ingress-journey.yaml` に将来 `path: /api/state, pathType: Exact`
(Audience: Operator, `internal/scoreboard/api/api.go:338` 相当) を手で書き足す誤りを
しても、I15 は検知しない。

### C3. なぜこれが D2 の「見落とし」であって「別の決定」ではないか

ADR-0021 D2 は Prefix エントリの audience 混入を **blocking** にした論拠として
ADR-0005 Decision 4 (origin-guard) の「両方向に事故がある = 契約」を援用した。
この論拠は Exact エントリにも**同じ強さで**当てはまる — #95/#235 はどちらも
「正しい Exact エントリを書き忘れる」(forward の欠落) だったが、その**逆方向**
「間違った Exact エントリ (誤った path、または誤って非 participant route と衝突する
path) を書いてしまう」も同じ手作業起因のリスクである。D2 が Exact について書いたのは
「死んだ登録 (advisory)」のケースだけで、「audience 混入 (blocking であるべき)」の
ケースへの言及が丸ごと抜けていた。**これは D2 の決定内容が変わるのではなく、D2 が
最初から適用されるべきだったが実装で対応漏れになった第 3 の分岐 (「一致しない」
「一致するが audience 違い」「一致して participant」のうち中央) を埋める**。

### C4. なぜそれでも「ADR 不要の実装追記」ではなく新規 ADR が必要か

ORGANIZATION.md §8 の発注基準①「Hard Invariants / Key Guards の**追加・変更・例外**」に
該当する。理由: I15 の正典文言 (`falco-ctf-app-conventions.md` の I15 行、および
ADR-0021 D1) は明示的に「同 allow-list の各 **Prefix** エントリが到達させる mux Route
は audience==Participant」と書いており、**"Prefix" という限定は意図的な決定の一部**
(D2 が Exact を別枠 (advisory dead-only) 扱いにする根拠を明示的に書いているため、
単なる書き漏れではなく検討済みの選択として記録されている)。この限定を外して
「各エントリ (Prefix/Exact 問わず)」に広げるには、**I15 の主張文そのものを書き換える
必要がある** — これは文言レベルでの Hard Invariant の変更であり、規模の大小に関わらず
①の基準を機械的に満たす。加えて「admin/operator route が participant 向け single-origin
ingress 経由で到達可能になる」という事象そのものが認可境界に隣接するため③
(認証・認可境界の設計変更) にも該当する。

## Options

本 ADR は ADR-0021 の O1 (CI 配線: `Dockerfile.test` への `go install helm` pin,
required `test` への相乗り) を**再検討しない** — 既に実装・landing 済みの機構
(`internal/apispec/ingressparity`, `make test`) にロジックを 1 つ足すだけで、
新しいツール・新しい CI job・新しい required check 名は一切必要ない。よって
CI 配線の選択肢は無く (自明に「既存機構に追記」のみ)、実質的な論点は
「この gap をどう埋めるか」の 1 点に絞られる。

### O1 (推奨). `CoverageDiff` の reverse ループから `PathType != "Prefix"` フィルタを削除し、`covers()` を Exact にもそのまま適用する

- **変更点**: `internal/apispec/ingressparity/ingressparity.go` の reverse ループ
  (現 `CoverageDiff` 2 つ目の `for` ブロック) から
  `if e.PathType != "Prefix" { continue }` を削除する。`covers(rt.Pattern, e.Path,
  e.PathType)` は ADR-0021 D3 の時点で**既に** `pathType == "Exact"` の分岐
  (`!hasParam && pattern == path`、リテラル完全一致・param 付き Pattern は非被覆) を
  正しく実装済みであり、この分岐は forward 検査 (V(I15)-1) で日常的に使われ続けている
  経路そのものなので、reverse 側で有効化しても新しいロジックを 1 行も書く必要が無い。
  `foreign` の注釈文字列 (`"... via ingress Prefix " + e.Path`) だけ
  `e.PathType` を使うよう動的化する (`"via ingress " + e.PathType + " " + e.Path`)。
- **コスト**: 実装差分は 3-4 行 (フィルタ削除 1 行 + 注釈文字列の動的化)。
  新規ヘルパ関数・新規ファイル・新規テストヘルパは不要 — 既存
  `coverage_test.go` の `route("GET", "/api/state", apispec.AudienceOperator)`
  ヘルパ (現に `TestCoverageDiff_GreenOnMatchedInput` が使用中) をそのまま
  V(I15)-6 の fixture に転用できる。
- **リスクと可逆性**: `covers()` の Exact 分岐は D3 で security-engineer レビュー済み
  (bare exact route の trailing-slash 非対称は Prefix 専用の懸念であり、Exact の
  `pattern == path` 完全一致には影響しない — D3 本文が既に「k8s の Exact は Prefix と
  異なり末尾 `/` を正規化しない」と明記済み)。よって新しい正確性リスクを持ち込まない。
  可逆性: 1 行 revert で完全に戻る。
- **効き始める閾値**: 1 本目の Exact エントリ×非 participant route 衝突から
  (I15 本体と同型)。

### O2. `DeadExact` を audience 判定込みに拡張し、3 分岐を 1 関数に統合する

- **変更点**: `DeadExact` の内部で一致した Route の audience も見て、
  `(dead []string, foreignExact []string)` の 2 値を返すよう signature を変える。
- **コスト**: 呼び出し側 (`internal/scoreboard/ingress_journey_parity_test.go`) の
  呼び出し規約変更が要る。「dead (advisory)」と「foreign (blocking)」という**検査の
  重大度が違う 2 つの主張**を 1 関数の 2 戻り値に同居させることになり、
  advisory と blocking の呼び分け (advisory は `t.Log`、blocking は `t.Error`/`t.Fatal`
  — V(I15)-3/V8 の既定) を呼び出し側が signature から読み取れず、テストコード側で
  混同するリスクを増やす。
- **リスクと可逆性**: 可逆性は中 (signature 変更なので呼び出し側 diff も伴う)。
  O1 より変更範囲が広いのに得られる検査能力は同じ。
- **効き始める閾値**: O1 と同じ。

## Decision

**O1 を採る。** 理由: (1) `covers()` の Exact 分岐は既に正しく実装・レビュー済みであり、
reverse ループの人為的な `PathType != "Prefix"` フィルタを外すだけで forward/DeadExact
と完全に独立したまま 3 分岐 (dead / foreign / OK) が自然に得られる — C3 で述べた
「一致しない」「一致するが audience 違い」「一致して participant」の 3 ケースが、
DeadExact (audience 不問で存在有無だけ見る) と拡張後の `CoverageDiff.foreign`
(audience 不問で存在する route を全走査し、非 participant なら報告) という
**既に独立した 2 つの述語の組み合わせで自動的に相互排他になる** (ある Exact entry が
同時に dead かつ foreign になることはない: dead は「一致 route が皆無」、foreign は
「一致 route が存在し audience が違う」で排他)。(2) O2 のような signature 変更は
advisory/blocking の重大度分離を弱める副作用があり、需要に対して過剰。

**Decision 詳細:**

### D1'. I15 の主張文を更新する (ADR-0021 D1 を「Prefix」限定から「Prefix/Exact 両方」へ拡張)

> **I15 (更新後)**: scoreboard の `AudienceParticipant` な mux Route
> (`scoreboard.Handler.Routes()`) は**すべて** `ingress-journey.yaml` がレンダリングする
> participant allow-list に含まれる。逆に、同 allow-list の**各エントリ (Prefix/Exact
> 問わず)** が到達させる mux Route (audience 不問) は**すべて**
> `Audience == AudienceParticipant` である (admin/operator/internal route の
> allow-list 混入を、エントリの pathType に関わらず禁止する)。例外・除外リストを
> 持たない。

`.claude/rules/falco-ctf-app-conventions.md` の I15 行の文言を、本 ADR の実装 PR と
**同じ PR で** 上記に更新する (「Prefix」の限定を削り「各エントリ (Prefix/Exact 問わず)」
に置き換える) — I15 という番号・機構の説明文の骨格は変えず、reverse 検査の対象範囲の
記述のみを訂正する。

### D2'. V(I15)-3 (DeadExact, advisory) の意味論を明確化する

DeadExact は**引き続き「一致する Route が皆無」の場合のみ**を advisory 報告する。
「一致するが audience が違う」場合は DeadExact の対象**ではなく**、D3' (新設
V(I15)-6, blocking) の対象である — 両者は排他的なので、実装がどちらか一方に統合
しようとする将来のリファクタ (O2 的な統合) は、advisory/blocking の重大度分離を
壊さない設計であることを個別にレビューすること。

### D3'. Verification 追記 (V(I15)-6)

**V(I15)-6. Reverse audience 混入検査 — Exact エントリ (blocking, 新設)**
`ingress-journey.yaml` の各 **Exact** エントリについて、literal 一致する
mux Route (any audience) が 1 本以上存在し、かつそのうち 1 本でも
`Audience != AudienceParticipant` であれば fail する。**DeadExact (V(I15)-3,
advisory) とは独立した検査**であり、「一致しない」(V(I15)-3 の対象) と
「一致するが audience 違い」(本項の対象) を混同しない。実装は
`CoverageDiff` の reverse ループから `PathType != "Prefix"` フィルタを削除するだけで
足りる (O1) — `covers()` の Exact 分岐 (ADR-0021 D3 で security-engineer レビュー済み)
をそのまま流用するため、新しいマッチングロジックは書かない。

mutation test (V8 スタイル、実出力付き):
1. **新規**: `route("GET", "/api/state", apispec.AudienceOperator)` (既存の
   `coverage_test.go` ヘルパをそのまま使う) を routes に含め、
   `paths = [{Path: "/api/state", PathType: "Exact"}]` を渡した合成入力で
   `CoverageDiff` の `foreign` に `"GET /api/state (audience=operator, via
   ingress Exact /api/state)"` が現れることを assert する。
2. 同じ合成入力を `DeadExact` にも渡し、**空スライスが返る**ことを assert する
   (「一致する route が存在する」ので dead ではない — D2' の排他性を固定する
   regression guard)。
3. **既存の `TestCoverageDiff_GreenOnMatchedInput` (`coverage_test.go:209`)** に
   `{Path: "/api/state", PathType: "Exact"}` を additive で足すと、本 ADR の修正
   **前**は green のまま (fix していないことの実害の実演)、修正**後**は red になる
   ことを、実装 PR の PR 本文に before/after の実出力として貼る (恒久化は上記 1 で
   別テストケースとして行うため、この 3 番目はレビュー時の実演用であり
   `coverage_test.go` へ恒久コミットする必要はない — 既存 green baseline test を
   汚さないため)。

## Consequences

### 諦めたもの

- 特になし。実装差分が小さく (3-4 行)、既存の独立した述語 (`covers()` の Exact 分岐、
  DeadExact) を再利用するだけなので、新しいトレードオフは生じない。

### 新たに守る不変条件

I15 の主張文を D1' のとおり更新する。**昇格条件**: 本 ADR の Verification
(V(I15)-6) が landing した PR と同じ PR で
`.claude/rules/falco-ctf-app-conventions.md` の I15 行を D1' の文言に更新する
(ADR-0021 と同じ「先に紙のルールだけ増やさない」規律)。

### ADR-0021 への影響 (Status ブロックのみ追記可)

ADR-0021 の Decision/Verification 本文は**編集しない** (C1 の規律)。ADR-0021 の
Status ブロックには、ADR-0005 の前例 (「Status ブロックは状態記述なので実態に
追随させる — 凍結対象は決定であって状態ではない」) に倣い、本 ADR への forward
reference を 1 行追記してよい (例: 「2026-08-29 Issue #240 で D2 の Exact エントリ
audience 混入検査の抜けを発見 → ADR-0022 で補完 (D2/Verification 本文は本 ADR の
まま凍結、追加のみ)」)。**本 ADR の Decision/Verification 節自体は編集しない** —
この追記は ADR-0021 の「状態」を正しく保つための 1 行に限る。

### runbook / 他ロールへの影響

- **software-engineer**: 実装は D3' の Verification に従う。差分は
  `internal/apispec/ingressparity/ingressparity.go` の 3-4 行 +
  `coverage_test.go` への mutation test 1 件 (V(I15)-6 項目 1・2) +
  `falco-ctf-app-conventions.md` の I15 行更新 (D1')。
- **release-engineer**: 作業ゼロ (ADR-0021 と同じ理由— 既存 required check `test`
  への追記のみ)。
- **security-engineer**: reverse 検査の対象範囲拡大 (Exact 分も blocking になる) は
  origin-guard/ingress 境界に隣接するため、ADR-0021 と同じ条件で実装 PR のレビューを
  必ず通すこと。
- **VP**: Accepted への昇格は、本 ADR に対する security-engineer の advisory
  コメントを得てから行う (ADR-0021 と同じ運用)。

## Signposts (この決定を覆す観測可能な信号)

1. **Exact エントリと Prefix エントリで異なる報告フォーマットが必要になったら**
   (例: 外部ツールが `foreign` の文字列を機械的に parse し始め、pathType ごとの
   構造化が要る) — `foreign` を `[]string` から構造化された型に変える再設計を検討。
2. **`covers()` の Exact 分岐に将来 D3 と別種の修正が入ったら** — 本 ADR が
   「D3 の Exact 分岐をそのまま流用できる」と依存している前提を再検証する。
3. **本 ADR 実装後に Exact エントリ経由の audience 混入が 1 回でも本番へ到達したら**
   — `covers()` の Exact 判定ロジック自体に別の穴があるので、D3 の判定規則を疑う。

## Verification (= software-engineer への発注仕様)

D3' に記載の V(I15)-6 を実装する。既存 V(I15)-1〜5 (ADR-0021) は無傷のまま
`make test` に残る — 本 ADR は V(I15)-6 の追加のみを発注する。

## Advice (受けた助言と出所)

- **VP (2026-08-29、本タスクの委任文)**: 「ADR-0021 への advisory 追記で足りるか
  新規 ADR かは security に諮る」という Issue #240 の自分自身の書き出しに対し、
  「同一方向の網羅範囲拡大なので navigational/事実補完に近いが、微妙なら supersede
  する追補 ADR も選択肢」という私見を添えて architect の一次判定を求めた。
  → **私見の「navigational/事実補完」は採らず、「限定 supersede する新規 ADR」を
  選んだ**。理由: I15 の正典文言 (「Prefix」限定) は D2 が明示的に検討した末の記述
  であり、これを「Prefix/Exact 問わず」に広げるのは ORGANIZATION.md §8 基準①
  (Hard Invariant の変更) に文言レベルで該当する — 変更の**規模**は小さいが、
  CEO 方針 (「規模を却下理由に使わない」) と対称に、**規模の小ささを ADR 省略の
  理由にも使わない**。かつ ADR-0021 自身が C2 節で確立した「Accepted ADR の
  Decision/Verification は書き換えず新設で対応する」という規律を、起草者自身の
  直近の成果物に対しても例外なく適用する一貫性を優先した。
- **software-engineer / Issue #240 起票文 (architect 本人による review-5x R4 の
  self-catch)**: Exact エントリの 3 分岐 (「一致しない」「一致するが audience 違い」
  「一致して participant」) を明確に区別する提案、DeadExact とは独立した検査として
  実装する提案。→ D3'/Decision に全面採用。「一致するが audience 違い」の実装が
  `covers()` の Exact 分岐の再利用で**新規ロジック無しに**閉じることは、本 ADR
  執筆時に architect が `internal/apispec/ingressparity/ingressparity.go` を
  実読して確認した (C2/O1 参照)。
