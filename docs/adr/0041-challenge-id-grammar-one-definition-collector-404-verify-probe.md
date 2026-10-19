# ADR-0041: challenge id の文法は 1 定義 (`challengeid.Pattern`) で、collector・scoreboard・platform の verify probe の 3 者が同じ文法を見る。文法外は collector が固定 404 で止め、文法内で catalog に無い id (`99-verify-probe`) は collector が転送して scoreboard の 404 で答える

- Status: **Proposed** (2026-10-19)。
  - クロスリポ契約 (collector の局所応答と platform verify (a-2) の probe) に触れるので、Class-2。architect 合意 + security-engineer APPROVE + VP 承認 (`ORGANIZATION.md` §4・§5) を経て Accepted にする。
  - HTTP の status は 1 つ変わる (collector の exfil: `400 invalid challenge id` → `404 unknown challenge`)。参加者の正規の経路 (正しい id) には影響しない。
  - 新 image・Dockerfile・Hard Invariant に触れない。
- Date / Deciders: 2026-10-19 / 起草: software-engineer。承認: architect (契約表と本 ADR の同意)・VP
- 関連:
  - Issue #445 (発注元。#441 review-5x の HIGH から切り出し)、#437 / #468 (文法の 1 定義)、#478 (`specparity` の識別子 pattern の表)
  - platform PR #264 (probe の id を `99-verify-probe` にし、(a-2) の green を「404 かつ body が `{"error":"unknown challenge` で始まる」に絞った)
  - ADR-0005 (spec ↔ mux の parity。collector の forward は 2 本だけ)
  - フェーズ: 非該当

## Context

- **C1 文法は 1 定義にした。** `internal/catalog/challengeid` の `Pattern = ^[0-9]{2}-[a-z0-9-]{1,60}$` が Go の唯一の定義で、catalog・scoreboard・collector・flags・生成器が import する。spec の `Cid.pattern` は同じ文字列を繰り返し、test が `Pattern` と等しいことを固定する (#468、#478)。
- **C2 collector の `exfil` は文法を見るが、`submit` は見なかった。** `exfil` は文法外に `400 invalid challenge id` を返し、`submit` は何も見ず verbatim に転送していた。同じ `{cid}` に対して、2 本の route で答えと層が違った。
- **C3 `submit` に文法検査を入れると、platform の probe が壊れる。** platform の verify (a-2) は `POST /api/challenges/<probe>/submit` を collector 経由で撃ち、「404 かつ scoreboard の固定 body」を green とする。旧い probe id `verify-probe` は文法外 (数字 2 桁の接頭辞が無い) で、collector に検査を入れると collector 自身の 404 が返り、scoreboard に届かないまま gate が緑になる (#441 review-5x 32 回目、HIGH)。platform #264 が probe を文法内の `99-verify-probe` に替えた。
- **C4 collector は catalog を持たない。** 持たせると yaml.v3 と catalog parser が image に入る (`internal/apispec` の依存境界が禁じる)。だから collector が知っているのは文法 (構文) だけで、「その id が challenge か」は scoreboard だけが答えられる。

## Decision

- **D1 文法は 1 つ。** challenge id の文法は `challengeid.Pattern` (= 両 spec の `Cid.pattern`) の 1 定義で、collector・scoreboard・platform の verify probe が同じものを見る。collector に別の文法を置かない (写しを作らない)。
- **D2 collector は構文でだけ拒否する。**
  - `{cid}` が文法外なら、`submit` も `exfil` も collector 自身が `404 {"error":"unknown challenge"}` を返し、転送しない。入力は body に出さない。
  - `exfil` の旧 `400 invalid challenge id` はこれに揃える。scoreboard が文法外・catalog に無い id に返す 404 と**同じ body・同じ status**で、参加者に見える規則は「challenge でない id は 404」の 1 つになる。
  - `{cid}` が文法内なら、catalog に有るかを問わず転送する (`submit` は verbatim、`exfil` は path を書き換える)。catalog に無い id の 404 は scoreboard が返す。
  - collector は catalog 由来の状態を持たない。
- **D3 verify の probe は「文法内で catalog に無い」id。** `99-verify-probe` がそれで、collector が転送し、scoreboard が `404 {"error":"unknown challenge` で始まる固定 body で答える。(a-2) はこの 404 と body の prefix だけを green にする。
  - 注意: collector の局所 404 は scoreboard の 404 と**同じ bytes**なので、body だけでは「どちらが答えたか」を区別できない。区別しているのは「probe が文法内だから collector は転送する」という事実で、これを test で固定する (V1・V2)。
- **D4 変更の順序と同時性。** probe の id・文法 (`Cid.pattern`)・collector の局所 404 のどれを変える PR も、両リポ同時 PR にする。順序は platform #264 (probe) → app #445 (本 ADR) → pin bump。

## Alternatives (退けたもの)

- **A1 collector の局所 404 の body を scoreboard のと変える** (gate が答えた側を見分けられる)。退けた: 参加者に見える規則が 2 つに増える (同じ「challenge でない id」に 2 種類の body)。区別は D3 の test で足りる。Signpost 2 を参照。
- **A2 `submit` を verbatim のままにする** (collector は `exfil` だけ検査)。退けた: 層が route ごとに違う状態が残り、fail-closed の層として collector でも止めたい (#441)。scoreboard 側の fold と固定 404 が受けるので害は小さいが、2 本の route の規則を揃える。
- **A3 collector に catalog の id 一覧を持たせ、catalog に無い id も止める。** 退けた: C4。依存境界を破り、catalog と collector の同期という新しい drift 源を作る。

## Verification (すべて `make test` = required の `test` に載せる)

- **V1** `internal/collector/collector_test.go` `TestSubmit_VerifyProbeIsForwarded`: `99-verify-probe` の `submit` が upstream に転送される。
- **V2** `internal/catalog/challengeid/challengeid_test.go` `TestVerifyProbeIsInsideTheGrammar`: `99-verify-probe` が文法内、旧 `verify-probe` が文法外。
- **V3** `internal/scoreboard/cid_label_test.go` `TestVerifyProbeCIDIsGrammarValidNotInCatalogAndAnsweredWithFixed404`: 文法内・実 `challenges/` の catalog の key でない・scoreboard が 404 と `{"error":"unknown challenge` で始まる固定 body で答える (既存の `AB.c` の 404 の test の隣)。
- **V4** `internal/collector/collector_test.go` `TestSubmit_OutOfGrammarCID_Fixed404NotForwarded` / `TestExfil_OutOfGrammarCID_Fixed404NotForwarded`: 文法外 (4096 文字・大文字・`.`・`%20`・桁違い・path traversal・非 UTF-8 ほか) は 404 と固定 body で、upstream を呼ばない。
- **変異**: `submit` の検査を外す (`if false && …`) と V4 の `submit` が赤になることを実出力で確認した。

## Consequences

- 良い: `submit` と `exfil` の規則が揃い、参加者に見える status が「challenge でない id は 404」の 1 つになる。gate の probe が collector 自身の応答で偽緑になる経路が、文法内の id では無くなる。
- 悪い / 注意: (a-2) の green は collector と scoreboard のどちらが 404 を返しても成立する。probe が文法外に出ると偽緑になる。守っているのは V1〜V3 の test だけ。
- 可逆性: 高い。collector の検査を戻せば元に戻る。ただし probe を文法外に戻す変更は D4 により両リポ同時。

## Signposts (この決定を覆す観測可能な信号)

1. **collector が catalog 由来の状態を持ち始める** → D2 の「構文でだけ拒否」が崩れる。A3 を含めて再検討し、依存境界と同期の方法を決める。
2. **platform の gate が「collector が答えた」と「scoreboard が答えた」を区別する必要が出る** (例: (a-2) が文法内の id でも collector の局所応答で緑になる事故) → A1 (body を変える) を再検討する。
3. **`Cid.pattern` が変わる** → probe の id が文法内であり続けるか (V2)、platform の probe を同時に直す (D4)。
4. **collector が文法内の id に局所応答を返し始める** (rate limit 以外) → D3 の前提 (文法内は必ず転送) が崩れる。(a-2) の読み方を platform と見直す。
