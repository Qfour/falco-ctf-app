# ADR-0041: challenge id の文法は Go と両 spec で 1 定義 (`challengeid.Pattern`)。文法外は collector が固定 404 で止め、文法内で catalog に無い id (platform verify の probe `99-verify-probe`) は collector が転送して scoreboard の 404 で答える。両者の 404 は同じ bytes で、test が保つ

- Status: **Accepted** (2026-10-19、architect = review-5x R4 yes-if、VP 承認。本 PR で昇格)。
  - クロスリポ契約 (collector の局所応答と platform verify (a-2) の probe) に触れるので、Class-2。architect 合意 (review-5x 52 回目 R4、yes-if の条件は本 PR で満たした) + security-engineer APPROVE (R1) + VP 承認 (`ORGANIZATION.md` §4・§5) を経て、本 PR 内で Accepted にした。
  - HTTP の status は 1 つ変わる (collector の exfil: `400 invalid challenge id` → `404 unknown challenge`)。参加者の正規の経路 (正しい id) には影響しない。
  - 新 image・Dockerfile・Hard Invariant に触れない。
- Date / Deciders: 2026-10-19 / 起草: software-engineer。承認: architect (review-5x R4)・VP
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

- **D1 文法は Go と両 spec で 1 つ。** challenge id の文法は `challengeid.Pattern` の 1 定義で、collector・scoreboard が import する。両 spec の `Cid.pattern` はこれと等しいことを `internal/apispec/specparity` (`identifier_patterns_test.go`) が固定する。collector に別の文法を置かない (写しを作らない)。**platform は文法を持たない**: verify の probe id が文法内で catalog に無いことは、platform ではなく app の V2・V3・V5 が固定する。shell 側の写し (検証 script・`gen-values.sh`・chart の guard) はまだ pin されておらず、app#472 で扱う。
- **D2 collector は構文でだけ拒否する。**
  - `{cid}` が文法外なら、`submit` も `exfil` も collector 自身が `404 {"error":"unknown challenge"}` を返し、転送しない。入力は body に出さない。
  - collector は「transparent に転送するだけ」の箇所ではない: challenge id の文法だけは collector が検査する。CTF 状態 (catalog / flags / DB) は持たない。
  - `exfil` の旧 `400 invalid challenge id` はこれに揃える。scoreboard が文法外・catalog に無い id に返す 404 と**同じ body・同じ status**で、参加者に見える規則は「challenge でない id は 404」の 1 つになる。
  - `{cid}` が文法内なら、catalog に有るかを問わず転送する (`submit` は verbatim、`exfil` は path を書き換える)。catalog に無い id の 404 は scoreboard が返す。
  - collector は catalog 由来の状態を持たない。
- **D3 verify の probe は「文法内で catalog に無い」id。** `99-verify-probe` がそれで、collector が転送し、scoreboard が `404 {"error":"unknown challenge` で始まる固定 body で答える。(a-2) はこの 404 と body の prefix だけを green にする。
  - 注意: collector の局所 404 は scoreboard の 404 と**同じ bytes**なので、body だけでは「どちらが答えたか」を区別できない。区別しているのは「probe が文法内だから collector は転送する」という事実で、これを test で固定する (V1・V2)。
- **D4 変更の順序と同時性。** probe の id・文法 (`Cid.pattern`)・collector の局所 404・**scoreboard の unknown challenge 404 の body prefix `{"error":"unknown challenge`** (platform の gate が実際に照合する) のどれを変える PR も、両リポ同時 PR にする。順序は platform #264 (probe。merge 済み) → app #445 (本 ADR、app #484) → platform の pin bump (platform #271)。

## Alternatives (退けたもの)

- **A1 collector の局所 404 の body を scoreboard のと変える** (gate が答えた側を見分けられる)。退けた: 参加者に見える規則が 2 つに増える (同じ「challenge でない id」に 2 種類の body)。区別は D3 の test で足りる。Signpost 2 を参照。
  - コスト: 低い (定数 1 つと spec・契約の更新)。可逆性: 高い。効き始める閾値: (a-2) が文法内の id でも collector の局所応答で緑になる事故、または probe が文法外に出る事故が実際に起きたとき (Signpost 2)。
  - 再検討先: body は変えず、答えた層を別の手段 (応答 header など) で示す案。参加者に見える body の規則は 1 つのまま、gate だけが答えた側を区別できる。
- **A2 `submit` を verbatim のままにする** (collector は `exfil` だけ検査)。退けた: 層が route ごとに違う状態が残り、fail-closed の層として collector でも止めたい (#441)。scoreboard 側の fold と固定 404 が受けるので害は小さいが、2 本の route の規則を揃える。
  - コスト: 無い (現状維持)。可逆性: 高い。効き始める閾値: collector への文法外 id の流入が scoreboard の負荷や log に現れたとき。
- **A3 collector に catalog の id 一覧を持たせ、catalog に無い id も止める。** 退けた: C4。依存境界を破り、catalog と collector の同期という新しい drift 源を作る。
  - コスト: 高い (依存境界・image の SBOM・catalog の配布)。可逆性: 低い。効き始める閾値: Signpost 1 (collector が catalog 由来の状態を必要とする要求が出たとき)。

## Verification (すべて `make test` = required の `test` に載せる)

- **V1 / V2 / V3** `internal/collector/unknown_challenge_contract_test.go` `TestVerifyProbeContract` (app#486: 3 つの test を 1 つに集め、probe の id は契約表の行 `challenge id の文法と collector の 404` の `POST /api/challenges/<probe>/submit` から読む。写しを test に置かない。collector の spec が同じ id を名指すことも見る): (V2) `99-verify-probe` が文法内、旧 `verify-probe` が文法外。(V3) 実 `challenges/` の catalog の key でない。(V1) collector が `submit` を upstream に転送する。(V3) scoreboard が 404 と `{"error":"unknown challenge` で始まる固定 body で答え、id を echo しない。
- **V4** `internal/collector/collector_test.go` `TestSubmit_OutOfGrammarCID_Fixed404NotForwarded` / `TestExfil_OutOfGrammarCID_Fixed404NotForwarded`: 文法外 (4096 文字・大文字・`.`・`%20`・桁違い・path traversal・非 UTF-8 ほか) は 404 と固定 body で、upstream を呼ばない。
- **V5** `internal/collector/unknown_challenge_contract_test.go` `TestUnknownChallenge404_CollectorAndScoreboardAreByteIdentical`: collector.New を、実 `challenges/` の catalog で作った実 scoreboard handler の前に置く。(i) 文法外 id (`AB.c`・`verify-probe`) は collector の 404 で、upstream の呼び出しは 0 回。(ii) `99-verify-probe` は転送され (呼び出し 1 回)、scoreboard が 404 で答える。(iii) (i) と (ii) の status・Content-Type・body が byte 単位で一致する。collector の局所 404 と scoreboard の 404 は本番では別々の定義なので、「同じ bytes」を保つのはこの test だけ。test だけの import で、collector の production closure は変わらない。
- **依存境界** `internal/apispec/dependency_boundary_test.go` `TestCollectorLinksTheChallengeIDLeafNotTheCatalog`: collector の closure に `challengeid` の leaf があり、`internal/catalog` と yaml.v3 が無い (D2 の「catalog を持たない」を機械で固定する既存の検査)。
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

## Advice (受けた助言。非拘束でも記録する)

- **review-5x 52 回目 (2026-10-19、T3) R4 Architecture (architect): yes, if。** 条件は次の 3 つで、本 PR で満たした。
  1. 「collector の 404 と scoreboard の 404 は同じ bytes」を機械で保つ合成 test を置く → V5。
  2. 契約表・D1・spec の `Cid` の説明を実態に合わせる (platform は文法を持たない。写しは Go と両 spec で 1 定義、shell の写しは app#472 で未 pin。「両リポ同時」の対象に scoreboard の 404 の body prefix を加える) → D1・D4・契約表・spec。
  3. Alternatives にコスト・可逆性・効き始める閾値を書き、A1 の再検討先 (body を変えず答えた層を示す) を Signpost 2 に結ぶ → 本 ADR。
- **review-5x 52 回目 R1 Security (security-engineer): APPROVE with comments。** 指摘 R1#1 (collector の `collector_request_duration_seconds` の method label が生の値で、default-deny 面に任意の method を送ると series が増える) は**本 PR の変更ではなく既存**で、app#485 に分離した (Class-2、別 PR)。本 PR は label の集合を変えない (route は pattern、`{cid}` は label に入らない)。
- **review-5x 52 回目 R2・R3・R5**: APPROVE with comments。upstream 失敗時の 502 の test と log の確認、LOW の束は app#486。platform の `operations.md` §10.6 と P13-RUNBOOK §4 の「collector 自身の 404 は text/plain」の記述の更新は、pin bump の platform#271 に含める。
