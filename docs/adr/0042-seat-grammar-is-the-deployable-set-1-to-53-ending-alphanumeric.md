# ADR-0042: seat の文法は deploy できる集合 (1〜53 文字、両端が英数字、`^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$`) に締める。ADR-0034 D2 の seat の文法の 1 文だけを置き換える

- Status: **Accepted** (2026-10-25。昇格条件を満たした: (1) B = app#496 (squash d3fc27c) と platform の対の PR = platform#282 (squash ca0572a) の両方が main に入った、(2) 両リポの表の照合が緑 — app は #496 の `make test` / `make check-flags`、platform は `scripts/test-seat-grammar-parity.sh` が app main d3fc27c の `seat-cases.tsv` (header 一致) で 51 行一致 + `--selftest` mutation 10 検出。Proposed は 2026-10-20、architect の合意 (yes, if) と VP の承認は Issue #480 のコメント。events の `app.ref` の pin bump は昇格の条件にしない (「platform の対の PR」節の follow-up = CEO の release tag の後))。
  - クロスリポ契約 (ADR-0034 D2 の seat の文法) の変更なので Class-2。**ADR-0034 は書き換えない**: D2 の「`seat` は `^[a-z0-9][a-z0-9-]{0,62}$`」の 1 文だけを本 ADR が置き換える (ADR-0034 の Status に導線を置いた)。D2 のそれ以外 (ロスターの形・正規化・解決・起動検査) は変えない。
  - 受理集合を**狭める**変更なので原則は破壊的だが、影響する既存の値は 0 (Consequences)。
  - Dockerfile・image・Hard Invariant の追加・変更は無い。I8 の「seat」の定義が狭まる (機械強制の列は本 PR で契約表に追記した)。
- Date / Deciders: 2026-10-20 / 起草: software-engineer。合意: architect (#480 のコメント、yes, if)。承認: VP (#480 のコメント、2026-10-19)。security-engineer は review-5x R1 (auth-policy の roster 検査・ingest の ns filter・Grader の gate の受理集合が変わる)。
- 関連:
  - Issue #480 (発注元)、#440 (seat 文法の 1 定義 `identity.SeatPattern`)、#478 (`specparity` の識別子 pattern の表)、#479 / ADR-0039 Signpost 3 (Grader の gate)、#493 (A: 共有 case 表 + `deploy-user.sh` の検査。文法は変えなかった)
  - ADR-0034 (D2。本 ADR が seat の文法の 1 文を置き換える)、ADR-0005 / 0009 (spec ↔ 実装の parity)、ADR-0041 (識別子の文法を 1 定義にする型)
  - platform: #239 (roster の生成 `scripts/gen-roster.sh`。seat は `user1..N` と `test1`)、#257 (開場前の新規 PVC / admin reset)。対の PR は本 ADR の「platform の対の PR」
  - フェーズ: 非該当

## Context

- **C1 文法が deploy できる集合より広い。** `identity.SeatPattern` は `^[a-z0-9][a-z0-9-]{0,62}$` (1〜63 文字、末尾の `-` を許す)。seat は workspace の名前で、deploy は seat から次の名前を作る。
  - Helm の release 名 = seat そのもの (`charts/ctf-user/deploy-user.sh` の `helm upgrade --install "${RELEASE}"`、`RELEASE="${USERNAME}"`)。Helm (`Dockerfile.test` の v3.21.4) は 53 文字以下、両端が英数字を要求し (`pkg/chartutil/validate_name.go`)、`helm template` でも検査する。
  - namespace `ctf-<seat>` (DNS label の 63 → seat は 59 以下)、label の値 `app.kubernetes.io/instance`・`falco-ctf/username` (63 以下、両端英数字)、Ingress host の先頭 label (63 以下、末尾英数字)。
  - 効いているのは Helm の 53 で、`ctf-` の接頭辞が付く namespace の 59 ではない (release 名は `ctf-<seat>` ではなく seat そのもの)。
  - → deploy できる集合 D = 1〜53 文字・両端が英数字。文法の 54〜63 文字と末尾 `-` は、roster に書かれても deploy の途中 (kubectl の namespace 作成と Pod の削除の後) で Helm が落とす。
- **C2 seat の定義が 2 つになりうる。** 文法をそのままにして deploy の制約を platform の roster / preflight に置くと、seat の定義が文法と「deploy できる集合」の 2 つになり、後者は Go と照合されない shell / rego に住む。しかも制約の元 (release 名・namespace・host の作り方) は app の chart と `deploy-user.sh` にあり、platform が app の内部の事実を写すことになる。spec の `Seat` は deploy できない値を有効と書き続ける。
- **C3 既存の値は全部 D に入る。** platform が作る seat は `user1..N` と `test1` だけ (`scripts/deploy-event-workspaces.sh`、#239 の `scripts/gen-roster.sh`)。app の tracked file にある seat 風の値も全部 D に入る (Verification の走査)。seat は今は全部機械生成なので、締めるのは最も安い (人が選ぶ seat が入った後だと実際の roster を壊す)。
- **C4 `--set` は seat を数値・真偽値として読む。** `deploy-user.sh` は `helm --set "username=${USERNAME}"` を使っていた。`0` `123` は整数、`true` は真偽値、`null` は nil (空になり、namespace は `ctf-`) になる。label の値も YAML の裸のスカラーとして書かれ (`falco-ctf/username: 0`)、Kubernetes が文字列でない label を拒否する。(`1e3` は `helm template` で確かめたところ `--set` でも文字列のまま `ctf-1e3` になり、`ctf-1000` にはならない。Helm の `--set` が型付けするのは整数・真偽値・null だけで、浮動小数点にはしない。values ファイルの YAML に書けば `1e3` は 1000 になるが、`deploy-user.sh` は values に seat を書かない。)文法は `0` や `123` を許すので、「文法 = deploy できる集合」を本当にするには、この 2 つも直す必要がある (本 PR の導出 test が `0` で赤になって見つけた)。

## Decision

- **D1 seat の文法は `^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$` (1〜53 文字、両端が英数字)。** Go の定義は `identity.SeatPattern` の 1 つのままで、doc comment の正典はこの ADR。spec 3 本 (`docs/openapi-scoreboard.yaml` の `components.schemas.Seat`、`docs/openapi-collector.yaml`、`docs/openapi-auth-policy.yaml` の `host`) の `pattern` は同じ値、`maxLength` は 53。`specparity` の表 (サイト数は変わらない) が等しさを固定する。
- **D2 共有 case 表が写しを全部照合する。** `internal/identity/testdata/seat-cases.tsv` (`input<TAB>accept|reject`、placeholder `{LF}` `{U+202E}` `{U+00FC}` `{U+00EF}` の閉集合、decode 後に `{` `}` が残った行は reader の誤り) を正典にする。
  - 登録済みの読み手: Go (`identity.ValidSeat`、`TestValidSeat_SharedCaseTable`)、`charts/ctf-user/deploy-user.sh` の `SEAT_PATTERN` (`scripts/check-seat-grammar.sh`。`TestDeployUserShellPatternIsTheGoPattern` が text を `identity.SeatPattern` に固定する)。platform の `scripts/lib/roster.sh`・`policy/key-guards.rego`・`scripts/preflight-identity.sh` は対の PR で同じ表を読む。
  - 表の 1 行目は `# pattern: ` + 正典の regex (platform の parity test が文法の literal として読む。app の Go ソースの字面は契約の面にしない)。
  - 表の path・書式 (1 行目の header・2 列)・placeholder の集合を変える PR は両リポ同時 (契約表に登録した)。`Makefile` の `make e2e-serve AS=` の検査は近似で、表には登録しない (e2e harness が Go で再検査する)。
- **D3 導出を test で固定する。** `internal/apispec/ingressparity/seat_render_test.go`: 文法内の端 (1 文字、`0`、`a--b`、53 文字、数値・真偽値・null に見える `123` `1e3` `true` `null`) で `helm template <seat> charts/ctf-user --set-string username=<seat>` が成功し、描画された `metadata.namespace`、label の値、Ingress の host が `k8s.io/apimachinery` の `IsDNS1123Label` / `IsValidLabelValue` を通る。文法のすぐ外 (54 文字、63 文字、末尾 `-`) では Helm 自身が release 名で失敗する。deploy が seat から作る名前を変えたら、この test が赤になる。helm が無ければ skip ではなく fail (ADR-0034 V12 と同じ)。**役割の分担**: V4 は `helm template <seat>` を直接呼ぶので、**chart が seat から作る名前**だけを見る。**release 名 (`RELEASE="${USERNAME}"`) と namespace (`NS="ctf-${USERNAME}"`) の導出は V2 (`scripts/check-seat-grammar.sh`) が `deploy-user.sh` の実呼び出しで固定する** (記録した `helm upgrade --install <seat> ... -n ctf-<seat>` と `kubectl create namespace ctf-<seat>` を完全一致で比べる)。V4 はその前提 (release 名 = seat、namespace = `ctf-<seat>`) で chart の名前を見る。
- **D4 `deploy-user.sh` と chart。** `SEAT_PATTERN` を D1 に揃える。`--set` を `--set-string` にし、chart の label の値 (`app.kubernetes.io/instance`、`falco-ctf/username`) を `quote` する (C4)。`user1` など既存の seat の描画は変わらない。 (app#513 の追補、決定文は不変) chart は `ctf-user.username` define で username が string でない・空なら描画で `fail` する (C4 の延長。呼び手は `--set-string` で渡す)。
- **D5 順序。** app (A: #493、済) → app (B: 本 PR) → platform の対の PR。途中の状態はどちらの向きでも fail-closed: app が先なら、platform の描画を通った D の外の seat で auth-policy が起動を拒む。platform が先なら描画で止まる。softlock も free-win も無く、今の seat は全部 D の中。効き始め: D の外の seat が roster に書かれた時点。

## Alternatives (退けたもの)

- **A1 文法はそのままにし、deploy の制約を platform の roster / preflight に置く。** 退けた: C2。seat の定義が 2 つになり、後者は Go と照合されない shell / rego に住む (#440 / #478 が消したばかりの drift の型)。持ち主も違う。
  - コスト: 小さい (契約を変えない)。可逆性: 高い。効き始める閾値: 人が選ぶ seat が入り、文法を締めると実際の roster が壊れる状況になったとき (Signpost 2)。
- **A2 両方 (文法を締め、platform にも別の deploy 制約の検査を置く)。** 退けた: 文法を締めた後は別の検査の中身が文法と同じになり、2 つ目の定義を足すだけになる。
  - コスト: 低い。可逆性: 高い。効き始める閾値: 無い (A1 と同じ drift の型を再び作る)。
- **A3 文法はそのままにして、Helm の release 名に接頭辞を付けて短くする。** 退けた: release 名は platform の運用 (teardown・roster 操作・`helm -n` の探し方) に既に使われており、名前の側を変えると両リポの手順が変わる。Signpost 1 (名前の作り方が変わったとき) の道。
  - コスト: 高い (名前の作り方を両リポで変える)。可逆性: 低い。効き始める閾値: Signpost 1。
- **A4 53 ではなく 49 や 59 にする。** 退けた: 49 / 59 は `ctf-` が付く名前の計算で、release 名は seat そのもの。実際に効いているのは Helm の 53 (C1)。

## Verification (すべて `make test` = required の `test` と、CI `flag-guard`)

- **V1** `internal/identity/seat_cases_test.go` `TestValidSeat_SharedCaseTable`: 共有 case 表の全行を `ValidSeat` に通す (53 / 54 文字、63 / 64 文字、末尾 `-`、先頭 `-`、大文字、`.` `,` `=` 空白、`{LF}`、bidi、非 ASCII を含む)。reader の negative test (`TestSeatCaseTable_ReaderFailsOnAMalformedRow`) が不正な行と未知 placeholder で赤になる。`TestSeatCaseTable_HeaderIsTheGoPattern` が表の 1 行目 `# pattern: <regex>` (platform が正典 literal として読む) を `identity.SeatPattern` に固定し、header が row reader に comment として読まれることを見る。
- **V2** `scripts/check-seat-grammar.sh` (`make check-flags`、CI `flag-guard`): 同じ表の全行を `deploy-user.sh` に通す (accept は `helm upgrade` まで届き、記録された呼び出しを**完全一致**で比べる: `helm upgrade --install <seat> ` で始まる (release 名 = seat)、namespace flag は `-n ctf-<seat>` がちょうど 1 つ、`kubectl create namespace ctf-<seat> --dry-run=client -o yaml`、`--set-string username=<seat>`。reject は exit 2 で kubectl / helm の呼び出し 0 件。`--egress-lockdown` でも同じ)。`SEAT_PATTERN` を 6 通りに壊した写し (何でも通す / 1 文字広い / 1 文字狭い / 末尾 `-` を許す / `^` なし / `$` なし) に加え、**導出を 2 通りに壊した写し (`RELEASE` に接頭辞を付ける / `NS` を `ctfx-<seat>` に変える)** が、それぞれの壊し方に対応する行で赤になる。release 名と namespace の導出の唯一の固定点がこの検査 (Signpost 1)。
- **V3** `TestDeployUserShellPatternIsTheGoPattern`: `deploy-user.sh` の `SEAT_PATTERN` が `identity.SeatPattern` と byte 単位で同じ。
- **V4** `internal/apispec/ingressparity/seat_render_test.go`: D3 の導出 test。`TestSeatGrammar_EverySeatInTheGrammarRendersWithValidNames`、`TestSeatGrammar_JustOutsideTheGrammarIsRefusedByHelm`、`TestSeatViolations_Mutations` (検査自体が名前の違反を報告できる)。実測した変異: chart の `falco-ctf/username` の `quote` を外すと `0` で赤になる。 (app#513 の追補) 新 test `TestSeatGuard_AUsernameThatIsNotAStringIsRefusedByTheChart`: 負の case (`--set username=0` / `123` / `true` / `null` / 空と、values file の `123` / `1e3` / `true` は fail、`--set-string` は成功)。
- **V5** `internal/apispec/specparity` (`TestSpecPatternsAreExactlyTheGoGrammars`): spec 3 本の `pattern` が `identity.SeatPattern` と等しく、サイト数が変わらない。さらに seat の pattern を持つ**全 site の `maxLength` が文法の上限 (`ValidSeat` に尋ねて得た 53) と等しい** (無い・違う site は赤。`TestMaxLengthViolations_Mutations`)。description に regex の写しは置かない (`Seat` schema への参照にする)。`make gen` の差分は `Seat` の description だけ。
- **V6** 検出器 (`internal/identity/users_test.go`): 新旧どちらの形の seat 文法の写しも見つけ、変異 (drift した写し) を両方の形で持つ。
- **境界の test**: `identity_test.go` (53 文字が上限、54 / 63 文字・末尾 `-` は拒否)、`scoreboard/user_slug_test.go` (HTTP 400)、`scoring_test.go` (Grader の gate)、`ingest/ratelimit_test.go` (`ctf-` + 54 文字と末尾 `-` の ns は ignored)。
- **走査**: app の tracked file の seat の値 (`seat:`、`user<N>` / `test<N>` 風の token) が全部 D に入る。入らないのは negative fixture (`-user1`、`User1` と、共有表の reject 行) だけ。

## Consequences

- 良い: seat の定義が 1 つになる。workspace を作れない値は seat ではなく、roster・auth-policy の起動・API・Grader・ingest の全部が同じ集合で止める。deploy の途中 (namespace 作成と Pod 削除の後) で Helm が落とす状態が無くなる。`deploy-user.sh` の入力が `--set` の別 key の代入として読まれる経路は A (#493) で閉じた。
- 悪い / 注意:
  - **受理集合が狭まる**: 末尾 `-` の seat と 54 文字以上の seat は、scoreboard が path / body の `user` を検査する API は 400 (`invalid user`)、`/check-workspace` は 400 (ingress 経由では auth-url の応答が 400 なので ingress が 500 にする)、`/check-participant` と scoreboard の identity gate (`<seat>@<domain>` が文法に合わない header) は 403、ingest は ignored、auth-policy は roster に書かれていれば起動を拒む。既存の roster に該当は無い。
  - **upgrade note**: すでに保存された行の seat が D の外なら、scoreboard の起動時の件数の Warn (#459) に出る。開場前に新規 PVC か admin reset で作り直す (platform#257)。
  - 写しが増えたら、表に登録しない限り照合されない (Makefile の近似は対象外)。
- 可逆性: 高い。D を広げ直すのは additive (request の受理集合が広がるだけ)。ただし deploy が作る名前の側 (Helm の 53) が変わらない限り、広げた分は deploy できない。

## Signposts (この決定を覆す観測可能な信号)

1. **導出の test が赤になった** (deploy が seat からもっと短い名前を作り始めた: release 名に接頭辞を付ける、別の substrate の hostname にする等) → 名前の側を短く設計し直すか、文法を締め直す (人が選ぶ seat が入る前に)。**release 名と namespace の導出は V2 (`check-seat-grammar.sh`) が `deploy-user.sh` の実呼び出しで固定し、V4 (`seat_render_test`) はその前提で chart の名前を見る**。接頭辞を付ける変更は V2 が先に赤になる (V4 だけでは見えない)。
2. **seat が機械生成でなくなる** (S3 で外部 identity から seat を作る、チーム名を seat にする) → 文法が人の目に触れる面になる。長さ・文字集合・紛らわしい文字を新しい ADR で決め直す。
3. **実際の roster の seat が `roster.sh` / auth-policy の起動 / `deploy-user.sh` で拒まれた** → 文法がイベントの必要より狭い。
4. **Helm の release 名の規則が変わった** (53 文字の上限や両端の規則。Helm のバージョンを上げるとき) → `Dockerfile.test` の helm の版を上げる PR で D3 の test が赤になるはず。赤になったら D1 を見直す。

## platform の対の PR (本 ADR の条件。private repo)

**実際の順序**: app#496 (本 PR) → **platform#282 (対の PR)** → events の `app.ref` の pin bump PR (別 PR)。

- 対の PR (platform#282): `scripts/lib/roster.sh`・`policy/key-guards.rego`・`scripts/preflight-identity.sh` の 3 つの seat の literal を D1 にし、`seat-cases.tsv` を読む parity test (`scripts/test-seat-grammar-parity.sh`) を持つ (同じ placeholder の閉集合、decode 後に `{` `}` が残った行は reader の誤りとして fail)。**文法の正典 literal は `seat-cases.tsv` の 1 行目 `# pattern: <regex>` から読む** (app の Go ソースの字面は契約の面にしない。app 側は `TestSeatCaseTable_HeaderIsTheGoPattern` が `identity.SeatPattern` との一致を固定する)。
- **platform CI (identity-selftest) の app の pin は、再現性のための test 入力の pin で、deploy の参照ではない。** bump は対の PR で app の merge SHA へ進める (対の PR の merge 前に、branch の SHA から #496 の squash SHA へ差し替え、TODO を消す)。events の `app.ref` (deploy が使う app の参照) とは別物で、混ぜない。
- events の `app.ref` を本 PR が入った commit 以降に進めるのは、**pin bump PR の follow-up** (対の PR の条件ではない)。本 PR の merge は deploy の参照を動かさず、`app.ref` を進めるまで deploy は旧い app の chart / `deploy-user.sh` を使う。
- `helm template` の導出 test は app 側 (D3 / V4) にあり、platform には要らない。

## Advice (受けた助言。非拘束でも記録する)

- **architect (Issue #480 のコメント、2026-10-19): yes, if。** 推奨は (a) 文法を D に締める。条件 5 つ: (1) 文法は D そのもの 1 本で `maxLength` は 53、導出を test で固定する → D1・D3・V4。(2) 定義は 1 つのまま、写しを共有の表で全部照合し、検出器は新旧両形を見つける → D2・V1〜V3・V6。(3) `deploy-user.sh` は kubectl / helm の前に username を検査し、外れたら exit 2 → A (#493) で入れ、本 PR で文法を D1 に揃えた。(4) 新しい ADR を起こし、ADR-0034 D2 の 1 文だけを置き換え、CHANGELOG に upgrade note → 本 ADR・CHANGELOG。(5) security-engineer の APPROVE → review-5x R1。A / B の分け方: A (#493) = 表 + 照合 + `deploy-user.sh` の検査、B (本 PR) = 文法を締める。
- **VP (Issue #480 のコメント、2026-10-19): 承認。** 推奨 (a) を採用。順序は app (A) → app (B) → platform は platform#239 の後。既存の seat (`user<N>` / `test1`) が全部通ることは確認済み。
- **review-5x 61 回目 (2026-10-20、#493 = A) R4 Architecture:** 共有表の path・2 列書式・placeholder の閉集合・「rename / 移動 / 書式変更は両リポ同時 PR」を、platform の対の PR が表を読み始める前に契約表へ登録する → 本 PR (B-1) で `.claude/rules/falco-ctf-app-conventions.md` に**新しい行「seat の文法と共有 case 表」**を足して登録した (「Identity 表と正規形」の行は変えていない)。1 行目の header `# pattern: <regex>` (platform の parity test が読む正典 literal) もこの行に書式として登録した (review-5x 63 回目 R4#4)。
- **実装中の発見 (software-engineer):** C4 (`--set` の型付けと label の裸のスカラー)。D3 の導出 test に `0` を入れて初めて赤になった。architect の事実の列挙には無かった。
