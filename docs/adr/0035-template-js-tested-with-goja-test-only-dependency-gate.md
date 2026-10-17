# ADR-0035: portal の template に書いた JS の振る舞いは、Go のテストが goja (test 専用の pure Go の JS エンジン) で実行し、required の `make test` で固定する。test 専用の第三者 Go module には入口の条件を置く

- Status: **Proposed** (2026-10-17 起草)。app#381 の merge の前に Accepted にする (ADR が要る変更の merge は Accepted の後。Proposed に 1 往復 objection が無ければ VP が Accepted にできる: workspace `ORGANIZATION.md:470-472`)。本番の image と契約には効かないので CEO の判断は要らない (D6 の統治文書の変更を採る場合だけ CEO)。
- Date / Deciders: 2026-10-17 / VP (承認) + architect (起草) + security-engineer (#381 の監査: goja は採用可、条件 F1) / 実装: software-engineer (go.mod・境界の test・CI)、application-engineer (portal の test)
- 関連: app#381 (`fix/display-name-reject-cf-c1`、#331・#343)、ADR-0031 (D1 (b)・V4・Advice (2))、ADR-0027 D6 / V7 (`scripts/check-portal-render.sh`)、ADR-0012 (`code` の追加。Proposed)、ADR-0036 (同時起草。apk の pin の戦略)、workspace `ORGANIZATION.md` §8 の基準④
- 読み方: app の main は origin/main `5bbabd7`、#381 は `origin/fix/display-name-reject-cf-c1` の `1bebedb` (F1 = 1882ef6・F2 = 1bebedb を反映済み)。`0031:N` などは `docs/adr/` の各 ADR。security の指摘は #381 の security review (2026-10-17) の F 番号。「実測」は 2026-10-17 に colima-falco-build (aarch64) で使い捨ての container を回した結果

## Context

- **C1 何を固定したいか。** Profile の form の表示名の検査 (`pane-me.tmpl:196-246` の `trimName`・`nameProblem`・`planSave`) は「server (`internal/scoreboard/api/api.go:1115` の `validDisplayName`) より厳しくならない」ことが契約 (`pane-me.tmpl:197-198`)。#343 はその破れ (form だけが拒否する)。#381 は共有のケース表 (`internal/scoreboard/api/testdata/display-name-parity/cases.yaml`) を server 側 (`display_name_parity_test.go:71,101`) と form 側の両方に流す。form 側は template の source から関数を切り出して goja で実行し (`internal/scoreboard/view/portal_nameproblem_test.go:17-36,38-95,170-215`)、全 code point を走査する (`:272-332`、約 3 秒: `:277`)。
- **C2 今ある JS の実行手段。**
  - jsc: `scripts/check-portal-render.sh` (ADR-0027 D6 の evade card の描画の行列) は macOS の jsc を使う任意の target で、`make test` にも CI にも無い (`check-portal-render.sh:15-18,22-33`、`Makefile:49,261-262`)。ADR-0031 は「jsc の拡張だけ」を退けた (`0031:57`)。
  - Chromium: `Dockerfile.e2e` の `make e2e` (advisory の job `e2e`: `.github/workflows/checks.yaml:146`)。Chromium は apk の exact pin で、index の更新で赤になる (2026-10-17 の #382、ADR-0031 D5: `0031:166-173`。頻度は ADR-0036 C3 で月 2〜3 回)。
  - `make test` = `Dockerfile.test` の `go vet` と `go test` (apk の package を 1 つも入れない: `Dockerfile.test:8-72`)。required の文脈は `test / go-test` ほか (2026-10-17 に branch protection を API で実測。ADR-0036 C6)。
  - 静的検査: `checkPortalEsc` など (`internal/scoreboard/view/portal_partials_test.go:540-563`) は source の構造 (宣言が 1 つ・順序・shadow が無い) を regex で見る。振る舞いは見ない。
- **C3 依存の事実。** `github.com/dop251/goja` (MIT。tag が 0 本 (`git ls-remote --tags`、2026-10-17) なので pseudo-version で pin する。master の HEAD は 313b6b66)。#381 の pin は maintainer の master first-parent の merge commit e1fc788e4f41 (#745。security F1 の条件: `go.mod:8`)。推移依存は `dlclark/regexp2/v2 v2.5.2`・`go-sourcemap/sourcemap v2.1.3+incompatible` (新規) と `google/pprof` (main の go.sum に既にあり、indirect で go.mod に載る) (`go.mod:23,43,45`)。
  - Dependabot の gomod は週次 (`.github/dependabot.yml:24-36`) だが、pseudo-version から pseudo-version への更新は出さない (dependabot-core#3017 の maintainer の回答。要望は #2028 で open)。goja の更新は手動になる。
  - `govulncheck ./...` は test だけが import する package を見ない (`.github/workflows/checks.yaml:74-79`、F5)。goja は今の脆弱性検査の外にある。
  - 本番の binary への混入の検査は `internal/apispec/e2e_boundary_test.go` の `jsEnginePrefix` (`:38-41,77-81`) と planted の fixture (`:125-137`)。見るのは module の中の package の静的な import の閉包だけで、第三者の module を経由した混入は見えない (F4)。
- **C4 忠実度。** goja はブラウザではない。正規表現は自前 (Go の regexp と regexp2 への fallback) で、`\p{..}` の表は Go の unicode (15.0.0) から取る。旧い pin では `/u` の `\p{..}` が壊れていた (F1: `/[\p{Cc}\p{Cf}]/u.test("c")` が true)。新しい Unicode の表を持つブラウザが、新しく Cf になった文字を拒否する残余は、テストの header に書いてある (`portal_nameproblem_test.go:31-36`)。
- **C5 規則。** 基準④「新規依存 / 新ツール / ...の追加」(workspace `ORGANIZATION.md:490-492`) に test 専用の除外は無い。test 専用の前例は chromedp で、ADR-0031 がコストと影響として記録した (`0031:47,180`)。

## Options (Alternatives)

1. **goja を `make test` で使う【推奨】** —
   変更点: test 専用の Go module 1 つ (+ 推移 2)。
   コスト: go.mod の 4 行、依存の手動更新 (C3)、`make test` が数秒増える (C1)。required の gate の中で決定的に回る (go.sum で固定。network も apk も使わない)。
   リスクと可逆性: ブラウザとの意味の差 (C4) — engine の自己検査と残余の明記で扱う。test と go.mod の行を消せば戻る。
   効き始める閾値: 即時 (#381)。
2. **`Dockerfile.e2e` の Chromium で、サーバ無しの頁として回す** (ADR-0031 Advice (2): `0031:189`) —
   忠実度はいちばん高い (実ブラウザの正規表現と Unicode の表)。
   コスト: gate が advisory の `e2e` (required でない) になり、Chromium の pin が index から消えるたびに赤になる (C2)。1 回 2 分前後 (ADR-0031 V5)。
   効き始める閾値: ADR-0031 D1 (c) で `e2e` が required になったとき、またはブラウザの表に依存する性質を固定したいとき (Signpost 3)。
3. **node を digest で pin した image から `Dockerfile.test` に入れる** —
   V8 なので Chrome に近い。
   コスト: `node:24-alpine` の node は `libstdc++.so.6`・`libgcc_s.so.1` (apk の package) に動的にリンクしている (実測) ので、binary だけを COPY できず、apk の pin (ADR-0036 の drift) か共有ライブラリの複写が要る。Class-2 (`Dockerfile.test`)、2 つ目の runtime、Go のテストから exec。

**方向として採らないもの**:
- **jsc**: macOS だけで、CI では動かず gate が fail-open になる (C2)。
- **node / qjs を `Dockerfile.test` に apk で入れる**: required の `test` を Alpine の index に結びつける。index は 1 版だけを持つので、exact pin なら更新のたびに全 PR の `test` と Stop hook が止まり、pin しなければ gate の engine の版が commit 無しに変わる (ADR-0036 C2・D2 (a))。
- **JS を Go に移す二重実装**: テストが見るのは移植で、出荷する JS ではない。#343 (form と server の食い違い) の型をそのまま残す。
- **client の検査をやめ、server の 400 だけにする**: 「form は server より厳しくならない」が構造で成り立ち、C4 の残余も消える。ただし (i) `planSave` の「名前を変えたときだけ検査する」ための trim は server と同じ集合でなければならず (`pane-me.tmpl:236-246`)、JS の検査が残るか、その判定を server に移す API の意味の変更になる。(ii) server の文言は短い (`api.go:1118-1124`) ので、ADR-0012 の `code` (Proposed) が要る。表示名の設計の判断で、依存の判断ではない (Signpost 1)。

## Decision

**Option 1。** 理由: 出荷する JS をそのまま required の gate の中で決定的に実行できるのは goja だけで、ブラウザとの差は engine の自己検査と残余の明記で閉じられる (ブラウザに依存する性質は ADR-0031 の e2e が持つ)。

- **D1 範囲。** portal の template (`internal/scoreboard/view/templates/portal/*.tmpl`) から切り出した、DOM・network・timer を使わない関数 (入力の検査、HTML の文字列を返す描画関数) の振る舞いを、`make test` の Go のテストが goja で実行して固定する。切り出しは source から行い、コピーを持たない。関数が見つからなければ Fatal にする (skip しない)。
- **D2 役割の分担。**
  - source の構造 (宣言が 1 つ・順序・shadow が無い) = 静的検査 (`checkPortalEsc` ほか)。goja で置き換えない。
  - 純粋な関数の振る舞い = goja (D1)。
  - ブラウザに依存する性質 (DOM・CSP の下での実行・ポーリング・要求の列・dialog・ブラウザの Unicode の表) = ADR-0031 の `make e2e`。goja のテストはブラウザと同じだとは主張せず、残余を header に書く。
- **D3 jsc の退役。** `scripts/check-portal-render.sh` の行列 (ADR-0027 D6 / V7) を goja の Go のテストに移し、その後で script と `make check-portal-render` を消す (template の JS を動かす engine を 1 つにし、macOS だけの検査を required の gate に入れる)。切り出しと実行の helper は、この移植で 2 つ目の利用者ができた時点で test 専用の 1 package にまとめる。ADR-0031 Advice (2) (Chromium で回す: 非拘束) は、純粋な関数については本 D3 で置き換える。担当: application-engineer (test)・software-engineer (script・Makefile)。#381 とは別の PR。
- **D4 test 専用の第三者 Go module の入口の条件** (goja は chromedp に次ぐ 2 つ目):
  - (a) どの `cmd/*` の依存の graph にも入らない。test 専用の prefix の一覧 (今は `github.com/chromedp/`・`github.com/dop251/`・`internal/e2e`) を 1 箇所に置き、実際の graph (`go list -deps ./cmd/...`) で確かめる (F4)。一覧の prefix が go.mod の require (または module の中の directory) に無ければ赤にする (古い一覧を残さない)。
  - (b) 脆弱性の検査が test の import を見る: `govulncheck -test ./...` (と `-tags e2e`) を advisory の job で回す (F5)。
  - (c) pin は maintainer が出した不変の revision: tag があれば tag、無ければ default branch の first-parent の merge commit (署名 verified を望む) (F1)。PR 本文に書く。
  - (d) 更新の経路を書く: tag があれば Dependabot、無ければ手動。手動の契機は (b) の finding・engine の不具合がテストに出たとき・version-watch の点検。
  - (e) 実行は secret の無い test の container の中だけ (`Dockerfile.test`、CI の go-test)。
  - (f) テストの判定が library の意味に依存するなら、その意味を自己検査で固定する (`TestEngine_UnicodePropertyEscapes_SelfCheck`: `portal_nameproblem_test.go:151-163`)。
- **D5 #381 の merge の条件。** #381 は次の表を満たす (PR 本文に貼る)。(a) の実 graph と (b) は follow-up とし、D3 の移植の PR か次の test 専用依存の PR の、どちらか早い方より前に main に入れる (security は follow-up を可とした: F4・F5)。

  | D4 | #381 (1bebedb) |
  |---|---|
  | (a) graph | 静的閉包は済み (`e2e_boundary_test.go:38-41,125-137`。security の実測で planted M1〜M3 が赤、`go list -deps ./cmd/<x>` で 6 本とも goja 0 件)。実 graph の test は follow-up |
  | (b) govulncheck -test | follow-up (手元の `govulncheck -test ./internal/scoreboard/view/` は No vulnerabilities found: security) |
  | (c) pin | e1fc788e4f41 = master first-parent の merge commit (#745、署名 verified) |
  | (d) 更新 | 手動 (pseudo-version のため Dependabot は上げない) |
  | (e) 実行の場所 | `Dockerfile.test` の中だけ (CI の go-test は `contents: read`、secret を渡さない: security) |
  | (f) 自己検査 | `TestEngine_UnicodePropertyEscapes_SelfCheck` (旧い pin では赤) |

- **D6 基準④の読み方。** 本 ADR は「test 専用の第三者依存にも ADR が要る」と読む。理由: 基準④に除外が無く、required の gate の判定を第三者の code が左右し、更新と脆弱性検査が既定の経路の外に出る (C3)。以後の test 専用依存で D4 をすべて満たすものは、PR 本文の D4 の適合表と security の review で ADR に代える案を出す (`ORGANIZATION.md` §8 の文言の変更 = 統治文書なので CEO が決める。採らなければ依存ごとに ADR を書く)。

## Consequences

- **諦めたもの**: ブラウザと同じ正規表現・Unicode の表での判定 (e2e が持つ)。goja の自動更新 (Dependabot は pseudo-version を上げない)。
- **新しい不変条件は足さない** (Hard Invariant に昇格しない)。D4 (a) は ADR-0031 V4 の境界の検査の延長。
- **影響**: go.mod に直接 1・推移 2 (+ pprof の indirect)。`make test` が数秒増える。`portal_nameproblem_test.go` は template の書式 (2 字下げの `function` と閉じ括弧) に依存し、整形を変えると Fatal で止まる (fail-closed)。
- **担当**: go.mod と D4 (a)(b) = software-engineer、portal の test と D3 = application-engineer、pin の出自の確認 = security-engineer。
- **runbook への影響**: なし。

## Signposts (この決定を覆す観測可能な信号)

1. **form と server の食い違い (form だけが拒否) がもう 1 件出る、または参加者のブラウザが新しい Unicode の表で正当な名前を拒否したという報告が 1 件出る** → 表示名の検査を server だけにする (Options の最後の案。ADR-0012 の `code` と、`planSave` の trim の判定の置き場を決める)。
2. **goja の不具合がテストの偽陽性・偽陰性として 6 ヶ月に 2 回出る、または goja の master に 6 ヶ月 commit が無い** → Option 2 (Chromium) か Option 3 (node) に移す。
3. **ADR-0031 D1 (c) で `e2e` が required になる** → C4 の残余 (ブラウザの表に依存する性質) を e2e のシナリオに足す。
4. **`govulncheck -test` が test 専用依存に到達可能な脆弱性を出し、30 日以内に修正版へ上げられない** → その依存を外す (Option 2 に移す)。

## Verification

- **V1 境界 (済み、required の `make test`)**: `TestNoProductionBinaryImportsTheE2EHarness` が `cmd/` の全 binary (0 本なら赤) の静的閉包に `github.com/dop251/` が無いことを見る (`e2e_boundary_test.go:104-121`)。planted: `cmd/fakebin` が goja を直に import すると赤 (`:125-137`)。security の実測で M1〜M3 が赤。
- **V2 実 graph (follow-up、D5)**: `make test` の中で `go list -deps ./cmd/...` の出力に D4 (a) の prefix が 0 件。一覧の prefix が go.mod に無ければ赤。planted: module の中の非 test file を経由して goja を引くと赤。
- **V3 engine の自己検査 (済み)**: `TestEngine_UnicodePropertyEscapes_SelfCheck` が `[true,false,true]` 以外で赤。旧い pin (67663e7a) に戻すと `[false true false]` で赤になる (#381 本文)。
- **V4 振る舞い (済み)**: 共有表の「form だけが拒否 = 0 件」(`portal_nameproblem_test.go:170-215`、`display_name_parity_test.go:101`) と全 code point の走査 (`:272-332`)。security の mutation M4〜M10 (M9 は F2 の 4 行で赤になった)。
- **V5 脆弱性検査 (follow-up、D5)**: `.github/workflows/checks.yaml` に `govulncheck -test ./...` と `-tags e2e` の step がある。
- **V6 D3 の完了**: `scripts/check-portal-render.sh` と Makefile の target が無く、ADR-0027 D6 の行列 (status × dirty × requireExfil × exfilReceived) が `make test` の goja のテストにある。
- **機械の確認が無いもの**: D4 (c) の pin の出自 (network が要る)。PR 本文の記録と security の review で確かめる。

## Advice

- security-engineer (2026-10-17、#381 の review、APPROVE with comments): F1 (pin を master first-parent の merge commit へ・engine の自己検査)・F4 (実 graph の検査)・F5 (`govulncheck -test`)、採用を推す理由 (jsc は CI で fail-open・node / qjs の apk は `make test` を止める・e2e は advisory)、check-portal-render の goja への移植の提案 → Options・D3・D4・D5。
- software-engineer (#381 の選定理由、PR 本文): jsc は macOS だけ・node / qjs は `Dockerfile.test` の apk pin が切れると `make test` と CI が止まる・go.sum で固定できる module の方が決定的 → Option 1 の理由。
- VP (2026-10-17、発注): 基準④への該当、代替 (jsc / node / qjs / e2e の Chromium / Go への移植 / server への問い合わせ) との比較、一般則として使うか (checkPortalEsc / check-portal-render.sh との分担)。
- architect (発注の外): node の digest pin の案を実測した (`libstdc++` への動的リンク)。server だけにする案は依存の判断でなく表示名の設計の判断として Signpost 1 に置いた。D6 (基準④の読み方の提案)。
