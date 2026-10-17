# ADR-0035: portal の template に書いた JS の振る舞いは、Go のテストが goja (test 専用の pure Go の JS エンジン) で実行し、required の `make test` で固定する。test 専用の第三者 Go module には入口の条件を置く

- Status: **Accepted** (2026-10-17。起草 2026-10-17、VP が承認: Proposed への objection が 1 往復で無かったとき VP が Accepted にできる委任の範囲 (workspace `ORGANIZATION.md:470-472`)。review-5x 16 回目 (app#381) の指摘の反映後)。本番の image と契約には効かないので CEO の判断は要らない。D3 (check-portal-render.sh の goja 移植) は Accepted の後の別 PR。
- Date / Deciders: 2026-10-17 / VP (承認) + architect (起草) + security-engineer (#381 の監査: goja は採用可、条件 F1) / 実装: software-engineer (go.mod・境界の test・CI)、application-engineer (portal の test)
- 関連: app#381 (`fix/display-name-reject-cf-c1`、#331・#343)、ADR-0031 (D1 (b)・V4・Advice (2))、ADR-0027 D6 / V7 (`scripts/check-portal-render.sh`)、ADR-0012 (`code` の追加。Proposed)、ADR-0036 (apk の pin の戦略。main 入り済み: 2a61724。本 ADR はその一次資料 (ADR-0031 と #382 / #384) だけでも読める)、workspace `ORGANIZATION.md` §8 の基準④、workspace issue #77 (基準④の運用の提案。CEO 判断)
- 読み方: app の main は origin/main `037f29d` (2026-10-17)、#381 は `origin/fix/display-name-reject-cf-c1` (rebase 済み。security の F1・F2 と review-5x 16 回目の採用 findings を反映済み)。file:line は #381 の tip のもの。`0031:N` などは `docs/adr/` の各 ADR。security の指摘は #381 の security review (2026-10-17) の F 番号。「実測」は 2026-10-17 に colima-falco-build (aarch64) で使い捨ての container を回した結果

## Context

- **C1 何を固定したいか。** Profile の form の表示名の検査 (`pane-me.tmpl:196-246` の `trimName`・`nameProblem`・`planSave`) は「server (`internal/scoreboard/api/api.go:1110` の `validDisplayName`) より厳しくならない」ことが契約 (`pane-me.tmpl:197-198`)。#343 はその破れ (form だけが拒否する)。#381 は共有のケース表 (`internal/scoreboard/api/testdata/display-name-parity/cases.yaml`) を server 側 (`display_name_parity_test.go` の `TestDisplayNameParity_ServerMatchesTable`・`_ClientIsNeverStricter`) と form 側の両方に流す。form 側は template の source から関数を切り出して goja で実行し (`internal/scoreboard/view/portal_nameproblem_test.go` の `extractJSFunc`・`runJS`・`TestNameProblem_AnswersTheSharedTable`)、全 code point を走査する (`TestNameProblem_SweepEveryCodePoint`、約 3 秒)。server も同じ全 code point を `TestDisplayNameParity_SweepEveryCodePoint` で走査し、両者は同じ規則 `testdata/display-name-parity/rule.yaml` と突き合わせる (server == rule、form == rule)。
- **C2 今ある JS の実行手段。**
  - jsc: `scripts/check-portal-render.sh` (ADR-0027 D6 の evade card の描画の行列) は macOS の jsc を使う任意の target で、`make test` にも CI にも無い (`check-portal-render.sh:15-18,22-33`、`Makefile:49,261-262`)。ADR-0031 は「jsc の拡張だけ」を退けた (`0031:57`)。
  - Chromium: `Dockerfile.e2e` の `make e2e` (advisory の job `e2e`: `.github/workflows/checks.yaml:146`)。Chromium は apk の exact pin で、index の更新で赤になる (2026-10-17 の #382・#384 は pin を更新した PR。ADR-0031 D5: `0031:166-173`。頻度は ADR-0036 C3 の集計で月 2〜3 回)。
  - `make test` = `Dockerfile.test` の `go vet` と `go test` (apk の package を 1 つも入れない: `Dockerfile.test:8-72`)。required の文脈は `test / go-test` ほか (2026-10-17 に branch protection を API で実測)。
  - 静的検査: `checkPortalEsc` など (`internal/scoreboard/view/portal_partials_test.go:540-563`) は source の構造 (宣言が 1 つ・順序・shadow が無い) を regex で見る。振る舞いは見ない。
- **C3 依存の事実。** `github.com/dop251/goja` (MIT。tag が 0 本 (`git ls-remote --tags`、2026-10-17) なので pseudo-version で pin する。master の HEAD は 313b6b66)。#381 の pin は maintainer の master first-parent の merge commit e1fc788e4f41 (#745。security F1 の条件: `go.mod:8`)。推移依存は `dlclark/regexp2/v2 v2.5.2`・`go-sourcemap/sourcemap v2.1.3+incompatible` (新規) と `google/pprof` (main の go.sum に既にあり、indirect で go.mod に載る) (`go.mod:23,43,45`)。
  - go.sum にはこれに加え、`Masterminds/semver/v3 v3.5.0` と `goccy/go-yaml v1.19.2` の各 2 行 (h1 と go.mod) が載る。どちらも go.mod の require には無く、goja 自身の test だけが引く module (`go mod why`)。この repo の binary にも test にも compile されない。`make tidy` が go.mod / go.sum を変えない (= tidy の産物で手書きでない) ことは 2026-10-17 に確認した。go.sum の h1 は sum.golang.org と一致する (security の確認)。
  - Dependabot の gomod は週次 (`.github/dependabot.yml:24-36`) だが、pseudo-version から pseudo-version への更新は出さない (dependabot-core#3017 の maintainer の回答。要望は #2028 で open)。goja の更新は手動になる。
  - `govulncheck ./...` は test だけが import する package を見ない (`.github/workflows/checks.yaml:74-79`、F5)。goja は今の脆弱性検査の外にある。
  - 本番の binary への混入の検査は `internal/apispec/e2e_boundary_test.go` の `jsEnginePrefix` (`:38-41,77-81`) と planted の fixture (`:125-137`)。見るのは module の中の package の静的な import の閉包だけで、第三者の module を経由した混入は見えない (F4)。
- **C4 忠実度。** goja はブラウザではない。正規表現は自前 (Go の regexp と regexp2 への fallback) で、`\p{..}` の表は Go の unicode (15.0.0) から取る。旧い pin では `/u` の `\p{..}` が壊れていた (F1: `/[\p{Cc}\p{Cf}]/u.test("c")` が true)。新しい Unicode の表を持つブラウザが、新しく Cf になった文字を拒否する残余は、テストの header に書いてある (`portal_nameproblem_test.go` の header (`What this is not: a browser`、:31-36))。
- **C5 規則。** 基準④「新規依存 / 新ツール / ...の追加」(workspace `ORGANIZATION.md:490-492`) に test 専用の除外は無い。test 専用の前例は chromedp で、ADR-0031 がコストと影響として記録した (`0031:47,180`)。

## Options (Alternatives)

1. **goja を `make test` で使う【推奨】** —
   変更点: test 専用の Go module 1 つ (+ 推移 2)。
   コスト: go.mod の 4 行、依存の手動更新 (C3)、`make test` が数秒増える (C1)。required の gate の中で決定的に回る (go.sum で固定。network も apk も使わない)。
   リスクと可逆性: ブラウザとの意味の差 (C4) — engine の自己検査と残余の明記で扱う。test と go.mod の行を消せば戻る。
   効き始める閾値: 即時 (#381)。
2. **`Dockerfile.e2e` の Chromium で、サーバ無しの頁として回す** (ADR-0031 Advice (2): `0031:189`) —
   忠実度はいちばん高い (実ブラウザの正規表現と Unicode の表)。
   コスト: gate が advisory の `e2e` (required でない) になり、Chromium の pin が index から消えるたびに赤になる (C2。#382・#384)。1 回 2 分前後 (ADR-0031 V5)。
   効き始める閾値: ADR-0031 D1 (c) で `e2e` が required になったとき、またはブラウザの表に依存する性質を固定したいとき (Signpost 3)。
3. **node を digest で pin した image から `Dockerfile.test` に入れる** —
   V8 なので Chrome に近い。
   コスト: `node:24-alpine` の node は `libstdc++.so.6`・`libgcc_s.so.1` (apk の package) に動的にリンクしている (実測) ので、binary だけを COPY できず、apk の pin (ADR-0036 の drift) か共有ライブラリの複写が要る。Class-2 (`Dockerfile.test`)、2 つ目の runtime、Go のテストから exec。

**方向として採らないもの**:
- **jsc**: macOS だけで、CI では動かず gate が fail-open になる (C2)。
- **node / qjs を `Dockerfile.test` に apk で入れる**: required の `test` を Alpine の index に結びつける。index は 1 版だけを持つ (ADR-0031 `0031:41`) ので、exact pin なら更新のたびに全 PR の `test` と Stop hook が止まり (実例: #382・#384 の pin 更新、ADR-0031 D5 `0031:166-173`)、pin しなければ gate の engine の版が commit 無しに変わる。
- **JS を Go に移す二重実装**: テストが見るのは移植で、出荷する JS ではない。#343 (form と server の食い違い) の型をそのまま残す。
- **client の検査をやめ、server の 400 だけにする**: 「form は server より厳しくならない」が構造で成り立ち、C4 の残余も消える。ただし (i) `planSave` の「名前を変えたときだけ検査する」ための trim は server と同じ集合でなければならず (`pane-me.tmpl:236-246`)、JS の検査が残るか、その判定を server に移す API の意味の変更になる。(ii) server の文言は短い (`api.go:1113-1119`) ので、ADR-0012 の `code` (Proposed) が要る。表示名の設計の判断で、依存の判断ではない (Signpost 1)。

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
  - (e) 実行は secret の無い test の container の中だけ (`Dockerfile.test`、CI の go-test)。事実として、本番 image の builder (`images/ttyd-proxy/Dockerfile` ほか) も `go mod download` で go.mod の全 module (goja を含む) を取得する。link も実行もしないので binary には入らない ((a) の検査が見る)。後続の test 専用依存を判断するときはこの取得も入口の面として数える。
  - (f) テストの判定が library の意味に依存するなら、その意味を自己検査で固定する (`TestEngine_UnicodePropertyEscapes_SelfCheck`: `portal_nameproblem_test.go` の `TestEngine_UnicodePropertyEscapes_SelfCheck`)。
- **D5 #381 の merge の条件。** #381 は次の表を満たす (PR 本文に貼る)。(a) の実 graph (V2) と (b) (V5) は follow-up とし、**app #400、期限 = 次の stand-up の前** (security は follow-up を可とした: F4・F5)。**追補 (2026-10-17): #400 で機械化済み (V2 / V5)。下の表の (a)(b) と、末尾の「追補」を見る。**#400 が期限までに main に入らなければ、次の test 専用依存の PR と D3 の PR はどちらも出さない。

  | D4 | #381 |
  |---|---|
  | (a) graph | 静的閉包は済み (`e2e_boundary_test.go:38-41,125-137`。security の実測で planted M1〜M3 が赤、`go list -deps ./cmd/<x>` で 6 本とも goja 0 件)。実 graph の test は follow-up (#400)。**#400 で機械化済み (V2)**: 一覧は `internal/apispec/testdata/test-only-deps.txt` の 1 箇所で、`e2e_boundary_test.go` の静的 closure と `testonly_deps_test.go` の `go list -deps ./cmd/...` (既定 tag と `-tags e2e`) が同じ file を読む |
  | (b) govulncheck -test | follow-up (#400。手元の `govulncheck -test ./internal/scoreboard/view/` は No vulnerabilities found: security)。**#400 で機械化済み (V5)**: `checks.yaml` の `go-vulncheck` に `-test` と `-test -tags e2e` の step、と test 専用 module を root にする `scripts/check-test-only-vuln.sh` の step。**`-test` だけでは goja を見ていない** (追補) |
  | (c) pin | e1fc788e4f41 = master first-parent の merge commit (#745、署名 verified) |
  | (d) 更新 | 手動 (pseudo-version のため Dependabot は上げない) |
  | (e) 実行の場所 | `Dockerfile.test` の中だけ (CI の go-test は `contents: read`、secret を渡さない: security) |
  | (f) 自己検査 | `TestEngine_UnicodePropertyEscapes_SelfCheck` (旧い pin では赤) |

- **基準④との関係。** goja は基準④「新規依存」に当たるので、本 ADR を書いた (基準④に test 専用の除外は無く、required の gate の判定を第三者の code が左右し、更新と脆弱性検査が既定の経路の外に出る: C3・C5)。以後の test 専用依存を ADR でなく PR 本文の適合表と security の review で済ませてよいか (`ORGANIZATION.md` §8 の運用変更) は組織の決定なので、ここでは決めない (workspace issue #77、CEO 判断)。それまでは依存ごとに ADR を書き、D4 を入口の条件にする。

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
- **V2 実 graph (#400 で機械化済み、D5)**: `make test` の中で `go list -deps ./cmd/...` の出力に D4 (a) の prefix が 0 件。一覧の prefix が go.mod に無ければ赤。planted: module の中の非 test file を経由して goja を引くと赤。
- **V3 engine の自己検査 (済み)**: `TestEngine_UnicodePropertyEscapes_SelfCheck` が `[true,false,true]` 以外で赤。旧い pin (67663e7a) に戻すと `[false true false]` で赤になる (#381 本文)。
- **V4 振る舞い (済み)**: 共有表の「form だけが拒否 = 0 件」(`TestNameProblem_AnswersTheSharedTable`、`TestDisplayNameParity_ClientIsNeverStricter`) と、server・form それぞれの全 code point の走査 (`rule.yaml` と突き合わせ)。security の mutation M4〜M10 (M9 は F2 の 4 行で赤になった)。
- **V5 脆弱性検査 (#400 で機械化済み、D5)**: `.github/workflows/checks.yaml` に `govulncheck -test ./...` と `-test -tags e2e ./...` の step、と `scripts/check-test-only-vuln.sh` の step がある (どれも `if: ${{ !cancelled() }}`、非 required の advisory job `go-vulncheck` の中。job 名は変えていない)。後者は一覧 (V2 と同じ file) の module の package を root にして走らせ、一覧の各 module が govulncheck の「scanned modules」に出ることを確かめる (出なければ赤): ログに goja・regexp2・go-sourcemap・google/pprof が出る。
- **V6 D3 の完了**: `scripts/check-portal-render.sh` と Makefile の target が無く、ADR-0027 D6 の行列 (status × dirty × requireExfil × exfilReceived) が `make test` の goja のテストにある。
- **機械の確認が無いもの**: D4 (c) の pin の出自 (network が要る)。PR 本文の記録と security の review で確かめる。

## 追補 (2026-10-17、#400)

- **`govulncheck -test` は in-package の test file の import を見ない。** 実測 (govulncheck v1.1.4 と v1.9.0、使い捨ての module): 脆弱な `golang.org/x/text v0.3.0` を `a_test.go` (`package t`) だけが import すると、`-test` は "No vulnerabilities found" で、scanned modules に x/text が出ない。同じ import を `package t_test` (外部 test package) に置くと報告される。goja は `portal_nameproblem_test.go` (in-package) から import されるので、`-test ./...` だけでは goja と推移依存 (regexp2・go-sourcemap・pprof) が scan の外にある。security の手元の確認 (上の表) はこの限界の下の "No vulnerabilities found" だった。
- **だから V5 は 2 面で満たす。** (1) `-test` / `-test -tags e2e` の step は、ADR が名指した形で残す (外部 test package と、test だけの chromedp 側の経路は見える)。(2) `scripts/check-test-only-vuln.sh` が、一覧 (D4 (a) の同じ file) と `go list -test -tags e2e -deps ./...` から test 専用 module の package を引き、それを root にして govulncheck を走らせる。library の root は export された API が入口になるので、test でしか動かない code に対して最も保守的な scan になる。各 module が scanned modules に出ることまで確かめるので、scan が goja を見ていない状態は赤になる。
- **一覧は両方向に検査される** (`testonly_deps_test.go`): go.mod にも module にも無い entry は赤 (古い entry が防御に見え続けない)。test が使い production が使わない module が一覧に無ければ赤 (新しい test 専用依存、または goja の更新で増えた推移依存は、同じ PR で一覧に足し、D4 (c)(d) を満たすまで `make test` が止める)。
- **planted** (実 toolchain、`go.mod`・`go.sum` を共有する使い捨ての module): `cmd/fakebin` が goja を直接 / 非 test file の経由で import、goja の推移依存 3 つを直接 import、internal/e2e/harness を 2 hop で import、build tag e2e の中の chromedp を `-tags e2e` で build、のどれも赤。clean な binary と、test file だけが goja を import する binary は緑。
- **V5 の step が存在し続けることは `make test` では見えない** (`.dockerignore` が `.github` を除くので、test の container に workflow が無い)。step は job の中で動くので、消せば PR の diff に出る。

## Advice

- security-engineer (2026-10-17、#381 の review、APPROVE with comments): F1 (pin を master first-parent の merge commit へ・engine の自己検査)・F4 (実 graph の検査)・F5 (`govulncheck -test`)、採用を推す理由 (jsc は CI で fail-open・node / qjs の apk は `make test` を止める・e2e は advisory)、check-portal-render の goja への移植の提案 → Options・D3・D4・D5。
- software-engineer (#381 の選定理由、PR 本文): jsc は macOS だけ・node / qjs は `Dockerfile.test` の apk pin が切れると `make test` と CI が止まる・go.sum で固定できる module の方が決定的 → Option 1 の理由。
- VP (2026-10-17、発注): 基準④への該当、代替 (jsc / node / qjs / e2e の Chromium / Go への移植 / server への問い合わせ) との比較、一般則として使うか (checkPortalEsc / check-portal-render.sh との分担)。
- architect (発注の外): node の digest pin の案を実測した (`libstdc++` への動的リンク)。server だけにする案は依存の判断でなく表示名の設計の判断として Signpost 1 に置いた。基準④の運用変更の提案は ADR から外し、workspace issue #77 に移した (review-5x 16 回目 R4#4)。
