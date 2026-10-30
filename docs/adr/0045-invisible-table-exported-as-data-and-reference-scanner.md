# ADR-0045: 不可視文字の表を data file として書き出し、参照 scanner を app に 1 本だけ置く。platform と workspace は scanner を走らせるだけにする
- Status: **Accepted** (2026-10-26。実装: app#536 = cf34518。review-5x 83 (T3) R1 APPROVE with comments (security)、HIGH 2 は MED に下げて反映済み。消費者 = platform#294 / ws#89 (未 merge。APP_PIN bump と同時か後))
- Date / Deciders: 2026-10-26 / VP + architect (起草) + security-engineer (R1)
- 関連: app#511 (security 仕様 F2)、#501 (bidi の gate)、#525 (表と scanner を sourcehygiene の非 test package に置いた)、#529 (= c8b9e0c、ADR-0043 の実装) / ADR-0043 (Option 3・Signpost 3)、ws#86 (review-5x の T2 下限に `internal/sourcehygiene/`)、platform#294 (platform の消費者 PR: wrapper・selftest・CI step・APP_PIN の bump)、ws#89 (workspace の消費者 PR: wrapper・`check-agent-skills.sh` への接続)、app#537 (walk と allowlist の signature 検査と、否定例の共有 data。follow-up)、app#542 (binary の path の閉集合と、Go だけにあった否定例の共有 dir への移動。#537 の follow-up)、platform#290 (ADR-0044。同じ APP_PIN の行を触る)、先例 ADR-0042 / ADR-0044 (app の表を platform が sibling clone から読む)

## Context
(file:line は app origin/main e47669f、platform origin/main ca0572a、workspace origin/main e97ed51 の版)
- C1. app の規則は Go の 1 定義で、公開面は述語だけ。
  - 規則の種別は `ruleKind` の 5 値 (internal/sourcehygiene/invisible.go:48-54)。表は `invisibleRanges` の 37 行 (:57-99)。
  - 文脈規則は `scan` にある (:144-203)。入口は `Invisible` (:137) と `Hidden` (:142)。bidi の 9 文字は `bidiControls` (chars.go:8-18)。
  - 文脈規則の中で使う範囲 (skin tone と VS) は、表ではなくコードの定数にある (invisible.go:129-130)。
  - 非 test の import は標準ライブラリだけ (:38-43)。
  - walk (file 集合・`binaryExt`・NUL・symlink) は test file にある (bidi_test.go:77-82, :148-180, :201-250)。allowlist の reader も test file にある (invisible_test.go:70-124)。
- C2. ADR-0043 は、述語を葉 package に切り出す案 (Option 3、0043:14) を保留にした。Signpost 3 (0043:33) は「sourcehygiene の非 test package に述語以外 (walker・allowlist reader・CLI) が入る PR が出る → 先に Option 3 で切り出す」。
- C3. platform と workspace は、app の Go module を import できない。
  - この machine の host には `go` が無い (実測。app の Go は Makefile:171-172 の Docker 経由で動く)。
  - platform の runner image は python3 を持つ (ci/runner/Dockerfile:43。verify-tools.sh:44 が 3.12 を固定)。この machine の python3 は 3.14.7。
- C4. 今の状態 (2026-10-26 実測)。
  - platform の tracked file には U+FE0F が 19 件、workspace には 8 件ある。直前はすべて U+26A0 (So) で、文脈規則で許される。ほかの不可視の code point は 0 件。
  - platform は PDF を 2 本 tracked している (`events/2026-06-pilot/decks/build/`)。この 2 本は走査していない。
- C5. platform の parity の先例。
  - CI の `identity-selftest` job (platform .github/workflows/ci.yaml:2070-2131) は app を APP_PIN で checkout する。APP_PIN の置き場はここ 1 か所 (:2074-2081)。
  - `scripts/test-seat-grammar-parity.sh:1-30` は表の placeholder を decode し、decode 後に `{` `}` が残る行を FAIL にする。表が無いときも SKIP にせず FAIL。
  - app の `internal/casetable/casetable.go:28-63` も同じ規則。
- C6. Unicode の版。
  - Go 1.26 の `unicode.Version` は "15.0.0"。Python の `unicodedata.unidata_version` は、この machine で 16.0.0 (実測)。runner の 3.12 は 15.0.0 になるはず (仮説)。
  - 表の行は静的な定数なので版に依存しない。版に依存する入力は、文脈規則の「非 ASCII の So」の判定 (invisible.go:128) だけである。
- C7. workspace の入口。
  - VP が回す検査は `scripts/claude/check-agent-skills.sh` で、結果の判定は :354-359。
  - `.claude/settings.json` は untracked のまま、セッションに読まれる。auto-memory の dir は git の外にあり、次のセッションにそのまま読まれる。
- C9. workspace は app を pin しない。REFACTORING.md の決定事項は「app の git SHA を 1 箇所で pin する」で、platform の APP_PIN がそれにあたる。workspace の検査は deploy の契約ではなく、VP の手元の衛生検査である。このため workspace には pin を適用せず、最新の規則を当てる (適用外。理由つき)。代わりに wrapper は、使った app の SHA を必ず出力する (ws#89)。
- C8. ws#86 (open) は review-5x の T2 下限に `internal/sourcehygiene/` を入れる。本 ADR の app PR は `internal/sourcehygiene/testdata/` を触るので、その対象になる。

## Options
1. **A: app が表を data file として書き出し、参照 scanner (Python 標準ライブラリだけ) も app に 1 本だけ置く**。
   - 変更点: Go の test が「data = Go の値」を固定する。app の flag-guard が、Python の scanner と `Hidden` の一致を共有 cases 表で確かめる。platform と workspace は、sibling clone の scanner を自分の tree に当てるだけにする。
   - コスト:
     - 実装が Go と Python の 2 つになる。文脈規則は Go の `scan` が 60 行、Python 版が 48 行。実測の大きさは scanner が 800 行 (reader・walk・allowlist・selftest を含む)、Go の test が 550 行、shell の mutant test が 185 行。
     - data file は 3 本 (印字可能な ASCII)。消費者は python3 が要る (どちらにもある)。新しい image も依存も足さない。
   - リスクと可逆性:
     - cases 表に無い入力で、Go と Python がずれうる。flag-guard で app tree の実 file を両方に通すことで、これを補う。
     - So の版の差が残る (D9)。
     - 可逆: scanner と data を消し、消費者の wrapper を外せば戻る。
   - 効き始め: app の CI は merge と同時。platform は APP_PIN の bump から。workspace は wrapper の merge から。
2. **B: Go の CLI (`cmd/sourcehygiene-scan`)**。
   - 変更点: 消費者が `go run` する。
   - コスト:
     - walker と allowlist reader が非 test コードになるので、先に ADR-0043 Option 3 で package を切る必要がある。
     - platform の CI と runner image に Go の toolchain と、その版の parity が要る。
     - host に Go が無いので、workspace の検査が Docker (colima) 経由になる。
   - リスクと可逆性: 意味は完全に同一で、再実装は 0。可逆。
   - 効き始め: 全消費者の環境に Go が揃ったとき。
3. **C: data file だけを共有し、scanner は各リポが書く**。
   - 変更点: 写すのは data だけ。
   - コスト: 実装が 3 つになり、parity の検査も 3 本要る。
   - リスクと可逆性: drift の面が A より広い。可逆。
   - 効き始め: A と同じ。消費者ごとに別の言語が要るときだけ A より良い。
- 選択肢にしないもの: 表と文脈規則を各リポに写すこと。1 定義の規則 (conventions:279「写しを作らない」) に反する。

## Decision
A。新しい toolchain を足さず、sourcehygiene の非 test package を広げず、2 実装の parity を app の CI の 1 か所で見られるため。

- **D1. data file は 3 本で、置き場は `internal/sourcehygiene/testdata/`。**
  - ここは security 必須の対象 `internal/sourcehygiene/**` の内側にある (ADR-0043 Consequences)。
  - 3 本とも、印字可能な ASCII (U+0020-007E)、TAB、LF だけで書く。
  - (a) `hidden-ranges.tsv`
    - header は 3 行。1 行目 `# unicode: <unicode.Version>`、2 行目 `# skin-tone: U+1F3FB-U+1F3FF`、3 行目 `# variation-selector: U+FE00-U+FE0F,U+E0100-U+E01EF`。
    - 行の形は `U+LLLL<TAB>U+HHHH<TAB><rule><TAB><name>`。code point は `U+%04X` の書き方を 1 つだけ許す。
    - 行は `invisibleRanges` と `bidiControls` を合わせたもので、lo の昇順、重なり無し。bidi の行は 1 code point で 1 行 (lo = hi)。
  - (b) `hidden-cases.tsv`
    - 行の形は `<name><TAB><input><TAB><expected>`。
    - input の書き方は D1 (d)。expected は `none` か、`<line>:<col> U+XXXX` を `,` で区切った列 (Go の test の `at()` と同じ形)。
    - 判定は `Hidden` に対して行う。
  - (c) `binary-ext.tsv`
    - 行の形は `<.ext><TAB><reason>`。`binaryExt` (bidi_test.go:77-82) の書き出しで、小文字、昇順、重複無し。
    - `.pdf` を足す (C4)。
    - 追記 (2026-10-27、app#537): 行の形は 3 列の `<.ext><TAB><reason><TAB><signature>` になった。`<signature>` は file の先頭 bytes の大文字 hex (2 byte 以上): `.pdf` = `255044462D` (`%PDF-`)、`.woff2` = `774F4632` (`wOF2`)、`.tgz` = `1F8B` (gzip)。file は拡張子と signature の両方が合うときだけ走査から外し、合わなければ text として走査する。data の書式は D8 により面ではないので、scanner・Go の test・data を同じ PR で変えた (app 単独 PR + security)。
  - (d) cases の placeholder
    - `{U+XXXX}` (4-6 桁の大文字 hex) は、その code point を UTF-8 にした byte 列になる。`{xHH}` (80-FF) は、生の 1 byte (不正な UTF-8) になる。
    - placeholder を取り除いた残りに `{` か `}` が残る行は、reader の誤り = FAIL にする (`{` は `{U+007B}` と書く)。
    - 次の行も FAIL にする。
      - `{U+XXXX}` で印字可能な ASCII (U+0021-007E。ただし `{` `}` は除く) を書いた行。
      - サロゲート (U+D800-DFFF) を書いた行と、U+10FFFF を超える値を書いた行。
      - `{xHH}` で 80 未満を書いた行。
      - 列が 3 つでない行、name が空か重複している行、name が `#` で始まる行。
  - (e) `binary-paths.tsv` (追記 2026-10-30、app#542)
    - binary と判定した file を**置いてよい場所**の閉集合。signature は印字可能な ASCII か 2 byte で偽造に耐えないので、場所で止める。
    - 行の形は `<.ext><TAB><directory prefix>`。prefix は `/` で終わる segment の列で、segment は `[A-Za-z0-9._+@-]` の literal (`.` と `..` は不可) か、単独の `*` (ちょうど 1 segment)。file は prefix の下に任意の深さで置ける。行は ext、prefix の昇順で、重複なし。comment だけの file は「閉集合 = 空」で、最も厳しい。
    - ext は `binary-ext.tsv` にあるものだけ (無ければ scanner は FAIL にする。一致する file が永久に無い行だから)。
    - 既定の走査は読まない。`--binary-paths <file>` で渡す (D4)。app の file は `.tgz charts/*/charts/` と `.woff2 internal/scoreboard/view/vendor/fonts/` の 2 行だけ。`.pdf` の行は無い (app は PDF を tracked しない)。消費者は自リポの file を渡す (platform = deck の PDF 2 本の path)。
- **D2. rule の語彙は、Go の識別子そのままの閉集合 `always` / `vsAfterSymbol` / `zwjInEmoji` / `bomAtStart` / `loneCR` に、`bidi` を足したもの。**
  - `bidi` は `ruleKind` ではない。`bidiControls` の行を表す。
  - 語彙は Go の識別子と 1 対 1 にし、別名の写像は持たない。
- **D3. Go の test が data を固定する。足すのは test package (`_test.go` と testdata) だけで、sourcehygiene の非 test package (invisible.go / chars.go) には何も足さない。**
  - walker、allowlist reader、CLI は `scripts/` の Python に置く。このため ADR-0043 Signpost 3 は発火しない。
  - その状態は V1-e が機械で保つ。
- **D4. 参照 scanner `scripts/sourcehygiene-scan.py`**
  - Python 標準ライブラリだけを使い、python3 は 3.9 以上。
  - data は、自分と同じ checkout の D1 の 3 file だけを、自分の位置からの相対 path で読む。data の場所を引数では受けない。
  - 述語は `Hidden` と同じにする。機械で parity を見ているのは述語だけ (共有 cases。V1-c と `--selftest`)。walk と allowlist は、Python の `--selftest` が固定するだけで、Go の gate との機械の parity は無い。見ているのは、両 gate が app tree で緑であることだけで、allowlist は bidi の code point も書けるので意味自体が同じではない。walk と allowlist の signature 検査と、否定例の共有 data は app#537 に残す。walk の規則は次のとおり (`make test` の walk に倣う)。
    - → 解消した。下の追記 (2026-10-27、app#537) を見る (この段落の原文は書き換えない)。
    - file 集合: `<dir>/.git` があれば (file でも可) `git ls-files`、無ければ disk 上の全 file。`--also-untracked <rel>` は `<rel>` の下の通常 file を足す。
    - symlink と submodule は追わない。拡張子が `binary-ext.tsv` にある file は走査しない。
    - NUL は file ごとに 1 件。U+0000 は finding から外す。
    - path は印字可能な ASCII だけ。判定は `re.fullmatch` で行う (`$` は末尾の LF を通す)。
    - lstat の `FileNotFoundError` だけを「無い」とし、ほかの OSError と、`os.walk` の列挙の失敗は FAIL にする (読めない subtree を黙って飛ばさない)。dir を指す symlink も列挙して path の規則をかける (Go の WalkDir と同じ集合)。
    - allowlist は closed set。列にある code point だけを許し、dead entry は FAIL。
  - 追記 (2026-10-27、app#537): 上の「walk と allowlist の signature 検査」と「否定例の共有 data」は app#537 で解消した。walk は signature 検査を持ち (D1 (c) の追記)、reader と walk の否定例は `internal/sourcehygiene/testdata/negatives/` の「1 dir = 1 否定例」(`expect.txt` + 入力 1 つ。形式は `negatives_test.go` の先頭) に置き、Go の `TestSharedNegatives` と scanner の `--selftest` が同じ dir 群を同じに判定する。共有しないもの (scanner の `--selftest` だけが固定する): ranges の reader (Go は読まずに Go の表と比べる)、binary だけの tree、bidi の allowlist、git mode、`--also-untracked`、symlink、列挙できない dir、command line。
  - 追記 (2026-10-27、app#537、review-5x 88):
    - 走査しない条件 (上の「拡張子が `binary-ext.tsv` にある file は走査しない」) は、拡張子が表にあり**かつ**先頭が signature に一致する file に読み替える。拡張子は小文字で、base name の先頭の dot の並びは拡張子にしない (`.woff2` / `..pdf` / `d/.tgz` は拡張子を持たない)。Python の `os.path.splitext` の規則で、Go の gate は同じ規則の `extOf` で合わせる。
    - 置き場の規則: **両実装が持つ挙動の否定例は `testdata/negatives/` に置く**。Go の表に残すのは共有しないもの (上の列挙) と、Go の文言の確認だけにする。plant.tsv の path は 1 segment (`/` を含まない。`.` / `..` でない)。違えば reader の拒否で、`out:` 行を持つ否定例として書く。
    - `--selftest` は `testdata/negatives/` も読む。通常の走査 (`<dir>`) が読むのは 3 file だけで足りる。bundle を部分コピーする消費者を作らない (D8 の追記)。
  - 追記 (2026-10-30、app#542):
    - **binary の path の閉集合**: `--binary-paths <file>` (D1 (e)) が渡されたとき、binary (拡張子と signature の両方が合う file) は、自分の拡張子の行の prefix の下にあるときだけ走査から外す。下に無い binary は problem で、**text としては走査しない** (赤にする。偽造 signature の置き場を増やさないため)。渡さなければ従来どおり、どこにあっても外す。名前を付けた file が読めない、書式が違う、`binary-ext.tsv` に無い ext の行がある、は FAIL。
    - app の gate は渡す。Go の `TestTrackedFilesHoldNoRawBidiOrInvisibleCharacter` は「tracked の binary 拡張子 ⊆ {.woff2, .tgz}」の tripwire を、`binary-paths.tsv` による同じ判定 (`checkRealTree` が walk の scanner として足す) に置き換えた。flag-guard の app tree の走査も渡す。閉集合の外の `.pdf` / `.woff2` / `.tgz` は赤になる。
    - 閉集合の判定 (`*` は 1 segment、file は prefix の下、拡張子ごと) は Go と Python で同じ。共有の否定例 (`walk-binpaths-*` と `reader-binpaths-*`) が機械で見る。
    - 置き場の規則の plant.tsv の path は、1 segment から clean な相対 path (`/` 区切り。空の segment と `.` / `..` の segment を含まない) に広げた。閉集合の下の path を置くため。違えば reader の拒否で、`out:` 行を持つ否定例のまま。
    - Go の表に残すもの (review-5x 88 R4#3 の follow-up。`invisible_test.go` の `TestCheckTree_Invisible` の 5 case を共有 dir に移した後): Go の文言と escape hint の確認、Go の gate の path (journey.yaml の hint)、bidi の allowlist、source が持てる escape の形、Go の表の形。理由は `negatives_test.go` の header に列挙してある。
  - 出力は path、line、col、code point、名前、理由だけにする。file の中身は出さない。
  - 終了コードは、0 = 違反なし、1 = 違反、data が読めない、走査が 0 件、2 = 使い方の誤り。
- **D5. app の CI**
  - required check の `flag-guard` が、`--selftest` と、app tree を `internal/sourcehygiene/testdata/invisible-allowlist.txt` で走査するステップを回す。
  - Go 側は required check の `test` (`make test`) で回る。
- **D6. platform**
  - `scripts/check-source-hygiene.sh` が、APP_PIN の sibling app clone の scanner を、自リポの tree と自リポの allowlist (closed set。追加は security review) に当てる。
  - CI は `identity-selftest` の 1 step にする。ここが APP_PIN の唯一の置き場だからである (C5)。
  - clone に scanner が無ければ FAIL にする。
  - platform は文法も表も持たない。
- **D7. workspace**
  - `scripts/claude/check-hidden-chars.sh` が、app の `refs/remotes/origin/main` から `git archive` で scanner と testdata を一時 dir に取り出す。
  - 取り出すのを worktree の checkout からにしない。worktree は feature branch のことがあるため。
  - 取り出した scanner を、tracked file と untracked の `.claude/` に当てる。auto-memory の dir があれば、それにも当てる。
  - `check-agent-skills.sh` の結果判定の前から呼ぶ。SessionStart hook にするかは CEO 判断。
- **D8. 消費者が読む面と、変更の規則**
  - 読む面: bundle の配置、scanner の CLI (`--selftest` / `<dir>` / `--allowlist <file>` / `--also-untracked <rel>` / `--binary-paths <file>`)、終了コード、allowlist の書式、出力の接頭辞。
    - bundle の配置 = `scripts/sourcehygiene-scan.py` と `internal/sourcehygiene/testdata/{hidden-ranges,hidden-cases,binary-ext}.tsv` の repo 相対の path。data の path の移動・rename は面の変更で、追加だけを許す (変えるなら新しい path)。
    - 判定に使うのは終了コードだけ。安定を約束する出力は、finding 行の接頭辞 `<path>:<line>:<col> U+XXXX` と、要約行の接頭辞 `OK sourcehygiene-scan:` / `FAIL` だけで、ほかの文言は安定を保証しない。消費者の selftest は終了コードと接頭辞だけで判定する。
    - allowlist の書式は `invisible-allowlist.txt` と同じ。違いは bidi の code point も書けることだけ。
    - data file の書式は面にしない。
    - 追記 (2026-10-30、app#542): `--binary-paths <file>` は CLI の**追加**で、渡さなければ従来の挙動なので、app 単独 PR で足せる (消費者 PR は後続でよい)。`<file>` の書式 (D1 (e)) は渡す側 (消費者) が書くので、面に含める。`binary-paths.tsv` は bundle (`testdata/` の全体) の中にあるが、通常の走査は読まず、渡された file だけを読む。
    - 追記 (2026-10-27、app#537、review-5x 88、VP 承認 2026-10-27): bundle の単位を「`scripts/sourcehygiene-scan.py` + ディレクトリ `internal/sourcehygiene/testdata/` の全体」にする (3 file から広げる。ws#90 は既にこの単位で `git archive` する)。`--selftest` は `testdata/negatives/` も読み、通常の走査 (`<dir>`) は 3 file だけで足りる。bundle を部分コピーする消費者を作らない。file / dir の移動・rename は面の変更で、追加は許す。
  - 変更の規則:
    - 表の行・case 行の追加 (= 狭める): app 単独 PR + security。
    - 行の削除、文脈規則の緩和: app 単独 PR + security + ADR。
    - `binary-ext.tsv` の行の追加: app 単独 PR + security。app の `binary-paths.tsv` の行の追加も同じ (app の閉集合を広げる = 偽造の置き場を足す。Go の `appBinaryPaths` と同じ diff で変える)。
    - scanner と mutant harness (`scripts/sourcehygiene-scan.py` / `scripts/test-sourcehygiene-scan.sh`) のコードの変更: app 単独 PR + security。platform / workspace が同じ規則を当てる単一の実装なので、`internal/sourcehygiene/**` と同じ扱いにする。
    - data の書式と rule の語彙: app 単独 PR + security。scanner、Go の test、data を同じ PR で変える。
    - 消費者が読む面: 追加だけを許す。意味を変えるなら新しい path にする。追加だけなので両リポ同時 PR は要らず、消費者 PR は後続でよい。意味を変えるときは app と platform の同時 PR にし、workspace は app の merge と同じセッションで追随する。
    - platform の APP_PIN の bump は対の PR にする。
- **D9. Unicode の版**
  - scanner は `unicodedata.unidata_version` が header と違えば、WARN を 1 行出す (終了コードは変えない)。
  - 版の間に新しく割り当てられた非 ASCII の So は、版によって判定が変わりうる。その直後の U+FE0E / U+FE0F / U+200D の判定は、Python の版が新しければ緩い側に、古ければ厳しい側にずれる。これは受け入れる残余とし、Signpost 3 で再訪する。

## Consequences
- 諦めたもの:
  - B の完全な同一性。parity は cases 表と、app tree の実 file の走査で見る。
  - 消費者ごとの binary 拡張子。`.pdf` を app の表に足すので、app の gate も今後 `.pdf` を走査しない。app には今 `.pdf` は無く、`TestTrackedFilesHoldNoRawBidiOrInvisibleCharacter` が「tracked の binary は `.woff2` と `.tgz` だけ」を固定する。PDF の描画内容は文字の規則の対象外で、受け入れる残余とする。
  - `*.pdf` と名付けた text file は、拡張子だけで判定するので走査されずに素通りする。中身が PDF であることの signature 検査は app#537 に残す。
    - 追記 (2026-10-27、app#537): signature 検査を足した。拡張子が表にあり、かつ先頭が signature に一致する file だけを走査しない。`*.pdf` と名付けただけで先頭が `%PDF-` でない text は走査される (`.woff2` と `.tgz` も同じ)。**残る残余: 拡張子が表にあり、先頭が signature に一致する file は、形式として正しいかを問わず (本物でも偽造でも) 走査しない。** signature は誤命名への対策で、偽造への対策ではない (`%PDF-` / `wOF2` は印字可能 ASCII、gzip は 2 byte。`wOF2` で始まる text を `*.woff2` と名付ければ Go と Python の両 gate を素通りする)。app で偽造 `.pdf` を止めるのは、`TestTrackedFilesHoldNoRawBidiOrInvisibleCharacter` の「tracked の binary 拡張子 ⊆ {.woff2, .tgz}」の検査だけで、偽造 `.woff2` / `.tgz` は止まらない。platform の 2 本の PDF の描画内容は文字の規則の対象外のまま。この残余の受容は review-5x 88 (2026-10-27) の R1 (security) が APPROVE with comments として記録した。
    - 追記 (2026-10-30、app#542): **偽造 signature は、閉集合の外では止まる** (D4。problem で、text としては走査しない)。app は `.woff2` を `internal/scoreboard/view/vendor/fonts/` の下、`.tgz` を `charts/*/charts/` の下 (git mode では 0 件)、`.pdf` を 0 件に限るので、上の「app で偽造 `.pdf` を止めるのは tripwire の検査だけで、偽造 `.woff2` / `.tgz` は止まらない」は、**偽造 `.pdf` / `.woff2` / `.tgz` のどれも、閉集合の外では止まる**に変わった。**残る残余: 閉集合の中の偽造**。font の dir に `wOF2` で始まる text を `*.woff2` と名付けて置けば、素通りする (共有否定例 `walk-binpaths-forged-woff2-inside-is-the-residual` が、この残余を固定している)。入れるには、閉集合の中に binary 拡張子の file を足す diff が要り、レビューで見える。platform の 2 本の PDF の描画内容は文字の規則の対象外のまま。消費者は自リポの閉集合 (`--binary-paths`) を渡し、それ以外の場所の PDF / 偽造を止める。
- 新しく守るもの:
  - 3 file が Go の値と一致すること (V1)。
  - scanner が data を自分の checkout からだけ読むこと。
  - 非 test package が述語だけであること (V1-e)。
- workspace は app を pin しない (C9)。VP の手元の衛生検査として最新の規則を当て、使った app の SHA を毎回出力する。platform は pin する消費者なので APP_PIN の対の PR を使う。
- `bidi-allowlist.txt` に行が入ると、flag-guard の app tree の走査が赤になる。scanner は bidi を code point 単位の 1 つの allowlist で扱うからである。その時は、scanner に bidi の allowlist を読ませる変更を同じ PR に入れる (fail-closed)。
- TestInvisible_Table (invisible_test.go:303-375) の行は `hidden-cases.tsv` に移す。test を消すのではなく移す。
  - V1-c が全行で「`Invisible` = `Hidden` − bidi」を確かめるので、被覆は落ちない。
  - diff は削除に見えるので、security R1 が移した前後の行の対応を確かめる。
- 順序:
  1. app PR (Class-2。security R1。ws#86 の T2 下限を下回らない)。
  2. platform PR (APP_PIN を app の squash SHA に上げ、ci.yaml:2077-2079 の手順で roster / seat の parity を再実行する)。platform#290 と同じ APP_PIN の行を触るので、直列にする。
  3. workspace PR (app の merge の後ならいつでもよい。1 Engineer 1 PR)。
- platform の Actions が課金ホールドの間は、PR 本文に手元の出力を貼る。
- runbook への影響: イベント運用には無い。VP 運用では、`check-agent-skills.sh` が auto-memory を含む不可視文字で赤くなりうる。直し方は escape (`U+XXXX`) への書き換え。
- Hard Invariant と image (I5) に変更は無い。

## Signposts
1. Python と Go が実 file で 1 回でも食い違う (flag-guard の app tree の走査と `make test` の結果が割れる) → B に移る。
2. host と platform の runner の両方に Go が揃う → B を再評価する。
3. Unicode 版の WARN が Go の更新 1 回分を超えて続く、または So の版の差で case か実 file の判定が割れる → 非 ASCII の So 集合を 4 本目の data file に書き出す (Go の test が固定する)。Python の版は pin しない。
4. python3 を走らせられない消費者が現れる、または walker を Go の非 test コードに置く必要が出る → ADR-0043 Option 3 で切り出した後に B に移る。
5. 消費者だけが持つ binary 形式の追加が 2 つ目になる → その形式は app の `binary-ext.tsv` に足さず、消費者側の closed set (自リポの allowlist と同じ review) に移す。
   - 状態 (2026-10-30、app#542): 1 つ目 (`.pdf`) のまま。2 つ目は出ていない。`.pdf` の**置き場**は app の `binary-paths.tsv` に無く (app は tracked しない)、消費者が自リポの `--binary-paths` file に持つ。`.pdf` の拡張子と signature は app の `binary-ext.tsv` のまま。2 つ目の形式が出たら、拡張子と signature も消費者側に移す。

## Verification
- V1 (Go、`make test` = required check `test`、`internal/sourcehygiene/exported_table_test.go`):
  - (a) `TestExportedRanges_EqualGoTables`: header の 1 行目が `unicode.Version` と一致する。2 行目・3 行目の範囲は、全 rune について `isSkinTone` / `isVS` と一致する。行を双方向に照合し、`invisibleRanges` とは順序・lo・hi・name・rule の識別子が、`bidiControls` とは集合として一致する。file は印字可能な ASCII、TAB、LF だけ。比較の関数に、行を 1 つ落とした写し、rule を 1 つ変えた写し、header を変えた写しを与えると、それぞれ error になる。
  - (b) `TestExportedBinaryExt_EqualsBinaryExt`: `binary-ext.tsv` が `binaryExt` (キーと理由) と一致する。
  - (c) `TestHidden_SharedCases`: 全行で `Hidden` の結果が expected と一致する。全行で `Invisible` が「`Hidden` − bidi」と一致する。行数は 45 以上。4 つの文脈規則のそれぞれに、緑の行と赤の行が 1 つ以上ある。bidi の赤の行と、`{xHH}` を含む行も 1 つ以上ある。
  - (d) `TestSharedCaseReader_RejectsMalformed`: D1 (d) の不正な行が全部 error になる。
  - (e) `TestNonTestFiles_ArePredicateOnly`: package の非 test の `.go` file の集合が {chars.go, invisible.go} で、import が {fmt, sort, unicode, unicode/utf8} に含まれる。これが ADR-0043 Signpost 3 の機械の tripwire になる。
  - 追記 (2026-10-27、app#537、review-5x 88):
    - (b) は reason に加えて signature も `binaryExt` と比べる (`parseBinaryExt` が 3 列の書式を読む)。
    - (d) は「D1 (d) の行の否定例」= `TestSharedNegatives` の `reader-cases-*` と `reader-binext-*`、「file 単位 (CR・非 ASCII・final newline)」= `TestSharedCaseReader_RejectsMalformed` の 2 つに分かれた。
    - (f) `TestSharedNegatives` (`negatives_test.go`): `testdata/negatives/` の全 dir を `expect.txt` どおりに判定する (reader の拒否と受理、planted tree の exit と出力。tree の exit:1 は `out:` を 1 行以上持つ)。dir の file 構成が規則どおりでなければ error。件数が床 (実数。67。追記 2026-10-30、app#542: 107) 未満なら error。scanner の `--selftest` が同じ dir 群を同じに判定する。
    - (g) (追記 2026-10-30、app#542) `binary_paths_test.go`: `TestBinaryPaths_FileIsTheClosedSetAppShips` (file = Go の `appBinaryPaths` の 2 行で、`.pdf` の行が無く、ext が `binaryExt` にある)、`TestBinaryPathRow_Covers` (`*` は 1 segment、prefix は segment 単位、file は prefix の下)、`TestRealGate_RejectsABinaryOutsideTheClosedSet` (gate = `checkRealTree` に閉集合の外の `.pdf` / `.woff2` / `.tgz` を planted すると赤、内側は緑。gate が閉集合に繋がっていることを、forgery の無い実 tree の代わりに固定する)。
- V2 (app の required check `flag-guard`):
  - `--selftest` が次を全部確かめる。
    - cases の全行が一致すること。
    - V1-c と同じ被覆。
    - 3 本の data mutant がそれぞれ 1 行以上で食い違うこと (M1 = U+200D の行を落とす、M2 = U+FE0E-FE0F を `always` にする、M3 = bidi の行を落とす)。
    - reader の否定例が全部 FAIL になること。
    - walk の否定例が exit 1 になること (空の dir、生の U+200B、dead entry、NUL、非 ASCII の path)。
    - So + U+FE0F の file が exit 0 になること。
  - app tree の走査は exit 0。
  - 追記 (2026-10-27、app#537、review-5x 88): `--selftest` は `shared_negatives` (V1 (f) と同じ dir 群。件数が床 (実数) 以上) も判定する。`scripts/test-sourcehygiene-scan.sh` の mutant は、signature 検査を外す・signature を file の先頭でなくどこかで探す・拡張子を見ず signature だけで飛ばす・dotfile に拡張子を与える・binary-ext の昇順検査を外す・expect.txt の期待を書き換える (以上 6 本) と、negatives を床未満に削る case が、それぞれ意図した理由で赤になること。control は「negatives の数 = dir の数」を報告する。
  - 追記 (2026-10-30、app#542): `scripts/test-sourcehygiene-scan.sh` の mutant に、閉集合の検査を外す・`--binary-paths` を読んで捨てる・閉集合の外の binary を text としても走査する・prefix を segment でなく文字列で見る・file が prefix と同じ深さで通る・`*` が 1 segment でない・他の拡張子の行が覆う・`binary-ext.tsv` に無い ext の行を通す・行の順序を見ない・`..` の segment を通す (以上 10 本) と、path 規則を binary の拡張子の file で飛ばす (移した `walk-nonascii-path-of-a-woff2` で赤) が足された。それぞれ意図した共有否定例で赤になる。control は「app tree が `binary-paths.tsv` の下で 0 件」と「空の閉集合では赤 (app は `.woff2` を tracked する)」を報告する。flag-guard の app tree の走査は `--binary-paths internal/sourcehygiene/testdata/binary-paths.tsv` を渡す。
- V3 (platform、後続 PR。merge されるまで機械の確認は無い): `identity-selftest` で `check-source-hygiene.sh` の本体と `--selftest` を回す。
  - selftest は、一時コピーに U+200B / U+E0041 / U+202E / 文字の直後の U+FE0F / 単独の CR を入れると FAIL になることを確かめる。
  - So + U+FE0F は PASS。scanner が無い、0 件、dead な allowlist 行は FAIL。
- V4 (workspace、後続 PR): 一時 file を混ぜると `check-hidden-chars.sh --selftest` が exit 1 を観測する。`origin/main` に scanner が無いときと、ref が無いときも exit 1 になる。`check-agent-skills.sh` は wrapper の非ゼロで FAIL する。workspace に CI は無いので、PR 本文に出力を貼る。
- V5: セッションの開始時に workspace の検査が必ず走ることを確かめる機械は無い。hook 化は CEO 判断で、それまでは VP の運用規律である。

## Advice
- architect の設計 (2026-10-26、「#511 F2 — 不可視文字 rule を workspace / platform に展開する設計」)。VP が案 A を承認した。
- 本文での設計からの変更 (architect、2026-10-26。VP が 2026-10-26 に 7 点を承認した。architect の判定 = yes, if (条件 5 つ)):
  - rule の語彙を Go の識別子と `bidi` にした。
  - data file の書式を消費者の面から外し、app 単独で変えられるようにした。
  - `binary-ext.tsv` と `.pdf` を足した。
  - cases に `name` 列と `{xHH}` を足した。
  - ranges の header を 3 行にした (定数を Python に写さないため)。
  - `--also-untracked` を足した。
  - TestInvisible_Table の行を cases に移すことにした。
- security-engineer (#511 F2 の仕様): workspace と platform にも同じ規則を当てる。両リポとも今は U+26A0 U+FE0F 以外 0 件 (C4 で再実測した)。
- review-5x (app 実装 PR = #536、T3): R1 / R2 / R3 / R5 APPROVE with comments、R4 REQUEST CHANGES。採用した findings (契約行の現在形の訂正、scanner を security 必須 path に、path 規則の `$`、walk の fail-open、面の絞り込み、parity の主張の分離、workspace の pin) を同じ PR に反映した。
- review-5x (app 実装 PR = #541、T3、88 回目、2026-10-27): 5 観点 APPROVE with comments、BLOCKING / HIGH 0。採用した findings = signature は偽造でなく誤命名への対策であるという残余の記述 (R1 が受容を記録)、bundle の単位を `testdata/` 全体に (VP 承認)、Verification の追記、共有否定例の置き場の規則、plant path の 1 segment 制限、dotfile の拡張子の定義、拡張子なしの signature の否定例、floor を実数に。
