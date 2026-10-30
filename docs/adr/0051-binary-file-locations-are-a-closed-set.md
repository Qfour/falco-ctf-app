# ADR-0051: binary と判定した file の置き場を閉集合にし、閉集合の外の binary は FAIL にする。閉集合を渡さない走査は空の閉集合 (strict) とする (ADR-0045 の D4 の走査しない条件・D8 の面と変更の規則・残余を限定 supersede)
- Status: **Accepted** (2026-10-30。実装: app#554 = 492af90。review-5x 93 (T3) R1 APPROVE with comments、architect = R4 (yes, if、反映済み)。V1〜V4 緑 (否定例 108 dir、mutant 12、app tree 5 binary 0 problems)。V5 (消費者) は platform#294 / ws#92 の merge で確かめる)
- Date / Deciders: 2026-10-30 / VP + architect (起草) + security-engineer (R1)
- 関連: app#542 (issue)、app#554 (実装 PR)、ADR-0045 (D1 (c)・D4・D8・Consequences・Signpost 5・V1 (f))、app#537 (= #541、signature 検査と共有否定例)、review-5x 88 (#541) / 93 (#554)、platform#294 (platform の消費者。未実装)、ws#89 / ws#90 (= 62dbc6e、workspace の消費者。実装済み)、ws#92 (ws の follow-up issue。自リポの閉集合と `.claude/worktrees/*/`)、ADR-0043 Signpost 3 (sourcehygiene の非 test package は述語だけ)

## Context
(file:line は app origin/main 05199fa、platform origin/main ca0572a、workspace origin/main 62dbc6e の版。app#554 の作業 tree は動いているので、名前で参照する)
- C1. signature は誤命名への対策で、偽造に耐えない。
  - `binary-ext.tsv` の signature は `.pdf` = `255044462D` (`%PDF-`)、`.woff2` = `774F4632` (`wOF2`)、`.tgz` = `1F8B` (internal/sourcehygiene/testdata/binary-ext.tsv:1-3)。前の 2 つは印字可能な ASCII で、gzip は 2 byte。
  - ADR-0045 は「拡張子が表にあり、先頭が signature に一致する file は、本物でも偽造でも走査しない」を残余として受け入れた (0045:147。review-5x 88 R1 が受容を記録)。
  - app で偽造 `.pdf` を止めていたのは、Go の gate の tripwire「tracked の binary 拡張子 ⊆ {.woff2, .tgz}」だけだった (internal/sourcehygiene/bidi_test.go:328-338)。偽造 `.woff2` / `.tgz` は止まらない。
  - 参照 scanner には tripwire が無い。拡張子と signature が合えば、置き場を問わず走査しない (scripts/sourcehygiene-scan.py:777)。platform と workspace はこの scanner だけを当てる (ADR-0045 D6 / D7) ので、消費者の tree では偽造の `.pdf` / `.woff2` / `.tgz` がどこに置かれても素通りする。
- C2. app#554 の最初の形は、閉集合を opt-in にしていた。
  - `--binary-paths <file>` は任意の flag で、渡さなければ従来どおり、binary をどこでも信用する (review-5x 93 R4#4 / R1#1 / R2#2)。flag を渡すのは app の 2 つの gate (Go の gate と flag-guard の走査) だけだった。
  - workspace の消費者は ws#90 で merge 済みで、scanner を flag 無しで呼ぶ (scripts/claude/check-hidden-chars.sh:124)。workspace は app を pin せず、app の origin/main に追随する (ADR-0045 C9 = 0045:31)。
  - platform の消費者は未実装 (platform#294 は open。ca0572a に `scripts/check-source-hygiene.sh` は無い)。
  - したがって **pin する消費者は 0 件**で、既定の意味を変えて壊れる消費者が居ない。platform#294 の merge 後に既定を変えると、ADR-0045 D8 の「意味を変えるときは app と platform の同時 PR」(0045:136) に当たる。
- C3. Go だけにあった否定例と、規則の二重実装。
  - origin/main の `TestCheckTree_Invisible` (internal/sourcehygiene/invisible_test.go:310) には、Python 側に対の無い否定例が 5 件あった (review-5x 88 R4#3)。app#554 はこれを `testdata/negatives/` の共有 dir に移す。
  - walk と allowlist の規則は、Go の gate と Python の scanner の両方に足す必要がある。足した PR は #537 (#541) と #542 (#554) の 2 本になった (review-5x 93 R4#6)。
- C4. 今の binary (2026-10-30 実測)。
  - app: tracked は `internal/scoreboard/view/vendor/fonts/` の下の `.woff2` 5 file だけ (`git ls-files`)。`.tgz` は `helm dependency build` が書く untracked の `charts/*/charts/*.tgz` で、Docker の経路 (.git の無い walk) にだけ現れる (bidi_test.go:91-93)。`.pdf` は 0 件。
  - platform: `events/2026-06-pilot/decks/build/handbook/01-initial-recon.pdf` と `events/2026-06-pilot/decks/build/presentation/01-initial-recon.pdf` の 2 本 (ca0572a の `git ls-tree`。中身は開いていない)。
  - workspace: tracked の `.pdf` / `.woff2` / `.tgz` は 0 件。`.claude/worktrees/` は空。ただし wrapper は `.claude/` の下を `--also-untracked .claude` で全部走査し、そこに置いた checkout も意図的に対象にする (check-hidden-chars.sh:46-47)。app の checkout を置けば `.woff2` が 5 本入る。
- C5. 面と変更の規則。
  - ADR-0045 D8 は、scanner の CLI・終了コード・allowlist の書式・出力の接頭辞を消費者が読む面にし、data file の書式は面にしない (0045:124-128)。
  - ADR-0045 D4 は、scanner が data を自分の checkout からだけ読み、data の場所を引数で受けないと定める (0045:94)。
  - Accepted の ADR の決定は書き換えず、supersede する新 ADR で変える (docs/adr/README.md:82)。

## Options
1. **path の閉集合 (採用)**: binary と判定した file を、`<.ext><TAB><directory prefix>` の行の閉集合の下にあるときだけ走査しない。
   - 変更点: data 1 file (app の閉集合)、CLI の flag 1 つ、reader と閉集合の判定を Go と Python の両方に足す。閉集合の外の binary は problem にする。
   - コスト:
     - 二重実装が 1 つ増える (C3)。共有否定例は 67 から 108 件 (作業 tree の実数。移した 5 件を含む)、harness の mutant は 12 本増える。
     - 消費者は自リポの閉集合を 1 file 書いて渡す。新しい image・依存・toolchain は無い。
     - font や deck の中身を更新しても、置き場が同じなら行は変わらない。untracked の build 出力 (`.tgz`) も dir で覆える。
   - リスクと可逆性:
     - 閉集合の中の偽造は止まらない (font の dir に `wOF2` で始まる text を `*.woff2` と名付けて置く)。ただし置くには、閉集合の中に binary 拡張子の file を足す diff が要り、app では D4 の file 単位の固定が reviewed line にする。
     - 消費者が過大な閉集合 (`*/` のように repo の top-level の全 dir を覆う行) を書けば、効果は薄まる (Signpost 3)。
     - 可逆: 行は足せば広がる。既定 (D2) を緩めるのは意味の変更で ADR が要る (D6)。
   - 効き始め: app は merge と同時。workspace は merge 後の最初の検査 (pin しない)。platform は platform#294 と、APP_PIN を app#554 以降に上げたとき。
2. **tracked の binary file の sha256 の閉集合**: binary と判定した file を、`<sha256><TAB><path>` の行と内容が一致するときだけ走査しない。
   - 変更点: 行が file の内容を pin する。閉集合の中の偽造という残余も消える。
   - コスト:
     - font の更新・deck の再 build のたびに行を書き換える。platform の deck は build 出力なので、再 build が hash の更新になる。
     - untracked の build 出力 (`charts/*/charts/*.tgz`) は、helm の版や依存の解決で中身が変わりうる (仮説。実測していない) ので、hash を固定できない。Docker の経路の Go の gate には path で残すしかない。
     - hash の計算は Go (`crypto/sha256`) と Python (`hashlib`) の両方の標準ライブラリにあり、依存は増えない。
   - リスクと可逆性: 行の更新が日常の作業になると、hash の書き換えの diff はレビューで中身を見られない (hash を見ても font かどうかは分からない) ので、review は「更新が来た」ことしか確かめられない。可逆。
   - 効き始め: binary の更新がほぼ無く、全部 tracked のとき。今の app は `.tgz` が untracked なので、path との併用が前提になる。
- 選択肢にしないもの:
  - binary を形式として検証すること (PDF / WOFF2 / gzip を parse する)。参照 scanner は Python の標準ライブラリだけ (ADR-0045 D4) で、WOFF2 の展開は標準ライブラリに無い。
  - binary も text として走査すること。圧縮された byte 列に生の bidi の並びが偶然現れる (bidi_test.go:27-32) ので、偽陽性で gate が使えなくなる。

## Decision
1 に、app の binary の file 単位の固定 (D4) を足す。置き場は中身の更新でも untracked の build 出力でも変わらない安定した軸で、2 の利点 (新しい binary を reviewed line にする) は app については D4 が file 名の粒度で得るから。sha256 の併用は Signpost 1 で再訪する。

- **D1. 閉集合の data は `binary-paths.tsv` で、行は `<.ext><TAB><directory prefix>`。**
  - 意味: binary と判定した file (拡張子が `binary-ext.tsv` にあり、かつ先頭がその signature に一致する file。ADR-0045 D1 (c) と app#537 の追記) を置いてよい場所。
  - `<.ext>` は `binary-ext.tsv` にある小文字の拡張子 (`\.[a-z0-9]+`)。`binary-ext.tsv` に無い ext の行は FAIL (一致する file が永久に無い行だから)。
  - `<directory prefix>` は `/` で終わる segment の列。segment は `[A-Za-z0-9._+@-]+` の literal (`.` と `..` は不可) か、単独の `*` (ちょうど 1 つの空でない segment)。空の prefix、絶対 path、空の segment、`/` で終わらない prefix、部分 glob (`a*`) は FAIL。
  - file は prefix の下に任意の深さで置ける。prefix と同じ深さ (`fonts` という名前の file など) は覆わない。拡張子の違う行は覆わない。
  - 行は (ext, prefix) の昇順で、重複しない。file は印字可能な ASCII・TAB・LF だけで、最後は LF。CR と非 ASCII は FAIL。`# ` で始まる行・`#` だけの行・空行は comment。comment だけの file は「空の閉集合」で、最も厳しい。
  - app の file は `internal/sourcehygiene/testdata/binary-paths.tsv` の 2 行 (`.tgz` = `charts/*/charts/`、`.woff2` = `internal/scoreboard/view/vendor/fonts/`)。`.pdf` の行は持たない (app は PDF を tracked しない)。Go の test の `appBinaryPaths` が同じ 2 行を持ち、file と一致することを固定する (行の追加が Go と data の同じ diff になる)。
  - これは呼び出し側の方針 (allowlist と同じ種類) で、app の data ではない。ADR-0045 D4 の「data の場所を引数では受けない」(0045:94) は変わらない: 3 本の data は今までどおり自分の checkout から読み、`--binary-paths` は呼び出し側の方針 file を名指すだけ。app も自分の file を flag で明示的に渡す (flag-guard の走査)。Go の gate は file を直接読む。
- **D2. `--binary-paths` を渡さない走査は、空の閉集合 (strict) にする。**
  - binary と判定した file を 1 つでも持つ tree は FAIL。binary を持たない tree は影響を受けない。
  - 理由: 渡し忘れた消費者が、偽造への防御が無いことに気づけない既定 (fail-open) を作らない。WARN で知らせる案 (review-5x 93 R1#1 / R2#2) は、終了コードで判定する消費者 (ADR-0045 D8) には届かない。
  - これは ADR-0045 D8 の面 (`<dir>` の走査の意味) を狭める変更である。D8 は意味の変更を app と platform の同時 PR にしているが、今は pin する消費者が 0 件 (C2) なので、platform に同時に直すものが無い。platform 側の義務は platform#294 の受け入れ条件に載せる (D5)。workspace は binary が 0 件 (C4) なので緑のまま。**platform#294 の merge 後にこの既定を変えるときは、D6 の規則 (両リポ同時 PR) に従う。**
- **D3. 閉集合の外の binary は problem (exit 1) で、text としても走査しない。**
  - 偽造 signature の file を text として走査し直すと、`wOF2` の後に不可視文字を持たない偽造は緑になる。置き場で止めるので、中身を問わず赤にする。
  - finding の文言は安定を保証しない (ADR-0045 D8)。消費者は終了コードで判定する。
  - 閉集合の外の binary に allowlist の行を書いても、binary は走査しないので dead entry として FAIL になる (今と同じ)。
- **D4. app の binary は file 単位でも固定する。**
  - Go の test の `appBinaryFiles` が、app の gate が binary と判定した file を、`.woff2` の既知の 5 file (`internal/scoreboard/view/vendor/fonts/` の `chakrapetch-500` / `chakrapetch-600` / `chakrapetch-700` / `inter-var` / `jetbrainsmono-var`) と一致させる。`.tgz` は数に入れない (untracked の build 出力)。
  - git mode (`.git` のある checkout) では、tracked の `.tgz` を 0 件に固定する。Go の gate (`checkAppBinaryFiles`) は `.git` があれば見る。Docker の経路には `.git` が無いので、harness (`scripts/test-sourcehygiene-scan.sh`) が `git ls-files '*.tgz'` の空を確かめる。
  - 帰結: 閉集合の dir に binary を 1 本足す PR は、`internal/sourcehygiene/**` の reviewed line (= security 必須の path) になる。閉集合の中の偽造は、app では「新しい file 名を足す diff」が要る残余に縮む。
- **D5. 消費者は自リポの閉集合を `--binary-paths` で渡す。**
  - platform (platform#294。ADR-0045 D6 に足す): wrapper `scripts/check-source-hygiene.sh` は自リポの閉集合 file を `--binary-paths` で渡す。file が無ければ FAIL (scanner も、名前を付けた file が無ければ FAIL にする)。閉集合は deck の PDF 2 本の dir に限る (C4。`events/` のような浅い prefix にしない)。行の追加は自リポの allowlist と同じ security review。
  - workspace (ADR-0045 D7 に足す。ws#92): 今は binary 0 件なので flag 無し (= 空の閉集合) で緑。binary を tracked するか、`.claude/worktrees/` に checkout を置く運用を始める前に、自リポの閉集合 file を `--binary-paths` で渡すか、`.claude/worktrees/*/` を走査の対象から外すかを、その issue で決める (外すなら ADR-0045 D7 の「.claude/ の下を全部」を変える決定になる)。
  - 消費者の selftest は、閉集合の外に置いた signature 付きの binary が exit 1 になることを観測する (V5)。
  - 消費者 PR の review-5x は、flag が渡っていることと、閉集合が過大でないこと (prefix が binary の dir より浅くないこと) を確かめる。
- **D6. 面と変更の規則。**
  - 消費者が読む面 (ADR-0045 D8 に足す): `--binary-paths <file>` の CLI、その file の書式 (D1。消費者が書くので allowlist の書式と同じ扱い)、flag を渡さないときの既定 (D2)。
  - `binary-paths.tsv` の書式は、ADR-0045 D8 の「data file の書式は面にしない」(0045:128) の対象外。面にしないのは 3 本の data (`hidden-ranges.tsv` / `hidden-cases.tsv` / `binary-ext.tsv`) の書式だけ。
  - 変更の規則:
    - 書式の受理を広げる追加 (今ある file がすべて有効なまま、新しい書き方を受ける): app 単独 PR + security。消費者 PR は後続でよい。
    - 書式を狭める変更・既存の行の意味を変える変更 (`*` の深さ、prefix の照合の単位など) と、既定 (D2) を緩める変更: 新しい flag にするか、app と platform の同時 PR + ADR。workspace は app の merge と同じセッションで追随する。
    - app の `binary-paths.tsv` の行の追加 (app の閉集合を広げる = 偽造の置き場を足す): app 単独 PR + security。Go の `appBinaryPaths` と同じ diff で変える。行の削除 (狭める) も app 単独 PR + security。
    - app に binary file を足す: `appBinaryFiles` の行の追加。app 単独 PR + security。
    - `binary-ext.tsv` の行の追加: app 単独 PR + security (ADR-0045 D8 のまま)。
    - `binary-ext.tsv` の行の削除と signature の変更: その ext を書いた消費者の `--binary-paths` の file は ext の存在検査で FAIL になり、その形式の file は binary でなくなる。ADR を要し、消費者の対応を先にする。platform は pin するので、APP_PIN をその SHA に上げる対の PR で、自分の file の行と binary の扱いを同時に直す。pin しない workspace は、app の merge の前に自分の file を直す。
- **D7. 否定例の置き場 (ADR-0045 D4 の追記 (app#537) の「置き場の規則」を、閉集合にも当てる)。**
  - 両実装が持つ挙動の否定例は `internal/sourcehygiene/testdata/negatives/` に置く: reader の否定例 `reader-binpaths-*`、walk の否定例 `walk-binpaths-*`、strict の既定 `walk-binary-without-a-closed-set-is-refused`、残余の固定 `walk-binpaths-forged-woff2-inside-is-the-residual` (exit 0 を期待する。残余が閉じたらこの否定例の期待を変える diff が要る)。dir の `binary-paths.tsv` は、`plant.tsv` の横に置けば走査に渡す閉集合、単独なら reader の入力。
  - `plant.tsv` の path は 1 segment から clean な相対 path (`/` 区切り。空の segment と `.` / `..` を含まない) に広げる。閉集合の下の path を置くため。
  - Go だけに残すもの: `appBinaryPaths` / `appBinaryFiles` の固定、`TestBinaryPathRow_Covers` (判定関数の表)、`TestRealGate_RejectsABinaryOutsideTheClosedSet` (実 gate が閉集合に繋がっていること)、git mode の tracked `.tgz`。
  - harness だけに残すもの: CLI の経路 (flag の 2 回指定と値の欠落 = exit 2、名前を付けた file が無い・非 ASCII・CR = exit 1) と、app tree の binary の数。
  - 共有否定例の床は実数 (merge 時の dir の数) で、Go の `minNegatives` と Python の `MIN_NEGATIVES` に同じ値を書く (ADR-0045 V1 (f) の床の 67 を置き換える)。

## Consequences
- 諦めたもの:
  - 閉集合の中の偽造の検出。font の dir に `wOF2` で始まる text を `*.woff2` と名付けて置けば、Go と Python の両 gate を素通りする。app では D4 により新しい file 名の diff が要り、`internal/sourcehygiene/**` のレビューを通る。既存の 5 file の中身の差し替え (同じ名前のまま text にする) は D4 でも止まらない。消費者には D4 に当たる固定が無いので、残余は閉集合の dir 全体のまま。sha256 の併用で閉じる (Signpost 1)。
  - 消費者の手間の少なさ。binary を持つ tree は、flag を渡さなければ FAIL する。
  - 2 の内容の pin。中身の更新を検出しない。
- 新しく守るもの:
  - app の binary = `appBinaryFiles` (+ Docker の経路の untracked `.tgz`)、tracked の `.tgz` = 0 件 (D4)。
  - app の閉集合 = `appBinaryPaths` = `binary-paths.tsv` (D1)。
  - `--binary-paths` を渡さない走査は空の閉集合 (D2)。
- ADR-0045 から置き換えるもの (限定 supersede。ADR-0045 の本文は書き換えず、Status の直後に案内行を置く):
  - D4 の走査しない条件 (「拡張子が `binary-ext.tsv` にある file は走査しない」と、その app#537 の読み替え) に「置き場の閉集合の下にあるときだけ」を足す (D1 / D3)。
  - D8 の読む面と変更の規則に、D6 を足す。既定の意味の変更 (D2) は、D8 の「意味を変えるときは app と platform の同時 PR」を、pin する消費者が 0 件の今について満たしたものとして記録する。
  - Consequences の残余の 2 文 (「`TestTrackedFilesHoldNoRawBidiOrInvisibleCharacter` が「tracked の binary は `.woff2` と `.tgz` だけ」を固定する」と、app#537 の追記の「app で偽造 `.pdf` を止めるのは …、偽造 `.woff2` / `.tgz` は止まらない」)。tripwire は D4 の file 単位の固定に置き換わり、偽造は閉集合の外では 3 形式とも止まる。
  - Signpost 5 の処方 (Signpost 4 に書き直す)。
  - V1 (f) の床の実数 (D7)。
  - 変わらないもの: ADR-0045 の D1 (c) の書式、D4 のそれ以外 (data の場所を引数で受けない、walk の規則)、D8 の bundle の配置と 3 本の data の書式を面にしないこと、Signpost 1〜4。
- 順序:
  1. app#554 (Class-2。security R1。ADR-0051 と、ADR-0045 の案内行・関連・Advice、README の索引、契約表の行を同じ PR に)。
  2. ws#92 (ws の follow-up issue。いつでもよい。今は binary 0 件で緑)。`.claude/worktrees/` に app の checkout を置く運用を始めるのは、その issue が閉じてから。
  3. platform#294 (APP_PIN を app#554 の squash SHA 以降に上げる対の PR。`--binary-paths` を渡す)。flag を渡さなければ deck の PDF 2 本で FAIL する (fail-closed)。
- runbook への影響: イベント運用には無い。VP 運用では、app#554 の merge 後、`check-agent-skills.sh` (経由の `check-hidden-chars.sh`) が、binary を持つ checkout を `.claude/worktrees/` に置いたときに赤くなる。直し方は、checkout を scratchpad などの `.claude/` の外に置く (今の運用) か、ws#92 (ws の follow-up issue) の決定に従う。
- Hard Invariant と image (I5) に変更は無い。

## Signposts
1. 閉集合の中の偽造が 1 件でも見つかる (review・incident)、または app の font と platform の deck の更新が直近 6 か月で 0 回 (sha256 の行を書き換える費用が実質 0) → tracked の binary について sha256 の閉集合を path と併用する (2 を新しい flag として足す。untracked の `.tgz` は path のまま)。
2. walk / allowlist の規則を Go と Python の両方に足す PR が 3 本目になる (#537、#554 に続く) → walk を参照 scanner 1 本 (flag-guard は required check) に寄せ、Go は述語と data の固定だけにする案を、ADR-0045 の B と並べて ADR で比較する。
3. 消費者の閉集合が過大になる: 先頭の segment が `*` の行 (`*/` など) が消費者の file に入る、または prefix が binary の dir より浅いことを review-5x が 2 回指摘する → 書式を狭める (先頭の segment を literal に限る、など)。platform#294 の merge 後なら D6 により新しい flag か両リポ同時 PR。
4. (ADR-0045 Signpost 5 の書き直し) 消費者だけが持つ binary 形式の追加が 2 つ目になる (1 つ目は `.pdf`) → その形式の拡張子と signature を消費者側に移す。移すには新しい CLI の面 (消費者が自分の拡張子と signature を渡す flag。ADR-0045 D4 の「data の場所を引数では受けない」の例外になるので ADR が要る) と、`--binary-paths` の ext の存在検査を「app の `binary-ext.tsv` ∪ 消費者の表」に対して行う変更が要る。`.pdf` の置き場は、今すでに消費者の閉集合にある (app の file に `.pdf` の行は無い)。

## Verification
- V1 (Go、`make test` = required check `test`):
  - `TestBinaryPaths_FileIsTheClosedSetAppShips`: `binary-paths.tsv` = `appBinaryPaths` の 2 行。`.pdf` の行が無い。ext がすべて `binaryExt` にある。
  - `TestBinaryPathRow_Covers`: `*` はちょうど 1 segment、prefix は segment 単位、file は prefix の下 (同じ深さは覆わない)。
  - `TestRealGate_RejectsABinaryOutsideTheClosedSet`: 実 gate (`checkRealTree`) に閉集合の外の `.pdf` / `.woff2` / `.tgz` を置くと赤、内側は緑。
  - `TestTrackedFilesHoldNoRawBidiOrInvisibleCharacter` (`checkAppBinaryFiles`): binary と判定した file = `appBinaryFiles` (+ `.tgz`)。`.git` があれば tracked の `.tgz` は error。
  - `TestSharedNegatives`: `testdata/negatives/` の全 dir を判定し、件数が床 (D7) 未満なら error。
- V2 (Python、`--selftest`、required check `flag-guard`): V1 の `TestSharedNegatives` と同じ dir 群を同じに判定する。`walk-binary-without-a-closed-set-is-refused` (strict の既定) と `walk-binpaths-forged-woff2-inside-is-the-residual` (残余) を含む。
- V3 (harness、`scripts/test-sourcehygiene-scan.sh --selftest`、`flag-guard`):
  - mutant がそれぞれ意図した共有否定例で赤になる: 閉集合の検査を外す、既定で信用する (`binary-paths-default-trusts`)、flag を読んで捨てる、外の binary を text として走査する、prefix を文字列で見る、prefix と同じ深さを通す、`*` を任意の深さにする、拡張子を見ない、`binary-ext.tsv` に無い ext を通す、行の順序を見ない、`..` を通す、path の規則を binary の拡張子で飛ばす。
  - CLI の経路: flag の 2 回指定と値の欠落は exit 2。名前を付けた file が無い・非 ASCII・CR は exit 1。
  - git mode: `git ls-files '*.tgz'` が空。app tree の走査が「5 binary、0 problems」。
- V4 (app tree、`flag-guard`): app tree の走査が `--binary-paths internal/sourcehygiene/testdata/binary-paths.tsv` を渡して exit 0。
- V5 (消費者、後続 PR。merge されるまで機械の確認は無い):
  - platform#294: selftest が、閉集合の外に置いた signature 付きの binary で exit 1、名前を付けた閉集合 file が無いときに FAIL、flag を渡さない走査が自リポの tree で exit 1 (PDF 2 本がある)、渡せば exit 0 を観測する。platform の Actions が課金ホールドの間は、PR 本文に手元の出力を貼る。
  - ws#92 の follow-up: selftest が、閉集合の外の signature 付きの binary で exit 1 を観測する。workspace に CI は無いので、PR 本文に出力を貼る。
- V6: 消費者の閉集合が過大でないことを確かめる機械は無い。消費者 PR の review-5x と security review が見る (D5)。このため本 ADR の D5 の「過大でない」は Hard Invariant に昇格させない。

## Advice
- review-5x 93 (app#554、T3、2026-10-30): R1 / R2 / R3 / R5 APPROVE with comments、R4 (architect) REQUEST CHANGES (HIGH 1 は検証で MED に)。要旨:
  - R1 (security): 閉集合が opt-in だと消費者が #542 以前の残余を引き継ぐ (D6 / D7 / V3 / V4 に flag の要件が無い) → D2 / D5 / V5。dir 単位の閉集合は dir の中の新しい binary を素通りさせる → D4。
  - R2: flag の 2 回指定の exit 2 と、CLI の経路の非 ASCII / CR の FAIL にテストが無い → V3。flag 無しの fail-open が表示されない → D2 (strict) により WARN は不要とした。
  - R3: ADR-0045 の Signpost 5 の追記の indent → ADR-0045 の追記を取り消したので解消。
  - R4 (architect): Accepted の ADR-0045 の D8 本文の書き換え (#1)、#542 は新しい決定で README の例外に当たらない (#2)、`--binary-paths` の書式を面にし、`binary-ext.tsv` の行の削除の結合を変更規則に (#3)、既定は platform#294 の merge 前に決める (#4)、存在しない「D1 (f)」の参照 (#5)、二重実装を見る Signpost (#6)。判定 = yes, if (この ADR で #1〜#4 と #6 を満たすこと)。
  - R5: 消費者の DoD に flag を渡すことを明記する (#1) → D5。`MIN_NEGATIVES` の床が Go と Python で conflict しうる (#2) → WIP ポリシー (同じ file を触る PR は 1 本) で直列化する。今回は決めない。
- VP 決定 (2026-10-30): R4#1 = ADR-0045 の本文の書き換えを取り消す。R4#2 = (a) 新 ADR (本 ADR) で限定 supersede し、ADR-0045 には案内行・関連・Advice の 1 項目だけを置く。R4#3 = 書式は allowlist と同じ扱いの面 (D6)。R4#4 = 既定を strict に (D2)。R1#1 = D5 / V5。R1#2 = D4 (software が実装)。R4#6 = Signpost 2。
- architect (2026-10-30): 1 + D4 を推奨。2 (sha256) は untracked の `.tgz` と deck の再 build に向かず、単独では採れないが、path との併用は Signpost 1 の信号で再訪する。D2 は、pin する消費者が 0 件の今だけ app 単独で意味を変えられる (platform#294 の後は両リポ同時 PR)。
