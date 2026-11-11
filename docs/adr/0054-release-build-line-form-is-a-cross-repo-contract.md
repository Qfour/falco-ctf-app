# ADR-0054: release の build が読む Makefile の build 行の形と、`-f` / context の path の規則をクロスリポ契約にする。規則は app に 1 つ (本 ADR・契約表の行・共有 case 表) 置き、app の `make test` と platform の test が同じ表で確かめる。規則から外れた Makefile では、platform の release は 1 つの image も build しない
- Status: **Proposed** (2026-11-10 起草)。Accepted の条件 = (1) 本 ADR の app の PR (契約表の行・V1・共有 case 表) の merge、(2) platform の対の PR (platform#318 PR-B2 の B2-5) の merge と、その `APP_PIN` が (1) の merge commit 以後であること、(3) V1 と V2 が緑、(4) security-engineer の R1 の APPROVE、(5) CTO の承認の記録 (private)
- Date / Deciders: 2026-11-10 / CTO (承認。経過措置中は CoS 代行) + architect (起草・合意) + security-engineer (R1。release の build の経路)
- 関連: platform#318 (PR-B2。設計 D6 (a) = `rs_build_args_checked`、D9 の architect 判定 = yes, if)、platform#314 (review-5x 2 巡目 R1#1)、app#512 (`IMAGES :=` の 1 行の契約と `internal/contracttable` の test。ADR-WS-0010 D8)、ADR-0042 / ADR-0047 (文法は app に 1 つ、platform は共有 case 表を読む先例)、ADR-0053 (platform は `APP_PIN` で app の bytes を固定する)、Hard Invariant I5

## Context
(file:line の版 = app origin/main `8727db2623377d6b1666ba974fd49b2d726565be` (app#512 の merge の後)。platform は C1 の「今の形」= origin/main `8742499` の `scripts/lib/release-scan.sh` / `scripts/release-images.sh` / `.github/workflows/ci.yaml` を実物で照合した。B2-5a の head `67df2f742df7f5eb2be87eb3a2e3b5637f405a18` では、C1 の `rs_build_args` (`head -1`) が `rs_build_args_checked` に置き換わる: `release-scan.sh` の `RS_PATH_RE` `:81`、`RS_BUILD_LINE_RE` `:82`、`rs_build_path_ok` `:101-106`、`rs_build_lines_ok` `:107-130`、`rs_build_args_checked` `:142-170`、`release-images.sh` の引数の解決 `:79-85` と build `:91`、`ci.yaml` の `APP_PIN` `:2166` と祖先の検査 `:2193`)
- C1. platform の release の手順は、app の `Makefile` から image 集合と build の引数を導く (写しを持たない)。
  - image 集合 = `IMAGES :=` の 1 行 (platform `scripts/lib/release-scan.sh:53-68`)。
  - build の引数 = image ごとに、`docker build -t $(REGISTRY)/<name>:$(TAG) -f <Dockerfile> <context>` の行から `<Dockerfile>` と `<context>` を抜く (`release-scan.sh:70-77`)。抜き方は「最初に一致した 1 行」(`head -1`) で、2 つの値の形は検査しない。
  - `scripts/release-images.sh` は、全 image の引数を build の前に解決し (`:49-55`)、app の clone の top で `docker build --no-cache --platform <RS_PLATFORM> -t … -f "<Dockerfile>" "<context>"` を回す (`:61`)。`--no-cache` と `--platform` は platform が付ける。Makefile の行の `-t` の値と、行に書いたほかの引数は release に渡らない。
- C2. したがって Makefile の build 行の 2 つの値は、release を build する手元で、どの file を build context として docker daemon に送るかを決める。今の形 (検査なし) では、絶対 path・`..`・symlink を書いた Makefile が merge されると、app の clone の外の file が context に入る (platform#314 の review-5x 2 巡目 R1#1)。
- C3. platform は platform#318 (PR-B2 の B2-5) で、2 つの値が規則に合わなければ 1 つの image も build せずに止める検査 (`rs_build_args_checked`) を足す。これで「Makefile の build 行の形」は、app の変更が platform の release を止めうる面 = クロスリポ契約になる。今の契約表には、この面の行が無い。
- C4. 今の Makefile は規則に合う (`Makefile:70-79`)。
  - build 行は 8 行。context は `.` が 6 本、`images/ttyd` と `images/detect-grader` が 1 本ずつ。`-f` はどれも context の内側。
  - 8 本の Dockerfile はどれも、追跡された mode `100644` の blob (`git ls-tree`)。追跡された symlink は 0 本。
- C5. 隣の契約。
  - app#512 (2026-11-11 merge、main `8727db2623377d6b1666ba974fd49b2d726565be`) は、`IMAGES :=` の 1 行の形を契約表の「Image naming」行に書き、`internal/contracttable` の Go の test (`MakefileImages`、`TestMakefileIMAGES_IsTheI5SetInTheFormPlatformReads`) で固定する。
  - `internal/contracttable` は main に在り (`Path`・`Rows`・`RowWhere`)、契約表を読む test (`internal/contractmetrics`、`internal/collector`) が使っている。
  - `.dockerignore` は `.git` を context から外す (`:6`)。契約表は context に入る (`:8-18`)。
- C6. 先例。文法を app に 1 つ置き、platform は共有 case 表を `APP_PIN` の版で読む (seat の文法 = ADR-0042、roster の正規化、DNS 名 = ADR-0047。platform `ci.yaml:2149-2160`)。
- C7. I5 (全 8 image を同一 SHA) との関係。platform は app の clone の HEAD が `--tag` と一致することを確かめ (`release-images.sh:43-44`)、全 image を同じ `--tag` で build する (`:61`)。本 ADR は image の数も SHA も変えない。
- C8. 本 ADR が扱わないもの (Makefile の文面では決まらない、platform の実行環境の検査):
  - app の clone の物理 path と所有者、context の中の untracked / ignored の file、docker の endpoint、build する VM の mount、release の commit の署名。
  - これらの正典は platform#318 の設計と platform の運用文書である。

## Options
1. **A: build 行の文面を契約にし、規則を app に 1 つ置いて、両リポの test が同じ表で確かめる。**
   - 変更点: 契約表に 1 行、`internal/contracttable` に build 行の読み取りと test、共有 case 表 `internal/contracttable/testdata/build-path-cases.tsv` を足す。Makefile は変えない。platform の検査は、同じ表を読む test で固定する。
   - コスト: app = Go の file 2 本と表 1 本 (`make test` に相乗り。新しい依存・CI の job・image は無い)。platform = parity の test 1 本と `APP_PIN` の bump。build 行の形・規則・表を変えるたびに、両リポ同時 PR になる。
   - リスクと可逆性: 規則は make の文法のごく一部を正規式で読むだけなので、make の書き方 (変数・`$(foreach)`・継続行) で build 行を作り直す自由を失う。可逆 (B へは supersede で移れ、path の規則と表はそのまま使える)。
   - 効き始め: app の PR の merge から。Makefile の変更が platform の release を止める前に、app の PR の時点で赤になる。
2. **B: 宣言の file (例 `images/release-build.tsv` = name・Dockerfile・context) を 1 つ置き、Makefile の `build` と platform の両方がそれを読む。**
   - 変更点: Makefile の `build` を表の loop にし、platform は make の文面でなく表を読む。`IMAGES :=` の契約 (app#512) も表へ移す。
   - コスト: 面が 1 つ増える (表の書式)。`IMAGES :=` の契約と build 行の契約を同時に supersede する。platform の読み手 (`rs_expected_images` / `rs_build_args`) を書き直す。
   - リスクと可逆性: make の文面を正規式で読む必要が無くなる。代わりに「`make build` が表をどう展開するか」と「platform が表をどう読むか」が別の実装になる。可逆。
   - 効き始め: build に引数を要する image が出たとき、または build の行を生成したくなったとき (Signpost 1・2)。
3. **C: 契約表の行と本 ADR だけ (app の機械検査なし)。**
   - 変更点: 契約表に 1 行。
   - コスト: 最小。
   - リスクと可逆性: 違反は platform の release の時点 (イベントの前の手元) で初めて見える。fail-closed なので安全側だが、見つかる時点が最も遅く、直すのは別のリポの PR になる。
   - 効き始め: なし。
- 選択肢にしないもの: platform が Dockerfile と context の写しを持つ形。`release-scan.sh:70-71` の「写しを持たない」に反し、写しの drift が新しい面になる。

## Decision
**A**。今の正典 (Makefile の `build`) と、platform が読む `IMAGES :=` の契約 (app#512) を動かさずに、release を止めうる面を明文化して PR の時点で赤にできるため。path の規則と共有 case 表は、後で B に移っても同じものを使える。B を今採らない理由は規模ではなく、release の経路にある 2 つの契約を、platform の読み手を固める PR と同時に supersede することになるため。

- **D1. build 行の形 (契約)。**
  - `IMAGES :=` の各 name について、`Makefile` の全体で次の形の行がちょうど 1 行ある。`IMAGES :=` に無い name について、この形の行は無い。
    `<空白 1 つ以上>docker build -t $(REGISTRY)/<name>:$(TAG)<空白 1 つ以上>-f<空白 1 つ以上><Dockerfile><空白 1 つ以上><context><行末までの空白>`
  - `docker`・`build`・`-t`・`$(REGISTRY)/<name>:$(TAG)` の間は空白 1 つ。行にほかの引数を置かない。
  - release の build に渡るのは `<Dockerfile>` と `<context>` だけである。`-t` の値と、`build` の他の行 (`$(MAKE) check-image-hygiene` など) は release に効かない。
- **D2. `<Dockerfile>` と `<context>` の規則 (契約)。**
  - 文字の集合と先頭 = `^[A-Za-z0-9._][A-Za-z0-9._/-]*$`。先頭の `/`、`$`、`~`、空白、引用符を含まない。
  - `/` で分けた要素に、`..` と空の要素 (`//` や末尾の `/`) を持たない。要素 `.` は、context が `.` そのものである場合だけ許す (`./x` や `x/./y` は不可)。= 正規形にするので、「内側か」の判定は文字列で決まる。
  - context は `.` か、追跡された directory。Dockerfile は追跡された通常の file (mode `100644`)。context が `.` であるか、Dockerfile が `<context>/` で始まる。
  - path のどの要素も symlink でない。
  - **1 つの image の行でも D1・D2 から外れたら、platform の release は 1 つの image も build しない** (fail-closed)。
- **D3. 規則の定義は app に 1 つ。**
  - 正典 = 本 ADR の D1・D2、契約表の行 (「release build の build 行」)、共有 case 表 `internal/contracttable/testdata/build-path-cases.tsv`。
  - 表の書式 = 1 行目は header `dockerfile<TAB>context<TAB>verdict`。以降は 1 行 1 case で、verdict は `OK` か `REJECT`。
  - 追跡や symlink の性質 (file system の状態) は表に書けない。表は文字列の規則 (D2 の 1〜2 つ目と「内側」) だけを持ち、file system の規則は両リポの test がそれぞれ fixture で確かめる。
  - platform の検査 (`rs_build_args_checked`) は、表の全行で app の Go の判定と同じ答えを出す (V2)。platform は表を写さず、`APP_PIN` の版の sibling の app clone から読む。
- **D4. app の機械検査 = `internal/contracttable` の Go の test (`make test` = required check の `test`)。**
  - 実際の Makefile について、D1 (行の数・形・`IMAGES :=` との双方向の一致) を確かめる。
  - D2 は、表と同じ判定関数で確かめる。あわせて test の build context の中で、Dockerfile が通常の file で実行 bit を持たないこと、context が directory であること、どの要素も symlink でないことを確かめる。読めた行が 0 本なら FAIL。
  - `IMAGES :=` の読み取りは app#512 の `MakefileImages` を使う (読み手を 2 つにしない)。
  - 契約表に本行が在り、`build-path-cases.tsv` と `release-scan.sh` を名指していることを確かめる (行を消す PR を赤にする。app#512 の Image naming 行の検査と同じ型)。
  - `scripts/check-*.sh` の形は採らない。Makefile の読み手が shell と Go の 2 つになり、required の check にするには CI の配線が要るため。
  - 追跡されているかの判定 (git) は、Go の test では見ない。test の build context に `.git` が無いため (`.dockerignore:6`)。CI は commit を checkout した木で回るので、在る file は追跡された file だという前提で足りる (前提。追跡の最終の判定は platform の実行時の検査)。
- **D5. 変更の規則。**
  - D1・D2 の規則、表の path と書式、本行を変える PR は両リポ同時にし、相互にリンクする。ADR を要する。
  - build に引数 (`--build-arg`・`--target`・`--secret`・`--build-context` など) を要する image を足す・変える PR も両リポ同時にする (release は行のほかの引数を使わない: C1)。あわせて B を検討する (Signpost 1)。
  - 規則の中で Dockerfile や context を変える PR (例: image の dir を移す) は app 単独でよい。ただし release の context の中身が変わるので、Dockerfile の変更と同じく security-engineer の review (既存の規則) に乗る。
  - image を足す・消す PR は I5 の変更 (既存の規則) であり、`IMAGES :=` と build 行を同じ PR で直す。
- **D6. 最初の導入の順序 (両リポ同時 PR)。**
  - (0) 本 ADR の app の PR は app#512 の merge (2026-11-11) の後に開いた (同じ conventions の file を触り、`MakefileImages` を使うため)。
  - (1) app の PR と platform の PR (B2-5) を開き、本文で相互にリンクする。
  - (2) 並行して review する。
  - (3) app の PR を先に merge する。追加だけなので、platform の main の読み手は変わらない。
  - (4) platform の PR の `APP_PIN` を (3) の merge commit に上げる (app の main の祖先であることは platform の CI が確かめる: `ci.yaml:2154`)。V2 が緑になってから merge する。
  - (3) と (4) の間に赤は出ない (platform の main はまだ表を読まない)。

## Consequences
- 諦めたもの: Makefile の `build` を make の変数・`$(foreach)`・継続行で書き直す自由 (書き直すなら B へ supersede する)。release の build に image ごとの引数を渡すこと。
- 新しく守るもの: D1・D2 (V1 が app の PR の時点で、platform の検査が release の時点で止める)。共有 case 表は面である (path と書式)。
- 運用への影響: release に使う app の clone は、D2 の file system の規則も満たす必要がある (symlink や追跡していない file を置かない)。clone の状態の検査と手順は platform が持つ (C8)。
- 公開の境界: release を build する環境の詳細は platform の private な文書に置き、本 ADR には書かない。
- Hard Invariant と image (I5) に変更は無い。新しい依存・CI の job・image も無い。

## Signposts
1. build に引数を要する image が 1 つでも要る、または 1 つの image に Dockerfile が 2 つ要る → B (宣言の file) を ADR で開く。
2. app が build の行を make で生成したい (path に変数・`$(foreach)`) という PR が出る → B。
3. app の V1 が緑のまま、platform の検査が release を止めたことが 1 回 (2 つの実装の判定が食い違った) → platform が app の持つ抽出の script を `APP_PIN` の bytes で実行する形 (ADR-0053 の型。実装を 1 つにする) を再評価する。
4. build 行を読む 3 つ目の消費者 (例: CI の build matrix を Makefile から導く) が出る → B。

## Verification
- V1 (app、`make test` = required の `test`)。`internal/contracttable` の test で次を確かめる。
  - (a) 実際の Makefile: `IMAGES :=` の各 name に D1 の行がちょうど 1 行あり、`IMAGES :=` に無い name の行は 0。読めた行の数 = `IMAGES` の数 (1 以上)。各行の 2 つの値が D2 の判定関数で OK。test の build context の中で、Dockerfile は通常の file で実行 bit なし、context は directory、どの要素にも symlink が無い。
  - (b) 共有 case 表: 全行を Go の判定関数にかけて verdict と一致すること。OK と REJECT の両方を含み、行数が下限 (起草の案 = 20) 以上であること。表が無い・header が違う・列数が違う行は FAIL。REJECT の case には最低限次を入れる: 絶対 path、`..` の要素、`$(X)`、`~`、空白、`./x`、`x//y`、末尾の `/`、context の外の Dockerfile、context が `x` で Dockerfile が `xy/Dockerfile` (接頭辞の誤判定)。
  - (c) D1 の形の負の case (Go の表): `-f` の前に引数を足した行、行末に引数を足した行、同じ name の 2 行目、`IMAGES` に無い name の行、`IMAGES` の name の行が無いこと、path に `$(VAR)`。
  - (d) file system の負の case (一時 dir の fixture): symlink の Dockerfile、symlink の要素を持つ context、実行 bit 付きの Dockerfile、directory の Dockerfile。
  - (e) 契約表に本行が在り、`build-path-cases.tsv` と `release-scan.sh` を含むこと。
  - (f) 判定関数から規則を 1 つずつ外した mutant が、(b) か (c) で赤になること (test の中に恒久化する)。
- V2 (platform、CI、platform#318 B2-5)。
  - `rs_build_args_checked` を共有 case 表の全行にかけ、verdict が一致すること。
  - 表は `APP_PIN` の版の sibling の app clone から読む。表が無い・空・行数が下限未満なら FAIL (SKIP にしない)。
  - `APP_PIN` の版の実際の Makefile で、全 image が通ること。
  - 違反の case では、1 つの build も起きないこと (stub の呼び出しの記録で確かめる)。
- 両リポの PR の順序 (D6) を機械で確かめる手段は無い。食い違いは V2 の赤として見える (fail-closed)。

## Advice
- architect (2026-11-10、platform#318 の設計): D9 の判定 = yes, if。条件は (1) 契約表に 1 行、(2) 両リポ同時 PR と相互リンク、(3) Makefile は今の main のまま (`Makefile:70-77`) で、変えるのは platform 側の検査だけ、(4) CTO が承認し security-engineer が合意する (build の経路)。本 ADR は (1)(2)(3) を D3・D6 と V1 で満たし、(4) を Accepted の条件にした。起草で足した点は 3 つ: 規則を正規形にした (D2 の 2 つ目。platform の検査も同じ規則にする)、「Makefile の全体でちょうど 1 行」(今の platform の読み手は最初の 1 行だけを読み、2 行目以降は黙って捨てる)、共有 case 表 (先例 ADR-0042 / 0047)。
- CoS (CTO 代行、2026-11-10): 分割 11 本と順序を承認した。D9 の契約の行は B2-5 で CTO 代行が承認し、両リポ同時 PR にする。本 ADR の起草は B2-5 の前に architect に委ねた。
- security-engineer: 未受領 (app の PR の R1 で取る)。
