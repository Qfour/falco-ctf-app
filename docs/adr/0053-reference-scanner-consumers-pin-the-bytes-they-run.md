# ADR-0053: 参照 scanner の消費者は、実行する bytes を内容で固定する。workspace は scanner と、通常の走査が読む data 3 file の sha256 を自リポに pin し、一致しなければ実行しない。pin の更新は app の PR と対の PR にする (ADR-0045 の C9・D7・D4 と D8 の追記の 1 句・D8 の変更の規則の 1 句・Consequences の 1 文・順序 3 と、ADR-0051 D6 の workspace の 2 句を限定 supersede)
- Status: **Accepted** (2026-11-03。条件の充足: architect 合意と CTO 承認の記録 (private)、workspace の対の PR ws#146 の merge (`6770213…`) と security review APPROVE、V1 (app の harness、app#585)・V2 (消費者の selftest)・V3 (実装) が緑)
- Date / Deciders: 2026-11-03 / CTO (承認。読み替えを含む。記録 = private、ws#143 の決定ブロック 2026-11-03) + architect (起草・合意) + security-engineer (workspace の対の PR の R1)
- 関連: ws#143 (workspace の実装 issue)、ws#144 (同じ issue の先行 PR の review。契約に触れない部分だけを分けて merge した)、ws#117 (判定の private な記録)、ADR-0045 (C9・D7・D4 と D8 の追記・D8 の変更の規則・Consequences・順序)、ADR-0051 (D6)、platform の `APP_PIN` (`.github/workflows/ci.yaml`)、app#536 / #541 / #554 (scanner と data の導入と変更)、workspace の `REFACTORING.md` の決定事項 (git SHA を 1 箇所でピン)

## Context
(file:line は app origin/main fa32f40、platform origin/main 05f353d、workspace origin/main afa28e4 の版)
- C1. 消費者は scanner を実行する。
  - workspace の wrapper (`scripts/claude/check-hidden-chars.sh`) は、app の sibling clone の `refs/remotes/origin/main` から `git archive` で scanner と `testdata/` を一時 dir に取り出し、python3 で実行する (wrapper:131-179。ADR-0045 D7 = 0045:121-123)。運用者の手元の定常の検査がこれを自動で呼ぶ。
  - 実行される code を決めているのは、ローカルの追跡 ref が指す commit である。追跡 ref は、clone に書ける主体なら動かせるローカルの状態で、review を経た成果物ではない。
  - wrapper の ADR-0051 の祖先検査 (wrapper:150-152) は scanner の新しさを見るだけで、実行する bytes の出所は固定しない。
- C2. platform は内容で固定している。
  - CI の `identity-selftest` は app を `APP_PIN` (40 桁の commit SHA。ci.yaml:2160) で checkout し、その SHA が app の main の祖先であることを確かめる (:2175-2190)。commit SHA は内容の address なので、platform が実行する scanner の bytes は pin で決まる。pin の bump は対の PR (0045:141)。
  - 実行する bytes を固定していない消費者は workspace だけである。
- C3. ADR-0045 C9 (0045:32) は、workspace を pin しない理由を「deploy の契約ではなく手元の衛生検査なので、最新の規則を当てる」とした。これは**どの規則を当てるか** (新しさ) の理由で、**誰の bytes を実行するか** (完全性) は扱っていない。C9 は 2 つを 1 つの「pin しない」で決め、結果として完全性をローカルの ref に預けた。
- C4. 変更の頻度 (実測)。scanner と data 3 file の bytes を変えた app の commit は 3 本 (cf34518 = 10-26、80ef45f = 10-27、492af90 = 10-30)。その後 fa32f40 (11-01) までは 0 本 (492af90..fa32f40 の 4 file の diff は空)。`testdata/` 全体では 5 本で、差の大半は `testdata/negatives/` (今 252 file) の追加。
- C5. 通常の走査 (`<dir>`) が読む app の file は、scanner 自身と data 3 file だけである (scripts/sourcehygiene-scan.py:61-62、:78-81、:322-324)。`testdata/negatives/` を読むのは `--selftest` だけ。workspace の wrapper は scanner を通常の走査でだけ呼ぶ (wrapper:179、:199)。
- C6. 「workspace は pin しない」を前提にした文: ADR-0045 C9 (0045:32)、D7 (0045:122)、D4 の追記 (0045:108) と D8 の追記 (0045:133) の「bundle を部分コピーする消費者を作らない」、D8 の変更の規則 (0045:140)、Consequences (0045:156)、順序 3 (0045:164)。ADR-0051 D6 (0051:88、:92)。契約表 (`.claude/rules/falco-ctf-app-conventions.md:426`) の 3 か所。
- C7. workspace の `REFACTORING.md` の決定事項は「バージョン付きアーティファクト参照 (images + OCI チャート + git SHA を 1 箇所でピン)」(:17-18) で、deploy の契約の話である。その 1 か所は platform の `APP_PIN` である (C2)。
- C8. workspace に CI は無い。検査は手元で回し、PR 本文に出力を貼る (0045:201)。

## Options
1. **A: 内容の pin (content pin)。**
   - 変更点: workspace が、実行する scanner と通常の走査が読む data 3 file の sha256 を自リポの tracked file に pin し、その path だけを取り出して実行の前に照合し、一致しなければ実行せずに FAIL する。pin の更新は app の PR と対の PR。
   - コスト: 4 file の bytes を変える app の PR ごとに、workspace の小さな PR が 1 本 (C4: 導入期の 5 日で 3 本、その後の 4 日で 0 本)。同じ bytes の review がもう 1 回 (機械の一致確認と app 側の review の参照で軽くできるかは security-engineer の判断 (Consequences))。network・認証・新しい依存・image は足さない。
   - リスクと可逆性: app の merge から workspace の pin の merge までは workspace の検査が赤になる (fail-closed で、見える。D5 で同じ作業の中に収める)。可逆: pin の file と照合を外せば ADR-0045 C9 の形に戻る。
   - 効き始め: workspace の対の PR の merge から。消費者の側で実行する bytes が review した bytes と食い違いうる限り (= 検査を自動で回す限り) 効く。
2. **B: GitHub が答える main の SHA で取り出す (content addressing)。**
   - 変更点: 検査のたびに GitHub の API から app の main の commit SHA を引き、その SHA を `git archive` する (clone に無ければ取得する)。ローカルの追跡 ref は使わない。C9 はそのまま。
   - コスト: pin の bump も赤の期間も無い。代わりに、手元の検査が network と GitHub の API (認証か、未認証の rate limit) に依存し、offline では FAIL (fail-closed) になる。検査自身が外向きの通信と ref の取得をする。
   - リスクと可逆性: 信頼の起点が「GitHub が答える app の main」になる。app の main に入ったものは、消費者の側の review を経ずに運用者の手元で自動で実行される。完全性は app の merge の統制だけに乗る。可逆。
   - 派生 (B + 監視): 取り出した 4 file の sha256 を手元に記録し、変わったら知らせる。知らせるだけで止めない (完全性は B と同じ)。
   - 効き始め: A より良くなるのは、bump が頻繁なとき (Signpost 1) か、消費者が app の main に分単位で追随する必要があるとき。
3. **C: 今のまま (ローカルの追跡 ref を信頼の起点にし、その ref を動かせる主体を消費者の環境の側で絞る)。**
   - 変更点: なし。
   - コスト: 0。
   - リスクと可逆性: 完全性が、この契約の外にあり、app からも検査自身からも確かめられない消費者の環境の統制に乗る。clone に書ける主体が、実行される code を決められる。
   - 効き始め: 該当なし。
- 選択肢にしないもの: scanner や data を workspace に写すこと (0045:59 の「写しを作らない」)。

## Decision
A。消費者が実行する code を、自リポで review した成果物にでき (platform の `APP_PIN` と同じ「内容で固定し、対の PR で動かす」型)、しかも手元の検査に network と認証の依存を足さないため。

- **D1. C9 を新しさと完全性に分ける。**
  - 新しさ: workspace は今までどおり app の commit を pin しない。追跡 ref の指す commit から取り出し、使った app の SHA を毎回出力する。
  - 完全性: 取り出した bytes が pin と一致するときだけ実行する。一致しなければ、古い規則でも review していない規則でも実行せず FAIL にする。
  - C9 の「最新の規則を当てる」は「app の main の bytes が pin と一致する限り、その最新の規則を当てる。一致しなければ止まる」に読み替える。
- **D2. pin するもの: scanner と、通常の走査が読む data (今は 3 file。D4 の read set)。**
  - pin の file は workspace の tracked file で、行は `<sha256 の小文字 hex 64 桁><空白 2 つ><app の repo 相対 path>` (`shasum -a 256` の出力の形)。scanner の行は必須。header に digest を計算した app の commit を書く (情報。照合には使わない)。
  - pin の file の変更は、workspace の review の最上位の下限と security review にかける。gate を緑にするための手段にしない。
  - data も pin する。data は実行されないが判定を決める (行が落ちれば検出が黙って緩む)。
- **D3. 取り出しと実行。**
  - 取り出すのは pin に載った path だけ。毎回新しい一時 dir に取り出し、実行の直前に全行を照合する。pin の file が無い・0 行・scanner の行が無い・書式違い・行の重複・digest の不一致・取り出せない path・取り出した path が regular file でない (symlink や directory) は FAIL で、scanner は実行しない。
  - 追跡 ref は「どこから取り出すか」の場所でしかなく、信頼の起点にしない。ref が別の commit を指していても bytes が pin と一致すれば実行してよく、一致しなければ止まる。
  - interpreter は隔離のモード (**`python3 -I -S`**) で動かす。`-I` は呼び出し元の環境変数 (`PYTHON*`) と user site と script の dir を無視し、`-S` は interpreter 自身の site-packages (の `.pth` / `sitecustomize`) も読まない。scanner は標準ライブラリだけを使う。残るのは標準ライブラリと interpreter の install 自体で、これは python3 の binary と同じ信頼に乗る (pin の外)。
  - wrapper の ADR-0051 の祖先検査は、pin の更新のときに「pin の bytes が ADR-0051 以降の scanner であること」を確かめれば要らない。外すか、照合の前に移して「clone が古い」を先に案内する (workspace の実装の判断)。消費者の実装は「照合の前に移す」を採った (古い clone の利用者には、先に「取得し直す」が案内される)。
- **D4. 通常の走査が読む file の集合 (read set) を、消費者が読む面に足す。部分の取り出しを、この集合に限って許す。**
  - read set = `scripts/sourcehygiene-scan.py` と `internal/sourcehygiene/testdata/{hidden-ranges,hidden-cases,binary-ext}.tsv`。
  - 通常の走査が新しい file を読むようにする変更と、read set の file の移動・rename は面の変更である。pin する消費者の全部と対の PR にし、ADR を要する。
  - 「bundle を部分コピーする消費者を作らない」(0045:108、:133) に例外を 1 つ足す: 通常の走査だけをする消費者は、read set だけを、実行のたびに一時 dir に取り出してよい。その取り出しで `--selftest` を走らせない。自リポに残る写しを作らない。それ以外は従来どおり bundle (scanner + `testdata/` の全体) を単位にする。
  - 理由: pin した path だけを取り出せば、通常の走査が pin していない file を必須の読み込み (読めなければ FAIL する読み込み。scanner では `read_ascii`) で読み始めたとき、file が無くて FAIL する (黙って緩まない)。bundle を取り出して 4 file だけを照合すると、新しく読まれる file が照合の外で読まれうる。
  - 部分の取り出しが FAIL にするのは必須の読み込みだけである。任意の読み込み (存在を確かめてから読む、読めない例外を握りつぶす) を足す変更は、取り出した dir に file が無くても緑で通り、消費者の側だけが「file が無い」ときの振る舞いに黙って変わる。この種の読み込みが足されていないことは機械では固定せず、pin の更新 (D5 の対の PR) の review の点検項目にする: read set の bytes の diff に、read set の外の path を読む code が足されていないかを見る (訂正 2026-11-10、app#586)。
  - V1 が read set を、必須の読み込みについて app の側で機械で固定する。
- **D5. 変更の規則 (内容を固定する消費者が 2 つになった後の形)。**
  - read set の bytes を変える app の PR は、app 側の review の区分 (app 単独 + security / + ADR。0045 D8、0051 D6) は変えずに、workspace の pin の bump を**対の PR** として持つ。PR 本文で相互にリンクする。platform の `APP_PIN` の bump は従来どおり対の PR。
  - 順序: (1) app の PR を開く。(2) workspace の pin の PR を、app の PR の head の bytes から計算して開き、並行して review する。(3) app の PR を merge する。(4) merge commit の bytes が pin と一致することを確かめる (digest の再計算と、GitHub の blob の SHA との照合)。(5) workspace の PR を、(3) と同じ作業のうちに merge する。
  - 証跡: (2) の時点で workspace の pin の PR が貼るもの = app の PR の head から取り出した read set の bytes で走らせた消費者の selftest (V2) の結果と、その bytes から再計算した digest (pin file の行と一致すること)。(5) で貼るもの = app の merge の後に、消費者が通常の検査 (selftest ではない) を緑で通し、使った app の SHA を出力したこと。手順と式は、workspace 側の運用文書 (private な記録 ws#143 から辿る) と揃える。
  - app の PR が (2) の後に read set を変えたら、(2) を計算し直す (同じ path を触る app の PR は同時に 1 本なので、merge commit の bytes は head の bytes と一致する)。
  - 赤の期間 = (3) から (5) まで。上限 = 同じ作業の中 (24 時間以内)。超えたら Signpost 2 に数える。赤の期間中は workspace の他の PR の必須検査も赤になる (scanner を走らせる検査は fail-closed で止まる) ので、pin の PR を merge の queue の先頭に置き、他の PR は待つ。
  - 2 世代 (旧と新の両方の digest) を同時に受け入れる形は採らない。古い規則を受け入れ続ける窓と、旧 scanner と新 data のような review していない組み合わせを作るため (Signpost 2 で再訪)。
  - read set の外の app の変更 (`testdata/negatives/`、app 自身の allowlist と `binary-paths.tsv`、Go の test、harness) は workspace の対の PR を要しない。
  - ADR-0051 D6 の「pin しない workspace は、app の merge の前に自分の file を直す」(0051:92) は「workspace は、pin の bump の対の PR で自分の `--binary-paths` の file を同時に直す」(platform と同じ) に置き換える。ADR-0045 D8 (0045:140) と ADR-0051 D6 (0051:88) の「workspace は app の merge と同じセッションで追随する」は「workspace は pin の bump の対の PR で追随する」に置き換える。
- **D6. REFACTORING の「1 箇所でピン」との関係。**
  - deploy の契約の pin は今までどおり platform の `APP_PIN` の 1 か所である。
  - workspace の pin は deploy の契約ではなく、消費者が実行する code の完全性の pin で、workspace の中の 1 か所に置く。commit ではなく file の digest を固定し、`APP_PIN` の値を写さない。「1 箇所」は消費者と目的ごとに 1 つと読む。決定事項そのものは変えない。この読み替えは、workspace 側の対の PR で決定事項の置き場 (REFACTORING.md) に注記として残す。

## Consequences
- 諦めたもの:
  - B の「bump なしで app の main に即時に追随する」こと。workspace は read set の変更ごとに対の PR を持ち、D5 の (3) から (5) の間は赤になる。
  - review の手間の少なさ。同じ bytes を workspace でもう一度見る (機械の一致確認と app の review の参照で済ませてよいかは security-engineer の判断)。
- 残るもの:
  - 標準ライブラリと interpreter の install 自体は pin の外で、python3 の binary と同じ信頼に乗る (D3)。
- 新しく守るもの:
  - workspace は、pin に載っていない bytes の scanner と data を実行しない・読ませない (D2、D3)。
  - read set は面である (D4)。app が V1 で固定する。
  - read set の bytes を変える app の PR は、workspace の対の PR を持つ (D5)。
- 限定 supersede (元の ADR の本文は書き換えず、Status の直後に案内行を置く):
  - ADR-0045 C9 の「このため workspace には pin を適用せず、最新の規則を当てる (適用外。理由つき)」→ D1。「代わりに wrapper は、使った app の SHA を必ず出力する」は変わらない。
  - ADR-0045 D7 の 1 つ目の箇条 (scanner と testdata を取り出す) → D3 (pin の path だけを取り出し、照合してから実行する)。2 つ目以降 (worktree から取り出さない、走査の対象、呼び出し元) と追記は変わらない。
  - ADR-0045 D4 の追記 (0045:108) と D8 の追記 (0045:133) の「bundle を部分コピーする消費者を作らない」→ D4 の例外を足す。bundle の単位そのものは変わらない。
  - ADR-0045 D8 の読む面 → read set を足す (D4)。D8 の変更の規則の「workspace は app の merge と同じセッションで追随する」(0045:140) → D5。
  - ADR-0045 Consequences の「workspace は app を pin しない (C9)。…」の文 (0045:156) → D1 と D5。順序 3 (0045:164) → D5 の対の PR。
  - ADR-0051 D6 の workspace の 2 句 (0051:88、:92) → D5。ADR-0051 の Context と Options の記述 (0051:16、:18、:42) は当時の事実の記録なので書き換えない (案内行で足りる)。
  - 変わらないもの: ADR-0045 と ADR-0051 のそれ以外 (data の書式、CLI、終了コード、出力の接頭辞、allowlist と `--binary-paths` の書式、strict の既定、app 側の review の区分、platform の配線)。
- runbook への影響: イベント運用には無い。workspace の運用手順 (pin の bump の手順と、drift を反映する担当の点検項目) は workspace の文書に置く。
- 公開の境界: 消費者の環境の詳細は workspace の private な記録に置き、この ADR には書かない。
- Hard Invariant と image (I5) に変更は無い。

## Signposts
1. 対の PR の数: read set の bytes を変える app の PR が 30 日に 4 本を超える状態が 2 か月続く → B (または B + D2 の digest の照合) を再評価する。
2. 赤の期間: D5 の (3) から (5) が 24 時間を超えたことが 30 日に 2 回 → 2 世代の pin に移る (新しい digest を app の merge の前に足し、merge の後に旧を消す。受け入れは 4 行の組の単位で、file ごとに混ぜない)。
3. workspace の別の検査が、GitHub から引いた main の SHA を信頼の起点として既に持つ → network の依存を足すコストが消えるので、「GitHub の SHA で取り出し、D2 の pin で照合する」形を再評価する。
4. scanner を実行する消費者が 3 つ目になる、または read set の変更 (D4) が 1 四半期に 2 回を超える → 消費者ごとの digest をやめ、app が scanner の bundle の manifest (digest の表) を release ごとに公開し、消費者がそれを pin する形に移る。

## Verification
- V1 (app、required check の `flag-guard`、`scripts/test-sourcehygiene-scan.sh`): read set の 4 file だけを空の一時 dir に置き (repo 相対の path を保つ)、通常の走査を clean な fixture に当てると exit 0、生の U+200B を 1 つ入れた fixture に当てると exit 1。呼び出しの形は 3 つ: option なし、`--allowlist` と `--binary-paths` に fixture の中の最小の file を渡す形、`.git` を持つ fixture の git mode (追跡していない file は走査せずに exit 0、`--also-untracked` で足すとその file の U+200B で exit 1)。後の 2 つは消費者と同じ `python3 -I -S` で起動する。data 3 file のどれか 1 つを除くと exit 1 (3 case)。「通常の走査は read set だけで足りる」(D4) を機械で固定する。赤にするのは `read_ascii` による必須の読み込みを足す変更である (5 つ目の file をそう読む scanner の mutant が、4 file の copy で exit 1 になる)。任意の読み込み (存在を確かめてから読む・例外を握りつぶす) を足す変更はこの case では赤にならず、pin の更新の review の点検項目である (D4) (訂正 2026-11-10、app#586)。
- V2 (workspace、wrapper の `--selftest`。CI は無いので PR 本文に出力を貼る): (a) digest の違う scanner は実行されない。改ざんした stub が実行されたら作るはずの marker の file が無いことで観測する。(b) 照合を外す・照合を実行の後ろに移す・scanner の行の必須を外す・bundle の全体を取り出す・`-I` を外す・`-S` を外す (interpreter の site-packages の `.pth` が走る)、の mutant がそれぞれ赤になる。(c) selftest の各 case は、手元の clone の scanner を照合の前に実行しない (冒頭で pin と照合した bytes から selftest 専用の repo を作って使う)。
- V3 (workspace、毎回の検査): 使った app の SHA と、pin の header の app の commit を出力する。不一致の FAIL は「clone を取得し直す」と「pin を更新する」の両方の手当てを示す。
- D5 の対の PR の規則を app の側で機械で確かめる手段は無い (app から workspace は見えない)。違反は workspace の検査が赤になることで見える (fail-closed)。

## Advice
- architect (2026-11-03): A を推奨。B は運用費が最も低いが、信頼の起点を消費者の外 (GitHub の答えと app の merge の統制) に置き、手元の検査に network と認証を足す。C は完全性を契約の外に預ける。最小の案 (C) を採らない理由は規模ではなく、検査が自動で回る文脈で実行する code の出所が review の外に残ること。2 世代の pin は採らず Signpost 2 に置いた。部分の取り出しは、pin していない file が読まれる経路を残さない点で bundle の取り出しより強いので、read set を面にした上で例外として許す。判定 = yes, if (条件は private な記録 ws#143)。
- review-5x (ws#144、2026-11-03、T3): 契約の変更を workspace 側だけで行わず、対の app PR・ADR・architect 合意・CTO 承認で入れること、Options に A と B を並べること、Signposts に bump の頻度と赤の期間を置くことを求めた。契約に触れない部分は分けて先に merge した。
- security-engineer (2026-11-03、判定は private な記録 ws#117): 消費者が実行する scanner の bytes を消費者の tracked file に pin し、不一致なら実行しないことを求めた。A はこれに沿う。
