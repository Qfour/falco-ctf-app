# ADR-0036: apk の exact pin は「版が振る舞いに効く package」と「base に入っている package を引き上げる一時的な pin」だけに使い、それ以外は版を書かない。全 Dockerfile の pin を毎日 index と突き合わせ、赤で Issue を起こす (ADR-0002 の pin 戦略と Signpost 4 を置き換える)

- Status: **Proposed** (2026-10-17 起草)。**Accepted 化は CEO が行う** (pin の方針は本番の image = challenge・ttyd・docs・detect-grader の中身に効く)。その前に security-engineer の同意を取る (版を書かない package が増える。#228 の HIGH との関係は C7)。実装 PR は Proposed のまま始めてよく、merge は Accepted の後 (workspace `ORGANIZATION.md:470-472`)。
- Date / Deciders: 2026-10-17 / CEO (承認) + VP (発注。#382 の暫定判断) + architect (起草) + security-engineer (同意) / 実装: software-engineer (checker・CI・Dockerfile)、sre-engineer (platform の release 手順)
- Supersedes: ADR-0002 の pin 戦略の部分 — Signpost 4 (`0002:135-136`)、Context の exact pin の前提 (`0002:37-41`)、cycle の同点決着の理由づけ「apk exact pin の再解決コストは bump 毎に発生するため、無用に新しい cycle を追わない」(`conventions:76-77`)。cycle 選定の 3 条件 (`conventions:69-75`) と緊急パス (`:80-88`)・除去を第一候補とする規則 (`:90-91`) は変えない。ADR-0002 の本文は書き換えず、先頭に本 ADR への導線を 1 行足す (`docs/adr/README.md` の例外「navigational なポインタの追記」)。
- 関連: app#382 (VP 判断 2026-10-17)・#384 (review-5x 12 回目、R4#1・R4#2 ほか)・#296・#307・#354・#266・#228 (security HIGH)・#369 (e2e-pins の赤を Issue にする)、ADR-0031 D5・D10・Signpost 3 (`Dockerfile.e2e` の Chromium)、ADR-0035 (同時起草。node / qjs を `Dockerfile.test` に apk で入れない理由の一部)
- 読み方: app は origin/main `5bbabd7` (Dockerfile・script・workflow・conventions・ADR-0002 / 0031 は #384 の `4b233dc` から変わっていない)、platform は origin/main `e126fff`。`conventions` は `.claude/rules/falco-ctf-app-conventions.md`、`0002:N` などは `docs/adr/` の各 ADR。「実測」は 2026-10-17 に colima-falco-build (aarch64) で使い捨ての container を回した結果。「aports」は `gitlab.alpinelinux.org` の API で各 stable branch の `APKBUILD` の commit を数えた結果 (commit の日付。index に載るのはその後の build の後)

## Context

- **C1 Signpost 4 は受理から 44 日で 4 回発火した。** ADR-0002 Signpost 4 は「exact pin の再解決が年 2 回以上」(`0002:135-136`)。受理 (2026-09-01) の後、既存の pin の版を変えた commit は 4 本で、4 本とも pin した版が index から消えたため:
  d53cb4f #296 (09-03、curl / libcurl)、2572090 #307 (10-05、libssl3 / libcrypto3・util-linux・vim 系・ttyd の ca-certificates)、ca1c5bc #354 (10-14、vim 系)、4b233dc #384 (10-17、vim 系・chromium)。数え方は Signpost 1。
  **追記 (2026-10-25、app#499 / #500)**: 5 回目。ttyd の `ca-certificates` 20260909-r0 → 20261020-r0 と `Dockerfile.e2e` の `chromium` 155.0.8059.39 → 155.0.8059.84 が同じ日に index から消え、`build (ttyd) / build` と `e2e` が赤になった (1 commit = 1 回。名前で数えると 2)。赤は 4 日間誰にも届かず (review-5x 64 回目の査定)、platform の本番 pin v2026.10.19 からは ttyd image を build できない (C6 の release の確率が実際に起きた例)。
  #266 (dfa0a0a、09-01) は cycle の bump で、challenge の参加者の道具 (bash・curl・libcurl・vim・vim-common・xxd・util-linux) に exact pin を足した commit (それまで challenge には版の指定が無かった: `0002:59`)。4 回とも #266 が足した pin を含む (#307 は base の引き上げと ttyd の ca-certificates も、#384 は chromium も)。
  VP の数え (#307 / #354 / #382 + #266) とは #296 の有無と #266 の扱いが違う。#266 は cycle の bump なので数えない。
- **C2 仕組み。** Alpine の index は各 package の最新の 1 版だけを載せる (`0031:41`。実測: `apk policy vim chromium` はそれぞれ 1 版)。exact pin を満たせるのは index にある版か base image に入っている版だけ (実測: base に入っている版と同じ pin は index に無くても通る (rc 0)。どちらにも無い版は `breaks: world[...]` で落ちる (rc 3))。だから **base に無い package の exact pin は、upstream が版を上げるたびに build を止める**。
- **C3 頻度は cycle の新しさでなく upstream の security release で決まる。** aports の 3.24-stable (06-09 リリース) で、community/vim の「security upgrade」は 15 回、community/chromium は 14 回、main/openssl は 3 回 (06-10・08-25・09-30)、main/curl は 2 回、main/util-linux は 2 回、main/ca-certificates は 2 回、main/zlib は 1 回 (10-06、CVE の backport)、community/ttyd・community/tini・main/bash は 0 回。
  3.23-stable の main/vim は 08-18 以降、3.24 と同じ版の列 (1011・1014・1091・1178・1202) を受けた (06〜07 月は 3.24 が 10 回・3.23 が 1 回で、新しい cycle の初期だけ多い)。3.22-stable の vim は 06 以降 security upgrade が無い (古い cycle は直らない = 条件 3 の問題)。
  → ADR-0002 Signpost 4 の仮説「条件 1 の patch 回数 3 が甘すぎる」では定常の churn を説明できない。古い cycle に寄せても vim の churn は減らない。
- **C4 今 pin しているもの** (base の中身は実測):

  | image | base に入っている package の引き上げ (`--upgrade`) | base に無い package の exact pin | 版を書かない package |
  |---|---|---|---|
  | challenge (`images/challenge/Dockerfile:110-130`) | libssl3・libcrypto3 3.5.9-r0 (base は 3.5.8-r0)、zlib 1.3.2-r1 (base は r0) | bash・curl・libcurl・vim・vim-common・xxd・util-linux | coreutils・busybox-extras・netcat-openbsd・jq・less・procps・grep・findutils・file・shadow・ca-certificates |
  | ttyd (`images/ttyd/Dockerfile:72-78`) | 同上 | ttyd・bash・ca-certificates・curl・tini | なし |
  | docs の serve stage (`images/docs/Dockerfile:93-94`) | libssl3・libcrypto3 3.5.9-r0 (**base が既に 3.5.9-r0 を持つ**)、zlib 1.3.2-r1 (base は r0) | なし | なし |
  | detect-grader (`images/detect-grader/Dockerfile:54-58`、Wolfi) | 7 本 | なし | なし |
  | `Dockerfile.e2e:33-35` (I5 の image でない) | なし | chromium・font-wqy-zenhei (ADR-0031 D5) | なし |

  Wolfi の index は版を残す (実測: falco 0.44.1 の base で `apk policy libssl3` が 37 版を返す)。detect-grader の pin は drift で落ちたことが無い。
- **C5 exact pin が実際に保証すること。** pin した名前について「その版が入るか、build が落ちるか」だけ。同じ git SHA から同じ package の集合が出る保証ではない — 版を書かない 11 本と推移依存は動き、pin した版が index から消えた後の再 build は落ちる。今も成り立つ再現性の単位は、push した image (I4・I5、tag = git SHA) と base の digest (`conventions:110-111`)。
  repo 自身も、版を書かない jq が index の更新で修正版へ上がり残存 CVE から外れたことを記録している (`images/challenge/Dockerfile:107-108`)。
- **C6 どこで痛むか。**
  - **PR**: `build (challenge|ttyd|docs)`・`image-hygiene`・`e2e` は required でない (required は `test / go-test`・`chart-lint`・`flag-guard`・`challenge-rules`・`build (scoreboard) / scan`・`build (auth-policy) / scan`。2026-10-17 に `gh api repos/Qfour/falco-ctf-app/branches/main/protection` で実測) が、drift の間は全 PR で赤になる (例: #381 の CI)。VP の Class-2 merge の条件に「変更した image の build / scan・image-hygiene・e2e が head で緑」が加わった (#384 の査定 R1#1) ので、drift はそれらの image に触れる Class-2 の merge も止める。
  - **検知**: main に commit が無い間 (09-03〜10-05) は誰も image を build しない。vim 9.2.1091 は aports に 09-13 に入り、re-pin は 10-05 (#307)。`e2e-pins` (毎日、`Dockerfile.e2e` だけ: `.github/workflows/e2e-pins.yaml:14-27`) は 10-15・10-16 とも緑で、10-17 の chromium の drift は #381 の PR CI が先に見つけた。赤が人に届く経路は無い (ADR-0031 D10 (3) の推奨・#369 は open)。
  - **release**: prod は release タグ (`v*`) の SHA の clone から、stand-up の時に全 image を手で build する (platform `docs/prod-deploy.md:23,236-294`)。1 つの image を直すときも全 image を同じ SHA で揃える (`:315-319`、I5)。tag の後に pin が drift すると、その tag は build できなくなり、新しい tag は CEO しか打てない (workspace `CLAUDE.md:32`、`ORGANIZATION.md:83-84`)。08-18〜10-17 に challenge・ttyd・docs が pin する package が動いた回数 (vim 4・openssl 2・curl 1・util-linux 1・ca-certificates 1・zlib 1 = 60 日で 10 回) から、tag の後 3 日以内にどれかが動く確率は約 39% (推定。Poisson・独立を仮定)。
  - **公開キット**: app は「再利用可能な CTF キット」(workspace `CLAUDE.md` のリポ表) だが、release tag を後から checkout した利用者は数日で challenge・ttyd・docs を build できなくなる。
  - **費用**: re-pin は Dockerfile の変更 = Class-2 (`ORGANIZATION.md:277`) で、security の review と review-5x を通る (#384 は 12 回目の review-5x を使った)。#384 の security review の中身は「pin が index と一致」の確認で、判断の余地は無かった。
- **C7 正典の制約。**
  - ADR-0031 D5: Chromium の pin は「緑に戻すために」unpin・範囲指定・別の repository への切替をしない (`0031:166-173`)。
  - #228 の security HIGH「apk upgrade 未 pin = 再現性後退」(#228 本文) → base の package の引き上げを exact pin にした (`images/docs/Dockerfile:51-52`)。対象は base の上書きで、challenge の版を書かない 11 本はこの指摘の対象になっていない。
  - 前例: 信頼する提供元の「動く参照」がセキュリティ修正を運ぶ場合、pin すると「修正が届かず手動 bump 負債になる」ので動く参照を許している (`conventions:167-174`、GitHub の action の `@vN`)。
  - platform の preflight §10 は `scripts/check-freshness.sh` の exit status を読み、0 = 鮮度 OK、2 = endoflife.date に届かない、それ以外 = 「base image に EOL あり」と表示する (platform `scripts/preflight-event.sh:393-409`。platform の CI はその文言を grep する: `.github/workflows/ci.yaml:679`)。#382 の VP 案 (pin の drift 検知を `check-freshness.sh` に入れる) は、platform が消費する script の意味を変え、drift を EOL と、docker の障害を endoflife.date の障害と誤って表示させる。
  - release 前の preventive gate は `make scan TAG=local` とされる (`.github/workflows/ci.yaml:288-289`、`.claude/rules/dev-flow.md:46,129`) が、platform の release 手順 (`docs/prod-deploy.md:236-294`) に scan の step は無い (`scan` の grep で 0 件)。

## Options

1. **今の pin を全部残し、検知を全 Dockerfile に広げ、bump を routine にする (VP の暫定 = (3))** —
   変更点: `check-e2e-pins.sh` を全 Dockerfile に一般化して毎日回し、赤で Issue を起こす。
   コスト: 強制 bump は C3 の頻度のまま (I5 の image で月 5 回前後 + chromium 月 2〜3 回)、各回 Class-2。
   リスクと可逆性: C6 の release の確率 (約 39% / 3 日) と公開キットの tag の劣化は残る (tag の時に build して保管する手順を platform が持つまで)。可逆性は高い。
   効き始める閾値: bump の review を軽くする経路 (D6) と、tag の時の build (Signpost 2) の両方があれば成り立つ。
2. **1 の機構に、exact pin の入口と出口の規則を足す【推奨】** —
   変更点: exact pin は「版が振る舞いに効く package」と「base に入っている package を引き上げる一時的な pin」だけ。それ以外は版を書かない (今の 11 本と同じ扱い)。範囲は使わない。
   コスト: 宣言の検査 (offline) と checker。参加者の道具 5 種の版の git 上の記録を失う。
   リスクと可逆性: 版を書かない package の機能の変化 (Signpost 3)、供給元の侵害を数日遅らせる機会 (Signpost 4)、古い build cache の層 (release は cache を使わない: Consequences)。強制 bump は I5 の image で月 1.5 回程度 (openssl・zlib の引き上げ。base の digest を上げれば消える) + chromium。release の確率は約 14% / 3 日 (推定、openssl 2 回・zlib 1 回 / 60 日から)。pin を戻すだけで元に戻る。
   効き始める閾値: 即時 (C1 の頻度を既に超えている)。
3. **範囲 (`>=` の下限) にする (VP の (2))** — 1 版だけで前にしか進まない index では、下限は版を書かない場合と同じ版に解決する (下限 ≦ 現行の版)。足すのは「下限が index より先にある間は落ちる」という失敗の型だけで、保護は増えない。checker の文法 (`name=version` だけを pin と読む: `scripts/check-e2e-pins.sh:30-31`) を壊し、ADR-0031 D5 (`0031:167`) に反する。浮かせたいなら、正直な形は版を書かないこと (Option 2)。**不採用**。
4. **PR CI で image を build しない (VP の (4))** — Dockerfile の変更 (Class-2) から PR の build / scan / image-hygiene を外し、最初の build が release (CEO の tag の後) になる = いちばん戻しにくい時点へ失敗を動かす。drift は減らず、見えなくなるだけ。required の `build (scoreboard) / scan` と `build (auth-policy) / scan` は同じ matrix にある (C6) ので、外すには CEO の admin 操作が要り、外さなければ永久 pending になる。**不採用**。**芯は残す**: 「release の image は tag の時に 1 回 build して保管し、stand-up では build しない」。platform の手順と registry の寿命・費用の判断なので、本 ADR は Signpost 2 で渡す。

**どの Option とも組み合わせられる手 (VP の (1)): package を外す。**
- **xxd だけを外すことはできない** (実測): `vim` は `xxd=<同じ版>` と `vim-common=<同じ版>` に依存する (`apk info -R vim`)。vim を入れたまま `apk del xxd` を実行すると「xxd: vim」で拒否され、xxd は残る。`xxd=`・`vim-common=` の行は vim の pin と同じ版を重ねて書いているだけで、消しても churn の回数は変わらない。
- **vim ごと外す**と vim・vim-common・xxd が消え、`/usr/bin/xxd` と `vi` は busybox の applet に戻る (実測。`xxd < file` は同じ形で出る)。mission 05 の想定解 `xxd < /root/.ssh/id_rsa` (`challenges/05-silent-search/journey.yaml:44` の hints[] の solution、`README.md:28`) は動き続けるが、handbook の `vim` (`challenges/PARTICIPANT-HANDBOOK.md:63`) は使えなくなる。参加者の道具の選定は product / content の判断。Option 1 なら challenge の強制 bump を約半分にする手 (vim は C1 の 4 回のうち 3 回) になり、Option 2 では vim の版を書かないので外す理由が消える。

## Decision

**Option 2。** 理由: index が 1 版しか持たない以上、exact pin の値打ち (版の変更を review に通す) は版が振る舞いに効く package と base の上書きにしか無く、参加者の道具の pin は毎回同じ答え (修正を受け入れる) の判断のために build を止め、release tag を数日で build 不能にする。

- **D1 文法。** `apk add` の版の指定は exact (`name=version`) だけ。範囲 (`>=`・`>`・`<`・`~`) と別の repository (`@edge` の tag・`--repository`) は使わない (ADR-0031 D5 を全 Dockerfile に広げる)。版を書かない (`apk add name`) は使ってよい。
- **D2 入口。** exact pin は次の 2 類だけ。どちらでもない package は版を書かない。
  - (a) **version-sensitive**: 版の違いが image の振る舞い (protocol・PID 1・ブラウザの API と chromedp の組) を変える package。名前と理由を 1 つの許可表 (例: `images/apk-pin-allowlist.txt`、1 行 = 名前と理由) に書く。今は `ttyd`・`tini` と、ADR-0031 D5 の `chromium`・`font-wqy-zenhei`。
  - (b) **base-upgrade**: base image に入っている package を修正版へ引き上げる `apk add --upgrade name=version`。類は構文 (`--upgrade` の command の中にあること) で決まり、base に入っていることは V3 が確かめる。今は challenge・ttyd・docs の `libssl3`・`libcrypto3`・`zlib` と、detect-grader の 7 本。
- **D3 出口。** (b) は、base の digest を上げてその版以上が base に入った時点で外す (以後その package の版は不変の digest が決める)。今は docs の `libssl3`・`libcrypto3` が該当する (base が 3.5.9-r0 を持つ: C4)。digest を上げられるなら、(b) を足すより digest を上げる方を先に試す (`conventions:119-154` の手順)。(a) は理由が無くなったら外す。
- **D4 今回の変更。** challenge の `bash`・`curl`・`libcurl`・`vim`・`vim-common`・`xxd`・`util-linux` と、ttyd の `bash`・`ca-certificates`・`curl` の版を書かない。docs の `libssl3`・`libcrypto3` の pin を外す (D3)。handbook と mission 05 は変えない (vim と xxd は残る)。
- **D5 検知。** 1 つの checker (`check-e2e-pins.sh` を吸収する。ADR-0031 V9 の 2 つの fixture はそのまま赤になる) が、`git ls-files '*Dockerfile*'` から導いた全 Dockerfile の exact pin を、その RUN の stage の base image の中の `apk policy` と毎日 (と `workflow_dispatch` で) 突き合わせる。対象を列挙しない。
  - 読む形: `\` の継続行、引用符 (`"ttyd=1.7.7-r0"`)、1 つの RUN の中の複数の command (`apk del … && apk add …`)、最初でない stage の apk (docs の最初の stage は python で apk が無い)、`FROM <stage>` の継承 (`Dockerfile.e2e:40`)。base の entrypoint は上書きする (falco の image)。
  - exit: 0 = すべての pin が index か base にある / 1 = 無い pin がある・全体で pin が 0 件・D1 の範囲がある・D2 の類に入らない pin がある / 2 = docker か network の障害 (pin についての判定ではない)。
  - 赤なら Issue を 1 本だけ開く (同じ label の開いた Issue があれば本文を更新する)。本文は file:line・name・pin の版・index の版。`GITHUB_TOKEN` の `issues: write` で足り、新しい action は要らない (ADR-0031 D10 (3))。#369 はこれで閉じる。workflow は `e2e-pins.yaml` を一般化した 1 本にし、ADR-0031 の本文の `e2e-pins.yaml` への参照には実装 PR で導線を 1 行足す。
  - `check-freshness.sh` には入れない (C7: platform の preflight §10 がその exit status を EOL として読む)。cycle の EOL と pin の index 一致は、別の script・別の exit status のままにする。頻度も違う (C3 の drift は数日おき、freshness は週次で十分)。
- **D6 routine。** 赤になった最初の定期 run から 2 日以内に bump を main に入れる (数え方は ADR-0031 D10 (1))。担当は Dockerfile の担当 (software-engineer: `ORGANIZATION.md:133`。`Dockerfile.e2e` は ADR-0031 D5 のまま)。実行は release-engineer に渡してよい (`ORGANIZATION.md:266`)。bump の PR が「pin の版だけを変えた」ことは機械で判定できる (V5)。その PR の review の重さ (review-5x を省く・security を checklist にする) は統治文書の変更なので CEO が決める。
- **D7 採らないもの。** Option 3・4 と、xxd だけの除去 (上の理由)。vim を外すかは本 ADR では決めない (D4 で pin の理由が消える。参加者の道具は product / content の判断)。Option 4 の芯 (tag の時に build して保管) は Signpost 2 で platform に渡す。

## Consequences

- **諦めたもの**: 参加者の道具 5 種 (vim 系・curl / libcurl・util-linux・bash・ttyd の ca-certificates) について、git 上の版の記録と「CI で build した版 = release で build した版」(今の版を書かない 11 本と同じ扱いになる)。この 5 種について、供給元の新しい版を人が受け入れるまで遅らせる機会。
- **新しい不変条件は足さない** (Hard Invariant にしない)。D1・D2 は V1・V2 で required の `flag-guard` に載るが、守るのは Dockerfile の書き方で、製品の性質ではない。
- **本番の image への効き方 (CEO の判断)**: challenge と ttyd で、commit 無しに版が変わる package が増える (challenge は 11 → 16 本、ttyd は 0 → 3 本)。CVE の下限は「index は前にしか進まない」ことと release 前の scan で守る。そのため **platform の release 手順に scan を入れることを、本 ADR の Accepted の条件にする** (C7: 今は無い)。
- **runbook (platform、sre-engineer)**: `docs/prod-deploy.md` Step 4 の build に `--no-cache` を付ける (版を書かない package が、前の build の cache の層から古い版のまま来ないように。今も 11 本で起こりうる)。build の後・push の前に scan する。stand-up の前に D5 の checker を回す (preflight に §10b を足すかは platform が決める。§10 の意味は変えない)。版の記録が要るなら、push した image の `apk info -v` を event の記録に残す。
- **conventions (D の実装 PR、software-engineer)**: `## Dockerfile 規約` の同点決着の理由づけ (`conventions:76-77`) を C3 の測定に合わせて直す (「最古を選ぶ」は条件 1 の安定性の理由で残す)。D1〜D3 の規則を足す。digest の bump 手順 (`:119-154`) に「base がその版以上を持ったら base-upgrade の pin を外す」を足す。docs の Dockerfile の「same discipline as challenge/ttyd/detect-grader」(`images/docs/Dockerfile:51-52`) を D2 (b) の言い方に直す。drift の台帳になった Dockerfile のコメント (`images/challenge/Dockerfile:69-109`) から、版を書かなくなる package の分を消す (#384 R4#3)。
- **残余**: (i) (b) は base の bump まで index に依存し、openssl・zlib の頻度 (C3) で強制 bump が起きる。(ii) chromium は月 2〜3 回のまま (ADR-0031 の routine。同 Signpost 3 で版が消えない配布を再検討)。(iii) 版を書かない package の機能はテストしていない (mission 01 の curl による自己署名の API 呼び出しなど。Signpost 3)。

## Signposts (この決定を覆す観測可能な信号)

1. **再 pin の回数**。測り方:
   ```sh
   git log --first-parent origin/main --since=<日付> --date=short --format='%h %ad %s' \
     -G '[a-z0-9][a-z0-9._+-]*=[0-9][^[:space:]"\\]*-r[0-9]+' -- $(git ls-files '*Dockerfile*')
   ```
   で pin の行を変えた commit を出し、その commit の前後の Dockerfile で同じ名前の pin の版が変わったものを 1 回と数える (pin の追加と削除は数えない。1 commit で複数の名前が動いても 1 回)。2026-10-17 の値: 09-01 以後 4 回 (C1)。2026-10-25 の値 (`scripts/check-repin-count.sh` で測定): 09-01 以後 5 回、直近 30 日 (09-25〜10-25) で 4 回 (10-05・10-14・10-17・10-25。うち 10-25 は ttyd と e2e の 2 名)。**I5 の image で 30 日に 2 回を超えたら** D2 の分け方を見直す (その package は本当に version-sensitive か、base の digest を上げれば消える (b) か)。`Dockerfile.e2e` の Chromium は ADR-0031 Signpost 3 (月 4 回) で見る。
2. **stand-up か開催中の hotfix で、pin の drift のために image を build できなかったことが 1 回** → release の image を tag の時に 1 回 build して保管し、stand-up は digest で deploy する手順 (registry の寿命・費用) を platform で起こす (Option 4 の芯)。
3. **版を書かない package の更新で mission・verify・e2e が壊れた (版を戻すと直る) ことが 1 回** → その package を D2 (a) に移す。
4. **Alpine の stable branch で改ざんされた package が公開されたと報告される、または image を版を残す配布 (Wolfi・apko の lock: C4) に移す判断が出る** → 前者は報告が片付くまで全 package を exact pin にする (一時)。後者は全 package を lock に切り替える (drift が起きないので exact pin の費用が消える)。

## Verification

- **V1 解析 (offline、required の `flag-guard`)**: checker の解析だけを fixture で回す (network・docker を使わない)。各形 (`\` の継続・引用符・`apk del … && apk add …`・最初でない stage の apk・`FROM <stage>`・`--upgrade`) の fixture について、(file, stage の base, name, version, upgrade か否か) の表が期待値と完全一致する。範囲 (`>=`・`~`) を含む fixture と、pin が 0 件の tree は exit 1。
- **V2 類 (offline、required の `flag-guard`)**: 実 tree の pin がすべて D2 の (a) 許可表にある名前か (b) の構文で、許可表の名前はどこかで pin されている (古い行を残さない)。planted: 許可表に無い非 upgrade の pin・pin の無い許可表の行・範囲 の 3 つがそれぞれ exit 1。
- **V3 index との一致 (network、毎日 + `workflow_dispatch`、advisory)**: 各 pin がその stage の base の `apk policy` に載る (index か installed)。(b) の pin は base に入っている package であること (入っていなければ exit 1 = 類の誤り)。base の版 ≧ pin なら「外せる」(D3) を出す (gate にしない)。docker / network の障害は exit 2。planted-bad (既存の `scripts/testdata/e2e-pin-BAD.txt`・`e2e-pin-BAD-continued.txt` と、多段・引用符・`del && add` の 3 本) を `workflow_dispatch` で流して赤になることを実装 PR に貼る。
- **V4 通知**: V3 が exit 1 のとき、Issue が 1 本だけ開くか更新される。`workflow_dispatch` の dry-run の入力で本文を出せる。
- **V5 版だけの diff (PR、advisory)**: Dockerfile を変える PR について、`=<版>` の部分とコメント行を伏せた before / after が一致するか (= 版だけを変えたか) を出す。D6 の判断の材料。
- **V6 測定 (gate ではない)**: Signpost 1 の数え方を script にし (原型: 起草時の scratchpad の `repin-count.sh`)、`/ceo-report` に月 1 回数字を出す。
- **実装の対応 (D1・D5 の実装 PR。D2〜D4 は別の PR で、本 PR の外)**: checker は `scripts/check-apk-pins.sh` (`check-e2e-pins.sh` は `Dockerfile.e2e` 用の wrapper として残す。ADR-0031 の参照を壊さないため)、workflow は `.github/workflows/apk-pins.yaml` (`e2e-pins.yaml` を置き換え)、Makefile は `check-apk-pins` / `check-apk-pins-selftest`。
  - **V1 の解析**: `--parse` が TSV (file, line, stage, base, kind, name, version, upgrade) を出し、`--selftest` が各形 (`\` の継続・引用符・`del && add`・最初でない stage・`FROM <stage>` の継承・`--upgrade`・exec 形・`--platform`) の表を期待値と完全一致で固定する。範囲・`@edge`・`--repository` / `-X`・shell 変数・pin 0 件は exit 1。**security の同意の条件 4 (app#382 F4)**: `--allow-untrusted`、`/etc/apk/repositories` と `/etc/apk/keys` への書き込み (RUN で読み取り (cat grep head tail wc ls stat test diff) 以外か `>` のあるもの、COPY / ADD) も exit 1 で、各 1 本以上の planted fixture が selftest にある (実ツリー 14 本は 0 件)。`-X` の結合形・短縮クラスタ、`--keys-dir`、`--repositories-file=`、`/etc/apk` 自体への COPY / ADD・`cp -r`・`RUN --mount` も同じ。**見えない形 (review が見る。網であって証明ではない)**: `COPY rootfs/ /` (source tree が `/etc/apk/...` を運ぶ)、heredoc の RUN 内の書き込み (そこに `apk add` があれば coverage の不一致で exit 1)、`cd /etc/apk && echo x > repositories` (path が 1 つの token にならない)、変数で組んだ path、`sh -c "..."` (同じく coverage)。`--root` / `--cache-dir` は今は許している (security の確認待ち)。実ツリーの文法・pin 0 件・coverage は `--lint` (offline、`--selftest` から分離 = #506、V2 もここに足す)、`--selftest` は checker 自身の検査で、どちらも required の `flag-guard` の独立 step (`ci.yaml`)。独立の数え (text の `apk ... add` の数 = parser が読んだ数) が一致しないと fail する (parser の死角 = 黙って緑を防ぐ)。
  - **V3 の index との一致**: 毎日 + `workflow_dispatch` の `apk-pins.yaml`。exit 0 / 1 / 2 は D5 のとおり (docker 無しは exit 2)。planted-bad の 2 fixture は `file` 入力で選ぶ。**network の planted は V3 の元の 5 本 (2 fixture + 多段・引用符・`del && add`) から 2 本に絞った**: 3 形は V1 の offline の表 (`--selftest`) が覆い、index との照合は文の形に依存しない (形ごとに network を使っても、確かめる対象は同じ `apk policy` の突き合わせ)。D2 の類の検査 (許可表・(b) の構文・「base に入っている」確認と「外せる」の表示) は V2・V3 の後半で、D2 の実装 PR の仕事 (本 PR には無い)。
  - **V4 通知**: 赤 (exit 1) だけが label `apk-pin-drift` の Issue を開く / 本文を更新する (`GITHUB_TOKEN` の `issues: write`、新しい action 無し)。exit 2 は job を赤にするが Issue は開かない。`dry_run` と fixture の run は本文を job summary に出すだけ。
  - V5・V6 は別 PR。
- **機械の確認が無いもの**: D2 (a) の「版が振る舞いに効く」という判断 (許可表の理由を review で見る)。release の scan (platform の手順。sre-engineer の stand-up のチェックリストで確かめる)。

## Advice

- VP (2026-10-17、#382 の判断と本 ADR の発注): exact pin を維持する・検知を機械化する・範囲 (fuzzy) は採らない・vim は handbook に明記があるので外さない・xxd の package 外しは content の判断・(4) を評価する。
  **採用**: D1 (範囲は使わない)・D5 (検知の機械化)・D6。
  **違う点**: (i) D2・D4 で exact pin の対象を絞る (VP 案は今の pin をすべて維持する)、(ii) 検知を `check-freshness.sh` (週次) でなく別の checker (毎日) にする (C7 の platform の preflight と、C3 の頻度)、(iii) xxd だけの除去は依存の構造上できない (実測)。
  VP 案を採るなら Option 1 に D5・D6 を付け、Signpost 2 の手順 (tag の時の build) を前倒しで必須にする (C6 の release の確率のため)。
- review-5x 12 回目 (2026-10-17、#384): R4#1 → 本 ADR。R4#2 = R5#1 = R3#3 = R2#2 (FROM から base・`\` の継続・0 件は exit 1・障害は exit 2・planted-bad) → D5・V1・V3。R1#1 (委任条件に変更 image の build などを足す) → C6・D6。R4#3 (drift の台帳になったコメント) → Consequences。
- security-engineer: #228 (2026-08-28) の HIGH「apk upgrade 未 pin = 再現性後退」→ D2 (b) を exact pin に残す理由。#384 (2026-10-17) の APPROVE with comments → C6 (review の中身は index との一致)。本 ADR の D2・D4 への同意は**未取得** (Accepted の前に取る)。
- software-engineer (ADR-0002 の起点、2026-08-18): 「基準を見直さないと次の CVE ラウンドで同じ議論が再発する」→ C3 で ADR-0002 Signpost 4 の仮説 (cycle の新しさ) を測り、pin の側で答えた。
- architect の測定 (2026-10-17、発注の外): aports の commit の数え、vim と xxd の依存、busybox の applet、base の中身、pin = base の版のときの apk の挙動、Wolfi の index、platform の release 手順に scan が無いこと。
