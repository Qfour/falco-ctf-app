# ADR-0026: challenge image の `/opt/ctf/missions/` を fixtures allowlist にし、hints・想定解・採点メタを同梱しない

- Status: **Proposed** (Accepted 化は CEO merge 時。期限 = P28-0d の software PR の merge 前)
- Date / Deciders: 2026-10-05 / CEO (2026-10-04「2026-06 の guided 方針を解除し、撤去する」) + VP + architect (起草) +
  security-engineer・qa-engineer (独立レビュー 2026-10-05。指摘は本版に反映済み、再確認待ち)
- 関連: workspace `REFACTORING.md` P28-0d / P22 (2026-08-14 CEO 決定) / P27-1、ADR-0001 (監査 LOW「plant.sh の同梱」・I12)、
  ADR-0007 (hygiene の entry-set 検査)、ADR-0017 (fixtures の絶対パスに依存する custom rule)、ADR-0030 (予約。同じ n-gram 規則を
  Quest content に使う)、app#308 / app#309 (content の先行 PR)。他 ADR の Decision は supersede しない

## Context

**C1. 現状 (e74d871 で実測)。** `images/challenge/Dockerfile:86-96` は `challenges/` を丸ごと `/opt/ctf/missions/` に COPY し、
コメントで「INTENTIONAL (guided-event decision, 2026-06)」と宣言している (`:91-95`)。tracked file 101 本 (ディレクトリを含めて
130 entry) のうち **82 本が `<id>/fixtures/**` 以外**である: 14 課題すべての `README.md` (想定解)・`journey.yaml` (ヒント全文)・
`falco-rule.yaml`・`rule.yaml`、`plant.sh` 3 本、生成 values 7 本、`gen-values.sh`、運営向け文書。03・05・10 の
`falco-rule.yaml` は `expectedFlag` を持ち、03・10 は `README.md` にも同じ値がある。リポにあるのは placeholder だが、flags の
上書きは列挙された id にだけ掛かり、欠けた evade id は placeholder のまま残る (`internal/catalog/flags.go:44-57`、
`charts/ctf-user/deploy-user.sh:202-223`)。欠落を fail-closed にする修正は別 Issue (Class-2) とし、本 ADR では扱わない。
COPY は追跡外のファイルも焼く: `.gitignore` 済みの `challenges/decks/` (`.gitignore:38`) や `.DS_Store` は `.dockerignore` に無い。

**C2. scenario モードでも閉じていない。** platform は環境の `scoreboardScenario` から `scenario:<name>` を自動導出する (契約表
Challenges path)。そのモードでも `missions-scope` initContainer は範囲内の課題ディレクトリを丸ごと複製する
(`charts/ctf-user/templates/pod.yaml:151-153`)。P27-1 が閉じたのは範囲外の課題だけで、範囲内の `README.md` / `journey.yaml` は
端末から読める。

**C3. 既決事項との矛盾。** 2026-08-14 の CEO 決定 (P22) は「ヒントの唯一経路 = journey の減点開放」「ttyd 迂回を完全閉塞」で
ある。ヒント 3 は 50 点の減点だが、同じ内容を端末で無料で読める。P27-1 は範囲外課題の同梱を「現状の欠陥」と認定して閉じた。
ADR-0001 はこの同梱を guided 方針の下で監査 LOW として受容していた
(`0001-flag-plant-initcontainer-not-challenge-env.md:230-240`)。**CEO 決定 2026-10-04: 撤去する。**

**C4. fixtures 自体もヒントを運んでいる。** image を絞っても `fixtures/welcome.txt` は残る。e74d871 では 8 課題
(01・02・06・08・09・11・12・13、すべて trigger) の welcome.txt が想定解のコマンドを逐語で持つ (qa-engineer が実行で確認、
architect の probe でも再現)。なお `/opt/ctf/INDEX.txt` は image にもリポにも無く、login 時に走るのは `banner.sh` だけである。

**C5. 制約。** I5 (全 8 イメージ同一 SHA。イメージを増やさない)。workspace 内で走る検査は shell builtin に限る (ingest は container
名を見ないので、検査のプロセスが参加者の発火として採点される: `charts/ctf-user/assert-flag-isolation.sh:22-57`)。prod は CI-free で、
一次ゲートは `make build` (`Makefile:66`)。path は動かせない: platform の Falco `customRules` が
`/opt/ctf/missions/13-archive-loot/fixtures/loot/` を条件に直書きしている
(`falco-ctf-platform/helmfile/releases/falco/values.yaml.gotmpl:171`)。

## Options

1. **現状維持 (guided 方針)** — 変更しない。コスト: ゼロ。リスク: 減点 (Score の一部) が、端末の中を知る参加者にだけ効かない。
   P28 の Quest content も同じ経路で読める。可逆。効き始める閾値: 順位を付けない解説会だけに使う場合。CEO 決定で不採用。
2. **build 時 allowlist (multi-stage)【推奨】** — builder stage だけが `challenges/` 全体を見て、final stage は `<id>/fixtures/` と
   生成済みの `answers.yaml` だけを受け取る。コスト: Dockerfile が 2 stage になる (base は同じ digest、イメージ数は不変)、検査 3 点、
   content の整理が前提。リスク: fixtures 以外を image に頼る課題は作れなくなる (現在 0 件)。COPY を戻せば可逆だが、I16 昇格後は
   supersede が要る。閾値: 順位を付ける回が 1 回でもある時点。(`Dockerfile.dockerignore` で context を絞る方法は、root の
   `.dockerignore` を丸ごと置き換えるので secret 除外が二重管理になる。採らない。)
3. **実行時に絞る** — image はそのまま、`missions-scope` を全モードに広げて fixtures だけ複製する (または final stage で `rm`)。
   コスト: chart だけで済む。リスク: image の layer に全量が残り、`all` / 単一課題モードや chart と image の版ずれで黙って露出する。
   将来 `challenges/` に足すファイルが既定で同梱される (fail-open)。可逆。閾値: 効かない (既定が露出側のまま)。

## Decision

**Option 2。** 理由: 既定を「入れない」側に倒せるのは build 時の allowlist だけで、今後 `challenges/` に足すファイルも自動で外れる。

- **D1 allowlist**: final image の `/opt/ctf/missions/` は、catalog の各 id について `<id>/fixtures/**` だけを持つ。fixtures の無い課題にも
  空の `<id>/fixtures/` を作る (`missions-scope` の `cp -a` と deploy 時の id 集合検査が id ディレクトリを前提にする)。bytes と mode は
  build context と同一に保つ (`11-cloud-cred-hunt/fixtures/aws` は実行ビットを持つ)。
- **D2 `answers.yaml`**: 生成 (`Dockerfile:103-112`) を builder stage へ移す。`falco-rule.yaml` を読むのは builder だけになる。
  `submit.sh` など 4 本の COPY と `/opt/ctf/plant-seed/` は無変更 (「`/etc` に触る最後の RUN」の規律 `:139-145` も維持)。
- **D3 path は不変、契約表に行を足す** (両リポ、相互リンク): 「workspace 内 `/opt/ctf/missions/<challengeId>/fixtures/**` =
  `challenges/<challengeId>/fixtures/**`。platform の `customRules` がこの絶対パスに依存する。変えると該当の trigger 課題が無検知
  (解けない) になる。変更は両リポ同時 PR」。
- **D4 I16 (提案・未昇格)**:
  > challenge image の `/opt/ctf/missions/` は、catalog の各 id について `<id>/fixtures/**` だけを持つ (他の entry を持たず、全 id に
  > `<id>/fixtures/` がある)。`challenges/*/fixtures/**` は、D5 の規則で違反となる n-gram (`hints[]` にあって無料表示に無い 10 rune) を
  > 含まない。例外・除外リストを持たない。

  **I16 は「ヒントの経路が 1 つである」とは主張しない** (検査できない)。主張するのは image の entry 集合と fixtures の文面だけである。
  conventions に載せる表題も「missions の fixtures allowlist と fixtures のヒント非同梱」とし、「ヒント単一経路」は使わない
  (主張していないことを名前が主張してしまう)。
- **D5 n-gram 規則** (ADR-0030 と単一実装で共有する。スコープ S ごとに評価する):
  1. **入力。** ヒント項目 = S の各課題の `hints[]` の各 `text`。無料表示項目 = S の各課題の `briefing`、各 `steps[].label`、各
     `steps[].detail`、`rule.yaml`。fixtures 項目 = **全課題**の `challenges/*/fixtures/**` の各ファイル (S で絞らない)。
     `journey.yaml` 由来の項目は YAML 解釈後の文字列、`rule.yaml` と fixtures は生バイトを UTF-8 として読む。非 UTF-8 は fail。
     `briefing` は、scenario の `narrative.yaml` に override があれば**置き換える** (追記しない。`catalog.ApplyNarrativeOverrides` と同じ)。
     title・tagline・bridge・`rule-explain.md` は無料表示に**含めない** (意図的。厳しい側に倒す)。
  2. **正規化。** Unicode White_Space (Go の `unicode.IsSpace` が真) の rune を除くだけ。NFC / NFKC・大小文字・記号は変えない。
  3. **n-gram。** n = 10 **rune**。**項目ごとに切る** (項目を連結しない。連結すると項目の境界をまたぐ並びまで無料に数え、緩い側に
     倒れる)。
  4. **違反。** fixtures 項目 f と n-gram g の組で、g が S のいずれかのヒント項目にあり、S のどの無料表示項目にも無く、f にある。
  5. **スコープ。** full catalog と、各 `scenarios/*/scenario.yaml`。scenario スコープでも fixtures は全課題を対象にする: platform の
     配布スクリプトは scenario の自動導出に失敗すると警告だけ出して `all` で配る (`falco-ctf-platform/scripts/deploy-event-workspaces.sh:180-203`)
     ので、「scoreboard は scenario 限定・端末は全課題」が実際に起こる。
  6. **合格と報告。** 全スコープで違反 0。数える単位は、スコープごとの (fixtures ファイル, 異なる n-gram) の組。除外リストは作らず、
     fixtures 側の言い換えで消す。
  - **n の根拠** (architect probe。security-engineer の独立実装と全スコープで件数が一致)。下限: n ≤ 9 では汎用の技術トークンが単独で一致
    する。整理後の fixtures (app#308、head 9c3ce1c) の full スコープで n=8 は 12 組、n=9 は 3 組 (9 文字の shebang など)、n ≥ 10 は
    全スコープで 0。上限: catalog で最短の想定解は 02 の 14 文字 (空白除去後) で、n ≥ 15 はその逐語コピーを取りこぼす (e74d871 の
    02 は n=14 で 1 個、n=15 で 0 個)。見逃しは無音で、誤検知は赤いテストとして見える。よって雑音の膝 (9) の直上を採る。n=10 では
    最短の想定解に 5 つの窓があり、e74d871 ではうち 3 つが違反になる。
  - **実測 (n=10)。** e74d871: full 364 / nimbusbreach-full 275 / nimbusbreach-with-tutorial 281 / tutorial-intro 42。
    tutorial-intro の 42 のうち 9 は「fixtures を全課題にする」ことで初めて拾える。app#308: 4 スコープとも 0。項目ごとに切る場合と
    連結する場合の差は、この 2 つの tree の full スコープでは 0 (定義として緩い側を塞ぐための規定である)。
- **D6 順序**: content (app#308 の welcome.txt、app#309 の配布文書) が先、software (Dockerfile・検査・I16 昇格・契約表) が後。逆順だと
  V5 が赤になる。content は「D5 の規則で全スコープ 0」を満たしてから merge する。

## Consequences

- **諦めたもの**: 端末で README と想定解を読める guided 体験 (2026-06 方針)。解説は portal と運営の実演に寄せる。
- **ADR-0001 の監査 LOW** (plant.sh と plant-target 宣言が読める) は閉じる。ADR-0001 の Decision は無変更。
- **追跡外ファイルの経路も閉じる**: `.gitignore` 済みだが `.dockerignore` に無いディレクトリ (例: `challenges/decks/`) が image に
  焼かれる経路は、final stage が `<id>/fixtures/` しか受け取らないので無くなる。fixtures の中の追跡外ファイルは V1 が落とす。
- **影響なし (静的読解で確認)**: `plant` (seed script は values に inline: `challenges/values-all.yaml:10-13`)、`missions-scope`
  (絞った tree をそのまま複製する)、submit / setname / submit-yaml / banner (missions を読まない)、docs image (build context から
  直接読む)、platform (path 不変。helmfile の変更なし、文書の行追加だけ)。
- **追随が要る記述**: conventions の Dockerfile 規約表 (challenge を single-stage と書いている)、`charts/ctf-user/values.yaml:78-80,135-142`、
  `pod.yaml:132-143,364-371`、`assert-flag-isolation.sh:94-97,509-516`、ORGANIZATION.md §2 (Dockerfile = software、fixtures = content)。
  配布文書にあった `INDEX.txt` と README への案内は app#309 が除く。
- **残余 (I16 の外。隠さない)**:
  1. 配布文書: e74d871 の `challenges/PARTICIPANT-HANDBOOK.md:188` (§6.3) と `challenges/REFERENCE.md` §3〜4 にある evade 課題の
     「回避の発想」は、image から外れても事前配布で届く。app#309 が除く (起草時点で open)。merge までは残余である。
  2. 公開リポ: `README.md` と `journey.yaml` は GitHub で読める。端末の egress は絞れても、参加者の手元の端末は絞れない。順位の
     真正性にはこの上限がある (P28 product brief が明記済み)。
  3. n-gram は逐語一致しか捕まえない。言い換えに対する防衛線は文面レビューで、V8 の規律で発動させる。
  4. `/opt/ctf/missions/` 以外への COPY は I16 の文言の外。V1 の sha256 照合が「そのまま置く」場合を落とす。内容を変えて置く場合は
     Dockerfile 変更の security-engineer レビュー (既存規律) に残る。
- **runbook**: allowlist 前の image を新しい chart で deploy すると V4 で止まる (意図した挙動。`deploy-user.sh` の非ゼロ exit は
  fail-closed 契約)。

## Signposts (この決定を覆す観測可能な信号)

1. fixtures 以外のファイルを image に要する課題の提案が 1 件出る → 例外で通さず、allowlist の単位を見直す ADR を書く。
2. n-gram の誤検知による書き換えが 1 PR に 3 件以上、が 2 PR 続く → n を上げる (上限 14) か、無料表示の定義を見直す。逆に、検査を
   通ったヒント (逐語でも言い換えでも) が fixtures から 1 件見つかる → 規則を補強する。
3. 次回イベントで「ヒント 3 の開示率 10% 未満、かつ solve 率 80% 超」の課題が 3 つ以上 → ヒントが別経路 (残余 1・2) で流れている。
   I16 の実効が無いので残余を先に閉じる。数値は仮 (基準データ未取得)。
4. 運営が「端末に解説を置きたい」回を決める → まず portal 側で応える設計を検討し、それでも要るなら本 ADR を supersede する (CEO 判断)。

## Verification

V1〜V6 と V8 は P28-0d の software PR で満たす (**未実装**)。V7 は実機でのみ確認可。V1〜V3 は `scripts/check-image-hygiene.sh` に足し、
`make build` の fail-closed 経路で必ず走らせる (CI の `image-hygiene` job は required check ではない: `.github/workflows/ci.yaml:386-387`)。

- **V1 build 時の entry-set**: 基準は `git ls-files 'challenges/*/fixtures/**'`。image の `/opt/ctf/missions/` 配下の全 path が
  `<id>(/fixtures(/.*)?)?` に一致し、全 id に `<id>/fixtures/` があり、基準の各ファイルが同じ bytes と mode で存在し、基準に無い
  ファイルが 1 つも無い (作業ツリーの fixtures に untracked / ignored のファイルがあれば fail)。通常ファイルとディレクトリ以外
  (symlink 等) は fail。id 0 件・fixtures 0 件は fail。`challenges/` の tracked かつ fixtures 以外のファイル (個別に COPY する
  ツール 4 本を除く) の sha256 が、image 内のどのファイルとも一致しない。`/opt/ctf/` 直下の entry 集合も固定する。
- **V2** `answers.yaml` のキー集合 = catalog の evade id (空は fail)。
- **V3** image 内に、リポの各 `expectedFlag` との完全一致が 0 件。加えて `/opt/ctf` 全体で、説明用の表記 `FALCO{...}` 以外の
  `FALCO{` が 0 件 (形の検査。placeholder 以外の値が紛れた場合も落とす)。
- **V4 deploy 時** (`deploy-user.sh` が呼ぶ既存 assert の 3-8 の隣。scenario / `all` / 単一課題の 3 モードすべて):
  `/opt/ctf/missions/` 直下の entry が、期待する id 集合と完全に一致し、すべてディレクトリである。各 `<id>/` の entry は `fixtures`
  だけ。列挙は shell builtin と glob だけで行い、`*` に加えて dot entry (`.[!.]*` と `..?*`) も見る。一致しない glob は文字列のまま
  残るので `[ -e ]` で実在を確かめてから数える。entry 0 件は fail。fixtures の中身は開かない。
- **V5 Go** (`make test` = required check): `TestFixtures_CarryNoHintOnlyNgrams` が D5 を全スコープで検査する。走査 0 件は fail。
- **V6 故意違反**: `TestHintLeakChecker_Mutation` — 合成入力で、別の課題のヒント文を fixtures に混ぜると赤 / 無料表示にある文は緑 /
  項目の境界をまたぐ並びは無料に数えない / 入力 0 件は赤。実 catalog の複製で、02 の想定解 (14 文字) を fixtures に混ぜると赤。
  スコープで結果が変わる例 (full では無料、ある scenario では無料でない文) がその scenario でだけ赤。あわせて、`README.md` を
  足した派生 image に V1 が非ゼロで終わる negative test。出力を PR 本文に貼る。
- **V7 実機**: scenario・`all`・単一課題の各モードで deploy し、V4 が緑で、mission 13 が従来の path で発火して solve すること。
- **V8 レビューの規律**: 実装 PR (P28-0d) は security-engineer レビュー必須。以後、`challenges/*/fixtures/**` と `journey.yaml` の
  `hints[]` を変える PR も security-engineer レビュー必須とし、dev-flow のゲート表に載せる (残余 3 の文面レビューを発動させる)。

**I16 昇格の条件 (architect: yes, if)**: V1〜V6 と V8 が landing する PR と同じ PR で、conventions の表と契約表 (D3) に追記する。
先に紙のルールを増やさない。V7 は本番投入の前に満たす。`image-hygiene` を required に上げるかは VP / CEO の判断として残す。

## Advice

- security-engineer R1 (2026-10-05、REQUEST CHANGES → 本版に反映): scenario スコープでも fixtures を全課題にする (tutorial-intro で
  9 個を実測)、項目ごとに n-gram を切る、V1 の基準を tracked file に固定し sha256 照合を足す、V3 に形の検査、V4 の 3 モードと
  dot entry、I16 の表題。
- qa-engineer R2 (2026-10-05、APPROVE with comments → 本版に反映): D5 を一意に実装できる文面にする、数える単位の明記、V6 の
  実 catalog ケース。前段の実測 (130 entry・82 本、重複 8 課題、検査の原型) も qa。
- content-engineer (2026-10-04〜05): welcome.txt 14 本を整理し、汎用句 2 種も言い換えた (app#308)。配布文書は app#309。
- VP (2026-10-04〜05): F1 を既決事項の実装漏れとして撤去へ進める。維持の分岐 (P28-0d') は CEO 決定で消滅。C1 の訂正 (flags の
  上書きは列挙された id にだけ掛かる) を実コードで確認。レビュー指摘は全件採用。
