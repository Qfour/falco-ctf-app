# ADR-0026: challenge image の `/opt/ctf/missions/` を fixtures allowlist にし、hints・想定解・採点メタを同梱しない

- Status: **Proposed** (Accepted 化は CEO merge 時。期限 = P28-0d の software PR の merge 前)
- Date / Deciders: 2026-10-05 / CEO (2026-10-04「2026-06 の guided 方針を解除し、撤去する」) + VP + architect (起草) +
  security-engineer (レビュー必須・未受領)
- 関連: workspace `REFACTORING.md` P28-0d / P22 (2026-08-14 CEO 決定) / P27-1、ADR-0001 (監査 LOW「plant.sh の同梱」・I12)、
  ADR-0007 (hygiene の entry-set 検査)、ADR-0017 (fixtures の絶対パスに依存する custom rule)、ADR-0030 (同じ n-gram 規則を
  Quest content に使う)。他 ADR の Decision は supersede しない

## Context

**C1. 現状 (e74d871 で実測)。** `images/challenge/Dockerfile:86-96` は `challenges/` を丸ごと `/opt/ctf/missions/` に COPY し、
コメントで「INTENTIONAL (guided-event decision, 2026-06)」と宣言している (`:91-95`)。tracked file 101 本 (ディレクトリを含めて
130 entry) のうち **82 本が `<id>/fixtures/**` 以外**である: 14 課題すべての `README.md` (想定解)・`journey.yaml` (ヒント全文)・
`falco-rule.yaml`・`rule.yaml`、`plant.sh` 3 本、生成 values 7 本、`gen-values.sh`、運営向け文書。03・05・10 の
`falco-rule.yaml` は `expectedFlag` を持ち、03・10 は `README.md` にも同じ値がある (リポにあるのは placeholder。`FLAGS_FILE` を
供給しない環境では、それがそのまま採点値になる)。

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

**C5. 制約。** I5 (全 8 イメージ同一 SHA。イメージを増やさない)。workspace 内で走る検査は shell builtin に限る (ingest は container 名を見ないので、
検査のプロセスが参加者の発火として採点される: `charts/ctf-user/assert-flag-isolation.sh:22-57`)。prod は CI-free で、一次ゲートは
`make build` (`Makefile:66`)。path は動かせない: platform の Falco `customRules` が
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
  > `<id>/fixtures/` がある)。`challenges/*/fixtures/**` は、`journey.yaml` の `hints[]` にあって無料表示に無い 10 文字 n-gram を
  > 含まない。例外・除外リストを持たない。

  **I16 は「ヒントの経路が 1 つである」とは主張しない** (検査できない)。主張するのは image の entry 集合と fixtures の文面だけ。
- **D5 n-gram 規則** (ADR-0030 と単一実装で共有する):
  - 正規化は空白の除去だけ (記号と大小文字は保つ。コマンドでは意味を持つ)。単位は rune、**n = 10**。
  - 無料表示 = `journey.yaml` の `briefing`・`steps[].label`・`steps[].detail` と `rule.yaml` の全文。
  - 違反 = スコープ内のいずれかの課題の `hints[].text` にあり、スコープ内のどの課題の無料表示にも無く、スコープ内のいずれかの
    fixtures ファイルにある n-gram。**課題を跨いで照合する** (ある課題の fixtures が別の課題のヒントを運びうる。e74d871 に実例がある)。
  - スコープ = full catalog と、各 `scenarios/*/scenario.yaml` (Restrict と narrative overlay の適用後)。
  - **n の根拠** (architect probe、上の規則どおり)。下限: n ≤ 9 では汎用の技術トークン (9 文字の shebang など) が単独で一致する。
    整理後の fixtures (P28-0d の content、起草時点の未 push 版) に対し、違反 n-gram は n=8 で 25 個、n=9 で 16 個、n=10〜14 で
    12 個 (汎用句 2 種)、n=15 で 0 個。上限: catalog で最短の想定解は 02 の 14 文字 (空白除去後) で、n ≥ 15 はその逐語コピーを
    取りこぼす (e74d871 の 02 は n=14 で 1 個、n=15 で 0 個)。見逃しは無音で、誤検知は赤いテストとして見える。よって雑音の膝 (9) の
    直上を採る。n=10 なら最短の想定解にも 5 つの窓がある。
  - 残る汎用句は fixtures 側の言い換えで消す (除外リストは作らない)。e74d871 は n=10 で 12 課題・23 組 (fixtures × ヒント) が違反する。
- **D6 順序**: content (welcome.txt と配布文書の整理) が先、software (Dockerfile・検査・I16 昇格・契約表) が後。逆順だと V5 が赤に
  なる。content は「D5 の規則で 0 件」を満たしてから merge する。

## Consequences

- **諦めたもの**: 端末で README と想定解を読める guided 体験 (2026-06 方針)。解説は portal と運営の実演に寄せる。
- **ADR-0001 の監査 LOW** (plant.sh と plant-target 宣言が読める) は閉じる。ADR-0001 の Decision は無変更。
- **影響なし (静的読解で確認)**: `plant` (seed script は values に inline: `challenges/values-all.yaml:10-13`)、`missions-scope`
  (絞った tree をそのまま複製する)、submit / setname / submit-yaml / banner (missions を読まない)、docs image (build context から
  直接読む)、platform (path 不変。helmfile の変更なし、文書の行追加だけ)。
- **追随が要る記述**: conventions の Dockerfile 規約表 (challenge を single-stage と書いている)、`charts/ctf-user/values.yaml:78-80,135-142`、
  `pod.yaml:132-143,364-371`、`assert-flag-isolation.sh:94-97,509-516`、ORGANIZATION.md §2 (Dockerfile = software、fixtures = content)。
- **残余 (I16 の外。隠さない)**:
  1. 配布文書: `challenges/PARTICIPANT-HANDBOOK.md:184-188` (§6.3) と `challenges/REFERENCE.md` §3〜4 に evade 課題の「回避の発想」が残る。image から
     外れても事前配布で届く。後続の content PR で除く。
  2. 公開リポ: `README.md` と `journey.yaml` は GitHub で読める。端末の egress は絞れても、参加者の手元の端末は絞れない。順位の
     真正性にはこの上限がある (P28 product brief が明記済み)。
  3. n-gram は逐語一致しか捕まえない。言い換えに対する最後の防衛線は content と security の文面レビュー。
  4. `/opt/ctf/missions/` 以外への COPY は I16 の対象外。Dockerfile の変更に security-engineer レビューを課す既存規律と、V1 の
     `/opt/ctf/` 直下 entry 検査で補う。
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

V1〜V6 は P28-0d の software PR で満たす (**未実装**)。V7 は実機でのみ確認可。

- **V1 build 時の entry-set** (`scripts/check-image-hygiene.sh`。`make build` から fail-closed、CI は `image-hygiene` job):
  `/opt/ctf/missions/` 配下の全 path が `<id>(/fixtures(/.*)?)?` に一致し、全 id に `<id>/fixtures/` があり、リポの各 fixtures
  ファイルが同じ bytes と mode で存在する (双方向)。id 0 件・fixtures 0 件は fail。あわせて `/opt/ctf/` 直下の entry 集合を固定する。
- **V2** `answers.yaml` のキー集合 = catalog の evade id (空は fail)。
- **V3** image 内に各 `expectedFlag` の完全一致が 0 件。
- **V4 deploy 時** (`deploy-user.sh` が呼ぶ既存 assert の 3-8 の隣。全 3 モード): 各 `<id>/` の entry が `fixtures` だけ。shell builtin と
  glob だけで書き、dotfile も列挙する (glob の `*` は拾わない)。ディレクトリ 0 件は fail。fixtures の中身は開かない。
- **V5 Go** (`make test` = required check): `TestFixtures_CarryNoHintOnlyNgrams` が D5 を検査する。走査 0 件と非 UTF-8 は fail。
- **V6 故意違反**: `TestHintLeakChecker_Mutation` (別の課題のヒント文を fixtures に混ぜると赤 / 無料表示にある文は緑 / 14 文字の
  想定解の逐語コピーは赤 / 入力 0 件は赤) と、`README.md` を足した派生 image に V1 が非ゼロで終わる negative test。出力を PR 本文に貼る。
- **V7 実機**: scenario モードと `all` モードで deploy し、V4 が緑で、mission 13 が従来の path で発火して solve すること。

**I16 昇格の条件 (architect: yes, if)**: V1〜V6 が landing する PR と同じ PR で、conventions の表と契約表 (D3) に追記する。先に紙の
ルールを増やさない。V7 は本番投入の前に満たす。CI の `image-hygiene` は required check ではない
(`.github/workflows/ci.yaml:386-387`)。本番経路は `make build` と V4 が守るが、required への昇格は VP / CEO の判断として残す。

## Advice

- qa-engineer (2026-10-04〜05): image の実測 (130 entry・82 本)、welcome.txt とヒント 3 の重複 8 課題、V1〜V3・V5・V6 の原型。
  原型は同一課題内の照合 (n=12)。本 ADR は課題跨ぎ・n=10 に改めた。
- content-engineer (2026-10-04): welcome.txt 14 本と配布文書を整理 (`content/p28-0d-welcome-handbook`、未 push)。同一課題内の
  照合では 10-gram が 0 件。本 ADR の規則 (課題跨ぎ) では汎用句 2 種が残るので、D6 の前にもう 1 回の整理が要る。
- VP (2026-10-04): F1 を既決事項の実装漏れとして撤去へ進める。維持の分岐 (P28-0d') は CEO 決定で消滅。
- security-engineer: **未受領**。Accepted 化の前に必須 (I16 の文言と主張しない範囲、V4 の builtin 制約、残余の受容)。
