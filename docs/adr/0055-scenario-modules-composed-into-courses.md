# ADR-0055: シナリオをモジュールにし、コースで組み立てる — `scenarios/<id>/scenario.yaml` は module.yaml / course.yaml から生成する物にし、組み合わせの正しさを生成時 (CI) と起動時に機械が確かめる

- Status: **Proposed** (起草 2026-11-16)
  - Accepted の条件: (1) S2 の app PR が merge されている、(2) V4・V5 が required check の上で緑、(3) CTO の承認の記録 (private) がある。
  - S1 は本 ADR の Accepted を待たない。S1 は今の仕組みの穴を塞ぐだけで、構造を変えないため。
- Date / Deciders: 2026-11-16 / CEO (案 B と 3 層の用語を 2026-11-16 に決定)、CTO (契約表の行)、architect (起草)、security-engineer (S3 の C4、生成器・assert の変更、detect の有効化。いずれも R1)
- 関連: product brief ws#185 (`docs/briefs/ir-scenario.md` §5・§6)、architect の設計提案 (2026-11-16)、REFACTORING.md P27 (P27-1 / P27-2) と新フェーズ (番号は CoS が決める)、ADR-0007 / 0014 / 0026 / 0027 / 0030 / 0033、ADR-0056 (予定。回答型と、痕跡束・答え表の注入)

## Context

### C1 scenario が持つもの
- 持つのは `id` / `title` / 順序付きの `challenges` だけ (`internal/catalog/scenario.go:13-17`)。
- decode は strict でない (`scenario.go:26`)。`tactics:` は Go が読み捨てる。
- `Restrict` は map に詰めるので、同じ課題 id が 2 回あっても黙って 1 つに潰れる (`scenario.go:38-49`)。一方、順序の側は `LoadScored` が `sc.Challenges` をそのまま `Order` にする (`internal/catalog/flags.go:41-66`)。その結果、重複は採点の順序には残る。
- scenario の id と dir 名の一致も、全 scenario の中で id が一意であることも、検査していない。

### C2 消費者が 6 つあり、それぞれ同じ一覧を別々に読む
- scoreboard: `SCENARIO_FILE` → `LoadScored` (`flags.go:41-66`)。物語は scenario の dir の `narrative.yaml` から読む (`cmd/scoreboard/main.go:207-217`)。
- 仕込み: `challenges/gen-values.sh` が awk で `challenges:` を抜き出し (`gen-values.sh:245-260`)、`values-scenario-<name>.yaml` を生成する (`:502-520`)。
- そのほか: `deploy-user.sh scenario:<name>`、`assert-flag-isolation.sh`、`scripts/gen-attack-layer.py` (`tactics:` は助言扱いで、課題から導出した値との drift を warn するだけ。`:22-24,361-372`)、platform の sed による逆解析 (C3)。
- image に焼き込む (`scoreboard/Dockerfile:24-25`)。新しい scenario を足すには、image の再 build と platform の `appImageTag` の bump が要る (platform `helmfile/environments/prod.yaml.gotmpl:128,140`)。

### C3 platform の導出が fail-open になっている
- `deploy-event-workspaces.sh` は描画した `scenarioFile` の path を sed で逆解析する (`:388`)。
- 失敗しても warning だけで、`--challenge` は `all` のまま進む (`:369-373` のコメント、`:385`)。結果として全課題を仕込み、全課題を見せる。P27-1 で塞いだ公平性の穴と同じ種類である。

### C4 1 イベントは 1 scenario が前提になっている
- platform の env 値は `scoreboardScenario` の 1 つだけ (`prod.yaml.gotmpl:140`)。scoreboard は 1 インスタンス (I1)。
- store の主キーは `(user, challenge)` で、scenario の次元が無い (`docs/db-schema.md:107-111`)。
- 組み合わせは手書きの複製で作っている。`nimbusbreach-with-tutorial` は 00 の後に `nimbusbreach-full` の 01-10 を写している (両 `scenario.yaml`)。`tutorial-intro` は 00 / 01 / 03 で、01 と 03 は `nimbusbreach-full` と重なる。

### C5 I11 の交差 test が 1 scenario に固定されている
- `TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules` は `nimbusbreach-full` の順序だけを読む (`internal/catalog/catalog_test.go:429-437`)。
- 他の scenario で、先行する trigger と後続の evade の交差が新しく生じても赤にならない。

### C6 plant の同居の現状 (事実。前回の提案の仮説を訂正する)
- **mount dir の属性の衝突は、課題のプール全体で検査済み。** gen-values は plant.sh を持つ全課題について、mount dir ごとに seed-source と readOnly の一致を確かめ、食い違えば exit 1 する (`gen-values.sh:340-367`)。検査は scenario と無関係なので、どの組み合わせでもこの検査は満たされる。
- **plant の実行順は、コースの順ではなく課題 id のソート順。** scenario の範囲でも同じ (`:376-377,481-487`)。
- **同じ file を 2 つの plant.sh が書くことは検査していない。** 2-5 の検査は「書き込み先が seed root の内側か」だけを見る (`:535-549`)。
- 今は 03 と 10 が同じ dir `/opt/nimbus/vault` を共有している。書く file は別で、03 が `creds.recover`、10 が `master.key` (`challenges/03-stealth-read/plant.sh:1-2,56`、`challenges/10-final-exfil/plant.sh:1-2,44`)。
- `gen-values.sh:319` のコメントは「03 と 10 が /etc/shadow を共有」と書いており、実態と合わない (古い。follow-up LOW)。
- 前回の提案は「同じ file を 2 本が書けば fail (生成器の今の扱いは仮説)」としていた。正しくは「検査が無い」である。

### C7 CEO の決定 (2026-11-16)
- 案 B (module.yaml + course.yaml、`scenario.yaml` は生成物) と 3 層の用語を採用する。
- 次回イベントは新シナリオで組む (防御側の流れ、2 時間枠)。
- 利用形態の優先順は イベント → 研修 → 自習 → デモ。
- 2026-08-31 の「detect 用の capture を録画しない」(`REFACTORING.md:35-39`) を、新シナリオの 2 課題分に限って開き直す。detect の有効化は R1 が前提 (`docs/detect-challenge-design.md:3-5`)。prod の値は今 `detectRunner: "off"` (`prod.yaml.gotmpl:166`)。

### C8 product の要件 (brief §6)
- モジュールは自己完結する。付帯情報 (時間・前提・学習成果・難易度・必要な機能) を持つ。
- 外の課題を参照しない。
- コースでは、課題を 1 回だけ出す、前提の順序を守る、合計時間が枠に収まる。
- 既存の killchain の 01→10、物語、★ を変えない。
- ヒントの lock の解除 (brief §6.3 は「未確認」としている) は ADR-0027 で Accepted・実装済み (`docs/adr/0027-hint-gate-decoupled-from-current.md:3`)。

### C9 置き場とオーナーシップ
- content-engineer の path は `falco-ctf-app/{challenges,scenarios,docs-site}` (workspace `ORGANIZATION.md:198`)。
- hintleak・sourcehygiene の対象 path は `scenarios/*` の file を含む (ADR-0030 Context の `scenarios/nimbusbreach-full/debrief.md`)。
- 新しい top-level dir を作ると、統治文書 (CEO だけが変更できる) と R1 対象の機械 (`internal/hintleak/**`) の両方の path を動かすことになる。

### C10 既存の決定との関係
- 「課題 = 再利用する技術の単位、scenario = 並びと物語の包み」(P27) の 1 段上に、モジュールを置く。
- 課題をプールに置く決定は変えない。
- flags はイベント × 課題 id で回す (ADR-0033、契約表の Flags 行 `.claude/rules/falco-ctf-app-conventions.md:432`)。モジュールとは独立である。

## Options

### A: 今の scenario.yaml をモジュールとみなし、組み合わせは手書きの複合 scenario にする
- 変更点: なし。
- コスト: 最小。
- リスクと可逆性: 一覧の複製が drift する (既に 1 件ある = C4)。組み合わせの検査が無い。可逆。
- 効き始める閾値: 1 イベントに書き下ろしの 1 本しか無い間だけ。

### B: module.yaml と course.yaml を source にし、`scenario.yaml` を生成する
- 変更点: source を 2 種類にし、平らな `challenges:` を持つ `scenario.yaml` を生成物にする。
- コスト: Go の parser が 1 つ、生成器、合成の検査 C1-C8。
- リスクと可逆性: 消費者 6 つ (C2) が読む path と形は変わらない。生成物を手書きに戻せば元に戻るので、可逆性は高い。
- 効き始める閾値: 2 本目のモジュール。新シナリオで既に該当する。

### C: モジュールが自分の課題を持つ。app の外のモジュール源も許す
- 変更点: 課題の path・fixtures・Dockerfile・I16 を全部移す。
- コスト: 大。
- リスクと可逆性: 課題をプールに置く決定に反する。外部のモジュール源は I6 と公開境界に反する。不可逆。
- 効き始める閾値: Signpost 4。

### B の中の置き場 (B1 / B2)
- B1 = `modules/<id>/module.yaml` を新設する。
- B2 = `scenarios/<id>/module.yaml` に置く (モジュールの dir = そのモジュール単体のコースの dir)。
- B2 は path の契約・オーナーシップ・hintleak の対象 path・docs-site の参照を 1 つも動かさない (C9)。
- B2 で既存の `nimbusbreach-full/` と `tutorial-intro/` は、file を 1 つも移さずに、`module.yaml` を足すだけでモジュールになる。
- 代償: 1 つの dir に source と生成物が並ぶ。生成物の header と `--check` で補う。

## Decision

**B を、置き場 B2 で採る。** 理由: 契約の面 (path・deploy のモード・flags) を動かさずに、再利用の単位と機械による合成の検査を足せる。B2 は、境界 (統治文書・R1 の対象 path) を動かさない。

### D1 用語は 3 層にする
- **課題 (challenge)**: `challenges/<id>/`。再利用するプール (今のまま)。
- **モジュール (module)**: 自己完結した学習単位 (CEO の言う「シナリオ」)。
- **コース (course)**: モジュールを並べたイベント構成。
- **`scenario` は実行時の名前として残す。** 意味は「コースを平らにした生成物」。`scenario.yaml`、`SCENARIO_FILE`、`scenario:<name>`、`scoreboardScenario` は改名しない (契約の名前を変えない)。
- 文書と UI では、モジュールとコースの語を使う。

### D2 source の置き場と名前空間
- `scenarios/<id>/` の dir 1 つは、次のどちらか 1 つを持つ。
  - `module.yaml`: そのモジュールと、モジュール単体のコース (solo course)。
  - `course.yaml`: 複数のモジュールを組んだコース。
- 両方ある dir、どちらも無い dir (S2 の後) は fail。
- module id と course id は同じ名前空間 (= dir 名) を使う。文法は `internal/catalog/testdata/scenario-name-cases.tsv`。
- `modules/` の top-level dir は作らない。

### D3 module.yaml (strict decode。未知の key は fail。ADR-0030 D1 と同じ規律)

    id:            # dir 名と一致
    title:         # 公開する文 (hintleak で、無料で見える側の集合に入れる)
    summary:       # 同上
    outcomes: []   # 観測可能な学習成果 3〜5 個 (同上)
    version:       # 整数 >= 1。missions または意味が変わったら上げる
    level:         # 1..5 (既存の ★ に揃える。閉じた範囲)
    duration: {handsOnMinutes, debriefMinutes}
    editions:      # 任意。<name>: {handsOnMinutes, debriefMinutes, playbook: <file>}
    requires: {modules: []}   # コースの中で先に置くモジュール
    missions: []   # プール (challenges/) の参照。順序付き

- 既存の `playbook-2h.md` は `nimbusbreach-full` の edition `2h` の playbook になる。
- **edition は時間と台本だけを変える。課題の範囲は変えない** (範囲が変わる版が要るなら Signpost)。

### D4 course.yaml (strict decode)

    id:
    title:
    timebox: {minutes, introMinutes, closingMinutes}
    modules:            # 順序付き
      - id: <module id>
        edition: <name> # 任意。無ければ duration を使う
    shared: []          # 任意。2 つのモジュールが含む課題 id を明示する (D7 の C1)

- コースは flags・課題・ヒントを持たない。持たせようとすると strict decode が拒否する (= C6)。

### D5 `scenario.yaml` は生成物。golden test で固定する
- 生成器は Go で書く。runtime と同じ parser を使い、正は 1 つにする (ADR-0033 D4 と同じ考え方)。make target は `gen-scenarios` と `gen-scenarios --check`。
- **gen-values より前に走る** (gen-values は生成物の `scenarios/*/scenario.yaml` を読む)。
- 出力の形:

    # GENERATED by gen-scenarios from scenarios/<id>/{module,course}.yaml — DO NOT EDIT
    id:
    title:
    challenges: []         # 平らな一覧。消費者は今のまま
    tactics: []            # 導出 (D6)
    source: {kind: module|course, modules: [{id, version, edition}]}
    requirements: {...}    # S3 から (D6、契約表の (b))

- S2 で `LoadScenario` を strict decode にする。上の key だけを受け付ける。
- S2 の後に module.yaml も course.yaml も無い dir の手書きの scenario.yaml は fail にする。
- **golden の内容**: 移行の前後で、3 つの既存 scenario の `id` / `challenges` が完全に一致する。一致の対象は、移行前の一覧を test の中に literal で pin したもの。`tactics` は導出に変わる。差分が出れば、移行 PR の diff として review する (隠さない)。

### D6 宣言させず導出するもの (宣言の写しは drift するため)
- `tactics` は課題から導出する。`gen-attack-layer.py` が既に導出している exercised tactics と同じ導出で、warn は構造的に消える。
- `requirements` は次を導出する。
  - `detect`: スコープに `type: detect` があるか。
  - `exfil`: スコープに exfil を採点に使う課題があるか。
  - `rules`: スコープの課題の `expectedRules ∪ forbiddenRules` の rule 名の集合。app は default ruleset と customRules の区別を持たない。名前が解決できるかの照合は platform が行う。
  - `plantMountDirs`。
  - `answers`: ADR-0056 の型の課題 id。ADR-0056 が Accepted になってから足す。
- Lv の母数 (= `challenges` の数) と、合計時間 (D7 の C2 の左辺)。
- solo course: module.yaml を持つ dir は、それ自体がモジュール単体のコースになる。生成器が `scenario.yaml` を出すので、course.yaml を宣言させない。

### D7 合成の検査 C1〜C8

| # | 検査 | 場所 | 段階 |
|---|---|---|---|
| C1 | 参照の実在と一意: missions は全部 `challenges/` に実在する (Restrict と同じ fail-closed)。モジュールの中で課題が重複しない。コースの中で課題は 1 回だけ。2 つのモジュールに出る課題は `shared:` に書いた id に限り、先に現れた位置に残す。`shared:` に書いたのに重複していない id も fail。scenario の id = dir 名、全 scenario で一意 | CI (生成器) + 起動時 (生成物の重複を `LoadScenario` が拒否) | 重複の拒否と id は S1、`shared` は S2 |
| C2 | 時間: 選んだ edition の Σ(handsOn + debrief) + intro + closing ≤ `timebox.minutes`。宣言した値どうしの検査で、実測ではない | CI | S3 |
| C3 | `requires` の順序: 前提のモジュールがコースの中で先に置かれている | CI | S3 |
| C4 | 同じ Pod に同居できる: (i) mount dir の属性の一致 (既存。プール全体、C6)、(ii) **plant の書き込み先の file が、プール全体の課題の間で互いに素** (新設。除外表は持たない)。プール全体で検査するので、どの組み合わせでも成り立つ。故意に違反させた fixture で赤になることを恒久 test にする (ADR-0007 V2 と同じ形) | CI (`gen-values --check`)、**R1** | S3 |
| C5 | 採点の独立: I11 の交差 test を、生成した全 scenario に対し、scenario ごとの pin で回す。列挙が 0 件なら fail | CI (`make test`) | S1 |
| C6 | flags は不変: module.yaml・course.yaml・生成物は flags の key を持たない (strict decode)。ADR-0033 D2 のスコープ = 生成物の `Restrict` 後の catalog (変更なし) | CI | S2 |
| C7 | 必要な機能 ⊆ 環境: (起動時) スコープに detect があり `DETECT_RUNNER` が `k8s` でなければ、scoreboard は exit 1。(platform) `requirements.rules` の全名が「pin した Falco 版の default ruleset ∪ customRules」で解決する。`detect` なら detectRunner が有効。どちらも課金の前に止める | 起動時 + platform の verify | S3 |
| C8 | 参照の閉包: overlay (narrative / quest) の entry が、そのモジュール・コースの外の課題を指せば fail。モジュールの参加者に見える文が外の課題を参照すれば fail (P27-2 の検査をモジュールの範囲に広げる) | CI + 起動時 | S4 |

### D8 score はコースごとに分ける
- 1 コースにつき scoreboard と DB を 1 つ (I1、store の主キー)。
- 範囲を変える再 deploy (同じ DB でコースを差し替える) は正規の運用にしない。I13a に依存し、I13a はまだ昇格していないため。
- コースの中で、あるモジュールが他のモジュールが Pod に残した状態に依存しないことを、module の規則にする。
- コースを 1 回 deploy するのが正規 (ADR-0027 の free browsing)。

### D9 移行 (file の移動なし)
- `nimbusbreach-full/` と `tutorial-intro/` に module.yaml を足す。
- 新設: `onboarding/` (module。missions = `[00-tutorial]`)。
- `nimbusbreach-with-tutorial/` は course.yaml (`modules: [onboarding, nimbusbreach-full]`) になる。生成される `challenges` は今の 00..10 と一致する (D5 の golden)。
- `narrative.yaml`、`debrief.md`、`playbook-2h.md`、`attack-coverage.md` は今の場所のまま。
- platform の `scoreboardScenario: "nimbusbreach-with-tutorial"` は値・path とも変わらない。

### D10 overlay は 3 層 (S4)
- 優先は コース > モジュール > 課題。
- 各層で、課題ごとに丸ごと置き換える (ADR-0014 Consequences の「フィールド単位の静かな部分マージは禁止」を各層で保つ)。
- 解決は生成時に行う。複数のモジュールを組んだコースでは、生成器が平らにした `narrative.yaml` / `quest.yaml` をコースの dir に出す。runtime (`main.go:207-217`) は変えない。
- モジュールの dir では、`narrative.yaml` が source で、solo course もそれを読む (今と同じ)。
- コース層の override の file 名は、生成物と同じ名前にしない (S4 で決める)。

### D11 段階と各段階の Verification

| 段階 | 内容 | Verification |
|---|---|---|
| **S1 (実装中)** | app: I11 の交差 test を全 `scenarios/*` に (C5)、scenario の id と、scenario の中の課題 id の重複を拒否 (C1 の一部)、契約表 (a) の行。platform: 導出の fail-closed (C3 を塞ぐ)。範囲の正は各 PR の本文。本 ADR は V1-V3 の性質だけを求める | V1・V2・V3 |
| S2 | module.yaml / course.yaml、生成器、golden、`LoadScenario` を strict に、`shared` | V4・V5 |
| S3 | C2・C3・C4 (ii)・C7、契約表 (b) | V6・V7・V8 |
| S4 | overlay の 3 層 (D10)、C8 | V9 |
| S5 | solo course が全モジュールにあることの CI の規則、local / 常設の runbook (COO) | V10 |

### D12 supersede と amend
- **ADR-0014 (Accepted) を部分 supersede する。** 対象は overlay の 2 層 (課題 → scenario) で、これを 3 層 (課題 → モジュール → コース、生成時に解決) にする。丸ごと置き換える規則は残す。ADR-0014 本文には navigational な pointer だけを足す。
- **ADR-0030 (Proposed) を amend する。** D1 の `scenarios/<name>/quest.yaml` (`0030:79`) を、モジュールの dir の quest.yaml + コース層の override に変え、平らにしたものをコースの dir に出す。範囲の記述 (`0030:133`) の「各 scenarios/*/scenario.yaml」は生成物を指すと読む。0030 の Accepted より前に、0030 に pointer を足す。
- ADR-0033 は変えない。D2 のスコープは生成物の `Restrict` 後で、意味は同じ。

### D13 クロスリポ契約
- **(a)** 「Challenges path」行 (`conventions.md:424`) を直す。S1、両リポ同時 PR。
  - 順序: 両 PR を相互リンクつきで同時に open する。merge は platform → app (行が merge 済みの挙動を記述するように)。
- **(b)** 新しい行「コースの必要な機能」を足す。S3、両リポ同時 PR。
  - 順序: app (生成物に `requirements:` + 行) → platform (verify。`APP_PIN` を app の merge commit 以後に bump、ADR-0054 B2-5a/5b と同じ型)。
- **(c)** Flags 行は変えない。

## Consequences
- **諦めたもの**:
  - scenario.yaml の手編集。編集は module.yaml / course.yaml を直して `make gen-scenarios` を走らせる。
  - 1 つの dir に source と生成物が並ぶ (B2 の代償)。
  - edition で課題の範囲を変えること。
  - 1 イベントで複数のコースを同時に採点すること (D8)。
- **新たに守る規則**: 規則は 2 つある。
  - 「`scenarios/*/scenario.yaml` は生成物」。V5 が required check に載るまでは Hard Invariant に昇格しない。昇格の条件 = V5 が required の上で 2 イベント緑。
  - C4 (ii) の「plant の書き込み先の file が互いに素」。gen-values の `--check` が機械強制する。
- **Hard Invariant への影響**: 違反なし。
  - 新しい image は無い (I5)。モジュールは app の scenarios/ (I6)。I12 / I16 は平らな一覧を読むので変わらない。C5 は I11 の強化。I13a には依存しない。
- **R1 の対象**: C4 の生成器・assert の変更 (S3)、module.yaml の公開文を hintleak の集合に入れる変更 (`internal/hintleak/**`)。
- **runbook**:
  - 新コースのチェックリスト: course.yaml → `make gen-scenarios` → `make gen-values` → image の再 build → `appImageTag`。
  - platform: 導出に失敗すると非ゼロ終了する。`--challenge` の明示は従来どおり優先。
  - S5 の local / 常設の手順は COO。
- **follow-up (LOW)**: `gen-values.sh:319` の古いコメント (/etc/shadow)。

## Signposts
1. 課題 id が 80 件を超える (文法 `^[0-9]{2}-` の上限は 100。ADR-0041 の再訪)。
2. 同じ Pod に同居できないモジュールの組がコースに要る (同じ file、別の NetworkPolicy、同名 rule の別条件)。1 seat に複数 Pod を置く設計に進む。
3. 1 cluster で 2 つ以上のコースを同時に常設したい (研修の複数 cohort など)。store の次元と I1 の再訪。
4. app の外 (非公開・第三者) でモジュールを書く要求が持続する (I6 と公開境界の再訪。ADR-0056 の秘匿の S3 案が要ると判定された場合を含む)。

## Verification
- **V1 (S1)**: scenario の中で課題 id が重複すると、`LoadScenario` と `gen-values --check` の両方が非ゼロになる。id と dir 名の不一致、全 scenario での id の重複も同じ。testdata の負の case を恒久 test にする。
- **V2 (S1)**: I11 の交差 test は `scenarios/*/scenario.yaml` を列挙し、列挙が 0 件なら fail。pin していない交差を持つ合成 scenario (testdata) で赤になる。
- **V3 (S1、platform)**: helmfile が無い / write-values が失敗 / 描画の形が合わない、の 3 つの case で `deploy-event-workspaces.sh` が非ゼロ終了し、払い出しを 1 つもしない。`--challenge` を明示すれば導出を経ない。
- **V4 (S2)**: module.yaml / course.yaml / 生成物に未知の key があれば fail (testdata)。module.yaml と course.yaml を両方持つ dir、どちらも無い dir も fail。
- **V5 (S2)**: `gen-scenarios --check` が required check の job で走る。生成物を 1 byte 手で直したコピーで赤になる。3 つの既存 scenario の `challenges` が、literal で pin した移行前の一覧と一致する。
- **V6 (S3)**: C2・C3・C4 (ii) に、それぞれ故意の違反 1 件の負の case を置く。C4 (ii) は gen-values の `--check` の内部 fixture で検査する (ADR-0007 V2 と同じ)。
- **V7 (S3)**: detect を含む scenario で `DETECT_RUNNER=off` なら、scoreboard が非ゼロ終了する (test)。
- **V8 (S3、platform)**: 生成物の `requirements.rules` から customRules の 1 名を消した環境で、verify が課金の前に止まる。`APP_PIN` の app に `requirements:` が無い ref でも止まる。platform の tree に rule 名の写しが無い (grep 0 件)。
- **V9 (S4)**: 3 層の優先と丸ごとの置き換えの単体 test。範囲外を指す overlay と、外の課題を参照する文で赤になる。
- **V10 (S5)**: module.yaml の集合 ⊆ 生成された scenario の集合 (CI)。runbook の部分は機械の確認が「無し」。

## Advice
- CEO (2026-11-16): 案 B と 3 層の用語、次回は新シナリオ、利用形態の順、capture の録画の決定を 2 課題分だけ開き直す (detect の有効化は R1 が前提)。秘匿は architect と security-engineer が検討する (ADR-0056)。
- product-engineer (brief ws#185 §6、2026-11-16): 利用者の要件 (C8)。「同じ課題は 1 回だけ出す」から、`shared:` の明示を導いた。
- architect (設計提案 2026-11-16): B を推奨。今回 C4 を事実で訂正し、置き場を B2 に詰めた (C9 の境界を動かさないため)。
- security-engineer: 未受領。S3 の C4 と生成器、detect の有効化で R1 を受ける。
