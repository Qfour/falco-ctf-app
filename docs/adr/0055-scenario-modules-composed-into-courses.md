# ADR-0055: シナリオをモジュールにし、コースで組み立てる — `scenarios/<id>/scenario.yaml` は module.yaml / course.yaml から生成する物にし、組み合わせの正しさを生成時 (CI) と起動時に機械が確かめる

- Status: **Accepted** (2026-11-25。起草 2026-11-16)
  - Accepted の条件 (すべて満たした): (1) S2 の app PR = S2a #687・S2b-1 #689・S2b-2 #690・S2c #692 が merge された (app main 815e4d1)。(2) V4 (`internal/catalog/module_test.go`・`scenario_test.go`) と V5 (`cmd/gen-scenarios/realtree_test.go`) は `go test ./...` = required の `test` で走り、#692 の merge の時に緑。(3) CTO の承認の記録 (private、ws#117 2026-11-25)。
  - S1 は本 ADR の Accepted を待たない。S1 は今の仕組みの穴を塞ぐだけで、構造を変えないため。
- Date / Deciders: 2026-11-16 / CEO (案 B と 3 層の用語を 2026-11-16 に決定)、CTO (契約表の行)、architect (起草)、security-engineer (S3 の C4、生成器・assert の変更、detect の有効化。いずれも R1)
- 関連: product brief ws#185 (`docs/briefs/ir-scenario.md` §5・§6)、architect の設計提案 (2026-11-16)、REFACTORING.md P27 (P27-1 / P27-2) と新フェーズ (番号は CoS が決める)、ADR-0007 / 0014 / 0026 / 0027 / 0030 / 0033、ADR-0056 (Proposed。調査型の課題と、痕跡束・答え表の注入。C4 (ii)・配置の規則・`requirements.answers` で本 ADR と接する = 0056 D17・D18)

## Context

(Context は起草の時点 = app 7bd5964 の事実で、行番号もその版のもの。S1・S2 の後の姿は D2・D5・D11 に書く)

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
- 両方ある dir、どちらも無い dir は fail (S2c で実装 = `catalog.LoadSource`)。source も生成物も regular file に限り、symlink は拒否する。`scenarios/` の直下の symlink の dir は生成器が拒否する。
- module id と course id は同じ名前空間 (= dir 名) を使う。文法は `internal/catalog/testdata/scenario-name-cases.tsv`。
- `modules/` の top-level dir は作らない。

### D3 module.yaml (strict decode。未知の key は fail。ADR-0030 D1 と同じ規律)

    id:            # dir 名と一致
    title:         # 公開する文 (参加者に表示する経路を作る PR で、同時に hintleak の無料で見える側の集合に入れる。表示しない文を入れると n-gram 検査が緩むので、表示までは入れない)
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
- edition の名前の文法は scenario の名前と同じ (`catalog.ValidScenarioName` = `dnsname.Label` で 54 文字以下)。S2a の review で本 ADR に定義が無いと分かり、scenario の名前の文法を借りた。`playbook` は module の dir の中の file 名 (`/`・`\` を含まず、`.`・`..` でない)。`duration` は handsOnMinutes が 1 以上、debriefMinutes が 0 以上。`requires.modules` に自分自身は書けない。

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
- 生成器は Go で書く。runtime と同じ parser を使い、正は 1 つにする (ADR-0033 D4 と同じ考え方)。make target は `gen-scenarios` と `check-gen-scenarios` (= `gen-scenarios --check`)。どちらも `Dockerfile.gen-scenarios` の中で走り、host の Go を使わない。
- **gen-values より前に走る** (gen-values は生成物の `scenarios/*/scenario.yaml` を読む)。
- 出力の形:

    # GENERATED by gen-scenarios from scenarios/<id>/{module,course}.yaml — DO NOT EDIT
    id:
    title:
    challenges: []         # 平らな一覧。消費者は今のまま
    # tactics は出さない (D6)
    source: {kind: module|course, modules: [{id, version, edition}]}
    requirements: {...}    # S3a から (D6、契約表の (b))

- `challenges` は block の列で出す (1 行に `  - <id>`、行末の comment なし、flow の `[...]` は使わない)。shell / awk で読む消費者 (gen-values・`validate-flags-file.sh`・`assert-flag-isolation.sh`・`deploy-user.sh`) が今の形のまま読めるようにするため。header の comment 行は `challenges:` で始めない。
- S2c で `LoadScenario` を strict decode にした (`catalog.DecodeScenario`。生成器の読み戻しと同じ 1 つの型 `catalog.Scenario` と、同じ decoder)。
  - 受ける key は `id`・`title`・`challenges`・`source` だけ (`requirements` は S3a から)。重複した key、anchor / alias / merge key、2 つ以上の文書も拒否する。
  - file の名前が `scenario.yaml` でないもの、symlink、`id` が dir 名と違うもの、`source.kind` が dir の定義の種類と違うものも拒否する。
- Go の loader は YAML として読むので、flow の形 (`[...]`) の `challenges` も受ける。block の形を守るのは生成器と、`go test ./...` で走る `--check` (commit した file が生成物と byte で一致すること) である。
- 起動時に定義から生成し直して比べることはしない。コースの合成には `scenarios/` の全モジュールが要り、比べるのは CI の `--check` の役目にした。生成物の header の有無も見ない。生成物かどうかは、dir に定義があることで決まる。(この 2 点は S2c で engineer が仮に決め、review で追認した)
- module.yaml も course.yaml も無い dir の手書きの scenario.yaml は fail にする (S2c)。起動時と、生成器の生成・`--check` の両方で fail する。生成器に `--allow-no-source` は無い。
- **golden の内容**: 移行の前後で、3 つの既存 scenario の `id` / `challenges` が完全に一致する。一致の対象は、移行前の一覧を test の中に literal で pin したもの (`cmd/gen-scenarios/realtree_test.go`: id・title・`LoadScored` の順序・scope の digest)。`tactics` は生成物から消える (D6)。差分が出れば、移行 PR の diff として review する (隠さない)。
- **参加者と platform から見て変わらないこと** (golden の外で確かめる): gen-values の生成物 (`challenges/values-all.yaml`・既存 3 本の `challenges/values-scenario-<name>.yaml`・各課題の `values.yaml`) が移行前と byte で一致する (差分は `values-scenario-onboarding.yaml` の追加だけ)。3 つの scope の digest (ADR-0056 B12 の `ScopeDigest`) が、移行前に手で計算して literal で pin した値と一致する。`narrative.yaml`・`debrief.md`・`playbook-2h.md` に差分が無い。

### D6 宣言させず導出するもの (宣言の写しは drift するため)
- `tactics` は生成物に出さない。課題からの導出は `gen-attack-layer.py` の 1 つだけにする (Go に 2 つ目の導出を作ると、Go と Python の parity が新しい drift 源になる)。宣言が無くなるので、宣言との照合の warn と、`attack-coverage.md` の「宣言 tactics」の節は消えた (S2b-2 #690 と S2c #692 で、`gen-attack-layer.py` から宣言を読む経路ごと消した)。
- `requirements` は次を導出する。
  - `detect`: スコープに `type: detect` があるか。
  - `exfil`: スコープに exfil を採点に使う課題があるか。
  - `rules`: スコープの課題の `expectedRules ∪ forbiddenRules` の rule 名の集合。app は default ruleset と customRules の区別を持たない。名前が解決できるかの照合は platform が行う。
  - `answers`: スコープの調査型の課題 id の、並べ替えた集合 (ADR-0056 D17)。A1b (#607) は merge 済みなので、S3a で最初から出す。ADR-0056 の P1b-1b (platform の render gate) がこれを読む。P1b-1b は、調査型の課題を main に置く A7 の前提である。
- **(2026-11-25 追補、決定 = CTO) `plantMountDirs` を `requirements` の項目から外した。** 元の記述 = 上の一覧の `rules` と `answers` の間にあった 1 項目 `` - `plantMountDirs`。 `` (説明の文は無かった)。理由 = 今の code では課題の catalog から導出できず (`plant.sh` の header からしか分からない)、読み手が居ない。要る場合は Signpost 5。
- **形と検査 (S3a で決めた細部)**: 4 つの key を `answers`・`detect`・`exfil`・`rules` の順で必ず書く。一覧は byte 順に並べ、同じ値を 2 回書かない。空の一覧は `[]` の 1 行、空でなければ block の列 (1 行に `    - <値>`。YAML の plain で読めない値だけ double-quote)。`exfil` は `requireExfil: true` の課題が scope にあるか (型を問わない)。導出の関数は 1 つ (`catalog.DeriveRequirements`) で、生成器 (`Compose` / `ComposeSolo`、したがって `--check`) と起動 (`catalog.LoadScored`) が呼ぶ。起動は、scope に Restrict した catalog から導出し直し、file の値と違えば起動しない。scope の catalog だけで導出できるので、D5 の「起動時に定義から生成し直さない」(コースの合成には全モジュールが要る) とは別の検査である。strict decode は、`requirements` の欠落、4 つの key の欠落と null、未知の key・重複・型の違い、並びの乱れと重複、scenario の `challenges` に無い `answers` を拒否する (古い image は `requirements` を未知の key として拒否する = image と app の checkout は同じ SHA)。
- Lv の母数 (= `challenges` の数) と、合計時間 (D7 の C2 の左辺)。
- solo course: module.yaml を持つ dir は、それ自体がモジュール単体のコースになる。生成器が `scenario.yaml` を出すので、course.yaml を宣言させない。

### D7 合成の検査 C1〜C8

| # | 検査 | 場所 | 段階 |
|---|---|---|---|
| C1 | 参照の実在と一意: missions は全部 `challenges/` に実在する (Restrict と同じ fail-closed)。モジュールの中で課題が重複しない。コースの中で課題は 1 回だけ。2 つのモジュールに出る課題は `shared:` に書いた id に限り、先に現れた位置に残す。`shared:` に書いたのに重複していない id も fail。scenario の id = dir 名、全 scenario で一意 | CI (生成器) + 起動時 (生成物の重複を `LoadScenario` が拒否) | 重複の拒否と id は S1、`shared` は S2 |
| C2 | 時間: 選んだ edition の Σ(handsOn + debrief) + intro + closing ≤ `timebox.minutes`。宣言した値どうしの検査で、実測ではない | CI | S3b |
| C3 | `requires` の順序: 前提のモジュールがコースの中で先に置かれている | CI | S3b |
| C4 | 同じ Pod に同居できる: (i) mount dir の属性の一致 (既存。プール全体、C6)、(ii) **plant の書き込み先の file が、プール全体の課題の間で互いに素** (新設。除外表は持たない)。プール全体で検査するので、どの組み合わせでも成り立つ。故意に違反させた fixture で赤になることを恒久 test にする (ADR-0007 V2 と同じ形)。**(ii) は ADR-0056 A5a-1 (app#619) の `check_claims` で実装済み。S3 で再実装しない** | CI (`gen-values --check`)、**R1** | (ii) は済み、(i) は既存 |
| C5 | 採点の独立: I11 の交差 test を、生成した全 scenario に対し、scenario ごとの pin で回す。列挙が 0 件なら fail | CI (`make test`) | S1 |
| C6 | flags は不変: module.yaml・course.yaml・生成物は flags の key を持たない (strict decode)。ADR-0033 D2 のスコープ = 生成物の `Restrict` 後の catalog (変更なし) | CI | S2 |
| C7 | 必要な機能 ⊆ 環境: (起動時) スコープに detect があり `DETECT_RUNNER` が `off` (未設定を含む) なら、scoreboard は exit 1 (`local` は開発の経路として受ける。イベントで `k8s` であることは platform の verify が見る)。(platform) `requirements.rules` の全名が「pin した Falco 版の default ruleset ∪ customRules」で解決する。`detect` なら detectRunner が有効。どちらも課金の前に止める | 起動時 + platform の verify | S3a |
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
- `onboarding` を足すと、生成される scenario が 1 つ増える (`scenarios/onboarding/scenario.yaml`・`challenges/values-scenario-onboarding.yaml`・I11 の pin の行)。名前が 1 つ増えるだけで、既存の名前と path は変わらない。
- モジュールの文は、採点に入るかどうかを書かない (例: `onboarding` の文から「採点に影響しない」を外した)。採点に入るかはコースが決める。モジュールは、自分がどのコースに入るかを知らない (C8 と同じ考え方)。
- 新しい課題の id の採番 (ADR-0056 V45 の帰結): scenario の無い順序 (課題 id の順) でも、調査型より大きい id の evade は置けない。この規則は課題のプール全体にかかる。調査型の課題は大きい番号の帯から採り (推奨 50 以上)、その下を evade・trigger・detect に残す。

### D10 overlay は 3 層 (S4)
- 優先は コース > モジュール > 課題。
- 各層で、課題ごとに丸ごと置き換える (ADR-0014 Consequences の「フィールド単位の静かな部分マージは禁止」を各層で保つ)。
- 解決は生成時に行う。複数のモジュールを組んだコースでは、生成器が平らにした `narrative.yaml` / `quest.yaml` をコースの dir に出す。runtime (`main.go:207-217`) は変えない。
- モジュールの dir では、`narrative.yaml` が source で、solo course もそれを読む (今と同じ)。
- コース層の override の file 名は、生成物と同じ名前にしない (S4 で決める)。
- **既存のコースへの影響 (S4 の PR で明示する)**: `nimbusbreach-with-tutorial` は今 `narrative.yaml` を持たない (scoreboard は scenario の dir の file だけを読む)。モジュールの overlay を平らにして出すと、`nimbusbreach-full` の overlay (3 課題の briefing / bridge) がこのコースにも入り、本番のコースで参加者に見える文が変わる。入れるかどうかは CPO が決める。入れないなら「このコースは narrative を出さない」を golden で固定する。

### D11 段階と各段階の Verification

| 段階 | 内容 | Verification |
|---|---|---|
| **S1 (済み = app#604・platform#331・#688 (V1 の残り = id と dir 名の一致、gen-values での重複の拒否))** | app: I11 の交差 test を全 `scenarios/*` に (C5)、scenario の id と、scenario の中の課題 id の重複を拒否 (C1 の一部)、契約表 (a) の行。platform: 導出の fail-closed (C3 を塞ぐ)。範囲の正は各 PR の本文。本 ADR は V1-V3 の性質だけを求める | V1・V2・V3 |
| **S2 (済み = S2a #687・S2b-1 #689・S2b-2 #690・S2c #692)** | S2a = parser と合成 (`shared` を含む C1、C6)。S2b = 生成器と移行 (module.yaml ×3・course.yaml ×1・golden)。S2c = `LoadScenario` を strict に、source の無い dir を拒否 | V4・V5 |
| S3a (実装中。app の最初の PR は `requirements:` の生成と起動時の照合まで。C7 の `DETECT_RUNNER` の起動時の拒否 (V7) は後続の app の PR。済みにするのは両方と platform の対が入ってから) | 生成物の `requirements:` (D6 の 4 項目 = answers・detect・exfil・rules)、C7 の起動時の拒否、契約表 (b) の行 (両リポ同時。platform の対 = ADR-0056 P1b-1b と V8 の verify) | V7・V8 |
| S3b | C2・C3 (C4 (ii) は ADR-0056 A5a-1 で済み) | V6 |
| S4 | overlay の 3 層 (D10)、C8 | V9 |
| S5 | solo course が全モジュールにあることの CI の規則、local / 常設の runbook (COO) | V10 |

### D12 supersede と amend
- **ADR-0014 (Accepted) を部分 supersede する。** 対象は overlay の 2 層 (課題 → scenario) で、これを 3 層 (課題 → モジュール → コース、生成時に解決) にする。丸ごと置き換える規則は残す。ADR-0014 本文には navigational な pointer だけを足す。
- **ADR-0030 (Proposed) を amend する。** D1 の `scenarios/<name>/quest.yaml` (`0030:79`) を、モジュールの dir の quest.yaml + コース層の override に変え、平らにしたものをコースの dir に出す。範囲の記述 (`0030:133`) の「各 scenarios/*/scenario.yaml」は生成物を指すと読む。0030 の Accepted より前に、0030 に pointer を足す。
- ADR-0033 は変えない。D2 のスコープは生成物の `Restrict` 後で、意味は同じ。

### D13 クロスリポ契約
- **(a)** 「Challenges path」行 (`conventions.md:424`) を直す。S1、両リポ同時 PR。
  - 順序: 両 PR を相互リンクつきで同時に open する。merge は platform → app (行が merge 済みの挙動を記述するように)。
- **(b)** 新しい行「コースの必要な機能」を足す。S3a、両リポ同時 PR。
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
- **R1 の対象**: 生成器と、その出力を採点・仕込みの scope として読む loader の変更 (S1 の残り・S2b・S2c)、C7 の起動時の拒否 (S3a)、overlay の 3 層 (S4。narrative は ADR-0056 B5 の無料の範囲を変える)、module.yaml の公開文を hintleak の集合に入れる変更 (`internal/hintleak/**`。表示の経路と同時)。C4 (ii) は ADR-0056 A5a-1 の R1 で済んだ。
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
5. platform が、コースの plant の mount dir を読む必要が出る (D6 で外した `plantMountDirs`)。先に mount dir を課題の catalog から導出できるようにし (今は `plant.sh` の header だけが持つ)、そのあと `requirements` に足す (契約表の (b) の行と両リポ同時)。
6. scenario が空 (全課題) のとき、platform は課題の定義 (`falco-rule.yaml` の `type:`) を自分で読む = `requirements` の導出が 2 本目になる (契約表の (b) の行)。catalog の型の解釈が変わる、または全課題のときにも platform が `rules` / `detect` を要るようになったら、app が全課題の `requirements` も生成物として出す形に寄せる。それまでは、platform の対の PR で、app の導出 (全 catalog) の `answers` と platform の読み取りを、`APP_PIN` の版で照らす test を持つ。

## Verification
- **V1 (S1)**: scenario の中で課題 id が重複すると、`LoadScenario` と `gen-values --check` の両方が非ゼロになる。id と dir 名の不一致、全 scenario での id の重複も同じ。testdata の負の case を恒久 test にする。
- **V2 (S1)**: I11 の交差 test は `scenarios/*/scenario.yaml` を列挙し、列挙が 0 件なら fail。pin していない交差を持つ合成 scenario (testdata) で赤になる。
- **V3 (S1、platform)**: helmfile が無い / write-values が失敗 / 描画の形が合わない、の 3 つの case で `deploy-event-workspaces.sh` が非ゼロ終了し、払い出しを 1 つもしない。`--challenge` を明示すれば導出を経ない。
- **V4 (S2)**: module.yaml / course.yaml / 生成物に未知の key があれば fail (testdata)。module.yaml と course.yaml を両方持つ dir、どちらも無い dir も fail。
- **V5 (S2)**: `gen-scenarios --check` が required check の job で走る。生成物を 1 byte 手で直したコピーで赤になる。3 つの既存 scenario の `challenges` が、literal で pin した移行前の一覧と一致する。
- **V6 (S3b)**: C2・C3・C4 (ii) に、それぞれ故意の違反 1 件の負の case を置く。C4 (ii) は gen-values の `--check` の内部 fixture で検査する (ADR-0007 V2 と同じ)。C4 (ii) の負の case は ADR-0056 A5a-1 (app#619) の `verify_claims_negative_tests` に既にある (ADR-0056 V42)。S3 で足すのは C2・C3 だけ。
- **V7 (S3a)**: detect を含む scenario で `DETECT_RUNNER=off` なら、scoreboard が非ゼロ終了する (test)。
- **V8 (S3a、platform)**: 生成物の `requirements.rules` から customRules の 1 名を消した環境で、verify が課金の前に止まる。`APP_PIN` の app に `requirements:` が無い ref でも止まる。platform の tree に rule 名の写しが無い (grep 0 件)。
- **V9 (S4)**: 3 層の優先と丸ごとの置き換えの単体 test。範囲外を指す overlay と、外の課題を参照する文で赤になる。
- **V10 (S5)**: module.yaml の集合 ⊆ 生成された scenario の集合 (CI)。runbook の部分は機械の確認が「無し」。

## Advice
- CEO (2026-11-16): 案 B と 3 層の用語、次回は新シナリオ、利用形態の順、capture の録画の決定を 2 課題分だけ開き直す (detect の有効化は R1 が前提)。秘匿は architect と security-engineer が検討する (ADR-0056)。
- product-engineer (brief ws#185 §6、2026-11-16): 利用者の要件 (C8)。「同じ課題は 1 回だけ出す」から、`shared:` の明示を導いた。
- architect (設計提案 2026-11-16): B を推奨。今回 C4 を事実で訂正し、置き場を B2 に詰めた (C9 の境界を動かさないため)。
- security-engineer: S1 の残りと、S2 の生成器・loader の PR で R1 を受けた (#688・#689・#690・#692。判定と条件は private = ws#117)。S3a の C7 と detect の有効化で、また R1 を受ける。
- review (S2a #687・S2c #692): edition の名前の文法が ADR に無い → D3。header を見ない・起動時に生成し直さない (engineer の仮決め) → D5 で追認。symlink と file 名の拒否 → D2・D5。
