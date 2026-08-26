# ADR-0014: journey narrative を課題ローカルからシナリオ所有のオーバーレイへ分離する

- Status: **Accepted** (2026-08-26 — implementation landed, Verification items 1-3 satisfied; see below)
- Date: 2026-08-26
- Deciders: VP (起票), architect (技術提案), product-engineer (シナリオ単位定義との整合が前提)
- 関連: REFACTORING.md P27 (challenge シナリオ体系の再構築)。新規 ADR — 他 ADR を supersede しない。

## Context

`internal/catalog/journey.go:9` の schema コメントは journey.yaml を「content
contract — changing it requires VP approval」と明記している。現行
`challenges/*/journey.yaml` の `briefing`/`bridge` は 01→10 という単一 killchain
シナリオ (`scenarios/nimbusbreach-full`) を前提に直接連鎖している:

- `challenges/03-stealth-read/journey.yaml:8` — 「Mission 02 で正面から /etc/shadow を
  読んだら盛大に検知された」(02 を解いた前提)
- `challenges/04..09/journey.yaml` の `bridge:` フィールド全件 — 次ミッションの手口を
  名前で予告する連鎖
- `challenges/10-final-exfil/README.md:15-24` — 10 は 01-09 の知識を前提にした capstone

`scenario.yaml` によるメンバーシップ/順序の再構成自体は
`cmd/scoreboard/main.go:138-156` / `internal/catalog/scenario.go:38-48` の
`Restrict()` で既に技術的に成立している (`11-cloud-cred-hunt` がこの型の実証例)。
しかし物語文はこの機構を知らずに書かれているため、01-10 以外の部分集合・順序を
選ぶと矛盾が生じる。**既に実害がある**: `scenarios/tutorial-intro` (00,01,03) は
02 を含まないが、03 の briefing は 02 前提の文言のままである。

CEO 方針 (今後シナリオを増やし、イベントごとに自由に組み合わせる) と
`scenarios/README.md:18-20` の現行宣言 (「Scenarios keep that ascending order —
never reorder」) は衝突している。

## Options

1. **現状維持 (物語は課題ローカルのみ)**
   コスト: 低 (変更なし)。リスク: 新シナリオを作るたびに journey.yaml を手で書き換える
   運用負荷が発生し、機械化されないため実質「新シナリオを作らない」選択に収束する。
   効き始める閾値: シナリオが2個を超えた時点で既に発生している (tutorial-intro で実測済み)。

2. **journey.yaml に中立層とシナリオ override 層を導入 (推奨)**
   `briefing`/`bridge` を課題ローカルの中立版として残しつつ、`scenarios/<name>/` 側に
   `challengeId -> {briefing, bridge}` の追加オーバーレイ (additive, nullable) を持たせ、
   存在する場合は課題ローカル版を明示的に置き換える (静かな部分マージは禁止)。
   既存 journey.yaml は無変更で fallback として動作する (後方互換、破壊的移行なし)。
   コスト: 中 (`LoadJourneys` に precedence ロジックを追加、既存 9 ファイルの briefing
   冒頭 1-2 文を中立化)。リスク: 中 (スキーマが2枚になり認知負荷が上がるが可逆)。

3. **物語を完全に scenario 側へ移管 (課題は技術記述のみ)**
   コスト: 高 (既存9ファイルの物語をシナリオ側へ移植)。リスク: 高 (課題単体 launch 時や
   docs-site 生成時にブリーフィングが失われる経路がある可能性、未検証)。

## Decision

**Option 2。**

理由: 既存投資 (9件の journey.yaml、`nimbusbreach-full` の物語) を破棄せず、後方互換を
保ったまま「シナリオが物語を選べる」余地を追加できる最小の変更。Option 1 は CEO の
新方針と直接矛盾する現状維持であり、Option 3 は検証されていないリスクを負う割に
Option 2 と得られる自由度がほぼ同じ。

## Consequences

- 何を諦めたか: 「1ファイルだけ見れば全体像が分かる」単純さ。読者は課題ローカル
  fallback とシナリオ override の2層の precedence を理解する必要がある。
- 新たに守る invariant: シナリオ override が存在する場合、課題ローカルの
  briefing/bridge は無視される (明示 override。フィールド単位の静かな部分マージは禁止)。
- 既存 01-10 の journey.yaml briefing 冒頭の他ミッション直接参照 (9件) は中立化する
  (P27-2)。中立化後も `nimbusbreach-full` は自身の `bridge` 連鎖を override として
  持てるので、看板シナリオとしての物語の強さは損なわれない。
- runbook への影響: 新規シナリオ作成チェックリストに「narrative override が無い場合、
  fallback の briefing が他ミッションを参照していないか grep で確認する」を追加する
  (P27-2 で実施)。

## Signposts (この決定を覆す観測可能な信号)

- シナリオが3個を超えても narrative override を書いたシナリオが0件のまま
  (= 誰も使わない機構だった) → Option 1 相当へ撤回し、override 機構を削除する。
- `LoadJourneys` の precedence ロジックが原因で本番起動が1回でも fail-loud した
  → 複雑さがコストに見合っていないので Option 3 (完全分離) へ倒す。
- product-engineer のシナリオ単位定義が「物語不要 (technique-only pool のみ)」と
  結論した → 本 ADR 自体を Rejected にする。

## Verification

**実測結果 (2026-08-26, feat/p27-2-journey-narrative-overlay, software-engineer)**:

格納場所は `scenarios/<name>/narrative.yaml` (新設ファイル。`scenario.yaml` は
無変更) を選択。実装は `internal/catalog/narrative.go`
(`Narrative`/`NarrativeOverride`/`LoadNarrative`/`ApplyNarrativeOverrides`)。
`cmd/scoreboard/main.go` が `LoadJourneys` の直後に
`LoadNarrative(filepath.Dir(scenarioFile)+"/narrative.yaml")` →
`ApplyNarrativeOverrides` を呼ぶ (scenario 未指定時は呼ばない)。

1. **override 適用時に課題ローカル版を完全に無視すること (単体テスト)**: 満たした。
   `internal/catalog/narrative_test.go` の
   `TestApplyNarrativeOverrides_ReplacesLocalWholesale` が
   briefing/bridge 両方が課題ローカルの文言 (Mission 02 / 04 への参照) を含まず
   override 値に置き換わることを確認。`TestApplyNarrativeOverrides_OmittedBridgeIsClearedNotFallback`
   が「フィールド単位の静かな部分マージ禁止」を反対側から証明: override が
   `bridge` を省略すると `""` にクリアされ、課題ローカルの bridge へは
   フォールバックしない。`go test ./internal/catalog/... -run Narrative -v`
   で該当 8 テストすべて PASS (下記 make test ログに包含)。
2. **override 未指定の既存シナリオ (`nimbusbreach-full`) の挙動が変化しないこと (回帰)**:
   満たした。`TestApplyNarrativeOverrides_NoOverride_ExistingScenariosUnaffected`
   (合成 journey で `reflect.DeepEqual` により無変化を確認) と、実物の
   `challenges/`+`scenarios/` ツリーを読む
   `TestTutorialIntroNarrative_ResolvesMission02Contradiction` の後半
   (`nimbusbreach-full` は `narrative.yaml` を持たないため、override 適用後も
   03 の briefing が元の "Mission 02" 文言を保持していることを assert) の
   両方で確認。既存の `TestLoadJourneys_*` 8 件・`scenario_test.go` の既存テストも
   無改変で green (回帰無し)。
3. **`tutorial-intro` で 03 の briefing 矛盾が解消されること (実機/テストで確認)**:
   満たした。`scenarios/tutorial-intro/narrative.yaml` を新設し
   `03-stealth-read` の briefing/bridge を「Mission 02」に触れない文言へ置換
   (9 課題全体の中立化は content-engineer の別 PR (P27-2 後半) に委ねる、
   これは機構実証用の最小フィクスチャ)。
   `TestTutorialIntroNarrative_ResolvesMission02Contradiction` が
   `LoadScenario` → `Restrict` → `LoadJourneys` → `LoadNarrative` →
   `ApplyNarrativeOverrides` を実際の main.go 配線と同じ順で再生し、
   tutorial-intro 側の 03 briefing に "Mission 02" が含まれないことを確認
   (テスト内の premise チェックが、課題ローカル版が依然 "Mission 02" を含む
   ことも確認しているので、override が実際に効いていることを両側から証明)。
4. Hard Invariant への昇格は行わない — 本 ADR は journey.yaml の schema 変更のみで、
   `.claude/rules/falco-ctf-app-conventions.md` への追記対象ではない (変更なし)。

**`make test` (Dockerfile.test, `go vet ./...` + `go test ./... -count=1`)**:
全パッケージ green (`internal/catalog` 含む、既存 `internal/scoreboard/apispec_parity_test.go`
`cmd/scoreboard` テストも green — I14 の mux ⇔ spec 一致に影響なしを確認)。

## Advice

- product-engineer: シナリオ単位の定義 (何が1シナリオの最小要件か) が本 ADR の
  override スキーマを制約しないよう additive に設計した。シナリオ単位定義が
  variantとして「物語なしの technique プール」を選ぶ場合でも、override を単に
  使わなければ済む (2026-08-26)。
