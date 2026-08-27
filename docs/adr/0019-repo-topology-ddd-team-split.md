# ADR-0019: リポジトリ構成は「2 リポ + ディレクトリ境界の DDD」を維持し、サービス単位への物理分割は採らない

- Status: **Proposed** (2026-08-27, architect 起案 → VP 検証待ち。CEO 相談への回答として architect が起案)
- Date / Deciders: 2026-08-27 / architect 起案、VP 承認 (時限自動承認: 1 往復 objection 無ければ Accepted)
- 関連: CEO → VP 経由の設計相談 (2026-08-27)。ORGANIZATION.md §1-3、REFACTORING.md「決定事項」、
  Hard Invariant I5/I6、`.github/CODEOWNERS`、GITHUB-OPS.md G1

## Context

CEO から 4 点の要求が来た: (1) 誰が clone しても同じ開発環境で進められること、
(2) コンポーネント単位でチーム/AI エージェントを分割できる構成、(3) DDD の推進、
(4) ORGANIZATION.md の 11 職と整合する組織づくり。

**既存の「決定事項 (再議論しない)」との関係** (`REFACTORING.md:10-32`):
- `REFACTORING.md:12` 「2 リポ分割は維持。境界は公開キット(app)/イベント実体(platform)」
- `REFACTORING.md:19-21` 「やらないこと: scoreboard サブパッケージ統合、2 リポ統合」
  (**統合しない**という決定であって、追加分割を明示的に禁じてはいない)
- `REFACTORING.md:22-23` 「やらないこと: アーキテクチャ大改造 — マイクロサービス化・
  SQLite からの移行・HA 前倒し。現構成は 30 人規模イベントに実証済みで十分」
- `REFACTORING.md:28-32` 「scoreboard DDD = scoring domain service 抽出(案 B)を 2026-07-14 に
  既に採用済み」— **DDD は既に走っている取り組みであり、`internal/scoreboard/scoring` への
  ドメインサービス抽出という Go パッケージレベルの話**。「サブパッケージ*統合*はしない」を
  「目的ある `scoring` パッケージの*追加*は射程外=承認」と再解釈した経緯がある
  (案 C = 集約・CQRS・repository 明示化は「大改造しない」に含め不採用)。

**Hard Invariant との衝突点**:
- **I5** (`falco-ctf-app-conventions.md:27`): 全 8 イメージを**同一 git SHA**でビルド・push する。
  これは「1 commit = 1 ビルド世代」という強い結合を前提にしている。サービスごとに repo を
  割ると、この結合を保つには submodule / monorepo tool / 別途オーケストレータが要る
  (現状ゼロコスト、分割後は非ゼロの新規複雑性)。
- **I6** (`falco-ctf-app-conventions.md:28`): `challenges/` は scoreboard と同一 repo。
  理由は「`falco-rule.yaml` が scoreboard の catalog loader に直接読まれ、リリースサイクルが
  完全一致する必要がある」(`falco-ctf-app/CLAUDE.md` 設計判断節)。別 repo にすると
  「scoreboard が古い challenge スキーマで動く事故」が起きる、と既に文書化済み。

**「小規模だから不要」を却下理由に使わない (CEO 方針)** ので、上記は規模論ではなく
**結合の強さ (I5/I6) と統合コスト (下記 MERGE-DRAIN 実績) という構造的根拠**で評価する。

**すでに存在する「コンポーネント単位のチーム分割」**: `ORGANIZATION.md:126-165` の
Build/Run/Verify/Integrate 表は、**ディレクトリ path を排他境界とした 8 Engineer への
分担**を既に定義・運用している (software/application/design/content/platform/sre/qa/
release-engineer)。CEO 要求 (2)(4) は現行 2 リポのままでも組織上は既に部分的に満たされている
可能性が高く、「リポを割る」ことと「担当を割る」ことは独立変数である。

**実証: リポ分割が増えると何が起きるか (推測ではなく実測)** — `MERGE-DRAIN.md` の全体診断
(memory `project_refactoring_assessment_2026_08_14`) は「両リポ計 ~38 draft PR 滞留」の
根因を「生産 >> 統合」(持続する統合ノードが VP 1 つしかない) と特定し、`ORGANIZATION.md:263-350`
の WIP ポリシー (open PR 上限 8、cross-repo ペアは 2 枠消費) はこれへの直接対応として設計された。
**リポジトリ数を増やすことは統合ノードを増やさずに調整対象だけを増やす**ので、
この根因を悪化させる方向に働く。これは規模論ではなく **実測された統合ボトルネックへの実害**
という、CEO が認める却下根拠の型に該当する。

**再現可能な開発環境の現状 gap (実測)**:
- `falco-ctf-app` の Go トゥールチェーンは Dockerfile.test/tidy/gen 経由でコンテナ内実行
  (`falco-ctf-app/CLAUDE.md:104-108`)。ローカル Go インストール不要という点では良い設計。
- しかし **devcontainer 定義・`.tool-versions`/`mise.toml`/`asdf` 相当の pin が存在しない**
  (`find . -iname "*devcontainer*" -o -iname ".tool-versions" -o -iname ".mise.toml"` は
  workspace 全体で 0 件、2026-08-27 実測)。colima/kubectl/helm/terraform/sops/age/gh の
  バージョンは `preflight.sh` が**存在確認**はするが (`falco-ctf-platform/scripts/preflight.sh`)、
  **バージョン pin・自動インストールはしない** (helm major version チェックのみ例外、
  `preflight.sh:248-260`)。
- **`make bootstrap` 相当のターゲットが両リポに存在しない**
  (`grep bootstrap falco-ctf-app/Makefile falco-ctf-platform/scripts/*.sh` は
  tfstate 初期化スクリプト 1 件のみヒット、トゥールチェーンのインストールとは無関係)。
- `ONBOARDING.md:92-119` (§4.5) は新マシンでの `gh auth` アカウント切り替えの落とし穴を
  文書化しているが、**手順は手動**(コマンドをコピペする形)であり機械化されていない。
- `.github/CODEOWNERS` (`falco-ctf-app/.github/CODEOWNERS:1-40`) は
  2026-08-18 以前の旧職名 (`app-lead`/`content-lead`) をコメントに残したまま全行 `@Qfour`
  で統一されており (`GITHUB-OPS.md:37-64` の G1 で「未実施」チェックボックスとして残存)、
  「clone した別 Engineer が担当領域を機械的に知る」導線としては形骸化している。

## Options

### Option A — 現状 2 リポ維持 + ディレクトリ境界の DDD を強化 (推奨)

**変更点**: リポ数は変えない。(1) `ORGANIZATION.md` の Engineer 担当表を
**bounded context マップ**として明文化し直す (下記参照)。(2) `.github/CODEOWNERS` を
現行 11 職名に更新し G1 の残作業を消化する。(3) `internal/scoreboard/scoring` の
ドメインサービス抽出 (2026-07-14 CEO 決定) を計画どおり完遂し、`internal/{scoreboard,
authpolicy,collector}` を**パッケージ境界=API 契約**として明示 (import 制約を
`internal/apispec` 方式の依存境界テストで機械強化: ADR-0005 V8 の手法を横展開)。
(4) 再現可能環境は devcontainer + `mise.toml`(colima/kubectl/helm/terraform/sops/age/gh
の pin) + `make bootstrap` を両リポに新設。

**コスト**: 実装コストは中 (bootstrap 機構の新設、CODEOWNERS 更新、import 境界テストの追加)。
運用コストは低 (リポ数不変 = WIP ポリシー・CI・ブランチ保護の追加設定不要)。

**リスクと可逆性**: 低リスク・**完全に可逆** (ディレクトリ構成・Makefile ターゲットの追加は
いつでも元に戻せる、既存 I5/I6 に抵触しない)。

**効き始める閾値**: 常時有効 (規模非依存の恒久投資)。特に効くのは「新しい人間協力者が
初めて clone する」瞬間 — そこが再現性の実地テストになる。

### Option B — サービス単位で 4〜6 リポに物理分割 (scoreboard-svc / auth-policy-svc /
collector-svc / challenges-content / charts / platform)

**変更点**: 各 Go サービス・content・charts を独立 repo 化し、それぞれに CI/CD・
branch protection・WIP 枠を持たせる。「1 Engineer 1 repo」を物理的に強制できる。

**コスト**: 高い。(a) I5 (全 8 イメージ同一 SHA) を保つには repo 横断でビルド SHA を
同期する仕組み (monorepo tool か release orchestrator) が新規に要る。(b) I6 の理由
(falco-rule.yaml と scoreboard catalog loader のスキーマ結合) を保つには
challenges-content と scoreboard-svc 間に**バージョン付き契約**(生成型配布や
OpenAPI 相当の schema pin) を新規構築する必要がある — 現状は「同一 repo・同一コミット」
という最も安いスキーマ同期手段をあえて使っている設計 (`falco-ctf-app/CLAUDE.md` 該当節)
であり、それを捨てて別の同期機構を作るコストが乗る。(c) WIP ポリシー
(`ORGANIZATION.md §5`) は cross-repo ペアに 2 枠を割く設計。2 リポ→6 リポになると
枠の消費が最大 3 倍になり、現行上限 8 (時限 10) では 2-3 ペアの並行作業しかできなくなる。

**リスクと可逆性**: **低可逆**。一度分割すると、SHA 同期機構・schema 同期機構という
新規の恒久資産に依存が生まれ、統合し直す (元の 2 リポに戻す) コストは分割コストより
一般に高い (git 履歴の再結合は損失を伴う)。

**効き始める閾値**: **独立した deploy 成果物・独自の CVE 面・独自のリリース周期・
独自の障害モードを持つに至ったとき**(`ORGANIZATION.md:225-229` が新職の正当化基準として
既に定義している基準をリポ分割にもそのまま適用できる)。現状 8 イメージは同一 SHA で
一括ビルド・一括 CVE scan されており、この基準を満たすサービスは無い (実測: 全 Dockerfile
が `Makefile` の単一 `build`/`scan` ターゲットに載っている)。

### Option C — 中間案: Go workspace の multi-module 化 (`go.work`) で内部 API 境界を
モジュール境界として明示。リポ数は変えない

**変更点**: `internal/scoreboard`・`internal/authpolicy`・`internal/collector` を
別々の `go.mod` を持つモジュールにし、`go.work` で束ねる。パッケージ import の代わりに
**モジュール依存**として境界を明示する (現状 `internal/apispec` の依存境界テストが
テストレベルでやっていることを、ツールチェーンレベルに引き上げる)。

**コスト**: 中。`go.mod` が複数になることで `make tidy`/`make gen` の対象が増える
(Dockerfile.tidy/gen の複製が要る)。CVE scan (govulncheck) はモジュール単位で走らせる
運用に変える必要がある。

**リスクと可逆性**: 中リスク・可逆 (repo 分割ほど不可逆ではないが、`go.work` 導入は
ビルドスクリプト・CI の書き換えを伴うため Option A より着手コストは高い)。

**効き始める閾値**: 3 サービス間で**意図しない import が実際に起きた**とき (現状
`internal/apispec/dependency_boundary_test.go` のテストが未然に検出しているので、
この閾値は今のところ未到達)。または Engineer 間で「同じファイルを触る PR」の衝突が
`internal/scoreboard`/`internal/authpolicy`/`internal/collector` を跨いで頻発したとき。

## Decision

**Option A を採る**。リポ数は現状 2 を維持し、既存の Engineer 担当表 (path 排他境界) を
bounded context マップとして明文化し、CODEOWNERS を現行化し、devcontainer/mise/
`make bootstrap` で再現可能性を機械化する。

理由 (1 文): CEO 要求 (2)(4) は既に `ORGANIZATION.md` の path 排他境界で構造的に
達成されており、要求 (1) の残 gap はリポ構成ではなく **toolchain pin とオンボーディング
自動化**にあり、要求 (3) の DDD は 2026-07-14 に scoring domain service 抽出という形で
既に射程が定義済みなので、**この 3 つのどれも物理的な repo 分割を必要としない**
一方、Option B は I5/I6 という既存の強い結合を壊すか高コストな再結合機構を新設する必要があり、
かつ MERGE-DRAIN.md が実測した統合ボトルネックを悪化させる方向に働く。

## Bounded Context マップ (Option A の下で明文化する内容)

| Bounded Context | 実体 (現行パス) | 担当 Engineer | リポ境界との関係 |
|---|---|---|---|
| Scoring (採点ドメイン) | `internal/scoreboard/{scoring,store,catalog}` | software-engineer | app 内。2026-07-14 で `scoring` domain service へ抽出中 |
| Ingest (Falco event 取り込み) | `internal/scoreboard/ingest` | software-engineer (security-engineer 監査必須) | app 内。CODEOWNERS で security ブロック済み |
| Authn/z (認可境界) | `auth-policy/`, `internal/authpolicy`, `internal/scoreboard/originguard` | software-engineer (security-engineer 監査必須) | app 内。I8 が正典 |
| Collector (参加者向け単一入口) | `collector/`, `internal/collector` | software-engineer | app 内。default-deny forward 契約 |
| Content (課題・シナリオ) | `challenges/`, `scenarios/` | content-engineer | app 内。**I6 により scoreboard と同一 repo が必須** (schema 結合) |
| Portal/Journey (参加者 UI) | `internal/scoreboard/view`, `charts/ctf-user` 参加者部分 | application-engineer | app 内 |
| Design System | design tokens/CSS | design-engineer | app 内 |
| Deploy Contract (chart) | `charts/*` | software (server 側) / application (ctf-user 参加者側) | app 内。platform helmfile が値供給 (I7) |
| Platform Substrate | `terraform/`, `helmfile/`, `scripts/` | platform-engineer | platform 内 (private) |
| Event Ops | `events/`, runbook | sre-engineer | platform 内 (private) |

**リポ境界とのズレ**: 大きなズレは無い。唯一の越境点は「Deploy Contract」— chart 定義は
app 内 (public) だが実値供給は platform (private) にあり、**この越境自体が公開境界の鉄則
(シークレット・実値を public に置かない) の直接の帰結**であり、解消すべきズレではなく
意図された設計。

## Consequences

- 諦めたこと: 「1 Engineer 1 repo」という物理的な強制。代わりに path 排他境界 (§ORGANIZATION.md)
  + CODEOWNERS + WIP ポリシー (同一ファイルを触る PR は 1 本) という**論理的な排他**で運用する。
  これは既に運用実績がある (ORGANIZATION.md §2 の "5. 境界は path で排他に切る")。
- 新たに守る invariant: 無し (既存 I5/I6 を維持するだけ)。
- runbook への影響: `ONBOARDING.md` に `make bootstrap` の実行手順が追加される
  (Option A 実装後)。CODEOWNERS 更新は GITHUB-OPS.md G1 の既存チェックボックスを消化するのみ。

## Signposts (この決定を覆す観測可能な信号)

1. **8 イメージのうち特定のサービスが独自のリリース周期・独自の CVE 面を持つに至った**
   (例: scoreboard だけ週次でパッチが要る一方 auth-policy は月次、が観測される)。
   `ORGANIZATION.md:225-229` の新職正当化基準をそのまま repo 分割の基準に転用する。
2. **`internal/scoreboard`/`internal/authpolicy`/`internal/collector` を跨いで
   同一ファイルを触る PR 衝突が持続的に (3 PR 以上/月) 発生する** — Option C (go.work) の
   閾値に到達したサイン。
3. **人間協力者が実際に増え、write 権限を分離する必要が生じた** (現状 CEO 1 名 + AI のみ、
   CODEOWNERS の auto-request が「現状不活性」なのはこれが理由 — `CODEOWNERS:1-9`)。
   このとき初めて GitHub の物理的な repo 単位アクセス制御が意味を持つ。
4. **I5/I6 の結合そのものが撤回される** (例: イベント運営が複数ゲームタイトルを持つように
   なり、challenges/ を scoreboard と独立にバージョニングする必要が生じる)。

## Verification

- CODEOWNERS が 11 職名を反映していることは `grep -c "software-engineer\|application-engineer\|design-engineer\|content-engineer" .github/CODEOWNERS` で機械確認可能 (実装後)。
- `make bootstrap` / devcontainer の到達性は「fresh clone → `make bootstrap` → `make test` が
  ネットワーク接続済み・非設定マシンで通る」ことを CI の matrix job もしくは手動チェックリストで
  検証する (実装後に具体化)。
- 本 ADR 自体の Decision (「repo 分割しない」) には機械検査を付けない
  (構成判断そのものであり、違反を検知する対象コードが無いため)。**Hard Invariant には
  昇格しない** (Verification が薄いため、既存の ADR 規律どおり)。

## Advice

- 助言者: なし (本 ADR は architect が CEO→VP の相談に直接回答する形で起案。
  他 Engineer への発注前の初期提案のため、この時点で受けた助言は無し)。
- VP へ: 本 ADR の Decision 部分 (repo 分割しない) は既存「決定事項」の**再確認**であり
  新規の Hard Invariant/契約変更ではないため、architect の同意権 (ORGANIZATION.md §4)
  の対象外と判断した。一方 Option A の実装項目 (CODEOWNERS 更新・devcontainer・
  `make bootstrap`・import 境界テスト) は software-engineer / platform-engineer への
  発注が必要な実装タスクであり、REFACTORING.md への新フェーズ (P28 候補) としての
  起票を VP に推奨する。
