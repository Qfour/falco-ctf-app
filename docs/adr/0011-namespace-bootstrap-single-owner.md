# ADR-0011: Namespace ownership を「app chart 自己 template」から「platform 側 bootstrap release の単一所有」へ移す
- Status: **Accepted** (設計。2026-08-25, VP 承認。review-5x [T3・5観点] 実施済み、
  BLOCKING 3件・MEDIUM 9件・LOW 7件を全反映。**実装は別PR、本番投入は Verification
  V1-V7 の実機確認が landing するまで不可** — 特にV7 [Helm v4.1.3のprune挙動] は
  scoreboardのsqlite PVCデータ損失リスクの裏付けであり実装PR前に最優先で実施すること。
  **2026-08-25 qa-engineer 追記**: V1 (2段記録)・V2・V3・V4・V7 は disposable
  colima profile 上で実機確認済み・全て予定どおり [V1-V4 PASS、V7は破壊シナリオ(b)の
  実在を確認] — 詳細は Verification 節。**V5/V6 は未実施のまま残っている**ので、
  本ADRはこの追記だけでは「本番投入可」に上がらない。実装ブランチ (app
  `feat/adr-0011-app-namespace-removal` / platform
  `feat/adr-0011-namespaces-bootstrap`) 自体は本追記の時点でも未merge)
  **2026-08-25 qa-engineer 追記 (2回目)**: 実装は既に両リポ main へ merge済み
  (app#190 `feat(charts): remove self-managed Namespace templates` / platform#113
  `feat(helmfile): add namespaces bootstrap release`)。この状態で **V5/V6 も実施し、
  両方 PASS** (詳細は Verification 節)。V1-V7 の全項目が実機確認済みになったので、
  本 ADR は Verification の観点からは「本番投入可」に到達した (残る前提は Consequences /
  Signposts に記載のもの、および platform#111 の follow-up 検査が未実装であること)。
- Date / Deciders: 2026-08-25 / architect (提案・5x レビュー反映) — VP (承認)
- 関連: platform#83 (P1相当, 本ADRの発端issue) / platform#75 (`deploy-user.sh` の `-n` 不在。**別issue、本ADRのDecisionはこれを解決しない** — Consequences 節参照) / Issue #144 (**ADR-0009 は Issue #144 用に予約済み。本ADRは 0009 を使わない** — `docs/adr/0008-mission05-positive-proof-gate.md:569`) / platform#111 (follow-up: 自己 Namespace template 再導入を防ぐ静的検査、2026-08-25 起票) / app#189 (V5/V6 実施発注) / platform#114 (follow-up: §9.3 collector uninstall 欠落drift、V6実施中に発見・起票) / platform#112 (kubeContext固定文字列 + docker+k3s image load の落とし穴、V1/V5実施中に発見・起票・追記)

## Context

### 発生した障害 (真に空のクラスタでの `helmfile -e local sync`)

`falco-ctf-platform/helmfile/helmfile.yaml.gotmpl` の `auth-policy` / `scoreboard` /
`collector` / `docs` の 4 release は `createNamespace: false` を明示し、コメントで
「chart templates its own Namespace (PSA restricted labels); helmfile pre-creating it
collides "already exists"」と理由を書いている
(`helmfile/helmfile.yaml.gotmpl:265,299,326,345`)。

これは **既存 namespace が存在する場合にだけ成立する** 前提だった。真に空のクラスタでは
両方向に失敗する:

1. namespace が無い → `helm upgrade --install` が release secret を保存する先の
   namespace が存在しないため `Error: create: failed to create: namespaces "auth-policy"
   not found` で失敗する。
2. 素の `kubectl create namespace` で作る → 今度は chart 自身が template する
   `Namespace` オブジェクトを Helm が適用しようとした際、そのオブジェクトに
   Helm の所有権 annotation (`meta.helm.sh/release-name` / `meta.helm.sh/release-namespace`
   / label `app.kubernetes.io/managed-by=Helm`) が付いていないため、
   `Error: unable to continue with install: ... invalid ownership metadata` で拒否される
   (Helm 3 以降、他 release が作った/未管理のオブジェクトを chart が「奪う」ことを
   デフォルトで禁止する仕組み)。

この 2 つの失敗モードは**両立しない要求**になっている: 「helm は release secret 保存の
ために namespace の事前存在を要求する」と「chart 自身が Namespace オブジェクトの
唯一の所有者であろうとする」は、空のクラスタでは同時に満たせない。

### 現状の Namespace 管理の実態 (実測)

| chart | 自己 template する Namespace | PSA label | file:line |
|---|---|---|---|
| `auth-policy` | あり (`name: auth-policy`, 固定) | `enforce: restricted` + `audit: restricted` (+`*-version: latest`) | `falco-ctf-app/charts/auth-policy/templates/namespace.yaml:1-10` |
| `collector` | あり (`name: collector`, 固定) | 同上 + `app.kubernetes.io/name: collector` | `falco-ctf-app/charts/collector/templates/namespace.yaml:1-11` |
| `scoreboard` | あり (`name: scoreboard`, 固定) | 同上 (name label 無し) | `falco-ctf-app/charts/scoreboard/templates/namespace.yaml:1-10` |
| `docs` | あり (`name: {{ .Release.Namespace }}`) | **無し** (`docs.labels` helper は `app.kubernetes.io/{name,part-of,managed-by}` のみ、PSA 系ラベルを一切含まない) | `falco-ctf-app/charts/docs/templates/namespace.yaml:1-6`, helper: `falco-ctf-app/charts/docs/templates/_helpers.tpl:1-5` |
| `ctf-user` | あり (`name: ctf-<username>`) | `enforce: baseline` + `audit/warn: restricted` (challenge コンテナが root 前提のため意図的に緩い) | `falco-ctf-app/charts/ctf-user/templates/namespace.yaml:1-13` |

**新規発見 (今回の調査で確定)**: `docs` namespace は PSA label を一切持たない。
4 チャートが「restricted を守るために自己 template している」と説明されている一方、
docs だけは実際には何も enforce していない。本ADRの Decision はこの不整合を
解消する機会として扱う (Consequences 参照)。

**detect-grader (platform-local chart) は同じ構造的欠陥を「潜在的に持つ」のではなく、
既に一度実際に発火させている (2026-08-25 再査読で訂正)**: `helmfile/helmfile.yaml.gotmpl
:289-292` の NOTE は将来 (`detectGrader.enabled: true` への再有効化時) の衝突を予告する
形で書かれているが、`helmfile/environments/prod.yaml.gotmpl:141-145` (実測) は
**2026-08-16 のリハーサルで実際に "namespaces ctf-detect-grader already exists" が
発生し、atomic 失敗で helmfile sync 全体を巻き込んだ**ことを記録している。その場の
回避策は他 4 release と同型の `createNamespace: false` ではなく、**release 全体を
`detectGrader.enabled: false` にする**という、機能そのものを止める粗い無効化だった
(`prod.yaml.gotmpl:146-147`)。

さらに **`helmfile/environments/default.yaml.gotmpl:24` の既定は `detectGrader.enabled:
true` であり、`local` 環境 (`environments/local.yaml.gotmpl` にこのキーの override は無い、
実測確認) はこの既定を継承する**。つまり本ADRの発端そのものである「真に空の
クラスタでの `helmfile -e local sync`」を今後実行すると、4 つの app namespace の衝突に
加えて detect-grader の衝突も **(prod と異なり) local では常に踏む**。ctf-user が
platform#75 という別の bug に偶然マスクされて「まだ発火していない」のとは対照的に、
detect-grader は「44.2 で有効化したら踏むかもしれない将来リスク」ではなく「**既に
一度踏んで、現在は prod だけ `enabled: false` で凍結して隠しているが、local は既定で
踏む状態のまま**」という、より切迫した状態にある。この事実により、Decision の対象に
detect-grader を含める判断は先回りの機能拡張ではなく、**既に実害を出している欠陥の
一括修正**として一層正当化される。

### `ctf-user` は対象外 — 別の bug (platform#75) に守られて今は発火しない

`ctf-user` chart も自己 Namespace template を持つが、**`deploy-user.sh` の
`helm upgrade --install` 呼び出しに `-n`/`--namespace` も `--create-namespace` も
渡していない** (`falco-ctf-app/charts/ctf-user/deploy-user.sh:252-263`)。この結果:

- release メタデータは helm のデフォルト namespace (通常 `default`。常に存在) に
  記録される → release secret 保存の失敗 (障害モード 1) が起きない。
- `Namespace` オブジェクト自体は初回 apply なので所有権の衝突 (障害モード 2) も
  起きない (最初に作る release が最初の所有者になるだけ)。

つまり **ctf-user が今回の障害を踏んでいないのは、platform#75 という別の bug が
偶然この障害を隠しているからであって、構造が健全だからではない**。platform#75 を
「`-n "${NS}" --create-namespace` を足すだけ」の形で直すと、その瞬間に本ADRと
同じ両方向障害が ctf-user にも新規発生する。本ADRは ctf-user を対象に含めない
(deploy-user.sh は helmfile 管理外で、実行順序も event 運用に応じて decouple されている
ため、helmfile 側の bootstrap release に素朴に相乗りさせられない — `namespaces` chart の
機構は helmfile レンダ時に確定する静的な `.Values.namespaces` list を `range` するだけ
なので、participant 毎に動的生成される ctf-user の namespace には構造的にそのまま
適用できない) が、**#75 を修正するときは本ADRと同じ「単一所有」パターンを ctf-user 側に
適用することを条件にする** (Consequences 参照。旧稿では Signposts に置いていたが、
これは「この決定を覆す信号」ではなく将来PRへの義務なので Consequences に移した —
R4 Finding 6)。混同を避けるため、#75 自体の修正方針はこのADRでは決定しない。

### 前セッション VP の所感 (非公式、再検討対象)

- (a) presync hook で「namespace 作成 → Helm に adopt (annotation 付与)」を機構化
  — 懸念: Helm の内部 annotation 表現に運用スクリプトが依存し、Helm バージョン更新で
  壊れうる
- (b) chart の Namespace 自己管理をやめ `createNamespace: true` + PSA label を別経路で当てる
- (c) namespace 専用の bootstrap release を先行して流す
- 所感: (b) か (c) が本命。条件: PSA restricted label を失わないこと

## Options

### Option 1 — Presync hook で「作成 → adopt」を機構化 (前所感 (a) の具体化)

**変更点**: platform helmfile の `auth-policy`/`scoreboard`/`collector`/`docs` の
各 release に `events: ["presync"]` hook を追加し、
`kubectl create namespace <ns> --dry-run=client -o yaml | kubectl apply -f -` の後、
`kubectl label ns <ns> app.kubernetes.io/managed-by=Helm --overwrite` +
`kubectl annotate ns <ns> meta.helm.sh/release-name=<rel> meta.helm.sh/release-namespace=<ns>
--overwrite` を実行する (既存の cert-manager release が同種の bash hook を既に使っている
前例に倣う、`helmfile.yaml.gotmpl:170-213`。**訂正 (2026-08-25 再査読, R2 finding 2-a):
当初「cert-manager/calico」と書いていたが、calico release (`helmfile.yaml.gotmpl:93-100`)
には hook が無い。前例は cert-manager のみ**)。もしくは Helm 3.17+ で追加された公式
フラグ `--take-ownership` (WebSearch で確認: 所有権検証をスキップして現行 release に
付け替える) を `helmfile` の release 単位 `args`/extraArgs として渡す variant もある。
app 側 chart は無改修 (5 つとも現状維持)。

- **コスト**: 運用低 (既存 hook パターンの延長)。認知中 (読者が Helm の
  ownership-annotation 仕組みを理解する必要)。依存: **Helm の adoption 機構そのもの**。
  イメージサイズ影響なし。
- **リスクと可逆性**: 可逆性は高い (hook を消せば元に戻る)。実測: このワークスペースの
  Helm は **v4.1.3** (`helm version` の `BuildInfo.Version` で確認。⚠ `helm version
  --client` という v3 系のフラグ表記は v4 では `Error: unknown flag: --client` で
  失敗する — 実行するなら `helm version` 単体を使うこと。2026-08-25 再査読で実機確認、
  R3 Finding 対応で訂正)。WebSearch で追加確認 (2026-08-25 再査読): `--take-ownership`
  フラグ自体は v3.17 で追加されたものだが、**Helm v4 は Server-Side Apply (SSA) を
  デフォルト化し、所有権の表現を v3 の `meta.helm.sh/release-name` 系 annotation 判定
  から `meta.helm.sh/owner` という新annotation + SSA の managed-fields ベースの
  所有権表現へ作り直している** (複数 owner によるフィールド単位所有は SSA でも
  非サポートのまま)。つまり「v3 系で観測された adoption 挙動が v4 でも同じ」は
  単に**未確認の仮説**というだけでなく、**確認した限りでは異なる仕組みに置き換わっている
  可能性が高い**、というより強い懸念に訂正する (R4 Finding 1 の裏付け強化)。
  Family 1 (Option 1) は本質的に「Helm の所有権判定ロジック (このワークスペースの
  v4.1.3 では v3 時代と表現が異なることが確認できた) に依存し続ける」設計であり、
  将来の Helm バージョンでこのロジックが変われば**壊れて初めて気づく**。
- **効き始める閾値**: 常時 (真に空のクラスタから bootstrap する必要が生じた瞬間)。

### Option 2 — chart の Namespace 自己管理を撤去 + `createNamespace: true` + PSA label を hook で付与 (前所感 (b) の素朴版)

**変更点**: app 側 4 chart (`auth-policy`/`collector`/`scoreboard`/`docs`) から
`templates/namespace.yaml` を削除。platform helmfile の各 release を
`createNamespace: true` に変更し、`postsync` hook (または `presync`) で
`kubectl label/annotate ns ... pod-security.kubernetes.io/enforce=restricted ...`
を都度実行して PSA label を当てる (4 release にほぼ同一の hook ブロックを複製)。

- **コスト**: 運用中 (ほぼ同一の hook を 4 箇所に複製、DRY でない)。認知中。
  依存: Helm の所有権機構には依存しない (chart が Namespace を template しなくなるため
  衝突自体が発生しない) が、**PSA label の適用そのものが `kubectl` 直叩きになり、
  `helmfile diff` の管理対象から外れる** — 誰かが手動で label を消しても
  `helmfile diff` は何も報告しない (ドリフト検出機構が無い)。イメージサイズ影響なし。
- **リスクと可逆性**: 可逆性は高い。だが「PSA label が chart/values の宣言的管理から
  外れる」という新しい弱さを生む。4 箇所の hook 複製は今後 namespace が増えるたびに
  複製がもう 1 つ増える (detect-grader も同様の対応が要る)。
- **効き始める閾値**: 常時。

### Option 3 (推奨) — 専用の namespaces bootstrap release による単一所有化

**変更点**: platform に「platform-local chart」パターン (既存の
`helmfile/releases/detect-grader/chart/` と同型) で新規 chart
`helmfile/releases/namespaces/chart/` を追加し、`.Values.namespaces` (list) を
`range` して **全 Namespace オブジェクトを 1 release が宣言的に所有する**。
app 側の `auth-policy`/`collector`/`scoreboard`/`docs` (+ platform 側
`detect-grader`) の 5 chart から `templates/namespace.yaml` を削除し、
Namespace の所有者を「app chart」から「platform の `namespaces` release」1 つに
一本化する。ダウンストリームの各 release は `createNamespace: false` を維持し、
`needs: [kube-system/namespaces]` を追加する (`namespace: kube-system` は常に
存在するので、この release 自身は bootstrap 問題を持たない)。

- **コスト**: 運用低〜中 (新規 chart 1 つ。既存 detect-grader パターンの流用で
  レビューコストは小さい)。認知**低** — 「誰が何を所有するか」が
  `helmfile/releases/namespaces/values.yaml.gotmpl` の 1 ファイルに集約され、
  現状 4+1 箇所に分散している同一の説明コメント (`helmfile.yaml.gotmpl:265,299,
  326,345,289-292`) が消える。依存: **「複数 release が同一 object の所有権を争う」
  という Helm の紛争解決ロジック (バージョンごとに実装が変わる — v3.17 の
  `--take-ownership`、v4 の SSA 化 + `meta.helm.sh/owner` 導入) には依存しない。
  ただし「単一 release が object を新規作成し、その所有権を通常どおり記録する」という
  Helm の最も基礎的な hotpath には依然依存する** (Verification V3 が検証する
  `meta.helm.sh/release-name` annotation はこの基礎的な記録そのものである。
  「一切依存しない」は Option 3 にも当てはまらない、Decision 参照。2026-08-25 再査読
  で訂正、R4 Finding 1)。この基礎的な hotpath は Helm のどのバージョンでも壊れたら
  Helm 全体が動かなくなるレベルの安定性を持つため、Option 1/2 が依存する紛争解決
  ロジックよりはるかに安定している。イメージサイズ影響なし (workload を持たない chart)。
- **リスクと可逆性**: 高い可逆性 (新規 release 1 つの追加 + 既存 5 箇所からの
  Namespace 定義削除。git revert で完全に戻せる)。**唯一の挙動変化**:
  今まで `helm uninstall auth-policy` は付随する Namespace も削除していたが、
  今後は Namespace のライフサイクルが `namespaces` release に移るため、
  個別 app release の uninstall では Namespace が残る (teardown 手順にとっては
  意図的に安全側の変化だが、`TEARDOWN.md` 等の既存前提が変わるので sre-engineer への
  申し送りが要る、Consequences 参照)。**ただし app 側の chart 変更と platform 側の
  helmfile 変更を別々に適用すると新規の破壊的失敗が起きる** — Decision の
  「適用順序の制約」参照 (R5 HIGH, 2026-08-25 追加)。
- **効き始める閾値**: 常時 (真に空のクラスタから bootstrap する必要が生じた瞬間 —
  これは本ADRの発端そのもの)。加えて、detect-grader が2026-08-16に一度実際に
  発火させた衝突 (`prod.yaml.gotmpl:141-145`) と、その将来の再発
  (`helmfile.yaml.gotmpl:289-292` の予告) も同じ変更で解消される。

## Decision

**Option 3 を採用する。** 理由: Family 1/2 (Option 1/2) は Helm の adoption 機構
(ownership annotation の付与/検査) に依存し続けるか、PSA label の適用を
Helm の宣言的管理から外すかのどちらかで新しい脆さを生むのに対し、Option 3 は
「1 つの Kubernetes オブジェクトを 2 つの Helm release が要求する」状況そのものを
構造的に無くす。

**訂正 (2026-08-25 再査読, R4/architect 自己指摘)**: 上記は「Option 3 は Helm の
ownership 機構に一切依存しない」という意味ではない。Verification V3 は
`meta.helm.sh/release-name: namespaces` という、Helm が通常の release install/upgrade で
必ず書き込む所有権記録を検査対象にしており、Option 3 もこの記録機構には依存している。
Option 3 が回避しているのは記録機構そのものではなく、**「複数 release が同一 object を
要求したときの紛争解決」という、Helm のバージョンごとに作り直されている周辺ロジック**
である (v3.17 で `--take-ownership` が追加され、v4 では SSA 化 + `meta.helm.sh/owner`
導入で表現が変わったことを WebSearch で確認済み、Option 1 の該当箇所参照)。したがって
Option 3 の正確な利点は「依存を無くす」ではなく、**「依存する対象を、Helm のバージョンで
頻繁に作り直される不安定な紛争解決ロジックから、単一 release による通常の object
新規作成という最も基礎的な hotpath (壊れたら Helm 全体が動かなくなるレベルの安定性を
持つ) へ移す」**ことである。ローカル環境の Helm クライアントが **v4.1.3** という、v3 と
所有権表現が異なることを確認した比較的新しい major version である今、この安定性の差は
無視できない。

### 適用順序の制約 (両方向に破壊的失敗があるので必読。R5 HIGH 対応)

**app 側 (5 chart 中 4 つ: `auth-policy`/`collector`/`scoreboard`/`docs`) の Namespace
self-template 削除と、platform 側の `namespaces` release 追加 + 既存 4 release +
detect-grader への `needs` 追加は、同一の `helmfile sync` 適用単位で同時に反映
されなければならない。** どちらかが先行した中間状態を経由すると、以下のいずれかで
**新規に**壊れる (「今は困っていないから後で直せばいい」が成立しない):

- **(a) platform 側が先行するケース** (`namespaces` release + `needs` を先に追加したが、
  app chart はまだ旧バージョン (Namespace を自己template する版) のまま sync してしまう):
  `namespaces` release が先に `auth-policy` 等の Namespace object を作成・所有する。
  その後 `auth-policy` release が sync されると、chart 側が同じ Namespace object を
  再度 template し、Helm はそれを「他 release (`namespaces`) が既に所有している object」
  として検出し `invalid ownership metadata` で拒否する。**これは Context で述べた
  障害モード 2 そのものであり、しかも真に空のクラスタに限らず、既存クラスタでも
  `auth-policy` を sync するたびに恒常的に発生するようになる** — 今までは「真に空の
  クラスタでだけ踏む」問題だったのに、この中間状態では「常に踏む」問題へ悪化する。
- **(b) app 側が先行するケース** (chart から `templates/namespace.yaml` を削除した
  バージョンを、`namespaces` release も `needs` も未追加の旧 platform helmfile 定義で
  sync してしまう): 直前の release revision の manifest には Namespace object が
  含まれていたが、新しい chart バージョンの manifest には含まれていない。Helm の通常の
  reconciliation (旧 v3 の 3-way merge、新 v4 の SSA ベース diff のいずれも) は
  「前revisionのmanifestにあり新revisionのmanifestに無いobjectは削除する」という
  prune 挙動を持つため、**`helm upgrade` が Namespace object そのものを削除しうる**
  (中身の Pod/PVC/Secret を含めて丸ごと消える。`scoreboard` の sqlite PVC ならデータ
  損失になる)。**この挙動がこのワークスペースの Helm v4.1.3 で実際にどう出るかは
  未検証** — Verification V7 で実測する。

**推奨する実務手順**: (1) app 側 4 chart から `templates/namespace.yaml` を削除する PR を
先に merge する (chart 単体の lint/build 上は無害。helmfile 側と組み合わせるまで実害は
出ない)。(2) その新しい app chart バージョン (SHA/`appChartVersion`) と、platform 側の
`namespaces` release 追加 + 既存 release への `needs` 追加 + `createNamespace: false`
コメント更新を **同じ `helmfile sync` 実行 (同じ PR / 同じ apply) で同時に適用する**。
(1) の chart 変更だけを先行して sync しない、(2) の helmfile 変更だけを先行して
(旧 chart バージョンのまま) sync しない — この 2 つの中間状態を作らないことが本
Decision の適用条件である。

### 実装方針 (pseudo-code — 実装は software-engineer / sre-engineer が担当)

**1. 新規 platform-local chart** `falco-ctf-platform/helmfile/releases/namespaces/chart/`

```yaml
# Chart.yaml
apiVersion: v2
name: namespaces
description: >-
  Platform-owned bootstrap release. Sole Helm owner of every Namespace object
  that app charts (auth-policy/collector/scoreboard/docs) and platform-local
  charts (detect-grader) live in. App/platform-local charts do NOT template
  their own Namespace object — this avoids "two releases own one object"
  ownership conflicts on a genuinely empty cluster (P1, ADR-0011). Holds no
  workload.
type: application
version: 0.1.0
```

```yaml
# templates/namespace.yaml — enforce/audit/warn は独立指定 (2026-08-25 修正,
# R1 HIGH + R2 finding 5-a/5-b 対応): 旧設計は単一の `.podSecurity` 値から
# `audit: restricted` を固定文字列で自動導出しており、(i) detect-grader が実際に
# 持つ `warn` を表現できず (detect-grader の実物 namespace.yaml は enforce+warn を
# 持ち audit を持たない、`helmfile/releases/detect-grader/chart/templates/
# namespace.yaml:9-14` 実測)、(ii) 将来 `enforce: baseline` の namespace を追加すると
# `audit: restricted` が無関係に自動生成される矛盾を生みうる。3 段を独立指定にし
# 「値を書かなければ何も出ない」fail-closed な形にすることで両方を解消する。
{{- range .Values.namespaces }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .name }}
  labels:
    app.kubernetes.io/managed-by: {{ $.Release.Service }}
    {{- with .extraLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
    {{- with .podSecurity }}
    {{- if .enforce }}
    pod-security.kubernetes.io/enforce: {{ .enforce }}
    pod-security.kubernetes.io/enforce-version: latest
    {{- end }}
    {{- if .audit }}
    pod-security.kubernetes.io/audit: {{ .audit }}
    pod-security.kubernetes.io/audit-version: latest
    {{- end }}
    {{- if .warn }}
    pod-security.kubernetes.io/warn: {{ .warn }}
    pod-security.kubernetes.io/warn-version: latest
    {{- end }}
    {{- end }}
{{- end }}
```

**2. 新規 values** `helmfile/releases/namespaces/values.yaml.gotmpl`

```gotmpl
namespaces:
  - name: auth-policy
    podSecurity:
      enforce: restricted
      audit: restricted
    extraLabels:
      app.kubernetes.io/part-of: falco-ctf
  - name: collector
    podSecurity:
      enforce: restricted
      audit: restricted
    extraLabels:
      app.kubernetes.io/name: collector
      app.kubernetes.io/part-of: falco-ctf
  - name: scoreboard
    podSecurity:
      enforce: restricted
      audit: restricted
    extraLabels:
      app.kubernetes.io/part-of: falco-ctf
  - name: docs
    # NEW: 現行 docs namespace は PSA label を一切持たない (Context 参照)。
    # このADRで restricted を明示的に付与する。docs コンテナは
    # nginxinc/nginx-unprivileged (UID 101, root 不要) なので restricted で
    # 動くはずだが、実機で未確認 — Verification V4 で確認する。
    podSecurity:
      enforce: restricted
      audit: restricted
    extraLabels:
      app.kubernetes.io/name: docs
      app.kubernetes.io/part-of: falco-ctf
  {{- if .Values.detectGrader.enabled }}
  - name: {{ .Values.detectGraderNamespace }}
    # detect-grader の実物 namespace.yaml (削除対象) は enforce+warn のみで audit を
    # 持たない (`helmfile/releases/detect-grader/chart/templates/namespace.yaml:9-14`
    # 実測、2026-08-25)。移行後もこの非対称を保持する — audit を新規に追加すると
    # 「移行前は無かった制約が増える」という本ADRの意図しない副作用になる。
    podSecurity:
      enforce: restricted
      warn: restricted
    extraLabels:
      app.kubernetes.io/name: detect-grader
      app.kubernetes.io/part-of: falco-ctf
  {{- end }}
```

**3. `helmfile.yaml.gotmpl` に release を追加** (ingress-nginx より前、依存無し):

```yaml
  - name: namespaces
    namespace: kube-system   # 常に存在。この release 自体は bootstrap 問題を持たない
    chart: releases/namespaces/chart
    installed: true
    values:
      - releases/namespaces/values.yaml.gotmpl
```

**4. 既存 4 release + detect-grader** — `createNamespace: false` は維持しつつ、
コメントを「chart templates its own Namespace...」から
「Namespace owned by kube-system/namespaces (ADR-0011) — this chart does not
template a Namespace object」に更新し、`needs` に `kube-system/namespaces` を追加:

```yaml
  - name: auth-policy
    namespace: auth-policy
    createNamespace: false  # Namespace owned by kube-system/namespaces (ADR-0011)
    chart: {{ .Values.appChartBase }}/auth-policy
    ...
    needs:
      - kube-system/namespaces
      {{- if .Values.oauth2Proxy.enabled }}
      - oauth2-proxy/oauth2-proxy
      {{- end }}
```
(同様に scoreboard / collector / docs / detect-grader へ `needs` を追加。**上記
「適用順序の制約」により、この変更は app 側 4 chart の Namespace template 削除と
同じ helmfile sync 適用単位で行う**)

**5. app 側 4 chart から自己 Namespace template を削除** (このADRの対象は 4 つ。
`ctf-user` は Context で述べた理由により対象外):

- `falco-ctf-app/charts/auth-policy/templates/namespace.yaml` を削除
- `falco-ctf-app/charts/collector/templates/namespace.yaml` を削除
- `falco-ctf-app/charts/scoreboard/templates/namespace.yaml` を削除
- `falco-ctf-app/charts/docs/templates/namespace.yaml` を削除

**6. platform-local `detect-grader` chart からも自己 Namespace template を削除**:

- `falco-ctf-platform/helmfile/releases/detect-grader/chart/templates/namespace.yaml`
  を削除し、`helmfile.yaml.gotmpl:289-292` の「再有効化時に createNamespace: false を
  足す必要がある」という NOTE コメントを削除 (この ADR の変更で構造的に解消されるため)

**7. Cross-repo 契約表への追記** — `falco-ctf-app/.claude/rules/falco-ctf-app-conventions.md`
の Cross-repo 契約表に新規行を追加 (この ADR が Accepted になった実装 PR で追加する。
今この場では追加しない — R5 の先例 (`docs/adr/0008` の Advice) に倣い、実装が
landing するタイミングで追加する):

| 接点 | 詳細 |
|---|---|
| Namespace ownership (ADR-0011) | `auth-policy`/`collector`/`scoreboard`/`docs` chart は Namespace オブジェクトを template しない。唯一の所有者は platform 側 `helmfile/releases/namespaces` release。PSA policy (enforce/audit/warn は namespace ごとに独立指定) は `helmfile/releases/namespaces/values.yaml.gotmpl` が正典。app 側は Namespace の name/label を chart から供給しない |

**8. follow-up: 自己 Namespace template 再導入を防ぐ静的検査 (R1 MEDIUM 対応 —
2026-08-25 再査読で issue 化済み)**: 「新しい chart を追加するときは Namespace を
自分で template せず `helmfile/releases/namespaces/values.yaml.gotmpl` に追記する」
という規律は、この組織の自己診断 (2026-08-18 org diagnosis: 「機械強制されない規律は
0% 遵守」) を踏まえると機械強制が要る。当初案では「実装 PR のレビューで判断する」と
Decision 対象外にしていたが、**platform#111 として follow-up issue を起票済み**
(chart-lint に `kind: Namespace` の再導入を検知する静的検査を required 化する)。
本ADR自体はこの検査の実装をスコープに含めない (issue として追跡するのみ)。

## Consequences

- **失ったもの**: 「app chart が自分の namespace の PSA レベルを自己完結して持つ」という
  局所性。今後 namespace の PSA レベルを変えるには platform 側の 1 ファイルを見る必要が
  あり、app repo だけを読んでいる開発者には見えなくなる (トレードオフとして受け入れる —
  Context の「両立しない要求」を解消するには、少なくとも一方の repo が Namespace の
  ライフサイクルを一元的に持つ必要があった)。
- **PSA label 構成の変更点 (R1 HIGH + R2 finding 5-a/5-b 対応で追加, 2026-08-25)**:
  `enforce`/`audit`/`warn` を独立指定にしたことで、detect-grader は移行後も
  `warn: restricted` を保持し (旧設計の pseudo-code では欠落する非対称があった、
  修正済み)、audit は新規に追加されない (旧設計では自動導出で追加されてしまっていた)。
  一方で detect-grader の namespace は新たに `pod-security.kubernetes.io/enforce-
  version: latest` / `warn-version: latest` を持つようになる (移行前はどちらの
  version field も無かった)。`-version: latest` は無害な runtime 指定であり実害は
  想定しないが、この正規化も本ADRが持ち込む変更点として明記しておく。
- **新たに守る前提**: 「Namespace オブジェクトを template する chart はこの workspace に
  存在しない」(`ctf-user` を除く — Context 参照)。新しい chart を追加するときは
  Namespace を自分で template せず、`helmfile/releases/namespaces/values.yaml.gotmpl`
  に追記する運用を守ること。**この規律を機械強制する静的検査は platform#111 として
  follow-up issue 化済み** (2026-08-25。「実装するかどうかを実装PRのレビューで判断する」
  という宙に浮いた表現から、issue番号を持つ具体的な追跡対象に変更した)。
- **docs namespace が新たに `restricted` を enforce するようになる**: 挙動変化。
  docs pod (nginx-unprivileged) が restricted で起動できなければ、この ADR の
  実装 PR の CI/E2E で気づく (Verification V4)。
- **teardown の挙動変化と runbook 反映箇所 (R5 Finding 2 対応 — 抽象的な「申し送りが
  要る」だけで終わらせず、具体的箇所を列挙する)**: 個別 app release の
  `helm uninstall` が Namespace を削除しなくなる。反映が必要な箇所:
  - `docs/operations.md` §9.3: `helm -n kube-system uninstall namespaces` を
    teardown 手順の末尾 (app 層 uninstall より後) に追加する。**同じ §9.3 は現状
    `collector` release の uninstall も欠落させている既存 drift**
    (`operations.md:1195-1224` 実測、本ADR起因ではない) — 同じPRで一緒に埋めるとよい。
  - `docs/prod-deploy.md:299` の既知の落とし穴表: 「該当4releaseにcreateNamespace:
    falseを設定済」を恒久対策として説明している現行の記述を、「Namespace の所有者は
    platform 側 `namespaces` release (ADR-0011) に一本化された。`createNamespace: false`
    はその結果として維持されるだけで、単独では真に空のクラスタのケースを解決しない」に
    訂正する。
  - `scripts/teardown.sh --only-orphan-check`: Namespace 自体は AWS リソースでは
    ないため直接の対象外。`namespaces` release が uninstall されずに Namespace が
    残留した状態で `terraform destroy` しても AWS 課金には影響しないことを確認済み
    (このADRのConsequencesとしての実害は無い、確認のため記録)。
  - `docs/PROD-GATE-E2E-PLAN.md:1723` の「Permanently fixed... manual ns-adoption
    workaround は不要」という記述は、platform#83 が明らかにした事実 (真に空の
    クラスタでは `createNamespace: false` だけでは解決しない) と矛盾する。実装PRの
    スコープでこの1行を訂正する。同 `:1722` の row #4 (detect-grader) の
    「Fixed, conditionally」も「2026-08-16に実際に発火し、release全体無効化という
    粗い回避で凍結中」に精緻化する。
- **detect-grader の予告済み landmine の解消**: `helmfile.yaml.gotmpl:289-292`
  の NOTE コメントが指していた将来の衝突は、**2026-08-16のリハーサルで既に一度
  実際に発火し**、`detectGrader.enabled: false` という release 全体無効化で凍結
  されていた (Context 参照)。本ADRの変更でこの凍結を解いても再発しない構造になる。
- **次回の真に空のクラスタからの stand-up はこのADR未解決の間ブロックされる
  (R5 Finding 4 対応)**: P17 のフルteardown後や P20 (substrate汎用化) の新規基盤での
  次回 stand-up が「真に空のクラスタ」から行われる場合、本ADRの実装 + Verification
  (少なくとも V1 相当) の実機確認が完了するまで、platform#83 の欠陥によりブロックされる。
- **platform#75 対応時の条件 (旧稿では Signposts に置いていたが、これは「この決定を
  覆す信号」ではなく将来PRへの義務なので Consequences に移した — R4 Finding 6)**:
  `deploy-user.sh` の `-n` 不在を修正する PR は「ctf-user の Namespace 所有権を
  どう扱うか」を明示的に決めること (本ADRと同じ単一所有パターンを適用する、または
  `deploy-user.sh` が `helmfile -e local apply` 実行後に限って動く前提を置く、等)。
  決めずに `-n`/`--create-namespace` だけ追加すると、ctf-user が本ADRと同じ両方向
  障害を新規に発生させる。
- **「適用順序の制約」は hard requirement であり、単なる推奨ではない (Verification
  V7 実測結果, qa-engineer, 2026-08-25 追記)**: `auth-policy` chart を使い、
  disposable colima profile 上で「旧 self-template chart で install → `namespaces`
  release/`needs` を介さず新チャート (Namespace template 削除済み) へ素の
  `helm upgrade`」という破壊シナリオ (b) を実際に再現したところ、
  `helm upgrade` 自体は正常終了 (`exit 0`) したにもかかわらず、対象 Namespace は
  数秒で `Terminating` → 完全に `NotFound` になった (Helm v4.1.3 の upgrade が
  旧revisionのmanifestにあり新revisionには無い Namespace オブジェクトを実際に
  prune する)。**これは「app 側の chart 変更と platform 側の helmfile 変更を
  同一 `helmfile sync` 適用単位で同時反映する」という Decision の適用順序の制約が、
  単なる運用上の推奨ではなく、破ると Namespace ごと (= `scoreboard` release であれば
  sqlite PVC ごと) 中身が消滅する、実際に起きる破壊的欠陥への唯一の防波堤である
  ことを意味する。** 実装 PR のレビュー/CI では、この2つの変更 (app 側4chartの
  `templates/namespace.yaml` 削除 と platform 側の `namespaces` release +
  `needs` 追加) が同一コミット/同一 apply 単位に含まれることを確認すること
  (release-engineer/VP のマージ順序チェック項目とする)。
- **platform#75 (`deploy-user.sh` の `-n` 不在) 対応の addendum (2026-08-26,
  architect)**: 上記「platform#75 対応時の条件」を満たす対応。**app#199として
  main に merge済み** (platform#116と同時、Issue platform#75 close済み)。

  **この addendum は navigational ではない。** 元の追記時 (2026-08-26 当日)
  navigational (既存 Decision/Verification への誘導のみ) と自称していたが、
  実際には本ADRの Consequences が platform#75 対応時に「決めること」として
  保留していた **ctf-user の namespace 所有パターンそのものを、この対応で
  初めて決定している** — 実質的に新規 Decision であり、下記
  「### Decision (addendum): ctf-user の namespace 所有パターン」として
  明示的に切る (architect R4 MEDIUM 指摘、5x review 収束)。新規 ADR は
  切らず、本ADRの枠内でこの 1 点だけ Decision として扱う。

### Decision (addendum): ctf-user の namespace 所有パターン

  採用した所有権パターン: `charts/ctf-user/templates/namespace.yaml` を削除し、
  `deploy-user.sh` が `helm upgrade --install` 実行前に `kubectl create
  namespace` + `kubectl label` (元の `ctf-user.labels` helper + PSA label と
  ほぼ同一のラベル集合 — 1点の意図的な差分は下記) で `ctf-<user>` Namespace
  を明示的に作成する「script-level 単一所有」方式
  (`charts/ctf-user/deploy-user.sh:257-268` 実測)。
  **本ADRの Decision (Option 3, platform 側 `namespaces` bootstrap release への
  集約所有) とは別の方式である。** これは後退ではなく、「1 release = 1
  namespace」という bootstrap release の前提 (静的な `.Values.namespaces` list
  を `range` するだけ) が、ctf-user のように **helmfile 管理外で参加者ごとに
  動的生成される** namespace には構造的にそのまま適用できない (Context 既述)
  ことに対応した選択であり、Context で予告されていた「単一所有パターンを
  ctf-user 側に適用する」という条件は、bootstrap release への相乗りではなく
  「namespace を作る唯一のスクリプト自身が単一所有者になる」という**同じ原則の
  別実装**として満たされている。

  **ラベル一致の検証結果 (訂正)**: VP が実コードで比較検証したのは、元の chart
  template (`ctf-user.labels` helper + PSA 3 ラベル) と `deploy-user.sh` の
  `kubectl label` 呼び出しの間で **完全一致ではない**。`app.kubernetes.io/
  managed-by` の 1 ラベルだけ値が異なる (元 chart: `{{ .Release.Service }}`
  → 常に `Helm`。`deploy-user.sh`: 固定文字列 `deploy-user.sh`)。他の全ラベル
  (`app.kubernetes.io/{name,instance,part-of}`・`falco-ctf/{username,
  challenge-id}`・PSA 3 ラベル `pod-security.kubernetes.io/{enforce,audit,
  warn}`) は完全一致する。この 1 点の差分はむしろ意図的で正しい —
  Namespace はもう Helm release の一部としてテンプレートされておらず
  script-level 所有になったので、`managed-by: Helm` と表示するのは実態と
  異なる誤表示になる。`managed-by: deploy-user.sh` の方が実際の所有者を
  正確に表す (R1/R2/R4 収束指摘、5x review)。cluster 実機検証は qa-engineer
  が並行実施中で、本追記の対象外。

  `scripts/check-namespace-ownership.sh` の `ctf-user` 除外は Issue #198
  (follow-up, 上で予告した通り) で**解除済み** (`ctf-user` は他4chartと同列に
  この検査対象になった。CI negative-test fixture と `.github/workflows/ci.yaml`
  の期待値も合わせて更新済み)。

  本追記は本ADRの既存 Verification (V1-V7) を書き換えない (それらは元々
  ctf-user を対象にしておらず、この追記時点でもその対象範囲は変わらない)。
  上記「Decision (addendum)」見出しのとおり、追記自体は Decision の追加である
  ことを明示する。


## Signposts

1. **実クラスタ E2E (Verification) が失敗したら Decision を白紙に戻す** — この
   ADR 自体が「実クラスタで発見された欠陥」を修正するものなので、修正の正しさも
   実クラスタでしか確認できない。V1-V7 のいずれかが失敗した場合は Option 1/2 を
   再検討する。
2. **namespace 数が増え、`namespaces` chart の 1 ファイル管理が煩雑になったら**
   (例: 10+ namespace、namespace ごとに quota/limitrange 等の追加ポリシーが要るように
   なったら) — 単一 chart から「ドメインごとの bootstrap chart」に分割する Option 2
   寄りの再設計を検討する。**ただし単一所有が構造的に必要なのは Namespace オブジェクト
   そのもの (複数 release が同一 object を要求しうる唯一の対象) に限られる**
   (R4 Finding 5 対応で追記, 2026-08-25): ResourceQuota/LimitRange/NetworkPolicy 等の
   namespaced object は、それを要求する release が (通常は) 1 つに定まるので、
   `namespaces` chart に集約する必要はなく、当該 object を必要とする app/platform-local
   chart 自身の `templates/` に置いてよい (例: `scoreboard` ns の Quota が要るなら
   `charts/scoreboard/templates/` に置く)。将来「namespace関連の設定は全部
   `namespaces` chart に集めよう」という誤った一元化に進まないよう、この区別を
   明記しておく。
3. **Helm が将来のメジャーバージョンで「複数 release が同じオブジェクトを
   安全に共有できる」一次サポートを導入したら** (例: shared/system namespace の
   公式概念) — 本ADRの bootstrap release という迂回が不要になる可能性がある。
   その時点で単純化を検討する。

## Verification

**全項目実施済み (2026-08-25, qa-engineer)。** V1 (2段記録)・V2・V3・V4・V7 は
実装 merge 前の初回ラウンドで実クラスタ確認済み (結果は下記「実施記録」)。
**V5・V6 は Issue app#189 で追加発注され、実装が両リポ main に merge 済みの状態
(app#190 / platform#113) で新規 disposable colima profile 上で実施し、両方 PASS**
(詳細は各項目の「実施記録」参照)。V1-V7 の全項目が実機確認済みになった。

- V1/V2/V3/V4: PASS
- V5: PASS (既存クラスタで `detectGrader.enabled` を false→true に切り替えても
  `already exists` 系の衝突が発生しないことを実機確認)
- V6: PASS ((i)(ii)(iii) の明示的合格基準すべて成立を実機確認。§9.3 の
  `collector` uninstall 欠落drift も実機で再確認し、platform#114 として起票)
- V7: 「削除される」の実測 (Decision の破壊シナリオ(b)が実際に起きることを確認—
  適用順序の制約は推奨ではなく hard requirement)
**各 V について、(a) fix適用前 (現行 main) の状態で実際にエラーが再現することを先に
記録する → (b) Decision適用後に再実行してエラーが解消したことを記録する、の2段を残すこと**
(R2 finding 1-b 対応, 2026-08-25 追記)。「fix後にgreenになった」だけでは、そもそも
壊れていたことの証明にならない (的外れなfixでもgreenに見えるケースを排除できない)。
V1 はこの2段を実施した (下記参照)。

- **V1 (空クラスタからの sync)**: **既存の共有・長寿命プロファイル `ctf-e2e` を使わない
  /破壊しない** (`ctf-e2e` は ADR-0007/ADR-0010 で「以後の E2E はこれを使う運用」と
  確立された再利用クラスタ — `docs/adr/0010-issue118-flag-env-leak-closure-and-i12-
  promotion.md:274-276`。R2 finding 1-a 対応, 2026-08-25)。新規の disposable profile
  名 (`ctf-e2e` と衝突しない名前) を明示指定して `colima start --profile <new-name>`
  で作成し、Falco/ingress-nginx/cert-manager 等を含む namespace が **一切存在しない**
  状態から `helmfile -e local sync` を実行する。sizing は独自に見積もらず
  `docs/PROD-GATE-E2E-PLAN.md §11.6` の「fresh, disposable rehearsal profile:
  4 vCPU / 6–8 GiB / 60 GiB」という既存手順を参照し、独自に再定義しない
  (R5 Finding 3 対応)。**2段記録**: (a) 本ADR適用前 (現行 main) のコード状態でこの
  新規 profile に対して実行し、Context 記載のエラー (`namespaces "auth-policy" not
  found` または `invalid ownership metadata`) が実際に再現することを先に確認・記録する
  → (b) Decision 適用後の状態で同じ新規 profile から再実行し、エラー無く完了することを
  確認する。検証後、新規 profile は `colima delete --profile <new-name>` で破棄してよい
  (`ctf-e2e` には触れない)。

  **実施記録 (qa-engineer, 2026-08-25)。結果: PASS (2段とも)。**
  - 新規 disposable profile `ctf-e2e-adr0011` を `colima start --profile ctf-e2e-adr0011
    --cpu 4 --memory 8 --disk 60 --kubernetes` で作成 (§11.6 の推奨値どおり。既存
    `ctf-e2e`/`default` は未使用・未変更)。
  - **kubeContext の落とし穴 (未文書化だったので明記)**: `helmfile.yaml.gotmpl` の
    `local` 環境は `kubeContext: colima` を**固定文字列で**参照しており、これは
    colima の *default* profile のコンテキスト名と一致する (named profile は
    `colima-<profile>` になる)。disposable profile を素朴に `helmfile -e local sync`
    すると、**気付かずに `default` profile (132日稼働の共有インスタンス、
    `docs/PROD-GATE-E2E-PLAN.md §11.0`) に向けて実行してしまう事故になる。**
    回避策: `kubectl config view --minify --context=colima-ctf-e2e-adr0011 --flatten`
    で disposable profile のコンテキストだけを抽出し、`kubectl config
    rename-context colima-ctf-e2e-adr0011 colima` で **スコープを切った一時
    kubeconfig ファイル内でのみ**コンテキスト名を `colima` に付け替え、
    `KUBECONFIG=<一時ファイル>` を helmfile 実行時にだけ指定した (実 `~/.kube/config`
    は無変更)。同様に `DOCKER_HOST` も disposable profile の docker socket に
    明示指定 (`make load-colima` 相当の `docker build` + `colima ssh --profile
    ctf-e2e-adr0011 -- sudo ctr -n k8s.io images import -` で `falco-ctf/{scoreboard,
    auth-policy,collector,docs}:dev` を当該 profile の containerd に個別ロード —
    `scripts/build-and-load.sh` は `colima ssh --` を素で呼ぶため active profile
    依存であり、そのままでは同じ事故を起こす。今回は script を使わず同義のコマンドを
    `--profile` 明示で手動実行した)。**この2点 (kubeContext 固定文字列/build-and-load.sh
    の active-profile 依存) は本ADRの対象外の既存事実だが、次回同種の disposable
    profile 検証をする者のために記録しておく。**
  - **(a) fix適用前 (main, both repos)**: 空の `ctf-e2e-adr0011` に対し
    `helmfile -e local sync` を実行 → **`auth-policy` release で
    `Error: create: failed to create: namespaces "auth-policy" not found`
    が実際に発生し FAILED (exit 1)** (Context 記載の障害モード1と完全一致)。
    `cleanupOnFail` により auth-policy の部分状態は残らず、それ以前に成功していた
    `detect-grader`/`ingress-nginx`/`falco`/`cert-manager`/`dex`/`oauth2-proxy` の
    6 release は正常に deployed のまま helmfile 全体が停止した。
  - **中間クリーンアップ**: (a) の結果クラスタは「一部 release だけ入った」半端な
    状態になったため、(b) を「真に空のクラスタ」から行う目的を守るために
    `helm uninstall` を6 releaseすべてに対して実行し (`detect-grader` の
    `helm uninstall` は旧chartの自己template Namespaceを実際に消し去った —
    ADR Consequences が予告する「個別 uninstall で Namespace が消える」旧挙動の
    直接確認になった)、残った空 Namespace 5 つも `kubectl delete ns` で削除して
    `kube-system`/`default`/`kube-*` だけの状態に戻した。
  - **(b) Decision適用後 (両branch同時checkout)**: 同じ `ctf-e2e-adr0011` に対し
    再度 `helmfile -e local sync` を実行 → **11 release (`namespaces`
    含む) 全てが `EXIT_CODE=0` で完了、FAILED RELEASES なし**。
    `namespaces` release (kube-system) が先に `auth-policy`/`collector`/`scoreboard`/
    `docs`/`ctf-detect-grader` の5 Namespaceを作成し、その後 `detect-grader` を含む
    5 release全てがその既存Namespaceへ問題なくdeployされた (`needs:
    kube-system/namespaces` の順序制御が実際に機能していることを確認)。
    全 pod (`auth-policy`/`cert-manager`×3/`collector`/`dex`/`docs`/`falco`関連×3/
    `ingress-nginx`/`oauth2-proxy`/`scoreboard`) が `1/1 Running` (画像は事前に
    `:dev` タグでロード済み)。**V1 は PASS。**
  - 検証後、`ctf-e2e-adr0011` profile はこのタスクの最後 (V7実施後) に
    `colima delete --profile ctf-e2e-adr0011` で破棄した (下記)。
- **V2 (2 回目の sync が no-op に近いこと)**: V1 直後にもう一度
  `helmfile -e local sync` を実行し、`namespaces` release も含め **エラーが出ない**
  (idempotent) ことを確認する。

  **実施記録 (qa-engineer, 2026-08-25)。結果: PASS。** V1(b) 完了直後に同じ
  `helmfile -e local sync` を再実行 → `EXIT_CODE=0`、FAILED RELEASES なし。
  11 release 全てが `UPDATED RELEASES` に上がり (差分無しの release は revision
  番号のみ増加。`namespaces` は `0s` duration でno-op相当)、エラーは一切出なかった。
- **V3 (Namespace の所有権)**: `kubectl get ns auth-policy -o yaml` で
  `meta.helm.sh/release-name: namespaces` (chart 側の release 名と一致) になっていること、
  `helm -n auth-policy list` で `auth-policy` release 自体は正常に見えることを確認する。

  **実施記録 (qa-engineer, 2026-08-25)。結果: PASS。** V1(b) 完了直後の状態で
  `kubectl get ns auth-policy -o yaml` を確認 → `annotations` に
  `meta.helm.sh/release-name: namespaces` / `meta.helm.sh/release-namespace:
  kube-system` (期待どおり)。`helm -n auth-policy list` は `auth-policy` release
  (`REVISION 1`, `STATUS deployed`) を正常に表示 — 「Namespace は `namespaces`
  release が所有し、`auth-policy` release 自体はその中で独立して健全に動く」という
  Decision の狙いが実測で成立していることを確認した。
- **V4 (docs の PSA restricted 化が pod 起動を壊さないこと)**: `docs` release の
  Pod が `restricted` PSA の下で `Running` になることを確認する (壊れる場合は
  `podSecurity.enforce: baseline` に後退させる判断が要る — この場合は本 ADR の
  Decision の該当行を訂正する追記 commit を同じ PR に含める)。

  **実施記録 (qa-engineer, 2026-08-25)。結果: PASS。** `kubectl get ns docs -o
  jsonpath='{.metadata.labels}'` で `pod-security.kubernetes.io/enforce: restricted`
  (+ `audit: restricted`、両方 `-version: latest`) を確認。`kubectl -n docs get
  pods` は `docs-<hash>` を `1/1 Running` で表示 (`nginxinc/nginx-unprivileged`
  ベースの想定どおり、restricted PSA 下でも起動を妨げない)。**Decision の該当行
  (podSecurity を baseline に後退させる分岐) は不要 — 後退は行わない。**
- **V5 (detect-grader 再有効化時の非衝突)**: **`local` 環境は `detectGrader.enabled`
  の既定が `true`** (`helmfile/environments/default.yaml.gotmpl:24`、`local.yaml.gotmpl`
  に override 無し、2026-08-25 実測確認、Context 参照) なので、**V1 (空クラスタでの
  `local` sync) がそのまま detect-grader の非衝突検証を兼ねる** — local について追加の
  フラグ操作は不要 (R2 finding 1-c + R4 Finding 2 対応で訂正)。`prod` (現在
  `detectGrader.enabled: false`, `prod.yaml.gotmpl:146-147`) については、44.2
  cutover 相当の確認として `detectGraderImage` はダミー値のまま `detectGrader.enabled:
  true` に一時的に切り替えて **`helmfile -e prod diff`** (apply はしない。prod への
  実 sync はスコープ外) で `already exists` 系のエラーが diff プランに出ないことを
  確認し、確認後は `false` に戻す。

  **実施記録 (qa-engineer, 2026-08-25, Issue app#189)。結果: PASS。** V5 の本質は
  「クラスタが既に他 release で稼働中の状態で `detectGrader.enabled` を
  false→true に切り替えても衝突しないか」であり、これは V1 (最初から
  `enabled: true` で空クラスタに sync する) では一度も踏んでいない遷移だった
  (V1 は「常に true」を確認しただけ)。この遷移を実機で作った:
  - 新規 disposable colima profile `ctf-e2e-v189-56` を `colima start --profile
    ctf-e2e-v189-56 --cpu 4 --memory 8 --disk 60 --kubernetes` で作成
    (`ctf-e2e`/`default` 未使用・未変更。V1 実施記録の kubeContext 固定文字列
    ワークアラウンドを再利用)。app 側 (`db57d55`, #190) / platform 側 (`9a10b38`,
    #113) は両方とも main に merge 済みの状態を使用。
  - **新規に遭遇した落とし穴 (V1実施記録にも build-and-load.sh の gotcha を追記済み
    だが、それとは別方向)**: `docker save <img> | colima ssh --profile <new> --
    sudo ctr -n k8s.io images import -` で containerd に import しても、この
    colima profile の k3s は `k3s server --docker` (cri-dockerd 経由) で動作しており
    **kubelet は VM の Docker daemon 自身の image store しか見ない**
    (`/run/k3s/containerd/containerd.sock` は listen していない — `connection
    refused`)。images を `ctr -n k8s.io images ls` で確認できても kubelet 側は
    `ErrImagePull: pull access denied for ..., repository does not exist` で
    real pull を試み失敗する (`auth-policy` Pod で実際に発生・観測)。
    正しい手順は `docker save <img> | colima ssh --profile <new> -- sudo docker
    load` (VM の Docker daemon へ直接 load)。この profile 単位の docker daemon への
    load を4イメージ (`auth-policy`/`scoreboard`/`collector`/`docs`, すべて `:dev`)
    に対して行い、以後の sync はすべて成功した。platform#112 に追記コメント済み
    (この issue の既存懸念 [build-and-load.sh の active-profile 依存] とは別方向の
    同根の落とし穴として記録)。
  - **(a) baseline**: `helmfile --state-values-set detectGrader.enabled=false
    -e local sync` を実行 → **11 release中10 release (namespaces含む、
    detect-grader除く) が `EXIT_CODE=0` で完了、FAILED RELEASES なし**。
    全 Pod `1/1 Running` (`kubectl get pods -A` で確認)。
  - **(b) 再有効化**: 同じ稼働中クラスタに対し
    `helmfile --state-values-set detectGrader.enabled=true -e local diff` を実行
    → **`already exists` も `Error` も出力ゼロ** (exit 0, 157行の diff plan)。
    続けて同フラグで `sync` を実行 → **11 release全て (`detect-grader` 含む)
    `EXIT_CODE=0`、FAILED RELEASES なし**。`kubectl get ns ctf-detect-grader
    -o yaml` で `meta.helm.sh/release-name: namespaces` (namespaces release が
    先に所有) を確認、`helm -n ctf-detect-grader list` で `detect-grader` release
    (`REVISION 1`, `deployed`) も正常。`ctf-detect-grader` の RBAC
    (`Role`/`RoleBinding: detect-grader-runner`) と `NetworkPolicy:
    detect-grader-deny-all` も正常に作成された。**`needs: kube-system/namespaces`
    が既存クラスタでの再有効化時にも機能し、V1 で確認した「最初から enabled:true」
    経路と同じ非衝突が、より厳しい「稼働中クラスタでの false→true 遷移」経路でも
    成立することを確認した。**
- **V6 (teardown 後の再 sync)**: **`helmfile destroy` は使わない**
  (`docs/P13-RUNBOOK.md:207-208` / `docs/prod-deploy.md:932` が明記する project の既定:
  helm v4 + helm-secrets 不整合で `unknown command secrets` になる。R4 Finding 3
  対応で訂正、2026-08-25)。`docs/operations.md §9.3` の順序どおり `helm uninstall` を
  直叩きしてteardownし (§9.3 が現状 `collector` の uninstall を欠落させている既存drift
  への対応として `helm -n collector uninstall collector` も手動で追加する)、その後
  `helm -n kube-system uninstall namespaces` を追加実行する。**明示的な合格基準**
  (R2 finding 1-d/4 対応): (i) 各 app release (`scoreboard`/`auth-policy`/`docs`/
  `collector`) を `helm uninstall` した**直後**に `kubectl get ns <ns>` が **succeed
  する**こと (Namespace がまだ残っている — Consequences で述べた挙動変化の直接確認)。
  (ii) その後 `helm -n kube-system uninstall namespaces` を実行し、`kubectl get ns
  auth-policy` 等が **NotFound になる**ことを確認する。(iii) 全て uninstall 後、
  再度 `helmfile -e local sync` を実行し、V1 と同じ手順でエラー無く完了することを
  確認する。

  **実施記録 (qa-engineer, 2026-08-25, Issue app#189)。結果: PASS ((i)(ii)(iii)
  すべて成立)。** V5 実施直後の同一クラスタ (`ctf-e2e-v189-56`, 11 release 全て
  `deployed`) を使用。`helmfile destroy` は使用していない (project 既定どおり)。
  - **§9.3 の `collector` uninstall 欠落drift を実機で再確認**: `docs/operations.md`
    §9.3 の「1. app 層」ブロックは `scoreboard`/`auth-policy`/`docs` の3行のみで
    `collector` の uninstall コマンドが実際に無いことをファイル読み込みで確認
    (`operations.md:1211-1215`)。既存の follow-up issue は無かったため
    **platform#114 として新規起票した** (2026-08-25)。
  - **(i) 各 app release uninstall 直後の namespace 残存確認**: `helm -n
    scoreboard uninstall scoreboard` → `kubectl get ns scoreboard` は
    `STATUS Active` (succeed、残存)。同様に `auth-policy`/`docs`/
    **`collector` (§9.3 drift の手動追加分)** の4releaseすべてについて、
    uninstall 直後の `kubectl get ns <ns>` が succeed し `Active` であることを
    確認した (期待どおり — Namespace のライフサイクルが `namespaces` release に
    移っているため、個別 app release の uninstall では消えない)。続けて
    `ingress-nginx`/`oauth2-proxy`/`dex`/`falco`/`cert-manager`/`detect-grader`
    も uninstall (§9.3 の残りの手順 + platform-local chart の同型対応)。
  - **(ii) `namespaces` release uninstall 後の NotFound 確認**: `helm -n
    kube-system uninstall namespaces` を実行 → 実行直後は
    `auth-policy`/`scoreboard`/`docs`/`collector`/`ctf-detect-grader` の5
    namespace が `Terminating` に遷移し、数秒後に全て
    **`Error from server (NotFound): namespaces "<ns>" not found`** になった
    (5/5 確認)。`cert-manager`/`dex`/`falco`/`oauth2-proxy`/`ingress-nginx` の
    5 namespace (各 release 自身が `createNamespace: true` で作成する、
    ADR-0011 の対象外) は helm uninstall 後も `Active` のまま残存 — これは
    ADR-0011 と無関係な既存の helm 標準挙動 (helm uninstall は
    `--create-namespace` で作った namespace を自動削除しない) であり、
    今回の検証範囲では問題ではない。
  - **(iii) 再sync確認**: 全 uninstall 後、`helmfile -e local sync` (フラグ
    override 無し = `local` の既定 `detectGrader.enabled: true` のまま) を再実行
    → **11 release全て `EXIT_CODE=0` で完了、FAILED RELEASES なし** (`namespaces`
    が5 namespace を再作成 → 4 app release + `detect-grader` が新規 install)。
    `kubectl get pods -A` で全 Pod (`auth-policy`/`cert-manager`×3/`collector`/
    `dex`/`docs`/`falco`関連×3/`ingress-nginx`/`oauth2-proxy`/`scoreboard`) が
    `1/1 Running` を確認。**V6 は PASS。**
  - 検証後、`ctf-e2e-v189-56` profile は `colima delete --profile
    ctf-e2e-v189-56 --force` で破棄した (`ctf-e2e`/`default` は無変更)。
- **V7 (Helm v4.1.3 の upgrade prune 挙動の実測 — R5 HIGH「適用順序の制約」の裏付け,
  2026-08-25 追加)**: Decision で述べた破壊シナリオ (b) (app 側が先行し、`namespaces`
  release/`needs` が未整備のまま sync してしまう中間状態) を実機で再現し、Namespace
  object が実際に削除されるかを記録する。手順: (i) 旧 chart (Namespace self-template
  あり) で `auth-policy` を空 profile に `helm install`。(ii) chart から
  `templates/namespace.yaml` を削除した新バージョンに対して、`namespaces` release も
  `needs` も追加していない旧 platform helmfile 定義のまま `helm upgrade` (または
  該当 release だけの `helmfile sync --selector name=auth-policy`) を実行する。
  (iii) `kubectl get ns auth-policy` の結果 (削除されたか/残ったか) を記録する。
  削除される場合は「適用順序の制約は hard requirement (単なる推奨ではない)」と
  Consequences に追記する。残る場合も「今回の Helm v4.1.3 では残ったが、将来の
  SSA 実装変更で挙動が変わりうる、これは保証ではない」と限定付きで記録する。

  **実施記録 (qa-engineer, 2026-08-25)。結果: 削除される (PASS = 破壊シナリオ (b) の
  実在を確認。「適用順序の制約は推奨ではなく hard requirement」— 下記の通り
  Consequences に追記済み)。**
  - V1(b)/V2/V3/V4 確認後の同クラスタ上で、まず現行 (fix適用済み) `auth-policy`
    release を `helm -n auth-policy uninstall auth-policy` で削除し、続けて
    `kubectl delete ns auth-policy --wait=true` で Namespace 自体も削除し、
    「まだ何も存在しない」状態から実験を開始した。
  - **(i)** `main` 時点の旧 `auth-policy` chart (`templates/namespace.yaml` あり、
    `git archive main -- charts/auth-policy` で抽出) を
    `helm install auth-policy <旧chart> -n auth-policy --create-namespace
    --set image.tag=dev ...` で新規 install。`--create-namespace` は「(ADR Context
    が説明する) 元々 namespace が既に存在していた世界」を再現するための手段に過ぎず、
    Namespace オブジェクト自体の所有権は旧chart自身の自己templateが握った
    (`kubectl get ns auth-policy` → `meta.helm.sh/release-name: auth-policy`、
    `release-namespace: auth-policy` — `namespaces`/kube-system ではない)。
  - **(ii)** `feat/adr-0011-app-namespace-removal` 側の新チャート
    (`templates/namespace.yaml` 削除済み) に対して、`namespaces` release・
    `needs` を一切介さない **素の `helm upgrade auth-policy <新chart> -n
    auth-policy --set image.tag=dev ...`** を実行 (helmfileも経由しない、
    最も直接的な「旧platform定義のまま」の再現)。
  - **(iii) 結果**: `helm upgrade` 自体は `STATUS: deployed` / `exit 0` で
    正常終了したにもかかわらず、コマンド返却直後の `kubectl get ns auth-policy`
    は既に **`Terminating`**、約5秒後には **`Error from server (NotFound):
    namespaces "auth-policy" not found`** — **Namespace オブジェクトが実際に
    削除された。** `helm -n auth-policy list` / `helm status auth-policy -n
    auth-policy` も `release: not found` (Namespace 削除に伴い release secret
    も消滅)。**Helm v4.1.3 の upgrade は「旧revisionのmanifestにあり新revisionの
    manifestに無いobjectをpruneする」という3-way-merge相当の挙動を実際に持ち、
    かつその対象は Namespace オブジェクトそのものを含む** ことが実機で確認された。
  - **結論・Decisionへの裏付け**: Decision が「未検証」としていた破壊シナリオ (b)
    は**仮説ではなく実際に起きる**。「app側が先行し、platform側の
    `namespaces`/`needs` 整備が伴わない中間状態」を経由すると、対象Namespaceは
    (中に何が入っていようと) 丸ごと削除される。**`scoreboard` release で同じ
    経路を辿れば sqlite PVC を含めて削除される、というデータ損失リスクの評価は
    「想定される」から「実証済み」に格上げする。**「適用順序の制約」節
    (Decision) は **hard requirement であり、単なる推奨ではない** — 本追記に伴い
    Consequences にもその旨を明記する (下記)。

## Advice

- **VP (前セッション, 日付不詳・本タスク発注時点で共有された所感)**: (a) presync
  adopt hook / (b) chart 自己管理撤去 + createNamespace / (c) namespace 専用
  bootstrap release、の 3 案を提示。(b) か (c) が本命、条件は PSA restricted label を
  失わないこと。本ADRは (c) を土台にしつつ、(b) が抱える「PSA label が
  `helmfile diff` の管理対象から外れる」弱点を避けるため、bootstrap chart 自体で
  PSA label も宣言的に管理する形 (b)+(c) の統合として Option 3 を組んだ。
- **5観点レビュー (R1 security-engineer / R2 qa-engineer / R3 conventions /
  R4 architect(自己, 独立再査読) / R5 cross-repo, 2026-08-25)**: 初稿を独立レビューし、
  合計19件 (BLOCKING 3件・MEDIUM 9件・LOW 7件) を指摘。VP が統合判断し全件反映済み。
  主な反映: PSA label の enforce/audit/warn 独立指定化 (R1 HIGH「warn欠落」+
  R2 finding 5-b「detect-graderの非対称変化」+ R2 finding 5-a「auditの自動導出不整合」)、
  app/platform 側の同時landing要件・破壊シナリオ明記・V7追加 (R5 HIGH)、detect-grader
  の障害が「潜在的」ではなく実際に発火済みという Context の訂正 (R2 finding 1-c +
  R4 Finding 2 — 収束)、V1 の `ctf-e2e` 保護と `PROD-GATE-E2E-PLAN.md §11.6` 参照
  (R2 finding 1-a + R5 Finding 3)、V6 の teardown 手順を project の禁止事項
  (`helmfile destroy` 不使用) に整合させる訂正 (R4 Finding 3 — 単独)、V1/V5/V6 の
  2段記録・明示的合格基準の追加 (R2 finding 1-b/1-d/4)、runbook反映箇所の具体化
  (R5 Finding 2)、静的検査の follow-up issue 化 platform#111 (R1 MEDIUM)、
  「Helm の ownership 機構に一切依存しない」という過大主張の訂正 (R4 Finding 1 —
  単独、WebSearchでHelm v4のSSA化/`meta.helm.sh/owner`導入を確認して裏付け強化)、
  Signposts項番2(旧)の Consequences への移動 (R4 Finding 6)、Signposts項番3への
  ResourceQuota/LimitRange拡張性の注記 (R4 Finding 5)。file:line の off-by-one
  4箇所と `helm version --client` の実行不能な表記も訂正 (R3, LOW)。
