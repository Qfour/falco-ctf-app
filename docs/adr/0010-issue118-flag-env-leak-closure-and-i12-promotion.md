# ADR-0010: Issue #118 (H1: 全ミッション CTF_FLAG_* の challenge コンテナ env 漏えい) は main で既に閉じている — 新設計は行わず、I12 を Hard Invariant へ昇格する

- Status: **Accepted** (2026-08-25, VP 承認。VP が自ら `charts/ctf-user/templates/pod.yaml` /
  `scripts/check-flag-isolation.sh` を実読・実行し [production-default scope `challengeId=all`
  を含む5 render-matrix scope 全て green] 、本 ADR の実測結果を独立に裏付けた上で承認)。
  新規の設計判断はゼロなので security-engineer の新規独立監査は要求しない。I12 昇格
  (`.claude/rules/falco-ctf-app-conventions.md`) は本 ADR の承認と同時に VP が実行済み。
- 関連: Issue #118 (`security: 本番既定経路で全ミッションの CTF_FLAG_* が env 注入され...`,
  OPEN, priority:P1, CEO 決定「次イベント前に閉じる」2026-08-18)、
  [ADR-0001](0001-flag-plant-initcontainer-not-challenge-env.md) (Accepted, Option B = H1 の本体解決),
  [ADR-0007](0007-plant-mount-directory-granularity.md) (Accepted, Option 1 = ADR-0001 の派生決定の欠陥修正。
  対象は Issue #150 — H1 とは別の欠陥),
  app#131/#135/#139 (ADR-0001 実装 merge済), app#177/#180 (ADR-0007 実装 merge済),
  app#178/#179 (ADR-0007 の follow-up, H1 とは無関係)

## Context

### 依頼の経緯

VP から「Issue #118 の設計を進めてほしい」という委任を受けた。Issue #118 は
「本番既定経路 (`deploy-event-workspaces.sh:66` `CHALLENGE=all` → `deploy-user.sh` `ALL_MODE=1`
→ `pod.yaml` の `range` で全ミッションの `CTF_FLAG_<ID>` を challenge コンテナの env に注入)
により `env | grep CTF_FLAG` で全 evade フラグが無検知取得できる」という **H1** を報告している。
依頼文は「(a) plant 実行後に env を落とす (b) file 経由注入 + 権限分離 (c) per-mission workspace」
という 3 option を検討候補として挙げ、「軽減 (mitigation) と遮断 (block) を区別して判定せよ」
と指示していた。

### 実測: この H1 は ADR-0001 が既に扱った問題そのものである

Issue #118 本文の「事実」節と ADR-0001 の Context 冒頭は、file:line までほぼ一致する:

| | Issue #118 | ADR-0001 Context |
|---|---|---|
| 経路 1 | `deploy-event-workspaces.sh:66 CHALLENGE=all` | 同一 file:line |
| 経路 2 | `deploy-user.sh:163-176 ALL_MODE=1 --set challenge.allMissions=true` | `:162-176` (1 行差は編集時期のずれ) |
| 経路 3 | `pod.yaml:149-153 range で CTF_FLAG_<ID> を env 注入` | `:164-173`、同一記述 |

Issue #118 は 2026-08-17 作成 (`gh api .../issues/118` 実測: `created_at: 2026-08-17T16:47:10Z`)、
ADR-0001 は 2026-08-18 に起草・Accepted (app#131 merge)。**Issue #118 は ADR-0001 を生んだ
発見チケットであり、別問題ではない** — 進行状況欄の「architect が ADR 設計中」は当時進行中だった
ADR-0001 の起草を指している。

### 実測: ADR-0001 (Option B) は main に完全実装済みで、H1 を「遮断」している

依頼で要求された「軽減 vs 遮断」の判定軸そのものが、ADR-0001 の Context に
「参加者が到達できる読み出し経路 全列挙」表として既に存在する
(`docs/adr/0001-flag-plant-initcontainer-not-challenge-env.md:243-255`)。
本 ADR はこれを再作成せず、**現行 main の実コードで再検証**した:

- `charts/ctf-user/templates/pod.yaml:209-247` (`challenge` コンテナ定義): `env` は
  `FALCO_CTF_USER` / `FALCO_CTF_CHALLENGE` / `FALCO_CTF_COLLECTOR` / `FALCO_CTF_SCOREBOARD` /
  `FALCO_CTF_DNS_SUFFIX` の 5 つのみ。`CTF_FLAG_*` は**存在しない**。同 `:240-244` は
  `challenge.extraEnv[].name` が `CTF_FLAG_` prefix を持つ場合に `helm template` 自体を
  `fail` させる template-time assert (Verification 1-12 相当)。
- `charts/ctf-user/templates/pod.yaml:67-89` (`plant` initContainer): `envFrom.secretRef.name:
  ctf-flags` のみでフラグを受け取る。`plant` は同一 Pod 内の initContainer で **`restartPolicy`
  キーを持たない** (`:89-95` のコメントどおり non-sidecar、完了後に終了 = `challenge` 起動時には
  既にプロセスが存在しない → `/proc/1/environ` 経路も再生しない)。
- `charts/ctf-user/values.yaml:90-99`: フラグは `plant.flags` として保持され、
  「NEVER injected into this container (ADR-0001 I12)」と明記。
- `challenges/values-all.yaml` (全ミッション deploy 時の生成物, `make gen-values` 出力):
  `plant.seedScript` が 03/05/10 の `plant.sh` を結合した initContainer 用 script、
  `plant.mounts` は `[{path: /etc, readOnly: false}, {path: /root/.ssh, readOnly: true}]`
  のみ。`challenge.extraEnv` や `flags:` の literal は**一切現れない**
  (`grep -rn CTF_FLAG` の全リポ走査で、`challenge` コンテナ側に到達する経路は 0 件、
  `plant` 側・生成物のコメント・ドキュメントの 3 種のみ — 本 ADR 起草時に architect が実測)。
- `charts/ctf-user/deploy-user.sh:277`: `assert-flag-isolation.sh` を **`set -e` 下・
  `||` ラップ無しで**呼ぶ (実機 fail-closed assert、ADR-0001 Verification 3 = F2)。
- `scripts/check-flag-isolation.sh`: `helm template` 出力に対する allowlist 型 static assert
  (ADR-0001 Verification 1 = F1)。CI `flag-guard` (`.github/workflows/ci.yaml:61,67`) から
  実行される required check。

→ ADR-0001 の読み出し経路 1-5 表 (env / `/proc/1/environ` / API 経由 Pod spec / 運用者画面 /
Helm release Secret) は **main の実装で ✅ (閉じている) のまま**であることを確認した。
経路 6 (planted file 自体) は設計上の意図 (それがミッション)、経路 7 (seed root の代替 path) は
F5 (seed root を mount しない) が禁止し、`scripts/check-flag-isolation.sh` の 1-4/F5 assert が
機械強制する。

**結論: H1 は main で「遮断」されている。「閉じたつもりで閉じていない」という Issue #118 の
懸念(最重要評価軸)は、ADR-0001 の readOnly/allowlist assert 実装によって既に晴れている。**
本 ADR はこれを再設計しない — 依頼で挙げられた (a)/(b)/(c) の評価は ADR-0001 が
Option A (却下・「閉じない」)/Option B (採用) として既に行っており、(c) per-mission workspace
は ADR-0001 の制約 C1 (「1 workspace = 全ミッション」の体験維持) の下で検討対象外と裁定済み。

### 実測: 残存していた別欠陥 (Issue #150) も ADR-0007 で既に閉じている

ADR-0001 (Option B) の初回実装 (mount 方式 B1 = plant-target をファイル単位で `subPath` bind)
は、**H1 とは別の欠陥**を生んでいた: ファイル destination への bind mount 自体が
container runtime の mount-setup 動作として `Read sensitive file untrusted` を deploy ごとに
発火させ、mission 02 が操作ゼロで auto-solve する (Issue #150、qa-engineer が 2026-08-19 発見)。
ADR-0007 (Option 1 = ディレクトリ granularity mount) がこれを修正し、2026-08-25 に Accepted・
merge 済み (`62acdfe` #180)。現行 `pod.yaml:278-286` の `plant.mounts` range は
ディレクトリ (`/etc`, `/root/.ssh`) を mount し、`scripts/check-flag-isolation.sh` の
1-4/1-18 assert (`granularity-neutral rewrite` とコメントされている、
`scripts/check-flag-isolation.sh:67,243,274-284`) がこれを機械強制している。

**Issue #150 は H1 と別問題であり、Issue #118 の scope ではない。** 混同しない
(ADR-0001 と ADR-0007 の関係と同型— 本決定 vs 派生決定の欠陥)。

### 未昇格のまま残っている手続き的な穴

`.claude/rules/falco-ctf-app-conventions.md` の Hard Invariants 表は I1-I10 と I14 のみを持ち、
I12 (フラグ隔離) は footnote 表で「機構は main に landing 済み。**残るのは昇格作業のみ**」
と記されたまま **Proposed のまま昇格されていない** (ADR-0001 rev.4 時点で発効条件 = F1 + F2 の実装、
2026-08-18 時点で `f4915d9`/`efc1396` により両方 landing 済み)。

ADR-0007 の Advice「I12 について」節はさらに 3 条件を課していた
(0007:676-694):

1. I12 の本文を「到達可能性」で書く (機構=`readOnly`ではなく)
2. `readOnly: true` に依拠する assert を granularity 中立に書き直す
3. I12 の本文に I13a/I13b (deploy 無汚染、まだ FAIL 中) を含めない

本 ADR が実測したとおり、3 条件は**すべて満たされている**:

1. ✅ I12 の確定文言 (ADR-0001:730-742) は「フラグ実値を到達させる経路を一切設けない」であり、
   `readOnly` のような機構語を含まない
2. ✅ `scripts/check-flag-isolation.sh:243-323` の `assert_challenge_mounts` が
   「granularity-neutral rewrite」(同ファイル `:67` のコメント) 済みで、
   `mountPath` は「宣言済み plant-target の enclosing directory」への一致を見ており、
   ファイル単位一致には依存していない
3. ✅ I12 の文言 (上記) は採点状態や catalog ルール発火に触れていない

→ **I12 は今、昇格条件をすべて満たしている。** Hard Invariant 昇格は意思決定マトリクス上
architect 合意 + VP 承認事項であり、architect (本 ADR) はこの手続きを実行する。

## Options

新設計ではないため、本節は「何をするか / しないか」の選択を記録する (トレードオフ表ではない)。

### Option 1 — 何もしない (Issue #118 を open のまま放置)

- 変更点: なし。
- コスト: ゼロ。
- リスクと可逆性: **CEO の「次イベント前に閉じる」指示に対して Issue が open のままだと、
  次に読む人間 (CEO/VP) が「まだ未着手」と誤解し、同じ調査を再度依頼する** (Issue #144 の
  ADR 番号衝突と同型の「台帳と実態のずれ」)。可逆だが無意味な再作業コストを生む。
- 効き始める閾値: 次にこの Issue を誰かが読んだ瞬間。

→ **却下。** 実態と台帳を一致させないコストが、閉じる作業コストより高い。

### Option 2 — Issue #118 の scope で全く新しい設計を行う (依頼された (a)/(b)/(c) を再評価)

- 変更点: ADR-0001 の Options 節を無視し、(a) postStart 後の env 落とし / (b) file 経由 +
  権限分離 / (c) per-mission workspace を再度評価する新規 ADR を書く。
- コスト: 高い。ADR-0001 (rev.1-7、1785 行) が既に (a) を「閉じない・有害」として却下し、
  (b) 相当を Option B として厳密に実装・機械検証済みであることを無視する。
- リスクと可逆性: **ADR の重複作成は「規律」節が禁じる方向そのもの** — 既存 Accepted ADR は
  書き換えず supersede する、が本件は supersede すべき新事実 (H1 に関する) が無い。
  重複 ADR は将来の読者に「どちらが正典か」を再調査させる負債になる。
- 効き始める閾値: 無し (常に有害)。

→ **却下。** 依頼時点では ADR-0001/0007 の存在と landing 状況が VP 側でも完全に把握されておらず
(進行状況欄が「architect が ADR 設計中」のまま更新されていなかった)、この再評価要求自体は
合理的な指示だった。しかし実測した結果、再設計に値する新事実が無い。

### Option 3 — 事実確認 + I12 昇格 + Issue クローズを ADR として記録する (本 ADR・推奨)

- 変更点: (1) 本 ADR で H1 の閉止を実測・記録する。(2) I12 を Hard Invariants 表に昇格する
  (`.claude/rules/falco-ctf-app-conventions.md` の編集、VP 承認後)。(3) Issue #118 を
  ADR-0001/ADR-0007/本 ADR へのリンク付きコメントでクローズする。
- コスト: 低い (文書のみ、コード変更ゼロ)。
- リスクと可逆性: 完全に可逆 (文書の追記・Issue の再オープンは常に可能)。
  唯一のリスクは「本当に閉じているか」の判定を architect 単独の再検証に依存する点だが、
  ADR-0001/ADR-0007 は既に security-engineer の独立監査を複数ラウンド (rev.2-7、review-5x T3) 経て
  Accepted になっており、本 ADR は**新しい独立監査を要求しない** (新しい設計判断が無いため)。
- 効き始める閾値: 即時 (VP 承認後)。

→ **採用。**

## Decision

**Option 3 を採る。**

1. **Issue #118 (H1) は main で既に「遮断」済みと判定する。** 新しい設計・実装 PR は不要。
   理由: ADR-0001 (Option B, Accepted, app#131/#135/#139 merge済) が H1 の読み出し経路 1-5 を
   ✅ で閉じ、ADR-0007 (Accepted, app#177/#180 merge済) が派生した別欠陥 (Issue #150) を修正し、
   両方の機械検証 (`scripts/check-flag-isolation.sh` = CI `flag-guard` required check、
   `charts/ctf-user/assert-flag-isolation.sh` = deploy 時 fail-closed) が main で稼働中である。
2. **I12 を Hard Invariant として昇格する。** ADR-0007 の Advice が課した 3 条件 (到達可能性表現 /
   granularity 中立な assert / I13a・I13b 非依存) をすべて満たしていることを実測確認した。
   昇格の実施 (`.claude/rules/falco-ctf-app-conventions.md` の編集) は VP が実行する
   (architect は文書のみを担当し、conventions.md の Hard Invariants 表への追記は本 ADR の
   承認をトリガーとする VP 作業とする — architect 単独では conventions.md を直接書かない)。
3. **Issue #118 は本 ADR + ADR-0001 + ADR-0007 へのリンクを付けて VP がクローズする。**
   Issue #150 / #178 / #179 / #120 / #121 は別欠陥の別 Issue であり、本クローズの対象に含めない
   (混同すると「H1 を閉じた PR がどれか」を将来追跡できなくなる)。

理由 (一文): **依頼された設計判断は、依頼が出された時点で既に別 ADR (0001/0007) によって
実装まで完了しており、本 ADR の役割は再設計ではなく実測による閉止確認と、その確認が可能に
した手続き上の後始末 (I12 昇格・Issue クローズ) である。**

## Consequences

### 諦めたもの

- 依頼で名指しされた Option (a)/(b)/(c) の**新規評価**。ADR-0001 の Options 節が既に扱っており、
  重複すると 2 つの ADR が同じ結論に別の言葉で到達し、将来の食い違いリスクを生む。
- **security-engineer による本 ADR 自体の新規独立監査。** ADR-0001/0007 は既に複数ラウンドの
  独立監査 (rev.2-7、review-5x T3) を経ているため、本 ADR (新しい設計判断を含まない) に対する
  追加監査は増える紙のレビューであって新しい保証を生まない。**ただし I12 昇格を含む
  `.claude/rules/falco-ctf-app-conventions.md` の実編集 PR には、通常の Hard Invariant 変更と
  同じ扱い (auth/ingest/secrets/CSP と同格ではないが、Hard Invariant 表の変更なので)
  VP レビューは必須とする** (下記 Verification)。

### 新たに守る不変条件

- **I12 (Hard Invariant へ昇格)**: workspace Pod の `challenge` コンテナには、フラグ実値を
  到達させる経路を一切設けない (env / envFrom / volumeMount / seed root mount / SA token を
  含むがこれらに限らない)。機械強制: `scripts/check-flag-isolation.sh` (静的、CI `flag-guard`)
  + `charts/ctf-user/assert-flag-isolation.sh` (実機、`deploy-user.sh` から fail-closed 呼び出し)。
  文言・機構の詳細は ADR-0001 §「新たに守る不変条件 (提案: I12)」および ADR-0007 §「I12 について」
  を正典として参照する (本 ADR は昇格の判定のみを行い、定義を再掲しない)。

### runbook / 運用への影響

- なし。本 ADR はコード変更を伴わない。ADR-0001 の runbook 影響 (本番投入ゲート等) は
  既に app#131/#135/#139/#177/#180 merge により発効済みで、本 ADR は追加の制約を課さない。
- Issue #118 のクローズは VP が実施 (本 ADR は architect 権限の範囲でクローズを推奨するのみ)。

## Signposts

この判定 (「H1 は既に閉じている・再設計不要」) を覆す観測可能な信号:

1. **`scripts/check-flag-isolation.sh` または `charts/ctf-user/assert-flag-isolation.sh` が
   CI/deploy から外れる、または skip される変更が入る** — H1 の遮断は allowlist assert に
   依存しているため、assert が回らなくなった瞬間に再度「軽減未満」に戻る。
2. **`charts/ctf-user/values.yaml` の `challenge.extraEnv` に将来 `CTF_FLAG_` 以外の経路で
   フラグ相当の秘密情報を流す変更が入る** (例: `extraEnvFrom` の新設。ADR-0001 Verification 1-13
   はこの口の非存在を assert しているが、chart 構造が変わればこの assert 自体を書き直す必要がある)。
3. **`plant` initContainer が `restartPolicy: Always` を持つ変更が入る** (native sidecar化。
   ADR-0001 Verification 1-14 が禁止しているが、将来 chart を大きく書き換える際に見落とされうる)。
4. **I12 昇格後、実際の本番 deploy (次イベント) で `env | grep CTF_FLAG` 相当が実機再現テストとして
   実施されていない状態のまま本番投入される** — 本 ADR も ADR-0001/0007 と同様、
   「実機でのみ確認可」の項目 (下記 Verification) を実機実行するまで「prod で確認済み」とは書かない。

## Verification

**この判定 (H1 は main で閉じている) が守られていることを機械で確認する方法:**

1. **既存 (再掲しない、新設なし)**: `make check-flag-isolation` (`scripts/check-flag-isolation.sh`,
   CI `flag-guard` required check) + `charts/ctf-user/assert-flag-isolation.sh` (deploy-user.sh:277,
   `set -e` 下で fail-closed) が ADR-0001 Verification 1-3 の全項目 (1-1〜1-21, 2-1〜2-8, 3-1〜3-2)
   + ADR-0007 Verification 1-2 (granularity assert + negative test) を検証し続けること。
   これは本 ADR が新設するものではなく、**すでに main で稼働中の機構が今も稼働していること**を
   確認する経路として記録する。
2. **I12 昇格の PR に対する検査 (新設)**: `.claude/rules/falco-ctf-app-conventions.md` の
   Hard Invariants 表への I12 追記 PR は、(i) 追記される文言が ADR-0001:730-742 の確定文言と
   一致すること (grep で diff)、(ii) 「未昇格」footnote 表 (同ファイル、I11-I13 節) から
   I12 の行を削除すること、を diff レビューで確認する (機械検査ではなく VP レビュー — Hard
   Invariant 表自体の変更は低頻度なので機械強制のコストが正当化されない。**「無し」とは書かない
   理由**: レビューという確認経路が存在するため)。
3. **Issue #118 クローズの追跡可能性**: GitHub Issue のクローズコメントに
   本 ADR (`docs/adr/0010-*.md`) + ADR-0001 (`docs/adr/0001-*.md`) + ADR-0007
   (`docs/adr/0007-*.md`) への相対リンクが含まれること (レビューで確認、機械検査なし)。
4. **実機再確認 (未実施・実施するまで「確認済み」と書かない)**: ADR-0001 layer 4 E2E
   (deploy 後に catalog ルール発火 0 件 + `solved`/`evade_dirty` delta 0) は
   ADR-0007 の「実施記録」節 (2026-08-25) で **「進行中の再deploy」regression の1点のみ**
   実クラスタ確認済み。**H1 (env 到達不能性) 自体の実クラスタ再現テスト
   (`env | grep CTF_FLAG` を実際に workspace 内で実行し 0 件を確認する E2E) は
   本 ADR の起草時点では実施記録が見当たらない** — ADR-0001 の Verification 1 (`helm template`
   ベースの static assert) と Verification 3 (`assert-flag-isolation.sh` の `ENV_HAS_CTF_FLAG`
   実機チェック、`charts/ctf-user/assert-flag-isolation.sh:257-292`) は**deploy 時に自動実行される
   実機チェック**であり、これが「実機で確認済み」の根拠になる (deploy 自体が実機なので、
   `assert-flag-isolation.sh` が green で完了した deploy は事実上 H1 の実機検証を経ている)。
   **ただし「参加者が実際に `kubectl exec` して `env | grep CTF_FLAG` を打った上での確認」という
   qa-engineer 視点の E2E は別に記録されていない** — 次回リハまでに qa-engineer が
   1 回実施し、結果を本 ADR に追記することを推奨する (追記は「navigational な訂正」の範囲内。
   決定を変える追記ではない)。

   **実施記録 (qa-engineer, 2026-08-25, Issue #185 対応)**: 上記の未実施項目を実クラスタで
   単独実行し、**0 件 (PASS)** を確認した (branch `main` @ `8a7c86b`、ADR-0010 自身の merge commit)。

   - colima **`ctf-e2e`** profile を使用 (`default` profile は 132 日稼働・disk 83%使用・
     Falco pod 再起動が既知の問題のため使い捨てでない、と platform#81 レビューで指摘済み。
     以後の E2E は `ctf-e2e` を使う運用)。`colima start --profile ctf-e2e` で起動
     (既存 5-6 日運用の cluster を再利用。arm64, k3s v1.35.0+k3s1)。
   - `ttyd` / `ttyd-proxy` / `challenge` の 3 image を本ブランチ (`main` HEAD) から再 build
     (`docker --context colima-ctf-e2e build -t docker.io/falco-ctf/<name>:dev ...`)、
     `docker save | colima ssh --profile ctf-e2e -- sudo ctr -n k8s.io images import -` で
     `k8s.io` namespace へロード (`--profile` を明示し、誤って `default` profile の
     containerd に読み込む事故を防止)。scoreboard/auth-policy/collector は本検証の対象外
     (env leak は `charts/ctf-user` chart のみが決めるため) だが、既存 5 日稼働のものが
     healthy に稼働していることを確認済み。
   - `kubectl config use-context colima-ctf-e2e` で対象クラスタに切替え、新規 user
     `qae2e185` (ns `ctf-qae2e185`) を production-default 相当の all-missions mode で deploy:
     `charts/ctf-user/deploy-user.sh --challenges-dir <repo>/challenges --dns-suffix
     192.168.5.3.nip.io qae2e185 all`。`[4/4] assert flag isolation` (`assert-flag-isolation.sh`,
     ADR-0001 Verification 3) も deploy 中に green (`OK — 3-1..3-7 clean for namespace
     ctf-qae2e185 (challenge-id=all)`)。
   - **参加者視点の実行コマンドと結果**:
     ```
     $ kubectl -n ctf-qae2e185 exec workspace -c challenge -- env | grep CTF_FLAG
     (出力なし、exit status 1 = マッチ 0 件)
     ```
     `challenge` container の env は `FALCO_CTF_{CHALLENGE,COLLECTOR,DNS_SUFFIX,SCOREBOARD,USER}`
     の 5 つと `KUBERNETES_*` / `HOME` / `HOSTNAME` / `PATH` のみで、`CTF_FLAG_*` は
     **1 件も存在しない**。
   - 追加の確認 (ADR-0001 読み出し経路表の他項目もこの機会に実測): `cat /proc/1/environ`
     (challenge container, PID 1) を `tr '\0' '\n' | grep CTF_FLAG` した結果も **0 件**。
     `mount | grep -E 'plant|seed'` は空 (seed root — `/plant-seed` — が challenge
     container に一切見えない。`plant` initContainer 側の `volumeMounts` にのみ
     `/plant-seed` が存在し、`challenge` 側には無いことを `kubectl get pod -o json` で確認)。
   - 事後処理: `helm uninstall qae2e185` + `kubectl delete ns ctf-qae2e185` で検証用
     workspace を削除し、`kubectl config use-context colima` で元の context に戻し、
     `colima stop --profile ctf-e2e` で停止した。

   **結論: H1 (env 到達不能性) の qa-engineer 視点 E2E は実施済み、結果は PASS (0 件)。
   本 ADR の Decision (H1 は main で「遮断」されている) を裏付ける。** この追記は
   決定を変えるものではなく、Verification 4 の「未実施」を「実施済み・green」に更新する
   navigational な訂正である。

## Advice

### 受けた助言

- **VP (2026-08-25, 委任時)**: Issue #118 の設計を委任。「(a)/(b)/(c) を検討」「軽減 vs 遮断を
  区別」という評価軸を明示。→ 本 ADR はこの評価軸を ADR-0001 の既存表に対して再適用し、
  「すでに遮断済み」と判定した。VP の評価軸自体は正しく、既存 ADR がそれを満たしていることの
  確認作業として活きた。
- **VP への確認事項 (本 ADR で新たに要求)**: I12 昇格 (`.claude/rules/falco-ctf-app-conventions.md`
  の編集) の実行、および Issue #118 のクローズ。architect は文書 (ADR) のみを担当し、
  conventions.md の Hard Invariants 表編集は VP 側の実行に委ねる (オーナーシップ境界)。
- **security-engineer への相談は行っていない** (理由: 本 ADR に新規の設計判断が無いため。
  ただし I12 昇格そのものは Hard Invariant の新設に相当するので、VP が承認する前に
  security-engineer への通知 (レビュー依頼ではなく fyi) を推奨する — ADR-0001/0007 の
  I12 に関する監査はすでに security-engineer が独立に行っている (ADR-0001 rev.2-7 各ラウンド)
  ため、二重監査は要求しないが、昇格という手続き自体は共有すべき)。
