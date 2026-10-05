# ADR 索引

このディレクトリの Architecture Decision Record の一覧。
**ADR を新設したらこの索引に 1 行追加する** —— 索引が無いと
「ある ADR を読んだ人が、それを部分 supersede した別の ADR に到達できない」という導線欠如が起きる
（実際に ADR-0003 → ADR-0004 で起きた）。

## 一覧

| # | 題 | Status | 何を決めたか | 部分 supersede |
|---|---|---|---|---|
| [0001](0001-flag-plant-initcontainer-not-challenge-env.md) | フラグの仕込みを initContainer に移す | **Accepted** | フラグ実値を challenge コンテナに一度も入れない (Option B / B1 / 09-ii / S-a)。提案 I12 (フラグ隔離) / I13a・I13b (deploy 経路の無汚染) | **派生決定 (1) の B1 (`subPath` によるファイル単位 bind)** を [0007](0007-plant-mount-directory-granularity.md) が supersede。**監査 LOW (plant.sh の同梱)** は [0026](0026-challenge-image-fixtures-allowlist.md) が閉じる (Decision は無変更。0026 は Proposed) |
| [0002](0002-alpine-cycle-selection-criteria.md) | alpine cycle の選定基準 | **Accepted** | 最新 cycle ではなく「リリース後 ~1 年経過した supported cycle」を選ぶ | — |
| [0003](0003-evade-clean-gate-attempt-scope.md) | evade の clean 判定を attempt スコープ付き永続 dirty に | **Accepted** | 固定長 sliding window を撤去し、attempt スコープ付きの永続 dirty フラグへ。提案 I11 | **Verification (d) の 1 項目**を [0004](0004-capstone-dual-path-e2e-order.md) が supersede。**Option 2 の有効条件と Signpost 1 / 4 / 5 の評価**を [0027](0027-hint-gate-decoupled-from-current.md) が記録 (Decision は無変更。0027 は Proposed) |
| [0004](0004-capstone-dual-path-e2e-order.md) | capstone の 2 経路 E2E の順序 | **Accepted** | mission 10 の auto-solve / 手動 submit を**この順で**通す (d′)。逆順禁止・reset 不要。(d) の**理由**を差し替え | — |
| [0005](0005-openapi-canon-and-parity-gate.md) | OpenAPI の対象を HTTP 面すべてに定め parity を機械検査 | **Accepted** | 1 サービス = 1 spec で mux の全ルートを記載 / `x-ctf-*` で audience・authz・origin-guard・collector forward を宣言 / 双方向 parity を fail-closed 検査 (除外リストゼロ)。I14 (Hard Invariants 昇格済み、#149) | **V5 の floor 記述ほか**を [0009](0009-response-field-coverage-and-fail-closed-compare.md) が限定 supersede。**Signpost 2** を [0028](0028-static-assets-single-route-content-hash.md) が supersede (0028 は Proposed。Accepted まで元の文言が有効) |
| [0006](0006-p25-qa-ticket-chat-contract.md) | P25 QA チケットチャットの API 契約・スキーマ・admin UI 配置 | **Accepted** | 新規 7 route (self-scope + admin)・`internal/qa` を `store`/`scoring` と物理分離・admin UI は portal 内タブ (index.html は不採用)。実装着手は WIP ドレイン後 かつ 0005 (#143/#149) merge 後 | — |
| [0007](0007-plant-mount-directory-granularity.md) | plant-target の mount をディレクトリ granularity に限定 | **Accepted** | ファイル単位の bind mount は destination が Falco の一致対象のとき **container ランタイム自身が deploy ごとに検知イベントを出す** —— mount 粒度をディレクトリに上げて原因を消す。ADR-0001 の派生決定 (1) = B1 を supersede。提案 I13c。**実装は別PR、本番投入はlandingまで不可** | — |
| [0008](0008-mission05-positive-proof-gate.md) | mission05 の forbidden rule 汎化 + evade 型への積極証明ゲート | **Accepted** | 04/05/10 共有ルール `Search Private Keys or Passwords` を proc 非依存の literal 一致へ汎化 (`shell_binaries` 除外。`container.name` には依存しない設計 — plant.sh の `chmod` を排除して deploy 経路の literal-bearing exec を `sh -c` 自身の1件に限定) + 新設 Falco rule `Shell Redirected Private Key Read` + `requireExpectedRuleFire` (evade 型の第2肯定ゲート、`RequireExfil` と対称) + `challenge-rules` CI ゲート対応のカスタムルール allowlist。ADR-0003 Signpost 2 を resolve (epoch 不要と判断)。提案候補 I13b 対象集合 +1 (未昇格)。**実装は別PR、本番投入は実機 Verification landing まで不可** | — |
| [0009](0009-response-field-coverage-and-fail-closed-compare.md) | ADR-0005 の設計欠陥3件 (V5列挙・CompareResponse fail-open・Decision-Verification不整合) を supersede | **Accepted** | V5 を機械列挙化 (200+json object 全16 operationを対象、除外リストゼロ) / `CompareResponse` を fail-closed 化 (properties欠如・oneOf 節点を検査対象に) / x-ctf-audience・authz・rate-limit の string parity (実装済み・main で landing 済) を正典 Verification (V3b) に条文化。提案候補なし (新規 Hard Invariant は不要) | **V5 の floor 記述** と **V3 に対応する Verification 項目の欠如**を [0005](0005-openapi-canon-and-parity-gate.md) から限定 supersede (Decision 1-5・V1-V2/V4/V6-V8・I14提案は無傷) |
| [0010](0010-issue118-flag-env-leak-closure-and-i12-promotion.md) | Issue #118 (全ミッション CTF_FLAG_* の challenge env 漏えい) は main で既に閉じている — I12 昇格 | **Accepted** | 新規設計ゼロ。ADR-0001 (Option B) が H1 の読み出し経路を実装済みで閉じており、Issue #118 は ADR-0001 を生んだ発見チケットそのものだったと判定。I12 を Hard Invariant へ昇格 (ADR-0007 が課した3条件を実測確認)。Issue #118 は本ADR承認と同時にクローズ | — |
| [0011](0011-namespace-bootstrap-single-owner.md) | Namespace ownership を app chart 自己 template から platform bootstrap release の単一所有へ | **Accepted** | 4 app chart (auth-policy/collector/scoreboard/docs) + platform-local detect-grader chart が自己 template していた Namespace を撤去し、platform 側の新規 `namespaces` bootstrap release が単一所有者になる (PSA enforce/audit/warn は独立指定)。真に空のクラスタでの `helmfile sync` が両方向に失敗する欠陥 (platform#83) を解消。app/platform 側変更の同時landing必須 (逆順だとNamespace object削除の恐れ、V7で実測)。ctf-user は対象外 (platform#75 に守られて未発火。#75 修正時に同パターン適用を条件付け)。**実装は別PR、本番投入はV1-V7 landingまで不可** | — |
| [0012](0012-error-body-code-field-and-copy-ownership.md) | エラー/採点 body に機械可読 `code` を additive で追加 + 表示文言の所有権を frontend へ | **Proposed** | `Error`/`SubmitFlagVerdict` に open-string `code` を additive 追加 (既存の metrics/audit 語彙を re-export、`enum:` にしない)。`err.Error()` 直書きは `httpx.WriteError` 1 本への集約で静的検査可能にする。RFC 9457 全面移行は「第三者クライアントが無く検証不能」を理由に見送り (Issue #113 の一部を解決、UI 文言所有権の移行方針は application-engineer への発注) | — |
| [0013](0013-p19-domain-hybrid-single-origin-consolidation.md) | ドメイン設計 subdomain→path ハイブリッド化 (P19) — 既に決定・実装・prod 投入済みを記録 | **Accepted** | 新規設計ゼロ。app#61/platform#24 の P19-1 設計メモ 10 論点は 2026-08-16 (P23 landing 後 3 観点スパイク + CEO 6 決定 + app#100/platform#57/#54 merge + stand-up 実証) に既に解決済みと判定。path-first (P18/P19 統合)・単一 origin `app.<suffix>` 集約・ttyd subdomain 無改修・cookie domain 不変 (PSL 下限) を正典化。cert/CF は当初想定より縮小 (無改修/6→3) で決定 | — |
| [0014](0014-journey-narrative-scenario-overlay.md) | journey narrative を課題ローカルからシナリオ所有のオーバーレイへ分離 (P27) | **Accepted** | `journey.yaml` の `briefing`/`bridge` を課題ローカル fallback + シナリオ側 additive override (`scenarios/<name>/narrative.yaml`) の2層にする。既存 journey.yaml は後方互換で無変更。実装 landing 済み (`internal/catalog/narrative.go`)、Verification 1-3 実測確認済み | — |
| [0015](0015-initial-access-out-of-scope.md) | Initial Access (TA0001) は challenge の模擬対象から除外 (P27) | **Accepted** | 単一Pod・Service/Ingress禁止(I9)・参加者は最初からttyd経由でシェルを持つという前提のもとでは「境界の外から内へ入る」行為が構造的に観測不能。06のfixtureパターンはExecution(T1059.004)の再演に留まり、新規challengeもタグの再付けもいずれも既存カテゴリの言い換えか I9 違反に帰結する。`ATTACK-COVERAGE.md`の除外表に追記対象 | — |
| [0016](0016-privilege-escalation-out-of-scope.md) | Privilege Escalation (TA0004, T1548/T1611) は challenge の模擬対象から除外 (P27) | **Accepted** | T1548 (Setuid/Setgid, Sudo) はchallengeコンテナが常時rootで非root起点が構造上存在しないため除外、T1611 (Escape to Host) は単一Pod隔離という防御境界(privileged未使用・hostPath/docker.sock非マウント・追加capability無し・seccompProfile RuntimeDefault・automountServiceAccountToken:false)が構造的に阻止済みのため除外。security-engineer判断+architect実測裏書き。`ATTACK-COVERAGE.md`の除外表に追記対象 | — |
| [0017](0017-collection-archive-loot-custom-rule.md) | mission 13 (Collection, T1560.001) の custom Falco rule — trigger 型・syscall/fd 主軸の `Archive Collected Data` | **Accepted** | project 史上2件目の `customRules` 利用 (ADR-0008 の chart-native 機構を再利用)。検知の核は `open_read` の syscall 事実 + staged collection ディレクトリの `fd.name` prefix + archive tool の `proc.name` の3条件AND (コマンドライン引数の文字列一致には依存しない — cd+相対パスでも発火する設計)。trigger 型のみ (flag/plant 不要、09/11/12 と同型)。evade 型 (積極証明ゲート) は mission10 との学習目標重複を理由に不採用。実装 landing 済み (platform#129・app#215)、実クラスタ fire/no-fire 実測確認済み | — |
| [0018](0018-lateral-movement-out-of-scope.md) | Lateral Movement (TA0008, T1021 系) は challenge の模擬対象から除外 (P27) | **Accepted** | T1021.001/.002 (RDP/SMB) は Linux コンテナ環境で技術的に無意味、T1021.004 (SSH) / T1021.007 (Cloud Services) は移動先となる第二の到達可能な Pod/ホスト/クラウド資源が単一Pod隔離・SA token狭域スコープ (role.yaml の resourceNames固定)・egress lockdown (P11.5, Calico enforced) により構造的に存在しないため除外。ADR-0016 T1611 除外 (単一Pod隔離という防御境界そのもの) と表裏一体であることを ATTACK-COVERAGE.md 自身が既に自認していた事実を出典明示で正典化。`ATTACK-COVERAGE.md` の除外表に ADR 引用を追記対象 | — |
| [0019](0019-repo-topology-ddd-team-split.md) | リポ構成: 2 リポ + ディレクトリ境界の DDD を維持、サービス単位分割は不採用 | **Proposed** | CEO 相談 (誰が clone しても同じ / コンポーネント単位のチーム分割 / DDD / 11 職との整合) への回答。bounded context マップを明文化、CODEOWNERS 現行化・devcontainer/mise/`make bootstrap` を Option A として推奨。サービス単位 4-6 リポ分割 (Option B) は I5 (全8イメージ同一SHA) / I6 (challenges/ 同一repo) の結合を壊し MERGE-DRAIN.md が実測した統合ボトルネックを悪化させるため不採用 | — |
| [0020](0020-sqlite-user-version-migrations.md) | scoreboard スキーマは PRAGMA user_version の単一線形 migration リストで進化させる (Issue #117) | **Accepted** | 既存 DDL を migration #1 として凍結し新規/レガシー DB を同一パスに合流。各 migration は 1 tx (version 更新込み、modernc.org/sqlite で rollback 実測済み)。downgrade は fail-closed 起動拒否。I1 前提で advisory lock 不採用。migrations 追加 PR は security-engineer レビュー必須 (dev-flow ゲート表反映済み) | — |
| [0021](0021-ingress-participant-route-coverage-gate.md) | scoreboard 単一起点 ingress の participant allow-list を機械検査する新規 Hard Invariant (I15) (Issue #238) | **Accepted** | `internal/apispec/ingressparity` (test-only) が `scoreboard.Handler.Routes()` の `AudienceParticipant` 集合と `helm template charts/scoreboard` がレンダリングする `ingress-journey.yaml` の participant allow-list を双方向比較 (#95/#235 の欠陥クラスの機械ゲート)。提案 I15 | **D2 の Exact エントリに関する記述** (reverse audience 混入検査を Prefix のみに限定していた部分) を [0022](0022-ingress-exact-entry-audience-mixing-gate.md) が限定 supersede (D1/D3/D4・CI 配線・V(I15)-1/4/5 は無傷) |
| [0022](0022-ingress-exact-entry-audience-mixing-gate.md) | I15 の reverse audience 混入検査を Exact エントリにも拡張 (Issue #240、ADR-0021 D2 の限定 supersede) | **Accepted** | `CoverageDiff` の reverse ループから Prefix 限定フィルタを削除し、`covers()` の既存 Exact 分岐 (ADR-0021 D3) をそのまま流用。新規 V(I15)-6 (blocking) を追加、DeadExact (V(I15)-3, advisory) とは排他的に独立。I15 の正典文言を「各 Prefix エントリ」→「各エントリ (Prefix/Exact 問わず)」に更新 | — |
| [0023](0023-rate-limit-client-ip-cf-connecting-ip.md) | rate-limit キーを `CF-Connecting-IP` 優先に切り替え XFF leftmost 偽装を是正 (クロスリポ契約、Issue #236) | **Accepted** | `ratelimit.ClientIP` を 3 段 fallback (CF-Connecting-IP valid → XFF leftmost → RemoteAddr)、collector が CF-Connecting-IP も strip (D1b、D1 と同一 PR)、platform ingress が prod/vm-prod で `forwarded-for-header: CF-Connecting-IP` 供給。fail-open 維持 + fallback 観測可能化。**Accepted ≠ 脆弱性解消済 (V2 実クラスタ確認まで実質未解消)** | — |
| [0024](0024-attack-v19-tactic-split-adoption.md) | MITRE ATT&CK v19 の Defense Evasion (TA0005) 分割 (Stealth / Defense Impairment 新設 TA0112) への追従 + version pin bump (Issue #249) | **Accepted** | `tactic: "Defense Evasion"` を使う 4 件 (03/05/09/12) のうち 3 件はラベルのみ `"Stealth"` へ更新、12-cover-tracks は techniqueId 自体を remap。`ATTACK_VERSION` を `"15"` → `"19"` に bump (Navigator layer JSON は tactic を持たないため描画影響なし。既存 14 件全数の v19 有効性を実機確認済み) | — |
| [0025](0025-evade-flag-placement-separation.md) | evade 課題 03/10 の flag を /etc/shadow から専用 vault `/opt/nimbus/vault/{creds.recover,master.key}` へ分離し、`Read sensitive file untrusted` へ dir-prefix append で sensitive 化 (クロスリポ契約、CEO 要望) | **Proposed** | 02 は /etc/shadow の loud baseline 維持、05 は flag clarity のみ。1 customRule (`fd.name startswith "/opt/nimbus/vault/" and container.name != "plant"`) で 03/10 を同時カバー。**デプロイ順序: platform 先行 (逆順で free-win)**。実機 fire/no-fire は次 stand-up 2026-09-03 待ち。app#278 / platform#170 | — |
| [0026](0026-challenge-image-fixtures-allowlist.md) | challenge image の `/opt/ctf/missions/` を fixtures allowlist にし、hints・想定解・採点メタを同梱しない (P28-0d) | **Proposed** | 2026-06 の guided 方針を解除 (CEO 2026-10-04)。build 時の multi-stage allowlist (final は `<id>/fixtures/` のみ)、`answers.yaml` の生成は builder stage へ、path は不変で契約表に行を追加。提案 I16 (image の entry 集合 + fixtures が `hints[]` 固有の 10 rune n-gram を含まない。規則は D5 = 項目ごと・全スコープで fixtures は全課題。昇格は Verification と同一 PR)。順序は content (app#308 / #309) が先・software が後。**実装は別 PR** | — |
| [0027](0027-hint-gate-decoupled-from-current.md) | ヒントと steps の gate を読み投影の `current` から切り離す (P28-0b) | **Proposed** | 2026-08-17 の「locked mission hints 秘匿」を改め、どの課題でも減点つきで開ける (CEO 2026-10-04)。変えるのは読み投影だけで、`CurrentMission`・taint・Score は無接触、`status: locked` の値は残す。非 current の evade の「クリーン」表示の中立化を P28-0b に含める。ADR-0003 Option 2 の有効条件 (進行が線形) が成り立っていないことを記録し、attempt epoch を扱う別 ADR を遅くとも P28-3 の前に要求する (期間の扱いは CEO 判断)。**実装は別 PR** | — |
| [0028](0028-static-assets-single-route-content-hash.md) | first-party 静的アセットを `GET /static/{asset}` 1 ルート + content-hash URL に集約 (P28-0c、app#277、クロスリポ契約) | **Proposed** | 8 route → 1 route、配信名は `<name>.<hash>.<ext>`、ingress は `/static/` Prefix 1 本、`/static/` には誰に読まれてもよい表示用アセットだけを置く (登録表を pin。css / woff2 のみ)。platform は文書と Cloudflare の cache 設定。ADR-0005 Signpost 2 を置き換える (JSON API の operation 数で数える・行数には `$ref` の物理分割で応える・サービス分割を処方しない)。**実装は別 PR** | — |
| [0033](0033-flags-file-completeness-fail-closed.md) | flags ファイルは指定したら完全であることを必須にする (クロスリポ契約、既存の fail-open の修正) | **Accepted** | 指定時は、スコープ内 (採点側 = scenario の Restrict 後 / 仕込み側 = deploy モード) の全 evade 課題に、どの既定値とも同値でなく課題間で重複しない flag を必須にし、破れば scoreboard は起動拒否・`deploy-user.sh` は cluster に触れる前に終了。文字集合を `^FALCO\{[A-Za-z0-9_-]+\}$` に限定 (`expectedFlag` にも適用)、ファイルは YAML の部分集合のみ受理。scoreboard の catalog は `catalog.LoadScored` 1 関数で読む。採点側 (Go) が正で、仕込み側 (shell) は早期検出、一致は parity テストで検査 (chart 描画への集約は follow-up の推奨)。platform に全 evade id の生成義務 (同時 PR)。HI 昇格は not yet | — |

## ADR 番号の採番

- ADR の番号は **ファイル名** (`docs/adr/NNNN-<slug>.md`) で決まる。本文の
  `# ADR-NNNN` ヘッダはファイル名と一致させる。
- 新規 ADR を書くときは `make check-adr` を実行し、標準出力の
  「Next free ADR number」を採番に使う (既存最大 + 1。予約済み欠番
  (例: ADR-0009) を自動では埋めない — 意図的な予約はそのままにする)。
- **0026〜0032 は未 merge の ADR が使用・予約中** (0026〜0028 = P28-0 の前提、0029〜0031 = P28 用の予約、0032 = 起草予定)。
  ADR-0033 はこれらを避けて採番した。`make check-adr` の「Next free ADR number」は既存の最大 + 1 を返すだけで
  未 merge の番号を知らないので、採番前にこの行と `git log --oneline --all -- 'docs/adr/*'` を確認する。
- CI (`flag-guard` job、`scripts/check-adr-numbers.sh`) が (a) 番号重複、
  (b) ファイル名とヘッダの不一致、(c) この索引への掲載漏れ、を機械的に
  検査し fail-closed で block する。この節冒頭の「ADR を新設したらこの
  索引に 1 行追加する」規律は、以後は人手の記憶ではなく CI が強制する。

## 規律（ADR-0003 / ADR-0001 で確立したもの）

- **ADR-0009 は欠番ではなく Issue #144 用に予約済み** (`docs/adr/0008-mission05-positive-proof-gate.md:569`)。新規 ADR を切るときは `git log --oneline --all -- 'docs/adr/*'` と `gh api search/code` で未マージの予約/衝突が無いか確認すること (これまで複数回の番号衝突歴あり — 確認できる明確な1例: Issue #144 が ADR-0008 を自称していたケース、R3 レビューが検出し ADR-0009 予約へ訂正 [`docs/adr/0008-mission05-positive-proof-gate.md:562-568`]。件数を精査できていないため「3回」から弱めた、2026-08-25 R3 対応)。

- **ADR-0029 / 0030 / 0031 は P28 用に予約済み** (workspace `REFACTORING.md` P28 architect §10。0029 = Quest 層の境界 [採点非干渉 I17・fail-soft・quest.db]、0030 = Quest content 契約と開示境界、0031 = ブラウザ E2E ハーネス)。ADR-0026 / 0027 / 0028 がこの番号で前方参照している。`make check-adr` の「Next free ADR number」は予約を知らず、ファイルが無い間は 0029 を出す。**P28 以外で新規 ADR を切るときは 0032 以降を使う。**

- **Accepted な ADR の決定は編集しない。** 変更は **supersede する新 ADR** で行う
  （ADR-0003 が自ら定めている）。例外は 2 つ:
  - **navigational なポインタの追記**（読者導線の確保。決定内容を変えない）
  - **非決定的な事実訂正**（例: 参照先スクリプトの所在・ファイルパスなど、
    Decision/Verification が主張する結論そのものを変えない記述の訂正。
    ADR-0005 の Status ブロックが「Decision/Verification 節は以後編集しない一方、
    Status ブロックは状態記述なので実態に追随させる」と自己宣言しながら
    Verification 節本文の事実訂正を行った先例を明文化するもの。決定を覆す
    編集ではないことが自明な場合のみ適用し、迷ったら supersede する新 ADR を書く）
- **Verification が無い ADR を Hard Invariant に昇格させない。**
  昇格条件は ADR 本文に書き、**機械強制が landing するまで
  `.claude/rules/falco-ctf-app-conventions.md` の表には追記しない**
- **推論のまま Hard Invariant に昇格させない。** 実測していないことは
  Verification の項目として立て、「実機でのみ確認可」と明示する
- **「N/A」と書かない。** 「対象不在のため未実施。Signpost N で再訪」のように**理由付きで**書く
  （無印 N/A は「測って問題なかった」と読める台帳になる）
