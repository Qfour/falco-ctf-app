# ADR 索引

このディレクトリの Architecture Decision Record の一覧。
**ADR を新設したらこの索引に 1 行追加する** —— 索引が無いと
「ある ADR を読んだ人が、それを部分 supersede した別の ADR に到達できない」という導線欠如が起きる
（実際に ADR-0003 → ADR-0004 で起きた）。

## 一覧

| # | 題 | Status | 何を決めたか | 部分 supersede |
|---|---|---|---|---|
| [0001](0001-flag-plant-initcontainer-not-challenge-env.md) | フラグの仕込みを initContainer に移す | **Accepted** | フラグ実値を challenge コンテナに一度も入れない (Option B / B1 / 09-ii / S-a)。提案 I12 (フラグ隔離) / I13a・I13b (deploy 経路の無汚染) | **派生決定 (1) の B1 (`subPath` によるファイル単位 bind)** を [0007](0007-plant-mount-directory-granularity.md) が supersede |
| [0002](0002-alpine-cycle-selection-criteria.md) | alpine cycle の選定基準 | **Accepted** | 最新 cycle ではなく「リリース後 ~1 年経過した supported cycle」を選ぶ | — |
| [0003](0003-evade-clean-gate-attempt-scope.md) | evade の clean 判定を attempt スコープ付き永続 dirty に | **Accepted** | 固定長 sliding window を撤去し、attempt スコープ付きの永続 dirty フラグへ。提案 I11 | **Verification (d) の 1 項目**を [0004](0004-capstone-dual-path-e2e-order.md) が supersede |
| [0004](0004-capstone-dual-path-e2e-order.md) | capstone の 2 経路 E2E の順序 | **Accepted** | mission 10 の auto-solve / 手動 submit を**この順で**通す (d′)。逆順禁止・reset 不要。(d) の**理由**を差し替え | — |
| [0005](0005-openapi-canon-and-parity-gate.md) | OpenAPI の対象を HTTP 面すべてに定め parity を機械検査 | **Accepted** | 1 サービス = 1 spec で mux の全ルートを記載 / `x-ctf-*` で audience・authz・origin-guard・collector forward を宣言 / 双方向 parity を fail-closed 検査 (除外リストゼロ)。I14 (Hard Invariants 昇格済み、#149) | — |
| [0006](0006-p25-qa-ticket-chat-contract.md) | P25 QA チケットチャットの API 契約・スキーマ・admin UI 配置 | **Accepted** | 新規 7 route (self-scope + admin)・`internal/qa` を `store`/`scoring` と物理分離・admin UI は portal 内タブ (index.html は不採用)。実装着手は WIP ドレイン後 かつ 0005 (#143/#149) merge 後 | — |
| [0007](0007-plant-mount-directory-granularity.md) | plant-target の mount をディレクトリ granularity に限定 | **Accepted** | ファイル単位の bind mount は destination が Falco の一致対象のとき **container ランタイム自身が deploy ごとに検知イベントを出す** —— mount 粒度をディレクトリに上げて原因を消す。ADR-0001 の派生決定 (1) = B1 を supersede。提案 I13c。**実装は別PR、本番投入はlandingまで不可** | — |
| [0008](0008-mission05-positive-proof-gate.md) | mission05 の forbidden rule 汎化 + evade 型への積極証明ゲート | **Accepted** | 04/05/10 共有ルール `Search Private Keys or Passwords` を proc 非依存の literal 一致へ汎化 (`shell_binaries` 除外。`container.name` には依存しない設計 — plant.sh の `chmod` を排除して deploy 経路の literal-bearing exec を `sh -c` 自身の1件に限定) + 新設 Falco rule `Shell Redirected Private Key Read` + `requireExpectedRuleFire` (evade 型の第2肯定ゲート、`RequireExfil` と対称) + `challenge-rules` CI ゲート対応のカスタムルール allowlist。ADR-0003 Signpost 2 を resolve (epoch 不要と判断)。提案候補 I13b 対象集合 +1 (未昇格)。**実装は別PR、本番投入は実機 Verification landing まで不可** | — |
| [0010](0010-issue118-flag-env-leak-closure-and-i12-promotion.md) | Issue #118 (全ミッション CTF_FLAG_* の challenge env 漏えい) は main で既に閉じている — I12 昇格 | **Accepted** | 新規設計ゼロ。ADR-0001 (Option B) が H1 の読み出し経路を実装済みで閉じており、Issue #118 は ADR-0001 を生んだ発見チケットそのものだったと判定。I12 を Hard Invariant へ昇格 (ADR-0007 が課した3条件を実測確認)。Issue #118 は本ADR承認と同時にクローズ | — |
| [0011](0011-namespace-bootstrap-single-owner.md) | Namespace ownership を app chart 自己 template から platform bootstrap release の単一所有へ | **Accepted** | 4 app chart (auth-policy/collector/scoreboard/docs) + platform-local detect-grader chart が自己 template していた Namespace を撤去し、platform 側の新規 `namespaces` bootstrap release が単一所有者になる (PSA enforce/audit/warn は独立指定)。真に空のクラスタでの `helmfile sync` が両方向に失敗する欠陥 (platform#83) を解消。app/platform 側変更の同時landing必須 (逆順だとNamespace object削除の恐れ、V7で実測)。ctf-user は対象外 (platform#75 に守られて未発火。#75 修正時に同パターン適用を条件付け)。**実装は別PR、本番投入はV1-V7 landingまで不可** | — |
| [0012](0012-error-body-code-field-and-copy-ownership.md) | エラー/採点 body に機械可読 `code` を additive で追加 + 表示文言の所有権を frontend へ | **Proposed** | `Error`/`SubmitFlagVerdict` に open-string `code` を additive 追加 (既存の metrics/audit 語彙を re-export、`enum:` にしない)。`err.Error()` 直書きは `httpx.WriteError` 1 本への集約で静的検査可能にする。RFC 9457 全面移行は「第三者クライアントが無く検証不能」を理由に見送り (Issue #113 の一部を解決、UI 文言所有権の移行方針は application-engineer への発注) | — |

## 規律（ADR-0003 / ADR-0001 で確立したもの）

- **ADR-0009 は欠番ではなく Issue #144 用に予約済み** (`docs/adr/0008-mission05-positive-proof-gate.md:569`)。新規 ADR を切るときは `git log --oneline --all -- 'docs/adr/*'` と `gh api search/code` で未マージの予約/衝突が無いか確認すること (これまで複数回の番号衝突歴あり — 確認できる明確な1例: Issue #144 が ADR-0008 を自称していたケース、R3 レビューが検出し ADR-0009 予約へ訂正 [`docs/adr/0008-mission05-positive-proof-gate.md:562-568`]。件数を精査できていないため「3回」から弱めた、2026-08-25 R3 対応)。

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
