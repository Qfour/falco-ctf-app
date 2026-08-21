# ADR 索引

このディレクトリの Architecture Decision Record の一覧。
**ADR を新設したらこの索引に 1 行追加する** —— 索引が無いと
「ある ADR を読んだ人が、それを部分 supersede した別の ADR に到達できない」という導線欠如が起きる
（実際に ADR-0003 → ADR-0004 で起きた）。

## 一覧

| # | 題 | Status | 何を決めたか | 部分 supersede |
|---|---|---|---|---|
| [0001](0001-flag-plant-initcontainer-not-challenge-env.md) | フラグの仕込みを initContainer に移す | **Accepted** | フラグ実値を challenge コンテナに一度も入れない (Option B / B1 / 09-ii / S-a)。提案 I12 (フラグ隔離) / I13a・I13b (deploy 経路の無汚染) | — |
| [0002](0002-alpine-cycle-selection-criteria.md) | alpine cycle の選定基準 | **Accepted** | 最新 cycle ではなく「リリース後 ~1 年経過した supported cycle」を選ぶ | — |
| [0003](0003-evade-clean-gate-attempt-scope.md) | evade の clean 判定を attempt スコープ付き永続 dirty に | **Accepted** | 固定長 sliding window を撤去し、attempt スコープ付きの永続 dirty フラグへ。提案 I11 | **Verification (d) の 1 項目**を [0004](0004-capstone-dual-path-e2e-order.md) が supersede |
| [0004](0004-capstone-dual-path-e2e-order.md) | capstone の 2 経路 E2E の順序 | **Accepted** | mission 10 の auto-solve / 手動 submit を**この順で**通す (d′)。逆順禁止・reset 不要。(d) の**理由**を差し替え | — |
| [0005](0005-openapi-canon-and-parity-gate.md) | OpenAPI の対象を HTTP 面すべてに定め parity を機械検査 | **Accepted** | 1 サービス = 1 spec で mux の全ルートを記載 / `x-ctf-*` で audience・authz・origin-guard・collector forward を宣言 / 双方向 parity を fail-closed 検査 (除外リストゼロ)。I14 (Hard Invariants 昇格済み、#149) | — |
| [0006](0006-p25-qa-ticket-chat-contract.md) | P25 QA チケットチャットの API 契約・スキーマ・admin UI 配置 | **Accepted** | 新規 7 route (self-scope + admin)・`internal/qa` を `store`/`scoring` と物理分離・admin UI は portal 内タブ (index.html は不採用)。実装着手は WIP ドレイン後 かつ 0005 (#143/#149) merge 後 | — |

## 規律（ADR-0003 / ADR-0001 で確立したもの）

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
