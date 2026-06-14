# Model routing for Claude Code

このリポジトリで Claude Code を使うときの、モデルとサブエージェントの
使い分けルール。default は **セッション起動時のモデル** (settings.json での
ピン留めは廃止 — モデル世代の更新に自動追従するため。最新の最上位モデルを推奨)。
目的別に上位/下位モデルのサブエージェントへ委譲する。

> 最新世代 (Fable 5 以降) は main session の品質が上がりレビュー往復が減るため、
> 「実装は中位・レビューは上位」という分担の価値は相対的に下がっている。
> 委譲は **context 分離** (diff やレビュー長考を main に持ち込まない) を主目的に使う。

## TL;DR

| やりたいこと | 何を使うか | モデル |
|---|---|---|
| 設計提案・トレードオフ分析・RCA | `/architect <topic>` | Opus |
| 仕様が明確な実装・テスト追加 | main session のまま | Sonnet (default) |
| pre-PR レビュー (コード + manifest 並走) | `/review` | Opus × 2 並列 |
| deploy/ だけ変わったときの manifest レビュー | `/review-manifests` | Opus |
| セキュリティ深掘りレビュー | `/security-audit` | Opus |
| challenge 新規作成・レビュー | `challenge-author` agent | Opus |
| git commit | `/commit` | Haiku |
| 広範な探索 (>3 grep 相当) | 組込 `Explore` agent | Sonnet |

## なぜサブエージェントに分けるのか

サブエージェントは **独立 context** で動く。効果は 2 つ:

1. **コスト最適化** — 定型作業 (git commit, file rename) を Haiku に
   振り、深い推論 (設計, レビュー) を Opus に振る。中間 (実装) は
   default Sonnet が担当。
2. **main context 保護** — `git diff` の長い出力やレビュー agent の
   長考を main session に持ち込まない。次のターンで cache を再利用
   しやすい。

## 主要な切り分けポイント

### 「提案 / 検討 / 設計」キーワード → `/architect`

例: 「マイクロコンポーネント化したい」「Python から書き直すべき?」
「20m ago の原因は?」「テストの粒度を見直したい」

ユーザーが提案を求めているフェーズで実装しない。`/architect` は
コードを書かず、option 列挙 + 推奨 + 将来の signposts を返す。
承認後の実装は **main Sonnet session に戻って実施**。再委譲しない
(planning context が main にあるため二度払いになる)。

### 「コミット」依頼 → 無条件で `/commit`

git status / diff / log の出力で main context が汚れるのを避ける。
半定型作業なので Haiku で十分。`/commit` は push しない。

### 「PR 出す前にレビューして」→ `/review`

ローカル branch の `main` との差分を読んで、CLAUDE.md / AGENTS.md /
`.claude/rules/` で定義された境界に違反していないか、クロスリポ契約
(webhook payload, /falco/events スキーマ, image tag = git SHA など)
が壊れていないかを確認。修正は提案するが書かない。

### セキュリティ視点でのレビュー → `/security-audit`

`auth-policy` / scoreboard ingest / Dockerfile / RBAC / Kustomize に
触る PR では基本これを通す。プロジェクト固有の threat model
(cross-user workspace 隔離 / flag 真正性 / Falco webhook 信頼) に
紐付いた findings を返す。

## やってはいけないこと

- **委譲の二度払い**: `/architect` で提案 → 受け取った推奨を別の
  agent (`/implement`) に投げ直す、はやらない。提案後の実装は main
  session のまま。
- **3 行の編集を Haiku agent に投げる**: agent spawn のオーバーヘッド
  (数百トークン) があるので、本当に **routine workflow** にだけ使う。
  単発のファイル編集は main session で直接やる。
- **`/architect` でコードを書かせる**: 設計エージェントの責務違反。
  実装させたいときは main session に戻る。
- **`/commit` で push する**: commit までで止まる仕様。push は人間
  の判断で。

## モデルの選定理由

| モデル | 強み | ここでの役割 |
|---|---|---|
| **Opus 4.7** | 多択判断、長考、cross-file 関連性、トレードオフ言語化 | 設計・レビュー (低頻度・高価値) |
| **Sonnet 4.6** | 明確な仕様の実装、テスト生成、既存パターン拡張、tool 使用 | 日常的な開発作業 (高頻度・中価値) |
| **Haiku 4.5** | 短いコンテキストで I/O 重視の定型作業を高速に | git commit、シンプルな rename (高頻度・低価値) |

将来モデルが更新されたら `.claude/agents/*.md` の `model:` フィールド
を見直す。`opus` / `sonnet` / `haiku` のエイリアスを使っているので、
Claude Code 側のエイリアス解決が自動で最新を指す想定。

## 既存 skill との関係

Claude Code には組込 skill (`/review`, `/security-review`,
`/ultrareview`) があり、それぞれ目的が異なる:

- **組込 `/ultrareview`** — multi-agent クラウドレビュー (ユーザー
  triggered)。このプロジェクトの規約は読まない。
- **組込 `/review` / `/security-review` skill** — 汎用。
- **当リポの `/review` / `/security-audit`** — プロジェクト規約・
  threat model に anchored。

迷ったら **当リポの slash command** を使う。汎用レビューが必要なら
組込を使い分ける。
