# challenges/ — ミッション定義とコンテンツ所有区分

各 `<NN>-<slug>/` は 1 課題。scoreboard がここを直接読み込むため、課題の正典はこのディレクトリ。

## ファイル別の所有区分

| ファイル | 所有 | 役割 |
|---|---|---|
| `README.md` (課題ごと) | operator doc | 運営・出題者向けの想定解 / 運用メモ (docs サイトの元ネタにもなる) |
| `journey.yaml` | **content-lead** | 参加者向けの guided journey narrative (title / tagline / briefing / steps / hints / docsUrl)。**表示専用 — 採点には一切影響しない** |
| `falco-rule.yaml` | content-lead + security-lead | scoreboard の採点メタ (expectedRules / forbiddenRules / expectedFlag)。採点真正性の一次ソース |
| `rule.yaml` | content-lead | docs サイト表示用の Falco ルール抜粋 (デプロイ中の実ルールセットから抽出) |
| `fixtures/`, `values.yaml`, `plant.sh` | app-lead + content-lead | 課題環境の仕込み。`values*.yaml` は `make gen-values` 生成物 (手書き禁止) |

## journey.yaml ⇔ 課題 README の drift 保証

`journey.yaml` (参加者向け narrative) と 課題ごとの `README.md` (operator 想定解) は
**別々に手書きされる**。両者の想定解手順が食い違うと参加者体験が壊れるため、以下で整合を担保する:

1. **challengeId 整合は起動時に自動検証済み**。`internal/catalog/journey.go` の `LoadJourneys`
   が各 `journey.yaml` の `challengeId` を catalog と突き合わせ、実在しない課題を指す journey は
   scoreboard 起動失敗 (fail-loud) になる。孤立した journey.yaml は本番に載らない。
2. **想定解 prose の drift は軽量運用で担保** (P15 スコープ): 課題の想定解 (steps / hints) を
   変更したら、同じ PR で `journey.yaml` と 課題 `README.md` の両方を更新する。content-lead が
   `/review-challenge` で両ファイルの手順一致を確認する。
   重い生成機構 (README → journey.yaml codegen 等) は現時点では**作らない** — 10 課題規模では
   レビューでの整合確認で十分で、生成器の維持コストが価値を上回るため。

> docsUrl は `/missions/<NN>-<slug>/` の相対パスで書く。docs は別ホスト (`docs.<suffix>`) に
> あるため、scoreboard は `DOCS_BASE_URL` env が非空なら journey API 応答で絶対 URL 化する
> (空なら相対のまま = local dev)。詳細は `internal/scoreboard/api/api.go` の `docsURL`。
