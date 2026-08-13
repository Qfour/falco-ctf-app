# コントリビューションガイド / Contributing

`falco-ctf-app` は再利用可能な Falco CTF キットの **公開リポジトリ** です。貢献を歓迎します。
まず本ページの鉄則とフローを確認してください。

## ⚠️ 公開リポの鉄則 (最優先)

以下は他のすべてのルールに優先します。**コミット・PR・Issue・ログ・スクリーンショットに
含めないでください:**

- 本番フラグの実値 (`FALCO{...}`) — 課題のフラグは公開済み = ローテーション前提
- シークレット・トークン・認証情報・kubeconfig
- **AWS アカウント ID**・本番ホスト名・内部エンドポイント
- 参加者情報

貼る前にマスクしてください。セキュリティ脆弱性は Issue にせず
[SECURITY.md](SECURITY.md) の非公開報告導線を使ってください。

## 貢献フロー

1. **Issue Form で起票** — バグは `🐛 バグ報告`、機能・改善は
   `✨ 改善提案` のフォームから起票します (空 Issue は無効)。
   `.github/ISSUE_TEMPLATE/` の各フォームが自動で `type:*` / `status:triage` ラベルを付けます。
2. **ブランチを切る** — `feat/…` / `fix/…` / `chore/…` / `docs/…` 等。
3. **PR を出す** — `.github/pull_request_template.md` に従い:
   - 本文に `Closes #<Issue番号>` を入れる。
   - 該当する **`type:*` ラベル** を付ける (`.github/labels.yml` の体系。未付与は
     Release ノートで Other に落ちる)。
   - パターン別ゲートチェックリスト (A: Go / B: chart / C: challenge / D: image) を満たす。
4. **レビュー** — 本組織のレビューの実体は **`/review-5x` (5 観点並行 AI レビュー) +
   VP 査定** です (AI 組織のため GitHub の human reviewer 承認は使いません)。
   CODEOWNERS の自動 request は現状不活性です ([.github/CODEOWNERS](.github/CODEOWNERS) 参照)。
5. **merge は CEO のみ** — 査定通過後、VP が push + draft PR を作成します。
   main への merge / ready 化 / タグ push / publish は **CEO のみ** が行います。

## 開発ゲート (ローカル)

変更パターンに応じて PR 前にローカルで通してください (詳細は PR テンプレと
`.claude/rules/dev-flow.md`):

- Go 変更 (`cmd/`, `internal/`, `go.mod`) → `make test`
- chart 変更 (`charts/`) → `make lint`
- image 変更 (`images/`, `Dockerfile.*`) → `make scan TAG=local`
- 生成物 (`values*.yaml` / oapi types) は手書き禁止。`make gen-values` / `make gen` で生成

Hard Invariants (I1–I10) を破らないこと (`.claude/rules/*-conventions.md`)。

## バージョニング / リリース

版・contract の正典は **SemVer タグ** です。bump 基準とリリース手順は
[`docs/RELEASING.md`](docs/RELEASING.md) を参照してください。タグ打ち・Release publish は
**CEO のみ** が行います。

## 行動規範

参加にあたっては [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) を守ってください。
