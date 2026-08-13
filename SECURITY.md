# セキュリティポリシー / Security Policy

`falco-ctf-app` は **公開リポジトリ** です。脆弱性・認証境界の欠陥・フラグ漏えい等の
セキュリティ問題を見つけた場合は、**公開 Issue を立てないでください。**

## 報告方法 (非公開)

GitHub Security Advisory 経由で **非公開** に報告してください:

- <https://github.com/Qfour/falco-ctf-app/security/advisories/new>

これは Issue Form の「🔒 セキュリティ報告 (非公開)」導線
(`.github/ISSUE_TEMPLATE/config.yml`) と同じ宛先です。公開 Issue / PR / Discussion で
脆弱性の詳細を先に開示しないでください。

## 報告に含めないもの (公開リポの鉄則)

報告本文・再現手順・ログ・スクリーンショットに以下を **絶対に含めないでください**。
貼る前にマスクしてください:

- 本番フラグの実値 (`FALCO{...}`)
- シークレット・トークン・認証情報・kubeconfig
- AWS アカウント ID・本番ホスト名・内部エンドポイント
- 参加者情報

## 対象バージョン

サポート対象は **最新の SemVer リリース** (最新 `vX.Y.Z` タグ) です。版・contract の
正典は SemVer タグであり、リリース運用は [`docs/RELEASING.md`](docs/RELEASING.md) を参照。

| バージョン | サポート |
|---|---|
| 最新リリース (`vX.Y.Z`) | ✅ |
| それ以前 | ❌ |

## 対応フロー

1. Advisory を受領後、非公開で影響範囲・再現性を確認します。
2. 修正は非公開ブランチ / draft で準備し、通常の運用サイクル
   (`/review-5x` + VP 査定 → CEO 承認) を通します。
3. 修正リリース後、必要に応じて Advisory を公開します (報告者クレジットは希望に応じ)。
