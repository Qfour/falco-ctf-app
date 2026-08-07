## 変更概要

<!-- 何を変えたか、なぜ変えたかを1〜3行で -->

関連 Issue: Closes #___

## 変更種別

`.github/labels.yml` の `type:*` ラベル体系に対応。マージ前に該当する
`type:*` ラベルを PR に付与すること (未付与は Release ノートで Other に落ちる)。

- [ ] type:feature — 新機能・機能追加
- [ ] type:bug — バグ・想定外挙動の修正
- [ ] type:ux — 体験・操作性・見た目の改善
- [ ] type:security — セキュリティ修正・強化
- [ ] type:docs — ドキュメント・runbook のみの変更
- [ ] type:infra — 基盤・CI・ビルドの変更

## ゲートチェックリスト

該当するパターンのチェックを入れる。複数パターン混在時は優先順 A > D > B > C。

### パターン A: Go コード変更 (`cmd/`, `internal/`, `go.mod`)

- [ ] `make test` ローカルで通過
- [ ] イメージ変更あり → `make scan TAG=local` 実施・全イメージ Clean 確認
- [ ] `/review-code` 通過

### パターン B: Chart 変更 (`charts/`)

- [ ] `make lint` (helm lint) ローカルで通過
- [ ] `values.yaml` default に実 host / registry / secrets を含めていない (I7, I10)
- [ ] `/review-manifests` 通過

### パターン C: Challenge 追加 (`challenges/`)

- [ ] `falco-rule.yaml` スキーマ正しい (`type: trigger|evade`、`FALCO{...}` flag 形式)
- [ ] `make dev` → `/api/state` でカタログ読込 OK を確認
- [ ] `/review-challenge` 通過

### パターン D: イメージ変更 (`images/`, `Dockerfile.*`)

- [ ] `make scan TAG=local` 実施・全イメージ Clean 確認
- [ ] `/security-audit` 通過

## 共通

- [ ] Hard Invariants (I1–I10) を破っていない

## CVE スキャン結果 (パターン A/D のみ)

| イメージ | Critical | High | 対応 |
|---|---|---|---|
| scoreboard | 0 | 0 | Clean |
| auth-policy | 0 | 0 | Clean |
| ttyd | - | - | - |
| challenge | 0 | 0 | Clean |

## 関連 Issue / 備考

<!-- なければ削除 -->
