## 変更概要

<!-- 何を変えたか、なぜ変えたかを1〜3行で -->

## 変更種別

- [ ] feat — 新機能
- [ ] fix — バグ修正
- [ ] chal — challenge 追加 / 修正
- [ ] deploy — Kustomize / manifest
- [ ] ci — GitHub Actions
- [ ] chore / refactor

## チェックリスト

- [ ] `make test` がローカルで通る
- [ ] Hard Invariants (I1–I10) を破っていない
- [ ] `deploy/` を変更した場合、base に hostname / secrets を含めていない (I7, I10)
- [ ] challenge を追加した場合、`expectedFlag` が空でない・`falco-rule.yaml` のスキーマが正しい

## 関連 Issue / 備考

<!-- なければ削除 -->
