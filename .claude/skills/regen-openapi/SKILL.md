---
name: regen-openapi
description: Procedure for regenerating OpenAPI types (make gen) and keeping docs/ in sync after handler changes.
---

# OpenAPI 再生成手順

## いつ実行するか

- `internal/scoreboard/` または `internal/authpolicy/` のハンドラを変更した
- レスポンス構造 / エンドポイントを追加・削除した
- `docs/openapi-*.yaml` を手で編集した（逆方向の同期）

## 1. 生成を実行

```bash
make gen
```

## 2. 生成物の差分を確認

```bash
git diff -- 'internal/**/*.gen.go' docs/
```

確認ポイント:
- 新しいエンドポイントが `types.gen.go` に反映されているか
- 削除したフィールドが型から消えているか
- `docs/openapi-*.yaml` の `paths` / `components` が意図通りか

## 3. ハンドラと型の整合チェック

```bash
go build ./...    # 型不整合はここで出る
make test         # 統合テスト (Docker 内)
```

## 4. docs/ を同期

`docs/openapi-scoreboard.yaml` と `docs/openapi-auth-policy.yaml` が
コードの実態を反映していることを確認。必要なら手で補完:
- `summary` / `description` フィールド
- `example` の値
- `security` スキーム

## 5. コミット

生成物とソースの変更を **同一コミット** に含める（分離すると CI で型不一致になる）:

```bash
git add internal/ docs/
# /commit で Haiku に委譲
```

## チェックリスト

- [ ] `make gen` がエラーなく完了
- [ ] `go build ./...` が通る
- [ ] `docs/openapi-*.yaml` が変更内容を反映
- [ ] 生成物とソース変更が同一コミット
- [ ] `make test` が通る（Docker 内）
