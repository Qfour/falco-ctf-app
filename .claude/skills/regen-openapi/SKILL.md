---
name: regen-openapi
description: Procedure for regenerating OpenAPI types (make gen) and keeping docs/ in sync after handler changes.
---

# OpenAPI 再生成手順

⚠ **正典は ADR-0005 + `.claude/skills/falco-api/SKILL.md`。** この手順書は
ADR-0005 が名指しした「0% 遵守の根因」（規約が手順書にしか書かれておらず、機構が
検査していなかった）そのものなので、書き換える際は必ず ADR-0005 の
`## Verification` (V1-V8) と整合させること — ここに書いた手順と `make test` の
parity gate が食い違ったら、gate が正しく手順が誤り。

## いつ実行するか

- `internal/scoreboard/`・`internal/authpolicy/`・`internal/collector/` の
  ハンドラを変更した
- レスポンス構造 / エンドポイントを追加・削除した
- `docs/openapi-*.yaml` を手で編集した（逆方向の同期）

## 0. ルートを追加/削除する場合は先にコードを直す

spec を先に書いてから型を生成する（spec → code）向きは維持するが、**ルート集合
そのもの**は各サービスの `Routes()`（`internal/scoreboard/api/api.go` /
`internal/scoreboard/view/view.go` / `internal/scoreboard/ingest/ingest.go` /
`internal/collector/collector.go` / `internal/authpolicy/server.go`）が唯一の
正 — 別建てのルート一覧を作らない（ADR-0005 V2）。ルートを足す/消すときは:

1. 対応する `Routes()` の `apispec.Route{}` エントリを足す/消す
2. **`x-ctf-audience` / `x-ctf-authz` / `x-ctf-origin-guard` /
   `x-ctf-collector-forward` / `x-ctf-rate-limit` の 5 つを Route と
   spec の両方に必ず書く**（ADR-0005 Decision 2(b)。欠落は
   `internal/apispec/specparity.BoolExtParity` / `StringExtParity` が
   fail-closed で落とす — 既定値で埋めない）
3. `x-ctf-origin-guard` / `x-ctf-collector-forward` を変える変更は
   **security-engineer レビュー必須**（`falco-api` skill の非対称表を読む —
   両方向に事故がある）

## 1. 生成を実行

```bash
make gen
```

（collector には生成物が無い — `docs/openapi-collector.yaml` は手で編集する
だけで良い。`make gen` は scoreboard/auth-policy の `types.gen.go` のみ作る）

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
make test         # 統合テスト (Docker 内) — ADR-0005 の parity gate もここで走る
```

`make test` が赤くなったら、それは大抵このステップの後回しではなく **ステップ 0
の 5 extension のどれかを書き忘れている**か、`Routes()` と spec のルート集合が
ズレている（`internal/apispec/specparity` の V1/V3/V4/V5 のいずれか）。
`gen-diff-check` は required check ではない（`falco-api` skill 参照）ので、
**このステップの `make test` が実質の同期ゲート**。

## 4. docs/ を同期

`docs/openapi-{scoreboard,collector,auth-policy}.yaml` がコードの実態を
反映していることを確認。必要なら手で補完:
- `summary` / `description` フィールド
- `example` の値

**`security` / `securitySchemes` は書かない** — ADR-0005 Decision 3 は
明示的にこれを不採用と決めている（`securitySchemes` は「クライアントが資格情報を
提示する」モデルしか表現できず、このリポの実際の認可 — プロキシが注入するヘッダ・
origin-guard・collector forward・self-or-admin の関係性 — を正確に表せない）。
認可・audience・origin-guard・collector-forward・rate-limit は **すべて
`x-ctf-*` extension で宣言する**（ステップ 0）。`security` を足すと、宣言と
実装比較の対象外の「二番目の、検査されない認可宣言」が spec に生まれる。

## 5. コミット

生成物とソースの変更を **同一コミット** に含める（分離すると CI で型不一致になる）:

```bash
git add internal/ docs/
# /commit で Haiku に委譲
```

## チェックリスト

- [ ] ルートを追加/削除した場合、対応する `Routes()` と spec の両方に
      5 つの `x-ctf-*` extension をすべて書いた
- [ ] `x-ctf-origin-guard` / `x-ctf-collector-forward` を変えた場合、
      security-engineer レビューを通した
- [ ] `security` / `securitySchemes` を spec に追加していない
- [ ] `make gen` がエラーなく完了
- [ ] `go build ./...` が通る
- [ ] `docs/openapi-*.yaml` が変更内容を反映
- [ ] 生成物とソース変更が同一コミット
- [ ] `make test` が通る（Docker 内、ADR-0005 parity gate 含む）
