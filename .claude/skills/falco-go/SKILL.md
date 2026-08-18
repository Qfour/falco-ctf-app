---
name: falco-go
description: falco-ctf-app 固有の Go 事実と経路 (module/layout/HTTP/SQLite/ツールチェーン/fail-closed の実装点)。Use when writing or reviewing Go code in falco-ctf-app — cmd/ internal/ の実装や修正、*_test.go の追加、go.mod の変更、goroutine/context/errors の取り扱い、make test / make gen の実行、Go コードの監査やレビューを行うとき。
---

# Go craft — falco-ctf-app (特化)

## 優先順位 (機械的規則)

- `go-expert` (汎用) と食い違ったら **このファイルが勝つ**
- **このファイルが沈黙している事項は `go-expert` に従う**
- **両方より `.claude/rules/falco-ctf-app-conventions.md` と `CLAUDE.md` が優先**
  (Hard Invariants と Cross-repo 契約の正典。skill には写経しない)

## このリポの Go 事実

- module `github.com/Qfour/falco-ctf-app` / **go 1.26.0**
- レイアウト: `cmd/` = 起動と wiring のみ / `internal/` = 実装
- HTTP は **`net/http` のみ** (1.22+ pattern routing)。chi/echo 等は入れない
- SQLite は **`modernc.org/sqlite`** (pure Go, CGO 不要)。**単一 writer 前提** (I1 — 正典は
  `.claude/rules/falco-ctf-app-conventions.md`。実装上は書き込みを並行化する設計を持ち込まない)
- `golangci-lint` の設定は**無い**。静的検査は `go vet` (PostEdit hook) + CI

## ツールチェーン (必ずこの経路)

Colima は host repo path を VM に共有しないため、**ホストの `go` を直接叩かない**。

| やること | コマンド | 備考 |
|---|---|---|
| テスト | `make test` | `Dockerfile.test` でコンテナ実行 |
| 依存整理 | `make tidy` | `go.mod`/`go.sum` を host に書き戻す |
| 生成 | `make gen` | oapi types。**生成物の手書き禁止** |
| chart values 生成 | `make gen-values` | plant.sh が単一ソース。**手書き禁止** |

⚠ `make test` は Docker のレイヤキャッシュにより **全レイヤ CACHED で完走してしまい得る**
(=何もテストされていないのに成功に見える)。変更を独立して確認したいときは
`docker build --no-cache` 経路で焼き直す。

## fail-closed の実装点 (採点・認証経路)

- **`MarkDirty` は in-memory taint を `db.Exec` の前に立てる** (書き込み失敗時に
  「dirty のはずが記録されていない」状態を作らない — fail-closed 側に倒す)
- **`ResetDirty` は単一トランザクション**で行う (部分的にリセットされた中間状態を作らない)
- 一般的な fail-closed パターン (sentinel error, 内部エラー非開示, ラップ/判定) は
  `go-expert` の `references/errors.md` を参照 — ここには写経しない

## HTTP ハンドラの作法

- レスポンスは `httpx.WriteJSON(w, status, body)`。ヘッダは body を書く**前**に確定させる
- 入力検証は既存の狭い validator に倣う (`internal/scoreboard/api` の `validUser` 等)。
  サイズ上限と文字集合を明示する
- 認可は既存のゲート関数を通す (`isAdmin` / `selfOrAdmin` 系)。
  **ハンドラ内でメールアドレスを自前照合しない** (I8 の緩和になる)
- oapi 生成型 (`internal/*/oapi`) を手書きしない。spec を変えて `make gen`

## 生成物の規律

- `values*.yaml` / `types.gen.go` を手編集しない (`make gen-values` / `make gen` のみ)
- ハンドラにビジネスロジックを溜めない (ドメインは `internal/` の該当パッケージへ)

## テストフィクスチャ (public repo)

- **実フラグ・実シークレット・参加者情報を入れない**。合成値のみ
- フラグは `FALCO{dev-<slug>}` placeholder
- メールは `user1@ctf.local` / `admin@ctf.local` の形の合成値
- 作業中の一時ファイルには `DO`+`NOT`+`COMMIT` マーカーを付ける
  (`make check-flags` が tracked file を検出して block する)
