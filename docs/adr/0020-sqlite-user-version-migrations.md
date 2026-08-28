# ADR-0020: scoreboard スキーマは PRAGMA user_version の単一線形 migration リストで進化させる

- Status: **Accepted** (2026-08-28。architect 起草 (review-5x R4, feat/117-db-migrations の
  レビューにて) → VP 査定で objection なし → 時限自動承認規律 (ORGANIZATION.md §7) により
  VP が Accepted 化。実装先行 + 事後 ADR の形 — ORGANIZATION.md の「ADR は実装をブロック
  しないが merge をブロックする」規律に従い、merge 前に本 ADR を Accepted 化して同一 PR に同梱)
- Date / Deciders: 2026-08-28 / architect (起草)、VP (承認)、CEO (発注: Issue #117)
- 関連: Issue #117 / PR (feat/117-db-migrations) / REFACTORING.md 決定事項 (SQLite 不変) /
  Hard Invariant I1 (single replica + Recreate)

## Context

- `internal/store/store.go` は `CREATE TABLE IF NOT EXISTS` を毎 `Open()` で無条件実行する
  のみで、ALTER TABLE 相当の列追加が構造的に不可能だった (Issue #117 の事実)。
- I1 (replicas:1 + Recreate。`charts/scoreboard/templates/deployment.yaml:10-11` の
  `fail` guard で機械強制) により SQLite は常に単一 writer。REFACTORING.md「やらないこと」は
  「SQLite からの移行はしない」「HA 前倒ししない」を決定事項として固定している。
- したがって選択肢は「SQLite のまま migration 機構を足す」に閉じ、advisory lock 等の
  分散協調機構は I1 が成立する限り不要。

## Options

1. **PRAGMA user_version + コード内 migration リスト (採用・実装済)** — 新テーブル無し、
   新規依存ゼロ (`go.mod`/`go.sum` diff 空)、既存 DDL を migration #1 として凍結宣言。
   新規 DB とレガシー DB (user_version=0) が同一コードパスに合流する。コスト: 低。
   リスクと可逆性: 可逆。効き始める閾値: 最初の列追加/新テーブルが必要になった瞬間 (= 今)。
2. **外部 migration ライブラリ (golang-migrate 等)** — 新規依存追加、embed.FS で .sql 管理。
   コスト: 中 (依存管理・イメージサイズ・学習)。効き始める閾値: migration 数が 10+ になり
   手書き番号管理が事故りやすくなった場合 (Signpost 2 で再訪)。
3. **schema_migrations テーブル + 行ロック方式** — 複数 writer 前提の協調機構。I1 と矛盾する
   設計で実質デッドコード。効き始める閾値: I1 自体が撤回された場合のみ (現状非計画)。

## Decision

Option 1 を採用。I1 が成立する限り (a) 新規依存を増やさず (b) 既存 DDL をそのまま
migration #1 として凍結する設計が最小コストで目的を満たすため。

- 各 migration は 1 トランザクション内で DDL 適用と `PRAGMA user_version` 更新を行う
  (modernc.org/sqlite v1.57.0 で rollback 時に version・スキーマとも巻き戻ることを実測済み —
  review-5x R2)。
- **fail-closed**: DB の user_version がバイナリの知る最新より新しい場合は起動を拒否する
  (ロールバックデプロイ事故への釣り合いの取れた対策)。
- 版番号は 1..N 連番を `assertConsecutiveVersions` が panic で機械強制する (fail-loud)。

## Consequences

- 諦めたもの: 複数 replica / advisory lock による同時 migration 保護は持たない
  (I1 が崩れたら migration 機構は無防備 — この前提は `migrations.go` package doc に明記し維持する)。
- 新たに守る規律: (1) 出荷済み migration の apply 関数は再定義しない・番号は 1..N 連番
  (機械強制あり)、(2) 新しい migration は additive のみ (CREATE / ALTER ADD COLUMN)、
  (3) **`migrations` スライスへ新規エントリを追加する PR は security-engineer レビュー必須**
  (採点真正性テーブル `solved`/`evade_dirty`/`expected_rule_fire`/`exfil` の防波堤がレビューのみの
  ため — review-5x R1 finding。`.claude/rules/dev-flow.md` のゲート表に反映済み)。
- runbook への影響: 無し (`migrate()` は `Store.Open()` に内包され、運用手順の追加ステップは
  発生しない)。

## Signposts (この決定を覆す観測可能な信号)

1. I1 (replicas:1) が撤回される計画が具体化した時 → advisory lock 方式の再設計が必要。
2. migrations リストが 10+ エントリになり、隣接 version の意図が読み取りにくいという指摘が
   2 回以上出た時 → 外部ツール化 (Option 2) を再検討。
3. 本番 DB で downgrade fail-closed が実際に 1 回でも発火した時 → CI/CD 側の
   バージョン go/no-go チェック追加を検討。

## Verification

`make test` (required check `test`) が以下を機械検証する (`internal/store/migrations_internal_test.go`):

- `TestMigrate_FreshDB_BootstrapsToLatestVersion` — 新規 DB が最新 version に到達
- `TestMigrate_LegacyDBWithoutUserVersion_UpgradesAndPreservesData` — 旧 DB のデータ保全 +
  `events_per_user` DROP 経路の実 exercise
- `TestMigrate_CanAddAColumn_AndPreservesExistingRows` — ALTER TABLE 経路の実証 (合成 migration、
  本番 `migrations` は不変)
- `TestMigrate_PartialFailure_RollsBackAndDoesNotAdvanceVersion` — 途中失敗時に user_version
  不変・部分スキーマ不残留・コネクション非リーク (`db.Stats().InUse`)。mutation 実証済み
  (`defer tx.Rollback()` 無効化で red)
- `TestMigrate_FailsClosed_WhenDBVersionNewerThanBinary` — downgrade fail-closed
- `TestAssertConsecutiveVersions_PanicsOnGap` — 連番不変条件

## Advice

- architect (2026-08-28, review-5x R4): I1 破れ検知テストはスコープ外で良いが、
  package doc の「I1 が唯一の防波堤」の明記を維持すること。非拘束。
