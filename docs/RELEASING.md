# リリース手順 (RELEASING)

`falco-ctf-app` の版管理は **各リポ独立 SemVer + GitHub Releases の自動リリースノート**。
要望 (Issue) → PR → Release → CHANGELOG の鎖を GitHub ネイティブ機能で辿れるようにする。

> ⚠️ **タグ打ち・Release publish は CEO のみが行う。** Lead / VP はここまで
> (CHANGELOG 確定・PR ラベル整備) を準備し、実際の `git tag` / push / Release 作成は
> CEO の承認・操作を待つ。

## SemVer bump 基準

- **MAJOR (`X`)** — 公開 contract の破壊的変更 (`/falco/events` payload・image 命名・challenges スキーマ)。
- **MINOR (`Y`)** — 後方互換の機能追加。
- **PATCH (`Z`)** — 後方互換のバグ修正・軽微改善。

## 手順

1. **`## [Unreleased]` を新バージョン節に確定する**
   `CHANGELOG.md` の `## [Unreleased]` を `## [X.Y.Z] - YYYY-MM-DD` に変え、
   空の Added/Changed/Fixed/Security を持つ新しい `## [Unreleased]` を上に足す。
2. **タグを打つ (CEO)**
   ```sh
   git tag vX.Y.Z
   ```
3. **Release を作成し PR を自動列挙する (CEO)**
   ```sh
   gh release create vX.Y.Z --generate-notes
   ```
   `.github/release.yml` の分類に従い、マージ済み PR がラベル別 (Features / Fixes /
   UX / Security / Docs / Infra) にグルーピングされる。PR には `.github/labels.yml` の
   `type:*` ラベルを付けておくこと (未付与は Other に入る)。

## 補足

- contract に触れる変更は platform 側と同時 PR。CHANGELOG の該当節にも contract 影響を明記する。
- 外部クライアントは MAJOR 差分を見て contract 対応版を判断する (CHANGELOG ヘッダ参照)。
