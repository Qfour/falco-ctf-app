# Changelog

> **機械的な版記録の正典は [GitHub Releases](https://github.com/Qfour/falco-ctf-app/releases)
> の自動リリースノート。** 本ファイルは人が読むためのハイライトとリンク集であり、
> 網羅性は Releases が担保する。

本リポ (`falco-ctf-app`) は再利用可能な CTF キットであり、**公開 contract**
(`POST /falco/events` webhook payload / image 命名 / challenges スキーマ) を持つ。
**外部クライアント (将来 Roblox 等) は SemVer タグで contract 対応版を判断する。**

バージョニングは [Semantic Versioning](https://semver.org/lang/ja/) に従う。
bump 基準は [`docs/RELEASING.md`](docs/RELEASING.md) を参照。

## [Unreleased]

### Added

### Changed

- portal: 進行位置にない (`locked`) 課題の見出しを `PREVIEW · LOCKED` から `UPCOMING MISSION` に変更
  (`locked` は「案内上の未到達」で、ヒントは減点つきで開ける: ADR-0027 D5)。`status` が `current` でなく
  禁止ルールの記録も無い evade の「検知状態」は、「クリーンです / このまま提出できます / クリーンな attempt を確認」
  を出さず、「未評価」(クリア済みの課題は「クリア済み」) の中立表示にする (ADR-0027 D6)。禁止ルールが記録されている
  場合の表示は status に関係なく従来どおり。API 側の変更 (hint 開封の判定を `current` から切り離す) と対で成立する。

### Fixed

### Security

- flags ファイル (`FLAGS_FILE` / `deploy-user.sh --flags-file`) の検証を fail-closed 化。
  これまでは evade 課題の id が欠けていても既定値 (placeholder) のまま起動していた。
  指定時は、スコープ内の全 evade 課題への供給、いずれの課題の既定値とも異なる値であること、
  課題間で値が重複しないこと、値が `FALCO{...} (only A-Za-z0-9_- inside the braces)` の形であることを必須にし、
  満たさなければ scoreboard は起動を拒否、`deploy-user.sh` は cluster に触れる前に終了する。
  flags ファイルを指定しない経路 (ローカル開発) は変更なし。
- **アップグレード時の注意**: 既存の `scoreboard-flags` Secret が不完全、既定値と同値、
  または上記の形に合わない場合、この版に上げた scoreboard は再起動時に起動を拒否する
  (ログは `flag overrides failed`)。上げる前に flags ファイルを確認すること。
- `falco-rule.yaml` の `expectedFlag` も `FALCO{...} (only A-Za-z0-9_- inside the braces)` に制限 (従来は `}` 以外の任意文字)。

<!--
  compare リンク参照定義。リリース時に vX.Y.Z を最新タグへ更新すること
  (docs/RELEASING.md の手順参照)。初期は最初のタグを打つまでプレースホルダ。
-->
[Unreleased]: https://github.com/Qfour/falco-ctf-app/compare/vX.Y.Z...HEAD
