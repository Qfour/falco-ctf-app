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

### Fixed

### Security

- flags ファイル (`FLAGS_FILE` / `deploy-user.sh --flags-file`) の検証を fail-closed 化。
  これまでは evade 課題の id が欠けていても既定値 (placeholder) のまま起動していた。
  指定時は、スコープ内の全 evade 課題への供給と、既定値と異なる値であることを必須にし、
  満たさなければ scoreboard は起動を拒否、`deploy-user.sh` は cluster に触れる前に終了する。
  flags ファイルを指定しない経路 (ローカル開発) は変更なし。

<!--
  compare リンク参照定義。リリース時に vX.Y.Z を最新タグへ更新すること
  (docs/RELEASING.md の手順参照)。初期は最初のタグを打つまでプレースホルダ。
-->
[Unreleased]: https://github.com/Qfour/falco-ctf-app/compare/vX.Y.Z...HEAD
