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
- 順番を飛ばした課題 (未到達の `locked` 課題) でも、ヒントを減点つきで開けるようになった。
  開いたヒントと、付けたステップのチェックは、その課題の画面にそのまま表示される
  (これまでは開封の API は通り減点も付くのに、画面には出なかった)。
  `status` (`solved | current | locked`) の値と減点額 (10 / 30 / 50) は変わらない。
  `GET /api/users/{user}/journey` の `detail.hints` と `detail.steps[].checked` は
  `status` ではなく保存済みの状態だけで決まる。応答のキー集合は変わらない。
  詳細: `docs/adr/0027-hint-gate-decoupled-from-current.md`。

### Fixed

- 手順確認 (steps/check)・ヒント開封・やり直し (reset-dirty) の rate limit を、提出 (submit) の
  IP 単位 bucket から切り離し、認証ヘッダーの email 単位 (1 req/s・burst 10) にした。
  会場の NAT の下で、誰かのヒント開封が他の参加者の提出を 429 にすることがなくなる (#315)。
  この 3 つのルートは、認証ヘッダーの無い要求を 403 で拒否する (bucket は消費しない)。
  これまではヘッダー無しでも (許可された Origin を付ければ) 通っていた。
- 上記 3 ルートの認可を self-or-admin (認証ヘッダー必須) に揃えた。route 表・OpenAPI の `x-ctf-authz` も実挙動に合わせて更新 (#315)。
  `ratelimit_identity_requests_total{bucket,outcome}` で bucket 別の allowed / limited / no_identity を見られる。

### Security
- challenge image の `/opt/ctf/missions/` は `<id>/fixtures/**` だけ、という条件を **deploy 時にも検査する** (ADR-0026 V4、不変条件 I16)。
  `deploy-user.sh` が `helm upgrade --wait` の直後に呼ぶ `assert-flag-isolation.sh` の check 3-8 を、scenario に加えて
  `all` / 単一課題の全モードで実行する: `/opt/ctf/missions/` の直下が期待する id 集合と完全に一致し、すべて実ディレクトリで、
  各 `<id>/` は実ディレクトリの `fixtures` だけを持つ (dot entry も見る。fixtures の中身は開かない)。違反があれば `deploy-user.sh` は
  非ゼロで終了する。**運用の注意**: 期待する id 集合は `--challenges-dir` (operator の checkout) から作るので、checkout と image の ref
  を揃えること。allowlist 前の image に新しい ctf-user chart を deploy すると 3-8 で止まる (image を先に更新する)。
  検査の selftest は `scripts/check-missions-allowlist-assert.sh` (`make check-flags` / CI `flag-guard`)。
- portal (`/portal`) と admin dashboard (`/`) は他の origin の iframe に埋め込めなくなった (`frame-ancestors 'none'` + `X-Frame-Options: DENY`)。oauth2-proxy の `SameSite=None` cookie の下で起こり得た clickjacking を閉じる。ttyd の埋め込み (portal が親) には影響しない (app#326)

- `POST /api/users/{user}/display-name` を collector 専用にした (ADR-0034 D12 S1 の前倒し)。`X-Auth-Request-*` ヘッダが 1 つでも付いた要求 (= ブラウザ経路) は本人でも admin でも 403、本文が `application/json` でなければ 415。これまでは journey ingress 経由の cross-site POST で本人 (admin セッションなら全員) の表示名を書き換えられ、偽ヘッダ付き要求の 200 / 403 の差で `ADMIN_EMAILS` への所属も推測できた。端末の `setname` (collector 経由・ヘッダ無し・JSON) は変更なし。
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
