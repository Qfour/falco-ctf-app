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

- 参加者のプロフィール (ADR-0034 D8〜D10)。表示名に加えて、用意した絵柄の id (`<glyph>-<color>`、8 glyph x 6 色 = 48 個。画像のアップロードは無い) を選べる。
  - `POST /api/users/{user}/profile` — body は `{display_name?, avatar?}` (1 つ以上、他の key は 400)。origin-guard 付き・self-or-admin (認証ヘッダー必須)・identity 単位の rate limit・collector は forward しない。全項目を検証してから 1 トランザクションで書く。`avatar` は 47 個から選べ、運営の掲示に付く固定の `flame-slate` は 400。
  - `POST /api/admin/users/{user}/profile-reset` — 表示名と絵柄を seat の既定に戻す (admin のみ・origin-guard 付き)。
  - 応答に `avatar` を additive で追加: `Me`・`Journey`・`LeaderboardEntry`・`ChallengeSolver`・`SolveRecord`、`BoardMessage` は `authorAvatar`。未設定の席は seat から決まる既定の id (`user1`〜`user40` は互いに異なる)。
  - `GET /static/{asset}` が `avatars/` の下に限り `.svg` を配る (ADR-0028 D5 の拡張子の集合を ADR-0034 D9 が限定 supersede)。登録表が起動時に SVG を要素・属性の allow-list で検査し、応答に `X-Content-Type-Options: nosniff` と `sandbox` の CSP を付ける。
  - SQLite の schema migration 2 (`avatars` 表。additive)。**アップグレード時の注意は下の「Upgrade note」。**
- **Upgrade note (migration 2 / ロールバック)**: この版の scoreboard が一度起動した DB は `PRAGMA user_version = 2` になる。以降、この版より前の image に戻すと、旧 image は ADR-0020 の downgrade guard (fail-closed) により起動を拒否する (`database schema version v2 is newer than this binary supports`)。復旧は次のどちらか。
  - **DB を復元する** — migration 前の PVC snapshot / 退避を戻す (確実。その後に書かれた solve は失われる)。
  - **`avatars` は additive なので `user_version` を 1 に戻す** — scoreboard を止めて (replicas=1 + Recreate)、DB ファイルに `PRAGMA user_version = 1;` を実行してから旧 image を起動する (scoreboard の image に `sqlite3` は無いので、DB を別 Pod にマウントするか取り出して実行する)。旧 image は `avatars` 表を読まず、自分の表はそのまま使える。後でこの版に上げ直すと migration 2 は `CREATE TABLE IF NOT EXISTS` なので、戻す前に選ばれていた絵柄は残る。`internal/store` の `TestMigrate_RollbackToV1_OldBinaryRunsAndAReUpgradeKeepsAvatars` が旧 binary の拒否・戻した後の起動・再アップグレードを固定している。実機の PVC での手順は未リハーサル。
  - **戻し先は display-name の封鎖 (Security 項) を含む版に限る** — それより前の image に戻すと、origin-guard の無い参加者用 display-name route が journey ingress に戻り、CSRF と ADMIN_EMAILS の oracle が復活する。
- **identity ロスター (ADR-0034 D2)**: auth-policy が `ROSTER_FILE` (YAML の `seats:` に `{seat, external?}`) を
  起動時に読み、認証済み identity を seat (workspace 名) に解決する唯一の表になった。
  正規化は ASCII のみ・小文字化・`gmail.com` / `googlemail.com` に限り dot と `+tag` を落とす。
  chart は roster の Secret (`roster.secretName`、key `roster.yaml`) を mount する。
- `GET /check-participant` (auth-policy): 参加者側の ingress の auth-url。`ADMIN_EMAILS` か、ロスターで seat に
  解決できる identity にだけ 200。解決できた identity には `X-Auth-Request-{Email,User,Preferred-Username}`
  を正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` だけで上書きして返す。
- `/healthz` (auth-policy) に `roster_seats` / `roster_external` (件数のみ)。
- scoreboard の `EXPECTED_EMAIL_DOMAIN` (chart: `env.expectedEmailDomain`)。

### Changed

- board: 件名 (thread の subject) が control (Cc: C0/C1、改行・tab を含む) と format (Cf: U+202E などの bidi 制御、ゼロ幅文字) の文字を含むと `POST /api/board/threads` が 400 になる (固定文 `subject contains forbidden characters`、入力は返さない)。表示名 (#331) と同じ規則で、ZWJ は絵文字の間だけ許可。`' " & < >` は散文なので許可のまま。portal は件名を `<bdi>` で隔離して表示する (#377)。
  - **Upgrade note**: すでに保存された件名は再検証されない。そのような件名も portal の `<bdi>` で表示は安全。本文 (body) の規則は変えていない。
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
- **破壊的変更 (公開 contract)**: 次の 3 つは外部クライアントや運用 script に見える除去である。[`docs/RELEASING.md`](docs/RELEASING.md) の MAJOR の列挙 (webhook payload / image 命名 / challenges スキーマ) には直接は当たらないが、contract の除去なので MAJOR 相当として扱う (実際の版は CEO のタグ運用で決める)。(1) 参加者用 `POST /api/users/{user}/display-name` の撤去 (Removed)、(2) collector の forward 2 本化 (下)、(3) `deploy-user.sh --display-name` の廃止 (下)。platform の `--names-file` 廃止を先に merge し、その後に events の app pin を進める。
- collector の forward を 3 本から 2 本 (`submit` / `exfil`) にした (ADR-0034 D12 S1)。`POST /api/users/{user}/display-name` は collector でも 404/405 (default-deny) になる。`docs/openapi-collector.yaml` は 5 → 4 operation、`docs/openapi-scoreboard.yaml` は `x-ctf-collector-forward: true` が 3 → 2 本。**公開 contract の変更**: 外部クライアントが collector 経由で表示名を書いていた場合は、認証済みの profile route に移る必要がある。
- 表示名と絵柄の設定は、ワークスペースの端末ではなくポータルの Me 画面に移った。初期値は seat のまま。案内文 (`banner.sh`、00-tutorial の welcome / step、ハンドブック、コマンド集) を差し替えた。
- `deploy-user.sh` の `--display-name` を廃止した (ADR-0034 D10)。渡すと理由を stderr に出して exit 2 になり、kubectl / helm を呼ばずに止まる。deploy は表示名を書かない (旧 step 6 を削除、step 数は常に 5)。platform の `deploy-event-workspaces.sh --names-file` も同時に廃止する (platform 側の変更)。**`--names-file` を使っている間に、この変更を含む app ref へ events の pin を進めると、全 user の deploy が exit 2 になる** (cluster に触れる前に止まり、理由が出る)。platform の廃止を先に merge すること。
- **破壊的変更 (auth-policy の endpoint)**: `GET /check?host=<h>` を **`GET /check-workspace?host=<h>` に改名して
  `/check` を削除**。新 chart + 旧 binary、旧 chart + 新 binary のどちらの組でも auth の subrequest は 404 になり、
  ingress が 500 で閉じる (開かない)。判定は「ロスターで解決した seat が host と完全一致」(前方一致をやめた)。
- **破壊的変更 (ロスター必須)**: auth-policy は `ROSTER_FILE` が無い・空・不正なら**起動しない**。
  `EXPECTED_EMAIL_DOMAIN` と `ADMIN_EMAILS` の各ドメインの最後のラベルは予約名 (`local` `test` `invalid`
  `example` `localhost`) でなければならず、`ADMIN_EMAILS` がロスターの seat / external と重なっても auth-policy は起動しない
  (scoreboard はロスターを持たないので重なりを検出できない: `ADMIN_EMAILS` は同じ 1 値を auth-policy と scoreboard の両 release に渡す)。
- **破壊的変更 (chart の値)**: `ingress.journeyAuthUrl` (scoreboard)、`ingress.adminAuthUrl` (docs)、
  `auth.authUrl` と **`auth.enabled` (ctf-user)** を廃止。全 Ingress の auth-url は template に固定
  (参加者 = `/check-participant`、workspace = `/check-workspace?host=<username>`、運営 = `/check-admin`)。
  古い値を渡すと描画が失敗する。Ingress の annotation passthrough は**許可 key の allowlist** (`nginx.ingress.kubernetes.io/ssl-redirect` /
  `nginx.ingress.kubernetes.io/proxy-body-size` / `cert-manager.io/cluster-issuer`) で、それ以外の key は描画が失敗する
  (`auth-*` に限らず `satisfy` や `whitelist-source-range` / `allowlist-source-range` も)。対象は 3 つの passthrough
  (scoreboard の admin / journey、docs の admin)。ctf-user には passthrough が無い。
- **破壊的変更 (scoreboard)**: self の照合を `<user>@<EXPECTED_EMAIL_DOMAIN>` との**完全一致**に変更
  (これまでは任意ドメインの `<user>@` 前方一致)。`EXPECTED_EMAIL_DOMAIN` が未設定の scoreboard は誰も self と
  みなさない (参加者は締め出される。fail-closed)。platform は auth-policy と scoreboard に同じ値を渡すこと。
- 403 の本文から email を除いた (固定文字列 `forbidden`)。

### Removed

- 端末の `setname` (`challenges/setname.sh` と、challenge image の `/opt/ctf/setname.sh`) を撤去した。ワークスペースから表示名を書く経路はなくなる。
- 参加者用 `POST /api/users/{user}/display-name` を spec と mux から撤去した。admin 用 `POST /api/admin/users/{user}/display-name` は残る。`internal-claimed-identity` の語彙は残す (webhook / exfil の browser-path 封鎖が同じ語彙を使うため)。

### Fixed

- 手順確認 (steps/check)・ヒント開封・やり直し (reset-dirty) の rate limit を、提出 (submit) の
  IP 単位 bucket から切り離し、認証ヘッダーの email 単位 (1 req/s・burst 10) にした。
  会場の NAT の下で、誰かのヒント開封が他の参加者の提出を 429 にすることがなくなる (#315)。
  この 3 つのルートは、認証ヘッダーの無い要求を 403 で拒否する (bucket は消費しない)。
  これまではヘッダー無しでも (許可された Origin を付ければ) 通っていた。
- 上記 3 ルートの認可を self-or-admin (認証ヘッダー必須) に揃えた。route 表・OpenAPI の `x-ctf-authz` も実挙動に合わせて更新 (#315)。
  `ratelimit_identity_requests_total{bucket,outcome}` で bucket 別の allowed / limited / no_identity を見られる。
- 検知条件の採点 (submit-detect) も identity キーの専用 bucket (`detect`、1 req/s・burst 10) に載せた。これまでは submit の IP 単位 bucket を
  共有していた。ヒント / step 確認 / reset-dirty の bucket とは別なので、将来 portal に Grade ボタンが付いたときも (現時点で呼び出し元は無い)、その連打でそれらが 429 にならない (逆も同じ)。
  認証ヘッダーの無い要求は 403 で拒否し、bucket を消費せず handler (body の読み取り) にも入らない。
  route 表・OpenAPI の `x-ctf-rate-limit` と /submit 側の「(shared with submit-detect)」も実挙動に合わせた (#328)。
- 表示名の検証が Unicode の Cf (U+200B 零幅スペース・U+202E bidi 上書きなど) と C1 制御文字 (U+0080〜009F) を通していたのを拒否にした。
  bidi 制御・ゼロ幅 (Cf)・C1 制御の拒否に限る (ADR-0026 D5-1 の Cf 拒否と同じ方針)。他の席への見た目のなりすましを防ぐものではない。プロフィール route (`POST /api/users/{user}/profile` の `display_name`) と admin 用 display-name route の両方で同じ検証。
  ZWJ (U+200D) で連結する絵文字は 2 つの絵文字に挟まれたときだけ通す。日本語・絵文字・結合文字の名前は従来どおり通る。**例外**: 地域旗の絵文字 (イングランド・スコットランド・ウェールズ = U+1F3F4 + tag 文字 U+E0020〜E007F) は tag 文字が Cf なので server・form とも拒否になる (受け入れる判断。`api.go` のコメントと case 表の行で固定) (#331)。
  **upgrade note**: この版より前に保存された名前は再検証されない (起動時の読み込みも admin reset も検査しない)。直す手段は admin の profile-reset (追跡 = #403)。
  Portal のプロフィール form の検査も同じ規則にした。form は server より厳しくならない (U+200D は常に通し、絵文字の間かどうかは server が判定する)。両端の空白は server の `strings.TrimSpace` と同じ集合 (U+0085 を含み U+FEFF は含まない) で落とす。名前を変えたときだけ検査するので、保存済みの名前のまま絵柄だけ変える保存は止まらない。共有の case 表 `internal/scoreboard/api/testdata/display-name-parity/cases.yaml` を server (`validDisplayName`) と form の両方に流して固定 (#343)。

### Security
- **`POST /api/challenges/{cid}/submit-detect` は `X-Auth-Request-Email` 必須になった (app#346)**。ヘッダ無しは 403 (以前は origin-guard を通れば claimed identity で通っていた)。body の `user` は identity の正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` との完全一致 (admin は例外)。合わせて `x-ctf-authz: self-or-admin-write` の語彙 (spec・`apispec.AuthzSelfOrAdminWrite`・ゲート関数) を廃止した。collector はこの route を元々転送せず workspace からも届かないので、外部クライアントへの実害は想定していない。`docs/RELEASING.md` の bump 基準 (公開 contract の破壊的変更 = MAJOR に当たらない、認可の厳格化) では **minor** 扱い。
- challenge image の `/opt/ctf/missions/` は `<id>/fixtures/**` だけ、という条件を **deploy 時にも検査する** (ADR-0026 V4、不変条件 I16)。
  `deploy-user.sh` が `helm upgrade --wait` の直後に呼ぶ `assert-flag-isolation.sh` の check 3-8 を、scenario に加えて
  `all` / 単一課題の全モードで実行する: `/opt/ctf/missions/` の直下が期待する id 集合と完全に一致し、すべて実ディレクトリで、
  各 `<id>/` は実ディレクトリの `fixtures` だけを持つ (dot entry も見る。fixtures の中身は開かない)。違反があれば `deploy-user.sh` は
  非ゼロで終了する。**運用の注意**: 期待する id 集合は `--challenges-dir` (operator の checkout) から作るので、checkout と image の ref
  を揃えること。allowlist 前の image に新しい ctf-user chart を deploy すると 3-8 で止まる (image を先に更新する)。
  検査の selftest は `scripts/check-missions-allowlist-assert.sh` (`make check-flags` / CI `flag-guard`)。
- portal (`/portal`) と admin dashboard (`/`) は他の origin の iframe に埋め込めなくなった (`frame-ancestors 'none'` + `X-Frame-Options: DENY`)。oauth2-proxy の `SameSite=None` cookie の下で起こり得た clickjacking を閉じる。ttyd の埋め込み (portal が親) には影響しない (app#326)

- `POST /api/users/{user}/display-name` のブラウザ経路を閉じた (ADR-0034 D12 S1 の前倒し)。`X-Auth-Request-*` ヘッダが 1 つでも付いた要求 (= ブラウザ経路) は本人でも admin でも 403、本文が `application/json` でなければ 415 にした。これまでは journey ingress 経由の cross-site POST で本人 (admin セッションなら全員) の表示名を書き換えられ、偽ヘッダ付き要求の 200 / 403 の差で `ADMIN_EMAILS` への所属も推測できた。**この項は、その hotfix を単独で入れた版の記録である。ADR-0034 S1 を含む版ではこの route 自体を Removed 項で撤去しており、collector の forward も、端末の `setname` もない。**
- Falco webhook (`POST /falco/events`) と collector 専用の exfil sink (`POST /internal/exfil/{cid}`) の受信をブラウザ経路から閉じた。`X-Auth-Request-*` ヘッダが付いた要求は 403、本文が `application/json` でなければ 415 (falcosidekick の webhook は元から JSON。exfil の受信は `Content-Type: application/json` を要求するので、`-H` 無しの `curl -d` は 415 になる)。
- **collector**: workspace からの要求のうち `X-Auth-Request-` で始まるヘッダを、すべての転送 route で無条件に消す
  (ADR-0034 D6)。これまでは通っており、転送先で proven identity と区別がつかなかった。
- 参加者の門を「認証済みなら誰でも」から「ロスターに載った identity」に替えた (外部 IdP を足す前提。ADR-0034 C2)。
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
