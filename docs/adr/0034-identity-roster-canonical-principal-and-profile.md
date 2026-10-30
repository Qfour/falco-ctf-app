# ADR-0034: identity はロスター 1 表で seat に解決し、正規形だけを後段に渡す (I8 の置き換え・Google ログインの前提)。プロフィールは表示名と用意した絵柄の id に限る

- Status: **Accepted** (2026-10-16。**D2 の seat の文法の 1 文 (`^[a-z0-9][a-z0-9-]{0,62}$`) は ADR-0042 が置き換える** (1〜53 文字、両端が英数字。それ以外の D2 は変わらない。**ADR-0042 は Accepted (2026-10-25、app#496 + platform#282)**。D2 のこの 1 文の現行は ADR-0042 の D1 に書いてある)。実装: app S1 = app#372、platform #217。S2 = app `feat/adr-0034-s2-identity-roster` / platform `feat/adr-0034-s2-identity-platform` は次)。
  旧 Proposed の記述: Accepted への昇格は CEO が行う (S1 の実装 PR の merge と同時、別 commit)。S2・S3 の D は各段の merge まで効力を持たない (「段階」)。
  I8 の表の書き換えは S2 の実装 PR で、V9〜V13 と同一 PR に限る。
  限定 supersede (2026-10-30): D7 の I8 の文言のうち ADMIN_EMAILS の範囲「任意の workspace と運営 route」を ADR-0050 が置き換える。Accepted 時に日付と SHA を足す。
- Date / Deciders: 2026-10-12 / CEO (2026-10-12 の要望。brief D1〜D7 の判断) + VP + architect (起草) + product-engineer (brief) +
  qa-engineer (R2)・security-engineer (R1) の独立レビューを反映済み (Advice)
- 関連: workspace の product brief「ログイン (Google) とプロフィール」(`docs/briefs/identity-and-profile.md`、2026-10-12、未 merge)、I8 (置き換え)・I1・I7・
  I14・I15、ADR-0005 / 0009 (spec parity)、ADR-0020 (migration)、ADR-0023 (collector の strip 義務)、ADR-0028 (**D5 の拡張子の集合だけを限定 supersede**)、
  ADR-0029 (I17。無接触)、ADR-0031 (E2E が注入する email の形)、ADR-0032 (migration の番号の先後)、app#315 (identity キーの rate-limit)、P28 VP 裁定 3・6
- 読み方: `file:line` は app の origin/main `c5e0761`、`falco-ctf-platform/…` は platform の origin/main `09f7d0d`。app#315 の実装は未 merge の branch
  `fix/hint-ratelimit-identity-key` で読んだ。外部製品の挙動は Advice の A1〜A6 (2026-10-12 参照。master の source で、platform が使う版での確認は V14〜V16)。

## Context

**C1. I8 は「認証できる email = 運営が発行した email」を暗黙の前提にしている。** `/check` は `strings.HasPrefix(email, host+"@")` だけで判定し
(`internal/authpolicy/server.go:250`)、ドメインを見ない。`EXPECTED_EMAIL_DOMAIN` は読まれて `/healthz` とログに出るだけで、判定に使われていない
(`cmd/auth-policy/main.go:18,33`、`server.go:147`)。scoreboard の写し `emailMatchesUser` も同じで (`internal/scoreboard/api/api.go:857-862`)、
`DeriveUsername` は `@` の前を username とし (`api.go:386-400`)、board の投稿者にも使う (`api.go:806-817`)。ドメインの制限は oauth2-proxy の
`email_domains` (`falco-ctf-platform/helmfile/releases/oauth2-proxy/values.yaml.gotmpl:36`、prod は `ctf.local` = `helmfile/environments/prod.yaml.gotmpl:108`)
にしか無い。Google を通すために `email_domains` を広げた時点で、外部の `user7@<任意のドメイン>` が user7 の workspace・portal・board に入る。

**C2. 参加者の門は「認証済みなら誰でも」である。** participant の Ingress は oauth2-proxy に直結する (`charts/scoreboard/templates/ingress-journey.yaml:10-12,28`、
platform `helmfile/releases/scoreboard/values.yaml.gotmpl:157`)。その後ろに、body で identity を申告する submit (`docs/openapi-scoreboard.yaml:598-614`、
`api.go:1071-1085`) と、認証済みなら書ける board がある。外部 IdP では「認証済み」⊋「招待済み」なので、この門は表で絞った門に替えるしかない。

**C3. email の検証。** Dex の Google connector は `email_verified` を identity に写すだけで、偽でも拒否しない (A2)。oauth2-proxy は
`insecure_oidc_allow_unverified_email = true` (platform `oauth2-proxy/values.yaml.gotmpl:67`)。Dex の静的パスワードの identity は常に
`EmailVerified: true` (A3) なので、この設定を偽にしても静的アカウントは影響を受けない。

**C4. 後段の identity は ingress の上書きで守られている。** `auth-response-headers` が `X-Auth-Request-*` を auth の応答で上書きする
(`ingress-journey.yaml:32-38`) ことが前提だが、偽造ヘッダの負のテストは platform の `scripts/verify-auth.sh` に無い (grep 0 件)。値から来る annotation の map は
固定の auth-url の後に描画されるので、値で `auth-*` を二重に定義できる (`ingress-journey.yaml:39-41`、`ingress.yaml:47-49`、docs の `ingress-admin.yaml:36-38`)。
collector は workspace からの要求の `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` だけを消し (`internal/collector/collector.go:118-123`)、
`X-Auth-Request-*` は通す。転送先の昇格にはならないが、display-name では偽の admin の email に対する 200 / 403 の差が `ADMIN_EMAILS` の所属を明かして
いた (D12 の hotfix で閉じた)。

**C5. プロフィールは表示名だけ。** 参加者の書き込みは workspace の `setname` から collector 経由の claimed-identity で、portal に設定画面は無い
(`openapi-scoreboard.yaml:1085-1108`。portal の改名ボタンは admin 用 `:1513-1529`)。store は last-write-wins で spec と一致し (`internal/store/store.go:433-435`)、
`docs/db-schema.md:125-128` と `charts/ctf-user/deploy-user.sh:85-89,508,531` の「first-set-only」は 9bbc225 以降の古い記述である。そのため
`deploy-user.sh --display-name` (ヘッダ無しで同じ route を叩く: `:508-531`) を再実行すると、参加者が付けた名前を上書きする (platform の
`deploy-event-workspaces.sh --names-file` が名簿を渡す)。順位表と Result は admin の `/api/state` だけで (`openapi-scoreboard.yaml:1440-1465`)、参加者は
自分の順位しか見ない (P28 柱 3)。CSP は `img-src 'self' data:` (`internal/scoreboard/view/csp.go:182`)、`/static/` の登録表は拡張子 `.css` / `.woff2` に
pin されている (ADR-0028 D5。P28-0c で実装中)。

**C6. Dex を経由する限り Google の画像は取れない。** Google connector の設定は `scopes` (既定 `profile email`、`openid` は常に付く)・`hostedDomains`・
`promptType` (既定 `consent`) で、identity に picture は無い (A1・A2)。

**C7. 削除の約束と git。** brief は Google の email の破棄 (イベント後 7 日、仮) と「実メールが追跡ファイルに 0 件」を求める。git の履歴は sops で暗号化しても
消せず、鍵の破棄で失効させることも前提にできない。app の追跡ファイルにある email は今すべて予約ドメイン (`ctf.local`・`.invalid`) で、例外は no-reply の
1 件 (`git grep` で実測)。

## Options

**A. identity の対応**
1. **正規形を既存ヘッダで渡す【推奨】** — auth-policy が表で seat に解決し、後段には `<seat>@<EXPECTED_EMAIL_DOMAIN>` だけを `X-Auth-Request-Email`
   として渡す。participant の Ingress も auth-policy を通す。コスト: auth-policy に表と route 1 本、chart の auth-url の固定、scoreboard の照合をドメイン込みの
   完全一致に (数行)、collector の strip。ヘッダ名・spec の identity 源・ADR-0031 の注入は変わらない。リスク: 「Email」という名前で正規形を運ぶ (spec に
   明記して嘘にしない)。auth-policy を通らない Ingress があると生の email が届く (V12 が塞ぐ)。可逆 (表を静的な seat だけにすれば今と同じ挙動)。
   閾値: 外部 IdP を 1 つでも足す時点。
2. **新しい principal ヘッダ** (`X-Ctf-User` / `X-Ctf-Role`) — 後段はそれだけを信じる。コスト: scoreboard の全 gate・board・rate-limit の鍵・spec・ADR-0031・
   全 Ingress の `auth-response-headers` を同時に変える。リスク: 1 つの Ingress で列挙を忘れると、クライアントが付けた `X-Ctf-Role: admin` がそのまま届く (案 1
   は全 Ingress が既に列挙している名前を使い、この失敗の型を作らない)。可逆性は低い。閾値: email の形に収まらない principal (複数 role・テナント) が要るとき。
3. **表を auth-policy と scoreboard の両方に置く** — participant の Ingress は oauth2-proxy 直結のまま、各サービスが解決する。コスト: 同じ表の 2 実装と
   2 つの mount (個人情報が採点プロセスに入る)。リスク: 既にある「2 つの半分」(`api.go:848-850`) の drift をもう 1 組作り、C2 の門も残る。不採用。

**B. アイコン**
1. **用意した絵柄 × 色から選ぶ【推奨】** — id だけを保存し、画像は `/static/`。コスト: 絵柄の制作と台帳、登録表に `.svg` を足す (D9)。リスク: ほぼ無い。
   可逆 (ただし D10 の migration があるので、image を戻すには DB の復元が要る: ADR-0020 の downgrade は起動拒否)。閾値: 即時。
2. **画像のアップロード** — 保存・decode・再エンコード (EXIF の位置情報の除去)・寸法上限・審査。リスク: 会場に投影された画像は取り消せない。採点の単一
   プロセス (I1) で信頼できない画像を decode すると、decompression bomb 1 枚で ingest ごと落ちる。顔写真が EBS snapshot の backup に残る。閾値: Signpost 4。
3. **Google の画像** — Dex が運ばない (C6) ので Dex を迂回する取得経路が要り、CSP に外部 origin を足し、閲覧者の通信が Google へ出る。静的アカウントでは
   使えず「既存アカウントでも」を満たさない。不採用。

## Decision

**A1 + B1。** 理由: 外部 IdP の identity を認証層の 1 箇所で運営の名前空間に写せば、後段の境界 (I8 の照合・HIDDEN_USERS・board・採点) を作り直さずに
「他人の席に入れない」「招待外は入れない」を今より強くでき、絵柄の id は投影・個人情報・採点プロセスのどれにも新しい面を作らない。

- **D1 経路 (S3)。** Dex に Google connector を足し、静的パスワードと併存させる。oauth2-proxy の issuer は Dex のまま (provider を増やさない)。connector は
  `scopes: [email]` (Google への要求は `openid email`)、`promptType: select_account` (会場の貸与端末)、`hostedDomains` は組織限定の回だけ。oauth2-proxy は
  `insecure_oidc_allow_unverified_email = false` (S2 で先に入れる)・`scope = "openid email"`・`oidc_email_claim` は既定のまま (他の claim では `email_verified`
  の検査が外れる: A4)・request log の format から `{{.Username}}` を外す (2 秒の poll で全員の email が出続けるため)。`email_domains` は platform がロスターの
  外部 identity のドメイン (gmail 系は 2 つとも) と `EXPECTED_EMAIL_DOMAIN` から描画する (表から導く粗い絞り込みで、許可の正典ではない。preflight check 6 の
  `*` 禁止は維持: platform `scripts/preflight-event.sh:132-140`)。**許可の正典は D2 の表で、oauth2-proxy に 2 つ目の許可表 (`authenticated_emails_file`) を
  置かない** — 同じ表の別形式の写しになり、D2 の正規化を実装できないので、正当な参加者を表の手前で落とす (A4)。組織のアカウントは組織の管理者が外部アプリを
  拒否すると Google 側で止まり運営には直せないので、静的アカウントを全席に残す (brief の C)。**admin は静的アカウントに限る** (Google の admin は許さない。D2)。
  Dex は起動時に Google の discovery を取りに行き、`ContinueOnConnectorFailure` が無効な版では失敗で起動を拒否する (A2・A6) ので、
  `DEX_CONTINUE_ON_CONNECTOR_FAILURE=true` を明示する (V15・V16)。Google への往復は `dex.<dnsSuffix>` の callback から appHost の `/oauth2/callback` へ戻る
  same-site の遷移で、`SameSite=None` の cookie と干渉しない (未実測、V16)。
- **D2 ロスター (identity 表)。** auth-policy が `ROSTER_FILE` から読む 1 ファイル。`seats:` の下に `{seat, external}` を並べる (`seat` は
  `^[a-z0-9][a-z0-9-]{0,62}$`、`external` は省略可で高々 1 つ)。
  - 正規化: ASCII に限る (非 ASCII は表でも要求でも拒否。`strings.ToLower` は U+212A を `k` に畳む)。小文字化と trim。`gmail.com` / `googlemail.com` に限り
    local-part のドットと `+` 以降を除き、ドメインを `gmail.com` にそろえる (同じアカウントの別表記)。関数は auth-policy に 1 つで、表と要求の両方に掛ける (D11)。
  - 解決: identity が `<s>@<EXPECTED_EMAIL_DOMAIN>` (s ∈ seats) なら s。正規化した identity がある seat の `external` ならその seat。他は未解決で、
    空の identity と、正規化で local-part が空になるもの (`+x@<gmail 系>`) も未解決。
  - 起動時に検査し、破れば起動を拒否する: ファイルが無い・seat が 0 件・未知のキー・seat の重複・`external` の重複・`external` の local-part が正規化で空・
    `external` が `EXPECTED_EMAIL_DOMAIN` にある・`external` か `<seat>@<domain>` が `ADMIN_EMAILS` にある・`EXPECTED_EMAIL_DOMAIN` と `ADMIN_EMAILS` の各ドメインの
    最後のラベルが予約名 (`local` `test` `invalid` `example` `localhost`) でない (末尾のドットも拒否)。重複と `ADMIN_EMAILS` との重なりは**正規化の後**で比べる。
    予約名の検査は「Google のアカウントは正規形の email も admin の email も検証済みで持てない」ことの保証で、C3 の `email_verified` と組で効く。
  - 追加と失効は Secret の差し替え + auth-policy の rolling restart (全体の再デプロイは要らない。hot reload はしない。HA 2 replicas + PDB で無停止)。
    要求ごとに表を引くので、行を消せば既存のセッションも次の要求から 403 になる。
  - Google の `sub` は束縛しない。招待時に運営が持つのは email だけで、初回ログインで束縛すると auth の hot path に書き込みと replica 間で共有する状態が
    入る。stateless であることが auth-policy の HA の前提である (Signpost 1・2)。
  - seat の集合は、platform が Dex の静的ユーザの生成元と同じ値から作る (prod は `dexParticipantCount` + `test1`)。2 つ目の写しを作らない。
- **D3 auth-policy の出力。** workspace 用の endpoint を `/check?host=<h>` から新設の `GET /check-workspace?host=<h>` に替え、`/check` は消す (新しい chart と
  古い binary、古い chart と新しい binary のどちらの組でも auth の subrequest が 404 になり、ingress が 500 で閉じる)。`ADMIN_EMAILS` なら 200 (現行どおり)、
  解決した seat == h なら 200、他は 403 (前方一致を使わない)。新設 `GET /check-participant` (audience internal、`x-ctf-authz: rostered` を新設) は admin か解決
  できた identity に 200、他は 403、未認証は 401。解決した identity の 200 では `X-Auth-Request-Email: <seat>@<domain>`・`X-Auth-Request-User: <seat>`・
  `X-Auth-Request-Preferred-Username: <seat>` だけを返し、IdP の email と `sub` を後段に出さない。admin は現行どおり透過する。生の email をログに出すのは未解決の
  拒否だけ (当日の表の修正に要る) で、403 の body には入れない (`server.go:253,283` を直す)。`/healthz` には件数 (`roster_seats`・`roster_external`) だけを足す。
- **D4 ingress。** app の chart の全 Ingress は auth-policy の endpoint を template に固定する (参加者 = `/check-participant`、workspace =
  `/check-workspace?host=<username>`、運営 = `/check-admin`)。value の `ingress.journeyAuthUrl` (scoreboard)・`ingress.adminAuthUrl` (docs)・`auth.authUrl` と
  `auth.enabled` (ctf-user。false で auth の無い Ingress になる: `charts/ctf-user/values.yaml:174`) を廃止し、値の annotation の map に `nginx.ingress.kubernetes.io/auth-*`
  があれば描画を `fail` にする (C4)。全 Ingress の `auth-response-headers` は `X-Auth-Request-{User,Email,Preferred-Username}` の 3 本 (docs-admin に 1 本足す)。
  platform の描画時の guard (`policy/key-guards.rego:192-207`、今は admin の Ingress だけ) を journey と docs-admin に広げる。
- **D5 scoreboard。** self の照合を `email == <user>@<EXPECTED_EMAIL_DOMAIN>` の完全一致にする (`emailMatchesUser` と `DeriveUsername`。env を新設し、空なら
  self は常に不成立 = fail-closed)。`ADMIN_EMAILS` と `EXPECTED_EMAIL_DOMAIN` に D2 と同じ予約名の起動検査を掛ける。HIDDEN_USERS (seat 指定) は変えない。
  spec の identity の記述を「正規形」に直す。
- **D6 collector。** workspace からの要求のうち、名前が `X-Auth-Request-` で始まるヘッダをすべて無条件に消す (ADR-0023 D1b と同格の義務)。
- **D7 I8 の置き換え (文言)。** 番号は I8 のまま、S2 の実装 PR で表の文言を次に替える:
  > **I8**: 認証済み identity (oauth2-proxy が検証した `email_verified` の email を D2 で正規化したもの) から seat (workspace 名) への対応は、auth-policy が
  > 読む**ロスター 1 表**だけが決める。auth-policy は表で解決できた identity に限り、後段へ正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` だけを渡し、
  > `/check-workspace?host=<h>` は seat == h の完全一致でのみ 200。表に無い identity は参加者と workspace の全 route で 403 (表の欠落・空は起動拒否)。scoreboard
  > の self 判定は `<user>@<EXPECTED_EMAIL_DOMAIN>` との完全一致。`EXPECTED_EMAIL_DOMAIN` の最後のラベルは予約名で、外部 IdP はこのドメインの email を検証済みで
  > 出せない。**唯一の例外**は `ADMIN_EMAILS` (任意の workspace と運営 route。要素は予約ドメインの静的アカウントだけ)。IdP の email の local-part を seat と読む
  > 経路を持たない。**前提 (ヘッダの完全性)**: app の chart の全 Ingress の auth-url が auth-policy を指して `X-Auth-Request-{User,Email,Preferred-Username}` を
  > 上書きし、collector が workspace からの `X-Auth-Request-*` を消し、scoreboard は ingress-nginx・collector・falco からしか受けない
  > (`charts/scoreboard/templates/networkpolicy.yaml:18-47`)。
- **D8 プロフィールの API (S1)。**
  - `POST /api/users/{user}/profile` — participant / `x-ctf-authz: self-or-admin` (ヘッダ必須。claimed-identity に落ちる `selfOrAdminWrite` を使わない) /
    origin-guard **あり** / collector forward **なし** / rate-limit は identity キーで fail-closed (app#315 の `ratelimit.MiddlewareStrict` + `IdentityKeyed`。
    ヘッダ無しは 403 でトークンを消費しない。board の IP への fallback: `api.go:439-450` は使わない)。body は `{display_name?, avatar?}` (1 つ以上、未知の
    キーは 400)。全項目を検証してから書き、2 表への書き込みは 1 transaction (片方だけ変わる状態を作らない)。応答は `{ok, user, display_name, avatar}`。
    表示名の規則は既存 (`validDisplayName`、1〜32 文字)。
  - `POST /api/admin/users/{user}/profile-reset` — operator / admin / origin-guard あり。表示名と絵柄を既定 (seat と既定の絵柄) に戻す。
  - 読みの route は足さない。表示名を返す応答 (`Me`・`Journey`・`LeaderboardEntry`・`ChallengeSolver`・`SolveRecord`・`BoardMessage`) に、対になる `avatar`
    を additive で足す (`BoardMessage` は `authorAvatar`。常に存在する文字列で、未設定は既定の id、運営の投稿は参加者が選べない固定の id)。P28 の
    冒険の書 (本人だけ) には足さず、印・称号との重ね掛けは P28-2 以降に委ねる (brief §4)。
  - email・氏名・画像の項目は、どの応答にも DB にも作らない。`/api/state` は admin のままで、参加者面に他人のデータを足さない (P28 裁定 6)。route は
    既存の `/api/users/` Prefix と admin の `/` に入るので、I15 の追加作業は無い。
- **D9 絵柄。** id は `<glyph>-<color>`。集合は Go の表 1 つで、検証・描画・既定値の正典にする。組合せは 48 以上 (40 席 + 予約 8。brief の 8 × 6 を仮置き、
  design が決める)。既定は seat から決める: `user<N>` (先頭 0 なしの 10 進で N ≤ 組合せ数 − 8) は N 番目、他の seat (`test1`・`user01`・範囲外の N) は
  末尾 8 個の予約域のうち、**運営の固定 id (48 番目) を除く 7 個**に hash で割り当てる (prod の席 = N 席 + `test1` で重複しない。運営の固定 id は D8 のとおり参加者が持てない: 既定にも選択肢にもせず、profile route は 400。S1 の review-5x R4#3 で実装に揃えた)。DB に表に無い id が残っていれば応答も描画も既定の id にする。画像は
  `/static/` の SVG とし、**ADR-0028 D5 の拡張子の集合に `.svg` を足す (限定 supersede)**。条件: (a) 登録表を作るときに (名前空間, 要素 / 属性) の組を
  allowlist で検査し (列挙に無いものは拒否。XHTML 名前空間の `script` も落ちる)、とくに `script`・`foreignObject`・`on*` 属性・`animate` / `set`・`xml:base`・
  `<?xml-stylesheet`・`<!DOCTYPE` / `<!ENTITY`・`#` 以外への参照・`url(#…)` 以外の url を起動時エラーにする (b) `.svg` の応答に `X-Content-Type-Options: nosniff`
  と `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox` を付け、直接開かれても script が動かないようにする (c) HTML からは `<img>`
  でだけ参照し (inline SVG・innerHTML にしない)、色は `<img>` の背景に tokens.css の変数で掛ける (SVG の中では変数が効かない)。資産は出自とライセンスの台帳に
  載せる (P28 裁定 3)。HTML shell の CSP は変えない。
- **D10 保存。** ADR-0020 の migration で `avatars (user PRIMARY KEY, avatar, set_at)` を足す (`display_names` は変えない)。admin reset (`/api/admin/reset`)
  は表示名と同じく絵柄を残す。migration の番号は merge 順で決まる (ADR-0032 の migration と先後する)。表示名の初期値は seat (条件 10) で、deploy の経路は
  表示名を書かない (C5 の上書きを消す。書き先の route も D12 で消える): app は `deploy-user.sh --display-name` を廃止し (渡されたら exit 非 0)、platform は
  `deploy-event-workspaces.sh --names-file` を廃止する (platform を先に merge)。`docs/db-schema.md` の「first-set-only」は S1 で直す (正典は spec と store)。
- **D11 データの境界。** Google の email は運営の手元のファイル (両リポの git の外、mode 0600) にだけ置き、platform はパスで受け取って auth-policy の Secret
  に描画する。scoreboard には届かない (D3)。Secret (helm の release 履歴を含む) は teardown で消え、手元のファイルはイベント後 7 日 (仮、CEO D4) 以内に消す。
  削除要求は表の行の削除 + `profile-reset`。app の test は予約ドメインの合成 email だけを使い、gmail の正規化は同じ関数に合成ドメインを渡して試す。本番の
  対象ドメインの集合 (`gmail.com`・`googlemail.com`) はドメイン名の定数としてテストで pin する (email の形でないので V17 に掛からない)。
- **D12 collector 経由の表示名 (brief 論点 7。security R1 の判断で確定)。** 絵柄はこの経路に載せない (D8)。参加者の `POST /api/users/{user}/display-name` は
  ブラウザから origin-guard なしで届き (`/api/users/` Prefix、cookie は `SameSite=None`)、外部サイトの POST で本人の、admin のセッションなら全員の表示名を
  書き換えられた。この CSRF と C4 の oracle は hotfix (`fix/display-name-browser-path-403`、849128e、本 ADR と別 PR) で閉じた: `X-Auth-Request-*` が 1 つでも
  あれば 403、JSON 以外は 415、Authz は新しい語彙 `internal-claimed-identity`。**S1 で `setname` (challenge image と文書) と route を撤去する**: collector の
  forward は 3 → 2 本、route は spec と mux から消え、ヘッダ無しの claimed-identity の書き込みを残さない (語彙は使う route が 0 本になれば消す)。forward の
  集合の変更は本 ADR が根拠になる (ADR-0005 Consequences)。

## 段階

| 段 | 中身 | merge class・レビュー | E2E (ADR-0031) | 前提・順序 |
|---|---|---|---|---|
| **S1 プロフィール** | D8〜D10・D12 と記述の修正 (ログインは無変更)。app = profile・絵柄・migration、`setname` と display-name route の撤去 (forward 3 → 2)、文書。platform = `--names-file` の廃止 (D10) | **Class-2** (challenge image・collector forward・両リポ)。security 必須 (migration・登録表の pin・origin-guard 付き route・forward の変更・`fixtures/` の変更: ADR-0026 V8) | 設定 → 再読込で保持 (Me と board の自分の投稿)、絵柄の 404 でも崩れない。順位表は admin の面で、E2E の子は `ADMIN_EMAILS` を持たない (ADR-0031 D1 (b)・V8) ので V4 で見る | P28-0c (ADR-0028 の実装) と app#315 の merge 後。platform の 1 本が先 |
| **S2 identity 表** | D2〜D7。Google は入れない。app = auth-policy (`/check-workspace`・`/check-participant`)・scoreboard・collector・chart・spec・compose の dev 用の表と env (`Makefile:86` の dev の admin を seat 以外に)・V17 の app 側。platform = 静的 seat の表の描画、D1 の oauth2-proxy の設定のうち Google 以外 (`email_domains` の描画を含む)、`journeyAuthUrl` の削除、rego の guard の拡張、`verify-auth.sh` の負のケース、`local` に表に無い Dex 静的ユーザ 1 人 (V14)、preflight の `roster_seats`、V17 の platform 側 | **Class-2**。security 必須。両リポ同時 PR + 相互リンク | harness の注入を正規形に | app を先に merge (pin を動かすまで届かない)。platform は pin と同時で、V14 の local の red → green が merge 条件。auth-policy を scoreboard より先に入れる (helmfile の `needs`) |
| **S3 Google** | D1・D11。platform = connector・client secret (SOPS)・外部 identity の描画・描画時の guard (V15)・runbook。app = handbook の入口を `/portal` に (content) | **Class-2** + CEO (D7: Google Cloud の project・同意画面・privacy policy)。security 必須 | 実 IdP は自動化しない (rehearsal の手動) | **S2 が有効なことを機械で確かめるまで入れない**: S2 の chart の auth-url は S2 より前の binary で 404 (→ 500 で閉じる)、preflight が稼働中の `/healthz` の `roster_seats` > 0 を FAIL 条件で見る (V15)。S2 より前の chart は journey の auth-url を見る rego で描画が止まる (V14) |

S1 は S2・S3 に依存しない。S2 は Google 無しでも C1・C2 の潜在的な穴 (ドメインを見ない前方一致・any-login の門) を閉じるので単独で価値がある。brief の 1 段を
S2 と S3 に分けたのは、外部 IdP より先に identity の変更を静的アカウントだけで実証し、同時に動く未知を減らすため。

## Consequences

- **諦めたもの**: oauth2-proxy での許可表 (D1)、admin の Google ログイン (D1)、`sub` の束縛と表の hot reload (D2)、設定画面の「ログイン: Google」表示
  (scoreboard は正規形しか知らない。要るなら非 PII の列挙ヘッダを S3 で別に設計する)、アップロードと Google の画像 (B2・B3)、ひとこと・所属 (brief D6)、
  運営が表示名を事前に配る `--names-file` と端末の `setname` (D10・D12。要るなら「未設定のときだけ書く」admin の一括 route を別に設計する)。
- **新たに守る不変条件**: I8 を D7 に置き換える。新しい番号は作らない。
- **契約表 (S2 の実装 PR で追記)**: 行「Identity 表と正規形」— platform は (1) seat の集合と外部 identity から auth-policy の表の Secret を描画する (外部
  identity は git の外から)、(2) `EXPECTED_EMAIL_DOMAIN` に予約名を渡し、auth-policy と scoreboard に同じ値を供給する、(3) oauth2-proxy を D1 の設定
  (未検証の email の拒否・既定の email claim・`email_domains` は表から描画) にする、(4) `ADMIN_EMAILS` には予約ドメインの静的アカウントだけを渡す。app は
  D2 の形と検査、D3 の正規形と endpoint、D4 の auth-url の固定、D6 の strip を保証する。どれかを変えるときは両リポ同時 PR。「Cookie domain」の行は変えない
  (Dex の callback は `dex.<dnsSuffix>` で、cookie の scope に触れない)。
- **runbook**: platform `docs/operations.md` §5.3「username は email の local-part と一致させる」と §7.1 の 403 の説明は S2 で事実でなくなる。表の更新
  (3 分以内、brief 条件 15)、7 日での破棄、貸与端末 (Google のセッションがブラウザに残るのでゲストのプロファイルを使う)、未登録者への案内を書く。行を
  消しても開いている ttyd の websocket は切れない (`charts/ctf-user/templates/ingress.yaml:11` の 3600 秒) ので、失効には workspace の pod を作り直す。portal に
  ログアウト (`/oauth2/sign_out`) の導線を置く。表は sops にも置かない (D11)。
- **ADR-0031**: harness の proxy は正規形 `<seat>@<EXPECTED_EMAIL_DOMAIN>` を注入し、scoreboard に同じドメインを渡す (同 ADR の `.test` の合成ドメイン)。
- **残余**: (1) 表に載った参加者どうしの submit の申告 (`openapi-scoreboard.yaml:598-614`) は変わらない。(2) oauth2-proxy は `email_domains` に入る招待外の
  Google アカウント (gmail 系など) にもセッションを出し、Dex は Info のログに login の email を出す。どちらのログも cluster 内で teardown と共に消える (外部へ
  送る経路を足さない。Sysdig Shield がコンテナのログを送らないことは未確認)。(3) Terminal の iframe 内で再認証が起きると、Google のログイン画面は枠内に
  出ない (未実測)。セッションの寿命 ≥ 開催時間を S3 で実測する。(4) 表示名で「運営」などを名乗る偽装は admin の reset で戻す (自動の拒否はしない、brief §5)。

## Signposts (この決定を覆す観測可能な信号)

1. 正当な参加者が email の表記の違い (ドット・`+`・別名・大小文字) で拒否された件数が 1 開催で 2 件以上 → 正規化の規則を見直すか、初回ログインでの
   `sub` の束縛 (状態を持つ設計) を起案する。
2. 開催が複数日になる、または回をまたぐ identity が要る (brief D2) → email を鍵にした表では付け替えと失効を扱えない。`sub` の束縛と永続ストアを ADR にする。
3. `/check-participant` の p99 が 100 ms を超える、または開催中に auth-policy の 5xx が出る (portal の 2 秒 poll がすべて auth-policy を通る) → ingress の
   auth の cache (`auth-cache-key`) か、正規形の署名による検証を検討する。
4. 自前の画像の要望が事後アンケートで product の閾値を超える、または席数が絵柄の組合せ数を超える → B2 を「採点プロセスの外で decode する別サービス」
   (I5 の image 追加 = CEO 判断) として再提案する。

## Verification

**S1** (app の `make test`、required check):
- **V1 route** — 2 route が I14 の parity に載り、`TestOriginGuard_AllProtectedRoutesEnforced` が 2 本の origin-guard を強制として見る。`/profile` は spec で
  `x-ctf-authz: self-or-admin` を pin し、許可済みの Origin を付けたヘッダ無しの要求は 403。`Routes()` から `self-or-admin` の全 route を導出してヘッダ無しの 403 を
  確かめる (今の導出は不一致のヘッダ付きでしか撃たない: `internal/scoreboard/authz_test.go:179-215,288`。無いと `selfOrAdminWrite` で実装しても緑)。参加者 B が
  A の profile を書くと 403 (条件 11)。collector forward は 2 本で、display-name の route は spec と mux に無い (D12)。
- **V2 絵柄の id** — 表に無い id は 400。`{display_name: 正しい値, avatar: 表に無い値}` も 400 で、表示名は変わらない (2 表の部分書き込み)。`image/*`・
  `multipart/*`・`application/octet-stream` の request body を持つ operation が spec に 0 件 (条件 9)。
- **V3 既定** — `user1`〜`user40` と `test1` の既定の絵柄がすべて異なる (条件 10)。`user01`・`user0`・予約域の境界の N・組合せ数 + 1 が予約域に入る。DB に
  表に無い id が残っていれば応答は既定の id。表示名の既定は seat。
- **V4 保持と差し戻し** — 静的アカウントの identity で設定し、store を開き直しても残る (条件 5)。設定の後の `/api/state` は新しい値を、`profile-reset` の後は
  既定を返す (条件 12。順位表への反映はここで見る)。
- **V5 採点不変** — 表示名と絵柄を変えても、同じ `solved` + `hint_views` で leaderboard の rank 列が変更前と一致する golden (条件 6)。HIDDEN_USERS の seat に
  設定があっても順位表から除かれる (条件 13)。
- **V6 SVG** — 登録表の検査が D9 (a) の各要素・属性 (`<animate>`・`<set>`・XHTML 名前空間の `script`・`<?xml-stylesheet`・`xml:base`・`url(#…)` 以外の url を含む)
  と、列挙していない要素で赤になる (1 ケース 1 欠陥。blocklist の実装を落とす)。`.svg` の応答が `image/svg+xml`・`nosniff`・D9 (b) の CSP (`sandbox` を含む) を
  持つ。Go の表の全 glyph に SVG があり全色に tokens.css の変数がある (逆向きも)。登録表の pin の更新 (ADR-0028 V6) を同じ PR で行う。
- **V7 保存** — `avatars` に email・氏名・画像の列が無い (列の集合を pin)。ADR-0020 の既存テストが green (条件 8 の DB の部分)。
- **V8 email 非露出** — admin の email を記録しうる書き込み (board の admin 返信・admin の改名・`profile-reset`) を admin の identity で通して seed し、
  `Routes()` の全 GET の応答に `ADMIN_EMAILS` の値が 0 件 (面を手で列挙しない。条件 7)。
- テストでなく PR の diff で確かめるもの: `points.go` の diff 0 (条件 6)、`csp_test.go` の HTML shell の期待値が無変更 (条件 9)。

**S2** (app は `make test`、platform は実機):
- **V9 解決** — auth-policy の表駆動テスト: 表に無い `user7@<外部ドメイン>` は `/check-workspace?host=user7` と `/check-participant` で 403、`external` が
  user7 の identity は user7 だけに 200 で user8 は 403、admin は 200、`/check` は 404。`external` を持たない seat がある表で upstream が email の空・欠落した 202
  を返す場合と、正規化で local-part が空になる場合も両 endpoint で 403。upstream の User / Preferred-Username に seat と違う値を返させて上書きを確かめる (今の fake
  は local-part と同じ値を返し、透過と区別できない: `internal/authpolicy/server_test.go:22`)。応答ヘッダと全 endpoint の 403 の body に email が出ない。照合を
  前方一致に戻す mutation で赤 (条件 1・2・7)。route は 5 本で I14 の parity に載り、`rostered` に `internal/authpolicy/authz_test.go` の分岐と件数 guard を足す。
- **V10 表の検査** — D2 の起動拒否の各条件が 1 ケース 1 欠陥で起動エラーになる。重複は正規化の後で比べる (gmail 系の `a.b@` と `ab+x@`、大小文字の違い。
  条件 3)。予約名は最後のラベルで判定する (`evil-local`・末尾のドット・予約名でないドメイン・予約名でない `ADMIN_EMAILS`)。非 ASCII (U+212A を含む) は拒否。
  本番の正規化の対象ドメインの集合を pin する (D11)。scoreboard の起動検査も同じケースで赤 (D5)。
- **V11 scoreboard** — `user7@<別ドメイン>` は user7 に self 一致しない。`EXPECTED_EMAIL_DOMAIN` が空ならヘッダ `alice@` でも self は不成立。ドメインの比較を
  外す mutation で赤 (条件 2)。
- **V12 ingress** — app の全 chart を全 Ingress が描画される値で `helm template` し、Ingress ごとに役割 → endpoint を pin する: journey = `/check-participant`、
  scoreboard の admin と docs-admin = `/check-admin`、ctf-user = `/check-workspace?host=<username>` で `host=` は username と Ingress の host に一致 (username を
  2 通りで描画)。chart ごとの件数を pin し (scoreboard 2・docs 1・ctf-user 1。journey は `ingress.journeyHost` が空だと描画されない:
  `charts/scoreboard/templates/ingress-journey.yaml:1`)、auth-url の無い Ingress は 0 件、全 Ingress の `auth-response-headers` が 3 本を含む。値の annotation
  の map に `auth-url` を入れた描画は失敗する。scoreboard の NetworkPolicy の送り元は ingress-nginx・collector・falco だけ (I8 の前提)。抽出が 0 件なら fail、
  helm が無ければ skip でなく fail (今は skip: `internal/apispec/ingressparity/helm_test.go:14-15`)。endpoint を入れ替えた合成入力 (journey → oauth2-proxy・
  `/check-workspace`、ctf-user → `/check-participant`) で赤 (条件 1)。
- **V13 collector** — CollectorForward の全 route (`Routes()` から導出) で、`X-Auth-Request-{Email,User,Preferred-Username,Groups}` と任意の
  `X-Auth-Request-*` を付けた workspace の要求が、転送先で 1 つも残らない。
- **V14 実機 (platform)** — `verify-auth.sh` に足す: 静的アカウントの既存ケースが無変更で green (条件 4)、参加者のセッションに偽の `X-Auth-Request-Email`
  (admin) を付けて他人の `me` を読むと 403、セッション無しで偽ヘッダを付けると 401、admin の catch-all と ttyd でも偽ヘッダが上書きされる、表から外した
  静的ユーザ (検証用に 1 人外す) は `/portal` と自分の workspace で 403 (条件 1)。描画結果が D1 の oauth2-proxy の設定 (Google 以外: 未検証の拒否・`scope`・
  既定の email claim・log の format・表から描いた `email_domains`) を持ち、`policy/key-guards.rego` が journey と docs-admin の auth-url も見る。**S2 の
  platform PR の merge 条件**: `local` (`oauth2ProxyEmailDomains: "*"`、platform `helmfile/environments/local.yaml.gotmpl:40`) に表に無い Dex 静的ユーザ
  `user7@<別の予約ドメイン>` を 1 人置き (values-local だけ)、main では user7 の workspace と `/api/users/user7/me` に入れ (赤)、S2 では 403 (緑) になる出力を
  PR に貼る (Google 無しで条件 2 の red → green)。
- **V17 境界 (S3 から前倒し)** — app の `make check-flags` (CI `flag-guard`) が、追跡ファイル中の予約ドメイン以外の email を fail にする (no-reply の 1 件は表に
  固定。今の走査は `|| true` の形なので、故意に違反させた fixture で赤になることをテストに持つ)。platform は予約ドメイン外の email の新規の追加を拒否する
  (既存の 6 種は address の hash の許可リストに載せて減らす方向にだけ変え、実アドレスを複製しない)。platform の preflight が、外部 identity のファイルが git の
  作業ツリーの外にあり mode 0600 であることを確かめる。scoreboard の Deployment に表の volume が無い (chart のテスト。条件 14)。

**S3** (platform と rehearsal):
- **V15 描画時の guard と前提の検査** — Google connector を有効にした値で `helmfile template` すると、`insecure_oidc_allow_unverified_email=false`・auth-policy の
  `ROSTER_FILE` と表の Secret・connector の `scopes: [email]`・`oidc_email_claim` が既定・request log の format に `{{.Username}}` が無い・Dex の
  `DEX_CONTINUE_ON_CONNECTOR_FAILURE=true` のどれかが欠けたら描画が失敗する (条件 3・4・8)。preflight は稼働中の auth-policy の `/healthz` の
  `roster_seats` > 0 を FAIL 条件で見る (S2 より前の binary はこの値を持たない)。
- **V16 rehearsal (手動)** — 表にある Google アカウントは自分の seat に入り、表に無いアカウントは 403。fail-soft は「Google への egress を遮断し、Dex の pod を
  再起動しても、静的アカウントでログインして全課題を solve できる」で確かめる (条件 4)。未登録の 1 名を表に足して 3 分以内に入場させ、その間 (auth-policy
  の rolling 中) の 5xx が 0 件 (条件 15)。`select_account`、iframe の再認証、受付の所要時間をパスワード方式と同じ回で測る (条件 15・16)。

**機械では確かめられないもの**: V16、7 日での破棄 (runbook)、Google の同意画面の設定。**I8 の表の書き換えは V9〜V13 と同一 PR**。V14 は local の
red → green が S2 の platform PR の merge 前、prod は次回 stand-up の参加者入場前。

**architect の判定 (同意権)**: 契約の追加 (Identity 表・`journeyAuthUrl` の廃止・endpoint の改名・collector の strip) と I8 の置き換えは **yes, if** — (i) V9〜V13
と I8 の書き換えが同一 PR (ii) S3 は V15 の guard と S2 の機械的な前提 (404 → 500・`roster_seats`) が入った後 (iii) S2・S3 が security-engineer のレビューを
通る。hotfix の Authz 語彙 `internal-claimed-identity` の追加は **yes, if** — (a) 定義は「名前が `X-Auth-Request-` で始まるヘッダが 1 つでも在れば、他の検査
より先に 403」(D6 と同じ接頭辞。応答が identity に依らない) (b) ヘッダ付きの 403 とヘッダ無しの非 403 を `Routes()` から導出して確かめる (c) S1 で使う route が
0 本になったら語彙も消す (`/internal/exfil/{cid}` に当てるかは、security R1 の範囲外の観測を扱う issue で決める)。

## Advice

- product-engineer (brief、2026-10-12): 論点 1〜7 を D に、受け入れ条件 1〜16 を V に対応づけた。brief と違う判断: (a) 段階を S2 と S3 に分けた (b) 設定画面の
  ログイン手段の表示を範囲外にした (c) ADR-0028 D5 の拡張子を足す (d) ロスターを「platform の events/ 配下 (sops)」ではなく git の外に置いた (C7)。
- qa-engineer R2 (2026-10-12。REQUEST CHANGES、HIGH 5 / MED 12 / LOW 6、VP が全件採用): HIGH-1 → D8・V1、HIGH-2 → V12、HIGH-3 → D2・V9、HIGH-4 → D2・V10、
  HIGH-5 → V14・段階 S2 (VP 決定: local の red → green を S2 の platform PR の merge 条件に)。MED (a)(b) → D8・V2、(c) → D9・V3、(d) → V6、(e) → V8、(f) → D6・
  V13、(g) → V11、(h) → D2・D11・V10、(i) → 段階 S1・V4、(j) → C5・D10、(k) → V17、(l) → D1・V15・V16。LOW → V12・V14・V16・V17・B1・S1 の diff の項。qa と
  違う判断: (j) は「未設定のときだけ書く」でなく「deploy は書かない」にした (条件 10 と一致し、ヘッダ無しで書く呼び手が減る)。
- security-engineer R1 (2026-10-12。REQUEST CHANGES、HIGH 1 / MED 4 / LOW 2、VP が全件採用): HIGH → D3・段階 S3・V15 (S3 の前提を機械で確かめる)。MED → D7
  (前提と予約名)・D1 / D2 (admin は静的アカウントだけ: VP 決定)、C4・D4・V12・V14 (annotation の二重定義・`auth.enabled`・rego)、D1 (check 6 はロスター由来の
  `email_domains`: VP 決定)、D12 (S1 で撤去: VP 決定。CSRF と oracle は hotfix)、D1・D11・残余 (ログと release 履歴)・V17 の前倒し。LOW → D9・V6 (SVG)、C7・
  runbook (鍵の関係と `.sops.yaml` の中身を公開側に書かない: VP 決定)、D3 (`server.go:283`)、D2・V10 (ASCII)、runbook (websocket)。範囲外の観測 (admin の
  catch-all から `/internal/exfil/{cid}` に届く) は別 issue。
- 外部の一次資料 (2026-10-12 参照): **A1** Dex docs「Google connector」。**A2** `dexidp/dex` master の `connector/google/google.go` — scopes の既定、
  `email_verified` を検査しない、`hd` の検査、identity に picture が無い、Open で discovery を取得する。**A3** dexidp/dex PR #1274 — passwordDB の identity
  は `EmailVerified: true`。**A4** `oauth2-proxy/oauth2-proxy` master の `validator.go` (domain と file の OR、小文字化、file の監視)。security R1 の確認: 同
  `providers/provider_data.go` (`email_verified` を見るのは既定の email claim のときだけ)・`pkg/middleware/request_logger.go` (log に session の email)。
  **A5** Google Cloud help 13461325 — External の本番には privacy policy・ホームページ・承認済みドメインが要る (「非機微 scope なら審査不要」「Testing は 100 名・
  token 7 日」は二次資料のみ)。**A6** `dexidp/dex` master の `server/server.go` — 起動時に全 connector を open し、`ContinueOnConnectorFailure` が無効なら
  1 つの失敗で起動を拒否する。v2.45.0 の release note — 同 flag を既定で有効にした。platform の Dex chart (`~0.24.0`) の版での A2・A3・A6 は未確認 (V14〜V16)。
