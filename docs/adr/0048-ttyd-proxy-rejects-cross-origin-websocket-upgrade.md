# ADR-0048: ttyd-proxy は WebSocket Upgrade の Origin が自 seat の https://<Host> でなければ 403 にする (fail-closed。ADR-0044 / ADR-0046 の対の入力)
- Status: Proposed (Accepted の条件: 実装 PR が main に入り V1〜V2 が緑。**V3 (実機) は Accepted 後の stand-up の go / no-go**。V4 は計画)
- Date / Deciders: 2026-10-27 / VP + application-engineer (起草) + architect (review-5x 91 R4、2026-10-27: yes, if = Status の型、契約表 419 / 403 行の追記、ingress controller 置換の Signpost) + security-engineer (review-5x 91 R1、APPROVE with comments)
- 関連: app#544、platform#297 (private。詳細と、oauth2-proxy の SameSite の再評価はそこ)、ADR-0044 (frame-ancestors の文法)、ADR-0046 (portal origin の出所と Status の型)、ADR-0013 (単一 origin)、ADR-0047、conventions の「ttyd-proxy 配線」行 (403) と「Cookie `SameSite=None`」行 (419)
## Context
- C1. ttyd の端末は WebSocket で動く (ttyd は `--writable`。arbitrary command の shell)。ttyd-proxy は Ingress が到達する唯一のコンテナで、全 request を ttyd (loopback) に reverse proxy し、`httputil.ReverseProxy` が Upgrade をそのまま tunnel する (ttydproxy.go の package doc)。
- C2. ADR-0044 は frame-ancestors (どの親ページが iframe に入れてよいか) を 1 origin に閉じた。これは HTML の描画の入力で、WebSocket の Upgrade は frame-ancestors の対象ではない。Upgrade の `Origin` は、ttyd・ttyd-proxy・Ingress・auth-policy のどこでも検査していない (platform#297)。
- C3. oauth2-proxy の cookie は SameSite=None + Secure + Domain=.<dnsSuffix> (conventions の「Cookie `SameSite=None`」行)。portal は seat の ttyd を iframe で埋め込む (frame-ancestors = https://<appHost>)。この cookie の設定のもとで、Origin の検査が Upgrade の唯一の「どのページが開いたか」の入力になる。SameSite の要否の再評価は platform#297 (platform の値と本リポの契約表を揃える)。
- C4. portal の iframe 内の ttyd のページ (seat host `https://<seat>.<dnsSuffix>`) が開く WebSocket の Origin は、seat host 自身になる。Host は要求の Host ヘッダ (`<seat>.<dnsSuffix>`) で、`httputil.ReverseProxy` の server 側では `r.Host` に残る。ingress-nginx は既定で元の Host を upstream に渡すが、**platform の ingress-nginx は `use-forwarded-headers=true` なので、`X-Forwarded-Host` が Host になりうる** (review-5x 91 R2#2。実測は V3)。Host が client の Host と違うと、正しい Upgrade が 403 になる (fail-closed)。
- C5. ttyd を別 origin のページから WebSocket で直接使う運用は無い (参加者の入口は portal の Terminal タブと、seat host の直接の top-level 表示だけ。どちらも Origin = seat host)。
## Options
1. ttyd の `--check-origin` を使う。コスト: ttyd の起動引数 1 つ。リスク: 受理集合 (scheme・port・Origin 無しの扱い) が ttyd の C の実装に従い、本リポの Go の test で固定できない (実測も未実施)。検査が CSP と別の場所に分かれる。可逆 (引数を外す)。効き始め: ttyd の image と chart (起動引数) の更新後で、image と chart の同時 pin が要る (ADR-0028)。
2. ttyd-proxy (Go) で検査する。コスト: handler に 1 つの検査。リスク: Host が Ingress 越しに保たれないと正しい Upgrade も拒否する (V3 で実機確認。fail-closed なので黙って通ることはない)。可逆 (旧 image に戻す)。効き始め: ttyd-proxy の image の更新後 (chart の値・env は変わらない)。
3. auth-policy の `/check-workspace` で検査する。コスト: auth-policy の API と platform の rego が同時に変わる。リスク: Origin は auth subrequest に届くが Upgrade かどうかは届かない (要実測。仮説)。Upgrade だけに絞るには ingress の配線 (ADR-0034 D4 で固定した auth-url) を変える必要がある。可逆 (配線を戻す)。効き始め: auth-policy と platform の両方の更新後 (ADR-0034 の 2 リポ同時 PR)。
## Decision
Option 2。CSP の frame-ancestors を付ける消費者 (ttyd-proxy) 自身が、Upgrade の Origin の最後の検査点になる。受理集合を Go の 1 か所で書いて test で固定でき、platform と chart に変更が要らないため。
- D1. 検査点は ttyd-proxy の `Handler.ServeHTTP`。CSP / XFO を付ける層と同じで、upstream (ttyd) に届く前に断る。
- D2. 受理集合は 1 つ: `Origin` ヘッダがちょうど 1 本で、値が `"https://" + r.Host` とバイト単位で一致する。正規化しない (大文字小文字・既定 port・末尾の `.` や `/` を揃えない)。ブラウザが自分で書く値だけを通し、浮動の受理を作らない。`r.Host` が空なら常に拒否する (素の `https://` と一致してしまうため)。
- D3. fail-closed: Origin 無し・複数・`null`・別 origin・http・port の食い違い・大文字小文字の違いは 403 (framing header を付ける。body は無い)。検査の対象は `httputil.ReverseProxy` が upgrade として tunnel するもの、つまり `Connection` に token `upgrade` があり (大文字小文字を問わず、複数行・カンマ区切りを含む)、`Upgrade` が空でないもの。値 `websocket` に限らない (限ると、proxy が tunnel するのに検査しない型が残る)。
- D4. upgrade でない request は変えない (通常の GET は Origin が無くても、別 origin でも従来どおり)。proxied 応答の CSP / XFO、upstream 不達の 502 の本体は変えない。framing header の付与は `stampFrameHeaders` の 1 か所で、proxied 応答・502・403 が同じ値を持つ ('none' なら 502 / 403 にも XFO DENY)。
- D5. 拒否の log は Origin の値を書かない: 本数・長さの合計・scheme (`http` / `https` / `other` / `none`) と、`%q` で escape した path だけ。
- D6. Host の出所は要求の `Host` のみ。env による上書き (期待 host の固定) は今は入れない (Signpost 1)。C4 のとおり platform の edge の経路で Host が変わりうるので、V3 は production と同じ経路で通す。
## Consequences
- 受理集合は seat 自身の origin だけ。portal の Terminal タブ (iframe 内の ttyd のページが開く WebSocket) は Origin = seat host なので壊れない想定。実機は V3 (未実施)。
- 別 origin のページから、または `curl` や非ブラウザの client が Origin 無しで ttyd に WebSocket を張ると 403 になる。運用者が `wscat` 等で直接 ttyd を叩く経路があるなら、`Origin: https://<seat host>` を付ける必要がある (認証は従来どおり Ingress の oauth2-proxy + auth-policy。本 ADR は認証を置き換えない)。
- 変更は ttyd-proxy の Go だけ (chart の値・env・platform の helmfile は変わらない)。I5 により全 image が同じ SHA で更新される。
- **V3 が落ちたら** Signpost 1 (Host 不保持) に進み、全 image を旧 tag に戻す (I5。旧 image に戻せば検査も戻る)。**順序条件**: platform の event pin (appImageTag / events) にこの SHA 以降を載せる前に V3 を通す。V3 が通るまで pin の更新は HOLD。
- Host の前提 (契約表 403 行): workspace Ingress の前段 (ingress controller・Cloudflare・LB) はクライアントの Host を変えずに ttyd-proxy へ渡す。platform の義務で、Host の扱いを変える変更 (upstream-vhost 相当、controller の置き換え、Gateway API) は両リポ同時 PR とし V3 をやり直す。
- 受理集合を広げる (2 つ目の origin、port、http) には ADR が要る (ADR-0044 D7 と同じ)。
- platform#297 の oauth2-proxy の SameSite 再評価は本 PR の外 (platform の値と契約表 419 行の根拠を同時に変える。両リポ同時 PR)。本 ADR はそれの結果に依存せず、SameSite がどちらでも検査は要る (Lax にしても本 ADR は変わらず、419 行の根拠の文だけが変わる)。419 行は (3) として本検査を前提条件に足した (app が既に満たす前提の追記)。platform CLAUDE.md の要約は platform#297 で揃える。
- runbook への影響: stand-up の smoke に「Terminal タブで shell が動く」を入れる (V3)。
## Signposts
1. V3 で Host が保たれないと分かる (Terminal が 403) → 期待 host を env (`TTYD_PROXY_EXPECTED_HOST`。ADR-0044 と同じ `dnsname` の文法で起動時に検査) で固定する案を ADR で足す。検査を緩めない。
2. ttyd を埋め込む 2 つ目の origin か、直接の WebSocket 利用 (別 origin のツール) が要る → ADR-0044 Signpost 1 と同時に、受理集合を広げる ADR を書く。
3. ttyd-proxy が HTTP/2 の WebSocket (RFC 8441 の extended CONNECT) を受ける構成になる → upgrade の判定 (D3) が別の形になるので、検査の入口を見直す。今は `serverutil.newServer` が Protocols を設定せず (unencrypted HTTP/2 は無効)、`internal/serverutil` の test が固定している。
4. ingress controller を置き換える (ingress-nginx の後継、P20 の substrate、Gateway API) → Host の扱いが変わりうるので V3 をやり直す (両リポ同時 PR)。
## Verification
- V1 (make test): `TestWebSocketUpgradeOrigin` が表で固定する。
  - 正 (101 で upstream に届く): Origin = `https://<Host>`、port 付き Host、Connection が list のときの own origin。正の行は D2 の完全一致の証明で、Connection の token 比較の証明ではない (Go の `ReverseProxy` は自分でも upgrade を判定するので、検査が効かなくても 101 になる)。
  - 負 (403 で upstream に届かない): Origin 無し・別 origin・http・port の食い違い 2 方向・大文字の Host / Origin・末尾の `/` と `.`・`null`・空・2 本・空の Host + 素の `https://`・`Upgrade: h2c`・`Connection` が 2 行。Connection の token 比較は 3 行が個別に固定する: ingress-nginx の形 (小文字 `upgrade` + Origin 無し)、Firefox の形 (`keep-alive, Upgrade` + 別 origin)、大文字 `UPGRADE` + 別 origin。
  - 非 upgrade: 通常 GET が Origin 無し / 別 origin でも 200、`Connection: Upgrade` だけ / `Upgrade` だけも 200。
  - 別の test が固定する: 403 の framing header と log に生の Origin が無いこと、path が escape されること (U+202E と改行)、'none' のとき 403 / 502 にも XFO DENY、`serverutil.newServer` が Protocols を設定しないこと。既存の `TestWebSocketUpgradeTunnelled` は Origin 付きで通る。
- V2 (mutation、PR 本文に実出力): (a) 検査を外す、(b) Origin 無しを通す、(c) `Upgrade` が `websocket` のときだけ検査する、(d) 大文字小文字を畳む、(e) Connection token の比較を大文字小文字区別にする / カンマ split と TrimSpace を外す、のそれぞれで V1 の負の行が赤になる。(e) は ingress-nginx の形と Firefox の形の行が赤にする。
- V3 (実機、未実施。Accepted 後の stand-up の go / no-go): **production と同じ edge の経路 (Cloudflare proxied → NLB → ingress-nginx) で**、新しい image の seat の portal の Terminal タブを開き shell が動く (colima だけでは `use-forwarded-headers` と Cloudflare の Host の扱いを確かめられない)。DevTools の Network で WebSocket が 101。Origin が seat host でない Upgrade が 403 になる (curl で `Origin` を変えて送る)。Terminal タブが 403 なら Signpost 1。
- V4 (計画。実装は別 issue): 既存の browser e2e で、TLS stub の handler を `ttydproxy.New` (upstream = 101 を返す stub) で包み、stub のページが自分の origin に開いた WebSocket が 101、別 origin のページから開いた WebSocket が 403 になることを固定する。これで V3 の手作業は Ingress 越しの Host 保持の確認だけに縮む。
## Advice
- security-engineer の指摘 (review-5x 89 R1#1、platform#296 の review、検証者 confirmed): 既存の欠陥。ttyd-proxy を推奨 (CSP と同じ消費者、test で固定できる)。
- review-5x 91 (T3、app#546、2026-10-27、VP 採用): R1 / R3 / R5 APPROVE with comments、R2 / R4 REQUEST CHANGES (BLOCKING 0。実装は正しく、HIGH 2 は test の被覆と ADR の文書の欠陥として MED)。反映: Connection token の負の 3 行と mutation (e) (R2#1 / R1#3)、Status と Accepted の条件を ADR-0046 の型に (R4#1 / R3#2 / R5#3)、契約表 419 / 403 行 (R4#2)、C4 / D6 の `use-forwarded-headers` (R2#2)、V4 (R4#4)、順序条件 (R5#1)、log の path escape・framing header の 1 method・Protocols の固定・Options の書き方 (R1#2 / R1#4 / R3#1 / R4#5 / R4#6)。
- architect (review-5x 91 R4、2026-10-27): yes, if = Status の型 (V3 は Accepted 後の go / no-go)、契約表 419 / 403 行の追記、ingress controller 置換の Signpost。
