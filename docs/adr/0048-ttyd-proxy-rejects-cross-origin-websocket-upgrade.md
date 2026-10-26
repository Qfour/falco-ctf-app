# ADR-0048: ttyd-proxy は WebSocket Upgrade の Origin が自 seat の https://<Host> でなければ 403 にする (fail-closed。ADR-0044 / ADR-0046 の対の入力)
- Status: Proposed (Accepted の条件: 実装 PR が main に入り、V1-V2 が緑で、V3 (実機の Terminal タブ) が通る)
- Date / Deciders: 2026-10-27 / VP + application-engineer (起草) + security-engineer (auth 境界 + CSP / iframe、review-5x R1)
- 関連: app#544、platform#297 (private。詳細と、oauth2-proxy の SameSite の再評価はそこ)、ADR-0044 (frame-ancestors の文法)、ADR-0046 (portal origin の出所)、ADR-0013 (単一 origin)、ADR-0047、conventions の「ttyd-proxy 配線」行と「Cookie `SameSite=None`」行
## Context
- C1. ttyd の端末は WebSocket で動く (ttyd は `--writable`。arbitrary command の shell)。ttyd-proxy は Ingress が到達する唯一のコンテナで、全 request を ttyd (loopback) に reverse proxy し、`httputil.ReverseProxy` が Upgrade をそのまま tunnel する (ttydproxy.go の package doc)。
- C2. ADR-0044 は frame-ancestors (どの親ページが iframe に入れてよいか) を 1 origin に閉じた。これは HTML の描画の入力で、WebSocket の Upgrade は frame-ancestors の対象ではない。Upgrade の `Origin` は、ttyd・ttyd-proxy・Ingress・auth-policy のどこでも検査していない (platform#297)。
- C3. oauth2-proxy の cookie は SameSite=None + Secure + Domain=.<dnsSuffix> (conventions の「Cookie `SameSite=None`」行)。portal は seat の ttyd を iframe で埋め込む (frame-ancestors = https://<appHost>)。この cookie の設定のもとで、Origin の検査が Upgrade の唯一の「どのページが開いたか」の入力になる。SameSite の要否の再評価は platform#297 (platform の値と本リポの契約表を揃える)。
- C4. portal の iframe 内の ttyd のページ (seat host `https://<seat>.<dnsSuffix>`) が開く WebSocket の Origin は、seat host 自身になる。Host は要求の Host ヘッダ (`<seat>.<dnsSuffix>`) で、ingress-nginx は既定で元の Host を upstream に渡し、`httputil.ReverseProxy` の server 側では `r.Host` に残る。
- C5. ttyd を別 origin のページから WebSocket で直接使う運用は無い (参加者の入口は portal の Terminal タブと、seat host の直接の top-level 表示だけ。どちらも Origin = seat host)。
## Options
1. ttyd の `--check-origin` を使う。コスト: ttyd の起動引数 1 つ。リスク: 受理集合 (scheme・port・Origin 無しの扱い) が ttyd の C の実装に従い、本リポの Go の test で固定できない (実測も本 PR では未実施)。検査が CSP と別の場所に分かれる。
2. ttyd-proxy (Go) で検査する。コスト: handler に 1 つの検査。リスク: Host が Ingress 越しに保たれないと正しい Upgrade も拒否する (V3 で実機確認。fail-closed なので黙って通ることはない)。可逆。効き始め: image と chart の更新後 (ttyd-proxy の image だけ)。
3. auth-policy の `/check-workspace` で検査する。コスト: 今の auth-url の配線は Origin を auth-policy に渡さず、渡すには Ingress の annotation を足す必要がある (ADR-0034 D4 で固定した配線を変える)。リスク: auth-policy の API と platform の rego が同時に変わる。auth-policy は Upgrade かどうかを知らない。
## Decision
Option 2。CSP の frame-ancestors を付ける消費者 (ttyd-proxy) 自身が、Upgrade の Origin の最後の検査点になる。受理集合を Go の 1 か所で書いて test で固定でき、platform と chart に変更が要らないため。
- D1. 検査点は ttyd-proxy の `Handler.ServeHTTP`。CSP / XFO を付ける層と同じで、upstream (ttyd) に届く前に断る。
- D2. 受理集合は 1 つ: `Origin` ヘッダがちょうど 1 本で、値が `"https://" + r.Host` とバイト単位で一致する。正規化しない (大文字小文字・既定 port・末尾の `.` や `/` を揃えない)。ブラウザが自分で書く値だけを通し、浮動の受理を作らない。`r.Host` が空なら常に拒否する (素の `https://` と一致してしまうため)。
- D3. fail-closed: Origin 無し・複数・`null`・別 origin・http・port の食い違い・大文字小文字の違いは 403 (CSP を付ける。body は無い)。検査の対象は `httputil.ReverseProxy` が upgrade として tunnel するもの、つまり `Connection` に token `upgrade` があり (大文字小文字を問わず、複数行・カンマ区切りを含む)、`Upgrade` が空でないもの。値 `websocket` に限らない (限ると、proxy が tunnel するのに検査しない型が残る)。
- D4. upgrade でない request は変えない (通常の GET は Origin が無くても、別 origin でも従来どおり)。応答 header の CSP / XFO、upstream 不達の 502 も変えない。
- D5. 拒否の log は Origin の値を書かない: 本数・長さの合計・scheme (`http` / `https` / `other` / `none`) と path だけ。
- D6. Host の出所は要求の `Host` のみ。env による上書き (期待 host の固定) は今は入れない (Signpost 1)。Ingress が Host を保たない構成は V3 が 403 で露呈する。
## Consequences
- 受理集合は seat 自身の origin だけ。portal の Terminal タブ (iframe 内の ttyd のページが開く WebSocket) は Origin = seat host なので壊れない想定。実機は V3 (未実施: stand-up 前に必須)。
- 別 origin のページから、または `curl` や非ブラウザの client が Origin 無しで ttyd に WebSocket を張ると 403 になる。運用者が `wscat` 等で直接 ttyd を叩く経路があるなら、`Origin: https://<seat host>` を付ける必要がある (認証は従来どおり Ingress の oauth2-proxy + auth-policy。本 ADR は認証を置き換えない)。
- 変更は ttyd-proxy の Go だけ (chart の値・env・platform の helmfile は変わらない)。I5 により全 image が同じ SHA で更新され、旧 image に戻せば検査も戻る。契約表の変更は ttyd-proxy 配線行の 1 句。
- 受理集合を広げる (2 つ目の origin、port、http) には ADR が要る (ADR-0044 D7 と同じ)。
- platform#297 の oauth2-proxy の SameSite 再評価は本 PR の外 (platform の値と contract 表 419 行を同時に変える。両リポ同時 PR)。本 ADR はそれの結果に依存せず、SameSite がどちらでも検査は要る。
- runbook への影響: stand-up の smoke に「Terminal タブで shell が動く」を入れる (V3)。
## Signposts
1. V3 で Ingress 越しに Host が保たれないと分かる (Terminal が 403) → 期待 host を env (`TTYD_PROXY_EXPECTED_HOST`。ADR-0044 と同じ `dnsname` の文法で起動時に検査) で固定する案を ADR で足す。検査を緩めない。
2. ttyd を埋め込む 2 つ目の origin か、直接の WebSocket 利用 (別 origin のツール) が要る → ADR-0044 Signpost 1 と同時に、受理集合を広げる ADR を書く。
3. ttyd-proxy が HTTP/2 の WebSocket (RFC 8441 の extended CONNECT) を受ける構成になる → upgrade の判定 (D3) が別の形になるので、検査の入口を見直す (今は plain HTTP/1.1 のみ)。
4. platform#297 の結果で SameSite を Lax にする → 本 ADR は変えず、contract 表 419 行の根拠の文だけが変わる。
## Verification
- V1 (make test): `TestWebSocketUpgradeOrigin` が、正 (Origin = `https://<Host>`、port 付き Host、`Connection: keep-alive, upgrade` + `Upgrade: WebSocket` → 101 で upstream に届く) と、負 (Origin 無し・別 origin・http・port の食い違い 2 方向・大文字の Host / Origin・末尾の `/` と `.`・`null`・空・2 本・空の Host + 素の `https://`・`Upgrade: h2c`・`Connection` が 2 行 → 403 で upstream に届かない)、非 upgrade (通常 GET が Origin 無し / 別 origin でも 200、`Connection: Upgrade` だけ / `Upgrade` だけも 200) を表で固定する。`TestWebSocketUpgradeRefusalLogsNoRawOrigin` が 403 の CSP と log に生の Origin が無いことを固定する。既存の `TestWebSocketUpgradeTunnelled` は Origin 付きで通る。
- V2 (mutation、PR 本文に実出力): (a) 検査を外す、(b) Origin 無しを通す、(c) `Upgrade` が `websocket` のときだけ検査する、(d) 大文字小文字を畳む、のそれぞれで V1 の負の行が赤になる。
- V3 (実機、未実施。stand-up 前に必須): 新しい image の seat で、portal の Terminal タブを開き shell が動く。DevTools の Network で WebSocket が 101 になる。Origin が seat host でない Upgrade が 403 になることも確かめる (curl で `Origin` を変えて送る)。Terminal タブが 403 になったら Host が保たれていないので Signpost 1。
## Advice
- security-engineer の指摘 (review-5x 89 R1#1、platform#296 の review、検証者 confirmed): 既存の欠陥。ttyd-proxy を推奨 (CSP と同じ消費者、test で固定できる)。
