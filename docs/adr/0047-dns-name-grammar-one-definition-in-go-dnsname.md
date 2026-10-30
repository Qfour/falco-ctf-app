# ADR-0047: RFC 1123 の DNS 名の文法を Go の internal/dnsname に 1 定義で置き、FrameAncestorsPattern はそれを合成し、deploy-user.sh の DNS_SUFFIX_PATTERN はその写しとして固定する (ADR-0044 D4 の host 部分の権威を限定 supersede)
- Status: **Accepted** (2026-10-27。実装: app#543 = f50190b。review-5x 90 (T3) 5 観点 APPROVE with comments、security = R1。V1〜V6 緑。V5 の platform 側 (`scripts/test-frame-ancestors-parity.sh --app-dir`) は platform#291 の dd2ea2e で実行した。platform main への反映は platform#291 の merge 後に再確認する。D6 実装: app#532 (PR #552)。merge 後に SHA を足す)
- Date / Deciders: 2026-10-27 / VP + architect (起草) + security-engineer (CSP の入力の文法・Dockerfile、R1)
- 関連: app#533、app#532、ADR-0044 D4 / V1 / Signpost 2 / 3、ADR-0042 (1 定義 + 共有 case 表 + shell の pin)、ADR-0041 (challengeid の葉)、#518 (app#510)、platform#291 (V4 parity)
## Context
- C1. 写しが 4 つ。charts/ctf-user/deploy-user.sh:289-290 (DNS_SUFFIX_PATTERN / DNS_SUFFIX_MAX_LEN。今の権威)。internal/ttydproxy/ttydproxy.go:86 (host の本体を literal で含む) と、それを shell の本体に固定する frame_ancestors_grammar_test.go:59-71。internal/identity/users_test.go:92-102 (seat 形の検出器の除外表。key は ttydproxy.FrameAncestorsPattern で、:16 で ttydproxy を import)。scoreboard の PORTAL_TTYD_SUFFIX (csp.go:198-216 は制御文字だけを見る。app#532)。
- C2. internal/catalog/deploy_operator_inputs_test.go:8 は「4 値に Go の定義は無い」と書き、:41 で dns-suffix の表を shell literal に固定している。:113 は 253 の固定、:127 は chart 既定値の受理。
- C3. 消費者の制約。ttyd-proxy は distroless で、build context は ttydproxy と serverutil だけ (images/ttyd-proxy/Dockerfile:13-15)。internal/catalog は yaml.v3 を引く (challengeid.go:5-10 が葉にした理由)。internal/casetable は test 専用 (casetable.go:6-7)。
- C4. platform が読むのは 2 つの表の 1 行目だけ (ADR-0044 D6 / D7)。path の移動と 1 行目の変更は、両リポ同時 PR。凍結は 1 行目 (header) と deploy-user.sh の 2 つの PATTERN literal で、2 行目以降のコメントは凍結ではない。
- C5. identity の検出器 seatShaped (users_test.go:88) は label の形に一致し、cmd/ と internal/ の test 以外の .go を走査する。新しい literal は、値で除外しない限り赤になる。
## Options
1. 新しい葉 internal/dnsname を作る。変更点: literal は Label 1 つで、Body / Pattern / MaxLen / Valid は合成。ttydproxy は合成し、shell は写しとして固定し、表は動かさない。コスト: package +1、Dockerfile +1 行、除外表の key の付け替え。リスク: 低い。可逆。効き始め: 即時 (写しが 1 つ減り、app#532 は 5 つ目の写しを作らずに済む)。
2. ttydproxy に HostPattern を公開し、scoreboard が import する。変更点: host の literal は ttydproxy に残し、FrameAncestorsPattern と同じ package から HostPattern を公開する。コスト: scoreboard の binary が reverse proxy の package (internal/ttydproxy。net/http/httputil を引く) を link する。依存の向きが逆 (CSP の消費者の 1 つが共有の文法を持つ)。リスクと可逆性: internal/ttydproxy の変更の影響範囲が ttyd-proxy image から scoreboard の build と閉包に広がる。戻すには文法を再び外の package へ移すしかなく (= Option 1)、そのとき消費者の import を全部付け替える。効き始め: 即時 (app#532 は写しを作らずに済む) だが、ttyd-proxy 以外の消費者が増えるたびに逆向きの依存が 1 本増える。
3. internal/catalog/dnsname に置く。変更点: Option 1 と同じ葉を catalog の下 (challengeid と同じ並び) に置く。コスト: Option 1 と同じ (package +1、Dockerfile +1 行、除外表の key の付け替え)。依存は中立 (葉なので yaml.v3 を引かない)。リスクと可逆性: DNS 名は catalog (課題の目録) の概念ではなく、境界が曖昧になる。課題を変える PR と CSP の入力の文法を変える PR が path で区別しにくくなり、security 必須の glob は internal/catalog/** の一部を切り出す形になる。可逆 (module 内の path の移動だけで、platform が読む表の path は変わらない)。効き始め: Option 1 と同じく即時。
## Decision
Option 1。消費者が import するだけで同じ集合を得られ、ADR-0042 の型 (Go の 1 定義、shell と表はその写し) に揃うため。
- D1. 1 定義 = internal/dnsname。literal は Label = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` の 1 つだけ。Body = Label + `(\.` + Label + `)*`、Pattern = `^` + Body + `$`。MaxLen = 253。label の上限 63 は Label の {0,61} が決める (doc に書く)。Valid(s) = len(s) <= MaxLen かつ Pattern に一致。Valid("") は false。import は標準ライブラリだけで、module 内の package を import しない。
- D2. ttydproxy.FrameAncestorsPattern = `^('none'|https://` + dnsname.Body + `)$`、FrameAncestorsMaxLen = len("https://") + dnsname.MaxLen。どちらも今と同じ byte 列と値。
- D3. deploy-user.sh の DNS_SUFFIX_PATTERN / DNS_SUFFIX_MAX_LEN は shell の写しで、internal/dnsname の test が固定する (固定の向きを逆にする)。FRAME_ANCESTORS_PATTERN / FRAME_ANCESTORS_MAX_LEN は、引き続き ttydproxy の test が固定する。
- D4. 表 internal/catalog/testdata/dns-suffix-cases.tsv は、path も 1 行目 (header) の byte も変えない。header == dnsname.Pattern。凍結するのは 2 つの表の path と 1 行目、deploy-user.sh の 2 つの PATTERN literal (DNS_SUFFIX_PATTERN / FRAME_ANCESTORS_PATTERN) で、2 行目以降の説明コメントと case の行は凍結ではない (case の行は V1 / V2 の全行検査が固定する)。表を internal/dnsname/testdata に移すのは、両リポ同時 PR (ADR-0044 D7)。
- D5. identity の検出器は、ttydproxy.FrameAncestorsPattern の代わりに dnsname.Label (定数の値) を除外する。除外表の key は、どれも走査で 1 回以上 literal として見つかること (見つからない除外は赤)。
- D6. PORTAL_TTYD_SUFFIX の起動時検査 (app#532) は dnsname.Valid を使う (空は「未構成」のまま許す)。本 ADR の PR には入れない。
- D7 (ADR-0044 の限定 supersede): D4 の「host 部分の権威は、現状は deploy-user.sh の DNS_SUFFIX_PATTERN … 一致を固定する。」の 2 文、同じ段落の「host 文法を Go の 1 定義に移すのは app#533。」、V1 の「host 部分 == DNS_SUFFIX_PATTERN の本体。」、Signpost 2 の「frame_ancestors_grammar_test.go の合成 test (host 部分 == DNS_SUFFIX_PATTERN の本体) を書き換える」を、D1-D3 と V1-V2 で置き換える。ADR-0044 Signpost 3 は本 ADR で発火した。D4 のそれ以外 (frame-ancestors の 1 定義、変更が両リポ同時 PR になること) は変えない。
## Consequences
- 変更の規則: dnsname を変えると --dns-suffix・--app-host・--frame-ancestors (PORTAL_TTYD_SUFFIX も: app#532) が同時に変わる。狭める変更も両リポ同時 PR。2 つの表の 1 行目の byte が変わる変更は、同値でも両リポ同時 PR。
- 新しく守るもの: 文法の新しい消費者は import する (写しを作らない)。internal/dnsname/** の変更は security 必須 (CSP に連結される値の文法)。dev-flow のゲート表に足す。
- ttyd-proxy の Dockerfile に COPY internal/dnsname を足す (足し忘れは make test の閉包 test (V6) が赤にする。build (ttyd-proxy) は required ではない)。
- 受理集合は変わらない。platform の parity (test-frame-ancestors-parity.sh) は影響を受けない。
- 運用の手順 (旧 Signpost 3 / 4。Accepted 化の docs PR で Signposts から移した): (a) seat 形の検出器 (internal/identity の seatShaped) が別の package の label 形の literal で赤になったら、その package は dnsname を import する。別の文法なら、定数の値を key にして除外する (D5)。(b) platform 側を別の理由で触る PR (platform#290 (d) 等) が出たら、そのときに表の internal/dnsname/testdata への移動と platform の FAG_HOST_TABLE を同時 PR で行う (D4、ADR-0044 D7)。それまで表は internal/catalog/testdata に置く。
- runbook への影響: 無し。
- scoreboard は文法外の PORTAL_TTYD_SUFFIX で起動しない (D6、app#532)。replicas=1 なので、起動しない scoreboard は採点も止める。値の出所は platform の env の dnsSuffix で、事前検知は platform#296 (未 merge) の dnsSuffix の検査 (preflight / 課金前 gate / 名簿前検査が `dns-suffix-cases.tsv` の 1 行目の pattern で検査する。#291 までは appHost の 2 値のみ)。chart の values.schema.json は作らない (文法の写しになる)。
## Signposts
1. 443 以外の port の substrate を採る (ADR-0044 Signpost 2) → dnsname は変えず、app-host と frame-ancestors の側で `dnsname.Body` + port を合成する。dns-suffix は port を持たない。
2. Go 以外の 3 つ目の写しが要る (helm の regexMatch guard、platform 側の検査) → pin を増やさず、ADR-0045 の型で data file として書き出すことを検討する。
3. dns-suffix と別の host 文法を要る消費者が出る (IDN / punycode を受ける、大文字を正規化して受ける、末尾の `.` を許す等。port は Signpost 1 の合成で足りる) → dnsname を広げず、定義を分ける (dnsname は「deploy が受ける DNS 名」のまま。別の文法は別の定義と別の表にする)。dnsname を広げると --dns-suffix・--app-host・--frame-ancestors が同時に広がるため。
4. 文法の消費者の多数が Go 以外になる (helm の regexMatch guard・platform の検査・shell の写しの数が Go の import の数を超える) → Go の定数を定義にするのをやめ、ADR-0045 の型で data file を定義にし、Go と shell はどちらもその読み手にする (新しい ADR で D1 / D3 を supersede)。Signpost 2 は Go を定義のまま data を書き出す段階で、こちらは定義の所在そのものを移す段階。
## Verification
- V1 (make test): dnsname.Pattern == deploy-user.sh の DNS_SUFFIX_PATTERN == dns-suffix-cases.tsv の header。MaxLen == DNS_SUFFIX_MAX_LEN == 253。表の全行が Valid と一致する (件数の下限は今の値: 50 行 / 15 accept / 30 reject)。chart 既定の dnsSuffix が受理される。label 63 / 64 と全長 253 / 254 の行がある。Valid("") は false。
- V2 (make test): FrameAncestorsPattern == "^('none'|https://" + dnsname.Body + ")$"、FrameAncestorsMaxLen == 8 + dnsname.MaxLen。既存の shell / header の固定、全行、New の検査は緑のまま。
- V3 (make test): dnsname は標準ライブラリだけを import する (identity と同じ AST の検査)。
- V4 (make test): 検出器の除外は dnsname.Label。Label の literal を別の package に写した合成ファイルは赤になる。見つからない除外 key は赤になる。
- V5 (PR 本文): `git diff origin/main -- internal/catalog/testdata/dns-suffix-cases.tsv internal/ttydproxy/testdata/frame-ancestors-cases.tsv | grep '^[-+]# pattern'` が空 (2 つの表の 1 行目が無変更。path の移動・削除も差分に出る) で、deploy-user.sh の 2 つの PATTERN literal の行 (`DNS_SUFFIX_PATTERN=` / `FRAME_ANCESTORS_PATTERN=`) に差分が無い。platform の `scripts/test-frame-ancestors-parity.sh --app-dir <この branch の clone>` が rc=0。
- V6 (make test): `internal/apispec` の `TestDistrolessDockerfilesCopyTheirWholeClosure` が、名前で COPY する distroless image の表 (collector / auth-policy / ttyd-proxy) の各 Dockerfile について、binary が link する module 内の package が全て COPY されていることを固定する。ttyd-proxy の `COPY internal/dnsname` を消すと `internal/dnsname` だけが報告される (表の行ごとに、COPY を 1 行消した mutation が 1 package だけを報告することも test が検査する)。
## Advice
- review-5x 81 (app#531、2026-10-26) R4#2 / R4#4 / R4#6: 写しが 4 つ、契約表 422 / 423 行の変更規則の食い違い、identity の除外表が 4 つ目の写し。
- architect (2026-10-27): 葉の package にして literal を 1 つにする。表は動かさない (platform への波及を 0 にする)。
- review-5x 90 (app#543、2026-10-27) R4#3 / R4#4 (LOW): Options 2 / 3 にリスクと可逆性・閾値が無い、Signpost 3 / 4 が覆す信号ではなく運用手順、README の 0044 行に本 ADR の限定 supersede が無い、契約表に DNS 名の文法の行が無く規則が 422 / 423 行・dev-flow・package doc に分散。architect が Accepted 化の docs PR で反映した (Options の補完、Signpost 3 / 4 の置き換えと運用手順の Consequences への移動、契約表の「DNS 名の文法 (ADR-0047)」行の新設と 422 / 423 行の参照化)。Decision と Verification は無変更。
- review-5x 92 (app#552、2026-10-30) の助言として記録: D6 の実装で `GET /portal` ごとの検査を残した (`view.New` を直に使う Handler への多層防御。正規表現 1 回)。制御文字の別の検査は撤去した (制御文字は dnsname.Valid の文法の外)。エラー文は値を載せず、長さ (bytes) と「not a DNS name」だけを出す。起動時の呼び出しは `cmd/scoreboard` の配線 test が固定する。
