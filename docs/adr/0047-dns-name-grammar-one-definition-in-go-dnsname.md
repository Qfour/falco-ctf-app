# ADR-0047: RFC 1123 の DNS 名の文法を Go の internal/dnsname に 1 定義で置き、FrameAncestorsPattern はそれを合成し、deploy-user.sh の DNS_SUFFIX_PATTERN はその写しとして固定する (ADR-0044 D4 の host 部分の権威を限定 supersede)
- Status: Proposed (Accepted の条件: 実装 PR が main に入り、V1-V5 が緑)
- Date / Deciders: 2026-10-27 / VP + architect (起草) + security-engineer (CSP の入力の文法・Dockerfile、R1)
- 関連: app#533、app#532、ADR-0044 D4 / V1 / Signpost 2 / 3、ADR-0042 (1 定義 + 共有 case 表 + shell の pin)、ADR-0041 (challengeid の葉)、#518 (app#510)、platform#291 (V4 parity)
## Context
- C1. 写しが 4 つ。charts/ctf-user/deploy-user.sh:289-290 (DNS_SUFFIX_PATTERN / DNS_SUFFIX_MAX_LEN。今の権威)。internal/ttydproxy/ttydproxy.go:86 (host の本体を literal で含む) と、それを shell の本体に固定する frame_ancestors_grammar_test.go:59-71。internal/identity/users_test.go:92-102 (seat 形の検出器の除外表。key は ttydproxy.FrameAncestorsPattern で、:16 で ttydproxy を import)。scoreboard の PORTAL_TTYD_SUFFIX (csp.go:198-216 は制御文字だけを見る。app#532)。
- C2. internal/catalog/deploy_operator_inputs_test.go:8 は「4 値に Go の定義は無い」と書き、:41 で dns-suffix の表を shell literal に固定している。:113 は 253 の固定、:127 は chart 既定値の受理。
- C3. 消費者の制約。ttyd-proxy は distroless で、build context は ttydproxy と serverutil だけ (images/ttyd-proxy/Dockerfile:13-15)。internal/catalog は yaml.v3 を引く (challengeid.go:5-10 が葉にした理由)。internal/casetable は test 専用 (casetable.go:6-7)。
- C4. platform が読むのは 2 つの表の 1 行目だけ (ADR-0044 D6 / D7)。path の移動と 1 行目の変更は、両リポ同時 PR。
- C5. identity の検出器 seatShaped (users_test.go:88) は label の形に一致し、cmd/ と internal/ の test 以外の .go を走査する。新しい literal は、値で除外しない限り赤になる。
## Options
1. 新しい葉 internal/dnsname を作る。変更点: literal は Label 1 つで、Body / Pattern / MaxLen / Valid は合成。ttydproxy は合成し、shell は写しとして固定し、表は動かさない。コスト: package +1、Dockerfile +1 行、除外表の key の付け替え。リスク: 低い。可逆。効き始め: 即時 (写しが 1 つ減り、app#532 は 5 つ目の写しを作らずに済む)。
2. ttydproxy に HostPattern を公開し、scoreboard が import する。コスト: scoreboard が reverse proxy の package を link する。依存の向きが逆 (CSP の消費者が共有の文法を持つ)。
3. internal/catalog/dnsname に置く。依存は中立だが、DNS 名は catalog の概念ではなく、境界が曖昧になる。
## Decision
Option 1。消費者が import するだけで同じ集合を得られ、ADR-0042 の型 (Go の 1 定義、shell と表はその写し) に揃うため。
- D1. 1 定義 = internal/dnsname。literal は Label = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` の 1 つだけ。Body = Label + `(\.` + Label + `)*`、Pattern = `^` + Body + `$`。MaxLen = 253。label の上限 63 は Label の {0,61} が決める (doc に書く)。Valid(s) = len(s) <= MaxLen かつ Pattern に一致。Valid("") は false。import は標準ライブラリだけで、module 内の package を import しない。
- D2. ttydproxy.FrameAncestorsPattern = `^('none'|https://` + dnsname.Body + `)$`、FrameAncestorsMaxLen = len("https://") + dnsname.MaxLen。どちらも今と同じ byte 列と値。
- D3. deploy-user.sh の DNS_SUFFIX_PATTERN / DNS_SUFFIX_MAX_LEN は shell の写しで、internal/dnsname の test が固定する (固定の向きを逆にする)。FRAME_ANCESTORS_PATTERN / FRAME_ANCESTORS_MAX_LEN は、引き続き ttydproxy の test が固定する。
- D4. 表 internal/catalog/testdata/dns-suffix-cases.tsv は、path も 1 行目の byte も変えない。header == dnsname.Pattern。表を internal/dnsname/testdata に移すのは、両リポ同時 PR (ADR-0044 D7)。
- D5. identity の検出器は、ttydproxy.FrameAncestorsPattern の代わりに dnsname.Label (定数の値) を除外する。除外表の key は、どれも走査で 1 回以上 literal として見つかること (見つからない除外は赤)。
- D6. PORTAL_TTYD_SUFFIX の起動時検査 (app#532) は dnsname.Valid を使う (空は「未構成」のまま許す)。本 ADR の PR には入れない。
- D7 (ADR-0044 の限定 supersede): D4 の「host 部分の権威は、現状は deploy-user.sh の DNS_SUFFIX_PATTERN … 一致を固定する。」の 2 文、同じ段落の「host 文法を Go の 1 定義に移すのは app#533。」、V1 の「host 部分 == DNS_SUFFIX_PATTERN の本体。」、Signpost 2 の「frame_ancestors_grammar_test.go の合成 test (host 部分 == DNS_SUFFIX_PATTERN の本体) を書き換える」を、D1-D3 と V1-V2 で置き換える。ADR-0044 Signpost 3 は本 ADR で発火した。D4 のそれ以外 (frame-ancestors の 1 定義、変更が両リポ同時 PR になること) は変えない。
## Consequences
- 変更の規則: dnsname を変えると --dns-suffix・--app-host・--frame-ancestors (app#532 の後は PORTAL_TTYD_SUFFIX も) が同時に変わる。狭める変更も両リポ同時 PR。2 つの表の 1 行目の byte が変わる変更は、同値でも両リポ同時 PR。
- 新しく守るもの: 文法の新しい消費者は import する (写しを作らない)。internal/dnsname/** の変更は security 必須 (CSP に連結される値の文法)。dev-flow のゲート表に足す。
- ttyd-proxy の Dockerfile に COPY internal/dnsname を足す (足し忘れは required の build が赤にする)。
- 受理集合は変わらない。platform の parity (test-frame-ancestors-parity.sh) は影響を受けない。
- runbook への影響: 無し。
## Signposts
1. 443 以外の port の substrate を採る (ADR-0044 Signpost 2) → dnsname は変えず、app-host と frame-ancestors の側で `dnsname.Body` + port を合成する。dns-suffix は port を持たない。
2. Go 以外の 3 つ目の写しが要る (helm の regexMatch guard、platform 側の検査) → pin を増やさず、ADR-0045 の型で data file として書き出すことを検討する。
3. seat 形の検出器が、別の package の label 形の literal で赤になる → その package は dnsname を import する。別の文法なら、定数の値を key にして除外する。
4. platform 側を別の理由で触る PR (#290 (d) 等) が出る → そのときに、表の internal/dnsname/testdata への移動と platform の FAG_HOST_TABLE を同時 PR で行う。
## Verification
- V1 (make test): dnsname.Pattern == deploy-user.sh の DNS_SUFFIX_PATTERN == dns-suffix-cases.tsv の header。MaxLen == DNS_SUFFIX_MAX_LEN == 253。表の全行が Valid と一致する (件数の下限は今の値: 50 行 / 15 accept / 30 reject)。chart 既定の dnsSuffix が受理される。label 63 / 64 と全長 253 / 254 の行がある。Valid("") は false。
- V2 (make test): FrameAncestorsPattern == "^('none'|https://" + dnsname.Body + ")$"、FrameAncestorsMaxLen == 8 + dnsname.MaxLen。既存の shell / header の固定、全行、New の検査は緑のまま。
- V3 (make test): dnsname は標準ライブラリだけを import する (identity と同じ AST の検査)。
- V4 (make test): 検出器の除外は dnsname.Label。Label の literal を別の package に写した合成ファイルは赤になる。見つからない除外 key は赤になる。
- V5 (PR 本文): `git diff --exit-code origin/main -- internal/catalog/testdata/dns-suffix-cases.tsv internal/ttydproxy/testdata/frame-ancestors-cases.tsv` が 0 で、deploy-user.sh の 2 つの PATTERN literal も無変更。platform の `scripts/test-frame-ancestors-parity.sh --app-dir <この branch の clone>` が rc=0。
## Advice
- review-5x 81 (app#531、2026-10-26) R4#2 / R4#4 / R4#6: 写しが 4 つ、契約表 422 / 423 行の変更規則の食い違い、identity の除外表が 4 つ目の写し。
- architect (2026-10-27): 葉の package にして literal を 1 つにする。表は動かさない (platform への波及を 0 にする)。
