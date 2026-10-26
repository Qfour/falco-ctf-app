# ADR-0046: platform の名簿の経路は --frame-ancestors / --app-host / --dns-suffix を env file から導き、明示の値は 'none' か導出値と同じものだけを受ける
- Status: Proposed (Accepted の条件: platform#292 が main に入り、V1-V3 が緑。V5 は次の stand-up)
- Date / Deciders: 2026-10-27 / VP + architect (起草) + security-engineer (CSP / iframe、R1)
- 関連: platform#292、platform#291 (#290)、ADR-0044 (Options「検討して外した構造」・Consequences・受け入れた残余 (b))、ADR-0013、契約表「ttyd-proxy 配線」「PORTAL_TTYD_SUFFIX⇔ctf-user.dnsSuffix」「--frame-ancestors / --app-host の文法」の 3 行、review-5x 82 R2#2 / R4#7
## Context
- C1. (platform の file:line は platform#291 の head dd2ea2e) standup.sh:842 の step 7 は deploy-event-workspaces.sh に --env / --flags-sops / --egress-lockdown / --api-server-cidr だけを渡す。deploy-event-workspaces.sh は --frame-ancestors / --app-host / --dns-suffix を省くと何も渡さない (:64-98 の usage。:108-109 は「後回し」と書く)。runbook の名簿の用例 (operations.md:141 / :2315) も 3 つとも渡さない。
- C2. このため ttyd-proxy は chart 既定の 'none' (charts/ctf-user/values.yaml:51) と X-Frame-Options: DENY (ttydproxy.go:151-153) を返す。portal は PORTAL_TTYD_SUFFIX があれば iframe を描き (pane-terminal.tmpl:71-84)、platform は全ての env でそれを入れる (releases/scoreboard/values.yaml.gotmpl:107)。結果、Terminal タブは拒否された空の枠になる。
- C3. ADR-0044 D6 (b) の名簿前検査、standup.sh:360-384 の課金前 gate、preflight-event.sh:573-578 の §13b は、どれも env の appHost から作る 2 値 (https://<appHost> と <appHost>) を検査する。だが名簿はその値を使わない (検査した値 ≠ 使う値)。operations.md:2348 がこの穴を明記している。
- C4. 同じ出所の先例: allowedOrigins = "https://{{ .Values.appHost }}" (values.yaml.gotmpl:131)、portalTtydSuffix = dnsSuffix (:107)。local も TLS で (同ファイル :124-131 のコメント、values-local)、origin は https。
- C5. sign-in の行き先: oauth2-proxy は /oauth2 を appHost と auth.<dnsSuffix> の両方で受ける (releases/oauth2-proxy/values.yaml.gotmpl:159 / :174-180)。redirect_url は appHost (:103)。--app-host を省くと chart は compat host auth.<dnsSuffix> に落ちる (charts/ctf-user/values.yaml:196-197)。
- C6. ctf-user chart の dnsSuffix の既定は "ctf-event.dev" (charts/ctf-user/values.yaml:18)。名簿の経路は --dns-suffix を渡さないので、契約表 418 行の一致 (PORTAL_TTYD_SUFFIX == ctf-user.dnsSuffix) は、prod / vm-prod では chart 既定との偶然の一致 (environments/prod.yaml.gotmpl:40、vm-prod.yaml.gotmpl:44) で成り立っている。local (local.yaml.gotmpl:22 = nip.io) では成り立たない (仮説。実機は未確認)。
- C7. ADR-0044:18 は、chart か deploy-user.sh が --app-host から導く案を (i)(ii)(iii) の理由で外した。再検討の条件は「2 値が常に同じ出所から作られる (platform が --frame-ancestors を手で受けなくなる)」。
## Options
1. deploy-event-workspaces.sh が、省略された値を --env の env file から導く。明示の値は 'none' (frame-ancestors のみ) か導出値と同じものに限る。変更点: platform の共有関数 1 つと呼び出し 1 か所。コスト: test の case と、既存の呼び出し assert の更新。app の CLI と chart の既定は不変。リスク: env を取り違えると、別の env の host が入る。そのとき囲める origin は狭まる側に働き、広がらない。可逆 (導出を外せば今に戻る)。効き始め: 次の名簿から。
2. 'none' を意図として、用例を直す。コスト: P23-4 の iframe 設計と契約表 419 行の埋め込み契約を捨てる。portal の分岐も要る。product の後退。
3. standup.sh の step 7 で 3 値を組み立てる。コスト: runbook の手動の名簿 (operations.md:141 / :2315) は導かないまま。同じ script に呼び手で挙動の違う 2 経路ができる。
## Decision
Option 1。値を fan-out する唯一の場所が出所も持てば、検査した値と使う値が構造上同じになるため。
- D1. 出所: platform の名簿の経路 (deploy-event-workspaces.sh。standup の step 7 と runbook の名簿はすべてここを通る) では、--frame-ancestors と --app-host の出所は --env の env file の appHost 1 つ。省略時は frame-ancestors = https://<appHost>、app-host = <appHost>。env file の読み取りは scripts/lib/frame-ancestors-grammar.sh の 1 関数だけ (fag_env_app_host → roster_env_value)。課金前 gate と §13b も、同じ関数の出力を検査する。
- D2. 明示の値: --frame-ancestors は 'none' (意図した無効化。尊重し、--app-host は導出する) か導出値と同じ値。--app-host は導出値と同じ値。違えば名簿の前 (seat・flags の復号・cluster の前) に exit 2。
- D3. appHost が空 (env file に無い・default の "" を継ぐ) とき。local 以外: exit 2 (何も払い出さない)。local (env が local かつ kube context が local 系 = 既存の TARGET_IS_LOCAL): 導出せず警告を出す (chart 既定の 'none' と compat host)。local でも appHost があれば導出する。
- D4. 導出値は ADR-0044 D6 (b) の名簿前検査に通す (導出が先、検査が後)。最大長と D3 の一致は、seat ごとの deploy-user.sh が権威のまま。app の CLI 契約 (deploy-user.sh の passthrough、chart 既定の 'none') は変えない。
- D5. --dns-suffix も同じ規則。出所は env file の dnsSuffix (portalTtydSuffix と同じ値)。省略時は導出し、明示は導出値と同じ値だけ。D4 と同じく、名簿の前に dns-suffix の表で検査する。
- D6. ADR-0044 の「検討して外した構造」(chart / deploy-user.sh で導く) は外したまま。理由 (i) と (iii) は app 側に残る。再検討の条件は、platform の経路について D1 と D2 で成り立った。
## Consequences
- 諦めたもの: platform の経路で、任意の frame-ancestors を手で渡すこと。2 つ目の origin は ADR-0044 Signpost 1 の ADR が要る。
- 省略は 'none' の意味でなくなる。囲めなくするには --frame-ancestors "'none'" を明示で渡す。platform の旧 frame-ancestors 正規表現 (deploy-event-workspaces.sh:381) は 'none' を拒むので、旧検査を消す (#290 (d)) まで、'none' はその検査の対象外にする。表の検査 (b) が先に走るので、受理集合は広がらない。
- ADR-0044 の受け入れた残余 (b) は、platform の経路では閉じる (2 値が常に両方渡るので D3 が常に効く)。deploy-user.sh を直接使う経路には残る。
- ADR-0044 Consequences の「operations.md の用例はこの形のまま変えなくてよい」を置き換える。seat 1 つの用例に --app-host を足し、10.4 の 3 と 4 を直す。
- ttyd を囲めるのは appHost の page だけになる。appHost は admin dashboard と同じ origin (ADR-0013) なので、appHost で XSS が起きれば root shell の clickjacking に繋がる。P23-4 以来受容している範囲と同じ (security R1 で再確認)。
- compat host auth.<dnsSuffix> は、導出した stand-up で sign-in に使われないと確かめた後に外せる (追跡 issue を起こす)。
- 順序: platform#291 → app の文書 PR と platform#292 を相互リンクで同時に出す → platform#292 の merge で Accepted。APP_PIN は変えない (e47669f の表と、既存の --app-host を使うだけ)。
## Signposts
1. ttyd を囲む origin が appHost でなくなる (portal の別 host・2 つ目の origin) → env file に別の key が要る。D1 の出所を見直す。
2. 実際の stand-up か runbook の作業で、D2 の exit 2 (明示値の不一致) が 1 回でも出る → 正当な 2 つ目の出所がある。D2 を見直す。
3. 導出値でも V5 が失敗する (ブラウザが iframe 内の third-party cookie を送らない等) → iframe の設計そのものを見直す。Pop out を主にし、'none' を既定に戻す。
4. 導出した stand-up で、auth.<dnsSuffix> への sign-in の要求が 0 件 → compat host を外す。
## Verification
- V1 (platform、scripts/test-frame-ancestors-gate.sh): 省略時、非 local と local (appHost あり) の deploy-user の呼び出しに --frame-ancestors https://<env の appHost> --app-host <env の appHost> --dns-suffix <env の dnsSuffix> が入る。明示 'none' は 'none' のまま渡り、--app-host は導出される。明示の値が導出値と同じなら通る。frame-ancestors / app-host / dns-suffix の明示値の不一致は exit 2 で、deploy-user と sops を呼ばない。非 local で appHost が空なら exit 2。local で空なら 3 フラグとも渡らない。mutant: 導出を外す / 不一致の検査を外す / 'none' を不一致として扱う / dnsSuffix から auth.<suffix> を作る。それぞれ case が赤にする。
- V2 (platform、test-flags-gates.sh): --env prod の deploy-user の呼び出しの assert が、導出した 3 値を含む形で緑。課金前 gate・§13b・deploy-event-workspaces.sh の appHost 読み取りが、共有関数の外に無い (静的検査)。
- V3: ADR-0044 V4 (test-frame-ancestors-parity.sh) が緑のまま。
- V5 (実機でのみ確認可): ADR-0044 V5 と同じ。手順は platform#292 の PR 本文に書く。
## Advice
- review-5x 82 R2#2 / R4#7 (platform#291、2026-10-26): stand-up の経路で 2 値が使われず、名簿前検査と V4 が空振りする。
- architect (2026-10-27): 明示値を絞らないと再検討の条件が成り立たない。--dns-suffix も同じ出所に入れる (C6)。
