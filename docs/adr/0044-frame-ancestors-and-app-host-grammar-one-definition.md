# ADR-0044: deploy-user.sh の --frame-ancestors と --app-host を閉じた文法にし、frame-ancestors の 1 定義を ttydproxy の Go に置く
- Status: Proposed (app PR の merge と同じセッションで Accepted。platform の対 PR は pin bump と同時か後)
- Date / Deciders: 2026-10-26 / VP + architect (起草) + security-engineer (CSP / iframe)
- 関連: app#520、#518 (app#510)、app#270、app#99、platform#54 (P19-2a)、ADR-0013、ADR-0041 / 0042 (文法の 1 定義の先例)
## Context
- C1. deploy-user.sh:134-141 は 2 つの値を受け取り、文法検査が無い (:256-257)。値は --set-string で渡す (:613-616, :622-625) が、helm は `,` で別の key として読む (:238-243)。
- C2. 描画: pod.yaml:266-267 は quote 無しの "…" で、`"` や改行で manifest が壊れる。values.yaml:196 の authSignin は `http://<appHost>/oauth2/start…` (ingress.yaml:33 は tpl + quote)。
- C3. 消費者: ttydproxy.go:99-109 / :155-170 は制御文字だけ拒否し、:125 / :141 で CSP に連結する。:129-133 は 'none' のときだけ XFO DENY を付ける。
- C4. platform: deploy-event-workspaces.sh:333-354 (`^https?://[A-Za-z0-9.-]+(:[0-9]+)?$`) と :367-387 (`^[A-Za-z0-9.-]+$`) で検査し、:458 で sibling app clone の deploy-user.sh に渡す (:134-135。版は appImageTag の pin: check-app-pin.sh)。
- C5. 値の形: scoreboard の allowedOrigins = "https://<appHost>" (platform releases/scoreboard/values.yaml.gotmpl:131)。appHost は env file ごとに小文字・port 無し。operations.md:560 / :1347 の用例は "https://<appHost>"。
- C6. originguard.originOf (originguard.go:134-140) は url.Parse の正規化で、閉じた文法ではない。
- C7. cookie は Secure + SameSite=None (conventions:419)。http の親ページでは session が成り立たない。origin は 1 つ (ADR-0013)。
- C8. 今 deploy-user.sh を直接呼ぶと、CSP に `*` を足せる (root shell の clickjacking)、別の helm key に注入できる、sign-in の redirect を外部 host に向けられる、annotation に nginx の `$` 変数を入れられる。信頼境界は運用者だが (:243-245)、他の運用者入力と同じ閉じた文法の規則を適用する。
## Options
1. shell の literal を正典にする (#518 の 4 値と同じ型)。ttydproxy は変えない。コストは小さい。リスク: deploy-user.sh 以外の経路 (values file・helm の直接実行) で入った値は制御文字の検査しか受けない。
2. Go の ttydproxy.FrameAncestorsPattern を正典にし、New が起動時に拒否する。shell の literal と case 表の header をそれに固定する (ADR-0042 の型)。app-host は shell だけで、DNS_SUFFIX_PATTERN を使い回す。コスト: 文法外の値では ttyd-proxy が起動しない (端末が落ちる)。今使われている 'none' と https://app.<suffix> は受理されるので影響は無い。可逆。効き始め: 即時。
3. originOf を正典にする。C6 のとおり受理集合が広がるので却下。
## Decision
Option 2。CSP を連結する消費者自身が最後の検査点になり、chart を直接使う経路も閉じるため。
- D1. app-host = DNS_SUFFIX_PATTERN + DNS_SUFFIX_MAX_LEN。
- D2. frame-ancestors = ちょうど 1 つで、'none' か https://<D1 の host>。≤ 261。'self'・*・*.・scheme だけ・http・port・path・`/`・query・userinfo・大文字・複数 (空白 / `,` / `;`)・他のキーワード・素の none は不可。
- D3. 両方を渡し、frame-ancestors が 'none' でなければ、frame-ancestors == "https://" + app-host。不一致は exit 2 (conventions:403 の「手で揃える運用規律」を機械の検査にする)。
- D4. 1 定義 = ttydproxy.FrameAncestorsPattern (+ 最大長)。deploy-user.sh の FRAME_ANCESTORS_PATTERN と internal/ttydproxy/testdata/frame-ancestors-cases.tsv の header がこれと一致し、host 部分は DNS_SUFFIX_PATTERN の本体と一致する。New は文法外を拒否する (空は 'none' のまま)。
- D5. pod.yaml の FRAME_ANCESTORS env を `| quote` で描画する。
- D6. platform は文法を持たない。deploy-event-workspaces.sh の 2 つの正規表現は、platform の app pin が本 ADR の app commit 以降になる PR と同時か後に消す。platform は env file の appHost から作る 2 値が app の case 表 header の pattern で受理されることを test する (APP_PIN の版)。
- D7. 狭めるのも広げるのも両リポ同時 PR。広げる (port・2 つ目の origin・http) のは ADR。
## Consequences
- 諦めたもの: http・port・複数 origin・'self'。platform が名簿の前に一度だけ出していたエラー (今後は seat ごとに kubectl の前で exit 2 になり、summary に全員が並ぶ)。
- 文法外の値では ttyd-proxy が CrashLoop になる (fail-closed)。runbook: operations.md の用例はこの形のまま変えなくてよい。
## Signposts
1. ttyd を埋め込む 2 つ目の origin (docs・admin を別 host にする等) が必要になる → 空白区切りで ≤ 2 に広げる ADR。
2. 443 以外の port で app を出す substrate (P20 の local 等) を採る → app-host と frame-ancestors の両方に :port を同じ PR で足す。
3. ADR-0013 の単一 origin を戻す決定、または http の local 経路が要る決定 → https 限定を見直す。
4. stand-up で ttyd-proxy が文法を理由に起動しない → 出所 (env file / 手入力) の形がずれている。文法ではなく出所を直す。
## Verification
- V1 (Go, make test): Go の pattern == deploy-user.sh の literal == case 表の header。host 部分 == DNS_SUFFIX_PATTERN の本体。case 表の全行が期待どおり。chart の既定値 'none' と noneAncestors が受理される。New は全ての拒否行で error、全ての受理行で成功する。
- V2 (shell, check-deploy-user-ids.sh): frame-ancestors の表を --frame-ancestors で、dns-suffix の表を --app-host で全行通す。受理なら helm の呼び出しに --set-string ttyd.frameAncestors=<v> / auth.appHost=<v> が完全一致で入る。D3 の不一致行は exit 2。pattern を壊す・検査を外す・一致検査を外す mutant がそれぞれ赤になる。
- V3 (chart-lint): `"` を含む値を helm template しても描画が壊れない (quote が効いている)。
- V4 (platform): env file の appHost から作る 2 値が APP_PIN の表の pattern で受理される。D6 の後は deploy-event-workspaces.sh にこの 2 つの文法の literal が無い。
- V5: 実機でのみ確認可。Terminal タブの iframe が表示され、ttyd の応答が `frame-ancestors https://<appHost>` を持つ。
## Advice
- VP brief (2026-10-26)。
- 経緯: platform#54 (P19-2a) の検査と、app#270 (app#99 に対する security MEDIUM)。
