# ADR-0050: 運営 (ADMIN_EMAILS) の要求は seat の Pod に渡さない (/check-workspace の admin 例外を外し I8 を締める)。challenge コンテナの capability は drop ALL + 監査した add にする
- Status: **Accepted** (2026-10-30。S1 = D1 / D4 の実装 app#557 = 9368993。段階制: D2 は S2 の merge まで効力を持たない)
- Date / Deciders: 2026-10-30 / VP + architect (起草) + security-engineer。運営の導線が変わるので CEO に報告する
- 関連: app#551、platform#301 (private。判断の詳細はそこにあり、本 ADR には写さない)、ADR-0034 (D3 / D7 / V9 の /check-workspace の admin に関する文言を限定 supersede)、ADR-0049 (Proposed、app#556、未 merge)、ADR-0048、conventions I8 / SecurityContext 節、platform operations.md §6.7
## Context
- C1. I8 (conventions の Hard Invariants) と ADR-0034 (D3 / D7 / V9) は、ADMIN_EMAILS を I8 の唯一の例外とし、その範囲に「任意の workspace」を含めている。実装は internal/authpolicy/server.go:305-313 で、admin なら identity header をそのまま通して 200 を返す。spec では x-ctf-authz: self-or-admin (docs/openapi-auth-policy.yaml:174、表は :188)。
- C2. 最小権限: seat の Pod は参加者の実行環境で、運営の作業に必要な場所ではない。本 ADR は seat の Pod を参加者の管理下にある環境として扱い、運営の identity をそこに渡さないことを設計の前提に置く。
- C3. 運営の seat 内操作は、誰が打っても参加者の採点に帰属する (operations.md §6.7)。ブラウザの Terminal から運営が打つ経路も同じ。トラブル対応は kubectl exec と §6.7 の汚染確認で足りる。
- C4. platform の文書と stub は、運営が seat host を直接開く前提で書かれている: operations.md:127-129、deploy-event-workspaces.sh:3-4 / :478 のコメント、test-verify-auth-v14.sh:76 の stub (admin で ttyd が 200)。verify-auth.sh の本体は、admin が seat host で拒否されるかを検査していない。
- C5. admin の portal は Terminal の iframe の host を admin の local part から作る (scoreboard/api/api.go:532-552。admin@<domain> は "admin" になる)。roster は ADMIN_EMAILS と seat の正規形の重なりを起動時に拒否する (internal/authpolicy/roster.go:194) ので、その host に seat は存在しない。
## Options
1. D1 だけ (workspace から admin 例外を外す)。変更点: auth-policy の分岐 1 つ、spec の authz 語、I8 の文言。コスト: 運営の導線が kubectl exec だけになる。リスク: 運営がブラウザで seat の画面を見られない。可逆 (ただし I8 の変更なので ADR が要る)。効き始め: auth-policy の image を更新した直後 (I5 により全 image)。
2. D2 だけ (challenge の capability を落とす)。変更点: pod.yaml の challenge に securityContext を置く。コスト: 課題の監査と、全課題の通し。リスク: 運営の identity が seat の Pod に渡る点 (C2) は変わらない。要る capability を取りこぼすと課題が壊れる。可逆 (Pod の作り直し。pod.yaml:8)。効き始め: seat を作り直した後。
3. D1 + D2。D1 を先に入れる。
## Decision
Option 3。D1 は、運営の identity を seat の Pod に渡さないことを auth の判定 1 か所で決める (最小権限)。D2 は D1 と独立の hardening で、参加者の root に課題で要らない権限を持たせない。
- D1. /check-workspace は ADMIN_EMAILS を例外にしない。admin の identity は 403 とし、body に identity を出さない。metric auth_policy_checks_total{endpoint="workspace"} に新しい result `admin_refused` を足す (/check-participant の ok_admin は変えない)。spec の x-ctf-authz には新しい語 `self` (proven identity の seat == host の完全一致。admin の上書きは無い) を足し、AuthzIdentitySources で proven に分類する。self-or-admin は scoreboard で使い続ける。
- D2. challenge コンテナに、コンテナ単位の securityContext として capabilities.drop: ["ALL"] と、監査で決めた最小の add を置く。add に入れてはならない集合 (禁止集合) を S2 の PR で定め、V4 / V5 で固定する。seccompProfile はコンテナ側に書かず、Pod レベルからの継承のままにする (conventions の SecurityContext 節の 3 経路に触れない)。runAsUser と allowPrivilegeEscalation は変えない (realism。これは別の判断)。
- D3. 段階: S1 = D1 / D4 (app + platform の verify)。S2 = D2 (content-engineer の監査と全課題の通しの後に chart を変える。merge の条件は V4〜V6)。
- D4. 運営が seat の中を見る・打つ経路は kubectl exec (§6.7 の汚染確認つき) だけにする。ブラウザで seat host を開くと 403 になる (login ループにはならない)。
## Consequences
- 諦めるもの: 運営がブラウザで参加者の Terminal を見る・打つ経路。サポートは kubectl exec か、参加者による画面共有で行う。
- ADR-0034 を 3 か所で限定 supersede する: D7 の I8 の文言のうち ADMIN_EMAILS の範囲「任意の workspace と運営 route」、D3 の /check-workspace についての「`ADMIN_EMAILS` なら 200 (現行どおり)」と「admin は現行どおり透過する」(/check-participant の透過は不変)、V9 の /check-workspace についての「admin は 200」。ADR-0034 の Status に navigational な 1 行を足す。
- I8 の文言を改訂する (V1 / V2 と同じ PR)。
- spec: auth-policy で self-or-admin のルートが 0 本、self が 1 本になる (internal/authpolicy/authz_test.go:148-150 の件数 pin も変える)。
- platform: verify-auth.sh に「admin の session で seat host が 403」を足し、v14 の stub を直す。operations.md と deploy-event-workspaces.sh のコメントも直す。適用の順序 (app を先に merge し、event の pin に S1 の SHA 以降を載せてから V3) と stand-up の手順は platform の runbook に置く。
- D2: Pod の securityContext は immutable なので、seat を作り直したときに効く。監査で要る capability を取りこぼすと課題が壊れる。
- runbook: §6.7 の手順が、運営が seat の中で操作する唯一の経路になる。stand-up の smoke に「admin で seat host を開くと 403」を入れる。
## Signposts
1. event 中に `admin_refused` が繰り返し増える (運営がブラウザの経路を必要としている) → seat の Pod を経由しない、運営向けの読み取り専用の観察経路を ADR で設計する。D1 は戻さない。
2. seat の Pod (workspace の upstream) に、参加者本人以外の要求を通す変更が入る (共有 seat、運営用の sidecar、ADR-0048 Signpost 5 の 2 つ目の WS 消費者) → D1 の前提 (Pod に届くのは本人の要求だけ) を見直す。
3. S2 の監査で外した capability を必要とする課題が出てくる → 課題の側を変えるか、ADR で決める。禁止集合を緩めない。
4. ingress controller を置き換える (Gateway API。ADR-0048 Signpost 4) → seat への route の認可が /check-workspace の判定を必ず通ることを、V3 で確かめ直す。
## Verification
- V1 (make test、S1): identity_v9_test.go の "admin on any workspace" の行 (:65) と server_test.go:195 を 403 に反転する。body に identity が出ないこと、`admin_refused` が 1 増えることを固定する。mutation: 分岐を 200 に戻すと赤になる (PR 本文に実出力)。
- V2 (make test、S1): `self` が AuthzIdentitySources で proven に分類されること、/check-workspace が `self` であること、spec の x-ctf-authz との parity (I14)、件数の pin (self 1 本、self-or-admin 0 本)、TestAuthz_EveryProvenRouteRejectsUnproven が self にも効くこと。
- V3 (platform、live の検査。stand-up の smoke): verify-auth.sh の V14 に「admin の session で seat host の / が 403」を足す。test-verify-auth-v14.sh の stub は admin → 403 にし、旧挙動 (200) の stub で赤になる mutation を足す。
- V4 (S2。chart-lint か make test。required check に載せる): ctf-user の描画で、challenge の capabilities.drop に ALL があること、add が監査で決めた集合の部分集合であること、禁止集合が含まれないこと、コンテナ側に seccompProfile が書かれていないこと。全コンテナ (initContainer を含む) で、add に禁止集合が無いこと。mutation: drop を外す / add に禁止集合の 1 つを足す / challenge の securityContext を消す、のそれぞれで赤になる。
- V5 (S2、deploy 時に fail-closed): charts/ctf-user/assert-flag-isolation.sh (deploy-user.sh から呼ばれる) で、challenge の PID 1 の CapEff に禁止集合のビットが立っていないことを確かめる。runtime の既定が chart の想定と違う場合を捕まえるため。
- V6 (S2 の merge 条件、手動): content-engineer の監査結果 (課題ごとに要る capability) と、sre が colima で全課題の trigger / evade / submit を通した結果を PR 本文に貼る。
- I8 の改訂は V1 / V2 と同じ PR に入れる。D2 の Hard Invariant への昇格は、V4 / V5 が main に入った後に別に判断する (それまでは conventions の SecurityContext 節に書くだけ)。
## Advice
- security-engineer (2026-10-30): 対策は (i) /check-workspace を admin に通さない、(ii) challenge の capability を最小化する、(iii) 運用規律 (検知的な統制にしかならない)。(i) の判断は architect に委ねる。公開文面は最小権限と hardening の記述に限る (review-5x 95 R1)。
- architect (2026-10-30): (i) と (ii) の両方を入れ、(i) を先にする。(ii) は drop ALL + 監査した add とし、禁止集合を render test と deploy 時の assert で固定する。
