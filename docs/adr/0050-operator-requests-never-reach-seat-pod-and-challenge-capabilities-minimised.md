# ADR-0050: 運営 (ADMIN_EMAILS) の要求は seat の Pod に渡さない (/check-workspace の admin 例外を外し I8 を締める)。challenge コンテナの capability は drop ALL + 監査した add にする
- Status: Proposed (段階制。S1 = D1、S2 = D2。S1 の実装 PR の merge で Accepted にし、D2 は S2 の merge まで効力を持たない)
- Date / Deciders: 2026-10-30 / VP + architect (起草) + security-engineer (platform#301)。運営の導線が変わるので CEO に報告する
- 関連: platform#301 (private。詳細はそこ)、ADR-0034 (D7 の I8 の文言の一部を限定 supersede)、ADR-0049、ADR-0048、conventions I8 / SecurityContext 節、platform operations.md §6.7
## Context
- C1. I8 (conventions の Hard Invariants) と ADR-0034 D7 は、ADMIN_EMAILS を I8 の唯一の例外とし、その範囲を「任意の workspace と運営 route」としている。実装は internal/authpolicy/server.go:305-313 で、admin なら identity header をそのまま通して 200 を返す。spec では x-ctf-authz: self-or-admin (docs/openapi-auth-policy.yaml:174、表は :188)。
- C2. workspace の Ingress (charts/ctf-user/templates/ingress.yaml:32-34) は、auth subrequest が 200 を返した要求を、ブラウザが付けた cookie ごと seat の Pod に渡す。401 / 403 なら upstream には渡さない。session cookie の Domain は .<dnsSuffix> (ADR-0049 C1)。
- C3. seat の Pod は参加者が root で操作する環境 (UID 表、ttyd の shell は challenge コンテナに入る: pod.yaml:194-195)。challenge にはコンテナ単位の securityContext が無く (pod.yaml:276-)、runtime 既定の capability を持つ。本 ADR は「seat の Pod に届いたものは参加者の手の内にある」を設計の前提に置く (最小権限)。
- C4. 運営の seat 内操作は、誰が打っても参加者の採点に帰属する (operations.md §6.7)。ブラウザの ttyd から運営が打つ経路も同じ。トラブル対応は kubectl exec と §6.7 の汚染確認で足りる。kubectl exec は kube API と kubelet を通るので、運営のブラウザ session を Pod に持ち込まない。
- C5. platform の文書と stub は、運営が seat host を直接開く前提で書かれている: operations.md:127-129、deploy-event-workspaces.sh:3-4 / :478 のコメント、test-verify-auth-v14.sh:76 の stub (admin で ttyd が 200)。verify-auth.sh の本体は、admin が seat に入れるかを検査していない。
- C6. admin の portal は Terminal の iframe の host を admin の local part から作る (scoreboard/api/api.go:532-552。admin@<domain> は "admin" になる)。roster は ADMIN_EMAILS と seat の正規形の重なりを起動時に拒否する (internal/authpolicy/roster.go:194) ので、その host に seat は存在しない。
- C7. raw socket や追加の capability を使う課題は grep で見つからない (challenges/、images/challenge/Dockerfile:105-126、PARTICIPANT-HANDBOOK.md:64)。ATTACK-COVERAGE.md:35 は「追加 capability 無し」を防御境界の一部に数えている。既定の capability のうち課題に要るものは、まだ監査していない。
## Options
1. D1 だけ (workspace から admin 例外を外す)。変更点: auth-policy の分岐 1 つ、spec の authz 語、I8 の文言。コスト: 運営の導線が kubectl exec だけになる。リスク: 運営がブラウザで seat の画面を見られない。可逆 (ただし I8 の変更なので ADR が要る)。効き始め: auth-policy の image を更新した直後 (I5 により全 image)。
2. D2 だけ (challenge の capability を落とす)。変更点: pod.yaml の challenge に securityContext を置く。コスト: 課題の監査と、全課題の通し。リスク: 運営の要求が Pod に届くこと自体は変わらず、Pod 内の root から見える面もゼロにはならない (platform#301)。要る capability を取りこぼすと課題が壊れる。可逆 (Pod の作り直し。pod.yaml:8)。効き始め: seat を作り直した後。
3. D1 + D2。D1 を先に入れる。
(検討して外した案: ingress で Cookie を upstream に渡さない案は、ingress-nginx では snippet が必要で、platform の annotation 規律に反する (Signpost 4)。ingress から Pod までを TLS にする案は、証明書の運用が重く、D1 で届けなくすれば不要。)
## Decision
Option 3。D1 は「届けない」ことで、経路に依らず閉じる。D2 は D1 と独立に、参加者の root に要らない権限を持たせない。
- D1. /check-workspace は ADMIN_EMAILS を例外にしない。admin の identity は 403 とし、body に identity を出さない。metric auth_policy_checks_total{endpoint="workspace"} に新しい result `admin_refused` を足す (/check-participant の ok_admin は変えない)。spec の x-ctf-authz には新しい語 `self` (proven identity の seat == host の完全一致。admin の上書きは無い) を足し、AuthzIdentitySources で proven に分類する。self-or-admin は scoreboard で使い続ける。
- D2. challenge コンテナに、コンテナ単位の securityContext として capabilities.drop: ["ALL"] と、監査で決めた最小の add を置く。add には NET_RAW / NET_ADMIN / SYS_ADMIN / SYS_PTRACE / SYS_MODULE / BPF を入れない (禁止集合)。seccompProfile はコンテナ側に書かず、Pod レベルからの継承のままにする (conventions の SecurityContext 節の 3 経路に触れない)。runAsUser と allowPrivilegeEscalation は変えない (realism。これは別の判断)。
- D3. 段階: S1 = D1 (app + platform の verify)。S2 = D2 (content-engineer の監査の後に chart を変える)。S2 の PR は、S1 が event の pin に載った後に公開する。
- D4. 運営が seat の中を見る・打つ経路は kubectl exec (§6.7 の汚染確認つき) だけにする。ブラウザで seat host を開くと 403 になる (login ループにはならない)。
## Consequences
- 諦めるもの: 運営がブラウザで参加者の Terminal を見る・打つ経路。サポートは kubectl exec か、参加者による画面共有で行う。
- I8 の文言を改訂する。ADR-0034 D7 の「任意の workspace と」を限定 supersede する (ADR-0034 の Status に navigational な 1 行を足す)。
- spec: auth-policy で self-or-admin のルートが 0 本、self が 1 本になる (internal/authpolicy/authz_test.go:148-150 の件数 pin も変える)。
- platform: verify-auth.sh に「admin の session で seat host が 403」を足し、v14 の stub を直す。operations.md と deploy-event-workspaces.sh のコメントも直す。
- 移行: S1 を適用する前に運営が seat host を開いていた場合、その session cookie は期限まで有効のまま残る。cookie secret を回せば、ADR-0049 D4 の移行と 1 回の操作で両方を閉じられる (CEO の判断)。
- D2: Pod の securityContext は immutable なので、seat を作り直したときに効く。監査で要る capability を取りこぼすと課題が壊れる。
- runbook: §6.7 の手順が、運営が seat の中で操作する唯一の経路になる。stand-up の smoke に「admin で seat host を開くと 403」を入れる。
## Signposts
1. event 中に `admin_refused` が繰り返し増える (運営がブラウザの経路を必要としている) → seat の Pod を経由しない、運営向けの読み取り専用の観察経路を ADR で設計する。D1 は戻さない。
2. seat の Pod (workspace の upstream) に、参加者本人以外の要求や資格情報を通す変更が入る (共有 seat、運営用の sidecar、ADR-0048 Signpost 5 の 2 つ目の WS 消費者) → D1 の前提 (Pod に届くのは本人の要求だけ) を見直す。
3. 禁止集合の capability を必要とする課題が出てくる → 課題の側を変えるか、seat のネットワークを分ける設計を ADR で決める。禁止集合を緩めない。
4. ingress controller を置き換える (Gateway API。ADR-0048 Signpost 4) → seat への route で request の Cookie を落とす設定を、3 つ目の層として足す。
## Verification
- V1 (make test、S1): identity_v9_test.go の "admin on any workspace" の行 (:65) と server_test.go:195 を 403 に反転する。body に identity が出ないこと、`admin_refused` が 1 増えることを固定する。mutation: 分岐を 200 に戻すと赤になる (PR 本文に実出力)。
- V2 (make test、S1): `self` が AuthzIdentitySources で proven に分類されること、/check-workspace が `self` であること、spec の x-ctf-authz との parity (I14)、件数の pin (self 1 本、self-or-admin 0 本)、TestAuthz_EveryProvenRouteRejectsUnproven が self にも効くこと。
- V3 (platform、live の検査。stand-up の smoke): verify-auth.sh の V14 に「admin の session で seat host の / が 403」を足す。test-verify-auth-v14.sh の stub は admin → 403 にし、旧挙動 (200) の stub で赤になる mutation を足す。
- V4 (S2。chart-lint か make test。required check に載せる): ctf-user の描画で、challenge の capabilities.drop に ALL があること、add が監査で決めた集合の部分集合であること、禁止集合が含まれないこと、コンテナ側に seccompProfile が書かれていないこと。全コンテナ (initContainer を含む) で、add に禁止集合が無いこと。mutation: drop を外す / add に NET_RAW を足す / challenge の securityContext を消す、のそれぞれで赤になる。
- V5 (S2、deploy 時に fail-closed): charts/ctf-user/assert-flag-isolation.sh (deploy-user.sh から呼ばれる) で、challenge の PID 1 の CapEff に禁止集合のビットが立っていないことを確かめる。runtime の既定が chart の想定と違う場合を捕まえるため。
- V6 (S2 の merge 条件、手動): content-engineer の監査結果 (課題ごとに要る capability) と、sre が colima で全課題の trigger / evade / submit を通した結果を PR 本文に貼る。
- I8 の改訂は V1 / V2 と同じ PR に入れる。D2 の Hard Invariant への昇格は、V4 / V5 が main に入った後に別に判断する (それまでは conventions の SecurityContext 節に書くだけ)。
## Advice
- security-engineer (platform#301、2026-10-30): HIGH。対策案は (i) /check-workspace を admin に通さない、(ii) NET_RAW を drop する、(iii) 運用規律 (検知的な統制にしかならない)。(i) の判断は architect に委ねる。
- architect (2026-10-30): (i) と (ii) の両方を入れ、(i) を先にする。(ii) は drop ALL + 監査した add とし、禁止集合を render test と deploy 時の assert で固定する。公開リポには経路を書かない。
