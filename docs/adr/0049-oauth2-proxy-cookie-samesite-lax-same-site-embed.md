# ADR-0049: oauth2-proxy の session / CSRF cookie は全 env で SameSite=Lax にする (portal と seat の ttyd は cross-origin だが same-site。P23-4 の None は前提の取り違え)
- Status: Proposed (merge の条件: V1〜V3 が緑 (platform#303 の CI と、PR 本文に貼った V3 の実出力) + sre が V-a / V-b を通したこと (V-a は local colima。architect の yes, if: Advice)。Accepted の条件: app と platform の対 PR (app#556 / platform#303) が merge されたこと。V-c は Accepted 後の stand-up の go / no-go で、platform#300 と同じ)
- Date / Deciders: 2026-10-30 / VP + architect (起草) + security-engineer (platform#297 の再評価、2026-10-30)
- 関連: 実装 PR = platform#303 (app = app#556)、platform#297 (private。要求 2)、platform#300、ADR-0050 (Accepted 2026-10-30、app#557 = 9368993、platform#301)、ADR-0013 (単一 origin)、ADR-0034 (V16)、ADR-0044 (C7)、ADR-0047 (Signpost 2 / 3)、ADR-0048、`REFACTORING.md` P23 (workspace の :574 / :588。C8)、conventions の Cross-repo 契約表「Cookie SameSite」行
## Context
- C1. platform の oauth2-proxy は cookie_domains = .<dnsSuffix>、cookie_secure = true、cookie_samesite = "none" (helmfile/releases/oauth2-proxy/values.yaml.gotmpl:119-132)。CSRF cookie も同じ値を継ぐ (同 :125-127 のコメント。実測は V-a)。
- C2. P23-4 の前提 (契約表の Cookie 行、values の :121-124 のコメント) は「portal が seat の ttyd を cross-origin の iframe で埋め込むので、Lax だと iframe 内の要求に cookie が付かない」。SameSite は origin ではなく site (scheme + registrable domain) で判定する。appHost (app.<dnsSuffix>) と seat host (<seat>.<dnsSuffix>) は cross-origin だが、両方 https で <dnsSuffix> の配下にあるので same-site。iframe 内の文書要求と、その文書が開く WebSocket の handshake は、祖先 (top = appHost) まで same-site なので Lax の cookie が付く (security の再評価 §1。ブラウザでの実測は V-a / V-b)。前提は cross-origin と cross-site の取り違えで、None は機能面で何も得ていなかった。
- C3. PSL: security が 2026-10-30 に現行版 (VERSION 2026-10-28) で確かめた。prod / vm-prod の dnsSuffix は public suffix `dev` の直下の 1 ラベルで、それ自身が registrable domain。その配下に当たる規則は無い。local の `nip.io` は PSL に載っておらず、registrable domain は `nip.io`。
- C4. cookie_domains = .<dnsSuffix> が動いている以上、<dnsSuffix> は public suffix ではない (public suffix なら Domain 属性が拒否される)。appHost が <dnsSuffix> の配下にあることは callback が cookie を置く条件 (values :103 の redirect_url)。ただしこれを機械で検査している箇所は無い。
- C5. None が開いている面: cookie 付きの cross-site 要求による XS-Leak、将来の og の付け忘れや副作用のある GET、subresource 経由の sign_out。今わかっている悪用経路は無い (MEDIUM、多層防御の欠け)。現行の統制 (originguard、ingest / exfil の identity header 拒否と JSON 必須、portal / admin の frame-ancestors 'none' + XFO DENY、ttyd-proxy の FRAME_ANCESTORS、ADR-0048) は SameSite に依らず、same-site の別 origin にも効く。
- C6. #291 / #296 が入るまで ttyd-proxy は 'none' を返すので、本番の iframe はまだ使われていない (契約表「ttyd-proxy 配線」行)。今変えれば、iframe を使い始める前に属性が決まる。
- C7. Dex から appHost/oauth2/callback への戻りは same-site。Google (ADR-0034 S3) は cross-site の top-level GET 遷移で、Lax は cookie を付けるが Strict は付けない。
- C8. workspace の `REFACTORING.md` P23 は None を前提にしている。目標アーキテクチャ (:574) は「cookie `SameSite=Lax→None`+Secure が必須 (cross-origin iframe で oauth2 cookie を通す唯一の正攻法)」、CEO 決定 2 (:588) は「cookie SameSite=None (iframe auth 必須) 受容」(どちらも強調と記号を除いて引用)。CEO 決定 2 は None の受容であり、Lax に締めることは再度の受容を要しない。前提の「iframe auth 必須」は C2 のとおり誤りだった (cross-origin と cross-site の取り違え)。REFACTORING.md の側の ADR-0049 への案内は workspace の docs PR で足す (VP)。
## Options
1. None のまま ADR で受容する。変更点: 契約表の前提文の訂正だけ。コスト: 無し。リスク: C5 の面がインターネット上のどのサイトにも開いたまま残り、og の付け忘れが 1 つあれば全世界から悪用できる形になる。可逆。効き始め: 該当なし。
2. 全 env を Lax にする。変更点: platform の 1 値 + render 検査。コスト: 値 1 つと検査 3 つ、運用面は D4 の移行窓。リスク: same-site の前提が崩れた env では Terminal タブが login ループになる (fail-safe で、隔離は破れない)。可逆 (1 値、helmfile apply)。効き始め: 新しく発行される cookie から。
3. 全 env を Strict にする。変更点: 同じ 1 値。リスク: cross-site から始まる遷移 (Google の往復、チャットのリンクから portal を開く) で cookie が付かず、S3 のログインが壊れ、初回の表示が未ログインに見える。可逆。
(env ごとに分ける案 (prod は Lax、local は None) は、前提 (local だけ cross-site) が C3 で成り立たないので選択肢にしない。分けると local の検証が prod を代表しなくなる。)
## Decision
Option 2。iframe と WebSocket は same-site なので Lax で足り、None が開く cross-site の面だけを閉じる。Strict はログインの往復を壊す。
- D1. platform の values で cookie_samesite = "lax"、cookie_secure = true にし、全 env で同じ値にする (env ごとの上書きを作らない)。cookie_csrf_samesite は設定せず、同じ値を継がせる (V-a で実測する)。
- D2. same-site の前提は platform の義務とする。(a) appHost と seat host は <dnsSuffix> の配下に置き、scheme は https だけ。(b) <dnsSuffix> は public suffix ではなく、<dnsSuffix> とその配下に PSL の規則 (wildcard と例外を含む) が当たらない。(b) は env を足すときと dnsSuffix を変えるときに、PSL の現行版で確かめる (手順。機械化は Signpost 3)。
- D3. SameSite は境界ではなく多層防御の 1 層とする。Lax の下でも次を外さない。(1) originguard。og の外の書き込み 3 ルートの扱いもそのまま: submit は identity が body の自己申告なので SameSite に依らない。/internal/exfil/{cid} と /falco/events は proxy の identity header 付きの要求を 403、JSON 以外を 415 にする。(2) ttyd-proxy の FRAME_ANCESTORS と、portal / admin の frame-ancestors 'none' + XFO DENY。(3) ADR-0048。Lax は same-site の別 origin (他の seat、dex、auth. bridge) から cookie が付くことを止めないので、「Lax にしたから外せる」はこれらを外す理由にならない。
- D4. 発行済みの cookie は、再発行されるか期限が切れるまで旧属性のまま残る (oauth2-proxy の既定の期限は 168h。values に cookie_expire の指定は無い)。cookie secret を回して揃えるか、168h を待つかは CEO の運用判断とする。
- D5. 契約表の Cookie 行をこの ADR の前提で置き換え、P23-4 の前提を書いた古いコメントを同じ PR で直す。
## Consequences
- 諦めるもの: cross-site からの埋め込み。frame-ancestors はもともと appHost の 1 つだけ (ADR-0044) なので、実際に失う用途は無い。
- local の registrable domain は nip.io なので、local では Lax の効果が無い (インターネット上の他の nip.io のサイトとも same-site)。dev データだけなので受容する (LOW)。local の検証で確かめられるのは機能面 (iframe と WS に cookie が付く) だけで、cross-site の拒否 (V-d) は prod の形でしか確かめられない。
- 新たに守るもの: D2 (platform の義務) と D3 (外さない統制)。D2 (a) が崩れても fail-safe。
- 168h の移行窓を選ぶと、その間は None の cookie が残る。secret を回すなら、ADR-0050 の移行と同じ 1 回の操作で両方を揃えられる。
- ADR-0044 C7 (http の親では session が成り立たない) は、Secure と schemeful same-site によって Lax でも成り立つ。ADR-0044 の決定は変わらない。ADR-0048 も変わらない (その Consequences が予告したとおり、変わるのは Cookie 行の根拠の文だけ)。
- SameSite は盗まれた cookie には効かない。運営の identity を seat の Pod に渡さない統制は I8 / ADR-0050 (Accepted 2026-10-30、app#557 = 9368993。platform 側の verify は platform#302、event pin 後)。
- platform CLAUDE.md:250 の契約の要約は、CEO の PR が入るまで旧前提 (`SameSite=None`、platform を先に merge する順序) のまま残る (統治文書なので CEO の手)。置換の文面は platform#303 の本文に置く。期限は #291 / #296 で iframe が使われ始める前 (C6)、遅くとも platform#300 の go / no-go の前。旧 Cookie 行にあった「platform CLAUDE.md の前提条件の要約は platform#297 で揃える」の案内は、ここに移した。
- ADR-0047 Signpost 2 (Go 以外の 3 つ目の写し。例に helm の regexMatch guard と platform 側の検査を挙げる) は、形の上では V2 の 2 つの正規表現に当たるが、発火していない。どちらも `dnsname.Pattern` と同じ集合を受ける写しではなく、その上位集合の構造検査で、文法との一致を要求しない (一致を検査する相手が無いので、ADR-0045 の型の data file にする理由も無い)。文法の強制は ADR-0047 の経路 (deploy-user.sh の --dns-suffix / --app-host) が持ち、env file の appHost / dnsSuffix がそこに届くのは platform#292 から (ADR-0046 D4 / D5)。Signpost 3 (別の host 文法の消費者) も発火していない (受ける集合を広げも分けもしない)。follow-up (platform#304): platform#292 の後に、check (4) が appHost / dnsSuffix を frame-ancestors-grammar.sh 経由で、表の 1 行目の pattern でも検査する。これが入れば V2 の構造検査は、文法の検査の手前の早期 fail になる。
- 旧行名「Cookie `SameSite=None`+Secure embed 契約」(と conventions の行番号) への参照 (ADR-0023:307-308、ADR-0031:30、ADR-0034:90 / :160、ADR-0044 C7、ADR-0048 の関連と C3) は当時の記述で、本文は書き換えない。ADR-0044 C7 と ADR-0048 の 2 箇所には、ADR-0049 への navigational な 1 句だけを足した。
- runbook: stand-up の smoke (platform#300) に V-a の観点を入れる。env を足す手順と dnsSuffix を変える手順に PSL の確認を入れる (platform)。
## Signposts
1. cross-site の埋め込み (appHost 以外の site から portal や seat を使う、外部の学習基盤への埋め込み) が必要になる → None に戻す ADR を書く。その ADR では D3 の 3 層と C5 の面を受容の条件として明示する。
2. PSL に <dnsSuffix> かその配下に当たる規則が入る、または dnsSuffix を変える / env を足す → D2 (b) をやり直す。崩れていれば V-a で Terminal タブの login ループとして見える。
3. PSL の確認を手作業で 2 回以上やることになる (env の追加が続く、P20 の substrate) → 版を記録した PSL の写しを持つ preflight の advisory を足す (写しの鮮度管理も含めて)。
4. Google (ADR-0034 V16) か Dex の往復が Lax で壊れる (callback が CSRF cookie を受け取れず login ループになる) → 往復の形を実測する。原因が SameSite ならこの ADR を見直す。Strict の方向には変えない。
## Verification
- V1 (platform。CI は ci.yaml:197 の scripts/test-oauth2-proxy-render.sh、preflight は check-roster.sh:91 から): scripts/check-oauth2-proxy-render.sh が描画結果に `cookie_samesite = "lax"` と `cookie_secure = true` があることを要求する。cookie_csrf_samesite が描画されていれば、それも "lax" であることを要求する。対象は local / prod / vm-prod の全 env (今の --env は prod|vm-prod だけ: :15)。
- V2 (platform、描画時の fail。行番号は platform#303 の時点): values の template (values.yaml.gotmpl:102-105) が、appHost が "." + dnsSuffix で終わらない描画を fail にする (空の appHost も fail。redirect_url が成り立たないため)。check-oauth2-proxy-render.sh の (4) (:141-155) は、描画結果の redirect_url と cookie_domains で同じ前提を別実装で見る。values の `$hostRe` (:102) と (4) の正規表現 (:152) は、label 境界と scheme / port / path を拒否するための構造検査で、host の文法の権威ではない (`dnsname.Pattern` の上位集合: label の長さ 63 の上限を持たない。文法の正典は ADR-0047 のまま)。`default` env (default.yaml.gotmpl:121 の appHost = "") で oauth2-proxy を描く経路は helmfile に実在する (helmfile.yaml.gotmpl:38-40) が、deploy 対象ではない (kubeContext を持たず、Usage の :7-9 は local / prod)。描けば roster guard (values :49-51。local 以外は CTF_ROSTER_FILE が必須) で止まり、roster を渡しても V2 で止まる。これは意図どおりの fail とする。
- V3 (mutation。test-oauth2-proxy-render.sh に恒久化し、PR 本文に実出力を貼る): (a) "none" に戻す、(b) "strict"、(c) cookie_secure = false、(d) appHost が dnsSuffix の外にある fixture env、(e) 文字列としては dnsSuffix で終わるがラベル境界が無い appHost (前に "." が無い)。それぞれで FAIL になること。
- V-a〜V-e (手動。security の再評価 §2 の手順): V-a は local colima (sre)、V-b は Chrome / Firefox / Safari、V-c は prod と同じ edge 経路 (platform#300 の go / no-go)、V-d は無関係なサイトから出した要求に cookie が付かないこと、V-e は S3 を入れるときの Google の往復 (ADR-0034 V16)。
- V-f (計画。実装は別 issue): ブラウザ e2e (ADR-0031) で、same-site の 2 host の間の iframe と WS に Lax の cookie が付くことを固定する。入れば V-a / V-b の手作業は edge 経路の確認だけになる。
- D2 (b) の PSL 確認は機械化していない (Signpost 3)。このため本 ADR は Hard Invariant に昇格させない。
## Advice
- security-engineer (platform#297 の再評価、2026-10-30): PASS with conditions。全 env を Lax にし、(1)(2)(3) と header 拒否は残す。env 分割と None の受容は不採用。render 検査で固定し、短い ADR を書く。ADR-0048 に /check-workspace の Signpost を足す。
- architect (2026-10-30): yes, if = 全 env 共通、V1〜V3 を同じ PR で緑にする、V2 は全 env の描画に効かせる、D3 の文面を契約表に入れる、merge 前に V-a / V-b。
- review-5x 94 (T3、2026-10-30、VP 採用): R4#1 / R1#2 / R2#3 / R4#6 (ADR-0050 の句を merge 順序に依らず真になる形に、契約の面を D1 / D2 / V1・V2 に絞る)、R3#1 / R1#3 / R4#4 (platform CLAUDE.md:250 の旧前提と期限)、R4#3 (V2 の正規表現は文法の写しではない、ADR-0047 Signpost 2 / 3 の評価、follow-up)、R4#5 (P23 の CEO 決定 2: C8)、R4#7 (Status の merge の条件と Accepted の条件を分ける)、R2#4 (`default` env)、R3#2 / R5#6 (旧行名への参照は履歴)、R5#3 (実装 PR の番号)。いずれもこの ADR と契約表に反映した。
