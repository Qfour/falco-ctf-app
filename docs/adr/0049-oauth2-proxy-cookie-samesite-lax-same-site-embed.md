# ADR-0049: oauth2-proxy の session / CSRF cookie は全 env で SameSite=Lax にする (portal と seat の ttyd は cross-origin だが same-site。P23-4 の None は前提の取り違え)
- Status: Proposed (Accepted の条件: app と platform の同時 PR が merge され、V1〜V3 が緑で、sre が V-a / V-b を local colima で通したこと。V-c は Accepted 後の stand-up の go / no-go で、platform#300 と同じ)
- Date / Deciders: 2026-10-30 / VP + architect (起草) + security-engineer (platform#297 の再評価、2026-10-30)
- 関連: platform#297 (private。要求 2)、platform#300、platform#301 (ADR-0050)、ADR-0013 (単一 origin)、ADR-0034 (V16)、ADR-0044 (C7)、ADR-0048、conventions の Cross-repo 契約表「Cookie SameSite」行
## Context
- C1. platform の oauth2-proxy は cookie_domains = .<dnsSuffix>、cookie_secure = true、cookie_samesite = "none" (helmfile/releases/oauth2-proxy/values.yaml.gotmpl:119-132)。CSRF cookie も同じ値を継ぐ (同 :125-127 のコメント。実測は V-a)。
- C2. P23-4 の前提 (契約表の Cookie 行、values の :121-124 のコメント) は「portal が seat の ttyd を cross-origin の iframe で埋め込むので、Lax だと iframe 内の要求に cookie が付かない」。SameSite は origin ではなく site (scheme + registrable domain) で判定する。appHost (app.<dnsSuffix>) と seat host (<seat>.<dnsSuffix>) は cross-origin だが、両方 https で <dnsSuffix> の配下にあるので same-site。iframe 内の文書要求と、その文書が開く WebSocket の handshake は、祖先 (top = appHost) まで same-site なので Lax の cookie が付く (security の再評価 §1。ブラウザでの実測は V-a / V-b)。前提は cross-origin と cross-site の取り違えで、None は機能面で何も得ていなかった。
- C3. PSL: security が 2026-10-30 に現行版 (VERSION 2026-10-28) で確かめた。prod / vm-prod の dnsSuffix は public suffix `dev` の直下の 1 ラベルで、それ自身が registrable domain。その配下に当たる規則は無い。local の `nip.io` は PSL に載っておらず、registrable domain は `nip.io`。
- C4. cookie_domains = .<dnsSuffix> が動いている以上、<dnsSuffix> は public suffix ではない (public suffix なら Domain 属性が拒否される)。appHost が <dnsSuffix> の配下にあることは callback が cookie を置く条件 (values :103 の redirect_url)。ただしこれを機械で検査している箇所は無い。
- C5. None が開いている面: cookie 付きの cross-site 要求による XS-Leak、将来の og の付け忘れや副作用のある GET、subresource 経由の sign_out。今わかっている悪用経路は無い (MEDIUM、多層防御の欠け)。現行の統制 (originguard、ingest / exfil の identity header 拒否と JSON 必須、portal / admin の frame-ancestors 'none' + XFO DENY、ttyd-proxy の FRAME_ANCESTORS、ADR-0048) は SameSite に依らず、same-site の別 origin にも効く。
- C6. #291 / #296 が入るまで ttyd-proxy は 'none' を返すので、本番の iframe はまだ使われていない (契約表「ttyd-proxy 配線」行)。今変えれば、iframe を使い始める前に属性が決まる。
- C7. Dex から appHost/oauth2/callback への戻りは same-site。Google (ADR-0034 S3) は cross-site の top-level GET 遷移で、Lax は cookie を付けるが Strict は付けない。
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
- runbook: stand-up の smoke (platform#300) に V-a の観点を入れる。env を足す手順と dnsSuffix を変える手順に PSL の確認を入れる (platform)。
## Signposts
1. cross-site の埋め込み (appHost 以外の site から portal や seat を使う、外部の学習基盤への埋め込み) が必要になる → None に戻す ADR を書く。その ADR では D3 の 3 層と C5 の面を受容の条件として明示する。
2. PSL に <dnsSuffix> かその配下に当たる規則が入る、または dnsSuffix を変える / env を足す → D2 (b) をやり直す。崩れていれば V-a で Terminal タブの login ループとして見える。
3. PSL の確認を手作業で 2 回以上やることになる (env の追加が続く、P20 の substrate) → 版を記録した PSL の写しを持つ preflight の advisory を足す (写しの鮮度管理も含めて)。
4. Google (ADR-0034 V16) か Dex の往復が Lax で壊れる (callback が CSRF cookie を受け取れず login ループになる) → 往復の形を実測する。原因が SameSite ならこの ADR を見直す。Strict の方向には変えない。
## Verification
- V1 (platform。CI は ci.yaml:197 の scripts/test-oauth2-proxy-render.sh、preflight は check-roster.sh:91 から): scripts/check-oauth2-proxy-render.sh が描画結果に `cookie_samesite = "lax"` と `cookie_secure = true` があることを要求する。cookie_csrf_samesite が描画されていれば、それも "lax" であることを要求する。対象は local / prod / vm-prod の全 env (今の --env は prod|vm-prod だけ: :15)。
- V2 (platform、描画時の fail): values の template が、appHost が "." + dnsSuffix で終わらない描画を fail にする (空の appHost も fail。redirect_url が成り立たないため。default.yaml.gotmpl:121 の空の値のまま oauth2-proxy を描く経路が無いことを PR で確かめ、もしあれば扱いをこの ADR に追記する)。
- V3 (mutation。test-oauth2-proxy-render.sh に恒久化し、PR 本文に実出力を貼る): (a) "none" に戻す、(b) "strict"、(c) cookie_secure = false、(d) appHost が dnsSuffix の外にある fixture env、(e) 文字列としては dnsSuffix で終わるがラベル境界が無い appHost (前に "." が無い)。それぞれで FAIL になること。
- V-a〜V-e (手動。security の再評価 §2 の手順): V-a は local colima (sre)、V-b は Chrome / Firefox / Safari、V-c は prod と同じ edge 経路 (platform#300 の go / no-go)、V-d は無関係なサイトから出した要求に cookie が付かないこと、V-e は S3 を入れるときの Google の往復 (ADR-0034 V16)。
- V-f (計画。実装は別 issue): ブラウザ e2e (ADR-0031) で、same-site の 2 host の間の iframe と WS に Lax の cookie が付くことを固定する。入れば V-a / V-b の手作業は edge 経路の確認だけになる。
- D2 (b) の PSL 確認は機械化していない (Signpost 3)。このため本 ADR は Hard Invariant に昇格させない。
## Advice
- security-engineer (platform#297 の再評価、2026-10-30): PASS with conditions。全 env を Lax にし、(1)(2)(3) と header 拒否は残す。env 分割と None の受容は不採用。render 検査で固定し、短い ADR を書く。ADR-0048 に /check-workspace の Signpost を足す。
- architect (2026-10-30): yes, if = 全 env 共通、V1〜V3 を同じ PR で緑にする、V2 は全 env の描画に効かせる、D3 の文面を契約表に入れる、merge 前に V-a / V-b。
