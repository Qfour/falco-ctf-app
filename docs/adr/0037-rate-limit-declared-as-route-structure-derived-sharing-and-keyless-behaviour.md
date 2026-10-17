# ADR-0037: rate-limit の宣言を Route の構造 (bucket と in-flight 上限) として Go に置き、spec の `x-ctf-rate-limit` は operation ごとにその正準形を写して等価検査し、共有・キー種別・数値の強制は `Routes()` から導いたテストで確かめる (ADR-0005 Decision 2(b) と ADR-0009 V3b の rate-limit の部分を限定 supersede)

- Status: **Proposed** (2026-10-17 起草)。Accepted 化は VP が S2 の merge と同じセッションの docs PR で行う (workspace `ORGANIZATION.md` §5 の Class-2 条件 (f))。HTTP の挙動を変えず、クロスリポ契約・新 image・新サービス・Dockerfile に触れないので CEO 判断を要さない。D7 の I14 追記は architect 合意 + VP 承認。実装は Proposed のまま始めてよい。
- Date / Deciders: 2026-10-17 / VP (承認) + architect (起草・I14 追記の同意) + security-engineer (S1a・S2・#397 のレビュー) / 実装: software-engineer (S1a・S2)、qa-engineer (S1b の engine と V8 の変異 test)
- Supersedes (限定): ADR-0005 Decision 2(b) のうち `x-ctf-rate-limit` の値の定義 (「the bucket applied, or "none"」= 散文: `docs/openapi-scoreboard.yaml:50`、`0005:153-157`) と V2 の必須フィールド `RateLimit` の型 (`0005:346-347`)。ADR-0009 V3b のうち `x-ctf-rate-limit` の文字列 parity (`0009:186-194`)。ADR-0005 / 0009 の他の節と、V3b の `x-ctf-audience` / `x-ctf-authz` は変えない。両 ADR の本文は書き換えず、Status ブロックと索引に導線を足す (`docs/adr/README.md:70-78` の例外「navigational なポインタの追記」)。
- 関連: Issue #390 (発注元。#379 review-5x R4#2)、#389 / PR #395 (`26a38d9` で main に入った。S1b の土台)、#397 (board の 2 bucket)、#393 (authz の identity の出所の分類)、#341 (detect の in-flight を identity ごとに)、#366 (eviction。範囲外)、app#315・app#328・app#359、ADR-0023 (C2 の表)、ADR-0028 (Signpost 2′)、I14。フェーズ: 非該当
- 読み方: app は origin/main `947b5b8` (PR #395 = `26a38d9` と #381 を含む)、platform は origin/main `e126fff`。`conventions` は `.claude/rules/falco-ctf-app-conventions.md`、`0005:N` などは `docs/adr/` の各 ADR、`api.go` は `internal/scoreboard/api/api.go`。

## Context

- **C1 limiter は 4 package に 9 個と、in-flight 上限が 1 個ある (応答に効かないログの間引き `ingest.go:175` は数えない)。宣言は自由文の文字列 1 本** (`internal/apispec/route.go:206-211`)。

  | binary / package | 識別子 (metric label か key の接頭辞) | キー | rate / burst | 組み立て | 配線 | route |
  |---|---|---|---|---|---|---|
  | scoreboard / api | `submit` | client IP (`ratelimit.ClientIP`) | 1/s / 10 | `api.go:359` | `:511` | submit (`:602-606`) |
  | 〃 | `participant_action` | identity。header 無しは limiter が 403 (strict) | 1/s / 10 | `:360` | `:523` | steps/check・hints・reset-dirty・profile (`:670-725`) |
  | 〃 | `detect` | identity (strict) | 1/s / 10 | `:361` | `:524` | submit-detect (`:627-631`) |
  | 〃 | in-flight (global) | — | 5 (`DefaultDetectInflightCap`、`:303`) | `:345-352` | handler の中 (`:1413-1422`) | submit-detect |
  | 〃 | `board_post` | identity (strict。header 無しは limiter が 403)。`Handler.boardPostLimiter` = `MiddlewareStrict(boardPostBucket, IdentityKeyed)` (#397 (a)、app#417) | 1/10s / 3 | `New` の `boardPostLimiter` | `Routes()` の `boardPostMW` | threads・messages |
  | 〃 | `board_like` | 〃 (`Handler.boardLikeLimiter`、`boardLikeMW`) | 1/s / 10 | `New` の `boardLikeLimiter` | `Routes()` の `boardLikeMW` | like・unlike |
  | scoreboard / view | `csp_report` | client IP | 5/s / 50 | `internal/scoreboard/view/csp_report.go:315-317` | `view.go:285` | csp-report |
  | scoreboard / ingest | (observation / scoring) | event の namespace (参加者) | 20/s / 100 → 429、100/s / 400 → taint して 200 | `internal/scoreboard/ingest/ingest.go:106-111, 172-176` | handler の中 | falco/events |
  | collector | (無名) | RemoteAddr | 1/s / 10 | `internal/collector/collector.go:101` | `:142` | submit・exfil (`:162-180`)。**2 route が 1 つの limiter を共有する** |

  in-flight 上限を本番で変える経路は無い (`cmd/scoreboard/main.go:272` は `InflightCap` を設定しない)。
- **C2 共有を散文で列挙しているので、bucket を 1 つ足すと他の route の文字列を書き直す。** 他の route を名指しする文字列は Go に 9 本 (`api.go:630,673,683,710,724,761,772,785,796`)、spec に 9 本 (`docs/openapi-scoreboard.yaml:587,850,917,986,1056,1162,1276,1334,1387`)。
- **C3 列挙は既に不完全で、1 か所は共有そのものが書かれていない。** submit-detect と action の 4 route の文字列は、board の 2 bucket と csp_report に触れない。collector の submit と exfil は 1 つの limiter を共有する (`collector.go:142,168,179`) が、spec の文字列 (`docs/openapi-collector.yaml:90,167`) は共有を書かない。
- **C4 宣言と実際の limiter の対応は、一部しか検査されていない。** `route.go:158-180` 自身がそう書いており、「Signposted, not fixed, by ADR-0005」(`:169-170`) は誤り (ADR-0005 の Signposts `0005:307-322` に rate-limit は無い)。V3b が比べるのは文字列どうしだけ (`internal/apispec/specparity/parity.go:111-133`。配線は `internal/scoreboard/apispec_parity_test.go:310`・`internal/collector/apispec_parity_test.go:177`・`internal/authpolicy/apispec_parity_test.go:128`)。PR #395 は identity の 4 bucket と submit の per-IP bucket を挙動で確かめたが、文字列から導けないので bucket の表を手で持つ (`internal/scoreboard/identity_bucket_test.go:29-30, 57-91`)。新しい bucket は表に行を足さないと赤になる。`route.go:178-180` が未検査として挙げるのは csp-report・ingest・submit の rate。ほかに、in-flight 上限を叩く test は無い (`*_test.go` で in-flight に触れるのは `origin_guard_test.go:523` のコメントだけ)。collector の rate-limit の test 3 本は submit だけを叩き (`internal/collector/collector_test.go:247,283,405`)、exfil の limit と共有は誰も見ていない。
- **C5 手で持った集約 (共有の一覧・数値の表・挙動の説明) は、すべて実装から離れている。**
  - `internal/scoreboard/ratelimit/metrics.go:11-12`: caller label の例に、もう無い `display_name` と `questions`。
  - ADR-0023 C2 (`0023:64-65`): ADR-0034 S1 で消えた display-name と、board に置き換わった questions の route を挙げる。board の client-IP fallback (`api.go:881`) は無い。
  - platform `docs/operations.md:962-964`: `/falco/events` を「per-IP 100 req/s, burst 200」と書く。実体は参加者ごとの 2 bucket (`ingest.go:106-111`)。
  - `internal/scoreboard/ratelimit/ratelimit.go:1-5`: 「primary controls are per-IP ingress-nginx rate limits」。ingress-nginx の rate-limit 設定は両リポに無い (`git grep limit-rps` は 0 件。edge の rate-limit は Cloudflare の手作業: platform `docs/prod-deploy.md:441-444`)。
  - `api.go:525-534, 870-874` は「board の route はどれも先に requireAuthenticated を通るので fallback は本番で発火しないはず」と書くが、limiter は handler の外側で先に動く。header 無しは IP の token を使ってから handler で 403 になる (#395 `identity_bucket_test.go:72-75`)。
  - spec の board の書き込み 4 route の 403 (`docs/openapi-scoreboard.yaml:1205,1305,1353,1403`「missing/blank identity header」) は、client IP の burst までしか真でない。それを越えた header 無しは 429。
- **C6 制約。**
  - `route.go` は collector と auth-policy の image に 1 ファイルだけ COPY される (`collector/Dockerfile:55`、`auth-policy/Dockerfile:65`)。`internal/apispec` の non-test file は `route.go` だけで、stdlib しか import しない (`internal/apispec/dependency_boundary_test.go:254`)。required check の image build は scoreboard と auth-policy だけで、collector は入らない (2026-10-17 `gh api repos/Qfour/falco-ctf-app/branches/main/protection`)。collector だけが壊れる分け方は required check をすり抜ける。
  - ADR-0005: extension は全 operation で必須、欠落は fail、既定値を持たない (`0005:153-157, 236-237`)。除外リストを持たない。Decision / Verification は凍結 (`0005:7`)。middleware の宣言 (origin-guard) は `Routes()` を正とし、spec をそれと機械比較する (`0005:223-237, 340-352`)。spec → code の生成は型だけ (`0005:397-402`)。`regen-openapi` も同じ規則 (`.claude/skills/regen-openapi/SKILL.md:22-27`)。
  - 拘束力のある検査は `make test` (= required の `test / go-test`) だけ。`gen-diff-check` は required でない (`.github/workflows/checks.yaml:98-133`)。
  - scoreboard の spec は 2,961 行。ADR-0028 の Signpost 2′ は 3,000 行で分割を許す (`0028:95-104`)。
  - metric の label は ADR-0023 Signpost 2 の query が使い、spec の description も名指す (`docs/openapi-scoreboard.yaml:603`) ので動かさない: `ClientIPSourceTotal{caller}` の `submit`・`csp_report`、`IdentityRequestsTotal{bucket}` の `participant_action`・`detect` (`api.go:164-172, 511`、`view.go:285`)。
  - ADR-0009 は V3b を I14 の外とした (`0009:13-17`)。
- **C7 `x-ctf-rate-limit` の読み手 (両リポの git grep)**: app は 3 service の parity test と、#395 の文字列による分類 (`internal/scoreboard/origin_guard_test.go:472-474`、`identity_bucket_test.go:447-457`) だけ。production code・docs-site・scripts・charts は読まない。platform は 0 件 (operations.md の表は数値を手で写したもので、文字列は読まない)。

## Options (Alternatives)

### O1 (推奨). 宣言の権威は Go。spec は operation ごとに正準形を写して等価検査する。集約はどこにも書かない
- 変更点: Route が bucket と in-flight 上限を構造で持ち、limiter はその値から作る。spec の `x-ctf-rate-limit` はその route の宣言の正準形 (全 field)。共有の一覧は書かず、test が `Routes()` から導く。
- コスト: 運用 = bucket の数値を変える PR は member の operation の行をすべて直す (今は最大 4 行。赤い test が正しい値を出す)。認知 = 「`x-ctf-rate-limit` は `Route` の写し」の 1 規則 (他の `x-ctf-*` と同じ)。依存・image = 増えない (`route.go` は stdlib の `time` を足すだけ。`ratelimit` → `apispec` の import は collector の COPY の内側)。
- リスクと可逆性: 低。HTTP の挙動は変えない (#397 は別の判断)。spec の形式の変更は、読み手が app の test だけなので 1 PR で戻せる。O3 へは「集約を生成物として足す」だけで移れる (operation の値の形は変わらない)。
- 効き始める閾値: 最初の PR から。数値・共有・キー種別を変えた PR が、spec の等価検査と挙動の test の両方で赤くなる。

### O2. spec を権威にして、Go の bucket の表を spec から生成する
- 変更点: spec の root に bucket の定義表 (手書き)、operation は bucket 名。`cmd/gen-ratelimit` が service ごとの Go を生成し、limiter はその値から作る。所属は spec と Go の両方に手で書いて parity。
- コスト: generator と `Dockerfile.gen-ratelimit` (Dockerfile は Class-2 の面)。生成した Go の鮮度を `make test` に別に持つ (`gen-diff-check` は required でない)。所属は 2 か所に手書きのまま。
- リスクと可逆性: rate-limit だけが「spec が権威」の `x-ctf-*` になり、ADR-0005 / regen-openapi の分類 (middleware の宣言は `Routes()` が正) と食い違う特例になる。runtime の値が YAML → 生成 Go → limiter の 2 段を通る。可逆性は中 (生成物の撤去が要る)。
- 効き始める閾値: spec を読む外部の道具が rate-limit の値を設定として使い始めたとき (Signpost 1)。

### O3. 宣言の権威は Go。bucket ごとの集約表 (定義 + members) を spec の root か別 file に描画し、operation は bucket 名だけ
- 変更点: operation は `[participant_action]`。root の `x-ctf-rate-limits` (または `docs/` の別 file) を writer が `Routes()` から生成し、`make test` が golden と比べる。
- コスト: 所属が変わるたびに集約も変わるので writer が必須で、Docker の中で回すための Dockerfile (Class-2 の面) が要る。spec の中に機械だけが書く領域ができる (別 file にすると operation の名前の参照先が spec の外に出る)。scoreboard の spec は約 70 行増えて 3,000 行を越える (Signpost 2′)。
- リスクと可逆性: 集約を 2 つ目の表現として保存する。C5 で実装から離れたものはすべて集約で、O3 はそれを「生成で守る」形に替えるだけ。保存する理由 (読み手の便) は grep と test の出力で足りる。可逆性は高い (表を消せば O1)。
- 効き始める閾値: 共有の一覧を人が組み立てて査定することが繰り返されたとき、または 1 bucket の member が 5 を越えたとき (Signpost 4)。

## Decision

**O1 を採る。** 理由: 宣言と強制を同じ値にできるのは limiter を組み立てる側に権威を置いたときだけで、C5 のとおり実装から離れたのは毎回、手で持った集約だった — だから spec には operation ごとの正準形だけを写して機械で比べ、集約は保存せず導く。

### D1. 宣言の形 (`internal/apispec/route.go` に置く。stdlib だけ、1 ファイル)

形の説明 (擬似コード。型名と API は software-engineer が決める):

```
Bucket   { Name; Key KeyKind; Rate {Tokens int; Per time.Duration}; Burst int; Applies; OnLimit }
Inflight { Name; Scope InflightScope; Max int; OnLimit }
Route.RateLimit = 明示の none | 1 つ以上の Bucket / Inflight
```

- **zero 値は「未宣言」で fail**。none の既定値にしない (ADR-0005 の「欠落は fail」の Go 側)。none は明示の構築子でだけ作る。
- **語彙 (閉じた集合。`route.go` だけが定義する。どの宣言も使わない語は置かない)**:
  - `KeyKind`: `ip` (`ratelimit.ClientIP`: CF-Connecting-IP → X-Forwarded-For の左端 → RemoteAddr。ingress / Cloudflare か collector の後ろでだけ信用できる、ADR-0023) / `remote-addr` (TCP の相手だけを見て転送ヘッダを見ない。collector) / `identity-strict` (`X-Auth-Request-Email`。header 無しは limiter が 403 を返し、token を使わない) / `participant` (event の namespace。handler の中で効く。ingest)
  - `Applies`: `all` / `observation-rules` (どの課題も forbid も expect もしない rule) / `scoring-rules` (いずれかの課題が forbid か expect する rule)
  - `OnLimit`: `reject-429` / `accept-and-taint` (200 で返し、通常の taint 述語だけを当てる。`Grader.TaintOnOverflow`、`conventions:381`)
  - `InflightScope`: `global` (#341 が入ったら `per-identity`)
- **名前**: binary の中で一意 (bucket と in-flight で同じ名前空間)、`^[a-z][a-z0-9_]*$`、metric label と同じ値。`submit`・`csp_report`・`participant_action`・`detect` は今の label のまま。ほかは例として ingest の `falco_observation`・`falco_scoring`、in-flight の `detect_grader`、collector の `forward` (この 4 つの名前は実装者が決めてよい)。
- **同じ名前 = 同じ token map。名前が違えば共有しない。** members (共有の一覧) はどこにも書かない。
- **header 無しの挙動はキー種別から決まる** (宣言に別の field を持たない)。
- **型はすべて `route.go` に置く** (C6)。`internal/apispec` に 2 つ目の non-test file を作らない。

### D2. 権威と描画の向き = Go → spec
- 宣言の権威は Go。limiter・middleware・in-flight の semaphore は宣言の値から作る。production code に数値を literal で渡す `ratelimit.New(…)` を残さない。キー種別から middleware を選ぶ処理は `ratelimit` に 1 つ置く (collector の `remoteIP` (`collector.go:278`) と board の `boardPostLimiter` / `boardLikeLimiter` (= `MiddlewareStrict(bucket, IdentityKeyed)`。`boardIdentityKeyed` は #417 で削除済み) はそこへ寄せる)。handler の中で効く種別 (`participant`) に middleware を求めたら起動時に失敗する。
- spec の operation の `x-ctf-rate-limit` は、その route の宣言を描画 (render) した正準形で、`make test` が意味で比べる。
- この向きにする理由: (a) ADR-0005 は middleware の宣言を「`Routes()` が正、spec はそれと機械比較」に分類し (`0005:223-237, 340-352`、regen-openapi `SKILL.md:22-27`)、spec → code の生成は型だけにした (`0005:397-402`)。rate-limit は origin-guard と同じ類。(b) 宣言と強制を同じ値にできるのは、組み立てる側に権威があるときだけ。(c) spec → Go にすると、生成物の鮮度を `make test` に別に持たなければならない (`gen-diff-check` は required でない)。
- **writer (`make gen-ratelimit`) は作らない。** (a) 保証は等価検査が持ち、writer は保証を足さない。(b) writer は canon (spec) に書き込む 2 本目の経路で、Docker の中で回すための Dockerfile (Class-2 の面) を足す。(c) operation の値は、operation を書くときに他の `x-ctf-*` と一緒に人が書く。赤い test は正しい正準形をそのまま出す (貼れば直る)。再訪は Signpost 4。

### D3. spec の operation の正準形

```yaml
x-ctf-rate-limit: none
x-ctf-rate-limit:
  - {bucket: participant_action, key: identity-strict, rate: 1/1s, burst: 10, applies: all, on-limit: reject-429}
x-ctf-rate-limit:
  - {bucket: detect, key: identity-strict, rate: 1/1s, burst: 10, applies: all, on-limit: reject-429}
  - {inflight: detect_grader, scope: global, max: 5, on-limit: reject-429}
x-ctf-rate-limit:
  - {bucket: falco_observation, key: participant, rate: 20/1s, burst: 100, applies: observation-rules, on-limit: reject-429}
  - {bucket: falco_scoring, key: participant, rate: 100/1s, burst: 400, applies: scoring-rules, on-limit: accept-and-taint}
```

- 全 field 必須、余分な key は fail、既定値なし。散文の文字列は fail (旧い形の再流入を止める)。並びは正準化するが、比較は名前の集合で行う。
- key 名 `x-ctf-rate-limit` は変えない (読み手は app の test だけ、C7)。`info.version` も変えない (HTTP 面は変わらない)。各 spec の `info.description` の extension の説明 (`docs/openapi-scoreboard.yaml:50` と collector の同じ節) を、この文法とキー種別の意味に書き換え、CHANGELOG に書く。
- `/internal/exfil/{cid}` の「(the limit lives on the collector front)」は `none` にし、理由は operation の description に移す。

### D4. 強制との結びつけ = 組み立ての一本化 (構造) + `Routes()` から導いた挙動 test (検出)
OriginGuarded / Authz と同じ「宣言 + 導出の挙動 test」の型 (`route.go:131-140`)。PR #395 の手書きの表 (`identity_bucket_test.go:57-91` の `identityBuckets` と `submitIPBucket`) は宣言からの導出に置き換えて消す。性質と検出器の test (Properties・ShareExactlyTheirRow・SharingDetectorCatchesMismatch・PropertyDetectorCatchesPassThrough・NoneMeansNoLimiter・og → limiter の順序) は、導出した表の上に移す。

### D5. 集約は保存しない
bucket ごとの members、client IP を使う route の一覧 (ADR-0023 C2)、運用の数値の表 (platform `docs/operations.md` §7.5) は手で書かない。必要な view は spec の grep (`key: ip` など) か test の出力から得る。ADR-0023 の C2 と platform の §7.5 には「spec の `x-ctf-rate-limit` が正」という導線だけを置く (C2 は 2026-08-28 時点の記録として残す)。C2 の導線は #417 で実行済み (C2 の表に追補 1 文)。

### D6. 移行 (各段は単独で緑。HTTP の挙動は変えない)
- **issue #390 の暫定 (「次に spec を触る PR で bucket 名に書き直す」) は行わない。** S2 が同じ 15 行をもう一度書き直す。`route.go:169-170` の誤りだけは本 ADR の PR で直す (コメント。「残りは ADR-0037 (Proposed) の V5 が閉じる」)。
- **順序**: S1a → S1b → S2 (同じ file を触るので直列)。PR #395 は main に入っているので前提は揃っている。#397 は S1a の前に決めるのが望ましい (D8) が、S1a を止めない。
- **S1a — 宣言と組み立て (Go だけ。spec に触れない)**: `route.go` に型と語彙、各 package が bucket と in-flight を宣言し、limiter・middleware・semaphore を宣言から作る。全 Route literal に宣言を足す (旧い `RateLimit string` は残し、V3b と spec はまだ変えない)。V2・V3・V4・V7 をここで入れる。`route.go:126-180` の表、`metrics.go:11-12`、`ratelimit.go:1-5`、`api.go:525-534, 870-874` を事実に直す。ingest の limiter の組み立てに触れるので Class-2、security-engineer のレビュー。
- **S1b — 導出の挙動 test (test だけ)**: #395 の表を宣言からの導出に置き換え、`ip`・`remote-addr` (collector)・handler の中で効く limit (ingest の 2 bucket、detect の in-flight) まで広げる (V5・V6)。engine は `internal/apispec` の下の test 専用 package に置き (specparity / ingressparity と同じ規律。dependency_boundary の検査を広げる)、scoreboard と collector は adapter だけを持つ。
- **S2 — spec の形式**: 旧い文字列の field を消し、spec の 15 行 (scoreboard 13・collector 2) を D3 の形に、`info.description` を書き換え、specparity に operation の値の parser と render を足し、3 service の parity test の rate-limit を V1 に切り替える (`requiredParityTestFuncs` に名前を足す: `internal/apispec/parity_coverage_test.go:61-65`)。I14 の追記 (D7)、ADR-0005 / 0009 / 0023 への導線、索引、CHANGELOG、`regen-openapi` の手順 0 を同じ PR で。security-engineer のレビュー (I14・spec)。
- **S2 で書き換える 15 行** (表に無い field は `applies: all`・`on-limit: reject-429`。spec にはすべて書く):

  | spec の行 | operation | 正準形 |
  |---|---|---|
  | scoreboard `:324` | POST /csp-report | `csp_report` (ip, 5/1s, 50) |
  | `:415` | POST /falco/events | `falco_observation` (participant, 20/1s, 100, observation-rules) + `falco_scoring` (participant, 100/1s, 400, scoring-rules, accept-and-taint) |
  | `:526` | POST /api/challenges/{cid}/submit | `submit` (ip, 1/1s, 10) |
  | `:587` | POST /api/challenges/{cid}/submit-detect | `detect` (identity-strict, 1/1s, 10) + `detect_grader` (in-flight, global, 5) |
  | `:671` | POST /internal/exfil/{cid} | `none` (「collector の前段で制限」は description へ) |
  | `:850,917,986,1056` | steps/check・hints・reset-dirty・profile | `participant_action` (identity-strict, 1/1s, 10) |
  | `:1162,1276` | board の threads・messages | `board_post` (identity-strict。1/10s, 3) |
  | `:1334,1387` | board の like・unlike | `board_like` (identity-strict。1/1s, 10) |
  | collector `:90,167` | exfil・submit | `forward` (remote-addr, 1/1s, 10)。2 route の共有を初めて書く |

- **大きさ (1 PR 400 行 / 15 file)**: S1a 約 400 行 / 12 file、S1b 約 350 行 / 6 file、S2 約 400 行 / 14 file の見込み。S1a が超えるなら V2〜V4 の静的検査を S1b に回す (S1a の挙動は #395 の test が引き続き見る)。
- **後続 (別 issue)**: Retry-After を宣言から導く (`ratelimit.go:106,250` は常に 1。refill 10s の `board_post` でも 1)。platform の §7.5 を導線にする (sre-engineer、platform の docs PR)。collector spec の Header hygiene に CF-Connecting-IP の strip (`collector.go:128`) を書く。

### D7. I14 への追記 (提案。S2 で、機構と同じ PR で入れる)
I14 の「… collector forward の集合も spec の宣言と一致する。」の後に次を足す:

> **rate-limit の宣言 (route ごとの bucket と in-flight 上限。bucket は名前・キー種別・rate・burst・適用範囲・超過時の挙動を持つ) も spec の `x-ctf-rate-limit` と一致し、宣言どおりに強制される** (同じ名前 = 同じ token map、キー種別どおりの keying と header 無しの挙動、burst と refill、`none` の route には limiter が無い)。機構: `TestAPISpec_RateLimitDeclarationMatchesSpec` (宣言 ↔ spec) + `TestRateLimit_DeclaredLimitsEnforced` (宣言 ↔ 強制。`Routes()` から導出。これを削ると rate-limit は宣言の一致しか保証しなくなる)。

ADR-0009 は V3b を I14 の外とした (`0009:13-17`)。ここで改める理由: (1) 検査が「宣言 ↔ 強制」の半分を持つようになり、I14 が origin-guard に求めているのと同じ形になる。(2) rate-limit の誤りは両方向に事故がある — 共有を誤ると venue の NAT の後ろで他人の提出を 429 にする (app#315)。scoring の bucket が 429 を返すと forbidden rule の発火が落ちて evade が clean に見える (app#359)。collector の keying を client IP に戻すと、workspace が bucket を作り放題になる (ADR-0023 D1b)。`x-ctf-authz` の I14 への編入は本 ADR の範囲外 (#393 の分類表の後で再訪)。

### D8. 周辺との関係
- **PR #395 (main)**: S1b の土台。S1b が手書きの表・`TableMatchesRoutes` の lenient の pin (`identity_bucket_test.go:154-157`)・`ClosedVocabulary` の文字列分類 (`:447-476`)・`submitIPBucket` を不要にする。
- **#397 (board の 2 bucket)**: **(a) strict で決着 (app#417、2026-10-18)。識別子 `identity-fallback` は不要** (board の 2 bucket は `MiddlewareStrict` になり、fallback 型の identity bucket は本番に無い。語彙に生まれない)。以下は決着前の検討の記録。本 ADR はどちらの結論も表せる。**architect の助言は (a) strict に揃える。** (1) fallback の key に届くのは header 無しの要求だけで、board の route はどれも handler の `requireAuthenticated` で 403 にする。fallback を必要とする呼び手が無い (参加者の ingress は auth-policy が header を必ず上書きし、collector は board を転送しない)。(2) 1 つの token map に identity と IP の 2 つの key 空間を混ぜる唯一の bucket で、そのためだけに語彙が 1 語増える。(3) strict にすると spec の 403 (`docs/openapi-scoreboard.yaml:1205,1305,1353,1403`) がそのまま真になり、「identity の bucket はすべて header 無しで 403・token を使わない」を 1 つの性質 test で言える。外から見える変化は、header 無しの flood が IP の burst を越えたときに 429 ではなく 403 になることと、`IdentityRequestsTotal{bucket="board_post"|"board_like"}` の系列が増えること (足すだけ)。(a) を S1a より先に入れれば `identity-fallback` は語彙に生まれない。後なら #397 の PR で消える (V3 が使われない語を落とす)。(b) を採るなら理由を `route.go` の語彙の doc に書き、「新しい identity bucket は strict」を守るために members の pin (= 例外リスト。#395 の lenient の pin と同じもの) が残る。どちらの場合も ADR-0023 C2 の行は手で直さず、D5 の導線にする。
- **#393**: 分類表が入ったら V7 を「header 無しで届く route (分類が claimed / none) は `identity-strict` を持たない」に一般化する。
- **#341**: `InflightScope` に `per-identity` を足す (そのとき語彙に入る)。

## Consequences

- **諦めたもの**
  - 共有の一覧を文書として持たない。見るのは spec の grep か test の出力。
  - 数値を変える PR は member の operation の行をすべて直す (今は最大 4 行)。writer が無いので、正しい値は赤い test の出力から貼る。
  - 宣言から配線を組み立てる形 (service ごとの wrap が og → limit → handler を `Route` から合成する) には、いまはしない。origin-guard の配線 (I14 の security の半分) を同じ変更に巻き込まないため。再訪は Signpost 3。
  - ingest の audit ログの間引き (`ingest.go:175`)、bucket の eviction (#366)、Retry-After は宣言の外 (応答の status を決めないか、別 issue)。
- **新たに守るもの**: D1 の語彙の規律 (1 か所で定義し、使われない語は置かない)。I14 の追記 (D7。S2 で昇格)。V1〜V8。
- **他ロールへの影響**: software-engineer = S1a・S2。qa-engineer = S1b の engine と V8。security-engineer = S1a (ingest の組み立て)・S2 (I14・spec)・#397。sre-engineer = platform `docs/operations.md` §7.5 を導線にする (platform の docs PR、Class-0)。skill の所有者 = `regen-openapi` の手順 0 と workspace の `falco-api` の `x-ctf-*` の説明 (S2 と同時)。
- **runbook**: platform §7.5 だけ。クロスリポ契約表の rate-limit の行 (`conventions:381,391`) は中身を変えない。

## Signposts (この決定を覆す観測可能な信号)

1. **`x-ctf-rate-limit` を app の parity test 以外が読み始めた** (platform の script、docs-site、外部の道具。ADR-0005 Signpost 5) → extension の JSON Schema と版を定め、spec を権威にする O2 を再評価する。
2. **どれかの limit を deploy 時に変えられるようにする** (env / Helm の値で rate・burst・Max を上書き。platform §7.5 の「allowance を上げる」が knob になる) → Go の宣言は runtime の値でなくなる。宣言は既定値と knob を持ち、V5 は実効値を読み、knob はクロスリポ契約の行になる。
3. **宣言と配線のずれが V5 をすり抜けて main に入った** (review-5x・e2e・本番で見つかった)、または **3 つ目の middleware 型の宣言が提案された** (例: #341 の per-identity in-flight を middleware で) → 宣言から配線を組み立てる形に進む (OriginGuarded も構造で守られる)。
4. **共有の一覧を手で組み立てる査定が 2 回以上あった** (review-5x / security の記録)、または **1 bucket の member が 5 を越えた** → 集約を生成物として足す (O3) か writer を作る。手書きの集約には戻さない。

## Verification (すべて `make test` = required の `test / go-test` に載せ、exit status で判定する)

- **V1 operation の宣言 ↔ spec (S2。ADR-0009 V3b の rate-limit の部分を置き換える)**: 3 spec の全 operation に `x-ctf-rate-limit` があり (欠落は fail)、値は `none` か D3 の形の空でない列 (field の欠け・余分・語彙の外・散文は fail)。同じ MuxPattern の Route の宣言の render と名前の集合で一致し、各名前の entry が完全に一致する。Route 側の zero 値 (未宣言) も fail。名前は `TestAPISpec_RateLimitDeclarationMatchesSpec`、`requiredParityTestFuncs` に足す。
- **V2 定義の一貫性 (S1a、静的)**: binary ごとに平らにした `Routes()` で、名前 → 定義がちょうど 1 つ (同じ名前で数値やキーが違えば fail)。bucket と in-flight の名前が重ならない。名前の形。`Tokens ≥ 1`・`Per > 0`・`Burst ≥ 1`・`Max ≥ 1`。
- **V3 語彙 (S1a)**: `KeyKind`・`Applies`・`OnLimit`・`InflightScope` の定数は `route.go` にだけあり、どれも non-test code の宣言で 1 回以上使われる。`internal/apispec/authz_vocabulary_test.go` の型検査による走査を、語彙の型ごとに当てる。
- **V4 組み立ての一本化 (S1a、静的)**: production code の `ratelimit.New(` は `internal/scoreboard/ratelimit` の中だけ (応答に効かないログの間引きは別の構築子にして区別する)。in-flight の semaphore の容量は `Inflight.Max` から作る。あわせて `internal/apispec` の non-test file の集合が、`collector/Dockerfile` と `auth-policy/Dockerfile` が COPY する集合と一致する (collector の image build は required でないので、ここで落とす)。
- **V5 宣言 ↔ 強制 (S1b、挙動、`Routes()` から導出)**: 名前は `TestRateLimit_DeclaredLimitsEnforced`、`requiredParityTestFuncs` に足す (limit を 1 つも持たない auth-policy でも走る)。
  - middleware で効くキー種別 (`ip`・`remote-addr`・`identity-*`) の bucket について、それを名指す**全 route** で: (a) 満杯から通るのがちょうど `Burst` 件。(b) `Per/Tokens` ちょうどで 1 token 戻り、その 1ms 前には戻らない。(c) キー種別どおりの keying (identity: 同じ IP の別 identity は満杯のまま。ip: 別の client IP は満杯、同じ IP の別 identity は共有。remote-addr: 1 つの接続から X-Forwarded-For / CF-Connecting-IP / X-Real-IP を変えても新しい bucket にならない)。(d) header 無しの挙動 (`identity-strict`: 毎回 limiter 自身の 403 で、`no_identity` の counter が送った数だけ動き、どの identity の token も減らない)。(e) limiter の 429 は `{"error":"rate limit exceeded"}` と Retry-After を返す。
  - 共有: binary の中の、middleware で制限された route の順序対すべてについて、新しい handler で A を使い切ってから B を 1 回送る。limiter の 429 が返る ⇔ 同じ bucket 名。
  - `none` の route: 通る identity で十分な数を送っても limiter の 429 に当たらない (#395 の NoneMeansNoLimiter)。
  - handler の中で効く limit (`participant`・in-flight): limit の名前を key にした test 側の driver が、宣言されたものすべてに揃っていること (欠けたら fail)。driver は数値を宣言から読む (ingest: 時計を止めて observation の rule を `Burst+1` 件 → 最後が 429。forbid された rule を `Burst+1` 件 → 最後も 200 で taint され、overflow の counter が動く。`Applies` どおり 2 つの bucket が独立。in-flight: grade を `Max` 件止めた状態で次が 429)。
  - 空でないこと: binary ごとに「試した route の数 = limit を持つ route の数」(どちらも導出)、全 binary の合計が 1 以上。
- **V6 順序 (S1b)**: origin-guard 付きで middleware の bucket を持つ route のすべてで og → limiter。#395 の `TestOriginGuardRunsBeforeRateLimiter` の対象の選び方を、文字列の判定 (`origin_guard_test.go:472-474`) から宣言の判定に替える。
- **V7 field をまたぐ性質 (S1a)**: `CollectorForward == true` の route は `identity-strict` の bucket を持たない (collector は `X-Auth-Request-*` を消すので、転送された要求はすべて header 無し。strict にすると curl の提出がすべて 403 になる)。#393 の後は D8 のとおり一般化する。
- **V8 検査が嘘でないこと (変異を常設の test にする)**: 次のそれぞれで赤くなる — spec の operation から `x-ctf-rate-limit` を消す (V1) / 散文に戻す (V1) / Go の `Burst` だけを変える (V1・V5) / route の handler を別 bucket の middleware に付け替え、宣言はそのまま (V5 の共有) / 同じ名前で数値の違う 2 つの宣言 (V2) / 使われない語彙の定数 (V3) / `api.go` に literal の `ratelimit.New(1, 10)` (V4) / `internal/apispec` に 2 つ目の non-test file (V4) / `identity-strict` と宣言して fallback の keying を配線 (V5 (d)) / handler の中の limit を driver 無しで足す (V5) / zero 値の宣言 (V1) / collector forward の route に `identity-strict` (V7) / og と limiter の順序を入れ替える (V6)。
- **この検査が見ないもの**: Cloudflare の edge の rate-limit (repo の外)、bucket の eviction (#366)、ログの間引き、in-flight 上限の 429 の本文の文言。
- **昇格の条件**: V1〜V7 が `make test` に入った PR (S2) で、同じ PR で I14 に D7 を足す。それより前に conventions に書かない。

## Advice (受けた助言。非拘束でも記録する)

- **VP (2026-10-17、本 ADR の発注)**: Route に bucket 名 / キー種別 / rate / burst / in-flight 上限を持たせ、spec を gen で描画し、描画の向きを ADR-0005 の流儀で決めること。→ D1・D2 で向きを Go → spec に決めた。writer は D2 の理由で作らない (Signpost 4 で再訪)。
- **Issue #390 (#379 review-5x R4#2)**: 構造化、描画、「同じ名前 = 共有」の導出 test、暫定の文字列の書き換え、`route.go:169-170` の修正。→ 構造化と導出は採用し、ingest の 2 bucket と detect の上限を正しく書くために `Applies`・`OnLimit`・in-flight を足した。暫定は D6 の理由で採らず、`route.go:169-170` だけを本 ADR の PR で直す。
- **qa-engineer (PR #395、2026-10-17)**: bucket の表 (burst・refill・strict・members)、性質の検出器、「新しい identity bucket は strict」の pin、`none` には limiter が無いこと。→ V5・V6・V8 にそのまま引き継ぐ。pin は #397 (a) なら語彙で置き換わる。
- **VP (#397 の推奨 (a))**: architect も (a) に同意する (D8)。
- **ADR-0009 (2026-08-31 Accepted)**: V3b を I14 の外とした判断。→ D7 で理由を挙げて改める。
- **security-engineer**: 未受領。S1a・S2・#397 のレビューで受け、ここに追記する。
