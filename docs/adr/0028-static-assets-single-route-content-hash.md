# ADR-0028: first-party 静的アセットを `GET /static/{asset}` 1 ルート + content-hash URL に集約する

- Status: **Proposed**。**実装 PR = app の P28-0c PR。その PR の CEO merge 時に Accepted へ昇格する** (昇格は CEO が別 commit で行う。
  実装 PR の commit は Status を変えない)。**Accepted は実機確認済み (V7) を意味しない** (先例: ADR-0023)。Accepted が指すのは決定の確定と
  V1〜V6・V9 の landing で、V7 (実機) と V8 の Cloudflare Cache Rule は次回 stand-up の参加者入場前まで未了である。何が済み何が未了かは
  「Verification」の各項目の「状態」を読む。
- Date / Deciders: 2026-10-05 / VP (2026-10-04 既定 3、CEO 承認済み) + architect (起草) + security-engineer・qa-engineer
  (独立レビュー 2026-10-05。指摘は本版に反映済み、再確認待ち) + CEO (merge。クロスリポの path 契約 = Class-2)
- 改訂: 2026-10-10 (architect。実装 PR に同梱)。Verification の各項目に状態 (満たすテスト名、未了の追跡先) を追記し、判定の時点を書き下し、
  Consequences に rollout の制約と昇格 commit の中身を、Context の C4 と Signposts (5) に I1 への依存を足した。Decision の内容は変えていない
  (D6 の末尾と Signpost 2′ の数字が実装後の実測に追随しただけ)。
- 関連: app#277、workspace `REFACTORING.md` P28-0c、ADR-0005 (**Signpost 2 だけを supersede する。** Decision 1-5・Verification・
  他の Signpost は無傷)、ADR-0021 / 0022 (I15)、ADR-0013 (単一 origin)、ADR-0023 (Accepted と実機確認を分ける先例)、I1・I5・I14・I15、
  app#306 (portal のソース分割。2026-10-05 merge 済みで、portal の template は `templates/portal/*.tmpl`)
- 読み方: Context の `file:line` と件数は **e74d871 (変更前) の実測**で、historical である。P28-0c が削除した
  `internal/scoreboard/view/vendorassets.go` などは `git show e74d871:<path>` で読む。Verification のテスト名は関数名で、
  `git grep -n 'func <名前>('` で引く (行番号は動くので書かない)。

## Context

**C1. 壊れたアセットが 24 時間直らない (app#277)。** 静的アセットは固定 URL に `Cache-Control: public, max-age=86400, immutable` で
出ている (`internal/scoreboard/view/vendorassets.go:55,90,140`)。`immutable` は再検証を省かせるので、壊れた bytes を取ったブラウザは
修正版の deploy 後も最大 24 時間それを使う (tokens.css の障害 app#275 で実際に踏んだ)。同ファイルのコメント (`:42-52`) は
「新しい deploy なら cache も新しい」と読めるが、HTTP cache の鍵は URL であって Pod ではない。P28 は tokens.css に `--q-*` を
足すので、このままでは再訪したブラウザに新しい部品のスタイルが当たらない。

**C2. 1 アセットにつき 4 箇所の登録が要る。** 8 アセットがそれぞれ mux の route (`internal/scoreboard/view/view.go:175-257`)、spec の operation
(`docs/openapi-scoreboard.yaml:229-424`、196 行)、ingress の Exact エントリ (`charts/scoreboard/templates/ingress-journey.yaml:211-266`)
を持ち、platform の文書への記載も要る。platform の文書は既に追随が落ちている: path 一覧にあるのは `/vendor/cybercore.min.css` と
`/static/tokens.css` の 2 本だけで、フォントの 6 本と `/api/board/` が無い (`falco-ctf-platform/CLAUDE.md:171`、
同 `docs/operations.md:65,602`。platform origin/main = 97e4a86 で確認)。ingress 側の登録漏れは過去に本番へ到達している (#235、ADR-0021 C1)。

**C3. ADR-0005 Signpost 2 が発火している。** 文言は「spec が 2,500 行を超えたら、または 1 サービスの operation が 35 本を超えたら
… 分割の単位は … サービス側を先に検討する」(`0005-openapi-canon-and-parity-gate.md:311-313`)。e74d871 の scoreboard spec は
**2,802 行・37 operation** で、両方を超えている。37 のうち 12 は JSON の応答を持たない (静的配信 8、HTML shell 2、`/metrics`、
`/csp-report`)。

**C4. 制約。** I15 の照合規則は「`{param}` は 1 セグメント全体」を前提にする (`{name...}` を使うなら規則の再設計 = ADR-0021
Signpost 1)。Exact エントリは param を持つ route を被覆できない (`internal/apispec/ingressparity/ingressparity.go:124`)。HTML と
アセットは同じバイナリに同居していて版ずれが無い (I5)。これは**同じプロセスから出る**ことにも依存し、replicas=1 + Recreate (I1) が保証している
(Signpost 5)。CSP は `'self'` で、path に依存しない
(`internal/scoreboard/view/csp.go:178-183`)。本番は Cloudflare を経由する (proxied)。platform リポに cache の設定は無い
(dashboard 側は未確認)。

## Options

1. **route は現状のまま、cache だけ直す** — `immutable` を外し、短い max-age と ETag の再検証にする。
   コスト: 最小。page load ごとに再検証が 8 本。リスク: C1 は閉じるが C2 が残る (アセットを足すたびに 4 箇所と両リポの文書)。
   可逆。効き始める閾値: アセットが今後増えない場合。
2. **`GET /static/{asset}` 1 ルート + content-hash URL【推奨】** — 配信名を `<name>.<hash>.<ext>` にし、登録表にある名前だけを返す。
   コスト: HTML と CSS の参照を登録表から解決する配線、ingress は Prefix 1 本、テストの追随、platform の cache 設定。リスク:
   Prefix は mux が出さない path にも ingress を開く (D4・D5 で扱う)。route は戻せるが、両リポの path 契約を 2 度動かすことになる。
   閾値: 次にアセットの中身を変える deploy から (P28-1 の `--q-*`)。
3. **scoreboard の外から配る** (docs の nginx、別サービス、CDN) — コスト: 参加者向けの allow-list がもう 1 つ増える (ADR-0021
   Signpost 2)。CDN なら egress-zero (P12) を崩す。リスク: HTML とアセットが別 image になり、同居による「版ずれなし」を失う。
   可逆性は低い (配信経路と契約が増える)。閾値: アセットが HTML と独立に更新される運用になったとき。

## Decision

**Option 2。** 理由: URL が内容で決まれば「古い cache が残る」こと自体が起きず、同時にアセット追加の登録が 1 箇所になる。

- **D1 route**: `GET /static/{asset}` の 1 本 (audience = participant、authz = none、origin-guard なし、collector forward なし、
  rate-limit なし)。`{asset}` は 1 セグメントで、サブディレクトリを作らない。既存の `/vendor/*` 7 本と `/static/tokens.css` は削除し、
  互換の別名も redirect も置かない (置けば集約が崩れ、Exact エントリが残る)。
- **D2 登録表**: 起動時に埋め込み bytes から「論理名 → 配信名 `<name>.<hash>.<ext>`」を作る。hash は**参照を解決した後の bytes** に
  対して取る (fonts.css は woff2 の配信名を書き込んでから hash する。フォントが変われば fonts.css の URL も変わる)。HTML
  テンプレートと CSS は登録表から URL を得て、リテラルの path を書かない。登録表に無い名前は 404 — ハッシュ無しの名前
  (`/static/tokens.css`) も、埋め込みディレクトリに在るだけのファイル (LICENSE・PROVENANCE.md) も返さない。埋め込み FS を
  `http.FileServer` でそのまま出さない。
- **D3 cache**: 配信名には `Cache-Control: public, max-age=31536000, immutable` (ETag と 304 は残す)。404 は `no-store` —
  配信名は公開リポの内容から計算できるので、deploy の前に将来の名前を叩かれると 404 が共有 cache に残りうる。それを防ぐ統制でも
  ある。HTML shell (`/`・`/portal`) には `no-store` を明示する (現状は cache の指定が無い)。shell は応答ごとの nonce と、利用者ごとの
  `__PORTAL_USER__`・`__PORTAL_TTYD_URL__` を埋め込んでいる (`internal/scoreboard/view/templates/portal.html:975-977`)。共有 cache に
  載れば他人の識別子が渡り、nonce も再利用される。性能のために緩めない。
- **D4 ingress**: participant allow-list の Exact 8 本を `path: /static/`・`pathType: Prefix` の 1 本に替える。配信名は build ごとに
  変わるので chart は列挙できず、Exact は構造上も使えない (C4)。同一 host にある admin ingress の `/` (Prefix、`/check-admin`) との
  優先は最長一致で `/static/` が勝つ。既存の Prefix 3 本 (`ingress-journey.yaml:183-203`) が P19-2b から依存しているのと同じ機構で
  ある (`charts/scoreboard/templates/ingress.yaml:15-27`。`/static/` での実機確認は V7)。I15 の照合規則は無変更で被覆を判定でき、
  `/static/` の下に participant 以外の route を置けば reverse 検査が落とす。
- **D5 `/static/` に置けるもの**: 誰に読まれてもよい表示用アセットだけ。課題の内容 (Quest content・図鑑の文・ヒント) や利用者ごとに
  変わるものは置かない (self-scope の API で出す)。散文の規則にせず、次で機械的に縛る。
  - **登録表を pin する**: 論理名の集合をテストで固定する (変えるには pin の更新が要り、その PR は security-engineer レビュー必須)。
    拡張子は `.css` と `.woff2` だけ。`.js` は Signposts 4 の supersede まで載せない (CSP は `script-src 'self'` を含むので、登録表に
    入った script は nonce なしで実行できる)。入力は `view/static` と `view/vendor` の埋め込みだけ。
  - **共有 cache の両面**: `public` で配るので、200 は認証を通らずに返りうる (だから公開してよいものだけを置く)。逆向きもある:
    未認証の GET には sign-in への 302 が返り、これは Cache-Control を持たない。edge に載れば、認証済みの参加者にも 302 が返りうる
    (**未実測**。現行の固定 URL にも同じ面がある)。V7 で測り、V8 で platform に「`/static/` は 200 以外を cache しない」設定を入れる。
    (`/static/` を認証なしの Ingress に分ける案は、匿名の通信を採点権威のプロセスまで届かせるので採らない。)
- **D6 クロスリポ**: path 契約の変更なので両リポ同時 PR + 相互リンク。platform 側は文書 (C2 の 2 ファイルと
  `docs/verification-gates-2026-08.md`) と Cloudflare の cache 設定 (V8)。helmfile は path を持たない。記載を「`/static/` (Prefix)」に
  替えれば、以後アセットを足しても platform の変更は要らない。app の契約表にも「participant path の正典は
  `ingress-journey.yaml`、I15 が機械照合する。platform は文書で参照するだけ」の行を同じ PR で足した
  (`.claude/rules/falco-ctf-app-conventions.md` の Cross-repo 契約表『Participant path 集合』と `CLAUDE.md` の概要表。以前は app 側に行が無かった)。

### ADR-0005 Signpost 2 の置き換え (Signpost 2′)

集約して 30 operation になったが、行数は約 2,670 行 (実装 PR の実測) で 2,500 を超えたままである。数字を合わせにいくのではなく、測るものを直す。

- **数えるもの**: JSON object の応答を持つ operation。ADR-0009 の V(A)-1 が spec から機械導出している集合で、required check の
  テストが件数を pin している (`internal/scoreboard/apispec_parity_test.go` の `TestAPISpec_VA1_ResponseObjectCoverageBidirectional`。
  e74d871 でも実装 PR でも 25)。静的配信や HTML shell は入らない。
  本 ADR の前後で 25 のまま、P28 後は 27 の見込み。**35 を超えたら**点検する (35 は ADR-0005 の値を引き継ぐ)。pin の行を
  変える PR で必ず目に入る。
- **行数の条件は廃止し、文書の大きさには文書の分割で応える。** 行数は description と schema の量で決まる (2,802 行のうち
  components が 979 行)。単一ファイルが 3,000 行を超えるか、spec を同時に触る open PR が 2 本になる事態が 2 回起きたら、`$ref` で
  `paths` / `components` を別ファイルに分けてよい。論理的には 1 サービス = 1 spec のままである (ADR-0005 Decision 3 は不変)。
  条件: I14 の parity と `make gen` が分割後の全ファイルを入力にし、抽出 0 件を fail にする。oapi-codegen v2.3.0 と `specparity` が
  外部 `$ref` に追随できるかは**未検証**で、分割する PR の完了条件とする。
- **処方からサービス分割を外す。** 理由: (1) 状態は単一 writer の SQLite にある (I1)。HTTP 面だけを別バイナリに切ると、同じ DB への
  複数 writer かバイナリ間の RPC が要る。(2)「マイクロサービス化しない」は再議論しない決定事項である (workspace `REFACTORING.md`
  決定事項、2026-07-07)。(3) バイナリを足すと image (I5、CEO 承認)・chart・ingress allow-list・identity 照合の写し (scoreboard と
  auth-policy の間に既に 1 組ある) が増える。増えるのは検査の対象となる境界である。(4) 行数と総 operation 数は静的配信の薄い
  項目で動く指標で、責務の数を測っていなかった。
- **35 を超えたときの処方**: 新しいバイナリではなく、bounded context の境界が import closure で引けているかを点検する (ADR-0019 の
  context map、ADR-0029 (予約) の I17)。単一 writer を保ったまま境界を引けないと示されたときに限り、バイナリ分割を I1 と上記決定の
  supersede (CEO 判断) として起案する。

## Consequences

- **諦めたもの**: 人が読める固定 URL。curl での確認には「HTML から配信名を拾う」1 手が要る (runbook と platform の
  `verification-gates` の手順を直す)。
- **deploy を跨いで開いたままのタブ**: 取得済みの CSS は使い続けられる。未取得のフォント (初めて使う weight) は旧配信名が 404 に
  なり、fallback フォントで表示される。機能は壊れず、再読込で直る。
- **新たに守る不変条件**: 増やさない。I14 (route = spec) と I15 (ingress) が既に対象にしている。
- **追随した検査 (実装 PR で完了)**: `TestTemplates_NoRawHexColorLiterals` (`internal/scoreboard/view/csp_test.go`) の `tokensCSSPath` の
  文字列検査は、template に `{{.Assets.URL "tokens.css"}}` があることの検査に替え、描画された参照が 200 で引けるかは V2 が見る。固定 path と
  個別 handler を前提にした旧ハンドラのテスト 4 本 (cybercore と tokens の Content-Type・条件付き GET) は、登録表の handler に合わせて
  `internal/scoreboard/view/static_assets_test.go` の V2・V4 のテストに統合した。route 数の pin は 37 → 30 (`apispec_parity_test.go`)、
  Authz の none 区分は 15 → 8 (`authz_test.go`)。`PROVENANCE.md` 2 本にある配信 path の記述も実装 PR で更新した。
- **V7・V8 が済むまでの残余**: 未認証の 302 が Cloudflare の edge に載りうる面は、現行の固定 URL (`/vendor/*`・`/static/tokens.css`) にも同じ形で
  ある (D5)。この変更が新しく持ち込む面ではないが、未測定である点は同じで、V7 が初めて測る。
- **rollout の制約 (運用): chart (ingress) と image は同じ SHA で同時に入れる。** participant ingress の allow-list (chart) と、HTML が参照する
  配信名 (image) は対になっている。platform は chart を app clone の checkout (`appChartBase`) から、image を `appImageTag` から別々に pin する
  (`falco-ctf-platform/helmfile/environments/prod.yaml.gotmpl:124-126`。契約表の『Charts』『Image naming』) ので、片方だけ進めると
  portal が壊れる (見込み。実測は V7)。chart だけ新しいと、`/vendor/*` が participant ingress に無く (admin ingress の `/` に落ちて非 admin には
  403)、旧 image の cybercore と fonts が取れない。image だけ新しいと、配信名が旧 chart の Exact 8 本に無く、全 CSS が取れずに無スタイルに
  なる。**戻すときも chart と image を前の pin に同時に戻す。** platform の runbook と stand-up gate に「app clone の checkout と `appImageTag` が
  同一 SHA」の確認を載せる (V8)。platform の `scripts/preflight-event.sh:68-77` は `versions.yaml` の ref と `appImageTag` の一致までしか見ず、
  clone の checkout は見ない (機械では確かめられない部分。Verification の末尾)。
- **cross-repo の merge 順**: app の実装 PR を先に merge してよい (platform が pin を動かすまで本番には届かない)。platform の文書 PR
  (branch `docs/adr-0028-static-path-contract`) は、この変更を含む SHA への re-pin と**同時**に merge する。先に merge すると文書が稼働中の
  pin (旧 path) と食い違い、re-pin の後に merge すると stand-up の gate が旧手順のまま新しい app に当たって偽の FAIL になる。
- **ADR-0005**: 本体は書き換えない。索引の 0005 の行から本 ADR へ導線を張ってある (#311 で追加済み)。本 ADR が Accepted になるまで
  Signpost 2 の元の文言が有効で、Accepted から Signpost 2′ が有効になる。
- **Accepted への昇格 (CEO の別 commit) の中身**: 触るのは次の 3 箇所だけ。(1) 本 ADR の Status 行 (Proposed → Accepted。V7 と V8 の Cache Rule が
  未了であることは Status に残す)、(2) 索引 `docs/adr/README.md` の 0028 の行の Status、(3) 索引の 0005 の行の括弧 (「0028 は Proposed … 元の文言が
  有効」を「0028 が Accepted で、Signpost 2′ が有効」に)。Decision と V1〜V9 の定義は編集しない。V7 の実測と V8 の完了は、Verification の
  「状態」行 (状態記述なので実態に追随させる) と Advice に、日付と結論を足す。

## Signposts (この決定を覆す観測可能な信号)

1. 埋め込みアセットの合計が 2 MB を超える、または 1 ファイルが 500 KB を超える (e74d871 は 8 本で 198 KB) → 圧縮済みの配信か
   別経路を検討する (バイナリと常駐メモリに載るため)。
2. `/static/` に認証や利用者に依存する内容を置く要求が 1 件出る → D5 を緩めず API 側に route を設計する。要求が続くなら D5 の
   線引きを ADR で見直す。
3. deploy 後に「表示が崩れた」報告が 1 件出る (古い HTML、旧配信名の 404、cache に載った 302 のいずれか) → D3 の cache 方針か、
   旧配信名の猶予配信を再設計する。
4. アセットにサブディレクトリが要る、または portal の JS / CSS を外部アセットにすると決まる (P28 architect §9 の覆す信号) →
   前者は I15 の照合規則の再設計が先 (ADR-0021 Signpost 1)。後者は script を登録表に載せる条件を本 ADR の supersede で決める。
5. **I1 を緩める提案が出る** (scoreboard の `replicas` を 1 より増やす、または `strategy` を `Recreate` 以外にする。
   `charts/scoreboard/templates/deployment.yaml` の `fail` (`replicas` > 1) と `type: Recreate` を変える提案) → 配信名は、HTML とアセットが
   **同じプロセス**から出ること (I1: replicas=1 + Recreate) に依存している。版の違うプロセスが同時に動くと、旧 Pod の HTML が旧配信名を参照し、
   新 Pod の登録表にその名前が無くて 404 になる (portal が無スタイルになる)。緩める前に、直前の版の登録表を併せて持つ猶予配信か、版に依存しない
   配信経路を先に設計する (Signpost 3 の「旧配信名の猶予配信」と同じ処方)。

## Verification

**状況 (実装 PR 時点)**: V1〜V6 は実装 PR で満たす (各項目の「状態」にテスト名)。V9 は既存の pin。**V7 (実機) は未了。V8 は (a) 追跡中、(b) 未了。**
V7 と V8(b) の期限は次回 stand-up の参加者入場前で、追跡先は platform の同時 PR (branch `docs/adr-0028-static-path-contract`)。
**Accepted は V7 の確認済みを意味しない** (ADR-0023 の先例)。各項目の「状態」は状態記述なので実態に追随させる (定義の本文は編集しない)。
**P28-0c の PR、登録表の pin を変える PR、platform の Cloudflare cache 設定は、いずれも security-engineer レビュー必須。**

- **V1 route**: 静的配信の route がちょうど 1 本。I14 の parity が green (spec は 37 → 30 operation)。
  **状態: 満たす (間接)。** `TestAPISpec_V1_RouteSetMatchesSpec` (`internal/scoreboard/apispec_parity_test.go`。route 集合 = spec の operation 集合で、
  件数の pin は 30)、`TestAuthz_AllDeclaredGatesEnforced` (`internal/scoreboard/authz_test.go`。区分の pin は 9 + 7 + 8 + 6 = 30 で、none の 8 本に
  `GET /static/{asset}` を含む)、`TestNoDirectMuxRegistrationOutsideTable` (`internal/apispec/staticreg_test.go`。route 表の外から mux に足せない)。
  旧 `/vendor/*` と `/static/tokens.css` が無いこと (D1: alias なし) は V4 の `TestStaticAssets_NotFoundIsNoStoreJSON` が固定する。
  **間接と書く理由**: 「静的配信の route が 1 本」を直接数える assert は無い。件数の pin が 1 本ぶんを固定し、増やす PR に pin の更新 (diff に出る変更) を
  強いる形である。`/static/` の下に 2 本目を足しても I15 の Prefix は participant の route なら被覆するので、関門は pin の更新だけになる。
- **V2 参照の完全性**: 対象は、`/` と `/portal` を描画した HTML (分割後は全 template を合成した結果) の `<link rel="stylesheet">` の
  `href` と `<script src>`、および配信する CSS の `url()` のうち、`/` で始まる same-origin の path。`data:`・絶対 URL・`#…` は対象外
  (cybercore の `url("data:…")`、`https://falco.org/…`、`<a href="/portal#story">` が実例)。対象がすべて、mux 経由で 200 を返す配信名で
  ある。`/vendor/` とハッシュ無しの `/static/` は 0 件。対象の抽出が 0 件なら fail。
  **状態: 満たす。** `TestRenderedDocuments_AssetReferencesResolve` (`internal/scoreboard/view/static_assets_test.go`。実際の `GET /` と `GET /portal` の
  描画結果から参照を抽出し、抽出件数が下限を下回れば fail にする。参照 (CSS の `url()` は再帰) がすべて mux 経由で 200 を返す `/static/` の配信名であること、
  `/vendor/` とハッシュ無しが 0 件であること、`@import` が無いことを見る)。`TestTemplates_NoRawHexColorLiterals` (`internal/scoreboard/view/csp_test.go`) は、
  template が `{{.Assets.URL "tokens.css"}}` で参照していることを見る。
- **V3 hash の性質**: アセットを 1 byte 変えると配信名が変わり、それを参照する CSS の配信名も変わる (合成した登録表でテスト)。
  **状態: 満たす。** `TestStaticAssets_HashProperties` (`static_assets_test.go`。フォントの 1 byte で、フォント自身と、それを参照する `fonts.css` の配信名が
  変わり、無関係な `tokens.css` は変わらない。`fonts.css` の本文には解決済みの参照が入り、`asset:` の placeholder は残らない)。
- **V4 header と 404**: 配信名は `max-age=31536000, immutable`。未知の名前・ハッシュ無しの名前・登録表に無い埋め込みファイルは 404 +
  `no-store` + `{"error": …}`。HTML shell は `no-store`。2 セグメントの名前 (`/static/a/b`)・`/static/..%2Fx`・`/static/%2e%2e` も 404 で、
  admin の HTML を返さない (`{asset}` に合わない形は catch-all の `GET /` に落ちる。そこで 404 にしているのは `internal/scoreboard/view/view.go` の
  `index` 冒頭の path 判定 1 行 (`r.URL.Path != "/"`) だけで、**この 1 行を消すと participant ingress の `/static/` Prefix から operator 向けの handler に
  届く**。固定するテストは `TestStaticAssets_ShapesOutsideTheAssetRoute`。同じ route 形の scratch probe (Go 1.26.6) では 3 形とも 404、リテラルの `..` は
  mux が redirect で正規化した)。
  **状態: 満たす。** `TestStaticAssets_ServeAndCacheHeaders` (配信名ごとに 200・`Cache-Control: public, max-age=31536000, immutable`・Content-Type・ETag・
  `nosniff`・空でない body で、一致する `If-None-Match` は空の 304)、`TestStaticAssets_NotFoundIsNoStoreJSON` (ハッシュ無し・未知・登録表に無い埋め込みファイル
  (`LICENSE`・`PROVENANCE.md`)・ハッシュ違い・旧 `/vendor/*` は 404。`/static/` の下は `no-store` + `{"error": …}`)、`TestStaticAssets_ShapesOutsideTheAssetRoute`
  (route 形ごとに**どの handler が答えるか**を固定する。単一 segment の `..%2Fx`・`%2e%2e` は asset route の JSON 404 + `no-store`。`/static`・`/static/`・`/static/a/b` など
  `{asset}` に合わない形は catch-all の `GET /` に落ち、`index` の path 判定による plain な 404 になる。admin の identity で組んだ mux で測るので、その判定を消すと
  dashboard の HTML が 200 で返って赤になる)、`TestHTMLShells_AreNoStore` (`/`・`/portal`、非 admin の `GET /` の 403、`writeSecurityHeaders` が失敗した
  `/portal` の 500 が `no-store`)。
- **V5 I15**: allow-list に `/static/` (Prefix) があり、`/vendor/*` の Exact が残っていない。合成入力で「`/static/` 配下の operator
  route」が reverse 検査で赤になる。
  **状態: 満たす。** `TestI15_StaticAssetsArePrefixOnly` (`internal/scoreboard/ingress_journey_parity_test.go`。実 chart の描画に `{/static/, Prefix}` が
  ちょうど 1 本あり、`/vendor` と Exact の `/static` が無い。合成した operator route `/static/operator-only.json` で reverse 検査が赤になる)。既存の
  `TestI15_IngressJourneyRouteCoverage` (forward / reverse を実 chart と実 route 表で見る) も green であること。
- **V6 pin と故意違反**: 登録表の論理名の集合と拡張子 (`.css` / `.woff2`) をテストで固定し、`.js` を足すと赤になる。テンプレートに
  リテラルの `/static/tokens.css` を書くと V2 が赤、登録表から 1 本落とすと V2 が赤、を恒久のテストケースにする。
  **状態: 満たす。** `TestStaticAssets_RegistryPin` (論理名の集合と拡張子 `.css` / `.woff2` を固定し、配信名の形 `<stem>.<16 桁の hex>.<ext>` も見る)、
  `TestBuildAssetRegistry_Rejects` (`.js`・許可外の拡張子・サブディレクトリ・大文字・重複・空のファイル・未登録の参照・前方参照・引用符や空白付きで解決されない
  `asset:` の参照・空の登録表は、起動時の `buildAssetRegistry` のエラーになる。1 ケース 1 欠陥で、エラー文言が欠陥の理由を含むことまで見る)、
  `TestCheckAssetRefs_MutationsGoRed` (template にリテラルの `/static/tokens.css` や `/vendor/…` を書く、配信されない `<script src>` を足す、登録表から
  tokens.css を落とす、登録表を付けない — いずれも V2 の検査か描画が赤になる。属性の順序が違う `<link>` も見逃さない)。
- **V7 実機 (単一 origin、Cloudflare 経由)**: admin でない参加者が配信名を 200 で取れる (`/check-admin` の 403 にならない)。
  `/static/does-not-exist` が 404 を返す (403 ではない)。同じ配信名を未認証 → 認証済みの順で取得し、各応答のステータスと
  `cf-cache-status` を記録する (認証済みの取得に cache 済みの 302 が返らないこと)。tokens.css を変えた image に入れ替えた後、
  再訪したブラウザが hard reload なしで新しい CSS を得る (app#277 の回帰。E2E ハーネスができるまでは qa の手動検証)。
  **状態: 未了 (実機でのみ確認可)。** 追跡先は platform の stand-up gate (platform の同時 PR `docs/adr-0028-static-path-contract` が
  `docs/verification-gates-2026-08.md` に登録する)。期限は次回 stand-up の参加者入場前。結果 (各応答の status と `cf-cache-status`、測った日時、SHA) は
  gate の記録に貼り、本 ADR の Advice に日付と結論を 1 行足す。
- **V8 クロスリポ (platform)**: 文書の PR が同時に出て相互リンクされている。Cloudflare に「`/static/` の 200 以外の応答を cache
  しない」Cache Rule を入れ、手順を runbook に残す。
  **状態: (a) 文書の PR は追跡中、(b) Cache Rule は未了。** (a) platform の同時 PR (branch `docs/adr-0028-static-path-contract`)。app の実装 PR の本文と
  platform の PR の本文に相互リンクを入れる (merge 前)。内容は、participant path の記載を「`/static/` (Prefix)」と「正典は app の `ingress-journey.yaml`」に直す、
  旧 G2 の固定 path への curl を「HTML から配信名を拾う」手順に直す、V7 を gate に登録する、chart と image が同一 SHA であることの確認と、赤のときの
  同時退避 (Consequences の rollout の制約) を載せる。(b) Cloudflare の dashboard の手動設定で、repo からは検証できない。手順は platform の
  `docs/prod-deploy.md` (Step 6)、設定値は security-engineer のレビューを通す。期限は次回 stand-up の参加者入場前。
- **V9 Signpost 2′ の計測点**: 既存の pin (`apispec_parity_test.go` の `len(derived) != 25`) をそのまま使う。新しい検査は足さない。
  **状態: 満たす (既存)。** `TestAPISpec_VA1_ResponseObjectCoverageBidirectional` の件数 pin は実装 PR でも 25 のまま。

**機械では確かめられないもの**: V7 (実機)。V8(b) (Cloudflare の dashboard)。chart (app clone の checkout) と image (`appImageTag`) が同一 SHA であること
(platform の `scripts/preflight-event.sh:68-77` は `versions.yaml` の ref と `appImageTag` の一致までで、clone の checkout を見ない。stand-up の gate の手動確認が
補う)。V1 の「静的配信の route が 1 本」を直接数えること (件数の pin による間接)。これらのために新しい Hard Invariant は作らない。

**architect の判定: yes, if** — V7 が緑であること、V8 が同時であること。

**時点の書き下し (2026-10-10 改訂)**:
- **merge の時点**: V8(a)、つまり platform の同時 PR が出て、app の実装 PR と相互リンクされていること。V7 が platform の stand-up gate に登録されていること。
- **次回 stand-up の参加者入場前**: V7 を実機で測って記録すること。V8(b)、つまり Cloudflare の Cache Rule を入れ、手順を runbook に残すこと。どちらかが未了の間は、
  ADR-0028 を含む SHA を参加者が使う環境で公開しない (platform の gate。手順上の gate で、機械の stop ではない)。
- 改訂前の文面は時点を書いていなかった。V7 は Cloudflare 経由の実機でしか測れず、cluster が無い間は merge の時点で満たせない。そこで V7 と V8(b) を merge の
  条件から外し、入場前の条件にした。根拠は 3 つ: (1) merge しても本番には届かない (platform が chart と image を別々に pin し、pin を動かすまで届かない)、
  (2) 未認証の 302 が edge に載りうる面は現行の固定 URL にも同じ形である (D5)、(3) platform の gate が入場前に V7 の緑を求める。(2) のとおり新しく持ち込む
  面ではないが、未測定である点は変わらないので、期限は日付でなく「入場前」という出来事に置いた。

## Advice

- security-engineer R1 (2026-10-05、REQUEST CHANGES → 本版に反映): D5 を機械強制にする (登録表の pin・拡張子・入力)、edge に
  載る 302 の面と V7 / V8、D3 の理由 (negative cache の汚染、nonce と利用者識別子)、V4 の 404 ケース。
- qa-engineer R2 (2026-10-05、APPROVE with comments → 本版に反映): V2 の対象の限定 (文面どおりでは必ず赤になる)、追随が要る
  テスト 4 本、app#306 との順序。
- app#277 (2026-09-01、review-5x R4): path に content hash を埋める案と、ingress を Prefix にする論点の指摘。
- VP 既定 3 (2026-10-04、CEO 承認): Signpost 2 にはサービス分割で応えず、閾値を本 ADR で再定義する。
- review-5x (2026-10-10、`feat/p28-0c-static-assets`。R4#2・R3#4・R4#4・R5#4・R5#5・R3#5 ほか → 本改訂に反映): 実装 PR に正典を同梱する
  (Verification の各項目の状態と対応テスト、契約表の D6 の行、「未実装」と行番号の訂正)、判定の時点の書き下し、I1 への依存の Signpost、
  chart と image の同一 SHA の rollout 制約。
- VP 指示 (2026-10-10): Status は Proposed のままにし、Accepted への昇格は CEO が merge 時に別 commit で行う。V7 / V8 の追跡先は platform の
  同時 PR と、次回 stand-up の参加者入場前。
