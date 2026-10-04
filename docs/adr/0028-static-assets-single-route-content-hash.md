# ADR-0028: first-party 静的アセットを `GET /static/{asset}` 1 ルート + content-hash URL に集約する

- Status: **Proposed** (Accepted 化は CEO merge 時。期限 = P28-0c の merge 前)
- Date / Deciders: 2026-10-05 / VP (2026-10-04 既定 3、CEO 承認済み) + architect (起草) + security-engineer (レビュー必須・未受領) +
  CEO (merge。クロスリポの path 契約 = Class-2)
- 関連: app#277、workspace `REFACTORING.md` P28-0c、ADR-0005 (**Signpost 2 だけを supersede する。** Decision 1-5・Verification・
  他の Signpost は無傷)、ADR-0021 / 0022 (I15)、ADR-0013 (単一 origin)、I1・I5・I14・I15

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
アセットは同じバイナリに同居していて版ずれが無い (I5)。CSP は `'self'` で、path に依存しない
(`internal/scoreboard/view/csp.go:178-183`)。

## Options

1. **route は現状のまま、cache だけ直す** — `immutable` を外し、短い max-age と ETag の再検証にする。
   コスト: 最小。page load ごとに再検証が 8 本。リスク: C1 は閉じるが C2 が残る (アセットを足すたびに 4 箇所と両リポの文書)。
   可逆。効き始める閾値: アセットが今後増えない場合。
2. **`GET /static/{asset}` 1 ルート + content-hash URL【推奨】** — 配信名を `<name>.<hash>.<ext>` にし、登録表にある名前だけを返す。
   コスト: HTML と CSS の参照を登録表から解決する配線、ingress は Prefix 1 本、テスト 3 箇所の追随。リスク: Prefix は mux が
   出さない path にも ingress を開く (D4・D5 で扱う)。route は戻せるが、両リポの path 契約を 2 度動かすことになる。
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
- **D3 cache**: 配信名には `Cache-Control: public, max-age=31536000, immutable` (ETag と 304 は残す)。404 は `no-store`。HTML shell
  (`/`・`/portal`) には `no-store` を明示する (現状は cache の指定が無い。古い HTML が古い配信名を指し続けないようにする)。
- **D4 ingress**: participant allow-list の Exact 8 本を `path: /static/`・`pathType: Prefix` の 1 本に替える。配信名は build ごとに
  変わるので chart は列挙できず、Exact は構造上も使えない (C4)。同一 host にある admin ingress の `/` (Prefix、`/check-admin`) との
  優先は最長一致で `/static/` が勝つ。既存の Prefix 3 本 (`ingress-journey.yaml:183-203`) が P19-2b から依存しているのと同じ機構で
  ある (`charts/scoreboard/templates/ingress.yaml:15-27`。`/static/` での実機確認は V7)。I15 の照合規則は無変更で被覆を判定でき、
  `/static/` の下に participant 以外の route を置けば reverse 検査が落とす。
- **D5 `/static/` に置けるもの**: 誰に読まれてもよい表示用アセットだけ。`public` で配るので、共有 cache が認証を通さずに返しうる
  (本番の edge が実際に cache しているかは未検証)。課題の内容 (Quest content・図鑑の文・ヒント) や利用者ごとに変わるものは
  置かない。それらは self-scope の API で出す。
- **D6 クロスリポ**: path 契約の変更なので両リポ同時 PR + 相互リンク。platform 側は文書だけである (C2 の 2 ファイルと
  `docs/verification-gates-2026-08.md`。helmfile は path を持たない)。記載を「`/static/` (Prefix)」に
  替えれば、以後アセットを足しても platform の変更は要らない。app の契約表にも「participant path の正典は
  `ingress-journey.yaml`、I15 が機械照合する。platform は文書で参照するだけ」の行を同じ PR で足す (現在 app 側に行が無い)。

### ADR-0005 Signpost 2 の置き換え (Signpost 2′)

集約すると 30 operation になるが、行数は約 2,640 行 (見込み) で 2,500 を超えたままになる。数字を合わせにいくのではなく、測るものを直す。

- **数えるもの**: JSON object の応答を持つ operation。ADR-0009 の V(A)-1 が spec から機械導出している集合で、required check の
  テストが件数を pin している (`internal/scoreboard/apispec_parity_test.go:610`、e74d871 で 25)。静的配信や HTML shell は入らない。
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
  context map、ADR-0029 の I17)。単一 writer を保ったまま境界を引けないと示されたときに限り、バイナリ分割を I1 と上記決定の
  supersede (CEO 判断) として起案する。

## Consequences

- **諦めたもの**: 人が読める固定 URL。curl での確認には「HTML から配信名を拾う」1 手が要る (runbook と platform の
  `verification-gates` の手順を直す)。
- **deploy を跨いで開いたままのタブ**: 取得済みの CSS は使い続けられる。未取得のフォント (初めて使う weight) は旧配信名が 404 に
  なり、fallback フォントで表示される。機能は壊れず、再読込で直る。
- **新たに守る不変条件**: 増やさない。I14 (route = spec) と I15 (ingress) が既に対象にしている。
- **追随が要る検査**: `tokensCSSPath` の文字列検査 (`internal/scoreboard/view/csp_test.go:680`) を「描画後の HTML が登録表の配信名を参照している」
  検査に替える。route 数の pin (`internal/scoreboard/apispec_parity_test.go:213` の 37 → 30、`internal/scoreboard/authz_test.go:272` の 15 → 8)。
  `PROVENANCE.md` 2 本にある配信 path の記述。
- **ADR-0005**: 本体は書き換えない。索引の 0005 の行から本 ADR へ導線を張る。本 ADR が Accepted になるまで Signpost 2 の元の
  文言が有効である。

## Signposts (この決定を覆す観測可能な信号)

1. 埋め込みアセットの合計が 2 MB を超える、または 1 ファイルが 500 KB を超える (e74d871 は 8 本で 198 KB) → 圧縮済みの配信か
   別経路を検討する (バイナリと常駐メモリに載るため)。
2. `/static/` に認証や利用者に依存する内容を置く要求が 1 件出る → D5 を緩めず API 側に route を設計する。要求が続くなら D5 の
   線引きを ADR で見直す。
3. deploy 後に「表示が崩れた」報告が 1 件出る (古い HTML か、旧配信名の 404 が原因) → D3 の HTML cache 方針か、旧配信名の
   猶予配信を再設計する。
4. アセットにサブディレクトリが要る、または portal の JS / CSS を外部アセットにすると決まる (P28 architect §9 の覆す信号) →
   前者は I15 の照合規則の再設計が先 (ADR-0021 Signpost 1)。後者は script を登録表に載せる条件を本 ADR の supersede で決める。

## Verification

V1〜V6 は P28-0c の PR で満たす (**未実装**)。V7 は実機でのみ確認可。V8 は両リポの PR で満たす。V9 は既に在る。

- **V1 route**: 静的配信の route がちょうど 1 本。I14 の parity が green (spec は 37 → 30 operation)。
- **V2 参照の完全性**: `/` と `/portal` を描画した HTML と、配信する全 CSS に現れる `href` / `url()` が、すべて mux 経由で 200 を返す
  配信名である。`/vendor/` とハッシュ無しの `/static/` は 0 件。参照の抽出が 0 件なら fail。
- **V3 hash の性質**: アセットを 1 byte 変えると配信名が変わり、それを参照する CSS の配信名も変わる (合成した登録表でテスト)。
- **V4 header**: 配信名は `max-age=31536000, immutable`。未知の名前・ハッシュ無しの名前・登録表に無い埋め込みファイルは 404 +
  `no-store` + `{"error": …}`。HTML shell は `no-store`。
- **V5 I15**: allow-list に `/static/` (Prefix) があり、`/vendor/*` の Exact が残っていない。合成入力で「`/static/` 配下の operator
  route」が reverse 検査で赤になる。
- **V6 故意違反**: テンプレートにリテラルの `/static/tokens.css` を書くと V2 が赤、登録表から 1 本落とすと V2 が赤、を恒久の
  テストケースにする。
- **V7 実機 (単一 origin)**: admin でない参加者が配信名を 200 で取れる (`/check-admin` の 403 にならない)。`/static/does-not-exist` が
  404 を返す (403 ではない)。tokens.css を変えた image に入れ替えた後、再訪したブラウザが hard reload なしで新しい CSS を得る
  (app#277 の回帰。ブラウザ E2E ハーネスができるまでは qa の手動検証)。
- **V8 クロスリポ**: platform の文書 PR が同時に出て、相互リンクされている。
- **V9 Signpost 2′ の計測点**: 既存の pin (`apispec_parity_test.go:610`) をそのまま使う。新しい検査は足さない。

**architect の判定: yes, if** — V7 が緑であること、V8 が同時であること、D5 を security-engineer が確認すること。

## Advice

- app#277 (2026-09-01、review-5x R4): path に content hash を埋める案と、ingress を Prefix にする論点の指摘。
- VP 既定 3 (2026-10-04、CEO 承認): Signpost 2 にはサービス分割で応えず、閾値を本 ADR で再定義する。
- R2 / R4 レビュー (2026-10-04): 集約しても行数の条件が残ること、`tokensCSSPath` の検査が壊れることの指摘。
- security-engineer: **未受領**。Accepted 化の前に必須 (D4 の Prefix と admin ingress の優先、D5 の線引き、404 の扱い)。
