# ADR-0012: エラー/採点 body に機械可読 `code` を additive で追加し、表示文言の所有権を frontend へ移す

- Status: Proposed
- Date / Deciders: 2026-08-25 / architect (起案)。**VP 承認待ち** (API 契約変更は同意権対象)。
  security-engineer の監査意見は本 ADR 執筆時点で未取得 (Advice 節参照)
- 関連: Issue #113 (本 ADR の起点)、Issue #159 (429/500 の JSON 統一、解消済み)、
  Issue #115 (spec 網羅性)、ADR-0005 (OpenAPI canon / parity gate。§Decision 5 で
  「形の契約だけ」を決め、本 ADR に RFC 9457 additive 移行を明示的に委譲した
  [`docs/adr/0005-openapi-canon-and-parity-gate.md` Consequences 「諦めたもの」
  + follow-up F3])
- フェーズ: P## 非該当 (組織診断 2026-08-18 の「機構化されていない規約は 0% 遵守」系の
  security P2 対応)

## Context

### C1. 実測 (本 ADR 執筆時点、`origin/main` = `eec7500`)

`internal/scoreboard/api` パッケージ (`api.go` 2302 行 + `qa.go`) は非 2xx を
`httpx.WriteJSON(w, status, map[string]any{"error": <string>})` の 1 形で返す
(`internal/scoreboard/httpx/httpx.go:10` の薄い wrapper のみ、body の形を強制する型は無い)。

- `"error"` キーの構築箇所: **api.go 60 箇所 + qa.go 29 箇所 = 89 箇所**
  (`grep -n '"error"' internal/scoreboard/api/api.go internal/scoreboard/api/qa.go`)。
  Issue #113 の「約 45 箇所」は api.go 単独かつ P25 QA チケット機能 (ADR-0006, qa.go 新設)
  landing 前の数字で、その後増えている。**契約自体は既に単一形に収束している** — spec
  (`docs/openapi-scoreboard.yaml:53-70`, `components/schemas/Error` at `:1405-1414`) が
  ADR-0005 Decision 5 で「非 2xx body は `{"error": string}` の 1 形のみ」と既に定めており、
  実装はこの契約に**形としては**従っている。欠けているのは形ではなく **機械可読性**。
- `err.Error()` を body に直接入れている箇所: api.go 13 + qa.go 7 = **20 箇所**
  (`grep -n '"error": err.Error()'`)。うち **api.go の 4 箇所 (729/774/826/1461) は 500
  (store 経由)** で、`internal/store/store.go` の `fmt.Errorf("reset solved: %w", err)`
  (`store.go:394` 等) のように SQL テーブル名を含む wrap がそのまま漏れる経路。
  qa.go の 7 箇所は全て 400 (JSON decode か `validQuestionSubject`/`validQuestionBody`
  の静的文字列由来、`qa.go:39-62`) で、store/driver 由来の漏出は無い — **api.go と qa.go
  で既に危険度に差がある実測結果**。
- **並行作業との重複回避**: `git worktree` 未使用のメインチェックアウトの working tree
  (branch `fix/csp-admin-dashboard`, 未 commit) に、この 20 箇所のうち reset/releaseHint/
  adminSetDisplayName/submit/submitDetect の decode パスを `errMsgResetFailed` 等の
  named constant に置き換える差分が**進行中**であることを確認した (このタスクの前提となる
  「即応対応」= software-engineer 並行実装)。本 ADR は**この作業と衝突しない設計**にする
  (constant への置換はそのまま活かし、各 constant に対の `code` を足す形にする)。
  本 ADR 自体は独立 worktree (`docs/adr-0012-error-contract-rfc9457`, base `origin/main`)
  で作業し、進行中の diff には触れていない。
- **UI 文言のサーバ側ハードコード**は「日本語の reason 文」というより、**英語散文の中に
  frontend のボタンラベルそのものが文字列として埋め込まれている**という形で存在する:
  `api.go` の `EvadeForbiddenFired` 分岐 (`reason` 生成、現在の行番号は約 924-931 —
  Issue 本文の「830/840/850」から後続 commit でずれている) が
  `"...use the mission panel's \"このミッションをやり直す\" (redo this mission) button..."`
  という文を組み立てており、この **`このミッションをやり直す` という文字列は
  `internal/scoreboard/view/templates/portal.html:1722` のボタンラベルと文字列として
  重複している**。frontend がボタン文言を変えても (i18n 対応や文言修正)、backend の
  この埋め込みは追随せず、**どのテストも検出できない**まま「存在しないボタン名を案内する
  文」に静かに劣化する。これは「サーバに散文がある」こと自体とは別の、**2 箇所所有の重複**
  という具体的な欠陥であり、Issue #113 の「表示文言の所有者が backend に漏れている」の
  最も濃い実例。
- **spec は既にこの ADR の着地点を予約している**: `docs/openapi-scoreboard.yaml:1512-1514`
  (`SubmitFlagVerdict.reason` の description) が
  「reason is display prose (currently server-side Japanese copy; the ownership of that
  copy is an open question — Issue #113)」と明記済み。`Error` schema (`:1405-1411`) も
  「`error` is meant to be a stable, operator-facing message; ... Issue #113 ... that is
  a defect against this schema, not an alternative contract」と明記済み。**本 ADR は
  この 2 箇所の「open question」を閉じる決定**であり、実装後は該当箇所を本 ADR 参照に
  更新する (この ADR の実装 PR の scope)。
- **機械可読な安定文字列の内部語彙は既に存在する**: `metrics.SubmissionsTotal.WithLabelValues`
  と `auditLog(...)` が、api.go の各分岐で `wrong_flag` / `not_evaded` / `not_proven` /
  `not_exfiltrated` / `solved` / `unknown_challenge` / `not_evade` / `bad_request` /
  `rate_limited` / `detect_invalid` / `detect_missed` / `detect_false_positive` /
  `exfil_not_required` / `received` 等の**安定した snake_case 文字列**を計算済みで
  持っている (`api.go:877-1232` 全体)。これはメトリクスラベルの cardinality 制約から
  すでに「有限集合の識別子」として運用されている値であり、**新しい語彙を発明する必要が
  ない** — クライアント向け `code` はこの既存語彙をそのまま re-export すればよい。
- `SubmitDetectVerdict.status` (`docs/openapi-scoreboard.yaml:1552-1554`) は
  `enum: [invalid, missed, false-positive, solved]` として**既に**機械可読な verdict
  識別子を持っている。`SubmitFlagVerdict` にはこの対がなく、`correct`/`evaded`/`proven`/
  `exfiltrated`/`solved` の boolean 合成のみで分岐させている (spec の
  description が「Clients MUST branch on the booleans only」と既に明示)。
- **frontend の消費実態**: `portal.html` は `d.error` (2780/2903/3172) と `d.reason`
  (1902/1903) を**すべて `textContent` への代入**で使っており (`msgEl.textContent = ...`,
  XSS 安全)、**文字列比較による分岐は 1 箇所も無い** (`grep -n "d\.error\s*===\|d\.reason\s*==="`
  が 0 件)。つまり現行クライアントは `error`/`reason` を**表示にのみ**使っており、
  分岐は boolean/status に対して既に正しく閉じている。この事実が本 ADR の additive 移行を
  低リスクにしている根拠— 既存クライアントの分岐ロジックを壊す経路が実測で存在しない。
- **collector は body を一切見ない**: `internal/collector/collector.go` は
  `net/http/httputil.ReverseProxy` によるバイト透過フォワードで、レスポンス body の
  JSON parse や Content-Type 判定を一切行わない (`grep -n 'json\.\|Decode\|Unmarshal'` が
  0 件)。エラー body の形式変更は collector に対して非事象。

### C2. 制約 (既存の決定事項との整合)

- ADR-0005 Decision 5 は「非 2xx body は `{"error": string}` の 1 形のみ」「`error` は
  2xx に出ない」「採点結果は 200 + 業務フィールド」「`reason` は非安定散文」を**既に確定**
  している。本 ADR はこれを**書き換えない** — additive にフィールドを足すだけ。
  Decision 5 の 5. がそのまま本 ADR に「`err.Error()` 漏出は schema 違反として扱う」を
  引き渡している。
- ADR-0005 V5 (レスポンスのフィールド集合一致検査) は `Journey`/`Me`/`State`/
  `SubmitFlagVerdict` の 4 schema のみを対象にしており、`Error` schema 自体は
  V5 の対象外 (`internal/scoreboard/api/apispec_parity_test.go` 相当が比較する
  4 schema のリストに `Error` が入っていない — 5x レビューで確認された既知の残余、
  ADR-0005 Consequences 「#149 で閉じていない残余」の V5 カバレッジ項目)。**本 ADR は
  `Error` schema にフィールドを足すが、それを機械検査に載せるかどうかは Verification 節で
  別途決める** (既存の V5 の射程を暗黙に拡張しない)。
- openapi-expert skill (汎用) の「response enum の非対称」原則: `code` を OpenAPI の
  `enum:` として宣言すると、将来の値追加が**クライアントへの新しい要求**になり破壊的になる。
  `SubmitDetectVerdict.status` は既に `enum:` で運用されているが、これは本 ADR が導入した
  ものではなく既存の別ミス — 本 ADR の対象外として指摘のみ残す (Signpost 4)。

## Options

### O1. 何もしない (即応対応の err.Error() 修正だけで完了とする)

- **変更点**: 進行中の即応対応 (named constant 化) のみ。`code` フィールドは追加しない。
- **コスト**: ゼロ (追加作業なし)。
- **リスクと可逆性**: Issue #113 が明示的に要求している「機械可読フィールドが無い」問題を
  解決しない。多言語クライアント (将来の外部連携、または単に英語以外の participant UI) は
  依然 `error`/`reason` の**自由文字列を parse**するしかなく、spec が「MUST NOT be parsed」
  と明記している契約と現実の需要が矛盾したまま残る。可逆性は高い (いつでも O2 に進める) が、
  Issue が re-open される。
- **効き始める閾値**: 効かない。Issue の受け入れ条件を満たさない。

### O2 (推奨). `Error` schema と `SubmitFlagVerdict` に `code` (open string set) を additive で追加する

- **変更点**:
  1. `components/schemas/Error` に `code: {type: string}` を追加。**`enum:` にしない**
     (openapi-expert 原則。将来の値追加を非破壊にするため open set とし、description に
     「未知の `code` に対してクライアントは既定の扱いに fall back すること」を明記する)。
  2. `SubmitFlagVerdict` に同名 `code` を追加。値は既存の `metrics.SubmissionsTotal`/
     `auditLog` 分岐がすでに計算している文字列 (`wrong_flag`/`not_evaded`/`not_proven`/
     `not_exfiltrated`/`solved`) をそのまま re-export する (新語彙の発明ゼロ)。
     `SubmitDetectVerdict.status` は既に同役割を果たしているため変更しない。
  3. Go 側は `httpx.WriteJSON` の直呼びを `httpx.WriteError(w, status, code, message string)`
     という位置引数ヘルパー呼び出しに寄せる (`internal/scoreboard/httpx` に新設)。
     位置引数にすることで「`code` を書き忘れる」ことを型システムで不可能にする —
     map リテラルへの追記という「省略可能な」書き方を構造的に閉じる。進行中の
     `errMsgXxx` named constant はそのまま `WriteError` の `message` 引数として使う
     (置き換えではなく合流)。
  4. `reason` (`SubmitFlagVerdict`/`SubmitDetectVerdict`) と `Error.error` は**そのまま残す**
     (breaking しない)。spec に `deprecated` は付けない — 「不安定な散文」という現行の
     契約以上の約束を新たにしないため、deprecated 宣言自体が不要 (deprecated は「将来消す」
     という約束を意味するが、消す計画は本 ADR の scope 外)。
  5. Issue #113 の「UI 文言を application-engineer 側へ」は、**`code` → ローカライズ済み
     文言の対応表を frontend (`portal.html` または将来の分離 JS) に持たせる**ことで実現する。
     移行完了までは `reason`/`error` を fallback 表示として残す (`code` 未知時、または
     対応表未実装時)。**この対応表の実装自体は application-engineer の作業** (本 ADR は
     方針のみ)。
  6. 即修正: `api.go` の `EvadeForbiddenFired` 分岐から `このミッションをやり直す` の
     literal embedding を削除し、ボタン名に依存しない文 (例:「use the mission panel's
     reset button」) に置き換える。**これは `code` 導入を待たずに software-engineer が
     即応対応と同じ PR で直せる程度の変更**であり、2 箇所所有という具体的な defect を
     本 ADR の待機なしで解消できる。
- **コスト**: spec 2 schema + 20〜89 箇所の Go 呼び出し変更 (段階的でよい。後述)。
  `httpx.WriteError` 新設は小さい。frontend 対応表は application-engineer 側の別工程。
- **リスクと可逆性**: 完全 additive (フィールド追加・新規オプション引数不要な既存呼び出しは
  そのまま動く設計にできる — 後述のロールアウト)。既存クライアント (portal.html) は
  `error`/`reason` を今後も読めるので破壊的影響は実測ゼロ (C1 で確認済み: 文字列分岐が
  存在しない)。可逆性は高い — `code` を読まないクライアントに実害はなく、追加自体を
  revert しても老朽化した状態に戻るだけ。
- **効き始める閾値**: **1 サービス以上で `error`/`reason` の英語散文を実際に parse する
  クライアントが現れた瞬間**、または **i18n (日本語以外の participant UI) の要求が出た瞬間**。
  どちらも Issue #113 が想定する「多言語クライアント」の具体化なので、O2 はその要求が
  来る**前**に安全な受け口を用意しておく設計 (先行整備。実装コストは低いので「効くまで
  待つ」必要はない)。

### O3. 今すぐ RFC 9457 (`application/problem+json`) へ全面移行する

- **変更点**: `type`/`title`/`status`/`detail`/`instance` を全 Error 応答に追加し、
  `Content-Type` を `application/problem+json` に切り替える (Accept ヘッダでの
  content negotiation を `httpx` に実装)。
- **コスト**: 3 spec 合計 89 箇所の non-2xx response に `content:` ブロックを
  media-type 別に持たせる必要が生じ、スキーマの認知コストが跳ねる
  (`docs/openapi-scoreboard.yaml` は既に 1,600+ 行)。`httpx` に content negotiation
  ロジックを新設 (既存の `WriteJSON` 1 関数から increase)。
- **リスクと可逆性**: **検証不能**という構造的な問題がある — RFC 9457 の価値は
  「標準化された `type` URI を複数クライアント/ツールが解釈できる」ことだが、
  現状の消費者は `portal.html` (同一 repo, co-versioned) のみで、collector は
  body を一切見ない (C1)。**外部の第三者クライアントが存在しない状態で
  「RFC 9457 準拠が役に立っている」ことを機械的に確認する方法が無い** —
  Verification 不能な ADR は Hard Invariant に昇格できない (ADR 索引の規律) のと
  同種の問題が、ADR 単体でも「導入した機構が一度も踏まれない」という形で起きる。
  可逆性は中 (Content-Type 変更は一度クライアントが依存すると戻しにくい)。
- **効き始める閾値**: **外部 (falco-ctf-platform 以外、または social/API 連携を持つ
  第三者) のクライアントが scoreboard のエラー body を構造的に消費する具体的な要求が
  出たとき**。それまでは `code` (O2) が同じ問題 (機械可読な分岐) を、
  Content-Type を変えずに解決できる。

## Decision

**O2 を採る。** 理由: Issue #113 が要求する「機械可読フィールド」は `code` の追加だけで
満たせ、既存クライアントの分岐ロジックが文字列比較を一切していない (実測) ため
additive 移行のリスクが構造的に低い。O3 (RFC 9457 全面移行) は今行っても検証手段が
無い投資であり、`code` の導入自体が O3 への足がかりになる (将来 `type` を
`"urn:falco-ctf:error:" + code` として機械的に導出できるため、今の投資は無駄にならない)。

## Consequences

### 諦めたもの

- **RFC 9457 の標準準拠そのもの**は今回獲得しない。`type`/`title`/`detail`/`instance` は
  無い。将来必要になったときに `code` から機械的に導出できる設計にしておくことで、
  「今回の投資が将来の選択を狭めない」ことだけを保証する。
- **`reason`/`error` の即時廃止**はしない。frontend の対応表実装 (application-engineer)
  が完了するまで、両方を並行して返す期間が続く (期間の長さは決めない — 決めるのは
  application-engineer が対応表を完成させたタイミングであり、本 ADR は
  「その後 deprecated を検討する」以上の期限を約束しない)。

### 新たに守る規約 (Hard Invariant への昇格はしない — Verification 節を機構化するまで)

- **非 2xx の JSON body を構築する経路は `httpx.WriteError` 1 本に統一する。**
  `map[string]any{"error": ...}` の直接構築は `internal/scoreboard/httpx` パッケージ
  自身を除いて禁止 (静的検査で強制する。Verification 参照)。
- **`code` を OpenAPI の `enum:` にしない。** 新しい `code` 値の追加は additive
  (クライアントは常に unknown-code fallback を持つことを spec の description に明記する)。

### runbook / 他ロールへの影響

- **software-engineer**: (1) 進行中の即応対応 (named constant 化) の上に
  `httpx.WriteError(w, status, code, message)` を新設し、全呼び出しをこれに寄せる。
  (2) `EvadeForbiddenFired` 分岐の `このミッションをやり直す` literal embedding を
  ボタン名非依存の文に置き換える (即応対応と同じ PR でよい、本 ADR の待機不要)。
  (3) `SubmitFlagVerdict`/`Error` の `code` を spec に additive で足し `make gen` する
  (生成型は response 側で使われていないので `types.gen.go` への実影響は小さいが、
  spec の schema 定義は正典なので必ず更新する)。
- **application-engineer**: `code` → ローカライズ文言の対応表を frontend に実装し、
  `d.reason`/`d.error` の直接表示を対応表経由の表示に置き換える。未知の `code` は
  現行の `reason`/`error` 表示に fall back する (fail-soft、参加者体験を壊さない)。
  `portal.html` のボタンラベルなど「backend が言及する UI 文言」は今後
  application-engineer の専有物とし、backend は `code` 以外の形で言及しない。
- **security-engineer**: `err.Error()` を `httpx.WriteError` の `message` 引数に
  渡す全箇所が「安全な定型文」であることの監査 (静的検査は「code を渡したか」しか
  見ない — メッセージの内容が安全かどうかは人間のレビューが必要。Verification V3 参照)。
- **qa-engineer**: `code` 追加後、`SubmitFlagVerdict`/`Error` を ADR-0005 V5 の
  フィールド集合検査の対象に含めるかどうかを判断する (含める場合は
  `apispec_parity_test.go` 系に schema を追加する PR が別途要る)。

## Signposts (この決定を覆す観測可能な信号)

1. **`code` を実際に消費する 2 つ目のクライアント (外部連携、CLI ツール、多言語 UI) が
   出たとき** — O3 (RFC 9457 全面移行) の検証可能性が生まれるので再訪する。
2. **application-engineer の対応表が完成し、`portal.html` が `reason`/`error` を
   一切表示しなくなったとき** — `reason`/`error` を `deprecated: true` にする
   (削除するかどうかは別判断。「使ってないはず」で消さない、実測で確認する)。
3. **`code` の値集合が 50 を超えたとき、または 1 レスポンスに複数の `code` 相当の
   概念が必要になったとき** — open string 1 個では表現力不足の信号。
   RFC 9457 の `type`/`detail` 分離、または `details[]` (フィールド単位エラー配列)
   の導入を検討する。
4. **`SubmitDetectVerdict.status` の `enum:` に新しい値を追加する PR が来たとき** —
   既存の response enum 拡張が破壊的変更になることが実際に問題化する。そのときに
   open string への変更 (breaking) を検討する。

## Verification

> 現状 **無し** — 本 ADR は Proposed であり実装 PR が無い。以下は
> software-engineer への発注仕様 (ADR-0005 と同じ形式)。**この節が「無し」のままでは
> Hard Invariant への昇格対象にしない** (ADR 索引の規律)。

**V1. 静的検査: `map[string]any{"error":` の直接構築がゼロであること (blocking)**
`internal/scoreboard/httpx` パッケージ自身を除く全ファイルに対し、この構文パターンの
出現を検出する Go テスト (文字列 grep で十分 — ADR-0005 V2 の「文字列 grep は脆い」は
mux 登録パターンの話であり、ここは単一の固定リテラルなので該当しない)。
`make test` に載せ、故意に 1 箇所復元して赤くなることを実装 PR 内で示す
(openapi-expert skill の「検査を書いたときに必ずやること」原則)。

**V2. `httpx.WriteError` が `code` を必須の位置引数として要求すること (blocking、型システムで自明)**
Go のコンパイルが強制するので追加テスト不要 — 関数シグネチャそのものが Verification。

**V3. `code` 値の安全性レビュー (blocking、人間レビュー)**
`httpx.WriteError` に渡される `message` 引数が `err.Error()` を直接含まないことを
security-engineer が実装 PR でレビューする (静的検査は困難 — `err.Error()` を
一度変数に代入してから渡すコードは grep で検出できない。ここは V1 のような機械検査
ではなく人間レビューのゲートとして明記する)。

**V4. spec の `code` フィールドが `enum:` を使っていないこと (blocking)**
`Error.code` / `SubmitFlagVerdict.code` の schema 定義に `enum:` キーが存在しないことを
検査する (yaml を読んで確認する軽量な Go/シェルテスト)。将来ここに `enum:` が
追加されたら fail する — Decision の「open string set」が実装後も維持されることを
機械的に保証する。

**V5. `このミッションをやり直す` の literal embedding がゼロであること (blocking、即応対応の一部)**
`internal/scoreboard/api` 配下に `portal.html` のボタンラベル文字列が literal で
出現しないことを検査する (前者が変わっても後者に影響しないことを保証する分離)。

## Advice

本 ADR は architect が Issue #113 の委任を受けて単独起案した (VP からの直接タスク)。
**執筆時点で security-engineer の助言は未取得。** `err.Error()` の 20 箇所は
security P2 (auth/ingest ではないが internal error 漏出) に該当するため、
CLAUDE.md の「auth / ingest / Dockerfile / secrets / CSP・iframe に触れた変更は
security-engineer レビューを必ず通す」の対象には厳密には該当しないが、**情報漏えいの
性質上、実装 PR (V3 のレビュー含む) は security-engineer を通すことを本 ADR が推奨する**
(義務ではなく助言 — 非拘束)。VP に判断を委ねる。
