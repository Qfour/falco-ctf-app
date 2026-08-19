# ADR-0005: OpenAPI spec の対象を「サービスの HTTP 面すべて」と定め、実装との parity を fail-closed で機械検査する

- Status: **Accepted** (2026-08-19 VP 承認。4 つのスコープ判断を批准した)
  - **Decision / Verification 節は以後編集しない** — 変更は後継 ADR で行う。
    **一方この Status ブロックは状態記述なので、実態に追随させる** (凍結対象は決定であって状態ではない)
  - **実装されたのは V1-V6 / V8**。`make test` (required check) に載る
  - **V7 は未実施** — `gen-diff-check` は依然 advisory (非 required)。昇格は
    `setup-rulesets.sh` (workspace-local・本リポには無い) の変更を伴うため release-engineer に残る
  - **★VP 裁定 (2026-08-19): V7 は I14 の前提条件ではない。** 上記「昇格の条件」は
    「V1-V8 が landing」と書いているが、**V7 が守るのは生成物の鮮度**であって、I14 が主張する
    「ルート集合 / origin-guard / forward の一致」とは**直交する別の不変条件**である。
    依存関係が無いため前提条件から外す。V7 の実体 (required 昇格) は独立の作業として残す。
    **口伝で運ぶと落ちるので裁定をここに残す** (ADR-0003 の教訓)
  - **5x レビュー 2 巡で判明し、本 PR で閉じた欠陥 3 件** (いずれも変異テストで閉止を独立確認済):
    1. **V3 が「宣言 ↔ spec」しか要求せず、宣言と実際の middleware 適用の一致を要求していなかった** →
       `TestOriginGuard_AllProtectedRoutesEnforced` を `Routes()` から導出。security-engineer が
       `og()` を恒等関数に変異させ **guarded 7 本すべて FAIL・生存 0** を確認 = 403 は origin-guard に
       排他的に帰属する
    2. **Decision 2(b) が必須とした `x-ctf-audience` / `x-ctf-authz` / `x-ctf-rate-limit` に
       Verification が無かった** → `specparity.StringExtParity` を 3 サービスに配線
    3. **V2 の走査範囲が手書きのファイル allowlist (6 本) だった** → `cmdOwnsServeMux` の
       import BFS から機械導出 (**実測 34 ファイル**)。除外は `internal/apispec/route.go` 1 本のみ =
       検査自身の登録箇所。走査集合が空なら fail する非空ガード付き
  - **本 PR で閉じていない残余** (→ 後継 **ADR-0006 / Issue #144** で条文化・#146 で構造化):
    - **宣言 ↔ 強制の非結合が `x-ctf-authz` に残る** — spec と宣言が一致していても
      **handler が認可ゲートを呼ばない**ルートを作れる (security-engineer が実証: 匿名 GET が 200 で
      store 内容を返した)。**origin-guard と同じ欠陥クラスの残存分**
    - **`apispec.Register` の 2 回目呼び出し** (戻り値破棄) で mux ⊋ `Routes()` を作れる (#146 で
      `NewMux` により構文的に不可能にする。本 PR は静的 assert で検出)
    - **V5 のカバレッジ** — 3 spec 合計 18 operation のうち 4 のみ。`CompareResponse` は
      `properties` を持たない節点を無言 return する
    - **`specparity` が test-only であることの Go レベルの強制**
- Date / Deciders: 2026-08-19 / architect (起案) + VP (承認) + software-engineer (実装) + qa-engineer (parity test) + security-engineer (origin-guard 契約のレビュー)
- 関連: Issue **#115** (spec が実ルートの 43-47% しか覆っていない — 本 ADR はその設計決定部分)、
  Issue **#113** (`err.Error()` 漏出 + エラー契約の不在。本 ADR は §Decision 5 で**形の契約だけ**を決め、
  RFC 9457 への移行は別 ADR に残す)、ADR-0003 (origin-guard を reset-dirty から外せない理由の出所)、
  ADR-0001 / ADR-0004 (ADR 規律の先例)、app conventions の Cross-repo 契約表
- フェーズ: P## 非該当 (組織診断 2026-08-18 の「機構化されていない規約は 0% 遵守」への対処)

## Context

### C1. 実測 (すべて本 ADR 執筆時の main = `be8809f` で確認)

scoreboard の mux に登録されているルートは **20 本**:

| 出所 | 本数 | file:line |
|---|---|---|
| `api.Handler.Register` | 14 | `internal/scoreboard/api/api.go:270-345` |
| `ingest.Handler.Register` | 1 | `internal/scoreboard/ingest/ingest.go:52-56` |
| `scoreboard.NewHandler` (healthz / metrics) | 2 | `internal/scoreboard/server.go:153-154` |
| `view.Handler.Register` | 3 | `internal/scoreboard/view/view.go:91-99` |

旧 spec (`docs/openapi-scoreboard.yaml` v1) が記載していたのは **10 本** = **50%**。
JSON API だけを分母にすると `api.go` の 14 本中 6 本 = **43%** (VP 実測値と一致)。
未記載の 8 本には **participant の主画面** `GET /api/users/{user}/journey`
(`api.go:273`、portal が 2 秒ごとに polling: `internal/scoreboard/view/templates/portal.html:2261`
が `/me`、Story pane が journey) と **collector の入口** `POST /internal/exfil/{cid}`
(`api.go:316`) が含まれていた。

他 2 サービスも同様:

| サービス | 実ルート | 旧 spec | 欠落 |
|---|---|---|---|
| auth-policy | 4 (`internal/authpolicy/server.go:81-84`) | 3 | `GET /check-admin` |
| collector | 5 (`internal/collector/collector.go:125-135`) | **0 (spec 自体が無い)** | 5 |
| ttyd-proxy | **0** (`internal/ttydproxy/ttydproxy.go:151` は catch-all の `ServeHTTP`。`ServeMux` を持たない) | — | 対象外 |

### C2. 「記載されているが嘘」の実測 (未記載より悪い部分)

旧 spec が**書いていた**内容のうち、実装と食い違っていたもの:

1. `GET /api/state` に **403 が無い**。実装は admin 以外を 403 で拒否する (`api.go:1769-1774`)。
   「認証不要の公開エンドポイント」と読める記述だった。
2. `State.challenges[].type` の enum が `[trigger, evade]`。実装には **`detect`** がある
   (`api.go:771` / `metrics.SolvesTotal(..., "detect")` `api.go:878`)。
3. `State.leaderboard[]` / `recent_solves[]` / `solved[]` に **`display_name` が無い**
   (実装は全て返す: `api.go:1786`, `1930`, `1990`)。UI が読んでいるフィールドが spec に無い。
4. `GET /` に **403 が無い** (`view.go:116-119` が非 admin に 403 HTML を返す)。
5. `/metrics` の系列一覧が古い: `taint_error` (`metrics.go` の doc)・`kind=detect`・
   submissions の `not_exfiltrated` / `not_detect` / `detect_*` / `rate_limited`・
   `scoreboard_http_request_duration_seconds` が**すべて未記載**。
6. `POST /api/challenges/{cid}/submit` の 200 に `exfiltrated` / `display_name` が無く、
   500 も無い (`api.go:666`, `701-710`, `717-723`)。
7. auth-policy `/check` の decision table が「5xx は upstream をそのまま surface」と書いていたが、
   実装は **予期しない status を 502 にマスクする** (`internal/authpolicy/server.go:148-152`)。
   これは「漏らさない」という設計意図と逆の記述だった。

### C3. 根因 (ここを外すと再発する)

- spec 同期は **手順書 (`.claude/skills/regen-openapi`) に委ねられていた**。組織診断 (2026-08-18) の
  結論どおり、**機構化されていない規約の遵守率は 0%** だった。
- 既存の `gen-diff-check` (`.github/workflows/checks.yaml:86`) は **spec → 生成型**の一方向しか見ない。
  spec に**書かれていないルート**は生成型にも現れないので、この job は永久に緑のままになる。
  しかも `gen-diff-check` は **required check ではない**
  (required は `test` / `chart-lint` / `flag-guard` / `shellcheck / shellcheck` / `challenge-rules` / `build`
   = `setup-rulesets.sh` (workspace-local・本リポには無い))。
- 生成型が**実質使われていない**: レスポンスは全て手書き `map[string]any`
  (`api.go:1713-1748` の missionDetail 等)。**レスポンス契約はコンパイル時に何も保証されていない。**
  だから `dirty` / `dirtyRules` / `exfilReceived` のフィールド名を知る手段が
  「実装を grep する」しか無かった (VP の実害報告)。

### C4. 決めるべき論点 (VP から明示的に委任された 4 つ)

1. `POST /internal/exfil/{cid}` を公開 spec に載せるか / 別 spec か / 載せないか
2. spec の対象は「HTTP 面すべて」か「JSON API のみ」か
3. admin 面と participant 面を 1 spec にまとめるか分けるか
4. origin-guard の有無 (`h.og`) を spec で表現すべきか

## Options

### O1. JSON API のみを spec の対象とし、カバレッジは advisory レポートで見る

- **変更点**: `/healthz` `/metrics` `/` `/portal` `/vendor/*` を spec から外し、
  API ルートのみ記載。CI はカバレッジ率を出力するだけ (fail させない)。
- **コスト**: 低。spec は短くなる。
- **リスクと可逆性**: 「API とは何か」の判定が人間の裁量に残るので、**除外リストが必要になる**。
  除外リストは伸びる — 実際に v1 は `/` を「API ではない」のに載せ、`journey` を「API」なのに
  落としていた (C1)。advisory は 0% 遵守の系譜 (C3) を繰り返す。可逆性は高いが、**再発したときに
  気づく手段が無い**のが本質的な欠陥。
- **効き始める閾値**: 効かない。カバレッジ率は「下がっても merge できる」ので指標にならない。

### O2 (推奨). サービスの HTTP 面すべてを spec の対象とし、宣言的ルートテーブルと双方向 parity で fail-closed 検査する

- **変更点**: (a) spec は **1 サービス = 1 ファイル**で mux に登録された**全ルート**を記載
  (非 JSON ルートは summary + status + audience の薄い項目)。(b) 各 operation に
  `x-ctf-audience` / `x-ctf-authz` / `x-ctf-origin-guard` / `x-ctf-collector-forward` /
  `x-ctf-rate-limit` を**必須**で持たせる。(c) 実装側は `Register` が**宣言的ルートテーブルを
  ループする**形に変え、そのテーブルと spec を Go テストで双方向比較する (`make test` = required)。
  (d) collector spec を新設。(e) 4 つの主要 projection に component schema を与え、
  生成型を段階的に採用できるようにする。
- **コスト**: spec が 3 ファイル・約 1,300 行になる (認知コスト)。`Register` のリファクタと
  parity test の実装 (software-engineer + qa-engineer 各 1 PR 相当)。**除外リストはゼロ**。
- **リスクと可逆性**: 薄い項目でも「書かないと CI が落ちる」ので、新ルートを足すときの摩擦が増える
  (それが狙い)。ルートテーブル導入は `Register` の**構造**を変えるので、レビュー範囲が広い。
  可逆性: spec は文書なので完全に可逆。ルートテーブルは revert 可能だが、
  revert すると parity test が動かなくなるので実質は一方向。
- **効き始める閾値**: **1 本目の新規ルートから**。ルートを足して spec を書き忘れた PR が
  その場で赤くなる。

### O3. 稼働サーバに対する外部契約テスト (Specmatic / Dredd 等) を CI に足す

- **変更点**: spec を対象に、実際に起動したサーバへリクエストを撃って契約検証する。
- **コスト**: 新規ツール依存 + CI でサーバを起動する仕組み。**CI-free prod 方針**
  (images は手動 build/push) と噛み合わず、`make test` のコンテナ内完結 (`Dockerfile.test`) から外れる。
- **リスクと可逆性**: 依存の CVE 面と bump 負債が増える (conventions のサプライチェーン節に新規例外が必要)。
  「ルートが spec に無い」ことは**検出できない** (撃つ対象が spec 由来なので spec の穴は見えない) —
  本 ADR が閉じたい穴に**構造的に届かない**。可逆性は中 (依存を抜けば戻る)。
- **効き始める閾値**: レスポンスの**型**まで検証したくなったとき。今の失敗モードは型ではなく
  **フィールド名と存在**なので、まだ閾値に達していない。

## Decision

**O2 を採る。** 理由: 今回の 8 本の欠落はどれも「書き忘れ」であって「書き方が分からなかった」の
ではないので、効く対策は**書き忘れを機械が落とすこと**に限られる (O1 は落とせず、O3 は構造的に
届かない)。

C4 の 4 論点に対する結論:

### Decision 1. `POST /internal/exfil/{cid}` は **scoreboard の spec に載せる** (別 spec にも、非記載にもしない)

- 「参加者が叩ける入口」との誤読は **`x-ctf-audience: internal` + 冒頭 2 行の明示**で閉じる。
  読者の推測に頼らない。
- **参加者向けの正典は collector 側の `POST /api/challenges/{cid}/exfil`** であり、
  そちらを新設 collector spec に書いた上で `x-ctf-forward-target` で結ぶ。
  「公開の面」と「内部の面」は**別サービスの spec に分かれている**ので、
  1 サービス内でさらに分割する理由が無い。
- 非記載を採らない決定的な理由: **非記載ルートが 1 本でもあると parity gate が除外リストを
  持たざるを得なくなる**。除外リストが v1 spec を 50% まで腐らせた機構そのものなので、
  ここでゼロにしておく (O1 のリスク欄と同じ論点)。

### Decision 2. spec の対象は **「そのサービスの mux に登録された全ルート」** (HTTP 面すべて)

- 判定規則: **`cmd/<x>` の handler が `http.ServeMux` を組み立てるなら、そのバイナリは spec を持つ。**
  `ttyd-proxy` は mux を持たない透過リバースプロキシなので**対象外**であり、これは
  「面倒だから除外」ではなく**機械判定できる規則**である (`grep ServeMux`)。
- 非 JSON ルート (`/` `/portal` `/vendor/*` `/metrics`) は schema を持たず、
  `content: {text/html: {}}` 等で**媒体だけ**を宣言する。安い。
- 得られるもの: **ルート集合の完全一致**という単一の不変条件。「API か否か」という
  人間の判断を検査から排除できる。

### Decision 3. **1 サービス = 1 spec。** audience で分割しない

- admin 面と participant 面は**同一バイナリ・同一 mux** から出ている。文書を分けると
  1 つのルート集合が 2 ファイルに散り、**どちらからも消える**事故が可能になる。
- 認可の差は文書の粒度ではなく **operation の粒度**にある。よって `x-ctf-authz` で表現する
  (`none` / `admin` / `self-or-admin` / `self-or-admin-write` / `claimed-identity`)。
- **`securitySchemes` は使わない。** `X-Auth-Request-Email` を apiKey として書くと
  「クライアントが送るヘッダ」に見えるが、実体は **ingress が上書きして注入する**ヘッダであり、
  クライアントが送った値は捨てられる。OpenAPI の security モデルは「呼び出し側が資格情報を
  提示する」前提なので、この境界を正しく表現できない。**誤解を生む標準表現より、
  正確な独自 extension + 散文を採る** (この判断自体を汎用 skill `openapi-expert` に一般化して書いた)。

### Decision 4. origin-guard は **spec の必須フィールドとして表現する** (`x-ctf-origin-guard`)

- OpenAPI に CSRF ミドルウェアの標準表現は無い。だが**この非対称は契約である**:
  `submit` / `display-name` / `internal/exfil` は collector forward 経路のため**意図的に非対象**で、
  ここに guard を足すと**全提出が 403 になり採点が壊れる**。逆に `reset-dirty` から guard を外すと
  **他人の exfil receipt を削除できる未認証パス**が開く (ADR-0003 A2-2)。
  **両方向に事故がある = 契約**。
- 実測した現状 (7 本が guarded):
  `POST /api/admin/{reset,hints}`・`POST /api/admin/users/{user}/display-name`・
  `POST /api/challenges/{cid}/submit-detect`・
  `POST /api/users/{user}/challenges/{cid}/{steps/{idx}/check, hints/{idx}, reset-dirty}`
  (`api.go:274,275,277,304,325,326,332`)。非対象: `submit` (`:294`)・
  `display-name` (`:344`)・`internal/exfil` (`:316`)・全 GET。
- **キーの省略は fail** (既定 false にしない)。「書き忘れたら guard 無しとして通る」規則は
  fail-open であり、この非対称の性質上許容できない。

### Decision 5. エラー契約 (形だけ。#113 の完全な解決は別 ADR)

1. **非 2xx の JSON body は `{"error": string}` の 1 形のみ** (`components/schemas/Error`)。
2. **`error` キーは 2xx body に出現してはならない。**
3. **採点結果は 200 + 業務フィールド** (`correct` / `evaded` / `exfiltrated` / `solved` / `status`)。
   フラグ不一致は HTTP エラーではない。`reason` は**表示用の散文で、安定性を保証しない** —
   クライアントは boolean / `status` のみで分岐する。
4. 現状の 2 つの逸脱 (rate limit の 429 と `GET /portal` の 500 が `http.Error` で `text/plain`) は
   **spec に `text/plain` としてそのまま書く**。**spec は願望ではなく実装を記述する。**
   JSON 統一は follow-up (下記 Consequences)。
5. `err.Error()` の body 漏出 (#113) は **この schema に対する違反**として扱う。
   spec 側は「安定した運用者向け文言」と定義し、実装を寄せる作業を #113 に残す。

## Consequences

### 諦めたもの

- **spec が長い** (scoreboard 1,685 行 / collector 288 行 / auth-policy 251 行)。
  薄い項目と散文の重複を許した代わりに、**除外リストと人間の裁量をゼロ**にした。
- **新ルートの摩擦が上がる。** ルートを 1 本足すと (i) ルートテーブル (ii) spec 項目
  (iii) 5 つの extension を書かないと CI が落ちる。これは意図した設計であって副作用ではない。
- **RFC 9457 (problem+json) への移行は今やらない。** 既存 `{"error"}` を壊さない additive
  (`code` フィールドの追加) が前提になるので、#113 の実装と同時に別 ADR で決める。
  本 ADR は「形が 1 つであること」だけを固定する。

### 新たに守る不変条件 (提案 = **I14**。今は conventions の表に**書かない**)

> **I14 (提案)**: `http.ServeMux` を組み立てる全バイナリについて、
> **mux に登録されたルート集合 = 対応する `docs/openapi-*.yaml` の operation 集合**であり、
> **origin-guard の有無と collector forward の集合も spec の宣言と一致する**。
> 例外・除外リストを持たない。

**番号の確認**: I11 は ADR-0003 が、I12 / I13a / I13b は ADR-0001 が提案済み (いずれも
まだ conventions の表に未昇格)。よって本 ADR は **I14** を使う。

**昇格の条件 (ADR 索引の規律に従う)**: 下記 Verification V1-V8 が landing し、
**その実装 PR と同じ PR で** `.claude/rules/falco-ctf-app-conventions.md` の表に I14 を追記する。
**先に紙のルールだけ増やさない** — 機構化されていない規約が 0% 遵守だったのが C3 の根因なので、
ここで同じ過ちを繰り返さない。

### runbook / 他ロールへの影響

- **software-engineer**: `make gen` の実行が必要 (本 ADR の spec 変更で `types.gen.go` が動く)。
  **本 ADR の PR は `gen-diff-check` を意図的に赤で出す** — architect は生成物を再生成しない
  規律なので、赤は「未実施」の正しい表示である。V1-V8 の実装と `make gen` は
  software-engineer の 1 PR で閉じる。
- **application-engineer**: portal が読むフィールドは今後 spec が正典。実装 grep をやめられる。
- **release-engineer / VP**: `gen-diff-check` を **required check へ昇格**する判断が必要
  (ruleset 変更 = `setup-rulesets.sh` (workspace-local・本リポには無い) の `CHECKS` に追加)。
  現状 advisory なので、生成物 drift は merge を止めない。
- **platform-engineer**: 契約表に変更なし。ただし collector spec が新設されたので、
  参加者向け exfil URL の正典が文書化された (以後の rename は両リポ同時 PR)。
- **follow-up (Issue 起票を VP に依頼)**:
  (F1) `ratelimit.Middleware` の 429 と `view.portal` の 500 を `httpx.WriteJSON` に寄せて
  「非 2xx は JSON」を例外ゼロにする。(F2) `buildState()` の戻りを `oapi.State` にし、
  レスポンス契約をコンパイラに守らせる (#115 項目 4)。(F3) #113 のエラー契約 ADR
  (RFC 9457 additive 移行)。

## Signposts (この決定を覆す観測可能な信号)

1. **parity test の「例外」要求が 1 件でも出たら** — 除外リストゼロという前提が崩れる。
   そのときは「なぜ spec に書けないルートが存在するのか」を先に問う (十中八九は
   ルート設計の問題であって検査の問題ではない)。
2. **spec が 2,500 行を超えたら、または 1 サービスの operation が 35 本を超えたら** —
   1 サービス 1 mux という前提自体が崩れかけている信号。分割の単位は audience ではなく
   **サービス** (= 新しいバイナリを切る) 側を先に検討する。
3. **フィールド名の drift が field-set parity をすり抜けて 1 回でも本番に出たら** —
   depth-1 + 宣言済みネストという検査深度が不足している。O3 (型まで見る外部契約テスト) の
   閾値に達したと判断する。
4. **`x-ctf-origin-guard` の値を変える PR が、security-engineer レビュー無しで 1 本でも通ったら** —
   宣言だけでは足りず、Decision 4 は「宣言 + 実挙動テスト」(#115 項目 3 の authz 実撃ち) へ
   進める必要がある。
5. **`x-ctf-*` を読む外部ツールを入れたくなったら** — 独自 extension のままか、
   標準 (`securitySchemes` / `x-` の共通化) へ寄せるかを再判断する (Decision 3 の再訪)。

## Verification (= software-engineer への発注仕様。全て fail-closed)

> **走る場所**: すべて Go テスト (`internal/scoreboard/api` / 新規 `internal/apispec` 等) として
> `make test` に載せる。**理由**: `test` は **required check** であり
> (`setup-rulesets.sh` (workspace-local・本リポには無い))、`go test` の exit status がそのまま
> パイプラインの成否になるので「出力の有無で成否を判定する」事故 (feedback memory の
> fail-open を 3 回踏んだ教訓) を構造的に避けられる。新しい CI job も新規依存も足さない
> (`gopkg.in/yaml.v3` は既に直接依存)。

**V1. ルート集合の双方向一致 (blocking)**
`METHOD + path template` の**集合として厳密一致**。spec のみに存在 → fail
(「documented but not implemented」)。実装のみに存在 → fail (「implemented but undocumented」)。
**除外リスト・allowlist を実装しない** (Decision 1 の理由)。対象は
`docs/openapi-{scoreboard,collector,auth-policy}.yaml` の 3 本。

**V2. 実装側の集合の取得方法 (blocking な設計制約)**
`http.ServeMux` は登録済みパターンを列挙できない。かつ **文字列リテラル前提の grep は既に破れている**:
`view.go:98` は `mux.HandleFunc("GET "+cybercoreCSSPath, ...)` と**連結**で登録している
(architect の dry-run で実測。lexical 抽出はこの 1 本を取り落とす)。よって:

- `Register` は **宣言的ルートテーブルをループする**形にする (#115 項目 1)。
  必須フィールド: `Method` / `Pattern` / `Audience` / `Authz` / `OriginGuarded` /
  `CollectorForward` / `RateLimit`。
- **テーブルは `Register` が実際にループする対象そのものでなければならない。**
  「並行して持つ一覧」にすると、それ自体が drift 源になる (この ADR が閉じている穴と同型)。
- parity test は **テーブル**と spec を比較する。あわせて
  「`mux.Handle*(` の呼び出しがテーブルのループ以外に存在しない」ことを静的に確認する
  (テーブル外の直接登録を禁止する。これが V1 の前提を守る)。

**V3. origin-guard parity (blocking)**
`OriginGuarded == true` のルート集合 == `x-ctf-origin-guard: true` の operation 集合。
どちらか片方にしか無ければ fail。**spec 側でキーが欠けていても fail** (既定値を持たない)。
現状の正解値は 7 本 (Decision 4 に列挙)。

**V4. collector forward の bijection (blocking)**
collector spec の `x-ctf-collector-forward: true` な各 operation の `x-ctf-forward-target` が、
scoreboard spec に実在し、かつ `x-ctf-collector-forward: true` を持つこと。逆に scoreboard 側で
`true` な operation は collector 側からちょうど 1 本に指されていること。
現状の正解は 3 本 (`submit` / `display-name` / `internal/exfil`)。
**`reset-dirty` がこの集合に入った時点で fail させる**追加 assert を置く
(ADR-0003 A2-2 の破壊的操作を未認証にしないための保険)。

**V5. レスポンスのフィールド集合一致 (blocking、深さ限定)**
200 レスポンスが `application/json` の object schema を宣言している operation について、
既存/追加のハンドラテストが生成した実 JSON と **top-level のキー集合が厳密一致**すること
(spec の `properties` と比較する。`required` ではない — `required` は
「null になり得ない常在フィールド」に限って付け、生成型がポインタになる余地を残すため)。
**ネストは spec が `properties` を宣言している箇所だけ再帰する** (`additionalProperties` や
schema 無しの箇所は見ない)。配列は先頭要素で判定する。
最低限カバーすべき 4 つ: `Journey` (`detail` / `detail.hints` / `missions[]` / `steps[]` を含む)・
`Me`・`State`・`SubmitFlagVerdict`。
**architect が本 PR で dry-run 済み** (`Me` 12/12・`Journey` 10/10・`MissionDetail` 19/19・
`State` 7/7 で一致) なので、実装時に既存の食い違いを直す作業は発生しない見込み。

**V6. spec ファイルの網羅 (blocking)**
`cmd/*` を列挙し、**`http.ServeMux` を組み立てるバイナリに対応する spec が存在すること**。
存在しなければ fail (= 新サービス追加時に spec を強制する)。`ttyd-proxy` は mux を持たないので
対象外になることを**テスト自身が判定する** (人間が書いた除外リストにしない)。

**V7. 生成物の鮮度 (blocking へ昇格を要求)**
`make gen` の出力が commit 済み `internal/{scoreboard,authpolicy}/oapi/types.gen.go` と一致すること。
機構は既に `gen-diff-check` (`.github/workflows/checks.yaml:86`) にあるが **required ではない**。
**required 集合への追加を VP に要求する** (`setup-rulesets.sh` — workspace-local・本リポには無い)。
これが無いと「spec を直して生成し忘れた」PR が緑で通る。

**V8. 検査自身の fail-closed 証明 (blocking / PR 提出物)**
実装 PR は次の 3 点を**実出力付きで**示すこと (`shell-expert` / 今日の教訓の適用):

1. **故意違反で赤くなること**: 変異させた spec コピー (ルート 1 本削除 / origin-guard フラグ 1 つ反転 /
   フィールド 1 つ rename) に対し検査が fail することを、**テストケースとして実装**し出力を貼る。
   「手で試した」ではなくテーブル駆動テストで恒久化する。
2. **抽出の非空 assert**: 実装側ルート集合が空、または spec の operation 数を下回った場合は
   即 fail (抽出が黙って 0 件になる = 常に緑になる、という fail-open を防ぐ)。
3. **exit status で判定していること**: 出力文字列の有無で成否を決めていないこと。
   `go test` に載せれば自動的に満たされるが、補助スクリプトを書く場合は
   パイプラインの終了状態が最後のコマンドのものになる点に注意する。

**この検査が見ないもの (「見ている」と誤解させないため明記する)**

- フィールドの**型**と値域 (キーの存在と名前だけ。型は V5 の範囲外 → Signpost 3)
- 実際の認可挙動 (401/403 を本当に返すか。#115 項目 3 の別作業)
- `text/plain` body の内容、`reason` 散文の文言
- `additionalProperties` で表現した map の中身 (`events_per_user` / `released`)

## Advice (受けた助言と出所)

- **VP (2026-08-19、本タスクの委任文)**: 「全 14 route を spec に入れるが自明に正しいとは限らない」
  として 4 論点を委任。あわせて「記載されているが嘘が最悪」「推測でフィールドを作らない」
  「検査を書いたら故意違反で fail することを実出力で示す」を条件として提示された。
  → Decision 1-4 / C2 / V5 / V8 に反映。**非拘束の助言ではなく委任条件として扱った。**
- **Issue #115 (2026-08-18 組織設計 research R-C)**: 宣言的ルートテーブル + 双方向 parity +
  authz 実撃ち + `oapi.State` 採用 + collector spec 新設 + advisory→required 昇格、
  および「外部ツール (Specmatic 等) は稼働サーバ前提で CI-free prod と噛み合わない」。
  → V2 / V4 / V7 / O3 の却下理由に反映。**「意図的除外は allowlist にコメント付きで」という
  #115 の記述だけは採らなかった** — 除外リストが根因側の機構だと判断したため (Decision 1)。
  この 1 点は本 ADR が #115 の案を**上書き**する。
- **Issue #113**: エラー契約は architect の ADR 案件、RFC 9457 additive 移行が推奨案。
  → Decision 5 で**形だけ**決め、移行は別 ADR に残した (本 ADR の範囲を膨らませない)。
- **ADR-0003 / app#124 5x review (R1 finding C3)**: `reset-dirty` の origin-guard を外すと
  A2-2 の破壊的 reset が未認証になる。→ Decision 4 と V4 の追加 assert の根拠。
