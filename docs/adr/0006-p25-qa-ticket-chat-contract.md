# ADR-0006: P25 参加者→運営 QA チケットチャットの API 契約・スキーマ・admin UI 配置

- Status: **Accepted** (security-engineer 軽量レビュー完了・5 findings は本文に反映済み
  [2026-08-21]。VP 承認済み [2026-08-21] — Class-2 相当の契約変更として architect 合意 +
  VP 承認の両方が揃った。実装着手は依然 WIP ドレイン後、かつ P25 は spec 正典化
  ADR-0005 相当 (app#143/#149) の main merge 後という順序が付く)
- Date / Deciders: 2026-08-21 / architect (起案) + VP (承認、2026-08-21)。Class-2 相当:
  新規永続化テーブル・新規 self-scope API サーフェス・origin-guard 表の変更を含むため
  クロスリポ契約ではないが app 内の契約変更として architect 合意 + VP 承認を要件とした
- 関連: `REFACTORING.md` P25 (product brief, product-engineer 2026-08-21)、
  I8 (self-scope prefix-exact)、origin-guard 表 (`.claude/rules/falco-ctf-app-conventions.md`
  の `falco-api` skill)、ADR-0005 相当 (**未 merge**。下記 Context の「番号の予約」を参照)、
  ADR-0003 (evade dirty の永続化・attempt scope の先例)

## Context

### 前提 (brief で確定済み、再議論しない)

- 「1 チケット = 1 スレッド」。参加者は複数チケット作成可。運営の返信は当該参加者のみ可視。
  参加者間チャットは対象外 (`REFACTORING.md` P25 product brief)
- 認可は I8 self-scope パターン (`selfOrAdmin` / `ADMIN_EMAILS`) を流用
- 永続化は新規 SQLite。`store`/`scoring` の採点正典テーブルとは分離
- 通信は既存ポーリング方式を継続 (新規 WebSocket/SSE は導入しない)。**間隔は 5 秒**
  (2026-08-21 VP amendment、review-5x R3 指摘を受けて記録。実装 (`feature/p25-qa-frontend`)
  が「QA は Journey/Me の 2 秒ポーリングと違い高頻度更新を要求しない」+「`questionLimiter`
  レート制限バケットへの負荷を抑える」を理由に 5 秒を採用したことを、この「再議論しない」前提
  ブロックに対する明示的な amendment として承認する。他の前提 [1チケット=1スレッド・self-scope
  認可・新規SQLite分離・rate limit再利用・admin UI配置] は無変更のまま)
- レート制限は既存 `internal/scoreboard/ratelimit` を再利用
- 運営 UI 配置は architect (このADR) が最終判断する

### C1. 既存の認可プリミティブの実装 (`internal/scoreboard/api/api.go`)

- `isAdmin` (api.go:354-361): `X-Auth-Request-Email` ∈ `ADMIN_EMAILS` (小文字化)。空 allowlist =
  fail-closed
- `selfOrAdmin` (api.go:416-433): 読み。ヘッダ**必須**、無ければ 403 (フォールバックなし)
- `selfOrAdminWrite` (api.go:461-478): 書き。ヘッダ**有れば** self-or-admin、**無ければ
  claimed-identity で通す** (cluster-internal — collector forward / workspace 用の弱い経路)。
  この弱い経路は、ブラウザ以外の到達元が無いルート (`steps/{idx}/check` / `hints/{idx}` /
  `reset-dirty`) では `h.og()` origin-guard を**併用**することで事実上閉じている
  (og が Origin/Referer 欠落を 403 にするので、ヘッダ無し = curl/server-to-server は og で
  弾かれ、`selfOrAdminWrite` の弱い分岐に到達しない)。**P25 の新規書き込みルートも同じ二段重ね
  (og + selfOrAdminWrite) を採用する** — 新しいゲート原始は増やさない
- origin-guard の対象 7 本 / 非対象の理由は `.claude/rules/falco-ctf-app-conventions.md` の
  `falco-api` skill 節に実測済み (api.go:274,275,277,304,325,326,332 が guarded)
- collector の forward allowlist は 3 本固定 (`internal/collector/collector.go:125-135`):
  exfil / submit / display-name。**QA はここに追加しない** (参加者の QA 送信はブラウザ (portal)
  からのみで、workspace/curl からの正当な呼び手が無い — 追加すると攻撃面が広がるだけ)

### C2. 永続化層の既存構造 (`internal/store/store.go`)

- `store.Open(path)` は単一 `*sql.DB` を単一 SQLite ファイルに対して開き、`solved` /
  `display_names` / `hint_release` / `exfil` / `hint_views` / `step_checks` / `evade_dirty`
  の 7 テーブルを**1 つの `CREATE TABLE IF NOT EXISTS` ブロック**で管理する
  (store.go:136-183)。単一 mutex (`Store.mu`) で全テーブルの読み書きを直列化
- `internal/scoreboard/scoring` は採点ロジック専用の別パッケージとして既に `store` から
  分離されている (`internal/scoreboard/scoring/scoring.go`) — **「新規機能は新規パッケージに
  分ける」は本 repo の既存の流儀**であり、QA を `store` パッケージに追記するのは既存の
  分離方針からの逸脱になる
- `cmd/scoreboard/main.go:28` — DB パスは `SCOREBOARD_DB` env (default
  `/var/lib/scoreboard/scoreboard.db`)、PVC mount は `charts/scoreboard/templates/
  deployment.yaml:164` の `/var/lib/scoreboard` (同一 PVC、I3 の fsGroup 65532 が既にカバー)

### C3. admin UI の既存の 2 面 (`internal/scoreboard/view/`)

- `GET /` (`index.html`, 584 行): **「legacy operator dashboard」** (`view.go:2` の doc)。
  admin-gate は**ページ全体**にかかる (`view.go:116-119`、非 admin は 403)。UI の中心は
  リーダーボード + `🏆 RESULTS` フルスクリーン表示 (index.html:262-282) — **イベント中に
  プロジェクタ/共有画面へ出す想定の「公開表示」画面**。2 秒ポーリングの hash-router は無く、
  admin 専用の書き込みは reset ボタンと display-name 上書きの 2 つのみ (index.html:528,542)
- `GET /portal` (`portal.html`, 2593 行): 参加者 + 運営が**共有する単一ページ**。
  `PORTAL_TABS` (portal.html:2534) + hash-router + `window.__PORTAL_ROLE__` による
  **defense-in-depth の hidden 属性**タブ切り替えが既にある。実例: `data-tab="scoreboard"`
  (id=`tab-scoreboard`, ラベル「Leaderboard」) は admin 専用で `role !== 'admin'` なら
  `hidden` (portal.html:908,2585)。実ゲートは `GET /api/state` 側の `isAdmin` (server-side)
  であり、client-side の hidden はあくまで「403 への誘導をしない」ための UX
- **esc() は共有モジュールではなく `<script nonce>` ブロックごとにローカル定義される慣行**
  (portal.html に 4 箇所、index.html に 1 箇所、独立コピー) — CSP nonce のスコープが
  script タグ単位のため。どちらのファイルに置いても新しい `esc()` の 1 行コピーが要る。
  **「既存の esc() を再利用できる」は決定の根拠にならない** (両方とも新規コピーが要る)

### C4. ADR 番号・Hard Invariant 番号の予約状況 (実測)

- `docs/adr/` に main へ merge 済みの ADR は 0001-0004 のみ。**ADR-0005 は未 merge**
  (`docs/adr/0005-openapi-canon-and-parity-gate.md` は open draft PR #143 / #149
  (`docs/api-spec-canon` / `feat/api-spec-parity-gate`) 上にのみ存在。`git log main -1` =
  `be8809f`、この commit のツリーに `0005-*` は無い)
- 同様に **I11-I14 は conventions.md の Hard Invariants 表に未昇格** (ADR-0001/0003/0005 が
  「提案」した番号で、機構化 landing まで表に書かない、という既存の規律どおり)
- したがって本 ADR は **ADR-0006 を名乗る** (0005 は #143/#149 の予約済み番号として空けておく —
  無視して 0005 を名乗ると、#143 merge 時に同一番号の 2 ファイルが衝突する)。新しい
  Hard Invariant 番号は要求しない (下記 Decision 4 で理由を述べる)

### C5. スケジュール依存 (VP へのシグナル)

- `feat/api-spec-parity-gate` (#149) が merge されると、`internal/scoreboard/api.Register`
  は「宣言的ルートテーブルをループする」形に変わり (ADR-0005 Decision 2/引用)、各 operation に
  `x-ctf-audience` / `x-ctf-authz` / `x-ctf-origin-guard` / `x-ctf-collector-forward` /
  `x-ctf-rate-limit` の 5 extension が spec 側で必須になる (fail-closed parity gate、
  `make test` に相乗り)
- P25 の実装が **#143/#149 merge 前に着手されると**、新規 7 ルートは現行の直接
  `mux.Handle(...)` 方式で登録することになり、#143/#149 merge 時に **route テーブルへの
  再登録 (二度手間) が発生**する。逆に **P25 が #143/#149 merge 後に着手されれば**、
  route テーブルへの追加 1 回で済み、5 extension も最初から正しい形で書ける
- **REFACTORING.md の WIP ドレイン方針 (実装着手は WIP ドレイン後) と、この順序依存は一致する**
  (#143/#149 は既存 draft PR なのでドレイン対象に含まれる)。VP への提言: **P25 の実装着手順は
  #143/#149 merge 後にする**(本 ADR の契約設計自体は先行して良い、というのが VP からの
  当初指示と一致)

## Options — 運営側 UI の配置

### O1. `GET /` (`index.html`) にチケット一覧+返信 UI を追加

- **変更点**: 584 行の projector 向けページに新しい section (チケット一覧・スレッド・返信フォーム)
  を追加。ページ全体が既に admin-gate 済みなので role 分岐は不要
- **コスト**: 2 秒ポーリング・hash-router が無いページに新規 UI パラダイムを持ち込む
  (現行の「reset ボタン 2 個」レベルの薄い admin UI から「日常的に読み書きする支援チケット
  ワークフロー」への役割拡大)。`esc()` はここでも新規コピーが要る (C3 の指摘どおり利点にならない)
- **リスクと可逆性**: **このページはイベント中にプロジェクタ/共有画面へ表示される想定の
  「公開表示」画面** (`🏆 RESULTS` フルスクリーンモードが実証)。運営が誤ってこのタブを
  会場のスクリーンに出したまま参加者の個別問い合わせ内容 (氏名相当の識別子・質問文) を
  第三者に晒す事故が物理的に起こり得る。これは「今は規模が小さいから起きない」話ではなく、
  **画面の用途そのものが公開表示である**ことに起因する構造的リスクであり、可逆ではあるが
  (UI を後で移設できる) 事故の実害は不可逆 (情報漏えい)
- **効き始める閾値**: このページを実際にプロジェクタへ出す運用が (過去のイベント運用実績から)
  ある、その時点で即座にリスクが実現する。スケール依存ではない

### O2 (推奨). `GET /portal` に admin 専用タブを追加 (`data-tab="qa-admin"`)

- **変更点**: `PORTAL_TABS` に `qa-admin` を追加。`tab-qa-admin` は既存の `tab-scoreboard` と
  同一パターンで `role !== 'admin'` のとき `hidden` (client-side defense-in-depth)。実ゲートは
  新規 `GET /api/admin/questions` の `isAdmin` (server-side)。運営はこのタブを**自分の
  ログインセッションの portal** (プロジェクタではなく個人デバイス/ブラウザタブ) で開く
- **コスト**: すでに 2593 行ある portal.html にさらにタブを追加 (認知コストの増加は認めるが、
  既存の Leaderboard タブが同型で存在するため**パターンの新設ではなく複製**)
- **リスクと可逆性**: 参加者向けタブと同一ページに admin 機能が乗る構造は既に
  Leaderboard タブで実証済みの安全性 (server-side isAdmin が実ゲート、client-side hidden は
  UX のみ)。可逆性は高い (タブの削除は index.html への移設と同程度に安価)
- **効き始める閾値**: portal.html が今後さらに肥大化し (例: 1 ファイルの行数が
  1 万行に近づく、または admin 専用ロジックの比率が参加者向けロジックを圧迫し始める) 場合、
  admin 面を別ページに切り出す再構成が要る。その時点で `index.html` を「projector 表示」
  専用に残し、admin の**作業系**機能 (QA 含む) を第三のページに集約する再設計が signpost になる

### 検討したが採らない: O3. 完全新規の admin-only ページ (`GET /admin/qa` 等)

- 変更点: 新規テンプレート + 新規ルート + 新規 admin-gate 実装
- コスト: 新しい認可ゲート実装面が増える (`isAdmin` の 3 番目の適用箇所)。ADR-0005 の
  parity gate 前提 (ルート集合の完全一致) にも新規ルートとして乗るが、既存 2 面 (`/`, `/portal`)
  で足りる要件に対して過剰。O1/O2 でカバーできる要件に第 3 のページを増やす理由が無い
- 不採用の理由: 「常に最適な設計」であっても、既存 2 面のどちらかで安全に収まる要件に
  3 番目の面を増やすのは複雑性の追加であって最適化ではない (境界を増やすほど admin-gate
  实装面が増え、O1 のリスクとは違う種類だが「新しい認可バグの温床」を増やす)

## Decision

**O2 (portal 内 admin タブ) を採る。** 理由: index.html はイベント中の公開表示 (プロジェクタ)
という**用途そのもの**が QA チケットの機密性と構造的に相性が悪く、この非適合はスケールに
依存しない (Option O1 の「効き始める閾値」参照)。portal の admin タブは既存パターン
(Leaderboard) の複製であり、新しい認可原始・新しい UI パラダイムを増やさない。

### Decision 1. 新規 API エンドポイント (7 本)

参加者向け (`selfOrAdmin` / `selfOrAdminWrite` + og + rate limit):

| メソッド/パス | ゲート | 用途 |
|---|---|---|
| `GET /api/users/{user}/questions` | `selfOrAdmin` | 自分のチケット一覧 (要約) |
| `GET /api/users/{user}/questions/{qid}` | `selfOrAdmin` + 所有権照合 (下記 Decision 2) | スレッド詳細 |
| `POST /api/users/{user}/questions` | `h.og` + `questionLimiter` + `selfOrAdminWrite` | 新規チケット作成 |
| `POST /api/users/{user}/questions/{qid}/messages` | `h.og` + `questionLimiter` + `selfOrAdminWrite` + 所有権照合 | スレッドへの追記 (フォローアップ) |

運営向け (`isAdmin`。og は書き込みのみ、既存 admin/reset・admin/hints と同型):

| メソッド/パス | ゲート | 用途 |
|---|---|---|
| `GET /api/admin/questions` | `isAdmin` | 全参加者の全チケット一覧 (要約 + `user` フィールド) |
| `GET /api/admin/questions/{qid}` | `isAdmin` | 任意チケットのスレッド詳細 |
| `POST /api/admin/questions/{qid}/reply` | `h.og` + `isAdmin` | 運営の返信を追記 |

- 参加者向け書き込み 2 本と運営向け書き込み 1 本を **origin-guard 表に追加** (7→10)。
  **security-engineer レビュー必須** (`falco-api` skill のチェックリスト item 4 と同じ理由:
  origin-guard は両方向に事故があるクラス)
- **collector の forward allowlist は変更しない** (3 本のまま)。QA はブラウザ専用機能であり
  workspace/curl からの正当な呼び手が存在しないため、追加は攻撃面を広げるだけ (Context C1)
- **admin-bypass 経路の扱い (security-engineer finding 5, LOW, 2026-08-21)**: `selfOrAdminWrite`
  は既存の全書き込みルートと同型で self-or-admin を通すため、admin は技術的には participant 向け
  `POST /api/users/{user}/questions/{qid}/messages` にも (`{user}` に任意の参加者を指定して)
  到達できる。**運営の正規返信経路は `POST /api/admin/questions/{qid}/reply` のみと定める** —
  participant path 経由の admin 書き込みは禁止 (運用規律であり、既存ゲート原始を増やさないため
  技術的な経路封鎖はしない)。上記 `author_role` ハードコードにより、admin が participant path
  を誤って叩いても記録される `author_role` は route 固定で `"participant"` になり、運営の返信が
  `answered` 導出に反映されない自己矛盾状態になる — これが誤用を検知する signal になる
  (専用の監視は設けないが、実装 PR で software-engineer が participant path に admin 用の
  近道を追加しないことを確認する)
- レスポンス形状 (すべて既存の `{"error": string}` エラー契約に従う):
  - `QuestionSummary`: `{id, subject, created_at, updated_at, answered, message_count}`
    (admin 一覧のみ `user` を追加)
  - `QuestionThread`: `{id, user, subject, created_at, messages: QuestionMessage[]}`
  - `QuestionMessage`: `{author_role: "participant"|"admin", author, body, created_at}`
  - `answered` はサーバ側で `messages` に `author_role == "admin"` が 1 件以上あるかどうかから
    **導出する** (専用の `status` カラムを持たない — 導出できる状態を別カラムで**二重に**
    持つと同期が崩れるドリフト源になるため、Decision で明示的に避ける)
- **`author` / `author_role` はリクエストボディから素通しで受理しない (security-engineer
  finding 1, HIGH, 2026-08-21)。** 参加者向け書き込み 2 本 (`POST .../questions` /
  `POST .../questions/{qid}/messages`) はサーバ側でルート単位に固定値をセットする:
  `author_role = "participant"`, `author = "{user}"` (self-scope 照合済みの path 由来 ID)。
  運営向け `POST /api/admin/questions/{qid}/reply` は `author_role = "admin"`,
  `author = "<X-Auth-Request-Email>"`。リクエストボディにこれらのキーが含まれていても
  **常に無視する** (decode 後に上書きするか、そもそも request 型に持たせない)。理由:
  `answered` は `author_role == "admin"` の存在から導出するため、素通しにすると participant
  が自分のチケットに `author_role: "admin"` を送って `answered: true` を偽装できる
  (IDOR 隣接の真正性問題)。この規律は Decision 2 の複合キー照合と同格の必須事項として扱う。
- 入力上限 (既存 `MaxBytesReader` 慣行に合わせる): `subject` ≤ 120 文字、`body` ≤ 4096 バイト。
  超過は 400 + `{"error": "..."}`
- 新規レート制限: `questionLimiter := ratelimit.New(0.1 /* 10秒に1回 */, 3 /* burst */)`。
  ticket 作成とフォローアップ追記の**両方が同一バケット**を共有 (`ratelimit.ClientIP` キー) —
  チケット数を分散させたスパムも同じ IP バケットで抑制できる。運営の返信には rate limit を
  掛けない (既存 `admin/reset` / `admin/hints` も無し、trusted actor という既存の判断を継承)

### Decision 2. IDOR 対策: `{qid}` の所有権照合を必ず複合キーで行う

`selfOrAdmin`/`selfOrAdminWrite` は「呼び手が `{user}` を名乗れるか」だけを保証し、
「その `{qid}` が実際に `{user}` のものか」は保証しない。**参加者向けの `{qid}` を含む全ルート
(スレッド詳細・フォローアップ追記) は SQL レベルで `WHERE id = ? AND user = ?` の複合キーで
照合し、単独の `WHERE id = ?` を書かない。** 一致しなければ 404 (403 ではない — 存在の有無を
漏らさない意図は無いが、既存の `journey` 等の self-scope 404/403 慣行に合わせる、
具体は software-engineer の実装判断で良い)。admin 向けエンドポイントは `{user}` を経由しない
単独 `{qid}` ルートを使う (Decision 1 表の admin 行) ので、この照合は不要 — admin は
`isAdmin` 単独で任意チケットに到達できるのが意図した挙動。

**照合と読み書きは同一 `qa.Store` メソッド・同一ロック保持区間で行う (security-engineer
finding 4, MEDIUM, 2026-08-21)。** 所有権照合 (`WHERE id=? AND user=?` の存在確認) と実際の
読み出し/追記を 2 ラウンドトリップに分けない — `qa.Store` の public API は
`GetThreadForUser(qid, user)` / `AppendMessageForUser(qid, user, msg)` のように
「照合込みの単一メソッド呼び出し」だけを公開し、`checkOwnership` を別関数として外に
切り出さない (`Store.mu` を 1 回だけ取得する 1 メソッド内に閉じる)。照合と書き込みが
別メソッド呼び出しに分かれると、その間に別の書き込みが割り込む TOCTOU 的な整合性崩れの
余地が生まれる。

### Decision 3. 永続化: `store`/`scoring` と物理的に分離した新規パッケージ + 新規 SQLite ファイル

- 新規パッケージ **`internal/qa`** (`internal/store` の姉妹パッケージ、`internal/scoreboard/
  scoring` が `internal/store` と既に分離されている流儀を踏襲)。`qa.Store` 型・`qa.Open(path)`
  関数を持つ。**`internal/qa` は `internal/store` を import しない** — これを機械検証する
  (Verification 参照)
- 新規 SQLite ファイル: 既存 `SCOREBOARD_DB` と**同一 PVC の同一ディレクトリ**に置く
  2 つ目のファイル。パスは `SCOREBOARD_DB` のディレクトリから導出する
  (`filepath.Join(filepath.Dir(dbPath), "qa.db")`) — **新規 env var は増やさない、chart の
  values.yaml 変更もゼロ、platform との調整もゼロ**。理由: I3 (`fsGroup: 65532`) は PVC 全体に
  かかるので、同じボリューム内に 2 つ目のファイルを置くのは既存の Hard Invariant の対象範囲に
  収まる。新しい env var を増やすと、それを I7 (chart values は環境非依存 default のみ) の
  文脈でも扱う必要が生じ、契約面を不必要に増やす
- テーブル:
  ```sql
  CREATE TABLE IF NOT EXISTS questions (
    id         TEXT PRIMARY KEY,
    user       TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_questions_user ON questions(user);

  CREATE TABLE IF NOT EXISTS question_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id TEXT NOT NULL REFERENCES questions(id),
    author_role TEXT NOT NULL CHECK (author_role IN ('participant','admin')),
    author      TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_qmsg_question ON question_messages(question_id);
  ```
- `id` (チケット ID) は `crypto/rand` ベースの乱数値 (16 バイトを hex エンコード、
  `internal/scoreboard/view/csp.go` の `newNonce()` と同じ乱数源だが URL path segment に出るため
  base64 ではなく hex を使う — base64 標準アルファベットの `+`/`/` は URL path で安全でない)。
  連番にしない理由: admin は一覧 API から辿るので連番である必要が無く、推測可能な ID を
  参加者に晒す理由も無い (defense-in-depth。self-scope の複合キー照合が主たる防御であることは
  Decision 2 のとおりで、ID のランダム性はこれを補強するだけの二次防御)

### Decision 4. 新しい Hard Invariant 番号は要求しない

Decision 2 の複合キー照合は本機能ローカルの実装規律であり、I1-I10 のような横断的な
アーキテクチャ制約 (replica 数・UID・イメージ本数など) とは性質が異なる。I11-I14 (未昇格) の
並びに乗せて「I15」を予約することもできるが、対象が単一機能の 1 パターンに留まるため、
本 ADR の Verification に留め、conventions.md の表を汚さない選択をする
(README.md の規律「Verification が無い ADR を Hard Invariant に昇格させない」の逆方向の
判断 — Verification があっても、横断性が無ければ昇格させない、というのが今回の追加判断)。
security-engineer が横断的リスクと判断すれば、後継 ADR で昇格を提案してよい。

### Decision 5. spec (`docs/openapi-scoreboard.yaml`) への追加方針

- 新規 7 operation を既存 `docs/openapi-scoreboard.yaml` に追記する (**新規 spec ファイルは
  作らない** — ADR-0005 Decision 3 「1 サービス = 1 spec、audience で分割しない」と同じ理由が
  そのまま適用できる。QA も admin/participant 両面が同一バイナリ・同一 mux から出る)
- **C5 のスケジュール依存に従う**: #143/#149 merge 前に P25 の実装が着手された場合でも、
  新規 operation には `x-ctf-audience` / `x-ctf-authz` / `x-ctf-origin-guard` /
  `x-ctf-collector-forward` / `x-ctf-rate-limit` の 5 extension を**先行して**書く
  (spec 全体がまだ揃っていなくても、新規箇所だけは前方互換に揃えておくのは無償)
- component schema (`QuestionSummary` / `QuestionThread` / `QuestionMessage`) を追加し、
  **request body には生成型 (`oapi-codegen`) を使う** — 既存の 3 箇所の request-body 使用例
  ("生成型はほぼ使われていない" という既存の負債) と同じ慣行に合わせる
- **response にも生成型を使うことを推奨する** (advisory。既存コードは response を全て
  手書き `map[string]any` で返しており、これが Issue #113/#115 (未 merge の ADR-0005 が
  指摘) の温床になっている。P25 は新規サーフェスなので、既存負債を追加せず生成型を使う
  機会がある。ただし他ルートとの一貫性を優先するなら手書きでも良く、**これは architect の
  同意権が及ぶ「契約」の範囲外の実装判断として software-engineer に委ねる**)
- `make gen` を同一 commit に含める (`falco-api` skill のチェックリスト item 3)

## Consequences

### 諦めたもの

- チケットに `status` (open/closed) の明示カラムは持たない。運営が「対応済みにする」操作
  (クローズ) は本 ADR のスコープ外 — `answered` は `messages` から導出するだけで、
  「クローズしたが返信していない」状態は表現できない。将来必要になれば新規カラム追加は
  additive (後方互換) なので ADR 単体で対応可能
- admin 一覧のページング/フィルタ (`?unanswered=1` 等) は MVP に含めない (小規模イベント
  規模では全件表示で足りる、という product brief のスコープ判断をそのまま継承)
- index.html への統合案 (O1) は採らない — 将来 index.html が「作業系 admin ページ」に
  路線変更されるなら再訪の余地はあるが、現在の「公開表示」という役割を変えない限り不採用

### 新たに守る規律 (Hard Invariant 表には追記しない。理由は Decision 4)

1. `internal/qa` は `internal/store` を import しない (物理的分離の機械検証、Verification 参照)
2. 参加者向け `{qid}` ルートは必ず `(id, user)` 複合キーで照合する (単独 `WHERE id=?` 禁止)、
   かつ照合と読み書きを同一 `qa.Store` メソッド・同一ロック区間で行う (finding 4)
3. QA の書き込みルートは collector forward allowlist に追加しない
4. `author` / `author_role` はリクエストボディの値を無視し、常にルート単位のサーバ側固定値
   (`participant`+`{user}` / `admin`+admin email) を書く (finding 1)
5. 運営の正規返信経路は `POST /api/admin/questions/{qid}/reply` のみ。participant path 経由の
   admin 書き込みは運用規律で禁止する (finding 5)

### runbook / 他ロールへの影響

- sre-engineer: 運営向け「回答でヒント/flag相当を答えない」運用ガイドラインの合意
  (product brief が明記済みの引き渡し事項。本 ADR は関与しない)
- security-engineer: 新規 origin-guard 対象 3 本のレビュー必須。IDOR 複合キー照合の実装確認
- release-engineer: #143/#149 merge 順を P25 着手前に確保 (C5)

## Signposts (この決定を覆す観測可能な信号)

1. **index.html が「公開表示」から「運営の日常作業ページ」へ役割変更される**
   (例: プロジェクタ表示モードが撤去される) → O1 を再検討できる
2. **portal.html が 1 ファイルとして肥大化しすぎ、admin 専用ロジックが参加者向けロジックの
   保守を妨げ始める** (例: 1 万行接近、admin タブが 3 つ以上に増える) → admin 面を別ページに
   切り出す再構成の signpost
3. **チケット/メッセージ量が SQLite の単一ファイル・単一 mutex (I1: replicas=1) の書き込み
   スループットを可視に圧迫する** (例: 参加者数が数百人規模のイベントに拡大する) →
   `qa.db` を独立サービスに切り出す、または非同期化を検討する signpost
4. **`answered` の導出コストが一覧 API のレイテンシで問題になる** (メッセージ数が多いチケットの
   JOIN/集計が遅い) → 導出をトリガー/カラムキャッシュに変える signpost。ただし
   Decision の「二重管理を避ける」判断はこの signpost が実現するまで維持する

## Verification

1. **`internal/qa` が `internal/store` を import しない**: ADR-0005 (#149) の
   `dependency_boundary_test.go` と同型の静的 import 検査を追加する
   (`go list -deps ./internal/qa/... | grep internal/store` が空であることを assert する
   Go テスト。故意に import を足したコピーで red になることをテストケースとして固定する)
2. **self / cross-user / prefix-adjacent / admin の 4-way**: `journey_api_test.go` の
   `TestJourneyWriteGate_StepCheck_HeaderPresent` と同型のテーブル駆動テストを QA の
   全書き込みルートに対して用意する (self→200, mismatch→403, prefix-adjacent (`alice2@`)→403,
   admin→200)
3. **IDOR 複合キー照合**: alice のチケット qid に対して bob が (a) `GET /api/users/bob/
   questions/{qid}` (bob 自身の user path、他人の qid) と (b) `POST /api/users/bob/questions/
   {qid}/messages` (フォローアップ追記。読みだけでなく書きでも同じ穴が開き得る) の**両方**を
   叩くと 404 になることを assert するテスト (self-scope は通るが所有権照合で落ちるケースを
   明示的に踏む — (b) が無いと Decision 2 の「複合キーで照合する」という規律が書き込み経路
   では検証されない。security-engineer finding 2, HIGH, 2026-08-21 で追加)
4. **participant→participant 到達不可**: 「participant 宛のメッセージ API が存在しない」は
   ルートテーブル (または `Register` の grep) に participant-to-participant な操作が
   存在しないことを目視 + このADRのDecision 1 表が全routeである、という前提を
   spec parity gate (#149 merge 後) に載せることで機械検証に格上げできる。**#149 merge 前は
   目視のみ** (無しとは書かない — 理由付きで明示)
5. **レート制限**: `ratelimit_test.go` と同型で、`questionLimiter` の burst 超過が 429 を返すこと
   をテストする
6. **回帰**: `internal/scoreboard/scoring/scoring_test.go` および既存 `store_test.go` が
   本機能の追加によって**無変更のまま** green であること (diff に scoring/store 関連ファイルが
   含まれないことは PR レビューで確認。構造的な保証は Decision 3 の物理分離そのものであり、
   テストの green は結果でしかない点に注意 — 本項目単体を「保証」と呼ばない)
7. **origin-guard**: 新規 3 本 (participant 2 + admin 1) が `TestOriginGuard_
   AllProtectedRoutesEnforced` (`internal/scoreboard/origin_guard_test.go:186-216`、#149 由来、
   あるいは #149 merge 前なら同型の手書きテスト) の対象集合に含まれること。
   ⚠ **このテーブルは `Register()` から自動導出されない手書きテーブルであり、新規ルートの
   追加漏れがあっても CI は red にならない (機械強制ではない。security-engineer finding 3,
   MEDIUM, 2026-08-21)。** #149 merge 前にこのギャップを埋める機械検査は無い。代わりに
   実装 PR レビューで security-engineer が目視で以下を確認するチェックリスト項目として残す:
   (a) 新規 3 ルートがテーブルに 1 行ずつ追加されているか、(b) 追加された行のルートパスが
   Decision 1 の表と一致するか。#149 merge 後、spec parity gate がこの手書きテーブルを
   置き換えたら、この目視確認ステップは不要になる (signpost)

## Advice

- product-engineer (2026-08-21, product brief): UX フロー・認可流用・レート制限必須・
  admin タブ推奨・運用ポリシーリスクの明記を受けた。本 ADR は admin タブの推奨を採用し、
  かつ根拠を index.html の「公開表示」という用途面の非適合という新しい論点で補強した
  (product brief 時点では「既存パターンとの一貫性」が主根拠だったが、architect 調査で
  「プロジェクタ表示への機密情報混入リスク」という不可逆コストのある論点を追加した)
- security-engineer (2026-08-21, 軽量レビュー・5 findings): (1) HIGH `author`/`author_role`
  はルート単位サーバ側ハードコードとし client 入力を無視、(2) HIGH IDOR 複合キー照合の
  Verification に POST messages (フォローアップ追記) の cross-user 404 テストを明示追加、
  (3) MEDIUM `TestOriginGuard_AllProtectedRoutesEnforced` は機械強制ではない旨を明示し
  実装 PR での目視チェックリストを Verification に残す、(4) MEDIUM 所有権照合と読み書きを
  同一 `qa.Store` メソッド・同一ロック区間に閉じる、(5) LOW 運営の正規返信経路は
  `/api/admin/questions/{qid}/reply` のみと明示し participant path 経由の admin 書き込みを
  運用規律で禁止。**全 5 件を本 ADR の Decision/Verification に反映済み (拘束力は無いが
  全件採用した)。security-engineer 判定により CEO/VP の追加判断は不要** (この反映で findings
  は閉じる。VP 承認ゲート自体 [Class-2] は別途残る — 上記 Status 参照)
