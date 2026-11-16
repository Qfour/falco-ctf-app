# ADR-0056: 調査型の課題を足す — 答えは閉じた形式の設問とし、scoreboard の Grader 1 点で「回数を加算してから比較」で判定する。イベント版の痕跡束 (席ごとの値と囮) は seat の Secret → plant → seed → 宣言した mount で、答え表は scoreboard の process だけに注入する。練習版は公開し、イベントのモード (`FLAGS_FILE`) では使わない

- Status: **Proposed** (起草 2026-11-16)
  - Accepted の条件: (1) 段階 A1〜A5 の app PR と P1 の platform PR が merge されている、(2) V1〜V6・V8〜V11 が required check (`test` / `flag-guard` / `chart-lint`) の上で緑、(3) security-engineer の R1 の記録 (A1〜A5・P1。private) と CTO の承認の記録がある。
  - D14 (detect の hold-out) は、本 ADR の Accepted を待たない独立の段階 (D1)。前提は #341 の merge と detect 有効化の R1。
- Date / Deciders: 2026-11-16 / CEO (秘匿 = 版を分ける。回答型は ADR-0056。利用形態の順 = イベント → 研修 → 自習 → デモ。イベント後の公開は都度 CEO)、CTO 代行 = CoS (席ごとの値 + 囮の位置 K。detect の応答の区別を潰すのは hold-out の変種だけ。I6 の解釈 = イベント版は flags と同じ「イベントのデータ」)、security-engineer (CISO 直下。5 点とも条件付きで可、2026-11-16)、architect (起草)
- 関連: product brief ws#185 (`docs/briefs/ir-scenario.md` §5.2・§5.3・§8)、ADR-0055 (Proposed、app#604。D6 の `requirements.answers`)、ADR-0001 / 0005 / 0007 / 0020 / 0026 / 0027 / 0029 / 0033 / 0037 / 0039 / 0042、`docs/detect-challenge-design.md`、REFACTORING.md の新フェーズ (番号は CoS が決める)、app#341

## Context

### C1 課題の型は 3 つで、「事実を答える」型が無い
- `type` は `trigger` / `evade` / `detect` だけ (`internal/catalog/catalog.go:1-35`、`:208`)。
- detect は flag も live の Falco も使わない (`validateDetect`、`catalog.go:223`)。調査型も同じく flag と live の Falco を使わない。
- `falco-rule.yaml` の decode は strict でない (`catalog.go:177`)。

### C2 公開の境界
- app は public。
- scoreboard image は `challenges/` と `scenarios/` を丸ごと持つ (`scoreboard/Dockerfile:23-24`)。
- challenge image の `/opt/ctf/missions/` は fixtures だけを持つ (I16、`.claude/rules/falco-ctf-app-conventions.md:37`)。
- 端末に載る課題ファイルは fixtures だけと定めている (workspace `ORGANIZATION.md:198`)。本 ADR は 2 つ目 (痕跡束) を足すので、この文も更新が要る (CEO の統治 docs)。

### C3 flags の型 (ADR-0033) と、その残余
- イベントの flags は platform から `FLAGS_FILE` で入る (`conventions.md:432`、`cmd/scoreboard/main.go:177-191`、`charts/scoreboard/templates/deployment.yaml:161-163`)。
- 指定が無ければ placeholder のまま動く (`0033:75`)。これを platform が塞いでいる。local 以外の env では flags 無しで render しない (`0033:81-101` の D9 (a))。
- 「指定しない構成」は ADR-0033 の範囲外の穴として明記されている (`0033:112`)。調査型で練習版を既定にすると、この穴をそのまま作り直す (security HIGH)。
- shell と Go の 2 実装は parity の負債になった (`0033:61`)。
- platform には required check が無い (`0033:101`)。

### C4 注入の経路の現状
- flags が届くのは `plant` initContainer だけで、経路は `envFrom: ctf-flags` (`charts/ctf-user/templates/pod.yaml:101-123`)。
- どの container にも SA の token は付かない (`pod.yaml:81`)。ttyd の SA は Pod の get と exec しかできず、Secret は読めない (`charts/ctf-user/templates/role.yaml:11-19`)。
- 「plant.sh を持つ = evade」と決め打ちしている (`challenges/gen-values.sh:105`)。
- 2-7(a) は `cp -a` の copy-source を snapshot root に限る (`gen-values.sh:594-609`)。
- 1-4 は challenge の mountPath を、宣言した plant-target の dir に限る (`scripts/check-flag-isolation.sh:308-313`)。
- I12 は challenge に flag の実値を届かせない (`conventions.md:34`)。

### C5 API の面
- origin-guard の pin は 15 (`internal/scoreboard/origin_guard_test.go:108`)。collector の forward は 2 本 (submit と exfil)。I14 / I15 (`conventions.md:35-36`)。
- `x-ctf-authz` の語彙に「self だけ (admin の代理なし)」が無い (`docs/openapi-scoreboard.yaml:31-39`)。
- 参加者向けの identity bucket は 4 route で共有している (`openapi-scoreboard.yaml:904`)。
- spec の `x-ctf-rate-limit` は今も散文の形 (`:575`、`:636`)。ADR-0037 の S2 (正準形) は未着地 (spec を読んだ観測)。
- journey の ingress は `/api/users/` を Prefix で開けている (`charts/scoreboard/templates/ingress-journey.yaml:171-172`)。

### C6 detect の現状
- 応答が `missed` と `false-positive` を区別し、fire の数を返す (`internal/scoreboard/api/api.go:1571-1590`、metric の outcome は `openapi-scoreboard.yaml:207-210`)。
- detect の caller はまだ無い (`openapi-scoreboard.yaml:644`)。
- **app#341 は OPEN** (`gh issue view 341`、2026-11-16)。design は「#341 の前にイベントで `DETECT_RUNNER=k8s` を有効にしない」としている (`docs/detect-challenge-design.md:198-205`)。
- capture は image に焼き込むか、ConfigMap / PVC から mount する (`design:180`、`:245-247`)。spike の chunk は 300〜740 KB (`design:252-254`)。
- scoreboard の SA は grader の ns に Job・Secret・Pod の RBAC を持つ (`conventions.md:420`)。

### C7 Board は他の参加者に見える
- `audience: all` の thread は認証済みの参加者全員に見える (`openapi-scoreboard.yaml:1182-1183`)。席ごとに値を変えないと、答えを Board で渡せる。

### C8 `hintleak` の入力の形
- `Input{Hints, Free, Targets []Item}`、`Item{Source, Text}` (`internal/hintleak/hintleak.go:52-60`)。
- 非 UTF-8 の item と不可視文字 (`sourcehygiene.Hidden`) は error (`hintleak.go:85-105`)。n = 10 rune (`:47`)。
- 痕跡束は 1 file = 1 Target として、そのまま渡せる。そのためには束が UTF-8 の text であることが条件になる。

### C9 「イベントのモード」に使える指標
- scoreboard の `FLAGS_FILE` (上の C3)。local 以外の env は ADR-0033 D9 (a) の下で必ず `FLAGS_FILE` を持つ。
- 起動時の拒否の log は、platform の `verify.sh` が読む契約 (`conventions.md:442`)。

### C10 決定済みのこと (2026-11-16)
- CEO: 版を分ける (練習版 = 公開、イベント版 = platform から注入)。回答型は ADR-0056。利用形態の順。イベント後の公開は都度 CEO。
- CTO 代行: 席ごとの値 + 囮 K。hold-out の変種だけで detect の区別を潰す (公開の capture への今の応答は変えない)。I6 の解釈。
- security-engineer: 5 点とも条件付きで可。HIGH 4 件と要件 1〜8。

### C11 product の要件 (brief §5.2・§8)
- 答えは痕跡から導く事実で、`FALCO{` を置かない。値はイベントごとに変わる。正誤だけを返す。総当たりできない回数の上限。判定はサーバ側の 1 点。
- 受け入れ条件 2〜5 (公開面に 0 件、ローテーション、`FALCO{` 0 件、巻き添えの solve 0 件)。

## Options

### 秘匿 (CEO が S2 に決定済み。記録のため)
- **S1 値だけを回す**: 構造が公開されるので調査を短絡できる (L1/L2 が測れない)。
- **S2 版を分ける (採用)**: 練習版を公開し、イベント版は platform から注入する。
- **S3 禁輸**: private で書き、後で merge する。release (I4/I5) と公開キットの境界を壊し、不可逆に近い。

### 痕跡束の注入経路
- **J1 seat の Secret → `plant` → seed emptyDir → 宣言した mount (採用)**
  - 変更点: plant を「evade の flag」と「調査型の束」の 2 用途にする。
  - コスト: gen-values の 2-7 と assert の拡張。Secret が 1 つ増える。
  - リスクと可逆性: 2-7(a) に copy-source が 1 つ増える。可逆。
  - 効き始める閾値: 最初の調査型の課題。
- **J2 Secret を challenge に volume で直接挿す**
  - 1-4 の mountPath の allowlist を緩める。Secret 名を打ち間違えると ctf-flags を丸ごと見せる経路になる (I12)。security が不可と判定した。
- **J3 イベント版の束を private build の challenge image に焼き込む**
  - 公開の同じ SHA から 8 image を作る前提 (I4/I5、ADR-0054) が崩れる。registry の image から束が抜ける。採らない。

### 値の粒度 (CTO 代行が P3 に決定済み)
- **P1 イベントごと**: Board (C7) や口頭で答えを渡せる。
- **P2 席ごと (値だけ)**: 2 席が diff すれば、違う位置が答えの在りかになる (security HIGH)。
- **P3 席ごと + 同じ形式の囮を K 箇所 (採用)**。

### 生成器の置き場
- **G1 platform (private) の生成器**
  - 生成のアルゴリズムも K の test も platform に置く。
  - リスク: platform には required check が無く (`0033:101`)、Actions は課金停止中。K の性質を機械で守る場所が無い。
  - 練習版との schema の drift を、2 つの実装の間で抱える。
- **G2 app の Go の renderer + platform の private なテンプレートと master 鍵 (採用)**
  - アルゴリズムは公開してよい (Kerckhoffs)。在りかを隠すのは、テンプレートと鍵である。
  - K の test・テンプレートの形式・練習版の golden を app の required check に載せる。
  - コスト: テンプレートの形式が契約になる (契約表の行に入れる)。
  - 可逆。効き始める閾値: 即時。

### validator の実行経路
- **E1 pin した scoreboard image の subcommand (`scoreboard edition check|render`) を `docker run --rm --network none --pull never` で呼ぶ (採用)**
  - 起動時の検査と同じ bytes で動く。image は増えない (I5)。
  - 前提: stand-up の端末に docker がある。release の手順は既に docker を使う (platform `scripts/test-release-scan.sh:175`)。stand-up の端末で使えるかは**仮説**で、COO が確認する。
  - これは ADR-0033 の Signpost 3 (A の再評価) を、版の検査に限って発火させる。
- **E2 `APP_PIN` の clone から `go build`**
  - 運用端末に Go を前提にする (`0033` Context では前提にしていない)。Signpost 3 で採る。

## Decision

**S2・J1・P3・G2・E1 を採る。** 理由: 判定・検査・生成の規則を app の Go 1 か所に置き、required check で守れる。注入は既存の I12 の経路 (plant → seed → 宣言した mount) の中に収まる。答え表は scoreboard の process から出ない。

### D1 4 つ目の type (名前は仮に `investigate`。CPO が決める)

    type: investigate
    investigate:                  # strict decode。未知の key は fail
      evidence:
        mountDir: <abs dir>       # 痕跡束を置く dir。plant-target として宣言する (ADR-0007 の dir 粒度)
      questions:                  # 1〜8 個。順序付き
        - id: <qid>               # ^[a-z][a-z0-9-]{0,30}$。課題の中で一意
          format: <D2 の閉じた列挙>
          attempts: <1..10>       # 既定 5
          params: {...}           # format ごとに閉じた key の集合

- `expectedFlag`・`expectedRules`・`forbiddenRules`・`requireExfil`・`requireExpectedRuleFire`・`detect` は空でなければならない (`validateDetect` と同じ形)。
- `mountDir` は次をすべて満たす。
  - 絶対 path である。
  - `/opt/ctf/missions/` (I16) と seed root の外にある。
  - `sensitive_dir_prefixes` (`gen-values.sh:94`) の外にある。理由は、deploy が catalog の rule を発火させないため (I13b)。
  - 他の plant-target と file が互いに素である (ADR-0055 C4 (ii))。
- 設問の文 (prompt) は `journey.yaml` の `questions[]` (`{id, prompt}`) に置く。
  - id の集合は catalog と完全に一致する (起動時に検査)。
  - prompt は hintleak の無料の集合に入れる。
  - 答えは catalog にも journey にも置かない。

### D2 設問の形式は閉じた列挙 (v1)

| format | 受け付ける形 (正規化の後) | 正規化 (format が決める。設問ごとの指定は無し) | 席ごとに変えられるか | 答えの空間 (code が計算する。作者は宣言しない) |
|---|---|---|---|---|
| `path` | 絶対 path。要素は `[A-Za-z0-9._-]+`、全長 ≤ 255 | 前後の ASCII 空白を除く。連続する `/` を 1 つにする。末尾の `/` を除く (root を除く)。大小文字は区別する | 可 | renderer の語彙の積 (D12) |
| `name` | `[A-Za-z0-9._-]{1,64}` | 前後の空白を除く。大小文字は区別する | 可 | 語彙の大きさ |
| `hexid` | `[0-9a-f]{L}` (`params.length` は 12〜64) | 前後の空白を除く。小文字化する | 可 | 16^L |
| `timestamp` | RFC 3339 の UTC、秒の精度 | 空白を除く。`+00:00` を `Z` にする。秒未満は拒否する | 可 | `params.windowSeconds` |
| `technique` | `T\d{4}(\.\d{3})?` (ATT&CK v19 の表にある ID) | 前後の空白を除く。大文字化する | 不可 | v19 の表の件数 |
| `choice-set` | 宣言した n 個の選択肢 id の空でない部分集合 (`,` 区切り) | 空白を除く。重複を除く。並べ替える | 不可 | 2^n − 1 |
| `sequence` | 宣言した m 個のラベルから k 個を並べた順列 | 前後の空白を除く | 不可 | m! / (m−k)! |

- format を足すことは、この ADR の amend とする (閉じた列挙を保つ)。
- 期待値の正規化は冪等でなければならない (table の値 v について normalize(v) == v)。冪等でなければ拒否する。
- 形式に合わない入力は 400 を返す。回数は消費しない (D5)。

### D3 答えの空間の下限 (security 要件 6 と、architect の追加)
- (a) **空間 ≥ 100 × attempts**。空間は code が計算する。
  - 計算に使えるのは、format と params (catalog の時点)、または renderer の語彙 (イベント版、validator の時点) だけ。
  - 下回れば拒否する (catalog の load、または validator)。
  - 帰結: 4 択の `choice-set` は書けない (2^4 − 1 = 15)。n ≥ 10 なら attempts ≤ 10 まで通る。
- (b) **候補の下限 (追加)**: 席ごとの format では、その席の束に現れる形式の合う別々の token の数を数える。これが R × attempts 以上であること。
  - 理由: 実際の総当たりは「束の中の候補を順に試す」ことなので、(a) の形式の空間だけでは捕まえられない。
  - R は CISO が決める (提案は 10)。validator が拒否の条件にする。

### D4 提出の route (spec・origin-guard の pin・ingress・collector)
- `POST /api/users/{user}/challenges/{cid}/questions/{qid}/answer` (operationId `submitAnswer`)。
- `x-ctf-audience: participant`。
- `x-ctf-authz: self` (**新しい語彙**)。
  - 証明された identity の正規形が `{user}` と完全に一致する場合だけ通す (I8)。
  - `ADMIN_EMAILS` も override しない。header が無い、または空なら 403 (`selfOrAdmin` と同じ前段で、rate-limit の token を使う前に返す)。
  - 理由: admin の代理提出は参加者の回数を消費して solve させてしまう (security LOW を採用)。非対称の理由は spec の description に書く。
- `x-ctf-origin-guard: true`。pin は 15 → **16** (`origin_guard_test.go:108`)。
- `x-ctf-collector-forward: false`。forward は 2 本のまま。端末の script から到達させない。
- `x-ctf-rate-limit`: identity を key にした専用の bucket (1 req/s、burst 5)。他の bucket とは共有しない。形は ADR-0037 の正準形 (S2 が着地していなければ今の散文の形)。
  - これは DoS の制御である。総当たりの防御は D7 の回数で行う。
- ingress: 既存の `/api/users/` Prefix (`ingress-journey.yaml:171-172`) で届くので、template は変えない。I15 の双方向の検査を緑に保つ。
- request: `AnswerRequest {answer: string, maxLength 256, x-ctf-text-origin: participant-opaque}`。`additionalProperties: false`、JSON だけ。
- response (200): `AnswerResult` (D6)。
- error (`{"error": string}` の 1 形で、入力を echo しない):
  - 400: 調査型でない cid / body の不正 / 形式に合わない。
  - 403: origin / identity / self でない。
  - 404: 未知の cid / qid。固定の body。
  - 429: rate-limit。
  - 500: store の失敗。比較はしない。
- `MissionDetail` に `questions` を足す (additive、key は 21 → 22)。
  - 形は `[{id, prompt, format, attempts, remaining, correct}]`。調査型でない課題では `[]`。
  - 生成型で組み立てる (Board / profile の型に倣う)。

### D5 判定の 1 点と順序 (fail-closed)
判定の場所は `internal/scoreboard/scoring` の Grader の `SubmitAnswer` だけ。比較を呼べるのも、solve を書けるのもここだけ (`detect-challenge-design.md:79-83` と同じ原則)。

1. route の前段: identity (self) → origin-guard → rate-limit。
2. catalog で cid / qid を引き、入力を format の規則で正規化する。形式に合わなければ 400 (回数は消費しない)。
3. **加算**: 1 つの transaction で `UPDATE attempts SET n = n + 1 WHERE (user, cid, qid) AND n < max AND correct = 0` を実行し、課題が solve 済みでないことも同じ tx で確かめる。
   - 0 行なら `exhausted` か `already-correct` を返す。**比較はしない**。
   - commit に失敗したら 500 を返す。**比較はしない** (MarkDirty と同じ順序)。
4. **比較**: `HMAC-SHA256(k_proc, normalized_input)` と `HMAC-SHA256(k_proc, expected[seat][cid][qid])` を `subtle.ConstantTimeCompare` で比べる。
   - `k_proc` は起動ごとに `crypto/rand` で作る 32 byte で、log に出さない。
   - 平文の表は HMAC にした後に捨てる。長さは漏れない。
   - 自分の席の行が無ければ 500 を返し、運営の log に残す (validator と予備の席で起きないはず)。
5. 一致したら、設問を correct にする。全設問が correct なら `MarkSolved` を呼ぶ (ヒントの減点は既存と同じ)。この書き込みが失敗したら 500 を返し、solve しない (回数は消費済みのまま)。
6. 一致しなければ、他の席の答え (HMAC から seat への map) と照らす。一致したら**運営だけの監査 log** に `answer matched another seat` (user, cid, qid, seat) を残す。応答と metrics には出さない。
- `scoreboard_solves_total` の kind に `investigate` を足す。`scoreboard_api_submissions_total` の outcome に `answer_correct` / `answer_incorrect` / `answer_exhausted` / `answer_already_correct` / `answer_store_error` を足す。label に qid と seat は入れない。

### D6 応答の形

    AnswerResult (すべて required):
      status:    correct | incorrect | exhausted | already-correct   # 閉じた enum。後から値を足さない (足すなら別 field)
      correct:   bool      # この設問が正解済みか
      solved:    bool      # 課題が solve 済みか
      remaining: integer   # この設問の残りの回数 (>= 0)

- 次のものは返さない: どこが違うか、入力、期待値、長さ、他の席との一致。
- `reason` のような散文は持たせない。portal の表示の文言は portal 側が status から決める。

### D7 回数の上限
- 上限は (user, cid, qid) ごとで、値は catalog の `attempts`。SQLite に持つので、再起動しても消えない。
  - 新しい table `answer_attempts(user, challenge, question, n, correct, PRIMARY KEY(user, challenge, question))` を足す。migration は ADR-0020 の `user_version`。`docs/db-schema.md` も更新する。I1 は変わらない。
- **上限に達した後と solve の後は比較しない** (D5 の 3)。
- `reset-dirty` は回数に触れない。`POST /api/admin/reset` (solve をすべて消す、`openapi-scoreboard.yaml:1515-1527`) は、同じ tx で回数も消す。
- 回数を変える route と、表を返す route は作らない。

### D8 練習版とイベント版、「イベントのモード」
- **練習版** (公開): `challenges/<id>/edition/` に置く。
  - `edition.yaml` と `template/` (D12 の形式)。
  - `practice/` (公開の鍵と席 `*` で render した束の file と `answers.tsv`)。
  - challenge image には入らない (I16 は fixtures だけ)。scoreboard image には入る (`Dockerfile:23`)。
- **イベント版** (private): 置き場は platform。
  - 答え表 → scoreboard の Secret (`answersSecret`。既定の名前は `scoreboard-answers`、key は `answers.tsv`) → `ANSWERS_FILE`。
  - 束 → seat の Secret `ctf-evidence` (D11)。
- **イベントのモードの定義**: scoreboard の process では「`FLAGS_FILE` が空でない」こと。ADR-0033 D9 (a) によって、local 以外の env は必ずこれを満たす。
  - (i) イベントのモードで、スコープに調査型があり、`ANSWERS_FILE` が無い → 起動を拒否する。
  - (ii) イベントのモードでないのに `ANSWERS_FILE` がある → 起動を拒否する (信号の食い違い)。
  - (iii) イベントのモードでは、練習版の答えを読む code path に到達しない。表は `edition.Load(cat, answersFile, eventMode)` の 1 回の呼び出しでだけ得る (ADR-0033 D6 と同じく、ソースの検査で固定する)。
- **練習版を既定にするのは local だけ** (security HIGH)。
  - platform の helmfile は、env が local 以外で、生成物の `requirements.answers` が空でなく、`answersSecret` が無効なら、render で失敗する (`0033` D9 (a) と同じ型)。
  - workspace の払い出しでは、束の出所を 1 つ明示する。イベント版の dir と digest か、練習版 (env が local で、kube context も local 系のときだけ) のどちらか (D9 (b) と同じ型)。
- **公開**: イベント版を、イベントの後に練習版として公開するかは CEO が決める。公開した版は image の練習版の集合に入るので、以後イベント版としては D10 の B4 が拒否する。
  - 公開していない過去のイベント版の再利用は検出しない (残余。ADR-0033 と同じ)。
- **I6**: 課題の定義 (`falco-rule.yaml` = 一次消費) は app に残る。イベント版は flags と同じ「イベントのデータ」とする (CTO 代行の解釈、2026-11-16)。

### D9 validator と renderer (app の Go 1 本、E1)
- `internal/edition` (表の parser・表の検査・束の検査・renderer・Judge) が規則の唯一の実装。shell の写しは作らない (`0033:61` の負債を繰り返さない)。
- `scoreboard edition check` の入力: `--answers` `--evidence-root <dir>/<seat>/` `--flags-file` `--seats <file>` (roster ∪ 予備) `--edition-dir <テンプレート>` `--scenario <image の中の path>`。
  - exit: 0 = 受理 / 1 = 拒否 / 2 = 使い方の誤り。
  - stderr に出すのは、行番号・seat・cid・qid・file 名だけ。値は出さない。
  - 受理したときだけ `--digests-out` に `seat<TAB>sha256(正規の束)` を書く。
- `scoreboard edition render` の入力: `--edition-dir` `--master-key-file` `--seats`。出力は席ごとの束と `answers.tsv`。
  - HTTP server の path から render に到達しない (ソースの検査で固定する)。
- platform は、課金が発生する最初の step の前に、render → check の順で、pin した scoreboard image の digest を `docker run --rm --network none --pull never` で呼ぶ。通らなければ何も apply しない。
- 採点の Secret と払い出しは、同じ実行で同じ出力から作る (`0033` D9 (c))。

### D10 拒否の条件 (どれか 1 つで拒否。1 ケースに 1 欠陥の test)
**scoreboard の起動時 (表について) と validator の両方**:
- T1 / T2: D8 の (i) と (ii)。
- T3: 表の形。
  - 1 行目は `# falco-ctf answers v1`。4 列の TSV (seat、cid、qid、value)。
  - quote・CR・空の列は不可。UTF-8 で、`sourcehygiene.Hidden` が 0 件。
- T4: 完全性。
  - スコープの調査型の cid × qid のすべてについて、すべての seat の行がある。
  - seat の集合が空でない。seat は ADR-0042 の文法に合う。
  - 重複と、未知の cid / qid は不可。イベントで seat `*` は不可。
- T5: 値が format に合い、正規化が冪等である。
- T6: 値が、練習版の (同じ format の) 答えのどれとも一致しない。
- T7: 値が `FALCO{`、flag の正規表現、dev の placeholder、今回の `FLAGS_FILE` の値のどれも含まない。
- T8: 席ごとの format では、同じ設問の値が席の間で重複しない。

**validator だけ (束は scoreboard に無いため)**:
- B1: 表の seat の集合が `--seats` (roster ∪ 予備) と一致し、すべての seat に束がある。
- B2: 束の形。
  - 平らな通常 file だけ。名前は `^[a-z0-9][a-z0-9._-]{0,62}$` で、`..` で始まらない。
  - file は 64 個以下で、席ごとの合計は 512 KiB 以下。UTF-8 で、Hidden が 0 件。
- B3: 束に `FALCO{`、flag の正規表現、dev の placeholder、今回の flags の値が 0 件。
- B4: 練習版との比較。次のどれかに当たれば拒否する。
  - file の digest か束の digest が、image の中のどれかの練習版と一致する。
  - 練習版の答えの値が束に現れる。
  - 10 rune の shingle の重なり (`|S_event ∩ S_practice| / |S_event|`。正規化は hintleak と同じで、`hintleak` から export した 1 つの関数を使う) が θ 以上である。θ は CISO が決める (提案は初回のイベントで実測してから)。
- B5: `hintleak.Check({Hints: スコープの hints, Free: ADR-0026 と同じ無料の集合, Targets: 席の束の各 file})` の違反が 0 件 (ADR-0026 D5 に新しい caller を足す)。
- B6: 席ごとの format の答えが、その席の束に現れる (導けることの最低限の確かめ)。
- B7: 囮 K (D12)。
- B8: D3 の (a) と (b)。
- B9: 席ごとの format の答えが、image の `/app/challenges` と `/app/scenarios` の bytes に現れない (brief §8 の 2)。

security の要件 3 は「起動拒否」と書いている。束の項目は、scoreboard ではなく validator (課金の前。何も払い出さない) と、deploy の digest の照合 (D11) で止める。理由は要判断 1 に書いた。

### D11 痕跡束の Secret と、plant 経由の注入 (J1)
- seat の ns の Secret `ctf-evidence`。
  - key = 束の file 名。key の族は `CTF_FLAG_*` と交わらない。
  - ctf-flags とは別の object で、答え表は入れない。
- `charts/ctf-user` に `ctf-evidence-secret.yaml` を置き、`.Values.evidence.files` から render する。
  - helm の `fail` で key の文法、64 個以下、合計 512 KiB 以下を強制する (validator と二重に)。
- Secret は `plant` にだけ、`/opt/ctf/evidence-src` に readOnly で volume mount する。challenge・ttyd・ttyd-proxy・missions-scope には mount しない。
- plant の生成 script は key を**名前で列挙して**、通常 file として copy する。
  - 形は `cp "/opt/ctf/evidence-src/<key>" "/plant-seed/<mountDir>/<key>"`。`-a` と `.` と glob は使わない。`..data` の symlink は辿られ、通常 file になる。
  - その後 `chmod 0444` する。
- 2-7(a) の copy-source の allowlist に足すのは `/opt/ctf/evidence-src/` だけで、その下の名前は values に列挙したものに限る。
- challenge は seed の subPath = `mountDir` を readOnly で mount する。
  - `mountDir` は plant-target として宣言するので、1-4 / 1-18 の既存の検査がそのまま効く (緩めない)。
- plant を付けるかどうかは、「plant.sh を持つ」(`gen-values.sh:105`) ではなく type から導く (evade の plant.sh、または調査型)。
- `deploy-user.sh --evidence-dir <dir> --evidence-digests <file>`: 正規の束の sha256 が digests の自分の seat の行と一致しなければ、cluster に触れる前に非ゼロで終了する。
  - これは内容の規則の写しではない。Go が受理した bytes であることの照合である。
  - 指定が無ければ練習版を使う (local の既定。platform が local 以外で止める、D8)。
- 新しい検査 3-x (`assert-flag-isolation.sh`、deploy の時、fail-closed):
  - challenge の `mountDir` の中に symlink が 0 件で、通常 file だけがある。
  - seat の ns の Secret 名の集合が {`ctf-flags`, `ctf-evidence`} と一致する。

### D12 席ごとの値・囮 K・予備の席・renderer (P3・G2)
- `edition.yaml` は slot を宣言する。
  - slot の項目は `{name, format, role: answer(<qid>) | decoy(<qid>) | filler, vocab: <語彙>}`。
  - テンプレートの file には `{{ctf:<slot>}}` の印を置く。
  - 未宣言の slot、使われない slot、render の後に印が残ることは、すべて fail。
- 値は `HMAC-SHA256(master, seat ‖ cid ‖ slot)` から導く決定的な DRBG で選ぶ。
  - master 鍵は platform の sops の中だけに置き、render の実行の中だけで使う。cluster・scoreboard・seat の ns には置かない。
- **K**: 答えの slot 1 つごとに、同じ format の decoy の slot を K 個以上置き、それらも席ごとに変える。
  - K の値は CISO が決める (提案は K ≥ 2 × attempts。2 席が結託しても、全候補を回数の内で試し切れない)。
  - 機械検査は 2 つ。renderer の test (合成テンプレートで、2 席の出力の差分の位置のうち答えでないものが K 以上) と、validator の B7 (実際の出力で、席の組ごとに同じことを確かめる)。
- 予備の席: platform は roster に予備を足して render する (数は COO が決める)。
  - 予備を超えて席を足すと、再 render と scoreboard の再起動 (I1 の Recreate) が要る。runbook に書く。
- 練習版: 公開の固定鍵 `practice` と seat `*` で render した出力を commit する。render(template) == 練習版の出力を golden test で確かめる。

### D13 答え表の到達範囲 (security #3)
到達してよいのは scoreboard の container の process だけ。経路ごとの塞ぎ方は次のとおり。
- API: D6 の 4 field だけ。
- 誤りの文: 入力・期待値・長さを echo しない。
- 起動時の error: 行番号と id だけ。
- log: 期待値は出さない。入力は出さないか、`k_proc` の keyed hash だけ。
- metrics: label は outcome (と既存の challenge_id) だけ。
- store: 平文を持たない (回数と correct だけ)。
- admin の route: 表を返さない。
- Board / ヒント: 表は app に無い。B5・B9 で検査する。
- detect-grader の Job: 表を mount しない。
- 答え表の Secret は scoreboard の ns にだけ置く。scoreboard の chart は、`answersSecret.enabled` で `DETECT_GRADER_NAMESPACE` が release の ns と同じなら、`fail` で止める。
- seat の ns には置かない (3-x)。

### D14 detect の hold-out (独立の段階 D1。#341 の後)
- catalog の `detect.holdout: {count: n}` は数だけを宣言する。capture 本体は repo にも image にも置かない。
- capture は grader の ns の read-only の object から Job に mount する。object の種類 (Secret / PVC など) は platform が決める (spike の大きさ、`design:252-254`)。
- 公開の capture への応答 (`missed` / `false-positive` と fire の数) は**変えない** (CTO 代行)。
- 公開の capture で合格したときだけ hold-out を回す。
  - 回す前に、(user, cid) ごとの hold-out の試行の予算を store で加算する (D5 と同じ順序。予算の値は CISO / CPO が決める。提案は 20)。
  - 結果は合否だけ。新しい status は `not-generalized` (fire の数とどの変種かは返さない) と `holdout-exhausted`。
  - 応答の enum に値を足すのは、caller が出荷される前 (`openapi-scoreboard.yaml:644`) に行う。
- イベントのモードで hold-out を宣言した課題では、Job は必ず hold-out を mount する。object が無ければ Job が失敗し、500 になる (solve にしない)。local では hold-out 無しで、公開の capture だけで採点する (練習)。
- 契約表の「detect-grader Job」行に (5) hold-out の object の名前・key・mount を足す。両リポ同時 PR。

### D15 新しい Hard Invariant の候補 (番号は昇格の時に、空いている I18 以降を振る)
- **候補 A (答え表の到達範囲)**: D13 の内容。
  - 昇格の条件: Accepted になっていること、V1・V2 が required の上で緑であること、最初のイベントで 3-x と Secret の allowlist の assert が通ったこと。
- **候補 B (判定の 1 点と順序)**: 比較を呼べるのは Grader の `SubmitAnswer` だけで、加算の commit が比較より先。
  - 昇格の条件: V5 (`-race` を含む) と、1 点であることのソースの検査が required の上で緑であること。
- **候補 C (I12 の拡張)**: 痕跡束が challenge に届く経路は plant → seed → 宣言した mount だけで、`ctf-evidence` は plant にしか mount しない。
  - 昇格の条件: I12 の機械強制 (`check-flag-isolation.sh` と assert) に、V2・V8 の case が入っていること。
- **候補 D (イベントのモードの fail-closed)**: ADR-0033 と同じく not yet。
  - 昇格の条件: Accepted になっていること、V3 の配線の test が揃っていること、platform の render gate (V12) が実機で確認されていること。
- どの候補も、機械強制が着地するまで conventions の表には書かない (`docs/adr/README.md` の規律)。

### D16 クロスリポ契約表 (新しい行と、既存の行の変更)
- **新しい行「答え表と痕跡束」** (下の文面。両リポ同時 PR)。
- 「scoreboard の起動ログ」行に (4) を足す。`msg="edition check failed"` (level ERROR、`os.Exit(1)` の直前に 1 回、値は出さない)。platform の `verify.sh` が読み、`bootlog_contract_test.go` が literal で固定する。
- 「detect-grader Job」行の (5) は D14。
- Flags 行は変えない (答えは `FALCO{...}` の文法に合わない)。

> | 答えと痕跡束 (ADR-0056、**クロスリポ契約・両リポ同時 PR**) | 調査型の課題の設問 (id・format・attempts・params) は app の `falco-rule.yaml` が正典。答えは app に置かない (練習版の `challenges/<id>/edition/practice/` を除く)。**イベント版**は platform が app のテンプレート形式 (`edition.yaml` + `template/`) で private に書き、`scoreboard edition render` で席ごと (roster ∪ 予備) に生成し、`scoreboard edition check` (pin した scoreboard image、`--network none`) が受理した出力だけを使う。CLI は exit 0 = 受理 / 1 = 拒否 / 2 = 使い方の誤り、stderr は値を含まない、`--digests-out` は `seat<TAB>sha256`。**答え表** (`# falco-ctf answers v1` の 4 列 TSV) は scoreboard の Secret (`answersSecret`、`ANSWERS_FILE`) だけに入れる。seat の ns・grader の ns には置かない。**痕跡束**は seat の Secret `ctf-evidence` (key = file 名、64 個以下、512 KiB 以下) で、`plant` だけに mount し、宣言した `mountDir` へ copy する。`deploy-user.sh --evidence-dir --evidence-digests` は digest が合わなければ cluster に触れずに非ゼロで終了する。**イベントのモード** = scoreboard の `FLAGS_FILE` が空でないこと。このモードでスコープに調査型があるのに `ANSWERS_FILE` が無い、または逆の場合は、起動を拒否する。platform は、env が local 以外で `requirements.answers` (ADR-0055 D6) が空でなければ、`answersSecret` 無しでは render せず、課金の前に render → check を通す。適用の順は platform が先 (ADR-0033 D9 (g) と同じ) |

### D17 ADR-0055 の `requirements.answers` との接点
- `requirements.answers` = スコープの調査型の課題 id の、並べ替えた集合。生成器が導出し、宣言はさせない (ADR-0055 D6)。
- platform はこの 1 つから次を決める。写しは持たない。
  - `answersSecret` が要るか。
  - 何を render / check するか。
  - どの seat に `ctf-evidence` を作るか。
- ADR-0055 D6 は「ADR-0056 が Accepted になってから足す」としている。次回のイベントに間に合わせるには、「本 ADR の A1 が merge されてから足す」に詰める必要がある (要判断 4)。
- scoreboard 側の照合 (スコープに調査型があるのに表が無ければ拒否) は D8 の (i) で、ADR-0055 C7 と同じ型である。

### D18 amend と参照
- **amend (navigational な pointer を足す)**:
  - ADR-0026: D5 の新しい caller (束 = Target)。
  - ADR-0001 / I12: plant の 2 つ目の用途と、copy-source を 1 つ足すこと。
  - ADR-0033: D9 の (a)(b)(c)(g) の型を `ANSWERS_FILE` と束に延長する。Signpost 3 を版の検査に限って発火させる。
  - ADR-0055: D6 の `answers`。
  - `docs/detect-challenge-design.md`: D14。
- **参照**:
  - ADR-0005 (parity。operation が 1 つ増える)
  - ADR-0007 (dir の粒度)
  - ADR-0020 (migration)
  - ADR-0027 (ヒントの lock は current と切り離されている。どの課題でも回答できる)
  - ADR-0029 / I17 候補 (Quest は solve の事実だけを読むので変わらない)
  - ADR-0037 (専用の bucket)
  - ADR-0039 (`participant-opaque`)
  - ADR-0040 (契約の metric family は足さない)
  - ADR-0042 (seat の文法)
- supersede するものは無い。

### D19 段階 (1 PR 400 行・15 file 以内。R1 = security-engineer のレビュー必須)

| 段階 | 内容 | R1 | 両リポ | Verification |
|---|---|---|---|---|
| A0 | 本 ADR (Proposed)、索引 | — | — | — |
| A1 | catalog の `investigate` (strict)、`internal/catalog/answerformat` (D2 の列挙・正規化・空間)、journey の `questions[]`、D3 (a) の catalog 側 | 要 | — | V6 (catalog)、V10 |
| A2 | `internal/edition` の表 (parser・T1〜T8・Judge)、`edition.Load` の 1 点、起動時の拒否と起動ログ (4)、`charts/scoreboard` の `answersSecret` と grader の ns の `fail` | 要 | 起動ログの行 ↔ P1a (verify.sh) | V1 (起動)、V2 (scoreboard)、V3 (T)、V13 |
| A3a | store の migration、Grader の `SubmitAnswer` (D5・D7)、admin reset | 要 | — | V5、V1 (store・log) |
| A3b | route・spec・`self` の語彙と authz の test・og の pin 16・rate-limit・`MissionDetail.questions`・metrics | 要 | — | V9、V1 (応答) |
| A4 | `internal/edition` の束の検査 (B1〜B9)・renderer・`edition check|render` の subcommand・testdata | 要 | CLI ↔ P1b | V3 (B)、V4、V6 (b)、V11 |
| A5 | ctf-user の `ctf-evidence`、plant の一般化、gen-values の 2-7、3-x、deploy-user の `--evidence-*`、helm の `fail`、契約表の新しい行 | 要 | 行 ↔ P1b | V2 (ctf-user)、V8 |
| A6 | portal の回答欄 (application-engineer) | — | — | 生成型と template の test |
| A7 | 新しい課題の練習版 (content-engineer) | 要 (fixtures と同じ扱い) | — | V11 (golden)、V3 を練習版で緑 |
| P1a / P1b | platform: helmfile の render gate、束の出所の明示、課金前の render → check、digests、seat の Secret の作成、`verify.sh` の (4)、イベント版の置き場 (sops) | 要 | 上の app PR と対 | V12 |
| D1 | detect の hold-out (app + platform)。#341 の後 | 要 | detect-grader の行 | V7 |

- 順序: A1 → A2 (+ P1a) → A3a → A3b → A4 (+ P1b) → A5 (+ P1b) → A6 / A7 → platform の `APP_PIN` の bump。
- platform のゲートを先に適用する (ADR-0033 D9 (g))。stacked の深さは 2 以内。

## Consequences
- **諦めたもの**:
  - 束の内容の検査を scoreboard の起動時に行うこと (束を持たないため。validator と digest で代える)。
  - 4 択の設問 (D3 (a))。
  - 席ごとに変えられない format (`technique` / `choice-set` / `sequence`) の答えは Board で共有できる (残余。要判断 3)。
  - 公開していない過去のイベント版の再利用は検出しない。
  - 正解なのに store の書き込みが失敗すると、回数を 1 つ失う (fail-closed の代償)。
- **新たに守る規則**: D15 の候補 A〜D (昇格の前は ADR の規則)。
- **I への影響**: 違反は無い。
  - I1: table が 1 つ増える。
  - I5: image は増えない (subcommand)。
  - I6: D8 の解釈による。
  - I12: 経路は同じで、copy-source が 1 つ増える。
  - I14: operation が 1 つ増える。
  - I15: Prefix の中に収まる。
  - I16: 束は image の外。
  - I13b: `mountDir` の制約による。
- **runbook (COO)**: render → check → 払い出しの順。予備の席。予備を超えたときの再起動 (I1 の Recreate で短い全断)。tag を上げる前に表を検査する (ADR-0033 と同じ注意)。
- **統治文書 (CEO)**: `ORGANIZATION.md:198` の「端末に載る唯一の課題ファイル」に痕跡束を足す。CLAUDE.md の R1 一覧に行を足す。
- **follow-up (LOW)**: `x-ctf-authz: self` を他の書き込み route へ広げるかの検討 (今は変えない)。

## Signposts
1. 監査 log の `answer matched another seat` が、1 イベントで seat の 5% を超える。または誤答の keyed hash が席の間で一致する率が高い → 席ごとに変えられない format の扱いと K を見直す。
2. 束が 512 KiB を超える要求が出る、または seat × 設問の表が 1 MiB の Secret に近づく → Secret の分割か PVC を宣言つきで設計する。
3. stand-up の端末で docker が使えない (E1 の前提が崩れる) → E2 (`APP_PIN` の clone からの `go build`) に移る。
4. 設問の 20% 超で回数を使い切る参加者が出る (CPO の指標)、または候補の下限 R で content が書けない → attempts・R・K を CISO と CPO が再設定する。
5. (補足) platform が evade の無いコースで flags を任意にする → 「イベントのモード」の指標を明示の `EVENT_ID` に替える。

## Verification (app は `make test` / `flag-guard` / `chart-lint` = required。exit status で判定。故意の違反で赤になる case を常設する)
- **V1 (security 要件 1)**: sentinel の答え表で、誤答・上限超過・already-correct・store の失敗・起動拒否の各経路を通す。応答の body・log・metrics・error・store の行に sentinel が 0 件 (Go の test)。
- **V2 (要件 2)**: sentinel を入れて `helm template` した結果、ctf-user には 0 件、scoreboard では scoreboard の container の mount にだけ現れる (CI)。deploy の 3-x で、seat の ns の Secret 名が {ctf-flags, ctf-evidence} と一致する。
- **V3 (要件 3)**: T1〜T8 と B1〜B9 のそれぞれについて、1 ケースに 1 欠陥の testdata で拒否する。T は scoreboard の起動の test と validator の両方で、B は validator で確かめる。stderr に値が 0 件。
- **V4 (要件 4)**: renderer の test。2 席の出力の差分の位置のうち答えでないものが、答えごとに K 以上。B7 は、K − 1 の fixture で赤になる。
- **V5 (要件 5)**: 加算の commit の前に比較が呼ばれない (store の stub で失敗を注入し、比較の呼び出しが 0 回)。上限 − 1 の状態で N 並行の要求を出し、比較は高々 1 回 (`go test -race`)。solve の後は比較しない。
- **V6 (要件 6)**: 空間 < 100 × attempts の catalog と edition を拒否する。4 択の `choice-set` の case で赤。D3 (b) の候補の下限を割る束を拒否する。
- **V7 (要件 7、D1)**: hold-out の応答は status と solved だけで、変種の fire の数の key が無い。予算は store にあり、予算の超過で回さない。公開の capture への応答は変更前と同じ (golden)。
- **V8 (要件 8)**: seed の mount に symlink を置いた fixture で 3-x が赤。512 KiB + 1 byte と 65 個の file で、helm の `fail` と validator の両方が赤。2-7(a) は `/opt/ctf/evidence-src/` 以外の copy-source、`cp -a`、glob で赤。
- **V9**: route は 31 → 32、og の pin は 16、forward は 2 のまま、I15 の双方向の検査が緑。`self` は admin を通さない (authz の test)。`MissionDetail` の key の集合は 22。
- **V10**: `investigate` の strict decode (未知の key、flag / rule の key が空でない、format の外、params の外、attempts の範囲外、`mountDir` が sensitive の dir・missions・seed root にある) で、どれも load に失敗する。
- **V11**: 練習版の golden (render の出力 == commit した練習版)。練習版が A4 の束の検査 (B2・B3・B5) に通る。
- **V12 (platform)**: env が local 以外で `requirements.answers` が空でなく、`answersSecret` が無ければ render で失敗する。check の stub が 1 を返すと何も apply しない。digest が合わなければ `deploy-user.sh` が helm / kubectl を 1 回も呼ばない。platform には required check が無いので、merge の時に人が Checks を確かめる。
- **V13**: `bootlog_contract_test.go` が `msg="edition check failed"` と ERROR を literal で固定する。
- **V14 (実機でのみ確認可)**: 参照解答の調査の手順をすべて実行しても、他の課題の solve と taint が 0 件 (qa の E2E、brief §8 の 5)。機械の確認は無し。

## Advice
- CEO (2026-11-16): 版を分けること、ADR-0056 として起草すること、利用形態の順、イベント後の公開は都度 CEO。
- CTO 代行 = CoS (2026-11-16): 席ごとの値 + 囮 K。hold-out だけで区別を潰す。I6 の解釈。
- security-engineer (2026-11-16): 5 点とも条件付きで可。HIGH 4 件 (2 席の diff、「既定は練習版」、detect の oracle、総当たり) と要件 1〜8 → D3・D5・D8・D10〜D14、V1〜V8。LOW の self 限定 → D4 で採用。
- product-engineer (brief ws#185 §5.2・§8): C11。D4 の代案 (ii) → D2 の `choice-set` (n ≥ 10)。
- architect (2026-11-16): G2・E1、D3 (b) の候補の下限、束の検査の digest による結びつけ。
