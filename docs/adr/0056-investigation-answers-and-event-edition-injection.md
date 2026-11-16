# ADR-0056: 調査型の課題を足す — 答えは閉じた形式の設問とし、scoreboard の Grader 1 点で「回数を加算してから比較」で判定する。イベント版の痕跡束 (席ごとの値と囮) は seat の Secret → plant → seed → 宣言した mount で、答え表は scoreboard の process だけに注入する。練習版は公開し、イベントのモード (`FLAGS_FILE`) では使わない

- Status: **Proposed** (起草 2026-11-16)
  - Accepted の条件: (1) 段階 A1〜A5 の app PR と P1 の platform PR が merge されている、(2) V1〜V6・V8〜V11・V15〜V64 (V15 の platform の部分を除く) が required check (`test` / `flag-guard` / `chart-lint`) の上で緑、(3) security-engineer の R1 の記録 (A1〜A5・P1。private) と CTO の承認の記録がある。
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
- 調査型の課題に限り、`falco-rule.yaml` と `journey.yaml` の top-level も strict にする (未知の key は fail。答えに見える key を書いても load が通る、という穴を塞ぐ)。
- 調査型の課題には `journey.yaml` が必須。journey の dir そのものが無い場合も拒否する (#608)。
- `type:` の許容集合は、catalog のほかに 3 か所の shell の写しとして書かれている。challenge image の builder の 2 か所 (`images/challenge/Dockerfile:39,51`) と `scripts/check-image-hygiene.sh:331,339` の V2 (ADR-0026 規則 7) である。
  - この 3 か所への `investigate` の追加は段階 A1d が持つ。catalog と 3 か所の集合が一致することは V23 が固定する。
  - spec の type enum (`openapi-scoreboard.yaml:2523,2685,2826`) と metric の kind (`:200`) は、応答に調査型が現れる A3b が追従させる。
- `answers.yaml` (flag の一括提出のテンプレート。key は evade の id だけ、`Dockerfile:34-53`) には、調査型を載せない (trigger / detect と同じ扱い)。テンプレートの注記に「調査型の課題は portal の回答欄で答える (この file では提出できない)」の 1 行を足す。
- `mountDir` は次をすべて満たす。
  - 絶対 path である。
  - `/opt/ctf/missions/` (I16) と seed root の外にある。
  - (a) `sensitive_dir_prefixes` (`gen-values.sh:94`) のどの entry の内側にも、上 (祖先) にも無い。(a2) sensitive な file (`sensitive_paths()`) の dirname と等しくなく、その祖先でもない。理由は、deploy が catalog の rule を発火させないため (I13b)。(a)(a2) は調査型の痕跡にだけ効く (evade の plant-target は、意図して sensitive な場所に仕込む)。
  - (b) 他の課題の mount dir・書き込みの file・痕跡の dir と、等しくもなく、入れ子 (内側 / 上) にもならない。束の file 名は gen-values の時点で分からないので、dir の共有を file の共有として扱う。(c) 同じ file を 2 つの plant.sh が書かない (dir の共有は可)。(c) が ADR-0055 C4 (ii) にあたる。
  - fail-closed の規則: `PLANT_SEED_ROOT` に触れる plant.sh の行は、列挙した形のどれかでなければならない。次はすべて拒否する: shell の展開を含む書き込み先、認識できる書き込み先が 1 つも無い plant.sh、`mountDir` を抜き出せない調査型、`investigate:` block を持つのに type が `INVESTIGATE_TYPE` でない file、空の表、空の sensitive の一覧。比べる path はすべて絶対で clean。
  - `INVESTIGATE_TYPE` (`gen-values.sh:1019`) は catalog の型の名前と parity の test で一致させる。
  - 実装は `challenges/gen-values.sh` の `collect_claims` / `check_claims` (A5a-1 #619)。Go の catalog には写さない (`internal/catalog/investigate.go:115-119`)。ADR-0055 C4 (ii) は、これで実装済み。
- **各課題に、席ごとに変えられる format (D2 の表で「可」) の設問を 1 つ以上置く。** 満たさなければ catalog の load で拒否する。判定は format だけで決まり edition を要らないので、A1b で検査する。
  - 理由: solve には全設問の正解が要るので、Board で共有した固定の答えだけでは solve できない (security-engineer、2026-11-16 の 2 回目)。
  - これで足りる条件は 2 つ。(i) 学習の要点 (L1 / L2) を、席ごとの設問の側に置く。(ii) 席ごとの設問の答えを、固定の設問の答えから導けないようにする。
  - (i)(ii) は機械では確かめられない。CPO の文面レビューと、初回のイベント版の R1 で見る。
- 設問の文 (prompt) は `journey.yaml` の `questions[]` (`{id, prompt}`) に置く。
  - id の集合は catalog と完全に一致する (起動時に検査)。
  - prompt は hintleak の無料の集合に入れる。
    - これは段階 A1e (`internal/hintleak/**` は R1 必須なので、独立の PR) で行う。A7 より前に要る。
    - scope の組み立ては、既存の caller (`internal/hintleak/content_test.go:207`、`fixtures_test.go:56`) と同じ 1 か所で行い、prompt を Free の item に足す。
  - 答えは catalog にも journey にも置かない。

### D2 設問の形式は閉じた列挙 (v1)

| format | 受け付ける形 (正規化の後) | 正規化 (format が決める。設問ごとの指定は無し) | 席ごとに変えられるか | 答えの空間 (code が計算する。作者は宣言しない) |
|---|---|---|---|---|
| `path` | 絶対 path。要素は `[A-Za-z0-9._-]+`、全長 ≤ 255 | 前後の ASCII 空白を除く。連続する `/` を 1 つにする。末尾の `/` を除く (root を除く)。大小文字は区別する | 可 | renderer の語彙の積 (D12) |
| `name` | `[A-Za-z0-9._-]{1,64}` | 前後の空白を除く。大小文字は区別する | 可 | 語彙の大きさ |
| `hexid` | `[0-9a-f]{L}` (`params.length` は 12〜64) | 前後の空白を除く。小文字化する | 可 | 16^L |
| `timestamp` | RFC 3339 の UTC、秒の精度 | 空白を除く。`+00:00` を `Z` にする。秒未満は拒否する | 可 | `params.windowSeconds` |
| `technique` | `T\d{4}(\.\d{3})?` (ATT&CK v19 の表にある ID) | 前後の空白を除く。大文字化する | 不可 | v19 の表の件数。**表は repo に無い**ので、表を入れる段階 A1c (D19) までは catalog が空間を計算できず、`technique` の設問を load で拒否する |
| `choice-set` | 宣言した n 個の選択肢 id の空でない部分集合 (`,` 区切り) | 空白を除く。重複を除く。並べ替える | 不可 | 2^n − 1 |
| `sequence` | 宣言した m 個のラベルから k 個を並べた順列 | 前後の空白を除く | 不可 | m! / (m−k)! |

- format を足すことは、この ADR の amend とする (閉じた列挙を保つ)。
- 期待値の正規化は冪等でなければならない (table の値 v について normalize(v) == v)。冪等でなければ拒否する。
- 形式に合わない入力は 400 を返す。回数は消費しない (D5)。

### D3 答えの空間の下限 (security 要件 6 と、architect の追加)
- (a) **空間 ≥ 100 × attempts**。空間は code が計算する。
  - 計算に使えるのは、format と params (catalog の時点)、または renderer の語彙 (イベント版、validator の時点) だけ。
    - catalog が計算するのは、params だけで空間が決まる `hexid` / `timestamp` / `choice-set` / `sequence`。
    - `path` / `name` の空間は catalog では保留する (語彙は edition にあり、catalog に無い)。A4 の validator (B8) が renderer の語彙で検査する。
    - `technique` は、D2 の表のとおり A1c まで拒否する。
  - 下回れば拒否する (catalog の load、または validator)。
  - 帰結: 4 択の `choice-set` は書けない (2^4 − 1 = 15)。n ≥ 10 なら attempts ≤ 10 まで通る。
- (b) **候補の下限 (追加)**: 席ごとの format では、その席の束に現れる形式の合う別々の token の数を数える。これが R × attempts 以上であること。
  - 理由: 実際の総当たりは「束の中の候補を順に試す」ことなので、(a) の形式の空間だけでは捕まえられない。
  - **R = 10** (CISO の決定、2026-11-16)。validator が拒否の条件にする。
  - attempts の既定は 5 以下に保つ (security の推奨。D1 の既定は 5)。

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
  - 読み方 (A3b-2 #621): 表示中の mission が調査型のときだけ、journey の polling (約 2 秒) のたびに `store.AnswerAttempts` を 1 回 SQL で読む (`internal/scoreboard/api/api.go:2546-2568`)。読めなければ journey 全体を 500 にする。回数と正解の表示を推測で出さない (fail-closed)。
  - 代案は、`hintViews` (`internal/store/store.go:124`) のような in-memory の写しを write-through で持つ形。読みは 0 になるが、写しと table の 2 つの正ができ、`Reset`・migration・自己修復 (D5 の 5) との整合を別に守ることになる。今は採らない (Signpost 7)。

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
   - **自己修復** (review #616 R4#2): 正解を記録した後に `MarkSolved` が失敗した場合 (500)、同じ設問への次の提出は 3 で 0 行になり、`already-correct` になる。このとき比較はせず、記録を読むだけで、全設問が正解済みなら solve を完了させる。
   - `AnswerResult` には Go だけの field `Newly` がある。その呼び出しが solve を記録したら true。API の 4 field (D6) には入らない。A3b の solve の metric はこれで数える。
   - 前提: A3b の route と A6 の portal は、「正解済みで未 solve」の設問に再提出の口を残す (正解済みの欄を無効にしない)。
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
  - 新しい table `answer_attempts(user, challenge, question, n, correct, PRIMARY KEY(user, challenge, question))` を足す。migration は ADR-0020 の `user_version` の 3 (2 → 3、A3a-1 #615)。`POST /api/admin/reset` は #615 で全体を 1 transaction にした。rollback (前の image に戻す) は、`PRAGMA user_version = 2;` と同時に `DELETE FROM answer_attempts;` を行う。table は additive で、旧 image は読まない。runbook とリハーサルは platform#333。`docs/db-schema.md` も更新する。I1 は変わらない。
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
  - (iii) イベントのモードでは、練習版の答えから Judge を作る code path に到達しない。練習版の答えは、T6 の比較のためにだけ読む (A4a-1)。表は `edition.Load` の 1 回の呼び出しでだけ得る (ADR-0033 D6 と同じく、ソースの検査で固定する)。
  - (iv) **練習のモードの採点** (A4a-2): イベントのモードでなく `ANSWERS_FILE` が無く、スコープに調査型があるときは、`edition.Load` が image の練習版の表 (`challenges/<id>/edition/practice/answers.tsv`。run id は 32 桁の 0、seat は `*`) をスコープの分だけ 1 つにまとめ、`Check` (EventMode false) と `NewJudge` を通して Judge にする。
    - `Load` の入口は 1 つのまま (引数に challengesDir を足す)。`Parse` / `NewJudge` を呼ぶのは load.go だけ。
    - スコープの調査型に練習版が欠けていれば、起動を拒否する (T4、起動ログの (4))。
    - 受理したときは (5) を run id 32 桁の 0 で出す。platform の verify は、イベントでこの値を見たら FAIL にする (P1b-2)。
    - A4a-2 までは、今の挙動 (`Load` が `(nil, "", nil)`、提出は 500 で何も消費しない。#622 の test) のままにする。
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
  - 受理したときだけ `--digests-out` を書く。1 行目は `# falco-ctf evidence-digests v1 run=<run id>`、2 行目以降は `seat<TAB>cid<TAB>digest` (束は (seat, 課題) ごと。D11)。(seat, cid) の集合は、席 × スコープの調査型と一致する。
  - **run id** (security 1(a))
    - `render` が、1 回の実行ごとに `crypto/rand` の 128 bit から作る (32 桁の小文字 hex)。
    - `answers.tsv` の 1 行目に書き、`check` は `--digests-out` に同じ値を書く。
    - `check` は、表の run id が読めない、または全部 `0` なら拒否する。
    - scoreboard は起動時に run id を log に 1 回出す (D16 の (5)。答えの値は出さない)。
    - platform の preflight は、表と digests の run id が一致しなければ何も apply しない。これが無いと、別々の実行で作った表と束が組み合わさり、誰も解けない席が生まれる。
  - **正規の束の digest** (security 1(b))
    - 定義は 1 つ。束の file を名前の byte 順に並べ、各 file について `name` + `\0` + `hex(sha256(内容))` + `\n` を連結する。その列の sha256 を小文字の hex で表したものを digest とする。
    - 実装は Go の `internal/edition` の 1 関数と、`deploy-user.sh` の写しの 2 つ。写すのは digest の定義だけで、内容の規則は写さない。
    - 両方の test が共有の case 表 `internal/edition/testdata/bundle-digest/` (入力の束と期待の digest) を読む (ADR-0033 D4 と同じ parity の型)。
    - 表の形 (A4b-1 #633): `cases.tsv` は 1 行が `case<TAB>digest<TAB>input` で、入力は case ごとの平らな dir。testdata は `.gitattributes` の `-text` で bytes を固定する。CRLF の内容と UTF-8 の名前の case を含める。
    - shell の写し (A5c) は、名前の byte 順を `LC_ALL=C` の sort で得る。
- `scoreboard edition render` の入力: `--edition-dir` `--master-key-file` `--seats`。出力は席ごとの束と `answers.tsv`。
  - HTTP server の path から render に到達しない (ソースの検査で固定する)。
- **validator が答え表を得る入口** (追補 7、#634 R4#1): `load.go` の exported な入口 1 つ (仮に `LoadEventTable(scored, answersFile)`)。door の数に入れ、呼んでよいのは `cmd/scoreboard` の `edition check` の 1 か所。
  - 中身は scoreboard の `Load` と共通の unexported な関数で、読む → `Parse` → `loadPractice` → `Check` (EventMode true、PracticeSet、FlagValues) の順。起動の経路と validator の経路は、同じ `Check` を通る。
  - 返すのは `*CheckedTable` (field は unexported、作れるのは load.go だけ) と run id。`loadPractice` が読む練習版の束と template の file の集合 (A4c-2 の B4 の入力) も `CheckedTable` が運ぶ。練習版の reader は 1 つのままで、追補 5 の J18 の「`Load` の外の入口」はこれに 1 つにまとめた。
  - `CheckBundles` は `*CheckedTable` だけを受け、結果は `*CheckedBundles` (作れるのは `CheckBundles` だけ)。`WriteDigests` はそれだけを受ける。検査していない表と束は、型の上で digests に届かない。
- **入力の木の所有** (#633 R1#1): validator の入力 (`--answers`・`--evidence-root`・`--flags-file`・`--seats`・`--edition-dir`) は運用者が所有する木で、validator の container には `:ro` で mount する。
  - そのうえで reader は O_NOFOLLOW で開き、開いた descriptor の `Stat` (dev / inode / 通常 file) を、先に取った `Lstat` と照らし合わせる。食い違えば B2 の違反にする (A4e)。
- platform は、課金が発生する最初の step の前に、render → check の順で、pin した scoreboard image の digest を `docker run --rm --network none --pull never` で呼ぶ。通らなければ何も apply しない。
- 採点の Secret と払い出しは、同じ実行で同じ出力から作る (`0033` D9 (c))。

### D10 拒否の条件 (どれか 1 つで拒否。1 ケースに 1 欠陥の test)
**scoreboard の起動時 (表について) と validator の両方**:
- T1 / T2: D8 の (i) と (ii)。
- T3: 表の形。
  - 1 行目は `# falco-ctf answers v1 run=<run id>` (run id は D9 の定義で、32 桁の小文字 hex)。4 列の TSV (seat、cid、qid、value)。
  - 練習版の run id は 32 桁の `0`。イベントのモードで run id が全部 `0` なら拒否する。
  - quote・CR・空の列は不可。UTF-8 で、`sourcehygiene.Hidden` が 0 件。
- T4: 完全性。
  - スコープの調査型の cid × qid のすべてについて、すべての seat の行がある。
  - seat の集合が空でない。seat は ADR-0042 の文法に合う。
  - 重複と、未知の cid / qid は不可。イベントで seat `*` は不可。
- T5: 値が format に合い、正規化が冪等である。
- T6: 値が、練習版の (同じ format の) 答えのどれとも一致しない。
- T7: 値が `FALCO{`、flag の正規表現、dev の placeholder、今回の `FLAGS_FILE` の値のどれも含まない。
- T8: 席ごとの format では、同じ設問の値が席の間で重複しない。

**edition.yaml について (renderer・validator・練習版の CI。追補 8)**:
- E1: 形。次をすべて満たさなければ拒否する。
  - UTF-8、Hidden が 0 件、`MaxSpecBytes` (1 MiB) 以下、document は 1 つ、anchor と alias が無い。
  - top-level の key は `version` (必須、`1`)・`time`・`fixed`・`slots` だけで、どの深さでも未知の key と型の誤りを拒否する (strict)。
  - slot は 1〜`MaxSlots` (512) 個。slot 名は `IDPattern` で、answer の slot は 27 文字以内。暗黙の decoy 名 `<name>-d<i>` を含めて一意。
  - `role` は `answer` か `filler`。answer は `question` と `decoys` を持ち、`format` を持たない。filler は `format` を持ち、`question` と `decoys` を持たない。
  - vocab は path と name の slot だけが持つ。name は list が 1 つ。path は位置ごとの list で、1〜`MaxVocabPositions` (16) 位置。各 list は 1〜`MaxVocabWords` (1024) 語で、語は format の正規形 (path では要素 1 つ)。位置の中に同じ語は 2 回出ない。最長の組が path の上限 (255 byte) に収まる。
  - hexid の filler は `length`、timestamp の slot は `window: {from, to}` (0 ≤ from < to) を持つ。timestamp の slot があれば `time.base` が要る。
  - message に語彙の値を出さない (slot 名・位置の番号・語の番号・行番号だけ)。
- E2: 課題の設問との対応。次をすべて満たさなければ拒否する。
  - 席ごとの format の設問それぞれに、answer の slot がちょうど 1 つある。answer の slot の `question` は、その課題の席ごとの設問を指す。
  - `decoys` ≥ K = max(2 × attempts, 4)。
  - answer の timestamp の窓の幅 (to − from) は、設問の `params.windowSeconds` と一致する。
  - `fixed` の key の集合は、席ごとでない設問の集合と一致し、値は `answerformat.Canonical` を満たす。
  - decoy は answer の slot から format・params・vocab・window を継ぐので、同一性は E2 の構成で成り立つ。
**validator だけ (束は scoreboard に無いため)**:
- B1: 表の seat の集合が `--seats` (roster ∪ 予備) と一致し、すべての (seat, スコープの調査型) に束がある。
- B2: 束の形。
  - 平らな通常 file だけ。名前は `^[a-z0-9][a-z0-9._-]{0,62}$` で、`..` で始まらない。
  - file は (seat, 課題) の束ごとに 64 個以下で、合計は 512 KiB 以下。UTF-8 で、Hidden が 0 件。
- B3: 束に `FALCO{`、flag の正規表現、dev の placeholder、今回の flags の値が 0 件。
- B4: 練習版との比較。次のどれかに当たれば拒否する。
  - file の digest か束の digest が、image の中のどれかの練習版と一致する。
  - 練習版の答えの値が束に現れる。
  - 10 rune の shingle の重なり (`|S_event ∩ S_practice| / |S_event|`。正規化は hintleak と同じで、`hintleak` から export した 1 つの関数を使う) が θ 以上である。比べる組は 2 つ。
    - (1) 出力同士: 席の束 × image の中の練習版の束。
    - (2) **テンプレート同士**: イベント版の `template/` × image の中のすべての練習版の `template/`。slot の印 `{{ctf:…}}` を除いてから比べる。席ごとの filler があると (1) の重なりは下がるので、公開のテンプレートの流用は (2) でしか確実に捕まらない。
  - **θ = 0.5** (暫定。CISO の決定、2026-11-16)。θ は `internal/edition` の定数で、test が値を pin する。
    - θ が設定されていない (0 以下、NaN、1 を超える) ときは、比較を skip せずに拒否する。
  - validator は (1)(2) の重なり率の数値 (最大値と、その組の id) だけを stderr に出す。本文の bytes は出さない。初回の実測で θ を見直す (Signpost 6)。
  - 初回のイベント版は、R1 で文面も見る。
- B5: `hintleak.Check({Hints: スコープの hints, Free: ADR-0026 と同じ無料の集合, Targets: 席の束の各 file})` の違反が 0 件 (ADR-0026 D5 に新しい caller を足す)。
  - Hints と Free を組み立てる定義は 1 つで、`internal/hintleak/scope` (非 test。R1 の path) に置く。これまで test の中にしか無かった `assembleScope` と prompt の数の検査 (A1f) を A4c-1 で移し、`content_test.go` と validator (A4e) の両方がそれを呼ぶ。`CheckBundles` は Hints / Free を引数で受ける (A4b-2) ので、組み立ての 2 つ目の定義は作らない。
- B6: 席ごとの format の答えが、その席の束に現れる (導けることの最低限の確かめ)。
- B7: 囮 K (D12)。次のどれかに当たれば拒否する。
  - (decoy の数と、decoy と answer の同一性は、静的な性質なので E2 に移した (追補 8)。decoy は answer の slot の `decoys: <n>` から作られ、format・params・vocab・window を継ぐ)。
  - 実際の出力で、席の組ごとに見て、答えでない差分の位置が答えごとに K より少ない。
- B8: D3 の (a) と (b)。(a) は edition.yaml の段 (A4d-1b) で、answer の slot の空間 (path / name は語彙の位置ごとの積、hexid / timestamp は設問の params) を 100 × attempts と比べる。(b) は出力の段 (A4d-2 と validator)。
- B9: 席ごとの format の答えが、image の `/app/challenges` と `/app/scenarios` の bytes に現れない (brief §8 の 2)。
  - 照らすのは、採点が受理する**綴りの族**全体 (追補 7、#634 R2#2)。corpus を format ごとの `answerformat.Fold(format, text)` で畳んでから、正規化した値を部分列として探す。
    - name: fold は恒等 (前後の空白は部分列の検索で覆える)。
    - path: 連続する `/` を 1 つにする (族は無限だが、fold で覆える)。
    - hexid: ASCII の小文字にする。
    - timestamp: `+00:00` を `Z` にする (受理される綴りは 2 つだけ)。
  - 席ごとでない format は B9 の対象外。
  - `Fold` は `Normalize` の隣に置き、「受理される綴り s の `Fold(s)` は、正規化した値を部分列に持つ」の性質の test で固定する (V55)。偽陽性は拒否の側なので許す (再 render で解ける)。
  - A4b-2 (#634) の byte の一致は、この fold に置き換える (A4c-2)。

security の要件 3 は「起動拒否」と書いている。束の項目は、scoreboard ではなく validator (課金の前。何も払い出さない) と、deploy の digest の照合 (D11) で止める。security-engineer は 2026-11-16 (2 回目) にこれを条件付きで可とした。条件は 3 つで、D9 の run id、D9 の digest の 1 定義、D11 の deploy-user 自身の fail-closed である。

### D11 痕跡束の Secret と、plant 経由の注入 (J1)
- seat の ns の Secret は**課題ごとに 1 つ**で、名前は `ctf-evidence-<cid>` (cid は ADR-0041 の文法。名前は 13 + 63 文字以内で DNS subdomain に収まる)。本 ADR で `ctf-evidence` と書くときは、この族を指す。
  - 決めた理由 (A5a-2 #629 の要判断。1 つの scope に調査型が 2 つ以上あると、flat な key から `mountDir` への対応が決まらない)。比べた案は 3 つ。
    - (K1) key に cid の prefix を付ける: chart が template で key を分解することになる。脆く、写しが増える。
    - (K2) 課題ごとに別の Secret: 版・練習版・validator・digest の単位と 1 対 1 になり、1 MiB の上限も課題ごとに効く。
    - (K3) evidence の mount が 2 つ以上なら helm の `fail`: 安いが、後で K2 に移ると Secret 名と digests の形 (P1b-3) を変えることになる。
  - 消費者がまだ無い今、K2 に決める。
  - key = 束の file 名。key の族は `CTF_FLAG_*` と交わらない。
  - ctf-flags とは別の object で、答え表は入れない。
- **Secret は chart の外で作る** (追補 6、L2)。`deploy-user.sh` (A5c) が helm の前に、`kubectl create secret generic ctf-evidence-<cid> --from-file=<name>=<path> …` で作る (file を名前で列挙し、dir は渡さない)。label は `app.kubernetes.io/managed-by=deploy-user` と `falco-ctf/evidence-of=<cid>`。
  - 毎回作り直す。スコープに無い `ctf-evidence-*` は helm の前に消す。
  - client-side の `kubectl apply` は使わない (last-applied の annotation に object の全体が入り、annotation の 256 KiB の上限に当たる)。
  - chart は Secret を render しない。名前で volume を参照して mount するだけ (optional なし。Secret が無ければ Pod は起動しない)。
  - 決めた理由: chart の values から render すると、束は Helm の release の記録 (Secret driver。chart の全 file + values + manifest を gzip + base64 にして 1 つの Secret に入れ、上限は 1 MiB) に、values の生の text と manifest の base64 の 2 回載る。
    - 圧縮が効かない最悪の場合、収まるのは全課題の合計で約 230 KB (chart の file が約 160 KB、`.helmignore` が無いため。仮説の計算)。
    - `--history-max` を指定していない (`deploy-user.sh:699`) ので、写しが過去の revision の数だけ残る。
    - (L1) 上限を下げる案: 予算が無関係な chart の大きさに連動し、上限が圧縮の効き方に依存して検証できない。(L3) driver の変更や分割: ConfigMap も 1 MiB、SQL は DB を足すことになる。どちらも採らない。
    - L2 なら、Kubernetes の Secret の上限が課題ごとにそのまま効き (K2 の理由が成り立つ)、digest を取った bytes がそのまま Secret に入る (D9)。
- chart の values は `.Values.evidence.challenges.<cid>.names` (束の file 名の list。内容は持たない) で、release の記録には名前しか載らない。
  - chart の `fail` (#632 の `ctf-user.evidence.check`) は、次のどれかに当たれば render を止める。
    - `plant.mounts` の `evidence` が boolean の true でない。
    - `challenge` が challenge id の文法に合わない、または同じ challenge が 2 回出る。
    - `path` が `[A-Za-z0-9._-]` の要素の絶対 path でない、または `.`・`..` を含む。
    - 課題ごとの `names` が 1〜64 個でない、重複がある、B2 の文法 (`^[a-z0-9][a-z0-9._-]{0,62}$`) に合わない。gen-values の `EVIDENCE_NAME_RE` も同じ文法。
    - 痕跡があるのに、`plant.seedScript` が `[sh, -c, <set -eu で始まる script>]` の形でない。
  - 大きさの上限 (課題ごとに 512 KiB、全課題の合計で 2 MiB = plant-seed の emptyDir の `sizeLimit: 4Mi` の半分。CoS の決定) は、chart からは見えない。deploy-user (A5c) が cluster に触れる前に byte を数えて強制し、validator の B2 と二重にする。上限の単位は (seat, 課題)。
  - `plant.mounts` の `evidence: true` の entry の `challenge` の集合と、`.Values.evidence.challenges` の key の集合が一致しなければ `fail` する (両方向)。
- 各 Secret は `plant` にだけ、`/opt/ctf/evidence-src/<cid>` に readOnly で volume mount する。challenge・ttyd・ttyd-proxy・missions-scope には mount しない。
- plant の生成 script は key を**名前で列挙して**、通常 file として copy する。
  - 形は `cp "/opt/ctf/evidence-src/<cid>/<key>" "${PLANT_SEED_ROOT}/<mountDir>/<key>"`。`-a` と `.` と glob は使わない。`..data` の symlink は辿られ、通常 file になる。
  - 形の定義は gen-values の `render_evidence_copy` の 1 か所 (#629)。束の file 名は gen-values の時点では分からないので、実際の copy 行は chart (A5b) が `.Values.evidence.challenges.<cid>.names` を byte 順に並べて render する。
  - chart の copy 行は、`render_evidence_copy` の出力と byte で一致する。`scripts/check-flag-isolation.sh` が、gen-values の検査用の入口 4 つ (`--check-seed-script`・`--render-evidence-copy`・`--list-evidence-mount-dirs`・`--emit-evidence-fixture`) を使って確かめる (V43 の実装。gen-values は source せずに呼ぶ)。
  - その後 `chmod 0444` する。
- 2-7(a) の copy-source の allowlist に足すのは `/opt/ctf/evidence-src/<cid>/<素の file 名>` だけ (cid はスコープの調査型)。`..`・glob・`$`・`cp -a`・`.`・別の root・空白を含む名前は拒否する (#629)。
- chart が render した copy 行にも同じ規則を掛ける。`scripts/check-flag-isolation.sh` が `helm template` の出力を読み、各行が `render_evidence_copy` の形と一致することを確かめる (A5b、V43)。
- challenge は seed の subPath = `mountDir` を readOnly で mount する。
  - `mountDir` は plant-target として宣言するので、1-4 / 1-18 の既存の検査がそのまま効く (緩めない)。
  - 調査型の分の 1-4 の allowlist だけは、`check-flag-isolation.sh` が gen-values の導出 (`--list-evidence-mount-dirs`) に委ねている (#632)。ADR-0007 の「検査は生成器から独立に持つ」とは非対称で、代わりにあるのは catalog の load (Go、strict) と gen-values の `--check` の二重化。
  - 二重化だけでは、2 つの導出が同じ誤りをしても捕まらない。そこで、catalog の `mountDir` の集合と commit 済みの生成物の `evidence: true` の path の集合が一致することを Go の test で固定し (V53)、第 3 の shell の parser を作らずに独立性を補う。
- plant を付けるかどうかは、「plant.sh を持つ」(`gen-values.sh:105`) ではなく type から導く (evade の plant.sh、または調査型)。調査型は plant.sh を持てない (#629)。
- gen-values と chart の間の生成物の契約: `plant.mounts` の調査型の entry は `{path: <mountDir>, readOnly: true, evidence: true, challenge: <cid>}`。`challenge` が #629 に無ければ、A5b の前に足す。
- `internal/catalog` の `reservedMountRoots` に `/opt/ctf/evidence-src` を足す (A5b)。gen-values の側と parity にする (V28 を広げる)。`mountDir` がこの下にあると、2-7 の文字列の判定が曖昧になるため。
- `deploy-user.sh --evidence-dir <dir> --evidence-digests <file>`: `<dir>` の下に、スコープの調査型の課題ごとに `<cid>/` を置く。次の場合は、cluster に触れる前に非ゼロで終了する。
  - `<cid>/` の集合がスコープの調査型と一致しない。
  - 各 `<cid>/` の正規の束の digest (D9) が、digests の (自分の seat, cid) の行と一致しない。
  - これは内容の規則の写しではない。Go が受理した bytes であることの照合である。
  - 照合が通った同じ file から、同じ実行の中で Secret を作り (K1)、`.Values.evidence.challenges.<cid>.names` を渡す。名前は B2 の文法で検査した後でだけ渡す。大きさ (課題ごとに 512 KiB、合計 2 MiB) もここで、cluster に触れる前に数える。
  - **deploy-user 自身が fail-closed にする** (security 1(c)、HIGH)。platform の V12 には required check が無いので、それに頼らない。
  - スコープに調査型があるとき、次のどれかに当たれば、cluster に触れる前に非ゼロで終了する。
    - `--flags-file` があるのに、`--evidence-dir` か `--evidence-digests` が無い (scoreboard の D8 (i) と同じ判定)。
    - `--evidence-dir` と `--evidence-digests` の片方だけがある。
    - digests の 1 行目の形か run id が読めない、自分の seat の行が無い、または digest (D9 の定義) が一致しない。
  - 練習版を使うのは、`--flags-file`・`--evidence-dir`・`--evidence-digests` のどれも無いときだけ (local の既定)。
- 新しい検査 3-x (`assert-flag-isolation.sh`、deploy の時、fail-closed):
  - challenge の `mountDir` の中に symlink が 0 件で、通常 file だけがある。
  - seat の ns の Secret のうち type が `Opaque` のものの名前の集合が、{`ctf-flags`} ∪ {`ctf-evidence-<cid>` | cid はスコープの調査型} と一致する。Helm の release の記録 (type `helm.sh/release.v1`) は別の類として数える。
  - `ctf-evidence-<cid>` の key の集合が、chart に渡した `names` と一致する。
  - release の記録 (`helm get values` / `helm get manifest`) に、束の内容 (sentinel) が 0 件である (V50)。

### D12 席ごとの値・囮 K・予備の席・renderer (P3・G2)
- `edition.yaml` は slot を宣言する。
  - schema (追補 8。規則は D10 の E1 / E2):

        version: 1                     # 必須
        time: {base: <RFC 3339 UTC>}   # timestamp の slot があるとき必須。練習版は公開の固定値、イベント版は private
        fixed: {<qid>: <値>}           # 席ごとでない設問 (technique / choice-set / sequence) の答え。全席の行として answers.tsv に書く
        slots:
          - name: <IDPattern、answer は 27 文字以内>
            role: answer               # answer | filler
            question: <qid>            # answer だけ。format と params は設問から引く
            decoys: <n>                # answer だけ。n ≥ K。<name>-d1…dn を作り、format・params・vocab・window を継ぐ
            vocab: [[語, …], …]        # path / name だけ。name は list 1 つ、path は要素の位置ごと (固定の要素は語 1 つの位置)
            window: {from: <秒>, to: <秒>}  # timestamp だけ。base からの半開区間。値は席ごとにこの中から一様に選ぶ
          - name: <…>
            role: filler
            format: <path | name | hexid | timestamp>
            length: <n>                # hexid の filler だけ

  - 作者向けの最小の例と template の対応は、追補 8 の PR の本文に載せる (語彙と値は placeholder だけ)。
  - D3 の前提: 語彙は公開で参加者が知っている (練習版の edition.yaml は公開)。空間は語彙の組の数なので、それでも 100 × attempts が残る。
  - テンプレートの file には `{{ctf:<slot>}}` の印を置く。
  - 未宣言の slot、使われない slot、render の後に印が残ることは、すべて fail。
- 値は `HMAC-SHA256(master, len(seat) ‖ seat ‖ len(cid) ‖ cid ‖ len(slot) ‖ slot)` から導く決定的な DRBG で選ぶ。
  - `len` は 4 byte の big-endian の byte 数 (長さの接頭辞)。区切りの無い連結では、別の組が同じ入力になるため。
  - renderer の test で、`("ab","c")` と `("a","bc")` が別の値になることを固定する。
  - master 鍵は platform の sops の中だけに置き、render の実行の中だけで使う。cluster・scoreboard・seat の ns には置かない。
- **K**: 答えの slot 1 つごとに、同じ format の decoy の slot を K 個以上置き、それらも席ごとに変える。
  - **K = max(2 × attempts, 4)** (CISO の決定、2026-11-16)。2 席が結託しても、全候補を回数の内で試し切れない。
  - decoy の slot の format・params・`vocab`・window は、その answer の slot と同一 (見分けが付かないこと)。decoy を answer の slot の `decoys: <n>` から作るので、同一性は構成で成り立つ (追補 8)。数は E2 が確かめる。
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
  - 回す前に、(user, cid) ごとの hold-out の試行の予算を store で加算する (D5 と同じ順序)。
    - 予算は **20** (CISO の決定、2026-11-16)。
    - 時間窓ではなく (user, cid) の累計で数え、`POST /api/admin/reset` のほかでは戻さない。1 回で 1 bit、最大 20 bit に抑える。
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
- **新しい行は 2 つに分ける** (review #614 R4#3)。
  - 文面 1「答え表」は main にある app の挙動を記述する。platform が使う前に要るので、A4-0 (P1b-1 と同時に open し、先に merge) で入れる。
  - 文面 2「痕跡束と版の検査」は、A4e が CLI の部分を (P1b-2 と対で)、A5c が痕跡束の部分を (P1b-3 と対で) 入れる。どちらも両リポ同時 PR。
- 「scoreboard の起動ログ」行に (4) を足す。`msg="edition check failed"` (level ERROR、`os.Exit(1)` の直前に 1 回、値は出さない)。platform の `verify.sh` が読み、`bootlog_contract_test.go` が literal で固定する。
- 同じ行に (5) も足す。`msg="edition loaded"` (level INFO、1 起動に 1 回、属性は `run_id` だけ)。platform の verify は、この run id が払い出しに使った digests の run id と一致することを確かめる (D9)。
- 「detect-grader Job」行の (5) は D14。
- Flags 行は変えない (答えは `FALCO{...}` の文法に合わない)。

文面 1 (A4-0):

> | 答え表 (ADR-0056 D8・D13、**クロスリポ契約・両リポ同時 PR**) | 調査型の課題の答え表は app に置かない (練習版の `challenges/<id>/edition/practice/answers.tsv` を除く)。イベントでは、platform が scoreboard の ns に Secret を作る。`charts/scoreboard` の `answersSecret` (`enabled` は既定 `false`、`name` は既定 `scoreboard-answers`、`key` は既定 `answers.tsv`) で有効にする。chart は、この Secret を scoreboard の container にだけ `/etc/ctf-answers` へ readOnly で mount し、`ANSWERS_FILE=/etc/ctf-answers/<key>` を渡す。render を拒否する条件は 3 つ: `answersSecret.enabled` なのに `flagsSecret.enabled` が無い / `env.detectGraderNamespace` が release の ns か `scoreboard` と同じ / `key` が `^[A-Za-z0-9][A-Za-z0-9._-]*$` に合わない。file の形は、1 行目が `# falco-ctf answers v1 run=<32 桁の小文字 hex>`、2 行目以降が 4 列の TSV (seat・cid・qid・value)。scoreboard が起動を拒否する (exit 1、起動ログの (4) `edition check failed`) 条件: イベントのモード (`FLAGS_FILE` が空でない) でスコープに調査型があるのに `ANSWERS_FILE` が無い / イベントのモードでないのに `ANSWERS_FILE` がある / 表が D10 の T3〜T8 のどれかに当たる / image の練習版が壊れている (T6 の比較のために読めない、A4a-1)。受理したときは (5) `edition loaded` に run id を出す。値は応答・log・metrics・error に出ない。platform は、seat の ns と grader の ns にこの Secret を置かない。helmfile による有効化は P1b-1a (platform#334)、render gate は P1b-1b (ADR-0055 S3 の後) |

文面 2 (A4e が CLI の部分を、A5c が痕跡束の部分を入れる):

> | 痕跡束と版の検査 (ADR-0056、**クロスリポ契約・両リポ同時 PR**) | 調査型の課題の設問 (id・format・attempts・params) は app の `falco-rule.yaml` が正典。答えは app に置かない (練習版の `challenges/<id>/edition/practice/` を除く)。**イベント版**は platform が app のテンプレート形式 (`edition.yaml` + `template/`) で private に書き、`scoreboard edition render` で席ごと (roster ∪ 予備) に生成し、`scoreboard edition check` (pin した scoreboard image、`--network none`) が受理した出力だけを使う。CLI は exit 0 = 受理 / 1 = 拒否 / 2 = 使い方の誤り、stderr は値を含まない、`--digests-out` は 1 行目が `run=<run id>`、以降が `seat<TAB>cid<TAB>digest` (digest の定義は D9 の 1 つ。共有の case 表は `internal/edition/testdata/bundle-digest/`)。platform の preflight は、表と digests の run id が一致しなければ何も apply しない。**答え表** (`# falco-ctf answers v1 run=<run id>` の 4 列 TSV) は文面 1「答え表」の行のとおり。**痕跡束**は課題ごとの seat の Secret `ctf-evidence-<cid>` (key = file 名、課題ごとに 64 個以下・512 KiB 以下) で、`plant` だけに `/opt/ctf/evidence-src/<cid>` として mount し、その課題の `mountDir` へ copy する。`deploy-user.sh --evidence-dir --evidence-digests` は、次のどれかに当たれば cluster に触れずに非ゼロで終了する。digest か run id が合わない。`--flags-file` があるのに 2 つのどちらかが無い。2 つの片方だけが渡された。**イベントのモード** = scoreboard の `FLAGS_FILE` が空でないこと。このモードでスコープに調査型があるのに `ANSWERS_FILE` が無い、または逆の場合は、起動を拒否する。platform は、env が local 以外で `requirements.answers` (ADR-0055 D6) が空でなければ、`answersSecret` 無しでは render せず、課金の前に render → check を通す。適用の順は platform が先 (ADR-0033 D9 (g) と同じ) |

### D17 ADR-0055 の `requirements.answers` との接点
- `requirements.answers` = スコープの調査型の課題 id の、並べ替えた集合。生成器が導出し、宣言はさせない (ADR-0055 D6)。
- platform はこの 1 つから次を決める。写しは持たない。
  - `answersSecret` が要るか。
  - 何を render / check するか。
  - どの seat に `ctf-evidence` を作るか。
- ADR-0055 D6 は「ADR-0056 が Accepted になってから足す」としていた。CTO 代行 (CoS、2026-11-16) が、これを「本 ADR の A1b が merge されてから足す」に詰めた。A1b は merge 済み。ADR-0055 D6 も同じ文に直した。
- scoreboard 側の照合 (スコープに調査型があるのに表が無ければ拒否) は D8 の (i) で、ADR-0055 C7 と同じ型である。

### D18 amend と参照
- **amend (navigational な pointer を足す)**:
  - ADR-0026: D5 の新しい caller (束 = Target)。
  - ADR-0001 / I12: plant の 2 つ目の用途と、copy-source を 1 つ足すこと。
  - ADR-0033: D9 の (a)(b)(c)(g) の型を `ANSWERS_FILE` と束に延長する。Signpost 3 を版の検査に限って発火させる。
  - ADR-0055: D6 の `answers`。C4 (ii) と V6 は ADR-0056 A5a-1 (#619) で実装済み (pointer)。
  - ADR-0038: D2 の `gate` の閉じた語彙に `self` を足す (A3b-4 #627)。ADR-0038 の D2 の表は書き換えず、header に限定 supersede の注記を置くだけにした (#627 の review MED)。`selfOrAdmin` は、`no_identity` のときは admin の集合を引かない。宣言する組は `self` × {`no_identity`, `non_canonical`, `mismatch`}。`self` の `mismatch` には、`{user}` と一致しない `ADMIN_EMAILS` の identity を含める (意図した拒否なので、alert に数えない)。
  - ADR-0003: W2 (`0003:221-243`) が調査型にも及ぶ。調査型が current に留まる間、その後ろの evade の clean gate は効かない。コースの配置の規則で塞ぐ (A3b-5 #625)。この規則は CI の test (V39) と、`catalog.LoadScored` の起動時の拒否 (`ErrEvadeAfterInvestigate`、`internal/catalog/scenario.go:92-139`) の両方で効く。scenario の無い順序 (課題 id の順) にも当たる。ADR-0003 の W2 には pointer を足した。I11 は変えない。
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
| A0 (#605) | 本 ADR (Proposed)、索引 | — | — | — |
| A1a (#606) | `internal/catalog/answerformat` (D2 の列挙と正規化。D3 (a) のうち catalog で計算する 4 format。`path` / `name` は保留、`technique` は拒否) | 要 | — | V6 (catalog)、V21 (format) |
| A1b (#607) | catalog の `investigate` (strict)、journey の `questions[]`、D1 の「席ごとの設問を 1 つ以上」。`catalog.LoadScored` による調査型を含む scope の拒否は、A3b-3 (#622) で外した | 要 | — | V10、V20、V21 |
| A1c (任意) | ATT&CK v19 の technique の表を入れ、`technique` を有効にする。設問に `technique` を使うときだけ、A7 の前に入れる | — | — | V21 (technique) |
| A1d (#611) | A1 の follow-up (#608): `type:` の許容集合に `investigate` を足す (`images/challenge/Dockerfile` の 2 か所、`scripts/check-image-hygiene.sh` の V2、`scripts/test-check-image-hygiene.sh` の case)。`answers.yaml` の注記。catalog と 3 か所の parity の Go test。調査型の top-level の strict と journey.yaml の必須 (journey の dir が無い場合を含む)。`CheckSpace` の test の強化。実課題の数の pin を外す | 要 (Dockerfile) | — | V22、V23、V25、V26、V27 |
| A1e (#612) | `internal/hintleak` の scope に設問の prompt を Free として足す (D1) | 要 | — | V24 |
| A1f (#618) | #608 の追記: prompt の数の検査を、組み立て側が数えた値ではなく Free の実体 (Source が `<cid> questions[<qid>].prompt` の形の item) で数える | 要 | — | V24、V35 |
| A2a (#610) | `internal/edition` の答え表: parser・T3〜T8・`ModeCheck` (T1 / T2 の判定。入力はイベントのモード・スコープの調査型の有無・`ANSWERS_FILE` の有無)・Judge。pure な package にする (env・file の読み・log・process の終了を持たない) | 要 | — | V1 (Judge と error の文)、V3 (T)、V15 (T3 の run id) |
| A2b-go (#613) | `edition.Load` の 1 点、`cmd/scoreboard` の起動時の拒否、起動ログの (4)(5)。クロスリポ契約の「起動ログ」行 | 要 | 起動ログの行 ↔ P1a (platform#332、先に merge) | V1 (起動)、V13、V15 (起動ログ) |
| A2b-chart (#614) | `charts/scoreboard` の `answersSecret` (scoreboard の container だけに mount)、render の拒否 3 つ | 要 | — (行は A4-0) | V2 (scoreboard) |
| A2b (分割前の記述) | `edition.Load` の 1 点、`cmd/scoreboard` の起動時の拒否 (`ModeCheck` の結果の配線)、起動ログの (4)(5)、`charts/scoreboard` の `answersSecret` と grader の ns の `fail` | 要 | 起動ログの行 ↔ P1a (verify.sh) | V1 (起動)、V2 (scoreboard)、V13、V15 (起動ログ) |
| A3a-1 (#615) | store: `answer_attempts` (migration 3)、`Reset` を 1 transaction に | 要 | — (rollback の runbook = platform#333) | V31、V5 (store の部分) |
| A3a-2 (#616) | Grader の `SubmitAnswer` (加算 → 比較 → solve、自己修復、`Newly`)、比較の入口のソース検査 | 要 | — | V5、V1 (store・log)、V30 |
| A3a (分割前の記述) | store の migration、Grader の `SubmitAnswer` (D5・D7)、admin reset | 要 | — | V5、V1 (store・log) |
| A3b-1 (#620) | route (`submitAnswer`)、認可 `self`、og の pin 16、専用の rate-limit の bucket、spec の operation。正解済みで未 solve の設問への再提出を受け付ける (D5 の 5) | 要 | — | V9 (route・og・forward・I15・`self`)、V1 (応答) |
| A3b-2 (#621) | `MissionDetail.questions` (H2 の読み方)、spec の type enum (3 つ) と kind、metrics の outcome | 要 | — | V9 (`MissionDetail` の 22 key)、V23 (spec まで)、V1 (metrics の label)、V41 |
| A3b-3 (#622) | `LoadScored` の調査型の拒否を外す。前提は A1d #611・A1e #612・A1f #618・A2b #613 / #614・A3a #615 / #616・A5a-1 #619 で、すべて満たした。表が無いときの提出は 500 で、何も消費しない (A4a-2 まで) | 要 | — | V21 (反転)、V37 |
| A3b-4 (#627) | identity_denials の `gate="self"` (D18 の ADR-0038。D2 の表は書き換えず、header に限定 supersede の注記)。`self` の系列の事前生成、`selfOnly` と `selfOrAdmin` の共通化 (#620 LOW。`selfOrAdmin` は `no_identity` のときに admin の集合を引かない)、`internal/scoreboard/api/answer.go` のコメントの訂正、契約表の「identity 拒否の観測」行の文言の修正 (app 単独) | 要 | — (platform はこの metric の gate を読まない) | V38 |
| A3b-5 (#625) | scoring の follow-up: コースの配置の規則 (調査型より後ろに evade を置かない。D18 の ADR-0003)。CI の test に加え、`catalog.LoadScored` が起動時に `ErrEvadeAfterInvestigate` で拒否する。scenario の無い順序 (課題 id の順) にも当たる。調査型が current の状態での overflow の taint の test と、sweeper の test を handler の Grader 経由にした (#622 LOW)。`docs/challenge-image-fixtures-allowlist.md` の規則 7 の `type:` を 4 値にした (#621 LOW) | 要 | — | V39、V45 |
| A4-0 (#624) | 契約表に文面 1「答え表」(D16)。ADR-0026 の pointer は、A3b-5 (#625) が規則 7 を 4 値に直したので落とした。行の literal (`scoreboard-answers`・`answers.tsv`・`/etc/ctf-answers`) と chart の既定値の一致を `internal/contracttable` の test で固定する | 要 (contracttable) | P1b-1a (platform#334、open) と対。A4-0 を先に merge した | V33 (検証: CI) |
| A4a-1 (#628) | 練習版の読み込み: `Load(cat, challengesDir, answersFile, eventMode)` の中の unexported の `loadPractice` が、image の**全課題**の `challenges/<id>/edition/practice/answers.tsv` を読み、PracticeSet にする (正規化済みの値だけを Add する。行の cid はその課題自身でなければならない)。練習版を読むのは、表がある起動だけ。T6 が起動時に効く。束と template の file の集合は読まない (A4c)。「全調査型に練習版がある」の CI は A4a-2 に送った | 要 | — | V34、V3 (T6) |
| A4a-2 (#630) | 練習のモードの採点 (D8 (iv)): `edition.Load` の中で、スコープの練習版の表から Judge を作る。練習版の欠けで起動を拒否する。(5) を 0 の run id で出す。契約表の「起動ログ」行の (5) に、練習版の表の run id が 32 桁の 0 であることを足す (app。platform の FAIL は P1b-2)。#628 の LOW 3 件もここで閉じる: (a) 練習版の表をスコープについて `Check` (EventMode false) に通し、全設問の網羅を T4 で確かめる。(b) 「全調査型に練習版がある」を実 tree の CI で固定する。(c) は A4a-3 に分けた (#630 の review。呼び出し 30 か所超の形が変わるため) | 要 | 行の (5) の追記 ↔ P1b-2 | V36、V47 (検証: CI) |
| A4a-3 (#631) | `catalog.LoadScored` が full catalog と challenges の dir も返す形にし、`edition.Load` の入力を `LoadScored` の結果 1 つにする (`challengesDir` の引数をなくす。`cat` と別の tree を渡せないことをソース検査で固定)。A4b の前 | 要 | — | V47 (3 つ目) (検証: CI) |
| A4b-1 (#633) | 束の reader と B2 (木 = `<root>/<seat>/<cid>/<file>`、2 MiB は席ごと、`MaxBundleFiles` / `MaxBundleBytes` / `MaxSeatBytes`)。束の digest の定義 (D9) と共有の case 表 (M1 の形、Go 側)。名前の文法 `NamePattern` と V52 の parity | 要 | — | V16 (Go)、V8 (validator の大きさ)、V52 (検証: CI) |
| A4b-2 (#634) | `CheckBundles`: B1・B3・B5・B6・B9 と digests の file (`WriteDigests` / `ParseDigests` / `CheckDigestSet`)。決めたことは次のとおり。file が 0 個の束は B1 の違反。list の外の席の dir は空でも B1 の違反。B5 の Hints / Free は引数。B3 は「flag を持つ課題がスコープにあるのに値が空」を違反にする (`FlagChallenges`)。違反があれば digest の行を 1 つも返さない。message に答えの値も束の内容も出さず、file 名は 48 文字で切る。`catalog.MentionsFlag` と board の flag の判定の関係を両方の doc に 1 行ずつ (#608)。入口の型 (M2) と B9 の fold (M4) は後続 (A4e / A4c-2) | 要 | — | V3 (B1・B3・B5・B6・B9)、V48 (Go)、V60 (検証: CI) |
| A4c-1 | hintleak: `assembleScope` と prompt の数の検査を非 test の `internal/hintleak/scope` に移し、`content_test.go` がそれを呼ぶ形にする。n-gram の正規化の関数を 1 つ export する。A4e の前提 | 要 (hintleak) | — | V56、V24 / V35 が緑のまま (検証: CI) |
| A4c-2 | B4: 練習版との digest・答えの出現・shingle の (1) 出力同士と (2) テンプレート同士、θ = 0.5 の定数と未設定の拒否、重なり率の stderr。練習版の束と template の file の集合は、`loadPractice` が読んで `CheckedTable` が運ぶ (M2。別の入口は作らない)。B9 を `answerformat.Fold` の形に置き換える (M4) | 要 | — | V3 (B4)、V19、V55 (検証: CI) |
| A4d-1a | `edition.yaml` の parser と E1 (D12 の schema、strict、anchor と alias の拒否、上限、message に語彙を出さない)。wip `3e888f0` を追補 8 に合わせる | 要 | — | V61 (検証: CI) |
| A4d-1b | E2 (設問との対応・`decoys` ≥ K・timestamp の窓の幅・`fixed` の集合) と B8 (a) (語彙の位置ごとの積・params からの空間) | 要 | — | V6 (edition)、V21 (path / name)、V62 (検証: CI) |
| A4d-2 | renderer: 印 `{{ctf:…}}` (宣言した slot と暗黙の decoy の全部が 1 回以上現れる、未宣言の印と render の後に残る印は fail)、長さ接頭辞の HMAC の DRBG、hexid は設問の `params.length` (filler は `length`)、timestamp は `time.base` + 窓から一様、`fixed` を全席の行として `answers.tsv` に書く、B7 の出力の半分 (差分の位置 ≥ K)、B8 (b)、練習版の golden の仕組み | 要 | — | V4、V6 (b)、V18、V11 (仕組み) (検証: CI) |
| A4e | `scoreboard edition check|render` の subcommand: 引数、exit 0/1/2、stderr に値を出さない、`--digests-out` (run id と digest)、表と digests の run id の一致、HTTP の path から render に届かないソース検査。答え表は M2 の入口 (`LoadEventTable` → `CheckedTable`) からだけ得る。B5 の入力は `internal/hintleak/scope` で組む。reader を O_NOFOLLOW + 開いた descriptor の `Stat` の照合にする (M2)。文面 2 の CLI の部分。digests の header と列の形を契約表と `internal/contracttable` で照らし合わせる。前提は A4b-2・A4c-1・A4d-2 | 要 | CLI ↔ P1b-2 | V3 (B の CLI)、V15 (check) (検証: Go は CI、`docker run` の経路は手元不可 = P1b-2 の stub の selftest だけ) |
| A4 (分割前の記述) | `internal/edition` の束の検査 (B1〜B9)・renderer・`edition check|render` の subcommand・testdata | 要 | CLI ↔ P1b | V3 (B)、V4、V6 (b)、V11、V15 (check)、V16 (Go)、V18、V19 |
| A5a-1 (#619) | gen-values の `--check` に `mountDir` の検査を入れた。規則は D1 の (a)(a2)(b)(c) と fail-closed の規則で、ADR の元の文面より厳しい。ADR-0055 C4 (ii) の実装を兼ねる。`reservedMountRoots` と SEED_ROOT / SNAPSHOT_ROOT の parity、`INVESTIGATE_TYPE` の parity の test | 要 | — | V28、V29、V42 |
| A5a-2 (#629) | gen-values: plant の導出を type から行う (evade の plant.sh ∪ 調査型。調査型が plant.sh を持つのは拒否)。調査型の `plant.mounts` の entry (`evidence: true`。D11 の形では `challenge: <cid>` も)。copy の形の定義 `render_evidence_copy` (D11 の J5 の形。列挙は A5b の chart)。2-7(a) に `/opt/ctf/evidence-src/<cid>/<素の file 名>` | 要 | — | V8 (2-7(a))、内部 fixture (正の tree と違反 43 通り)、生成物は byte で不変 (検証: CI) |
| A5b (#632。追補 6 の L2) | chart: Secret は render せず、`ctf-evidence-<cid>` を名前で参照して plant にだけ mount する (L2)。values は `.Values.evidence.challenges.<cid>.names`。helm の `fail` は D11 の K2 の一覧 (名前の文法は B2、1〜64 個、重複、`plant.mounts` の `challenge` と values の key の集合の一致、seedScript の形)。`ctf-evidence-secret.yaml` と、内容の大きさの検査は #632 から外す (上限は A5c と validator)。plant の copy 行を values の key から byte 順に render する。`reservedMountRoots` に `/opt/ctf/evidence-src` を足す (gen-values との parity)。plant に `/opt/ctf/evidence-src` を readOnly で、challenge に seed の subPath を mount。`scripts/check-flag-isolation.sh` に「`ctf-evidence` は plant にだけ mount される」の静的検査。A5a-2 の後 | 要 (pod.yaml・check-flag-isolation) | — | V2 (ctf-user の sentinel)、V8 (helm の `fail`)、V43、V44 (検証: chart-lint / flag-guard の CI) |
| A5c | `deploy-user.sh --evidence-dir --evidence-digests`: fail-closed (D11)、digest の shell 側 (A4b の case 表を読む)。Secret `ctf-evidence-<cid>` を helm の前に `kubectl create secret generic --from-file=<name>=<path>` で作る (毎回作り直し、スコープに無いものは消す、client-side の apply は使わない)。大きさの上限 (課題ごとに 512 KiB、合計 2 MiB) を cluster に触れる前に数える。`names` を chart に渡す。文面 2 の痕跡束の部分。A4b・A5b の後 | 要 | 行 ↔ P1b-3 | V16 (shell)、V17 (検証: flag-guard の CI。helm / kubectl は stub) |
| A5d | `assert-flag-isolation.sh` の 3-x (`mountDir` の中の symlink が 0 で通常 file だけ、seat の ns の Secret 名 = {ctf-flags} ∪ {ctf-evidence-<cid> | cid はスコープの調査型})。V53 (catalog の mountDir の集合と commit 済みの生成物の `evidence: true` の path の集合の一致、Go の test)。`check-flag-isolation.sh` の実 scope (values-all・scenario) に調査型が入ったときの `names` の出所 = その課題の公開の練習版の束 (`challenges/<cid>/edition/practice/` の束の file 名) と、scope ごとの期待する `ctf-evidence-*` の集合の導出。challenge から `/opt/ctf/evidence-src` が見えないことの実行時の assert (`assert-flag-isolation.sh`、3-4 と同じ作法) は A5c。A5b の後 | 要 | — | V8 (3-x)、V2 (Secret 名) (検証: stub の test は CI、実 cluster は実機でのみ) |
| A5 (分割前の記述) | ctf-user の `ctf-evidence`、plant の一般化、gen-values の 2-7、3-x、deploy-user の `--evidence-*`、helm の `fail`、契約表の新しい行。gen-values の `--check` に `mountDir` の検査 (sensitive_dir_prefixes の外であること、全 plant-target の書き込み先と file が互いに素であること (ADR-0055 C4 (ii)。先に着地した側の検査を 1 つの実装として使う)) を入れる。`reservedMountRoots` と gen-values の SEED_ROOT / SNAPSHOT_ROOT の parity の test | 要 | 行 ↔ P1b | V2 (ctf-user)、V8、V16 (shell)、V17、V28、V29 |
| A6 (#626) | portal の回答欄 (application-engineer)。未到達 (locked) の課題でも回答できる (ADR-0027 の free browsing。既存の flag 欄と同じ。CoS の決定、test で固定)。前提は A3b-1〜3 (#620〜#622) で、満たした。範囲は次のとおり。prompt は `esc()` を通す。`status` (と `correct` / `solved` / `remaining`) だけで分岐し、文言は portal が持つ。正解済みで未 solve の設問には再提出の口を残す (D5 の 5)。400 (形式が違う、回数は減らない)・429・500 をそれぞれ表示する。500 の表示は「採点できなかった。回数は消費済みのことがある」とし、再描画 (journey) で実際の残りを見せる (D5 の 3〜5 に合わせる。文言は portal の実装が正)。journey の 500 (H2) では、前の表示を残す。local で通しで確かめるには A4a-2 が要る | — | — | V40 (検証: 生成型と template の test、goja = ADR-0035) |
| A7 | **前提**: merge 済みは A1d #611・A1e #612・A1f #618・A3b-1〜5 #620〜#622・#627・#625・A4a-1 #628・A4a-2 #630・A4a-3 #631・A5a-1 #619・A5a-2 #629・A5b #632・A4b-1 #633・A6 #626。残りは A4b-2 (#634)・A4c-1・A4c-2・A4d-1・A4d-2・A4e・A5c・A5d (V53 が緑)・V51 の実測 (設問に `technique` を使うなら A1c も)。A5c の merge までは、調査型の課題を main に置かず、イベントの values に `evidence.challenges` を渡さない (Secret を作る者がいないので Pod が起動しない)。platform が `evidence` を渡す P1b-3 は A5c の後。A7 では V47 の実 tree の検査を非空の要求に反転させる。課題を置くコースは V39 を満たす。**課題 id は、全 evade の課題の id より大きくする**。scenario の無い順序 (課題 id の順) でも `LoadScored` が拒否するため (今の evade は 03・05・10)。調査型の課題を main に置く前に、platform の P1b-2 (イベントで (5) の run id が全部 0 なら FAIL) と P1b-1b (render gate) を merge する (イベントで `FLAGS_FILE` が空のまま起動すると、公開の練習版の答えで採点が始まる誤設定を、platform の側で止めるため)。新しい課題の練習版 (content-engineer) | 要 (fixtures と同じ扱い) | — | V11 (golden)、V3 を練習版で緑、V22 (実課題の `edition/**` が image に無い)、V27 を反転 |
| P1a (platform#332) | `verify.sh` の `[flags]`: (4) があれば FAIL。(5) の最新の 1 行の `run_id` が 32 桁の小文字 hex でなければ FAIL、正しければ報告する。(5) が無いときは、Deployment に `ANSWERS_FILE` が無ければ「表が要らない起動」、あれば「未検証」、env を読めなければ「未検証」とし、失敗にはしない。digests の run id との照合は P1b-2 | 要 | app#613 と対 (P1a が先) | V32 |
| P1b-1a | helmfile: イベントの設定で明示したときだけ `answersSecret` を有効にする (Secret 名と key は契約表の「答え表」の行)。ここでは render gate を持たない。調査型があるのに表が無い場合の fail-closed は、scoreboard の起動時の拒否 (D8 (i)) と P1a の (4) の FAIL が担う | 要 | A4-0 と同時 | V12 (有効化の部分) |
| P1b-1b | helmfile: local 以外で `requirements.answers` が空でないのに `answersSecret` が無効なら、render を失敗させる (D8)。前提: ADR-0055 S3 の生成物の `requirements:` が app にあること (main にはまだ無い)。S3 の後に入れる | 要 | ADR-0055 S3 の app PR の後 | V12 (render gate) |
| P1b-2 (platform#335 を含む) | 課金の前に `edition render` → `edition check` を行う (pin した scoreboard image、docker)。出力 (表・束・digests) の置き場 (sops)。表と digests の run id の照合 (digests は `seat<TAB>cid<TAB>digest`)。verify の (5) と digests の照合、run id が全部 0 なら FAIL。platform#335 の項目: scoreboard の答え表の Secret を Deployment より先に作る順序と preflight、namespace の固定、Secret の name / key を app の契約表の行 (`answersSecret` の既定値) と照合すること、pin した app の chart が #614 以降であることの gate | 要 | A4e・A4a-2 と対 | V12 (gate)、V15 (platform) (検証: docker の経路は手元不可、stub の selftest) |
| P1b-3 | 払い出しが seat ごとに `--evidence-dir --evidence-digests` を渡す。束の出所を明示する (D8) | 要 | A5c と対 | V12 (払い出し)、V17 (platform 側) |
| P2 (platform#333、open) | rollback の runbook を DB の版 3 に対応させ、PVC の写しでリハーサルする | — | — | 実機でのみ確認可 (リハーサルの記録) |
| P1a / P1b (分割前の記述) | platform: helmfile の render gate、束の出所の明示、課金前の render → check、digests、seat の Secret の作成、`verify.sh` の (4)、イベント版の置き場 (sops) | 要 | 上の app PR と対 | V12 |
| D1 | detect の hold-out (app + platform)。#341 の後 | 要 | detect-grader の行 | V7 |

- 順序 (2026-11-16 時点)
  - merge 済み: A0 #605 → A1a #606 → A1b #607 → A2a #610 → A1d #611 → A1e #612 → A2b-go #613 (P1a = platform#332 が先) → A2b-chart #614 → A3a-1 #615 → A3a-2 #616 → 追補 3 #617 → A1f #618 → A5a-1 #619 → A3b-1 #620 → A3b-2 #621 → A3b-3 #622 → 追補 4 → A4-0 #624 → A3b-5 #625 → A6 #626 → A3b-4 #627 → A4a-1 #628 → 追補 5 → A5a-2 #629 → A4a-2 #630 → A4a-3 #631 → 追補 6 と A5b #632 → A4b-1 #633。open は A4b-2 #634 と platform の P1b-1a #334。
  - 残りは 3 列で進める (並列は WIP の枠と stacked の深さ 2 の範囲で)。
    - (列 1) 完了 (A6 #626・A3b-4 #627・A3b-5 #625)。
    - (列 2) A4b-2 (#634) → A4c-1 → A4c-2。A4d-1 → A4d-2。A4e (+ P1b-2) は A4b-2・A4c-1・A4d-2 の後。
    - (列 3) A5c (A4b-1 の後、+ P1b-3。V58 を含む) → A5d → V51 の実測 (P1b-3 の rehearsal)。A5b は #632 で済んだ。
  - 最後に A7 → platform の `APP_PIN` の bump。A1c は `technique` を使うときだけ、A7 の前に入れる。
- (分割前の順序): A1a → A1b → A1d / A1e (触る file が別なので並行してよい) → A2a → A2b (+ P1a) → A3a → A4 (+ P1b) → A5 (+ P1b) → A3b → A6 → A7 → platform の `APP_PIN` の bump。A1c は `technique` を使うときだけ、A7 の前に入れる。
- A3b を A5 の後に置く理由: `mountDir` の sensitive dir と互いに素の検査は gen-values にあり、Go の catalog には写さない (写すと 2 つ目の一覧になる、`internal/catalog/investigate.go:115-119`)。拒否を外す前に、その検査が main に要る。前提になるのは A5 のうち A5a-1 だけ (G16)。
- platform のゲートを先に適用する (ADR-0033 D9 (g))。stacked の深さは 2 以内。
- #608 の 8 件の割り当て: MED 1 → A1d / A3b、MED 2 → A1e、MED 3 → A3b の前提、LOW 4 件 → A1d、LOW (`reservedMountRoots`) → A5。

## Consequences
- **諦めたもの**:
  - 束の内容の検査を scoreboard の起動時に行うこと (束を持たないため。validator と digest で代える)。
  - 4 択の設問 (D3 (a))。
  - 席ごとに変えられない format (`technique` / `choice-set` / `sequence`) の答えは Board で共有できる (残余。検出はしない)。D1 の「席ごとの設問を 1 つ以上」によって、固定の答えを共有しただけでは solve できない。
  - 調査型の課題は、A3b-3 (#622) から、課題さえあれば提出から採点まで動く。ただし練習のモードでは、A4a-2 まで Judge が無く、提出は 500 になる (何も消費しない)。`technique` は A1c まで使えない。
  - コースの中で、調査型の課題より後ろに evade を置けない (ADR-0003 W2 が調査型に及ぶため。V39)。
  - journey の polling は、表示中の調査型について SQL を 1 回読み、読めなければ 500 になる (H2、Signpost 7)。
  - 公開していない過去のイベント版の再利用は検出しない。
  - 正解なのに設問の correct の書き込みが失敗すると、回数を 1 つ失う (fail-closed の代償)。correct を記録した後の `MarkSolved` の失敗は、次の提出で自己修復する (D5 の 5)。
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
- **runbook (COO)**: DB の版 3 からの rollback は、`user_version = 2` と `DELETE FROM answer_attempts` を同時に行う (platform#333。stand-up の前に PVC の写しでリハーサルする)。render → check → 払い出しの順。予備の席。予備を超えたときの再起動 (I1 の Recreate で短い全断)。tag を上げる前に表を検査する (ADR-0033 と同じ注意)。
- **統治文書 (CEO)**: `ORGANIZATION.md:198` の「端末に載る唯一の課題ファイル」に痕跡束を足す。CLAUDE.md の R1 一覧に行を足す。
- **follow-up (LOW)**: `x-ctf-authz: self` を他の書き込み route へ広げるかの検討 (今は変えない)。

## Signposts
1. 監査 log の `answer matched another seat` が、1 イベントで seat の 5% を超える。または誤答の keyed hash が席の間で一致する率が高い → 席ごとに変えられない format の扱いと K を見直す。
2. 束が課題あたり 512 KiB を超える要求が出る、全課題の合計が 2 MiB (plant-seed の `sizeLimit` の半分) に近づく、または seat × 設問の表が 1 MiB の Secret に近づく → Secret の分割か PVC を宣言つきで設計する (`sizeLimit` も合わせて見直す)。
8. chart の values から release の記録に載るものが file 名の一覧を超える要求が出る (内容を values で渡したい、など)、または Helm の storage driver を platform が変える → 追補 6 の L1 / L3 を再評価する。そのときは、release の記録の最悪の大きさを実測して上限を決める。
3. stand-up の端末で docker が使えない (E1 の前提が崩れる) → E2 (`APP_PIN` の clone からの `go build`) に移る。
4. 設問の 20% 超で回数を使い切る参加者が出る (CPO の指標)、または候補の下限 R で content が書けない → attempts・R・K を CISO と CPO が再設定する。
5. (補足) platform が evade の無いコースで flags を任意にする → 「イベントのモード」の指標を明示の `EVENT_ID` に替える。
6. 初回のイベント版で validator が stderr に出した重なり率 (B4 の (1)(2)) が、正当なイベント版で θ = 0.5 に近いか超える、または流用したテンプレートが 0.5 未満で通る → CISO が θ を設定し直す (変えるのは定数と、その pin の test)。
9. 席ごとの format を足す、または `Normalize` が受理する綴りを広げる → `answerformat.Fold` に同じ PR で族を足す (V55 の性質の test が、足し忘れを赤にする)。B9 の偽陽性による再 render が 1 イベントで 3 回を超える → fold の粒度を見直す。
10. validator の入力の木を運用者以外 (CI の runner や共有の端末) が書ける形で使う → M2 の「運用者の所有」の前提が崩れる。読む前に木の写しを取ってから検査するよう、入口を設計し直す。
11. 作者が decoy を answer と違う形で置きたい要求が出る (別の語彙の囮・別の時間帯の囮など) → `decoys: <n>` の暗黙の生成を、宣言の decoy (同一性を E2 で検査する形) に広げる。schema は `version: 2` にする。
12. timestamp の窓では書けない時系列 (相対的な順序の制約、席ごとに伸び縮みする間隔) が content に要る → `time` に順序の制約を足す。窓の幅 = `windowSeconds` という空間の主張は保つ。
7. 次のどれかが観測された → `answer_attempts` の in-memory の写し (write-through。`Reset` と自己修復で同時に更新する) に移る。
   - 開催中に、journey の 500 のうち「could not read the mission's questions」の log が 1 件でも出る。
   - `GET /journey` の p99 が 100 ms を超える。
   - 調査型の課題を 2 本以上同時に表示する UI が要る (読みが mission の数に比例する)。

## Verification (app は `make test` / `flag-guard` / `chart-lint` = required。exit status で判定。故意の違反で赤になる case を常設する)
- **V1 (security 要件 1)**: sentinel の答え表で、誤答・上限超過・already-correct・store の失敗・起動拒否の各経路を通す。応答の body・log・metrics・error・store の行に sentinel が 0 件 (Go の test)。
- **V2 (要件 2)**: sentinel を入れて `helm template` した結果、ctf-user には 0 件、scoreboard では scoreboard の container の mount にだけ現れる (CI)。deploy の 3-x で、seat の ns の Secret 名が {ctf-flags, ctf-evidence} と一致する。
- **V3 (要件 3)**: T1〜T8 と B1〜B9 のそれぞれについて、1 ケースに 1 欠陥の testdata で拒否する。T は scoreboard の起動の test と validator の両方で、B は validator で確かめる。stderr に値が 0 件。
- **V4 (要件 4)**: renderer の test。2 席の出力の差分の位置のうち答えでないものが、答えごとに K 以上。B7 は、K − 1 の fixture で赤になる。
- **V5 (要件 5)**: 加算の commit の前に比較が呼ばれない (store の stub で失敗を注入し、比較の呼び出しが 0 回)。上限 − 1 の状態で N 並行の要求を出し、比較は高々 1 回 (`go test -race`)。solve の後は比較しない。
- **V6 (要件 6)**: 空間 < 100 × attempts の catalog と edition を拒否する。4 択の `choice-set` の case で赤。D3 (b) の候補の下限を割る束を拒否する。
  - edition の側 (A4d-1b): 語彙の位置ごとの積が 100 × attempts − 1 の path の slot、199 語の name の slot (attempts 2) で赤。語が 1 つの位置を足しても空間が変わらないことも確かめる。
- **V7 (要件 7、D1)**: hold-out の応答は status と solved だけで、変種の fire の数の key が無い。予算は store にあり、(user, cid) の累計で 20。時間が経っても戻らず、21 回目は回さない。公開の capture への応答は変更前と同じ (golden)。
- **V8 (要件 8)**: seed の mount に symlink を置いた fixture で 3-x が赤。512 KiB + 1 byte と 65 個の file で、helm の `fail` と validator の両方が赤。2-7(a) は `/opt/ctf/evidence-src/` 以外の copy-source、`cp -a`、glob で赤。
- **V9**: route は 31 → 32、og の pin は 16、forward は 2 のまま、I15 の双方向の検査が緑。`self` は admin を通さない (authz の test)。`MissionDetail` の key の集合は 22。
- **V10**: `investigate` の strict decode (未知の key、flag / rule の key が空でない、format の外、params の外、attempts の範囲外、`mountDir` が sensitive の dir・missions・seed root にある) で、どれも load に失敗する。
- **V11**: 練習版の golden (render の出力 == commit した練習版)。練習版が A4 の束の検査 (B2・B3・B5) に通る。
- **V12 (platform)**: env が local 以外で `requirements.answers` が空でなく、`answersSecret` が無ければ render で失敗する。check の stub が 1 を返すと何も apply しない。digest が合わなければ `deploy-user.sh` が helm / kubectl を 1 回も呼ばない。platform には required check が無いので、merge の時に人が Checks を確かめる。
- **V13**: `bootlog_contract_test.go` が、`msg="edition check failed"` と ERROR、および (5) の `msg="edition loaded"` と INFO と属性 `run_id` を literal で固定する。
- **V14 (実機でのみ確認可)**: 参照解答の調査の手順をすべて実行しても、他の課題の solve と taint が 0 件 (qa の E2E、brief §8 の 5)。機械の確認は無し。
- **V15 (security 1(a))**: 次の場合に `check` が 1 を返す。表の run id が無い、形が違う、全部 `0` である。scoreboard の起動の test で、イベントのモードに全部 `0` の run id を渡すと拒否する。platform: preflight の stub で表と digests の run id を違えると、何も apply しない (platform には required check が無いので、merge の時に人が確かめる)。
- **V16 (security 1(b))**: Go と `deploy-user.sh` が、共有の case 表 `internal/edition/testdata/bundle-digest/` の全行で同じ digest を返す。名前の順・`\0`・改行のそれぞれを 1 byte 変えた case で、両方が別の digest になる。
- **V17 (security 1(c)、`flag-guard` の上)**: スコープに調査型がある deploy-user で、次の 4 つが非ゼロで終了し、helm / kubectl を 1 回も呼ばない (stub で記録)。(a) `--flags-file` だけがある。(b) `--evidence-dir` だけがある。(c) `--evidence-digests` だけがある。(d) digest が不一致。3 つとも無い場合は、練習版で通る。
- **V18**: K の式を pin する (attempts が 1 / 2 / 5 のとき K が 4 / 4 / 10)。`decoys` が K − 1 の edition.yaml を E2 が拒否する。decoy の slot を宣言で書こうとする (`role: decoy` や、decoy に vocab を書く) と E1 が拒否する (同一性は構成で成り立つ)。E12 の長さ接頭辞の test。
- **V19**: θ を未設定 (0 / NaN / 1.5) にした build で、B4 は skip せずに拒否する。練習版のテンプレートの filler だけを変えたイベント版で、(1) は通り、(2) が赤。stderr には重なり率の数値と組の id だけが出て、本文の bytes は 0 件。
- **V20 (A1b)**: 席ごとに変えられない format だけの課題では catalog の load が失敗する。席ごとの設問が 1 つあれば通る。
- **V21 (A1 の事実)**
  - `technique` の設問は、A1c までは load が失敗する。
  - `path` / `name` の空間は catalog では計算しない (保留を test で固定する)。語彙の小さい edition は、A4d-1b の B8 (a) が拒否する (V6 の edition の側)。
  - A1b (#607) から A3b-3 (#622) の直前までは、調査型を含む scope を `LoadScored` が拒否した。#622 でこの test を反転させ、調査型を含む scope で起動できることを確かめる (V37)。
- **V22 (A1d、型と image)**
  - `scripts/test-check-image-hygiene.sh` に `type: investigate` の課題を 1 つ持つ tree の case を足す。builder と V2 の両方が受理し、`answers.yaml` の key にその id が出ないこと (key = evade の id のまま)。
  - `type: investigat`・`type: "investigate"`・`type: investigate # c` では、builder と V2 の両方が赤になること。
  - その tree の `challenges/<id>/edition/**` の file が V1 の参照集合 (fixtures 以外の tracked file) に入り、image に無いこと。
- **V23 (A1d、型の parity)**
  - Go の test が、catalog の型の集合 (4 つ) と、`images/challenge/Dockerfile` と `scripts/check-image-hygiene.sh` の case の行から抜いた集合が一致することを確かめる。抜いた集合が空なら fail。
  - どれか 1 か所から `investigate` を消したコピーで赤になること。
  - A3b で、spec の type enum (3 つ) と kind の行も同じ集合に加える。
- **V24 (A1e)**: hint にだけある 10 rune の n-gram を、prompt に置いた scope と置かない scope で比べる (fixture には両方とも置く)。prompt に置けば通り、置かなければ違反になること。調査型の scope では、prompt の item の数が設問の数と一致すること (0 件なら fail)。合成した in-memory の scope を `internal/hintleak` の test の関数 `assembleScope` に通して確かめる。`isQuestionPromptSource` の境界は table test で固定する (A4c、#618 LOW)。prompt の数は、Free の実体のうち Source が `<cid> questions[<qid>].prompt` の形の item を数える。組み立て側が数えた値は使わない (A1f、#608)。
- **V25 (A1d、LOW)**: 調査型の課題で、`falco-rule.yaml` と `journey.yaml` の top-level に未知の key があれば load が失敗する。journey.yaml が無い場合と、journey の dir そのものが無い場合も失敗する (負の test。`LoadJourneys` が早期 return する経路を含む)。
- **V26 (A1d、LOW)**: `TestCheckSpaceN_RefusesOutOfRangeInputs` の path の枝は、`ErrSpaceFromVocabulary` 以外の error を要求する。`CheckSpace` の先頭の attempts の検査を消したコピーで赤になること。
- **V27 (A1d、LOW)**: 回帰 test は実課題の数を pin せず、「空でない」と「調査型が無い」だけを確かめる。A7 でこれを反転させ、「A7 の課題を含む」にする。
- **V28 (A5、LOW)**: test が `challenges/gen-values.sh` の SEED_ROOT / SNAPSHOT_ROOT の代入を読み、`reservedMountRoots` に含まれることを確かめる。片方だけを変えたコピーで赤になること。
- **V29 (A5a-1、A3b の前提)**: gen-values の `--check` が、次の 2 つの負の fixture で非ゼロになること。`mountDir` が sensitive_dir_prefixes の内側にある。`mountDir` の file が他の plant-target の書き込み先と重なる。
- **V30 (A3a-2、自己修復)**: 正解を記録した後の `MarkSolved` を stub で 1 回失敗させると 500 になる。次の同じ設問への提出は `already-correct` で、比較の入口 (`Judge.Match`) の呼び出しが 0 回、solve が完了し、`Newly` が true。その次の提出では `Newly` が false。未正解の設問が残っていれば、`already-correct` では solve しない。
- **V31 (A3a-1)**: version 2 の DB から migration 3 が通る。version 3 の DB は前の版の image で起動を拒否する (既存の downgrade guard)。`Reset` の途中で失敗を注入すると、どの table も変わらない (1 transaction)。rollback の手順のリハーサルは実機でのみ確認可 (platform#333)。
- **V32 (P1a、platform#332)**: `scripts/test-flags-gates.sh` の case。(4) で FAIL、(5) の run id の形の不正 7 通りで FAIL、record が無い場合 × `ANSWERS_FILE` の有無と読み取りの失敗で「表が要らない」/「未検証」。platform には required check が無いので、merge の時に人が確かめる。
- **V33 (A4-0)**: `internal/contracttable` の test が、契約表の「答え表」の行の code span (`scoreboard-answers`・`answers.tsv`・`/etc/ctf-answers`) と、`charts/scoreboard/values.yaml` と `templates/deployment.yaml` の既定値が一致することを確かめる。どちらか片方だけを変えたコピーで赤になること。
- **V34 (A4a)**: 練習版の読み込みは、スコープではなく image の全課題を読む。正規化されていない練習版の答え (normalize(v) ≠ v) は load で失敗する。練習版が無ければ空の集合になる。`internal/edition/load.go` に literal の `PracticeSet{}` が残らないこと (ソースの検査)。testdata の練習版の値と同じ値を持つイベント版の表を、起動時に T6 が拒否する。
- **V35 (A1f #618)**: Free に prompt の item を入れず、組み立て側の数だけを設問の数に合わせたコピーで、V24 の数の検査が赤になること。
- **V36 (A4a-2)**: イベントのモードでなく `ANSWERS_FILE` も無い状態で、testdata の調査型 (練習版あり) を使う。正しい答えで solve し、誤った答えで incorrect になり回数が減る。#622 の「500 で何も消費しない」の test は、この PR で反転させる。スコープの調査型の練習版を 1 つ消したコピーでは、起動を拒否し (4) が出る。受理したときは (5) が run id 32 桁の 0 で出る。イベントのモードで練習版があり `ANSWERS_FILE` が無いときは `ErrTableMissing` で、練習版から Judge を作らない (ソースの検査: 練習版から Judge を作る呼び出しは、イベントのモードでない分岐の中だけ)。`Parse` / `NewJudge` を呼ぶ file は load.go だけのまま。
- **V37 (A3b-3 #622)**: 調査型を含む scope で `LoadScored` と起動が通る。表が無いときの提出は 500 で、`answer_attempts` の行が増えない。
- **V38 (A3b-4)**: `self` の route で、header が無い → `gate="self",reason="no_identity"` が +1。非正規形 → `non_canonical` が +1。`{user}` と違う正規形・`ADMIN_EMAILS` → `mismatch` が +1。`gate="self_or_admin"` の系列は、`self` の route では増えない。起動の直後に `{gate="self",reason="no_identity"}` が 0 で存在する (契約の保証 (2)。`internal/contractmetrics` の事前生成の検査に載る)。`self` を `self_or_admin` に戻したコピーで赤になること。
- **V39 (A3b-5)**: 全 scenario (生成物を含む) について、調査型の課題より後ろに evade の課題があれば、test が赤になる。列挙が 0 件なら fail。違反する合成の scenario (testdata) で赤になること。調査型が current の状態で、forbidden rule の overflow の taint が後続の evade に付かないこと (W2 の現状) を test で固定し、規則が塞ぐ理由を残す。
- **V40 (A6 #626)**: template の test (goja)。prompt にある HTML の特殊文字が escape される。`status` の 4 値と 400 / 429 / 500 のそれぞれで表示が分かれる。500 の文言は「回数は消費済みのことがある」を含み、次の journey の再描画で `remaining` が実際の値になる。`correct && !solved` の設問の欄は有効のまま。応答の `remaining` をそのまま表示する。
- **V41 (A3b-2 #621)**: store の読みに失敗を注入すると、journey は 500 になる。body は `{"error": …}` の固定文で、部分的な `MissionDetail` を返さない。log には cid と remote_addr を出し、値は出さない。
- **V42 (A5a-1 #619)**: `verify_claims_negative_tests` の fixture で、(a) sensitive な dir の祖先、(a2) sensitive な file の dirname と等しい場合とその祖先、(b) 他の課題の mount dir と等しい場合 / 入れ子、(c) 同じ file への 2 つの書き込み、認識できない書き込みの形、`INVESTIGATE_TYPE` の不一致のそれぞれで、`--check` が非ゼロになる。
- **V43 (A5b)**: 調査型が 2 つある fixture の values で `helm template` すると、次のとおりになる。
  - `ctf-evidence-<cid>` が 2 つでき、それぞれ plant にだけ `/opt/ctf/evidence-src/<cid>` で mount される。
  - copy 行は values の key の byte 順で、`render_evidence_copy` の形と一致する (`check-flag-isolation.sh` が `helm template` の出力に掛ける)。
  - `plant.mounts` の `challenge` と values の key の集合を 1 つずらすと `fail`。
  - 課題ごとの 65 個の名前・B2 の文法の外の名前・重複した名前で、chart の `fail` が効く。512 KiB + 1 byte と合計 2 MiB + 1 byte は、deploy-user (V49) と validator (B2) が拒否する (chart は内容を見ない)。
  - copy 行を 1 本 `cp -a` にした出力で、`check-flag-isolation.sh` が赤になる。
- **V44 (A5b)**: `mountDir` が `/opt/ctf/evidence-src` の下にある課題は、catalog の load と gen-values の `--check` の両方で拒否される。`reservedMountRoots` と gen-values の該当する定数の parity の test (V28) に `/opt/ctf/evidence-src` が入る。
- **V45 (A3b-5 #625)**: 調査型の id が evade の id より小さい合成の catalog を使い、scenario の無い順序で `LoadScored` が `ErrEvadeAfterInvestigate` を返す。調査型の後ろに evade を置いた scenario でも同じ。
- **V46 (A6 #626)**: 未到達 (locked) の調査型の課題でも、回答欄が有効で、提出が採点される。
- **V47 (A4a-2)**
  - 設問を 1 つ欠いた練習版の表で、練習のモードの起動が T4 で拒否される。
  - 実 tree の全調査型に `edition/practice/answers.tsv` がある (CI)。調査型が 0 件の間はこの検査が空のまま通る (#630 の LOW) ので、A7 の PR で「調査型が 1 件以上ある」を同じ test に足して反転させる。足さずに A7 を merge しない。
  - `Load` の入力が `LoadScored` の結果 1 つで、`challengesDir` の引数を持たない (ソース検査) (A4a-3)。
- **V48 (A4b / A5c)**: digests の (seat, cid) の集合が席 × スコープの調査型と一致しなければ、`check` が拒否し、deploy-user も cluster に触れずに非ゼロで終了する。`<cid>/` を 1 つ欠いた `--evidence-dir` でも、deploy-user は同じく非ゼロで終了する。
- **V49 (A5c、`flag-guard` の上)**: kubectl を stub にして argv を記録し、次を確かめる。
  - Secret を `kubectl create secret generic` の `--from-file=<name>=<path>` (名前を列挙) で作る。dir を渡さず、client-side の `kubectl apply` も呼ばない。
  - スコープに無い `ctf-evidence-*` を helm の前に消す。
  - 課題ごとに 512 KiB + 1 byte、合計 2 MiB + 1 byte、65 個の file、B2 の外の名前のどれかで、kubectl と helm を 1 回も呼ばずに非ゼロで終了する。
- **V50 (A5b / A5c)**: sentinel を書いた束の fixture で、helm に渡る引数・values の file・`helm template` の出力に sentinel が 0 件 (release の記録に内容が載らない)。
- **V51 (実機でのみ確認可。sre-engineer、P1b-3 の rehearsal、調査型を含む最初の stand-up の前。手は CoS / CEO、agent は helm / kubectl を実行できない)**: 4 課題 × 512 KiB の圧縮が効かない text の束 (乱数を base64 にした行) を deploy-user で通す。確かめること: Pod が起動する、plant-seed が evict されない、`helm get values` / `helm get manifest` に束の内容が 0 件、Secret の key と bytes が digest と一致する。local (colima) と rehearsal の cluster の両方で測る。結果は ws#117 に貼る。
- **V52 (A4b、R4#2)**: Go の test が、`charts/ctf-user/templates/_helpers.tpl` の正規表現の literal (challenge id の 2 か所、file 名の 1 か所) と gen-values の `EVIDENCE_NAME_RE` を読み、`challengeid.Pattern` と B2 の名前の文法の Go の定義 (A4b) と一致することを確かめる。どれか 1 つを変えたコピーで赤になること。
- **V53 (A5d、R4#3)**: Go の test が、catalog の全調査型の `investigate.evidence.mountDir` の集合と、commit 済みの `challenges/values-*.yaml` の `plant.mounts[evidence: true]` の path の集合 (それぞれの scope ごと) が一致することを確かめる。gen-values の導出は使わない。片方だけを変えたコピーで赤になること。
- **V54 (A4e、M2)**: `load_source_test.go` の `doorGuarded` に、validator の入口が入っている。
  - 呼び手は `cmd/scoreboard` の `edition check` の 1 か所だけ。
  - `Check` を呼ぶのは、`Load` とその入口が共有する unexported な関数 (と練習版の経路) だけ。
  - `CheckedTable` / `CheckedBundles` を値として作る式 (composite literal) が、それぞれ load.go / bundlecheck.go の外に無い。
  - `CheckBundles` が `*Table` を受ける形に戻したコピーで、型の検査か source test が赤になる。
- **V55 (A4c-2、M4)**: `answerformat.Fold` の性質の test。席ごとの 4 format について、受理される綴りを生成する。生成する綴りは次の 4 種類で、どれも `Fold(s)` が正規化した値を部分列に持つ。
  - path: `/` を 1〜3 個に増やす。
  - hexid: 大文字と小文字を混ぜる。
  - timestamp: `+00:00`。
  - 前後の空白。
  - 公開の corpus に hexid の大文字の綴りだけを置いた fixture で、B9 が拒否する (byte の一致のままなら通ってしまう case)。
- **V56 (A4c-1)**: `internal/hintleak/scope` の非 test の関数を、`content_test.go` と validator の両方が呼ぶ。`_test.go` の中に、Free を組み立てる 2 つ目の定義が無い (source test)。
- **V57 (A4e、M2)**: 次の 2 つのそれぞれで、B2 の違反になる。
  - `Lstat` の後、open の前に file を symlink に差し替えた case (test の hook)。
  - inode を差し替えた case。
- **V58 (A5c、#633 R4#2)**: Go の test が、次の literal を読んで `MaxBundleFiles` / `MaxBundleBytes` / `MaxSeatBytes` と一致することを確かめる。どれか 1 つを変えたコピーで赤になること。
  - `charts/ctf-user/templates/_helpers.tpl` の「64」。
  - `charts/ctf-user/deploy-user.sh` の、課題ごとの byte の上限と席ごとの byte の上限。
- **V59 (A4e、#634 R4#3)**: `internal/contracttable` の test が、契約表の文面 2 の digests の header (`# falco-ctf evidence-digests v1 run=<run id>`) と列 (`seat<TAB>cid<TAB>digest`) を、`WriteDigests` の出力と照らし合わせる。
- **V60 (A4b-2 #634)**: 次のそれぞれが違反になる。
  - file が 0 個の束 (B1)。
  - list の外の席の空の dir (B1)。
  - flag を持つ課題がスコープにあるのに `FlagValues` が空 (B3)。
  - さらに、違反があるときに digest の行が 0 件であること、message に答えの値と束の内容が 0 件 (sentinel) であること、49 文字以上の file 名が 48 文字で切られることを確かめる。
- **V61 (A4d-1a、E1)**: 次のそれぞれで E1 の違反になる。どの message にも語彙の値 (sentinel) が 0 件。
  - 未知の key (top-level・slot・window の各深さ)。
  - `version` が無い、または 2。
  - anchor (`&a`)、alias (`*a`)、2 つ目の document。
  - 1 MiB + 1 byte。
  - slot が 0 個と 513 個。
  - 28 文字の answer の slot 名。
  - 暗黙の decoy 名と衝突する slot 名 (`who` と `who-d1`)。
  - answer の slot に `format` がある。filler に `question` がある。
  - path に 17 位置。1 つの位置に 1025 語、または同じ語が 2 回。
  - 正規形でない語 (`/` を含む path の語、大文字の hexid)。
  - name の vocab が 2 list。
  - hexid / timestamp の slot に vocab がある。
  - timestamp の slot があるのに `time.base` が無い。
  - `from` ≥ `to`。
- **V62 (A4d-1b、E2)**: 次のそれぞれで E2 の違反になる。
  - answer の slot が無い席ごとの設問。answer の slot が 2 つある設問。存在しない qid を指す answer。席ごとでない設問を指す answer。
  - `decoys` が K − 1。
  - timestamp の窓の幅が `params.windowSeconds` ± 1。
  - `fixed` に席ごとでない設問が欠けている、または余分な key がある。`fixed` の値が `Canonical` でない。
- **V63 (A4d-2)**: 作者向けの最小の例 (追補 8) が render を通る。
  - 暗黙の decoy の印を template から 1 つ消すと fail。
  - timestamp の値は窓の中にあり、席ごとに違う (2 席で比べる)。
  - `fixed` の値が `answers.tsv` の全席の行に現れる。
- **V64 (T6 の範囲)**: 席ごとでない format の event の値が、練習版の同じ format の答えと同じなら T6 が拒否する (今の `Check` の挙動を固定する。`internal/edition/check.go:262-264`)。

## Advice
- CEO (2026-11-16): 版を分けること、ADR-0056 として起草すること、利用形態の順、イベント後の公開は都度 CEO。
- CTO 代行 = CoS (2026-11-16): 席ごとの値 + 囮 K。hold-out だけで区別を潰す。I6 の解釈。
- security-engineer (2026-11-16): 5 点とも条件付きで可。HIGH 4 件 (2 席の diff、「既定は練習版」、detect の oracle、総当たり) と要件 1〜8 → D3・D5・D8・D10〜D14、V1〜V8。LOW の self 限定 → D4 で採用。
- product-engineer (brief ws#185 §5.2・§8): C11。D4 の代案 (ii) → D2 の `choice-set` (n ≥ 10)。
- architect (2026-11-16): G2・E1、D3 (b) の候補の下限、束の検査の digest による結びつけ。
- security-engineer (2026-11-16、2 回目)
  - 束の項目と名簿の完全性を、validator と digest の照合で止めること: 条件付きで可。条件は run id、digest の 1 定義と parity、deploy-user の fail-closed の 3 つ (1(c) は HIGH で、唯一の弱め箇所) → D9・D10・D11・D16、V15〜V17。
  - 数値: K = max(2 × attempts, 4) で、decoy と answer の語彙・format を同一にする。R = 10。attempts の既定は 5 以下。hold-out の予算は (user, cid) の累計で 20。θ は暫定 0.5 で、未設定なら拒否する。テンプレート同士も比べ、重なり率を stderr に出す。初回のイベント版は文面も R1 で見る → D3・D10・D12・D14、V7・V18・V19。
  - 席ごとに変えられない format: 条件付きで可。規則は「席ごとの設問を 1 つ以上」→ D1、V20。
  - LOW (HMAC の入力の区切り) → D12。
  - そのほかの HIGH 4 件と要件 1〜8 に弱められた箇所は無い。D14 で公開の capture への応答を変えないことも許容する。
- software-engineer (A1 の実装報告、2026-11-16): ATT&CK v19 の全表が repo に無い (→ `technique` は A1c まで拒否)。`path` / `name` の空間は A4 の validator で見る。`LoadScored` は A3b まで調査型の scope を拒否する。規模を理由に A1a / A1b に分けた → D2・D3・D19、V21。
- review-5x T3 の A1b (#607、R1 は APPROVE w/ comments、2026-11-16) と follow-up の #608
  - MED 3 件 (`type:` の許容集合、prompt の hintleak、A3b の前提) → D1・D19 (A1d・A1e・A3b の前提・順序)、V22〜V24・V29。
  - LOW 5 件 → A1d と A5、V25〜V28。
- CTO 代行 = CoS (2026-11-16)
  - A2 を A2a (pure な package) と A2b (配線と P1a) に分ける → D19。
  - ADR-0055 D6 の `answers` を「A1b が merge されてから」に詰める → D17、ADR-0055 D6。
- review-5x (2026-11-16): #616 の R4#2 (自己修復) → D5 の 5、V30。#614 の R4#3 (契約表の行の答え表の半分) → D16 の文面 1、A4-0、V33。#608 の追記 4 件 → A1f・A4-0・A4a・A4b、V24・V34・V35。
- CTO 代行 = CoS (2026-11-16、追補 3): 実際の分割 (A2b-go / A2b-chart、A3a-1 / A3a-2) と P1a の範囲を D19 に記録した。A4 / A5 を review できる大きさに分けた (architect の提案) → D19。
- review-5x (2026-11-16、#619〜#622) と #608 の追記 2
  - #622 R4#1 (練習版での採点) → D8 (iv)、A4a-2、V36。CoS の決定: それまでは今の挙動のまま、A7 の前提に入れる。
  - #620 R4#2 (`self` の gate) → ADR-0038 の限定の supersede、A3b-4、V38。
  - #621 R4#2 (journey の読み) → D4、Signpost 7、V41。
  - #619 の規則 → D1、V42、ADR-0055 の pointer。
  - #622 R1#1 (W2) → ADR-0003 の amend、A3b-5、V39。
  - LOW 4 件 → A3b-4・A3b-5・A4c。
- architect (2026-11-16、追補 4): P1b-1 を 1a / 1b に分ける (render gate は ADR-0055 S3 の後。本来の fail-closed は起動時の拒否と P1a)。
- software-engineer (2026-11-17、A4d-1 の wip `3e888f0`) と architect (追補 8): edition.yaml の schema を確定した。
  - 採用: E1 / E2 の名前、位置ごとの語彙の直積、上限 4 つ、message に語彙を出さないこと。
  - 変更: `version`・`time`・`fixed` を足した。role を answer / filler + `question` の 2 key にした。decoy を `decoys: <n>` から作る形にした。anchor と alias を拒否する。hexid / timestamp の生成を設問の params・`time.base` + 窓で決めた。
  - T6 は固定の答えにも効く (公開の練習版から解ける答えを、イベントで繰り返さない) ことを V64 で固定する。
