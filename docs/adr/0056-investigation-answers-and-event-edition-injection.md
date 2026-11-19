# ADR-0056: 調査型の課題を足す — 答えは閉じた形式の設問とし、scoreboard の Grader 1 点で「回数を加算してから比較」で判定する。イベント版の痕跡束 (席ごとの値と囮) は seat の Secret → plant → seed → 宣言した mount で、答え表は scoreboard の process だけに注入する。練習版は公開し、イベントのモード (`FLAGS_FILE`) では使わない

- Status: **Proposed** (起草 2026-11-16)
  - Accepted の条件: (1) 段階 A1〜A5 の app PR と P1 の platform PR が merge されている、(2) V1〜V6・V8〜V11・V15〜V101 のうち app の部分が required check (`test` / `flag-guard` / `chart-lint`) の上で緑 (除くのは、platform の部分 = V15・V32・V75・V76・V83 の platform 側・V97・V99・V100・V101 と、実機の V51)、(3) security-engineer の R1 の記録 (A1〜A5・P1。private) と CTO の承認の記録がある、(4) (2) で除いた platform と実機の V を、人が merge か rehearsal の時に確かめた記録がある (private)。
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
  - これは 1 席の総当たりへの耐性。席の間の一意性 (T8) は別の性質で、render の割り当て (D12 の U2、追補 10) が構成で守る。そのために、席ごとの format の answer の slot について S ≥ 2 × N も求める (N は `--seats` の数)。edition.yaml の段 (100 × attempts、B8 (a1)) と、`--seats` のある段 (2N、B8 (a2): renderer の E3 と validator) の 2 段に分けて判定する。
  - 計算に使えるのは、format と params (catalog の時点)、または renderer の語彙 (イベント版、validator の時点) だけ。
    - catalog が計算するのは、params だけで空間が決まる `hexid` / `timestamp` / `choice-set` / `sequence`。
    - `path` / `name` の空間は catalog では保留する (語彙は edition にあり、catalog に無い)。A4 の validator (B8) が renderer の語彙で検査する。
    - `technique` は、D2 の表のとおり A1c まで拒否する。
  - 下回れば拒否する (catalog の load、または validator)。
  - 帰結: 4 択の `choice-set` は書けない (2^4 − 1 = 15)。n ≥ 10 なら attempts ≤ 10 まで通る。
- (b) **候補の下限 (追加)**: 席ごとの format では、その席の束に現れる形式の合う別々の token の数を数える。これが R × attempts 以上であること。
  - 理由: 実際の総当たりは「束の中の候補を順に試す」ことなので、(a) の形式の空間だけでは捕まえられない。
  - **R = 10** (CISO の決定、2026-11-16)。validator が拒否の条件にする。
  - 数える単位は B7 と同じ token。束の中の、format に合う別々の token の数を席ごとに数える。name は普通の語にも合うので、多めに数える (緩い) 側に出る。name の守りの本体は、空間・K・回数の上限 (Signpost 13)。練習版には当てない。
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
  - `edition.yaml` と `template/` (D12 の形式。template は平らで、名前は B2 の文法)。
  - `practice/` (追補 9): 公開の鍵 `practice` と席 `*` で 1 回だけ render した出力で、次の 3 つ。練習版は席ごとに違わず、全席が同じ束を受け取る。
    - `answers.tsv`: 練習版の答え (run id は全部 0、席 `*`)。束ではない。
    - `digests.tsv`: 練習版の束の digest (D9 の定義。run id は全部 0、行は `*<TAB><cid><TAB><digest>`)。
    - `evidence/<file>`: 練習版の束。plant が copy するのはここの file だけ。
    - deploy-user の `names` と `--from-file`、`check-flag-isolation.sh` の実 scope の `names`、B4 が比べる「練習版の束」は、どれも `evidence/` だけを読む。答えと digests は構造上 seat に届かない。
    - イベント版の木 `<root>/<seat>/<cid>/<file>` の 1 葉が、`<cid>/edition/practice/evidence/<file>` (席 `*`) にあたる。束の形 (B2) と digest の定義 (D9) は同じものを使う。
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
- `scoreboard edition check` の引数・exit code・検査の順序・出力は **D20** (追補 11) が正典。
  - exit: 0 = 受理 / 1 = 拒否 / 2 = 使い方の誤り・読めない入力 / 3 = 検査の後の書き出しの失敗 (環境。追補 13)。platform は 0 以外ではすべて何も apply しない。
  - stderr に出すものと出さないもの、exit code は D20 が正典 (値・鍵・語彙・束の内容は出さない)。
  - 受理したときだけ `--digests-out` を書く。1 行目は `# falco-ctf evidence-digests v1 run=<run id>`、2 行目以降は `seat<TAB>cid<TAB>digest` (束は (seat, 課題) ごと。D11)。(seat, cid) の集合は、席 × スコープの調査型と一致する。席 `*` と、全部 0 の run id は、練習版の digests (`practice/digests.tsv`) だけのもの。入口を分ける: イベントの `ParseDigests` / `WriteDigests` (#634) は全部 0 の run id と席 `*` を拒否し、練習版は `ParsePracticeDigests` / `WritePracticeDigests` (全部 0 の run id と席 `*` だけを要求。書く側は A4d-2b、読む側は A5c-2) を通る。入力の中身からモードを推さない。deploy-user も、`--evidence-digests` (イベント) と練習版の経路で同じ 2 つの規則を別々に当てる。
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
- `scoreboard edition render` の引数・出力の layout・手順は **D20** (追補 11) が正典。
  - HTTP server の path から render に到達しない (ソースの検査で固定する)。
- **validator が答え表を得る入口** (追補 7、#634 R4#1): `load.go` の exported な入口 1 つ (仮に `LoadEventTable(scored, answersFile)`)。door の数に入れ、呼んでよいのは `CheckEvent` の 1 か所 (`CheckEvent` の呼び手は `edition check` の `runEditionCheck` の 1 か所。D20 の到達範囲、#648・#649)。
  - 中身は scoreboard の `Load` と共通の unexported な関数で、読む → `Parse` → `loadPractice` → `Check` (EventMode true、PracticeSet、FlagValues) の順。起動の経路と validator の経路は、同じ `Check` を通る。
  - 返すのは `*CheckedTable` (field は unexported、作れるのは load.go だけ) と run id。
  - `loadPractice` は、練習版の答えの表を読み、`edition/` の場所を決めるだけ。束と template の file を読むのは `readPracticeFiles` で、validator の経路専用 (#640)。**scoreboard の起動の経路は、束も template も読まない** (壊れた束で起動を止めないため。起動の経路が読むのは答えの表だけ、という A4a の決定と整合する)。
  - validator の入口 (A4e) が、練習版の file と PracticeSet を `CheckedTable` に載せる。追補 5 の J18 の「`Load` の外の入口」は、この validator の入口に 1 つにまとめた。
  - `CheckBundles` は `*CheckedTable` だけを受け、結果は `*CheckedBundles` (作れるのは `CheckBundles` だけ。規則は B1・B2・B3・B5・B6・B9)。
  - `WriteDigests` は `*CheckedEvent` だけを受ける (追補 12)。`*CheckedEvent` を作れるのは `CheckEvent` だけで、D20 の検査 (E1・E2 (`<cid>` の集合を含む)・E3 (template の印)・B8 (a1)(a2)・B1〜B11) を全部通ったときにだけ作る。`*CheckedBundles` は `CheckEvent` の中間の値。検査していない表と束は、型の上で digests に届かない。
- **入力の木の所有** (#633 R1#1): validator の入力 (D20 の `edition check` の入力の引数のすべて: `--challenges`・`--scenario`・`--flags-file`・`--answers`・`--render-record`・`--evidence-root`・`--seats`・`--edition-root`・`--previous-digests`・`--corpus`) は運用者が所有する木で、validator の container には `:ro` で mount する。
  - そのうえで reader は O_NOFOLLOW|O_NONBLOCK で開き (`openRegular`。FIFO への差し替えで block しない)、開いた descriptor の `Stat` (dev / inode / 通常 file) を、先に取った `Lstat` と照らし合わせる。食い違えば B2 の違反にする (A4e-1 #646)。
    - **保証の範囲は path の最後の要素だけ**。途中の dir の差し替えは、「運用者の所有・`:ro`」の前提が担う。
    - 例外は scoreboard の起動の `ANSWERS_FILE` だけ。Kubernetes の Secret の volume は link を含むので、link を辿る open (`openFollowing`) のまま。
    - 練習版の答え表は image の中の file なので `openRegular` (以前から Lstat で link を拒否していた。#646 で加わったのは、Lstat と open の間の差し替えの拒否)。
    - どの door がどちらの open を使うかは、`safeopen_source_test.go` が固定する。
- platform は、課金が発生する最初の step の前に、render → check の順で、pin した scoreboard image の digest を `docker run --rm --network none --pull never --user <運用者の uid>:<gid>` で呼ぶ (image の既定の user 65532 では、運用者だけが読める入力を読めない。D20 の P1b-2、追補 13)。通らなければ (exit が 0 でなければ) 何も apply しない。platform が読むのは exit code と出力の file だけで、stdout は読まない (追補 13)。
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
- T8: 席ごとの format では、同じ設問の値が席の間で重複しない (緩めない。追補 10)。独立に引くと、席の数とともに重なりはほぼ確実になる (C(N,2)/S。S = 200・N = 30 で 2.2 組)。そこで renderer が、席の list の順に、slot の位置ごとに先着で値を割り当てて重なりを避ける (D12)。

**edition.yaml について (renderer・validator・練習版の CI。追補 8)**:
- E1: 形。次をすべて満たさなければ拒否する。
  - UTF-8、Hidden が 0 件、`MaxSpecBytes` (1 MiB) 以下、document は 1 つ、anchor と alias が無い。
  - top-level の key は `version` (必須、`1`)・`time`・`fixed`・`slots` だけで、どの深さでも未知の key と型の誤りを拒否する (strict)。
  - slot は 1〜`MaxSlots` (512) 個。slot 名は `IDPattern` で、answer の slot は 27 文字以内。暗黙の decoy 名 `<name>-d<i>` を含めて一意。
  - `role` は `answer` か `filler`。answer は `question` と `decoys` を持ち、`format` を持たない。filler は `format` を持ち、`question` と `decoys` を持たない。
  - vocab は path と name の slot だけが持つ。name は list が 1 つ。path は位置ごとの list で、1〜`MaxVocabPositions` (16) 位置。各 list は 1〜`MaxVocabWords` (1024) 語で、語は format の正規形 (path では要素 1 つ)。位置の中に同じ語は 2 回出ない。最長の組が path の上限 (255 byte) に収まる。
  - hexid の filler は `length`、timestamp の slot は `window: {from, to}` (0 ≤ from < to) を持つ。timestamp の slot があれば `time.base` が要る。`time.base` + `to` − 1 秒は `9999-12-31T23:59:59Z` 以下 (answerformat の timestamp が表せる最後の時刻。renderer の `lastTimestamp` はこの 1 つの定義を使う)。
  - message に語彙の値を出さない (slot 名・位置の番号・語の番号・行番号だけ)。
- E2: 課題との対応 (`<cid>` の集合と設問)。次をすべて満たさなければ拒否する。
  - `--edition-root` の `<cid>` の dir の集合が、スコープの調査型の集合と一致する (余分な dir も欠けた dir も E2。render と validator の両方で exit 1。追補 13)。`<cid>` の dir の中の `edition.yaml` と template が無い・通常 file でない・link なら exit 2 (D20。束の B1 と reader の誤りの分け方と同じ)。
  - 席ごとの format の設問それぞれに、answer の slot がちょうど 1 つある。answer の slot の `question` は、その課題の席ごとの設問を指す。
  - `decoys` ≥ K = max(2 × attempts, 4)。
  - answer の timestamp の窓の幅 (to − from) は、設問の `params.windowSeconds` と一致する。
  - `fixed` の key の集合は、席ごとでない設問の集合と一致し、値は `answerformat.Canonical` を満たす。
  - decoy は answer の slot から format・params・vocab・window を継ぐので、同一性は E2 の構成で成り立つ。
  - answer の slot の vocab と window の有無は、設問の format に合う (path / name は vocab を持ち window を持たない、timestamp は window を持ち vocab を持たない、hexid はどちらも持たない)。name は list が 1 つ。語は設問の format の正規形。E1 は、answer の slot の語を path の要素の文法でだけ見る (format を知らないため)。
**render について (renderer。追補 10)**:
- E3: render の fail。次のどれかで拒否する (wip の `RND` を改名)。1 つ目 (印) のうち lexer の失敗 (印の文法の誤り・token として独立していない印) は、validator も `--edition-root` の template に同じ lexer で当て、同じ規則名 E3 で拒否する (exit 1。`checkevent.go` の `RuleTemplateMark` と render の `RuleSpecRender` の値の一致を test が固定する。追補 13)。ほかの項は render だけで、validator の側の対応は B8 (a2) (S ≥ 2N) と B10 (前回との連続)。
  - 印が未宣言、宣言した slot か暗黙の decoy の印が無い、render の後に印が残る。answer と decoy の印が token として独立していない (前後が token の文字 `[A-Za-z0-9._:/-]`)。
  - event を練習版の鍵で render する、席 `*` を event で render する。
  - 席が 0、席の list に重複がある。
  - `--previous-seats <file>` が、新しい `--seats` の接頭辞でない (並べ替え・削除・挿入)。`--previous-seats` と `--no-previous` (初回) は、どちらか一方を必ず渡す (D20)。
  - 席ごとの format の answer の slot で S < 2N (B8 (a2)。draw の前に決定的に判定する)。
  - 値を引けない (やり直しが 1000 回に達した。S ≥ 2N なら、1 回の draw が当たる確率は (N − 1)/S < 1/2 で、1000 回続く確率は < 2^−1000)。
  - message に値・鍵・語彙を出さない。
**validator だけ (束は scoreboard に無いため)**:
- B1: 表の seat の集合が `--seats` (roster ∪ 予備) と一致し、すべての (seat, スコープの調査型) に束がある。
- B2: 束の形。
  - 平らな通常 file だけ。名前は `^[a-z0-9][a-z0-9._-]{0,62}$` で、`..` で始まらない。
  - file は (seat, 課題) の束ごとに 64 個以下で、合計は 512 KiB 以下。UTF-8 で、Hidden が 0 件。
- B3: 束に `FALCO{`、flag の正規表現、dev の placeholder、今回の flags の値が 0 件。
- B4: 練習版との比較。次のどれかに当たれば拒否する。
  - file の digest か束の digest が、image の中のどれかの練習版と一致する。
  - 練習版の答えの値が束に現れる。format は限らない (全 format。追補 10)。席ごとの format は `answerformat.Fold` で畳んで探し、席ごとでない format は、正規化した値を byte の部分列としてそのまま探す。
    - 席ごとでない format の綴り違い (technique の大小文字、choice-set の区切りと順序) は見逃す。これは許す。固定の答えの漏れの本体は T6 (正規化した値の完全一致で、練習版の答えの繰り返しを拒否する) が止めていて、B4 の本文の検索は流用を見つける補助だから (V19)。
  - 入力の完全性 (#640): event の束がある課題の練習版の template が欠けていれば、B4 の違反。event の束があるのに比較の件数が 0 なら、B4 の違反 (練習版が 0 件を「違反なし」と読まない)。調査型の課題が無い image で B4 を呼ばないことは、A4e が持つ。
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
  - 実際の出力で、席ごとに、各 answer の decoy の位置の token (`[A-Za-z0-9._:/-]` の連なり、format の判定は `Canonical`) のうち format に合うものが、K より少ない (追補 10)。
  - 各 answer の位置と各 decoy の位置で、2 つの席が同じ token を持つ (追補 10 の改訂)。
    - validator は renderer を信頼しない。`--edition-root` の template を lexer で読み、answer と decoy の印の token の番号 (E3 が印の独立を保証する) を得て、位置ごとに全席の token を集合に入れる。費用は O(席 × slot)。filler は照らさない (割り当ての対象外)。
    - この 2 つ (席ごとの数と、席の間の重複の無さ) がそろえば、「どの組でも、答えでない差分の位置が K 以上」は検査済みの性質になる。組ごとの比較は、renderer の test (小さな N) に残す (V4)。
    - 1 席のときは、席ごとの検査を当て、席の間の検査は組が無いので空になる (結託する相手がいないので、fail-open ではない)。練習版 (席 `*`、公開) には当てない。
- B8: D3 の (a) と (b)。
  - (a1) edition.yaml の段 (A4d-1b #637): answer の slot の空間 (path / name は語彙の位置ごとの積、hexid / timestamp は設問の params) を 100 × attempts と比べる。
  - (a2) `--seats` のある段: 同じ空間 S を 2N と比べる。renderer は draw の前に E3 で判定し (A4d-2a)、validator は B8 として判定する (A4e)。
  - (b) 出力の段 (A4d-2c と validator)。
- B9: 席ごとの format の答えが、image の `/app/challenges` と `/app/scenarios` の bytes に現れない (brief §8 の 2)。
  - 照らすのは、採点が受理する**綴りの族**全体 (追補 7、#634 R2#2)。corpus を format ごとの `answerformat.Fold(format, text)` で畳んでから、正規化した値を部分列として探す。
    - name: fold は恒等 (前後の空白は部分列の検索で覆える)。
    - path: 連続する `/` を 1 つにする (族は無限だが、fold で覆える)。
    - hexid: ASCII の小文字にする。
    - timestamp: `+00:00` を `Z` にする (受理される綴りは 2 つだけ)。
  - 席ごとでない format は B9 の対象外。
  - `Fold` は `Normalize` の隣に置き、「受理される綴り s の `Fold(s)` は、正規化した値を部分列に持つ」の性質の test で固定する (V55)。偽陽性は拒否の側なので許す (再 render で解ける)。
  - A4b-2 (#634) の byte の一致は、この fold に置き換えた (A4c-2a #639)。
- B10: 前回の render との連続 (追補 10 の改訂)。`edition check` は `--previous-digests <file>` か `--no-previous` (初回) のどちらか一方を必ず受ける (D20)。前回の digests の (seat, cid) の集合は、今回の (seat, cid) の集合に含まれなければならない (含まれなければ拒否する。席や課題を消した list と、共通が 0 件の previous = 取り違えた file を、ここで止める。#648)。両方にある (seat, cid) の束の digest が一致しなければ拒否する (同じ鍵で、席の list が接頭辞の延長なら、前の席の束は byte で同じはず)。前回の digests の run id は今回と照らさない (run id は render のたびに作り直すので、正しい previous でも必ず違う。D9)。前回の digests は `ParseDigests` (イベント) の形で読み、形の誤りと 0 行は exit 2 (D20)。全席の配り直し (鍵の交換など) は、`--no-previous` を渡すことを運用の明示の手順にする (Signpost 15)。開催の途中でスコープの課題を変えるのも、配り直しとして扱う。
- B11: 表と render-record の run id の一致 (validator だけ。追補 13)。`--answers` の 1 行目の run id と、`--render-record` の `run-id` の行の値が一致しなければ拒否する (同じ render の出力でない組を止める)。render-record の形 (header・行・key 名・指紋の桁) の誤りは exit 2 で、B11 ではない。T3 は scoreboard の起動でも当たる表の形の規則なので、この照合には使わない (#648 は仮に T3 の名前で出す。A4e-2c で B11 に直す)。
- B12: 生成の scope と検査の scope の一致 (validator だけ。追補 19、A4e-6)。
  - render は、render に渡した scope (`--scenario <file>` か `--all-challenges` で `catalog.LoadScored` が返した課題の id の、順序つきの列) の digest を render-record に書く。check は、自分に渡された scope から同じ digest を計算し、違えば拒否する (exit 1)。renderer と validator は、`internal/edition` の同じ 1 つの scope の digest の関数を呼ぶ (digest の定義は 1 つ。D9 と同じ規律)。check はこれを、表を読む前 (D20 の step 1b) に行う (追補 19 の改訂、#672 R2#1 = R4#2)。
  - digest = sha256 (byte 列の定義は 1 つ: label の bytes `falco-ctf/edition/scope/v1` に LF (0x0A) を 1 つ続け、その後に scope の課題の id を順に、それぞれの直後に LF を 1 つ付けて連結する。各 id は LF で終わり、join ではない。id は `challengeid.Pattern` に合うので LF を含まない) の、64 桁の小文字 hex。1 件と 2 件の scope の期待の digest を golden として `internal/edition/testdata/` に置く (値は、実装の関数とは別の経路 = byte 列の定義どおりの手計算 (たとえば `printf` と `sha256sum`) で得て置く。実装の出力から写すと、定義の取り違えを固定してしまうため。入力の id は合成の値 (公開してよい challengeid の形) にする。review 2 の R2#4。追補 19 の改訂、#672 R2#2)。
  - B12 は表を読む前に走るので、scope の違いは、調査型の課題の集合に及ぶときも、check の scope に調査型の課題が 1 つ以上残る限り、B12 が最初に名指しして止める (1 つも残らなければ、step 1 が exit 2 で先に止める。review 2 の R4#5) (step 1〜5 は最初の違反で止まるので、T4・E2 には届かない)。B12 が無ければ、調査型の集合の違いは T4 (step 2) で止まるが、evade など調査型でない課題だけが違うとき (B3 の `FlagChallenges`・B5 の Hints・T7 の範囲が変わる) と、順序だけが違うときは、B12 だけが止める。
  - `--all-challenges` と、同じ課題を同じ順に並べた scenario は、同じ digest になり通る。
  - B12 が束ねる scope は、課題の id の順序つきの列だけ (`catalog.LoadScored` が返す順)。digest の入力は、この id の順序つきの列に確定する。edition の検査が scenario から受けるのがこの列だけであること (scenario のほかの属性が版の検査の結果に効かないこと) は、A4e-6 の PR (#674) で確かめた (追補 20): check の結果に効く scenario 由来の入力は 2 つで、(1) 課題の id の順序つきの列と、(2) scenario と同じ dir の `narrative.yaml` (`catalog.LoadHintInputs` が読み、B5 の Hints / Free の範囲を書き換える) である。scenario の ID と title は使わない。B12 が束ねるのは (1) だけ。(2) は render の出力 (答え表・束・render-record) に効かない (render は narrative を読まない。B5 は validator だけの規則) ので、render と check の間の束ねには要らない。digest に入れると、ヒントの文面だけを直しても再生成が要る、効き目の無い結合になる。(2) を一致させる必要があるのは check と scoreboard の起動の間で、どちらも同じ dir の `narrative.yaml` を読む。これは B12 の外で、platform が同じ出所の scenario を両方に渡すこと (P1b-2 の要件、V97) で担保する。入力を足すときは、label の版を上げる (`falco-ctf/edition/scope/v2`) 追補で行う (追補 19 の改訂、#672 R2#5。改訂 2、review 2 の R4#6)。

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
  - chart の copy 行は、`render_evidence_copy` の出力と byte で一致する。`scripts/check-flag-isolation.sh` が、gen-values の検査用の入口 5 つ (5 つ目の `--check-evidence-names` は A5d #663 で足した。練習版の束の名前を、helm の `--set-string` に渡す前に B2 の名前の文法で確かめ、共有の `evidence_bundle_digest` を通す。追補 16。残りの 4 つは `--check-seed-script`・`--render-evidence-copy`・`--list-evidence-mount-dirs`・`--emit-evidence-fixture`) を使って確かめる (V43 の実装。gen-values は source せずに呼ぶ)。
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
  - 練習版を使うのは、`--flags-file`・`--evidence-dir`・`--evidence-digests` のどれも無いときだけ (local の既定)。イベントの指標は `--flags-file` で、scoreboard の D8 と同じ信号。
  - 練習版の経路 (A5c-2、追補 9): スコープの調査型の課題ごとに、deploy-user は既に持つ `CHALLENGES_DIR` の `<cid>/edition/practice/` を読む。
    - `digests.tsv` の 1 行目の run id が全部 0 で、行の席が `*` であることを確かめる。
    - `evidence/` の束の digest を、D9 の定義の shell の写しで計算し、`(*, cid)` の行と照らし合わせる (照合は省かない。イベントと同じ code の道を通す)。
    - 照合が通った `evidence/` の file だけから、`ctf-evidence-<cid>` を作る (K1 と同じ `--from-file=<name>=<path>`)。`answers.tsv` と `digests.tsv` は、`--from-file` にも `names` にも入らない。
    - 次の場合は、cluster に触れる前に非ゼロで終了する: 練習版が無い、`evidence/` が B2 の外 (名前の文法・個数・大きさ・symlink)、digest が合わない、run id が 0 でない。
    - 練習版の経路に入ったことを stderr に 1 行出す (値は出さない)。
- 新しい検査 3-x (番号と担当は各項の末尾。追補 16) (`assert-flag-isolation.sh`、deploy の時、fail-closed):
  - challenge の `mountDir` の中に symlink が 0 件で、通常 file だけがある。空の dir も赤 (実装の番号は 3-9、A5d #663。platform の runbook の一部は「3-9」を ADR-0026 の missions の allowlist (app ではその検査は 3-8) の意味で使っていた = 番号の衝突。P1b-3 で直す。追補 16 の改訂、#664 R4#3)。
  - seat の ns の Secret のうち type が `Opaque` のものの名前の集合が、{`ctf-flags`} ∪ {`ctf-evidence-<cid>` | cid はスコープの調査型} と一致する。Helm の release の記録 (type `helm.sh/release.v1`) は別の類として数える。それ以外の type の Secret (image の pull の Secret など) が seat の ns に 1 つでもあれば赤 = 閉じた集合 (実装の番号は 3-10、A5d #663。ADR の元の文より厳しい形を追認した。追補 16、#663 R4#4)。これは platform への制約で、P1b-3 の要件と、契約表の文面 2 (A4e-4、散文) に書く。3-10 は全部の scope に適用される (evade だけの scope を含む。そのときの期待の集合は {`ctf-flags`} だけ)。#663 が main に入った時点から効くので、実 cluster での最初の確認 (seat の ns に別の type の Secret が置かれない構成であること) は、調査型の最初の stand-up を待たず、`005437e` より後の app を pin する最初の platform の APP_PIN の bump の verify / rehearsal で行う (V51。CoS が platform#335 に追記した。追補 16 の改訂、#664 R4#2)。契約表 (A4e-4) を、その bump の前に入れることは求めない。それまでの正典は、この D11 と D19 の P1b-3 の行。
    - 期待の集合は、helm に渡した values の `evidence: true` の項から、assert の中の builtin だけの reader で読む。これは shell の 3 つ目の reader で、assert が builtin だけで動く制約 (ADR-0001) のためにある。parity は、gen-values の `evidence_scope_cids` と照らす受理と拒否の 23 通りの表と、commit 済みの values の上の test で保つ (#663 R4#2)。A5e の後は、deploy-user が引数で渡した values の file だけを読む (A5e #665 で実装した。assert の 5 つ目の引数。追補 17)。
  - `ctf-evidence-<cid>` の key の集合が (A5e #665 で実装した = 3-11。names は values の file には無い (deploy-user が `--set-string` で helm に渡す)。そこで deploy-user が、helm に渡す names と同じ loop の 1 つの導出から、`<cid>/<name>` を assert の引数で渡す。どの cid が調査型か (`evidence: true` の項) は、渡された values の file から読む。key の名前は kubectl の go-template で読み、余分・不足・同数で違う、のどれも赤。ADR の元の文 (「values の file から names を読む」) を、この形に直した。追補 17。#663 R2#1・R4#3。A5e (#665) の前は、(3) を deploy の時に見る機械は無かった。その間、key の集合は、deploy-user が束の file から `--from-file` で Secret を作ることと、その前の digest の照合が担う。追補 16 の改訂、#664 R2#2)、chart に渡した `names` と一致する。
  - release の記録 (`helm get values` / `helm get manifest`) に、束の内容 (sentinel) が 0 件である (V50)。deploy の時の自動の検査にはしない (追補 16、#663 R2#1): 実データの束には sentinel が無く、内容の部分一致の検索は偽陽性と取りこぼしの両方を出す。構造の性質 (chart は名前しか受けない) は V50 が CI で、実データでの 0 件は V51 が rehearsal で確かめる。

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
- 値は `HMAC-SHA256(master, len(v) ‖ v ‖ len(seat) ‖ seat ‖ len(cid) ‖ cid ‖ len(slot) ‖ slot)` から導く決定的な DRBG で選ぶ。`v` は版の label `falco-ctf/edition/v1` (追補 10)。
  - stream は block(i) = HMAC-SHA256(seed, be32(i)) (i = 0, 1, …)。選ぶときは、64 bit の draw の rejection sampling で偏りを除く。
  - **席の間の割り当て (U2、追補 10)**: 席の list (`--seats`) は順序があり、追記だけ (roster ∪ 予備。消えた席も残す)。
    - renderer はこの順に席を処理する。各 slot の位置 (answer と各 decoy) で、前の席が使った値に当たったら、同じ stream から次を引く。1 席の中でも、answer と decoy の値は互いに異なる。
    - 末尾に席を足しても、前の席の値は変わらない。これを機械で守る: renderer は `--previous-seats` (初回は `--no-previous`。D20) が `--seats` の接頭辞でなければ E3、validator は前回の digests との連続 (B10)、platform は前回の list と digests を sops に残して渡す (P1b-2)。
    - 条件は S ≥ max(100 × attempts, 2N) (B8 (a1)・(a2))。
  - event の鍵は 32 byte 以上。練習版の鍵は公開の固定値 `practice` で、event とは鍵だけが違う。
  - run id は render の入力にしない (入れると、予備の追加の再 render で全員の値が変わる)。鍵はイベントごとに新しくする。render は鍵の指紋 HMAC-SHA256(key, len ‖ `falco-ctf/edition/key-fingerprint/v1`) の hex を `render-record` (run id と指紋の 2 行。header を含めて 3 行。A4e-6 からは scope の digest の行を足して、header を含めて 4 行 (行の数は、どこでも header を含めて数える。review 2 の R2#2) (B12。追補 19)。値と鍵は書かない) に書く。platform の preflight は、過去のイベントの指紋の台帳と照らし合わせ、一致すれば FAIL にする (P1b-2。これは新しい鍵 = `--first` / `--rekey` のとき。同じ event の延長 = `--extend` は、台帳に行を足さず、今回の event の生成の表の最新の行と同じ指紋を要求する。event の同一性と、終了した event の延長の拒否は、D19 の P1b-2 の行の (i')。追補 19 の改訂、#672 R1#1。再利用すると、run id を入れないのでイベントをまたいで答えが同じになるため)。
  - `len` は 4 byte の big-endian の byte 数 (長さの接頭辞)。区切りの無い連結では、別の組が同じ入力になるため。
  - renderer の test で、`("ab","c")` と `("a","bc")` が別の値になることを固定する。
  - master 鍵は platform の sops の中だけに置き、render の実行の中だけで使う。cluster・scoreboard・seat の ns には置かない。
- **K**: 答えの slot 1 つごとに、同じ format の decoy の slot を K 個以上置き、それらも席ごとに変える。
  - **K = max(2 × attempts, 4)** (CISO の決定、2026-11-16)。2 席が結託しても、全候補を回数の内で試し切れない。
  - decoy の slot の format・params・`vocab`・window は、その answer の slot と同一 (見分けが付かないこと)。decoy を answer の slot の `decoys: <n>` から作るので、同一性は構成で成り立つ (追補 8)。数は E2 が確かめる。
  - 機械検査は 2 つ。renderer の test (合成テンプレートで、小さな N の全組について、2 席の出力の差分の位置のうち答えでないものが K 以上。V4) と、validator の B7 (実際の出力で、席ごとに format に合う decoy が K 以上と、answer と decoy の位置ごとの席の間の重複の無さ。D10 の B7)。
- 予備の席: platform は roster に予備を足して render する (数は COO が決める)。席の list は追記だけで、順序を変えない (順序を変えると、後ろの席の値が変わる。D12 の U2。E3 と B10 が止める)。
  - 予備を超えて席を足すと、再 render と scoreboard の再起動 (I1 の Recreate) が要る。runbook に書く。
- 練習版: 公開の固定鍵 `practice` と seat `*` で render した出力 (`practice/` の `evidence/`・`answers.tsv`・`digests.tsv`) を commit する。これが golden で、別の dir は作らない。render(edition.yaml, template, `practice`, `*`) == commit した `practice/` を、byte の一致で確かめる (A4d-2b、V67)。

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

> | 痕跡束と版の検査 (ADR-0056、**クロスリポ契約・両リポ同時 PR**) | 調査型の課題の設問 (id・format・attempts・params) は app の `falco-rule.yaml` が正典。答えは app に置かない (練習版の `challenges/<id>/edition/practice/` を除く)。**イベント版**は platform が app のテンプレート形式 (`edition.yaml` + `template/`) で private に書き、`scoreboard edition render` で席ごと (roster ∪ 予備) に生成し、`scoreboard edition check` (pin した scoreboard image、`--network none`) が受理した出力だけを使う。`--seats` は順序つきで追記だけ (消えた席も残す。並べ替えると既存の席の値が変わる)。`edition render` は `--previous-seats`、`edition check` は `--previous-digests` を必須で受け、前回の接頭辞の延長でない list (E3) と、前回と digest の違う席の束 (B10) を拒否する (初回は `--no-previous` を明示する。引数の全体は D20 と、契約表の確定版の行 (A4e-4))。render は鍵の指紋を `render-record` に書く。CLI は exit 0 = 受理 / 1 = 拒否 / 2 = 使い方の誤り / 3 = 検査の後の書き出しの失敗 (環境)、stdout は人のための表示 (契約ではない)、validator の container は運用者の uid の `--user` で動かし (uid 0 は不可)、B10 は前回の (seat, cid) の包含と共通部分の digest の一致、B11 は表と render-record の run id の一致 (この 3 点は A4e-4 で確定の行に入れる。追補 13 の改訂)、stderr は値を含まない、`--digests-out` は 1 行目が `run=<run id>`、以降が `seat<TAB>cid<TAB>digest` (digest の定義は D9 の 1 つ。共有の case 表は `internal/edition/testdata/bundle-digest/`)。platform の preflight は、表と digests の run id が一致しなければ何も apply しない。**答え表** (`# falco-ctf answers v1 run=<run id>` の 4 列 TSV) は文面 1「答え表」の行のとおり。**痕跡束**は課題ごとの seat の Secret `ctf-evidence-<cid>` (key = file 名、課題ごとに 64 個以下・512 KiB 以下) で、`plant` だけに `/opt/ctf/evidence-src/<cid>` として mount し、その課題の `mountDir` へ copy する。`deploy-user.sh --evidence-dir --evidence-digests` は、次のどれかに当たれば cluster に触れずに非ゼロで終了する。digest か run id が合わない。`--flags-file` があるのに 2 つのどちらかが無い。2 つの片方だけが渡された。**イベントのモード** = scoreboard の `FLAGS_FILE` が空でないこと。このモードでスコープに調査型があるのに `ANSWERS_FILE` が無い、または逆の場合は、起動を拒否する。platform は、env が local 以外で `requirements.answers` (ADR-0055 D6) が空でなければ、`answersSecret` 無しでは render せず、課金の前に render → check を通す。適用の順は platform が先 (ADR-0033 D9 (g) と同じ) |

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
| A4c-2a (#639) | `answerformat.Fold(format string, text []byte) ([]byte, error)` と `ErrNoFold` (席ごとでない format)、B9 を fold の形に (M4) | 要 | — | V55 (検証: CI) |
| A4c-2b (#640) | 練習版の束と template の reader (`readPracticeFiles`、validator の経路専用。template の上限は B2 の束の上限を流用) と B4 (digest・答えの出現 (全 format)・shingle の (1)(2)・θ = 0.5 と未設定の拒否・入力の完全性 (Q4))。重なり率を stderr に出すこと、`checkPracticeOverlap` の配線、`CheckedTable` に載せることは A4e | 要 | — | V3 (B4)、V19 (検証: CI) |
| A4c-3 (#661、済み) | hintleak: shingle の窓と正規化を 1 つの関数として export し、B4 がそれを呼ぶ (#640 R4#4。実績 (#661): `hintleak.GramSet` を export した (非公開の `gramSet` の改名)。B4 がそれを呼ぶ。#640 の parity の test は元から無く、挙動の test だけがあった) | 要 (hintleak) | — | V73 (検証: CI) |
| A4d-1a (#636) | `edition.yaml` の parser と E1 (D12 の schema、strict、anchor と alias の拒否、上限、message に語彙を出さない)。wip `3e888f0` を追補 8 に合わせる | 要 | — | V61 (検証: CI) |
| A4d-1b (#637) | E2 (設問との対応・`decoys` ≥ K・timestamp の窓の幅・`fixed` の集合) と B8 (a) (語彙の位置ごとの積・params からの空間) | 要 | — | V6 (edition)、V21 (path / name)、V62、V64 (検証: CI) |
| A4d-2a | renderer の本体: DRBG (版の label・長さ接頭辞・HMAC の expand・rejection sampling)、鍵 (32 byte 以上、練習版の鍵の分離)、値の生成 (hexid は設問の `params.length`、filler は `length`、timestamp は `time.base` + 窓から一様)、U2 の割り当て (席の list の順に、slot の位置ごとに先着)、印 `{{ctf:…}}` の lexer (印の文法の唯一の定義。B4 の `slotMarkRE` はこれに置き換える、#640 R4#3)、E3 (`--previous-seats` の接頭辞、S ≥ 2N の事前検査、印の token の独立を含む)、鍵の指紋と `render-record` | 要 | — | V4、V18、V63、V68、V70、V71、V74、V76 (検証: CI) |
| A4d-2b | 表の writer (`fixed` を全席の行に)、`WritePracticeDigests`、練習版の golden (V67) | 要 | — | V67、V11 (仕組み) (検証: CI) |
| A4d-2c | token、B7 (席ごとの検査と、answer と decoy の位置ごとの席の間の重複の検査。D10 の B7)、B8 (b) (D3 (b)) | 要 | — | V6 (b)、V69 (検証: CI) |
| A4e-1 (#646) | D20 の型と door: `LoadEventTable` (→ `*CheckedTable`)、`*CheckedBundles`、`WriteDigests` は `*CheckedBundles` だけを受ける、`CheckEvent` / `RenderEvent` の骨組み、`internal/edition/practicelayout.go` (`practice/` の layout の唯一の定義)、`WritePracticeDigests` を `digests.go` へ、O_NOFOLLOW + Stat の照合の reader (束・template・練習版・鍵・seats・answers・digests)、hintleak の `scope` を `hlscope` で import、source test。`PreviousSeatsOf(空)` を「与えられていない」と同じ扱いにして `Render` が E3 にする変更、`render.go` の doc の修正、`render_assign_test.go:266` の case の反転。原子的な writer (一時 → rename、0700 / 0600、O_EXCL|O_NOFOLLOW) の helper。実績 (#646): `openRegular` / `openFollowing` と `safeopen_source_test.go`、単一 file の `os.Link` → `os.Remove` と tree の rename の writer。入れなかったもの (後の段へ): 鍵・seats・previous の reader (A4e-2 / A4e-3)、`CheckEvent` / `RenderEvent` の骨組み (A4e-2 / A4e-3)、V78 の正の pin (A4e-2 / A4e-3)、golden の test の reader の共有 (A4e-3) | 要 | — | V54、V57、V74、V78 (検証: CI) |
| A4e-2 (分割前の記述。実績は下の A4e-2a #648・A4e-2b #649 の行) | `scoreboard edition check` (D20 の引数・順序・exit code・出力)。`CheckEvent(in CheckInput) (*CheckedEvent, CheckReport, error)` と `checkevent.go`、`WriteDigests(w, *CheckedEvent)` への署名の変更 (追補 12)、`--digests-out` を一時 file → `os.Link`、鍵・seats・previous の reader (`openRegular`)、V78 の正の pin (`CheckEvent` の呼び手・server の path から届かない・`hlscope`) | 要 | CLI は先に merge してよい (platform はまだ呼ばない) | V3 (B の CLI)、V15 (check)、V72、V75、V77、V79 (検証: CI) |
| A4e-2a (#648) | `CheckEvent(in CheckInput) (*CheckedEvent, CheckReport, error)` と `checkevent.go` (D20 の順序の全体、B10、render-record の run id の照合)。`WriteDigests(w, *CheckedEvent)` への署名の変更と `WriteDigestsFile` (`--digests-out` の writer)。入力の reader (seats・render-record・前回の digests・event の edition。link を辿らない open。`editioninput.go`)。入力の形の誤り (`InputError`) と規則の違反 (`Violation`) を、呼び元が exit 2 / 1 に分けられる型で返す。review の fix: B10 は前回の (seat, cid) が今回に含まれなければ拒否する (共通 0 件の previous を通さない) | 要 | — | V54、V75、V77、V78、V86、V87 (検証: CI) |
| A4e-2b (#649) | `cmd/scoreboard` の `edition check` (`editioncmd.go` の `runEditionCheck`。引数の解釈・exit code の写像・stdout / stderr)。command は file を直接開かず、書かない。`CheckEvent` / `WriteDigestsFile` の呼び手の pin を、`internal/edition/load_source_test.go` の `doorViolations` の 1 つにした (review の fix)。`edition render` は未実装で exit 2 (A4e-3 まで) | 要 | CLI は先に merge してよい (platform はまだ呼ばない) | V3 (B の CLI)、V15 (check)、V72、V78、V79 (検証: CI) |
| F-fmt (#650、済み) | `scripts/fmt-check.sh` (`gofmt -l` の出力が空でなければ赤。gofmt 自体の失敗も赤、gofmt が無ければ exit 2) と、その自己検証 `scripts/test-fmt-check.sh`。`Dockerfile.test` が `go vet` の前に 2 本を直接走らせる (image に make が無いため。required の `test` の job は `Dockerfile.test` を build するだけなので、workflow は変えていない)。`make fmt-check` は host に gofmt がある機械のための同じ script の入口。未整形だった 3 file をこの PR で整形した。`Dockerfile.test` の変更なので Class-2 | — | — | V88 (検証: CI) |
| A4e-2c (#653、済み) | hint の入力 (journeys・narrative の override・rule の抜粋) の読み込みを、非 test の 1 つの関数に寄せる (今は `cmd/scoreboard/main.go`・`internal/hintleak/content_test.go`・`internal/edition/checkevent.go` の 3 か所の写し。#648 の review)。置き場は、データの型を持つ非 test の package で、server が表示に使う関数そのものにする (B5 は、server が見せる内容を検査する)。呼び手は server の起動・`CheckEvent`・`content_test.go`。あわせて、render-record の run id の不一致の規則名を T3 から B11 に直す (追補 13)。A4e-3 の前 | 要 (hintleak) | — | V89、V90 (検証: CI) |
| A4e-2d (#652、済み) | test の支援 package: `cmd/scoreboard` と `internal/edition` の test が複製している正の fixture の組み立て (席・答え表・束・render-record・edition root・corpus) を 1 つの package に寄せる。支援 package は renderer の関数 (`render_reach_test.go` の `renderCallers` が閉じている集合) を呼ばず、関数の値としても受けない。renderer の呼び出しは各 package の `_test.go` に残し、支援 package は renderer の出力 (bytes と dir) を受けて組み立てる部品 (席・corpus・layout の定数・入力の木の配置) だけを持つ (V78 の閉じた一覧は変えない。追補 13 の改訂、#651 R4#1)。非 test の file から import されないことを source test で固定する (#649 の review)。A4e-3 の往復の test (V80) はこれを使う | 要 | — | V91 (検証: CI) |
| A4e-3 (分割前の記述。実績は下の A4e-3a-i #654・A4e-3a-ii #655・A4e-3b の行) | `scoreboard edition render` と `--practice` (D20 の引数・出力の layout・手順、一時 dir → rename、自己検査、event の出力に digests を含めない、`--out` の git と `--challenges` の guard)、鍵の reader (`openRegular`。D20 の鍵の形と mode)、cmd の写像を、`*Violation` だけ 1・`*InputError` と未分類の error を 2・検査を全部通った後の書き出しの失敗だけ 3 に変える (render と check の両方。今の check は `*InputError` だけ 2、それ以外は 1、`WriteDigestsFile` の失敗は 2。`errors.Join` に 2 にあたる error と `*Violation` が混ざれば 2。追補 13 と改訂)、commit の後の後始末の失敗は exit 0 で残った名前を stderr に出す (D20 の exit 3 の節、追補 13 の改訂)、`RenderEvent` の呼び手の pin (V78)、`make edition-practice CID=<cid>` (export stage)、flag-guard の event の header の検査 (`scripts/check-flags.sh` の作法、R1) | 要 | CLI は先に merge してよい (platform はまだ呼ばない) | V67、V80、V81、V84、V87 (exit 3)、V92 (検証: CI) |
| A4e-3a-i (#654、済み) | check の側の exit 3 と commit の点: `writeFileAtomic` (一時 file → 書く → sync → `os.Link` → 一時名を消す) と `writeTreeAtomic` (一時 dir → rename) で、commit の前の失敗 (書き出しの失敗の型と、残った名前) と、commit の後の後始末の失敗 (警告) を分ける。cmd の写像 (`*Violation` だけ 1、書き出しの失敗だけ 3、それ以外は 2)。commit の後の後始末の失敗は exit 0 + stderr | 要 | — | V87 (exit 3)、V92 (check の分。library の seam の test と cmd の配線の source test の組) (検証: CI) |
| A4e-3a-ii (#655、済み) | `edition render` の event の分: `RenderEvent` (`eventrender.go`)、鍵の reader (D20 の鍵の形)、`--out` の guard (git の worktree の中・`--challenges` の中)、往復の test (render → check で exit 0)、`RenderEvent` の呼び手の pin | 要 | CLI は先に merge してよい (platform はまだ呼ばない) | V78 (`RenderEvent`)、V80、V92 (render の event の分) (検証: CI) |
| A4e-3b (分割前の記述。実績は下の A4e-3b-i #657・A4e-3b-ii #658 の行) | `edition render --practice` (renderer を呼んでよい 2 つ目の非 test の file。D20 の到達範囲)、`make edition-practice CID=<cid>`、`Dockerfile.edition-practice` (export stage)、flag-guard の event の header の検査 (`scripts/check-flags.sh` の作法)。V84 は、A4e-3 の分割でどの段にも割り当てられていなかったので、ここに置く (#655 R4#1、追補 14)。実績 (engineer の報告。PR は review の後): 実装の file は `internal/edition/practiceedition.go` (`RenderPracticeEdition(challenges, cid)`)、cmd は `runEditionRenderPractice`。置き換えは `replaceTreeAtomic` (一時 dir → 既存の `practice/` を退避 → rename = commit の点 → 退避を消す。commit の前の失敗は退避を戻す)。flag-guard は `scripts/check-edition-headers.sh` (`--selftest` つき) を `check-flags.sh` から呼ぶ (追跡中の file の行頭が V84 の event の header なら拒否する。練習版 = 全部 0 の run id は除く。除外は `internal/edition/testdata/digests-golden/digests.tsv` の名指しの 1 件)。`make edition-practice` は、export を一時 dir に出してから host の `practice/` を置き換える (`-o .` だと古い file が残るため)。`RenderEvent` の自己検査の配線の source test (V78) も、この段で足す (#656 R4#1) | 要 (Dockerfile・flag-guard) | — | V67、V78 (`RenderPracticeEdition` の呼び手と `RenderEvent` の自己検査の配線)、V80 (鍵の負の case のうち #655 に無い分)、V81、V84、V92 (`--practice` の分) (検証: CI) |
| A4e-3b-i (#657、済み) | header の guard: `scripts/check-edition-headers.sh` (`--selftest` つき) を `check-flags.sh` から呼ぶ。追跡中の file の行頭が V84 の event の header なら拒否する (練習版 = 全部 0 の run id は除く)。除外は `internal/edition/testdata/digests-golden/digests.tsv` の名指しの 1 件。header の無い束 (evidence だけ) の混入は見ない (#657 R4#1。A4e-3c で覆う) | 要 (flag-guard) | — | V84 (検証: flag-guard の CI) |
| A4e-3b-ii (#658、済み) | `edition render --practice` (`internal/edition/practiceedition.go` の `RenderPracticeEdition`、cmd は `runEditionRenderPractice`、置き換えは `replaceTreeAtomic`)、`make edition-practice CID=<cid>` と `Dockerfile.edition-practice` (D20 の実際の形)、`RenderEvent` の自己検査の配線の pin、鍵の負の case、`OutputError` の `Left` / `Restore`、commit された `practice/` の鮮度の test (`render_golden_test.go` の `practiceStale`) | 要 (Dockerfile) | — | V67、V78、V80 (鍵の負の case)、V81、V92 (`--practice` の分) (検証: CI) |
| A4e-3c (#660、済み) | evidence だけの混入の guard (追補 15、#657 R4#1): 追跡中の path に、event の `--out` の layout の `evidence/<seat>/<cid>/<file>` (seat は ADR-0042 の文法、cid は `challengeid.Pattern`) が現れたら、flag-guard が赤にする。練習版の layout (`practice/evidence/<file>`、席の dir が無い) はこの形に合わない。一致は部分一致: path の中のどの位置でも、segment の並び `evidence/<seat>/<cid>/` の後に 1 つ以上の segment が続けば赤 (`<file>` の入れ子を含む。`evidence`・seat・cid は segment の全体で照らす)。練習版の `practice/evidence/` の下の seat の形の入れ子も、同じ規則で赤。それ以外の入れ子は練習版の layout の誤りで、`practicelayout.go`・V11 (B2)・V81 (`practiceStale`) が持つ (shell に練習版の layout の 2 つ目の定義を作らない)。script の pattern の 3 つの部品 (evidence の dir 名・cid・seat の文法) は、Go の test が Go の定義と照らす (V93 の parity)。除外は名指しの testdata だけ。この PR に、app の `.claude/rules/dev-flow.md` の D (image) の行への `Dockerfile.edition-practice` の追記を同梱する (`.claude/rules/**` は Edit の deny の外。#659 R4#2)。`check-edition-headers.sh` に足した (新しい script にしていない。実績 #660、追補 16: seat の文法の正典は `internal/identity/seat.go` の `SeatPattern`、cid は `challengeid.Pattern`。どちらも ERE として同じ言語なので、byte のまま写した。除外の一覧は空。parity の test は `internal/edition/flagguard_evidence_internal_test.go`。dev-flow.md の D の行は、同梱して入った)。`check-flags.sh` から呼ぶ。A7 の前、A4e-4 と独立 | 要 (flag-guard) | — | V93 (検証: flag-guard の CI) |
| A4e-4 (#667、済み) | 行に入れるものは、D20 の「契約の分け方」の一覧 (追補 14)。 契約表の文面 2 の確定版の行 (D20 の CLI・file の形・痕跡束の部分。A5c-1 で後回しにした分を含む) と `internal/contracttable` の固定。実績 (#667、追補 18): (1) 契約表に 2 行 = CLI の行 (D20) と、痕跡束と払い出しの行 (D11・P1b-3。全部散文で、code span を置かない)。 (2) `internal/contracttable/editionrow_test.go` が、行の code span を、cmd の source (AST) と、fixture の event を `RenderEvent` → `CheckEvent` → `WriteDigests` に通した実際の出力と照らす (V82・V59・V92 の契約表の分)。 (3) `internal/edition/practice_layout_holders_test.go` が、練習版の layout の literal を持つ `charts/` と `scripts/` の shell の file の集合を閉じる (V85。範囲の外 = Makefile と `Dockerfile.edition-practice`。無関係な綴りを持つ file は、理由つきの除外の一覧)。 (4) ADR と違う形を追認した: 鍵の上限は、行に `4096` byte と書いた (`MaxKeyFileBytes` を export して照らす)。出力の mode は、定数ではなく、実際の出力を Stat して照らす (定数と実際の書き方がずれる余地を残さない)。 (5) 名前を付けた定数: `editioncmd.go` の subcommand と引数の名前 | 要 (contracttable) | P1b-2・P1b-3 と同時に open し、app の行を先に merge | V59、V82、V85 (検証: CI) |
| A4e (分割前の記述。廃止、D20 と A4e-1〜4 が正典。以下の旧文は参照しない) | `scoreboard edition check|render` の subcommand: 引数、exit 0/1/2、stderr に値を出さない、`--digests-out` (run id と digest)、表と digests の run id の一致、HTTP の path から render に届かないソース検査。答え表は M2 の入口 (`LoadEventTable` → `CheckedTable`) からだけ得る。B5 の入力は `internal/hintleak/scope` で組む。reader を O_NOFOLLOW + 開いた descriptor の `Stat` の照合にする (M2)。文面 2 の CLI の部分。digests の header と列の形を契約表と `internal/contracttable` で照らし合わせる。#640 から送られた 3 項目: (1) 練習版の file と PracticeSet を `CheckedTable` に載せる、(2) `checkPracticeOverlap` を validator の経路に配線する、(3) 重なり率を stderr に出す。加えて、調査型の課題が無い image で B4 を呼ばない判断、`edition render` を render の唯一の呼び手として source test に足す。`--previous-digests` (必須) と B10、B8 (a2) (S ≥ 2N を `--seats` の数で判定)、B7 の席の間の検査に template の lexer を渡す。前提は A4b-2・A4c-1・A4c-2b・A4d-2a〜c | 要 | CLI ↔ P1b-2 | V3 (B の CLI)、V15 (check) (検証: Go は CI、`docker run` の経路は手元不可 = P1b-2 の stub の selftest だけ) |
| A4 (分割前の記述) | `internal/edition` の束の検査 (B1〜B9)・renderer・`edition check|render` の subcommand・testdata | 要 | CLI ↔ P1b | V3 (B)、V4、V6 (b)、V11、V15 (check)、V16 (Go)、V18、V19 |
| A5a-1 (#619) | gen-values の `--check` に `mountDir` の検査を入れた。規則は D1 の (a)(a2)(b)(c) と fail-closed の規則で、ADR の元の文面より厳しい。ADR-0055 C4 (ii) の実装を兼ねる。`reservedMountRoots` と SEED_ROOT / SNAPSHOT_ROOT の parity、`INVESTIGATE_TYPE` の parity の test | 要 | — | V28、V29、V42 |
| A5a-2 (#629) | gen-values: plant の導出を type から行う (evade の plant.sh ∪ 調査型。調査型が plant.sh を持つのは拒否)。調査型の `plant.mounts` の entry (`evidence: true`。D11 の形では `challenge: <cid>` も)。copy の形の定義 `render_evidence_copy` (D11 の J5 の形。列挙は A5b の chart)。2-7(a) に `/opt/ctf/evidence-src/<cid>/<素の file 名>` | 要 | — | V8 (2-7(a))、内部 fixture (正の tree と違反 43 通り)、生成物は byte で不変 (検証: CI) |
| A5b (#632。追補 6 の L2) | chart: Secret は render せず、`ctf-evidence-<cid>` を名前で参照して plant にだけ mount する (L2)。values は `.Values.evidence.challenges.<cid>.names`。helm の `fail` は D11 の K2 の一覧 (名前の文法は B2、1〜64 個、重複、`plant.mounts` の `challenge` と values の key の集合の一致、seedScript の形)。`ctf-evidence-secret.yaml` と、内容の大きさの検査は #632 から外す (上限は A5c と validator)。plant の copy 行を values の key から byte 順に render する。`reservedMountRoots` に `/opt/ctf/evidence-src` を足す (gen-values との parity)。plant に `/opt/ctf/evidence-src` を readOnly で、challenge に seed の subPath を mount。`scripts/check-flag-isolation.sh` に「`ctf-evidence` は plant にだけ mount される」の静的検査。A5a-2 の後 | 要 (pod.yaml・check-flag-isolation) | — | V2 (ctf-user の sentinel)、V8 (helm の `fail`)、V43、V44 (検証: chart-lint / flag-guard の CI) |
| A5c-1 (#638) | `deploy-user.sh --evidence-dir --evidence-digests`: fail-closed (D11。スコープに調査型があるのに evidence の引数が無く、`--flags-file` があれば拒否。3 つとも無ければ、練習版の経路 (A5c-2) ができるまでは非ゼロで終了する)、digest の shell 側 (A4b の case 表を読む)。Secret `ctf-evidence-<cid>` を helm の前に `kubectl create secret generic --from-file=<name>=<path>` で作る (毎回作り直し、スコープに無いものは消す、client-side の apply は使わない)。大きさの上限 (課題ごとに 512 KiB、合計 2 MiB) を cluster に触れる前に数える。`names` を chart に渡す。契約表の文面 2 の痕跡束の行は、P1b-3 と同時の docs PR に回した (#638 の決定)。follow-up: 束を private な dir に 1 回 copy してから照合と Secret の作成をすること、create と label を 1 回の書き込みにすること。文面 2 の痕跡束の部分。A4b・A5b の後 | 要 | 行 ↔ P1b-3 | V16 (shell)、V17 (検証: flag-guard の CI。helm / kubectl は stub) |
| A5c-2 (#662、済み) | local の練習版の deploy の経路 (D11 の追補 9): 3 つの引数がどれも無く、スコープに調査型があるとき、`CHALLENGES_DIR/<cid>/edition/practice/` の `digests.tsv` (run id が 0、席 `*`) で `evidence/` を照合し、そこから `ctf-evidence-<cid>` と `names` を作る。`ParsePracticeDigests` を足し、deploy-user の練習版の経路でも同じ規則を当てる (D9。イベントの `ParseDigests` は変えない)。A5c-1 の後、A7 の前。練習版の file は fixture の木で test する。実績と追認した仮決め (#662、追補 16): 3 つの引数 = `--flags-file`・`--evidence-dir`・`--evidence-digests`。練習版の木の誤り (無い・形が違う・digest が合わない) は exit 1、引数の組の誤りは exit 2。digests は自課題の 1 行だけ。途中の dir (`<cid>/`・`edition/`・`practice/`・`evidence/`) が link なら拒否する。`practice/` の中の余分な entry は拒否しない (layout は V81 と `practicelayout.go` が持つ)。kube context は見ない (platform の担当。P1b-3)。`ParsePracticeDigests` は `ParseDigests` と行の文法を共有する。V85 の一部 (`practice_deploy_layout_test.go`) を足した。運用の注意: 3 つとも無しで呼ぶと練習版を配る (A5c-1 までは拒否していた) = platform の `--dev-flags` の経路。イベントの払い出しの引数は scope で決まる: 調査型の課題を含む scope は 3 つ、evade だけの scope は `--flags-file` だけ。local でない経路で、3 つとも無い呼び出しは作らない (P1b-3。追補 18) | 要 | — | V65、V66 (検証: flag-guard の CI。kubectl / helm は stub) |
| A5d (#663、済み) | `assert-flag-isolation.sh` の 3-x (`mountDir` の中の symlink が 0 で通常 file だけ、seat の ns の Secret 名 = {ctf-flags} ∪ {ctf-evidence-<cid> | cid はスコープの調査型})。V53 (catalog の mountDir の集合と commit 済みの生成物の `evidence: true` の path の集合の一致、Go の test)。`check-flag-isolation.sh` の実 scope (values-all・scenario) に調査型が入ったときの `names` の出所 = その課題の公開の練習版の束 (`challenges/<cid>/edition/practice/evidence/` の file 名。`answers.tsv` と `digests.tsv` は束ではないので入らない) と、scope ごとの期待する `ctf-evidence-*` の集合の導出。challenge から `/opt/ctf/evidence-src` が見えないことの実行時の assert (`assert-flag-isolation.sh`、3-4 と同じ作法) は A5c。A5b の後。実績 (#663、追補 16): 3-x の (1) は 3-9、(2) は 3-10 (D11。(2) は閉じた集合)。期待の集合は、helm に渡した values の `evidence: true` の項から、assert の中の builtin だけの reader で読む (shell の 3 つ目の reader。D11)。V53 は `internal/catalog/evidence_mount_parity_test.go` (今は両側が空で、A7 から効く)。`check-flag-isolation.sh` の names の出所は公開の練習版の束で、名前は gen-values の 5 つ目の入口 `--check-evidence-names` と、共有の `evidence_bundle_digest` を通す。challenge から `/opt/ctf/evidence-src` が見えないことの assert は、既に 3-4 にあった。V85 の一部も足した。3-x の (3) は A5e、(4) は V50・V51 (D11) | 要 | — | V8 (3-x)、V2 (Secret 名) (検証: stub の test は CI、実 cluster は実機でのみ) |
| A5 (分割前の記述) | ctf-user の `ctf-evidence`、plant の一般化、gen-values の 2-7、3-x、deploy-user の `--evidence-*`、helm の `fail`、契約表の新しい行。gen-values の `--check` に `mountDir` の検査 (sensitive_dir_prefixes の外であること、全 plant-target の書き込み先と file が互いに素であること (ADR-0055 C4 (ii)。先に着地した側の検査を 1 つの実装として使う)) を入れる。`reservedMountRoots` と gen-values の SEED_ROOT / SNAPSHOT_ROOT の parity の test | 要 | 行 ↔ P1b | V2 (ctf-user)、V8、V16 (shell)、V17、V28、V29 |
| A6 (#626) | portal の回答欄 (application-engineer)。未到達 (locked) の課題でも回答できる (ADR-0027 の free browsing。既存の flag 欄と同じ。CoS の決定、test で固定)。前提は A3b-1〜3 (#620〜#622) で、満たした。範囲は次のとおり。prompt は `esc()` を通す。`status` (と `correct` / `solved` / `remaining`) だけで分岐し、文言は portal が持つ。正解済みで未 solve の設問には再提出の口を残す (D5 の 5)。400 (形式が違う、回数は減らない)・429・500 をそれぞれ表示する。500 の表示は「採点できなかった。回数は消費済みのことがある」とし、再描画 (journey) で実際の残りを見せる (D5 の 3〜5 に合わせる。文言は portal の実装が正)。journey の 500 (H2) では、前の表示を残す。local で通しで確かめるには A4a-2 が要る | — | — | V40 (検証: 生成型と template の test、goja = ADR-0035) |
| A5e (#665、済み) | 3-x の (3) (追補 16、#663 R2#1・R4#1・R4#3): deploy-user.sh が helm に渡した values の file を、`assert-flag-isolation.sh` に引数で渡す (5 つ目の引数。実績は行の末尾)。assert は渡された file だけを読み、values の file を自分で選ぶ規則 (実装では 3 通りの分岐だった。#665 で消した) を消す。そのうえで、seat の ns の `ctf-evidence-<cid>` の key の集合が、deploy-user が helm に渡すのと同じ導出の `names` と一致することを確かめる。V95 の case のうち #663 の test に無いものも、ここで足す。V51 の rehearsal の前。A7 の直接の前提ではない (A7 の前提の V51 の実測を介してだけ、A7 より前に要る。#664 R2#1)。実績 (#665、追補 17): (1) 呼び方は `assert-flag-isolation.sh <ns> <challenges-dir> <challenge-id> <scenarios-dir> <values-file|-> [<cid>/<name>...]`。5 つ目が無い・空なら exit 2。`-` (values を helm に渡していない) は単一課題の mode だけで許し、`all` / `scenario:*` の mode での `-` は exit 2 (deploy-user は、この 2 つの mode で必ず values の file を helm に渡す)。 (2) `<cid>/<name>` は、deploy-user が helm に渡す names と同じ loop の導出から渡す。(3) の番号は 3-11。 (3) V94 の受け渡しは、挙動の test (`scripts/check-deploy-user-evidence.sh`、4 通り、mutant 3 つ) で確かめる。test 用の切り替え `CT_HELM_UPGRADE_PASS` は harness の stub の中だけにあり、本番の script は読まない。 (4) V95 のうち #665 で足した case は、type `kubernetes.io/dockerconfigjson` の Secret の 1 件 (ほかは #663 の test にあった)。 | 要 (assert-flag-isolation・deploy-user) | P1b-3 (assert の呼び方を platform の runbook に合わせる) | V94、V95 (検証: flag-guard の CI。kubectl / helm は stub) |
| A4e-5 (#671、済み) | 空の scenario の明示の形 (追補 18): `edition render` と `edition check` に `--all-challenges` を足す (`--scenario <file>` と排他で、どちらか一方が必須。空の値の `--scenario` は今どおり exit 2)。scope は、scenario の無い `catalog.LoadScored` (scoreboard の `scoreboardScenario` が空の起動と同じ)。契約表の CLI の行に code span を足し、V82 で照らす。P1b-2c の前。実績 (#671、追補 19): (1) `edition.CheckInput` と `RenderEventInput` に `AllChallenges bool` を足した (空の文字列に意味を持たせない)。(2) `LoadScored` の呼び方と、renderer の呼び手の閉じた集合は変えていない。(3) 契約表の CLI の行: synopsis と引数に `--all-challenges`、「どれも必須」を「2 つの排他の組はちょうど一方、ほかは必須」に直した。(4) V96 = 4 通りの組 × render / check、fixture での比較、`--all-challenges` の round trip、V82 の変異 8 件。(5) `render --practice` に `--all-challenges` を混ぜると、unknown argument で exit 2 (名指しの拒否ではない。exit code が同じなので許す) | 要 (contracttable) | P1b-2c と対 (platform は、A4e-5 を pin してから、空の scenario を `--all-challenges` に写す) | V96、V82 (検証: CI) |
| A4e-6 (#674。追補 20 と同じ PR) | 生成の scope の記録と B12 (追補 19): (1) render-record を v2 にし、4 行目に `scope<TAB><64 桁の hex>` を足す (D20 の file の形)。(2) `edition check` に B12。(3) 契約表の render-record の記述を v2 の 4 行に直す: header の code span を `# falco-ctf render-record v2` に、「3 行」を「4 行」に、4 行目の `scope<TAB><64 桁の hex>` を code span で足し、規則の意味に B12 (render と check の scope の一致。platform は render と check に同じ出所の scope を渡す) を足す。V82 で照らす (#672 R4#3)。(4) V84 の header の定数と `scripts/check-edition-headers.sh` に v2 の render-record の header を足す (v1 も拒否のまま残す。#672 R2#4)。V85 の走査の範囲の拡張は A4e-6b に分けた (#672 R4#5)。P1b-2b (platform#339) の本番の最初の生成の前。実績 (#674、追補 20): (1) `internal/edition/scopedigest.go` の `ScopeDigest(ids []string)` を、`WriteRenderRecord` と `CheckEvent` の両方が呼ぶ (digest の 1 定義)。(2) B12 は `LoadScored` の直後 (step 1b)。reader は `parseRenderRecord` (v2 だけ)。(3) golden = `internal/edition/testdata/scope-digest/cases.tsv` (1 件・2 件・順序違い。digest の値は `printf` と `shasum -a 256` で手計算したもので、実装の出力から写していない)。(4) 契約表の行は v2 の 4 行と B12 (placeholder は `scope<TAB><scope digest>`)。(5) V84 の guard に v2 の header を足した (v1 も拒否のまま)。(6) 練習版は render-record を持たないので変更なし。(7) check の結果に効く scenario 由来の入力を確かめ、D10 の B12 に記録した | 要 (contracttable) | platform の render-record の reader を v2 (header と 4 行、scope の行) に上げる PR と同時 (platform#340 で済んだ = reader の v2 化・`--all-challenges`・scope の出所 (V97・V99)・APP_PIN → a4a7b393 を、同じ 1 つの PR にした。追補 21) = 課金前の gate の lib (P1b-2a #336、main 入り。今は v1 の header と 3 行ちょうどを要求する) と、同じ lib で読む段 P (P1b-2b #339)。A4e-6 を pin する APP_PIN の bump (A4e-6 以後を pin する) と同じ 1 つの PR (別の PR にすると、間の platform の main で、段 P / 段 S の gate が v1 と v2 の食い違いで止まる。platform には required check が無いので、ずれを機械で捕まえられない。review 2 の R4#2)。両リポ同時 PR (#672 R4#1) | V98、V99、V84、V82 (検証: app は CI、platform は V99 の selftest) |
| A4e-6b (#673、済み) | V85 の走査の範囲に、Makefile の `edition-practice` の target と `Dockerfile.edition-practice` を足す (追補 19 の改訂、#672 R4#5。練習版の layout の parity で、A4e-6 の scope の記録とは関心が別。A4e-6 は platform の PR と対で待つので、分けて先に入れてよい) | 要 | — | V85 (検証: CI) |
| A7 | **前提**: merge 済みは A1d #611・A1e #612・A1f #618・A3b-1〜5 #620〜#622・#627・#625・A4a-1 #628・A4a-2 #630・A4a-3 #631・A5a-1 #619・A5a-2 #629・A5b #632・A4b-1 #633・A6 #626。残りは V51 の実測 (CEO の手。A4e-5 は #671 で済んだ。A4e-4 は #667、A5e は #665 で済んだ。V53 は今は両側が空で緑、A7 で非空になる) (設問に `technique` を使うなら A1c も。済んだのは A4b-2 #634・A4c-1 #635・A4d-1a #636・A4d-1b #637・A5c-1 #638・A4c-2a #639・A4c-2b #640・A4d-2a #642・A4d-2b #643・A4d-2c #644・A4e-1 #646・A4e-2a #648・A4e-2b #649・F-fmt #650・A4e-2d #652・A4e-2c #653・A4e-3a-i #654・A4e-3a-ii #655・A4e-3b-i #657・A4e-3b-ii #658・A4e-3c #660・A4c-3 #661・A5c-2 #662・A5d #663・A5e #665・A4e-4 #667・A4e-5 #671・A4e-6b #673・A4e-6 #674)。A7 の課題の `practice/` は、`edition render --practice` (A4e-3b-ii #658) で作る。A7 の課題は `edition/practice/` を追補 9 の layout で持ち、V67 (golden) が緑。A5c の merge までは、調査型の課題を main に置かず、イベントの values に `evidence.challenges` を渡さない (Secret を作る者がいないので Pod が起動しない)。platform が `evidence` を渡す P1b-3 は A5c の後。A7 では V47 の実 tree の検査を非空の要求に反転させる。課題を置くコースは V39 を満たす。**課題 id は、全 evade の課題の id より大きくする**。scenario の無い順序 (課題 id の順) でも `LoadScored` が拒否するため (今の evade は 03・05・10)。調査型の課題を main に置く前に、platform の P1b-2 (イベントで (5) の run id が全部 0 なら FAIL) と P1b-1b (render gate) を merge する (イベントで `FLAGS_FILE` が空のまま起動すると、公開の練習版の答えで採点が始まる誤設定を、platform の側で止めるため)。新しい課題の練習版 (content-engineer) | 要 (fixtures と同じ扱い) | — | V11 (golden)、V3 を練習版で緑、V22 (実課題の `edition/**` が image に無い)、V27 を反転 |
| P1a (platform#332) | `verify.sh` の `[flags]`: (4) があれば FAIL。(5) の最新の 1 行の `run_id` が 32 桁の小文字 hex でなければ FAIL、正しければ報告する。(5) が無いときは、Deployment に `ANSWERS_FILE` が無ければ「表が要らない起動」、あれば「未検証」、env を読めなければ「未検証」とし、失敗にはしない。digests の run id との照合は P1b-2 | 要 | app#613 と対 (P1a が先) | V32 |
| P1b-1a | helmfile: イベントの設定で明示したときだけ `answersSecret` を有効にする (Secret 名と key は契約表の「答え表」の行)。ここでは render gate を持たない。調査型があるのに表が無い場合の fail-closed は、scoreboard の起動時の拒否 (D8 (i)) と P1a の (4) の FAIL が担う | 要 | A4-0 と同時 | V12 (有効化の部分) |
| P1b-1b | helmfile: local 以外で `requirements.answers` が空でないのに `answersSecret` が無効なら、render を失敗させる (D8)。前提: ADR-0055 S3 の生成物の `requirements:` が app にあること (main にはまだ無い)。S3 の後に入れる | 要 | ADR-0055 S3 の app PR の後 | V12 (render gate) |
| P1b-2 (platform#335 を含む) | 課金の前に `edition render` → `edition check` を行う (pin した scoreboard image、docker)。出力 (表・束・digests) の置き場 (sops)。表と digests の run id の照合 (digests は `seat<TAB>cid<TAB>digest`)。verify の (5) と digests の照合、run id が全部 0 なら FAIL。platform#335 の項目: scoreboard の答え表の Secret を Deployment より先に作る順序と preflight、namespace の固定、Secret の name / key を app の契約表の行 (`answersSecret` の既定値) と照合すること、pin した app の chart が #614 以降であることの gate。追補 10 の改訂: イベントごとに前回の席の list・digests・鍵の指紋を sops に残す。render には `--previous-seats`、check には `--previous-digests` (前回の `edition check` の `--digests-out`) を渡す。初回は両方に `--no-previous` を渡す。`--previous-*` と `--no-previous` のどちらも無い、または両方あれば FAIL。新しい鍵の指紋が過去のイベントの台帳と一致すれば FAIL。追補 18: (1) 分割 = P1b-2a (platform#336、main 入り = CEO の承認、CI の証跡なし = 手元の selftest。中身は 課金前の gate の lib + 段 S の gate + selftest。新規の file だけで、未配線)。残り = P1b-2b (platform#339 = 段 P の script: `--first` / `--extend` / `--rekey`。済み。(3) の (a)(b) を含む)。P1b-2f (platform#342) と、render-record の reader の v2 化 + APP_PIN の bump (platform#340)、払い出しの selftest の CI (platform#341) も済んだ (追補 21)。残り = P1b-2c (段 S の配線。終了の印の検査 = P1b-2g の (4) を含む)・P1b-2d・P1b-2e・P1b-2g、gate の selftest の分割と CI の job、契約の literal の parity (中身は platform#335)。追補 19: (i) CEO の決定 (2026-11-19、推奨どおり) = 段 P (生成) と段 S (課金の前の gate と払い出し) の 2 段、版の原稿は private repo の平文、1 回の生成 = 1 つの sops の tar、鍵の指紋の台帳 = ops 所有の state file と、署名された tree の生成の表の和、同じイベントの延長は同じ鍵。(i') 台帳の照合は mode で分ける (#339 の段 P、追補 19 の改訂、#672 R1#1): `--first` / `--rekey` = 新しい鍵の指紋が、ops の台帳と全 event の生成の表のどこにも無いこと (一致で FAIL)。`--extend` = 保存したその event の鍵を復号して使い、指紋が今回の event の生成の表の最新の行と同じこと (違えば FAIL)。延長は台帳に行を足さない。event の同一性は、署名された tree の生成の表が持つ event の名前で決め、env や引数の自由な文字列からは決めない。`--extend` は、その event の生成の表が無い・0 行・同じ名前が台帳に 2 つ以上ある・その event が終了の印を持つ、のどれかで FAIL (終了した過去の event を「今回」と名乗って同じ鍵を使い、イベントをまたいで答えを同じにする経路を閉じる)。終了の印は、teardown が ops の台帳に書く (P1b-2f。書けなければ teardown は fail-loud。V100)。P1b-2f が入るまでの間は、台帳の形の版が P1b-2f の形でなければ `--extend` を FAIL にする (印を書く側が無い台帳では、終了した event を見分けられないため。延長が要るなら `--first` で新しい鍵を作る。追補 19 の改訂 2、review 2 の R1#1 = R4#1)。(ii) 段 P と段 S の scope の束ねは、app の B12 (render-record の scope の digest) が持つ。段 S の check は、段 P と違う scope を受ければ exit 1。platform は生成の表に scope の名前を人のための記録として持ってよいが、照合の正典にしない。(iii) image の版を変えた後の段 P のやり直しは、まず `--extend` (同じ鍵・同じ席の list。前回と同じ list は E3 の接頭辞として通る。束が byte で同じなら B10 も通る)。check が B10 で拒否したら、配った束が変わる = 自動で `--rekey` に進まず、止めて COO が判断する。配り直すなら `--no-previous` を render と check の両方に渡す (Signpost 15)。同じイベントなら同じ鍵でよい ((i) の決定)。`--rekey` は、鍵を替える理由 (漏えいの疑い・イベントをまたぐ) があるときだけ。 (2) scope の受け渡し (P1b-2c の前の要件): scoreboard の `scoreboardScenario` が空 (全部の課題) なら、`edition render` / `edition check` に `--all-challenges` を渡す。空でなければ、同じ scenario の file を `--scenario` に渡す。課金前の gate は、scoreboard の scope と render / check に渡した scope が同じ値の出所から来ることを確かめ、違えば FAIL (V97)。同じ出所の scenario を渡すことで、check の B5 と scoreboard の起動が、同じ `narrative.yaml` (scenario と同じ dir) を読むことも担保する (narrative は B12 の digest に入らないので、この一致は platform の要件で守る。追補 20)。A4e-5 を pin するまでは、#336 の「空なら FAIL」の仮決めのままでよい。 (3) platform の仮決めの追認: (a) 保管する生成の束 (sops の tar) に、render に渡した版の原稿 (`--edition-root` の木) の写しを入れる (後の `edition check` と B10 の再検査が、同じ原稿を要るため)。 (b) 課金前の gate の image は、その `appImageTag` の release scan の要約にある scoreboard の `repo_digest` を使う。生成の表の `image_digest` と違えば、INFO ではなく FAIL にする (B4 の練習版と B9 の corpus は image の中身なので、検査した image と配る image が違えば検査が意味を失う) | 要 | A4e・A4a-2 と対 | V12 (gate)、V15 (platform) (検証: docker の経路は手元不可、stub の selftest) |
| P1b-2f (platform#342、済み) | teardown が ops の台帳に、その event の終了の印を書く (追補 19 の改訂 2、CTO 代行の決定、review 2 の R1#1 = R4#1)。(1) 印を書けなかったら、teardown は fail-loud (非ゼロで終わり、印が無いことを報告する)。(2) 台帳の形の版を、終了の印の欄を持つ形に上げる。段 P の `--extend` は、台帳がこの版でなければ FAIL (P1b-2 の行の (i'))。(3) 期限 = 調査型の課題を含む最初のイベントの teardown の前、かつ段 P を ops で最初に実行する前。実績 (platform#342、追補 21): 台帳の形を v2 に上げ、teardown の最後の独立した step が終了の印を書く (書けなければ fail-loud)。event は明示の event の dir だけで決める。段 P は、台帳が v2 でなければ全部の mode で FAIL。ADR に無かった規則を 2 つ追認した: (x) `--first` は、台帳で一度使われた event の名前なら FAIL (event の同一性が 2 つの鍵に分かれ、`--extend` の照合の前提が崩れるため)。(y) `--rekey` は、終了の印のある event なら FAIL (終わった event の鍵を替えることは、その event の再開と同じため)。細目は platform#335 | 要 | P1b-2b と対 (`--extend` の、台帳の版の検査) | V100 (検証: platform の selftest。platform には required check が無いので、merge の時に人が確かめる) |
| P1b-2g | 終わりでない teardown と、終わった event の束の再配布の拒否 (追補 21、platform#342 の review の R4 と R1 の LOW)。(1) teardown の既定は、終了の印を書く (今の形のまま)。event の終わりでない teardown (開催中の cluster の作り直し、stand-up のやり直し) だけ、理由を要求する明示の引数で印を書かず、その理由を台帳に追記の行として残す (env や手順から推さない)。(2) rehearsal は、本番と別の event の名前で行う (rehearsal の teardown は、その event の終了の印を書く)。(3) local でない teardown は、event の dir か「この event は版を使わない」という明示の宣言のどちらかを要求する (印が要らないことを、この機械の台帳と tree から推さない)。(4) 段 S の gate (P1b-2c) と払い出しの lib (P1b-3b) は、event に終了の印があれば FAIL (終わった event の既存の束を、別の開催として配る経路を閉じる)。細目は platform#335 | 要 | P1b-2c・P1b-3b と対 | V101 (検証: platform の selftest。platform には required check が無いので、merge の時に人が確かめる) |
| P1b-3 | 払い出しが seat ごとに `--evidence-dir --evidence-digests` を渡す。束の出所を明示する (D8)。追補 16 の要件: イベントの払い出しの引数は scope で決まる (追補 18 で直した): 調査型の課題を含む scope は 3 つ (`--flags-file`・`--evidence-dir`・`--evidence-digests`)、evade だけの scope は `--flags-file` だけ。local でない経路で、3 つとも無い呼び出しは作らない (3 つとも無いと、A5c-2 から練習版を配る = `--dev-flags` の経路)。 (1) 分割 = P1b-3a (platform#337、main 入り = CEO の承認、CI の証跡なし = 手元の selftest。中身は 払い出しの判定の lib + selftest。新規の file だけで、未配線)。P1b-3c (platform#338 = 払い出しの runbook) は済んだ。残り = P1b-3b (払い出しの配線。終了の印のある event の束を配らない = P1b-2g の (4)。追補 21)。 (2) platform の仮決めの追認 (追補 18): (c) 払い出しの lib は、全部 0 の run id (練習版) の digests を、local でも拒否する (練習版の経路は deploy-user の「3 つとも無い」呼び出しだけで、lib を通らない)。 (d) 払い出しの lib は、flags の file・束の dir・digests の file に「運用者だけが書ける・symlink でない」を要求する (D9 の「入力の木は運用者の所有」の前提を、払い出しの入力にも当てる)。seat の ns に置く Secret は閉じた集合 (D11 の 3-10: type `Opaque` の {`ctf-flags`} ∪ {`ctf-evidence-<cid>`} と、Helm の release の記録だけ。image の pull の Secret などを seat の ns に置かない)。A5e (#665) の後の呼び方 (`assert-flag-isolation.sh <ns> <challenges-dir> <challenge-id> <scenarios-dir> <values-file|-> [<cid>/<name>...]`。D19 の A5e の行。engineer が確かめた範囲では、platform の docs と scripts に assert を直接呼ぶ箇所は無い。CoS が platform#335 に追記した) に、runbook を合わせる。platform の `docs/operations.md` と `docs/prod-deploy.md` の「3-9」の参照 (ADR-0026 の missions の allowlist の意味。app ではその検査は 3-8) を直し、3-9 / 3-10 を D11 の新しい意味にする (誤記の 3 行は CoS が platform#335 に記録した。追補 16 の改訂、#664 R4#3)。3-10 は evade だけの scope にも効くので、次の APP_PIN の bump の verify / rehearsal で確かめる (D11) | 要 | A5c と対 | V12 (払い出し)、V17 (platform 側) |
| P2 (platform#333、open) | rollback の runbook を DB の版 3 に対応させ、PVC の写しでリハーサルする | — | — | 実機でのみ確認可 (リハーサルの記録) |
| P1a / P1b (分割前の記述) | platform: helmfile の render gate、束の出所の明示、課金前の render → check、digests、seat の Secret の作成、`verify.sh` の (4)、イベント版の置き場 (sops) | 要 | 上の app PR と対 | V12 |
| D1 | detect の hold-out (app + platform)。#341 の後 | 要 | detect-grader の行 | V7 |

- 順序 (2026-11-16 時点)
  - merge 済み: A0 #605 → A1a #606 → A1b #607 → A2a #610 → A1d #611 → A1e #612 → A2b-go #613 (P1a = platform#332 が先) → A2b-chart #614 → A3a-1 #615 → A3a-2 #616 → 追補 3 #617 → A1f #618 → A5a-1 #619 → A3b-1 #620 → A3b-2 #621 → A3b-3 #622 → 追補 4 → A4-0 #624 → A3b-5 #625 → A6 #626 → A3b-4 #627 → A4a-1 #628 → 追補 5 → A5a-2 #629 → A4a-2 #630 → A4a-3 #631 → 追補 6 と A5b #632 → A4b-1 #633 → 追補 7 と A4b-2 #634 → A4c-1 #635 → 追補 8・9 と A4d-1a #636 → A4d-1b #637 → A5c-1 #638 → A4c-2a #639 → A4c-2b #640 → 追補 10 と改訂 #641 → A4d-2a #642 → A4d-2b #643 → A4d-2c #644 → 追補 11 と改訂 #645 → A4e-1 #646 → 追補 12 #647 → A4e-2a #648 → A4e-2b #649 → F-fmt #650 → 追補 13 と改訂 #651 → A4e-2d #652 → A4e-2c #653 → A4e-3a-i #654 → A4e-3a-ii #655 → 追補 14 と改訂 #656 → A4e-3b-i #657 → A4e-3b-ii #658 → 追補 15 と改訂 #659 → A4e-3c #660 → A4c-3 #661 → A5c-2 #662 → A5d #663 → 追補 16 と改訂 #664 → A5e #665 → 追補 17 → A4e-4 #667 → 追補 18 (#668) → A4e-5 #671 → 追補 19 (#672) → A4e-6b #673 → A4e-6 と追補 20 #674 → 追補 21。platform の P1b-1a #334 も merge 済み。
  - 残りは 3 列で進める (並列は WIP の枠と stacked の深さ 2 の範囲で)。
    - (列 1) 完了 (A6 #626・A3b-4 #627・A3b-5 #625)。
    - (列 2) app の実装の段は全部済んだ (A4e-6 は #674、A4e-6b は #673)。platform の側で済んだもの: P1b-2a #336・P1b-2b #339・P1b-2f #342・P1b-3a #337・P1b-3c #338、render-record の reader の v2 化と APP_PIN の bump #340 (同じ 1 つの PR)、払い出しの selftest の CI #341 (追補 21)。残りは platform の側: P1b-2c (段 S の配線と、終了の印の検査)・P1b-2d・P1b-2e・P1b-2g (終わりでない teardown)・P1b-3b、gate の selftest の分割と CI の job、契約の literal の parity。app の側は V51 の実測と A7 (どちらも CEO)。A4e-5 は #671 で済んだ。A4e-4 は #667 で済んだ。platform の列: P1b-2a #336・P1b-3a #337 は済んだ → P1b-2b #339 (修正中)・P1b-3c #338 (CEO の確認待ち) → P1b-2c〜2e・P1b-3b。A4e-3c は #660 で済んだ。A4e-3b は #657・#658 で済んだ。F-fmt は #650 で済んだ。A4e-2d は #652、A4e-2c は #653、A4e-3a は #654・#655 で済んだ。A4c-3 は #661 で済んだ。A4e-1 は #646、A4e-2 は #648・#649 で済んだ。
    - (列 3) A5e (#665、済み) → V51 の実測 (P1b-3 の rehearsal)。A5c-1 は #638、A5c-2 は #662、A5d は #663 で済んだ。A5b は #632 で済んだ。
  - 最後に A7 → platform の `APP_PIN` の bump。A1c は `technique` を使うときだけ、A7 の前に入れる。
- (分割前の順序): A1a → A1b → A1d / A1e (触る file が別なので並行してよい) → A2a → A2b (+ P1a) → A3a → A4 (+ P1b) → A5 (+ P1b) → A3b → A6 → A7 → platform の `APP_PIN` の bump。A1c は `technique` を使うときだけ、A7 の前に入れる。
- A3b を A5 の後に置く理由: `mountDir` の sensitive dir と互いに素の検査は gen-values にあり、Go の catalog には写さない (写すと 2 つ目の一覧になる、`internal/catalog/investigate.go:115-119`)。拒否を外す前に、その検査が main に要る。前提になるのは A5 のうち A5a-1 だけ (G16)。
- platform のゲートを先に適用する (ADR-0033 D9 (g))。stacked の深さは 2 以内。
- #608 の 8 件の割り当て: MED 1 → A1d / A3b、MED 2 → A1e、MED 3 → A3b の前提、LOW 4 件 → A1d、LOW (`reservedMountRoots`) → A5。

### D20 版の検査と生成の CLI (A4e。追補 11)

D9・D11・D12・D16 の「A4e に送る」は、すべてここに集める。順序と fail-closed の規則は `internal/edition` の `CheckEvent` / `RenderEvent` が持つ。file の reader (O_NOFOLLOW + Stat の照合) と原子的な writer (一時の file / dir → rename、mode の固定) も `internal/edition` が持つ。`cmd/scoreboard` は、引数の解釈・error から exit code への写像・stdout / stderr への出力だけを持つ。

**入口**: `scoreboard edition check …` と `scoreboard edition render …`。`main` は、argv[1] が `edition` のときだけ subcommand に分かれる。subcommand は server を起動しない。HTTP の server の path から subcommand の code には届かない (V78)。

**file の形** (どれも UTF-8・LF・通常 file。`openRegular` = O_NOFOLLOW|O_NONBLOCK で開き、開いた descriptor の Stat と照らし合わせる (V57)。保証は path の最後の要素まで (D9)。seats・`--previous-digests`・render-record の reader は A4e-2a (#648) が `openRegular` で作った (`--previous-seats` は seats の reader を使う)。鍵の reader は A4e-3 が `openRegular` で作る)
- seats: 1 行目が `# falco-ctf seats v1`、以降は 1 行 1 席 (ADR-0042 の文法)。順序あり、重複なし、空行とコメントなし。追記だけ (D12 の U2)。`--seats` は 1 席以上。
- previous: `--previous-seats` は seats の形で 1 席以上、`--previous-digests` は digests の形で 1 行以上。header だけ (0 席 / 0 行) の file は exit 2 (初回は `--no-previous` でしか表さない。途中で切れた file を初回と読まないため)。library でも、`PreviousSeatsOf` に空の list を渡すと「与えられていない」と同じ扱いになり、`Render` が E3 で拒否する。B10 も 0 行の previous を拒否する。
- 鍵: 小文字 hex の 1 行と、末尾の LF 1 つ (必須。LF が無い file は、途中で切れた書き込みとして拒否する。CR・空白・2 行目は不可)。偶数桁かつ 64 桁以上 (32 byte 以上 = `MinMasterKeyBytes` × 2 桁)。file は 4 KiB 以下。group と other が読めないこと (mode & 0o077 == 0)。link を辿らない (`openRegular`)。どれに外れても exit 2 (#655 の仮決めを追認。追補 14)。platform は鍵を、`openssl rand -hex 32` の出力 (64 桁と LF) として umask 077 の下で作る (P1b-2)。
- answers: `# falco-ctf answers v1 run=<run id>` と 4 列 (D10 の T3)。`MaxTableBytes` 以下。
- digests: `# falco-ctf evidence-digests v1 run=<run id>` と `seat<TAB>cid<TAB>digest` (D9)。練習版は `ParsePracticeDigests` の形。
- render-record: `# falco-ctf render-record v1`、`run-id<TAB><run id>`、`key-fingerprint<TAB><64 桁の hex>` の 3 行 (#642)。鍵も値も書かない。A4e-6 (追補 19) で v2 に上げる: header を `# falco-ctf render-record v2` にし、4 行目に `scope<TAB><64 桁の hex>` (B12 の scope の digest) を足す。check は v2 だけを受ける (v1 は形の誤りで exit 2。本番の生成がまだ無いので、v1 の互換は持たない)。

**`edition render`** (event)
- 引数はすべて必須。
  - `--challenges <dir>` `--scenario <file>` `--flags-file <file>`: catalog の入力 (`catalog.LoadScored`)。flags は自己検査の T7 / B3 に使う。scope は、`--scenario <file>` か `--all-challenges` (全部の課題 = scenario の無い `catalog.LoadScored`。scoreboard の `scoreboardScenario` が空の起動と同じ scope) のどちらか一方で渡す。どちらも無い・両方ある・空の値の `--scenario` は exit 2 (空の値を「全部」と読まない。追補 18、A4e-5)。空の scenario の扱いで比べた案 (追補 18。D15 の候補 A〜D とは別の label): 案 S-A = 答え表が有効なら `scoreboardScenario` を空にできない (platform の env の gate で強制)。案 S-B = CLI に `--all-challenges` を足す (採用、A4e-5 #671)。S-B を採ったのは、scoreboard の 2 つの scope の形を CLI がそのまま写し、検査した scope と配る scope が同じ `catalog.LoadScored` の呼び方で一致するから。
  - `--edition-root <dir>`: `<dir>/<cid>/edition.yaml` と `<dir>/<cid>/template/<file>`。`<cid>` の集合は、スコープの調査型と一致しなければならない (E2、exit 1。validator と同じ。追補 13)。
  - `--seats <file>`。`--previous-seats <file>` か `--no-previous` のどちらか一方。`--key-file <file>`。
  - `--out <dir>`: 既にあれば exit 2。書き込み可で mount した親 dir の下の、存在しない path を渡す (mount 点そのものを渡さない)。`--out` を `filepath.Abs` + `EvalSymlinks` した親から上に辿って `.git` (dir か file) が見つかるとき、または `--challenges` の木の中のときは exit 2 (公開リポへの混入の guard。`--practice` は対象外)。この guard は、process から見える path だけを見る。container で動かして親 dir を bind mount すると、host の側の git の worktree は見えない (`.git` が mount の外にある)。その経路の歯止めは platform の host の側の確認で、出力先が git の worktree の中なら docker を呼ぶ前に FAIL にする (P1b-2・V83。#655 R4#3、追補 14)。
- 手順 (`RenderEvent`)。どこで止まっても、`--out` には何も残さない。
  1. 入力を読み、課題ごとに `ParseSpec` (E1)・`CheckQuestions` (E2・B8 (a1))・`CheckSeatSpace(cid, qs, len(seats), …)` (B8 (a2)) を通す。
  2. run id を作る (crypto/rand の 128 bit。全部 0 は作り直す)。
  3. 課題ごとに `Render` (`Previous` = `PreviousSeatsOf` か `NoPreviousSeats`) を呼ぶ。E3 を含む。
  4. 自己検査: 自分の出力に `CheckDecoySpread` (B7) と `CheckOutputSpace` (B8 (b)) を当てる。表の bytes が `Parse` と `Check` (EventMode、PracticeSet、FlagValues) を通り、`MaxTableBytes` 以下であることを確かめる。`Parse` と `Check` は load.go の共有の関数を通す (door の数を増やさない)。
  5. `--out` の兄弟の一時 dir (0700) に、次を書いてから `--out` に rename する。dir はすべて 0700、file はすべて 0600 で、O_CREAT|O_EXCL|O_NOFOLLOW で作る (umask に依らない。作った後に mode を assert する)。
     - `answers.tsv` (`WriteAnswers`)
     - `evidence/<seat>/<cid>/<file>` (`validator` の `--evidence-root` の形と同じ)
     - `render-record.tsv` (`WriteRenderRecord`)
     - event の digests は書かない。event の digests を作るのは `edition check` の `--digests-out` だけ (`WriteDigests` が受ける `*CheckedEvent` は `CheckEvent` だけが作る。D9 と V78)。
     - `--out` の名前 (`answers.tsv`・`evidence/`・`render-record.tsv`) は、`practicelayout.go` の中の、練習版とは別の名前の定数で表す (2 つは別の契約。値の文字が同じでもよい)。
- stdout: 成功のときだけ 1 行 `ok run=<run id> seats=<n> challenges=<m> key-fingerprint=<hex>` を出す (指紋は公開してよい値)。stdout は人のための表示で、契約ではない (追補 13)。platform は exit code と出力の file だけを読み、指紋の台帳には `render-record.tsv` の `key-fingerprint` の行を記録する。
- **`edition render --practice`**
  - 引数: `--challenges <dir>`・`--cid <cid>` (鍵・seats・previous・`--out` は受けない。渡せば exit 2)。
  - `<challenges>/<cid>/edition/{edition.yaml,template/}` を読み、`RenderPractice` → `PracticeOutput` の結果で `<challenges>/<cid>/edition/practice/` を置き換える。
    - 置き換えの手順: 一時 dir に作る → 既存の `practice/` があれば退避の名前に rename → 一時 dir を `practice/` に rename → 退避を消す。途中で失敗したら、退避を `practice/` に戻す。
    - 練習版は公開の版なので、mode は通常 (dir 0755・file 0644)、`--out` の guard は当てない。
    - 実行の経路は `make edition-practice CID=<cid>` (A4e-3b-ii #658)。
      - container の中で render し、export を一時 dir に出す (`-o .` に直接出すと、置き換え先の古い file が残るため)。
      - host の `practice/` は次の順で置き換える: 置き換え先と同じ dir の一時の名前に移す → 既存を退避 → mv → 退避を消す。失敗したら退避を戻す (#658 R3#3)。
      - container の中では、COPY で入った既存の `practice/` を render の前に消す。`edition render --practice` を、既存の `practice/` が image の下の layer にある container の中で直接走らせると、退避の rename が overlayfs で EXDEV になり、exit 3 で止まる。`make edition-practice` は、それを避ける形になっている (追補 15)。
  - golden の test (V67) と実課題の再生成は、この 1 つの経路を通る。出力の answers.tsv は `Parse` と `Check` (EventMode false) と `MaxTableBytes` を通る (#643 の LOW)。

**`edition check`** (validator)
- 引数はすべて必須。
  - `--challenges <dir>` `--scenario <file>` `--flags-file <file>`: `catalog.LoadScored`。
  - `--answers <file>`、`--render-record <file>`、`--evidence-root <dir>` (`<seat>/<cid>/<file>`)、`--seats <file>`、`--edition-root <dir>` (render と同じ形)。
  - `--previous-digests <file>` か `--no-previous` のどちらか一方。
  - `--corpus <dir>` (1 つ以上。B9。image の `/app/challenges` と `/app/scenarios`)。
  - `--digests-out <file>`: 既にあれば exit 2。書き込み可で mount した親 dir の下の、存在しない path を渡す。
  - platform は、入力をすべて `:ro` で mount する (P1b-2)。
    - scope の渡し方は `edition render` と同じ (`--scenario <file>` か `--all-challenges` の一方。追補 18、A4e-5)。platform は、render と check と scoreboard の起動に、同じ値の出所から同じ scope を渡す (P1b-2)。
- 順序 (`CheckEvent`。#648 の実装の順)。実行できない検査が 1 つでもあれば止める (fail-closed)。入力が欠けている・読めない・形が誤りなら exit 2、読めた中身が D10 の規則に違反するなら exit 1 (exit code の節)。
  0. 最初に見る使い方の誤りは、引数 (`cmd/scoreboard`) と、seats・previous の読み込み (`CheckEvent` の最初)。ほかの入力 (answers・render-record・`edition.yaml`・template・束) の形の誤りは、その入力を読む step で出る。
  1. `LoadScored`。スコープに調査型が無ければ exit 2 (使い方の誤り。B4 は呼ばない、V72)。
  1b. B12 (追補 19 の改訂、#672 R2#1 = R4#2): render-record を読み (形の誤り = v2 でない header・行の数・key 名・桁は exit 2)、その scope の digest が、step 1 の scope の digest と一致することを確かめる。表を読む前に置くのは、scope の違いを T4 の症状 (未知の cid・欠けた行) ではなく、原因の名前で止めるため。step 3 の B11 は、step 1b で読んだ render-record を使う。
  2. `LoadEventTable` → `*CheckedTable` (T3〜T8、T6 の PracticeSet、`readPracticeFiles` による練習版の束と template)。
  3. B11: render-record の run id が、表の run id と一致する (D10。#648 は仮に T3 の名前で出す。A4e-2c で直す)。
  4. `--edition-root` の `<cid>` の集合 (E2)。課題ごとに E1・E2・B8 (a1)・B8 (a2) (`CheckSeatSpace`)、template の読み込みと印の lexer (lexer の失敗は E3)。
  5. `CheckBundles` (B1・B2・B3・B5・B6・B9。B5 の Hints / Free は `hlscope.Assemble`、Corpus は `ReadCorpus`)。
  6. B4 (`checkPracticeOverlap`、θ = `OverlapTheta`)。
  7. B7 (`CheckDecoySpread`) と B8 (b) (`CheckOutputSpace`)。
  8. B10 (`--previous-digests` との連続)。
  - 1〜5 のどれかで違反があれば、そこで止める (後の step はその結果を前提にする)。6〜8 は互いに独立なので、5 までを通った後は全部を走らせて違反を並べる (`maxViolations` まで。#648)。
- 全部を通ったときだけ、`CheckEvent` が返す `*CheckedEvent` を `WriteDigests` で一時 file (0600、O_CREAT|O_EXCL|O_NOFOLLOW、sync する) に書き、`os.Link` で `--digests-out` に置いてから一時 file を `os.Remove` する (A4e-1 #646)。`--digests-out` が既にあれば EEXIST で原子的に拒否する。
  - hard link を作れない filesystem (一部の bind mount) では失敗する (exit 3 = 環境の失敗、何も残さない。A4e-3 で 2 から変える。追補 13)。出力先の親 dir の filesystem の要件は P1b-2。
  - tree の出力 (render の `--out`) は rename で置く。出力先の確認と rename の間に作られた空の dir は置き換わりうるので、「親 dir は運用者だけが書ける」が前提。file は sync し、dir は sync しない。
- stdout: 成功のときだけ 1 行 `ok run=<run id> seats=<n> challenges=<m>`。人のための表示で、契約ではない (追補 13)。platform は run id を `--digests-out` の 1 行目から読む。

**exit code と stderr** (両方の subcommand)
- 0 = 受理 (書いた)。
- 1 = 読めた中身が D10 の規則 (T / B / E) に違反 (何も書かない)。answers (T)・束 (B1〜B9。束の file の中身の B2 = 大きさ・UTF-8・Hidden と、束の file の種類 = link・通常 file でないを含む)・`edition.yaml` と template (E1・E2・E3 の印・B8 (a))・前回の digests との連続 (B10)・render-record の run id (B11)・render-record の scope の digest (B12)・`--edition-root` の `<cid>` の集合 (E2)。
- 2 = 使い方の誤りか、読めない入力・入力の形の誤り。次がこれにあたる。
  - 引数の欠け・重複・未知、`--previous-*` と `--no-previous` の両方 / どちらも無し。
  - file が無い・通常 file でない・link (answers・seats・previous・render-record・鍵・`edition.yaml`・template。束の file は B2 = 1)。`--edition-root` の `<cid>` の entry が dir でない・link のときも 2 (集合の不一致の E2 = 1 とは別。追補 13 の改訂)。
  - seats・previous・render-record・鍵の file の形の誤り (header・行の文法・render-record の key 名・render-record の header が v2 でない (v1 を含む)・重複・0 席 / 0 行・奇数桁・短い鍵・mode が広い鍵)。
  - 既にある出力先 (引数の段の確認と、書き出しの時の EEXIST の両方)、`--out` が git の worktree か `--challenges` の中。
  - スコープに調査型が無い。
  - 分類できない error (`*Violation` でも、検査の後の書き出しの失敗でもない error)。何も書かない。`errors.Join` の写像は次のとおり。1 = `*Violation` だけ。3 = 検査の後の書き出しの失敗だけ (後始末の失敗で残った名前を伴ってよい)。それ以外 (`*InputError` を含む・2 種類以上の混在・未分類) は 2 (検査が全部は走っていないか、「書くのは全部通った後だけ」の前提が崩れているので、人が見る)。たとえば「EEXIST + 後始末の失敗」と「`*Violation` + 書き出しの失敗」は、どちらも 2 (#654 の仮決めを追認。追補 14)。panic の exit code は契約にしない (0 でないので apply されない)。
- 3 = 環境の失敗 (追補 13)。検査を全部通った後の出力の書き出しの失敗が、これにあたる。
  - check では `--digests-out` の一時 file の作成・書き込み・sync・`os.Link` の失敗 (ENOSPC・EACCES・hard link を作れない filesystem・長すぎる名前など)。render では、自己検査の後の一時 dir の書き出しと rename の失敗、`--practice` の置き換えの失敗。
  - 出力の commit の点は、check では `os.Link` の成功、render では `--out` (か `practice/`) への rename の成功 (追補 13 の改訂、#651 R2#1)。commit の前の失敗は exit 3 で、出力先は作られていない。後始末 (一時 file・一時 dir の削除) は best-effort で、消せなかった一時の名前を stderr に出す (48 文字で切る。値は出さない)。一時の名前は出力先と別で、O_EXCL で毎回新しく作るので、再実行を妨げない。
    - 書き出しの失敗の型 `OutputError` は、2 つの名前を分けて持つ。cmd は、それぞれに合う指示を stderr に出す (#658 R2#2、追補 15)。
      - `Left`: 消してよい一時の名前。指示は「消してよい」。
      - `Restore`: 戻すべき退避の名前 (`--practice` で、退避を `practice/` に戻せなかったとき)。指示は「この名前を `practice/` に戻す」。
  - commit の後の後始末の失敗 (check の一時名の `os.Remove`、`--practice` の退避の削除) は exit 0 とする (出力先は sync 済みの完全な内容で、置き直しは要らない)。残った名前を stderr で知らせる。巻き戻して exit 3 にする形は採らない (出力先の削除も同じ dir の同じ原因で失敗しうるので、両方が残り、再実行が EEXIST の 2 になる)。
  - 入力は受理できる状態なので、exit 3 のとき platform は入力を作り直さず、出力先の環境 (mount・filesystem・`--user`) を直して同じ入力で再実行する。platform は exit code に依らず、実行の後に作業の dir を丸ごと消す (成功のときは sops で包んだ後。残った一時の名前と平文を残さない。P1b-2)。
  - 書き出しの時の EEXIST は 3 ではなく 2 (既にある出力先)。入力を読む段の I/O の失敗は 2 のまま。
- platform は 0 以外ではすべて何も apply しない。1 / 2 / 3 は次の手の区別にだけ使う (1 = 版を直して render から、2 = 呼び方か入力を直す・人が見る、3 = 出力先の環境を直して再実行)。
- stderr に出すのは、規則名・席・課題・設問・file 名 (48 文字で切る)・位置の番号・行番号と、B4 の重なり率の数値と組の id (成功でも失敗でも出す)。値・鍵・語彙・束の内容は出さない。
- 違反は先頭の 20 件 (`maxViolations`) を出し、残りは件数だけを出す。

**練習版と B7 / B8 (b)**: 席 `*` の束を `CheckDecoySpread` / `CheckOutputSpace` に渡すと拒否する (呼び手の誤り。#644)。練習版には当てない、という D10 の規則の機械の形。

**到達範囲 (V78)**
- renderer の関数を呼んでよい非 test の file は、閉じた一覧の 2 つ。`eventrender.go` (`RenderEvent`) と、A4e-3b-ii (#658) が作った `internal/edition/practiceedition.go` (`RenderPracticeEdition`) = `--practice` の実装の 1 file (CoS = CTO 代行の決定、#655 R4#2。追補 14)。一覧は `render_reach_test.go` の `renderCallers` が固定する。event と練習版の経路を同じ file に混ぜない。
- `RenderEvent` の呼び手は `edition render` の 1 か所。`RenderPractice` の呼び手は `edition render --practice` と test。
- `LoadEventTable` の呼び手は `CheckEvent` の 1 か所。`CheckEvent` と `WriteDigestsFile` (`--digests-out` の writer) の呼び手は、`cmd/scoreboard/editioncmd.go` の `runEditionCheck` の 1 か所 (#648・#649)。正典の source test は `internal/edition/load_source_test.go` の `doorViolations` の 1 つ (#649 の review で、cmd の側の pin をここに寄せた)。
- `CheckedTable` / `CheckedBundles` / `CheckedEvent` は、それぞれ load.go / bundlecheck.go / checkevent.go の外で作れない。
- `WriteDigests` は `*CheckedEvent` だけを受ける (追補 12)。render の自己検査は、`CheckDecoySpread` / `CheckOutputSpace` を関数として呼ぶだけで、`CheckedEvent` を作らない。
- 各 door が使う open (`openRegular` / `openFollowing`) は `safeopen_source_test.go` が固定する (#646)。
- edition の中で、hintleak の `scope` は `hlscope` の名前で import する。
- `practice/` の file 名と dir 名の literal は、`internal/edition` の非 test の Go の string literal では `practicelayout.go` にだけ置く (comment は対象外)。A5c-2 / A5d の shell の path は、parity の test (V85) で `practicelayout.go` に結ぶ。

**契約の分け方**
- app の CLI (A4e-1〜3) は、platform がまだ呼ばないので先に merge してよい。
- 契約表の確定版の行 (A4e-4) は、P1b-2・P1b-3 と同時に open し、app の行を先に merge する (行が描くのは main にある CLI)。「同時」は、open と相互リンクが同時という意味で、merge が同時という意味ではない (追補 15)。
  - platform の CI が課金で止まっている間も、次を満たせば app の行を先に merge してよい。
    - (i) P1b-2・P1b-3 の PR が open (draft でよい) で、本文が app の PR と相互にリンクしている。
    - (ii) 行が描く CLI が全部 main にある (A4e-3 で満たした)。
    - (iii) platform は P1b-2 の merge まで CLI を呼ばない。
  - platform の PR の merge は、V83 の selftest を人が手元か self-hosted runner で走らせ、結果を PR に貼ってから行う (platform には required check が無い)。
  - 契約表の file は app の `.claude/rules/falco-ctf-app-conventions.md` で、これまでの行は通常の app PR で足した (A4-0 #624、ADR-0054 #597、A2b #613 など)。user settings の Edit の deny は `.claude/` の agents・commands・hooks・settings・skills・workflows で、`.claude/rules/**` は入っていない (CoS が確かめた。追補 15 の改訂、#659 R4#2)。だから A4e-4 は、engineer が通常の app PR で編集する。classifier に止められたときだけ、同じ操作を別の形で再試行せず、CEO の手にする。
  - 行に入れるもの (追補 14)。各項の [ ] は、契約表で code span にして `internal/contracttable` が app の定数と照らすもの (V82) か、散文で検査の対象外のものか、を表す (追補 14 の改訂、#656 R4#2)。照らし合わせの無い code span は、契約表に置かない:
    - [code span。V82 が `cmd/scoreboard` の定数と照らす] subcommand の名前と、引数の全体 (`--key-file`・`--previous-*` / `--no-previous`・`--digests-out`・`--out` を含む)。
    - [exit の値は code span で、V82 が cmd の exit の定数と照らす。同じ項の「stdout は契約ではない」は散文で、V92 が `ok run=` の code span が 0 件であることを確かめる] exit の 4 値と意味 (0 受理 / 1 規則の違反 / 2 使い方の誤り・読めない入力・形の誤り・混在 / 3 検査の後の書き出しの失敗)。stdout は契約ではない。
    - [code span。V82・V59 が `internal/edition` の定数と照らす] 4 つの file の header と列。
    - [桁と上限の数値は code span で、V82 が `MinMasterKeyBytes` と鍵の file の上限の定数と照らす。mode の規則 (group / other が読めない) は散文] 鍵の形 (64 桁以上の小文字 hex と末尾の LF、4 KiB 以下)。
    - [mode の値 (0700 / 0600) は code span で、V82 が `internal/edition` の実際の出力を Stat して照らす (定数とは照らさない。A4e-4 #667、追補 18)。同じ項の `:ro` と `--user` は散文で、platform の要件 = V83] 出力の mode (`--out` の dir 0700 / file 0600、`--digests-out` 0600)。入力は `:ro`。`--user` は運用者の uid (0 は不可)。
    - [散文。規則の意味の説明で、契約表の検査の対象外。規則そのものは V75・V90 が app の test で確かめる] B10 の包含と共通部分の digest の一致、B11。
    - `--out` の guard の限界 (host の側の確認は platform が持つ)。[散文。platform の要件 = V83]
    - [散文。contracttable の照合の対象外。deploy の時は 3-10 (V95) が止める] seat の ns の Secret は閉じた集合: type `Opaque` の {`ctf-flags`} ∪ {`ctf-evidence-<cid>`} と、Helm の release の記録 (type `helm.sh/release.v1`) だけ。ほかの type の Secret があれば失敗する。全部の scope に適用される (evade だけの scope を含む。D11 の 3-10。追補 16 の改訂、#664 R4#1)。
    - [散文。platform の要件 = V83] イベントの払い出しの引数は scope で決まる: 調査型の課題を含む scope は、deploy-user に 3 つの引数 (`--flags-file`・`--evidence-dir`・`--evidence-digests`) を渡し、evade だけの scope は `--flags-file` だけを渡す。local でない経路で、3 つとも無い呼び出しは作らない (D19 の P1b-3。追補 18)。
- platform#335 に溜めた要件の対応:
  - P1b-2: 前回の席の list・`edition check` の `--digests-out`・鍵の指紋の台帳を sops に残す。初回は `--no-previous` を render と check の両方に渡す。validator の入力を `:ro` で mount する。出力先は、書き込み可で mount した親 dir の下の、存在しない path で渡す。その親 dir は hard link を作れる filesystem で (`--digests-out` は `os.Link` で置く)、運用者だけが書ける。container は `--user <運用者の uid>:<gid>` で動かす (scoreboard の image の既定の user は 65532 = distroless の nonroot。`.claude/rules/falco-ctf-app-conventions.md` の UID 一覧)。入力は運用者の所有のまま `:ro` で mount し、mode を広げない (鍵は group / other が読めないことを validator が要求するので、65532 では読めない)。出力先の親 dir も同じ uid が書ける。mount 元を 65532 に chown する形は採らない (host の root が要り、鍵の所有が運用者から離れる)。鍵は `openssl rand -hex 32` の出力 (64 桁の小文字 hex と LF) として、umask 077 の下で作る (D20 の鍵の形)。出力先が host の git の worktree の中なら、docker を呼ぶ前に FAIL にする (container の中の `--out` の guard からは見えないため)。`--user` の uid は 0 にしない。platform は運用者の `id -u` が 0 なら、docker を呼ぶ前に FAIL にする (root で動かすと、運用者の作業の dir に root 所有の平文と一時の名前が残り、運用者の権限で消せなくなる)。Hard Invariant I2 (scoreboard / auth-policy / collector のコンテナ `runAsUser: 65532`) は cluster の中の container (chart の securityContext) を指し、運用者の機械での `edition check|render` の実行は対象の外とする (I2 の解釈。追補 13 の改訂、#651 R4#3)。exit 3 は「検査は通った。出力先の環境を直して同じ入力で再実行」と報告する。stdout は読まない。平文の `--out` は運用者だけが読める場所 (tmpfs など。同期される dir と repo の外) に置き、sops で包んだら平文を消す。答え表の Secret を Deployment より先に作る。stand-up の step の数。席の list の運用 (追記だけ、消えた席を残す)。namespace の固定と name / key の照合、chart が #614 以降の gate (既存)。
  - P1b-3: 席ごとの `deploy-user.sh --evidence-dir --evidence-digests` と、evidence の Secret の作成の順。要件の正典は D19 の P1b-3 の行 (scope に応じた引数 (調査型を含む scope は 3 つ、evade だけの scope は `--flags-file` だけ)、seat の ns の閉じた集合、A5e の後の assert の呼び方、platform の docs の 3-9 の参照の修正)。ここには写さない (追補 16 の改訂、#664 R4#1)。

## Consequences
- **諦めたもの**:
  - 束の内容の検査を scoreboard の起動時に行うこと (束を持たないため。validator と digest で代える)。
  - 4 択の設問 (D3 (a))。
  - 席ごとに変えられない format (`technique` / `choice-set` / `sequence`) の答えは Board で共有できる (残余。検出はしない)。D1 の「席ごとの設問を 1 つ以上」によって、固定の答えを共有しただけでは solve できない。
  - 調査型の課題は、A3b-3 (#622) から、課題さえあれば提出から採点まで動く。ただし練習のモードでは、A4a-2 まで Judge が無く、提出は 500 になる (何も消費しない)。`technique` は A1c まで使えない。
  - コースの中で、調査型の課題より後ろに evade を置けない (ADR-0003 W2 が調査型に及ぶため。V39)。
  - journey の polling は、表示中の調査型について SQL を 1 回読み、読めなければ 500 になる (H2、Signpost 7)。
  - 公開していない過去のイベント版の再利用は検出しない。ただし鍵の再利用は、指紋の台帳で platform が検出する (D12、追補 10 の改訂)。
  - 席ごとでない format の綴り違いは、B4 の本文の検索で見逃す (固定の答えの漏れは T6 が止める。D10 の B4)。
  - 正解なのに設問の correct の書き込みが失敗すると、回数を 1 つ失う (fail-closed の代償)。correct を記録した後の `MarkSolved` の失敗は、次の提出で自己修復する (D5 の 5)。
- **新たに守る規則**: D15 の候補 A〜D (昇格の前は ADR の規則)。
- **I への影響**: 違反は無い。
  - I1: table が 1 つ増える。
  - I2: 運用者の機械で `--user` (運用者の uid、0 は不可) で動かす validator / renderer は、I2 の対象の外 (D20 の P1b-2。cluster の中の scoreboard の container は 65532 のまま)。
  - I5: image は増えない (subcommand)。
  - I6: D8 の解釈による。
  - I12: 経路は同じで、copy-source が 1 つ増える。
  - I14: operation が 1 つ増える。
  - I15: Prefix の中に収まる。
  - I16: 束は image の外。
  - I13b: `mountDir` の制約による。
- **runbook (COO)**: DB の版 3 からの rollback は、`user_version = 2` と `DELETE FROM answer_attempts` を同時に行う (platform#333。stand-up の前に PVC の写しでリハーサルする)。render → check → 払い出しの順。予備の席。予備を超えたときの再起動 (I1 の Recreate で短い全断)。tag を上げる前に表を検査する (ADR-0033 と同じ注意)。
- **統治文書 (CEO)**: `ORGANIZATION.md:198` の「端末に載る唯一の課題ファイル」に痕跡束を足す。CLAUDE.md の R1 一覧に行を足す。(app の `.claude/rules/dev-flow.md` の D (image) の行への `Dockerfile.edition-practice` の追記 (#658 R3#1) は、統治文書ではない。`.claude/rules/**` は Edit の deny の外なので、通常の app PR = A4e-3c に同梱する。追補 15 の改訂、#659 R4#2)
- **follow-up (LOW)**: `x-ctf-authz: self` を他の書き込み route へ広げるかの検討 (今は変えない)。

## Signposts
1. 監査 log の `answer matched another seat` が、1 イベントで seat の 5% を超える。または誤答の keyed hash が席の間で一致する率が高い → 席ごとに変えられない format の扱いと K を見直す。
2. 束が課題あたり 512 KiB を超える要求が出る、全課題の合計が 2 MiB (plant-seed の `sizeLimit` の半分) に近づく、または seat × 設問の表が 1 MiB の Secret に近づく → Secret の分割か PVC を宣言つきで設計する (`sizeLimit` も合わせて見直す)。
3. stand-up の端末で docker が使えない (E1 の前提が崩れる) → E2 (`APP_PIN` の clone からの `go build`) に移る。
4. 設問の 20% 超で回数を使い切る参加者が出る (CPO の指標)、または候補の下限 R で content が書けない → attempts・R・K を CISO と CPO が再設定する。
5. (補足) platform が evade の無いコースで flags を任意にする → 「イベントのモード」の指標を明示の `EVENT_ID` に替える。
6. 初回のイベント版で validator が stderr に出した重なり率 (B4 の (1)(2)) が、正当なイベント版で θ = 0.5 に近いか超える、または流用したテンプレートが 0.5 未満で通る → CISO が θ を設定し直す (変えるのは定数と、その pin の test)。
7. 次のどれかが観測された → `answer_attempts` の in-memory の写し (write-through。`Reset` と自己修復で同時に更新する) に移る。
   - 開催中に、journey の 500 のうち「could not read the mission's questions」の log が 1 件でも出る。
   - `GET /journey` の p99 が 100 ms を超える。
   - 調査型の課題を 2 本以上同時に表示する UI が要る (読みが mission の数に比例する)。
8. chart の values から release の記録に載るものが file 名の一覧を超える要求が出る (内容を values で渡したい、など)、または Helm の storage driver を platform が変える → 追補 6 の L1 / L3 を再評価する。そのときは、release の記録の最悪の大きさを実測して上限を決める。
9. 席ごとの format を足す、または `Normalize` が受理する綴りを広げる → `answerformat.Fold` に同じ PR で族を足す (V55 の性質の test が、足し忘れを赤にする)。B9 の偽陽性による再 render が 1 イベントで 3 回を超える → fold の粒度を見直す。
10. validator の入力の木を運用者以外 (CI の runner や共有の端末) が書ける形で使う → M2 の「運用者の所有」の前提が崩れる。読む前に木の写しを取ってから検査するよう、入口を設計し直す。
11. 作者が decoy を answer と違う形で置きたい要求が出る (別の語彙の囮・別の時間帯の囮など) → `decoys: <n>` の暗黙の生成を、宣言の decoy (同一性を E2 で検査する形) に広げる。schema は `version: 2` にする。
12. timestamp の窓では書けない時系列 (相対的な順序の制約、席ごとに伸び縮みする間隔) が content に要る → `time` に順序の制約を足す。窓の幅 = `windowSeconds` という空間の主張は保つ。
13. name の設問で、B8 (b) が普通の語で満たされるのに、実際の参加者が少ない候補で当てている (誤答の分布が狭い) → name の候補の数え方を、文脈 (key=value の値の位置など) で絞る形に見直す。
14. B4 の全 format の検索で、`fixed` の短い値 (technique の id・選択肢の id) による偽陽性が、1 イベントで 2 回を超えて文面の言い換えを強いる → 席ごとでない format を B4 から外すことを、CISO の同意を取って検討する。
15. 席の list を追記だけに保てない運用 (roster の並べ替え、席の削除) が出る、または E3 (`--previous-seats` の接頭辞) か B10 が開催の前に 1 回でも止まる → 全席の配り直し (`--no-previous` を render と check の両方に渡す) を、runbook の明示の手順として COO が決める。並べ替えに強い割り当て (席の名前だけで決まる形) が要るかを再評価する。
16. 鍵の指紋の台帳が、イベントの間で引き継がれない (sops の置き場の移動、台帳の欠け) → preflight が台帳の非空を確かめるよう P1b-2 を締める。

## Verification (app は `make test` / `flag-guard` / `chart-lint` = required。exit status で判定。故意の違反で赤になる case を常設する)
- **V1 (security 要件 1)**: sentinel の答え表で、誤答・上限超過・already-correct・store の失敗・起動拒否の各経路を通す。応答の body・log・metrics・error・store の行に sentinel が 0 件 (Go の test)。
- **V2 (要件 2)**: sentinel を入れて `helm template` した結果、ctf-user には 0 件、scoreboard では scoreboard の container の mount にだけ現れる (CI)。deploy の 3-x で、seat の ns の Secret 名が {ctf-flags, ctf-evidence} と一致する。
- **V3 (要件 3)**: T1〜T8 と B1〜B9 のそれぞれについて、1 ケースに 1 欠陥の testdata で拒否する。T は scoreboard の起動の test と validator の両方で、B は validator で確かめる。stderr に値が 0 件。
- **V4 (要件 4)**: renderer の test。2 席の出力の差分の位置のうち答えでないものが、答えごとに K 以上。B7 は、K − 1 の fixture で赤になる。U2 のもとで、小さな N (例 8 席) の全組でこれが成り立つこと、割り当てを外したコピー (独立に引く) で S を小さくすると赤になることも確かめる。
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
- **V17 (security 1(c)、`flag-guard` の上)**: スコープに調査型がある deploy-user で、次の 4 つが非ゼロで終了し、helm / kubectl を 1 回も呼ばない (stub で記録)。(a) `--flags-file` だけがある。(b) `--evidence-dir` だけがある。(c) `--evidence-digests` だけがある。(d) digest が不一致。3 つとも無い場合は、練習版で通る (A5c-2 から。それまでは非ゼロで終了する)。
- **V65 (A5c-2、練習版の経路)**: 練習版の fixture の木 (`<cid>/edition/practice/{evidence/, answers.tsv, digests.tsv}`) と、kubectl の stub で確かめる。
  - 3 つの引数が無く、スコープに調査型があると、`ctf-evidence-<cid>` が作られる。
  - `--from-file` の path は、すべて `practice/evidence/` の下。`answers.tsv` と `digests.tsv` は、`--from-file` にも `names` にも出ない。
  - `names` は `evidence/` の file 名の byte 順 (`LC_ALL=C`)。
- **V66 (A5c-2、fail-closed)**: 次のそれぞれで、kubectl / helm を 1 回も呼ばずに非ゼロで終了する。
  - `evidence/` の file を 1 byte 変えた木。
  - `digests.tsv` の run id が 0 でない木。
  - `practice/` が無い木。
  - `evidence/` に symlink や B2 の外の名前がある木。
  - `--flags-file` だけがある (練習版の経路に入らない)。
  - イベントの digests の run id が全部 0。
  - イベントの digests に席 `*` の行がある。
  - さらに、`ParseDigests` (イベント) が全部 0 の run id と席 `*` を拒否し続け、`ParsePracticeDigests` が 0 でない run id と `*` 以外の席を拒否する (Go。どちらかの入口がもう一方の入力を受理するコピーで赤になる)。
- **V67 (A4d-2b / A7、golden)**: render(edition.yaml, template, `practice`, `*`) の出力が、commit した `practice/` の `evidence/`・`answers.tsv`・`digests.tsv` と byte で一致する。どれか 1 つを手で直したコピーで赤になる。A7 の課題では、実 tree でこの test が非空で走る。
- **V68 (A4d-2a、U2)**: 割り当ての性質を確かめる。
  - S = 200・N = 100 (S = 2N) の fixture で、どの slot の位置でも値が全席で異なり、T8 が通る。
  - 席の list の末尾に 1 席を足して再 render すると、前の席の answer・decoy・filler の値が byte で変わらない。
  - list の順を入れ替えると、後ろの席の値が変わる (順序に依存することを固定する)。
  - S = 200・N = 101 と、S = 2N − 1 の組で、draw の前に E3 になる (決定的。乱数の結果に依らない)。
- **V69 (A4d-2c)**: B7 と B8 (b) の境界を確かめる。
  - decoy の印を token の途中に埋めた template (例 `x{{ctf:who-d1}}y`) は、位置を特定できないので E3 で拒否される (render の段。validator も同じ lexer で拒否する)。
  - 2 席の束で、ある decoy の位置の token を同じにすると、B7 (席の間の重複) が赤になる。answer の位置でも同じ。
  - 1 席では、席ごとの検査は当たる (format に合う decoy を K − 1 にすると赤)。席の間の検査は空になる。練習版 (席 `*`) の束を `CheckDecoySpread` / `CheckOutputSpace` に渡すと拒否する (呼び手の誤り、#644)。
  - B8 (b) は、別々の token が 10 × attempts − 1 個で赤になる。
- **V70 (A4d-2a、鍵)**: 次を確かめる。
  - `NewMasterKey` が 31 byte の鍵と、bytes `practice` を拒否する。
  - 版の label を変えると値が変わる。
  - 同じ鍵なら、run id を変えても値は同じ。
  - rejection sampling の偏りの test (scripted な draw で、`2^64 mod n` より下の draw が捨てられる)。
- **V71 (A4d-2a、E3)**: 次のそれぞれで E3 になり、message に値も鍵も 0 件。
  - 未宣言の印、宣言した slot の印が無い、render の後に残る印。
  - 練習版の鍵での event、event での席 `*`、席 0、席の重複。
- **V72 (A4e-2)**: 調査型の課題が無い image では、A4e が B4 を呼ばない (source test か挙動の test。B4 の側には「呼ばれたら違反」の規則を置かない)。重なり率の stderr が A4e の CLI から出る。
- **V73 (A4c-3、#640 R4#4)**: B4 の shingle の窓と hintleak の窓が、同じ export された関数である (source test)。実績 (#661): B4 が `hintleak.GramSet` (非公開の `gramSet` を改名して export したもの) を呼ぶ。source test は `internal/edition/shingle_source_test.go` と `internal/hintleak/gramset_test.go`。#640 の parity の test は元から無かった (挙動の test だけ。追補 16)。
- **V74 (A4d-2a、E3 の接頭辞)**: 次のそれぞれで、draw の前に E3 になる。
  - `--previous-seats` と `--no-previous` のどちらも無い、または両方ある (exit 2)。`--no-previous` は初回として通る。
  - 前回の list の 2 席を入れ替えた list、前回の 1 席を消した list、前回の途中に 1 席を挿入した list。
  - 前回の list の末尾に足した list と、前回と同じ list (0 席の延長。image の版を変えた後のやり直し = 追補 19) は通り、前の席の値が byte で変わらない (V68)。
  - answer の印を token の途中に置いた template も E3 になる (`x{{ctf:who}}y`)。
- **V75 (A4e-2、B10)**: 次を確かめる。
  - 前回の digests の 1 席の digest を変えた入力で、B10 が拒否する。
  - `--previous-digests` も `--no-previous` も無いと exit 2。header だけ (0 行) の `--previous-digests` も exit 2。
  - `--no-previous` は初回として通る。`--previous-digests` と `--no-previous` を両方渡すと exit 2。
  - 前回に無い席が足されているだけなら通る。
  - 前回の (seat, cid) が今回に無い digests (席を消した list に対する previous) と、今回と共通の (seat, cid) が 0 件の digests (取り違えた file) のそれぞれで、B10 が拒否する (#648)。前回の digests の run id が今回と違うだけでは拒否しない。
  - platform: P1b-2 の selftest で、`--previous-*` と `--no-previous` のどちらも無い、または両方あると FAIL。platform には required check が無いので、merge の時に人が確かめる。
- **V76 (A4d-2a / P1b-2、鍵の指紋)**: 次を確かめる。
  - 同じ鍵からは同じ指紋が出る。違う鍵からは違う指紋が出る。
  - 指紋は seed の label と domain が別である (seed の block と一致しない)。
  - `render-record` に鍵も値も 0 件。
  - platform: 台帳にある指紋で preflight が FAIL (selftest)。
- **V77 (A4e-2、B8 (a2))**: validator が、`--seats` が 101 席で S = 200 の edition を B8 として拒否する (renderer の E3 と同じ判定)。
- **V78 (A4e-1、到達範囲)**: source test で、D20 の「到達範囲」の各項を確かめる。
  - `RenderEvent`・`LoadEventTable`・`CheckEvent` の呼び手の数と場所。
  - renderer の関数を呼ぶ非 test の file が、閉じた一覧の 2 つ (`eventrender.go` と `--practice` の実装の file) だけである (`render_reach_test.go` の `renderCallers`)。3 つ目の非 test の file から呼ぶコピーで赤 (追補 14)。一覧の 2 つ目は `internal/edition/practiceedition.go` (A4e-3b)。
  - `RenderEvent` の自己検査の配線 (正の pin、source test): `RenderEvent` が自己検査の段で、cid ごとに `CheckDecoySpread` と `CheckOutputSpace` を呼び、その結果を拒否 (exit 1) に入れる。呼び出しの抽出が 0 件なら赤。どちらかの呼び出しを消したコピーと、結果を捨てたコピーでも赤 (A4e-3b。#656 R4#1。B7 は renderer の入力からは破れないので、この配線は source test が守る)。
  - `CheckedTable` / `CheckedBundles` / `CheckedEvent` の composite literal が、それぞれ load.go / bundlecheck.go / checkevent.go の外に無い。
  - `WriteDigests` の引数の型が `*CheckedEvent` である (A4e-2 で `*CheckedBundles` から変える)。
  - 正の pin のうち、`CheckEvent` / `WriteDigestsFile` の呼び手 (`runEditionCheck`)・server の path から subcommand に届かない・`hlscope` の import は、A4e-2 (#648・#649) が足した。`RenderEvent` の呼び手は A4e-3a-ii (#655) が足した。`RenderPracticeEdition` の呼び手 (`runEditionRenderPractice` の 1 か所) は A4e-3b-ii (#658) が足した。
  - `cmd/scoreboard` の server の path (subcommand に分かれない側) から subcommand の関数に届かない。
  - edition の中の hintleak の `scope` の import 名が `hlscope`。
  - `internal/edition` の非 test の Go の file のうち `practicelayout.go` の外に、`practice/` の file 名と dir 名の string literal が無い (comment は対象外)。
- **V79 (A4e-2、`edition check`)**: 次を確かめる。
  - 各必須の引数を 1 つずつ欠く、未知の引数、`--previous-digests` と `--no-previous` の両方 / どちらも無し、既にある `--digests-out` のそれぞれで exit 2。
  - スコープに調査型が無い catalog で exit 2、B4 は呼ばれない。
  - D10 の各規則を 1 つずつ破る fixture で exit 1。stderr に規則名が出て、値の sentinel が 0 件、`--digests-out` は作られない。
  - render-record と表の run id の不一致で exit 1 (規則名は B11。V90)。
  - 違反が 21 件以上なら 20 件と残りの件数。
  - 成功で `--digests-out` が一時 file → `os.Link` で作られ (追補 12)、stdout が 1 行 (形は人のための表示で、契約ではない。追補 13)。
- **V80 (A4e-3a-ii #655。鍵の負の case の一部は A4e-3b-ii #658、`edition render`)**: 次を確かめる。
  - 鍵の file が無い / 63 桁 / hex でない / mode 0644 / 末尾の LF が無い / CRLF / 2 行目がある / 4 KiB を超える で、それぞれ exit 2。どの message にも鍵の bytes (sentinel) が 0 件。ちょうど 64 桁 + LF は受理する。#655 にある case は、LF なし・4 KiB 超・64 桁の受理。CRLF と 2 行目の case は、A4e-3b-ii (#658) で足した (追補 14 の改訂、#656 R2#3)。既にある `--out` で exit 2。
  - 2 つ目の課題で E3 を起こす fixture で exit 1、`--out` も一時 dir も残らない。
  - 自己検査は多重の守り (renderer の構成で成り立つ性質を、出力の上で確かめ直す)。test で破れるのは次の 2 つで、どちらも exit 1、何も書かれない (#655)。
    - B8 (b): 別々の token が足りない template。
    - T6: 固定の設問の答えを、練習版と同じにした `edition.yaml`。
  - B7 (decoy の数と席の間の重複) と T7 (答えが flag と一致) は、renderer が受ける入力からは構成上作れない (decoy の印・位置・席ごとの値は renderer が作る。flag は `FALCO{...}` の形で、どの answerformat の値にも `{` が入らない)。この 2 つは validator の側 (V86 の fixture) で破る (追補 14)。T7 が構成上作れないのは、flag が `FALCO{...}` の形である前提が成り立つ限りである。この前提は、event の flags file について app の loader が強制する (`internal/catalog/flags.go` の検査 = `FALCO{...}` の形で、括弧の中は英数字・`_`・`-` だけ。追補 15)。だから、追加の case は置かない。renderer の自己検査の T7 は、loader の検査が将来ゆるんだときの歯止めとして残す (多重の守り。#656 R1#1)。
  - `--edition-root` の余分な `<cid>` の dir と欠けた `<cid>` の dir で、それぞれ E2 (exit 1)。`<cid>` の entry が file か link なら exit 2。どれも `--out` は作られない。
  - 往復の test: render の出力 (answers・evidence・render-record) を、edition root・seats・corpus と一緒に `edition check` に渡して exit 0、`--digests-out` ができる。render の出力に `digests.tsv` が無い。
  - `--out` の木の mode: dir が 0700、file が 0600 (umask 022 と 077 の両方で走らせる)。
  - 奇数桁の鍵、header だけの `--previous-seats` で exit 2。`--out` が git の worktree の中 (`.git` が dir のときと file のとき)、`--challenges` の中で exit 2。
  - run id は全部 0 でなく、2 回の render で違う。render-record が D20 の形 (A4e-6 からは v2 の 4 行。scope の digest は、render に渡した scope から計算した値)。
- **V81 (A4e-3b-ii #658、`--practice`)**: `edition render --practice` の出力が、commit した `practice/` と byte で一致する (V67 と同じ fixture)。鍵・seats・`--out` を渡すと exit 2。出力の answers.tsv が `Parse`・`Check` (EventMode false)・`MaxTableBytes` を通る。置き換えの途中 (退避の後、rename の前) に失敗を注入すると、既存の `practice/` が byte で不変。退避を戻せなかったときは、`OutputError` の `Restore` の名前が stderr に出る (#658 R2#2)。commit されている `practice/` が、`edition.yaml` + `template/` の新しい render と byte で一致することを、required の test (`internal/edition/render_golden_test.go` の `practiceStale`) が照らす。対象は `challenges/` の中で `edition/` を持つ課題の全部 (今は 0 件。A7 の最初の課題から働き、A7 で非空の要求に反転させる = V47 と同じ。#658 R4#2、追補 15)。
- **V82 (A4e-4、契約表)**: `internal/contracttable` の test が、契約表の文面 2 の確定版の行の code span (subcommand 名・引数の名前・exit code の 4 値・4 つの file の header・鍵の形の数値 (桁と上限)・出力の mode の値 (定数ではなく、実際の出力を Stat して照らす。A4e-4 #667 で実装)。D20 の「契約の分け方」で [code span] と印を付けた項。追補 14 の改訂) を、`cmd/scoreboard` と `internal/edition` の定数と照らし合わせる。どれか 1 つを変えたコピーで赤になる。契約表の文面 2 の行が 0 件なら赤 (空の検査で緑にしない。V59 の digests の header と列もここで照らす)。
- **V83 (P1b-2 / P1b-3、platform)**: D20 の「契約の分け方」の platform の要件のそれぞれに、selftest の case を 1 つ置く (前回の list・digests の欠けと、`--no-previous` との両方 / どちらも無し、指紋の台帳との一致 (mode ごと。V99)、`:ro` でない mount、mount 点そのものを出力先に渡す形、平文の `--out` が運用者だけの場所でない、出力先の親 dir が hard link を作れない filesystem、`--user` の無い `docker run` (image の既定の 65532 で動く形)、`id -u` が 0 の運用者 (docker を呼ぶ前に FAIL)、出力先が host の git の worktree の中 (docker を呼ぶ前に FAIL。container の中の `--out` の guard からは見えない)、`openssl rand -hex 32` で作った鍵を `edition render` が受理すること (D20 の鍵の形との parity)、0 でない exit の後と、exit 0 で stderr に残った名前が出た後の作業の dir (どちらも、実行の後に一時の名前と平文が 0 件)、exit 3 の stub (環境の失敗として報告し、何も apply せず、入力を作り直さない)、stdout の形を変えた stub (platform は stdout を読まないので、結果が変わらない)、Secret の作成の順)。rehearsal では実際の mount で 1 回、0600 の鍵が `--user` つきで読めること、0644 の鍵が exit 2 になること、`--digests-out` が置けることを確かめる (bind mount の種類で、mode と hard link の扱いが変わるため。実機でのみ確認可)。
- **V86 (A4e-2、`CheckedEvent`)**: 次を確かめる。
  - `WriteDigests` は `*CheckedEvent` だけを受ける (型。`*CheckedBundles` を渡すコピーは compile できない)。
  - E1・E2・E3 (template の印)・B8 (a1)・B8 (a2)・B4・B7・B8 (b)・B10・B11 (run id の照合) のそれぞれを 1 つずつ破る fixture で、`CheckEvent` が nil の `*CheckedEvent` と error を返し、`CheckReport` (B4 の重なり率) は返す。
  - `CheckedEvent` の composite literal が、`checkevent.go` の外に無い (V78 と同じ source test)。
- **V87 (A4e-1 #646 / A4e-2、writer と open)**: 次を確かめる。
  - `--digests-out` が既にあれば EEXIST で拒否し、元の file は byte で不変。
  - `os.Link` が失敗する出力先 (test の hook) では exit 3 (A4e-3 で 2 から変える。V92) で、一時 file も `--digests-out` も残らない。
  - FIFO に差し替えた入力で、reader が block せずに拒否する。
  - `ANSWERS_FILE` の起動の経路だけが `openFollowing` を使う (`safeopen_source_test.go`)。
- **V88 (F-fmt)**: `scripts/fmt-check.sh` (`make fmt-check` の中身) が、未整形の Go の file を 1 つ足したコピーで赤になり、required の `test` の job の中 (`Dockerfile.test`) で走る。自己検証 (`scripts/test-fmt-check.sh`: 整形済み = 0 / 未整形 = 1 / 構文 error = 1 / gofmt なし = 2) も同じ image の中で走る (#650)。
- **V89 (A4e-2c、hint の入力の読み込み)**: 次を確かめる。
  - source test: 対象は「narrative の override を journeys に当てて、server が表示し B5 が検査する hint の列を組む処理」(追補 13 の改訂、#651 R4#2)。override の適用 (override の読み込みと journeys への当て込み) を行う code は、寄せた 1 つの非 test の関数の中にだけある (`_test.go` の中にも 2 つ目の適用が無い)。その関数の呼び手に、server の起動 (`cmd/scoreboard/main.go`)・`CheckEvent` (`hintInputs` の置き換え)・`internal/hintleak/content_test.go` の 3 つが入っている。server の起動の経路が表示に使う journeys と rule の抜粋は、寄せた関数の戻り値から得る (今の `main.go` の `LoadJourneys` / `LoadRuleExcerpts` の直接の呼び出しを置き換える)。呼び手の抽出が 0 件なら赤。
  - 対象の外: override を当てずに `catalog.LoadJourneys` / `LoadRuleExcerpts` だけを使う呼び手 (`internal/e2e/harness/seed.go`・`cmd/scoreboard/investigate_boot_test.go`・`internal/homefragments/manifest_verified_test.go`・`internal/scoreboard/journey_hint_gate_test.go`)。これらは表示も B5 の入力も組まない。
  - 挙動: narrative の override にだけ置いた sentinel の hint の文を束に置いた fixture で、`CheckEvent` が B5 で拒否する (server が見せる override を、B5 が見ている)。override を読まない形に戻したコピーで、この test が赤になる。
- **V90 (A4e-2c、規則名)**: stderr の規則名を確かめる (どれも exit 1、値の sentinel は 0 件)。
  - render-record と表の run id の不一致 → B11 (T3 ではない)。
  - `--edition-root` の余分な `<cid>` の dir と、欠けた `<cid>` の dir → それぞれ E2。`<cid>` の entry が file か link なら exit 2 (E2 ではない)。
  - template の印の lexer の失敗 → E3。`RuleTemplateMark` と `RuleSpecRender` の値の一致の test が残っている。
- **V91 (A4e-2d、test の支援 package)**: source test が、module の非 test の Go の file のうち支援 package を import するものが 0 件であることを確かめる。支援 package の file に renderer の関数の識別子が 0 件 (呼び出しも関数の値も) で、`render_reach_test.go` の `renderCallers` は変えずに緑 (追補 13 の改訂、#651 R4#1)。import する `_test.go` の抽出は、`cmd/scoreboard` と `internal/edition` の両方を含む 1 件以上で、0 件なら赤。支援 package で組んだ正の fixture を、`CheckEvent` が受理し、`edition check` が exit 0 で返す。
- **V92 (分担: check の分 = A4e-3a-i #654、render の event の分 = A4e-3a-ii #655、`--practice` の分 = A4e-3b-ii #658、契約表の分 = A4e-4、exit 3 と stdout)**: 次を確かめる。
  - check: 検査を全部通った後の書き出しの失敗 (test の hook で `os.Link` の失敗と ENOSPC) で exit 3 になり、一時 file も `--digests-out` も残らず、stderr に値が 0 件。引数の段の確認の後、書き出しの前に `--digests-out` を作る hook では、EEXIST で exit 2。
  - render: 自己検査の後の一時 dir の書き出しの失敗と rename の失敗で exit 3 になり、`--out` も一時 dir も残らない。`--practice` で退避の後に失敗すると exit 3 で、`practice/` は byte で不変 (V81)。
  - 入力を読む段の失敗 (読めない file) は 2 のまま。
  - cmd の写像: 型の付かない error (`errors.New`) を返す stub で exit 2。`errors.Join(*Violation, *InputError)` で exit 2、`*Violation` だけの Join で exit 1。D10 の各規則の fixture は exit 1 のまま (V79。`CheckEvent` が違反をすべて `*Violation` で返していること)。
  - check の commit の後: 次の 2 つの組で満たす (cmd の test から seam に届かないため。#654、追補 14)。
    - library の test: `writeFileAtomic` の seam で `os.Link` を成功させ、一時名の `os.Remove` を失敗させる。error が nil で、残った名前が返り、`--digests-out` が期待の bytes であること。
    - cmd の配線の source test (AST): 残った名前は `printLeftWarning` に、error は `finishRefusal` に渡り、残った名前だけのときの exit が 0 であること。配線を入れ替えたコピーで赤、抽出が 0 件でも赤。stderr に値は 0 件。
  - check の commit の前: 書き出しが失敗し、後始末の `os.Remove` も失敗する hook で exit 3。`--digests-out` は無く、stderr に残った一時の名前が出る。同じ入力でもう 1 度実行すると exit 0 (残った一時の名前が再実行を妨げない)。
  - render: 一時 dir の書き出しの失敗と後始末の `RemoveAll` の失敗が重なる hook で exit 3、`--out` は無い。`--practice` で rename が成功し、退避の削除が失敗する hook で exit 0。`practice/` は新しい内容で、stderr に退避の名前が出る。
  - (A4e-4) 契約表の文面 2 の確定版の行に exit code の 4 値があり、stdout の形 (`ok run=`) の code span が 0 件 (V82 の test に足す)。
- **V84 (A4e-3b-i #657。`scripts/check-edition-headers.sh` (`--selftest` つき) を `check-flags.sh` から呼ぶ。除外は `internal/edition/testdata/digests-golden/digests.tsv` の名指しの 1 件、flag-guard)**: 公開リポへの混入の guard を確かめる。
  - tracked file に、run id が全部 0 でない `# falco-ctf answers v1 run=` / `# falco-ctf evidence-digests v1 run=` の header、または `# falco-ctf render-record v1` の header (A4e-6 からは `# falco-ctf render-record v2` も。v1 も拒否のまま残す) を足した木で、flag-guard が赤になる。
  - 練習版 (run id が全部 0) の `practice/` は緑のまま。
  - 抽出が 0 件の木でも、検査そのものは走る (exit status で判定する)。
- **V93 (A4e-3c、evidence だけの混入)**: 次を確かめる。
  - 追跡中の path に `evidence/<seat>/<cid>/<file>` の形 (seat は ADR-0042 の文法、cid は `challengeid.Pattern`) を 1 つ足した木で、flag-guard が赤になる。
  - 一致は部分一致 (A4e-3c の行の規則)。先頭を 1 段下げた path (`x/evidence/<seat>/<cid>/<file>`) と、`<file>` を入れ子にした path (`evidence/<seat>/<cid>/a/b`) でも赤。`evidence`・seat・cid が segment の一部だけに一致する path (`myevidence/…`) は緑。
  - 練習版の入れ子: `challenges/<cid>/edition/practice/evidence/<seat>/<cid>/<file>` (seat の形) は赤。`practice/evidence/` の下の seat の形でない入れ子は、この guard では緑 (練習版の layout の誤りは、V11 と V81 が持つ)。
  - parity (#659 R4#1): Go の test が、script の pattern の 3 つの部品 (event の `--out` の evidence の dir 名、cid の文法、seat の文法) を、それぞれ `practicelayout.go` の event の名前の定数・`challengeid.Pattern`・ADR-0042 の seat の文法の Go の定義と照らす。V84 の `flagguard_headers_internal_test.go` と同じ作法にする。部品を 1 つ変えたコピーで赤、部品の抽出が 0 件でも赤。
  - `challenges/<cid>/edition/practice/evidence/<file>` (練習版の平らな layout) と名指しの testdata は、緑のまま。selftest に、ここまでの赤と緑の case を全部置く (先頭を 1 段下げた path、入れ子の `<file>`、segment の一部の一致、練習版の seat の形の入れ子とそれ以外の入れ子を含む)。
  - 対象の path が 0 件の木でも、検査そのものは走る (exit status で判定する)。
  - 覆わない範囲: `evidence/` の dir 名を変えた混入と、席の dir だけの混入。この 2 つの歯止めは、`--out` の guard と platform の V83。
- **V94 (A5e #665、3-x の (3) = 3-11 と、values の file・names の受け渡し)**: kubectl の stub で、次を確かめる。
  - deploy-user が、helm に渡した values の file を assert に引数で渡す。assert はその file だけを読む (候補になりうる values の file を 2 つ置いた木で、渡した方だけが使われる)。実績 (#665): この受け渡しは、挙動の test で確かめる。`scripts/check-deploy-user-evidence.sh` が、stub の helm で upgrade を通し、chart の dir の一時の copy の assert を、argv を記録する stub に差し替える。all / scenario / 単一課題 (values あり・なし) の 4 通りで、5 つ目の引数 == helm の `-f`、`<cid>/<name>` の集合 == helm に渡した `names[i]` を照らす。mutant 3 つで赤になる。`all` / `scenario:*` の mode で 5 つ目が `-` なら exit 2。引数が無ければ、非ゼロで終了する。
  - `ctf-evidence-<cid>` の key の集合が names より 1 つ多いとき、1 つ少ないとき、同数で違うときのそれぞれで赤 (3-11)。一致すれば緑。names は、deploy-user が helm に渡すのと同じ導出から引数で受ける (values の file からは読まない)。
- **V95 (A5d #663 / A5e、seat の ns の閉じた集合 = 3-10)**: kubectl の stub で、次を確かめる。
  - type `kubernetes.io/dockerconfigjson` の Secret を 1 つ足すと赤。名前の違う `Opaque` の Secret を 1 つ足すと赤。`ctf-evidence-<cid>` が 1 つ欠けると赤。
  - Helm の release の記録 (type `helm.sh/release.v1`) があっても緑 (別に数える)。
  - #663 の test に無かった case (type `kubernetes.io/dockerconfigjson` の Secret の 1 件) は、A5e (#665) で足した。
- **V96 (A4e-5、空の scenario の明示の形)**: 次を確かめる。
  - `edition render` と `edition check` が、`--scenario <file>` と `--all-challenges` のどちらか一方だけを受ける。どちらも無い・両方ある・空の値の `--scenario` で exit 2。
  - `--all-challenges` の scope が、scenario の無い `catalog.LoadScored` (scoreboard の `scoreboardScenario` が空の起動) と同じ課題の集合になる (fixture での両方の結果の比較が必須。#671 の実装。source test だけでは足りない = 同じ関数を呼んでも、引数の組み立てが違えば集合が違いうる)。
  - 契約表の CLI の行に `--all-challenges` の code span があり、V82 が `editioncmd.go` の名前の定数と照らす (足したコピーと消したコピーで赤)。
- **V97 (P1b-2c の前、platform)**: 課金前の gate の selftest で、次を確かめる。
  - `scoreboardScenario` が空なら render / check に `--all-challenges` を、空でなければ同じ file の `--scenario` を渡す。scoreboard の scope と render / check の scope の出所が違う設定で FAIL。check に渡す scenario と scoreboard の起動に渡す scenario が、同じ出所 (同じ dir の `narrative.yaml` を含む) であることも確かめ、違う設定で FAIL (narrative は B5 の入力で、B12 の digest に入らない。追補 20)。
  - A4e-5 より前の app (pin した app の契約表の CLI の行に `--all-challenges` の code span が無い。SHA の祖先関係では判定しない = platform は app の履歴を持たないことがあり、契約表の行は V82 が app の定数と結んでいる) を pin したまま `scoreboardScenario` が空なら FAIL (#336 の仮決め)。
  - scan の要約の `repo_digest` と生成の表の `image_digest` が違えば FAIL。
  - platform には required check が無いので、merge の時に人が確かめる。
- **V98 (A4e-6、生成の scope と B12)**: 次を確かめる。
  - `edition render` の render-record が v2 の 4 行 (`# falco-ctf render-record v2`・`run-id`・`key-fingerprint`・`scope`) で、`scope` の値が、render に渡した scope の課題の id の順序つきの列から B12 の digest の定義で、renderer と validator が呼ぶ同じ 1 つの関数で計算した digest と一致する。1 件と 2 件の scope の golden の digest と一致する。
  - `edition check` が、次のそれぞれで exit 1 になり、stderr の規則名が B12 である。
    - render と違う scope (evade の課題だけを 1 つ足した scenario)。
    - 同じ課題で順序だけが違う scenario。
    - 調査型の課題を 1 つ外した scenario (B12 が step 1b で先に止め、T4・E2 には届かない。fixture は調査型の課題を 2 つ以上持つ = 1 つ外しても check の scope に調査型が残り、step 1 の exit 2 にならない。review 2 の R4#5)。
  - `--all-challenges` で render した出力を、同じ課題を同じ順に並べた scenario の check に渡すと通る (逆も)。
  - v1 の render-record を渡すと exit 2 (形の誤り)。v2 の header で、次のそれぞれでも exit 2 になる (B12 ではない。step 1b の reader が B12 の比較に進まない。review 2 の R2#1): scope の行が無い 3 行、5 行、scope の値が 64 桁の小文字 hex でない (63 桁・大文字・hex でない)、key 名の違い、scope の行の重複。V99 の platform の case と同じ集合を、app の側にも持つ。
  - 契約表の CLI の行の render-record の header の code span が v2 で、V82 が定数と照らす。
  - digest の定義を 1 byte 変えたコピー (label、label の後の LF、id の後の LF のどれか) で、golden の test が赤になる。renderer と validator のどちらかが別の関数で digest を計算するコピーで、source test が赤になる。
- **V99 (A4e-6 と対の platform、render-record v2 と台帳の mode)**: platform の selftest で、次を確かめる (platform には required check が無いので、merge の時に人が確かめる)。
  - 課金前の gate の lib (P1b-2a) と、同じ lib で読む段 P (P1b-2b) が、v2 の 4 行の render-record を受理する。v1 の header の 3 行、v2 の header で scope の行が無い 3 行、5 行、scope の値が 64 桁の小文字 hex でない、のそれぞれで FAIL (指紋が 63 桁の FAIL の case は残す)。
  - `--first` / `--rekey`: 新しい鍵の指紋が、ops の台帳か、どれかの event の生成の表にあれば FAIL。
  - `--extend`: 指紋が今回の event の生成の表の最新の行と違えば FAIL。今回の event の生成の表が無い・0 行・同じ event の名前が台帳に 2 つ以上ある・その event が終了の印を持つ、のそれぞれで FAIL。成功しても台帳に行を足さない。
- **V100 (P1b-2f、終了の印を書く側)**: platform の selftest の通しの case で、次を確かめる (platform には required check が無いので、merge の時に人が確かめる)。
  - 生成 (`--first`) → teardown (終了の印を書く) → 同じ event への `--extend` が FAIL。
  - teardown で印の書き込みを失敗させる stub では、teardown が非ゼロで終わり、印が無いことを報告する (fail-loud)。
  - 終了の印の欄を持たない旧い版の台帳では、`--extend` が FAIL。台帳が v2 でなければ全部の mode で FAIL。`--first` は、台帳で一度使われた event の名前なら FAIL。`--rekey` は、終了の印のある event なら FAIL (platform#342 の規則の追認。追補 21)。
- **V101 (P1b-2g、終わりでない teardown と再配布の拒否)**: platform の selftest で、次を確かめる (platform には required check が無いので、merge の時に人が確かめる)。
  - 理由つきの明示の引数の teardown は印を書かず、理由の行を台帳に足し、その後の同じ event への `--extend` が通る。理由が空なら FAIL。
  - 既定の teardown の後は、同じ event への `--extend`・`--first`・`--rekey` が FAIL。
  - 終了の印のある event で、段 S の gate と払い出しの lib が FAIL。
  - local でない teardown で、event の dir も「版を使わない」の宣言も無ければ FAIL。
- **V85 (A4e-4 / A5c-2・A5d、layout の parity)**: test が、A5c-2 / A5d の shell が使う `practice/` の dir 名と file 名を、`practicelayout.go` の定数と照らし合わせる。片方だけを変えたコピーで赤になる。実績: A5c-2 (#662) が `practice_deploy_layout_test.go` を、A5d (#663) が一部を足した。残りは A4e-4 (#667) が持った (実装 = `internal/edition/practice_layout_holders_test.go`。範囲の外は Makefile と `Dockerfile.edition-practice` だった。A4e-6b で足す (CI で走らない経路なので、黙って壊れるのを避ける。追補 19 の改訂、#672 R4#5)。無関係な綴りを持つ file は理由つきの除外の一覧。追補 18)。元の要求 (追補 16): 練習版の layout の literal を持つ shell の file の集合を閉じる。`charts/` と `scripts/` の shell の file を走査し、`practicelayout.go` の名前の literal を持つのに parity の test の対象に無い file があれば赤 (抽出が 0 件でも赤)。どの file が今覆われているかは、A4e-4 の PR 本文に一覧で貼る。platform には required check が無いので、merge の時に人が確かめる。
- **V18**: K の式を pin する (attempts が 1 / 2 / 5 のとき K が 4 / 4 / 10)。`decoys` が K − 1 の edition.yaml を E2 が拒否する。decoy の slot を宣言で書こうとする (`role: decoy` や、decoy に vocab を書く) と E1 が拒否する (同一性は構成で成り立つ)。E12 の長さ接頭辞の test。
- **V19**: θ を未設定 (0 / NaN / 1.5) にした build で、B4 は skip せずに拒否する。練習版のテンプレートの filler だけを変えたイベント版で、(1) は通り、(2) が赤。stderr には重なり率の数値と組の id だけが出て、本文の bytes は 0 件。event の束がある課題の練習版の template を消した木、練習版が 0 件の木 (比較の件数 0) で、B4 が違反を返す。席ごとでない format の練習版の答えを event の束の本文に置くと、B4 が拒否する (全 format)。
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
- **V24 (A1e)**: hint にだけある 10 rune の n-gram を、prompt に置いた scope と置かない scope で比べる (fixture には両方とも置く)。prompt に置けば通り、置かなければ違反になること。調査型の scope では、prompt の item の数が設問の数と一致すること (0 件なら fail)。合成した in-memory の scope を `internal/hintleak/scope` の `scope.Assemble` (A4c-1 #635 で非 test に移した。旧名 `assembleScope`) に通して確かめる。`isQuestionPromptSource` の境界は table test で固定する (A4c、#618 LOW)。prompt の数は、Free の実体のうち Source が `<cid> questions[<qid>].prompt` の形の item を数える。組み立て側が数えた値は使わない (A1f、#608)。
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
- **V51 (実機でのみ確認可。sre-engineer、P1b-3 の rehearsal、調査型を含む最初の stand-up の前。手は CoS / CEO、agent は helm / kubectl を実行できない)**: 4 課題 × 512 KiB の圧縮が効かない text の束 (乱数を base64 にした行) を deploy-user で通す。確かめること: Pod が起動する、plant-seed が evict されない、`helm get values` / `helm get manifest` に束の内容が 0 件、Secret の key と bytes が digest と一致する。seat の ns に、3-10 の閉じた集合の外の Secret (image の pull の Secret など) を置かない構成で、3-10 が緑で通る。A5e の key の集合の検査 (3-x の (3) = 3-11。kubectl の go-template で key の名前だけを読む取得が、実 cluster の kubectl で動くことを含む) が、実 cluster で通る (追補 16)。3-10 の確認だけは、この V51 を待たずに、`005437e` より後の app を pin する最初の platform の APP_PIN の bump の verify / rehearsal で先に行う (evade だけの scope にも 3-10 が効くため。D11。追補 16 の改訂、#664 R4#2)。local (colima) と rehearsal の cluster の両方で測る。結果は ws#117 に貼る。
- **V52 (A4b、R4#2)**: Go の test が、`charts/ctf-user/templates/_helpers.tpl` の正規表現の literal (challenge id の 2 か所、file 名の 1 か所) と gen-values の `EVIDENCE_NAME_RE` を読み、`challengeid.Pattern` と B2 の名前の文法の Go の定義 (A4b) と一致することを確かめる。どれか 1 つを変えたコピーで赤になること。
- **V53 (A5d、R4#3)**: Go の test が、catalog の全調査型の `investigate.evidence.mountDir` の集合と、commit 済みの `challenges/values-*.yaml` の `plant.mounts[evidence: true]` の path の集合 (それぞれの scope ごと) が一致することを確かめる。gen-values の導出は使わない。実績 (#663): `internal/catalog/evidence_mount_parity_test.go`。今は両側が空で、A7 から効く。片方だけを変えたコピーで赤になること。
- **V54 (A4e-1、M2)**: `load_source_test.go` の `doorGuarded` に、validator の入口が入っている。
  - `LoadEventTable` の呼び手は `CheckEvent` の 1 か所だけで、`CheckEvent` の呼び手は `cmd/scoreboard/editioncmd.go` の `runEditionCheck` の 1 か所だけ (`load_source_test.go` の `doorViolations`。#648・#649)。
  - `Check` を呼ぶのは、`Load` とその入口が共有する unexported な関数 (と練習版の経路) だけ。
  - `CheckedTable` / `CheckedBundles` / `CheckedEvent` を値として作る式 (composite literal) が、それぞれ load.go / bundlecheck.go / checkevent.go の外に無い。
  - `CheckBundles` が `*Table` を受ける形に戻したコピーで、型の検査か source test が赤になる。
- **V55 (A4c-2a #639、M4)**: `answerformat.Fold` の性質の test。席ごとの 4 format について、受理される綴りを生成する。生成する綴りは次の 4 種類で、どれも `Fold(s)` が正規化した値を部分列に持つ。
  - path: `/` を 1〜3 個に増やす。
  - hexid: 大文字と小文字を混ぜる。
  - timestamp: `+00:00`。
  - 前後の空白。
  - 公開の corpus に hexid の大文字の綴りだけを置いた fixture で、B9 が拒否する (byte の一致のままなら通ってしまう case)。
- **V56 (A4c-1)**: `internal/hintleak/scope` の非 test の関数を、`content_test.go` と validator の両方が呼ぶ。`_test.go` の中に、Free を組み立てる 2 つ目の定義が無い (source test)。
- **V57 (A4e-1、M2)**: 次の 2 つのそれぞれで、B2 の違反になる。
  - `Lstat` の後、open の前に file を symlink に差し替えた case (test の hook)。
  - inode を差し替えた case。
- **V58 (A5c、#633 R4#2)**: Go の test が、次の literal を読んで `MaxBundleFiles` / `MaxBundleBytes` / `MaxSeatBytes` と一致することを確かめる。どれか 1 つを変えたコピーで赤になること。
  - `charts/ctf-user/templates/_helpers.tpl` の「64」。
  - `charts/ctf-user/deploy-user.sh` の、課題ごとの byte の上限と席ごとの byte の上限。
- **V59 (A4e-4、#634 R4#3。V82 に統合)**: `internal/contracttable` の test が、契約表の文面 2 の digests の header (`# falco-ctf evidence-digests v1 run=<run id>`) と列 (`seat<TAB>cid<TAB>digest`) を、`WriteDigests` の出力と照らし合わせる。
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
  - `from` ≥ `to`。`time.base` + `to` − 1 秒が `9999-12-31T23:59:59Z` を超える。
- **V62 (A4d-1b、E2)**: 次のそれぞれで E2 の違反になる。
  - answer の slot が無い席ごとの設問。answer の slot が 2 つある設問。存在しない qid を指す answer。席ごとでない設問を指す answer。
  - `decoys` が K − 1。
  - timestamp の窓の幅が `params.windowSeconds` ± 1。
  - `fixed` に席ごとでない設問が欠けている、または余分な key がある。`fixed` の値が `Canonical` でない。
  - answer の slot の vocab / window が設問の format に合わない (4 つの format それぞれ)。
- **V63 (A4d-2a)**: 作者向けの最小の例 (追補 8) が render を通る。
  - 暗黙の decoy の印を template から 1 つ消すと fail。
  - timestamp の値は窓の中にあり、席ごとに違う (2 席で比べる)。
  - `fixed` の値が `answers.tsv` の全席の行に現れる。
- **V64 (A4d-1b、T6 の範囲)**: 席ごとでない format の event の値が、練習版の同じ format の答えと同じなら T6 が拒否する (今の `Check` の T6 の分岐の挙動を固定する)。

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
- software-engineer (2026-11-17、A4d-2 の wip `1390014`) と architect (追補 10)
  - 席間の衝突の指摘 → T8 は緩めず、U2 (追記だけの席の list と、位置ごとの先着の割り当て) で守る。
  - token の定義と `CandidateFactor = 10` は採用。B7 は席ごとの検査に変えた。
  - 鍵は 32 byte 以上で、版の label を足し、run id は入れない。rejection sampling は採用。`RND` は E3 にした。
  - 分割は A4d-2a / 2b / 2c。
- platform-engineer (platform#340・#341・#342) と review-5x (platform#342 の R4 = MED、R1 = LOW)、CEO (platform の PR の merge の条件、2026-11-19)、architect (追補 21)
  - 終わりでない teardown は、既定で印を書き、例外は理由つきの明示の引数だけ (台帳に理由を残す)。rehearsal は別の event の名前で行う。local でない teardown は、event の dir か「版を使わない」の宣言を要求する。
  - 終わった event の束の再配布は、段 S の gate と払い出しの lib の両方が終了の印を読んで止める (手順では閉じない)。新しい段 P1b-2g、V101。
  - platform#342 の規則 (x) (`--first` は使われた名前で FAIL) と (y) (`--rekey` は終わった event で FAIL) を追認した。
  - platform の内部の手順の細目は、app の ADR に足さず platform#335 に置く (追補 20 の follow-up の方針。移すのは platform の文書ができてから)。
- software-engineer (A4e-6 = #674、A4e-6b = #673) と review-5x T2 の #674 (R4 REQUEST CHANGES = HIGH 1、検証者は confirmed、severity は MED 案)、architect (追補 20)
  - B12 の入力を確かめた: check の結果に効く scenario 由来の入力は、課題の id の順序つきの列と、scenario の隣の `narrative.yaml` (B5 の入力) の 2 つ。B12 が束ねるのは前者だけ。narrative は render の出力に効かないので、digest に入れない。
  - check と scoreboard の起動の間の narrative の一致は、platform が同じ出所の scenario を渡すこと (P1b-2 の要件、V97) で守る。
  - A4e-6 と A4e-6b を済みにした。app の実装の段は全部済み。
- review-5x T2 の #672 の再実行 (追補 19 の改訂。merge 推奨、R4 APPROVE with comments、R1 の条件 = R1#1。MED 3・LOW 9) と CoS (CTO 代行。P1b-2f の新設の決定)、architect (追補 19 の改訂 2)
  - 終了の印を書く側を P1b-2f に名指しした (fail-loud、期限、V100)。P1b-2f が入るまでは、台帳の版で `--extend` を fail-closed にする。
  - V98 に、check の reader の negative を足した (v2 の header の形の誤りは exit 2 で、B12 ではない)。
  - step 3b の墓標の行を消した。platform の reader の v2 化と APP_PIN の bump を、同じ 1 つの PR にした。行の数は header を含めて数える。golden は実装と別の経路で得る。B12 が最初に名指しする条件と、fixture の条件を書いた。digest の入力を id の順序つきの列に確定した。
  - follow-up (この改訂では直さない。review 2 の R4#7): platform の内部の手順 (台帳の mode、event の同一性、やり直しの手順、V99・V100 の細目) は、platform の ADR か設計の文書に移し、app の ADR には契約の面 (render-record v2・B12・終了の印の要求) と参照だけを残す。移すのは、platform の文書が main に入った後の追補で行う。
- review-5x T2 の #672 (追補 19。R4 REQUEST CHANGES = HIGH 1 (検証者は confirmed、severity は MED 案)・MED 5・LOW 6) と CoS (platform の lib の render-record の読み方と、段 P の台帳の mode の照合)、architect (追補 19 の改訂)
  - A4e-6 の対の相手を、platform の render-record の reader (P1b-2a の lib と、それで読む段 P) を v2 に上げる PR と確定した。V99 を足した。
  - 台帳の照合を mode で分けた (`--first` / `--rekey` = 全 event と不一致、`--extend` = 今回の event の最新の行と一致)。event の同一性は署名された tree の生成の表で決め、終了した event の延長は FAIL にする。
  - B12 を表を読む前 (step 1b) に動かした。digest を byte 列で 1 つに定義し、golden と、renderer と validator が呼ぶ同じ関数を求めた。
  - 契約表の render-record の記述を v2 の 4 行に広げ、exit の列挙に B12 と v2 でない header を足した。V84 に v2 の header を足した (v1 も拒否のまま)。V85 の拡張は A4e-6b に分けた。
- software-engineer (A4e-5 = #671) と platform-engineer (P1b-2b = platform#339 の review の R4)、CEO (計画の判断事項、2026-11-19)、architect (追補 19)
  - 生成の scope は、app の B12 (render-record v2 の scope の digest) で束ねる。app の check は、調査型でない課題だけの違いと順序の違いを、B12 の前は止めなかった。platform の表の列だけで束ねると、照合が required check の無い側に寄る。
  - image の版を変えた後のやり直しは、`--extend` (同じ list は E3 を通る) → B10 で拒否されたら止めて COO が判断 → 配り直しは `--no-previous`。同じイベントなら同じ鍵。
  - V96 の fixture での比較を必須にした。V97 の判定は、pin した app の契約表の行で行う。V85 に Makefile と `Dockerfile.edition-practice` を足す (A4e-6。改訂で A4e-6b に移した)。案の label を S-A / S-B にした。
- software-engineer (A4e-4 = #667) と platform-engineer (P1b-2a = platform#336、P1b-3a = platform#337) の review、architect (追補 18)
  - A4e-4 の実績を記録した。鍵の上限 `4096` byte と、mode を実際の出力の Stat で照らす形を追認した。
  - 空の scenario は、案 S-B (D20 の記録。D15 の候補 B とは別) (`--all-challenges` を足す = A4e-5) にした。scoreboard の 2 つの scope の形を CLI がそのまま写すので、検査した scope と配る scope が同じ関数で一致する。空の値は今どおり拒否する。
  - 払い出しの引数を scope に合わせた (evade だけの scope は `--flags-file` だけ)。契約表の散文も直した。
  - platform の仮決め (a)〜(d) を追認した。(b) は、digest が違うときを INFO から FAIL に変えた。
- software-engineer (A5e = #665) と review-5x (#665。R1 の LOW と、差分の再査定)、architect (追補 17)
  - names の出所を、「values の file から読む」から「deploy-user が helm に渡す names と同じ導出を、引数で渡す」に直した (names は values の file に無い)。どの cid が調査型かは、values の file から読む。
  - 5 つ目の引数 (values の file か `-`)、`all` / `scenario:*` の mode での `-` は exit 2、(3) = 3-11、自己選択の 3 通りの分岐の削除を追認した。
  - V94 の受け渡しを挙動の test (4 通り、mutant 3 つ) で確かめる形を追認した。V51 に、go-template による key の取得の実機の確認を足した。
- review-5x T2 の #664 (追補 16。R4 MED 3・R2 LOW 2。R1 APPROVE) と CoS (CTO 代行。(4) を自動の検査にしないこと・閉じた集合の追認・A5e の新設を承認)、architect (追補 16 の改訂)
  - 閉じた集合と 3 つの引数を、D20 の契約の分け方に [散文] で足した。D20 の P1b-3 の項は、D19 の行を正典として参照する。
  - 3-10 は全部の scope に適用される。実 cluster での確認は、次の APP_PIN の bump の verify / rehearsal で行う。
  - platform の runbook の「3-9」との番号の衝突を注記し、修正を P1b-3 の要件に入れた。
  - A5e は、A7 の直接の前提ではない (V51 を介してだけ)。A5e までの (3) の状態を書いた。
- software-engineer (A4e-3c = #660、A4c-3 = #661、A5c-2 = #662、A5d = #663) と review-5x (#663 R2#1・R4#1〜#4)、architect (追補 16)
  - 3-x の (3) は A5e (values の file を引数で渡し、assert の自己選択の規則を消す)。(4) は deploy の時の自動の検査にせず、V50 と V51 に割り当てた。
  - seat の ns の閉じた集合 (3-10) を追認した。platform への制約として、P1b-3 と契約表の文面 2 (散文) に書く。
  - shell の 3 つ目の reader を、理由 (ADR-0001 の builtin の制約) と parity の仕組みとともに記録した。
  - A5c-2 の仮決めを全部追認した。V85 の残り (shell の file の集合を閉じる) は A4e-4 が持つ。
  - 実装の番号 3-9・3-10 を D11 に記録した (runbook と照らす正典。platform の runbook の旧い「3-9」(= app の 3-8) との衝突は P1b-3 で直す)。gen-values の入口を 5 つに直した。
- review-5x T2 の #659 (追補 15。R4 MED 1・LOW 2、R2 LOW 2) と CoS (`.claude/rules/**` が Edit の deny の外であることの照合)、architect (追補 15 の改訂)
  - V93 に parity を足した (script の pattern の 3 つの部品を Go の定義と照らす)。
  - 一致の規則を部分一致にした (segment の全体で照らす)。練習版の seat の形でない入れ子は、練習版の layout の持ち主に任せる。
  - 段の名前と未来形を、b-i / b-ii の実績に直した。
  - dev-flow.md の D の行は、統治文書ではなく A4e-3c の PR に同梱する。契約表の編集の手順も、事実の文にした。
- software-engineer (A4e-3b-i = #657、A4e-3b-ii = #658) と review-5x (#657 R4#1、#658 R2#2・R3#1・R3#3・R4#2)、CoS (flags の loader の形の照合)、architect (追補 15)
  - A4e-3 が全部 main 入り。A4e-3b を b-i / b-ii として記録した。
  - evidence だけの混入は、path の規則 (A4e-3c、V93) で止める。理由: B6 によって、束 1 つが答えの漏えいになる。
  - T7 は loader (`internal/catalog/flags.go`) が flag の形を強制するので、追加の case は置かない。
  - `make edition-practice` の実際の形と、container の中の EXDEV を記録した。`OutputError` の `Left` / `Restore`、`practiceStale` も記録した。
  - A4e-4 は、platform の CI が止まっている間も、3 つの条件を満たせば app の行を先に merge してよい。
- review-5x T2 の #656 (追補 14。R4 MED 1・LOW 5) と software-engineer (A4e-3b の実績)、architect (追補 14 の改訂)
  - `RenderEvent` の自己検査の配線を、V78 の正の pin (source test) で守る (B7 は renderer の入力から破れないため)。
  - T7 は「flag の形の前提が崩れたときの歯止め」として残し、loader が形を強制しないなら A4e-3b で case を足す。
  - 鍵の負の case (LF なし・CRLF・2 行目・4 KiB 超) を V80 に足した。
  - 契約の分け方の各項目に、[code span = V82 が照らす] か [散文 = 検査の対象外] かの印を付け、V82 の範囲を合わせた。
  - V の見出しを 3a-i / 3a-ii / 3b の分担に直した。A4e-3b の実績 (`practiceedition.go`・`replaceTreeAtomic`・`check-edition-headers.sh`) を段の表に記録した。
- software-engineer (A4e-2d = #652、A4e-2c = #653、A4e-3a-i = #654、A4e-3a-ii = #655) と review-5x (#655 R4#1〜#3)、CoS (CTO 代行、#655 R4#2)、architect (追補 14)
  - A4e-3 を 3a-i / 3a-ii / 3b に分けた。V84 を 3b に割り当てた。
  - 仮決めを追認した: 鍵の形 (末尾の LF は必須 = 切れた書き込みの検出)、Join の写像 (1 = 違反だけ、3 = 書き出しの失敗だけ、ほかは 2)。
  - `--out` の guard の限界を記録し、host の側の確認を platform に置いた。renderer を呼んでよい非 test の file は 2 つ。
  - V80 を実態に合わせた (B7 / T7 は validator の側で破る)。V92 の check の分を、seam と AST の組にした。
  - A4e-4 の行に入れるものを列挙した。
- review-5x T2 の #651 (追補 13。R2 MED 2・R4 MED 3・LOW 2) と architect (追補 13 の改訂、2026-11-20)
  - exit 3 の commit の点を `os.Link` / rename の成功に置いた。commit の後の後始末の失敗は exit 0 + stderr で、作業の dir の掃除は platform が持つ。
  - cmd の写像は `*Violation` だけ 1・未分類は 2・Join の混在は 2。panic は契約にしない。
  - test の支援 package は renderer を呼ばない ((b)。V78 の閉じた一覧は変えない)。
  - V89 の対象を「override を当てて hint の列を組む処理」に定め、`LoadJourneys` / `LoadRuleExcerpts` だけを使う呼び手を対象の外と列挙した。
  - I2 は cluster の中の container を指すと解釈した。`--user` の uid 0 は platform が実行の前に止める。
- software-engineer (A4e-2a = #648、A4e-2b = #649) と review-5x (#648 T2、#649 T3)、architect (追補 13、2026-11-19)
  - 規則名: render-record の run id の不一致は、新しい B11 にした (T3 は起動でも当たる表の形の規則なので分けた)。`--edition-root` の `<cid>` の集合は E2。validator の template の lexer の失敗は E3 (render と同じ名前)。
  - exit 3 = 検査を全部通った後の書き出しの失敗 (環境) を足した (#649 の review: 使い方の誤りと環境の失敗が同じ 2 だった)。stdout は人のための表示で、契約ではない。
  - B10 は包含 (前回の (seat, cid) ⊆ 今回) と、共通部分の digest の一致。前回の run id は照らさない。
  - validator の container は、`--user` = 運用者の uid で動かす (P1b-2)。
  - hint の入力の読み込みの 3 つの写し (#648 の review) は A4e-2c で、test の正の fixture の複製 (#649 の review) は A4e-2d で、1 つにする。
  - A4e-2 の分割と V の割り当て、`CheckEvent` の実際の順序を、D19・D20 に記録した。
- software-engineer (A4e-1 = #646) と review-5x (#646 R4#1)、architect (追補 12、2026-11-19)
  - 「event の digests を書いてよい」を、`CheckEvent` だけが作る `*CheckedEvent` で表した (G1)。`WriteDigests` は A4e-2 でそれだけを受ける形に変える。
  - #646 の実績を D9・D20・P1b-2・V に記録した: `openRegular` / `openFollowing`、保証は最後の要素だけ、O_NONBLOCK、`os.Link` → `os.Remove`、hard link を作れない filesystem。
  - event の `--out` の名前は、練習版とは別の定数にする。gofmt の検査は F-fmt。
- software-engineer (A4d-2a〜c = #642〜#644) と architect (追補 11、2026-11-18)
  - 採用した仮決め: `render-record` の 3 行の形、練習版を B7 / B8 (b) に渡すと拒否、印が token の途中にある template は E3、`PracticeOutput` の印は全部 0 の run id だけ。
  - A4e の仕様を D20 に集めた。「初回」は `--no-previous` で表す。鍵は `--key-file` だけ。出力は一時 dir → rename。`edition render --practice` を足した。A4e を 4 本に分けた。
- review-5x の #641 (追補 10、2026-11-18、R1 APPROVE w/ comments、R4 REQUEST CHANGES = HIGH 1) と architect (追補 10 の改訂)
  - 追記だけの席の list を機械の検査にした (E3 の接頭辞・B10・P1b-2)。
  - validator の B7 に、席の間の重複の検査を足した (renderer を信頼しない)。
  - B8 (a) を 2 段にした (2N は renderer の E3 と validator)。V68 の fixture を直した。
  - E3 を E2 の後に置き直した。D12 の旧文面と V72 を直した。
  - 鍵の指紋を採用した。
  - B4 の席ごとでない format の完全一致は、T6 を理由に許した。
  - 旧名と Q の参照を直した。Signpost を移動だけで昇順にした。
- review-5x の #640 (2026-11-17)
  - B4 は全 format (CoS の差し戻しを支持)。
  - M2 を訂正した (起動の経路は束も template も読まない)。
  - B4 の入力の完全性。印の文法は renderer の lexer が持つ。shingle の窓は A4c-3。
- software-engineer (2026-11-17、A4d-1 の wip `3e888f0`) と architect (追補 8): edition.yaml の schema を確定した。
  - 採用: E1 / E2 の名前、位置ごとの語彙の直積、上限 4 つ、message に語彙を出さないこと。
  - 変更: `version`・`time`・`fixed` を足した。role を answer / filler + `question` の 2 key にした。decoy を `decoys: <n>` から作る形にした。anchor と alias を拒否する。hexid / timestamp の生成を設問の params・`time.base` + 窓で決めた。
  - T6 は固定の答えにも効く (公開の練習版から解ける答えを、イベントで繰り返さない) ことを V64 で固定する。
