# ADR-0033: flags ファイルは指定したら完全であることを必須にする — スコープ内の全 evade 課題に既定値と異なる flag が無ければ、採点側は起動を拒否し、仕込み側は cluster に触れる前に止まる (クロスリポ契約)

- Status: **Proposed** (Accepted 化は、本 ADR を同梱した実装 PR の CEO merge 時。ORGANIZATION.md §7 のゲート)
- Date / Deciders: 2026-10-05 / CEO (同日「P28 と切り離して先に直す」、Class-2 merge)、VP (ADR 必須の裁定、レビュー指摘の
  採用)、architect (起草)、software-engineer (実装)、security-engineer (採点真正性の確認 — 確認待ち)
- 関連: 実装ブランチ `fix/flags-file-fail-closed` (e416705 + レビュー反映 e628ea4)、契約表 Flags 行 (`.claude/rules/falco-ctf-app-conventions.md`)。ADR-0001
  (flag の到達経路。C6 の引数面は不変) と ADR-0010 (I12) は supersede しない — あちらは「値がどこへ届くか」、本 ADR は
  「入力をどの条件で受理するか」。未 merge の ADR-0026 C1 が「別 Issue」とした修正の実体。platform の同時 PR (番号は起票時に追記)

## Context

- **契約**: flag の正典は platform の `events/<date>/flags.sops.yaml` で、同じ 1 ファイルを 2 つの消費者が読む
  (platform `events/README.md:31`)。採点側 = scoreboard (`FLAGS_FILE`。変更前は `catalog.ApplyFlagOverrides`)、
  仕込み側 = `charts/ctf-user/deploy-user.sh --flags-file` (→ `ctf-flags` Secret → `plant` initContainer、ADR-0001)。
  公開リポが持つのは placeholder (`FALCO{dev-<slug>}`) だけで、その値は公開されている。
- **変更前 (e74d871)**: 両消費者とも、ファイルに列挙された id にだけ上書きを掛けていた。evade 課題の id が欠けていても
  エラーにならず、欠けた課題は既定値のまま動いていた (`internal/catalog/flags.go:44-57`、`charts/ctf-user/deploy-user.sh:206-224`)。
  既定値と同じ値の供給も受理していた。
- **生成側にも検証が無い**: platform の preflight は暗号化だけを見ており (`scripts/preflight-event.sh:20-47`)、生成手順は
  evade の id をハードコードしている (`events/2026-09-03/flags-README.md:23`)。既存 4 イベントのファイルの key は、すべて
  evade の全集合 (03/05/10) である (2026-10-05 実測。sops は key を平文で持つので復号は不要)。
- **2 つの消費者はスコープも実行場所も違う**: scoreboard は scenario で採点対象を絞れる (`Restrict`)。deploy は `all` /
  `scenario:<name>` / `<NN-slug>` のモードを持ち、platform の `scripts/deploy-event-workspaces.sh` は helmfile の読み取りに
  失敗すると `all` に倒れる (`:180-203`)。scoreboard は `appImageTag` (git SHA、I4) で固定された image の catalog を読み、
  deploy は運用端末の兄弟 app checkout を直接呼ぶ (`:111`)。運用端末に Go は前提されていない。
- **ADR を書く理由**: ORGANIZATION.md §8 の基準 ② クロスリポ契約の変更、③ 採点真正性の設計変更 (2026-10-05 VP 裁定)。

## Options (仕込み側の検証を、採点側の Go 実装とどう揃えるか — Decision 1-3・5-8 は共通の要件で、選択肢ではない)

- **A. Go の検証を scoreboard バイナリのサブコマンドにし、deploy は pinned image を `docker run -i` で呼ぶ。** コスト: deploy
  経路に docker と image の取得が加わる (運用端末への常在は保証されていない)。image は増えない (I5 不変)。リスク/可逆性:
  可逆。image の CLI が新しい契約面になる。モードから plant する id を導く規則は Go で再導出したままで、chart template との
  2 定義が残る。効き始める閾値: 運用端末に scoreboard image が常在するようになったとき。
- **B. 仕込み側の検査を `charts/ctf-user/templates/ctf-flags-secret.yaml` の描画に寄せる。** `--flags-file` 指定時に、描画する
  `CTF_FLAG_*` が placeholder のままなら `fail` し、deploy-user.sh は cluster に触れる前に `helm template` でオフライン判定する。
  コスト: override 後は既定値が見えないので、placeholder を判定する述語 (例: placeholder 形式 `FALCO{dev-<slug>}` の値を契約上
  禁止する) を決める必要があり、values の契約に触れる。利点: 仕込みスコープの定義元で検査するので欠落と未ローテーションが
  1 つの述語になり、shell によるスコープの再導出と `values.yaml` の書式への結合が消える。新しい依存なし。可逆。閾値: Signpost 1・2。
- **C. shell 実装を残し、Go と shell が共通の入力集で同じ判定を返すことを parity テストで機械検査する。** コスト: 最小、
  新しい依存なし。リスク: 定義は Go / shell / template の 3 つ残るが、Go と shell の判定の割れは required check で red になる。
  可逆。効き始める閾値: 即時。

## Decision

**flags ファイルは指定したら完全であることを必須にし、二重実装は C で揃える。B を follow-up の推奨とする。** 理由: 何を
採点するかの真正性は Go に一本化されており、shell の判定の割れは、レビューで確認した範囲では止まる側 (拒否) にしか出ない。
A・B は新しい依存か values 契約の変更を伴うので、fail-open の修正 (CEO 決定) とは切り離して決める。

1. **flags ファイルを指定したら、次をすべて必須にする**: (a) スコープ内の全 evade 課題に flag が供給されている (b) どの値も、
   どの課題のリポ既定値とも同値でない (c) 課題間で値が重複しない (d) 未知の id・evade 以外の id・同じ id の重複・形式違反が
   無い。1 つでも破れば、採点側は起動を拒否し、仕込み側は cluster に触れる前に非ゼロで終了する。全件を検証してから適用する。
2. **スコープ**: 採点側 = scenario の `Restrict` 後の catalog。仕込み側 = deploy モードが plant する evade 課題 (`all` = 全 evade、
   `scenario:<name>` = その scenario の evade、`<NN-slug>` = その課題が evade なら 1 件)。スコープ外の id は (b)(c)(d) の検証
   だけを行い、適用しない (helm にも渡さない)。1 イベント 1 ファイルを、どのモード・どの scenario でも使い回せるようにするため。
3. **値の形と書き方を絞る。** 値は `^FALCO\{[A-Za-z0-9_-]+\}$` に限る。同じ `catalog.flagRE` が `falco-rule.yaml` の
   `expectedFlag` (catalog の読込時) にも効くので、課題側の placeholder も同じ文字集合に収める。ファイルは YAML の部分集合に
   限る: top-level の `flags:` は 1 つだけの block mapping、1 行 1 エントリ、値はキーと同じ行にリテラルで書かれた scalar
   (`'...'` / `"..."` は可。エスケープ・ブロック/フロー/複数行・エイリアス・複数ドキュメント・重複キーは不可)。Go は
   デコーダの既定挙動に頼らず `yaml.Node` を歩いて自前で拒否し、shell は行単位でさらに狭く読む (差は D4 の 6 件)。理由: YAML と shell の
   引用・エスケープの解釈差による採点値と仕込み値の食い違い、および helm の `--set-string` への値の注入を閉じる。
4. **採点側 (Go、`internal/catalog`) が真正性の正。** 仕込み側 (shell、`charts/ctf-user/validate-flags-file.sh`) は cluster に
   触れる前の早期検出で、判定が食い違ったら Go に従う (直すのは shell 側)。一致は parity テストで確かめる: 共通の入力集
   `internal/catalog/testdata/flags-parity/` を両側のテストが読み、受理した側は `expected.tsv` どおりに読むこと、判定が
   分かれる入力は `cases.tsv` に固定すること、「shell だけ受理」が 0 件であることを両側が assert する。2026-10-05 時点で
   43 入力: 両側受理 7 / 両側拒否 30 / Go 受理・shell 拒否 6 (CRLF・行末コメント・anchor・BOM・quoted key・`key : value`) /
   shell だけ受理 0。
5. エラー文言とログには行番号と検証済みの課題 id だけを出す。flag の値、解釈できなかった行の内容、YAML デコーダの文言は出さない。
6. **catalog の読込を `catalog.LoadScored(challengesDir, scenarioFile, flagsFile)` 1 関数にまとめる** (読込 → scenario の
   Restrict → flag の検証と適用)。元の catalog は変更せず新しい catalog を返し、旧 `ApplyFlagOverrides` は廃止する (検証と適用の
   本体は package の外から呼べない)。`cmd/scoreboard/main.go` は catalog を `LoadScored` 1 回の呼び出しだけで得て、2 つ目の
   catalog 値を持たない。2 つの catalog を引数で受ける形には、取り違えてもエラーにならず、上書きが採点に届かない経路が残るため。
7. **flags ファイルを指定しない経路 (ローカル開発) は変えない。** 検証せず placeholder を使う。
8. **クロスリポ契約**: 契約表 Flags 行に要件を追記する。受理条件が「欠けた id は既定値」から「欠けたら拒否」に変わる
   (optional → required の破壊的変更) ので、platform はイベント用ファイルを **全 evade id** について生成する義務を負う。
   platform の同時 PR は、要件の明記、生成する id を app の evade 集合 (pinned `appImageTag` 時点) から導くこと、preflight での
   key の完全性検査、`scripts/standup.sh` が `--flags-file` を渡していない件、example 値の拒否を扱う。merge 順序は問わない
   (両側とも fail-closed。既存ファイルの key は要件を満たし、値の条件は復号が要るので platform の preflight で確かめる)。

## Consequences

- **諦めたもの**: 規則の単一実装 (2 実装を parity テストで縛る)。shell の検証器は `charts/ctf-user/values.yaml` の
  `challenge.flags` の書式に結合する (B で解消する)。網羅性をスコープ単位で求めるので、platform の「全 evade id を生成する」
  義務は消費者側では一部しか検証されず、platform の preflight で補う。
- **課題の content 契約が狭まる**: `expectedFlag` も `^FALCO\{[A-Za-z0-9_-]+\}$` に収める (従来は `}` 以外の任意文字)。
  外れた課題は、`FLAGS_FILE` の有無に関係なく catalog の読込で落ちる。
- **検出しないもの (残余)**: 過去のイベントの値の再利用。検査は既定値・重複・形式に限られ、本 ADR は「ローテーション済み」を主張しない。
- **範囲外として明記する既存の穴**: flags ファイル自体を指定しない構成 (`FLAGS_FILE` 未設定、`--flags-file` 未指定または空) は
  本 ADR の検査の対象外で、従来どおり placeholder で動く。本番構成でこれを防ぐゲート (本番環境では flags の供給を必須にする)
  は platform 側 (同時 PR の範囲) で扱う。
- **運用への影響**: image tag を上げた scoreboard は、不完全な Secret のまま再起動すると起動を拒否し、I1 (replicas 1 + Recreate)
  なのでその間は全断する。tag を上げる前に preflight で key の完全性を確かめる (runbook に追加。CHANGELOG に注意を記載済み)。
  同じ tag での再起動では挙動は変わらない (I4)。仕込み側は運用端末の app checkout を直接呼ぶので、app の merge 時点で効く。
- **evade 課題を足す変更**は、次のイベントのファイルにその id が無ければ両側で止まる。`.claude/skills/add-challenge/SKILL.md` の
  チェックリストが既に求めている手順を、機械で強制する形になる。
- **Hard Invariant への昇格: not yet。** この ADR の Accepted、Decision 6 の配線テスト、Go と shell の一致の機械検査が required
  check に揃ったら、採点側の性質 (「`FLAGS_FILE` 指定時、採点スコープの全 evade 課題に既定値と異なる flag が供給されない限り
  scoreboard は起動しない」) に絞って昇格する。それまで conventions の表には追記しない (`docs/adr/README.md` の規律)。

## Signposts

1. ADR-0025 / P28 で `ctf-flags-secret.yaml` のスコープ規則を変える PR が出た → B を前倒しする (shell によるスコープの
   再導出が、3 つ目の定義として古くなる前に)。
2. 判定が分かれる行 (`cases.tsv`、現在 6) が増え続ける、「shell だけ受理」を許す必要が出る、または規則を変えるたびに入力集の
   手直しが要る → B へ移る。
3. 運用端末に scoreboard image が常在し、deploy 経路で docker を前提にできると確認できた → A を再評価する。
4. スコープを絞った部分ファイルを使う運用が次のイベントまで 1 件も無い → 網羅性をスコープ非依存 (全 evade id 必須) に
   締める。締める方向は後から緩められるが逆は破壊的で、締めれば Decision 2・6 の複雑さが消える。

## Verification

テスト名は e628ea4 時点。「変更前に red」= e74d871 の挙動では受理されてしまうケース (API が変わったので挙動で比べる)。

- **採点側** (`make test` = required の `test`): `internal/catalog/flags_test.go`
  - `TestScored` の拒否系サブテスト (変更前に red): `no scenario, one evade flag missing: rejected` /
    `no scenario, two evade flags missing: both named` / `full scenario, one evade flag missing: rejected` /
    `subset scenario, its evade flag missing while others are supplied: rejected` /
    `value equals that challenge's repository default: rejected` / `value equals ANOTHER challenge's repository default: rejected` /
    `out-of-scope entry equals a repository default: still rejected` / `two challenges share one value: rejected` /
    `out-of-scope entry shares a value with an in-scope one: still rejected` /
    `same challengeId twice: rejected (not left to the YAML decoder's defaults)` / `two top-level flags keys: rejected` /
    `second YAML document: rejected` / `value on the line after the key: rejected`。同じテストが、拒否時に何も適用しないこと
    (D1) とエラー文言に値が出ないこと (D5) も確かめる。
  - `TestScored_FlagCharacterSet` (D3。comma などは変更前に red)、`TestScored_EmptyPathAppliesNothing` (D7)、
    `TestScored_MissingFileFailsClosed`、`TestFlagsFileParity` (D4)。
  - `TestLoadScored_RealCatalogAndScenarios` (D2・D6): 実 `challenges/` と全 scenario で、採点 catalog がファイルの flag を持ち、
    flags ファイル無しなら既定値のまま、evade id が欠けたファイルはその id がスコープ内のときだけ拒否されること。
  - `cmd/scoreboard/main_test.go` の `TestMainLoadsCatalogOnlyThroughLoadScored` (D6): `main.go` が `LoadScored` を 1 回だけ呼び、
    `catalog.Load(` / `catalog.LoadScenario(` / `.Restrict(` を直接呼ばないことをソースで検査する。
- **仕込み側** (`make check-flags` / CI `flag-guard` = required): `scripts/check-flags-file-validation.sh`
  - A 部 (変更前に red。e74d871 の deploy-user.sh は検証を持たない): `all: one evade flag missing` /
    `all: value equals the repository default` / `all: value equals ANOTHER challenge's repository default` /
    `all: two challenges share one value` / `all: comma in a value` / `all: duplicate id` /
    `scenario nimbusbreach-full: one evade flag missing` / `scenario tutorial-intro: its evade flag missing` /
    `single evade challenge: its flag missing`。
  - stdout 系 (D2): `scenario tutorial-intro, full event file: stdout is its one pair only` ほか。P 部 (D4): `cases.tsv` の全行。
  - B 部: `expect_deploy_rejected` が、拒否時に非ゼロで終了し、helm / kubectl を 1 回も呼ばず (stub で記録)、値を出さないことを
    確かめる。`…, full event file: only its own flag reaches helm` (D2) と `no --flags-file (local dev): unchanged, no override` (D7)。
- **platform 側**: preflight の key の完全性検査は、platform の同時 PR の landing で確かめる。
- **機械では確かめられないもの**: 過去のイベントの値の再利用 (Consequences の残余)。

## Advice

- R4 architect (2026-10-05): ADR は必須 (§8 ②③)。platform の同時 PR が要る。2 つの catalog 引数の取り違え (→ D6)。
  二重実装は follow-up とし B を推奨。HI 昇格は not yet。
- R3 conventions (2026-10-05): HI の新設・変更には当たらない。単一ソース化の follow-up を残す。1 PR のまま進める (片側だけ
  先に land すると「両側 fail-closed」が成り立たない期間ができる点で、architect も同意)。
- R1 security-engineer (2026-10-05): flags ファイル自体を指定しない経路を要判断として提起 → 範囲外として明記した。
- R4 architect 再確認 (2026-10-05、e628ea4): Finding 3 (→ D6 の `LoadScored`)・4 (Go が正)・6 (「ローテーション済み」を主張しない) の閉止を確認。
- VP (2026-10-05): ADR の要否は R4 を採用 (R3 は不要と判定)。レビュー指摘を全件採用し、D1 (b)(c)・D3・D4 の parity・D6 を実装に追加。
