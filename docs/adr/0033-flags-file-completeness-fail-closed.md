# ADR-0033: flags ファイルは指定したら完全であることを必須にする — スコープ内の全 evade 課題に既定値と異なる flag が無ければ、採点側は起動を拒否し、仕込み側は cluster に触れる前に止まる (クロスリポ契約)

- Status: **Proposed** (Accepted 化は、本 ADR を同梱した実装 PR の CEO merge 時。ORGANIZATION.md §7 のゲート)
- Date / Deciders: 2026-10-05 / CEO (同日「P28 と切り離して先に直す」、Class-2 merge)、VP (ADR 必須の裁定、レビュー指摘の
  採用)、architect (起草)、software-engineer (実装)、security-engineer (採点真正性の確認 — 確認待ち)
- 関連: 実装ブランチ `fix/flags-file-fail-closed`、契約表 Flags 行 (`.claude/rules/falco-ctf-app-conventions.md`)。ADR-0001
  (flag の到達経路。C6 の引数面は不変) と ADR-0010 (I12) は supersede しない — あちらは「値がどこへ届くか」、本 ADR は
  「入力をどの条件で受理するか」。未 merge の ADR-0026 C1 が「別 Issue」とした修正の実体。platform の同時 PR (番号は起票時に追記)

## Context

- **契約**: flag の正典は platform の `events/<date>/flags.sops.yaml` で、同じ 1 ファイルを 2 つの消費者が読む
  (platform `events/README.md:31`)。採点側 = scoreboard (`FLAGS_FILE` → `catalog.ApplyFlagOverrides`)、
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
  `CTF_FLAG_*` が placeholder のままなら `fail` する。deploy-user.sh は cluster に触れる前に `helm template` でオフライン判定
  する。コスト: override 後は既定値が見えないので placeholder を判定する述語を決める必要があり (例: placeholder 形式
  `FALCO{dev-<slug>}` の値を契約上禁止する)、values の契約に触れる。利点: 仕込みスコープの定義元で検査するので、欠落と
  未ローテーションが 1 つの述語になり、shell によるスコープの再導出と `values.yaml` の書式への結合が消える。新しい依存は
  無い。可逆。効き始める閾値: Signpost 1・2。
- **C. shell 実装を残し、Go と shell が共通の入力集で同じ判定を返すことを parity テストで機械検査する。** コスト: 最小、
  新しい依存なし。リスク: 定義は Go / shell / template の 3 つ残るが、Go と shell の判定の割れは required check で red になる。
  可逆。効き始める閾値: 即時。

## Decision

**flags ファイルは指定したら完全であることを必須にし、二重実装は C で揃える。B を follow-up の推奨とする。** 理由: 何を
採点するかの真正性は Go に一本化されており、shell の判定の割れは、レビューで確認した範囲では止まる側 (拒否) にしか出ない。
A・B は新しい依存か values 契約の変更を伴うので、fail-open の修正 (CEO 決定) とは切り離して決める。

1. **flags ファイルを指定したら、次をすべて必須にする**: (a) スコープ内の全 evade 課題に flag が供給されている (b) どの値も、
   どの課題のリポ既定値とも同値でない (c) 課題間で値が重複しない (d) 未知の id・evade 以外の id・形式違反が無い。1 つでも
   破れば、採点側は起動を拒否し、仕込み側は cluster に触れる前に非ゼロで終了する。全件を検証してから適用する (部分適用しない)。
2. **スコープ**: 採点側 = scenario の `Restrict` 後の catalog。仕込み側 = deploy モードが plant する evade 課題 (`all` = 全 evade、
   `scenario:<name>` = その scenario の evade、`<NN-slug>` = その課題が evade なら 1 件)。スコープ外の id は (b)(c)(d) の検証
   だけを行い、適用しない (helm にも渡さない)。1 イベント 1 ファイルを、どのモード・どの scenario でも使い回せるようにするため。
3. **flag の文字集合を `^FALCO\{[A-Za-z0-9_-]+\}$` に絞る。** YAML と shell の引用・空白の解釈差による採点値と仕込み値の
   食い違い、および helm の `--set-string` への値の注入を閉じる。
4. **採点側 (Go、`internal/catalog`) が真正性の正。** 仕込み側 (shell、`charts/ctf-user/validate-flags-file.sh`) は cluster に
   触れる前の早期検出で、判定が食い違ったら Go に従う。一致は共通の入力集による parity テストで確かめる。
5. エラー文言とログには課題の id だけを出し、flag の値は出さない。
6. **Restrict と上書きを 1 関数にまとめ**、採点に使う catalog と検証用の全 catalog を呼び出し側 (`cmd/scoreboard/main.go`) で
   取り違えられない形にする。2 つの catalog を引数で受ける形には、取り違えてもエラーにならず、上書きが採点に届かない経路が
   残るため。
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
- **検出しないもの (残余)**: 過去のイベントの値の再利用。検査は既定値・重複・形式に限られ、本 ADR は「ローテーション済み」を主張しない。
- **範囲外として明記する既存の穴**: flags ファイル自体を指定しない構成 (`FLAGS_FILE` 未設定、`--flags-file` 未指定または空) は
  本 ADR の検査の対象外で、従来どおり placeholder で動く。本番構成でこれを防ぐゲート (本番環境では flags の供給を必須にする)
  は platform 側 (同時 PR の範囲) で扱う。
- **運用への影響**: image tag を上げた scoreboard は、不完全な Secret のまま再起動すると起動を拒否し、I1 (replicas 1 + Recreate)
  なのでその間は全断する。tag を上げる前に preflight で key の完全性を確かめる (runbook に追加)。同じ tag での再起動では挙動は
  変わらない (I4)。仕込み側は運用端末の app checkout を直接呼ぶので、app の merge 時点で効く。
- **evade 課題を足す変更**は、次のイベントのファイルにその id が無ければ両側で止まる。`.claude/skills/add-challenge/SKILL.md` の
  チェックリストが既に求めている手順を、機械で強制する形になる。
- **Hard Invariant への昇格: not yet。** この ADR の Accepted、Decision 6 の配線テスト、Go と shell の一致の機械検査が required
  check に揃ったら、採点側の性質 (「`FLAGS_FILE` 指定時、採点スコープの全 evade 課題に既定値と異なる flag が供給されない限り
  scoreboard は起動しない」) に絞って昇格する。それまで conventions の表には追記しない (`docs/adr/README.md` の規律)。

## Signposts

1. ADR-0025 / P28 で `ctf-flags-secret.yaml` のスコープ規則を変える PR が出た → B を前倒しする (shell によるスコープの
   再導出が、3 つ目の定義として古くなる前に)。
2. Go と shell の判定が割れた実例が出た、または規則を変えるたびに parity の入力集の手直しが要る → B へ移る。
3. 運用端末に scoreboard image が常在し、deploy 経路で docker を前提にできると確認できた → A を再評価する。
4. スコープを絞った部分ファイルを使う運用が次のイベントまで 1 件も無い → 網羅性をスコープ非依存 (全 evade id 必須) に
   締める。締める方向は後から緩められるが逆は破壊的で、締めれば Decision 2・6 の複雑さが消える。

## Verification

テスト名は e416705 時点 (レビュー反映で変わりうるので merge 前に VP が突合する)。「変更前に red」= e74d871 の挙動では受理されるケース。

- **採点側** (`make test` = required の `test`): `internal/catalog/flags_test.go`
  - `TestApplyFlagOverrides` の拒否系サブテスト (変更前に red): `no scenario, one evade flag missing: rejected` /
    `no scenario, two evade flags missing: both named` / `full scenario, one evade flag missing: rejected` /
    `subset scenario, its evade flag missing while others are supplied: rejected` /
    `supplied value equals the repository default: rejected` / `out-of-scope entry equals the repository default: still rejected`。
    同じテストが、拒否時に何も適用されないこと (D1)、エラー文言に値が出ないこと (D5)、受理後に既定値のまま残る evade
    課題が無いことも確かめる。
  - `TestApplyFlagOverrides_RealCatalogAndScenarios`: 実 catalog と全 scenario が evade の全集合を持つファイルを受理し続けること。
  - レビュー反映で追加 (名前は未確定): 他の課題の既定値との一致 (D1 b)、課題間の値の重複 (D1 c)、文字集合 (D3)、
    Decision 6 の 1 関数を実 catalog・実 scenario で通す配線テスト。
- **仕込み側** (`make check-flags` / CI `flag-guard` = required): `scripts/check-flags-file-validation.sh`
  - A 部 (変更前に red): `all: one evade flag missing` / `all: value equals the repository default` /
    `scenario nimbusbreach-full: one evade flag missing` / `scenario tutorial-intro: its evade flag missing` /
    `single evade challenge: its flag missing`。
  - B 部: `expect_deploy_rejected` が、拒否時に非ゼロで終了し、helm / kubectl を 1 回も呼ばず (stub で記録)、出力に値を出さない
    ことを確かめる。`no --flags-file (local dev): unchanged, no override` が D7 を確かめる。
- **一致 (D4)**: Go と shell に同じ入力集を与え、受理/拒否が一致することを確かめる parity テスト (レビュー反映で追加、名前は未確定)。
- **platform 側**: preflight の key の完全性検査は、platform の同時 PR の landing で確かめる。
- **機械では確かめられないもの**: 過去のイベントの値の再利用 (Consequences の残余)。

## Advice

- R4 architect (2026-10-05): ADR は必須 (§8 ②③)。platform の同時 PR が要る。2 つの catalog 引数の取り違え (→ D6)。
  二重実装は follow-up とし B を推奨。HI 昇格は not yet。
- R3 conventions (2026-10-05): HI の新設・変更には当たらない。単一ソース化の follow-up を残す。1 PR のまま進める (片側だけ
  先に land すると「両側 fail-closed」が成り立たない期間ができる点で、architect も同意)。
- R1 security-engineer (2026-10-05): flags ファイル自体を指定しない経路を要判断として提起 → 範囲外として明記した。
- VP (2026-10-05): ADR の要否は R4 を採用 (R3 は不要と判定)。レビュー指摘を全件採用し、D1 (b)(c)・D3・D4 の parity・D6 を実装に追加。
