# ADR-0008: mission 05 の実効ゲート — forbidden rule の proc 非依存汎化 + evade 型への積極証明ゲート (`requireExpectedRuleFire`) の新設

- Status: **Accepted** (設計。2026-08-25, VP 承認。review-5x 2 巡目で security-engineer advisory
  済み — R1 の HIGH 2 件は Decision (1) の全面再設計・Verification (a-1) 追加で解消済みのため
  別途の advisory ラウンドは不要と判断)。**実装は別PR。本番投入は Verification (a)/(a-1)/(e)
  が実機で landing するまで不可** (ADR-0007 と同じ運用)
- Date / Deciders: 2026-08-25 / architect (起草・5x レビュー反映)、VP (承認)
- 関連: Issue #121 (mission05 実効ゲート不在)、Issue #133 (#121 に吸収・close)、REFACTORING.md P26 (product brief)、
  ADR-0001 (§限界 — 取得元は閉じるが取得手段が技法であることは保証しない)、
  ADR-0003 (C5 — 負の条件だけの gate は原理的に不健全、A7 — #121 の scope に mission10 を含める要求、
  Signpost 2 — 本 ADR が resolve する)、ADR-0007 (plant-target の mount granularity。本 ADR の
  Verification (a) が依拠する deploy 経路の無汚染設計。**加えて、同 ADR §C1/§C6 の実測ログが
  本 ADR の Decision (1) 再設計の直接の根拠になっている** — 後述)

## Context

- **現状の欠陥 (実測)**: `challenges/04-key-search/rule.yaml:29-36` の `Search Private Keys or
  Passwords` は private-key ファイル名 (`id_rsa`/`id_dsa`/`id_ed25519`/`id_ecdsa`) の cmdline
  一致を `proc.name = "find"` にだけ結び付けている。したがって `cat /root/.ssh/id_rsa` (直接引数)
  は無検知であり、mission05 の README (「NG: `cat /root/.ssh/id_rsa` (発火)」) は事実に反する
  (product brief, REFACTORING.md P26)。
- **積極証明の欠如**: mission03/05 は `requireExfil` を持たず (`challenges/03-stealth-read/
  falco-rule.yaml` / `challenges/05-silent-search/falco-rule.yaml`)、「forbidden 未発火」という
  否定条件のみで clean 判定される。ADR-0003 C5 が明記した通り、これは原理的に「回避技法を一度も
  使わずに solve できる」構造であり、健全化は attempt ごとの積極証明 (`requireExfil`/
  `expectedRules`) しかない。
- **10 は "requireExfil はあるが積極証明ではない"**: ADR-0003 A7/W2 が明記した通り、10 の
  `requireExfil` はフラグ配送の証跡であって回避技法を使った証跡ではない。本 ADR は 10 への適用を
  scope 外とする (product brief のスコープ外節)。**帰属の訂正 (2026-08-25, R4 self-review)**:
  「10 は既に `requireExfil` を持つため不要な可能性が高い」という仮説を提示したのは
  product-engineer だが、**10 への適用可否そのものは product brief が明示的に architect の判断に
  委譲している** (`REFACTORING.md:1312-1314`)。本 ADR はその委譲を受けて scope 外に置く、という
  architect 自身の決定であり、product-engineer の確定判断ではない。10 に将来同型のゲートを
  追加できる「土台」を作ることを ADR-0003 A7 が要求しているため、B の機構 (catalog の
  `requireExpectedRuleFire`) は 10 にもそのまま適用できる形で設計する。
- **デプロイ経路には現在 Falco ルールの override 機構が存在しない (実測)**:
  `falco-ctf-platform/helmfile/releases/falco/values.yaml.gotmpl` に `customRules` は無く、
  `.claude/skills/falco-rules/SKILL.md:70-79` (workspace root の特化 skill。**app/platform とは
  別の第三のリポジトリに属する** — 後述 Consequences) が「default ruleset がそのまま稼働している」
  ことを明記している。したがって A (forbidden rule の汎化) は
  **この project で初めて Falco rule の override/追加を行うことになる** — 前例のない構造変更。
- **plant 経路の構造 (実測)**: `charts/ctf-user/templates/pod.yaml:67-79` の `plant`
  initContainer は `command: {{ toYaml .Values.plant.seedScript | nindent 8 }}` を実行し、
  `.Values.plant.seedScript` は `[sh, -c, "<全 plant.sh の本文を連結したスクリプト>"]`
  (`challenges/values-all.yaml:10-14`)。**現行の** `challenges/05-silent-search/plant.sh` はこの
  スクリプト内で `mkdir -p ".../root/.ssh"` → `cat > ".../root/.ssh/id_rsa" <<EOF ... EOF` →
  `chmod 600 ".../root/.ssh/id_rsa"` を実行する (Decision (1) でこの `chmod` 行自体を無くす)。
- **Hard Invariant 候補 I13a/I13b** (`.claude/rules/falco-ctf-app-conventions.md` I11-I13 表):
  「deploy 経路は catalog の `expectedRules` ∪ `forbiddenRules` に現れるルール名を1本も
  発火させない」。機構は landing 済みだが**実機 cluster 実測が残 gate**。本 ADR が新たに
  この候補の対象集合に加えるルール名は **1 本 (新設 `Shell Redirected Private Key Read`)**。
  `Search Private Keys or Passwords` は condition が変わるが既に 9 本の中に含まれている
  既存ルール名であり、I13a/I13b が「件数ではなくルール名で見る」規律 (ADR-0007 Signpost 3 と
  同じ規律) である以上、集合のサイズには影響しない — **condition 変更のため再検証は必要だが、
  「2本追加」という表現は不正確だったので訂正した (2026-08-25, R4 self-review)**。

## Options

### Option 1 — A のみ (forbidden rule の汎化だけ、積極証明を追加しない)

**変更点**: `Search Private Keys or Passwords` の id_rsa 系分岐を `proc.name` 非依存に汎化する
(下記 Decision の条件式)。

- **コスト**: 最小。Falco rule 1 本の condition 変更 + platform 側 `customRules` の初期導入。
- **リスクと可逆性**: 完全に可逆 (customRules を削除すれば default に戻る)。
  05 のプレーンな「素の `cat`」バイパスは閉じるが、**否定条件のみの gate という構造は残る**
  (ADR-0003 C5)。A で捕捉できない未知の読み取り経路 (Falco の exec-arg マッチが原理的に
  捉えられない技法) が見つかれば、技法を一度も使わずに solve される余地が残る。
- **効き始める閾値**: A のカバレッジの外側にある読み取り経路が実際に発見されたとき
  (「先に進んだ参加者だけが知る裏技」が生まれた時点)。

### Option 2 — A + B (汎化 + evade 型への積極証明ゲート新設) 【推奨】

**変更点**: Option 1 に加え、(1) shell が fork 後 exec 前に `/root/.ssh/id_rsa` を open した
イベントを検知する新規 Falco rule、(2) catalog に `requireExpectedRuleFire: bool`、
(3) `evaluateClean` への新規ゲート、(4) 新規永続テーブル `expected_rule_fire`
(`reset-dirty` では消えない — 後述 Decision (4))。

- **コスト**: catalog 1 field・scoring 1 gate + `RuleFireOutcome` 1 field・store 1 table + 2
  method・API 1 response field (`docs/openapi-scoreboard.yaml` の `MissionDetail` +2 key)・
  Falco rule 1 本 (既存ルールとの名前衝突なし)・`challenges/05-silent-search/plant.sh` の
  1 行差し替え (`chmod` 排除、下記 Decision (1))・`scripts/check-challenge-rules.sh` の
  対象集合拡張 (下記 Decision (5))。**`RequireExfil` と完全に対称な形**なので、
  実装者が新しいパターンを 1 つ学ぶのではなく既存パターンを 1 回複製するだけで済む。
- **リスクと可逆性**: 05 の `requireExpectedRuleFire: false` に戻せば Option 1 の挙動へ
  完全に後退できる (catalog の bool 1 個で切替可能)。scoring package の複雑度はわずかに増える
  (ゲートが 1 つ増える) が、既存の `RequireExfil` と同型なので保守コストは限定的。
- **効き始める閾値**: 単一ミッションのためだけなら Option 1 より重い投資だが、
  ADR-0003 A7 が「#121 の scope に mission10 を含める（土台を作る）」ことを要求しているため、
  2 問目 (将来 10 への適用) で投資が償却される前提が ADR-0003 の時点で既に確定している。

### Option 3 — attempt epoch を導入する (ADR-0003 Option 1 を今、格上げする)

**変更点**: `evade_attempt(user, challenge, epoch, started_at)` を新設し、`exfil` /
`evade_dirty` / 新設 `expected_rule_fire` に `epoch` 列を持たせ、reset = `epoch++`。

- **コスト**: 最高。新テーブル + migration 機構 (app#117 未着手) + 既存ゲート全面リワイヤ。
- **リスクと可逆性**: ADR-0003 Signpost 2 は文字通り「evade 課題が `expectedRules`
  (積極証明) を得る」ことを Option 3 への切替トリガーとして名指ししている。しかし
  **Signpost 2 が守ろうとしている実害** (flag に紐づく receipt が reset を生き延び、
  Sweeper が再検証なしに auto-solve する — A2-2 が exfil に対して閉じた穴) は、
  本 ADR の `expected_rule_fire` には当てはまらない (Decision (4) で詳述)。
  文字通りの signpost 発火と、その signpost が守る実害の発火は別物であり、
  後者が起きていない今 Option 3 に進むのは過剰投資である。
- **効き始める閾値**: 将来の積極証明ゲートが flag に紐づく/再生可能な証跡を使う場合
  (Signposts 参照)。

## Decision

**Option 2 を採る。** 以下 5 点を実装の規範とする (architect が product brief から補正した点、
および 5x レビュー (R1 security-engineer・R2 qa-engineer・R3 conventions・R5 cross-repo) を
反映して再設計した点を含む)。

### (1) A — forbidden rule の汎化は「deploy 経路で id_rsa 系 literal を argv に持つ exec を
    作らない」ことで安全化する (`container.name` には依存しない)

product brief は A を「`proc.name = "find"` の縛りを外し、どの proc でも cmdline に literal が
現れたら発火」と提案したが、これを**そのまま**実装すると deploy 経路を汚染する。
現行 `plant` initContainer の `sh -c "<script>"` 自体の argv (script 全文) に `.../id_rsa` という
literal が含まれ (`plant.sh` がその path へ `cat >`/`chmod` するため)、かつ `chmod 600
".../id_rsa"` は独立した exec イベントとして `id_rsa` を自身の args に持つ。**素朴な汎化は
この 2 つのイベントで発火し、04 (trigger、`evaluateTrigger` は attempt スコープ外で
無条件 solve) を全参加者の deploy 時点で自動 solve させる** — Hard Invariant 候補 I13b
の新規違反であり、ADR-0001/ADR-0007 が防いだクラスの欠陥を作る。

**再設計の経緯 (2026-08-25, R4 self-review + R1 security-engineer レビューが独立に収束)**:
初稿は上記 2 イベントを `container.name = "plant" or proc.name in (shell_binaries)` という
macro で免除する設計だったが、これは**実測データと矛盾する**。ADR-0007
(`docs/adr/0007-plant-mount-directory-granularity.md:43,248-251,602`) が実クラスタで採取した
Falco ログは `container.name` の実際の値が

```
container.name=k8s_challenge_workspace_ctf-<user>_<poduid>_0
```

という **k8s の短縮コンテナ名ではない複合文字列**であることを示しており、`k8s.pod.name`
(短い値 `workspace`) とは明確に異なる。同 ADR §C6 は「同じコンテナで通常の exec を行っても
同一の複合形式になる」ことも確認しており、これは新規コンテナ生成直後の一時的なフォールバック値
ではなく、そのコンテナのライフサイクル全体で一貫した値である。したがって `plant` initContainer
の `container.name` も `k8s_plant_workspace_ctf-<user>_<poduid>_<attempt>` 相当になる可能性が高く、
**`container.name = "plant"` という完全一致条件は一度も真にならない**。R1 (security-engineer) は
独立に別の根拠 (**enrichment race** — 短命なコンテナは exec/終了が Falco の container メタデータ
取得完了より先に起こりうるため、`container.name` 系フィールドの enrichment が間に合わない
ケースがある) から同じ結論 (`container.name` に安全機構を依存させてはならない) に到達している。
**2 人の独立レビュアーが異なる根拠から同じ結論に達したため、これは設計の中核欠陥として扱う。**

このうち `sh -c "<script>"` 自体のイベントは `proc.name in (shell_binaries)` 分岐だけで
（`container.name` 抜きでも）免除できる。**免除できないのは `chmod` イベントだけ**
(`chmod` は shell_binaries に属さない独立した exec)。よって `container.name` に依存する
代わりに、**`chmod` という exec イベントそのものを deploy 経路から無くす**ことで問題を根本から
消す。

対策 (1a): `challenges/05-silent-search/plant.sh` を、独立した `chmod` exec を伴わない形に
書き換える。ファイルの書き込み (`cat > ... <<EOF`) はシェル自身が行う redirection であり、
別プロセスの exec を伴わない。この redirection を **限定 `umask`** の下で行えば、生成される
ファイルの mode はシェルの `open()` 呼び出し自体によって決まり、事後の `chmod` が不要になる:

```sh
mkdir -p "${PLANT_SEED_ROOT}/root/.ssh"
(
  umask 077
  cat > "${PLANT_SEED_ROOT}/root/.ssh/id_rsa" <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAA
tzc2gtZWQyNTUxOQAAACBm${CTF_FLAG_05_SILENT_SEARCH:?flag env not set by ctf-user chart}_FAKEKEY=
-----END OPENSSH PRIVATE KEY-----
EOF
)
```

`umask 077` は `open()` の mode 引数 (通常 `0666`) から `0077` を引いて `0600` にする —
`chmod 600` と同じ最終結果を、追加の exec を発生させずに得る。`( ... )` の subshell は
`fork()` のみで `execve()` を伴わないため `spawned_process` (`evt.type in (execve, execveat)`)
に一致せず、macro の対象にもならない。subshell で scope することで、`values-all.yaml` が
全 evade ミッションの `plant.sh` を連結する構造 (`challenges/values-all.yaml:10-30`) において
この `umask` 変更が後続の行 (03 の `/etc` snapshot 等) に漏れないことも保証する。

これにより、deploy 経路で `id_rsa` 系 literal を argv に持つ exec は **`sh -c "<script>"`
自身の 1 件のみ**になり、`proc.name in (shell_binaries)` だけで安全に免除できる —
**`container.name` への依存が完全に無くなる。**

対策 (1b): 新設 macro を

```yaml
- macro: private_key_filename_literal
  condition: >
    (proc.args contains "id_rsa" or proc.args contains "id_dsa" or
     proc.args contains "id_ed25519" or proc.args contains "id_ecdsa")

- macro: key_search_deploy_and_shell_exempt
  condition: (proc.name in (shell_binaries))

- rule: Search Private Keys or Passwords
  append: true
  condition: or (spawned_process and private_key_filename_literal and not key_search_deploy_and_shell_exempt)
```

とする (`falco-ctf-platform/helmfile/releases/falco/values.yaml.gotmpl` の新設 `customRules`
block)。`shell_binaries` 除外は deploy 安全のためだけでなく **A の意図そのもの**でもある —
A が捉えたいのは「読み取りツール自身が cmdline にファイル名を持つ」ことであり、`sh -c` が
渡された script 文字列を argv に持つことは「ツールが引数でファイルを指定した」ことと同じ
ではない。この除外により `sh -c "cat < /root/.ssh/id_rsa"` (技法を明示的に `sh -c` で
包んだ形) も forbidden にならず B (下記) を満たす — 一貫した挙動になる。
`find`/`grep`/`egrep`/`fgrep` は `shell_binaries` に含まれないため、04 の想定解は非退行。

**実装 PR の DoD**: (1a) の `plant.sh` 差し替えと (1b) の `customRules` 追加は**同一 PR で
セットで landing すること** — (1b) の `container.name` 依存を無くす安全性は (1a) が `chmod`
を排除したことに完全に依存している。**将来の plant.sh 変更で、id_rsa 系 literal を自身の
argv に持つ非 shell バイナリ (`chmod`/`install`/`mv` 等) を deploy 経路で再び spawn すると
この設計は成立しなくなる** — Signpost 5 に明記する。

### (2) B — 積極証明の新規 Falco rule

```yaml
- rule: Shell Redirected Private Key Read
  desc: >
    A shell opened a private-key file for reading BEFORE exec'ing its next
    command (input-redirection: `cmd < keyfile`), which keeps the filename
    out of the exec'd child's cmdline. Positive proof of the evasion
    technique — contrast with reading the same file via a direct argument
    (`cat /root/.ssh/id_rsa`), which opens the file from the CHILD process
    AFTER execve, when proc.name is already the child command, never a
    shell (caught instead by "Search Private Keys or Passwords").
  condition: >
    open_read
    and proc.name in (shell_binaries)
    and fd.name = "/root/.ssh/id_rsa"
    and container.name != "plant"
  output: >
    Shell opened private key via redirection (technique proof)
    file=%fd.name shell=%proc.name command=%proc.cmdline user=%user.name
    k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name
  priority: NOTICE
  tags: [maturity_stable, host, container, process, filesystem, ctf_positive_proof]
```

既存の default macro (`open_read`) と default list (`shell_binaries`) を再利用し、新規 macro は
増やさない (mission05 専用の1リテラルパスのみ)。

**`container.name != "plant"` の位置づけ (2026-08-25, Decision (1) の再設計に合わせて訂正)**:
`plant.sh` は `cat >` (書込モード) しかこのファイルに触れないため、この除外は現状の
plant.sh に対しては理論上不要であり、**この除外節が本ルールの安全性の根拠ではない**。
かつ Decision (1) の再設計で判明した通り、`container.name` の実測フォーマットは本
project で未確認 (ADR-0007 実測 + R1 enrichment race 指摘、いずれもこの exact-match が
機能しない可能性を示す)。よって **B の安全性は `container.name != "plant"` に依拠しない**
— 唯一の根拠は「`plant.sh` がこの path を read モードで open しない」という構造的事実
(コードレビューで確認済み、Decision (1a) 後も変わらず成立)。この除外節は**将来
plant.sh がこのファイルを read モードで触るように変わった場合の belt-and-suspenders**
としてのみ残し、機能する保証があるとは主張しない (Verification (a) に確認手順を記載するが
non-blocking とする — 根拠が別にあるため)。

**技術的根拠 (falco-rules-expert による確認)**: シェルの入力リダイレクト設定 (`open`+`dup2`) は
fork 後 execve 前、まだシェル自身の image を持つプロセスが行う。したがって
`proc.name in (shell_binaries)` の時点で observable であり、execve 後に子プロセス
(`cat` 等) が持つ cmdline にはファイル名が一切現れない (redirection はシェルが消費し、
子プロセスの argv には渡らない) — この非対称は Linux の fork/exec モデルの標準的な性質であり、
`sh -c` の単一コマンド最適化 (vfork 等) でも「open→execve の順序」自体は変わらないため成立する。

### (3) catalog / scoring — `requireExpectedRuleFire`

`catalog.Challenge` に `RequireExpectedRuleFire bool \`yaml:"requireExpectedRuleFire"\`` を追加。
load 時検証: `type == "evade" && RequireExpectedRuleFire` なら `len(ExpectedRules) > 0` を要求
(trigger 型の既存検証と対称)。05 の `falco-rule.yaml` は:

```yaml
challengeId: 05-silent-search
type: evade
forbiddenRules: [Search Private Keys or Passwords]
expectedRules: [Shell Redirected Private Key Read]
requireExpectedRuleFire: true
expectedFlag: FALCO{dev-silent-search}
```

`internal/store`: 新規テーブル `expected_rule_fire (user, challenge, rule, at)
PRIMARY KEY (user, challenge, rule)` (`evade_dirty` と同型)。新規メソッド
`HasExpectedRuleFire(user, challenge) bool` / `RecordExpectedRuleFire(user, challenge, rule,
at) error` (`INSERT OR IGNORE`、`MarkDirty`と同型、in-memory mirror も同様に持つ)。

`internal/scoreboard/scoring`: `OnRuleFire` に第3の内部ステップ
`recordExpectedRuleFire(user, rule)` を追加する (unexported、`OnRuleFire` 経由のみ —
A4 の規律を継承)。**attempt スコープを適用しない** (`markDirtyOnRuleFire` とは非対称。
理由: この新規ルール名は 05 専用で他ミッションと共有されないため、ADR-0003 A1 が
`forbiddenRules` に対して attempt スコープを必要とした「双子ミッション構造による
誤 taint」のリスクがそもそも存在しない。scope しても新たに閉じる穴はなく、
scope すると「05 の attempt が始まる前に技法を証明した参加者」を不当に不利にするだけ)。

**write 側の走査条件 (2026-08-25 追記, R4 self-review — ADR-0003 A1 と同水準の精度で明記する。
ADR-0003 C1 の教訓 = 限定句を会話/文章粒度で運ぶと転記時に落ちる、を write 側にも適用する)**:

```
on ruleFire(u, r):                        # ingest から 1 event 1 回 (OnRuleFire 内)
    markDirtyOnRuleFire(u, r)             # ADR-0003 A1 (既存、変更なし)
    recordExpectedRuleFire(u, r)          # ← 本 ADR が追加する第3ステップ
    applyTriggerSolves(u, r)              # ADR-0003 A1 (既存、変更なし。常に最後)

recordExpectedRuleFire(u, r):
    for c in catalog where c.Type == "evade"
                       and c.RequireExpectedRuleFire
                       and r in c.ExpectedRules:
        store.RecordExpectedRuleFire(u, c.ID, r, now())   # INSERT OR IGNORE、失敗は ExpectedFireErr へ
```

**`c.Type == "evade"` の判定が必須である**: `catalog.Challenge.ExpectedRules` は
`type: trigger` の `evaluateTrigger` (`internal/scoreboard/scoring/scoring.go:360-380`, `ch.Type
!= "trigger"` で早期 continue) と本ステップの両方から読まれる**共有フィールド**になる。
この type ガードにより、05 (evade) の `ExpectedRules` が `evaluateTrigger` の auto-solve
ループに紛れ込むことはなく (`evaluateTrigger` 側が `evade` を弾く)、逆に本ステップが trigger
型の `ExpectedRules` を誤って `expected_rule_fire` に書き込むこともない (本ステップ側が
`evade` 以外を弾く)。**この 1 行を実装で落とすと、trigger 型の課題の rule fire が意味もなく
`expected_rule_fire` に記録される** (実害は小さいが、Verification (c) の一意性検査が
無意味になる)。第 3 ステップの既存 2 ステップに対する順序は自由 (相互作用が無いため) だが、
実装は既存 2 ステップの後に置く (diff を最小化するため)。

`RuleFireOutcome` に第3のフィールド `ExpectedFireErr error` を追加する (`TaintErr`/
`TriggerErr` と同じ理由で `errors.Join` しない — 別の criticality クラス:
書き込み失敗は参加者が同じ無害な操作を再実行すれば回復するので `TriggerErr` と同じ
「ログ+200」扱いだが、独立した観測性のため名前を分ける)。

`evaluateClean` に4番目のゲートを追加する (dirty → **expectedRuleFire** → exfil → solve の順。
安い local check を先に評価する):

```go
if ch.RequireExpectedRuleFire && !g.store.HasExpectedRuleFire(user, ch.ID) {
    return EvadeOutcome{Status: EvadeExpectedRuleFireRequired}, nil
}
```

**新規 `EvadeStatus` 定数 `EvadeExpectedRuleFireRequired` を `EvadeForbiddenFired` と
`EvadeExfilRequired` の間に追加する** (2026-08-25 訂正, R2 qa-engineer 指摘: 初稿は
「`EvadeExfilRequired` と `EvadeSolved` の間」としていたが、これは上記ゲート実行順
[dirty → expectedRuleFire → exfil → solve] と矛盾する。既存コードは「enum 宣言順 = gate
実行順」という自己文書化パターンを保っているため、宣言順を実行順に合わせて訂正した)。
**`EvadeStatus` の数値が他所 (DB/JSON) に生の int として永続化されていないことを実装者が
確認すること** (`internal/scoreboard/api/api.go:895,911,935,948` は switch が named
const で分岐しており、実測では raw int 比較は見当たらないが、確認は software-engineer の
作業として残す)。`Sweep()` は `evaluateClean` を再利用するため変更不要 — 新ゲートは
自動的に auto-solve 経路にも効く。

`GET /api/users/{user}/journey?mission=<cid>` の `MissionDetail` に2キー追加
(`requireExfil`/`exfilReceived` と対称):

- `"requireExpectedRuleFire": bool`
- `"expectedRuleFired": bool` (= `h.store.HasExpectedRuleFire(user, cid)`)

`docs/openapi-scoreboard.yaml` の `MissionDetail` は 19→**21** キーになる。app-side parity
テストのキー数定数を同じ PR で更新する (I14/ADR-0005)。

### (4) `expected_rule_fire` は `ResetDirty` で消さない — ADR-0003 Signpost 2 の解決

ADR-0003 の Signpost 2 は「evade 課題が `expectedRules` (積極証明) を得たら epoch 列
(Option 1) が必要になる」と予告していた。**この signpost は文字通り発火した
(#121 がまさにそれを作る) が、signpost が守ろうとしていた実害は本設計には当てはまらない
と判断する。**

理由: ADR-0003 A2-2 が `exfil` receipt を reset で消すことを要求したのは、**receipt が
「提出された flag 値と対になる、再検証なしで Sweeper が信用する証跡」であり、
発火履歴と無関係に古い receipt が残ると reset 後も stale な証跡で auto-solve される**
という実害があったため (A2 の file:line 群参照)。`expected_rule_fire` は構造的に異なる:
どの flag 値にも紐づかず、「この参加者の shell が、ある時点で、この特定の path を
読み取りモードで open した」という一方向の事実である。forbidden rule のその後の発火や
reset は、この事実を偽にしない。**「reset 後にもう一度技法を証明させる」ことに
セキュリティ上の利益は無く、参加者に無意味な繰り返し作業を課すだけ**であり、product brief
自身の要求 (「既存の難易度を上げない」) に反する。

よって: **`ResetDirty` は `expected_rule_fire` に触れない。admin の全体 `Reset()`
(イベント全体のワイプ) は触れる** (他の全テーブルと対称)。この非対称は意図的であり、
理由をコード上の doc コメントに明記すること (openapi-expert の「非対称は必ず理由を持つ」
規律)。

### (5) 新設ルール名と `challenge-rules` CI ゲート (`scripts/check-challenge-rules.sh`) の整合

**BLOCKING (R2 qa-engineer 指摘)**: `scripts/check-challenge-rules.sh` は
`challenges/*/falco-rule.yaml` の `expectedRules`/`forbiddenRules` に列挙された全ルール名が
upstream `falcosecurity/rules` (`FALCO_RULES_REF` 固定タグ, 同ファイル `:15-16`) に**実在する**
ことを確認する required check (`challenge-rules`) の実体である。新設 `Shell Redirected
Private Key Read` は **project 固有のカスタムルールであり upstream には存在しない** ため、
05 の `falco-rule.yaml` に `expectedRules: [Shell Redirected Private Key Read]` を追加すると、
**このスクリプトは現状のままでは確実に fail する**。

対策: 新規マニフェスト `challenges/custom-falco-rules.txt` (1 行 1 ルール名、project が
`customRules` として platform に追加したカスタムルールの一覧。現時点では
`Shell Redirected Private Key Read` の 1 行のみ) を追加し、`scripts/check-challenge-rules.sh`
を「upstream からの fetch 結果 ∪ このマニフェストの内容」を既知集合として比較する形に
変更する。これにより:

- 本当に typo/存在しないルール名を参照した場合は**従来通り fail する** (typo 検出力を落とさない
  — マニフェストは「project が意図して追加したカスタムルール」だけを許可する allowlist であり、
  何でも許可する脱出口ではない)。
- `Shell Redirected Private Key Read` のような project 固有ルールは正しく pass する。
- **このマニフェストは app 側での「カスタムルール名の単一の正典」になる**。platform 側
  `customRules` (Decision (1)(2)) のルール名は、実装 PR でこのマニフェストの内容と**手動で**
  一致させること (両リポ間の自動整合機構は現状無い — `challenges/*/rule.yaml` を
  「deploy 中の実ルールセットから再抽出する」既存の運用と同じ性質の手動規律であり、
  本 ADR で新しい機構を作るものではない)。

**実装 PR の DoD**: (1)(2) の Falco rule 追加、(5) のマニフェスト追加・スクリプト変更は
**同一 PR で landing すること** (順序がずれると `challenge-rules` が赤くなる)。

## Consequences

- **手放すもの**: 完全な attempt-epoch 分離 (Option 3)。将来、flag に紐づく/再生可能な
  積極証明ゲートが必要になったら、そのミッション**個別**に `epoch` 相当の仕組みか
  「reset で consume する」フラグを追加すべきで、全ミッションに epoch を強制する必要はない
  (Signposts 参照)。
- **新たに守る候補不変条件 (未昇格・Verification 未着手)**: 「evade 課題の
  `requireExpectedRuleFire` ゲートは、flag に紐づかない永続的な rule-fire 記録で満たされ、
  `reset-dirty` では消えないが admin の全体 `Reset()` では消える」。
  ORGANIZATION.md/docs/adr/README.md の歯止め (Verification 無しの ADR は Hard Invariant に
  昇格させない) に従い、機械強制 (下記 Verification) が landing するまで
  `.claude/rules/falco-ctf-app-conventions.md` には追記しない。
- **前例の追加**: `falco-ctf-platform` の Falco ruleset が初めて default から override される。
  `.claude/skills/falco-rules/SKILL.md:70-79` の「default ruleset がそのまま稼働している」記述は
  この PR で stale になる。**訂正先の訂正 (2026-08-25, R5 cross-repo 指摘)**: この skill ファイルは
  `falco-ctf-app` でも `falco-ctf-platform` でもなく、**workspace root という独立した第三の
  リポジトリ**に属する (`falco-ctf/.claude/skills/falco-rules/SKILL.md`)。したがって
  「同じ PR で訂正する」ことは文字通り不可能 (3 リポジトリを跨ぐ単一 PR は存在しない)。
  正しい要件: **platform 側の実装 PR と同一の変更ウィンドウ内で、workspace root リポジトリに
  相互リンク付きの追従コミット/PR を作成する** (Hard Invariant ではないが、事実の看板を
  放置しない)。
- **クロスリポ**: platform (`helmfile/releases/falco/values.yaml.gotmpl` の `customRules`)
  が先に landing し、その後 app 側の `challenges/{04-key-search,05-silent-search,
  10-final-exfil}/rule.yaml` (表示用抜粋) を新しい deployed ruleset から再抽出する
  (既存の「デプロイ中の実ルールセットから抽出する」運用を踏襲。順序は逐次で良く、
  同時 PR を必須としない — architect の同意権対象である「API / クロスリポ契約」の列挙
  (image tag / challenges path / webhook payload / cookie domain / flags /
  `ALLOWED_ORIGINS` / `FRAME_ANCESTORS` の **7 項目**。**2026-08-25 訂正 (R5 cross-repo 指摘)**:
  初稿は「8 項目」と書いていたがこの列挙自体は 7 項目であり数え間違いだった。なお、これは
  `.claude/rules/falco-ctf-app-conventions.md` の「Cross-repo 契約」表 [現在 10 行、image
  naming/ttyd-proxy配線/detect-grader Job/Charts/deploy-user.sh exit status/Challenges
  path/Webhook payload/Cookie domain/Flags/`ALLOWED_ORIGINS`] とは粒度が異なる別の列挙
  [architect の同意権スコープの要約] なので、両者を混同しないこと) には含まれないため。
  ただし今後の構造的結合点として、**今すぐではなく、platform 側で `customRules` を初めて
  導入する実装 PR のタイミングで** `.claude/rules/falco-ctf-app-conventions.md` の
  Cross-repo 契約表に「Falco custom rule override」行を追加することを推奨する
  [Verification 無しの機構を正典に先行して書かない、という本 ADR 自身の規律を契約表にも適用する]）。
- **参加者向け runbook**: 新規の reset 文言変更は不要 (`expected_rule_fire` は参加者に
  見せる reset ボタンの挙動を変えない — ADR-0003 A2 が確立した `dirty`/`exfil` の文言に
  影響しない)。

## Signposts

1. **将来の evade ミッションが `requireExpectedRuleFire` を採用し、その積極証明ルールが
   flag 値や再生可能な証跡に依存する**場合 — Decision (4) を再検討し、ミッション単位の
   `resettable` フラグ、または該当ミッションだけの epoch 相当機構を検討する
   (全ミッション一律の Option 3 に飛ばない)。
2. **`expected_rule_fire` の行が常に (user, challenge) につき rule 1 本しか記録されない状態が
   2 ミッション以上続く** — テーブルを `(user, challenge) -> bool` に単純化し、
   `rule` 列の audit 価値 (`DirtyRules` 同型で持たせた設計) が実際に使われていないなら削る。
3. **Falco のメジャーバージョンが上がり `open_read`/`shell_binaries`/`container.name` の
   意味論が変わる** — B の condition を新しい deployed ruleset から再抽出し再検証する
   (falco-rules-expert の「バージョンが上がったら再抽出する」原則)。
4. **将来の plant.sh が `shell_binaries` に載るバイナリを `plant` コンテナ外の文脈で
   経由するようになる** (今回は無いが、plant の再設計が起きたら) —
   `container.name != "plant"` 除外がその新しい経路を覆っているか再確認する (ただし
   Decision (2) の訂正どおり、この除外は non-blocking な belt-and-suspenders でしかない)。
5. **`container.name` の実測値が本 ADR の想定と異なることが判明した場合、または将来の
   plant.sh が id_rsa 系 literal を自身の argv に持つ非 shell バイナリを deploy 経路で
   再び spawn するようになった場合** (2026-08-25 追加, R4 self-review + R1 独立指摘の収束) —
   Decision (1) の前提 (deploy 経路の唯一の literal-bearing exec は `sh -c` 自身であり
   `shell_binaries` だけで免除できる) が崩れる。`container.name` に依存する免除機構を
   新たに設計する前に、必ず ADR-0007 と同じ probe 手法で実測値を確認すること
   (「実測せずに Falco フィールドの意味を仮定する」ことが本 ADR の初稿の欠陥だったため、
   同じ過ちを繰り返さないための signpost)。

## Verification

- **(a) deploy 経路無汚染 [blocking・実機 cluster 実測が残 gate]**: I13a/I13b の
  既存 9 ルール名に本 ADR が新たに加える 1 ルール名 (新設 `Shell Redirected Private Key
  Read`。`Search Private Keys or Passwords` は既存の 9 本に含まれる既存ルール名だが condition
  変更のため同じ E2E で再検証する) を追加した集合で、`docs/PROD-GATE-E2E-PLAN.md`
  の cluster E2E に組み込む。**I13a/I13b 自体が現状「実機 cluster 実測が残 gate」であり
  (`.claude/rules/falco-ctf-app-conventions.md`)、本 ADR の deploy 安全性の主張もこの
  ステータスを継承する — 実機で確認するまで「検証済み」と書かない。**
  - **(a-1) [blocking] `customRules` の DaemonSet 起動確認 (2026-08-25 追加, R1/自己
    Finding が収束)**: `customRules` を追加した Falco Helm values を実際に colima/dev
    cluster にロードし、(i) Falco DaemonSet Pod が `Running` のまま `CrashLoopBackOff` に
    ならないこと、(ii) `append: true` の対象ルール (`Search Private Keys or Passwords`) が
    存在する状態で正しくロード順序が解決され、起動ログにルール読み込みエラーが出ないこと、を
    確認する。falcosecurity/falco Helm chart の既定 `rules_file` 順序 (`falco_rules.yaml` →
    `falco_rules.local.yaml` → `rules.d/*`、`customRules` は `rules.d` に配置される) では
    `append: true` は理論上機能するはずだが、**この chart version (`~8.0.0`) の実際の挙動を
    ロードして確認するまでは仮説として扱う**。
  - **(a-2) [non-blocking・参考] `container.name` 実測値の確認 (2026-08-25 追加)**:
    ADR-0007 と同じ probe 手法 (`arch-probe` ns、`falco-ctf/challenge:dev`) で `plant`
    という名前の initContainer を実際に立て、`container.name` の実測値を確認する。
    Decision (1) はこの値に依存しない設計へ再設計済みなので **blocking ではない**が、
    Decision (2) の belt-and-suspenders (`container.name != "plant"`) が実際に機能するか
    どうかの記録として残す。Signpost 5 の一次情報になる。
  - 安価な proxy として: `customRules` の YAML に `not proc.name in (shell_binaries)` の
    除外句 (Decision (1)) と `container.name != "plant"` の除外句 (Decision (2)) が字面として
    存在することを platform 側の静的テスト (YAML parse + grep 相当) で pin する。
- **(b) 採点回帰テスト [`make test`, 必須]**: **注記 — (b) は Go 層 (scoring/store) の
  wiring のみを検証する。「Falco の条件が実際にどのコマンドで発火するか」という主張はここでは
  検証できず、(a) の cluster E2E の対象である (2026-08-25 訂正, R2 qa-engineer 指摘: 初稿の
  (i)/(ii) は Falco condition の発火可否を `make test` で検証できると誤って分類していた)。**
  - (i) [Go 層: wiring のみ] 04 の `expectedRules` が `Search Private Keys or Passwords` の
    ままであり、その名前の**シミュレートされた** rule-fire イベントで 04 が非退行で solve する
    こと (既存テスト拡張)。`find`/`grep` コマンドが実際にこの Falco ルールを発火させること
    そのものは検証しない。
  - (ii) [Go 層: wiring のみ] `Search Private Keys or Passwords` の**シミュレートされた**
    rule fire が 05 を current の間 taint し solve を拒否すること。`cat /root/.ssh/id_rsa`
    が実際にこのルールを発火させることそのものは検証しない (a) の対象。
  - (iii) 新設ルールの**シミュレートされた** fire + 正しい flag submit で 05 が solve すること。
  - (iv) 新設ルール未発火なら forbidden 未発火でも solve 不可
    (`EvadeExpectedRuleFireRequired`。既存の `TestSubmitEvade_ExfilRequired_NotDelivered`
    と同型 — **2026-08-25 訂正 (R2 qa-engineer 指摘)**: 初稿が参照していた
    `TestSubmitEvade_ExfilRequired_NotSolved` は実在しないテスト名だった)。
  - (v) `ResetDirty` が `expected_rule_fire` を削除しないことを assert する negative test。
  - (vi) admin `Reset()` が `expected_rule_fire` を削除することを assert する positive test。
- **(c) catalog 交差テスト [新規の独立テスト関数。既存テストの拡張ではない —
  2026-08-25 訂正, R2 qa-engineer 指摘]**: ADR-0003 Verification (a) の交差テストとは対象データ・
  assertion 形が異なる新規のテスト関数を追加し、**新設ルール名 `Shell Redirected Private Key
  Read` に限定して**、他のどの challenge の `expectedRules`/`forbiddenRules` にも再利用されて
  いないことを assert する (専用ルールという前提の崩れを検出する)。**`Search Private Keys or
  Passwords` は 04/05/10 で意図的に共有されるルール名なので、この一意性検査の対象に含めない**
  (含めると必ず fail する)。
- **(d) API parity [`make test`, 必須]**: `MissionDetail` のキー数定数を 19→21 に更新し、
  apispec parity テストと `docs/openapi-scoreboard.yaml` を同じ PR で更新する (I14)。
  リクエストボディのフィールドは変わらないため `make gen` は不要 (レスポンスのみの追加)。
- **(e) `challenge-rules` CI ゲート整合 [必須。Decision (5)]**: `challenges/custom-falco-
  rules.txt` の追加と `scripts/check-challenge-rules.sh` の変更を、Falco rule 追加と同一 PR で
  landing し、ローカルで `scripts/check-challenge-rules.sh` (または相当する `make` target) を
  実行して green になることを確認する。加えて、故意に存在しないルール名を
  `challenges/*/falco-rule.yaml` に追加した fixture で red になることを確認する (openapi-expert
  の「検査は故意に違反させて赤くなることを示すまで『ある』と言わない」規律を踏襲)。
- **(f) 参考: `PROD-GATE-E2E-PLAN.md` との整合 (2026-08-25 追加, R5 cross-repo 指摘)**:
  `falco-ctf-platform/docs/PROD-GATE-E2E-PLAN.md` の Phase 5 step 6/8 は、現行バグ
  (mission05 の bare `cat` が発火しないことを期待値としている) を前提に書かれている。
  本 ADR の (a) を単純に追記するだけでは済まず、**期待値の反転** (bare `cat` は発火する側に
  変わる) と**シーケンスの再構成** (taint → reset → prove → submit の順に組み直す) が必要
  になる。詳細な platform 側 follow-up issue は、本 ADR が Accepted になった後に VP が起票する
  — 本 ADR 本文にはこの事実だけを記録する。
- **(g) 本 ADR は Hard Invariant を新設しない。** Consequences の候補文言は (a)+(b) が
  実機で landing するまで候補のままとする。

## Advice

- **product-engineer (2026-08-25, Issue #121 コメント / REFACTORING.md P26)**: 学習目標の
  再定義、A/B の二層構成、`/root/.ssh/*` の open/openat ベース forbidden 追加案の却下
  (ADR-0003 の非対称基準に基づく正しい判断) を提供。architect はこの判断をそのまま採用した。
  一方、product brief は A の condition が **deploy 経路自身の `sh -c` script 文字列 /
  `chmod` の argv と衝突する**ことを検査しておらず (`plant.sh`/`pod.yaml` の実装を読んでいない
  ため)、architect が実ファイル (`challenges/05-silent-search/plant.sh`,
  `charts/ctf-user/templates/pod.yaml:67-79`, `challenges/values-all.yaml:10-14`) を読んで
  発見・補正した (Decision (1)(2))。
- **falco-rules-expert skill (2026-08-25)**: shell の入力リダイレクトが fork 後 exec 前に
  親プロセス (shell) の image のまま file を open する、という B の技術的前提の Linux
  fork/exec モデル上の正しさを確認した (非拘束の技術助言)。
- **security-engineer (R1, 2026-08-25)**: 本 ADR の初稿を独立レビューし、以下を指摘。
  1. **`container.name` を deploy 安全性の根拠にすることへの懸念** — 短命コンテナでは
     Falco の container メタデータ enrichment が exec/終了より遅れる race がありうる
     (enrichment race)。architect の independent finding (ADR-0007 実測ログとの矛盾) とは
     **別の根拠から同じ結論**に到達しており、Decision (1) の全面再設計 (`container.name`
     依存の撤廃) に直結した。
  2. **`customRules`/`append: true` のロード順序未検証によるFalco DaemonSet 起動失敗リスク**
     (platform に CI/branch protection が無く機械的な安全網が無いことも踏まえて指摘) →
     Verification (a-1) として反映。
- **qa-engineer (R2, 2026-08-25)**: 本 ADR の初稿を独立レビューし、以下を指摘。全て反映済み。
  1. **BLOCKING**: 新設ルール名が `scripts/check-challenge-rules.sh` (required check
     `challenge-rules`) の upstream 名照合で確実に fail する → Decision (5) を新設。
  2. `EvadeExpectedRuleFireRequired` の宣言位置が実行順と矛盾 → Decision (3) を訂正。
  3. Verification (b)(i)/(ii) が Go テストで検証できない主張を含んでいた → Verification (b)
     の対象を wiring のみに限定し、条件発火の主張は (a) に移した。
  4. Verification (b)(iv) が参照するテスト名が実在しない → 実在する
     `TestSubmitEvade_ExfilRequired_NotDelivered` に訂正。
  5. Verification (c) が「既存テストの拡張」ではなく新規の独立テストであることが未記載、
     対象が広すぎた (既存の共有ルール名まで一意性検査の対象にしていた) → 訂正・スコープ限定。
- **R3 (conventions レビュー)**: ADR 番号衝突 (Issue #144 が自称していた ADR-0008) を指摘。
  **VP が直接対処済み** (Issue #144 → ADR-0009 に訂正、app#181 起票)。本 ADR はこの点に触れない。
- **R5 (cross-repo レビュー, 2026-08-25)**: 本 ADR の初稿を独立レビューし、以下を指摘。全て反映済み。
  1. 「契約表の列挙 8 項目」という記述が、その場で列挙している項目数 (7) とも
     `.claude/rules/falco-ctf-app-conventions.md` の実表の行数 (10) とも合わない → 数え直して
     訂正 (Consequences)。
  2. 「今すぐ契約表に行を追加する」という文言 → 「platform 側で `customRules` を初めて
     導入する実装 PR のタイミングで追加する」に補正 (Consequences)。
  3. `PROD-GATE-E2E-PLAN.md` Phase 5 step 6/8 が現行バグを前提にしており、単純な追記では
     済まないことが未記載 → Verification (f) を追加。
  4. 「同じ PR で `.claude/skills/falco-rules/SKILL.md` を訂正する」が、この skill は
     app/platform とは別の第三のリポジトリ (workspace root) に属するため文字通り不可能 →
     「同一変更ウィンドウ内で workspace root に追従コミット/PR」に訂正 (Consequences)。
- **architect (R4, 自己レビュー / 2代目セッションによる独立再査読, 2026-08-25)**: 初稿の
  `container.name = "plant"` が ADR-0007 自身の実測ログと矛盾することを発見し、Decision (1) の
  全面再設計 (`plant.sh` の `chmod` 排除による deploy-safety の構造的保証) に至った。
  R1 の enrichment race 指摘と独立に収束したため、設計の中核欠陥として扱った。
  Decision (3) の write 側走査条件の精度不足、Context の帰属誤り、I13b 対象集合の算術誤りも
  自己検出し訂正した。
