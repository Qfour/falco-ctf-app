# ADR-0017: mission 13 (Collection, T1560.001) の custom Falco rule — trigger 型・syscall/fd 主軸の `Archive Collected Data`

- Status: **Accepted** (2026-08-26 — implementation landed on both repos, Verification
  (a)/(a-1)/(a-2)/(a-3)/(b)/(c)/(d) satisfied; see below)
- Date / Deciders: 2026-08-26 / architect (起草)、VP (承認)
- 関連: REFACTORING.md P27-4 (Collection の実現性調査完了・次の空き課題番号 `13` を予約
  [`REFACTORING.md:1404-1407,1417`])、ADR-0008 (custom Falco rule 新設の project 初 precedent。
  本 ADR は project 史上 **2 件目**の `customRules` 利用)、ADR-0001/0007 (deploy 経路の
  無汚染設計・I13a/I13b)、ADR-0003 (evade の attempt スコープ・FP/FN 評価基準。本 ADR は
  **trigger 型を採るため直接の適用対象ではない**が、判断根拠として引用する)、ADR-0015/0016
  (Initial Access / Privilege Escalation 除外の同型判断フォーマット)

## Context

- **upstream に Collection (T1005/T1560) の default rule が無い (content-engineer 実測、
  25本の stable rules を全数確認済み。REFACTORING.md:1404-1405)**。本 ADR 起草時に
  `falcosecurity/rules` の `falco-rules-3.0.1` タグ (`scripts/check-challenge-rules.sh:15`
  が pin する参照) を実際に fetch し、`tar`/`gzip`/`zip`/`archive`/`compress`/`7z` の
  いずれの文字列も条件・list・macro・rule 名に一致しないことを確認した (grep 0 件)。
  したがって検知には ADR-0008 と同型の **project 固有 custom rule 新設**が必須というのは
  仮説ではなく実測結果である。
- **課題番号は `13`** — product brief 時点の案 `12` は後続の Defense Evasion 拡張
  (`Clear Log Activities`, T1070.002) が先に `12-cover-tracks` として merge 済みのため
  空いていない (`REFACTORING.md:1406-1407,1411-1414`)。`git log`/`ls challenges/` で
  `13-*` 未使用を確認済み。
- **単一 Pod・Service/Ingress 無し・root 実行という既存制約内で完結する** (I9 不変)。
  ADR-0001 の flag isolation を緩めない設計にする必要がある —— 後述の通り、本課題は
  **trigger 型を採るため flag もplant initContainer も一切不要**であり、緩める対象自体が
  存在しない (09/11/12 の precedent と同型。下記 Decision (2) 参照)。
- **課題コンテナに実在する archive ツール (実測)**: `images/challenge/Dockerfile` の
  base は `alpine:3.22`。busybox が `tar`(1.37.0)/`gzip`/`gunzip`/`unzip`/`cpio` を
  symlink 経由で提供する (`docker run --rm alpine:3.22 sh -c 'which tar gzip ...'` で実測)。
  追加パッケージ (`bash`/`coreutils`/`busybox-extras`/…) を見ても `zip`(作成)/`7z` は
  入っていない。よって本 CTF の想定解は **`tar` (実測で確実に存在) が主導線**であり、
  `gzip`/`bzip2`/`xz` 等はパイプ併用の亜種として fixture 上有効だが必須ではない。
- **ADR-0003 基準の適用範囲についての判断**: ADR-0003 の FP/FN 基準
  (honest path を誤検知させない / exploit path の簡単な回避手段を残さない) は
  **evade 型 (forbiddenRules による否定条件ゲート)** を主眼に確立されたものだが、
  本 ADR は同じ基準の**片側**(honest path での誤検知を避ける)を trigger 型にも適用する
  ——「trigger だから何でも検知して良い」ではなく、無関係な操作を誤って auto-solve
  させないことは trigger 型でも守るべき設計品質だからである (下記 Decision (1) で
  具体的に検討する)。もう片側 (回避手段の単純さ) は trigger 型には本質的に適用されない
  ——参加者は検知を**逃げる**必要が無く、**踏む**ことがゴールである。この非対称を
  明示することが本 ADR の判断の核。

## Options

### Option 1 — trigger 型 + `open_read`/`fd.name` 主軸の syscall 検知 【推奨】

**変更点**: 新規 Falco rule `Archive Collected Data` を追加。検知の核は
「archive ツールの `proc.name`」と「そのプロセスが実際に open_read した file の
`fd.name` が staged collection ディレクトリ配下」という **2 つの外形的事実の AND**
(コマンドライン引数の文字列一致には依存しない)。`challenges/13-archive-loot/
falco-rule.yaml` は `type: trigger`, `expectedRules: [Archive Collected Data]`
のみ (forbiddenRules 無し、flag 無し、plant.sh 無し — 09/11/12 と同型)。

- **コスト**: 最小に近い。Falco rule 1 本 (list 1・macro 2・rule 1) + platform
  `customRules` への追記 (既存 block に rule を追加するだけ。falco chart 側の
  ConfigMap/mount 機構は ADR-0008 で既に landing 済みなので**新規の機構は不要**、
  中身の追記のみ) + app 側 `challenges/13-archive-loot/{README,journey.yaml,
  falco-rule.yaml,fixtures/loot/*}` (別 PR、content-engineer 領域) +
  `challenges/custom-falco-rules.txt` に1行追加。
- **リスクと可逆性**: 完全に可逆 (customRules block からこの rule だけ削除すれば
  default 相当に戻る。他課題の customRules — ADR-0008 の `Shell Redirected Private
  Key Read` 等 — に影響しない、名前空間が排他)。**リスク**: `kubectl cp` は
  コンテナ内で `tar` を起動する (`falco-ctf-platform/docs/falco-detection-conditions.md`
  §5 で既に文書化済みの事実)。運営が staged loot ディレクトリを対象に ad-hoc
  `kubectl cp` すると、その participant の trigger が意図せず auto-solve する
  ——**これは新しいリスクではなく、既存ミッション (02/03/10) が既に抱えている
  同種のリスクの延長**であり、既存の運用規律 (`operations.md` §6.7 — kubectl exec/cp
  後に rule-fire 増分を確認する) がそのまま covers する。新しい機構は不要 (下記
  Consequences で明記)。
- **効き始める閾値**: 実クラスタでの mutation test (`tar`/`gzip` で fixture を
  archive → 発火、`cat`/`less` で覗くだけ → 非発火) が確認できるまでは仮説。

### Option 2 — evade 型 + 積極証明ゲート (ADR-0008 の `requireExpectedRuleFire` を横展開)

**変更点**: 「loot を archive しても検知されないように隠す」ことを exploit path とし、
forbiddenRules (何らかの汎用 archive 検知) + expectedRules (証明用の別ルール) +
`requireExpectedRuleFire` を新設する。

- **コスト**: 最高。ADR-0008 と同水準の機構複製 (catalog field・store table・
  scoring gate・API 2 フィールド追加・parity テスト更新) に加え、**「archive を
  隠す」という pedagogically 説得力のある exploit path をこの技法単体では設計できない**
  — Collection (T1560) の本質的なステルス性は「archive したこと自体を隠す」ではなく
  「archive した結果 (少数の大きい転送) を exfiltration 段階でどう検知回避するか」
  にあり、それは既に mission 10 (`10-final-exfil`) の scope である。本課題単体に
  無理に「回避」の軸を持たせると、10 と学習目標が重複するか、恣意的な forbidden
  条件を作るだけになる。
- **リスクと可逆性**: 機構は `requireExpectedRuleFire: false` で Option 1 相当へ
  後退可能だが、**そもそも作る動機が薄い** (10 との重複)。ADR-0008 が
  「2 問目で投資が償却される」ことを Option 2 採用の根拠にしたのに対し、
  本課題は 3 問目にもならず、単独では投資が回収されない。
- **効き始める閾値**: 将来、Collection 系の課題を複数追加する計画が生まれ、
  かつそのうち少なくとも 1 つに「archive の存在を隠す」という固有の exploit path
  が具体的に設計できたとき。

### Option 3 — proc.args のコマンドライン文字列一致 (mission04/11 の idiom をそのまま流用)

**変更点**: `proc.name in (archive_binaries) and proc.args contains "<collection-dir
のリテラル文字列>"` という、mission04 (`find` + `id_rsa` literal) / mission11
(`grep`/`find` + AWS credential literal) と全く同じ idiom を流用する。

- **コスト**: 最小 (04/11 と完全に同型なので実装者が新しいパターンを学ばない)。
- **リスクと可逆性**: 可逆だが、**構造的な偽陰性を持つ** — `cd` して相対パスで
  archive する自然な操作 (`cd /opt/ctf/missions/13-archive-loot/fixtures/loot &&
  tar czf /tmp/out.tar.gz .`) では `proc.args` に絶対パスの literal が現れないため
  **発火しない**。04/11 はこの弱点を意識せず同じ idiom を採っている
  (04 は `find`/`grep` の args 自体が探索対象の literal を含むことが前提の技法なので
  この弱点が現れない — 05 の対称、mission 04/11 の `proc.args contains` は
  「検索対象の語がコマンドの引数として現れる」という技法の性質と一致するが、
  「archive 対象のディレクトリ」は cd 一つで引数から消える、という技法上の違いがある)。
  trigger 型なので偽陰性は「セキュリティホール」ではなく **「自然な操作をしたのに
  auto-solve されない」という参加者体験の劣化**として現れる。
- **効き始める閾値**: 採らない。ここでは「idiom の流用が常に正しいとは限らない」
  ことの記録として残す (Consequences 参照)。

## Decision

**Option 1 を採る。**

### (1) 検知の核: 3 条件の AND (`open_read` × 対象ディレクトリ × archive ツール識別)

```yaml
- list: archive_binaries
  items: [tar, gzip, gunzip, bzip2, bunzip2, xz, unxz, zip, unzip, 7z, 7za, cpio]

- macro: archive_tool_procs
  condition: (proc.name in (archive_binaries))

- macro: collection_target_dir
  condition: (fd.name startswith "/opt/ctf/missions/13-archive-loot/fixtures/loot/")

- rule: Archive Collected Data
  desc: >
    An archive/compression utility opened a file for reading under the
    staged "collected data" directory for mission 13 — the archive-before-
    exfiltrate step of MITRE ATT&CK T1560.001 (Archive Collected Data:
    Archive via Utility). Detection keys on the syscall fact (which file an
    archive tool actually opened for read) rather than on the tool's
    command-line arguments, so it fires the same way whether the invocation
    uses an absolute path, a relative path after `cd`, or a glob.
  condition: >
    open_read
    and collection_target_dir
    and archive_tool_procs
  output: >
    Archive utility read file under staged collection target
    file=%fd.name tool=%proc.name command=%proc.cmdline user=%user.name
    k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name
  priority: NOTICE
  tags: [maturity_stable, host, container, process, filesystem, mitre_collection, T1560.001, ctf_custom]
```

**なぜこの 3 条件か (falco-rules-expert の「除外を厚くする/proc.name 単独に頼らない」
craft をそのまま適用)**:

- `open_read` (upstream macro, `evt.type in (open,openat,openat2) and
  evt.is_open_read=true and fd.typechar='f' and fd.num>=0`) — 「ファイルが実際に
  読み取りモードで open された」という外形的 syscall 事実。`proc.args` のような
  攻撃者が完全に制御できる文字列より偽装しにくい。
- `collection_target_dir` (`fd.name startswith ".../fixtures/loot/"`) — 対象を
  この課題専用の staged ディレクトリに絞る。**`fd.name` の絶対パスは kernel の
  dirfd 解決を経て Falco が補完する**ため、`cd` して相対パスで開いても正しく
  絶対パスとして評価される (Option 3 の偽陰性がここで解消される)。
  **末尾に `/` を付ける**ことで `.../loot-backup/` のような同一 prefix を持つ
  兄弟ディレクトリへの誤マッチ (startswith の古典的な罠) を避ける。
- `archive_tool_procs` (`proc.name in (archive_binaries)`) — 「ただ `cat`/`less`
  で loot を覗いただけ」(honest な探索操作) を除外する唯一の gate。この条件が
  無いと `open_read and collection_target_dir` だけで **catalog を読むだけの
  操作 (`cat README.md` 相当の探索)** まで発火してしまい、ADR-0003 が確立した
  「honest path で誤検知しない」という規律を trigger 型でも破ることになる。
- **3 条件のうち 1 つでも外すと成立しない設計にした** — falco-rules-expert の
  「除外は最小限、gate 条件を厚くする」を検知の**成立条件**側に適用したもの
  (本課題には除外/exception 節は無い。単純な AND 3 項で十分に絞れているため、
  除外を追加する必要が生じていない)。

### (2) trigger 型・flag/plant 無し (09/11/12 と同型)

`challenges/13-archive-loot/falco-rule.yaml` (実装は別 PR、content-engineer 領域):

```yaml
challengeId: 13-archive-loot
type: trigger
expectedRules:
  - Archive Collected Data
attack:
  tactic: "Collection"
  techniqueId: "T1560.001"
  techniqueName: "Archive Collected Data: Archive via Utility"
```

- **flag/plant initContainer は不要** — trigger 型は rule fire だけで solve が
  確定し (`evaluateTrigger` は attempt スコープ外で無条件 solve、ADR-0008
  Context 参照)、フラグ提出を要求しない。ADR-0001 の flag isolation (I12) を
  緩める対象がそもそも存在しないため、緩和の検討自体が不要。
- **fixtures は build-time に静的に焼き込む** (`images/challenge/Dockerfile` の
  既存の一括 `COPY challenges/ /opt/ctf/missions/` に自動的に含まれる。新しい
  `COPY`/`RUN` 行は不要 — 09/11 の fixtures 追加時と同じ)。
  `challenges/13-archive-loot/fixtures/loot/` に、実データに見えるが機密ではない
  ダミーファイル 2〜3 本 (例: 顧客名簿風 CSV・社内メモ風テキスト。11 の
  `aws-credentials.sample` と同水準の「本物らしいが非機密」なダミー、I10 不変)
  を置く。**実フラグ・実 PII は一切含めない**。
- **T1560.001 (親 T1560 ではなく sub-technique) を選ぶ理由**: 検知の核が
  「CLIアーカイブユーティリティ (`tar` 等) の呼び出し」という具体的な技法なので、
  T1560.002 (Archive via Library) や T1560.003 (Archive via Custom Method) とは
  区別できる。02/06/12 で既に確立された「upstream の粗いタグより実測に基づく
  honest な sub-technique を選ぶ」規律 (12-cover-tracks の T1070.002 判断と同型)
  をここでも適用した。

### (3) デプロイ経路の無汚染 (I13a/I13b 系の候補集合 +1、静的に確認済み・実機は未確認)

- **deploy 経路 (`images/challenge/Dockerfile` の RUN/COPY 群、`deploy-user.sh`、
  `plant` initContainer) はこの課題向けに `tar`/`gzip` を一切実行しない** —
  そもそも plant.sh 自体が存在しない (上記 (2))。実測: `images/challenge/Dockerfile`
  の全 RUN/COPY 行、`challenges/{submit-all,banner,setname,submit-yaml}.sh`、
  既存の全 `plant.sh`、`charts/ctf-user/` 配下を `grep -rn "tar\b"` した結果、
  一致は 0 件 (本 ADR 起草時点の実測)。
- **本 ADR が新たに I13b の対象候補集合に加えるルール名は 1 本
  (`Archive Collected Data`)** — 昇格済み Hard Invariant ではなく、
  ADR-0008 と同じ「実機 cluster 実測が残 gate」の未昇格候補として扱う
  (`.claude/rules/falco-ctf-app-conventions.md` の I13a/I13b 注記表に、
  実装 PR のタイミングで対象数を更新する)。
- **`kubectl cp` によるコンテナ内 `tar` 起動という既知の運用汚染経路が、この新
  rule 名にも及ぶ** (`falco-ctf-platform/docs/falco-detection-conditions.md` §5 —
  既存 02/03/10 と同種のリスク)。新しい機構は追加しない — 既存の
  `operations.md` §6.7 の「kubectl exec/cp 後に rule-fire 増分を確認する」運用
  規律がそのまま適用範囲を拡張する。実装 PR で該当 doc に 1 行 (対象ルール名の
  追記) することを推奨する (blocking ではない)。

### (4) `challenges/custom-falco-rules.txt` / `challenge-rules` CI ゲート

ADR-0008 Decision (5) と同じ理由・同じ機構 (allowlist の追記のみ、スクリプト自体は
無改修)。実装 PR で `Archive Collected Data` を1行追加し、platform 側
`helmfile/releases/falco/values.yaml.gotmpl` の既存 `customRules` block に本 rule
を**追記** (ADR-0008 の rule と同じ ConfigMap キー、または新規キーを追加。
新設のトップレベル機構は不要 — chart-native `customRules` は既に landing 済み)。
**同一 PR で app 側マニフェスト追記と (実装 PR の一部としての) 内容確定を揃えること**
(ADR-0008 と同じ DoD)。

### (5) デプロイ順序依存 (Cross-repo 契約表への追記を推奨)

ADR-0008 と同じクラスの順序依存が生じる: platform 側 `customRules` に
`Archive Collected Data` が landing する**前**に app 側の
`challenges/13-archive-loot/falco-rule.yaml` (`expectedRules: [Archive Collected
Data]`) を有効化すると、その課題は（永久ではなく）**platform 側の対応する
release が追いつくまで発火しない**。trigger 型で forbiddenRules も flag も
持たないため、ADR-0008 (evade 型・`requireExpectedRuleFire`) ほど深刻な
「softlock」ではない — 単に「まだ solve できない」状態が続くだけで、他ミッションの
進行やキャプストンの採点をブロックしない (09/11/12 と同じ独立ボーナス scope
である限り)。それでも **platform → app の順を守ること**を推奨する
(`.claude/rules/falco-ctf-app-conventions.md` の Cross-repo 契約表「Falco custom
rule override (ADR-0008)」行に、実装 PR のタイミングで本 rule 名を追記する)。

## Consequences

- **手放すもの**: 「archive すること自体を隠す」という evade 型の学習目標
  (Option 2)。Collection のステルス性を教えたい場合は、将来 mission 10
  (exfiltration) の拡張、または新規の独立課題として別途設計すべきで、本課題に
  無理に統合しない。
- **新たに守る候補不変条件 (未昇格・実機検証待ち)**: I13a/I13b の対象候補集合に
  `Archive Collected Data` を +1 する。ADR-0008 と同じ理由で、実機 cluster
  実測が完了するまで `.claude/rules/falco-ctf-app-conventions.md` の表には
  追記しない (Hard Invariant への昇格条件はそこに既に明記されている規律のまま)。
- **既存の運用リスクの延長 (新規機構なし)**: `kubectl cp` による ad-hoc tar 起動が
  この新 rule にも及ぶ。`operations.md` §6.7 の対象ルール名リストへの追記を
  実装 PR の non-blocking follow-up として推奨する。
- **前例の蓄積**: project 史上 2 件目の `customRules` 追加。ADR-0008 が作った
  chart-native 機構 (ConfigMap → `/etc/falco/rules.d`) をそのまま再利用するので、
  「機構自体」の新設コストは既に payoff 済み — 本 ADR のコストは condition の
  設計のみに絞られている (ADR-0008 の Signpost 群が「2 問目でこの投資が
  償却される」と予告していたのは `requireExpectedRuleFire` の再利用文脈だったが、
  `customRules` chart 機構そのものの再利用という意味でも同じ効果が出ている)。
- **クロスリポ**: platform 側 `helmfile/releases/falco/values.yaml.gotmpl` の
  `customRules` block への追記 (既存キー構造の維持、新規トップレベル機構なし) と
  app 側 `challenges/13-archive-loot/*` は architect の同意権スコープ
  (Falco custom rule override は Cross-repo 契約表に既に行がある) に該当するため
  **両リポ同時 PR + 相互リンク必須**。ただし本 ADR 自体はどちらのリポにもコードを
  書かない (ADR ドキュメントのみ)。
- **参加者向け runbook**: 新規の reset 文言は不要 (trigger 型は reset-dirty の
  対象外 — dirty はforbiddenRulesを持つevade型にのみ存在する概念)。

## Signposts

1. **将来、archive 段階そのものに「検知を隠す」pedagogically 説得力のある
   exploit path が具体的に設計できた場合** (例: 圧縮方式やチャンク分割で
   単一の大きな `open_read` パターンを分散させる、等) — Option 2 (evade 型 +
   `requireExpectedRuleFire`) を再検討する。ただし mission 10 との学習目標重複を
   まず確認すること。
2. **`kubectl cp` による運用汚染が実際に一度でも観測された場合** (この rule に
   限らず、既存 02/03/10 でも同様) — `operations.md` §6.7 の「検知的統制のみ」
   という現状を機械強制 (例: 特定 namespace への `kubectl cp` を audit log で
   自動検知しアラート) へ格上げする議論を始める。
3. **将来の plant.sh (別課題) が `/opt/ctf/missions/13-archive-loot/fixtures/loot/`
   配下に書き込みを行うようになった場合** — 本 ADR の「deploy 経路は tar/gzip を
   一切実行しない」という前提 (Decision (3)) が崩れる可能性があるため、
   ADR-0001/0007 と同じ実測手順で deploy 経路の無汚染を再確認する。
4. **Falco のメジャーバージョンが上がり `open_read`/`fd.name` の意味論が変わる**
   場合 — 新しい deployed ruleset から `challenges/13-archive-loot/rule.yaml`
   (表示用抜粋) を再抽出し、本 ADR の condition を再検証する
   (falco-rules-expert の「バージョンが上がったら再抽出する」原則)。

## Verification

- **(a) deploy 経路無汚染 [blocking・実機 cluster 実測が残 gate]**: 静的 grep で
  deploy 経路 (Dockerfile/plant.sh/deploy-user.sh/charts) に `tar`/`gzip`/
  `archive_binaries` の呼び出しが無いことを確認済み (本 ADR 起草時点、上記
  Decision (3))。ただし **実クラスタで新 customRules を deploy した後、
  新規 workspace の deploy 直後に該当 user の `Archive Collected Data`
  発火数が 0 であること**を実測するまで「無汚染」と結論しない
  (I13a/I13b 系の既存の残 gate と同じ扱い)。
  - **(a-1) [blocking] `customRules` の DaemonSet 再起動確認**: 本 rule を
    追記した Falco Helm values を実際に colima/dev cluster にロードし、
    Falco DaemonSet Pod が `Running` のまま `CrashLoopBackOff` にならないこと、
    起動ログにルール読み込みエラーが出ないことを確認する (ADR-0008
    Verification (a-1) と同型)。
  - **(a-2) [blocking・本 ADR 固有] 意図した trigger 操作での発火確認**:
    disposable colima 環境で `tar czf /tmp/loot.tar.gz
    /opt/ctf/missions/13-archive-loot/fixtures/loot/` (絶対パス) と
    `cd .../fixtures/loot && tar czf /tmp/loot.tar.gz .` (相対パス、Option 3 が
    落とすケース) の**両方**で `Archive Collected Data` が発火することを実測する。
  - **(a-3) [blocking・本 ADR 固有] 意図しない正規操作での非発火確認**:
    同環境で `cat`/`less` で loot ファイルを読むだけの操作、および loot dir
    と無関係な場所 (`/tmp`, `/etc` 等) への `tar` 操作で `Archive Collected
    Data` が発火**しない**ことを実測する。
- **(b) catalog 交差テスト [`make test`, 必須]**: `Archive Collected Data` が
  他のどの課題の `expectedRules`/`forbiddenRules` にも再利用されていないことを
  assert する (ADR-0008 Verification (c) と同型の新規独立テスト)。
- **(c) `challenge-rules` CI ゲート整合 [必須]**: `challenges/custom-falco-
  rules.txt` への追記と Falco customRules への追記を同一変更ウィンドウで
  landing し、`scripts/check-challenge-rules.sh` が green になることを確認する。
  故意に typo したルール名の fixture で red になることも確認する
  (ADR-0008 Verification (e) と同型)。
- **(d) API parity [`make test`, 必須]**: 新課題追加は既存の `MissionDetail`/
  `Journey` schema のキー集合を変えない (trigger 型は既存フィールドのみで
  表現できる、09/11/12 も schema変更を伴わなかった)。したがって ADR-0005 の
  parity gate は**回帰確認のみ**で新規対応は不要 — この点を明示することで
  「新課題追加のたびに spec を変える」という誤解を防ぐ。
- **(e) 本 ADR は Hard Invariant を新設しない。** I13a/I13b の候補集合拡張は
  (a) が実機で landing するまで候補のままとする。

**実測結果 (2026-08-26, platform-engineer + content-engineer + VP 独立確認)**:

- **(a)/(a-1)**: platform-engineer が disposable colima profile `ctf-adr0017` で
  `helmfile -e local -l name=falco sync` を実行。Falco DaemonSet は `Running`・
  restart 0、起動ログにエラー無し、`falco -V` ドライランで
  `{"errors":[],"successful":true,"warnings":[]}`。mission05 の既存ルールも
  無変更で正常動作を継続 (diff は純追加、削除行 0 件)。list/macro/rule 名の衝突は
  静的 (upstream タグ) と実機 (deploy 済み embedded ruleset) の両方で 0 件確認。
- **(a-2)/(a-3)**: content-engineer が別の disposable colima profile
  `ctf-adr0017-verify` で、platform ブランチの customRules と本課題の実 fixtures を
  同時デプロイし、falcosidekick `/metrics` の event カウンタで4パターン実測:
  絶対パス `tar czf .../loot/` → FIRE、`cd` 後の相対パス `tar czf .` → FIRE
  (Option 3 が落とすはずだったケース)、`cat` での探索のみ → NO FIRE、無関係
  ディレクトリへの `tar` → NO FIRE。実際の Falco JSON 出力
  (`rule=Archive Collected Data`, `file=.../customer-roster.csv`, `tool=tar`) を
  challenge README に転記済み。
- **(b)**: `TestExpectedRuleFire_NewRuleNameUniqueToMission13`
  (`internal/catalog/catalog_test.go`) を新設、ADR-0008 の
  `...Mission05` 版と同型。`make test` (`docker build --no-cache`, VP 独立再実行)
  で green。
- **(c)**: `challenges/custom-falco-rules.txt` に追記、`make check-rules` green。
  VP が実際に `falco-rule.yaml` の rule 名へ typo を注入する mutation test を実施し、
  `check-rules` が `FAIL: a challenge references a Falco rule that does not
  exist...` で red になることを確認 → revert して green 復帰を確認
  (ADR-0008 Verification (e) と同型の red→green 実証)。
- **(d)**: `make test` の API parity テスト群 (`internal/apispec` 含む) green。
  新課題追加で spec のキー集合が変化しないことを確認 (回帰のみ、新規対応不要の
  想定どおり)。
- 両リポの実装 PR: falco-ctf-platform#129 (customRules 追加)・
  falco-ctf-app#215 (challenge 13-archive-loot 本体)。デプロイ順序
  (platform → app) を守って CEO merge 済み。

## Advice

- **content-engineer (先行調査, REFACTORING.md P27-4)**: Collection の
  upstream rule 不在の実測、および trigger 型を推奨する初期判断を提供。
  architect はこの推奨をそのまま採用し、fd/syscall 主軸の condition 設計と
  Option 2/3 の比較検討で補強した (content-engineer の調査は condition の
  具体形までは踏み込んでいなかったため)。
- **falco-rules-expert skill (2026-08-26)**: `open_read` の upstream 定義
  (`fd.typechar='f'` 必須)・`proc.name` 単独への依存を避け gate を厚くする
  craft・`startswith` の prefix collision 罠を確認した (非拘束の技術助言)。
  この助言が Option 3 (cmdline literal 一致) を rejected とし、Option 1
  (fd/syscall 主軸) を採用する直接の根拠になった。
- **falco-ctf-conventions / falco-ctf-app-conventions skill**: ADR-0008 の
  precedent (`customRules` の chart-native 機構、`challenges/custom-falco-
  rules.txt` allowlist、デプロイ順序依存の記法) をそのまま継承する方針の
  裏付けに使用。
