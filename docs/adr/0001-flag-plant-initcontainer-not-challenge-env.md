# ADR-0001: フラグの仕込みを initContainer に移し、challenge コンテナにフラグ実値の到達経路を一切設けない

- Status: Proposed
- Date / Deciders: 2026-08-18 (rev.2 / rev.3 同日改訂) / VP (承認) + architect (設計) + security-engineer (独立監査) + CEO (merge)
- 関連: CEO 決定「本番経路のフラグ env 注入を次イベント前に閉じる」(2026-08-18)、
  **security-engineer 独立監査 (2026-08-18): 判定 PASS with conditions / findings F1-F6 + 限界指摘**、
  **ADR-0003 (evade attempt スコープ, Accepted)** — deploy 経路と採点の相互作用の正典 (rev.3 で追加)、
  P11.5 (egress lockdown)、P23-3 (ttyd-proxy)、Hard Invariants I5/I7/I9/I10、
  `.claude/rules/falco-ctf-app-conventions.md` §フラグ注入 (単一ソース)、
  CEO 決定「`falco-ctf-app-prodlocal/` 削除 + LIVE hotfix を `origin/archive/live-hotfix-2026-08-16` へ退避」(2026-08-18)

> **rev.2 (2026-08-18) の改訂点**: security-engineer の独立監査を反映。
> Verification を列挙型 assert → **allowlist 型 assert** に変更 (F1)、layer 3 を人手 runbook →
> **deploy 時 fail-closed 機械 assert** に変更 (F2)、**検証コマンド自身の採点汚染**を修正 (F3)、
> **mission 09 の EXDEV 破壊**を Options と完了条件に前倒し (F4)、**seed root mount 禁止**を明文化 (F5)、
> **重複 plant-target の dedupe と seed 初期化**を gen-drift に追加 (F6)、
> **本 ADR の限界 (mission 05 で「技法の証明」前提が成立しない)** を明記。
> I12 は **F1 + F2 の実装をもって発効** (ADR merge と同時発効にしない)。

> **rev.3 (2026-08-18) の改訂点**: **本 ADR 内部の矛盾を解消した** (VP 指摘 + architect の実コード検証)。
> rev.2 の Verification 2-3 が必須化した seed 初期化 (「image rootfs から `cp -a /etc/shadow` する」) は、
> **同じ rev.2 の §F3 が禁止した行為そのもの**であり、しかも assert (検証時に 1 回) ではなく
> **本番 deploy 経路 (全 workspace・毎 deploy)** で起きる —— rev.2 のままでは
> **mission 02 が全参加者・全 deploy で submit 無しに auto-solve する**。改訂点:
> 1. **§F3 を「assert について」から「deploy 経路と assert の両方について」に一般化** (§F3′)。
>    要件は **「Falco イベントを 1 件も出さない」**、手段は文脈依存 (assert = builtin-only /
>    deploy = 禁じ手集合を踏まない) と書き分けた
> 2. **派生決定 (3)「seed 初期化の供給元」を新設**し、層ごとに 5 案 (S-a〜S-e) を評価して
>    **S-a (image build 時に非 sensitive path へ素データを snapshot し、実行時は sensitive path を
>    一切 read しない)** を採用。**Verification 2-3 の「image rootfs から実行時コピー」要件は撤回**
> 3. **plant-target × mission の全網羅表**と **deploy 経路の禁じ手表**を追加 (rev.2 は 02 のみ暗示していた)
> 4. **ADR-0003 との非対称**を明記 —— trigger 側は汚染される / evade 側は初回 deploy では汚染されないが
>    **再 deploy では恒久 taint される** (rev.2 はどちらも扱っていない)
> 5. **Verification layer 4 (E2E) を新設**。残る prod gate である **ADR-0003 Verification (d) と同一 run 内**で
>    deploy 経路の無汚染を観測する (現状の (d) はこの欠陥に対して盲目である)
> 6. 本 ADR が提案する不変条件を **I11 → I12 に改番** (ADR-0003 が Accepted として I11 候補を先に
>    主張しているため。下記「不変条件の番号」節)。**新たに I13 (deploy 経路の無汚染) を提案**
> 7. DoD を **11 → 14 項目**に (差し替え内容は「実装 PR の完了条件」冒頭に明記)

## Context

### 現状の経路 (実コードで確認)

本番の roster deploy は全 workspace を all-missions モードで作る:

```
falco-ctf-platform/scripts/deploy-event-workspaces.sh:66    CHALLENGE=all
  → falco-ctf-app/charts/ctf-user/deploy-user.sh:162-176     ALL_MODE=1 → --set challenge.allMissions=true
    → charts/ctf-user/templates/pod.yaml:164-173             range で全ミッションの CTF_FLAG_<ID> を
                                                             challenge コンテナの env に注入
```

`challenges/<NN>/plant.sh` (03/05/10 の 3 本) がこの env を読んでフラグを仕込む。plant は
`pod.yaml:179-185` の `lifecycle.postStart` で **challenge コンテナ自身の中で** 実行される
(`challenges/gen-values.sh:26-60` が plant.sh から `challenge.postStart` argv を生成、
生成物は `challenges/values-all.yaml:6-37`)。

参加者は challenge コンテナで root (`pod.yaml:36` `runAsNonRoot: false` — CTF realism として意図的)。
したがって:

- **H1 (本 ADR の対象)**: `env | grep CTF_FLAG` で全 evade ミッションのフラグを、
  ミッションを 1 つも解かずに取得できる。Falco の検知も一切発火しない。
- しかも challenge image は `challenges/` を丸ごと焼く (guided-event 決定、
  `images/challenge/Dockerfile:42-47`)。焼かれた `challenges/03-stealth-read/README.md:12-15` は
  「実値はイベント毎に注入される (`CTF_FLAG_03_STEALTH_READ`)」と **env 変数名まで参加者に明示している**。
  H1 は「見つかるかもしれない穴」ではなく **参加者向けドキュメントに書かれた近道**である。
- `charts/ctf-user/values.yaml:88-102` は既知として記録済み
  ("To avoid leaking other missions' answers ... unless allMissions=true, which injects all") ——
  つまり本番既定値 (`allMissions=true`) が、その注記が避けようとした状態そのものになっている。

guided-event 方針 (想定解を image に焼く) との差: 想定解を読むことは「課題をやる」ことだが、
`env | grep` は何もしなくて済む。性質が一段重い。

### 影響範囲: フラグは全参加者で同一値 [監査 MEDIUM]

roster deploy は `--flags-file` を **1 つだけ受け取り** (`deploy-event-workspaces.sh:79`)、
それを全 user の `deploy-user.sh` 呼び出しに verbatim で fan-out する
(`deploy-event-workspaces.sh:161-169`)。per-user のフラグ生成は存在しない。

→ **H1 の影響範囲は「踏んだ 1 名」ではなく「参加者全員」である。** 1 名が `env` を打って
Slack / 画面共有 / 隣席の会話でフラグを共有した時点で、全員の evade 3 課題が採点上無意味になる。
per-user フラグ化は H1 とは独立の改善だが、本 ADR は per-user 化に依存せず H1 を閉じる
(逆に per-user 化しても H1 は閉じない — 各参加者が自分の env を読めることは変わらない)。

### plant.sh は challenge image に焼かれている [監査 LOW]

`images/challenge/Dockerfile:47` (`COPY challenges/ /opt/ctf/missions/`) により `plant.sh` も
participant から読める。Option B 後は plant.sh に追加する `# plant-target:` 宣言 —— つまり
「どこに何が仕込まれるか」の機械可読な地図 —— も同様に読める。

**これは guided-event 方針として意図的である** (`images/challenge/Dockerfile:42-46` が
「参加者は brief / 想定解を読んでよい。競技化するならここで除外する」と明記済み)。
plant-target 宣言は「/etc/shadow に flag がある」という README で既に開示済みの情報の
機械可読版にすぎず、フラグ実値は含まない。競技化する場合は Dockerfile:45-46 の指示どおり
`README.md` / `falco-rule.yaml` / `plant.sh` / `values*.yaml` をまとめて除外する。

### 採点モデル (整合性の前提を確認)

evade 課題の solve 条件は `evaluateClean` (`internal/scoreboard/scoring/scoring.go:341-358`。
手動 submit 経路の入口は `SubmitEvade` `scoring.go:306-339`):
(1) フラグ一致 → (2) `forbiddenRules` が直近 `windowSeconds` に発火していない → (3) `requireExfil`
なら collector receipt あり。窓の実装は `internal/store/store.go:644-672` で
`cutoff = now - windowSeconds` の **sliding window** (03/05 は 10 秒:
`challenges/03-stealth-read/falco-rule.yaml:9`、10 は 30 秒 + requireExfil:
`challenges/10-final-exfil/falco-rule.yaml:13,18`)。

つまり **フラグは bearer token であり、その秘匿性のみが「課題をやった」証明**になっている。
これが H1 が致命的である理由であり、同時に第 2 の穴を露呈させる:

- **H2 (本 ADR の対象外・要 follow-up)**: `cat /etc/shadow` で騒がしくフラグを取り、
  11 秒待って submit すれば窓は clean になり solve する。H1 を閉じても H2 は残る。

H1 と H2 の非対称性 (H1 を先に閉じる根拠): H2 は forbidden rule の発火という
**永続的な痕跡** (`eventsPerUser` / rule fires、admin dashboard で観測可能) を残し、参加者側にも
「失敗した」フィードバックが出る。H1 は痕跡ゼロ・フィードバックゼロ・所要 1 コマンド。
H1 は厳密に H2 より悪い。

### 参加者が到達できる読み出し経路 (全列挙 — 監査で「漏れ無し」確認済み)

challenge コンテナ内 root として。**経路 7 は Option B が新設する面** (F5)。

| # | 経路 | 現状 | 根拠 |
|---|---|---|---|
| 1 | **shell の env** | 到達可 | ttyd は `kubectl exec` でシェルを生やす (`images/ttyd/entrypoint.sh:18-23`)。exec した新プロセスはコンテナ設定の env を継承する |
| 2 | **`/proc/1/environ`** | 到達可 | PID 1 は `sleep infinity` (`pod.yaml:147`) で、コンテナ env 付きで起動済み。**実行中コンテナの env は k8s/runtime から後から取り消せない** |
| 3 | **API 経由の Pod spec** | 到達可 | `pod.yaml:25-26` が `serviceAccountName: ttyd` + `automountServiceAccountToken: true` を Pod レベルで指定 → SA token は **challenge コンテナにも** mount される。その SA は `templates/role.yaml:12-15` で `pods get` (resourceNames: workspace) を持つ。challenge image には curl があり (`images/challenge/Dockerfile:22`)、egress NP は apiserver CIDR を許可している (`deploy-user.sh:30-36`)。よって `curl -k -H "Authorization: Bearer $(cat /var/run/secrets/.../token)" https://kubernetes.default.svc/api/v1/namespaces/ctf-<u>/pods/workspace` で env value ごと Pod spec が読める。(mission 01 の brief `challenges/01-initial-recon/README.md:22` は「curl が SA token を持たないため 401」と書くが、これは token を付けない curl の話であり、token file は実在する) |
| 4 | **運用者の画面** | 到達可 (運用者経由) | `kubectl describe pod` / `get pod -o yaml` に平文フラグが出る。2026-08-16 リハで PW 露出事故の前例あり |
| 5 | **Helm release Secret** (`sh.helm.release.v1.<user>.<n>`) | 到達不可 | values 経由でフラグが入るが `secrets get` を要し ttyd SA には無い (`role.yaml:12-19` は pods/pods-exec のみ) |
| 6 | **planted file 自体** (`/etc/shadow`, `/root/.ssh/id_rsa`) | 到達可 (**設計上意図**) | それがミッション。読むと forbidden rule が発火する (ただし 05 は例外 — 後述「限界」) |
| 7 | **seed volume の代替 path** (`/plant-seed/etc/shadow`) | **Option B が新設しうる面 (F5)** | seed root を challenge に mount すると `fd.name` が `/etc` 始まりでなくなり `sensitive_files` マクロ (`challenges/03-stealth-read/rule.yaml:1-2` の `fd.name startswith /etc and fd.name in (sensitive_file_names)`) を外れる。**mission 03 の forbidden rule を完全に回避する代替 path** ができ 03 が無条件 solve になる。現在 challenge コンテナは volumeMounts を 1 つも持たない (`pod.yaml:101-105` は ttyd のみ) ので、これは Option B が初めて開ける面である |

### 定理 (設計判断の核)

**challenge コンテナが任意の時点で読めるものは、root の参加者も読める。**
参加者は container が Running になった瞬間から `kubectl exec` できる (postStart 完了は exec の
ゲートではない) ので、「plant 後に隠す」系の対策は原理的に race である。加えて経路 2 は
race ですらなく恒久的である。
→ **フラグを challenge コンテナに一度も入れないこと以外に、H1 を閉じる方法は存在しない。**

### 【最重要】本 ADR の限界 —— mission 05 で「技法の証明」前提が成立しない

> **本 ADR は *フラグの取得元* を閉じるが、*取得手段が技法であること* は保証しない。
> 後者は forbidden rule の設計 (05 は積極条件不在) と H2 の問題である。**

security-engineer が実コードで確認した反例:

- mission 05 (`challenges/05-silent-search/falco-rule.yaml:3-4`) の forbidden rule は
  `Search Private Keys or Passwords` **1 本のみ**。
- そのルールの条件 (`challenges/04-key-search/rule.yaml:29-47`) は
  `spawned_process and ((grep_commands and private_key_or_password) or (proc.name = "find" and proc.args contains "id_rsa"...))`
  —— すなわち **`grep`/`egrep`/`fgrep` の args** (`rule.yaml:1-2` の `grep_binaries`) **か
  `find` の args** しか見ていない。
- フラグは `/root/.ssh/id_rsa` に埋め込まれる (`challenges/05-silent-search/plant.sh:4-11`)。
  **`cat /root/.ssh/id_rsa` は `proc.name=cat` なので発火しない。**
- `/root/.ssh/id_rsa` の *読み取り自体* を捉えるルールは 05 の forbidden 集合に存在しない
  (`Read sensitive file untrusted` の `sensitive_files` マクロは
  `challenges/03-stealth-read/rule.yaml:1-2` のとおり `/etc` 配下の 4 ファイル +
  `/etc/sudoers.d` `/etc/pam.d` のみ。`/root/.ssh/id_rsa` は対象外であり、そもそも 05 の
  forbiddenRules に列挙されていない)。

→ **05 のフラグは「素の `cat`」で無検知に取得でき、そのまま solve する。**
H1 を閉じても、05 について参加者の手数は `env | grep` から `cat` に変わるだけで、
**「フラグ所持 = 回避技法を実施した証明」という前提は 05 では成立しない。**

本 ADR はこれを **修正しない** (スコープ外)。理由: 05 の実効ゲート不在は *フラグの供給経路* の
問題ではなく *ルール設計* の問題であり、修正は forbidden rule の追加 (=採点難易度の変更) と
参加者 UX に踏み込むため独立の判断を要する。**別 Issue として起票する** (下記「残存リスク」)。
H1 を閉じる価値は 05 の穴があっても失われない —— 03/10 では planted file の読み取りが
実際に検知され、かつ H1 は「全課題を 1 コマンドで無効化する」唯一の経路だからである。

### 【rev.3・最重要】rev.2 の Verification 自身が deploy 経路で採点を汚す (内部矛盾)

> **rev.2 は「assert がイベントを出さないこと」(F3) を厳格に規定した一方で、
> 同じ rev.2 が本番 deploy 経路に「イベントを出す行為」を必須検査項目として書いていた。
> 前者は検証時に 1 回、後者は全 workspace・毎 deploy で必ず起きる。後者の方が重い。**

矛盾の実体 (すべて実ファイル / 実バイナリで確認):

| # | 事実 | 根拠 |
|---|---|---|
| 1 | rev.2 の Verification 2-3 は seed 初期化として「各 plant-target について append の *前* に image rootfs から素データをコピーする (`cp -a /etc/shadow /seed/etc/shadow` 等)」を **必須検査項目**にしていた | 本 ADR rev.2 §Verification 2 の 2-3 (rev.3 で撤回) |
| 2 | rev.2 の §F3 は「assert 自身が採点を汚してはならない」として `grep` / `cat` / `head` / `tail` / `awk` を禁止した。根拠は `proc.name` がどの除外リストにも無いこと | `challenges/03-stealth-read/rule.yaml:51,59,178-183` |
| 3 | **`cp` の除外は条件付きで、plant の文脈では成立しない。** `cp` は除外マクロ `cmp_cp_by_passwd` に現れるが条件は `proc.name in (cmp, cp) and proc.pname in (passwd, run-parts)` である。plant script から起動される `cp` の親は `sh` なので、`not cmp_cp_by_passwd` と `not user_read_sensitive_file_conditions` の両方を**通過する** = 発火する | `challenges/03-stealth-read/rule.yaml:98-99,122-123,184,189` |
| 4 | plant initContainer の image は **challenge と同一 image** (Option B の 1) なので、その syscall は ingest の image repo フィルタを通過する | 本 ADR §Options B-1、`internal/scoreboard/ingest/ingest.go:88-99` |
| 5 | **ingest は container 名で絞り込まない。** フィルタは (i) ns が `ctf-` 始まり、(ii) `k8s.pod.name == "workspace"`、(iii) image repo substring の 3 つだけ。initContainer は同一 Pod (`workspace`) の中で走るので 3 つすべてを満たす | `internal/scoreboard/ingest/ingest.go:77-99`。`grep -rn "container.name" internal/` と `grep -rn "ContainerName" internal/` はいずれも該当 0 件 (architect 実測) |
| 6 | user は namespace から導出される → initContainer のイベントは **その参加者に帰属する** | `internal/scoreboard/ingest/ingest.go:112` |
| 7 | `sensitive_files` は **`fd.name` ベース**の判定である (`fd.name startswith /etc and fd.name in (sensitive_file_names)`、または `fd.directory in (/etc/sudoers.d, /etc/pam.d)`)。**中身ではなくパスが効く** | `challenges/03-stealth-read/rule.yaml:1-2,90-93` |

→ **帰結: `plant` が `cp -a /etc/shadow ...` を実行した瞬間に
`Read sensitive file untrusted` が発火 → ingest 通過 →
mission 02 (`type: trigger`, `expectedRules: [Read sensitive file untrusted]`,
`challenges/02-credential-files/falco-rule.yaml:2-4`) が
**全参加者・全 deploy で submit 無しに auto-solve する。**

副作用 (どれも単独で重い):

- **02 の学習が消える。** 02 は「ルールが中身ではなく path 文字列を見ている」ことを体験させる課題で
  (`challenges/02-credential-files/README.md:22`)、それが 03 の核心の前提になっている
  (同 :23、`challenges/02-credential-files/journey.yaml:24-27` の bridge)。
  deploy 時点で CLEARED になっていると、参加者はこのミッションを一度も実行しない
- **配点が全員に無条件で入る**ので leaderboard が t=0 で歪む
- **`eventsPerUser` が全参加者で汚れる** → 本 ADR §Signposts 2
  (「evade solve が workspace 作成から 60 秒未満 かつ rule fire 0 件」) が機能しなくなる
- **ADR-0003 §Signpost 5 も機能しなくなる。** 同 signpost は「10 を auto-solve した参加者のうち
  solve 時刻より前に 10 の禁止ルールを発火させていた者の割合」で capstone gate の inert 化を測る設計だが
  (`docs/adr/0003-evade-clean-gate-attempt-scope.md:535-541`)、deploy 時の 1 発が
  **全参加者の全 solve より前に必ず入る**ので、この指標は常に 100% を返す

#### ADR-0003 との相互作用 —— 「trigger は汚染される / evade は初回 deploy では汚染されない」という非対称

VP の読み (「evade 側の taint は起きないが trigger 側の auto-solve は起きる」) は
**初回 deploy については正しい**。architect が実コードで検証した:

- `evaluateTrigger` は **attempt スコープ外**で、`current` に関係なく expectedRules 一致で solve する
  (doc「Deliberately NOT attempt-scoped」= `internal/scoreboard/scoring/scoring.go:347-352`、実装 `:360-380`)
- `markDirtyOnRuleFire` は **`current` が evade 型のときだけ** taint を書く
  (`internal/scoreboard/scoring/scoring.go:415-429`: `cur := g.currentMission(user)` の直後に
  `if !ok || ch.Type != "evade" { return nil }`)
- deploy 時点の participant は solve ゼロなので `current` = 進行順の先頭 = `01-initial-recon`
  (`scenarios/nimbusbreach-full/scenario.yaml:8-9`)。これは **trigger 型**
  (`challenges/01-initial-recon/falco-rule.yaml:2`) → **taint されない**
- 02 が auto-solve されても `current` は 01 のまま (`CurrentMission` = order 中の最初の未 solve、
  `internal/scoreboard/scoring/scoring.go:275-285`) なので、この時点で evade 側は無傷

**この非対称は直感に反する** (「イベントは出たのに evade は無傷」) ので rev.3 は明記する。
**ただし「evade は無害」は初回 deploy に限る。**

**再 deploy では evade も汚染される (rev.3 の新規指摘)**:

- 参加者が 01 を solve 済のまま workspace を再作成・再 deploy すると
  (LIVE hotfix の再デプロイ、scale-to-0 復帰で bare Pod の workspace が失われた後の再デプロイなど、
  いずれも 2026-08-16/17 に実在した運用)、その時点の `current` は **03-stealth-read (evade)** になりうる
- 03 の forbiddenRules は `Read sensitive file untrusted` (`challenges/03-stealth-read/falco-rule.yaml:3-4`)
  = seed 初期化が出すイベントそのもの → **`current` = 03 に恒久 taint が付く**
- ADR-0003 の taint は**永続**で、解除は reset のみである。
  **reset の参加者導線は main に landing 済み** (`3843d23` = app#125 / PR #128、
  `internal/scoreboard/view/templates/portal.html:1557` の reset ボタン →
  `internal/scoreboard/api/api.go:332` の `POST /api/users/{user}/challenges/{cid}/reset-dirty`)
  なので **「永久に詰む」ではない**。しかし残る害は小さくない:
  - 参加者は **自分の操作でない taint** を見せられる → 原因を説明できない (最悪の摩擦源)
  - **`requireExfil` の 10 では reset が exfil receipt も削除する** (ADR-0003 §A2-2、
    実装 `internal/store/store.go:800-832` が単一トランザクションで両方削除) →
    **flag の再配送が必要**になる
  - 運用者が問い合わせ対応コストを負う (16 名規模なら全員分)
- 同様に再 deploy 時の `current` が 10 なら capstone が taint される
  (10 の forbiddenRules に同ルールが含まれる: `challenges/10-final-exfil/falco-rule.yaml:5`)

→ **「trigger だけの問題」として扱ってはならない。deploy 経路の無汚染は trigger / evade 両方の前提である。**

### 制約 (壊してはいけないもの)

- C1: 「1 workspace = 全ミッションセット」の参加者体験を維持する
- C2: 採点側 `FLAGS_FILE` と仕込み側 `CTF_FLAG_*` は platform の同一 `flags.sops.yaml` から
  render され必ず一致する (conventions §フラグ注入, `.claude/rules/falco-ctf-app-conventions.md:203-215`)
- C3: `challenges/<NN>/plant.sh` が唯一の正典。フラグ実値を書かない
- C4: `values.yaml` / `values-all.yaml` は `make gen-values` 生成物 (手書き禁止)
- C5: I5 (イメージ数)・I7 (chart default は環境非依存)・I9 (challenge に Service/Ingress を足さない)・I10
- C6: `deploy-user.sh --challenges-dir` / `--flags-file` は platform が呼ぶクロスリポ契約
- C7: egress lockdown (P11.5) と ttyd の `kubectl exec` 経路
- **C8 (rev.2 追加)**: 既存 mission の想定解を壊さない —— 特に mission 02 (trigger,
  `Read sensitive file untrusted`)・03 (evade)・**09 (trigger, `Create Hardlink Over Sensitive Files`)**・
  05 (evade)。09 は plant-target と同じ `/etc/shadow` を hardlink するため Option B の
  mount 方式に直接依存する (F4、下記 Options)

## Options

### Option A — postStart で plant した後に env を落とす

変更点: plant 実行後にシェルの env から `CTF_FLAG_*` を除去する (profile での unset 等)。

- コスト: ほぼゼロ (数行)
- リスクと可逆性: 可逆。ただし **閉じない**:
  経路 2 (`/proc/1/environ`) は取り消し不能 (実行中コンテナの env は変更 API が無い)、
  経路 3 (API で Pod spec) は無関係に生き残る、`kubectl exec -- env` は login profile を通らない。
  実効は「`env | grep` → `tr '\0' '\n' </proc/1/environ | grep` の 1 コマンド差」。
  さらに「閉じた」という誤った安心感を残すため、**軽減ではなく有害**と判定する。
- 効き始める閾値: 無し (どの規模でも閉じない)

→ **却下。** 完全に閉じないどころか、脅威モデルを誤認させる。

### Option B — plant を initContainer に出し、flags を Secret 経由で initContainer だけに渡す (推奨)

変更点:

1. 新 initContainer `plant` を workspace Pod に追加。image は **challenge と同一 image**
   (I5 のイメージ数に影響なし。fixture / `/etc` の素データが必要なので同一 image が正しい)。
2. フラグは chart が render する Secret (`ctf-flags`, ns `ctf-<user>`) に入れ、`plant` は
   `secretKeyRef` / `envFrom` で受ける。→ Pod spec には **secret 名しか出ない**。
3. `plant` は emptyDir `plant-seed` に仕込み済みアーティファクトを書く。challenge コンテナは
   それを各ミッションの実パスへ mount する (**mount 方式は下記 B1/B2 の派生決定**)。
4. Pod レベル `automountServiceAccountToken: false` にし、SA token は `projected` volume として
   **ttyd コンテナにのみ** mount する (`serviceAccountToken` + `kube-root-ca.crt` +
   namespace fieldRef の標準 3 点。`images/ttyd/entrypoint.sh:16-17` が期待する
   `/var/run/secrets/kubernetes.io/serviceaccount/` パスに置くので kubectl の in-cluster 検出は不変)。
5. `challenge.postStart` はフラグ仕込み用途から退役 (現状 flag 以外の用途は無い)。
6. plant.sh は正典のまま (C3)。ただし **仕込み先パスを機械可読に宣言する** ヘッダ行
   (例 `# plant-target: /etc/shadow`) を持ち、`gen-values.sh` が seed script と chart 側の
   mount リストの両方を生成する (C4 の生成物規律をそのまま拡張)。**同一 plant-target を
   複数の plant.sh が共有する** (03 と 10 はいずれも `/etc/shadow` へ append:
   `challenges/03-stealth-read/plant.sh:4`・`challenges/10-final-exfil/plant.sh:6`) ため、
   mount リスト生成は **dedupe が必須**、seed 側は **素データを先に置いてから sort 順に append する
   初期化ステップ**が必須 (F6、下記 Verification 2)。
   **【rev.3】その素データの供給元は「image build 時に非 sensitive path へ焼いた snapshot」でなければならない
   (派生決定 (3) = S-a)。実行時に実 `/etc/shadow` を読む形 (rev.2 の書き方) は採点を汚すので採らない。**
7. **seed root を challenge に mount しない** (F5)。challenge の seed 参照は宣言済み
   plant-target に対応する mount のみ。

閉じるか (最重要評価軸):

| 経路 | 閉じるか | 理由 |
|---|---|---|
| 1 shell env | ✅ | challenge の env は allowlist の 5 変数のみ (Verification 1) |
| 2 `/proc/1/environ` | ✅ | PID 1 がフラグ env 無しで起動する |
| 3 API で Pod spec | ✅✅ | 二重: (a) challenge に SA token が無い、(b) Pod spec に値が無い (secret 名のみ) |
| 4 `kubectl describe` (運用者画面) | ✅ | secret 名のみ表示 |
| 5 Helm release Secret | ✅ (現状維持) | 参加者からは到達不可のまま |
| 6 planted file 自体 | ❌ (設計上意図) | それがミッション。残る近道は H1 ではなく H2 (05 は「限界」節参照) |
| 7 seed volume の代替 path | ✅ (**要 assert**) | I12 + Verification 1 が seed root mount と未宣言 mountPath を機械的に禁止する。**assert が無ければ閉じない** |

- コスト: chart +40 行程度 / plant.sh 3 本の書き換え (seed dir 前提へ) / `gen-values.sh` 拡張
  (dedupe + seed 初期化 + `--check`) / README・docs-site の env 変数名記述の削除
  (`challenges/03-stealth-read/README.md:12-15` 他 2 本、`docs-site/docs/missions/{03,05,10}*.md`) /
  検証スクリプト 2 本 (`scripts/check-flag-isolation.sh`,
  `charts/ctf-user/assert-flag-isolation.sh`) / platform 側 roster script の exit status 伝播 /
  リハで mission 02/03/05/09/10 と ttyd exec の再検証。
  認知コスト: 「plant は別コンテナで動き、成果物を volume で渡す」という一段の間接。
  イメージサイズ: 増加ゼロ (同一 image)。依存: 増加ゼロ。
- リスクと可逆性: **クロスリポ *引数* 契約の変更なし** (`deploy-user.sh` の引数・env 名は不変 → C6 を満たす)。
  ただし **`deploy-user.sh` の非ゼロ exit を fail-closed 契約として明文化し、platform 側が
  伝播する**必要がある (F2、下記 Verification 3) → **platform 側 PR が必要** (両リポ同時 PR)。
  chart 変更自体の revert は 1 commit。
  主要リスクは (i) `subPath` single-file bind の挙動 (mount 前にファイルが存在しないと kubelet が
  空ファイル/dir を作る → initContainer が必ず書くので満たす)、
  (ii) bind mount 化した `/etc/shadow` に対し Falco の `Read sensitive file untrusted` が
  同じく発火するか (rule は `fd.name` ベースなので発火する見込み。**リハで実測必須**)、
  (iii) **mission 09 の `link()` が EXDEV で失敗する見込み** (F4、下記派生決定)。
  mount の改竄耐性: 参加者は root だが `CAP_SYS_ADMIN` を持たない (default capability set) ので
  `umount` できない。加えて `pod.yaml:37-38` の RuntimeDefault seccomp が `mount`/`umount2` を
  落とし二重化する (`make check-seccomp` / `scripts/check-seccomp.py` が機械強制、CI `chart-lint`)。
- 効き始める閾値: **次イベントの参加者 1 人目が `env` と打った瞬間**。前回リハは 16 名で、
  フラグは全員同一値 (上記「影響範囲」) なので 1 人で全員分が漏れる。

#### Option B の派生決定 (1): seed delivery 方式 — B1 / B2 / B3

`plant` が書いた seed をどう challenge の実パスに見せるか。**F5 と F4 がこの選択を支配する。**

- **B1 — plant-target 単位の `subPath` bind** (`/etc/shadow` は単一ファイル bind、
  `/root/.ssh` はディレクトリ mount)。
  - 変更点: `volumeMounts` に plant-target ごとに 1 エントリ (`subPath` 付き)。
  - コスト: 最小 (chart 数行)。blast radius も最小 (image の `/etc` は素のまま)。
  - F5: **安全** —— mount point が実パスと一致するので代替 path が生まれない。
  - リスク: **mission 09 が壊れる見込み**。`/etc/shadow` が emptyDir 由来の bind mount、
    `/tmp` が container overlay になり別 mount → `link()` は `do_linkat` の
    `old_path.mnt != new_path.mnt` 判定で **EXDEV** を返す。想定解
    (`challenges/09-hidden-cache/README.md:16`) と確認手順 (同 :18 「リンク数 2」) が
    どちらも不成立。**Falco が失敗した `link()` でも発火するかは不明** ——
    `create_hardlink` マクロの定義は表示用抜粋に含まれていない
    (`challenges/09-hidden-cache/rule.yaml` は 14 行で list と rule のみ) ので、
    `evt.res` 述語の有無は **デプロイ済み ruleset から実測**する必要がある。
    なお EXDEV は「/etc 側が bind mount である」ことに起因するので、**B2 でも
    `/tmp` を target にする限り解消しない**。
  - 可逆性: 高 (mount 定義の差し替えのみ)。
  - 効き始める閾値: mission 09 を出題する全イベント (= 現行の全イベント)。
- **B2 — plant-target のディレクトリ全体を emptyDir にし、`plant` が build 時 snapshot から `cp -a` する**
  (`/etc` 全体を emptyDir で覆い、`plant` が `cp -a /opt/ctf/plant-seed/etc/. /seed/etc/` した後に append。
  **rev.3 訂正: rev.2 は `cp -a /etc/. /seed/etc/` と書いていたが、これは実 `/etc/shadow` を読むので
  §F3′ 違反 = 採点を汚す。build 時 snapshot 経由 (S-a) に置き換える。**)
  - 変更点: mount 単位がファイルからディレクトリへ。`plant` に snapshot コピー段が入る。
    image 側に `RUN cp -a /etc /opt/ctf/plant-seed/etc` 相当が入る (S-a)。
  - コスト: 中。`/etc` を覆うため image の `/etc` 変更が seed 初期化に暗黙依存する。
  - F5: **安全** (mount point = `/etc` = 実パス。代替 path なし)。
  - **利点**: `/etc` 内が単一 mount になるので **`/etc` 内での `link()` が成立する** ——
    09 の想定解を `ln /etc/shadow /etc/.cache.bak` に変えれば動く
    (Falco 側は `evt.arg.oldpath in (sensitive_file_names)` のみを見るので newpath 変更は無害:
    `challenges/09-hidden-cache/rule.yaml:9-11`)。
  - リスク: kubelet は `/etc/hosts` と `/etc/resolv.conf` を個別のファイル bind mount として
    重ねる。volume mount された `/etc` の上にこれらが乗る挙動は **実測必須** (仮説: 動く)。
    加えて `cp -a` の permission/ownership 保持と `/etc/shadow` の 0640 維持を要確認。
  - 可逆性: 中 (B1 へ戻すのは mount 定義 + plant 初期化の巻き戻し)。
  - 効き始める閾値: 09 を `/tmp` 以外へ retarget できない場合、または将来 planted file に
    同一 fs 操作 (hardlink / rename) を要求する mission が出た場合。
- **B3 — seed root (`/plant-seed`) を challenge に mount し、challenge 側でコピーする**
  - **選択肢ではない (提案しない)。** 経路 7 をそのまま開き、mission 03 の forbidden rule を
    完全に回避する代替 path (`/plant-seed/etc/shadow`) を作る = 03 が無条件 solve になる。
    I12 に正面から違反する。**記録のためだけに列挙する。**

#### Option B の派生決定 (2): mission 09 の救済 — 09-i / 09-ii / 09-iii

**どの mount 方式でも `/etc/shadow` → `/tmp` の cross-mount hardlink は成立しない。**
したがって 09 は *mission content* 側で救済する。実装 PR は **EXDEV 実測の結果でどれかを選ぶ**
(VP 裁定: 実測は完了条件)。

- **09-i — link 先を seed mount 内に移す** (`ln /etc/shadow /etc/.cache.bak`)。**B2 が前提。**
  コスト: README / journey.yaml / docs-site の想定解と確認手順を書き換え。
  リスク: B2 のリスク (kubelet の `/etc/hosts` 重ね) を引き受ける。可逆性: 高 (content のみ)。
- **09-ii — link 元を *planted でない* sensitive file に retarget する** (`ln /etc/sudoers /tmp/.cache.bak`)。
  **B1 で成立する** —— `/etc/sudoers` は `sensitive_file_names`
  (`challenges/09-hidden-cache/rule.yaml:2`) に含まれるがフラグの仕込み先ではないので
  bind mount されず、`/tmp` と同じ container overlay 上に残る → `link()` 成功・リンク数 2 成立・
  `evt.arg.oldpath=/etc/sudoers` で発火。
  **前提**: alpine base の challenge image に `/etc/sudoers` は存在しない (sudo 未導入:
  `images/challenge/Dockerfile:18-34` のパッケージ一覧に sudo が無い) → **fixture として
  ダミー `/etc/sudoers` を image に追加する必要がある** (数行、CTF realism としても自然)。
  コスト: 最小 (image 1 行 + README 1 行)。可逆性: 高。**B1 を維持できるので推奨候補。**
- **09-iii — 09 の破壊を受容する** —— **却下。** 09 は trigger 型 (`falco-rule.yaml:2-4`) なので
  参加者は発火しない原因を診断できず「壊れている」としか見えない。C8 違反。

#### Option B の派生決定 (3): seed 初期化の供給元 —— S-a / S-b / S-c / S-d / S-e 【rev.3 で新設】

**問題**: seed は emptyDir なので空で始まる。現行 plant.sh は `>>` 前提で
「素の `/etc/shadow` が既に存在する」ことを暗黙に仮定している
(`challenges/03-stealth-read/plant.sh:4`・`challenges/10-final-exfil/plant.sh:6`、
生成物 `challenges/values-all.yaml:16,37`)。初期化なしでは `/etc/shadow` が
**フラグ 2 行だけのファイル**になり、mission 02 のブリーフ
(「パスワードハッシュの実体ファイル」= `challenges/02-credential-files/journey.yaml:8,13`) と噛み合わない。
一方で **実行時に実 `/etc/shadow` を読むと採点が汚れる** (上記 Context の内部矛盾)。
この 2 つを同時に満たす層はどこか。

**rev.2 の根拠の再評価 (VP 指示)**: 2-3 の根拠は「realism と `sensitive_files` 判定の文脈」だった。
このうち **`sensitive_files` 判定は `fd.name` ベース**なので
(`challenges/03-stealth-read/rule.yaml:1-2,90-93`) **中身に一切依存しない** ——
`/etc/shadow` という path に bind mount されていれば、中身が何であれ 02/03/10 の判定は成立する。
残るのは **realism だけ**であり、realism は「素データが *存在すること*」を要求するが
**「実行時に実ファイルから読むこと」は要求しない**。
→ **2-3 の要件のうち「初期化が存在すること」は維持し、「image rootfs から実行時コピーすること」は撤回する。**

**実測 (architect, 2026-08-18)**: challenge image のパッケージ集合
(`images/challenge/Dockerfile:18-34`) を alpine:3.22 (digest pin 同一) に適用した状態で
`/etc/shadow` は **0640 root:shadow / 260 bytes / 17 行、すべて locked (`*` または `!`)、
crypt ハッシュ形の文字列は 0 件**。`/root/.ssh` は **存在しない** (`/root` は 0700 で空) ため、
**素データを要するのは `/etc/shadow` ただ 1 つ**である
(05 の plant は `mkdir -p` + `cat >` で新規作成する: `challenges/05-silent-search/plant.sh:4-11`)。

- **S-a — image build 時に素データを非 sensitive path へ snapshot する 【推奨】**
  - 変更点: `images/challenge/Dockerfile` に `RUN mkdir -p /opt/ctf/plant-seed/etc && cp -a /etc/shadow /opt/ctf/plant-seed/etc/shadow`
    (B2 に切替える場合は `/etc` 全体)。生成 seed script は **`/opt/ctf/plant-seed/...` からのみ**コピーする。
  - 犠牲にするもの: image に 1 ステップ増える。plant-target は「build 時に snapshot 可能なもの」に限られる
    (プロセス状態や実行時にしか存在しないファイルは対象にできない → Signpost 8)。
  - コスト: Dockerfile 2 行 + `gen-values.sh` の生成テンプレ 1 箇所。イメージサイズ +260 bytes。
    依存増加ゼロ。イメージ数不変 (I5 に触れない)。認知コスト: 「seed の素データは image に焼いてある」1 文。
  - **イベント数: 構造的にゼロ。** 実行時に読むのは `/opt/ctf/plant-seed/...` であり、
    `sensitive_files` の **2 つの選択肢のどちらにも当たらない** ——
    (i) `fd.name startswith /etc and fd.name in (sensitive_file_names)` は path prefix で外れ、
    (ii) `fd.directory in (/etc/sudoers.d, /etc/pam.d)` も外れる
    (`challenges/03-stealth-read/rule.yaml:90-93`)。
    **「除外されるから発火しない」ではなく「ルールの条件に到達しない」**のが S-a の性質である。
  - **I10 に触れないか (VP 指示による明示的検討)**: **触れない。**
    (i) 焼くのは **フラグ実値ではなく素の `/etc/shadow`** であり、
    (ii) それは **同一イメージ内に既に存在するビットの複製**である (build 時に image 自身から derive する) ので
    **新規のマテリアルを一切導入しない** —— I10 が禁じる「トークン・実シークレットの焼き込み」に当たらない。
    (iii) 実測どおり中身は locked エントリのみで crypt ハッシュを含まない。
    (iv) それでも「将来 image に本物のハッシュが入る」ことを紙で保証しないため、
    **機械検査を付ける** (Verification 2-8: snapshot と `/etc/shadow` の双方に crypt ハッシュ形と `FALCO{` が
    現れないことを image build job で確認する) —— この検査は S-a が無くても価値がある I10 の実強制である。
  - **経路 7 (F5) を新設しないか**: しない。snapshot は **flag を含まない** (flag は実行時に seed 側へ append される)。
    したがって `/opt/ctf/plant-seed/etc/shadow` を読んでも **フラグは得られず**、
    mission 03 の代替 path にならない。participant は root なのでこの path を読めるが、
    読めても得るものが無い (guided-event 方針として `challenges/` 丸ごと焼いているのと同じ性質)。
  - リスクと可逆性: 可逆 (Dockerfile 2 行 + 生成テンプレの revert)。
    リスクは **snapshot と image の実 `/etc` の drift** —— ただし build 時に derive するので
    パッケージ追加でユーザが増えれば snapshot も追随する (drift は原理的に起きない)。
    B2 に切替えても手法が変わらない (派生決定 (1) と直交)。
  - 効き始める閾値: **最初の 1 deploy から**。deploy 経路は毎回走るので猶予が無い。
- **S-b — builtin-only コピー (実行時に shell builtin で読む)**
  - 変更点: 生成 seed script が `while read -r l; do ...; done </etc/shadow > /seed/etc/shadow` 形で複製する。
  - **成立はする**: `proc.name=sh` は `shell_binaries` に含まれ (`challenges/03-stealth-read/rule.yaml:59`)
    ルールの除外節 (同 :178-183) に該当するため `Read sensitive file untrusted` は発火しない。
    §F3 の assert 側と同じ理屈である。
  - 犠牲にするもの: **メタデータとバイト忠実性**。`while read` は行志向なので
    (i) permission / ownership を保存しない (実測どおり `/etc/shadow` は **0640 root:shadow** であり、
    本 ADR の B2 節が要求する 0640 維持のために `chmod` + `chgrp` を別途書く必要がある)、
    (ii) 末尾改行の有無・バックスラッシュ・NUL を保存しない、
    (iii) 将来 plant-target がバイナリ / symlink / sparse になった瞬間に壊れる。
  - コスト: 生成テンプレが per-target の metadata 復元コードを持つ = 生成物の複雑度が上がる。
    さらに **静的検査が難しい** —— builtin での read は「何を読んだか」が script の構文解析でしか分からず、
    Verification 2-7 (禁じ手の静的走査) の精度が落ちる。
  - リスクと可逆性: 可逆。リスクは「除外リストに依存している」こと ——
    `shell_binaries` からの除外は **Falco 側の ruleset に依存する外部前提**であり、
    Falco 版 bump で除外節が変われば無言で発火側に倒れる (S-a の「条件に到達しない」より弱い)。
  - 効き始める閾値: plant-target が 2 種類目のメタデータ (ownership / mode / symlink) を要求した時点で破綻する。
- **S-c — plant initContainer の image を challenge と分ける**
  - 変更点: `falco-ctf/plant` を新設し、ingest の image repo フィルタ
    (`internal/scoreboard/ingest/ingest.go:95`) に一致しないことでイベントを落とす。
  - 犠牲にするもの: **I5 のイメージ数 8 → 9 (CEO 批准が必要)**、および
    **plant image と challenge image の `/etc` 一致**という新しい暗黙依存
    (素データは challenge image のものでなければ realism が崩れる)。
  - コスト: 新 Dockerfile + build/push/scan/digest-pin の 1 系統追加。CI の `build (<image>)` matrix +1。
    S-a を併用しないなら「plant image の `/etc/shadow` を読む」ので **イベントは Falco 側では発火し続ける**
    (落とすのは ingest だけ) → Falco / Sysdig 側の event stream は汚れたままになる。
  - リスクと可逆性: 中程度に不可逆 (イメージ契約 = Cross-repo 契約表と platform 側 pin に波及)。
    さらに **命名で壊れる** —— 例えば `falco-ctf/challenge-plant` と命名すると substring `falco-ctf/challenge` に
    一致してフィルタが効かなくなる。**採点の正しさを image 名の綴りに依存させる**のは境界として悪い。
  - 効き始める閾値: 「plant が challenge image のツール群を必要としなくなった」場合のみ検討に値する。
  - → **採らない。** S-a はイメージ数も ingest も触らずに同じ結果 (イベント 0) を得る。
- **S-d — ingest 側で initContainer を除外する**
  - 変更点: webhook payload に container 名 (`k8s.container.name` / `container.name`) を持たせ、
    ingest が `challenge` 以外を捨てる。
  - 犠牲にするもの: **採点の入口を緩める** (security-engineer 同意権の領域)。加えて
    **クロスリポ契約の変更** (`docs/openapi-scoreboard.yaml` の FalcoEvent output_fields と
    platform 側 falcosidekick 設定 → 両リポ同時 PR)。
  - コスト: spec + 実装 + platform 側の field 供給確認。
  - リスクと可逆性: 可逆。偽陰性の評価: フィールド欠落時に「除外しない」側へ倒せば
    **fail-closed (採点する側)** に保てるので偽陰性は作らない。participant は challenge コンテナにいるため
    自分のイベントの `container.name` を偽装できない (Falco が runtime から取る)。
    しかし **構造的な問題は「deploy 経路が騒がしくてよい」ことを許す**点にある ——
    今回の欠陥は「ingest が拾ってしまった」ことではなく「deploy 経路がイベントを出した」ことなので、
    S-d は症状を隠す。将来 plant が別の禁じ手を踏んでも観測されなくなる。
  - 効き始める閾値: **「workspace Pod 内で challenge 以外のコンテナが定常的に syscall を出す」構成に
    なったとき** (例: sidecar が増える)。そのときは S-a と併せて **defense-in-depth として採る価値がある**。
  - → **本 ADR では採らない (推奨に含めない)。** ただし follow-up として起票する価値はあり、
    採るなら **security-engineer 同意 + fail-closed 既定 + spec 追記**が条件 (下記 Consequences)。
- **S-e — Falco ルール側の除外を足す**
  - 変更点: `Read sensitive file untrusted` の除外に plant の文脈を追加する。
  - 犠牲にするもの: **採点そのもの。** 除外は participant にも等しく効くので、
    **同じ条件を満たせば participant も 02/03 の判定を回避できる**。しかも `rule.yaml` は
    docs サイトが参加者に描画する表示用抜粋である (`.claude/rules/falco-ctf-app-conventions.md` §課題ドキュメント用 rule.yaml)
    ので、除外条件は**参加者に開示された近道**になる。
  - リスクと可逆性: 可逆だが、入れた版で走ったイベントの採点結果は取り返せない。
  - → **却下。採点の穴を作る案は選択肢ではない。**

**推奨: S-a。** 「実行時に sensitive path を読まない」ので **除外リストにも ingest フィルタにも依存せず、
条件そのものに到達しない**。イメージ数 (I5)・ingest・Falco ルール・`deploy-user.sh` の契約 (C6) を
いずれも触らず、静的検査 (Verification 2-7) で機械強制できる。

## Decision

**Option B を採用する** — H1 を完全に閉じる方法は「フラグを challenge コンテナに一度も入れない」
以外に存在せず (上記「定理」)、Option B はクロスリポの *引数* 契約を変えずに chart 内でそれを実現する唯一の案。

派生決定は以下のとおり **既定 + 実測による切替**とする:

- seed delivery = **B1 (`subPath` bind) を既定**とする。F5 に対して最小面であり、
  image の `/etc` に暗黙依存しないため。
- **seed 初期化の供給元 = S-a (image build 時に `/opt/ctf/plant-seed/` へ焼いた snapshot) を採る (rev.3)。**
  実行時に sensitive path を read しないことで **deploy 経路のイベントを構造的にゼロにする**。
  B1 / B2 のどちらに切り替えても手法は変わらない (派生決定 (1) と直交)。
- mission 09 = **09-ii (`/etc/sudoers` fixture へ retarget) を既定**とする。B1 を維持でき、
  変更が image 1 行 + README 1 行で済み、Falco ルール側の変更が不要だから。
- **実測が既定を否定した場合の切替先**: (a) `/etc/sudoers` retarget で発火しない、または
  (b) `subPath` bind 化で mission 02/03 が発火しない → **B2 + 09-i** に切替える。
  切替の判断は実装 PR 内で行い、結果を本 ADR に追記する (supersede ではなく追記で足る)。

## Consequences

### 諦めたもの

- plant.sh の実行文脈の単純さ。今後 plant は「対象コンテナの rootfs に直接書く」のではなく
  「seed dir に書き、chart が mount する」。**新しいミッションを書くとき、仕込み先が
  bind mount 可能なパスであることが制約になる**。プロセス状態や多数の rootfs 位置に
  跨る仕込みが必要なミッションはこのモデルに乗らない (その時は Signpost 4 を参照)。
- **planted file に対する同一ファイルシステム操作** (hardlink / rename / `mv` を跨ぐ mission)。
  09 がその第 1 例であり、mission content 側で回避する (09-ii)。**これは今後 mission を
  書くときの明示的な制約として `challenge-author` に伝える。**
- `postStart` によるフラグ仕込み。`.claude/agents/challenge-author.md:48-54` の
  challenge 作者向け手順も更新が必要。
- **【rev.3】deploy 経路の記述自由度。** plant / seed 初期化は
  **「Falco イベントを 1 件も出さない」制約下でしか書けない** (§F3′)。具体的には
  素データは build 時 snapshot からのみ供給し (S-a)、plant-target は
  **build 時に snapshot 可能なもの**に限られる (プロセス状態・実行時生成物は乗らない → Signpost 8)。
  **これも `challenge-author` に伝える明示的な制約である** (DoD 10)。

### 新たに守る不変条件 (提案: I12) —— 性質ベース

> **I12**: workspace Pod の `challenge` コンテナには、**フラグ実値を到達させる経路を一切設けない**。
> 「経路」には env / `envFrom` / volume (`volumeMount`) / **seed root の mount** /
> ServiceAccount token を **含むが、これらに限らない**。
> evade フラグの仕込みは `plant` initContainer + emptyDir seed 経由のみ。
> challenge 側の seed 参照は **宣言済み `# plant-target:` に対応する mount だけ**とし、
> **seed volume の root mount を禁止**する (禁止理由: `fd.name` が `/etc` 始まりでなくなり
> mission 03 の forbidden rule を回避する代替 path になる)。
> SA token は ttyd コンテナ限定の projected volume で供給する。
> **機械強制**: `make check-flag-isolation` / `scripts/check-flag-isolation.sh` (静的、CI `chart-lint`)
> \+ `charts/ctf-user/assert-flag-isolation.sh` (実機、`deploy-user.sh` から fail-closed 呼び出し)。

**列挙は例示であり定義ではない** (F1)。名前ベースの列挙 assert は迂回される ——
たとえば challenge に `envFrom: {secretRef: {name: ctf-flags}}` を付けると env 名が manifest に
一切現れないまま全フラグが注入され、`^CTF_FLAG_` を探す assert を素通りする。
したがって assert は **allowlist 型** (既知集合以外を全部落とす) でなければならない (Verification 1)。

#### I12 の発効条件 (VP 裁定 2026-08-18)

**I12 は「F1 (allowlist 型 static assert) + F2 (deploy 時 fail-closed 実機 assert) の
実装をもって発効」する。ADR merge と同時発効にはしない。**
根拠: ORGANIZATION.md:326 「`Verification` が「無し」の ADR は Hard Invariant に昇格させない」
の趣旨 —— 検証機構より先にルールだけ表に載せると、「閉じたつもりで閉じていない」を
Hard Invariants 表そのものが再生産する。

Hard Invariants 表 (`.claude/rules/falco-ctf-app-conventions.md` §Hard Invariants) への追記は
実装 PR で行い、**`seccompProfile` 節が `make check-seccomp` を明記しているのと同じ粒度で
上記 2 スクリプト名を併記**する。I12 の新設は architect 合意 + VP 承認事項 (意思決定マトリクス)。

#### 不変条件の番号 (rev.3 で改番) —— ADR-0003 との衝突解消

rev.2 は本 ADR の不変条件を **I11** と呼んでいたが、**ADR-0003 (Status: Accepted) も
別の性質を I11 候補として主張している** (attempt スコープ =
`docs/adr/0003-evade-clean-gate-attempt-scope.md:475-483`)。現行の
`.claude/rules/falco-ctf-app-conventions.md` §Hard Invariants は **I1-I10 まで**しか無いので、
両方が先着順に I11 を取ると **同じ番号で違うルールが 2 つ**表に載る。

**architect 判定: 本 ADR の番号を I12 に譲る。**

| 番号 | 性質 | 出典 ADR | 状態 |
|---|---|---|---|
| I11 | evade の clean 判定は attempt スコープで評価する | ADR-0003 | **Accepted**。昇格条件 = Verification (a)+(b)+(e) の landing |
| **I12** | challenge コンテナにフラグ実値の到達経路を設けない | 本 ADR | Proposed。昇格条件 = F1 + F2 の実装 |
| **I13** | deploy 経路 (plant / seed 初期化) は Falco イベントを 1 件も出さない | 本 ADR (rev.3) | Proposed。昇格条件 = 下記 |

根拠: ADR-0003 は既に Accepted かつ実装 PR が main に merge済 (`6701f3b` / `3843d23` / `c06e7ff`) で
**昇格条件が本 ADR より先に揃う**ため。**この割り当ては VP 批准を要する** (どちらに I11 を割るかは
本 ADR 単独では決められない。ただし「両方 I11」は選択肢ではない)。

### 新たに守る不変条件 (提案: I13) —— deploy 経路の無汚染 【rev.3 で新設】

> **I13**: **workspace の deploy 経路 (`plant` initContainer / seed 初期化 / 運用 assert) は、
> Falco イベントを 1 件も発生させてはならない。**
> 「window の外だから安全」は根拠にならない —— `eventsPerUser` と rule fire 履歴は永続し、
> trigger 課題の auto-solve は attempt スコープ外である
> (`internal/scoreboard/scoring/scoring.go:347-352`)。
> 要件は**イベント数ゼロ**であり、手段は文脈で異なる (assert = builtin-only /
> deploy = §F3′ の禁じ手表を踏まない)。
> **機械強制**: `challenges/gen-values.sh --check` の静的走査 (Verification 2-7) +
> `charts/ctf-user/assert-flag-isolation.sh` の自己 grep (Verification 3) +
> **E2E の deploy 直後観測 (Verification layer 4)**。

**I13 の発効条件**: Verification 2-7 と layer 4 の両方が landing すること
(I12 と同じ理由: 検証機構より先に紙のルールを増やさない)。

**なぜ I12 と分けるのか**: I12 は「フラグ実値の到達経路」、I13 は「deploy 経路のイベント数」で
**別の性質・別の検証手段**である。1 つの不変条件に束ねると、どちらかが破れたときに
「I12 は満たしている」と言えてしまう (rev.2 が実際にそうなっていた —— フラグ隔離は満たすが
採点は汚す設計が「I12 準拠」として書かれていた)。

### 新たなクロスリポ契約の明文化 (F2)

`deploy-user.sh` の **非ゼロ exit は fail-closed 契約**であり、呼び出し側は必ず伝播する。
現状 `deploy-event-workspaces.sh:161-170` は各 workspace の deploy をバックグラウンドで起動し
(`"$DEPLOY" ... &`)、bare `wait` で回収するため **個々の exit status を破棄している**
(bash の引数無し `wait` は待機したジョブの失敗を戻さない)。
→ **isolation assert を deploy-user.sh に入れても、roster 経路では今のところ silently swallow される。**
実装 PR は roster script 側で exit status を収集し、1 件でも失敗したら
`✓ done` を出さずに非ゼロ終了することを含める。これを Cross-repo 契約表に 1 行追記する。

### 残存リスク (正直に記録)

- **H2 (sliding window の待ち抜け) は閉じない。** H1 を閉じても採点真正性は完全には回復しない。
  H2 は独立の設計判断 (窓を monotonic dirty flag にする / evade に `expectedRules` で
  技法の積極的証明を要求する / workspace reset で再挑戦させる) を要し、参加者 UX に影響するため
  **別 ADR + CEO 判断**とする。本 ADR ではスコープ外と明記する。
- **mission 05 の実効ゲートが存在しない** (上記「限界」)。`cat /root/.ssh/id_rsa` は
  どの forbidden rule にも当たらない。**別 Issue として起票する** (ADR-0001 のスコープ外)。
  H2 と同じ「forbidden rule 設計」クラスの問題なので、H2 の ADR と束ねる余地がある。
- **フラグが全参加者で同一値** (`deploy-event-workspaces.sh:79,161-169`)。H1 を閉じた後も、
  1 名が planted file を読んで得たフラグを共有すれば全員が submit できる。
  per-user フラグ化は独立の改善であり本 ADR のスコープ外。
- `ctf-flags` Secret と Helm release Secret は ns 内 `secrets get` を持つ主体には読める
  (現状 cluster-admin のみ)。ctf-user の Role を今後広げる際は I12 と衝突しないか確認する。
- 運用者マシン上では `--set-string challenge.flags.*` が helm の argv に載る (現状も同じ)。
  shell history / `ps` 経由の露出は本 ADR では変えない。
- **【rev.3】再 deploy 時の taint リスクは S-a で消えるが、経路自体は残る。**
  deploy 経路が将来また禁じ手を踏んだ場合、進行中の participant の `current` が evade なら
  **恒久 taint** になる。reset 導線は main に landing 済み (`3843d23`) なので復旧は可能だが、
  **参加者は自分の操作でない taint の原因を説明できず**、`requireExfil` の 10 では
  **flag の再配送**まで要求される (ADR-0003 §A2-2)。
  I13 + Verification 2-7 / layer 4 がその再発を機械で止める唯一の層である。
- **【rev.3】S-d (ingest 側で initContainer を除外) を採用しない残余。**
  workspace Pod 内に challenge 以外のコンテナが増える構成 (sidecar 追加など) では、
  deploy 経路以外からも「参加者に帰属するが参加者の操作でないイベント」が入りうる。
  現状 workspace Pod は ttyd / ttyd-proxy / challenge の 3 コンテナで、
  前 2 者は challenge image ではないため ingest の image フィルタで落ちる
  (`internal/scoreboard/ingest/ingest.go:95`)。**この防御は image 名の綴りに依存している**ので、
  Signpost 7 を観測したら S-d (container 名フィルタ + spec 追記 + security-engineer 同意) を起票する。
- **CI assert は「本番に適用される manifest」を保証しない** (F2 の構造的残余)。CI-free prod 方針
  (charts = local clone、`project_ci_free_prod`) では chart の main が本番に届く保証は無い。
  監査が指摘した乖離 checkout (`falco-ctf-app-prodlocal/`) は CEO 決定で削除済み・LIVE hotfix は
  `origin/archive/live-hotfix-2026-08-16` に退避し内容は main の後続作業 (P19-2b / P22-1) で
  置換済みと VP が確認したが、**「local clone が main と一致している」ことを機械保証する仕組みは無い**。
  だから layer 3 (実機 assert) が必要であり、layer 1 の代替にはならない。

### runbook への影響

- platform 側の deploy *引数* は不変。ただし:
  - **`deploy-event-workspaces.sh` に post-deploy assert の集約と exit status 伝播を追加**
    (fail-closed。1 件でも violation があれば roster deploy を abort)。owner = sre-engineer。
  - **人手の preflight ステップは追加しない** (F2)。人手手順は「やらなかった」が観測できないため
    layer にならない。機械 assert が唯一の layer 3 とする。
- **assert *と deploy 経路の両方* が「Falco イベントを 1 件も発生させない」ことが要件**
  (§F3′、下記 Verification 3 / 2-7 / layer 4)。runbook には
  「検証コマンドも plant/seed script も思いつきで足さない。追加は §F3′ の禁じ手表と
  `assert-flag-isolation.sh` の builtin-only 規約に従う」旨を明記する。
- **【rev.3】再 deploy の扱い**: 進行中の participant の workspace を再 deploy する運用
  (LIVE hotfix / scale-to-0 復帰) は、deploy 経路がイベントを出す実装では
  **その participant の `current` evade を恒久 taint する**。S-a 採用後はイベント 0 なので安全だが、
  **runbook の再 deploy 手順に「deploy 後に当該 user の rule fire が増えていないことを確認する」を
  1 行入れる** (owner = sre-engineer)。
- リハーサル手順に mission **02/03/05/09/10** の再走を追加する (Signpost 1)。

## Signposts

この決定を覆す / 見直す観測可能な信号:

1. **リハで mission 02 / 03 / 09 / 05 のいずれかが期待どおりに動かない** (F4 で拡張):
   - **02** (trigger): `cat /etc/shadow` で `Read sensitive file untrusted` が発火しない
     → bind mount 化で `fd.name` が変わった。→ **B2 + 09-i** に切替、または Option B 撤回。
   - **03** (evade): `/proc/self/root/etc/shadow` 経由で flag が読めない / 逆に発火する
     → mount 方式の見直し。
   - **09** (trigger): `ln` が EXDEV で失敗する / `Create Hardlink Over Sensitive Files` が
     発火しない / リンク数が 2 にならない → 09-ii が不成立。**B2 + 09-i** に切替。
   - **05** (evade): `/root/.ssh/id_rsa` の dir mount 化で flag が読めない → mount 方式の見直し。
     (05 の *ゲート不在* は本 ADR では直さない。「限界」節参照)
2. **evade 課題の solve が「workspace 作成から 60 秒未満 かつ その参加者の rule fire 0 件」で発生**
   (scoreboard は solve 時刻と `eventsPerUser` を保持している) —— 隔離が漏れているか H2 が使われている。
   イベント中に検出したい信号なので admin dashboard に出す価値がある。
   **前提**: 検証・運用コマンドが Falco イベントを汚さないこと (F3)。`eventsPerUser` が
   assert 由来で汚れるとこの Signpost は機能しない。
3. **ttyd の `kubectl exec` 失敗が発生する** (ttyd コンテナログの 403/401、workspace が
   ready なのにターミナルが繋がらない) —— projected token 化の回帰。→ 即 revert 対象。
4. **新ミッションの仕込み先が bind mount で表現できない、または planted file に同一 fs 操作が必要**
   (2 件以上出たら。09 を 1 件目として数える) —— initContainer + seed volume モデルの一般性が
   尽きた。→ challenge の rootfs 全体を initContainer が生成するモデル、または
   「フラグを workspace に置かない」方向 (技法の積極的証明で採点する) へ再設計。
5. **【rev.3】deploy 直後の `eventsPerUser` が 0 でない participant が 1 人でもいる** ——
   deploy 経路が禁じ手を踏んでいる直接の証拠。観測は scoreboard の admin state を読むだけで済み、
   **観測自体はイベントを出さない** (Verification layer 4)。→ 該当 script を §F3′ に照らして修正するまで
   本番投入しない。
6. **【rev.3】participant が着手していないミッションが deploy 直後に solve 済**
   (とくに 02-credential-files) —— trigger の auto-solve 汚染。5 より弱い信号だが
   参加者から「もう終わってる」と申告される形で先に届くことがある。
7. **【rev.3】workspace Pod に challenge image を使うコンテナが 2 つ以上になる、または
   challenge 以外のコンテナが定常的に syscall を出す構成になる** ——
   ingest の image repo フィルタ (`internal/scoreboard/ingest/ingest.go:95`) が
   「参加者の操作かどうか」の代理として機能しなくなる。
   → **S-d (container 名フィルタ)** を security-engineer 同意付きで起票する。
8. **【rev.3】新しい plant-target が build 時 snapshot で表現できない**
   (実行時にしか存在しないファイル / プロセス状態 / 動的生成物)。1 件出たら S-a の一般性が尽きたので、
   Signpost 4 と併せて initContainer + seed volume モデル自体の再設計を検討する。

## Verification

機械で確認する方法 (**rev.3 で 4 層**)。**layer 1 と layer 3 は独立の必要条件であり、互いの代替ではない**
(layer 1 = chart の main が正しいこと、layer 3 = 本番に適用された実物が正しいこと)。
**layer 4 (rev.3 新設) は「deploy 経路が採点を汚していないこと」を実機で観測する層**であり、
残る prod gate = ADR-0003 Verification (d) の同一 run 内で実行する。

> **rev.3 の自己保証**: 本 Verification の全項目は **それ自身が Falco イベントを 1 件も出さない**
> (layer 1/2 = 静的、layer 3 = builtin-only、layer 4 = 運用者マシンから scoreboard 状態を読むだけ)。
> 唯一の例外は layer 4 の 4-7 (未実測項目の実測) で、これは **`test1` workspace 限定**
> (§F3′ の (B)) とし、既定経路では走らせない。

### 1. CI: レンダリング済み manifest への **allowlist 型** 静的 assert (F1)

新 `scripts/check-flag-isolation.sh` (Make target `make check-flag-isolation`)。
既存 required job `chart-lint` (`.github/workflows/ci.yaml:45-59`、既に `helm template` と
`check-seccomp.py` を回している) に追加する。

**列挙型 (「`^CTF_FLAG_` という env 名が無い」) は採らない** —— `envFrom` と volumeMount で
迂回されるため。allowlist 型で「既知集合以外は全部 fail」にする。

対象レンダリング (**すべての分岐を検査する**):

- `--set challenge.allMissions=true` (本番既定、`pod.yaml:165` 側)
- `--set challenge.allMissions=false --set challengeId=<id>` を **03/05/10 それぞれ** で
  (`pod.yaml:170` の `else if` 側。監査 F1: この分岐も assert 対象)
- いずれも `--set-string challenge.flags.03-stealth-read='FALCO{dev-probe}'` 等を与える

`kind: Pod` の container `challenge` に対する assert:

| # | assert | 迂回する攻撃 |
|---|---|---|
| 1-1 | `env[].name` が **allowlist と完全一致以下**: `FALCO_CTF_USER` / `FALCO_CTF_CHALLENGE` / `FALCO_CTF_COLLECTOR` / `FALCO_CTF_SCOREBOARD` / `FALCO_CTF_DNS_SUFFIX` の 5 変数のみ (`pod.yaml:149-163`)。集合外が 1 つでもあれば fail | env 名を変えた注入 |
| 1-2 | **`envFrom` キー自体が存在しない** | `envFrom: {secretRef: {name: ctf-flags}}` による無名注入 |
| 1-3 | 各 env entry が `value:` のみを持つ (`valueFrom` を持たない) | `secretKeyRef` / `configMapKeyRef` 経由の注入 |
| 1-4 | `volumeMounts[].mountPath` が **宣言済み plant-target の allowlist と完全一致以下**。seed volume を参照する entry は `subPath` が宣言済み plant-target に対応するもののみ (B2 採用時は mountPath = 宣言済み plant-dir)。**`subPath` 無しの seed volume mount (= seed root mount) は fail** | F5: `/plant-seed` mount による mission 03 回避 path |
| 1-5 | `/var/run/secrets/kubernetes.io/serviceaccount` への volumeMount が無い | 経路 3 |
| 1-6 | challenge コンテナ block 内に文字列 `CTF_FLAG` が現れない (plant initContainer は除外) | 見落とし全般の網 |
| 1-7 | `lifecycle.postStart` がフラグを参照しない (1-6 に含まれる) | postStart 経由の再導入 |

`kind: Pod` 全体に対する assert:

| # | assert |
|---|---|
| 1-8 | 出力全体のどこにも `FALCO{dev-probe}` という文字列が現れない (値は Secret に `b64enc` される) |
| 1-9 | `spec.automountServiceAccountToken == false` |
| 1-10 | initContainer `plant` が存在し、その env は `secretKeyRef` / `envFrom.secretRef` のみ (平文 `value:` を持たない) |
| 1-11 | ttyd の SA token は projected volume で、`plant` / `challenge` には mount されていない |

**negative test (テンプレートを落とす検査)**:

| # | assert |
|---|---|
| 1-12 | `--set challenge.extraEnv[0].name=CTF_FLAG_03_STEALTH_READ --set challenge.extraEnv[0].value=x` を与えた `helm template` が **非ゼロ終了する**。実装は `pod.yaml:174-176` の `with .Values.challenge.extraEnv` 内で `CTF_FLAG_` prefix を検出したら Helm の `fail` を呼ぶ (監査 F1: `extraEnv` は allowlist assert の後段で値が展開されるため、テンプレート側で落とすのが唯一の fail-closed) |
| 1-13 | 同様に `challenge.extraEnvFrom` 相当の口を新設しない (存在しないことを assert)。将来追加するなら I12 の改訂 = architect 合意 + VP 承認 |

`platform` 側の conftest/OPA Key Guards (G5-2b) にもこの assert 集合を移植できる (任意)。

### 2. CI: 生成物 drift + **重複 plant-target / seed 初期化** (F6)

`challenges/gen-values.sh --check` を拡張 (既存 required job `flag-guard`,
`.github/workflows/ci.yaml:65-70`)。追加する検査:

| # | assert | 根拠 |
|---|---|---|
| 2-1 | 各 `plant.sh` が `# plant-target:` 宣言を 1 行以上持つ | 宣言なしは mount リストに乗らない = plant が捨てられる |
| 2-2 | **同一 plant-target を宣言する plant.sh が複数あるとき、生成される mount リストで 1 エントリに畳まれている (dedupe)** | 03 と 10 はいずれも `/etc/shadow` へ append (`03-stealth-read/plant.sh:4`, `10-final-exfil/plant.sh:6`)。dedupe しないと volumeMount の mountPath 重複で Pod が作れない / kubelet が非決定的に振る舞う |
| 2-3 | **【rev.3 で差し替え】seed 初期化ステップが存在し、その供給元が *image build 時に焼いた非 sensitive snapshot* であること** —— 生成された seed script が、素データを要する plant-target について append の *前* に **`/opt/ctf/plant-seed/` 配下からのみ**コピーする (S-a)。**rev.2 の「image rootfs から実行時コピー (`cp -a /etc/shadow ...`)」は撤回** | 現行 plant.sh は `>>` 前提で「素の `/etc/shadow` が既に存在する」ことを暗黙に仮定している (`values-all.yaml:16,37`)。emptyDir seed は空で始まるので、初期化なしでは `/etc/shadow` がフラグ 2 行だけのファイルになり mission 02 のブリーフ (`challenges/02-credential-files/journey.yaml:8,13`) と噛み合わない。一方 **実行時に実 `/etc/shadow` を読むと mission 02 が auto-solve する** (§F3′)。`sensitive_files` は `fd.name` ベースなので (`challenges/03-stealth-read/rule.yaml:90-93`) **判定の文脈は path で決まり中身に依存しない** → snapshot で足りる |
| 2-4 | append の順序が `gen-values.sh:19-21` の `sort` 順 (03 → 05 → 10) と一致し、生成が決定的であること | 順序が揺れると `--check` が false drift を出す |
| 2-5 | 各 plant.sh の書き込み先が宣言済み plant-target 配下に収まっている (`>` / `>>` / `cat >` / `mkdir -p` の宛先を静的走査。**best-effort ヒューリスティック**であることを script 内に明記) | 未宣言の書き込みは mount されず silently 消える |
| 2-6 | 既存の values.yaml / values-all.yaml の drift 検査 (現行 `gen-values.sh:62-76` を維持) | C4 |
| **2-7** | **【rev.3 新設・I13 の機械強制】生成された seed script が §F3′ の禁じ手集合に触れないこと** (静的走査): (a) 入力リダイレクト / コピー元が **`/opt/ctf/plant-seed/` 配下の allowlist のみ**、(b) `sensitive_file_names` の 4 path と `/etc/sudoers.d` `/etc/pam.d` が **read 位置に現れない**、(c) `grep` / `egrep` / `fgrep` / `find` / `ln` を呼ばない、(d) seed (emptyDir) 上に書いたファイルを exec しない。**2-5 と同じ best-effort ヒューリスティックである旨を script 内に明記する** | §F3′ の禁じ手表。deploy 経路は全 workspace・毎 deploy で走るので、assert 側より厳しく扱う |
| **2-8** | **【rev.3 新設・I10 の機械強制】challenge image の `/etc/shadow` と `/opt/ctf/plant-seed/etc/shadow` の双方に、crypt ハッシュ形の文字列 (`:$<n>$...`) と `FALCO{` が現れないこと** (image build job 内で確認)。実測 (2026-08-18): 現行パッケージ集合では 0640 root:shadow / 17 行すべて locked (`*` / `!`) / ハッシュ 0 件 | S-a は「同一イメージ内のビットの複製」なので I10 の面を増やさないが、**将来 image に本物のハッシュが入ったら 2 箇所に増える**。紙で保証せず検査で止める |

### 3. **deploy 時の実機 assert (fail-closed)** —— 人手 runbook ではない (F2)

新 `charts/ctf-user/assert-flag-isolation.sh` を `deploy-user.sh` が
`helm upgrade --install ... --wait` の**直後に実行**し、violation があれば **非ゼロ終了**する。
`deploy-event-workspaces.sh` は各 `deploy-user.sh` の exit status を収集し、
**1 件でも失敗したら roster deploy を abort する** (現状 `deploy-event-workspaces.sh:161-170` は
background job の status を破棄しているので、この収集自体が実装項目である)。

検査内容 (`kubectl -n ctf-<user> exec workspace -c challenge -- sh -c ...`):

| # | assert | 期待値 |
|---|---|---|
| 3-1 | `env` に `CTF_FLAG` が現れない | 0 件 |
| 3-2 | `/proc/1/environ` に `CTF_FLAG` が現れない | 0 件 |
| 3-3 | `/var/run/secrets/kubernetes.io/serviceaccount/token` が存在しない | not exist |
| 3-4 | seed root (`/plant-seed` 等) が challenge から見えない | not exist |
| 3-5 | planted 済み: `/etc/shadow` に `FALCO{` を含む行が 2 本 (03 + 10) | 2 |
| 3-6 | planted 済み: `/root/.ssh/id_rsa` が存在する (`test -f` のみ。**読まない**) | exists |
| 3-7 | ttyd の `kubectl exec` が成功する (Signpost 3 の裏返し) | exit 0 |

#### 【必須】§F3′ —— **deploy 経路と assert の両方**が採点を汚してはならない (rev.3 で F3 を一般化)

> **要件は「Falco イベントを 1 件も出さない」ことである** —— rev.2 が assert について
> 「`window` 安全ではなく **『イベントを 1 件も出さない』を要件とする**」と書いた言い回しを、
> **そのまま deploy 経路にも適用する**。**手段は文脈で異なる**:
> **assert = builtin-only 規約** (下記 (A))、**deploy 経路 (plant / seed 初期化) = 禁じ手表を踏まない**
> (S-a + Verification 2-7)。**「window の外だから安全」は根拠にならない** ——
> `eventsPerUser` は永続し、trigger の auto-solve は attempt スコープ外である
> (`internal/scoreboard/scoring/scoring.go:347-352`)。
> **これが I13 の本体である。**

**なぜ deploy 経路の方が重いか**: assert は「検証時に 1 回」だが、deploy 経路は
**全 workspace・毎 deploy で必ず**走る。rev.2 は前者だけを守っていた (上記 Context の内部矛盾)。

##### plant-target × mission の網羅表 (rev.3。VP 指示により全 plant-target を列挙)

現行の plant-target は 2 つだけである (`# plant-target:` 宣言は Option B の 6 で新設するが、
実体は現行 plant.sh の書き込み先と同じ):

| plant-target | 宣言する plant.sh | 素データを要するか | **実行時に read すると発火するルール** | **当たる mission** | S-a 採用後 |
|---|---|---|---|---|---|
| `/etc/shadow` | 03 (`plant.sh:4`) / 10 (`plant.sh:6`) —— **重複 (F6)** | **要** (両者 `>>` 前提) | `Read sensitive file untrusted` (`challenges/03-stealth-read/rule.yaml:166-198`。`sensitive_files` = 同 :90-93 で `/etc/shadow` に一致) | **02 expectedRules → 全員 auto-solve** (`challenges/02-credential-files/falco-rule.yaml:3-4`) / **03 forbiddenRules → `current`=03 のとき恒久 taint** (`challenges/03-stealth-read/falco-rule.yaml:3-4`) / **10 forbiddenRules → `current`=10 のとき恒久 taint** (`challenges/10-final-exfil/falco-rule.yaml:5`) | **0 件** —— 読むのは `/opt/ctf/plant-seed/etc/shadow` で `fd.name startswith /etc` が不成立 |
| `/root/.ssh/id_rsa` (dir `/root/.ssh`) | 05 (`plant.sh:4-11`) | **不要** —— image に `/root/.ssh` が存在しない (実測: `/root` は 0700 で空)。plant が `mkdir -p` + `cat >` で新規作成する | (仮に read しても) **どのルールにも当たらない** —— `/root/.ssh/id_rsa` は `sensitive_file_names` に無く (`challenges/03-stealth-read/rule.yaml:1-2`)、`Search Private Keys or Passwords` は `proc.name in (grep,egrep,fgrep)` + args に `BEGIN * PRIVATE`、または `proc.name=find` + args に `id_rsa` 等を要求する (`challenges/04-key-search/rule.yaml:16-43`) ので `cp` / `sh` では成立しない | 無し (04 / 05 は当たらない) | 変化なし (もともと 0 件) |

→ **rev.2 の 2-3 が実際に危険なのは `/etc/shadow` の 1 件だけ**だが、
その 1 件が **catalog 中で最も観測されるルール** (02 の expected / 03 と 10 の forbidden の三重) に当たる。

##### deploy 経路の禁じ手表 (全 mission 網羅。rev.3)

**覚え方: 「mission 10 の forbiddenRules 7 本 + 00 と 11 の expectedRules 2 本 = 計 9 本のうち
1 本も発火させない」** —— 10 の 7 本は 01/02/04/06/07/08/09 の expectedRules 全部と一致する
(`challenges/10-final-exfil/falco-rule.yaml:4-10`) ので、これで catalog 12 課題を網羅する。

| mission (type) | ルール | deploy 経路の禁じ手 | S-a + B1 で該当するか |
|---|---|---|---|
| 00-tutorial (trigger) | Execution from /dev/shm | `/dev/shm` 配下から exec しない | しない (本番 scenario 非含: `challenges/00-tutorial/falco-rule.yaml:8-11`) |
| 01-initial-recon (trigger) | Contact K8S API Server From Container | **workspace 内から** apiserver へ connect しない (運用者マシンからの `kubectl exec` は対象外) | しない |
| **02-credential-files (trigger)** | **Read sensitive file untrusted** | `sensitive_file_names` の 4 path と `/etc/sudoers.d` / `/etc/pam.d` 配下を **open-for-read しない**。実測: この image に実在するのは `/etc/shadow` と `/etc/pam.d/*` (6 ファイル) のみ (`/etc/sudoers` / `/etc/pam.conf` / `/etc/security/pwquality.conf` は不在) | **rev.2 は該当した。S-a で該当しなくなる** |
| 03-stealth-read (evade) | 同上 (forbidden) | 同上 | 同上 |
| 04-key-search (trigger) | Search Private Keys or Passwords | `grep`/`egrep`/`fgrep` を `BEGIN * PRIVATE` を含む args で起動しない。`find` を `id_rsa`/`id_dsa`/`id_ed25519`/`id_ecdsa` を含む args で起動しない | しない (2-7 (c) が静的に禁止) |
| 05-silent-search (evade) | 同上 (forbidden) | 同上 | しない |
| 06-web-rce-shell (trigger) | Run shell untrusted | **禁じ手ではない** —— ルールは `protected_shell_spawner` (nginx/httpd/mysqld 等が祖先) を要求する (`challenges/06-web-rce-shell/rule.yaml:20-24,137-150,219-223`)。containerd 直下の `sh` は該当しない。**これは builtin-only 方式 (A) が成立する前提でもある** | しない |
| 07-persist (trigger) | Drop and execute new binary in container | `proc.is_exe_upper_layer=true` の実行体を起動しない = **image 由来のバイナリだけを exec する** (seed / emptyDir に書いたファイルを exec しない) | しない見込み。**emptyDir 上の実行体が upper layer 判定になるかは未実測** → layer 4 の 4-7 |
| 08-c2-beacon (trigger) | Redirect STDOUT/STDIN to Network Connection in Container | socket fd を stdio に dup しない | しない |
| 09-hidden-cache (trigger) | Create Hardlink Over Sensitive Files | `evt.arg.oldpath in (sensitive_file_names)` の hardlink を作らない = sensitive path に対して `ln` / `cp -l` / `cp --preserve=links` を使わない。**`cp -a` は `--preserve=links` を含む**点に注意 (source 側に hardlink 対があれば `link()` を発行しうる) | しない。実測: `/etc/shadow` の link 数は 1。**B2 (`/etc` 全体) は面が広いので layer 4 の 4-7 で確認** |
| 10-final-exfil (evade) | 上記 7 本 (forbidden) | 上記すべて | しない |
| 11-cloud-cred-hunt (trigger) | Find AWS Credentials | aws credential 文字列を `grep` / `find` で探さない (`challenges/11-cloud-cred-hunt/falco-rule.yaml:3-4`) | しない |

##### assert 側 (rev.2 の F3 をそのまま維持)

監査が実コードで確認したとおり、**素朴な検証コマンドが採点を壊す**:

- 旧案の `grep -cE 'FALCO\{' /etc/shadow` は `proc.name=grep` で
  **`Read sensitive file untrusted` を発火させる**。`grep` は除外リストに含まれない ——
  `shell_binaries` (`challenges/03-stealth-read/rule.yaml:59`) にも
  `read_sensitive_file_binaries` (同 :51) にも無く、ルールの除外節 (同 :179) を通らない
  (`grep` が現れるのは `linux_bench_reading_etc_shadow` マクロだけで、そちらは
  `proc.aname[2]=linux-bench` を要求する)。
- 発火すると ingest フィルタを通過し (`internal/scoreboard/ingest/ingest.go:130`
  → `EvaluateTrigger`)、**mission 02 (`type: trigger`,
  `expectedRules: [Read sensitive file untrusted]`,
  `challenges/02-credential-files/falco-rule.yaml:1-4`) が submit 無しで auto-solve する。**
- さらに `eventsPerUser` が汚れ、**Signpost 2 の前提が崩れる**。
- 同じ理由で **`cat` / `head` / `tail` / `awk` も使用禁止** (いずれも除外リストに無い)。
  `cat /etc/shadow` は mission 02 の想定解そのものである。
- **【rev.3】`cp` も使用禁止。** `cp` は除外マクロ `cmp_cp_by_passwd`
  (`challenges/03-stealth-read/rule.yaml:98-99`) に現れるが、その条件は
  `proc.name in (cmp, cp) and proc.pname in (passwd, run-parts)` であり、
  **plant / assert から起動する `cp` の親は `sh` なので除外に該当しない**
  (`not cmp_cp_by_passwd` = 同 :184 と `not user_read_sensitive_file_conditions` = 同 :122-123,189 の
  両方を通過する = 発火する)。**「除外リストに `cp` の文字がある」ことを免除の根拠にしてはならない。**
  なお **除外条件を満たすように親プロセス名を仕立てる派生案は採らない** ——
  `rule.yaml` は docs サイトが参加者に描画する表示用抜粋なので、それは
  **参加者に開示された回避手段**になり採点の穴を作る (派生決定 (3) の S-e と同じ理由で却下)。

**採用する方式 (runbook レベルで確定)**:

> **(A) shell builtin だけで読む。** `sh -c` の中で入力リダイレクトと `while read` /
> `case` のみを使い、外部バイナリを一切 spawn しない。
> 例 (形のみ): `sh -c 'n=0; while read -r l; do case $l in *FALCO\{*) n=$((n+1));; esac; done </etc/shadow; test "$n" -eq 2'`
> `proc.name=sh` は `shell_binaries` (`challenges/03-stealth-read/rule.yaml:59`) に含まれ、
> ルール除外節 (同 :179) に該当するため **発火しない**。

- 3-1 / 3-2 は `/etc/shadow` を読まないので `env | grep` / `tr </proc/1/environ | grep` でも
  発火しないが (`/proc/1/environ` は `sensitive_file_names` に無い。`grep CTF_FLAG` は
  `Search Private Keys or Passwords` の `private_key_or_password` 条件
  (`challenges/04-key-search/rule.yaml:16-27`) を満たさない)、**規約を単純に保つため
  assert script 全体を builtin-only とする**。
- 3-6 は `test -f` のみ (open しない)。**`/root/.ssh/id_rsa` の内容は読まない。**
- **(B) は補助的に併用する**: roster に含まれる `test1` workspace
  (`deploy-event-workspaces.sh:157`) を、builtin 以外の破壊的検証が必要になったときの
  専用ターゲットとする。ただし **既定経路では使わない** ——
  (B) は「1 workspace 分の `eventsPerUser` を犠牲にする」ことでしか成立せず、
  (A) は犠牲ゼロで全 workspace を検査できるため、(A) が既定である。
- **(C) 「Falco / scoreboard 起動前に実行」は採らない**: roster deploy は helmfile sync 後に
  走る (platform runbook Step 3) ため順序を作れず、順序に依存する検証は運用者が
  再現できない = layer にならない。
- assert が spawn しうる `sh` について: `Run shell untrusted` は mission 10 の forbiddenRules に
  含まれるが (`challenges/10-final-exfil/falco-rule.yaml:3-10`)、(i) ttyd 自身が全参加者の
  ターミナルで `/bin/bash -l` を exec しており (`images/ttyd/entrypoint.sh:18-23`) 実運用で
  発火していない、(ii) 仮に発火しても 10 の window は 30 秒
  (`challenges/10-final-exfil/falco-rule.yaml:13`) で、assert は roster deploy 時 =
  イベント開始の数十分前に走るため排出される。
  **ただし `eventsPerUser` は永続する**ので、「window 安全」ではなく
  **「イベントを 1 件も出さない」を要件**とする (これが builtin-only 規約の理由)。

### 4. **E2E: deploy 経路の無汚染** —— ADR-0003 Verification (d) と同一 run 内 【rev.3 で新設】

**前提**: 残る prod gate は **ADR-0003 Verification (d) = cluster 実機 E2E** だけである
(`docs/adr/0003-evade-clean-gate-attempt-scope.md:610-619`)。
そして **現状の (d) は本 ADR の欠陥に対して盲目である** —— (d) の受け入れ条件は
「正規順に 01, 02, 04, 06, 07, 08, 09 をクリアした後、手動 reset なしで 03 / 05 / 10 が
submit / auto-solve 可能であること」であり、**02 が deploy 時に auto-solve されていても (d) は green になる**
(02 は「クリア済」に見える)。よって rev.3 は (d) に観測を追加する。

**自己汚染しない設計**: 4-1〜4-4 は **workspace 内でコマンドを実行しない** ——
運用者マシンから scoreboard の状態を読むだけなので、**検査自体が Falco イベントを出さない**。
これは layer 3 に置けない理由でもある (`deploy-user.sh` は scoreboard の admin 面に到達しない前提)。

| # | assert | 期待値 | 取得元 |
|---|---|---|---|
| 4-1 | deploy 完了直後、対象 user の rule fire が **0 件** | 0 | admin state の `eventsPerUser` |
| 4-2 | deploy 完了直後、対象 user の solved が **0 件** (とくに `02-credential-files`) | 0 | 同 |
| 4-3 | deploy 完了直後、対象 user の全 evade 課題の `dirtyRules` が **空** | 空 | journey detail の `dirtyRules` (ADR-0003 §A3) |
| 4-4 | **進行中の再 deploy を模す**: 01 を solve させて `current` を進めた後に同一 user を再 deploy し、4-1 の増分ゼロ・4-3 の空を再確認 | 変化なし | 同 (**Context の「再 deploy では evade も汚染される」経路の回帰**) |
| 4-5 | mission 02 が **参加者の操作で** solve すること (`cat /etc/shadow` → CLEARED) | solve | (d) の通常手順に含まれる |
| 4-6 | **B2 を採る場合のみ**: `/etc` ディレクトリ mount 下で kubelet の `/etc/hosts` / `/etc/resolv.conf` 重ねが壊れていないこと | 名前解決成功 | workspace 内 (この 1 件だけ workspace 内実行。`sh` builtin と `getent` は §F3′ の禁じ手に当たらない) |
| 4-7 | **未実測項目の実測 (`test1` workspace 限定 = §F3 の (B))**: (i) **`cp -a /etc/shadow ...` が実際に `Read sensitive file untrusted` を発火させること** (架空の前提で設計しないため。故意違反 patch で 1 回だけ)、(ii) emptyDir 上の実行体が `proc.is_exe_upper_layer` と判定されるか、(iii) B2 の `cp -a` が `link()` を発行しないこと、(iv) `proc.name` が `cp` / `sh` として観測されること (alpine の `/bin/cp` は coreutils multicall への symlink、`/bin/sh` は busybox への symlink である) | (i) 発火する (ii)(iii)(iv) 記録 | `test1` workspace (`deploy-event-workspaces.sh:157`)。**既定経路では走らせない** |

> **4-7 の位置づけ**: 「`cp` が発火する」は本 rev.3 では **除外条件の構造 (`proc.pname` gate) からの
> 推論**であって実測ではない。**推論のまま Hard Invariant に昇格させない** ため、
> 4-7 (i) を実測項目として明示する。ただし **推論が外れていても S-a は無駄にならない**
> (S-a は「発火しない」ではなく「条件に到達しない」ので、`cp` の発火有無に依存しない)。

### 実装 PR の完了条件 (Definition of Done)

> **rev.3 の差分 (11 → 14 項目)**: **項目 2 と 3 を差し替え**、**項目 12 / 13 / 14 を追加**した。
> 項目 1 / 4 / 5 / 6 / 7 / 8 / 9 / 10 / 11 は rev.2 のまま (番号も変えない)。
> 差し替えた 2 つはいずれも **rev.2 の内部矛盾に由来する** ——
> 旧 2 は「seed 初期化が image rootfs 由来であること」を要求していたが、これが欠陥の本体だった。
> 旧 3 は builtin-only 規約を **assert についてのみ**要求していた。

1. `scripts/check-flag-isolation.sh` が Verification 1 の 1-1〜1-13 を実装し、
   `chart-lint` job から呼ばれ、**allowlist を 1 つ外した / `envFrom` を足した /
   seed root を mount した / `extraEnv` に `CTF_FLAG_*` を渡した 4 つの故意違反 patch で
   実際に fail することを PR 本文に貼る** (assert が assert していることの証明)。
2. **【rev.3 で差し替え】** `challenges/gen-values.sh --check` が Verification 2 の **2-1〜2-8** を実装し、
   **重複 plant-target (03/10 = `/etc/shadow`) が mount リストで 1 エントリに畳まれること**と、
   **seed 初期化の供給元が `/opt/ctf/plant-seed/` 配下の build 時 snapshot であること (2-3)**、
   **生成 seed script が §F3′ の禁じ手集合に触れないこと (2-7)** を検査する。
   併せて image 側に snapshot の焼き込み (`images/challenge/Dockerfile`) と
   **I10 guard (2-8)** を入れる。
   **旧 2 の「seed 初期化が image rootfs 由来であること」は撤回** (それが汚染の原因だった)。
3. **【rev.3 で差し替え】** `charts/ctf-user/assert-flag-isolation.sh` が Verification 3 の 3-1〜3-7 を
   **builtin-only** で実装し、`deploy-user.sh` から呼ばれて violation で非ゼロ終了する。
   **script 内に外部バイナリ (`grep`/`cat`/`head`/`tail`/`awk`/`find`/**`cp`**) を使わない旨と理由を明記**し、
   静的に検査する (自己 grep で足りる)。
   **加えて、同じ「イベント 0」要件を deploy 経路 (plant / seed script) にも適用する** (§F3′) ——
   deploy 側の手段は builtin-only ではなく **禁じ手表 + S-a** であり、機械強制は 2-7 である。
4. `deploy-event-workspaces.sh` が per-user deploy の exit status を収集し、
   **1 件でも失敗したら `✓ done` を出さず非ゼロ終了する** (platform 側 PR、両リポ相互リンク)。
5. **mission 09 の EXDEV 実測** (VP 裁定): 実クラスタで `ln` を実行し、
   (i) `link()` の errno、(ii) `Create Hardlink Over Sensitive Files` の発火有無、
   (iii) リンク数、を記録して PR 本文に貼る。既定 09-ii が成立しなければ B2 + 09-i に切替え、
   切替結果を本 ADR に追記する。
6. **Signpost 1 の全 4 mission (02 / 03 / 09 / 05) を実機で再走**し、結果を PR 本文に貼る
   (+ 10 は requireExfil 経路まで)。
7. Hard Invariants 表に I12 を追記 (機械強制スクリプト名 2 本を併記)。
   **1〜4 が揃うまで追記しない** (I12 の発効条件)。
8. Cross-repo 契約表に「`deploy-user.sh` の非ゼロ exit は fail-closed 契約。呼び出し側は伝播する」を追記。
9. README / journey.yaml / docs-site から `CTF_FLAG_*` env 変数名の記述を削除
   (`challenges/03-stealth-read/README.md:12-15` 他)、09 の想定解を retarget に合わせて更新。
10. `.claude/agents/challenge-author.md` に「plant-target は bind mount 可能なパスに限る」
    「planted file に同一 fs 操作 (hardlink/rename) を要求する mission は書けない」を追記。
11. **mission 05 の実効ゲート不在**を別 Issue として起票し、本 ADR の「限界」節をリンクする
    (実装は本 PR のスコープ外)。
12. **【rev.3 追加】Verification layer 4 (4-1〜4-5、B2 採用時は 4-6) を ADR-0003 Verification (d) の
    E2E に組み込み**、結果を PR 本文に貼る。**4-4 (進行中の再 deploy) を必ず含める** ——
    これが「再 deploy で evade が恒久 taint される」経路の唯一の回帰である。
    owner = qa-engineer (未取得の助言、下記 Advice)。
13. **【rev.3 追加】4-7 の未実測項目を `test1` workspace で実測し、結果を PR 本文に貼る**
    ((i) `cp` の発火有無 (ii) emptyDir 実行体の upper-layer 判定 (iii) `cp -a` の `link()`
    (iv) `proc.name` の観測値)。**既定経路 (全 workspace) では走らせない。**
14. **【rev.3 追加】Hard Invariants 表に I13 を追記**し、**I11 / I12 / I13 の番号割り当てを
    VP が批准する** (Consequences の「不変条件の番号」表)。
    I13 の追記は **2-7 と layer 4 が揃うまで行わない** (I12 と同じ発効条件の考え方)。
    ADR-0003 側の I11 候補との衝突を残したまま `.claude/rules/` に書かない。

## Advice

- **security-engineer (2026-08-18, 独立監査)**: 判定 **PASS with conditions**。
  読み出し経路の列挙に漏れは無し (7 経路を潰して確認済み)。
  Verification 3 層に機械検証の穴 6 件を指摘し、うち 2 件 (F1 / F2) は
  「閉じたつもりで閉じていない」を再生産すると評価:
  - **F1 [HIGH]** assert を列挙型 → allowlist 型へ (`envFrom` / volumeMount / `allMissions=false`
    分岐 / `extraEnv` 経由の迂回) → Verification 1 に反映。
  - **F2 [HIGH]** layer 1 は本番適用 manifest を保証しない。layer 3 を人手 runbook ではなく
    deploy 時の fail-closed 機械 assert にせよ → Verification 3 に反映。
  - **F3 [HIGH]** 提案されていた検証コマンド `grep -cE 'FALCO\{' /etc/shadow` 自体が
    mission 02 を auto-solve し `eventsPerUser` を汚す → builtin-only 方式 (A) を確定。
  - **F4 [MEDIUM]** mission 09 (`ln /etc/shadow /tmp/.cache.bak`) が EXDEV で壊れる見込み →
    Signpost 1 を 02/03/09 + 05 に拡張、B1/B2 と 09-i/ii/iii を Options に前倒し、
    EXDEV 実測を完了条件化。
  - **F5 [MEDIUM]** seed root の mount は mission 03 の forbidden rule を回避する代替 path に
    なる → I12 と Verification 1-4 に明文化。
  - **F6 [MEDIUM]** 03 と 10 が同一 `/etc/shadow` に append するため gen-drift に dedupe と
    seed 初期化の検査が必要 → Verification 2-2 / 2-3 に反映。
  - **限界指摘 [最重要]** mission 05 の forbidden rule は `grep`/`find` の args しか見ておらず
    `cat /root/.ssh/id_rsa` は無検知 → 「限界」節を新設。別 Issue へ。
  - 追記依頼: フラグが全参加者で同一値 [MEDIUM] / `plant.sh` は image に焼かれている [LOW] →
    Context に反映。
  - 先行評価 (VP 経由): 「H1 は今回検出した 104 件の High CVE 全部より採点真正性への影響が大きい」。
    本 ADR はこの評価を前提に、CVE 対応より優先する順序を採る。
- **VP (2026-08-18)**: 制約 C1-C7 の提示。Option A の実現可能性を実コードで判定せよという指示に対し、
  「原理的に閉じない」ことを Pod env の不変性と exec タイミングから示した (上記「定理」)。
- **VP 裁定 (2026-08-18, 監査後)**: (i) I12 は F1 + F2 の実装をもって発効 (ADR merge と同時発効に
  しない)、(ii) mission 09 の EXDEV 実測を実装 PR の完了条件とする、(iii) Signpost 1 を
  02/03 → 02/03/09 + 05 に拡張する、(iv) `falco-ctf-app-prodlocal/` は削除済み・
  LIVE hotfix 5 commit は `origin/archive/live-hotfix-2026-08-16` に退避し内容は main の
  後続作業 (P19-2b portal 統合 / P22-1 hint 集約) で置換済みであることを確認 (CEO 決定)。
- **software-engineer (2026-08-18, VP 経由)**: `apk policy` による cycle 実測 (ADR-0002 側)。
- **VP (2026-08-18, rev.3 発注)**: **rev.2 の内部矛盾を現物で指摘**した ——
  (i) Verification 2-3 が必須化した seed 初期化は §F3 が禁止した行為そのもの、
  (ii) plant initContainer の image は challenge と同一、
  (iii) **ingest は container 名で絞り込まない** (`grep -n "container.name|ContainerName" ingest.go` → 0 hits)、
  (iv) したがって **§F3 が守っているのは deploy 時 assert だけで、本番 deploy 経路が素通し**。
  併せて **「`cp` が発火する」は除外リストに無いことからの推論であり実測ではない**と自己申告があり、
  rev.3 はこれを **Verification 4-7 (i) の実測項目**として落とした
  (推論のまま Hard Invariant に昇格させないため)。
  また **S-c (イメージ追加) を安易に選ばないこと**、**S-d (ingest 緩和) は
  security-engineer 同意権の領域であること**を制約として提示。
- **architect (2026-08-18, rev.3 起草 + 自己レビュー)**: VP の 4 点をすべて実コードで再検証し、
  **2 点を訂正 / 1 点を追加**した:
  - **訂正 1**: 「`cp` もどの除外リストにも無い」は不正確。`cp` は除外マクロ `cmp_cp_by_passwd`
    (`challenges/03-stealth-read/rule.yaml:98-99`) に**現れる**が、条件が
    `proc.pname in (passwd, run-parts)` で **親プロセス名に gate されている**ため plant では成立しない。
    **結論 (発火する) は変わらないが、根拠は「無い」ではなく「条件を満たさない」である** ——
    この違いは重要で、「除外リストに文字がある」ことを免除の根拠にする誤りを塞ぐ (§F3′)。
  - **訂正 2**: rev.2 の 2-3 の根拠のうち **`sensitive_files` 判定の文脈は中身に依存しない**
    (`fd.name` ベース = `challenges/03-stealth-read/rule.yaml:90-93`)。
    したがって 2-3 は **realism だけを根拠に「初期化の存在」を要求できる**が
    **「実行時に実ファイルを読むこと」は要求できない** → S-a が成立する。
  - **追加 1 (新規指摘)**: ADR-0003 との非対称について、VP の読み
    (「trigger は汚染 / evade は無害」) は **初回 deploy に限って正しい**。
    **進行中の再 deploy では `current` が evade になりうるため恒久 taint が起きる**
    (`markDirtyOnRuleFire` = `internal/scoreboard/scoring/scoring.go:415-429`)。
    reset の参加者導線が ADR-0003 F3 として未閉止であるため、**復旧手段が無い**。
    → Context に明記し、Verification 4-4 で回帰を張った。
  - **実測した項目 (`docker run`、challenge image のパッケージ集合を適用した状態)**:
    `/etc/shadow` = 0640 root:shadow / 260 bytes / 17 行すべて locked (`*` / `!`) / crypt ハッシュ 0 件 /
    link 数 1、`/root` = 0700 で空 (`/root/.ssh` 不在)、`/etc/pam.d` は **存在する** (6 ファイル) ため
    `sensitive_files` の `fd.directory` 節に当たる、`/etc/sudoers` / `/etc/pam.conf` /
    `/etc/security/pwquality.conf` は **不在** (= 09-ii の fixture 追加要求は正しい)、
    `cp` = GNU coreutils 9.7 (`/bin/cp` は multicall への symlink)。
  - **実測できていない項目** (→ 4-7): `cp` の実発火、emptyDir 上実行体の `proc.is_exe_upper_layer`、
    `cp -a` が `link()` を発行しないこと、Falco が観測する `proc.name` の実値。
- **未取得の助言**: sre-engineer (roster script の exit status 収集と abort 挙動 —— 実装項目 4 の
  owner。**rev.3 で追加: 再 deploy 手順への rule-fire 確認 1 行**)、
  qa-engineer (mission 02/03/09/05 の発火テストと EXDEV 実測の手順化 —— 実装項目 5/6。
  **rev.3 で追加: layer 4 を ADR-0003 (d) の E2E に組み込む = 実装項目 12/13**)、
  **security-engineer (rev.3 で追加: (a) S-d を採らない判断と Signpost 7 の起票条件、
  (b) I13 の文言、(c) 4-7 の実測手順が `test1` 1 workspace 以外を汚さないことの独立確認)**。
  **実装 PR までに取得すること。**
- **CEO 批准が不要になった事項 (rev.3)**: S-c (plant 用の新イメージ = I5 の 8 → 9) を**採らない**ので、
  本 ADR はイメージ数を変更しない。**I11 / I12 / I13 の番号割り当ては VP 批准事項**
  (Consequences の表)。
