# ADR-0007: plant-target の bind mount は **ディレクトリ granularity** に限定する (ADR-0001 の派生決定 (1) = B1 を supersede)

- Status: **Proposed**
- Date / Deciders: 2026-08-19 / architect (起草) + VP (承認 2026-08-19) + security-engineer (独立監査を要求) + CEO (merge / 本番投入)
- 関連:
  - **supersede 対象**: [ADR-0001](0001-flag-plant-initcontainer-not-challenge-env.md) の
    **派生決定 (1) 「seed delivery 方式」で採用された B1 (plant-target 単位の `subPath` bind)** のみ。
    **ADR-0001 の本決定 (Option B = フラグを challenge コンテナに一度も入れない) は維持する** ——
    本 ADR は Option B を否定せず、その *配送手段* を差し替える
  - ADR-0001 の **Signpost 1** (「新しい mount 方式が fire 挙動を変えるか」) への **Yes** の回答
  - ADR-0001 が提案した **I12 (フラグ隔離) / I13a (deploy 前後の採点状態 delta ゼロ) / I13b (catalog ルール 0 発火)**
  - [ADR-0003](0003-evade-clean-gate-attempt-scope.md) (attempt スコープ・恒久 taint。**時間経過での回復は無い**)、
    [ADR-0004](0004-capstone-dual-path-e2e-order.md) (capstone 2 経路 E2E の順序)
  - 発見: qa-engineer (2026-08-19, ローカル $0 E2E)。再現: VP (独立)。
    因果の切り分けと却下根拠の実証: architect (§C2 / §C5 の実測表)
  - フェーズ: リハ後 hygiene / prod gate (P## 非該当)

> **番号について (2026-08-25 訂正)**: 本 ADR 起草時 (2026-08-19) は 0005/0006 が未確定だったため
> 「0005 = app#143 の open PR」「0006 = app#144 (Issue) の予約」と記載していたが、これは stale。
> 現状 (実測): **0005** (`docs/api-spec-canon`, app#143) と **0006** (P25 QA チケットチャットの
> API 契約, app#144 とは無関係の別トピック) はいずれも **Accepted で main 入り済み**。
> app#144 (OpenAPI parity gate の設計欠陥 supersede) は 0006 との衝突が判明したため
> VP が **ADR-0008** に再割番済み。したがって **0005/0006/0008 は他で確定済み、0007 が空いていた
> ため本 ADR に確定**という経緯になる (結論の番号自体は変わらず 0007)。

---

## Context

### C1. 何が起きているか (実測)

ローカル $0 クラスタ (colima k3s `ctf-e2e`, arm64, Falco **0.43.1** `modern_ebpf`, containerd + runc) で、
**workspace Pod を deploy しただけで `Read sensitive file untrusted` が 2 件発火し、mission 02 が
参加者操作ゼロで auto-solve する。**

```
proc.name=runc:[1:CHILD]  proc.exepath=/usr/bin/runc  proc.pname=runc
proc.aname[2]=containerd-shim  proc.aname[3]=systemd
proc.cmdline="runc:[1:CHILD] init"  fd.name=/etc/shadow  evt.type=openat2
container.name=k8s_challenge_workspace_ctf-<user>_<poduid>_0
k8s.pod.name=workspace  k8s.ns.name=ctf-<user>  container.image.repository=falco-ctf/challenge
```

採点への帰結 (VP 実測): deploy しただけの user が `solved=1` = `02-credential-files`。
00/01 を解いて `current=03-stealth-read` に進めた user を **再 deploy すると 03 が
`dirty=true` / `dirtyRules=["Read sensitive file untrusted"]` に反転**し、
ADR-0003 に時間経過での回復は無いので **この taint は永続**する。

ingest がこれを参加者に帰属させるのは、フィルタが ns prefix (`ctf-`) + pod 名 (`workspace`) +
image repo 部分文字列の 3 条件だけで **container 名を見ていない**ため
(`internal/scoreboard/ingest/ingest.go:70-99`, `:112`)。

→ **no-go #2 / #3 / #4 / #10 に該当。I13a と I13b がローカルで FAIL。**

### C2. 因果の切り分け 【本 ADR の中核・architect が実クラスタで実測】

「どこに置いても、置く行為自体が検知される」のか、それとも `subPath` 固有か —— **どちらでもない。**
**mount の *destination* が Falco の `sensitive_files` マクロの一致対象であるときだけ**発火する。

**probe 方法**: ns `arch-probe` (= `ctf-` prefix でないので `ingest.go:78` が無条件に ignore、
pod 名も `workspace` でない = 二重に隔離) に `falco-ctf/challenge:dev` で
mount 形態だけが異なる 10 コンテナを立て、**Falco DaemonSet の stdout を一次ソース**として観測した。
scoreboard のログに solve / dirty 行が 1 件も出ていないことで無汚染も確認済み (probe ns は削除済み)。

| # | mount 形態 | destination | 起動時の `Read sensitive file untrusted` |
|---|---|---|---|
| a | emptyDir + **`subPath`** (現行実装と同一, `readOnly: true`) | **`/etc/shadow`** | **2 件 (発火)** |
| d | **`hostPath` type: File (`subPath` 無し)** | **`/etc/shadow`** | **2 件 (発火)** |
| e | emptyDir + `subPath` | **`/etc/sudoers`** | **2 件 (発火)** |
| b | emptyDir + `subPath` | `/opt/planted/shadow` | 0 件 |
| c | emptyDir **ディレクトリ全体** | `/etc` (中に `shadow` を含む) | **0 件** |
| i | emptyDir **ディレクトリ全体** (実 `/etc` を `cp -a` した 49 entry) | `/etc` | **0 件** |
| j | emptyDir **ディレクトリ全体** | `/etc/security` (中に `pwquality.conf`) | **0 件** |
| g | emptyDir **ディレクトリ全体** | `/etc/sudoers.d` | **0 件** |
| h | emptyDir **ディレクトリ全体** | `/etc/pam.d` | **0 件** |
| f | mount なし (対照) | — | 0 件 |

読み取れること:

1. **`subPath` 固有ではない。** `hostPath` の素のファイル bind (d) が同じく 2 件発火する。
   → 「`subPath` をやめる」は**修正にならない**。
2. **path 固有でもない。** `/etc/sudoers` (e) も同じく発火する。
   → 「plant-target を `/etc/shadow` 以外の *ファイル* にする」も修正にならない。
3. **効いているのは「mount の destination が `sensitive_files` の一致対象か」だけ。**
   b は destination が一致対象でないので 0 件。
4. **ディレクトリ granularity の mount は 1 件も発火しない** (c/i/j/g/h)。
   これは経験則ではなく**構造**である —— deployed ruleset の `open_read` マクロは
   `fd.typechar='f'` (**通常ファイル**) を要求する
   (deployed `/etc/falco/falco_rules.yaml`。表示用抽出は `challenges/03-stealth-read/rule.yaml:47`)。
   **ディレクトリの open は原理的に `open_read` を満たせない。**
   → catalog の `open_read` 系ルール (`Read sensitive file untrusted` /
   `Search Private Keys or Passwords`) は、**ディレクトリ destination の mount では踏めない。**
   (VP が deployed ruleset を独立に読んで確認済み, 2026-08-19)

### C3. ディレクトリ mount にしても **ミッションは全部生きる** (実測)

「発火を消す」だけなら簡単だが、02 / 03 / 09 / 10 の想定解が死んだら意味がない。
probe i (`/etc` を実 `/etc` の `cp -a` コピーで丸ごと mount) で確認した:

| 検証 | 結果 |
|---|---|
| `cat /etc/shadow` → `Read sensitive file untrusted` | **発火する** (mission 02 の trigger / 03・10 の forbidden がそのまま成立) |
| `ln /etc/shadow /etc/.cache.bak` | **成功** (`links=2`) かつ `Create Hardlink Over Sensitive Files` **発火** (mission 09) |
| `id` / `getent passwd root` / `getent hosts kubernetes.default.svc` | 正常 |
| kubelet の `/etc/hosts` / `/etc/hostname` / `/etc/resolv.conf` overlay | **/etc volume mount の上に正しく重なる** (`/etc/hosts` は Kubernetes-managed 内容) |
| `apk info -e busybox` / `cat /etc/os-release` | 正常 (49 entry すべて復元) |
| `curl -k https://kubernetes.default.svc/api` | 401 (= 到達する。mission 01 の前提) |

**ADR-0001 §Options B2 が「実測必須 (仮説: 動く)」としていた 2 点
(kubelet の `/etc/hosts` overlay、`cp -a` の permission 保持) は、これで実測済みになった。**

### C4. 現行 B1 が mission 09 を壊していることも実測で確定した (ADR-0001 F4 の未解決点)

ADR-0001 は「`/etc/shadow` が bind mount だと `link()` が EXDEV になる」「**Falco が失敗した
`link()` でも発火するかは不明**」として、09 の plant-target を `/etc/sudoers` へ retarget した
(`challenges/09-hidden-cache/README.md:21-22` が参加者に「この環境では `/etc/shadow` は
別ファイルシステム上にあるため hardlink が作れない」と明記している)。実測結果:

- probe a (`/etc/shadow` が `subPath` bind): `ln /etc/shadow /tmp/x` → **EXDEV**、
  `ln /etc/shadow /etc/.c2` → **EXDEV** (同一 `/etc` 内でも失敗する)
- **その失敗した `linkat` でも `Create Hardlink Over Sensitive Files` は発火する**
  (Falco ログに `target=/etc/shadow linkpath=/tmp/x` の Warning が出た)

→ **B1 の下では「コマンドが失敗したのに trigger が solve する」状態が実在する。**
09 は現在 `/etc/sudoers` に retarget して回避しているが、これは B1 が作った制約への迂回であり、
本 ADR の Option 1 を採ると**不要になる** (`/etc/shadow` に戻せる)。

### C5. 却下方向の実証 —— 「proc 系フィールドでの除外」は fail-open である

VP の事前判断 (`proc.name` が `runc*` のイベントを ingest で除外する案は fail-open) を
**実測で裏づけた。反論しない。**

参加者は challenge コンテナで root で、rootfs は書き込み可能である。probe f (mount 無しの
素のコンテナ) の中から、participant 側の操作だけで次のイベントを作れた:

| フィールド | 本物 (deploy 時) | **参加者が偽装したもの** |
|---|---|---|
| `proc.name` | `runc:[1:CHILD]` | **`runc:[1:CHILD]` (完全一致)** |
| `proc.exepath` | `/usr/bin/runc` | 偽装した名前のパス ※ 別プロセスでは **`/usr/bin/runc` そのものも達成** |
| `proc.pname` | `runc` | 任意 (親プロセスの名前を作れば一致させられる) |
| `proc.cmdline` | `runc:[1:CHILD] init` | 任意 |
| `fd.name` | `/etc/shadow` | `/etc/shadow` |
| `user.uid` / `user.loginuid` | 0 / -1 | 0 / -1 (同じ) |

**手数は「image に既にある実行可能ファイルを 1 つ複製して実行する」程度である。**
`proc.name` (= comm) は **実行するファイルの名前で決まる**ので、
偽装したい comm と同じ名前のファイルを作るだけで一致する。
**具体的なコマンド列は意図的にここには書かない (ADR-0001 rev.6 の L1 と同じ線引き:
「何をするな」は公開・「どう回避が成立するか」の手順は private)。**
必要なら `falco-ctf-platform/docs/falco-detection-conditions.md` (private) に置く。

`proc.name` と `proc.exepath` の**両方**を同時に一致させるには `prctl(PR_SET_NAME)` が要るが、
**この CTF は mission 06 の expectedRule が `Drop and execute new binary in container`
(`challenges/06-web-rce-shell/falco-rule.yaml`) であり、バイナリを持ち込んで実行することを
参加者に明示的に教えている。** よって「参加者は comm と exepath を同時に制御できない」は
防御根拠として成立しない。

→ **`proc.*` に依存する除外 (ingest 側でも rule 側でも) は、そのまま検知回避の手口になる。却下。**

### C6. 「非偽装フィールドでの区別」(VP 案 (b)) が成立しない構造的理由

deploy 由来イベントの output_fields のうち **参加者が改竄できないもの**は
`container.id` / `container.image.repository` / `container.image.tag` / `container.name`
(= `k8s_challenge_workspace_<ns>_<poduid>_0`) / `k8s.pod.name` / `k8s.ns.name` / `k8smeta.*` だけである。
そして **これらはすべて、同じ参加者が同じコンテナで `cat /etc/shadow` したときと完全に同一の値になる**
(probe で両方のイベントを取得して照合済み)。

- **`container.name` での除外も不可** —— runc の mount setup は **challenge コンテナ自身の rootfs 構築**なので、
  Falco はそれを challenge コンテナに帰属させる (probe では各コンテナの fire がそのコンテナ名で出た)。
  VP の「container 名で除外も危険」という判断は、**より強い形で正しい**:
  危険なだけでなく**効かない**。
- 残る候補は (i) 偽装可能な `proc.*` = C5 で却下、(ii) **時間窓** (`container.start_ts` との差など) =
  VP が明示的に排した方向であり、かつ ADR-0001 の「定理」(参加者は container が Running になった瞬間から
  exec できる) と同じ理由で race を作る、(iii) Falco の output template に新フィールドを足す =
  **`POST /falco/events` の payload はクロスリポ契約** (`.claude/rules/falco-ctf-app-conventions.md`
  Cross-repo 契約表の Webhook payload 行) なので両リポ同時 PR を要し、しかも足せるのは結局 (ii) の時間情報。

→ **区別に使える情報はイベントの中に存在しない。** (b) は「まだできない」ではなく
**「原理的に採れない」**。採点側での事後区別は放棄し、**イベントを作らない**方向で閉じる。

### C7. 副産物の finding 2 件 (本 ADR の決定には影響しないが記録する)

1. **表示用抽出 `challenges/*/rule.yaml` が deployed ruleset と乖離している。**
   `challenges/03-stealth-read/rule.yaml:1-2` の `sensitive_files` は
   `(fd.name startswith /etc and fd.name in (sensitive_file_names)) or fd.directory in (...)` だが、
   deployed Falco 0.43.1 の `/etc/falco/falco_rules.yaml` は
   `(fd.name in (sensitive_file_names) or fd.directory in (/etc/sudoers.d, /etc/pam.d))` で
   **`startswith /etc` 節が無い** (architect が実機で確認、VP が独立に再確認)。
   → **ADR-0001 の read-path 7 (F5) の *理由づけ* はこの stale な抽出に依拠している**
   (「seed root を mount すると `fd.name` が `/etc` 始まりでなくなるから外れる」)。
   **結論 (seed root を mount しない) は変わらない** —— `fd.name in (sensitive_file_names)` は
   exact-list 照合なので `/plant-seed/etc/shadow` はやはり一致しない —— が、**根拠文は誤り**である。
   conventions の「Falco バージョンを上げたら rule.yaml を再抽出」規約の未実施分。
   → follow-up issue (owner = content-engineer / qa-engineer)。
2. **`fd.directory in (/etc/sudoers.d, /etc/pam.d)` 分岐は実際に発火する** (probe g/h/f で確認)。
   よって将来 `/etc/pam.d/<x>` や `/etc/sudoers.d/<x>` を **ファイル granularity** で mount すると
   同じ欠陥が再発する。本 ADR の I13c はこれも閉じる。

### C8. 壊してはいけないもの

ADR-0001 §制約 C1-C8 を継承する (C1 = 1 workspace で全ミッション / C2 = `FLAGS_FILE` と
`CTF_FLAG_*` の単一ソース / C3 = `plant.sh` が唯一の正典・実値を書かない / C4 = `values*.yaml` は生成物 /
C5 = I5・I7・I9・I10 / C6 = `deploy-user.sh` の引数契約 / C7 = egress lockdown + ttyd exec /
C8 = mission 02・03・05・09・10 の想定解)。
**加えて本 ADR は ADR-0001 の I12 (フラグ隔離) と read-path 7 (F5) を壊してはならない。**

---

## Options

### Option 1 — plant-target を **最小の enclosing directory** で mount する 【推奨・VP 承認済 2026-08-19】

**変更点**: `plant.mounts` の要素を「plant-target のパス」から
「**plant-target を含む最小のディレクトリ**」に変える。plant-target が既にディレクトリなら
それ自身 (mission 05 の `/root/.ssh` は**現状すでにこの形**)、ファイルならその親ディレクトリ。

| plant-target | 現行 mount (B1) | Option 1 の mount |
|---|---|---|
| `/etc/shadow` (03 / 10 が共有) | `/etc/shadow` (`subPath: etc/shadow`, **file**) | **`/etc`** (`subPath: etc`, **dir**) |
| `/root/.ssh` (05) | `/root/.ssh` (dir) | `/root/.ssh` (**変更なし**) |

これに伴い必要になるもの:

1. **build 時 snapshot (ADR-0001 S-a) の対象をディレクトリ全体に広げる** ——
   `/opt/ctf/plant-seed/etc/shadow` (1 ファイル) → `/opt/ctf/plant-seed/etc/` (image の `/etc` 全体)。
   snapshot は image build 時に作るので **Falco イベントは出ない**
   (I13 の外延に image build は含まれない = ADR-0001 rev.4 M6)。
   snapshot に**フラグは入らない** (フラグは runtime に Secret から seed へ append される) ので I12 に触れない。
2. **`plant` の seed 初期化を「ディレクトリごと復元 → append」に変える** ——
   `cp -a /opt/ctf/plant-seed/etc/. "$PLANT_SEED_ROOT/etc/"` → その後 03 / 10 が `>>` で append。
   **読む側の path は `/opt/ctf/plant-seed/etc/shadow` であって `/etc/shadow` ではない**ので
   `fd.name in (sensitive_file_names)` に一致せず、ADR-0001 §F3′
   (deploy 経路が Falco イベントを 1 件も出さない) を満たす。
   ⚠ **逆に、実 `/etc` を runtime に読む形 (`cp -a /etc/. ...`) にすると 4 件発火する** ——
   probe の seed コンテナで実測した (`/etc/shadow` / `/etc/sudoers` /
   `/etc/pam.d/` 配下 2 件)。**§F3′ の禁止は実在の穴に対するものである。**
3. **`gen-values.sh` の mount 生成規則を「plant-target → enclosing directory」に変え、
   dedupe を親ディレクトリ単位で行う** (03 と 10 はどちらも `/etc` に落ちるので 1 エントリ)。
4. **`readOnly` を落とす** —— `/etc` は書き込み可能でなければならない
   (mission 07 / 09 が `/etc` 配下に書く)。ADR-0001 rev.4 L2 が `readOnly: true` に期待していた
   「planted 行数 = 2 の assert 安定化」は失う (下記 Consequences)。
5. **mission 09 を `/etc/shadow` に戻せる** (C4)。ただしこれは**別 PR / 別判断**にする
   (参加者向け記述と難易度に触れるので content-engineer + product-engineer の領域)。
   本 ADR は「戻せる」ことだけを記録する。

- **コスト**: chart は `subPath` の与え方が変わるだけ (数行) / `gen-values.sh` の生成規則 /
  `images/challenge/Dockerfile` に snapshot 行 1 本。
  **イメージサイズ**: image の `/etc` の複製 1 部 (実測 49 entry、数十 KB オーダー) → 無視できる。
  **依存**: 増加ゼロ。**新規イメージ**: なし (I5 不変)。
  **認知コスト**: 「plant-target はファイル単位で宣言するが mount はディレクトリ単位」という
  一段の間接。これは `gen-values.sh` が導出するので challenge 作者には見えない。
  **参加者向け content の変更: ゼロ** (path が一切変わらない)。
- **リスクと可逆性**: 可逆 (mount 定義と生成規則を戻すだけ)。
  主要リスクは **snapshot と image `/etc` の drift** —— snapshot 後に `/etc` を書く `RUN` 行が入ると
  challenge の `/etc` が古くなる。これは **`make check-image-hygiene` (ADR-0001 2-8) の対象を
  `/opt/ctf/plant-seed/` ツリー全体 = image の対応ディレクトリと mode/owner 一致まで広げることで
  機械的に閉じる** (既存の検査の拡張であり新機構ではない)。
  第 2 のリスクは **`/etc` が emptyDir 由来になること** —— probe i で
  users / DNS / apk / os-release / kubelet overlay を実測し正常を確認済み (§C3)。
- **効き始める閾値**: **次の deploy の 1 発目**。修正前は 100% の workspace が deploy 時に
  mission 02 を無償で獲得する (VP 実測)。

### Option 2 — フラグを `/etc/security/pwquality.conf` に移し、`/etc/security` をディレクトリ mount する

**変更点**: plant-target を `/etc/shadow` → `/etc/security/pwquality.conf` にし、
`/etc/security` をディレクトリ granularity で mount する。`pwquality.conf` は
`sensitive_file_names` の 4 要素の 1 つなので **読み取りは同じ `Read sensitive file untrusted` を
発火させる** (probe j で実測: mount 時 0 件・読み取りで発火)。

- **コスト**: mount の blast radius が Option 1 より**格段に小さい** (`/etc` 全体ではなく
  `/etc/security` のみ。ただし image の `/etc/security` には pam 系ファイルが実在するので snapshot は必要)。
  一方で **参加者向け記述の書き換えが発生する** —— `challenges/{03,10}/README.md` / `journey.yaml` /
  `fixtures/welcome.txt` / `docs-site` のミッションページ + PDF 再生成 + platform private の
  `docs/falco-detection-conditions.md`。ADR-0003 §Consequences F2 のインベントリが示すとおり、
  **参加者可視テキストの追随漏れは実証済みの失敗モード**である。
  加えて **product-engineer (ミッションの意味論・難易度) と content-engineer (文言) と CEO
  (参加者体験の変更) の判断**を要する。
- **リスクと可逆性**: 可逆。リスクは「`/etc/shadow` に credential がある」という題材の説得力低下
  (03 は「shadow を静かに読む」課題であり、`pwquality.conf` は同じ説得力を持たない = **出題品質の劣化**)。
- **効き始める閾値**: Option 1 の `/etc` 丸ごと mount が運用上壊れたとき (下記 Signpost 2)。

### Option 3 — 現行 B1 のまま、暫定運用で回避する (deploy → admin reset → 開始)

**変更点**: コードを変えない。全 workspace の deploy 完了後・参加者開始前に
**admin の「全体リセット」を 1 回実行**して I13a の delta を消す。

- 根拠: `Store.Reset()` は `solved` / `exfil` / `hint_views` / `step_checks` / `evade_dirty` を削除する
  (`internal/store/store.go:874-901`) ので、**初回 deploy 由来の汚染は完全に消える**。
- **コスト**: ゼロ (コード変更なし)。ただし運用に 2 つの恒久制約が付く:
  1. **イベント中の再 deploy を禁止する** (LIVE hotfix / scale-to-0 復帰は 2026-08-16/17 に実在した運用)。
     再 deploy すると `current` が evade のとき恒久 taint が付く。全体 reset は全員の進捗を消すので使えず、
     per-user の `reset-dirty` を admin が **portal から**押すしかない
     (`POST /api/users/{user}/challenges/{cid}/reset-dirty` は origin-guard 付き
     (`internal/scoreboard/api/api.go:332`) なので **curl では 403**)。
  2. `current` が 10 の参加者を reset すると **exfil receipt も消える** (ADR-0003 A2-2) →
     **フラグ再配送**が必要。
- **リスクと可逆性**: 完全に可逆だが、**t=0 の時間圧下での運用者規律に採点公平性を賭ける**。
  2026-08-16 の stand-up と 2026-08-17 の teardown でいずれも runbook 乖離が発生している。
  さらに **admin reset を忘れた場合、参加者全員が mission 02 を無償で得た状態で開始し、
  誰も気づかない** (portal は「CLEARED」と表示するだけ) = **fail-open**。
- **効き始める閾値**: 修正が次の stand-up に間に合わないと確定した時点。**それまでは採らない。**

---

## Decision

**Option 1 を採る** (VP 承認 2026-08-19) —— `plant.mounts` を **ディレクトリ granularity** に限定する
(現行カタログでは `/etc/shadow` の mount を `/etc` に、`/root/.ssh` は現状維持)。
理由: **`open_read` が `fd.typechar='f'` を要求するので、ディレクトリ destination の mount は
catalog の read 系ルールを構造的に踏めない —— 参加者可視の path も出題内容も 1 文字も変えずに、
欠陥の原因を消せる唯一の選択肢である。**

**Option 3 (deploy → admin reset) は「Option 1 が次の stand-up に間に合わない場合の明示的な暫定」として
記録するが、既定の運用にはしない** (VP 裁定)。採用する場合は **CEO 判断**とし、
runbook に上記 2 制約を明記することを条件とする。

**Option 2 は棄却しない (fallback として保持する)。** Signpost 2 が観測されたら Option 2 に切り替える。

---

## Consequences

### 諦めたもの

- **`/etc` の `readOnly: true` を諦めた。** ADR-0001 rev.4 L2 が期待していた
  「参加者が `/etc/shadow` に append できないので planted 行数 = 2 の assert が安定する」性質は失う。
  **代替**: この assert は **deploy 時 (participant が exec する前)** に走るので、実害は
  「参加者が自分の `/etc/shadow` を壊して自分の 03 を解けなくする」自己損害のみ。フラグ実値は
  `FLAGS_FILE` と照合されるので**偽フラグを書いても solve できない**。
  → assert は「deploy 時点で行数 = 2」を見る形に限定し、**runtime 不変性は主張しない**。
- **image の `/etc` が「生成物の元データ」になった。** `/opt/ctf/plant-seed/etc/` が image `/etc` と
  一致していることが challenge コンテナの `/etc` の正しさの前提になる。**紙の規約にしない** ——
  `make check-image-hygiene` の機械検査で閉じる (下記 Verification 3)。
- **mission 09 の `/etc/sudoers` retarget を「今は」そのままにした。** `/etc/shadow` に戻せるが、
  参加者向け記述に触れるので本 ADR のスコープ外 (別 PR + content / product 判断)。
  **ただし `challenges/09-hidden-cache/README.md:21-22` の「この環境では `/etc/shadow` は
  hardlink できない」は Option 1 後に *虚偽* になる**ので、同 PR か直後の follow-up で直す必要がある
  (ADR-0003 F2 と同種の participant-visible drift)。

### 新たに守る不変条件 (候補)

> **I13c (候補・昇格条件は下記 Verification 1 + 2 + 4 の landing)**
> **`plant.mounts` のすべてのエントリは *ディレクトリ* でなければならない。**
> plant-target がファイルの場合、mount するのはそれを含む**最小のディレクトリ**であり、
> そのディレクトリの素データは **image build 時の snapshot** から復元する。
> **`plant-seed` の root は決して mount しない** (ADR-0001 F5 を継承)。
> 理由: ファイル granularity の bind mount は、destination が Falco の一致対象であるとき
> **container ランタイム自身が deploy ごとに検知イベントを生成する** (§C2 実測)。

ORGANIZATION.md の歯止め (「`Verification` が無い ADR を Hard Invariant に昇格させない」) に従い、
**機械強制が landing するまで I13c は候補のままとし、
`.claude/rules/falco-ctf-app-conventions.md` の表には追記しない。**

**I13a / I13b の昇格はこの修正の landing までブロックする** (VP 裁定 2026-08-19。
現状 FAIL しているので、昇格させたら「既知で偽の不変条件」になる)。
**I12 の昇格は独立に可能** (VP 承認 2026-08-19) —— 条件は下記 §Advice の「I12 について」節。

### runbook / 運用への影響

- **本番投入**: `main` は現在 B1 なので、**この修正が landing するまで prod に載せない**
  (載せると全参加者が mission 02 を無償で得る)。2026-08-16 のリハは env 注入方式だったので
  この欠陥は出ていない —— **「前回動いたから大丈夫」は成立しない。**
- Option 3 を暫定採用する場合の runbook 追記 2 点 (上記 Options 参照): ①deploy 完了後に
  admin 全体リセットを 1 回、②イベント中の再 deploy 禁止 / やむを得ない場合は portal から
  per-user reset-dirty (`requireExfil` 課題ではフラグ再配送)。
- **ADR-0001 Verification layer 4 (E2E) は「deploy 後に catalog ルール由来の fire が 0」を
  必ず含める** —— 現状の ADR-0003 (d) / ADR-0004 (d′) はこの欠陥に対して盲目だった
  (ADR-0001 rev.3 の指摘どおり)。本 ADR はそれを**必須 gate**として再確認する。

---

## Signposts

この決定 (Option 1) を覆す**観測可能な信号**:

1. **`plant.mounts` に、素データを snapshot から復元できないディレクトリが必要になる** ——
   例: plant-target が `/var/lib/<stateful>/x` のように**実行時に生成されるディレクトリ**の中に入る、
   あるいは snapshot 対象が数 MB を超えて image / emptyDir のサイズが問題になる。
   → ディレクトリ mount が破綻する。**Option 2 (plant-target 自体を移す) が唯一解になる。**
2. **`/etc` をディレクトリ mount したことに起因する障害が 1 件でも出る** ——
   具体形: 参加者の workspace で DNS / user 解決 / `apk` / TLS 証明書のいずれかが壊れる、
   `check-image-hygiene` が snapshot drift を検出する、または kubelet の
   `/etc/hosts` overlay 順序が k8s / containerd の版差で変わる。
   → **Option 2 に切り替える** (`/etc/security` は数ファイルなので blast radius が桁違いに小さい)。
3. **deploy 後の Falco ログに catalog 由来のルール名が 1 本でも出る (件数ではなくルール名で見る)** ——
   Option 1 が閉じたのは `open_read` 系だけである。`linkat` / `execve` / network 系の
   catalog ルール (`Create Hardlink Over Sensitive Files` /
   `Drop and execute new binary in container` / `Contact K8S API Server From Container` 等) を
   deploy 経路が踏む変更が入れば、同じクラスの欠陥が再発する。
   → **I13b の外延を「mount 以外の deploy 経路」に広げ、layer-4 E2E を required check に上げる。**
4. **`sensitive_file_names` / `sensitive_files` / `open_read` が Falco の版上げで変わる** ——
   deployed ruleset の macro が変わり、いま安全な mount destination
   (`/etc` / `/root/.ssh` / `/etc/security`) のいずれかが一致対象になる、
   または `fd.typechar` 条件が緩む。
   → **「ディレクトリなら安全」という構造的前提が崩れる。** ruleset 版と `plant.mounts` の
   交差検査 (Verification 4) を required に上げる。

---

## Verification

**機械で確認する方法。1 + 2 + 4 が landing した時点で I13c を Hard Invariant に昇格できる。**

### 1. `plant.mounts` の静的 assert (fail-closed) 【昇格の必須条件】

`challenges/gen-values.sh --check` (CI `flag-guard` から呼ばれる。ADR-0001 Verification 2 の枠) に追加:

- 生成された `plant.mounts` のすべての要素について、**`plant` の seed ツリー上で対応するパスが
  ディレクトリであること**を assert する。1 件でもファイルなら **非ゼロ終了**。
- `plant.mounts` に `/` および seed root 相当が現れたら非ゼロ終了 (ADR-0001 F5 の継承)。
- **抽出結果の非空を assert する** —— `plant.mounts` が空集合のとき「違反なし」で緑にしない
  (all-missions モードでは必ず 1 件以上ある)。空なら非ゼロ終了。
- **判定は exit status で行う** (出力文字列の有無で判定しない)。

### 2. 故意違反の negative test 【昇格の必須条件】

`plant.mounts` に **ファイル granularity のエントリを 1 つ持つ fixture values** を用意し、
上記 assert が **非ゼロで落ちることをテストとして恒久化**する
(`make test` に載せる = required check `test` に相乗り)。
**この negative test が無い assert は「永久に緑」になりうるので、assert 本体と同一 PR で入れる。**

### 3. snapshot drift の検査 (既存検査の拡張)

`make check-image-hygiene` (ADR-0001 2-8。`make build` から fail-closed で呼ばれる) の対象を
`/opt/ctf/plant-seed/` **ツリー全体**に広げ、**mount 対象ディレクトリについて
image の対応ディレクトリと entry 集合・mode・owner が一致すること**を assert する。
→ 「snapshot 後に `/etc` を書く `RUN` が入った」を build 時に落とす。

### 4. cluster E2E (ADR-0001 layer 4 / ADR-0004 の run に相乗り) 【昇格の必須条件・実機のみ】

**ADR-0003 Verification (d′) と同一 run 内**で、deploy 直後に:

- **I13a**: deploy 前後で `solved` / `evade_dirty` / `exfil` の **delta が空**であること
  (進行中の再 deploy では `solved` は空でないのが正常なので delta で見る = ADR-0001 rev.5 N5)。
  **deploy のみの新規 user については絶対値で `solved=0`** を assert する。
- **I13b**: settle window (Falco / scoreboard が Running であることを事前確認した上で) 後、
  **Falco DaemonSet の stdout / falcosidekick を一次ソース**として
  **catalog の `expectedRules` ∪ `forbiddenRules` (現在 9 本) のルール名が 1 本も現れない**こと。
  **禁じ手集合は catalog から導出し、ハードコードしない** (ADR-0001 rev.5 N6)。
- **進行中の再 deploy の回帰**: `current` が evade (03) の user を再 deploy し、
  `dirty=false` のままであることを assert する。**これが今回の欠陥の本体なので、
  E2E に入っていなければ同じ欠陥が再発する。**
- 非 catalog ルールの発火は **構造的に I13a を破れない** (`RecordRuleFire` はルール名を見ないが、
  solve / taint は catalog のルール名一致を要求する = ADR-0001 rev.4 H3) ので、
  **絶対 0 ではなく「catalog 由来 0」で判定する**。

### 5. 検査の自己検証 (規律)

上記 1-4 のいずれについても、**故意に違反させて赤くなることを実出力で示す**まで
「検査がある」と書かない。2026-08-19 の本件は「ユニットテスト全 green で通過した欠陥」であり、
**単体テストではこのクラスの回帰を検出できない**ことの 2 例目である
(1 例目 = app#124 / ADR-0003)。

---

## Advice

### 受けた助言

- **qa-engineer (2026-08-19)**: ローカル $0 E2E で本欠陥を発見。deploy のみの user の `solved=1`、
  進行中 user の再 deploy による 03 の `dirty` 反転を Phase 4 相当で直接再現。
  **mission 10 側は未再現 (推論)** と明示した —— 本 ADR もそれを推論として扱う
  (10 の forbiddenRules に同一ルールが含まれる (`challenges/10-final-exfil/falco-rule.yaml`) ので
  同型のはずだが、Verification 4 で実測する)。
- **VP (2026-08-19)**: Falco ログと `/api/state` を独立に読んで再現確認。
  **`proc.name` / container 名による除外は fail-open** という事前判断を提示
  (→ §C5 / §C6 で実測裏づけ。**反論しない**)。
  「偽陽性を honest path に、偽陰性を exploit path に落とす緩和は採らない」という
  ADR-0003 の基準を再確認 (→ 本 ADR も同基準で Option 3 を既定にしなかった)。
  ADR-0001 は Accepted なので本文を編集せず**後継 ADR で supersede**する方針 (→ 採用)。
  **deployed ruleset を独立に読んで `open_read` の `fd.typechar='f'` 要求と
  `sensitive_files` に `startswith /etc` が無いことを確認** (→ §C2-4 / §C7-1 の裏づけ)。
  **Option 1 承認 / I12 の先行昇格を承認 / I13a・I13b の昇格ブロック維持 /
  本番投入は Option 1 landing まで不可 (CEO へ上げる)** を裁定。
- **security-engineer (未実施)**: 本 ADR は **`plant` の mount 面と challenge コンテナの `/etc` の出自**を
  変えるので、**独立監査が必要**。特に見てほしい点:
  1. `/etc` を emptyDir 由来にすることで **I12 (フラグ隔離) と read-path 7 (F5) が壊れていないか**
     (architect の判定: 壊れない。mount するのは seed の `etc` サブツリーであって seed root ではなく、
     `/opt/ctf/plant-seed/etc/` の snapshot にはフラグが入らない)
  2. `/etc` が書き込み可能になることで**新しい特権昇格経路**ができないか
     (challenge は既に root であり、image layer の `/etc` も現状すでに書き込み可能である)
  3. §C5 の記述範囲。**architect の判定: 「`proc.name` は偽装できる」という事実と、
     除外案を却下する根拠として必要な範囲までを公開し、実行可能な手順は書かない。**
     ADR-0001 rev.6 の L1 と同じ線引き。詳細が必要なら
     `falco-ctf-platform/docs/falco-detection-conditions.md` (private) に置く

### I12 について

**I12 は独立に昇格できる (VP 承認 2026-08-19)。ただし条件付き (yes, if)。**

- **成立している根拠 (VP 実測)**: challenge の env に `CTF_FLAG` ゼロ / `/proc/1/environ` ゼロ /
  SA token なし / `/plant-seed` 不可視 / `/etc/shadow` は read-only。
  これらは **mount granularity と独立**であり、本 ADR の修正で 1 つも変わらない
  (`/etc/shadow` の read-only だけは Option 1 で失われる —— **だから下記の条件が付く**)。
- **条件 (これを満たさずに昇格させない)**:
  1. **I12 の本文を「到達可能性」で書く** —— 「`subPath` 完全一致」「`readOnly: true`」のような
     **機構**で書くと、Option 1 が landing した瞬間に**自分で書いた不変条件を破る**ことになる。
     書くべきは「challenge コンテナから、planted file を実パスで読む以外の経路でフラグに到達できない」。
  2. **`readOnly: true` に依拠している assert (ADR-0001 Verification 1-18 相当) を
     granularity 中立に書き直す** ——
     「`plant.mounts` は宣言済み plant-target を含む最小ディレクトリのみ / seed root を含まない」。
  3. **I12 の本文に deploy 経路の無汚染 (I13a / I13b) を一切含めない** ——
     含めると FAIL している主張を昇格させることになる。
- **昇格させる価値は高い**: I12 が閉じているのは ADR-0001 の**本決定**の成果であり、
  今回の欠陥は**派生決定 (mount 方式)** の欠陥である。両者を混ぜて全部を保留にすると、
  「Option B は失敗だった」という誤った教訓が残る。**Option B は正しく、B1 が間違っていた**
  (VP 支持, 2026-08-19)。

### 番号と scope の裁定

- **番号 = ADR-0007 で確定** (2026-08-25 訂正: 0005/0006 は他ADRがAccepted済みで確保、
  app#144 [OpenAPI parity gate の supersede] は 0006 との衝突判明後 ADR-0008 に再割番済み。
  上記コールアウト参照)。
- **scope = ADR-0001 の派生決定 (1) の B1 のみを supersede する。**
  ADR-0001 の Status は **Accepted のまま**で、本文は編集しない。索引 (`docs/adr/README.md`) の
  ADR-0001 行の「部分 supersede」欄に本 ADR へのポインタを 1 行足す
  (**navigational な追記は ADR-0003 が定めた例外**であり、決定内容を変えない)。
- **ADR-0001 を Superseded にはしない。** 本決定 (Option B) は生きており、
  DoD の大半 (I12 側の機械強制 3 層) も生きている。
