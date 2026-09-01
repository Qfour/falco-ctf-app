<!--
falco-ctf 当日の導入プレゼン (約 20-25 分)。

Markdown スライド (`---` で区切り)。そのまま読んでも、Marp / Slidev /
reveal-md で render しても OK。

Marp で PDF にする例:
  npx @marp-team/marp-cli --pdf --allow-local-files PRESENTATION.md

進行イメージ:
  P1-P2  自己紹介・本日のゴール       2 min
  P3-P6  なぜ runtime セキュリティか  5 min
  P7-P9  Falco アーキテクチャ          4 min
  P10-13 List / Macro / Rule           10 min   ← 中核
  P14-15 検知と回避の表裏              4 min
  P16    Hands-on へ                   1 min

スライド本文の下に `> speaker:` ブロックを置いた箇所は登壇メモ。
-->

---
marp: true
theme: default
paginate: true
backgroundColor: "#1E1E22"
color: "#FFFFFF"
style: |
  section { font-family: 'Mulish', 'Inter', sans-serif; }
  h1, h2, h3 { color: #BDF78B; }
  code { background: #2B2D30; color: #BDF78B; padding: 1px 6px; border-radius: 3px; }
  pre { background: #2B2D30; border-radius: 6px; padding: 1em; }
  table { border-collapse: collapse; }
  th, td { border: 1px solid #3E4042; padding: 6px 10px; }
  th { background: #2B2D30; color: #BDF78B; }
  a { color: #BDF78B; }
---

# Falco CTF

### Runtime security, hands-on.

<br>

参加者ハンドブック: `/opt/ctf/INDEX.txt` → `/opt/ctf/missions/<NN>-<slug>/fixtures/welcome.txt`

> speaker: 今日の流れ — まず 25 分で **「Falco とは何か / なぜ要るか /
> ルールはどう書かれているか」** を話します。その後すぐにワークスペースに
> 入って 5 つのチャレンジを解いていただきます。

---

## 本日のゴール

1. **「runtime security とは何か」** を、実例ベースで理解する
2. **Falco のルール構造 (List / Macro / Rule)** を読めるようになる
3. その理解を使って **CTF 5 問** を解く
   (= 攻撃側 = ルールを発火 / 回避 の両視点)

> speaker: 単にツールの使い方ではなく、**「攻撃者がどう動くか」「防御側は
> 何を見ているか」** を体で覚える 60 分。

---

# Part 1 — なぜ runtime security?

---

## コンテナセキュリティのスタック

```
  ┌──────────────────────────┐
  │  Image build / scan       │  ← CVE / SBOM / 署名検証
  ├──────────────────────────┤
  │  Admission (Pod 起動時)   │  ← PSA / OPA / Kyverno
  ├──────────────────────────┤
  │  Runtime  ← 今日ここ      │  ← syscall / プロセス挙動
  └──────────────────────────┘
```

scan も admission も **「ビルド時 / 起動時に正しいことを保証」する仕組み**。
動き出した後、コンテナの中で何が起きるかは別の話。

> speaker: 「Image scan で CVE ゼロでも、コードが正規でも、 攻撃者が
> ハイジャックすれば中で `cat /etc/shadow` は走る」。

---

## 起動後に何が起きるか — 攻撃の現実

**典型シナリオ**:

1. Web アプリの SSRF / RCE 脆弱性で初期侵入
2. コンテナ内で **`/etc/shadow` や `~/.aws/credentials` を読む**
3. そこで得た credential で **lateral movement** (別 Pod / 別アカウント)
4. **マイナー or バックドアを常駐**

これらは **コンテナイメージ自体は何も悪くない**。**攻撃者の挙動** だけが異常。

> speaker: 攻撃者目線で見ると、image scan を通った正規のシェルや curl を
> 「目的外の使い方」するだけ。signature でも CVE でも捕まらない。

---

## 「正規バイナリの目的外使用」を見抜くには

選択肢:

| アプローチ | 限界 |
|---|---|
| ファイルアクセス監視 (auditd) | ログ膨大 / Pod 単位の文脈が無い |
| API server audit | Pod 内部の挙動は見えない |
| Sidecar IDS | 1 Pod 1 サイドカー → コスト爆増 |
| **Falco (eBPF カーネル観測)** | **1 ノード 1 DaemonSet で全 Pod カバー** |

Falco は **kernel に近い syscall を eBPF で観測** → ルール照合 → 即時アラート。

> speaker: eBPF は kernel 4.x 以降の標準機能。Falco は modern-eBPF (CO-RE)
> なので、ノードごとのカーネルヘッダ不要。

---

# Part 2 — Falco アーキテクチャ

---

## 全体図

```
  [container]   syscall   [host kernel]
      │  ─────────→ ─────→
      │                  ┌──────────────┐
      └─────────────────►│ eBPF probe   │
                          │  (Falco DS)  │
                          └──────┬───────┘
                                 │  rule eval
                                 ▼
                          ┌──────────────┐
                          │ Falco engine │
                          └──────┬───────┘
                                 │  alert event
                                 ▼
                       stdout / webhook / etc.
                                 │
                                 ▼
                          (CTF: 今日の scoreboard)
```

Falco は **1 つの DaemonSet** として全ノードに配置。
コンテナ境界の内側で起きた syscall も、ホスト側カーネルから観測可能。

> speaker: 「アプリ側に何も組み込まない / SDK 不要」 が Falco の強み。

---

## Falco が見ているもの

- **すべての process exec** (`execve`)
- **すべての file open** (`open`, `openat`)
- **すべての network connect** (`connect`)
- **コンテナ・Pod の metadata** (CRI socket + Kubernetes API watcher)

イベント1件には、こんなフィールドが付いてくる:

```
fd.name = /etc/shadow
proc.name = cat
proc.pname = bash
proc.cmdline = cat /etc/shadow
container.image.repository = falco-ctf/challenge
k8s.ns.name = ctf-alice
k8s.pod.name = workspace
```

CTF ではこの中の `k8s.ns.name` + `container.image.repository` で
**誰の操作か**を scoreboard が特定している。

> speaker: 後で「攻撃者は **どのフィールドをコントロールできるか**」が
> 鍵になる、と話します。

---

# Part 3 — Falco ルールの 3 要素

---

## ルールは 3 つの部品からできている

```
List   →  ただの値の集合     (例: 危険なファイル一覧)
Macro  →  再利用可能な条件式 (例: 「open で read 用に開いた」)
Rule   →  発火条件 + 出力    (この組み合わせが発火したら alert)
```

それぞれ独立に書ける → 編集・再利用しやすい。

> speaker: Linux の audit ルールが「条件直書き」なのに対して、
> Falco は List/Macro/Rule で **「人間が読める」「テストできる」**形に
> 設計されている。

---

## List — 名前付きの値リスト

```yaml
- list: sensitive_file_names
  items: [/etc/shadow, /etc/sudoers, /etc/pam.conf]

- list: shell_binaries
  items: [bash, sh, dash, zsh, ksh, ash]

- list: shell_mgmt_binaries
  items: [httpd, nginx, apache2, postgres, mysqld, php-fpm]
```

ただの YAML 配列。**「これは敵」「これは身内」をデータとして定義** する場所。

CTF で 04/05 がからむのが `shell_mgmt_binaries` (= 「shell を起こすのは
怪しい」プロセス名一覧)。

> speaker: List は誰でも書ける。組織ごとにカスタム List を足して
> 「うちの環境で『信頼できる』バイナリ」を定義していくのが運用パターン。

---

## Macro — 再利用可能な条件式

```yaml
- macro: open_read
  condition: >
    (evt.type=open or evt.type=openat) and
    evt.is_open_read=true and fd.typechar='f' and fd.num>=0

- macro: sensitive_files
  condition: >
    fd.name startswith /etc and
    (fd.name in (sensitive_file_names) or
     fd.directory in (/etc/sudoers.d, /etc/pam.d))
```

ここがポイント:
- `open_read` は **syscall レベル**の判定
- `sensitive_files` は **path レベル**の判定 — `fd.name startswith /etc` が
  入ってるところ、後で 02 の伏線になります

> speaker: Macro を組み合わせて Rule を作るので、Macro の境界をどう
> 引くかが「ルールの精度」に直結する。

---

## Rule — 発火条件 + 出力

```yaml
- rule: Read sensitive file untrusted
  desc: An attempt to read any sensitive file (e.g. files in /etc...)
  condition: >
    sensitive_files and open_read and
    proc_name_exists and
    not user_known_read_sensitive_files_activities
  output: >
    Sensitive file opened for reading by non-trusted program
    (file=%fd.name proc=%proc.name pid=%proc.pid …)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
```

3 つの部品が組み合わさって 1 つの Rule になる:

- **`sensitive_files`** (macro) — 対象ファイル判定
- **`open_read`** (macro) — open 系 syscall 判定
- **`not user_known_…`** (macro) — 既知の正規プロセス除外

> speaker: 注目してほしいのは `condition` の構造。これは「**人間が
> 読めるアラートの定義**」になっていて、組織独自のルールも同じ流儀で
> 書ける。

---

## 出力 — falcosidekick → scoreboard

Falco の alert は YAML 1 行から実体化されたあと:

```
stdout (ノード上のログ)
    ↓
falcosidekick (一段中継 / fan-out)
    ↓ Webhook (POST JSON)
今日の scoreboard (= /falco/events を受ける Go サービス)
    ↓
SQLite → ダッシュボード (admin only)
```

**solve 判定はこの経路で自動的に**:
scoreboard は ルール名 + k8s.ns.name + image.repository を見て、
「誰が」「どの課題を」発火させたかを 100ms 以下で記録します。

> speaker: 本番のシステムでは Sysdig Secure や PagerDuty / Slack に
> 飛ばすのが典型。CTF では「solve カウント」が出力先になっている。

---

# Part 4 — 検知 ⇄ 回避の表裏

---

## ルールの判定は「文字列」次第

CTF で扱う 7 ルール、それぞれ判定に使うフィールド:

| ルール | 判定するフィールド | 意味 |
|---|---|---|
| Contact K8S API Server From Container | `evt.type=connect` + dst ip | K8s API への匿名 connect |
| Read sensitive file untrusted | `fd.name` | open に渡した path |
| Search Private Keys or Passwords | `proc.cmdline` | コマンドライン文字列 |
| Run shell untrusted | `proc.pname` | 親プロセスの comm |
| Drop and execute new binary in container | `proc.is_exe_upper_layer` | overlay 追加層からの exec |
| Redirect STDOUT/STDIN to Network Connection | `dup` + ipv4/ipv6 fd | reverse shell の典型 |
| Create Hardlink Over Sensitive Files | `link` syscall | hardlink で sensitive を別 path 化 |

**全部、攻撃者が(間接的に)コントロールできる文字列**。

> speaker: ここが今日のキーフレーズ。「Falco は文字列マッチで判定する。
> その文字列を攻撃者がいじれるなら、ルールは抜けられる」。
> 攻撃者の発想と防御者の発想を **同じ語彙** で語れるのが Falco の良さ。

---

## CTF Company — 10 missions

> あなたは CTF Company の本番 K8s クラスタに潜入したペンテスター。
> 目標は本番 DB の master credential を盗み出すこと。
> CTF Company は **Falco を導入**している。**「見つからずに最後まで辿り着け」**。

ATT&CK のキルチェーン順 + trigger/evade の対 (5 ペア):

| # | Mission | 種類 | Falco rule | 想定難易度 |
|---|---|---|---|---|
| 01 | Initial Recon | trigger | Contact K8S API Server From Container | ★☆☆☆☆ |
| 02 | Credential Files | trigger | Read sensitive file untrusted | ★☆☆☆☆ |
| **03** | **Stealth Read** | **evade** | (02 の回避) | ★★☆☆☆ |
| 04 | Key Search | trigger | Search Private Keys or Passwords | ★★☆☆☆ |
| **05** | **Silent Search** | **evade** | (04 の回避) | ★★★☆☆ |
| 06 | Web RCE Shell | trigger | Run shell untrusted | ★★★☆☆ |
| 07 | Persist | trigger | Drop and execute new binary in container | ★★★☆☆ |
| 08 | C2 Beacon | trigger | Redirect STDOUT/STDIN to Network Connection | ★★★★☆ |
| 09 | Hidden Cache | trigger | Create Hardlink Over Sensitive Files | ★★★★☆ |
| **10** | **The Final Exfil ★BOSS★** | **evade** | **上記 7 ルールを同時回避** | ★★★★★ |

10 を解いた段階で、次の問い:
**「もし自分が運用者なら、このバイパスをどう塞ぐか?」**

> speaker: 「ルールを書く人 = ルールを抜く人」両方の視点を持って
> ほしい。今日はその基礎体力をつける場。10 を解けた人にはぜひ
> 「もし自分が SOC エンジニアなら 03 のバイパスをどう塞ぐか?」を
> 聞いてみる (= `fd.ino` ベースのルール / Sysdig Secure の rule
> chain 等)。

---

# Part 5 — 今から始めること

---

## ワークフロー

1. **ブラウザで `https://<your-username>.<domain>/`**
   → Dex ログイン (ユーザ名 + パスワード は配布カード)

2. **Web ターミナル (ttyd)** が開く

3. 最初の画面 — ログイン時に **`/opt/ctf/INDEX.txt`** が自動表示。
   そこから次のコマンドへ:
   ```bash
   cat /opt/ctf/missions/01-initial-recon/fixtures/welcome.txt
   ```
   10 ミッション全部が同じワークスペースに既に展開済み。

4. trigger 課題: コマンド実行 → 自動 solve
5. evade 課題: `source /opt/ctf/submit.sh && submit <mission-id> 'FALCO{...}'`

詰まったら Journey UI でヒントを段階解放 (気付き → 概要 → 解答)。

---

## チートシート (もう一度)

```bash
$FALCO_CTF_USER          # 自分のユーザ名
ls /opt/ctf/missions/    # 10 ミッション一覧
cat /opt/ctf/INDEX.txt   # ログイン時に自動表示される overview

# evade の提出
source /opt/ctf/submit.sh
submit <mission-id> 'FALCO{...}'
```

`PARTICIPANT-HANDBOOK.md` と `REFERENCE.md` は事前配布版。
ワークスペース内では `welcome.txt` を主軸に進めて OK。

---

# それでは — Have fun.

<br>

質問はいつでも運営に。

---

<!--
=========================================================================
登壇メモ (スライドには出さない)
=========================================================================

# よくある質問への即答リスト

Q: "本番でこのルールセットそのまま使える?"
A: Falco 公式 rules リポジトリの上に、組織固有の List を足して使う
   のが推奨。生のままだと false positive が多い (例: 監視エージェント
   が `/etc/shadow` を読みに行く運用は普通にある)。

Q: "Sysdig Secure と何が違う?"
A: Sysdig Secure は Falco + SaaS UI + 商用サポート + Posture (CSPM) +
   Vuln scan が統合された商用版。Falco OSS は検知エンジン単体。
   今日は OSS の世界だけで完結する。

Q: "eBPF って遅くない?"
A: 速い。1 ノード 1 DaemonSet で 10k events/s 程度まで余裕。CTF では
   100 人参加 × 数 events/sec ぐらいなので問題にならない。

Q: "ルール書くの大変そう"
A: 公式 rules リポジトリにすでに 200+ ルールあり、ほとんどの組織は
   そこに自社の List を足すだけで足りる。本気で書くのは滅多にない。

# タイムキープ (合計 25 分)

P1-P2   2 min  → 2 分経過
P3-P6   5 min  → 7 分経過
P7-P9   4 min  → 11 分経過
P10-P13 10 min → 21 分経過    ← ここで余ったら例を増やす
P14-P15 3 min  → 24 分経過
P16-P17 1 min  → 25 分経過

# CTF 中の運営アクション

1. 全員が welcome.txt を読み始めるのを確認
2. 5-10 分後 「みなさん 01 解けてますか?」と声かけ
3. evade 課題 (02 / 05) で詰まった人がいたら個別に Journey UI の 2 段目ヒントを促す
4. 最後の 10 分で「あと 5 問残ってる方は Journey UI の 3 段目ヒントまで開いて OK」と告知
-->
