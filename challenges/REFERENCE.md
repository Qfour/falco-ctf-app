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
| 発火条件 (大意) | 上記パターンを含むコマンドが exec された (結果は問わない) |
| 上記出題 | 03 (発火のみ) |
| 回避の発想 | 同 path に到達できる別のコマンドを使う / 文字列を分割する |

例:
```bash
find /tmp -iname id_rsa          # ← 発火 (cmdline に "id_rsa" を含む)
find / -name id_rsa 2>/dev/null  # ← 発火 (同上)
grep -rE 'BEGIN.*PRIVATE KEY' /etc 2>/dev/null   # ← 発火 (PRIVATE KEY パターン)
```

### 3.3 `Run shell untrusted`

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.pname` が `shell_mgmt_binaries` (`httpd`/`nginx`/`apache2`/`postgres` 等) |
| 発火条件 (大意) | shell プロセス (bash/sh/zsh ...) が起動された、かつその親 comm が「Web サーバ系の名前」 |
| 上記出題 | 04 (発火), 05 (回避) |
| 回避の発想 | `proc.comm` は **kernel が exec 時に basename から決める**。別名でインタプリタに渡せば comm を変えられる |

例:
```bash
# スクリプトファイルが /opt/ctf/httpd にあると仮定:
/opt/ctf/httpd                    # ← proc.comm = "httpd" → 発火
sh /opt/ctf/httpd                 # ← proc.comm = "sh"   → 発火しない
cat /opt/ctf/httpd | sh           # ← proc.comm = "cat" "sh" → 発火しない
. /opt/ctf/httpd                  # ← 現在の shell の中で動く (fork なし)
cat /opt/ctf/httpd                # ← 単に中身を見るだけ。何も exec しない
```

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
