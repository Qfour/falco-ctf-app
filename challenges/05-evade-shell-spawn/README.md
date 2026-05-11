# 05 — evade-shell-spawn

課題 04 で発火させた `Run shell untrusted` を **回避**しながら flag を取り出す。
`Run shell untrusted` は **`proc.pname` が `shell_mgmt_binaries`** (httpd, nginx,
apache2 等) かつ子が shell の時に発火する。

## 出題文

「`/opt/ctf/httpd` という名前のスクリプトが置いてある。その内部で
`/bin/sh -c 'echo <flag>'` が実行されるため、**そのまま `/opt/ctf/httpd`
として実行**すると `Run shell untrusted` が発火する。
実行せず、あるいは実行しても発火させずに flag を取得して提出せよ。」

## クリア条件

scoreboard `/api/challenges/05-evade-shell-spawn/submit` に正しい flag を POST し、
かつ過去 `windowSeconds=10` 秒間に `Run shell untrusted` が発火していないこと。

## 想定解(複数あり)

`proc.comm`(= `/proc/<pid>/comm`)は **kernel が exec 時に basename から決める**。
`/opt/ctf/httpd` を kernel に直接 exec させなければ `proc.comm=httpd` の
プロセスを作らずに済む。

```bash
# 解1: そもそも実行せずファイルを読む
cat /opt/ctf/httpd
# → 中身に /bin/sh -c "echo FALCO{...}" が見える

# 解2: 別名のインタプリタに食わせる(comm=sh / bash)
sh /opt/ctf/httpd

# 解3: パイプ渡し(httpd 自体が exec されないので proc.comm が httpd にならない)
cat /opt/ctf/httpd | sh
```

## 仕組みの解説 (講評用)

| 実行コマンド | proc.comm | 子 sh の proc.pname | 発火 |
|---|---|---|---|
| `/opt/ctf/httpd` | `httpd` (basename から) | `httpd` | ✗ 発火 |
| `sh /opt/ctf/httpd` | `sh` | `sh` | ○ 発火しない |
| `cat /opt/ctf/httpd \| sh` | `cat` (左) / `sh` (右) | `sh` | ○ 発火しない |

- ポイントは「**スクリプトファイルを kernel に exec させない**」こと
- 本番防御: ファイル名で comm を決められる挙動は OS 由来。Falco rule で
  `proc.exe` (実行ファイルパス) を使うか、`shell_mgmt_binaries` 一覧を厳密化する
- 攻撃者視点: マルウェアが `cron` や `systemd` 配下で動かすことで pname を
  「正規プロセス」に偽装する、というのは現実の手口

## 提出方法

```bash
source /opt/ctf/fixtures/submit.sh
submit 'FALCO{...}'
```

## ヒント (難易度別)

1. (易) `/opt/ctf/httpd` を読んでみる(実行はしない)
2. (中) 同じファイルを別の方法で実行する
3. (難) 攻撃者が逆にこれを利用して検知回避する例を 3 つ挙げよ
