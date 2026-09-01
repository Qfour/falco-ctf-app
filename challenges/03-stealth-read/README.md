# 03 — Stealth Read

02 で `/etc/shadow` を読んで `Read sensitive file untrusted` が発火することを
学んだ。同じ検知は `/etc/shadow` 専用ではない — CTF Company の SOC は
資格情報退避用の vault ファイルにも同じルールを効かせている。ここでは
「中身は取得しつつ発火させない」方法で抜ける。Falco ルールが **path 文字列**
で判定する性質をついて、同じ inode に別 path で到達する。

## ゴール (operator view)

`Read sensitive file untrusted` を**発火させずに** `/opt/nimbus/vault/creds.recover`
の flag を取得し、scoreboard に提出する。一度でも発火させると、この attempt
(このミッションが現在の課題になって以降) はずっと dirty のまま
(Journey 画面の「このミッションをやり直す」ボタンでやり直すまで解除
されない。時間では解除されない)。

## Flag

plant (initContainer) が `/opt/nimbus/vault/creds.recover` に flag だけを
書き込む(コメントや前後の内容は無し — `cat` すれば flag そのものが出る)。
実値はイベント毎に注入される。ローカルでは chart の dev default
`FALCO{dev-stealth-read}`。

## 想定解

```bash
cat /proc/self/root/opt/nimbus/vault/creds.recover
# fd.name = "/proc/self/root/opt/nimbus/vault/creds.recover" → 監視対象の
# path 文字列と一致しない → 発火せずに読める
```

他にも `/proc/$$/root/opt/nimbus/vault/creds.recover`、bind mount、busybox 経由
など複数解。

## 解説

- `/proc/<pid>/root` はそのプロセスの mount namespace の root を指す
  symlink。fd.name には resolved path ではなく **開く時に渡した path**
  が入る (Falco 実装) ので、監視対象の path 文字列と一致しない経由を
  使えれば抜ける
- 02 で見た `/etc/shadow` も、ここで見る vault ファイルも、Falco から見れば
  「同じルールが監視している path 文字列のどちらか」でしかない — path
  ベースの検知は対象ファイルが増えても同じ弱点を持ち続ける
- 本番防御: `fd.ino` ベースのルール / Falco の他フィールド (`fd.inum`) を
  使うルールに切り替え
