# 03 — Stealth Read

02 で発火させた検知を、ここでは「中身は取得しつつ発火させない」方法
で抜ける。Falco ルールが **path 文字列** で判定する性質をついて、
同じ inode に別 path で到達する。

## ゴール (operator view)

`Read sensitive file untrusted` を**発火させずに** `/etc/shadow` 末尾の
flag を取得し、scoreboard に提出する。一度でも発火させると、この attempt
(このミッションが現在の課題になって以降) はずっと dirty のまま
(`/api/users/{user}/challenges/{cid}/reset-dirty` でやり直すまで解除されない)。

## Flag

postStart (`plant.sh`) で `/etc/shadow` 末尾に `# FALCO{...}` として追記。
実値はイベント毎に注入される (`CTF_FLAG_03_STEALTH_READ`)。ローカルでは
chart の dev default `FALCO{dev-stealth-read}`。

## 想定解

```bash
cat /proc/self/root/etc/shadow | grep FALCO
# fd.name = "/proc/self/root/etc/shadow" → /etc 始まりにならない → 抜ける
```

他にも `/proc/$$/root/etc/shadow`、bind mount、busybox 経由など複数解。

## 解説

- `/proc/<pid>/root` はそのプロセスの mount namespace の root を指す
  symlink。fd.name には resolved path ではなく **開く時に渡した path**
  が入る (Falco 実装) ので、`/etc` 始まりでない path を経由できれば抜ける
- 本番防御: `fd.ino` ベースのルール / Falco の他フィールド (`fd.inum`) を
  使うルールに切り替え
