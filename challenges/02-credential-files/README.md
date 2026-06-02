# 02 — Credential Files

「書き込めない」を知った attacker は「読み出すならどうだろう」を試す。
古典的な `/etc/shadow` の読み取りが Falco に検知されることを学ぶ。

## ゴール (operator view)

Falco ルール `Read sensitive file untrusted` を発火させる。条件: `fd.name`
が `sensitive_files` macro に一致 + `open_read` + プロセスが trusted リスト外。

## 想定解

```bash
cat /etc/shadow
# あるいは
less /etc/sudoers
head /etc/pam.d/su
```

## 解説

- ファイル中身ではなく **path 文字列** をルールが見ている
- これが 03 の核心 (同 inode を別 path で開けば抜けられる)
