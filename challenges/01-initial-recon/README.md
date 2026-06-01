# 01 — Initial Recon

NimbusBreach のオープニング。参加者は侵入直後の Pod で「何かを書こうとした」
瞬間に Falco が反応することを体験する。

## ゴール (operator view)

Falco ルール `Modify binary dirs` をユーザ Namespace で発火させる。
ルールの condition: 書き込みオープン (`evt.is_open_write`) + 対象 dir が
`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` のいずれか。

## 想定解

```bash
touch /usr/bin/backdoor
# あるいは
echo > /bin/x
cp /bin/sh /usr/local/sbin/  # 注: /usr/local は対象外
```

`/usr/local/bin` は `bin_dirs` リストに**入らない**ことが多い (実装依存)。
標準 Falco rules では `/bin /sbin /usr/bin /usr/sbin` のみ。

## 解説

- 侵入直後の attacker は「書き込めるか」「root か」を試す
- これが即検知される事を知ると、その後の動きが慎重になる動機付け
- 次の 02 で「読むだけならどうか」という伏線
