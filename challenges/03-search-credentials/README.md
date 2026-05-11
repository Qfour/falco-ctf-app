# 03 — search-credentials

Falco の `Search Private Keys or Passwords` ルール発火を体験する課題。
ルールは **`proc.cmdline` のパターン**を見ているので、ファイルの中身ではなく
「探す」行為そのものが検知される。

## 出題文

「攻撃者がよくやる『鍵ファイルや認証情報の探索』を再現せよ。
Falco に `Search Private Keys or Passwords` を発火させたらクリア。」

## クリア条件

ユーザの Namespace で Falco ルール `Search Private Keys or Passwords` が発火すること。

## 想定解

```bash
find /tmp -maxdepth 1 -iname id_rsa
# あるいは
grep -rE 'BEGIN.*PRIVATE KEY' /etc 2>/dev/null
# あるいは
find / -name id_rsa 2>/dev/null
```

ルールは `proc.cmdline` が `id_rsa` / `id_dsa` / `BEGIN.*PRIVATE KEY` 等の
パターンに一致するかを見ている。**コマンドライン文字列が肝**で、
本当にファイルが存在するかは無関係。

## 仕組みの解説 (講評用)

- Falco rule の `condition: proc.cmdline icontains "id_rsa"` のような行
- `find` や `grep` の引数として "id_rsa" が現れた時点で、結果が空でも発火
- 攻撃者が「クレデンシャル探索」する典型挙動を syscall+cmdline 観測で見抜ける
- 回避方法は次の課題(あるいは独習)で考えてみよう
