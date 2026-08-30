# 04 — Key Search

`Search Private Keys or Passwords` の発火を体験。ルールは `proc.cmdline`
の文字列マッチで判定するので、ファイルが実在しなくても発火する。

## 想定解

```bash
find /tmp -iname id_rsa
find / -name id_rsa 2>/dev/null
grep -r "BEGIN OPENSSH PRIVATE" /etc 2>/dev/null
```

## 解説

- cmdline マッチなので結果 (実ファイル有無) は無関係
- grep 系は `BEGIN PRIVATE` 等のリテラル部分文字列一致 (`icontains`) で判定
  される。正規表現 (`.*` 等) を挟むと連続部分文字列にならず発火しない
  (`grep -rE 'BEGIN.*PRIVATE KEY'` は発火しない一例)
- 攻撃者が credential 探索する典型挙動
- 05 (Silent Search) で同ルールを回避する技を学ぶ
