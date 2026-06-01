# 07 — Persist

`Write below binary dir` の発火。01 (Modify binary dirs) と紛らわしい
が別ルール: こちらは **binary 配置済み dir に書き込み = backdoor 配置**
シナリオを captures。

## ゴール

`/usr/local/bin/` 等の **PATH に含まれる bin dir** にスクリプトを
配置して `Write below binary dir` を発火させる。

## 想定解

```bash
echo '#!/bin/sh' > /usr/local/bin/backdoor
chmod +x /usr/local/bin/backdoor
```

## 解説

- `Write below binary dir` の対象 dir: `/usr/local/bin`, `/opt/bin`,
  `/sbin/*`, `/bin/*` 等 (実装依存)
- 攻撃者: PATH 順位を悪用して `ls` 等の正規コマンドを乗っ取る
- 01 (Modify binary dirs) との違い: 01 は `/bin /usr/bin` のみ、
  07 は `/usr/local/bin` 等の拡張バイナリ dir もカバー
