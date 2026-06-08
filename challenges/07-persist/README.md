# 07 — Persist

`Drop and execute new binary in container` の発火。コンテナの base
image に含まれない binary を **drop** (= filesystem 上に置く) し、
**execute** する古典 attacker パターン。Falco は overlayfs の
upper layer (= run time に追加された層) から exec された事を検知。

## ゴール

base image にない binary を drop して exec し、`Drop and execute new
binary in container` を発火させる。

## 想定解

```bash
cp /bin/sleep /usr/local/bin/backdoor    # drop (upper layer に書く)
/usr/local/bin/backdoor 1                # execute
```

実行ファイル本体は何でも良い。**「コンテナ image にない場所」+
「そこからの exec」** が条件。

## 解説

- Rule の判定: `proc.is_exe_upper_layer=true` — exec した binary が
  base image ではなく upper layer (runtime に追加された場所) に
  あるかを overlayfs で問い合わせる
- 攻撃者の手口: パッケージマネージャでツール install / wget で
  binary 配置 / メモリ上で書き出して exec
- 本番防御: read-only root filesystem / image immutability
