# 09 — Cryptojacker

クラスタの計算資源を流用するクリプトマイナー attack。Falco の
miner 検知系ルール (process name ベース or stratum protocol 検出) を
発火させる。

## ルール選択の注意

Falco 公式 rules には複数の miner 検知ルールがあるが、CTF 環境で
**ノード経由の stratum protocol 通信は NetworkPolicy で block** される
ので protocol 系は発火させづらい。代わりに **`proc.name` ベース**
のルール (上流の rules リポジトリにある "Detect crypto miners using
the Stratum protocol" 派生 or custom "Mining Binary Detected") を
利用する想定。

このリポジトリで使う Falco rules の version によって正確なルール名
が異なる可能性あり — 出題前に `kubectl -n falco get cm falco-rules -o yaml`
で実際のルール名を確認すること。

## 想定解

```bash
sh /opt/ctf/fixtures/start-miner.sh
# fixture が /tmp/xmrig (= /bin/sleep のコピー) を起動 → proc.name = "xmrig"
# Falco の miner detection ルール (proc.name in (xmrig, minerd, ...))が発火
```

## 解説

- 攻撃者が暗号通貨マイナーをコンテナ内で動かす = Impact (T1496)
- Falco は `proc.name` の名前リスト or 特徴的な通信パターンで検知
- 本番では Sysdig Secure の image scan + runtime detection の組み合わせ
