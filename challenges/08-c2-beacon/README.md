# 08 — C2 Beacon

C2 (command-and-control) シナリオ。`Launch Suspicious Network Tool in
Container` ルールは `nc`/`ncat`/`socat`/`nmap`/`tcpdump`/`tshark` 等
**コンテナで普通使わないネットワークツール** の exec を検知。

## 想定解

```bash
nc -zv 8.8.8.8 53
# あるいは
nc -lp 4444 &
nmap localhost
```

ルールの判定: `proc.name in (suspicious_network_tools)`。実通信の
成否は無関係 (exec しただけで発火)。

## 解説

- 攻撃者が C2 接続を貼る / port scan をする典型挙動
- 通信先 (8.8.8.8 等) は問わない。NetworkPolicy で blocked でも発火する
- nc は busybox にも組み込まれているが、`nc` という名前で exec されれば
  proc.name = "nc" → 発火
