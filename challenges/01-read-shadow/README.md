# 01 — read-shadow

Falco の最も基本的な検知ルール `Read sensitive file untrusted` を体験する入門課題。

## 出題文

「コンテナの中から `/etc/shadow` の中身が見られる状態にあるかを確認しなさい。
`/opt/ctf/fixtures/welcome.txt` にヒントがある。」

## クリア条件

ユーザの Namespace `ctf-<username>` の challenge コンテナで、Falco ルール
**`Read sensitive file untrusted`** が発火すること。

## 想定解

```bash
cat /etc/shadow
# または:
less /etc/shadow
# または readlink 経由:
ln -s /etc/shadow /tmp/x && cat /tmp/x
```

いずれでも `Read sensitive file untrusted` が発火する(busybox 系の `cat` は
Falco の trusted process リストに入っていないため)。

## 仕組みの解説 (講評用)

- Falco は Linux の `openat(2)` syscall を eBPF プローブで観測している
- ルール `Read sensitive file untrusted` の条件: 「`/etc/shadow` を `proc_name` が
  trusted リスト外のプロセスが open_read で開く」
- コンテナ内であっても syscall は host kernel に入り Falco が観測する
- 検知イベントには `k8s.ns.name`, `k8s.pod.name`, `container.image.repository`
  が付与され、scoreboard はこれを使ってユーザを特定する

## ヒント (難易度別)

1. (易) `/etc/shadow` を `cat` で覗くだけで OK
2. (中) `cat` 以外の方法でも発火するか?(`less`, `head`, `od` …)
3. (難) ルールの除外条件を読み、検知**回避**できるか?
   ([参考](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml))
