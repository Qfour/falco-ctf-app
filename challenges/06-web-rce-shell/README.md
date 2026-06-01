# 06 — Web RCE Shell

ストーリー上「Web サーバの RCE で shell を取った」状況を再現。Falco の
`Run shell untrusted` を発火させる。

## 想定解

```bash
sh /opt/ctf/fixtures/fake-httpd.sh
```

fixture は `/tmp/httpd` (basename = httpd → comm = httpd) を生成・実行
し、その中で `/bin/sh` を起こす → 親 comm = httpd → 発火。

## 解説

- proc.comm は kernel が exec 時にファイルの basename から決める
- shell_mgmt_binaries: httpd / nginx / apache2 / postgres / mysqld 等
- 攻撃者の手口: Web サーバの脆弱性で `system()` 呼ばれたら親が httpd
