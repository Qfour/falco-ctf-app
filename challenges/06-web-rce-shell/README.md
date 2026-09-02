# 06 — Web RCE Shell

ストーリー上「Web サーバの RCE で shell を取った」状況を再現。Falco の
`Run shell untrusted` を発火させる。

## 想定解

```bash
printf '#!/bin/sh\n/bin/sh -c "echo pwned"\n' > /tmp/httpd
chmod +x /tmp/httpd
/tmp/httpd
```

`httpd` という名前のスクリプトを書き出して実行し (basename = httpd →
comm = httpd)、その中で `/bin/sh` を起こす → 親 comm = httpd → 発火。

**実行ファイル自体をコピーしない** (`cp /bin/sh /tmp/httpd` は不可):
busybox の multicall dispatch (`argv[0]` で挙動が変わる) により意図通り
動かず、かつ新規バイナリの drop+exec として `Drop and execute new binary
in container` (Mission 07 の目標ルール) も同時発火してしまう。スクリプト
(shebang 経由の interpreter 実行) は実体が base image 内の `/bin/busybox`
のままなので `proc.is_exe_upper_layer` が false に保たれ、この副作用が
起きない (2026-09-03 実クラスタ実測で確認)。

## 解説

- proc.comm は kernel が exec 時にファイルの basename から決める
  (shebang スクリプトの場合はスクリプト自身の名前になる — interpreter の
  名前ではない)
- shell_mgmt_binaries: httpd / nginx / apache2 / postgres / mysqld 等
- 攻撃者の手口: Web サーバの脆弱性で `system()` 呼ばれたら親が httpd
