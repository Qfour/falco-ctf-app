# 04 — spawn-shell-untrusted

Falco の `Run shell untrusted` ルール発火を体験する課題。
ルールは **プロセスの親子関係 (`proc.pname`)** を見ている — Web サーバ等の
非シェルプロセスからシェルが起動されたら攻撃の可能性が高い、という発想。

## 出題文

「Web サーバの脆弱性を突いて RCE で shell を取った状況を再現せよ。
具体的には親プロセス名が **`httpd` / `nginx` / `apache2` 等の web/proxy
バイナリ**になっている状態でシェルを spawn し、Falco に
`Run shell untrusted` を発火させたらクリア。」

## クリア条件

ユーザの Namespace で Falco ルール `Run shell untrusted` が発火すること。

## 想定解

`proc.pname` (`/proc/<pid>/comm`) は **実行ファイルの basename** から決まる。
shell を `httpd` という名前のラッパー経由で起動すれば、shell の親の
`comm` は `httpd` になる:

```bash
# fixtures に用意されたラッパーを使う:
sh /opt/ctf/fixtures/fake-httpd.sh

# または手動で:
cat > /tmp/httpd <<'EOF'
#!/bin/sh
/bin/sh -c "ls > /dev/null"
EOF
chmod +x /tmp/httpd
/tmp/httpd
```

## 仕組みの解説 (講評用)

- Falco rule `Run shell untrusted` の発火条件:
  ```
  spawned_process and shell_procs and proc.pname exists
  and proc.pname in (shell_mgmt_binaries)   ← httpd, nginx, apache2 等
  and not proc.pname in (shell_binaries)    ← bash, sh, dash, ...
  ```
- Linux カーネルが `/proc/<pid>/comm` を実行ファイル basename で初期化する性質を悪用
- 実装: shell スクリプトを `httpd` という名前で保存・実行するだけ
- 本番運用では Pod のプロセス起動を限定する seccomp / AppArmor / Pod Security Standards で塞ぐ
