#!/bin/sh
# fake-httpd.sh — Web RCE シナリオを simulate する。
# Run with: sh /opt/ctf/fixtures/fake-httpd.sh
#
# 動作:
#   1. /tmp/httpd という shell スクリプトを書き出す (= proc.comm "httpd")
#   2. これを exec
#   3. /tmp/httpd 内で /bin/sh -c "..." が走る
#   4. Falco: child shell の proc.pname = "httpd" → "Run shell untrusted" 発火

set -eu

cat > /tmp/httpd <<'EOF'
#!/bin/sh
# Falco の "Run shell untrusted" が発火する理由:
#   - この実行ファイルの basename = "httpd" → proc.comm = "httpd"
#   - "httpd" は Falco の shell_mgmt_binaries リストに含まれる
#   - その子として /bin/sh が起動される → proc.pname = "httpd"
/bin/sh -c "echo 'shell spawned from non-shell parent' > /dev/null"
EOF
chmod +x /tmp/httpd
exec /tmp/httpd
