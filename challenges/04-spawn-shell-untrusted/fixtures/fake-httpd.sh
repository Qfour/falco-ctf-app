#!/bin/sh
# fake-httpd.sh — installs and runs a shell-spawning binary named "httpd".
# Run with `sh /opt/ctf/fixtures/fake-httpd.sh`. The script:
#   1. drops a tiny shell wrapper at /tmp/httpd (proc name = "httpd")
#   2. executes it
#   3. /tmp/httpd forks /bin/sh -> Falco sees proc.pname=httpd, fires rule

set -eu

cat > /tmp/httpd <<'EOF'
#!/bin/sh
# Falco's `Run shell untrusted` triggers because `proc.pname` = httpd
# (= basename of /tmp/httpd) is in `shell_mgmt_binaries`.
/bin/sh -c "echo 'shell spawned from non-shell parent' > /dev/null"
EOF
chmod +x /tmp/httpd
exec /tmp/httpd
