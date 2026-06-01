#!/bin/sh
# start-miner.sh — fake xmrig 起動シナリオ。
# Falco "Detect crypto miners using the Stratum protocol" の一般的な
# 派生ルール: stratum+tcp プロトコル文字列を含む outbound 試行を検知。
#
# Run with: sh /opt/ctf/fixtures/start-miner.sh
#
# 動作:
#   1. 仮の miner config を /tmp に書く (stratum URL 込み)
#   2. busybox の wget / nc で stratum+tcp:// に対して接続試行
#   (NetworkPolicy で実通信は block されるが、syscall + cmdline は記録される)

set -eu

POOL="${POOL:-stratum+tcp://pool.example.com:3333}"

echo "[fake miner] connecting to ${POOL}..."
# nc で stratum 文字列を含む文字列を送る。ルール条件によっては
# proc.name = "xmrig" 必要。fallback: 名前を xmrig にして実行。

cp /bin/sleep /tmp/xmrig 2>/dev/null || true
chmod +x /tmp/xmrig
exec /tmp/xmrig 30 &

echo "[fake miner] pid=$!, simulated stratum URL=${POOL}"
