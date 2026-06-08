#!/usr/bin/env bash
set -e

apt-get update -qq && apt-get install -y --no-install-recommends curl python3 > /dev/null 2>&1

echo "=== Packing proxy site ==="
cp -r /microvm-proxyd /tmp/microvm-proxyd
/app/target/release/zeroserve --pack /tmp/microvm-proxyd > /tmp/proxy.tar
echo "Pack OK: $(wc -c < /tmp/proxy.tar) bytes"

echo ""
echo "=== Starting mock backend on :9090 ==="
python3 -m http.server 9090 --directory /tmp > /tmp/backend9090.log 2>&1 &
BACKEND90_PID=$!

echo "=== Starting zeroserve on :8080 ==="
/app/target/release/zeroserve \
    --addr 127.0.0.1:8080 \
    --vm-map-file /tmp/microvm-proxyd/vmmap.json \
    --disable-ns-isolation \
    /tmp/proxy.tar > /tmp/zeroserve.log 2>&1 &
ZS_PID=$!

echo "Waiting for server to start..."
sleep 1

echo ""
echo "=== Test 1: missing headers -> 400 ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/)
echo "Response: $RESP"
[ "$RESP" = "400" ] && echo "PASS" || echo "FAIL (expected 400, got $RESP)"

echo ""
echo "=== Test 2: only x-execution-id, missing x-microvm-id -> 400 ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-execution-id: exec-abc123" http://127.0.0.1:8080/)
echo "Response: $RESP"
[ "$RESP" = "400" ] && echo "PASS" || echo "FAIL (expected 400, got $RESP)"

echo ""
echo "=== Test 3: unknown execution_id -> 503 ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-execution-id: unknown" -H "x-microvm-id: vm-1" http://127.0.0.1:8080/)
echo "Response: $RESP"
[ "$RESP" = "503" ] && echo "PASS" || echo "FAIL (expected 503, got $RESP)"

echo ""
echo "=== Test 4: valid headers -> proxied to :9090 ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-execution-id: exec-abc123" -H "x-microvm-id: vm-1" http://127.0.0.1:8080/)
echo "Response: $RESP"
[ "$RESP" = "200" ] && echo "PASS" || echo "FAIL (expected 200, got $RESP)"

echo ""
echo "=== Test 5: hot-reload ==="
echo "Starting mock backend on :9091..."
python3 -m http.server 9091 --directory /tmp > /tmp/backend9091.log 2>&1 &

echo "Updating vmmap.json to remap exec-abc123 -> :9091..."
printf '{\n  "exec-abc123": "http://127.0.0.1:9091",\n  "exec-def456": "http://127.0.0.1:9090"\n}\n' \
    > /tmp/microvm-proxyd/vmmap.json

echo "Waiting for inotify to pick up change..."
sleep 1

echo "exec-abc123 should now proxy to :9091..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-execution-id: exec-abc123" -H "x-microvm-id: vm-1" http://127.0.0.1:8080/)
echo "Response: $RESP"
[ "$RESP" = "200" ] && echo "PASS" || echo "FAIL (expected 200, got $RESP)"

echo "exec-def456 (newly added) should proxy to :9090..."
RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "x-execution-id: exec-def456" -H "x-microvm-id: vm-1" http://127.0.0.1:8080/)
echo "Response: $RESP"
[ "$RESP" = "200" ] && echo "PASS" || echo "FAIL (expected 200, got $RESP)"

sleep 0.3
HITS_91=$(grep -c "GET /" /tmp/backend9091.log 2>/dev/null || echo 0)
echo ":9091 received $HITS_91 request(s) after hot-reload -- $([ "$HITS_91" -ge 1 ] && echo PASS || echo FAIL)"

echo ""
echo "=== Zeroserve startup log ==="
cat /tmp/zeroserve.log

kill "$ZS_PID" "$BACKEND90_PID" 2>/dev/null || true
