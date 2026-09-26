#!/usr/bin/env bash
# mdns_interop.sh — discover mdns_demo with Avahi, the stock Linux mDNS stack
# (REQ-MDNS-040, REQ-DNSSD-027).
#
# Checks: avahi-resolve finds the host name, avahi-browse resolves the
# _pyro._tcp service (host, IP, port, TXT), the advertised TCP port answers,
# and the service disappears when the SUT sends its goodbye on SIGTERM.
#
# Requires root, avahi-daemon running on the TAP interface (allow-interfaces),
# avahi-utils and netcat-openbsd.
#
#   sudo tests/blackbox/mdns_interop.sh ./build/demo/mdns_demo

set -u

SUT_BIN=${1:-./build/demo/mdns_demo}
SUT_IP=${SUT_IP:-10.0.0.2}
HOST=pyro-dead01.local
SUT_LOG=$(mktemp)
BROWSE_LOG=$(mktemp)
fail=0

check() {
  local what=$1
  shift
  if "$@"; then
    echo "  ✓ $what"
  else
    echo "  ✗ $what"
    fail=1
  fi
}

"$SUT_BIN" >"$SUT_LOG" 2>&1 &
SUT_PID=$!
trap 'kill "$SUT_PID" 2>/dev/null' EXIT

for _ in $(seq 1 50); do
  grep -q '\[mdns\] running' "$SUT_LOG" && break
  sleep 0.1
done

timeout 15 avahi-browse -rp _pyro._tcp >"$BROWSE_LOG" 2>&1 &

echo "=== Avahi interop against $SUT_BIN ==="
check "avahi-resolve $HOST -> $SUT_IP" \
  bash -c "timeout 10 avahi-resolve -4 -n $HOST | grep -q '$SUT_IP'"
sleep 3
check "avahi-browse resolves _pyro._tcp (host, IP, port 80)" \
  grep -q "$HOST;$SUT_IP;80;" "$BROWSE_LOG"
check "avahi-browse sees the TXT metadata" \
  grep -q '"txtvers=1"' "$BROWSE_LOG"
check "advertised TCP port answers (echo)" \
  bash -c "echo interop | timeout 3 nc -q1 $SUT_IP 80 | grep -q interop"

kill -TERM "$SUT_PID"
wait "$SUT_PID" 2>/dev/null
trap - EXIT
sleep 3
check "service withdrawn after goodbye (SIGTERM)" \
  grep -q '^-;.*_pyro\._tcp' "$BROWSE_LOG"

echo "--- avahi-browse events (+ added, = resolved, - removed) ---"
cat "$BROWSE_LOG"
echo "--- SUT output ---"
cat "$SUT_LOG"
rm -f "$SUT_LOG" "$BROWSE_LOG"
exit $fail
