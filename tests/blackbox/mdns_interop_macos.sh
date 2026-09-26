#!/usr/bin/env bash
# mdns_interop_macos.sh — discover mdns_demo with macOS's own mDNS stack
# (mDNSResponder, via dns-sd) — REQ-MDNS-040, REQ-DNSSD-026.
#
# Checks: dns-sd -B finds the instance, -L resolves it to host:80 with the
# TXT metadata, -G resolves the host name, the advertised TCP port answers,
# and the instance is removed when the SUT sends its goodbye on SIGTERM.
#
# Needs the feth pair (see run_blackbox_macos.sh) and BPF access for the SUT.
#
#   tests/blackbox/mdns_interop_macos.sh ./build/demo/mdns_demo

set -u

SUT_BIN=${1:-./build/demo/mdns_demo}
SUT_IP=${SUT_IP:-10.0.0.2}
HOST=pyro-dead01.local
INSTANCE="Pyro Unit 1"
SUT_LOG=$(mktemp)
BROWSE_LOG=$(mktemp)
OUT=$(mktemp)
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

# dns-sd never exits on its own: run it for a few seconds into $OUT
dnssd_for() {
  local secs=$1
  shift
  dns-sd "$@" >"$OUT" 2>&1 &
  local pid=$!
  sleep "$secs"
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}

"$SUT_BIN" >"$SUT_LOG" 2>&1 &
SUT_PID=$!
trap 'kill "$SUT_PID" 2>/dev/null; kill "$BROWSE_PID" 2>/dev/null' EXIT

for _ in $(seq 1 50); do
  grep -q '\[mdns\] running' "$SUT_LOG" && break
  sleep 0.1
done

dns-sd -B _pyro._tcp local >"$BROWSE_LOG" 2>&1 &
BROWSE_PID=$!

echo "=== mDNSResponder interop against $SUT_BIN ==="
sleep 2
check "dns-sd -B finds \"$INSTANCE\"" \
  grep -Eq "Add .*_pyro\._tcp\. +$INSTANCE\$" "$BROWSE_LOG"

dnssd_for 3 -L "$INSTANCE" _pyro._tcp local
check "dns-sd -L resolves to $HOST:80" grep -q "can be reached at $HOST.:80" "$OUT"
check "dns-sd -L sees the TXT metadata" grep -q "txtvers=1" "$OUT"

dnssd_for 3 -G v4 "$HOST"
check "dns-sd -G v4 $HOST -> $SUT_IP" grep -Eq "$HOST\. +$SUT_IP " "$OUT"

check "advertised TCP port answers (echo)" \
  bash -c "echo interop | nc -w 2 $SUT_IP 80 | grep -q interop"

kill -TERM "$SUT_PID"
wait "$SUT_PID" 2>/dev/null
sleep 3
check "instance removed after goodbye (SIGTERM)" \
  grep -Eq "Rmv .*_pyro\._tcp\. +$INSTANCE\$" "$BROWSE_LOG"

kill "$BROWSE_PID" 2>/dev/null
wait "$BROWSE_PID" 2>/dev/null
trap - EXIT
echo "--- dns-sd -B events ---"
grep -E "Add|Rmv" "$BROWSE_LOG"
rm -f "$SUT_LOG" "$BROWSE_LOG" "$OUT"
exit $fail
