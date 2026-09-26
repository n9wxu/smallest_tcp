#!/usr/bin/env bash
# http_interop.sh — browse to the demo by name on Linux: Avahi discovers
# "_http._tcp", nss-mdns resolves pyro-dead01.local, curl fetches pages.
#
# Requires root, avahi-daemon running on the test interface, avahi-utils,
# libnss-mdns (hosts: ... mdns4_minimal ... in /etc/nsswitch.conf) and curl.
#
#   sudo tests/blackbox/http_interop.sh ./build/demo/http_demo [SUT_IF] [TEST_IF]
#   sudo tests/blackbox/http_interop.sh ./build/demo/http_demo raw:veth-sut   # raw socket

set -u

SUT_BIN=${1:-./build/demo/http_demo}
SUT_IF=${2:-} # e.g. raw:veth-sut; empty: the demo's default (tap0)
TEST_IF=${3:-tap0} # harness interface (for the IPv6 link-local check)
SUT_IP=${SUT_IP:-10.0.0.2}
HOST=pyro-dead01.local
SUT_LOG=$(mktemp)
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

"$SUT_BIN" ${SUT_IF:+"$SUT_IF"} >"$SUT_LOG" 2>&1 &
SUT_PID=$!
trap 'kill "$SUT_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  (exec 3<>"/dev/tcp/$SUT_IP/80") 2>/dev/null && break
  sleep 0.2
done
sleep 2 # mDNS probing + announcing

echo "=== Browse to http://$HOST/ (Linux: Avahi + nss-mdns) ==="
timeout 10 avahi-browse -rpt _http._tcp >"$OUT" 2>&1
check "avahi-browse resolves _http._tcp (host, IP, port 80)" \
  grep -q "$HOST;$SUT_IP;80;" "$OUT"
check "getent hosts $HOST -> $SUT_IP (nss-mdns)" \
  bash -c "getent hosts $HOST | grep -q '$SUT_IP'"

TIMES=$(curl -sS -o "$OUT" -w '%{http_code} %{time_namelookup}' --max-time 10 \
  "http://$HOST/")
CODE=${TIMES% *}
LOOKUP=${TIMES#* }
check "curl http://$HOST/ -> 200" test "$CODE" = 200
check "page is the demo's status page" grep -q "Pyro Unit 1" "$OUT"
check "name lookup under 2 s (took ${LOOKUP}s)" \
  awk -v t="$LOOKUP" 'BEGIN { exit !(t < 2.0) }'

curl -sS --max-time 5 "http://$HOST/api/status" >"$OUT"
check "JSON API by name reports $SUT_IP" grep -q "\"ip\":\"$SUT_IP\"" "$OUT"

# A dual-stack demo serves the same pages over IPv6 (link-local, the EUI-64
# of 02:00:00:de:ad:01), if the harness interface has IPv6
if ip -6 addr show dev "$TEST_IF" 2>/dev/null | grep -q fe80 &&
  grep -q 'IPv6 .* preferred' "$SUT_LOG"; then
  URL6="http://[fe80::ff:fede:ad01%25$TEST_IF]/"
  check "curl -6 $URL6 -> 200" \
    test "$(curl -g -sS -o "$OUT" -w '%{http_code}' --max-time 5 "$URL6")" = 200
fi

kill -TERM "$SUT_PID"
wait "$SUT_PID" 2>/dev/null
trap - EXIT
rm -f "$SUT_LOG" "$OUT"
exit $fail
