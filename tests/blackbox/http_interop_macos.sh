#!/usr/bin/env bash
# http_interop_macos.sh — browse to the demo by name on macOS: mDNSResponder
# discovers "_http._tcp" and resolves pyro-dead01.local, curl fetches pages.
#
# Checks the Milestone 10 + 11 goal end to end, including that a dual-stack
# lookup (A + AAAA) of the name is fast — it stalled 5 s before the
# responder answered AAAA with NSEC.
#
# Needs the feth pair (see run_blackbox_macos.sh) and BPF access for the SUT.
#
#   tests/blackbox/http_interop_macos.sh ./build/demo/http_demo

set -u

SUT_BIN=${1:-./build/demo/http_demo}
SUT_IP=${SUT_IP:-10.0.0.2}
HOST=pyro-dead01.local
INSTANCE="Pyro Unit 1"
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

"$SUT_BIN" >"$SUT_LOG" 2>&1 &
SUT_PID=$!
trap 'kill "$SUT_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  nc -z -w 1 "$SUT_IP" 80 2>/dev/null && break
  sleep 0.2
done
sleep 2 # mDNS probing + announcing

echo "=== Browse to http://$HOST/ (macOS) ==="
dns-sd -B _http._tcp local >"$OUT" 2>&1 &
BROWSE_PID=$!
sleep 2
kill "$BROWSE_PID" 2>/dev/null
wait "$BROWSE_PID" 2>/dev/null
check "dns-sd -B _http._tcp finds \"$INSTANCE\"" \
  grep -Eq "Add .*_http\._tcp\. +$INSTANCE\$" "$OUT"

TIMES=$(curl -sS -o "$OUT" -w '%{http_code} %{time_namelookup}' --max-time 10 \
  "http://$HOST/")
CODE=${TIMES% *}
LOOKUP=${TIMES#* }
check "curl http://$HOST/ -> 200" test "$CODE" = 200
check "page is the demo's status page" grep -q "$INSTANCE" "$OUT"
check "name lookup (A + AAAA) under 1 s (took ${LOOKUP}s)" \
  awk -v t="$LOOKUP" 'BEGIN { exit !(t < 1.0) }'

curl -sS --max-time 5 "http://$HOST/api/status" >"$OUT"
check "JSON API by name reports $SUT_IP" grep -q "\"ip\":\"$SUT_IP\"" "$OUT"

kill -TERM "$SUT_PID"
wait "$SUT_PID" 2>/dev/null
trap - EXIT
rm -f "$SUT_LOG" "$OUT"
exit $fail
