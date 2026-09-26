#!/usr/bin/env bash
# dhcpv6_interop.sh — a real router and DHCPv6 server (dnsmasq) configure the
# dual-stack tcp_echo_demo (REQ-DHCPv6-011..032, REQ-NDP-047).
#
# dnsmasq advertises a prefix with the M flag; the demo starts DHCPv6, leases
# an address from the range, runs DAD, and logs the DNS server option.  The
# host then pings the leased address and gets a TCP echo from it.
#
# Requires root, dnsmasq (dnsmasq-base is enough), iproute2, iputils-ping.
#
#   sudo tests/blackbox/dhcpv6_interop.sh ./build/demo/tcp_echo_demo
#   sudo tests/blackbox/dhcpv6_interop.sh ./build/demo/tcp_echo_demo \
#        raw:veth-sut veth-test                                   # raw socket

set -u

SUT_BIN=${1:-./build/demo/tcp_echo_demo}
SUT_IF=${2:-}          # demo argument; empty: its default (tap0)
TEST_IF=${3:-tap0}     # harness interface dnsmasq serves
PREFIX=2001:db8:6
SUT_LOG=$(mktemp)
DNSMASQ_LOG=$(mktemp)
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

cleanup() {
  [[ -n "${SUT_PID:-}" ]] && kill "$SUT_PID" 2>/dev/null
  [[ -n "${DNSMASQ_PID:-}" ]] && kill "$DNSMASQ_PID" 2>/dev/null
  ip -6 addr del "$PREFIX::1/64" dev "$TEST_IF" 2>/dev/null
}
trap cleanup EXIT

ip -6 addr add "$PREFIX::1/64" dev "$TEST_IF" nodad
dnsmasq --keep-in-foreground --port=0 --no-resolv --conf-file=/dev/null \
  --interface="$TEST_IF" --bind-interfaces --enable-ra \
  --dhcp-range="$PREFIX::10,$PREFIX::20,64,1h" \
  --dhcp-option="option6:dns-server,[$PREFIX::53]" \
  --log-facility="$DNSMASQ_LOG" --log-dhcp &
DNSMASQ_PID=$!
sleep 1

"$SUT_BIN" ${SUT_IF:+"$SUT_IF"} >"$SUT_LOG" 2>&1 &
SUT_PID=$!

for _ in $(seq 1 100); do
  grep -q "DHCPv6 bound" "$SUT_LOG" && grep -q "$PREFIX:.* preferred" "$SUT_LOG" && break
  sleep 0.2
done

echo "=== DHCPv6 interop: dnsmasq on $TEST_IF, demo ${SUT_IF:-on its default} ==="
check "dnsmasq's RA (M flag) started DHCPv6; lease bound" \
  grep -q "DHCPv6 bound" "$SUT_LOG"
ADDR=$(sed -n "s/.*IPv6 \($PREFIX:[0-9a-f:]*\) preferred.*/\1/p" "$SUT_LOG" | head -1)
check "leased address $ADDR is in the dnsmasq range and passed DAD" \
  test -n "$ADDR"
check "DNS server option reached the application" \
  grep -q "DHCPv6 DNS server $PREFIX:0:0:0:0:53" "$SUT_LOG"
if [[ -n "$ADDR" ]]; then
  check "host pings the leased address" \
    bash -c "ping -6 -c 2 -W 2 $ADDR >/dev/null"
  check "TCP echo at the leased address" \
    python3 -c "import socket,sys; c=socket.create_connection(('$ADDR',7),5); c.sendall(b'dhcpv6'); sys.exit(c.recv(16)!=b'dhcpv6')"
fi

echo "--- SUT output ---"
cat "$SUT_LOG"
echo "--- dnsmasq log (DHCPv6) ---"
grep -iE "dhcp|RTR" "$DNSMASQ_LOG" | tail -20
rm -f "$SUT_LOG" "$DNSMASQ_LOG"
exit $fail
