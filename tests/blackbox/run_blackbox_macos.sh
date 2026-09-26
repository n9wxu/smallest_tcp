#!/usr/bin/env bash
# run_blackbox_macos.sh — run every blackbox suite on macOS over a feth pair.
#
# feth0 (10.0.0.1/24) is the test side; the demos open feth1 through BPF.
# The tests' source address, 10.0.0.100, is deliberately NOT assigned to the
# Mac, so the macOS kernel ignores the SUT's replies (no pf rule needed —
# on Linux, run_blackbox.sh needs an iptables rule for the same reason).
#
# One-time setup per boot (root):
#   sudo ifconfig feth0 create && sudo ifconfig feth1 create
#   sudo ifconfig feth0 peer feth1
#   sudo ifconfig feth0 inet 10.0.0.1/24 up && sudo ifconfig feth1 up
#
# BPF access: with Wireshark's ChmodBPF (you are in the access_bpf group) this
# runs without sudo; otherwise run it with sudo.
#
# Python (Homebrew Python refuses global pip installs):
#   python3 -m venv .venv && .venv/bin/pip install -r tests/blackbox/requirements.txt
#
# Usage, from the repo root after `cmake -S . -B build && cmake --build build`:
#   tests/blackbox/run_blackbox_macos.sh [BUILD_DIR]      (default: build)
#   PYTHON=/path/to/python tests/blackbox/run_blackbox_macos.sh

set -u

BUILD=${1:-build}
PYTHON=${PYTHON:-.venv/bin/python}
IFACE=feth0
SUT_IP=10.0.0.2
OUR_IP=10.0.0.100
HERE=$(cd "$(dirname "$0")" && pwd)
LOG_DIR=$(mktemp -d)
PASSED=()
FAILED=()
SUT_PID=""

die() {
  echo "error: $*" >&2
  exit 2
}

cleanup() {
  [[ -n "$SUT_PID" ]] && kill "$SUT_PID" 2>/dev/null
  pkill -x dhcp_echo_demo 2>/dev/null # left running by the DHCP fixture
  true
}
trap cleanup EXIT

run_suite() {
  local name=$1
  shift
  echo ""
  echo "── $name"
  if "$PYTHON" -m pytest -p no:cacheprovider -q "$@"; then
    PASSED+=("$name")
  else
    FAILED+=("$name")
  fi
}

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $(uname) == Darwin ]] || die "macOS only (on Linux use run_blackbox.sh)"
for i in feth0 feth1; do
  ifconfig "$i" >/dev/null 2>&1 || die "$i does not exist — see the setup at the top of $0"
done
ifconfig feth0 | grep -q "peer: feth1" || die "feth0 is not peered with feth1"
ifconfig feth0 | grep -q "inet 10.0.0.1 " || die "feth0 needs inet 10.0.0.1/24"
for d in tcp_echo_demo dhcp_echo_demo mdns_demo; do
  [[ -x "$BUILD/demo/$d" ]] || die "$BUILD/demo/$d not built (cmake --build $BUILD)"
done
"$PYTHON" -c "import scapy, pytest" 2>/dev/null ||
  die "$PYTHON cannot import scapy + pytest — see the setup at the top of $0"

# ── ARP / IPv4 / ICMPv4 / UDP / TCP against tcp_echo_demo ─────────────────────
"$BUILD/demo/tcp_echo_demo" >"$LOG_DIR/tcp_echo_demo.log" 2>&1 &
SUT_PID=$!
sleep 1
for s in arp ipv4 icmp udp tcp; do
  run_suite "test_${s}_conform.py" "$HERE/test_${s}_conform.py" \
    --iface "$IFACE" --sut-ip "$SUT_IP" --our-ip "$OUR_IP" --sut-port 7
done
kill "$SUT_PID" 2>/dev/null
wait "$SUT_PID" 2>/dev/null
SUT_PID=""

# ── DHCPv4 client against dhcp_echo_demo (the fixture restarts it) ────────────
"$BUILD/demo/dhcp_echo_demo" >"$LOG_DIR/dhcp_echo_demo.log" 2>&1 &
SUT_PID=$!
echo "$SUT_PID" >"$LOG_DIR/dhcp_sut.pid"
sleep 1
run_suite "test_dhcpv4_conform.py" "$HERE/test_dhcpv4_conform.py" \
  --iface "$IFACE" --our-ip "$OUR_IP" --dhcp-sut-mac 02:00:00:de:ad:01 \
  --dhcp-server-ip 10.0.0.1 --dhcp-offered-ip 10.0.0.50 \
  --dhcp-sut-bin "$BUILD/demo/dhcp_echo_demo" \
  --dhcp-sut-pid-file "$LOG_DIR/dhcp_sut.pid"
kill "$SUT_PID" 2>/dev/null
wait "$SUT_PID" 2>/dev/null
SUT_PID=""
pkill -x dhcp_echo_demo 2>/dev/null

# ── mDNS + DNS-SD (launches a fresh mdns_demo per test), then interop ─────────
run_suite "test_mdns_conform.py" "$HERE/test_mdns_conform.py" \
  --iface "$IFACE" --sut-ip "$SUT_IP" --our-ip "$OUR_IP" \
  --mdns-sut-bin "$BUILD/demo/mdns_demo"
echo ""
echo "── mdns_interop_macos.sh"
if "$HERE/mdns_interop_macos.sh" "$BUILD/demo/mdns_demo"; then
  PASSED+=("mdns_interop_macos.sh")
else
  FAILED+=("mdns_interop_macos.sh")
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  Blackbox Conformance Suite (macOS, feth) — Results"
echo "══════════════════════════════════════════════════════════════════"
for s in "${PASSED[@]+"${PASSED[@]}"}"; do echo "  ✓  $s"; done
for s in "${FAILED[@]+"${FAILED[@]}"}"; do echo "  ✗  $s"; done
echo "  ${#PASSED[@]} passed, ${#FAILED[@]} failed   (SUT logs: $LOG_DIR)"
echo "══════════════════════════════════════════════════════════════════"
[[ ${#FAILED[@]} -eq 0 ]]
