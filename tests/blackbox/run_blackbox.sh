#!/usr/bin/env bash
# run_blackbox.sh — Full-stack blackbox conformance suite runner.
#
# Starts the SUT, runs every conformance test program in order, stops the SUT,
# and reports a per-suite PASS/FAIL summary.  Exits 0 only if all suites pass.
#
# Usage:
#   sudo ./tests/blackbox/run_blackbox.sh [OPTIONS]
#
# Options:
#   --sut-bin PATH     Path to SUT binary (default: ./build/demo/tcp_echo_demo)
#   --iface   IFACE    TAP interface name (default: tap0)
#   --sut-ip  IP       SUT IPv4 address   (default: 10.0.0.2)
#   --our-ip  IP       Phantom source IP  (default: 10.0.0.100)
#   --sut-port PORT    TCP echo port      (default: 7)
#   --setup-tap        Create & configure tap0 (skip if already up)
#   --teardown-tap     Destroy tap0 on exit
#   --no-start-sut     Skip starting the SUT (caller already started it)
#   --fuzz             Also run fuzz tests (slow, default: off)
#   -v / --verbose     Pass -v to pytest

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SUT_BIN="${SUT_BIN:-./build/demo/tcp_echo_demo}"
IFACE="${IFACE:-tap0}"
SUT_IP="${SUT_IP:-10.0.0.2}"
OUR_IP="${OUR_IP:-10.0.0.100}"
SUT_PORT="${SUT_PORT:-7}"
SETUP_TAP=0
TEARDOWN_TAP=0
NO_START_SUT=0
RUN_FUZZ=0
VERBOSE=""

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sut-bin)      SUT_BIN="$2";    shift 2 ;;
    --iface)        IFACE="$2";      shift 2 ;;
    --sut-ip)       SUT_IP="$2";     shift 2 ;;
    --our-ip)       OUR_IP="$2";     shift 2 ;;
    --sut-port)     SUT_PORT="$2";   shift 2 ;;
    --setup-tap)    SETUP_TAP=1;     shift   ;;
    --teardown-tap) TEARDOWN_TAP=1;  shift   ;;
    --no-start-sut) NO_START_SUT=1;  shift   ;;
    --fuzz)         RUN_FUZZ=1;      shift   ;;
    -v|--verbose)   VERBOSE="-v";    shift   ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT_PID=""

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "── Stopping SUT ──────────────────────────────────────────────────"
  if [[ -n "$SUT_PID" ]] && kill -0 "$SUT_PID" 2>/dev/null; then
    kill "$SUT_PID" 2>/dev/null || true
    wait "$SUT_PID" 2>/dev/null || true
    echo "SUT (pid $SUT_PID) stopped."
  fi

  if [[ $TEARDOWN_TAP -eq 1 ]]; then
    echo "── Tearing down $IFACE ────────────────────────────────────────"
    ip link set "$IFACE" down 2>/dev/null || true
    ip tuntap del dev "$IFACE" mode tap 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── TAP setup ─────────────────────────────────────────────────────────────────
if [[ $SETUP_TAP -eq 1 ]]; then
  echo "── Setting up TAP interface $IFACE ───────────────────────────────"
  ip tuntap add dev "$IFACE" mode tap user "$(whoami)" 2>/dev/null || true
  ip link set "$IFACE" up
  ip addr add "$OUR_IP/24" dev "$IFACE" 2>/dev/null || true
  # Drop kernel RSTs so Scapy's phantom connections aren't torn down
  iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true
fi

# ── Start SUT (unless caller already started it) ──────────────────────────────
if [[ $NO_START_SUT -eq 0 ]]; then
  echo "── Starting SUT: $SUT_BIN ──────────────────────────────────────"
  if [[ ! -x "$SUT_BIN" ]]; then
    echo "ERROR: SUT binary not found or not executable: $SUT_BIN" >&2
    exit 1
  fi
  "$SUT_BIN" "$IFACE" "$SUT_IP" >/tmp/sut_blackbox.log 2>&1 &
  SUT_PID=$!
  echo "SUT pid: $SUT_PID"
  sleep 2   # let the SUT initialize and open the TAP fd

  if ! kill -0 "$SUT_PID" 2>/dev/null; then
    echo "ERROR: SUT crashed at startup." >&2
    cat /tmp/sut_blackbox.log >&2
    exit 1
  fi
  echo "SUT log:"
  cat /tmp/sut_blackbox.log || true
else
  echo "── Skipping SUT start (--no-start-sut) — using already-running SUT ──"
fi

# ── Common pytest arguments ───────────────────────────────────────────────────
PYTEST_ARGS=(
  --iface    "$IFACE"
  --sut-ip   "$SUT_IP"
  --our-ip   "$OUR_IP"
  --sut-port "$SUT_PORT"
  -p no:cacheprovider
  --tb=short
)
[[ -n "$VERBOSE" ]] && PYTEST_ARGS+=("$VERBOSE")

# ── Suite list ────────────────────────────────────────────────────────────────
# Ordered from lowest to highest layer so failures are easy to attribute.
SUITES=(
  "test_arp_conform.py"
  "test_ipv4_conform.py"
  "test_icmp_conform.py"
  "test_udp_conform.py"
  "test_tcp_conform.py"
)
[[ $RUN_FUZZ -eq 1 ]] && SUITES+=("test_tcp_fuzz.py")

# ── Run suites ────────────────────────────────────────────────────────────────
PASSED=()
FAILED=()

for SUITE in "${SUITES[@]}"; do
  echo ""
  echo "══════════════════════════════════════════════════════════════════"
  echo "  Running: $SUITE"
  echo "══════════════════════════════════════════════════════════════════"

  SUITE_PATH="$SCRIPT_DIR/$SUITE"
  if python3 -m pytest "$SUITE_PATH" "${PYTEST_ARGS[@]}" 2>&1; then
    PASSED+=("$SUITE")
  else
    FAILED+=("$SUITE")
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  Blackbox Conformance Suite — Results"
echo "══════════════════════════════════════════════════════════════════"
for s in "${PASSED[@]}"; do echo "  ✓  $s"; done
for s in "${FAILED[@]}"; do echo "  ✗  $s"; done
echo "  ${#PASSED[@]} passed, ${#FAILED[@]} failed"
echo "══════════════════════════════════════════════════════════════════"

[[ ${#FAILED[@]} -eq 0 ]]   # exit 0 on all pass, 1 on any failure
