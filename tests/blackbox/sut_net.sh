#!/usr/bin/env bash
# sut_net.sh — create or remove the link between the test harness and the SUT
# for one Linux MAC driver.
#
#   sudo tests/blackbox/sut_net.sh up   tap|raw [--rst-drop]
#   sudo tests/blackbox/sut_net.sh down tap|raw
#
#   tap  tap0.  The SUT opens the TAP device; the harness (Scapy, the host
#        kernel, Avahi) uses tap0.
#   raw  veth pair veth-test <-> veth-sut.  The SUT opens veth-sut with the
#        raw-socket (AF_PACKET) driver; the harness uses veth-test.  veth-sut
#        has no addresses, so the kernel stays out of the SUT's way.
#
# Either way the harness end gets OUR_IP/24 (default 10.0.0.100).  "up"
# prints the two names as shell assignments, ready for eval or $GITHUB_ENV:
#   TEST_IF=veth-test      interface for Scapy (--iface), Avahi, ping ...
#   SUT_IF=raw:veth-sut    argument for the demo binaries (--sut-iface)
#
# --rst-drop drops the host kernel's own RSTs on the harness end, which would
# otherwise tear down Scapy's hand-made connections (the TCP suites need it;
# suites that use the kernel as a real TCP client must not have it).

set -euo pipefail

OUR_IP=${OUR_IP:-10.0.0.100}
action=${1:-}
driver=${2:-}
rst_drop=0
[[ ${3:-} == --rst-drop ]] && rst_drop=1

case "$driver" in
  tap) test_if=tap0 sut_if=tap0 ;;
  raw) test_if=veth-test sut_if=veth-sut ;;
  *)
    echo "usage: $0 up|down tap|raw [--rst-drop]" >&2
    exit 2
    ;;
esac

rst_rule=(OUTPUT -p tcp --tcp-flags RST RST -o "$test_if" -j DROP)

case "$action" in
  up)
    if [[ $driver == tap ]]; then
      ip tuntap add dev tap0 mode tap user "${SUDO_USER:-root}"
    else
      ip link add veth-test type veth peer name veth-sut
      # Keep the host's IPv6 (router solicitations, MLD, DAD) off the SUT's
      # wire, as on tap0 where the SUT end has no kernel stack at all.
      sysctl -qw net.ipv6.conf.veth-sut.disable_ipv6=1
      ip link set veth-sut up
    fi
    ip link set "$test_if" up
    ip addr add "$OUR_IP/24" dev "$test_if"
    if [[ $rst_drop -eq 1 ]]; then
      iptables -A "${rst_rule[@]}"
    fi
    echo "TEST_IF=$test_if"
    if [[ $driver == raw ]]; then
      echo "SUT_IF=raw:$sut_if"
    else
      echo "SUT_IF=$sut_if"
    fi
    ;;
  down)
    iptables -D "${rst_rule[@]}" 2>/dev/null || true
    if [[ $driver == tap ]]; then
      ip tuntap del dev tap0 mode tap 2>/dev/null || true
    else
      ip link del veth-test 2>/dev/null || true # removes both ends
    fi
    ;;
  *)
    echo "usage: $0 up|down tap|raw [--rst-drop]" >&2
    exit 2
    ;;
esac
