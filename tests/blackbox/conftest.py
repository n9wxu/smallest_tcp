"""
conftest.py — Shared fixtures for smallest_tcp black-box tests.

Usage
-----
  sudo pytest tests/blackbox/ \
      --iface eth0          \   # network interface to send/receive on
      --sut-ip  10.0.0.2    \   # SUT's IPv4 address
      --our-ip  10.0.0.100  \   # phantom source IP (MUST NOT be assigned to --iface)
      -v

The phantom-IP trick
--------------------
Scapy sends all packets with ``src=our_ip`` (the phantom address).  The
test machine's kernel never sees replies addressed to that IP, so it does
NOT auto-RST Scapy's hand-crafted connections.  No iptables rules needed.

The SUT learns ``our_ip → our_mac`` from the first ARP request and sends
all TCP replies to our MAC; Scapy's AF_PACKET socket captures them because
it sees *all* L2 traffic on the interface regardless of IP destination.

Platform notes
--------------
- Linux  : Scapy uses AF_PACKET/SOCK_RAW — needs ``sudo`` (or CAP_NET_RAW).
- macOS  : Scapy uses BPF — needs ``sudo``.  Set iface to the feth peer.
- CI     : Use iface=``tap0`` with the SUT running as a userspace process.
"""

import time
import pytest
from scapy.all import (
    Ether, IP, TCP, ARP,
    srp1, sendp, sniff,
    get_if_hwaddr, conf,
)


# ── CLI options ────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption("--iface",  default="tap0",      help="Network interface")
    parser.addoption("--sut-ip", default="10.0.0.2",  help="SUT IPv4 address")
    parser.addoption("--our-ip", default="10.0.0.100",
                     help="Phantom source IP (must NOT be assigned to --iface)")
    parser.addoption("--sut-port", default=7, type=int,
                     help="TCP port the SUT echo service listens on (default 7)")


# ── Context object ─────────────────────────────────────────────────────────────

class SutContext:
    """Holds resolved addresses and interface name for the test session."""
    def __init__(self, iface, sut_ip, sut_mac, our_ip, our_mac, sut_port):
        self.iface    = iface
        self.sut_ip   = sut_ip
        self.sut_mac  = sut_mac
        self.our_ip   = our_ip
        self.our_mac  = our_mac
        self.sut_port = sut_port

    def __repr__(self):
        return (f"SutContext(iface={self.iface!r}, sut={self.sut_ip}/"
                f"{self.sut_mac}, us={self.our_ip}/{self.our_mac})")


def _arp_resolve(iface, sut_ip, our_ip, our_mac, timeout=3):
    """
    Send an ARP 'who-has sut_ip tell our_ip' and return the SUT's MAC.

    Side-effect: the SUT will cache our_ip → our_mac from the ARP request,
    so subsequent TCP packets addressed from our_ip will be routed to our_mac
    at L2.
    """
    arp_req = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac) /
        ARP(op="who-has", hwsrc=our_mac, psrc=our_ip, pdst=sut_ip)
    )
    reply = srp1(arp_req, iface=iface, timeout=timeout, verbose=False)
    if reply is None:
        raise RuntimeError(
            f"ARP timeout: no reply from {sut_ip} on {iface} within {timeout}s. "
            "Is the SUT running?"
        )
    return reply[ARP].hwsrc


# ── Session-scoped fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def ctx(request):
    """
    Resolve SUT MAC via ARP and return a SutContext for the whole test session.
    Fails fast with a clear error if the SUT is not reachable.
    """
    iface    = request.config.getoption("--iface")
    sut_ip   = request.config.getoption("--sut-ip")
    our_ip   = request.config.getoption("--our-ip")
    sut_port = request.config.getoption("--sut-port")
    our_mac  = get_if_hwaddr(iface)

    conf.iface = iface          # set Scapy's default interface

    sut_mac = _arp_resolve(iface, sut_ip, our_ip, our_mac)

    ctx = SutContext(iface, sut_ip, sut_mac, our_ip, our_mac, sut_port)
    print(f"\nSUT resolved: {ctx}")
    return ctx


# ── Per-test port counter (avoids TIME_WAIT port reuse collisions) ─────────────

_port_counter = 50000

def alloc_port():
    """Return a fresh ephemeral source port for each test."""
    global _port_counter
    _port_counter += 1
    if _port_counter > 59999:
        _port_counter = 50001
    return _port_counter
