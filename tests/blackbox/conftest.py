r"""
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

import os
import signal
import subprocess
import time
import pytest
from scapy.all import (
    Ether, IP, TCP, ARP,
    srp1, sendp, sniff,
    get_if_hwaddr, conf,
)


# ── Custom marks ───────────────────────────────────────────────────────────────

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "sut_specific: test behaviour is specific to the SUT under test "
        "(timing, MSS handling, etc.) and may not hold for all TCP stacks",
    )


# ── CLI options ────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption("--iface",  default="tap0",      help="Network interface")
    parser.addoption("--sut-ip", default="10.0.0.2",  help="SUT IPv4 address")
    parser.addoption("--our-ip", default="10.0.0.100",
                     help="Phantom source IP (must NOT be assigned to --iface)")
    parser.addoption("--sut-port", default=7, type=int,
                     help="TCP port the SUT echo service listens on (default 7)")
    parser.addoption("--fuzz-count", default=200, type=int,
                     help="Number of fuzz iterations per test (default 200)")
    # DHCP client blackbox options
    parser.addoption("--dhcp-sut-mac", default="02:00:00:de:ad:01",
                     help="SUT MAC for DHCP client tests (dhcp_echo_demo)")
    parser.addoption("--dhcp-server-ip", default="10.0.0.1",
                     help="IP address the test harness pretends to be a DHCP server on")
    parser.addoption("--dhcp-offered-ip", default="10.0.0.50",
                     help="IP address the test DHCP server will offer to the SUT")
    parser.addoption("--dhcp-sut-bin", default=None,
                     help="Path to dhcp_echo_demo binary; enables per-test SUT restart "
                          "so each test begins with the SUT in the INIT/SELECTING state")
    parser.addoption("--dhcp-sut-pid-file", default="/tmp/dhcp_sut.pid",
                     help="PID file written by the CI workflow for the DHCP SUT process")


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


# ── Post-test SUT settle fixture ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def sut_settle():
    """
    Sleep 50 ms BEFORE every test so Scapy's AsyncSniffer has time to open
    its AF_PACKET socket and register its BPF filter before we send any
    stimulus frames.  On a loaded CI runner the kernel thread-scheduling
    window can exceed the 20 ms sleep inside send_recv_* helpers, causing
    the SUT's reply to arrive before the socket is registered — this is
    especially visible on the very first test, which runs immediately after
    the session-level ctx fixture's srp1() socket closes.

    Sleep 100 ms AFTER every test so the SUT has time to finish any
    in-flight do_listen() → usleep(50 ms) and return to LISTEN before the
    next test sends a SYN.  Without this gap, tests that intentionally
    abort a connection (RST, out-of-window RST, etc.) can leave the SUT in
    CLOSED for a brief window and cause the next test's SYN to get RST.
    """
    time.sleep(0.05)   # pre-test: let socket layer settle
    yield
    time.sleep(0.10)   # post-test: let SUT return to LISTEN


# ── DHCP client blackbox fixture ──────────────────────────────────────────────

class DhcpSutContext:
    """
    Minimal context for DHCP-client blackbox tests (dhcp_echo_demo SUT).

    The SUT starts with no IP address — we cannot ARP-resolve it upfront.
    The SUT MAC is taken from the CLI option (default matches the hard-coded
    MAC in demo/dhcp_echo/main.c: 02:00:00:de:ad:01).
    """
    def __init__(self, iface, our_ip, our_mac, sut_mac,
                 server_ip, offered_ip):
        self.iface       = iface
        self.our_ip      = our_ip
        self.our_mac     = our_mac
        self.sut_mac     = sut_mac
        self.server_ip   = server_ip
        self.offered_ip  = offered_ip
        self.sut_ip      = None   # filled in after BOUND

    def __repr__(self):
        return (f"DhcpSutContext(iface={self.iface!r}, sut_mac={self.sut_mac}, "
                f"server={self.server_ip}, offer={self.offered_ip})")


@pytest.fixture(scope="session")
def dhcp_ctx(request):
    """Session fixture for DHCP client blackbox tests."""
    iface       = request.config.getoption("--iface")
    our_ip      = request.config.getoption("--our-ip")
    sut_mac     = request.config.getoption("--dhcp-sut-mac")
    server_ip   = request.config.getoption("--dhcp-server-ip")
    offered_ip  = request.config.getoption("--dhcp-offered-ip")
    our_mac     = get_if_hwaddr(iface)

    conf.iface = iface

    ctx = DhcpSutContext(iface, our_ip, our_mac, sut_mac, server_ip, offered_ip)
    print(f"\nDHCP SUT context: {ctx}")
    return ctx


# ── DHCP per-test SUT restart fixture ────────────────────────────────────────

@pytest.fixture
def dhcp_sut_fresh(request):
    """
    Kill and restart dhcp_echo_demo before each DHCP test.

    After test_ack_binds_ip the SUT holds a bound IP and stops sending
    DISCOVERs; subsequent tests that call _wait_for_discover() would time out
    without a restart.  This fixture is only active when --dhcp-sut-bin is
    supplied on the CLI; omitting it falls back to the externally-managed SUT
    (useful for local development where the developer manually controls the SUT).
    """
    sut_bin  = request.config.getoption("--dhcp-sut-bin")
    pid_file = request.config.getoption("--dhcp-sut-pid-file")

    if sut_bin:
        # ── Terminate the current SUT ────────────────────────────────────────
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.3)
            except (OSError, ValueError, ProcessLookupError):
                pass  # already dead or stale PID file

        # ── Start a fresh SUT ────────────────────────────────────────────────
        log = open("/tmp/dhcp_sut.log", "a")
        proc = subprocess.Popen([sut_bin], stdout=log, stderr=log)
        log.close()
        with open(pid_file, "w") as f:
            f.write(str(proc.pid))
        # Allow the SUT to open the TAP device and broadcast its first DISCOVER
        time.sleep(1.0)

    yield


# ── Per-test port counter (avoids TIME_WAIT port reuse collisions) ─────────────

_port_counter = 50000

def alloc_port():
    """Return a fresh ephemeral source port for each test."""
    global _port_counter
    _port_counter += 1
    if _port_counter > 59999:
        _port_counter = 50001
    return _port_counter
