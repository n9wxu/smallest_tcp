"""
test_ipv6_conform.py — IPv6 (RFC 8200), ICMPv6 (RFC 4443), Neighbor
Discovery (RFC 4861) and Duplicate Address Detection (RFC 4862) conformance.

SUT: demo/tcp_echo (built dual-stack).  Each test launches a fresh SUT, so
start-up behaviour — the DAD probe — can be observed; most tests wait for the
SUT to log that its link-local address is preferred.  The harness talks from
a phantom link-local address (fe80::100) with the interface's real MAC, like
the IPv4 suites' phantom IP.

Usage (Linux, tap0 up):

    sudo python3 -m pytest tests/blackbox/test_ipv6_conform.py \\
        --iface tap0 --ipv6-sut-bin ./build/demo/tcp_echo_demo -v

Raw-socket driver instead of TAP: set the link up with sut_net.sh up raw,
then --iface veth-test --sut-iface raw:veth-sut.

Skipped when --ipv6-sut-bin is not given.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

import pytest
from scapy.all import (
    Ether, IPv6, Raw, conf, get_if_hwaddr, sendp,
    ICMPv6DestUnreach, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA,
    ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
    ICMPv6ParamProblem, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, UDP,
    in6_chksum,
)

from helpers import start_sniffer, sut_argv

OUR_LL = "fe80::100"      # phantom: never assigned to the harness interface
ALL_NODES = "ff02::1"
ALL_NODES_MAC = "33:33:00:00:00:01"
UNSPEC = "::"


def ll_from_mac(mac):
    """fe80:: + Modified EUI-64 (RFC 4291 App. A)."""
    b = bytes.fromhex(mac.replace(":", ""))
    iid = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:6]
    return socket.inet_ntop(socket.AF_INET6, b"\xfe\x80" + bytes(6) + iid)


def solicited_node(addr):
    raw = socket.inet_pton(socket.AF_INET6, addr)
    return socket.inet_ntop(socket.AF_INET6,
                            bytes.fromhex("ff02" + "00" * 9 + "01ff") +
                            raw[13:])


def mcast_mac(group):
    raw = socket.inet_pton(socket.AF_INET6, group)
    return "33:33:" + ":".join(f"{x:02x}" for x in raw[12:])


# ── SUT management ─────────────────────────────────────────────────────────────

class Ipv6Sut:
    """A fresh dual-stack tcp_echo_demo plus the addresses the tests need."""

    def __init__(self, binary, iface, sut_mac, sut_iface=None):
        self.argv = sut_argv(binary, sut_iface)
        self.iface = iface
        self.sut_mac = sut_mac.lower()
        self.sut_ll = ll_from_mac(self.sut_mac)
        self.snm = solicited_node(self.sut_ll)
        self.snm_mac = mcast_mac(self.snm)
        self.our_mac = get_if_hwaddr(iface)
        self.proc = None
        self.log_path = None

    def start(self, wait_ready=True, timeout=6.0):
        fd, self.log_path = tempfile.mkstemp(prefix="ipv6_sut_", suffix=".log")
        self.proc = subprocess.Popen(self.argv, stdout=fd,
                                     stderr=subprocess.STDOUT)
        os.close(fd)
        if wait_ready:
            self.wait_for(" preferred", timeout)

    def output(self):
        if not self.log_path:
            return ""
        with open(self.log_path, errors="replace") as f:
            return f.read()

    def wait_for(self, text, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in self.output():
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        raise AssertionError(f"SUT never logged {text!r}; output:\n{self.output()}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    # ── Frames ───────────────────────────────────────────────────────────────

    def eth(self, dst=None):
        return Ether(src=self.our_mac, dst=dst or self.sut_mac)

    def exchange(self, pkt, lfilter, timeout=2.0):
        """Send pkt; return the first frame from the SUT matching lfilter."""
        sn = start_sniffer(self.iface, filter=f"ip6 and ether src {self.sut_mac}",
                           lfilter=lfilter, count=1, timeout=timeout)
        sendp(pkt, iface=self.iface, verbose=False)
        sn.join(timeout=timeout + 1)
        return sn.results[0] if sn.results else None


@pytest.fixture
def sut(request):
    binary = request.config.getoption("--ipv6-sut-bin")
    if not binary:
        pytest.skip("--ipv6-sut-bin not given")
    iface = request.config.getoption("--iface")
    conf.iface = iface
    s = Ipv6Sut(binary, iface, request.config.getoption("--ipv6-sut-mac"),
                request.config.getoption("--sut-iface"))
    yield s
    s.stop()
    if s.log_path:
        print(f"\n--- SUT output ---\n{s.output()}")
        os.unlink(s.log_path)


def is_na(p):
    return ICMPv6ND_NA in p


def is_echo_reply(p):
    return ICMPv6EchoReply in p


# ── Duplicate Address Detection (RFC 4862 §5.4) ────────────────────────────────

def test_ipv6_001_dad_probe_on_start(sut):
    """REQ-SLAAC-004..006: NS from :: to the solicited-node group, no SLLA."""
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: ICMPv6ND_NS in p, count=1, timeout=4)
    sut.start(wait_ready=False)
    sn.join(timeout=5)
    assert sn.results, "no DAD Neighbor Solicitation at start-up"
    p = sn.results[0]
    assert p[Ether].dst == sut.snm_mac
    assert p[IPv6].src == UNSPEC
    assert p[IPv6].dst == sut.snm
    assert p[IPv6].hlim == 255
    assert p[ICMPv6ND_NS].tgt == sut.sut_ll
    assert ICMPv6NDOptSrcLLAddr not in p


def test_ipv6_002_address_preferred_after_dad(sut):
    """REQ-SLAAC-010: no conflict within RetransTimer → address usable."""
    t0 = time.monotonic()
    sut.start(wait_ready=True, timeout=5)
    assert time.monotonic() - t0 < 4.0


def test_ipv6_003_dad_conflict_disables_address(sut):
    """REQ-SLAAC-008: an NA for the tentative address means it is taken."""
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: ICMPv6ND_NS in p, count=1, timeout=4)
    sut.start(wait_ready=False)
    sn.join(timeout=5)
    assert sn.results, "no DAD probe to answer"
    sendp(sut.eth(ALL_NODES_MAC) /
          IPv6(src="fe80::bad", dst=ALL_NODES, hlim=255) /
          ICMPv6ND_NA(tgt=sut.sut_ll, R=0, S=0, O=1) /
          ICMPv6NDOptDstLLAddr(lladdr="02:00:00:00:0b:ad"),
          iface=sut.iface, verbose=False)
    sut.wait_for(" duplicate", 3)
    assert " preferred" not in sut.output()
    # The duplicate address is never used: solicitations go unanswered
    ns = (sut.eth(sut.snm_mac) / IPv6(src=OUR_LL, dst=sut.snm, hlim=255) /
          ICMPv6ND_NS(tgt=sut.sut_ll) / ICMPv6NDOptSrcLLAddr(lladdr=sut.our_mac))
    assert sut.exchange(ns, is_na, timeout=1.5) is None


def test_ipv6_004_dad_probe_from_others_defended(sut):
    """REQ-NDP-016,018: NS from :: for our address → NA to all-nodes, S=0."""
    sut.start()
    ns = (sut.eth(sut.snm_mac) / IPv6(src=UNSPEC, dst=sut.snm, hlim=255) /
          ICMPv6ND_NS(tgt=sut.sut_ll))
    na = sut.exchange(ns, is_na)
    assert na is not None, "SUT did not defend its address"
    assert na[Ether].dst == ALL_NODES_MAC
    assert na[IPv6].dst == ALL_NODES
    assert na[ICMPv6ND_NA].S == 0
    assert na[ICMPv6ND_NA].O == 1
    assert na[ICMPv6ND_NA].tgt == sut.sut_ll


# ── Neighbor Solicitation / Advertisement (RFC 4861 §7) ────────────────────────

def test_ipv6_005_ns_answered(sut):
    """REQ-NDP-011..013,017,019."""
    sut.start()
    ns = (sut.eth(sut.snm_mac) / IPv6(src=OUR_LL, dst=sut.snm, hlim=255) /
          ICMPv6ND_NS(tgt=sut.sut_ll) / ICMPv6NDOptSrcLLAddr(lladdr=sut.our_mac))
    na = sut.exchange(ns, is_na)
    assert na is not None, "no Neighbor Advertisement"
    assert na[Ether].dst == sut.our_mac
    assert na[IPv6].src == sut.sut_ll
    assert na[IPv6].dst == OUR_LL
    assert na[IPv6].hlim == 255
    adv = na[ICMPv6ND_NA]
    assert (adv.R, adv.S, adv.O) == (0, 1, 1)
    assert adv.tgt == sut.sut_ll
    assert na[ICMPv6NDOptDstLLAddr].lladdr == sut.sut_mac


def test_ipv6_006_ns_hop_limit_not_255_ignored(sut):
    """REQ-NDP-001: ND messages must come from the link (Hop Limit 255)."""
    sut.start()
    ns = (sut.eth(sut.snm_mac) / IPv6(src=OUR_LL, dst=sut.snm, hlim=254) /
          ICMPv6ND_NS(tgt=sut.sut_ll) / ICMPv6NDOptSrcLLAddr(lladdr=sut.our_mac))
    assert sut.exchange(ns, is_na, timeout=1.5) is None


# ── ICMPv6 echo (RFC 4443 §4) ──────────────────────────────────────────────────

def test_ipv6_007_echo(sut):
    """REQ-ICMPv6-004..008."""
    sut.start()
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           ICMPv6EchoRequest(id=0x4242, seq=7, data=b"ipv6 ping"))
    rep = sut.exchange(req, is_echo_reply)
    assert rep is not None, "no Echo Reply"
    assert rep[IPv6].src == sut.sut_ll
    assert rep[IPv6].dst == OUR_LL
    e = rep[ICMPv6EchoReply]
    assert (e.id, e.seq) == (0x4242, 7)
    assert bytes(e.data) == b"ipv6 ping"


def test_ipv6_008_echo_to_all_nodes(sut):
    """REQ-ICMPv6-009: a multicast echo is answered from a unicast source."""
    sut.start()
    req = (sut.eth(ALL_NODES_MAC) / IPv6(src=OUR_LL, dst=ALL_NODES) /
           ICMPv6EchoRequest(id=1, seq=1, data=b"all"))
    rep = sut.exchange(req, is_echo_reply)
    assert rep is not None
    assert rep[IPv6].src == sut.sut_ll
    assert rep[IPv6].dst == OUR_LL


def test_ipv6_009_echo_bad_checksum_ignored(sut):
    """REQ-ICMPv6-002."""
    sut.start()
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           ICMPv6EchoRequest(id=2, seq=2, data=b"bad", cksum=0x1234))
    assert sut.exchange(req, is_echo_reply, timeout=1.5) is None


def test_ipv6_010_echo_behind_hop_by_hop_header(sut):
    """REQ-IPv6-018,019: extension headers are skipped by their length."""
    sut.start()
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) / IPv6ExtHdrHopByHop() /
           ICMPv6EchoRequest(id=3, seq=3, data=b"hbh"))
    rep = sut.exchange(req, is_echo_reply)
    assert rep is not None
    assert bytes(rep[ICMPv6EchoReply].data) == b"hbh"


# ── Errors and unsupported features ────────────────────────────────────────────

def test_ipv6_011_unknown_next_header_parameter_problem(sut):
    """REQ-IPv6-017, REQ-ICMPv6-026,027: code 1, pointer at Next Header."""
    sut.start()
    pkt = sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll, nh=253) / Raw(b"x" * 8)
    err = sut.exchange(pkt, lambda p: ICMPv6ParamProblem in p)
    assert err is not None, "no Parameter Problem"
    assert err[ICMPv6ParamProblem].code == 1
    assert err[ICMPv6ParamProblem].ptr == 6
    assert err[IPv6].dst == OUR_LL


def test_ipv6_012_fragments_dropped(sut):
    """REQ-IPv6-022: no reassembly — fragments are silently discarded."""
    sut.start()
    pkt = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           IPv6ExtHdrFragment(m=0, offset=0, id=99) /
           ICMPv6EchoRequest(id=4, seq=4, data=b"frag"))
    assert sut.exchange(pkt, lambda p: True, timeout=1.5) is None


# ── Interop with the host's own IPv6 stack ─────────────────────────────────────

def host_has_link_local(iface):
    cmd = (["ifconfig", iface] if sys.platform == "darwin"
           else ["ip", "-6", "addr", "show", "dev", iface])
    r = subprocess.run(cmd, capture_output=True, text=True)
    return "fe80" in r.stdout


def test_ipv6_013_kernel_ping(sut):
    """The host resolves the SUT with NDP and pings it."""
    if not host_has_link_local(sut.iface):
        pytest.skip(f"no IPv6 on {sut.iface} (macOS: sudo ifconfig "
                    f"{sut.iface} inet6 -ifdisabled)")
    sut.start()
    target = f"{sut.sut_ll}%{sut.iface}"
    cmd = (["ping6", "-c", "2", target] if sys.platform == "darwin"
           else ["ping", "-6", "-c", "2", "-W", "2", target])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, r.stdout + r.stderr


# ── UDP over IPv6 (RFC 768, RFC 8200 §8.1) ─────────────────────────────────────

def is_udp_echo(p):
    return UDP in p and p[UDP].sport == 7


def test_ipv6_014_udp_echo(sut):
    """UDP echo on port 7 over IPv6; the reply's checksum is valid."""
    sut.start()
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           UDP(sport=40007, dport=7) / Raw(b"udp over ipv6"))
    rep = sut.exchange(req, is_udp_echo)
    assert rep is not None, "no UDP echo"
    assert rep[IPv6].src == sut.sut_ll
    assert rep[IPv6].dst == OUR_LL
    assert rep[UDP].dport == 40007
    assert bytes(rep[UDP].payload) == b"udp over ipv6"
    assert rep[UDP].chksum != 0
    assert in6_chksum(17, rep[IPv6], bytes(rep[UDP])) == 0


def test_ipv6_015_udp_zero_checksum_dropped(sut):
    """REQ-IPv6-045: a zero UDP checksum is invalid over IPv6."""
    sut.start()
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           UDP(sport=40008, dport=7, chksum=0) / Raw(b"no checksum"))
    assert sut.exchange(req, is_udp_echo, timeout=1.5) is None


def test_ipv6_016_udp_closed_port_unreachable(sut):
    """REQ-ICMPv6-016: Destination Unreachable, code 4, quoting the datagram."""
    sut.start()
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           UDP(sport=40009, dport=4444) / Raw(b"closed"))
    err = sut.exchange(req, lambda p: ICMPv6DestUnreach in p)
    assert err is not None, "no Destination Unreachable"
    assert err[ICMPv6DestUnreach].code == 4
    assert err[IPv6].dst == OUR_LL
    assert b"closed" in bytes(err[ICMPv6DestUnreach].payload)


def test_ipv6_017_kernel_udp_echo(sut):
    """The host's own UDP socket talks to the SUT over IPv6."""
    if not host_has_link_local(sut.iface):
        pytest.skip(f"no IPv6 on {sut.iface}")
    sut.start()
    scope = socket.if_nametoindex(sut.iface)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(b"kernel udp6", (sut.sut_ll, 7, 0, scope))
        data, addr = s.recvfrom(64)
    finally:
        s.close()
    assert data == b"kernel udp6"
    assert addr[0].split("%")[0] == sut.sut_ll
