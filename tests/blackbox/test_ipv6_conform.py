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
    ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, ICMPv6TimeExceeded,
    ICMPv6ParamProblem, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, TCP, UDP,
    in6_chksum,
)

from scapy.layers.dhcp6 import (
    DHCP6_Advertise, DHCP6_InfoRequest, DHCP6_Reply, DHCP6_Request,
    DHCP6_Solicit, DHCP6OptClientId, DHCP6OptDNSServers, DHCP6OptIA_NA,
    DHCP6OptIAAddress, DHCP6OptOptReq, DHCP6OptServerId, DUID_LL, DUID_LLT,
)

from scapy.layers.inet6 import (
    ICMPv6MLDMultAddrRec, ICMPv6MLQuery2, ICMPv6MLReport2, RouterAlert,
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
    answer = (lambda p: ICMPv6EchoReply in p or ICMPv6ParamProblem in p or
              ICMPv6TimeExceeded in p or ICMPv6DestUnreach in p)
    assert sut.exchange(pkt, answer, timeout=1.5) is None


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


# ── TCP over IPv6 (RFC 9293, RFC 8200 §8) ──────────────────────────────────────

def is_synack(p):
    return TCP in p and (p[TCP].flags & 0x12) == 0x12


def tcp6_handshake(sut, sport):
    """SYN → SYN-ACK → ACK from the phantom address; returns the SYN-ACK."""
    syn = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           TCP(sport=sport, dport=7, flags="S", seq=1000,
               options=[("MSS", 1440)]))
    synack = sut.exchange(syn, is_synack)
    assert synack is not None, "no SYN-ACK over IPv6"
    sendp(sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
          TCP(sport=sport, dport=7, flags="A", seq=1001,
              ack=synack[TCP].seq + 1),
          iface=sut.iface, verbose=False)
    return synack


def test_ipv6_018_tcp_syn_ack(sut):
    """Passive open over IPv6: SYN-ACK from the link-local address, MSS for
    a 1500-byte link (1440), valid checksum."""
    sut.start()
    synack = tcp6_handshake(sut, 41018)
    assert synack[IPv6].src == sut.sut_ll
    assert synack[IPv6].dst == OUR_LL
    assert synack[TCP].ack == 1001
    assert ("MSS", 1440) in synack[TCP].options
    assert in6_chksum(6, synack[IPv6], bytes(synack[TCP])) == 0


def test_ipv6_019_tcp_echo(sut):
    """Data over an IPv6 connection is echoed."""
    sut.start()
    synack = tcp6_handshake(sut, 41019)
    data = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
            TCP(sport=41019, dport=7, flags="PA", seq=1001,
                ack=synack[TCP].seq + 1) / Raw(b"tcp over ipv6"))
    echo = sut.exchange(data, lambda p: TCP in p and Raw in p)
    assert echo is not None, "no echo over IPv6"
    assert bytes(echo[Raw]) == b"tcp over ipv6"
    assert echo[TCP].seq == synack[TCP].seq + 1


def test_ipv6_020_tcp_closed_port_rst(sut):
    """A SYN to a closed port draws RST+ACK over IPv6."""
    sut.start()
    syn = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           TCP(sport=41020, dport=4444, flags="S", seq=5000))
    rst = sut.exchange(syn, lambda p: TCP in p and p[TCP].flags & 0x04)
    assert rst is not None, "no RST"
    assert rst[TCP].flags & 0x10  # ACK
    assert rst[TCP].ack == 5001
    assert rst[IPv6].src == sut.sut_ll


def test_ipv6_021_kernel_tcp_echo(sut):
    """The host's own TCP stack connects over IPv6 and gets its echo."""
    if not host_has_link_local(sut.iface):
        pytest.skip(f"no IPv6 on {sut.iface}")
    sut.start()
    scope = socket.if_nametoindex(sut.iface)
    with socket.create_connection((f"{sut.sut_ll}%{scope}", 7),
                                  timeout=5) as c:
        c.sendall(b"kernel tcp6")
        data = b""
        while len(data) < 11:
            chunk = c.recv(64)
            if not chunk:
                break
            data += chunk
    assert data == b"kernel tcp6"


# ── Router discovery and SLAAC (RFC 4861 §6.3, RFC 4862 §5.5) ──────────────────

ROUTER_LL = "fe80::1"
PREFIX = "2001:db8:1::"
OFF_LINK = "2001:db8:2::100"     # a phantom global peer beyond the router


def global_addr(sut):
    """PREFIX + the SUT's interface identifier."""
    iid = socket.inet_pton(socket.AF_INET6, sut.sut_ll)[8:]
    return socket.inet_ntop(socket.AF_INET6,
                            socket.inet_pton(socket.AF_INET6, PREFIX)[:8] + iid)


def log_form(addr):
    """How the demo logs an address: eight uncompressed hex groups."""
    raw = socket.inet_pton(socket.AF_INET6, addr)
    return ":".join(f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2))


def send_ra(sut, hop_limit=64, valid=86400, preferred=14400):
    """Advertise ourselves as the router, with an autonomous /64."""
    sendp(sut.eth(ALL_NODES_MAC) /
          IPv6(src=ROUTER_LL, dst=ALL_NODES, hlim=255) /
          ICMPv6ND_RA(chlim=hop_limit, routerlifetime=1800) /
          ICMPv6NDOptSrcLLAddr(lladdr=sut.our_mac) /
          ICMPv6NDOptPrefixInfo(prefixlen=64, L=1, A=1, validlifetime=valid,
                                preferredlifetime=preferred, prefix=PREFIX),
          iface=sut.iface, verbose=False)


def test_ipv6_022_router_solicitation(sut):
    """REQ-NDP-034..037: RS to all-routers from the link-local address."""
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: ICMPv6ND_RS in p, count=1, timeout=6)
    sut.start(wait_ready=False)
    sn.join(timeout=7)
    assert sn.results, "no Router Solicitation"
    p = sn.results[0]
    assert p[Ether].dst == "33:33:00:00:00:02"
    assert p[IPv6].src == sut.sut_ll
    assert p[IPv6].dst == "ff02::2"
    assert p[IPv6].hlim == 255
    assert p[ICMPv6NDOptSrcLLAddr].lladdr == sut.sut_mac


def test_ipv6_023_slaac_global_address(sut):
    """REQ-SLAAC-014..018: an autonomous /64 gives a global address (after
    DAD), which answers from itself, back through the router."""
    sut.start()
    target = global_addr(sut)
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: ICMPv6ND_NS in p and
                       p[ICMPv6ND_NS].tgt == target, count=1, timeout=4)
    send_ra(sut)
    sn.join(timeout=5)
    assert sn.results, "no DAD probe for the SLAAC address"
    assert sn.results[0][IPv6].src == UNSPEC
    sut.wait_for(f"{log_form(target)} preferred", 4)
    req = (sut.eth() / IPv6(src=OFF_LINK, dst=target) /
           ICMPv6EchoRequest(id=23, seq=1, data=b"global"))
    rep = sut.exchange(req, is_echo_reply)
    assert rep is not None, "no reply at the global address"
    assert rep[IPv6].src == target
    assert rep[IPv6].dst == OFF_LINK
    assert rep[Ether].dst == sut.our_mac


def test_ipv6_024_ra_cur_hop_limit(sut):
    """REQ-NDP-042: the RA's Cur Hop Limit is used for what we send."""
    sut.start()
    send_ra(sut, hop_limit=42)
    time.sleep(0.3)
    req = (sut.eth() / IPv6(src=OUR_LL, dst=sut.sut_ll) /
           ICMPv6EchoRequest(id=24, seq=1, data=b"hlim"))
    rep = sut.exchange(req, is_echo_reply)
    assert rep is not None
    assert rep[IPv6].hlim == 42


def test_ipv6_025_host_reaches_global_address(sut):
    """With the prefix on its interface, the host resolves the SUT's global
    address with NDP, pings it and connects to it."""
    if sys.platform == "darwin" or not host_has_link_local(sut.iface):
        pytest.skip(f"needs Linux with IPv6 on {sut.iface}")
    sut.start()
    target = global_addr(sut)
    ours = PREFIX + "100"
    subprocess.run(["ip", "-6", "addr", "add", f"{ours}/64", "dev", sut.iface,
                    "nodad"], check=True)
    try:
        send_ra(sut)
        sut.wait_for(f"{log_form(target)} preferred", 4)
        r = subprocess.run(["ping", "-6", "-c", "2", "-W", "2", target],
                           capture_output=True, text=True, timeout=15)
        assert r.returncode == 0, r.stdout + r.stderr
        with socket.create_connection((target, 7), timeout=5) as c:
            c.sendall(b"global tcp6")
            assert c.recv(64) == b"global tcp6"
    finally:
        subprocess.run(["ip", "-6", "addr", "del", f"{ours}/64", "dev",
                        sut.iface])


# ── DHCPv6 (RFC 8415), started by the RA's M / O flags ─────────────────────────

DHCP6_SERVER_LL = "fe80::5"
DHCP6_ADDR = "2001:db8:3::77"
DNS6 = "2001:db8::53"


def send_ra_flags(sut, managed, other):
    sendp(sut.eth(ALL_NODES_MAC) /
          IPv6(src=ROUTER_LL, dst=ALL_NODES, hlim=255) /
          ICMPv6ND_RA(M=managed, O=other, routerlifetime=1800) /
          ICMPv6NDOptSrcLLAddr(lladdr=sut.our_mac),
          iface=sut.iface, verbose=False)


def dhcp6_to_sut(sut, msg):
    return (sut.eth() / IPv6(src=DHCP6_SERVER_LL, dst=sut.sut_ll) /
            UDP(sport=547, dport=546) / msg)


def test_ipv6_026_dhcpv6_stateful(sut):
    """REQ-DHCPv6-011..032: Solicit → Advertise → Request → Reply, then the
    leased address (after DAD) answers."""
    sut.start()
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: DHCP6_Solicit in p, count=1,
                       timeout=4)
    send_ra_flags(sut, managed=1, other=0)
    sn.join(timeout=5)
    assert sn.results, "no Solicit after an RA with M=1"
    sol = sn.results[0]
    assert sol[IPv6].dst == "ff02::1:2"
    assert sol[IPv6].src == sut.sut_ll
    assert (sol[UDP].sport, sol[UDP].dport) == (546, 547)
    duid = sol[DHCP6OptClientId].duid
    assert bytes(duid) == bytes(DUID_LL(lladdr=sut.sut_mac))
    iaid = sol[DHCP6OptIA_NA].iaid

    server = DHCP6OptServerId(duid=DUID_LLT(lladdr=sut.our_mac, timeval=1))
    ia = DHCP6OptIA_NA(iaid=iaid, T1=1800, T2=2880, ianaopts=[
        DHCP6OptIAAddress(addr=DHCP6_ADDR, preflft=3600, validlft=7200)])
    adv = dhcp6_to_sut(sut, DHCP6_Advertise(trid=sol[DHCP6_Solicit].trid) /
                       DHCP6OptClientId(duid=duid) / server / ia)
    req = sut.exchange(adv, lambda p: DHCP6_Request in p)
    assert req is not None, "no Request after the Advertise"
    assert bytes(req[DHCP6OptServerId].duid) == bytes(server.duid)
    assert req[DHCP6OptIAAddress].addr == DHCP6_ADDR

    sendp(dhcp6_to_sut(sut, DHCP6_Reply(trid=req[DHCP6_Request].trid) /
                       DHCP6OptClientId(duid=duid) / server / ia),
          iface=sut.iface, verbose=False)
    sut.wait_for("DHCPv6 bound", 3)
    sut.wait_for(f"{log_form(DHCP6_ADDR)} preferred", 4)
    rep = sut.exchange(sut.eth() / IPv6(src=OFF_LINK, dst=DHCP6_ADDR) /
                       ICMPv6EchoRequest(id=26, seq=1, data=b"leased"),
                       is_echo_reply)
    assert rep is not None, "no reply at the leased address"
    assert rep[IPv6].src == DHCP6_ADDR


def test_ipv6_027_dhcpv6_stateless(sut):
    """REQ-DHCPv6-001..008: Information-Request after an RA with O=1; the
    DNS servers of the Reply reach the application."""
    sut.start()
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: DHCP6_InfoRequest in p, count=1,
                       timeout=4)
    send_ra_flags(sut, managed=0, other=1)
    sn.join(timeout=5)
    assert sn.results, "no Information-Request after an RA with O=1"
    inf = sn.results[0]
    assert DHCP6OptIA_NA not in inf
    assert 23 in inf[DHCP6OptOptReq].reqopts  # DNS Recursive Name Server
    sendp(dhcp6_to_sut(sut, DHCP6_Reply(trid=inf[DHCP6_InfoRequest].trid) /
                       DHCP6OptClientId(duid=inf[DHCP6OptClientId].duid) /
                       DHCP6OptServerId(duid=DUID_LLT(lladdr=sut.our_mac,
                                                      timeval=1)) /
                       DHCP6OptDNSServers(dnsservers=[DNS6])),
          iface=sut.iface, verbose=False)
    sut.wait_for("DHCPv6 configured", 3)
    assert f"DNS server {log_form(DNS6)}" in sut.output()


# ── MLD (RFC 3810) ─────────────────────────────────────────────────────────────

def mld_groups(p):
    return {r.dst for r in p[ICMPv6MLReport2].records}


def test_ipv6_028_mld_report_at_start(sut):
    """REQ-SLAAC-013, RFC 3810: the solicited-node group is reported (Hop
    Limit 1, Router Alert) before DAD probes on it."""
    sn = start_sniffer(sut.iface, filter=f"ip6 and ether src {sut.sut_mac}",
                       lfilter=lambda p: ICMPv6MLReport2 in p, count=1,
                       timeout=4)
    sut.start(wait_ready=False)
    sn.join(timeout=5)
    assert sn.results, "no MLDv2 report at start-up"
    p = sn.results[0]
    assert p[IPv6].dst == "ff02::16"
    assert p[IPv6].hlim == 1
    assert any(isinstance(o, RouterAlert) for o in p[IPv6ExtHdrHopByHop].options)
    assert sut.snm in mld_groups(p)
    assert "ff02::1" not in mld_groups(p)  # all-nodes is never reported


def test_ipv6_029_mld_general_query_answered(sut):
    """RFC 3810 §6.2: a general query from a router gets a report of our
    groups within Maximum Response Delay."""
    sut.start()
    time.sleep(1.2)  # let the unsolicited reports go by
    query = (sut.eth(ALL_NODES_MAC) /
             IPv6(src=ROUTER_LL, dst=ALL_NODES, hlim=1) /
             IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)]) /
             ICMPv6MLQuery2(mrd=1000))
    rep = sut.exchange(query, lambda p: ICMPv6MLReport2 in p, timeout=2.5)
    assert rep is not None, "no MLD report after a general query"
    assert rep[IPv6].src == sut.sut_ll
    assert sut.snm in mld_groups(rep)
