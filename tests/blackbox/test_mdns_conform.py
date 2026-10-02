"""
test_mdns_conform.py — mDNS (RFC 6762) + DNS-SD (RFC 6763) responder conformance.

SUT: demo/mdns_demo.  Each test launches a fresh SUT (so start-up behaviour —
IGMP join, probes, announcements — can be observed) and stops it afterwards
with SIGTERM (which makes it send goodbye packets).  The SUT advertises:

    pyro-dead01.local.            A    <sut-ip>                (TTL 120)
    _pyro._tcp.local.             PTR  Pyro Unit 1._pyro._tcp.local.
    Pyro Unit 1._pyro._tcp.local. SRV  0 0 80 pyro-dead01.local.
    Pyro Unit 1._pyro._tcp.local. TXT  txtvers=1 fw=1.2.3 serial=DEAD01

Usage (Linux, tap0 up with 10.0.0.100/24):

    sudo python3 -m pytest tests/blackbox/test_mdns_conform.py \\
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \\
        --mdns-sut-bin ./build/demo/mdns_demo -v

Raw-socket driver instead of TAP: set the link up with sut_net.sh up raw,
then --iface veth-test --sut-iface raw:veth-sut.

Skipped when --mdns-sut-bin is not given.
"""

import os
import signal
import socket
import subprocess
import tempfile
import time

import pytest
from scapy.all import Ether, IP, IPv6, UDP, conf, get_if_hwaddr, sendp
from scapy.layers.dns import DNS, DNSQR, DNSRR

from helpers import start_sniffer, sut_argv

MDNS_GROUP = "224.0.0.251"
MDNS_MAC = "01:00:5e:00:00:fb"
MDNS_PORT = 5353

HOST = "pyro-dead01.local"
SVC = "_pyro._tcp.local"
INST = "Pyro Unit 1._pyro._tcp.local"
META = "_services._dns-sd._udp.local"

T_A, T_PTR, T_TXT, T_SRV, T_ANY = 1, 12, 16, 33, 255

# RFC 6762 §6: the SUT multicasts a record at most once a second, holding
# it one to two seconds after it was sent
RATE_LIMIT_S = 2.1


# ── SUT management ─────────────────────────────────────────────────────────────

class MdnsSut:
    """A fresh mdns_demo process plus the addresses the tests need."""

    def __init__(self, binary, iface, sut_ip, sut_mac, our_ip, our_mac,
                 sut_iface=None):
        self.argv = sut_argv(binary, sut_iface)
        self.binary = binary
        self.iface = iface
        self.sut_ip = sut_ip
        self.sut_mac = sut_mac.lower()
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.proc = None
        self.log_path = None

    def start(self, wait_running=True, timeout=6.0):
        fd, self.log_path = tempfile.mkstemp(prefix="mdns_sut_", suffix=".log")
        self.proc = subprocess.Popen(self.argv, stdout=fd,
                                     stderr=subprocess.STDOUT)
        os.close(fd)
        if wait_running:
            self.wait_for("[mdns] running", timeout)
            # RFC 6762 §6: a record just announced is not multicast again
            # for a second (the responder holds it one to two)
            time.sleep(RATE_LIMIT_S)

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

    def stop(self, sig=signal.SIGTERM):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None


@pytest.fixture
def sut(request):
    binary = request.config.getoption("--mdns-sut-bin")
    if not binary:
        pytest.skip("--mdns-sut-bin not given")
    iface = request.config.getoption("--iface")
    conf.iface = iface
    s = MdnsSut(binary, iface,
                request.config.getoption("--sut-ip"),
                request.config.getoption("--mdns-sut-mac"),
                request.config.getoption("--our-ip"),
                get_if_hwaddr(iface),
                request.config.getoption("--sut-iface"))
    yield s
    s.stop()
    if s.log_path:
        print(f"\n--- SUT output ---\n{s.output()}")
        os.unlink(s.log_path)


# ── Packet helpers ─────────────────────────────────────────────────────────────

def _n(name):
    """Normalise a DNS name (bytes or str) for comparison."""
    if isinstance(name, bytes):
        name = name.decode(errors="replace")
    return name.rstrip(".").lower()


def records(section):
    """DNS section as a list (Scapy >= 2.6 lists, older chained packets)."""
    if section is None:
        return []
    if isinstance(section, list):
        return list(section)
    out = []
    while section is not None and section.__class__.__name__ != "NoPayload":
        out.append(section)
        section = section.payload
    return out


def find(section, name, rtype):
    return [rr for rr in records(section)
            if rr.type == rtype and _n(rr.rrname) == _n(name)]


def send_query(s, qname, qtype, qu=False, qid=0, sport=MDNS_PORT,
               known=None):
    dns = DNS(id=qid, qr=0,
              qd=[DNSQR(qname=qname, qtype=qtype, unicastresponse=int(qu))])
    if known:
        dns.an = known
    pkt = (Ether(dst=MDNS_MAC, src=s.our_mac) /
           IP(src=s.our_ip, dst=MDNS_GROUP, ttl=255) /
           UDP(sport=sport, dport=MDNS_PORT) / dns)
    sendp(pkt, iface=s.iface, verbose=False)


def sut_filter(s, extra=""):
    # IPv4 only: a dual-stack SUT sends the same over IPv6 (tests 020-021)
    bpf = f"ip and udp and src port {MDNS_PORT} and ether src {s.sut_mac}"
    return f"{bpf} and {extra}" if extra else bpf


def is_response(p):
    return DNS in p and p[DNS].qr == 1


def is_probe(p):
    return DNS in p and p[DNS].qr == 0


def ask(s, qname, qtype, timeout=1.5, extra="", retry=True, **kw):
    """Send a query; return the SUT's responses seen within @timeout.

    Unanswered, it is asked once more RATE_LIMIT_S later (@retry), as a
    querier does: the SUT multicasts a record at most once a second
    (RFC 6762 §6), and it may just have — re-announcing when its IPv6
    link-local address comes up after it started running, or answering
    another querier on the link (the Mac's mDNSResponder, say)."""
    for attempt in range(2 if retry else 1):
        if attempt:
            time.sleep(RATE_LIMIT_S)
        sniffer = start_sniffer(s.iface, filter=sut_filter(s, extra),
                                lfilter=is_response, count=1, timeout=timeout)
        send_query(s, qname, qtype, **kw)
        sniffer.join(timeout=timeout + 1)
        if sniffer.results:
            break
    return list(sniffer.results)


def capture_startup(s, seconds):
    """Launch the SUT and capture everything mDNS it sends for @seconds."""
    sniffer = start_sniffer(s.iface, filter=sut_filter(s), timeout=seconds)
    s.start(wait_running=False)
    sniffer.join(timeout=seconds + 1)
    return list(sniffer.results)


# ══════════════════════════════════════════════════════════════════════════════
# Answering queries
# ══════════════════════════════════════════════════════════════════════════════

def test_mdns_001_hostname_a_query(sut):
    """REQ-MDNS-009, 014, 026, 078: A query for the host name → A record with
    our IP, TTL 120, the cache-flush bit."""
    sut.start()
    resp = ask(sut, HOST, "A")
    assert resp, "no response to A query"
    a = find(resp[0][DNS].an, HOST, T_A)
    assert a, f"no A record in answer: {resp[0][DNS].summary()}"
    assert a[0].rdata == sut.sut_ip
    assert a[0].ttl == 120                    # REQ-MDNS-014
    assert a[0].cacheflush == 1               # unique record


def test_mdns_002_ptr_query_additionals(sut):
    """REQ-DNSSD-001, 007: PTR answer + SRV, TXT and A in Additional."""
    sut.start()
    resp = ask(sut, SVC, "PTR")
    assert resp, "no response to PTR query"
    dns = resp[0][DNS]
    ptr = find(dns.an, SVC, T_PTR)
    assert ptr and _n(ptr[0].rdata) == _n(INST)
    assert ptr[0].ttl == 4500                 # REQ-DNSSD-016
    assert ptr[0].cacheflush == 0             # shared record
    assert find(dns.ar, INST, T_SRV), "SRV missing from Additional"
    assert find(dns.ar, INST, T_TXT), "TXT missing from Additional"
    assert find(dns.ar, HOST, T_A), "A missing from Additional"


def test_mdns_003_srv_query(sut):
    """REQ-DNSSD-002, 008: SRV → port 80 on the host, A in Additional."""
    sut.start()
    resp = ask(sut, INST, "SRV")
    assert resp, "no response to SRV query"
    dns = resp[0][DNS]
    srv = find(dns.an, INST, T_SRV)
    assert srv, f"no SRV answer: {dns.summary()}"
    assert srv[0].port == 80
    assert _n(srv[0].target) == HOST
    assert find(dns.ar, HOST, T_A), "A missing from Additional"


def test_mdns_004_aa_bit_set(sut):
    """REQ-MDNS-004, 031: every response has QR=1 and AA=1.  The PTR is
    asked last: its additionals (SRV, TXT, A) are multicast with it, and
    then not again for a second (RFC 6762 §6)."""
    sut.start()
    for name, qtype in ((HOST, "A"), (INST, "SRV"), (INST, "TXT"),
                        (SVC, "PTR")):
        resp = ask(sut, name, qtype)
        assert resp, f"no response to {qtype} {name}"
        assert resp[0][DNS].qr == 1
        assert resp[0][DNS].aa == 1, f"AA not set for {qtype} {name}"


def test_mdns_005_id_zero(sut):
    """REQ-MDNS-005: multicast responses carry ID 0 whatever the query ID."""
    sut.start()
    resp = ask(sut, HOST, "A", qid=0x5555)
    assert resp
    assert resp[0][DNS].id == 0
    assert resp[0][IP].dst == MDNS_GROUP


def test_mdns_006_ip_ttl_255(sut):
    """REQ-MDNS-001, 006: IP TTL 255 on responses, from port 5353
    (announcements: test 011)."""
    sut.start()
    resp = ask(sut, HOST, "A")
    assert resp
    assert resp[0][IP].ttl == 255
    assert resp[0][UDP].sport == MDNS_PORT    # REQ-MDNS-001


def test_mdns_007_known_answer_suppression(sut):
    """REQ-MDNS-029: no answer the querier already holds at >= half TTL."""
    sut.start()
    fresh = DNSRR(rrname=SVC, type="PTR", ttl=4500, rdata=INST)
    assert not ask(sut, SVC, "PTR", known=[fresh], retry=False), \
        "SUT answered despite a fresh known answer"
    stale = DNSRR(rrname=SVC, type="PTR", ttl=100, rdata=INST)
    assert ask(sut, SVC, "PTR", known=[stale]), \
        "SUT suppressed an answer whose known copy was stale"


def test_mdns_008_goodbye_on_shutdown(sut):
    """REQ-MDNS-032, 033, REQ-DNSSD-018: SIGTERM → records with TTL 0."""
    sut.start()
    sniffer = start_sniffer(sut.iface, filter=sut_filter(sut),
                            lfilter=is_response, count=1, timeout=3)
    sut.stop(signal.SIGTERM)
    sniffer.join(timeout=4)
    assert sniffer.results, "no goodbye packet on shutdown"
    rrs = records(sniffer.results[0][DNS].an)
    assert rrs and all(rr.ttl == 0 for rr in rrs)
    assert find(sniffer.results[0][DNS].an, HOST, T_A)
    assert find(sniffer.results[0][DNS].an, SVC, T_PTR)
    assert find(sniffer.results[0][DNS].an, META, T_PTR)


def test_mdns_009_meta_query(sut):
    """REQ-DNSSD-014, 015: service type enumeration lists _pyro._tcp."""
    sut.start()
    resp = ask(sut, META, "PTR")
    assert resp, "no response to _services._dns-sd._udp meta-query"
    ptr = find(resp[0][DNS].an, META, T_PTR)
    assert ptr and _n(ptr[0].rdata) == SVC


# ══════════════════════════════════════════════════════════════════════════════
# Start-up: IGMP, probing, announcing
# ══════════════════════════════════════════════════════════════════════════════

def test_mdns_010_probes_on_startup(sut):
    """REQ-MDNS-016..018: three probes ~250 ms apart, QU, records in Authority."""
    pkts = capture_startup(sut, 3.0)
    probes = [p for p in pkts if is_probe(p)]
    assert len(probes) == 3, f"expected 3 probes, saw {len(probes)}"
    for p in probes:
        dns = p[DNS]
        assert dns.id == 0 and p[IP].ttl == 255
        q = [r for r in records(dns.qd) if _n(r.qname) == HOST]
        assert q and q[0].qtype == T_ANY and q[0].unicastresponse == 1
        assert find(dns.ns, HOST, T_A), "A record missing from Authority"
        assert find(dns.ns, INST, T_SRV), "SRV missing from Authority"
    gaps = [b.time - a.time for a, b in zip(probes, probes[1:])]
    assert all(0.15 <= g <= 0.45 for g in gaps), f"probe spacing {gaps}"


def test_mdns_011_announcements(sut):
    """REQ-MDNS-021..023: two multicast announcements ~1 s apart, after probing."""
    pkts = capture_startup(sut, 3.5)
    probes = [p for p in pkts if is_probe(p)]
    anns = [p for p in pkts if is_response(p)]
    assert len(anns) >= 2, f"expected 2 announcements, saw {len(anns)}"
    assert probes and anns[0].time > probes[-1].time
    gap = anns[1].time - anns[0].time
    assert 0.8 <= gap <= 1.5, f"announcement spacing {gap:.2f}s"
    for p in anns[:2]:
        dns = p[DNS]
        assert dns.aa == 1 and dns.id == 0
        assert p[IP].dst == MDNS_GROUP and p[IP].ttl == 255
        a = find(dns.an, HOST, T_A)
        assert a and a[0].cacheflush == 1
        assert find(dns.an, SVC, T_PTR) and find(dns.an, INST, T_SRV)
        assert find(dns.an, INST, T_TXT)


def test_mdns_012_conflict_renames(sut):
    """REQ-MDNS-019, 020: a conflicting response during probing → the SUT
    renames itself and never announces the contested name."""
    first = start_sniffer(sut.iface, filter=sut_filter(sut), lfilter=is_probe,
                          count=1, timeout=3)
    sut.start(wait_running=False)
    first.join(timeout=4)
    assert first.results, "SUT never probed"
    rival = DNS(qr=1, aa=1, an=[DNSRR(rrname=HOST, type="A", ttl=120,
                                      rdata="10.0.0.99", cacheflush=1)])
    rest = start_sniffer(sut.iface, filter=sut_filter(sut), timeout=4)
    sendp(Ether(dst=MDNS_MAC, src=sut.our_mac) /
          IP(src=sut.our_ip, dst=MDNS_GROUP, ttl=255) /
          UDP(sport=MDNS_PORT, dport=MDNS_PORT) / rival,
          iface=sut.iface, verbose=False)
    rest.join(timeout=5)
    anns = [p for p in rest.results if is_response(p)]
    assert anns, "SUT never announced after renaming"
    for p in anns:
        assert not find(p[DNS].an, HOST, T_A), "announced the contested name"
    assert any(find(p[DNS].an, "pyro-dead01-2.local", T_A) for p in anns)
    assert "renamed to pyro-dead01-2.local" in sut.output()


def test_mdns_013_igmp_join(sut):
    """REQ-MDNS-002: IGMPv2 Membership Report for 224.0.0.251 on start-up."""
    sniffer = start_sniffer(sut.iface, filter=f"igmp and ether src {sut.sut_mac}",
                            count=1, timeout=3)
    sut.start(wait_running=False)
    sniffer.join(timeout=4)
    assert sniffer.results, "no IGMP report from SUT"
    p = sniffer.results[0]
    igmp = bytes(p[IP].payload)
    assert igmp[0] == 0x16, f"IGMP type 0x{igmp[0]:02x}, want v2 report"
    assert igmp[4:8] == bytes([224, 0, 0, 251])
    assert p[IP].dst == MDNS_GROUP and p[IP].ttl == 1


# ══════════════════════════════════════════════════════════════════════════════
# Unicast responses, scope, record content
# ══════════════════════════════════════════════════════════════════════════════

def test_mdns_014_legacy_unicast(sut):
    """REQ-MDNS-041, 076 (RFC 6762 §6.7): query from a port other than 5353 →
    unicast reply with the query ID and question, TTL <= 10 s, no
    cache-flush bit."""
    sut.start()
    resp = ask(sut, HOST, "A", qid=0x4242, sport=40000,
               extra="dst port 40000")
    assert resp, "no legacy unicast response"
    p = resp[0]
    assert p[Ether].dst == sut.our_mac and p[IP].dst == sut.our_ip
    dns = p[DNS]
    assert dns.id == 0x4242
    assert [r for r in records(dns.qd) if _n(r.qname) == HOST]
    a = find(dns.an, HOST, T_A)
    assert a and a[0].ttl <= 10 and a[0].cacheflush == 0


def test_mdns_015_qu_unicast(sut):
    """REQ-MDNS-028: QU question → unicast response to the querier."""
    sut.start()
    resp = ask(sut, HOST, "A", qu=True, extra=f"dst host {sut.our_ip}")
    assert resp, "no unicast response to QU query"
    assert resp[0][UDP].dport == MDNS_PORT
    assert find(resp[0][DNS].an, HOST, T_A)


def test_mdns_016_foreign_names_ignored(sut):
    """REQ-MDNS-030, 064: names we do not own, or outside .local, get no
    answer."""
    sut.start()
    assert not ask(sut, "pyro-dead01.example", "A", timeout=1.0, retry=False)
    assert not ask(sut, "nobody.local", "A", timeout=1.0, retry=False)


def test_mdns_017_txt_record(sut):
    """REQ-DNSSD-003, 011, 013: TXT carries the key=value metadata."""
    sut.start()
    resp = ask(sut, INST, "TXT")
    assert resp
    txt = find(resp[0][DNS].an, INST, T_TXT)
    assert txt
    assert list(txt[0].rdata) == [b"txtvers=1", b"fw=1.2.3", b"serial=DEAD01"]


def test_mdns_018_any_query(sut):
    """REQ-MDNS-026, 072: ANY for the instance → both SRV and TXT."""
    sut.start()
    resp = ask(sut, INST, T_ANY)
    assert resp
    dns = resp[0][DNS]
    assert find(dns.an, INST, T_SRV) and find(dns.an, INST, T_TXT)


def test_mdns_019_nsec_for_missing_type(sut):
    """REQ-MDNS-065, 067 (RFC 6762 §6.1): a type our host name doesn't have
    (HINFO) → NSEC asserting which types exist, so lookups don't wait for a
    timeout (an IPv4-only build answers AAAA this way; without it a
    dual-stack resolver waits 5 s for the AAAA answer)."""
    sut.start()
    resp = ask(sut, HOST, "HINFO")
    assert resp, "no negative response to HINFO query"
    nsec = find(resp[0][DNS].an, HOST, 47)
    assert nsec, f"no NSEC answer: {resp[0][DNS].summary()}"
    assert nsec[0].ttl == 120 and nsec[0].cacheflush == 1



# ══════════════════════════════════════════════════════════════════════════════
# mDNS over IPv6 (dual-stack SUT): ff02::fb, AAAA (RFC 6762 §6.2, §20)
# ══════════════════════════════════════════════════════════════════════════════

MDNS_GROUP6 = "ff02::fb"
MDNS_MAC6 = "33:33:00:00:00:fb"
OUR_LL = "fe80::100"


def sut_ll(mac):
    b = bytes.fromhex(mac.replace(":", ""))
    iid = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:6]
    return socket.inet_ntop(socket.AF_INET6, b"\xfe\x80" + bytes(6) + iid)


def ipv6_up(sut):
    """Wait until the dual-stack demo's link-local address is usable."""
    try:
        sut.wait_for(" preferred", 5)
    except AssertionError:
        pytest.skip("SUT is not dual-stack")


def test_mdns_020_aaaa_over_ipv6(sut):
    """REQ-MDNS-013, 038, 039: a query to ff02::fb for AAAA → answer over IPv6
    to ff02::fb (Hop Limit 255) with the link-local address; the A record
    as additional."""
    sut.start()
    ipv6_up(sut)
    time.sleep(RATE_LIMIT_S)  # the announcement over IPv6 that follows
    ll = sut_ll(sut.sut_mac)
    sn = start_sniffer(sut.iface,
                       filter=f"ip6 and udp and src port {MDNS_PORT} and "
                              f"ether src {sut.sut_mac}",
                       lfilter=is_response, count=1, timeout=2)
    sendp(Ether(src=sut.our_mac, dst=MDNS_MAC6) /
          IPv6(src=OUR_LL, dst=MDNS_GROUP6, hlim=255) /
          UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
          DNS(id=0, qr=0, qd=DNSQR(qname=HOST, qtype="AAAA")),
          iface=sut.iface, verbose=False)
    sn.join(timeout=3)
    assert sn.results, "no answer over IPv6"
    p = sn.results[0]
    assert p[IPv6].dst == MDNS_GROUP6 and p[IPv6].hlim == 255
    aaaa = find(p[DNS].an, HOST, 28)
    assert aaaa and ll in {r.rdata for r in aaaa}
    assert find(p[DNS].ar, HOST, T_A), "A record not in additionals"


def test_mdns_021_announced_over_ipv6(sut):
    """REQ-MDNS-039, 059 (RFC 6762 §8.3, §8.4): the records are announced
    over IPv6 once the link-local address is usable, AAAA included."""
    sn = start_sniffer(sut.iface,
                       filter=f"ip6 and udp and src port {MDNS_PORT} and "
                              f"ether src {sut.sut_mac}",
                       lfilter=is_response, count=1, timeout=6)
    sut.start(wait_running=False)
    sn.join(timeout=7)
    if " preferred" not in sut.output():
        pytest.skip("SUT is not dual-stack")
    assert sn.results, "no announcement over IPv6"
    p = sn.results[0]
    assert p[IPv6].dst == MDNS_GROUP6
    assert find(p[DNS].an, HOST, 28), "AAAA missing from the announcement"
    assert find(p[DNS].an, HOST, T_A), "A missing from the announcement"
