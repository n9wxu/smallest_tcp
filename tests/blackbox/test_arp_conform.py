r"""
test_arp_conform.py — Black-box ARP conformance tests.

SUT: any stack reachable via Ethernet (tcp_echo_demo recommended).
Protocol: ARP (RFC 826, RFC 1122 §2.3.2.1).

Run standalone:
    sudo pytest tests/blackbox/test_arp_conform.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

Each test traces to one or more REQ-ARP-NNN requirements (docs/requirements/arp.md).
"""

import time
import pytest
from scapy.all import Ether, ARP

from helpers import (
    build_arp, send_recv_arp, send_pkt, silence_any, RECV_TIMEOUT,
)


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ARP-001  ARP who-has for SUT IP → reply received
# REQ-ARP-001
# ══════════════════════════════════════════════════════════════════════════════

def test_arp_001_who_has_gets_reply(ctx):
    """REQ-ARP-001: SUT MUST reply to ARP who-has for its own IP."""
    req = build_arp(ctx, op="who-has", target_ip=ctx.sut_ip)
    replies = send_recv_arp(ctx, req)
    assert replies, f"No ARP reply from {ctx.sut_ip}"
    r = replies[0][ARP]
    assert r.op == 2, f"Expected ARP reply (op=2), got op={r.op}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ARP-002  Reply hwsrc and sender IP are correct
# REQ-ARP-001, REQ-ARP-002
# ══════════════════════════════════════════════════════════════════════════════

def test_arp_002_reply_fields_correct(ctx):
    """REQ-ARP-002: ARP reply hwsrc MUST be SUT's MAC; sender IP MUST be SUT's IP."""
    req = build_arp(ctx, op="who-has", target_ip=ctx.sut_ip)
    replies = send_recv_arp(ctx, req)
    assert replies, "No ARP reply received"
    r = replies[0][ARP]
    assert r.hwsrc.lower() == ctx.sut_mac.lower(), (
        f"ARP reply hwsrc={r.hwsrc} does not match resolved sut_mac={ctx.sut_mac}"
    )
    assert r.psrc == ctx.sut_ip, (
        f"ARP reply sender IP={r.psrc}, expected {ctx.sut_ip}"
    )
    assert r.pdst == ctx.our_ip, (
        f"ARP reply target IP={r.pdst}, expected our IP {ctx.our_ip}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ARP-003  who-has for unrelated IP → silence
# REQ-ARP-003
# ══════════════════════════════════════════════════════════════════════════════

def test_arp_003_who_has_wrong_ip_is_silent(ctx):
    """REQ-ARP-003: SUT MUST NOT reply to who-has for an IP it does not own."""
    foreign_ip = "10.0.0.99"   # not the SUT's IP
    req = build_arp(ctx, op="who-has", target_ip=foreign_ip)

    from scapy.all import AsyncSniffer
    bpf = f"arp and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf, count=1, timeout=2)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, req)
    sniffer.join(timeout=3)
    assert len(sniffer.results) == 0, (
        f"SUT replied to ARP who-has for {foreign_ip} (not its IP)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ARP-004  ARP request causes SUT to learn our MAC (verified via ping)
# REQ-ARP-005
# ══════════════════════════════════════════════════════════════════════════════

def test_arp_004_request_populates_cache(ctx):
    """
    REQ-ARP-005: SUT MUST cache the sender's IP→MAC from every ARP request it
    receives.  Verified by: send ARP who-has → SUT learns our IP→MAC → send
    ICMP ping → SUT's reply arrives on our MAC (not dropped).
    """
    from helpers import build_icmp_echo, send_recv_icmp
    # Re-send ARP who-has so SUT (re-)learns our MAC
    req = build_arp(ctx, op="who-has", target_ip=ctx.sut_ip)
    send_pkt(ctx, req)
    time.sleep(0.05)

    ping = build_icmp_echo(ctx, id=0xAA, seq=1, data=b"cache")
    replies = send_recv_icmp(ctx, ping)
    assert replies, (
        "No ICMP reply after ARP cache update — SUT may not have learned our MAC"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ARP-005  Repeated who-has → consistent MAC
# REQ-ARP-001
# ══════════════════════════════════════════════════════════════════════════════

def test_arp_005_repeated_consistent_mac(ctx):
    """REQ-ARP-001: SUT MUST reply with the same MAC for every who-has."""
    macs = []
    for _ in range(3):
        req = build_arp(ctx, op="who-has", target_ip=ctx.sut_ip)
        replies = send_recv_arp(ctx, req)
        if replies:
            macs.append(replies[0][ARP].hwsrc.lower())
        time.sleep(0.05)

    assert len(macs) >= 2, "Could not collect enough ARP replies"
    assert len(set(macs)) == 1, (
        f"Inconsistent MACs across ARP replies: {macs}"
    )
