r"""
test_icmp_conform.py — Black-box ICMPv4 conformance tests.

SUT: any stack reachable via Ethernet (tcp_echo_demo recommended).
Protocol: ICMPv4 (RFC 792, RFC 1122 §3.2.2).

Run standalone:
    sudo pytest tests/blackbox/test_icmp_conform.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

Each test traces to one or more REQ-ICMPv4-NNN requirements
(docs/requirements/icmpv4.md).
"""

import struct
import pytest
from scapy.all import Ether, IP, ICMP

from helpers import (
    build_icmp_echo, send_recv_icmp,
    send_pkt, silence_any, RECV_TIMEOUT,
)


def _icmp_checksum_ok(pkt):
    """Recompute ICMP checksum over the ICMP portion and verify it is 0xFFFF."""
    from scapy.all import ICMP as ScapyICMP
    raw = bytes(pkt[ICMP])
    # Zero out checksum field (bytes 2-3)
    data = raw[:2] + b"\x00\x00" + raw[4:]
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += word
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s & 0xFFFF) == 0xFFFF


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-001  Echo Request → Echo Reply
# REQ-ICMPv4-001
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_001_ping_reply(ctx):
    """REQ-ICMPv4-001: SUT MUST respond to Echo Request (type 8) with Echo Reply (type 0)."""
    ping = build_icmp_echo(ctx, id=0x1001, seq=1, data=b"hello")
    replies = send_recv_icmp(ctx, ping)
    assert replies, f"No ICMP reply from {ctx.sut_ip}"
    assert replies[0][ICMP].type == 0, (
        f"Expected ICMP Echo Reply (type 0), got type={replies[0][ICMP].type}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-002  Identifier and Sequence Number preserved in reply
# REQ-ICMPv4-002
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_002_id_seq_preserved(ctx):
    """REQ-ICMPv4-002: Echo Reply MUST carry the same id and seq as the request."""
    my_id  = 0xBEEF
    my_seq = 0x42
    ping = build_icmp_echo(ctx, id=my_id, seq=my_seq, data=b"idseq")
    replies = send_recv_icmp(ctx, ping)
    assert replies, "No ICMP reply"
    r = replies[0][ICMP]
    assert r.id  == my_id,  f"Reply id={r.id:#x}  expected {my_id:#x}"
    assert r.seq == my_seq, f"Reply seq={r.seq:#x} expected {my_seq:#x}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-003  Payload data preserved verbatim in reply
# REQ-ICMPv4-003
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_003_data_preserved(ctx):
    """REQ-ICMPv4-003: Echo Reply data MUST be identical to Echo Request data."""
    payload = b"SmallestTCP-ICMP-test-payload-0123456789"
    ping = build_icmp_echo(ctx, id=3, seq=1, data=payload)
    replies = send_recv_icmp(ctx, ping)
    assert replies, "No ICMP reply"
    reply_data = bytes(replies[0][ICMP].payload)
    assert reply_data == payload, (
        f"Echo Reply data mismatch:\n  got:      {reply_data!r}\n"
        f"  expected: {payload!r}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-004  Echo Reply checksum is valid
# REQ-ICMPv4-006, REQ-ICMPv4-032
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_004_reply_checksum_valid(ctx):
    """REQ-ICMPv4-006/032: ICMP Echo Reply MUST have a correct checksum."""
    ping = build_icmp_echo(ctx, id=4, seq=1, data=b"cksum")
    replies = send_recv_icmp(ctx, ping)
    assert replies, "No ICMP reply"
    assert _icmp_checksum_ok(replies[0]), (
        "ICMP Echo Reply has an incorrect checksum"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-005  Bad ICMP checksum → silent drop
# REQ-ICMPv4-031
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_005_bad_checksum_silently_dropped(ctx):
    """REQ-ICMPv4-031: ICMP message with bad checksum MUST be silently discarded."""
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip) /
        ICMP(type=8, code=0, id=5, seq=1, chksum=0xDEAD) /
        b"badcksum"
    )
    bpf = f"icmp and ether src {ctx.sut_mac}"
    from scapy.all import AsyncSniffer
    import time
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf, count=1, timeout=2)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=3)
    assert len(sniffer.results) == 0, (
        "SUT responded to ICMP with bad checksum (MUST be silently dropped)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-006  Broadcast ping → no reply (echo to 255.255.255.255)
# REQ-ICMPv4-009
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_006_broadcast_ping_silent(ctx):
    """REQ-ICMPv4-009: SUT MUST NOT reply to Echo Request sent to broadcast."""
    bcast_pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst="255.255.255.255") /
        ICMP(type=8, code=0, id=6, seq=1) /
        b"bcast"
    )
    assert silence_any(ctx, bcast_pkt, timeout=2), (
        "SUT replied to ICMP Echo sent to 255.255.255.255 (MUST NOT reply to broadcast)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-ICMPv4-007  No ICMP error generated in response to ICMP error
# REQ-ICMPv4-034
# ══════════════════════════════════════════════════════════════════════════════

def test_icmp_007_no_error_for_icmp_error(ctx):
    """REQ-ICMPv4-034: SUT MUST NOT send ICMP error in response to an ICMP error."""
    # Send an ICMP Destination Unreachable (type 3 code 3) to the SUT
    # The body must include a fake original IP header + 8 bytes
    fake_orig_ip = bytes(
        IP(src=ctx.sut_ip, dst=ctx.our_ip, proto=17) /
        b"\x00\x07" + b"\x00\x07" + b"\x00\x0c" + b"\x00\x00"  # fake UDP hdr
    )[:28]
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip) /
        ICMP(type=3, code=3) /
        fake_orig_ip
    )
    assert silence_any(ctx, pkt, timeout=2), (
        "SUT sent an ICMP reply to an ICMP error message (REQ-ICMPv4-034 violation)"
    )
