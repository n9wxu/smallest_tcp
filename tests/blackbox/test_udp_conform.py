r"""
test_udp_conform.py — Black-box UDP conformance tests.

SUT: any stack with a UDP echo service on port 7 and no handler on port 9999
     (tcp_echo_demo with UDP port 7 registered).
Protocol: UDP (RFC 768, RFC 1122 §4.1), ICMP Port Unreachable (RFC 792).

Run standalone:
    sudo pytest tests/blackbox/test_udp_conform.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

Each test traces to one or more REQ-UDP-NNN / REQ-ICMPv4-NNN requirements.
"""

import time
import pytest
from scapy.all import Ether, IP, UDP, ICMP

from helpers import (
    build_udp, send_recv_udp, send_recv_icmp,
    send_pkt, silence_any, RECV_TIMEOUT,
)

_UDP_ECHO_PORT   = 7     # SUT has a handler registered here
_UDP_CLOSED_PORT = 9999  # SUT has NO handler → ICMP port unreachable
_OUR_SPORT       = 54321


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-001  Echo on port 7 — data returned verbatim
# REQ-UDP-001
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_001_echo_data_returned(ctx):
    """REQ-UDP-001: UDP datagram to echo port MUST be echoed back."""
    payload = b"hello-udp"
    pkt = build_udp(ctx, sport=_OUR_SPORT, dport=_UDP_ECHO_PORT, payload=payload)
    replies = send_recv_udp(ctx, pkt)
    assert replies, f"No UDP reply from {ctx.sut_ip}:7"
    echo = bytes(replies[0][UDP].payload)
    assert echo == payload, f"Echo mismatch: got {echo!r}, expected {payload!r}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-002  Echo reply has src/dst ports correctly swapped
# REQ-UDP-003
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_002_echo_ports_swapped(ctx):
    """REQ-UDP-003: Echo reply MUST have sport=7 (SUT) and dport=our sport."""
    pkt = build_udp(ctx, sport=_OUR_SPORT, dport=_UDP_ECHO_PORT, payload=b"ports")
    replies = send_recv_udp(ctx, pkt)
    assert replies, "No UDP reply"
    r = replies[0][UDP]
    assert r.sport == _UDP_ECHO_PORT, (
        f"Reply sport={r.sport}, expected {_UDP_ECHO_PORT}"
    )
    assert r.dport == _OUR_SPORT, (
        f"Reply dport={r.dport}, expected {_OUR_SPORT}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-003  Unknown port → ICMP Destination Unreachable, Port Unreachable
# REQ-UDP-005, REQ-ICMPv4-018
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_003_unknown_port_icmp_unreachable(ctx):
    """REQ-UDP-005/REQ-ICMPv4-018: UDP to closed port MUST elicit ICMP type 3 code 3."""
    pkt = build_udp(ctx, sport=_OUR_SPORT, dport=_UDP_CLOSED_PORT, payload=b"knock")
    replies = send_recv_icmp(ctx, pkt)
    assert replies, (
        f"No ICMP reply for UDP to port {_UDP_CLOSED_PORT} "
        "(expected ICMP Destination Unreachable, Port Unreachable)"
    )
    icmp = replies[0][ICMP]
    assert icmp.type == 3, f"Expected ICMP type 3, got {icmp.type}"
    assert icmp.code == 3, f"Expected code 3 (Port Unreachable), got {icmp.code}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-004  ICMP Unreachable body contains original IP header + 8 UDP bytes
# REQ-ICMPv4-038
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_004_icmp_unreachable_body_correct(ctx):
    """
    REQ-ICMPv4-038: ICMP error body MUST contain the original IP header plus
    the first 8 bytes of the original datagram (= entire UDP header).
    Verifies that the embedded UDP header identifies our source/destination ports.
    """
    import struct
    our_sport = 54322
    pkt = build_udp(ctx, sport=our_sport, dport=_UDP_CLOSED_PORT, payload=b"body")
    replies = send_recv_icmp(ctx, pkt)
    assert replies, "No ICMP Port Unreachable received"

    icmp = replies[0][ICMP]
    assert icmp.type == 3 and icmp.code == 3, (
        f"Expected ICMP 3/3, got type={icmp.type} code={icmp.code}"
    )

    # After the 4-byte ICMP type/code/checksum/unused header, the body starts.
    # body = original IP header (20 bytes) + first 8 bytes of original datagram.
    body = bytes(icmp.payload)
    assert len(body) >= 28, (
        f"ICMP body too short ({len(body)} bytes) — expected at least 28 "
        "(20-byte IP header + 8-byte UDP header)"
    )
    # The first 8 bytes after the original IP header are the original UDP header:
    # sport(2) | dport(2) | length(2) | checksum(2)
    udp_hdr = body[20:28]
    emb_sport, emb_dport = struct.unpack("!HH", udp_hdr[:4])
    assert emb_sport == our_sport, (
        f"Embedded UDP sport={emb_sport}, expected {our_sport}"
    )
    assert emb_dport == _UDP_CLOSED_PORT, (
        f"Embedded UDP dport={emb_dport}, expected {_UDP_CLOSED_PORT}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-005  Bad UDP checksum → silent drop
# REQ-UDP-006
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_005_bad_checksum_silently_dropped(ctx):
    """REQ-UDP-006: UDP datagram with bad checksum MUST be silently discarded."""
    pkt = build_udp(ctx, sport=_OUR_SPORT, dport=_UDP_ECHO_PORT,
                    payload=b"badcksum", bad_checksum=True)
    # Must receive neither a UDP echo nor an ICMP error
    from scapy.all import AsyncSniffer
    bpf = f"(udp or icmp) and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf, count=1, timeout=2)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=3)
    assert len(sniffer.results) == 0, (
        "SUT responded to a UDP datagram with bad checksum (MUST be silently dropped)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-006  Zero UDP checksum is accepted (optional checksum in IPv4)
# REQ-UDP-007
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_006_zero_checksum_accepted(ctx):
    """REQ-UDP-007: UDP checksum=0 means 'not computed'; SUT MUST accept and echo."""
    payload = b"zerocksum"
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip) /
        UDP(sport=_OUR_SPORT, dport=_UDP_ECHO_PORT, chksum=0) /
        payload
    )
    replies = send_recv_udp(ctx, pkt)
    assert replies, (
        "SUT did not echo UDP datagram with checksum=0 (MUST be accepted)"
    )
    echo = bytes(replies[0][UDP].payload)
    assert echo == payload, f"Echo mismatch: got {echo!r}, expected {payload!r}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-UDP-007  UDP length field smaller than minimum (< 8) → silent drop
# REQ-UDP-008
# ══════════════════════════════════════════════════════════════════════════════

def test_udp_007_length_too_small_silently_dropped(ctx):
    """REQ-UDP-008: UDP Length < 8 (minimum header size) MUST be silently dropped."""
    pkt = build_udp(ctx, sport=_OUR_SPORT, dport=_UDP_ECHO_PORT,
                    payload=b"toolong", udp_len_override=4)  # 4 < 8
    assert silence_any(ctx, pkt, timeout=2), (
        "SUT responded to UDP with Length=4 (< 8) — MUST be silently dropped"
    )
