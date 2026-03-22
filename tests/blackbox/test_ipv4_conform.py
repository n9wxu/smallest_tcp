r"""
test_ipv4_conform.py — Black-box IPv4 conformance tests.

SUT: any stack reachable via Ethernet (tcp_echo_demo recommended).
Protocol: IPv4 (RFC 791, RFC 1122 §3.2, §3.3).

Run standalone:
    sudo pytest tests/blackbox/test_ipv4_conform.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

Each test traces to one or more REQ-IPv4-NNN requirements (docs/requirements/ipv4.md).
"""

import struct
import pytest
from scapy.all import Ether, IP, ICMP, UDP

from helpers import (
    build_ip_raw, build_icmp_echo, send_recv_icmp,
    send_pkt, silence_any, RECV_TIMEOUT,
)

# Unknown/unregistered IP protocol number for testing
_PROTO_UNKNOWN = 253   # RFC 3692 "Experimental" — nothing uses it in our SUT


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-001  Bad IP header checksum → silent drop
# REQ-IPv4-005
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_001_bad_checksum_silently_dropped(ctx):
    """REQ-IPv4-005: packet with corrupt IP header checksum MUST be silently discarded."""
    pkt = build_ip_raw(ctx, proto=1,  # ICMP
                       payload=bytes(ICMP(type=8, code=0, id=1, seq=1) / b"test"),
                       bad_ip_checksum=True)
    assert silence_any(ctx, pkt, timeout=2), (
        "SUT responded to a packet with bad IP checksum (MUST be silently dropped)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-002  Wrong destination IP → silent drop
# REQ-IPv4-011
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_002_wrong_dst_silently_dropped(ctx):
    """REQ-IPv4-011: packet addressed to a foreign IP MUST be silently discarded."""
    pkt = build_ip_raw(ctx, proto=1,
                       payload=bytes(ICMP(type=8, code=0, id=2, seq=1) / b"test"),
                       dst_ip="10.0.0.99")   # not the SUT's IP
    assert silence_any(ctx, pkt, timeout=2), (
        "SUT responded to a packet with a foreign destination IP"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-003  Unknown protocol → ICMP Protocol Unreachable
# REQ-IPv4-020, REQ-ICMPv4-017
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_003_unknown_proto_icmp_unreachable(ctx):
    """REQ-IPv4-020: unrecognized IP protocol MUST elicit ICMP type 3 code 2."""
    pkt = build_ip_raw(ctx, proto=_PROTO_UNKNOWN, payload=b"\x00" * 8)
    replies = send_recv_icmp(ctx, pkt)
    assert replies, (
        f"No ICMP reply for IP proto={_PROTO_UNKNOWN} "
        "(expected ICMP Destination Unreachable, Protocol Unreachable)"
    )
    icmp = replies[0][ICMP]
    assert icmp.type == 3, f"Expected ICMP type 3 (Dest Unreachable), got {icmp.type}"
    assert icmp.code == 2, f"Expected code 2 (Protocol Unreachable), got {icmp.code}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-004  Fragment (MF=1) → silent drop
# REQ-IPv4-024
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_004_fragment_silently_dropped(ctx):
    """REQ-IPv4-024: received IP fragment (MF=1) MUST be silently discarded."""
    # flags=1 sets MF bit; frag=0 means first fragment
    pkt = build_ip_raw(ctx, proto=1, payload=b"\x08\x00\x00\x00\x00\x01\x00\x01",
                       flags=1, frag=0)
    assert silence_any(ctx, pkt, timeout=2), (
        "SUT responded to an IP fragment (MF=1) — MUST be silently dropped"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-005  IHL too small (IHL=4) → silent drop
# REQ-IPv4-002
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_005_ihl_too_small_silently_dropped(ctx):
    """REQ-IPv4-002: packet with IHL < 5 MUST be silently discarded."""
    pkt = build_ip_raw(ctx, proto=1, payload=b"\x08\x00\x00\x00\x00\x01\x00\x01",
                       ihl=4)    # IHL=4 → 16-byte header, invalid
    assert silence_any(ctx, pkt, timeout=2), (
        "SUT responded to a packet with IHL=4 (must be silently dropped)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-006  TTL=1 packet still accepted (hosts do not check TTL on RX)
# REQ-IPv4-044
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_006_ttl_1_packet_accepted(ctx):
    """REQ-IPv4-044: SUT MUST accept packets regardless of TTL; TTL=1 is not discarded."""
    ping = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip, ttl=1) /
        ICMP(type=8, code=0, id=42, seq=1) /
        b"ttl1"
    )
    replies = send_recv_icmp(ctx, ping)
    assert replies, "SUT did not reply to ICMP echo with TTL=1 (MUST accept)"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-007  SUT's outbound packets have DF=1
# REQ-IPv4-023
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_007_outbound_df_bit_set(ctx):
    """REQ-IPv4-023: every SUT outbound IPv4 packet MUST have DF=1."""
    ping = build_icmp_echo(ctx, id=7, seq=1, data=b"df")
    replies = send_recv_icmp(ctx, ping)
    assert replies, "No ICMP reply (needed to inspect DF bit)"
    ip = replies[0][IP]
    df = (ip.flags >> 1) & 1   # bit 1 = DF; Scapy flags is an int
    # Scapy presents flags as a FlagValue object; check string or int
    assert "DF" in str(ip.flags) or df == 1, (
        f"SUT outbound IP packet does not have DF set (flags={ip.flags!r})"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-IPv4-008  IP options (IHL=6) are accepted; payload still processed
# REQ-IPv4-026
# ══════════════════════════════════════════════════════════════════════════════

def test_ipv4_008_ip_options_accepted(ctx):
    """REQ-IPv4-026: SUT MUST accept packets with IP options (IHL>5) and process payload."""
    # IHL=6 → 24-byte header: 20-byte standard + 4-byte options (NOP×4)
    # Build manually: Scapy handles options, but we need IHL=6 with 4 NOP bytes
    icmp_payload = bytes(ICMP(type=8, code=0, id=8, seq=1) / b"opts")
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip, options=b"\x00\x00\x00\x00") /
        ICMP(type=8, code=0, id=8, seq=1) /
        b"opts"
    )
    replies = send_recv_icmp(ctx, pkt)
    assert replies, (
        "SUT did not reply to ICMP echo with IP options (IHL=6) — "
        "REQ-IPv4-026: MUST accept and process packets with options"
    )
