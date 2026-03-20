"""
test_tcp_fuzz.py — Scapy fuzz-based robustness tests for TCP.

Uses scapy.fuzz() to generate randomized TCP header fields while keeping
the Ethernet/IP layers valid so the SUT actually receives the frames.

The key invariant being tested: **the SUT MUST NOT crash**.
After any fuzz barrage, a sanity handshake is performed to verify the
stack is still functional.

Run:
    sudo pytest tests/blackbox/test_tcp_fuzz.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
        --fuzz-count 200 -v

Note: fuzz tests are slow (each fuzz iteration adds ~10 ms of send time
plus the sanity-check timeout). Do not run on every PR — use a scheduled
CI job or trigger manually.
"""

import time
import pytest
from scapy.all import Ether, IP, TCP, fuzz, sendp

from conftest import alloc_port
from helpers import (
    TcpConn, tcp_connect,
    send_pkt, recv_tcp, send_recv,
    _eth_ip_tcp, next_isn, RECV_TIMEOUT,
)


# ── Pytest option ──────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    """Allow --fuzz-count to control iterations (default 200)."""
    try:
        parser.addoption("--fuzz-count", default=200, type=int,
                         help="Number of fuzz iterations per test (default 200)")
    except ValueError:
        pass  # already registered by another plugin


@pytest.fixture
def fuzz_count(request):
    return request.config.getoption("--fuzz-count", default=200)


# ── Sanity check helper ────────────────────────────────────────────────────────

def _sanity_connect(ctx, label="sanity"):
    """
    Verify the SUT is still alive after fuzzing by completing a full
    handshake + echo exchange + clean close.
    Fails the calling test with a descriptive message if the SUT is dead.
    """
    time.sleep(0.2)   # let SUT settle
    try:
        conn, synack = tcp_connect(ctx, alloc_port(), timeout=4)
        payload = b"fuzz-ok"
        replies = send_pkt(ctx, conn.ack(extra_flags="P", payload=payload))
        conn.close()
    except AssertionError as e:
        pytest.fail(
            f"[{label}] SUT appears unresponsive after fuzz: {e}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-001  Fuzz all TCP header fields on SYN
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_001_syn_header_fields(ctx, fuzz_count):
    """
    Fuzz all TCP header fields while sending SYN-like frames.
    SUT MUST NOT crash. A sanity connect is performed at the end.

    REQ-TCP-018 (bad checksum silent drop), robustness.
    """
    our_mac = ctx.our_mac
    sut_mac = ctx.sut_mac

    for i in range(fuzz_count):
        # Keep ETH and IP valid; fuzz only TCP
        pkt = (
            Ether(dst=sut_mac, src=our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            fuzz(TCP(dport=ctx.sut_port))
        )
        sendp(pkt, iface=ctx.iface, verbose=False)
        # Small gap to avoid flooding the SUT's receive buffer
        if i % 50 == 49:
            time.sleep(0.05)

    _sanity_connect(ctx, label="fuzz_syn_header")


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-002  Fuzz data segments on established connection
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_002_data_segments_on_established(ctx, fuzz_count):
    """
    Open a real connection, then bombard it with fuzzed data segments.
    SUT MUST NOT crash; sanity connect verified afterwards.
    """
    conn, _ = tcp_connect(ctx, alloc_port())

    for i in range(fuzz_count):
        pkt = (
            Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            fuzz(TCP(sport=conn.sport, dport=ctx.sut_port,
                     seq=conn.our_seq, ack=conn.our_ack,
                     flags="AP"))
        )
        sendp(pkt, iface=ctx.iface, verbose=False)
        if i % 50 == 49:
            time.sleep(0.05)

    # Best-effort close (connection may be in weird state)
    send_pkt(ctx, conn.rst())
    _sanity_connect(ctx, label="fuzz_data_established")


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-003  Fuzz flags byte — all 256 flag combinations
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_003_all_flag_combinations(ctx):
    """
    Send every possible TCP flags value (0x00..0xFF) to the listening port.
    SUT MUST NOT crash on any combination.
    """
    sport = alloc_port()
    for flags_val in range(256):
        pkt = (
            Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            TCP(sport=sport, dport=ctx.sut_port,
                seq=next_isn(), ack=0, flags=flags_val,
                window=4096)
        )
        sendp(pkt, iface=ctx.iface, verbose=False)

    time.sleep(0.1)
    _sanity_connect(ctx, label="fuzz_flags")


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-004  Fuzz TCP options field
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_004_tcp_options(ctx, fuzz_count):
    """
    Send SYN frames with fuzzed TCP options.
    SUT MUST NOT crash; option parsing must be robust.
    REQ-TCP-115: unknown options MUST be skipped using Length field.
    """
    for i in range(fuzz_count):
        pkt = (
            Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            fuzz(TCP(dport=ctx.sut_port, flags="S"))
        )
        sendp(pkt, iface=ctx.iface, verbose=False)
        if i % 50 == 49:
            time.sleep(0.05)

    _sanity_connect(ctx, label="fuzz_options")


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-005  Truncated / short frames
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_005_truncated_frames(ctx):
    """
    Send TCP segments that are shorter than the minimum header (< 20 bytes).
    SUT MUST NOT crash — truncated frames must be silently discarded.
    REQ-TCP-021: Data Offset >= 5 must be validated.
    """
    from scapy.all import raw

    for trunc_len in range(0, 20):
        # Build a valid SYN, then truncate the TCP portion
        full = (
            Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            TCP(sport=alloc_port(), dport=ctx.sut_port,
                seq=next_isn(), flags="S", window=4096)
        )
        raw_bytes = raw(full)
        # Truncate at ETH+IP+trunc_len into the TCP header
        eth_ip_len = 14 + 20
        truncated = raw_bytes[:eth_ip_len + trunc_len]
        if len(truncated) >= 14:
            sendp(Ether(truncated), iface=ctx.iface, verbose=False)

    _sanity_connect(ctx, label="fuzz_truncated")
