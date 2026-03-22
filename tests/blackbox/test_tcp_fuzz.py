r"""
test_tcp_fuzz.py — Scapy fuzz-based robustness tests for TCP.

Uses scapy.fuzz() to generate randomized TCP header fields while keeping
the Ethernet/IP layers valid so the SUT actually receives the frames.

The key invariant being tested: **the SUT MUST NOT crash**.
After each fuzz barrage we verify the SUT is still alive via ARP ping.
ARP is the correct liveness tool: it does not require the SUT to be in
LISTEN state and cannot be confused by a legitimately-busy connection.

Why ARP rather than a TCP connect?
  Scapy's fuzz() generates frames with valid checksums (scapy recomputes
  the checksum at build time).  Roughly 12.5 % of fuzz(TCP()) frames have
  flags=SYN-only (bit 1 set, bits 2 and 4 clear), so the SUT legitimately
  enters SYN_RECEIVED from one of the early fuzz frames.  While in
  SYN_RECEIVED, the SUT correctly RSTs new SYNs from unknown ports (no
  LISTEN match, single slot busy).  Interpreting that RST as "SUT crashed"
  is wrong; the SUT is behaving correctly.

How we restore LISTEN state after the SUT enters SYN_RECEIVED:
  The SUT retransmits the SYN-ACK at ~1 s, 3 s, 7 s, … (exponential
  backoff, TCP_MAX_RETRANSMITS = 8, NET_DEFAULT_TCP_RTO_INIT_MS = 1000).
  Those retransmit packets contain the half-open connection's remote port
  and the SUT's rcv_nxt.  We sniff for one, then send a single valid RST
  (seq = SYN-ACK.ack = SUT's rcv_nxt) to the matched 4-tuple.  The SUT's
  RFC-correct RST handler in SYN_RECEIVED fires TCP_EVT_RESET → want_listen
  → do_listen().

  This is standard TCP behaviour; we are not "doing something good with bad
  packets" — we are sending a normal RST to close a half-open connection,
  exactly as any well-behaved peer would.

Run:
    sudo pytest tests/blackbox/test_tcp_fuzz.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
        --fuzz-count 200 -v

Note: fuzz tests are slow (each fuzz iteration adds ~10 ms of send time
plus the sanity-check overhead). Do not run on every PR — use a scheduled
CI job or trigger manually.
"""

import time
import pytest
from scapy.all import Ether, IP, TCP, ARP, fuzz, sendp, srp1

from conftest import alloc_port
from helpers import (
    TcpConn, tcp_connect, tcp_send_recv_data,
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


# ── Liveness and recovery helpers ─────────────────────────────────────────────

def _assert_sut_alive(ctx, label="sanity"):
    """
    Verify the SUT is still running by sending an ARP 'who-has' and expecting
    a reply.  ARP works regardless of TCP connection state, so it correctly
    distinguishes "SUT crashed" from "SUT is busy in SYN_RECEIVED".

    Raises pytest.fail if no ARP reply arrives within 3 s.
    """
    arp_req = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=ctx.our_mac) /
        ARP(op="who-has", hwsrc=ctx.our_mac, psrc=ctx.our_ip, pdst=ctx.sut_ip)
    )
    reply = srp1(arp_req, iface=ctx.iface, timeout=3, verbose=False)
    if reply is None:
        pytest.fail(
            f"[{label}] SUT does not respond to ARP after fuzz — likely crashed"
        )


def _release_syn_received(ctx, max_wait_s=5):
    """
    If the SUT is stuck in SYN_RECEIVED (because a fuzz SYN was accepted),
    free it by catching one of the SUT's SYN-ACK retransmits and sending a
    valid in-window RST.

    Algorithm:
      1. Sniff for any SYN+ACK from the SUT (it retransmits at ~1, 3, 7 … s).
      2. The SYN-ACK tells us:
           sport = 7         (SUT's local port)
           dport = fuzz_sport (the fuzz SYN's source port — what we need)
           ack   = rcv_nxt   (the next seq the SUT expects from that peer)
      3. Send RST(sport=fuzz_sport, dport=7, seq=ack).
         This RST is in-window (seq == rcv_nxt) so the SUT processes it in
         SYN_RECEIVED step 2 → CLOSED → TCP_EVT_RESET → want_listen →
         do_listen().
      4. Brief sleep so do_listen() completes before the caller sends a SYN.

    Returns True if a SYN-ACK was found and RST sent, False if none seen.
    """
    # BPF: TCP packets from the SUT with both SYN and ACK bits set (0x12).
    # 'tcp[13] & 18 == 18' matches flags byte where bits 1 (SYN) and 4 (ACK)
    # are both set.
    synacks = recv_tcp(ctx, timeout=max_wait_s, count=1,
                       extra_filter="tcp[13] & 18 == 18")
    if not synacks:
        return False

    sa = synacks[0]
    fuzz_sport = sa[TCP].dport   # the half-open connection's remote port
    rst_seq    = sa[TCP].ack     # SUT's rcv_nxt — the RST must have this seq

    rst = _eth_ip_tcp(ctx,
                      sport=fuzz_sport, dport=ctx.sut_port,
                      seq=rst_seq, ack=0, flags="R")
    send_pkt(ctx, rst)
    time.sleep(0.15)   # let SUT process RST, EVT_RESET, do_listen()
    return True


def _sanity_connect(ctx, label="sanity", retries=2, retry_delay=2.0):
    """
    Post-fuzz sanity check: verify the SUT is alive and (optionally) that it
    can still serve a TCP connection.

    Step 1 — ARP liveness (mandatory):
        Proves the SUT process is still running and the network layer is OK.
        If this fails the test is marked as a genuine crash.

    Step 2 — TCP connectivity (best-effort, retried):
        If the SUT is in SYN_RECEIVED from a fuzz SYN, we sniff for its
        SYN-ACK retransmit and RST the half-open connection, then retry.
        Failure here means the SUT is alive but TCP is broken — also a fail.
    """
    time.sleep(0.5)   # let any in-flight processing complete

    # ── Step 1: ARP alive ─────────────────────────────────────────────────────
    _assert_sut_alive(ctx, label)

    # ── Step 2: TCP connectivity ──────────────────────────────────────────────
    last_exc = None
    for attempt in range(retries):
        try:
            conn, _ = tcp_connect(ctx, alloc_port(), timeout=4)

            # Send data and ACK the echo before FIN to keep SUT's ack correct.
            echo_replies = tcp_send_recv_data(ctx, conn, b"fuzz-ok")
            for p in echo_replies:
                d = bytes(p[TCP].payload)
                if d:
                    conn.our_ack = p[TCP].seq + len(d)
            send_pkt(ctx, conn.ack())   # ACK echo before FIN
            conn.close()
            return           # success

        except AssertionError as e:
            last_exc = e
            # Got RST instead of SYN-ACK → SUT likely in SYN_RECEIVED.
            # Sniff for SUT's retransmit and RST the half-open connection.
            freed = _release_syn_received(ctx, max_wait_s=retry_delay)
            if not freed and attempt < retries - 1:
                time.sleep(retry_delay)   # retransmit not seen; wait and retry

    pytest.fail(
        f"[{label}] SUT alive (ARP OK) but TCP unresponsive "
        f"after {retries} attempts: {last_exc}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-001  Fuzz all TCP header fields
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_001_syn_header_fields(ctx, fuzz_count):
    """
    Fuzz all TCP header fields while sending frames to the listening port.
    SUT MUST NOT crash. ARP-based liveness verified at the end.

    fuzz(TCP(dport=ctx.sut_port)) generates frames with valid checksums but
    random flags, seq, ack, window, options, etc.  Some frames will cause
    the SUT to enter SYN_RECEIVED; the sanity check handles this gracefully.

    REQ-TCP-018 (bad checksum silent drop), robustness.
    """
    our_mac = ctx.our_mac
    sut_mac = ctx.sut_mac

    for i in range(fuzz_count):
        pkt = (
            Ether(dst=sut_mac, src=our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            fuzz(TCP(dport=ctx.sut_port))
        )
        sendp(pkt, iface=ctx.iface, verbose=False)
        if i % 50 == 49:
            time.sleep(0.05)

    _sanity_connect(ctx, label="fuzz_syn_header")


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-002  Fuzz data segments on established connection
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_002_data_segments_on_established(ctx, fuzz_count):
    """
    Open a real connection, then bombard it with fuzzed data segments.
    SUT MUST NOT crash; sanity verified afterwards.
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

    # Best-effort RST: fuzz may have already torn down the connection
    send_pkt(ctx, conn.rst())
    _sanity_connect(ctx, label="fuzz_data_established")


# ══════════════════════════════════════════════════════════════════════════════
# FUZZ-TCP-003  Fuzz flags byte — all 256 flag combinations
# ══════════════════════════════════════════════════════════════════════════════

def test_fuzz_003_all_flag_combinations(ctx):
    """
    Send every possible TCP flags value (0x00..0xFF) to the listening port.
    SUT MUST NOT crash on any flag combination.
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
    Send TCP segments shorter than the minimum header (< 20 bytes).
    SUT MUST NOT crash — truncated frames must be silently discarded.
    REQ-TCP-021: Data Offset >= 5 must be validated.
    """
    from scapy.all import raw

    for trunc_len in range(0, 20):
        full = (
            Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
            IP(src=ctx.our_ip, dst=ctx.sut_ip) /
            TCP(sport=alloc_port(), dport=ctx.sut_port,
                seq=next_isn(), flags="S", window=4096)
        )
        raw_bytes = raw(full)
        eth_ip_len = 14 + 20
        truncated = raw_bytes[:eth_ip_len + trunc_len]
        if len(truncated) >= 14:
            sendp(Ether(truncated), iface=ctx.iface, verbose=False)

    _sanity_connect(ctx, label="fuzz_truncated")
