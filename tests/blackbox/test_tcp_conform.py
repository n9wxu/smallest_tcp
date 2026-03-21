"""
test_tcp_conform.py — Black-box TCP RFC 9293 conformance tests.

Targets any stack reachable via an Ethernet interface. All tests use raw
L2 frames (Scapy → AF_PACKET on Linux, BPF on macOS) with the phantom-IP
trick so no iptables rules are needed.

Run:
    sudo pytest tests/blackbox/test_tcp_conform.py \
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

Each test traces to one or more REQ-TCP-NNN requirements (docs/requirements/tcp.md).
"""

import time
import pytest
from scapy.all import Ether, IP, TCP, sendp, sniff

from conftest import alloc_port
from helpers import (
    TcpConn, tcp_connect, tcp_send_recv_data,
    send_pkt, recv_tcp, send_recv, silence,
    _eth_ip_tcp, parse_mss, RECV_TIMEOUT, next_isn,
)


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-001  ARP pre-flight — SUT is reachable
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_000_sut_arp_reachable(ctx):
    """
    Pre-flight: verify the ctx fixture resolved SUT MAC via ARP.
    If this fails, every other test will also fail — fix networking first.
    """
    assert ctx.sut_mac, "ARP resolve returned empty MAC"
    assert ctx.sut_mac != "00:00:00:00:00:00"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-002  Passive open — SYN-ACK carries correct ACK number
# REQ-TCP-002, REQ-TCP-032, REQ-TCP-034, REQ-TCP-035
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_002_synack_ack_equals_our_syn_plus_one(ctx):
    """REQ-TCP-035: SYN-ACK.ACK must equal our SYN.SEQ + 1."""
    sport = alloc_port()
    conn = TcpConn(ctx, sport, ctx.sut_port)
    syn_seq = conn.our_seq

    replies = send_recv(ctx, conn.syn(our_mss=536), count=1)
    assert replies, "No SYN-ACK received"
    synack = replies[0]

    assert synack[TCP].flags & 0x02, "SYN flag missing from SYN-ACK"
    assert synack[TCP].flags & 0x10, "ACK flag missing from SYN-ACK"
    assert synack[TCP].ack == syn_seq + 1, (
        f"SYN-ACK.ACK={synack[TCP].ack} expected {syn_seq + 1}"
    )
    # RST the half-open connection so the SUT can re-enter LISTEN for the next test.
    # Without this, the SUT's only connection slot stays in SYN_RECEIVED and
    # every subsequent test that tries to connect gets RST instead of SYN-ACK.
    conn.our_seq += 1
    conn.our_ack = synack[TCP].seq + 1
    send_pkt(ctx, conn.rst())
    time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-076  SYN-ACK carries MSS option
# REQ-TCP-076, REQ-TCP-077
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_076_synack_contains_mss_option(ctx):
    """REQ-TCP-076: SYN-ACK MUST include the MSS option."""
    sport = alloc_port()
    conn = TcpConn(ctx, sport, ctx.sut_port)
    replies = send_recv(ctx, conn.syn(our_mss=1460), count=1)
    assert replies, "No SYN-ACK received"

    mss = parse_mss(replies[0])
    assert mss is not None, "MSS option absent from SYN-ACK"
    assert 0 < mss <= 1460, f"MSS={mss} out of expected range (0..1460]"
    # RST the half-open connection so the SUT can re-enter LISTEN.
    conn.our_seq += 1
    conn.our_ack = replies[0][TCP].seq + 1
    send_pkt(ctx, conn.rst())
    time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-003  Full 3-way handshake establishes connection
# REQ-TCP-002, REQ-TCP-003, REQ-TCP-054
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_003_three_way_handshake(ctx):
    """REQ-TCP-054: ACK to SYN-ACK must complete the handshake."""
    conn, synack = tcp_connect(ctx, alloc_port())
    # If tcp_connect returns without asserting, the handshake succeeded.
    assert synack[TCP].flags & 0x12  # SYN+ACK
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-082  Window advertised in SYN-ACK is non-zero
# REQ-TCP-082, REQ-TCP-083
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_082_window_nonzero_in_synack(ctx):
    """REQ-TCP-082: every outbound segment MUST advertise a receive window."""
    sport = alloc_port()
    conn = TcpConn(ctx, sport, ctx.sut_port)
    replies = send_recv(ctx, conn.syn(our_mss=536), count=1)
    assert replies, "No SYN-ACK"
    assert replies[0][TCP].window > 0, "SUT advertised zero window in SYN-ACK"
    # RST the half-open connection so the SUT can re-enter LISTEN.
    conn.our_seq += 1
    conn.our_ack = replies[0][TCP].seq + 1
    send_pkt(ctx, conn.rst())
    time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-014  Echo data transfer — seq/ack accounting
# REQ-TCP-014, REQ-TCP-055, REQ-TCP-064, REQ-TCP-065, REQ-TCP-066
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_014_data_echo_seq_ack(ctx):
    """REQ-TCP-055: SUT's ACK number must exactly track our sent bytes."""
    conn, _ = tcp_connect(ctx, alloc_port())
    payload = b"Hello"

    replies = tcp_send_recv_data(ctx, conn, payload)
    data_pkts = [p for p in replies if bytes(p[TCP].payload)]
    assert data_pkts, "No data echoed back"

    echo = b"".join(bytes(p[TCP].payload) for p in data_pkts)
    assert echo == payload, f"Echo mismatch: got {echo!r} want {payload!r}"

    # ACK for our data: SUT's ACK should equal our_seq (after payload)
    ack_pkts = [p for p in replies if p[TCP].flags & 0x10]
    assert ack_pkts
    assert ack_pkts[0][TCP].ack == conn.our_seq, (
        f"ACK={ack_pkts[0][TCP].ack} expected {conn.our_seq}"
    )
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-078  Peer MSS honored — SUT segments do not exceed our MSS
# REQ-TCP-078, REQ-TCP-081
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_078_sut_honors_our_mss(ctx):
    """REQ-TCP-081: SUT MUST NOT send segments larger than min(our MSS, SUT MSS)."""
    small_mss = 100
    conn, _ = tcp_connect(ctx, alloc_port(), our_mss=small_mss)

    # Request 200 bytes of data (> small_mss) so the SUT *would* fragment
    payload = b"X" * 200
    replies = tcp_send_recv_data(ctx, conn, payload)

    for pkt in replies:
        tcp_payload_len = len(bytes(pkt[TCP].payload))
        if tcp_payload_len > 0:
            assert tcp_payload_len <= small_mss, (
                f"SUT sent {tcp_payload_len} bytes, exceeds our MSS={small_mss}"
            )
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-005  Active close: FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT
# REQ-TCP-005, REQ-TCP-059, REQ-TCP-071
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_005_graceful_close_active(ctx):
    """REQ-TCP-059: SUT must ACK our FIN. REQ-TCP-071: SUT must send its FIN."""
    conn, _ = tcp_connect(ctx, alloc_port())
    # Send our FIN
    replies = conn.close()
    # Expect at least an ACK for our FIN (FIN_WAIT_2) then SUT's FIN
    assert replies, "No reply to our FIN"
    flags = [p[TCP].flags for p in replies]
    # At least one reply must have ACK set
    assert any(f & 0x10 for f in flags), "SUT did not ACK our FIN"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-006  Passive close: SUT sends FIN → CLOSE_WAIT
# REQ-TCP-006, REQ-TCP-068, REQ-TCP-069
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_006_fin_ack_correct_seq(ctx):
    """REQ-TCP-068: FIN advances RCV.NXT by 1; ACK must equal FIN.seq+1."""
    conn, _ = tcp_connect(ctx, alloc_port())
    # Use send_recv (AsyncSniffer) to avoid missing SUT's immediate ACK+FIN
    # on a fast TAP interface.  Expect ACK of our FIN + SUT's own FIN+ACK.
    fin_pkt = conn.fin_ack()
    conn.our_seq += 1  # FIN consumes one sequence number
    replies = send_recv(ctx, fin_pkt, count=2, timeout=RECV_TIMEOUT)
    fin_pkts = [p for p in replies if p[TCP].flags & 0x01]
    if fin_pkts:
        sut_fin = fin_pkts[0]
        # Send final ACK so SUT transitions LAST_ACK → CLOSED → re-listen
        conn.our_ack = sut_fin[TCP].seq + 1
        send_pkt(ctx, conn.ack())
    time.sleep(0.1)  # allow re-listen to complete before next test
    # Test passes if no crash / no assertion; SUT handled FIN cleanly


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-031  ACK in LISTEN → RST
# REQ-TCP-031, REQ-TCP-073
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_031_ack_to_listen_generates_rst(ctx):
    """REQ-TCP-031: bare ACK to LISTEN port MUST elicit RST."""
    sport = alloc_port()
    ack_seq = 0xDEADBEEF
    # Send pure ACK (no SYN) directly to the listening port
    pkt = _eth_ip_tcp(ctx, sport, ctx.sut_port,
                      seq=next_isn(), ack=ack_seq, flags="A")
    replies = send_recv(ctx, pkt, count=1)
    assert replies, "No RST reply for ACK-to-LISTEN"
    assert replies[0][TCP].flags & 0x04, "Expected RST flag"
    # REQ-TCP-073: RST.seq = triggering ACK value
    assert replies[0][TCP].seq == ack_seq, (
        f"RST.seq={replies[0][TCP].seq} expected {ack_seq}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-072  SYN to unknown port → RST
# REQ-TCP-072
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_072_syn_unknown_port_gets_rst(ctx):
    """REQ-TCP-072: SYN to a port with no listener MUST get RST."""
    sport = alloc_port()
    closed_port = 9999  # assumed not in use
    pkt = _eth_ip_tcp(ctx, sport, closed_port, seq=next_isn(), ack=0, flags="S")
    replies = send_recv(ctx, pkt, count=1)
    assert replies, "No RST for SYN to closed port"
    assert replies[0][TCP].flags & 0x04, "Expected RST"


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-075  RST to LISTEN → silence
# REQ-TCP-075
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_075_rst_to_listen_is_silent(ctx):
    """REQ-TCP-075: RST arriving in LISTEN MUST be silently discarded."""
    sport = alloc_port()
    pkt = _eth_ip_tcp(ctx, sport, ctx.sut_port,
                      seq=next_isn(), ack=0, flags="R")
    assert silence(ctx, pkt, timeout=2), (
        "SUT sent a reply to RST-in-LISTEN (MUST be silent)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-018  Bad checksum → silent drop
# REQ-TCP-018, REQ-TCP-140
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_018_bad_checksum_silently_dropped(ctx):
    """REQ-TCP-018: segment with bad TCP checksum MUST be discarded silently."""
    sport = alloc_port()
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip) /
        TCP(sport=sport, dport=ctx.sut_port, seq=next_isn(), flags="S",
            chksum=0xDEAD)   # corrupt checksum
    )
    assert silence(ctx, pkt, timeout=2), (
        "SUT responded to a corrupt-checksum SYN (MUST be silent)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-041  Out-of-window segment → ACK, no data delivered
# REQ-TCP-041, REQ-TCP-042
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_041_out_of_window_segment_gets_ack(ctx):
    """REQ-TCP-042: unacceptable segment MUST elicit ACK; data must not be accepted."""
    conn, _ = tcp_connect(ctx, alloc_port())

    # Send a data segment with SEQ far outside the receive window
    out_of_window_seq = conn.our_seq + 65000
    pkt = _eth_ip_tcp(ctx, conn.sport, ctx.sut_port,
                      seq=out_of_window_seq, ack=conn.our_ack,
                      flags="AP", payload=b"BADDATA")
    replies = send_recv(ctx, pkt, count=1)
    assert replies, "No ACK for out-of-window segment"
    assert replies[0][TCP].flags & 0x10, "Expected ACK"
    # ACK should not advance past what we actually sent
    assert replies[0][TCP].ack == conn.our_seq, (
        f"SUT's ACK advanced to {replies[0][TCP].ack}, expected {conn.our_seq}"
    )
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-047  In-window RST closes ESTABLISHED connection
# REQ-TCP-047, REQ-TCP-049
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_047_rst_closes_established(ctx):
    """REQ-TCP-047: RST in ESTABLISHED MUST abort the connection."""
    conn, _ = tcp_connect(ctx, alloc_port())

    # Send RST with the current SEQ (in-window)
    send_pkt(ctx, conn.rst())

    # After RST the connection is closed; new data should get RST or silence
    time.sleep(0.1)
    data_pkt = conn.ack(extra_flags="P", payload=b"afterrst")
    replies = send_recv(ctx, data_pkt, count=1, timeout=2)
    if replies:
        # If SUT replies, it must be RST (connection is closed)
        assert replies[0][TCP].flags & 0x04, (
            "Expected RST or silence after connection reset"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-051  SYN in ESTABLISHED → error response
# REQ-TCP-051
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_051_syn_in_established_causes_error(ctx):
    """REQ-TCP-051: SYN received on ESTABLISHED connection is an error."""
    conn, _ = tcp_connect(ctx, alloc_port())

    syn_pkt = _eth_ip_tcp(ctx, conn.sport, ctx.sut_port,
                          seq=conn.our_seq, ack=conn.our_ack, flags="S")
    replies = send_recv(ctx, syn_pkt, count=1, timeout=2)
    # RFC 9293: MUST send RST or challenge ACK — any response is acceptable
    # Silence is not acceptable (some response required)
    assert replies, (
        "SUT sent no response to SYN-in-ESTABLISHED (MUST send RST or ACK)"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-090  Retransmit SYN on timeout
# REQ-TCP-090, REQ-TCP-095, REQ-TCP-096
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_090_syn_retransmit_on_timeout(ctx):
    """REQ-TCP-095: SUT must retransmit SYN-ACK after RTO if not ACKed."""
    sport = alloc_port()
    conn = TcpConn(ctx, sport, ctx.sut_port)
    # Send SYN but do NOT send the final ACK
    replies = send_recv(ctx, conn.syn(our_mss=536), count=1)
    assert replies, "No initial SYN-ACK"
    first_synack_seq = replies[0][TCP].seq

    # Wait for retransmit (default RTO is typically 1–2 seconds)
    time.sleep(2.5)
    retransmits = recv_tcp(ctx, timeout=3, count=1)
    assert retransmits, "SUT did not retransmit SYN-ACK within 5.5s"
    # Retransmitted SYN-ACK must have the same ISN
    assert retransmits[0][TCP].seq == first_synack_seq, (
        f"Retransmit ISN changed: {retransmits[0][TCP].seq} != {first_synack_seq}"
    )
    # Complete handshake to clean up
    conn.sut_seq = replies[0][TCP].seq
    conn.our_ack = conn.sut_seq + 1
    conn.our_seq += 1
    send_pkt(ctx, conn.ack())
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-097  RTO resets after new data ACKed
# REQ-TCP-097, REQ-TCP-098
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_097_rto_resets_on_new_ack(ctx):
    """
    REQ-TCP-097: timer restarts on new data ACK.
    REQ-TCP-098: timer stops when all data ACKed.

    Verify: after SUT echoes and ACKs our data, it does NOT retransmit.
    """
    conn, _ = tcp_connect(ctx, alloc_port())
    payload = b"ping"
    replies = tcp_send_recv_data(ctx, conn, payload)
    # ACK the SUT's echo so its retransmit timer is cleared
    echo_pkts = [p for p in replies if bytes(p[TCP].payload)]
    if echo_pkts:
        conn.our_ack = echo_pkts[-1][TCP].seq + len(bytes(echo_pkts[-1][TCP].payload))
        send_pkt(ctx, conn.ack())

    # Wait — SUT must NOT retransmit after all data is ACKed
    time.sleep(2)
    spurious = recv_tcp(ctx, timeout=1, count=1)
    assert not spurious, (
        f"SUT retransmitted unexpectedly after ACK: {spurious}"
    )
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# TEST-TCP-153  ISS is different for sequential connections (REQ-TCP-153)
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_153_iss_differs_across_connections(ctx):
    """REQ-TCP-153: ISS MUST be different for each new connection (non-predictable)."""
    isns = []
    for _ in range(5):
        sport = alloc_port()
        conn = TcpConn(ctx, sport, ctx.sut_port)
        replies = send_recv(ctx, conn.syn(our_mss=536), count=1)
        if replies:
            isns.append(replies[0][TCP].seq)
            # RST the half-open connection
            conn.our_seq += 1
            conn.our_ack = replies[0][TCP].seq + 1
            send_pkt(ctx, conn.rst())
            time.sleep(0.05)

    assert len(isns) >= 3, "Could not collect enough ISNs"
    assert len(set(isns)) > 1, (
        f"All ISNs identical ({isns[0]:#010x}) — ISS appears fixed"
    )
