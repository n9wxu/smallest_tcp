"""
helpers.py — Packet-building and send/receive helpers for black-box tests.

All helpers take a SutContext (from conftest.py) as their first argument.
They build raw Ethernet+IP+TCP frames using the phantom source IP so the
local kernel's TCP stack never sees the replies.
"""

import time
from scapy.all import (
    Ether, IP, TCP,
    sendp, sniff, srp1,
    AsyncSniffer,
)


# ── Receive timeout (seconds) ──────────────────────────────────────────────────
RECV_TIMEOUT = 3

# ── Initial sequence number seed (incremented per call) ────────────────────────
_isn_seed = 0x12345678


def next_isn():
    """Return a new ISN that is different each call (not random — deterministic
    for reproducibility, but different enough to avoid SUT's TIME_WAIT)."""
    global _isn_seed
    _isn_seed = (_isn_seed + 0x00010001) & 0xFFFFFFFF
    return _isn_seed


# ── Low-level frame send / receive ─────────────────────────────────────────────

def _eth_ip_tcp(ctx, sport, dport, seq, ack, flags, window=4096,
                options=None, payload=b""):
    """Build a complete Ethernet+IP+TCP frame using the phantom IP."""
    tcp_kwargs = dict(sport=sport, dport=dport, seq=seq, ack=ack,
                      flags=flags, window=window)
    if options is not None:
        tcp_kwargs["options"] = options
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        IP(src=ctx.our_ip, dst=ctx.sut_ip) /
        TCP(**tcp_kwargs)
    )
    if payload:
        pkt = pkt / payload
    return pkt


def send_pkt(ctx, pkt):
    """Send a packet (no receive)."""
    sendp(pkt, iface=ctx.iface, verbose=False)


def recv_tcp(ctx, timeout=RECV_TIMEOUT, count=1, extra_filter=""):
    """
    Sniff TCP packets *from* the SUT addressed to our phantom MAC.
    Returns a list of matching packets.
    """
    bpf = f"tcp and ether src {ctx.sut_mac}"
    if extra_filter:
        bpf += f" and {extra_filter}"
    pkts = sniff(iface=ctx.iface, filter=bpf, timeout=timeout, count=count)
    return pkts


def send_recv(ctx, pkt, timeout=RECV_TIMEOUT, count=1):
    """Send pkt and wait for up to `count` TCP replies from the SUT.

    Uses AsyncSniffer to open the AF_PACKET capture socket BEFORE sending.
    On a fast TAP/loopback interface the SUT can reply within microseconds;
    the classic send-then-sniff pattern misses the reply because the socket
    is not yet open when the reply arrives.  AsyncSniffer eliminates that
    race: we arm the socket, yield briefly to let the kernel register it,
    then send the stimulus.
    """
    bpf = f"tcp and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=count, timeout=timeout)
    sniffer.start()
    time.sleep(0.02)          # give the kernel time to register the socket
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return list(sniffer.results)


def silence(ctx, pkt, timeout=2):
    """
    Send pkt and verify no TCP reply arrives within timeout.
    Returns True if silence observed (test passes), False otherwise.

    Also uses AsyncSniffer so we don't miss a fast reply.
    """
    bpf = f"tcp and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=1, timeout=timeout)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return len(sniffer.results) == 0


# ── TCP handshake helpers ──────────────────────────────────────────────────────

class TcpConn:
    """
    Lightweight manual TCP connection state for use in tests.
    Tracks seq/ack numbers so tests can build in-order segments easily.
    """
    def __init__(self, ctx, sport, dport):
        self.ctx    = ctx
        self.sport  = sport
        self.dport  = dport
        self.our_seq = next_isn()
        self.our_ack = 0          # set after SYN-ACK received
        self.sut_seq = 0          # SUT's ISN, set after SYN-ACK
        self.sut_mss = 0          # SUT's advertised MSS, parsed from SYN-ACK

    # ── Build helpers ──────────────────────────────────────────────────────────

    def syn(self, our_mss=None):
        """Build a SYN packet (optionally with MSS option)."""
        opts = [("MSS", our_mss)] if our_mss else []
        return _eth_ip_tcp(self.ctx, self.sport, self.dport,
                           seq=self.our_seq, ack=0, flags="S",
                           options=opts if opts else None)

    def ack(self, extra_flags="", payload=b""):
        """Build an ACK (or ACK+data) using current seq/ack state."""
        flags = "A" + extra_flags
        pkt = _eth_ip_tcp(self.ctx, self.sport, self.dport,
                          seq=self.our_seq, ack=self.our_ack,
                          flags=flags, payload=payload)
        if payload:
            self.our_seq += len(payload)
        return pkt

    def fin_ack(self):
        """Build a FIN+ACK."""
        return _eth_ip_tcp(self.ctx, self.sport, self.dport,
                           seq=self.our_seq, ack=self.our_ack, flags="FA")

    def rst(self):
        """Build a RST."""
        return _eth_ip_tcp(self.ctx, self.sport, self.dport,
                           seq=self.our_seq, ack=self.our_ack, flags="R")

    # ── Handshake ──────────────────────────────────────────────────────────────

    def connect(self, our_mss=536, timeout=RECV_TIMEOUT):
        """
        Perform SYN → SYN-ACK → ACK handshake.
        Returns the SYN-ACK packet on success, raises AssertionError on failure.
        """
        replies = send_recv(self.ctx, self.syn(our_mss=our_mss),
                            timeout=timeout, count=1)
        assert replies, (
            f"No SYN-ACK from {self.ctx.sut_ip}:{self.dport} "
            f"(sport={self.sport})"
        )
        synack = replies[0]
        assert synack[TCP].flags & 0x12, "Expected SYN+ACK flags"  # SA

        self.sut_seq = synack[TCP].seq
        self.our_ack = self.sut_seq + 1   # ACK = SYN-ACK.seq + 1
        self.our_seq += 1                  # our SYN consumed one seq number

        # Parse MSS option from SYN-ACK
        for kind, val in (synack[TCP].options or []):
            if kind == "MSS":
                self.sut_mss = val

        # Send ACK to complete handshake
        send_pkt(self.ctx, self.ack())
        return synack

    def close(self, timeout=RECV_TIMEOUT):
        """Send FIN+ACK and wait for SUT's FIN+ACK, then send final ACK.

        Uses send_recv (AsyncSniffer) so we don't miss the SUT's ACK/FIN
        on a fast TAP interface where the reply can arrive before a naive
        send-then-sniff socket is even open.
        """
        fin_pkt = self.fin_ack()
        self.our_seq += 1  # FIN consumes a sequence number
        # Expect up to 2 replies: ACK of our FIN, then SUT's own FIN+ACK
        replies = send_recv(self.ctx, fin_pkt, timeout=timeout, count=2)
        for pkt in replies:
            if pkt[TCP].flags & 0x01:  # FIN flag set
                self.our_ack = pkt[TCP].seq + 1
                send_pkt(self.ctx, self.ack())
                break
        return replies


def tcp_connect(ctx, sport, dport=None, our_mss=536, timeout=RECV_TIMEOUT):
    """
    Convenience: create a TcpConn, run the handshake, return (conn, synack).
    dport defaults to ctx.sut_port.
    """
    if dport is None:
        dport = ctx.sut_port
    conn = TcpConn(ctx, sport, dport)
    synack = conn.connect(our_mss=our_mss, timeout=timeout)
    return conn, synack


def tcp_send_recv_data(ctx, conn, payload, timeout=RECV_TIMEOUT):
    """
    Send payload bytes and collect all TCP replies (data + ACK).
    Returns list of reply packets.
    """
    pkt = conn.ack(extra_flags="P", payload=payload)
    return send_recv(ctx, pkt, timeout=timeout, count=4)


# ── TCP option parsing ─────────────────────────────────────────────────────────

def parse_mss(pkt):
    """Return the MSS value from a TCP packet's options, or None."""
    if TCP not in pkt:
        return None
    for kind, val in (pkt[TCP].options or []):
        if kind == "MSS":
            return val
    return None
