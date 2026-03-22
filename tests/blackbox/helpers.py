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
    time.sleep(0.05)          # give the kernel time to register the socket
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
    time.sleep(0.05)
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
        # Check SYN and ACK bits independently.
        # flags & 0x12 is NOT sufficient: RST+ACK (0x14) also satisfies it
        # because 0x14 & 0x12 = 0x10 (truthy) even though SYN bit is absent.
        # A false positive here would accept an RST as a SYN-ACK, causing
        # _sanity_connect() to return "success" while the SUT is still stuck
        # in SYN_RECEIVED, corrupting all subsequent tests.
        assert synack[TCP].flags & 0x02, (
            f"SYN flag missing — got {synack[TCP].flags!r} instead of SYN+ACK"
        )
        assert synack[TCP].flags & 0x10, (
            f"ACK flag missing — got {synack[TCP].flags!r} instead of SYN+ACK"
        )

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
        # Give the SUT time to process the final ACK, exit LAST_ACK, run the
        # do_listen() usleep(50 ms), and return to LISTEN before the next test
        # sends a SYN.  Without this pause the next test's SYN can arrive
        # while the SUT is still in CLOSED/LAST_ACK and receive RST.
        time.sleep(0.15)
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
    Send payload bytes and collect the immediate TCP replies (ACK + echo data).

    count=2 captures the SUT's pure ACK of our data and its echo segment.
    Using count > 2 would force a 3-second wait while the sniffer hunts for
    more packets; during that time the SUT retransmits its un-ACKed echo
    segment, causing concatenated duplicate payloads ("HelloHello" instead
    of "Hello") and false test failures.
    """
    pkt = conn.ack(extra_flags="P", payload=payload)
    return send_recv(ctx, pkt, timeout=timeout, count=2)


# ── TCP option parsing ─────────────────────────────────────────────────────────

def parse_mss(pkt):
    """Return the MSS value from a TCP packet's options, or None."""
    if TCP not in pkt:
        return None
    for kind, val in (pkt[TCP].options or []):
        if kind == "MSS":
            return val
    return None


# ── ARP helpers ────────────────────────────────────────────────────────────────

from scapy.all import ARP, ICMP, UDP, IP as ScapyIP

def build_arp(ctx, op="who-has", target_ip=None):
    """Build an ARP request (who-has) or reply directed at the SUT."""
    if target_ip is None:
        target_ip = ctx.sut_ip
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=ctx.our_mac) /
        ARP(op=op, hwsrc=ctx.our_mac, psrc=ctx.our_ip,
            hwdst="00:00:00:00:00:00", pdst=target_ip)
    )


def send_recv_arp(ctx, pkt, timeout=RECV_TIMEOUT):
    """Send pkt and return ARP replies from the SUT."""
    bpf = f"arp and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=1, timeout=timeout)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return list(sniffer.results)


# ── ICMP helpers ───────────────────────────────────────────────────────────────

def build_icmp_echo(ctx, id=1, seq=1, data=b"ping", dst_ip=None, dst_mac=None):
    """Build an ICMP Echo Request toward the SUT."""
    if dst_ip is None:
        dst_ip = ctx.sut_ip
    if dst_mac is None:
        dst_mac = ctx.sut_mac
    return (
        Ether(dst=dst_mac, src=ctx.our_mac) /
        ScapyIP(src=ctx.our_ip, dst=dst_ip) /
        ICMP(type=8, code=0, id=id, seq=seq) /
        data
    )


def send_recv_icmp(ctx, pkt, timeout=RECV_TIMEOUT, count=1):
    """Send pkt and return ICMP replies from the SUT."""
    bpf = f"icmp and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=count, timeout=timeout)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return list(sniffer.results)


# ── UDP helpers ────────────────────────────────────────────────────────────────

def build_udp(ctx, sport, dport, payload=b"", bad_checksum=False,
              udp_len_override=None):
    """Build an Ethernet/IP/UDP frame using the phantom IP."""
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        ScapyIP(src=ctx.our_ip, dst=ctx.sut_ip) /
        UDP(sport=sport, dport=dport) /
        payload
    )
    if bad_checksum:
        pkt[UDP].chksum = 0xDEAD
    if udp_len_override is not None:
        pkt[UDP].len = udp_len_override
    return pkt


def send_recv_udp(ctx, pkt, timeout=RECV_TIMEOUT, count=1):
    """Send pkt and return UDP replies from the SUT."""
    bpf = f"udp and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=count, timeout=timeout)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return list(sniffer.results)


# ── Raw IPv4 helpers ───────────────────────────────────────────────────────────

def build_ip_raw(ctx, proto, payload=b"", bad_ip_checksum=False,
                 ihl=5, flags=2, frag=0, ttl=64, dst_ip=None):
    """Build Ethernet/IP with arbitrary protocol and payload."""
    if dst_ip is None:
        dst_ip = ctx.sut_ip
    pkt = (
        Ether(dst=ctx.sut_mac, src=ctx.our_mac) /
        ScapyIP(src=ctx.our_ip, dst=dst_ip, proto=proto,
                ihl=ihl, flags=flags, frag=frag, ttl=ttl) /
        payload
    )
    if bad_ip_checksum:
        pkt[ScapyIP].chksum = 0xDEAD
    return pkt


# ── DHCP helpers ──────────────────────────────────────────────────────────────

from scapy.all import BOOTP, DHCP

# Well-known DHCP field constants
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_BCAST_IP    = "255.255.255.255"
DHCP_BCAST_MAC   = "ff:ff:ff:ff:ff:ff"


def build_dhcp(ctx, msg_type, xid=None,
               server_ip="0.0.0.0", our_ip="0.0.0.0",
               offered_ip="0.0.0.0", extra_opts=None,
               yiaddr="0.0.0.0", siaddr="0.0.0.0",
               src_ip="0.0.0.0", dst_ip=None, dst_mac=None,
               chaddr=None):
    """
    Build a raw Ethernet/IP/UDP/BOOTP/DHCP packet.

    msg_type: "discover" | "offer" | "request" | "ack" | "nak" | "release"
    xid     : transaction ID (int); auto-generated if None
    """
    import random
    if xid is None:
        xid = random.randint(0, 0xFFFFFFFF)
    if dst_ip is None:
        dst_ip = DHCP_BCAST_IP
    if dst_mac is None:
        dst_mac = DHCP_BCAST_MAC
    if chaddr is None:
        chaddr = ctx.our_mac

    dhcp_opts = [("message-type", msg_type), "end"]
    if extra_opts:
        # Insert before "end"
        dhcp_opts = [("message-type", msg_type)] + list(extra_opts) + ["end"]

    pkt = (
        Ether(dst=dst_mac, src=ctx.our_mac) /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT) /
        BOOTP(op=1, xid=xid, chaddr=chaddr,
              yiaddr=yiaddr, siaddr=siaddr,
              flags=0x8000) /  # broadcast flag
        DHCP(options=dhcp_opts)
    )
    return pkt, xid


def build_dhcp_server(ctx, msg_type, xid,
                      yiaddr, server_ip,
                      lease=3600, t1=0, t2=0,
                      subnet="255.255.255.0", router=None,
                      dst_mac=None):
    """
    Build a DHCP server reply (OFFER / ACK / NAK) to send to the SUT.

    The SUT's MAC is used as dst_mac and the src_ip is server_ip.
    """
    if dst_mac is None:
        dst_mac = ctx.sut_mac if hasattr(ctx, "sut_mac") else DHCP_BCAST_MAC

    opts = [
        ("server_id", server_ip),
        ("lease_time", lease),
    ]
    if subnet:
        opts.append(("subnet_mask", subnet))
    if router:
        opts.append(("router", router))
    if t1:
        opts.append(("renewal_time", t1))
    if t2:
        opts.append(("rebinding_time", t2))

    dhcp_opts = [("message-type", msg_type)] + opts + ["end"]

    pkt = (
        Ether(dst=dst_mac, src=ctx.our_mac) /
        IP(src=server_ip, dst=DHCP_BCAST_IP) /
        UDP(sport=DHCP_SERVER_PORT, dport=DHCP_CLIENT_PORT) /
        BOOTP(op=2, xid=xid, yiaddr=yiaddr, siaddr=server_ip,
              chaddr=ctx.sut_mac if hasattr(ctx, "sut_mac") else DHCP_BCAST_MAC,
              flags=0x8000) /
        DHCP(options=dhcp_opts)
    )
    return pkt


def send_recv_dhcp(ctx, pkt, timeout=5, count=1):
    """
    Send a DHCP packet and return DHCP replies (UDP port 67) from the SUT.
    Uses AsyncSniffer to avoid the send-then-sniff race.
    """
    bpf = f"udp port 67 and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=count, timeout=timeout)
    sniffer.start()
    time.sleep(0.05)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return list(sniffer.results)


def sniff_dhcp_from_sut(ctx, timeout=5, count=1, bpf_extra=""):
    """
    Sniff DHCP messages sent BY the SUT (UDP sport=68) without sending anything.
    Useful for waiting for the first DISCOVER after SUT startup.
    """
    bpf = f"udp port 67 and ether src {ctx.sut_mac}"
    if bpf_extra:
        bpf += f" and {bpf_extra}"
    pkts = sniff(iface=ctx.iface, filter=bpf, timeout=timeout, count=count)
    return list(pkts)


def dhcp_msg_type(pkt):
    """Return the DHCP message-type integer from a captured Scapy packet."""
    if DHCP not in pkt:
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return opt[1]
    return None


def dhcp_get_opt(pkt, name):
    """Return a DHCP option value by name, or None."""
    if DHCP not in pkt:
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == name:
            return opt[1]
    return None


# ── Multi-protocol silence check ───────────────────────────────────────────────

def silence_any(ctx, pkt, timeout=2):
    """
    Send pkt and verify no IP reply (TCP/UDP/ICMP) arrives from SUT.
    Returns True on silence (test passes).
    """
    bpf = f"ip and ether src {ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=ctx.iface, filter=bpf,
                           count=1, timeout=timeout)
    sniffer.start()
    time.sleep(0.02)
    send_pkt(ctx, pkt)
    sniffer.join(timeout=timeout + 1)
    return len(sniffer.results) == 0
