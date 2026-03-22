"""
test_dhcpv4_conform.py — DHCPv4 client conformance tests.

The SUT is dhcp_echo_demo (a DHCP client).  This test suite acts as a
DHCP server: it sniffs DISCOVERs, sends OFFERs/ACKs/NAKs, and verifies
the SUT's protocol behaviour.

Run with:
  sudo pytest tests/blackbox/test_dhcpv4_conform.py \
      --iface tap0                 \
      --dhcp-sut-mac 02:00:00:de:ad:01 \
      --dhcp-server-ip  10.0.0.1   \
      --dhcp-offered-ip 10.0.0.50  \
      -v

The SUT must already be started (by run_blackbox.sh or manually):
  sudo ./build/demo/dhcp_echo_demo tap0
"""

import time
import pytest
from scapy.all import (
    Ether, IP, UDP, ARP,
    BOOTP, DHCP,
    AsyncSniffer, sniff, sendp, srp1,
    get_if_hwaddr,
)

from helpers import (
    send_pkt, send_recv_arp,
    build_dhcp_server, send_recv_dhcp, sniff_dhcp_from_sut,
    dhcp_msg_type, dhcp_get_opt,
    DHCP_SERVER_PORT, DHCP_CLIENT_PORT, DHCP_BCAST_IP,
)

# DHCP message-type codes (RFC 2132 §9.6)
MSG_DISCOVER = 1
MSG_OFFER    = 2
MSG_REQUEST  = 3
MSG_ACK      = 5
MSG_NAK      = 6

# ── Shared DHCP exchange helper ────────────────────────────────────────────────

def _wait_for_discover(dctx, timeout=8):
    """
    Sniff on the TAP interface for a DHCP DISCOVER from the SUT.
    Returns the packet or raises AssertionError.
    """
    bpf = f"udp port 67 and ether src {dctx.sut_mac}"
    pkts = sniff(iface=dctx.iface, filter=bpf, timeout=timeout, count=1)
    assert pkts, (
        f"No DHCPDISCOVER from SUT ({dctx.sut_mac}) within {timeout}s — "
        "is dhcp_echo_demo running?"
    )
    return pkts[0]


def _offer_and_get_request(dctx, discover_pkt, timeout=5):
    """
    Send an OFFER in response to `discover_pkt`, wait for REQUEST.
    Returns (xid, request_pkt) or raises AssertionError.
    """
    xid = discover_pkt[BOOTP].xid
    offer = build_dhcp_server(
        dctx,
        msg_type="offer",
        xid=xid,
        yiaddr=dctx.offered_ip,
        server_ip=dctx.server_ip,
        lease=3600,
        subnet="255.255.255.0",
        router=dctx.server_ip,
    )
    replies = send_recv_dhcp(dctx, offer, timeout=timeout, count=1)
    assert replies, (
        f"No DHCPREQUEST from SUT after OFFER (xid=0x{xid:08x})"
    )
    req = replies[0]
    assert dhcp_msg_type(req) == MSG_REQUEST, (
        f"Expected DHCPREQUEST, got type {dhcp_msg_type(req)}"
    )
    return xid, req


def _complete_handshake(dctx, discover_pkt, timeout=5):
    """
    Run a full DISCOVER→OFFER→REQUEST→ACK exchange.
    Returns the ACK packet; also sets dctx.sut_ip = offered_ip after binding.
    """
    xid, req = _offer_and_get_request(dctx, discover_pkt, timeout=timeout)

    ack = build_dhcp_server(
        dctx,
        msg_type="ack",
        xid=xid,
        yiaddr=dctx.offered_ip,
        server_ip=dctx.server_ip,
        lease=3600,
        subnet="255.255.255.0",
        router=dctx.server_ip,
    )
    send_pkt(dctx, ack)
    # Give the SUT time to process the ACK and configure its IP
    time.sleep(0.3)
    dctx.sut_ip = dctx.offered_ip
    return ack


# ══════════════════════════════════════════════════════════════════════════════
# Test cases
# ══════════════════════════════════════════════════════════════════════════════

# REQ-DHCPv4-002: SUT sends DISCOVER on startup
# REQ-DHCPv4-008: op=1 (BOOTREQUEST)
# REQ-DHCPv4-012: magic cookie present
# REQ-DHCPv4-013: message-type option = 1 (DISCOVER)
# REQ-DHCPv4-016: UDP dport = 67
# REQ-DHCPv4-017: dst IP = 255.255.255.255
def test_sut_sends_discover(dhcp_ctx, dhcp_sut_fresh):
    """SUT broadcasts a well-formed DHCPDISCOVER on startup."""
    d = _wait_for_discover(dhcp_ctx)

    # REQ-DHCPv4-008: BOOTREQUEST
    assert d[BOOTP].op == 1, f"Expected op=1 (BOOTREQUEST), got {d[BOOTP].op}"
    # REQ-DHCPv4-013: message type
    assert dhcp_msg_type(d) == MSG_DISCOVER, (
        f"Expected DHCPDISCOVER (1), got {dhcp_msg_type(d)}"
    )
    # REQ-DHCPv4-012: DHCP magic cookie
    assert d[BOOTP].options == b"c\x82Sc", (
        "BOOTP magic cookie missing or wrong"
    )
    # REQ-DHCPv4-016,017: broadcast destination
    assert d[IP].dst == "255.255.255.255", (
        f"DISCOVER not broadcast: dst={d[IP].dst}"
    )
    assert d[UDP].dport == 67, f"DISCOVER UDP dport should be 67, got {d[UDP].dport}"
    assert d[UDP].sport == 68, f"DISCOVER UDP sport should be 68, got {d[UDP].sport}"
    # REQ-DHCPv4-011: chaddr = SUT MAC
    chaddr_bytes = bytes.fromhex(dhcp_ctx.sut_mac.replace(":", ""))
    assert d[BOOTP].chaddr[:6] == chaddr_bytes, (
        f"chaddr mismatch: {d[BOOTP].chaddr[:6].hex()} != {chaddr_bytes.hex()}"
    )


# REQ-DHCPv4-018: OFFER triggers REQUEST
# REQ-DHCPv4-019: REQUEST echoes xid
# REQ-DHCPv4-020: REQUEST contains Requested IP option = offered IP
def test_offer_triggers_request(dhcp_ctx, dhcp_sut_fresh):
    """OFFER → SUT sends a valid DHCPREQUEST with correct XID and Requested IP."""
    d = _wait_for_discover(dhcp_ctx)
    xid = d[BOOTP].xid
    _, req = _offer_and_get_request(dhcp_ctx, d)

    # REQ-DHCPv4-019: XID echoed
    assert req[BOOTP].xid == xid, (
        f"REQUEST XID 0x{req[BOOTP].xid:08x} != DISCOVER XID 0x{xid:08x}"
    )
    # REQ-DHCPv4-020: Requested IP option
    req_ip = dhcp_get_opt(req, "requested_addr")
    assert req_ip == dhcp_ctx.offered_ip, (
        f"Requested IP {req_ip} != offered IP {dhcp_ctx.offered_ip}"
    )
    # REQ-DHCPv4-021: Server ID option matches our server IP
    server_id = dhcp_get_opt(req, "server_id")
    assert server_id == dhcp_ctx.server_ip, (
        f"Server ID {server_id} != our server IP {dhcp_ctx.server_ip}"
    )


# REQ-DHCPv4-028..036: ACK → SUT configures IP, replies to ARP
@pytest.mark.sut_specific
def test_ack_binds_ip(dhcp_ctx, dhcp_sut_fresh):
    """Full DISCOVER→OFFER→REQUEST→ACK; after ACK the SUT's IP is reachable via ARP."""
    d = _wait_for_discover(dhcp_ctx)
    _complete_handshake(dhcp_ctx, d)

    # REQ-DHCPv4-029: verify SUT IP is bound by ARP-resolving it
    arp_req = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=dhcp_ctx.our_mac) /
        ARP(op="who-has",
            hwsrc=dhcp_ctx.our_mac, psrc=dhcp_ctx.our_ip,
            hwdst="00:00:00:00:00:00", pdst=dhcp_ctx.offered_ip)
    )
    replies = send_recv_arp(dhcp_ctx, arp_req, timeout=3)
    assert replies, (
        f"No ARP reply for {dhcp_ctx.offered_ip} after DHCP bind — "
        "SUT did not configure its IP"
    )
    sut_mac = replies[0][ARP].hwsrc
    assert sut_mac.lower() == dhcp_ctx.sut_mac.lower(), (
        f"ARP reply MAC {sut_mac} != SUT MAC {dhcp_ctx.sut_mac}"
    )


# REQ-DHCPv4-037: NAK → SUT restarts discovery (sends new DISCOVER)
@pytest.mark.sut_specific
def test_nak_triggers_rediscover(dhcp_ctx, dhcp_sut_fresh):
    """NAK after REQUEST causes SUT to restart DISCOVER."""
    d = _wait_for_discover(dhcp_ctx)
    xid, _req = _offer_and_get_request(dhcp_ctx, d)

    # Send NAK
    nak = build_dhcp_server(
        dhcp_ctx,
        msg_type="nak",
        xid=xid,
        yiaddr="0.0.0.0",
        server_ip=dhcp_ctx.server_ip,
        lease=0,
    )
    send_pkt(dhcp_ctx, nak)

    # Wait for a new DISCOVER
    time.sleep(0.5)
    d2 = _wait_for_discover(dhcp_ctx, timeout=8)
    assert dhcp_msg_type(d2) == MSG_DISCOVER, (
        f"Expected new DISCOVER after NAK, got type {dhcp_msg_type(d2)}"
    )


# REQ-DHCPv4-023: OFFER with wrong XID must be silently ignored
@pytest.mark.sut_specific
def test_wrong_xid_offer_ignored(dhcp_ctx, dhcp_sut_fresh):
    """OFFER with a wrong XID must not trigger a REQUEST."""
    d = _wait_for_discover(dhcp_ctx)
    correct_xid = d[BOOTP].xid
    wrong_xid = (correct_xid ^ 0xDEAD0000) & 0xFFFFFFFF

    # Arm sniffer BEFORE sending the bad OFFER
    bpf = f"udp port 67 and ether src {dhcp_ctx.sut_mac}"
    sniffer = AsyncSniffer(iface=dhcp_ctx.iface, filter=bpf,
                           count=1, timeout=2)
    sniffer.start()
    time.sleep(0.05)

    bad_offer = build_dhcp_server(
        dhcp_ctx,
        msg_type="offer",
        xid=wrong_xid,
        yiaddr=dhcp_ctx.offered_ip,
        server_ip=dhcp_ctx.server_ip,
        lease=3600,
    )
    send_pkt(dhcp_ctx, bad_offer)
    sniffer.join(timeout=3)

    if sniffer.results:
        # Any reply with a REQUEST for the wrong XID is a bug
        for pkt in sniffer.results:
            assert dhcp_msg_type(pkt) != MSG_REQUEST, (
                f"SUT sent DHCPREQUEST for wrong XID 0x{wrong_xid:08x}"
            )


# REQ-DHCPv4-025: DISCOVER ciaddr must be 0.0.0.0 (no IP before binding)
def test_discover_ciaddr_is_zero(dhcp_ctx, dhcp_sut_fresh):
    """DISCOVER ciaddr must be 0.0.0.0 (SUT has no IP yet)."""
    d = _wait_for_discover(dhcp_ctx)
    assert d[BOOTP].ciaddr == "0.0.0.0", (
        f"DISCOVER ciaddr should be 0.0.0.0, got {d[BOOTP].ciaddr}"
    )


# REQ-DHCPv4-045: SUT retransmits DISCOVER if no reply arrives
@pytest.mark.sut_specific
def test_discover_retransmit(dhcp_ctx, dhcp_sut_fresh):
    """SUT retransmits DISCOVER if no server responds (REQ-DHCPv4-045)."""
    # Capture first DISCOVER but DON'T reply
    d1 = _wait_for_discover(dhcp_ctx, timeout=8)
    xid1 = d1[BOOTP].xid

    # Wait for retransmit (SUT retransmits after ~4s)
    d2 = _wait_for_discover(dhcp_ctx, timeout=12)
    assert dhcp_msg_type(d2) == MSG_DISCOVER, (
        "Expected retransmitted DISCOVER, got something else"
    )
    # REQ-DHCPv4-046: XID must be stable across retransmits
    assert d2[BOOTP].xid == xid1, (
        f"XID changed across retransmit: {xid1:#010x} → {d2[BOOTP].xid:#010x}"
    )


# REQ-DHCPv4-070: RELEASE is sent when dhcp_echo_demo shuts down
# (tested here as a parse-only check — the SUT must be killed externally)
# This test is marked 'sut_specific' and skipped in the reference-SUT run.
@pytest.mark.sut_specific
def test_request_contains_server_id(dhcp_ctx, dhcp_sut_fresh):
    """REQUEST contains the Server Identifier option (RFC 2131 §4.3.2)."""
    d = _wait_for_discover(dhcp_ctx)
    _, req = _offer_and_get_request(dhcp_ctx, d)

    server_id = dhcp_get_opt(req, "server_id")
    assert server_id is not None, "REQUEST missing Server Identifier option"
    assert server_id == dhcp_ctx.server_ip, (
        f"Server Identifier {server_id} != offered server IP {dhcp_ctx.server_ip}"
    )
