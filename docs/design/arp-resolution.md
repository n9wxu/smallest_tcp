# Address Resolution — Design

**Files:** `include/arp.h`, `src/arp.c`; IPv6 in `src/ndp.c`, `src/ipv6.c`
**Last updated:** 2026-09-27

## 1. No cache

The stack keeps **no ARP cache and no IPv6 neighbour cache**.  Link-layer
addresses live where they are used:

| Where | Holds | Filled by |
|---|---|---|
| `net_t.gateway_mac`, `gateway_mac_valid` | The IPv4 gateway's MAC | `arp_input()`, from an ARP *reply* whose sender IP is `net->gateway_ipv4` |
| `net_t.ip6.router.mac` | The IPv6 default router's MAC | Router Advertisements (Source Link-Layer Address option, else the frame's source) |
| `tcp_conn_t.remote_mac`, `mac_valid` | The peer's (or next hop's) MAC for the connection's life | The SYN that opened a passive connection, or the `remote_mac` argument of `tcp_connect()` / `tcp6_connect()` |
| `tftp_client_t.server_mac` | The TFTP server's MAC | The `server_mac` argument of `tftp_client_get()` |

A cache costs RAM per entry, needs ageing timers, and still has to be sized
for the worst case.  A small device talks to a few peers, and most of its
traffic is replies — which need no resolution at all (§2).

## 2. Where each frame's destination MAC comes from

| Traffic | Destination MAC |
|---|---|
| **Replies** — ARP replies, ICMP echo replies and errors, UDP replies built from a handler's `src_mac`, TCP segments on a passively opened connection, NDP Neighbor Advertisements | The source MAC of the frame being answered.  On a single link that is the sender itself or the router that forwarded the packet, so the reply takes the right first hop without a lookup. |
| **The DHCPv4 client's renewals and RELEASE** | The source MAC of the server's last ACK — the server, or the relay agent on the way to it ([dhcpv4.md §3.4](dhcpv4.md#34-messages-sent)) |
| **Broadcast and multicast** — the DHCPv4 client's other messages, DHCPv4 server replies that must be broadcast, mDNS, IGMP, MLD, NDP solicitations, DHCPv6 | Computed: broadcast, `ipv4_mcast_mac()` (01:00:5e + 23 bits), `ipv6_mcast_mac()` (33:33 + 32 bits) |
| **New conversations** — `udp_send()`, `tcp_connect()`, `tftp_client_get()` | Supplied by the application (§3) |

## 3. Resolving a MAC for an active open

The stack provides the pieces; the application sequences them.

```c
uint32_t arp_next_hop(const net_t *net, uint32_t dst_ip); /* dst_ip if on-link, a broadcast or a group, else gateway */
net_err_t arp_request(net_t *net, uint32_t target_ip);    /* broadcast a request */
```

`arp_next_hop()` compares the destination with our address under
`net->subnet_mask` (`ipv4_is_local()`).  The limited broadcast and multicast
groups are their own next hop, never the gateway: they go straight to the
link, at the broadcast MAC or the group's (RFC 1122 §3.3.1.1, RFC 1112 §6.2;
REQ-ARP-041).  Because the only MAC the stack
learns from ARP is the gateway's, a peer on the local subnet is resolved by
pointing the gateway at it for the duration — this is what the `tls_client`
demo does:

```c
uint32_t hop = arp_next_hop(&net, server);
net.gateway_ipv4 = hop;          /* learn this MAC */
net.gateway_mac_valid = 0;
while (!net.gateway_mac_valid && !timed_out()) {
  if (every_500_ms())
    arp_request(&net, hop);
  /* net_poll(), net_tick() ... */
}
tcp_connect(&net, &conn, server, net.gateway_mac, port, local_port);
```

This changes where all off-link traffic goes while it is in effect; a device
that also needs its real gateway must restore `gateway_ipv4` and resolve it
again afterwards.  A device that only talks through its gateway resolves the
gateway once and leaves it.

**A gateway from DHCP.**  The DHCPv4 client sets `gateway_ipv4` from the
lease's router option, and clears it with the address.  Whenever that
changes the gateway it also clears `gateway_mac_valid` (REQ-DHCPv4-048):
the MAC held was the old gateway's.  The application resolves the new one
as above — `arp_request(&net, net.gateway_ipv4)` after `DHCPV4_EVT_BOUND`
or `DHCPV4_EVT_RENEWED` while `gateway_mac_valid` is 0 — and the
gateway's reply fills in `gateway_mac` (REQ-DHCPv4-049).  A renewal that
keeps the gateway keeps its MAC.

**Retries and time-outs are the application's** (the demo retries every
500 ms).  The stack keeps two ARP timers of its own, run by `arp_tick()` from
`net_tick()`:

- **No flooding** (REQ-ARP-039, RFC 1122 §2.3.2.1): `arp_request()` remembers
  the targets it asked for in the last second (`NET_ARP_RATE_SLOTS`, default
  2) and refuses, with `NET_ERR_BUSY` and nothing sent, to ask for one of
  them again — or for any target while every slot is in use.  A demo
  retrying every 500 ms therefore sends a request a second.
- **Out-of-date entries flushed** (REQ-ARP-038): a gateway MAC learned from
  an ARP reply is valid for `NET_ARP_GATEWAY_TIMEOUT_MS` (5 minutes by
  default, configurable), and each reply from the gateway starts the time
  again; then `gateway_mac_valid` drops to 0 and the application resolves it
  afresh.  A MAC the application sets by hand (`gateway_mac_s` 0) does not
  expire.  The former
`NET_DEFAULT_ARP_RETRY_MS` / `NET_DEFAULT_ARP_MAX_RETRIES` settings and the
`arp_retry_ms` / `arp_max_retries` fields in `net_t` never had any code
behind them and have been removed.

### Gateway-only mode

The smallest configuration resolves nothing but the gateway and sends every
new conversation to `gateway_mac`, even for on-link destinations.  That is
legal: the gateway forwards the packet back onto the link (and may send an
ICMP Redirect, which this stack ignores).  It costs one extra hop and nothing
in RAM.

## 4. What `arp_input()` does

- **Request for our address** (`TPA == net->ipv4_addr`): unicast a reply to
  the requester's MAC.  The requester's mapping is not remembered.  Before
  an address is configured (0.0.0.0, waiting for DHCP) nothing is answered.
- **Reply from the gateway** (`SPA == net->gateway_ipv4`): store its MAC and
  set `gateway_mac_valid`.  Without a gateway (0.0.0.0) no reply is one.  Any such reply is accepted, solicited or not, so
  a gratuitous ARP reply from the gateway updates it; so would a spoofed one
  (ARP has no authentication).
- **Everything else** — requests for other addresses, replies from other
  hosts, requests *from* the gateway — is ignored.  Only Ethernet/IPv4 ARP
  (hardware type 1, protocol 0x0800, lengths 6 and 4) is considered.

The gateway's MAC expires `NET_ARP_GATEWAY_TIMEOUT_MS` after the last
reply from the gateway (REQ-ARP-038); the next reply replaces it.

Not implemented: Address Conflict Detection (RFC 5227 probes, announcements
and defence) and automatic gratuitous ARP when an address is configured.  An
application can announce its address itself with
`arp_request(net, net->ipv4_addr)`, which sends a request whose sender and
target addresses are both ours.

## 5. IPv6

Neighbor Discovery (`ndp.c`) follows the same model:

- **Neighbor Solicitations for our addresses** are answered with a Neighbor
  Advertisement to the solicitor (its Source Link-Layer Address option, else
  the frame's source MAC).
- **The default router's MAC** comes from Router Advertisements;
  `ipv6_router_mac()` returns it while the router lifetime runs, else NULL.
- **On-link or not:** `ipv6_on_link()` treats link-local destinations and
  destinations inside the /64 of one of our global addresses as on-link;
  everything else goes to the router's MAC.
- **Neighbor Advertisements** are examined only for Duplicate Address
  Detection (one claiming a tentative address of ours marks it DUPLICATE).
  They are not recorded, so active resolution of an on-link neighbour is not
  implemented: `ndp_send_ns(net, target, 0)` can send the solicitation, but
  the answer is not kept.  To open a conversation with an on-link IPv6 peer,
  the application needs its MAC from elsewhere — typically a packet the peer
  sent first.

Neighbour Unreachability Detection and Redirects are not implemented
([ipv6.md](ipv6.md)).
