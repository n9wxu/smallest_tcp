# IPv6 — Design (Milestone 12)

**Status:** in progress — stage 1 (IPv6 core, ICMPv6, neighbor discovery responder, DAD)
**Requirements:** [ipv6.md](../requirements/ipv6.md), [icmpv6.md](../requirements/icmpv6.md), [ndp.md](../requirements/ndp.md), [slaac.md](../requirements/slaac.md), [dhcpv6.md](../requirements/dhcpv6.md)
**RFCs:** 8200 (IPv6), 4291 (addressing), 4443 (ICMPv6), 4861 (ND), 4862 (SLAAC), 6724 (address selection), 2464 (IPv6 over Ethernet), 3810 (MLDv2), 8415 (DHCPv6)

## 1. Goals and stages

A dual-stack host that is reachable over IPv6 the way it is over IPv4 —
ping, UDP, TCP, HTTP by name — without growing IPv4-only builds by a byte.

| Stage | Delivers | Browsable result |
|---|---|---|
| 1 | IPv6 header in/out, extension-header walk, ICMPv6 (echo, errors), NS/NA responder, DAD of the link-local address | `ping -6 fe80::…%tap0`, the host's neighbour table resolves the SUT |
| 2 | UDP over IPv6 | UDP echo over IPv6 |
| 3 | TCP over IPv6 | `nc -6`, TCP echo |
| 4 | Router discovery (RS/RA), SLAAC global address, default router | reachable at a global address |
| 5 | DHCPv6 (stateless information, then stateful address) | address/DNS from a DHCPv6 server |
| 6 | MLDv2 reports; mDNS over IPv6 (ff02::fb, AAAA); HTTP over IPv6 | `curl http://pyro-dead01.local/` over IPv6 |

## 2. Compile-time selection

`NET_USE_IPV6` (default 0 in `net_config.h`) gates every IPv6 field and the
Ethernet dispatch.  IPv4-only builds — including every `make arm-size*`
configuration — compile exactly as before.  CMake has
`SMALLEST_TCP_IPV6` (default ON): it adds `ipv6.c`, `icmpv6.c` and `ndp.c`
to the core library and defines `NET_USE_IPV6=1` publicly, so everything
linked against the core agrees on the `net_t` layout.  `make test` keeps
building the IPv4-only configuration, except for the IPv6 test suites,
which compile their own sources with `-DNET_USE_IPV6=1`.  CI therefore
covers both: Make = IPv4-only, CMake = dual stack.

## 3. Addresses

IPv6 addresses are 16-byte arrays in network byte order — never converted.
`net_t` gains (under `NET_USE_IPV6`):

```c
typedef struct {
  uint8_t addr[16];
  uint8_t state;      /* NONE, TENTATIVE, PREFERRED, DEPRECATED, DUPLICATE */
  uint8_t dad_left;   /* DAD probes still to send */
  uint16_t timer_ms;  /* until the next DAD step */
} net_ip6_addr_t;

net_ip6_addr_t ip6[NET_IPV6_ADDRS]; /* [0] link-local, [1..] global */
uint8_t ip6_hop_limit;              /* 64, or Cur Hop Limit from an RA */
uint32_t ip6_rng;                   /* xorshift32 for protocol jitter */
```

`NET_IPV6_ADDRS` defaults to 2: the link-local address and one global
address (SLAAC, DHCPv6 or static).  Slot 0 is formed at `net_init()` from the
MAC as a Modified EUI-64 interface identifier (RFC 4291 App. A) and stays
`NONE` until `ipv6_start()`.

Only PREFERRED and DEPRECATED addresses are *ours* for normal traffic.  A
TENTATIVE address receives nothing but DAD messages and is never a source
(RFC 4862 §5.4).

**Source selection** (RFC 6724, the rules that matter on one interface):
link-local or link-scope multicast destination → the link-local address;
any other destination → a PREFERRED global address, else a DEPRECATED one,
else nothing.

## 4. Receive path

```
eth_input ── 0x86DD ──► ipv6_input ── 58 ─► icmpv6_input ── 133..137 ─► ndp_input
                                      ├─ 17 ─► udp6_input   (stage 2)
                                      └─  6 ─► tcp6_input   (stage 3)
```

**Ethernet filter.**  IPv6 multicast maps to `33:33` + the group's low 32
bits (RFC 2464 §7).  `eth_input` accepts the all-nodes MAC
(`33:33:00:00:00:01`) and the solicited-node MAC of every configured
address, tentative ones included (DAD needs them).

**`ipv6_parse`** checks the version and that 40 + Payload Length fits the
frame (a longer frame is Ethernet padding), then walks the extension
headers: Hop-by-Hop (0, only first), Routing (43) and Destination Options
(60) are skipped by their length; a Fragment header (44) drops the packet —
there is no reassembly (a documented deviation; hosts on Ethernet rarely
see fragments); No Next Header (59) ends processing.  The result names the
upper-layer protocol, its offset and length, and the offset of the Next
Header field that named it — the Parameter Problem pointer.

**`ipv6_input`** drops multicast sources and packets from our own
addresses, accepts destinations that are one of our addresses, all-nodes,
or a solicited-node group of a configured address, and dispatches.  The
unspecified source `::` is legal only for DAD Neighbor Solicitations; NDP
checks that.  An unknown upper-layer protocol draws ICMPv6 Parameter
Problem code 1 pointing at that Next Header field (RFC 8200 §4).

## 5. ICMPv6

- **Checksum** over the IPv6 pseudo-header (RFC 8200 §8.1) — mandatory.
- **Echo**: reply in place with the request's identifier, sequence and
  data.  An echo to a multicast group (e.g. `ff02::1`) is answered from our
  unicast address (RFC 4443 §4.2).
- **Errors sent** (Destination Unreachable, Parameter Problem) carry as
  much of the invoking packet as fits in 1280 bytes and the TX buffer.
  None are sent in response to an ICMPv6 error, to a multicast destination
  (except Parameter Problem code 2 and Packet Too Big, which we never
  send), or to a multicast or unspecified source (RFC 4443 §2.4).
- **Errors received** are logged (as for ICMPv4).  Unknown informational
  types are dropped.
- **Rate limiting** (RFC 4443 §2.4(f), SHOULD) is not implemented yet: the
  stack sends at most one error per received packet.

## 6. Neighbor Discovery

**Validation** (RFC 4861 §7.1): Hop Limit 255, code 0, ICMPv6 length,
options with non-zero length, target not multicast; an NS from `::` must
go to a solicited-node group and carry no Source Link-Layer Address option.

**Neighbor Solicitation → Advertisement.**  For one of our addresses we
answer with Solicited = 1 (Override = 1, Router = 0) and our MAC in a Target
Link-Layer Address option, to the solicitor — its SLLA option or, failing
that, the frame's source MAC.  An NS from `::` (someone's DAD) is defended
with an unsolicited NA (S = 0) to all-nodes.

**Distributed cache, as ARP.**  There is no neighbour cache: replies go to
the MAC the request came from; connections keep their peer's MAC; the
default router's MAC lives in `net_t` (stage 4).  NUD is simplified to
"resolved neighbours stay reachable" (REQ-NDP-059).

**Duplicate Address Detection** (RFC 4862 §5.4), per address:

```
ipv6_start ─► TENTATIVE ── random 0..1 s ──► NS(src ::, dst solicited-node,
                                                target = address)
                  │ RetransTimer (1 s) with no NA/NS for the address
                  ▼
              PREFERRED
   NA for the address, or an NS from :: for it, while TENTATIVE ─► DUPLICATE
```

A DUPLICATE address is never used.  For the EUI-64 link-local address that
means IPv6 is off on the interface (RFC 4862 §5.4.5); the application can
see it with `ipv6_addr_state()`.  NS for a tentative address from a unicast
source is ignored.

## 7. Timers and randomness

`ipv6_tick(net, elapsed_ms)` drives DAD (and RS/lifetimes from stage 4),
like `tcp_tick()`.  Delays are drawn from `ip6_rng`, an xorshift32 seeded
from the MAC — no `%` or `/` (Cortex-M0 has no divider).

## 8. Dual-stack UDP and TCP (stages 2–3)

- **UDP**: `udp_port_entry_t` gains `handler6` (IPv6 source as a 16-byte
  pointer) under `NET_USE_IPV6`, so existing tables `{port, handler}` still
  compile and IPv4-only builds are unchanged.  `udp6_send()` /
  `udp6_send_inplace()` mirror the IPv4 calls (`UDP6_PAYLOAD_OFFSET` = 62).
- **TCP**: `tcp_conn_t` gains the IP version, the peer's IPv6 address and
  which of our addresses the peer used, so replies keep the same source.
  One segment builder, IPv4 or IPv6 by the connection's version; the MSS
  from the TX buffer is 20 bytes smaller over IPv6 (default 1220).

## 9. Deviations and deferred items

| Item | Reason / plan |
|---|---|
| No fragment reassembly (RFC 8200 §4.5) | RAM; fragments are dropped |
| No neighbour cache / NUD | distributed-cache model, as ARP |
| Redirect ignored (REQ-NDP-053) | no per-destination routes |
| MLD reports | stage 6 (solicited-node + ff02::fb); links without MLD snooping work without them |
| ICMPv6 error rate limiting | not yet; at most one error per packet |
