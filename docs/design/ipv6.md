# IPv6 — Design

**Files:** `include/ipv6.h`, `src/ipv6.c` (packets, addresses, groups); `include/icmpv6.h`, `src/icmpv6.c`; `include/ndp.h`, `src/ndp.c` (Neighbor Discovery, DAD, router discovery, SLAAC); `include/mld.h`, `src/mld.c`; `include/dhcpv6_client.h`, `src/dhcpv6_client.c`.  The interface's IPv6 state is `net_ip6_t` in `include/net.h`.
**Requirements:** [ipv6.md](../requirements/ipv6.md), [icmpv6.md](../requirements/icmpv6.md), [ndp.md](../requirements/ndp.md), [slaac.md](../requirements/slaac.md), [dhcpv6.md](../requirements/dhcpv6.md)
**RFCs:** 8200 (IPv6), 4291 (addressing), 4443 (ICMPv6), 4861 (ND), 4862 (SLAAC), 6724 (address selection), 2464 (IPv6 over Ethernet), 3810 (MLDv2), 8201 (path MTU), 8415 (DHCPv6)
**Size (Cortex-M0):** 9,497 B flash / 832 B RAM for a dual-stack UDP echo (IPv4-only: 4,110 B / 720 B; IPv6-only: 6,465 B / 760 B); see [size-comparison.md](size-comparison.md#adding-ipv6-dual-stack).

## 1. Goals and scope

A dual-stack host that is reachable over IPv6 the way it is over IPv4 —
ping, UDP, TCP, HTTP by name — without growing IPv4-only builds by a byte.

| Part | Provides | Seen as |
|---|---|---|
| IPv6 core | IPv6 header in/out, extension-header walk, ICMPv6 (echo, errors), NS/NA responder, DAD of the link-local address | `ping -6 fe80::…%tap0`, the host's neighbour table resolves the device |
| UDP | UDP over IPv6 | UDP echo over IPv6 |
| TCP | TCP over IPv6 | `nc -6`, TCP echo |
| Router discovery | RS/RA, SLAAC global address, default router | reachable at a global address |
| DHCPv6 | stateless information, stateful address | address/DNS from a DHCPv6 server |
| Groups | MLDv2 reports; mDNS over IPv6 (ff02::fb, AAAA); HTTP over IPv6 | `curl http://pyro-dead01.local/` over IPv6 |

## 2. Compile-time selection

`NET_USE_IPV6` (default 0 in `net_config.h`) gates every IPv6 field of
`net_t` and the Ethernet dispatch; IPv4-only builds carry no IPv6 code or
state.  CMake has `SMALLEST_TCP_IPV6` (default ON): it adds `ipv6.c`,
`icmpv6.c`, `ndp.c` and `mld.c` to the core library and defines
`NET_USE_IPV6` publicly, so everything linked against the core agrees on
the `net_t` layout; the DHCPv6 client is its own library
(`smallest_tcp::dhcpv6_client`), built only then.

IPv4 can be left out the same way: `NET_USE_IPV4` 0 (CMake
`SMALLEST_TCP_IPV4=OFF`) builds an IPv6-only stack with no ARP, IPv4, ICMP
or IGMP, UDP and TCP over IPv6 alone, and mDNS with AAAA records only
([configuration.md §5](configuration.md#5-compile-time-protocol-selection)).
The IPv4 API is then not declared, and the headers of the protocols that
run only over IPv4 (ARP, ICMP, IGMP, DHCPv4, TFTP) stop the build.  Demos
that need no IPv4 — `tcp_echo_demo`, `tls_echo_demo`, `frame_dump` — build
IPv6-only too.

CI builds and tests all three ways: the default CMake job is dual stack,
`cmake-ipv4-only` sets `SMALLEST_TCP_IPV6=OFF`, `cmake-ipv6-only` sets
`SMALLEST_TCP_IPV4=OFF`, and the IPv6 blackbox suite runs against an
IPv6-only `tcp_echo_demo` as well as the dual-stack one.
`make arm-size-ipv6` measures the dual-stack footprint and
`make arm-size-ipv6-only` a UDP echo over IPv6 alone.

| Setting | Default | Meaning |
|---|---|---|
| `NET_IPV6_ADDRS` | 2 | Address slots: the link-local address and one global (SLAAC, DHCPv6 or static) |
| `NET_MAX_MCAST6_GROUPS` | 1 | Groups `ipv6_mcast_join()` can hold (mDNS needs one for ff02::fb) |
| `NET_IPV6_DAD_TRANSMITS` | 1 | DAD probes per address |
| `NET_IPV6_DEFAULT_HOP_LIMIT` | 64 | Until a Router Advertisement says otherwise |
| `NDP_MAX_RTR_SOLICITATIONS` (`ndp.h`) | 3 | Router Solicitations after start-up; 0 disables router discovery |
| `ICMPV6_ERROR_BURST` (`icmpv6.h`) | 10 | ICMPv6 errors that may be sent at once (§5) |
| `ICMPV6_ERROR_INTERVAL_MS` (`icmpv6.h`) | 100 | Milliseconds for one more error; at most 65535 |
| `DHCPV6_MAX_DUID` (`dhcpv6_client.h`) | 20 | Largest server DUID the client keeps (§8) |

## 3. Interface state

IPv6 addresses are 16-byte arrays in network byte order — never converted.
Everything the stack knows about the interface's IPv6 side is one
struct, `net->ip6` (`include/net.h`):

```c
typedef struct {
  uint8_t addr[16];
  uint8_t state;            /* NET_IP6_NONE, TENTATIVE, PREFERRED, DEPRECATED, DUPLICATE */
  uint8_t dad_probes_left;
  uint16_t dad_timer_ms;    /* until the next DAD step */
  uint32_t valid_s;         /* seconds, or NET_IP6_INFINITE */
  uint32_t preferred_s;
} net_ip6_addr_t;

typedef struct {
  net_ip6_addr_t addr[NET_IPV6_ADDRS]; /* [0] link-local, [1..] global */
  uint8_t hop_limit;                   /* 64, or Cur Hop Limit from an RA */
  uint8_t ra_flags;                    /* NDP_RA_MANAGED | NDP_RA_OTHER of the last RA */
  net_ip6_router_t router;             /* default router: addr, mac, lifetime_s */
  uint8_t router_solicits_left;
  uint8_t error_tokens;                /* ICMPv6 errors that may be sent now */
  uint16_t router_solicit_ms;          /* until the next RS */
  uint16_t lifetime_carry_ms;          /* ms toward the next lifetime second */
  net_mld_t mld;                       /* query_reply_ms, report_repeat_ms, v1_querier_left_s */
  uint16_t error_refill_ms;            /* ms toward the next error token */
} net_ip6_t;
```

**Start.**  `ipv6_start()` clears all of `net->ip6`, sets the default hop
limit, fills the ICMPv6 error bucket, forms the link-local address in
slot 0 — fe80::/64 plus the Modified EUI-64 interface identifier of the
MAC (RFC 4291 App. A) — with infinite lifetimes, and starts DAD on it
after a random 0–1 s delay (RFC 4862 §5.4.2).  Until then slot 0 is `NONE`
and the interface ignores IPv6: `ipv6_input()` and `ipv6_mac_accepted()`
both test it.  Because the reset covers every slot, static global
addresses are added *after* `ipv6_start()`; calling it again (after a link
change, say) starts IPv6 over, DAD and router discovery included.

Joined multicast groups are deliberately *outside* `net_ip6_t`, in
`net->mcast6_groups` (`::` = free slot): a module may join before IPv6 is
started — `mdns_start()` joins ff02::fb whenever it runs — and the reset
must not forget the membership.  The MLD report sent before the
link-local address's first DAD probe announces them (§9).

The well-known addresses `ipv6_unspecified` (::), `ipv6_all_nodes`
(ff02::1) and `ipv6_all_routers` (ff02::2) are defined once, in `ipv6.c`.

**Address states** (RFC 4862 §2).  Only PREFERRED and DEPRECATED
addresses are *ours* for normal traffic (`ipv6_is_ours()`).  A TENTATIVE
address receives nothing but DAD messages and is never a source
(RFC 4862 §5.4); a DUPLICATE one is never used.  One rule chooses between
the two usable states, applied when DAD completes and whenever lifetimes
change: PREFERRED while the preferred lifetime is non-zero, else
DEPRECATED (still accepted, chosen as a source only when nothing preferred
fits).

**Lifetimes have one owner.**  `ipv6_addr_set_lifetimes(net, slot,
valid_s, preferred_s)` stores new lifetimes for an existing address and
re-applies that rule (a TENTATIVE address stays tentative; DAD applies
the rule when it finishes).  Every change goes through it, so SLAAC and
DHCPv6 cannot disagree on when a deprecated address becomes preferred
again:

- aging — `lifetimes_elapse()` in `ipv6.c`, once per whole second; a slot
  whose valid lifetime reaches 0 is cleared instead;
- SLAAC — `slaac_prefix()` in `ndp.c`, after the two-hour rule (§7);
- DHCPv6 — `bind()` in `dhcpv6_client.c`, when a Reply extends a lease
  for an address that is already configured (§8).

A new address gets its lifetimes from `ipv6_addr_add()` (static
configuration, SLAAC, DHCPv6), which then starts DAD without the start-up
delay; it returns `NET_ERR_INVALID_PARAM` for a multicast or unspecified
address and `NET_ERR_BUF_TOO_SMALL` when every slot is taken.
`NET_IP6_INFINITE` (0xFFFFFFFF) never counts down.  The link-local address
is never aged, and `ipv6_addr_remove()` refuses slot 0.

**Source selection** (`ipv6_src_for()`, RFC 6724 rules 2 and 3 for one
interface): a link-scope destination — link-local unicast, or multicast of
scope ≤ 2 — gets the link-local address; any other destination a
PREFERRED global address, else a DEPRECATED one — the first in slot
order: there is no longest-prefix match among several; a wider-scope
multicast group with no global address falls back to the link-local
address.  Otherwise there is no source and the send fails with
`NET_ERR_INVALID_PARAM`.  The unspecified address has no source either:
nothing is sent to `::` (RFC 4291 §2.5.2).

## 4. Receive path

```
eth_input ── 0x86DD ──► ipv6_input ── 58 ─► icmpv6_input ── 128 ──────────► echo reply
                                      │                   ├─ 133..137 ────► ndp_input
                                      │                   ├─ 130..132, 143 ► mld_input
                                      │                   └─ other < 128 ─► udp6_icmp_error / tcp6_icmp_error
                                      ├─ 17 ─► udp6_input ─► net->udp6_ports handler
                                      └─  6 ─► tcp6_input
```

**Ethernet filter.**  IPv6 multicast maps to `33:33` + the group's low 32
bits (RFC 2464 §7).  Once IPv6 is started, `ipv6_mac_accepted()` (called
by `eth_input()`) accepts the all-nodes MAC, the solicited-node MAC of
every configured address — tentative ones included, DAD needs them — and
the MAC of every joined group.

**`ipv6_parse()`** checks the version and that 40 + Payload Length fits the
frame (a longer frame is Ethernet padding), then walks the extension
headers: Hop-by-Hop (0, only straight after the fixed header), Routing
(43) and Destination Options (60) are skipped by their length, without
looking at the options inside; a Fragment header (44) is dropped — there
is no reassembly (hosts on Ethernet rarely see fragments); No Next Header
(59) ends processing.  The resulting `ipv6_hdr_t` names the upper-layer
protocol, its offset and length, and `nh_offset`, the offset of the Next
Header field that named it — the Parameter Problem pointer.  A Routing
header with Segments Left ≠ 0 would have the host forward: the walk stops
at it, and the header itself is reported as the "upper layer"
(`next_header` = `IPV6_NH_ROUTING`, `header_len` its offset).

**`ipv6_input()`** ignores everything until IPv6 is started, drops
multicast sources and packets from our own usable addresses, accepts
destinations that are one of our usable addresses, all-nodes, a joined
group, or the solicited-node group of a configured address
(`destination_is_us()`), and dispatches.  It does not reject the
unspecified source `::`, which DAD probes and MLD reports from a host
without a usable address legitimately carry; the upper layers decide —
NDP treats an NS from `::` as a DAD probe, echo requests and errors are
never answered to `::`, TCP drops a segment from it, mDNS does not answer
a legacy query from it.  An unknown upper-layer protocol draws ICMPv6
Parameter Problem code 1 pointing at that Next Header field (RFC 8200
§4), and a Routing header with segments left Parameter Problem code 0
pointing at its Routing Type (RFC 8200 §4.4).

## 5. ICMPv6

- **Checksum** over the IPv6 pseudo-header (`ipv6_cksum()`, RFC 8200
  §8.1) — mandatory; shorter than 4 bytes or a bad checksum is dropped.
- **Echo** (`echo_reply()`): reply in place with the request's identifier,
  sequence and data, to the frame's source MAC.  An echo to a multicast
  group (e.g. ff02::1) is answered from our unicast address for the
  requester (RFC 4443 §4.2); one from `::` is not answered, and one too
  large for the TX buffer is dropped.
- **Errors sent** (`icmpv6_send_error()`): Parameter Problem codes 0 and 1
  from `ipv6_input()` and Destination Unreachable code 4 (port
  unreachable) from `udp6_input()`.  The source is the address the packet
  was sent to when it is ours, else `ipv6_src_for()`; the error goes to
  the invoking frame's source MAC and quotes as much of the invoking
  packet as fits in the 1280-byte minimum MTU and in the TX buffer
  (`quote_len()`).
- **When errors are allowed** (`error_allowed()`, RFC 4443 §2.4(e)): not
  about a packet sent to an IPv6 multicast group or to a link-layer
  multicast/broadcast address — except Packet Too Big and Parameter
  Problem code 2, which the stack never sends but the function lets
  through so that it states the rule as the RFC does; not about a packet
  from a multicast or unspecified source; not about an ICMPv6 error
  (`is_icmpv6_error()`: type below 128, or a message too short to tell).
- **Rate limit** (RFC 4443 §2.4(f)): a token bucket in `net->ip6`.
  `icmpv6_send_error()` spends one of `error_tokens` per error and returns
  `NET_ERR_BUSY`, sending nothing, when none is left; `icmpv6_tick()`
  (from `ipv6_tick()`) adds a token every `ICMPV6_ERROR_INTERVAL_MS`
  (100 ms) up to `ICMPV6_ERROR_BURST` (10) — the values RFC 4443 suggests
  for a small device.  Echo replies and Neighbor Discovery are not
  limited.
- **Errors received** (`error_input()`): any message of type below 128 —
  Destination Unreachable, Packet Too Big, Time Exceeded, Parameter
  Problem, or a type the stack does not know (RFC 4443 §2.4(a)) — that
  quotes at least an IPv6 header whose source is one of our usable
  addresses goes to the transport its Next Header names, with the type,
  the code, the MTU of a Packet Too Big, and the quote in place:
  `udp6_icmp_error()` or `tcp6_icmp_error()` (§12).  The transport header
  is taken to follow the IPv6 header directly: the stack sends no
  extension headers before UDP or TCP.  A Packet Too Big whose MTU is
  below 1280 is discarded (RFC 8201 §4).  Errors about anything else —
  our ICMPv6 or MLD messages — are dropped.
- **Informational messages** of unknown type are dropped (§2.4(b)).

## 6. Neighbor Discovery

`ndp.c` has three layers: options (`options_valid()` checks that every
option has a non-zero length and fits; `option_find()` then walks them
without re-checking), senders that build in place at `ICMPV6_OFFSET`
(`send_na()`, `ndp_send_ns()`, `send_rs()`), and receivers (`ns_input()`,
`na_input()`, `ra_input()`) behind `ndp_input()`.  The timers are
`dad_step()`, `start_router_discovery()` and `ndp_tick()`.

**Validation** (RFC 4861 §6.1, §7.1): every ND message must have Hop Limit
255 and code 0 — so it came from the link — and be long enough for its
type, with valid options.  NS and NA targets must not be multicast; an NS
from `::` must go to the target's solicited-node group and carry no Source
Link-Layer Address option; an NA to a multicast address must not have S
set; an RA must come from a link-local address.  RS (we are not a router)
and Redirect (no per-destination routes, REQ-NDP-053) are ignored.

**NS → NA** (`ns_input()`).  For one of our usable addresses we answer with
Solicited = 1, Override = 1, Router = 0 and our MAC in a Target
Link-Layer Address option, from the target address, to the solicitor —
at its SLLA option's MAC or, failing that, the frame's source MAC.  An NS
from `::` for a usable address (someone's DAD) is defended with an
unsolicited NA (S = 0) to all-nodes.  For a TENTATIVE address an NS from
`::` means another node is probing the same address: DUPLICATE; an NS
from a unicast source is ignored (RFC 4862 §5.4.3).  DUPLICATE addresses
are not defended.

**NA** (`na_input()`).  With no neighbour cache, an NA only matters when it
claims one of our TENTATIVE addresses: DUPLICATE.  After DAD, a
conflicting NA is ignored (RFC 4862 §5.4.4 leaves the reaction open).

**Distributed cache, as ARP.**  There is no neighbour cache: replies go to
the MAC the request came from; TCP connections keep their peer's MAC; the
default router's MAC is in `net->ip6.router`.  NUD is simplified to
"resolved neighbours stay reachable" (REQ-NDP-059).  Nothing resolves an
arbitrary on-link neighbour: `ndp_send_ns()` with `dad = 0` sends the
solicitation — from the address `ipv6_src_for()` picks for the target,
with our MAC as SLLA; `NET_ERR_INVALID_PARAM` without a source — but
answers are not recorded, so an application that opens a connection
passes the peer's MAC (`tcp6_connect()`), or the router's from
`ipv6_router_mac()` for an off-link peer.

**Duplicate Address Detection** (RFC 4862 §5.4), per address:

```
ndp_dad_start() ─► TENTATIVE ── delay: link-local random 0..1 s, others 0 ──►
       first probe only: MLD report of all our groups
       NS (src ::, dst the solicited-node group, target the address, no SLLA)
       × NET_IPV6_DAD_TRANSMITS, RetransTimer (1 s) apart
                   │ 1 s after the last probe, nothing heard
                   ▼
            PREFERRED (DEPRECATED if its preferred lifetime is 0)
            slot 0: MLD report of all our groups, start_router_discovery()

  while TENTATIVE: an NA for the address, or an NS from :: for it ─► DUPLICATE
```

The MLD report precedes the first probe so that a snooping switch
forwards the solicited-node group — and any answer to the probe
(RFC 4862 §5.4.2).  The one sent when the link-local address passes DAD
repeats it from an address routers accept (§9).

A DUPLICATE address is never used.  Its slot stays taken until its
valid lifetime runs out (never, for an infinite static address: remove it
with `ipv6_addr_remove()`).  Router Advertisements do not refresh a
DUPLICATE address, so a SLAAC address is formed and probed again only
once its old valid lifetime has expired.  For the EUI-64 link-local
address, DUPLICATE means no link-scope packet has a source and router
discovery never starts; RFC 4862 §5.4.5 asks for IP operation to be
disabled, and the stack does not otherwise switch IPv6 off.  The
application can see it with `ipv6_addr_state(net, 0)`.

## 7. Router discovery and SLAAC

**Router Solicitation** (`start_router_discovery()`, `ndp_tick()`).  Once
the link-local address is usable, after a random 0–1 s, up to
`NDP_MAX_RTR_SOLICITATIONS` RS go to all-routers (ff02::2) 4 s apart, from
the link-local address with our MAC as SLLA.  The first valid RA stops
them.

**Router Advertisement** (`ra_input()`): a non-zero Cur Hop Limit replaces
`net->ip6.hop_limit`; M and O are kept in `net->ip6.ra_flags`
(`NDP_RA_MANAGED`, `NDP_RA_OTHER`) for the application to start DHCPv6
(§8); a non-zero Router Lifetime makes the sender the default router —
address, MAC (SLLA option, else the frame source) and lifetime in
`net->ip6.router`; lifetime 0 from that router removes it.  One router is
remembered: the last to advertise a non-zero lifetime.  Every Prefix
Information option goes to `slaac_prefix()`.  The MTU option and the
Reachable Time and Retrans Timer fields are not read.

**Next hop.**  `ipv6_on_link()` says which destinations are on-link:
link-local ones, and those in the /64 of one of our configured global
addresses (the L flag is not tracked separately, and an address from
DHCPv6 or the application counts as much as one from SLAAC).  Off-link
destinations go to `ipv6_router_mac()`, NULL when there is no default
router.  Replies still go to the MAC the request came from, which for
off-link peers is the router's.

**SLAAC** (`slaac_prefix()`, RFC 4862 §5.5.3).  A Prefix Information
option is used only with A = 1, a prefix that is not link-local,
preferred ≤ valid, and a prefix length of 64 (our interface identifier is
64 bits).  The address is the prefix plus the interface identifier of the
link-local address:

- not yet configured, valid > 0 → `ipv6_addr_add()` → DAD without the
  start-up delay (nothing happens when every slot is taken);
- configured and not DUPLICATE → `ipv6_addr_set_lifetimes()` with the
  advertised preferred lifetime and the valid lifetime
  `slaac_valid_lifetime()` returns — the two-hour rule of §5.5.3(e): an
  advertised valid lifetime above two hours, or above the remaining one,
  is taken; otherwise the remaining lifetime is cut to two hours if it
  was longer, and kept if not.  The rule stops an unauthenticated RA from
  expiring an address quickly.

**Lifetimes** count down in whole seconds (§11).  Preferred reaching 0
makes the address DEPRECATED; valid reaching 0 frees the slot.

## 8. DHCPv6 client

`dhcpv6_client.c`, a separate library like the DHCPv4 client, with the
same shape: an application-owned `dhcpv6_client_t`, `init` / `start` /
`tick` / `input` / `release`, and an option-handler table for DNS servers
and the like.  It is wired up like every protocol module
([integrating-modules.md](../integrating-modules.md)): a udp6 port-546
handler passes its payload pointer to `dhcpv6_client_input()`.  The
application starts it when the Router Advertisement asks —
`net->ip6.ra_flags & NDP_RA_MANAGED` → `DHCPV6_MODE_STATEFUL`,
`NDP_RA_OTHER` → `DHCPV6_MODE_STATELESS`; the dual-stack `tcp_echo_demo`
does exactly that.  The first message of an exchange that the client
begins by itself — at the start, and at an information refresh — waits a
random 1–1000 ms (`start_delay()`; RFC 8415 §18.2.1, §18.2.6, §21.23).

- **Identity**: DUID-LL (type 3, Ethernet, MAC) — no clock needed; IAID =
  the low four MAC bytes.  The transaction ID is 24 bits of
  `net_random()`, new for every exchange (`begin()`) and for Release.
- **Stateless** (`DHCPV6_CLI_INFO_REQUEST` → `DHCPV6_CLI_INFORMED`):
  Information-request → Reply; top-level options go to the handlers
  (`DHCPV6_EVT_INFO`); refreshed after the Information Refresh Time
  (default 24 h, at least 10 min).
- **Stateful** (`DHCPV6_CLI_SOLICIT` → `_REQUEST` → `_BOUND` → `_RENEW` →
  `_REBIND`): Solicit (IA_NA) → first usable Advertise → Request (Server
  ID, address) → Reply → BOUND (`DHCPV6_EVT_BOUND`).  `bind()` installs a
  new address with `ipv6_addr_add()` (so DAD runs) and refreshes one that
  is already configured with `ipv6_addr_set_lifetimes()` (§3).  Renew at
  T1 to the server, Rebind at T2 to any server (`DHCPV6_EVT_RENEWED` at
  the Reply to either); the lease expires at the valid lifetime (address
  removed, `DHCPV6_EVT_EXPIRED`, Solicit again).  T1/T2 of 0 become 0.5
  and 0.8125 of the preferred lifetime (shifts).  A Request that goes
  unanswered 10 times (REQ_MAX_RC), or answered without a usable lease,
  sends the client back to Solicit; an unusable Reply to Renew or Rebind
  is ignored and the client keeps trying until T2 or expiry.
- **Release** (`dhcpv6_client_release()`): the address is removed from
  the interface, one Release goes to the server, and the client is
  `DHCPV6_CLI_IDLE`.
- **Two clocks.**  The client keeps its own lease clock (`since_s`,
  advanced by `net_whole_seconds()` from `sec_ms`) for T1, T2 and expiry;
  the address's lifetimes age independently in `ipv6.c`, on the
  interface's whole seconds (§11) — so the interface may drop the address
  up to a second before the client's clock says the lease has expired;
  the client's `ipv6_addr_remove()` at expiry is then a no-op.
- **Validation**: transaction ID, options well-formed, our Client
  Identifier, a Server Identifier of 1–`DHCPV6_MAX_DUID` (20) bytes,
  Status Code success (top level and in the IA_NA), our IAID, T1 ≤ T2
  where both are set, and an IAADDR with valid > 0 and preferred ≤ valid.
  A SOL_MAX_RT or INF_MAX_RT option from the server is honoured within
  60–86 400 s — read before the Status Code, so a server that refuses the
  client can still slow it down (RFC 8415 §18.2.9).
- **Retransmission** (RFC 8415 §15): RT = IRT ± 10 %, then 2·RT ± 10 %,
  capped at MRT ± 10 %; the first Solicit waits strictly more than IRT.
  IRT / MRT are 1 s / 3600 s for Solicit and Information-request (MRT
  being SOL_MAX_RT or INF_MAX_RT if the server gave one), 1 s / 30 s for
  Request, 10 s / 600 s for Renew and Rebind.  A tenth is (v · 205) >> 11
  (or (v >> 11) · 205 for large v) — no division on Cortex-M0, at the
  price of a result a thousandth too large — and the random span is kept
  within 32 bits even for an 86 400 s SOL_MAX_RT from the server, which
  the client honours (and requests, as §21.24 requires).  Elapsed Time
  counts from the first transmission of an exchange, in hundredths of a
  second, capped at 0xFFFF.
- **Messages** are built in place in `net->tx.buf` and sent to
  All_DHCP_Relay_Agents_and_Servers (ff02::1:2) from the link-local
  address; `send_msg()` needs a TX buffer of `UDP6_PAYLOAD_OFFSET` + 128 =
  190 bytes and sends nothing with less.
- **Deviations**: the first Advertise is taken (no collection window, no
  preference); one Release, not up to five; no Confirm, Decline,
  Reconfigure or Rapid Commit — a leased address that fails DAD stays
  DUPLICATE until the lease expires.

Interop: `tests/blackbox/dhcpv6_interop.sh` lets dnsmasq (`--enable-ra`
with a DHCPv6 range) configure the demo — lease, DNS option, host ping and
TCP echo at the leased address — over both Linux drivers in CI.

## 9. MLD and multicast groups

`mld.c` makes the host visible to switches that snoop MLD — otherwise they
may stop forwarding the solicited-node traffic that address resolution
depends on, and ff02::fb for mDNS.  Its timers live in `net->ip6.mld`.

- **Groups** (`our_groups()`, `is_our_group()`): the solicited-node group of
  every configured address except DUPLICATE ones, deduplicated (a SLAAC
  address with our interface identifier shares the link-local one's
  group), plus the groups joined with `ipv6_mcast_join()`
  (`NET_ERR_INVALID_PARAM` for an address that is not multicast,
  `NET_ERR_BUF_TOO_SMALL` beyond `NET_MAX_MCAST6_GROUPS`).  All-nodes is
  never reported (RFC 3810 §6).  Joined groups pass the Ethernet filter
  and the destination check.
- **Reports**: MLDv2 (type 143, `send_v2()`) to ff02::16, Hop Limit 1,
  behind a Hop-by-Hop header with a Router Alert, from the link-local
  address — or from `::` while it is not yet usable (RFC 3810 §5.2.13).
  `mld_report_change()` sends one before each address's first DAD probe,
  when the link-local address passes DAD — routers discard the reports
  sent from `::`, so the groups are reported again from an address they
  accept — and on every new join: a record per group, CHANGE_TO_EXCLUDE,
  no sources (`report_all()`).  `mld_tick()` repeats it once after 1 s
  (Robustness Variable 2).  Before `ipv6_start()` it sends nothing: the
  report before the link-local address's first probe covers every group.
  A leave (`ipv6_mcast_leave()`) is one CHANGE_TO_INCLUDE record, sent
  once.  Removing an address sends nothing for its solicited-node group;
  snooping switches age it out.
- **Queries** (`mld_input()`: type 130, Hop Limit 1, link-local source,
  24 bytes or at least 28; the Router Alert is not looked for): a general
  query, or one for a group of ours, schedules a report of all groups
  (MODE_IS_EXCLUDE) after a random delay up to the Maximum Response Delay
  (`max_response_ms()` decodes MLDv2's floating-point code; the delay is
  capped at 65.535 s).  An earlier pending answer stands.  A
  group-specific query is answered with every group — a simplification
  that costs a few bytes on the wire, not 16 bytes of RAM per pending
  group.  Reports and Dones of other listeners need nothing from a host.
- **MLDv1 compatibility** (RFC 3810 §8): a 24-byte query switches
  reporting to MLDv1 (`send_v1()`: one Report per group, to the group;
  Done to ff02::2) for the Older Version Querier Present Timeout, 260 s,
  counted down in seconds by `mld_seconds_elapse()`.  Linux bridges query
  with MLDv1 by default.

## 10. mDNS and HTTP over IPv6

**mDNS** (`mdns.c`, RFC 6762 §6.2, §20) is dual stack when IPv6 is
compiled in: `mdns_start()` also joins ff02::fb (MLD reports it), the
application feeds udp6 port-5353 datagrams to `mdns_input6()`, a
`DNS_TYPE_AAAA` record with `.rdata.aaaa = NULL` stands for every usable
IPv6 address, probes, announcements and goodbyes go to both groups, and
answers go back on the family the query came on.  `mdns_readdress6()`
re-announces over IPv6 when an address becomes usable (RFC 6762 §8.4) —
the demos call it when the link-local, SLAAC or DHCPv6 address comes up.
The details are in [mdns.md](mdns.md#11-dual-stack-ipv6).

**HTTP**: nothing to do in the server — TCP listeners accept IPv6.
`http_request_t` has `remote_ip6` (NULL over IPv4).  `mdns_demo` and
`http_demo` are dual stack; `curl -6 'http://[fe80::ff:fede:ad01%25tap0]/'`
and `avahi-resolve -6 -n pyro-dead01.local` work against them in CI.

## 11. Timers and randomness

The application calls `net_tick(net, elapsed_ms)`, which runs the IPv4
timers, `tcp_tick()` and `ipv6_tick()`.  `ipv6_tick()` does, in order:

1. **Whole seconds** — `net_whole_seconds(&net->ip6.lifetime_carry_ms,
   elapsed_ms)` (a subtraction loop: Cortex-M0 has no divider); if any
   passed, `lifetimes_elapse()` ages the global addresses (§3), the
   default router's lifetime and, through `mld_seconds_elapse()`, MLDv1
   compatibility mode.  The seconds are the interface's, not each
   address's: a lifetime that began between two of them ends up to a
   second early.
2. **`icmpv6_tick()`** — the error rate limit's tokens (§5).
3. **`mld_tick()`** — query answers and the repeat of a change report.
4. **`ndp_tick()`** — Router Solicitations, then DAD steps.

The order is deliberate: MLD runs before ND, so a report that DAD's first
probe triggers is repeated a full interval later, not in the same tick;
Router Solicitations run before DAD, so the solicitation that a completed
DAD schedules waits for the next tick.  Millisecond timers count down
with `net_countdown16()`; they are 16-bit (the longest is 4 s, or 65.535 s
for an MLD answer).

Random delays — the DAD and RS start-up jitter, MLD answer delays,
DHCPv6 start delay, retransmission jitter and transaction IDs — come from
the stack's one generator, `net_random()` / `net_random_below()` (a keyed
hash, HalfSipHash-2-4, with its key in `net_t`; scaled rather than reduced
with `%`; [architecture.md §9](../architecture.md#9-randomness)).
`net_init()` keys it from the MAC; an application with a real entropy source
mixes that in with `net_random_seed()`.

## 12. Dual-stack UDP and TCP

- **UDP**: IPv6 ports live in their own table, bound with
  `udp6_set_ports()` and kept in `net_t` (`net->udp6_ports`), whose
  handlers get the source as a 16-byte pointer and, like the IPv4 ones,
  the payload as a pointer into `net->rx.buf`, valid during the call.
  `udp_port_entry_t` is untouched — a third field would make every
  positional `{port, handler}` initializer warn under `-Wextra` — and a
  port missing from the IPv6 table is closed over IPv6 (ICMPv6 Port
  Unreachable).  A zero UDP checksum is invalid over IPv6 (RFC 8200 §8.1).
  `udp6_send()` / `udp6_send_inplace()` mirror the IPv4 calls
  (`UDP6_PAYLOAD_OFFSET` = 62), with the source from `ipv6_src_for()`.
  An ICMPv6 error about a datagram we sent reaches the handler set with
  `udp6_set_error_handler()` as a `udp6_icmp_error_t`: the datagram's
  ports and destination, the error's type and code, the MTU of a Packet
  Too Big, and the quote (valid during the call).  The stack keeps no
  path MTU per destination: an application told of a smaller one sends
  smaller datagrams.
- **TCP**: `tcp_conn_t` has the IP version, the peer's IPv6 address and
  which of our addresses the peer used (a slot index), so replies keep the
  same source.  Inside `tcp.c` an *endpoint* (peer address + MAC, and our
  IPv6 address) stands for the IPv4 address everywhere a segment is built
  or matched: one segment builder, one input state machine, with thin
  `tcp_input()` / `tcp6_input()` entry points.  A listening connection
  accepts either family.  `tcp6_connect()` mirrors `tcp_connect()`.  Where
  the families differ, `BY_FAMILY(ep, v4, v6)` picks the expression for the
  endpoint's family; a single-stack build keeps only its own, so the other
  family's names need not exist (`mdns.c` does the same for its
  destinations).  `tcp6_icmp_error()` handles an ICMPv6 error about a
  segment in flight: Packet Too Big lowers the connection's segment size
  to MTU − 60 and the retransmission timer resends in smaller pieces
  (RFC 8201), Port Unreachable aborts the connection, anything else is a
  soft error (`TCP_EVT_SOFT_ERROR`; `tcp_last_error()` gives the ICMPv6
  type << 8 | code) ([tcp.md §3.8](tcp.md#38-icmp-errors-tcp_icmp_error-tcp6_icmp_error)).
- **MSS**: our MSS comes from the RX frame buffer and is 20 bytes smaller
  over IPv6: 1440 for a buffer of 1514 bytes or more, since it is capped at
  what one Ethernet frame carries; without an MSS option the peer's is 1220
  over IPv6 (536 over IPv4).  The send MSS is also clamped to what the TX
  frame buffer carries: a segment larger than the buffer could not be
  built, and a peer that advertises more than a small buffer holds — which
  the larger IPv6 header makes likelier — must not stall the connection
  ([tcp.md §4.4](tcp.md#44-segment-size)).

## 13. Deviations and limitations

| Item | Reason |
|---|---|
| No fragment reassembly (RFC 8200 §4.5); an atomic fragment is dropped too | RAM; fragments are dropped |
| Hop-by-Hop and Destination Options skipped without looking at the options (no Parameter Problem code 2 for unrecognized ones; the Router Alert of an MLD query is not required) | size; hosts rarely receive options |
| No neighbour cache / NUD; NA answers to our own NS are not recorded | distributed-cache model, as ARP |
| Redirect ignored (REQ-NDP-053) | no per-destination routes |
| RA MTU option, Reachable Time and Retrans Timer ignored | Ethernet MTU assumed; fixed 1 s RetransTimer |
| One default router (the last to advertise) | RAM |
| On-link = our /64s (L flag not tracked; DHCPv6 and static addresses count) | RAs set L and A together in practice |
| Duplicate EUI-64 link-local address does not disable IPv6 | no link-scope source and no RS follow from it anyway |
| A SLAAC address is probed at once, without the random delay RFC 4862 §5.4.2 asks for | `ipv6_addr_add()` treats static, SLAAC and DHCPv6 addresses alike |
| Address lifetimes end up to a second early | one second counter for the interface (§11) |
| Source selection: rules 2 and 3 of RFC 6724; the first preferred global address | one global address by default |
| No path MTU kept per destination: TCP lowers its segment size, a UDP application is told | RAM |
| MLD: group-specific queries answered with all groups; leaves sent once; the repeat of a report comes exactly 1 s later; no leave for a removed address's solicited-node group | RAM; see §9 |
| DHCPv6: first Advertise, one Release, no Confirm/Decline/Reconfigure/Rapid Commit | see §8 |
