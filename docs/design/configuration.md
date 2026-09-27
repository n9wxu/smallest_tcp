# Configuration — Design

**Files:** `include/net_config.h`; tunables in `ipv4.h`, `ndp.h`,
`dns_wire.h`, `http.h`, `dhcpv6_client.h`
**Last updated:** 2026-09-27

## 1. Overview

Configuration falls into three kinds, by when the value is known:

| Kind | Mechanism | Examples |
|---|---|---|
| **Compile-time settings** | Preprocessor macros with `#ifndef` defaults | Which transports IP dispatches to, multicast group slots, IPv6 address slots, TCP timer constants |
| **Compile-time defaults for run-time values** | `NET_DEFAULT_*` macros that `net_init()` copies into `net_t` | IPv4 address, subnet mask, gateway, MAC |
| **Run-time state** | Fields the stack or the application sets | Addresses from DHCP or SLAAC, learned MACs, sequence numbers, lease timers |

Buffer sizes are not configuration macros: the application declares its
buffers and passes their sizes to `net_init()` and the module init functions,
and the stack derives what it can from them (TCP MSS, TFTP block size, which
messages fit).

## 2. Setting values

Every setting is a default wrapped in `#ifndef`, so any of them can be
overridden in either of two ways:

1. **`-D` on the compiler command line**, e.g. `-DNET_USE_IPV6=1`.
2. **An application configuration header.**  Define `NET_CONFIG_FILE` as a
   quoted header name; `net_config.h` includes it before any default, so its
   definitions win:

   ```sh
   cc -DNET_CONFIG_FILE='"app_net_config.h"' -Iapp/include ...
   ```

   ```c
   /* app_net_config.h */
   #define NET_MAX_MCAST_GROUPS 2
   #define NET_IPV6_ADDRS 3
   #define NET_DEFAULT_IPV4_ADDR 0 /* wait for DHCP */
   ```

   With CMake, the cache variable `SMALLEST_TCP_CONFIG_FILE=<path>` names
   that header; it becomes a `PUBLIC` definition of the core target, so the
   library and everything linked to it see the same header.

Use one mechanism per macro: defining the same macro both with `-D` and in
the header is a redefinition error under `-Werror` unless the values match.
In particular, with CMake choose the protocols with the `SMALLEST_TCP_IPV6`,
`SMALLEST_TCP_UDP` and `SMALLEST_TCP_TCP` options (which select the sources
and define `NET_USE_IPV6`, `NET_USE_UDP` and `NET_USE_TCP`) and debug output
with `SMALLEST_TCP_DEBUG` (`NET_DEBUG=1`), not in the header.  Turning UDP or
TCP off also drops the libraries built on it and the tests and demos, which
use the whole stack.

Every header with a tunable includes `net_config.h` (directly or through
`net.h`), so the module tunables of §4 can go in either place.

## 3. Library and application must agree

The library and the application must be compiled with the same settings.
Several of them change the layout of structures that both sides use, and a
mismatch is not a link error: the two sides simply disagree about field
offsets and corrupt each other's memory.

| Setting | Changes |
|---|---|
| `NET_USE_IPV6` | `net_t` (the `ip6` block, `mcast6_groups`, the IPv6 port table), `tcp_conn_t`, `http_request_t`, `http_conn_t`, and which functions exist |
| `NET_USE_UDP`, `NET_USE_TCP` | `net_t` (port tables, connection table) |
| `NET_MAX_MCAST_GROUPS`, `NET_MAX_MCAST6_GROUPS` | `net_t` (group arrays) |
| `NET_IPV6_ADDRS` | `net_t` (`ip6.addr[]`) |
| `DHCPV6_MAX_DUID` | `dhcpv6_client_t` |
| `DNS_COMPRESS_MAX` | `dns_writer_t` (shared by `dns_wire.c` and `mdns.c`) |

This is why the CMake build declares the `NET_USE_*` settings as `PUBLIC`
compile definitions of the core target, and why a configuration header is preferable
to scattered `-D` flags: one file, included by every translation unit.

## 4. Settings

### `net_config.h`

| Macro | Default | Effect |
|---|---|---|
| `NET_USE_IPV4` | 1 | `eth_input()` dispatches ARP and IPv4 and accepts IPv4 multicast MACs.  That is all it gates: `net_t` keeps its IPv4 fields and IPv4 objects are still linked when something references them.  0 is untested. |
| `NET_USE_IPV6` | 0 | IPv6, ICMPv6, NDP, SLAAC, MLD dispatch; `net->ip6`; IPv6 fields in TCP; the udp6 API.  The CMake option `SMALLEST_TCP_IPV6` (default ON) adds the IPv6 sources and sets it. |
| `NET_USE_UDP` | 1 | `ipv4_input()` / `ipv6_input()` dispatch to UDP; `net_t` has the port tables.  `udp.h` needs it.  CMake: `SMALLEST_TCP_UDP` (default ON). |
| `NET_USE_TCP` | 1 | The same for TCP; `net_tick()` runs `tcp_tick()`.  `tcp.h` (and so `tcp.c`, `http.c`) needs it.  CMake: `SMALLEST_TCP_TCP` (default ON). |
| `NET_MAX_MCAST_GROUPS` | 1 | IPv4 groups joinable at once (`ipv4_mcast_join()`, `igmp_join()`).  0 compiles multicast reception out; `mdns.c` refuses to compile with 0. |
| `NET_MAX_MCAST6_GROUPS` | 1 | IPv6 groups joinable with `ipv6_mcast_join()` (mDNS uses `ff02::fb`).  All-nodes and our solicited-node groups are always accepted and need no slot. |
| `NET_IPV6_ADDRS` | 2 | IPv6 address slots: `[0]` link-local, the rest global (SLAAC, DHCPv6, static). |
| `NET_IPV6_DAD_TRANSMITS` | 1 | Neighbor Solicitations per Duplicate Address Detection run (RFC 4862 `DupAddrDetectTransmits`). |
| `NET_IPV6_DEFAULT_HOP_LIMIT` | 64 | Hop limit until a Router Advertisement supplies one. |
| `NET_8BIT_TARGET` | 0 | Consulted by `net_endian.h` only when the compiler does not predefine `__BYTE_ORDER__`: 1 selects big-endian, making `net_htons()` and friends no-ops.  Field access never depends on it ([byte-order.md](byte-order.md)). |
| `NET_DEBUG` | 0 | 1 makes `NET_LOG()` print to `stderr` (hosted builds only).  CMake: `SMALLEST_TCP_DEBUG`. |
| `NET_DEFAULT_IPV4_ADDR` | 10.0.0.2 | Copied into `net->ipv4_addr` by `net_init()`.  Set 0 for a device that waits for DHCP. |
| `NET_DEFAULT_SUBNET_MASK` | 255.255.255.0 | `net->subnet_mask`. |
| `NET_DEFAULT_GATEWAY` | 10.0.0.1 | `net->gateway_ipv4`. |
| `NET_DEFAULT_MAC` | 02:00:00:de:ad:01 | Used when `net_init()` is given a NULL MAC.  A locally administered address for development; production devices pass their own. |
| `NET_DEFAULT_TCP_RTO_INIT_MS` | 1000 | Initial retransmission timeout and first zero-window probe interval. |
| `NET_DEFAULT_TCP_RTO_MAX_MS` | 60000 | Ceiling for the doubling retransmission and probe intervals. |
| `NET_DEFAULT_TCP_MSL_MS` | 120000 | Maximum segment lifetime; TIME-WAIT lasts 2 × MSL. |

`NET_IPV4(a, b, c, d)` builds a host-order IPv4 address for these defaults;
it is a helper, not a setting.

### Module headers

| Macro | Header | Default | Effect |
|---|---|---|---|
| `NET_DEFAULT_TTL` | `ipv4.h` | 64 | TTL of IPv4 datagrams sent through `ipv4_build()` / `udp_send()`. |
| `NDP_MAX_RTR_SOLICITATIONS` | `ndp.h` | 3 | Router Solicitations sent at start-up if no Router Advertisement arrives. |
| `DNS_COMPRESS_MAX` | `dns_wire.h` | 16 | Label offsets a DNS writer remembers as compression targets. |
| `HTTP_HDR_MAX` | `http.h` | 192 | Largest response header block, formatted on the C stack. |
| `HTTP_REQUEST_TIMEOUT_MS` | `http.h` | 10000 | Time a connection slot may take to receive a complete request. |
| `HTTP_RESPONSE_TIMEOUT_MS` | `http.h` | 10000 | Time allowed to send the response and close. |
| `DHCPV6_MAX_DUID` | `dhcpv6_client.h` | 20 | Largest server DUID kept (layout-affecting). |

Other protocol constants are plain `#define`s — fixed by their RFCs or by the
implementation, and not meant to be overridden: for example
`TFTP_TIMEOUT_MS` and `TFTP_MAX_RETRIES` (`tftp.h`), the mDNS probe and
announce timings and `MDNS_MAX_RECORDS` (the width of its record bitmasks,
`mdns.h`), the DHCPv4 retransmission back-off (`dhcpv4_client.c`), and
`TCP_MAX_RETRANSMITS` (`tcp.c`).

TLS has no settings here.  The Mbed TLS backend is configured by
`tls_mbedtls_user_config.h`, which CMake passes to Mbed TLS as
`MBEDTLS_USER_CONFIG_FILE`.

### Removed

These appeared in earlier versions of `net_config.h` or of this document and
no longer exist, because nothing used them:

- `NET_MAC_CAP_TX_CKSUM_IPV4/TCP/UDP`, `NET_MAC_CAP_RX_CKSUM_OK` —
  checksum offload was documented but never implemented
  ([checksum.md §7](checksum.md#7-hardware-offload-not-implemented)).
- `NET_USE_DHCPV4`, `NET_USE_DHCPV6`, `NET_USE_DNS`, `NET_USE_TFTP`,
  `NET_USE_HTTP` — application protocols are selected by linking (§5).
- `NET_ASSERT` / `NET_ASSERT_ENABLED`.
- `NET_DEFAULT_DNS_SERVER`, `NET_DEFAULT_TCP_RTO_MIN_MS`,
  `NET_DEFAULT_TCP_DELAYED_ACK_MS` (there is no RTT estimator and no delayed
  ACK), `NET_DEFAULT_ARP_RETRY_MS`, `NET_DEFAULT_ARP_MAX_RETRIES` and the
  matching `net_t` fields `arp_retry_ms` / `arp_max_retries` (the stack does
  not retry ARP; the application does — see
  [arp-resolution.md](arp-resolution.md)).

## 5. Compile-time protocol selection

The stack is composed in two different ways, and the difference matters when
sizing a build.

**The core is composed at compile time.**  `eth.c` dispatches to ARP/IPv4
and IPv6 under `NET_USE_IPV4` / `NET_USE_IPV6`; `ipv4.c` and `ipv6.c`
dispatch to UDP and TCP under `NET_USE_UDP` / `NET_USE_TCP`.  Those calls are
references, so **linking IPv4 pulls in `udp.o` and `tcp.o`** unless the build
compiles with `-DNET_USE_UDP=0` or `-DNET_USE_TCP=0`.  A transport that is
switched off is not dispatched to, its fields leave `net_t`, and its header
no longer compiles — so its source files must also be left out of the build.
The ARM size benchmark does this (`make arm-size` builds with
`-DNET_USE_TCP=0` and without `tcp.c`), and so do the CMake options
`SMALLEST_TCP_UDP` and `SMALLEST_TCP_TCP`: turned off, they leave the
transport's sources out of the core, define its `NET_USE_*` as 0, and skip
the libraries that need it.

"Link only what you need" is therefore really "configure what you need" for
the transport layer.

**Application protocols are composed at link time.**  Nothing in the core
refers to DHCP, TFTP, mDNS, HTTP or TLS; the application calls them and
routes their traffic to them (UDP port tables, TCP connection tables).  An
unused module is simply not linked.  In CMake each is its own library:

| Target | Sources |
|---|---|
| `smallest_tcp::smallest_tcp` | The core: `net`, `net_cksum`, `net_text`, `eth`, `arp`, `ipv4`, `icmp`, `udp`, `tcp`, `tcp_buf_saw`; with `SMALLEST_TCP_IPV6`, also `ipv6`, `icmpv6`, `ndp`, `mld` |
| `smallest_tcp::dhcpv4_client`, `::dhcpv4_server` | `dhcpv4_client.c`, `dhcpv4_server.c` |
| `smallest_tcp::dhcpv6_client` | `dhcpv6_client.c` (IPv6 builds) |
| `smallest_tcp::tftp` | `tftp.c` |
| `smallest_tcp::mdns` | `mdns.c`, `dns_wire.c`, `igmp.c` |
| `smallest_tcp::http` | `http.c` |
| `smallest_tcp::tls`, `::tls_tcp`, `::https`, `::tls_mbedtls` | TLS 1.3, its glue to a TCP connection, HTTPS (`http_tls.c`), and the Mbed TLS crypto backend ([tls.md](tls.md)) |
| `smallest_tcp::driver_tap`, `::driver_rawsock`, `::driver_bpf` | Platform MAC drivers |

## 6. Run-time values

`net_init()` zeroes `net_t` and applies the identity defaults; after that the
values are ordinary fields the application or a protocol changes:

| Field | Initial value | Changed by |
|---|---|---|
| `net->ipv4_addr`, `subnet_mask`, `gateway_ipv4` | `NET_DEFAULT_*` | The application (static configuration), the DHCPv4 client (lease, and 0 again on expiry or release) |
| `net->mac` | `mac` argument, else `NET_DEFAULT_MAC` | Set once at init |
| `net->gateway_mac`, `gateway_mac_valid` | unset | ARP replies from the gateway |
| `net->ip6` | zero | `ipv6_start()`, NDP, SLAAC, DHCPv6, `ipv6_addr_add()` |
| `net->rng` | seeded from the MAC | `net_random_seed()` ([architecture.md §9](../architecture.md#9-randomness)) |

Values that exist only at run time — TCP sequence numbers, the peer's window
and MSS, lease and lifetime timers, DAD state, transaction IDs — live in the
structures of the protocol that owns them and have no configuration.
