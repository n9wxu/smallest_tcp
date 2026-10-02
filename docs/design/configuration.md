# Configuration — Design

**Files:** `include/net_config.h`; tunables in `ipv4.h`, `ndp.h`,
`dns_wire.h`, `http.h`, `dhcpv4_client.h`, `dhcpv6_client.h`, `tftp.h`,
`tls.h`, `dtls.h`

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
In particular, with CMake choose the protocols with the `SMALLEST_TCP_IPV4`,
`SMALLEST_TCP_IPV6`, `SMALLEST_TCP_UDP` and `SMALLEST_TCP_TCP` options (which
select the sources and define `NET_USE_IPV4`, `NET_USE_IPV6`, `NET_USE_UDP`
and `NET_USE_TCP`) and debug output with `SMALLEST_TCP_DEBUG` (`NET_DEBUG=1`),
not in the header.  Turning UDP or TCP off also drops the libraries built on
it and the tests and demos, which use the whole stack; turning IPv4 off drops
the applications that run only over IPv4 and their tests (§5).

Every header of the stack with a tunable includes `net_config.h` (directly
or through `net.h`), so its tunables (§4) can go in either place.  The TLS
and DTLS headers (`tls.h`, `dtls.h`) are the exception: they do not depend
on the network stack and do not include it, so `TLS_USE_DTLS` and the
`DTLS_*` timer settings take effect only with `-D` (CMake defines
`TLS_USE_DTLS` from `SMALLEST_TCP_DTLS`), not from the configuration header.

## 3. Library and application must agree

The library and the application must be compiled with the same settings.
Several of them change the layout of structures that both sides use, and a
mismatch is not a link error: the two sides simply disagree about field
offsets and corrupt each other's memory.

| Setting | Changes |
|---|---|
| `NET_USE_IPV4` | `net_t` (the IPv4 address, mask, gateway and its MAC, `mcast_groups`, the IPv4 port table), `tcp_conn_t` (`remote_ip`), `http_request_t` (`remote_ip`), and which functions exist |
| `NET_USE_IPV6` | `net_t` (the `ip6` block, `mcast6_groups`, the IPv6 port table), `tcp_conn_t`, `http_request_t`, `http_conn_t`, and which functions exist |
| `NET_USE_UDP`, `NET_USE_TCP` | `net_t` (port tables, connection table) |
| `NET_MAX_MCAST_GROUPS`, `NET_MAX_MCAST6_GROUPS` | `net_t` (group arrays) |
| `NET_ARP_RATE_SLOTS` | `net_t` (`arp_recent[]`) |
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
| `NET_USE_IPV4` | 1 | IPv4, ARP and ICMP: their dispatch in `eth_input()`, the IPv4 fields of `net_t`, the IPv4 halves of UDP, TCP, mDNS and HTTP.  0 builds an IPv6-only stack (§5): `udp_send()`, `tcp_connect()`, `mdns_input()` and the rest of the IPv4 API are not declared, and `ipv4.h` — so `arp.h`, `icmp.h`, `igmp.h`, `tftp.h` and the DHCPv4 headers with it — stops the build with "IPv4 is not compiled in".  The CMake option `SMALLEST_TCP_IPV4` (default ON) adds the IPv4 sources and sets it. |
| `NET_USE_IPV6` | 0 | IPv6, ICMPv6, NDP, SLAAC, MLD dispatch; `net->ip6`; IPv6 fields in TCP; the udp6 API.  The CMake option `SMALLEST_TCP_IPV6` (default ON) adds the IPv6 sources and sets it.  With `NET_USE_IPV4` 0 as well, `net_config.h` stops the build: there would be no network layer. |
| `NET_USE_UDP` | 1 | `ipv4_input()` / `ipv6_input()` dispatch to UDP; `net_t` has the port tables.  `udp.h` needs it.  CMake: `SMALLEST_TCP_UDP` (default ON). |
| `NET_USE_TCP` | 1 | The same for TCP; `net_tick()` runs `tcp_tick()`.  `tcp.h` (and so `tcp.c`, `http.c`) needs it.  CMake: `SMALLEST_TCP_TCP` (default ON). |
| `NET_MAX_MCAST_GROUPS` | 1 | IPv4 groups joinable at once (`ipv4_mcast_join()`, `igmp_join()`).  The all-hosts group 224.0.0.1 is joined besides them, without a slot, whenever this is ≥ 1 (RFC 1112 §7.2).  0 compiles multicast reception out; `mdns.c` refuses to compile with 0. |
| `NET_MAX_MCAST6_GROUPS` | 1 | IPv6 groups joinable with `ipv6_mcast_join()` (mDNS uses `ff02::fb`).  All-nodes and our solicited-node groups are always accepted and need no slot.  With `NET_USE_IPV6`, `mdns.c` refuses to compile with 0. |
| `NET_IPV6_ADDRS` | 2 | IPv6 address slots: `[0]` link-local, the rest global (SLAAC, DHCPv6, static). |
| `NET_IPV6_DAD_TRANSMITS` | 1 | Neighbor Solicitations per Duplicate Address Detection run (RFC 4862 `DupAddrDetectTransmits`). |
| `NET_IPV6_DEFAULT_HOP_LIMIT` | 64 | Hop limit until a Router Advertisement supplies one. |
| `NET_8BIT_TARGET` | 0 | Consulted by `net_endian.h` only when the compiler does not predefine `__BYTE_ORDER__`: 1 selects big-endian, making `net_htons()` and friends no-ops.  Field access never depends on it ([byte-order.md](byte-order.md)). |
| `NET_DEBUG` | 0 | 1 makes `NET_LOG()` print to `stderr` (hosted builds only).  CMake: `SMALLEST_TCP_DEBUG`. |
| `NET_DEFAULT_IPV4_ADDR` | 10.0.0.2 | Copied into `net->ipv4_addr` by `net_init()`.  Set 0 for a device that waits for DHCP. |
| `NET_DEFAULT_SUBNET_MASK` | 255.255.255.0 | `net->subnet_mask`. |
| `NET_DEFAULT_GATEWAY` | 10.0.0.1 | `net->gateway_ipv4`. |
| `NET_DEFAULT_MTU` | 1500 | `net->mtu`, the link MTU: no datagram sent is longer (RFC 1122 §3.3.3).  The application may lower it at run time. |
| `NET_ARP_GATEWAY_TIMEOUT_MS` | 300000 | How long a gateway MAC learned by ARP stays valid without a new reply (RFC 1122 §2.3.2.1). |
| `NET_ARP_RATE_SLOTS` | 2 | ARP targets remembered so that none is requested more than once a second (RFC 1122 §2.3.2.1); `net_t` holds them. |
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
| `HTTP_HDR_MAX` | `http.h` | 224 | Largest response header block, formatted on the C stack. |
| `HTTP_REQUEST_TIMEOUT_MS` | `http.h` | 10000 | Time a connection slot may take to receive a complete request. |
| `HTTP_RESPONSE_TIMEOUT_MS` | `http.h` | 10000 | Time allowed to send the response and close. |
| `DHCPV6_MAX_DUID` | `dhcpv6_client.h` | 20 | Largest server DUID kept (layout-affecting). |
| `DHCPV4_START_DELAY_MAX_MS` | `dhcpv4_client.h` | 10000 | The first DISCOVER waits a random 1 s up to this (RFC 2131 §4.4.1); 0 sends it at once, else 1000..65535. |
| `DHCPV4_PROBE_WAIT_MS` | `dhcpv4_client.h` | 1000 | How long the client waits after its ARP probe of an ACK's address before using it (RFC 2131 §4.4.1). |
| `DHCPV4_SPLIT_OPTION_MAX` | `dhcpv4_client.h` | 255 | Buffer, on the stack, in which an option split in parts (RFC 3396) is joined for its handler; 1..255. |
| `TFTP_RTO_MIN_MS`, `TFTP_RTO_MAX_MS` | `tftp.h` | 1000, 16000 | Bounds of the TFTP client's adaptive retransmission timeout (RFC 1123 §4.2.3.2); the maximum also caps its backoff. |

Other protocol constants are plain `#define`s — fixed by their RFCs or by the
implementation, and not meant to be overridden: for example
`TFTP_TIMEOUT_MS` (the first timeout) and `TFTP_MAX_RETRIES` (`tftp.h`), the mDNS probe and
announce timings and `MDNS_MAX_RECORDS` (the width of its record bitmasks,
`mdns.h`), the DHCPv4 retransmission back-off (`dhcpv4_client.c`), and
`TCP_MAX_RETRANSMITS` (`tcp.c`).

`TLS_USE_DTLS` (`tls.h`, default 1; CMake `SMALLEST_TCP_DTLS`) builds the
shared TLS handshake for DTLS 1.3 too; 0 leaves DTLS's formats and cookie
out of it, and `dtls.c` refuses to build.  DTLS's retransmission timer is
tunable in `dtls.h`: `DTLS_RTO_INITIAL_MS` (1000), `DTLS_RTO_MAX_MS`
(60000) and `DTLS_MAX_RETRANSMITS` (6).  TLS has no other settings here;
the Mbed TLS backend is configured by `tls_mbedtls_user_config.h`, which
CMake passes to Mbed TLS as `MBEDTLS_USER_CONFIG_FILE`.

### What has no setting

Some things a stack often configures have no setting here, because the
stack does not do them or does not choose them:

- Hardware capabilities such as checksum offload: checksums are computed in
  software ([checksum.md §7](checksum.md#7-hardware-offload-not-implemented)).
- Which application protocols are built in (DHCP, TFTP, mDNS, HTTP, TLS):
  they are selected by linking (§5).
- Run-time assertions: there are none.
- A DNS server (there is no resolver), a minimum RTO or a delayed-ACK time
  (TCP has no RTT estimator and acknowledges at once), ARP retries (the
  stack does not retry ARP; the application does — see
  [arp-resolution.md](arp-resolution.md)).

## 5. Compile-time protocol selection

The stack is composed in two different ways, and the difference matters when
sizing a build.

**The core is composed at compile time.**  `eth.c` dispatches to ARP/IPv4
and IPv6 under `NET_USE_IPV4` / `NET_USE_IPV6`; `ipv4.c` and `ipv6.c`
dispatch to UDP and TCP under `NET_USE_UDP` / `NET_USE_TCP`.  Either network
layer can be left out, not both: an IPv6-only build (`NET_USE_IPV4` 0, CMake
`-DSMALLEST_TCP_IPV4=OFF`) has no `arp.c`, `ipv4.c`, `icmp.c` or `igmp.c`,
UDP and TCP keep only their IPv6 halves, and mDNS answers over IPv6 with
AAAA records only (`mdns_init()` refuses an A record).  The DHCPv4 client
and server and TFTP run only over IPv4 and are not built; DHCPv6, mDNS, HTTP
and TLS are.  On Cortex-M0 a UDP echo over IPv6 alone is 6,105 bytes, 3.0 KB
less than the dual stack ([size-comparison.md](size-comparison.md)).  Those calls are
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
| `smallest_tcp::core` (alias `smallest_tcp::smallest_tcp`) | The core: `net`, `net_cksum`, `net_text`, `eth`; with `SMALLEST_TCP_IPV4`, also `arp`, `ipv4`, `icmp`; with `SMALLEST_TCP_IPV6`, also `ipv6`, `icmpv6`, `ndp`, `mld`; with `SMALLEST_TCP_UDP`, `udp`; with `SMALLEST_TCP_TCP`, `tcp` and `tcp_buf_saw` |
| `smallest_tcp::dhcpv4_client`, `::dhcpv4_server` | `dhcpv4_client.c`, `dhcpv4_server.c` (UDP over IPv4) |
| `smallest_tcp::dhcpv6_client` | `dhcpv6_client.c` (UDP over IPv6) |
| `smallest_tcp::tftp` | `tftp.c` (UDP over IPv4) |
| `smallest_tcp::mdns` | `mdns.c`, `dns_wire.c`; `igmp.c` with IPv4 (UDP) |
| `smallest_tcp::http` | `http.c` (TCP) |
| `smallest_tcp::tls` | TLS 1.3, and DTLS 1.3 with `SMALLEST_TCP_DTLS` ([tls.md](tls.md), [dtls.md](dtls.md)); no dependencies |
| `smallest_tcp::tls_tcp`, `::https` | A TLS connection carried over a TCP connection, and HTTPS (`http_tls.c`) (TCP) |
| `smallest_tcp::tls_mbedtls` | The Mbed TLS crypto backend (`SMALLEST_TCP_TLS`) |
| `smallest_tcp::driver_tap`, `::driver_rawsock`, `::driver_bpf`, `::driver_stm32f4_eth` | Platform MAC drivers (`SMALLEST_TCP_BUILD_DRIVERS`; the last when cross-compiling for ARM) |

## 6. Run-time values

`net_init()` zeroes `net_t` and applies the identity defaults; after that the
values are ordinary fields the application or a protocol changes:

| Field | Initial value | Changed by |
|---|---|---|
| `net->ipv4_addr`, `subnet_mask`, `gateway_ipv4` | `NET_DEFAULT_*` | The application (static configuration), the DHCPv4 client (lease, and 0 again on expiry or release) |
| `net->mac` | `mac` argument, else `NET_DEFAULT_MAC` | Set once at init |
| `net->mtu` | `NET_DEFAULT_MTU` | The application (a smaller link MTU) |
| `net->gateway_mac`, `gateway_mac_valid` | unset | ARP replies from the gateway, valid for `NET_ARP_GATEWAY_TIMEOUT_MS` |
| `net->ip6` | zero | `ipv6_start()`, NDP, SLAAC, DHCPv6, `ipv6_addr_add()` |
| `net->secret` | derived from the MAC address | `net_random_seed()` ([architecture.md §9](../architecture.md#9-randomness)) |
| `net->random_count` | 0 | `net_random()`, once per output |
| `net->tcp_clock` | 0 | `tcp_tick()`, 250 per elapsed millisecond ([tcp.md §4.6](tcp.md#46-initial-sequence-numbers)) |

Values that exist only at run time — TCP sequence numbers, the peer's window
and MSS, lease and lifetime timers, DAD state, transaction IDs — live in the
structures of the protocol that owns them and have no configuration.
