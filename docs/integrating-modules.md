# Integrating Protocol Modules

The application protocols — DHCPv4 client and server, DHCPv6 client, TFTP
client, mDNS responder, HTTP server — are optional libraries.  The core
stack never calls them: it cannot see them, because the application owns
their state.  Every one is wired in the same way, and this page is that
recipe.

## 1. The pattern

1. **Initialise the stack.**  `net_init()` with two frame buffers and a MAC
   driver, then open the driver (`driver->init(ctx)` — `net_init()` does not),
   then seed the random generator with real entropy:
   `net_random_seed(&net, entropy, len)`.  For IPv6, `ipv6_start(&net)`.
2. **Initialise the module** with its `*_init()` function: its state
   structure, callbacks, tables.  Nothing is sent yet.
3. **Route its traffic to it.**  A UDP module gets an entry in the
   application's port table — `udp_set_ports()` for IPv4,
   `udp6_set_ports()` for IPv6 — whose handler calls the module's
   `*_input()` with the payload pointer it was given.  The HTTP server's
   slots go into the table given to `tcp_set_connections()`.
4. **Start it** with its start function, when its preconditions hold (an
   address for mDNS, a usable link-local address for DHCPv6).
5. **Drive it** from the main loop: `net_poll()` delivers frames (and so
   calls the handlers), `net_tick()` runs the stack's own timers — ARP,
   IPv4 reassembly and IGMP, TCP, IPv6 — and the application calls each
   module's `*_tick()` with the same elapsed time
   ([timer-model.md](design/timer-model.md)).

The handler is glue and nothing more:

```c
static void dhcp_port(net_t *n, uint32_t src_ip, uint16_t src_port,
                      const uint8_t *src_mac, const uint8_t *payload,
                      uint16_t len) {
  (void)src_port;
  dhcpv4_client_input(n, &dhcp, src_ip, src_mac, payload, len);
}
```

`payload` points into `net->rx.buf` and is valid only during the call
([udp.md §3](design/udp.md#3-port-tables)); every module parses it in place
and copies what it keeps.  A module may send its reply from inside the call:
replies are built in `net->tx.buf`, a separate buffer.

## 2. Modules

| Module | Header, CMake target | State | Init | Traffic → input | Start | Tick |
|---|---|---|---|---|---|---|
| DHCPv4 client | `dhcpv4_client.h`, `smallest_tcp::dhcpv4_client` | `dhcpv4_client_t` | `dhcpv4_client_init(c, net, on_event, ctx, opts)` | UDP **68** → `dhcpv4_client_input(net, c, src_ip, src_mac, payload, len)` | `dhcpv4_client_start(net, c)` | `dhcpv4_client_tick(net, c, ms)` |
| DHCPv4 server | `dhcpv4_server.h`, `smallest_tcp::dhcpv4_server` | `dhcpv4_server_t`, `const dhcpv4_server_cfg_t` | `dhcpv4_server_init(s, net, cfg, on_event, ctx)` | UDP **67** → `dhcpv4_server_input(net, s, src_ip, src_mac, payload, len)` | — (answers requests) | — |
| DHCPv6 client | `dhcpv6_client.h`, `smallest_tcp::dhcpv6_client` | `dhcpv6_client_t` | `dhcpv6_client_init(c, on_event, ctx, opts)` | UDP over IPv6 **546** (udp6 table) → `dhcpv6_client_input(net, c, src_ip, payload, len)` | `dhcpv6_client_start(net, c, mode)` | `dhcpv6_client_tick(net, c, ms)` |
| TFTP client | `tftp.h`, `smallest_tcp::tftp` | `tftp_client_t` | `tftp_client_init(c, local_port, on_data, on_done, ctx)` | UDP **`local_port`** (your choice) → `tftp_client_input(net, c, src_ip, src_mac, src_port, payload, len)` | `tftp_client_get(net, c, server_ip, server_mac, filename, blksize_opt)` | `tftp_client_tick(net, c, ms)` |
| mDNS / DNS-SD responder | `mdns.h`, `smallest_tcp::mdns` | `mdns_t`, `const mdns_record_t[]` | `mdns_init(m, net, records, count, on_conflict, ctx)` | UDP **5353** → `mdns_input(m, src_ip, src_mac, src_port, payload, len)`; over IPv6 also udp6 **5353** → `mdns_input6(...)` | `mdns_start(m)` | `mdns_tick(m, ms)` |
| HTTP server | `http.h`, `smallest_tcp::http` | `http_server_t`, `http_conn_t[]` | `http_conn_init()` per slot, then `http_server_init(s, net, port, routes, n_routes, conns, n_conns)` | TCP: each slot's `http_conn_tcp(&conns[i])` in the `tcp_set_connections()` table | (init listens) | `http_server_poll(s)` every loop, `http_server_tick(s, ms)` |

Notes per module:

- **DHCPv4 client.**  `dhcpv4_client_init()` refuses frame buffers smaller
  than 342 bytes (TX) and 590 bytes (RX).  `dhcpv4_client_start()` clears
  `net.ipv4_addr`, `subnet_mask` and `gateway_ipv4`; the client writes the
  lease into them once bound and clears them again on expiry; options beyond
  those reach the application through the option-handler table.  The first
  DISCOVER goes after a random delay of 1 to 10 s
  (`DHCPV4_START_DELAY_MAX_MS`).  Call `dhcpv4_client_release()` on
  shutdown.
- **DHCPv4 server.**  Stateless, single client: it always offers
  `cfg->offered_ip` and sends from `cfg->server_ip`, which must be
  `net.ipv4_addr` when `dhcpv4_server_init()` is called.  No timers.
- **DHCPv6 client.**  Start it once the link-local address is PREFERRED
  (`ipv6_addr_state(&net, 0) == NET_IP6_PREFERRED`) and a Router
  Advertisement has told you which mode: `DHCPV6_MODE_STATEFUL` if
  `net.ip6.ra_flags & NDP_RA_MANAGED`, `DHCPV6_MODE_STATELESS` for
  `NDP_RA_OTHER`.  Its first message goes after a random delay of up to
  1 s.  The client installs a leased address itself with `ipv6_addr_add()`
  (Duplicate Address Detection included).
- **TFTP client.**  The server's MAC must be known before `tftp_client_get()`
  ([arp-resolution.md §3](design/arp-resolution.md#3-resolving-a-mac-for-an-active-open)).
  The file arrives one block at a time through `on_data`; `blksize_opt` 1
  asks for the largest block `net->rx.buf` can hold.
- **mDNS.**  Needs `NET_MAX_MCAST_GROUPS ≥ 1` (and a slot of
  `NET_MAX_MCAST6_GROUPS` for IPv6).  `mdns_start()` joins 224.0.0.251 with
  `igmp_join()`, which installs IGMP in the IP layer — `net_tick()` runs its
  timers from then on — and `ff02::fb` with `ipv6_mcast_join()`, which MLD
  reports.  Start it once the IPv4 address is known;
  call `mdns_start()` again after a conflict (with a new name in the record
  table) or an address change, and `mdns_readdress6()` when an IPv6 address
  appears or goes (once running, it announces over IPv6 only).  `mdns_stop()` sends the goodbye.
- **HTTP.**  The slot's TCP connections must be in the table given to
  `tcp_set_connections()`; that table may hold other connections too.
  `net_tick()` runs their TCP timers; `http_server_tick()` runs only the
  request and response time-outs.

**API shape.**  `mdns_*` and `http_server_*` keep the `net_t *` they were
initialised with; the DHCP and TFTP functions take it on every call.

**TLS is not a UDP module.**  A `tls_conn_t` rides on a `tcp_conn_t`: the
application keeps both, and `tls_tcp_carry(net, tcp, tls)` (`tls_tcp.h`)
moves ciphertext between them after `net_poll()` and after `tls_write()`.
HTTPS is the HTTP server with `http_conn_use_tls()` (`http_tls.h`) on each
slot.  TLS has no timers.  CMake targets: `smallest_tcp::tls`, `::tls_tcp`,
`::https`, and a crypto backend such as `::tls_mbedtls`.  See
[tls.md](design/tls.md).

**DTLS is.**  The application's UDP handler looks up the peer's
`dtls_conn_t` by address and port (a server takes a new one for a
ClientHello), calls `dtls_input()`, then sends every datagram
`dtls_pending()` returns with `udp_send()` and `dtls_sent()`.  The main
loop calls `dtls_tick()`, whose retransmissions are sent the same way.  The
connection keeps no address: where its datagrams go is the application's.
CMake target: `smallest_tcp::tls` built with `SMALLEST_TCP_DTLS`, and a
crypto backend.  See [dtls.md](design/dtls.md) and `demo/dtls_echo`.

## 3. What the core offers a module

Two things in the core are installed by a call, and cost nothing — no
code linked, no time in `net_tick()` — in a program that does not make it:

- **Reassembly of IPv4 fragments.**  `ipv4_set_reassembly(&net, buf, size)`
  gives IPv4 a buffer (sized with `IPV4_REASSEMBLY_BUFFER(emtu_r)`) and
  installs reassembly's input and its 60 s timer; without it fragments are
  dropped.
- **IGMP.**  `igmp_join(&net, group)` joins a group, sends the report and
  installs IGMP's input and timers.

**Errors from the network.**  An ICMP or ICMPv6 error about a packet the
device sent goes to the transport that sent it.  A TCP connection handles
it itself: a hard error aborts it, a soft one is reported
(`TCP_EVT_SOFT_ERROR`, `tcp_last_error()`), Fragmentation Needed or Packet
Too Big lowers its segment size.  For UDP the application registers one
handler per address family, which gets the ports, the destination, the
type and code and the quoted packet:

```c
static void udp_error(net_t *n, const udp_icmp_error_t *err) {
  (void)n;
  if (err->local_port == 6969 && err->type == ICMP_TYPE_DEST_UNREACH)
    server_gone = 1; /* acted on in the main loop */
}

/* after net_init() */
udp_set_error_handler(&net, udp_error);
```

`udp6_set_error_handler()` takes a handler of `const udp6_icmp_error_t *`
the same way.  The errors the device itself sends need nothing from the
application; those over IPv6 are limited to `ICMPV6_ERROR_BURST` at once
and one more every `ICMPV6_ERROR_INTERVAL_MS`
([configuration.md §4](design/configuration.md#4-settings)).

## 4. Rules for handlers and callbacks

Handlers and module callbacks (`on_event`, `on_data`, `on_conflict`, option
handlers) run inside `net_poll()` or a tick:

- Keep them short; the MAC driver's receive slot is held during `net_poll()`
  ([mac-hal.md §3](design/mac-hal.md#3-the-receive-lifecycle-net_poll)).
- Copy what you need from pointers you are given; they are valid only during
  the call.
- Prefer setting a flag and acting from the main loop, as in the example
  below.  For TCP's `on_event` this is required: it must not send or close.
- Everything runs in one thread; the stack is not reentrant
  ([timer-model.md §5](design/timer-model.md#5-concurrency)).

## 5. A minimal main loop

A DHCPv4 client and an mDNS responder on a bare-metal board.  The `board_*`
functions stand for the platform: a MAC driver, a millisecond counter, an
entropy source.

```c
#include "dhcpv4_client.h"
#include "mdns.h"
#include "net.h"
#include "udp.h"

/* Platform code supplied by the board support package */
extern const net_mac_t board_mac_ops;
extern void *board_mac_ctx;
extern uint32_t board_millis(void);
extern void board_entropy(uint8_t *buf, uint16_t len); /* a hardware RNG */

static uint8_t rx_buf[1514];
static uint8_t tx_buf[1514];
static net_t net;

static dhcpv4_client_t dhcp;
static mdns_t mdns;
static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A, .ttl = MDNS_TTL_HOST, .name = "sensor-01.local",
     .rdata.a = 0}, /* 0: net.ipv4_addr */
};

static volatile uint8_t bound; /* set by the DHCP event, acted on below */

static void on_dhcp(uint8_t event, void *ctx) {
  (void)ctx;
  if (event == DHCPV4_EVT_BOUND)
    bound = 1;
}

/* UDP handlers: forward the payload pointer to the module */
static void dhcp_port(net_t *n, uint32_t src_ip, uint16_t src_port,
                      const uint8_t *src_mac, const uint8_t *payload,
                      uint16_t len) {
  (void)src_port;
  dhcpv4_client_input(n, &dhcp, src_ip, src_mac, payload, len);
}

static void mdns_port(net_t *n, uint32_t src_ip, uint16_t src_port,
                      const uint8_t *src_mac, const uint8_t *payload,
                      uint16_t len) {
  (void)n;
  mdns_input(&mdns, src_ip, src_mac, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {
    {68, dhcp_port},
    {MDNS_PORT, mdns_port},
};

int main(void) {
  uint8_t entropy[16];
  uint32_t last;

  /* 1. The stack */
  if (net_init(&net, rx_buf, sizeof rx_buf, tx_buf, sizeof tx_buf, NULL,
               &board_mac_ops, board_mac_ctx) != NET_OK ||
      board_mac_ops.init(board_mac_ctx) != 0)
    return 1;
  board_entropy(entropy, sizeof entropy);
  net_random_seed(&net, entropy, sizeof entropy);
  udp_set_ports(&net, udp_ports, sizeof udp_ports / sizeof udp_ports[0]);

  /* 2. The modules: init, then start */
  if (dhcpv4_client_init(&dhcp, &net, on_dhcp, NULL, NULL) != NET_OK ||
      mdns_init(&mdns, &net, records, 1, NULL, NULL) != NET_OK)
    return 1;
  dhcpv4_client_start(&net, &dhcp); /* no address until the lease */

  /* 3. The main loop */
  last = board_millis();
  for (;;) {
    uint32_t now = board_millis();
    uint32_t elapsed = now - last;

    while (net_poll(&net) > 0) {
    }
    if (elapsed >= 10) {
      last = now;
      net_tick(&net, elapsed);
      dhcpv4_client_tick(&net, &dhcp, elapsed);
      mdns_tick(&mdns, elapsed);
    }
    if (bound) {
      bound = 0;
      mdns_start(&mdns); /* announce the new address */
    }
  }
}
```

Adding the HTTP server to the same program:

```c
#include "http.h"

#define SLOTS 2
static http_conn_t slots[SLOTS];
static uint8_t slot_tx[SLOTS][536];
static uint8_t slot_rx[SLOTS][536];
static char slot_req[SLOTS][512];
static tcp_conn_t *tcp_table[SLOTS];
static http_server_t http;

static int hello(const http_request_t *req, http_response_t *resp,
                 void *ctx) {
  static const char body[] = "hello\n";
  (void)req;
  (void)ctx;
  resp->content_type = "text/plain";
  resp->body = (const uint8_t *)body;
  resp->body_len = sizeof body - 1;
  return 0;
}

static const http_route_t routes[] = {{"/", HTTP_GET, hello, NULL}};

/* Call after net_init() */
static void http_setup(void) {
  uint8_t i;
  for (i = 0; i < SLOTS; i++) {
    http_conn_init(&slots[i], slot_tx[i], sizeof slot_tx[i], slot_rx[i],
                   sizeof slot_rx[i], slot_req[i], sizeof slot_req[i]);
    tcp_table[i] = http_conn_tcp(&slots[i]);
  }
  tcp_set_connections(&net, tcp_table, SLOTS);
  http_server_init(&http, &net, 80, routes, 1, slots, SLOTS);
}
```

and in the loop, `http_server_poll(&http)` after draining `net_poll()`, and
`http_server_tick(&http, elapsed)` next to the other ticks.  Each slot's TCP
buffers bound the window and the segments it sends; 536 bytes is TCP's
default MSS.

The hosted demos do the same through `demo/common/demo_loop.h`
(`demo_net_open()`, `demo_run()` with per-demo tick and service hooks); each
demo's `main.c` is a working example of one or more modules.

## 6. Randomness

`net_init()` seeds the stack's one generator from the MAC address, which is
unique per device but public.  TCP initial sequence numbers, DHCPv4 and
DHCPv6 transaction IDs, and the random delays of mDNS, NDP, MLD and DHCPv6
all come from it, so call `net_random_seed(&net, bytes, len)` after
`net_init()` with whatever entropy the platform has — a hardware RNG, ADC
noise, the microseconds until the first frame, a value kept in flash across
boots.  Every byte counts; 8 random bytes fill the 64-bit key.  It may be
called again at any time to mix in more.  See
[architecture.md §9](architecture.md#9-randomness) for what the generator is
and is not.
