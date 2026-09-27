# DHCPv4 Design

**Protocol:** Dynamic Host Configuration Protocol v4 (RFC 2131, options RFC 2132)  
**Files:** `include/dhcpv4_client.h`, `src/dhcpv4_client.c`,
           `include/dhcpv4_server.h`, `src/dhcpv4_server.c`,
           `src/dhcpv4_wire.h` (private, shared)  
**Requirements:** [dhcpv4.md](../requirements/dhcpv4.md)  
**Last updated:** 2026-09-27

---

## 1. Overview and Split Design

DHCPv4 is two independent libraries — a client and a minimal stateless
server.  An application links only what it needs:

| Use case | What to link |
|---|---|
| MCU on an Ethernet LAN — gets IP from router | `smallest_tcp::dhcpv4_client` |
| USB/CDC-ECM device — assigns IP to the PC peer | `smallest_tcp::dhcpv4_server` |
| Two-interface bridge / router | Out of scope (single `net_t` / single MAC) |

Both are integrated like every protocol module — an application-owned
state struct, an `init` call, and a UDP port handler (68 for the client,
67 for the server) that passes the datagram to the module; the client
also needs a `start` call and a `tick` from the main loop.  See
[integrating-modules.md](../integrating-modules.md).

The two share the message format through `src/dhcpv4_wire.h` (§2).  It is
private to the library — not in `include/` — and header-only: constants
and `static inline` functions, so each library compiles in only what it
uses and neither depends on the other.  Before it existed the client and
the server each defined the same 28 layout and option constants, and the
option list was walked by five hand-written loops.

---

## 2. Message Format (`dhcpv4_wire.h`)

### 2.1 Reading options

| Helper | Returns |
|---|---|
| `dhcp_next_option(msg, len, &pos, &data, &olen)` | The next option's code (start with `pos = DHCP_OFF_OPTIONS`), with its value and length; `DHCP_OPT_END` at End, at the end of the message, or on an option whose length runs past it |
| `dhcp_find_option(msg, len, code, &olen)` | The first option `code`, or NULL |
| `dhcp_message_type(msg, len)` | Option 53, or 0 if absent |
| `dhcp_option_u32(msg, len, code, absent)` | A 4-byte option in host order, or `absent` |

Pad options are skipped; a truncated option ends the walk instead of
being read out of bounds.  Option Overload (52) is not supported: options
carried in the `sname`/`file` fields are not seen.

### 2.2 Building in place

Messages are built directly in the UDP payload area of `net->tx.buf`
(`UDP_PAYLOAD_OFFSET`) and sent with `udp_send_inplace_from()` — no copy.
(They used to be built in 300-plus-byte stack buffers and copied by
`udp_send()`.)

```c
uint8_t *msg = dhcp_begin(net, DHCP_OP_REQUEST, xid, net->mac); /* NULL if TX too small */
uint16_t pos = DHCP_OFF_OPTIONS;
pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, DHCP_MSG_DISCOVER);
pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, server_ip);
udp_send_inplace_from(net, src_ip, dst_ip, dst_mac, DHCP_CLIENT_PORT,
                      DHCP_SERVER_PORT, dhcp_end(msg, pos), NET_DEFAULT_TTL);
```

`dhcp_begin()` zeroes `DHCP_MIN_LEN` (300) bytes and fills `op`, `htype`,
`hlen`, `xid`, `chaddr` and the magic cookie; the caller sets `flags`,
`ciaddr`, `yiaddr` and `siaddr` as needed.  `dhcp_end()` writes the End
option and returns the length to send, padded to 300 bytes (the BOOTP
minimum that relays and servers expect).

**Invariant:** every message this library builds fits in 300 bytes, so
the `dhcp_put_*()` helpers do not bounds-check.  The largest is the
client's REQUEST in REQUESTING: 240 + 3 (type) + 6 (server ID) + 6
(requested IP) + 37 (a Parameter Request List of at most 35 codes) + 1
(End) = 293.  A new option must fit in that budget.

**Source address.**  The IPv4 source is passed explicitly: the client
sends from 0.0.0.0 until a lease has been ACKed (`client_address()`), the
server from its configured address.  The old code temporarily overwrote
`net->ipv4_addr` around each send.

---

## 3. DHCPv4 Client

### 3.1 State Machine

| State | Entered | Sends | Timer | Next |
|---|---|---|---|---|
| INIT | `dhcpv4_client_init()`, `dhcpv4_client_release()` | — | none | `dhcpv4_client_start()` → SELECTING |
| SELECTING | start, NAK, lease expiry, REQUESTING's give-up (`start_selecting()`: new xid) | DISCOVER, broadcast | back-off (below) | first OFFER → REQUESTING |
| REQUESTING | OFFER | REQUEST, broadcast | back-off (below) | ACK → BOUND (`DHCPV4_EVT_BOUND`); NAK → SELECTING (`DHCPV4_EVT_NAK`); four retransmissions unanswered → SELECTING (`DHCPV4_EVT_TIMEOUT`) |
| BOUND | ACK | — | lease clock | T1 → RENEWING |
| RENEWING | T1 | REQUEST to the server's IP; again after half the time left until T2, at least 60 s later | lease clock | ACK → BOUND (`DHCPV4_EVT_RENEWED`); NAK → SELECTING; T2 → REBINDING |
| REBINDING | T2 | REQUEST, broadcast; again after half the time left until the lease ends, at least 60 s later | lease clock | ACK → BOUND (`DHCPV4_EVT_RENEWED`); NAK → SELECTING; lease end → `DHCPV4_EVT_EXPIRED`, SELECTING |

A NAK or an expired lease clears `net->ipv4_addr`, `subnet_mask` and
`gateway_ipv4` and restarts discovery with a new transaction ID
(`lose_address()`).

**Retransmission** in SELECTING and REQUESTING (`begin_exchange()`,
`transmit()`): the first wait is 4 s, then 8, 16, 32 and 64 s, then every
64 s, each randomized by a uniform ±1 s (`retransmit_wait_ms()`, in
milliseconds from `net_random_below()`), with the same transaction ID
(RFC 2131 §4.1).  SELECTING retransmits until an offer arrives.
REQUESTING gives up after four retransmissions — RFC 2131 §3.1's example,
60 s: when the 64 s wait after the fourth runs out with no ACK or NAK,
discovery starts again with a new transaction ID (`retransmit()`,
RFC 2131 §4.4.1), and `DHCPV4_EVT_TIMEOUT` tells the application, as
RFC 2131 §3.1 says the client SHOULD ("notify the user that the
initialization process has failed and is restarting").

**Renewing and rebinding** (RFC 2131 §4.4.5) run on the lease clock
(§6): `since_s`, the seconds since the lease was requested.  `lease_phase()` names the
state the lease's age calls for — BOUND before T1, RENEWING before T2,
REBINDING after — and `lease_tick()` enters it, sending its first
REQUEST, or else sends the next REQUEST once `since_s` reaches
`next_request_s`.  `request_extension()` sends each REQUEST and sets the
next one half the time left until the state's deadline — T2 in RENEWING,
the end of the lease in REBINDING — but at least 60 s later; when the
deadline comes first, it brings its own REQUEST (REBINDING's first) or
none (expiry).  When `since_s` reaches `lease_time` the lease has
expired.

**T1 and T2 are fuzzed** (`fuzz_renewal_times()`): RFC 2131 §4.4.5 wants
them "chosen with some random 'fuzz' around a fixed value, to avoid
synchronization of client reacquisition" — devices that got their leases
together, after a power cut, would otherwise renew together.  Whether the
server sent them or they are the defaults, both come forward by the same
random share of themselves, less than 1/16 (up to 112 s of a 1800 s T1):
never later than the server said, and still in their order.  The share is
`net_random()`'s low 12 bits in 65536ths, applied without a 64-bit
product or a divide (`share_of()`).  An infinite lease has neither time.

A 3600 s lease with the default T1 and T2 (1800 s, 3150 s), as they are
before the fuzz:

| Seconds into the lease | State | Sends | Time left | Next REQUEST |
|---|---|---|---|---|
| 1800 | RENEWING | REQUEST to the server | 1350 s to T2 | 2475 (+675) |
| 2475 | RENEWING | REQUEST to the server | 675 s | 2812 (+337) |
| 2812 | RENEWING | REQUEST to the server | 338 s | 2981 (+169) |
| 2981 | RENEWING | REQUEST to the server | 169 s | 3065 (+84) |
| 3065 | RENEWING | REQUEST to the server | 85 s | 3125 (+60, not 42) |
| 3125 | RENEWING | REQUEST to the server | 25 s | T2 (+60 would pass it) |
| 3150 | REBINDING | REQUEST, broadcast | 450 s to the end | 3375 (+225) |
| 3375 | REBINDING | REQUEST, broadcast | 225 s | 3487 (+112) |
| 3487 | REBINDING | REQUEST, broadcast | 113 s | 3547 (+60, not 56) |
| 3547 | REBINDING | REQUEST, broadcast | 53 s | none (+60 would pass the end) |
| 3600 | SELECTING | DISCOVER, broadcast (`DHCPV4_EVT_EXPIRED`) | — | back-off |

**Infinite leases.**  A lease time of 0xFFFFFFFF is infinite (RFC 2131
§3.3) — `dhcpv4_server` sends it when its `lease_time_s` is 0.  Such a
lease is never renewed and never expires: the lease clock does not run,
whatever T1 and T2 say (`lease_is_endless()`).

### 3.2 Client State Structure

```c
typedef struct {
  uint8_t state;           /* DHCPV4_CLI_* */
  uint8_t retries;         /* retransmissions of the DISCOVER or REQUEST */
  uint16_t sec_ms;         /* ms toward the next second of since_s */
  uint32_t xid;            /* transaction ID, from net_random() */
  uint32_t offered_ip;     /* yiaddr of the OFFER */
  uint32_t server_ip;      /* Server Identifier (54) */
  uint8_t server_mac[6];   /* source MAC of the ACK: the server, or the
                              relay agent on the way to it */
  uint32_t lease_time;     /* seconds; 0xFFFFFFFF = infinite */
  uint32_t t1;             /* option 58, or 0.5 × lease (seconds) */
  uint32_t t2;             /* option 59, or 0.875 × lease (seconds) */
  uint32_t since_s;        /* the lease clock: seconds since the lease was
                              requested (from the first REQUEST) */
  uint32_t request_s;      /* since_s at the state's first REQUEST: a lease
                              its ACK grants starts then */
  uint32_t next_request_s; /* since_s of the next REQUEST: T1, then the
                              RENEWING and REBINDING retransmissions */
  uint32_t timer_ms;       /* SELECTING, REQUESTING: until the next
                              retransmission */

  const dhcpv4_opt_table_t *opt_table;
  dhcpv4_client_event_fn_t on_event;
  void *evt_ctx;
} dhcpv4_client_t;
```

The application owns the struct (static, or wherever it fits);
`dhcpv4_client_init()` zeroes it.

### 3.3 Client API

```c
net_err_t dhcpv4_client_init(dhcpv4_client_t *c, const net_t *net,
                             dhcpv4_client_event_fn_t on_event, void *evt_ctx,
                             const dhcpv4_opt_table_t *opts); /* opts may be NULL */
void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c);   /* DISCOVER now */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms);
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len); /* from the port-68 handler */
void dhcpv4_client_release(net_t *net, dhcpv4_client_t *c);
uint8_t dhcpv4_client_state(const dhcpv4_client_t *c);
```

The event callback type is per role — `dhcpv4_client_event_fn_t` here,
`dhcpv4_server_event_fn_t` in the server — where one shared
`dhcpv4_event_fn_t` used to need an include-guard trick to be defined by
whichever header came first.

### 3.4 Messages Sent

| Message | Function | Flags | `ciaddr` | Options | IP source → destination | MAC destination |
|---|---|---|---|---|---|---|
| DISCOVER | `send_discover()` | broadcast | 0 | 53, 55 | 0.0.0.0 → 255.255.255.255 | broadcast |
| REQUEST (REQUESTING) | `send_request()` | broadcast | 0 | 53, 54, 50, 55 | 0.0.0.0 → 255.255.255.255 | broadcast |
| REQUEST (RENEWING) | `send_request()` | broadcast | our address | 53, 55 | our address → server | the server's (`server_mac`) |
| REQUEST (REBINDING) | `send_request()` | broadcast | our address | 53, 55 | our address → 255.255.255.255 | broadcast |
| RELEASE | `dhcpv4_client_release()` | — | our address | 53, 54 | our address → server | the server's (`server_mac`) |

Only a REQUEST that selects an offer names the server (54) and the
address (50); one that extends a lease MUST NOT carry either (RFC 2131
§4.3.2, Table 5) — the address is in `ciaddr`, and any server may answer a
rebinding client.  The Server Identifier used to go in all three.

The broadcast flag asks the server to broadcast its replies: before a
lease the stack accepts only broadcast (and 0.0.0.0) IPv4 destinations,
so a unicast OFFER or ACK to the new address would be dropped.

A message to the server goes to `server_mac`, the source MAC of its last
ACK (`dhcpv4_client_input()` takes the frame's source MAC for this).  That
is the server's own MAC when it is on the link, or the relay agent's when
the ACK came through one — the router a unicast to the server takes
anyway.  The client used to send these to the broadcast MAC, since it
never learned the server's: every host on the link received them, and a
router does not forward a frame sent to the broadcast MAC, so behind a
relay only rebinding could reach the server.

### 3.5 Receiving

`dhcpv4_client_input()` accepts a message of at least 244 bytes with
`op` = BOOTREPLY, the magic cookie and our current `xid`; the source
address is not checked.  By message type (`dhcp_message_type()`):

- **OFFER**, in SELECTING only: the first one is taken — `yiaddr` becomes
  `offered_ip`, option 54 `server_ip` — and the client enters
  REQUESTING.
- **ACK**, in REQUESTING, RENEWING or REBINDING, if it grants a lease
  (`grants_a_lease()`): RFC 2131 Table 3 requires the lease time (51) in
  an ACK to a REQUEST, and one without it — or with a lease of 0 s — is
  dropped, and the client keeps retransmitting.  Such an ACK used to be
  taken, and a lease time of 0 counted as infinite, so the client stayed
  bound for good.  Then `take_lease()` applies
  the lease and restarts the lease clock, the frame's source MAC becomes
  `server_mac`, the client enters BOUND, and the event fires (BOUND after
  REQUESTING, RENEWED otherwise).
- **NAK**, in the same states, from the server asked
  (`nak_from_server_asked()`): its Server Identifier must be the server's
  the client selected (REQUESTING) or holds its lease from (RENEWING); a
  rebinding client asked every server, so any may refuse it.  A NAK
  without a Server Identifier — which RFC 2131 Table 3 requires — is
  dropped.  Then `DHCPV4_EVT_NAK`, address cleared, discovery restarts.
  Any NAK with our `xid` used to be taken, so another server's refusal
  of a request it was not asked cost the client its lease.

**`take_lease()`** walks the ACK's options once: `yiaddr` →
`net->ipv4_addr`; 1 → `net->subnet_mask`; 3 → `net->gateway_ipv4` (the
first router); 51, 58, 59, 54 → the client's lease time, T1, T2 and
server; each of these only when present with at least 4 bytes.  Every
option, built-in or not, is then offered to the option handlers
(`run_option_handlers()`).  T1 and T2 default to 0.5 and 0.875 of the
lease (RFC 2131 §4.4.5).  The first REQUEST is due at T1.

**The lease starts with the REQUEST** (RFC 2131 §4.4.1, §4.4.5: "the time
at which the original request was sent").  The lease clock runs from the
first REQUEST for an offer, through REQUESTING; `request_s` marks where
the current state's first REQUEST went — 0 in REQUESTING, T1 or T2 when
renewing or rebinding — and `take_lease()` sets the clock to the time
since then.  A REQUEST's retransmissions are the same request, so an ACK
to one of them is timed from the first: a renewal answered after a lost
REQUEST comes back sooner, never later than the server's lease allows.
The lease used to be timed from the ACK, and so ended a round trip after
the server's did — or a whole retransmission interval after it.

### 3.6 Option Handlers and the Parameter Request List

```c
typedef void (*dhcpv4_opt_handler_t)(uint8_t option, const uint8_t *data,
                                     uint8_t len, void *ctx);
typedef struct { uint8_t option; dhcpv4_opt_handler_t handler; void *ctx; } dhcpv4_opt_entry_t;
typedef struct { const dhcpv4_opt_entry_t *entries; uint8_t count; } dhcpv4_opt_table_t;
```

- A handler is called for each option of an ACK — every ACK, renewals
  included — whose code has an entry (the first matching entry only).
  Offers are not passed to handlers.
- `data` is the raw value (no code or length byte) and points into
  `net->rx.buf`: valid during the call only.
- An option the server leaves out never reaches its handler, so the
  application initialises its variables to a sensible default before
  starting DHCP.
- Handlers run inside `dhcpv4_client_input()`, before the BOUND or
  RENEWED event.

**Parameter Request List (option 55).**  DISCOVER and REQUEST carry the
built-in codes — subnet mask (1), router (3), lease time (51) — followed
by the `option` of every table entry, up to 35 codes in all
(`put_param_request_list()`).  The application says what it wants purely
by registering handlers.

#### Example — TFTP server IP + NTP server list

```c
static uint32_t g_tftp_server = 0;          /* defaults: none */
static uint32_t g_ntp_servers[2] = {0, 0};
static uint8_t  g_ntp_count = 0;

static void on_tftp(uint8_t opt, const uint8_t *d, uint8_t len, void *ctx) {
  /* Option 150 value: one 4-byte IP address */
  if (len >= 4)
    g_tftp_server = net_read32be(d);   /* big-endian → host order */
}

static void on_ntp(uint8_t opt, const uint8_t *d, uint8_t len, void *ctx) {
  /* Option 42 value: list of 4-byte IP addresses */
  g_ntp_count = 0;
  for (uint8_t i = 0; i + 4 <= len && g_ntp_count < 2; i += 4)
    g_ntp_servers[g_ntp_count++] = net_read32be(d + i);
}

static const dhcpv4_opt_entry_t app_opts[] = {
  { 150, on_tftp, NULL },   /* TFTP server IP  (RFC 5859) */
  {  42, on_ntp,  NULL },   /* NTP server list            */
};
static const dhcpv4_opt_table_t opt_table = { app_opts, 2 };

dhcpv4_client_init(&dhcp, &net, on_dhcp_event, NULL, &opt_table);
```

After `DHCPV4_EVT_BOUND`, `g_tftp_server` is non-zero only if the server
included option 150.

### 3.7 Events

| Event | When | `net_t` at the time of the callback |
|---|---|---|
| `DHCPV4_EVT_BOUND` | ACK in REQUESTING | Address, mask and gateway set (mask and gateway keep their previous values if the ACK lacks options 1 and 3); handlers already called |
| `DHCPV4_EVT_RENEWED` | ACK in RENEWING or REBINDING | As BOUND, with the new lease |
| `DHCPV4_EVT_EXPIRED` | The lease clock reaches `lease_time` | Still the old address — it is cleared right after the callback, and a DISCOVER follows |
| `DHCPV4_EVT_NAK` | NAK in REQUESTING, RENEWING or REBINDING | As EXPIRED |
| `DHCPV4_EVT_TIMEOUT` | REQUESTING's fourth retransmission unanswered | No address yet; a DISCOVER follows |

On EXPIRED and NAK the application tears down its TCP connections: the
address they use is gone.  Release fires no event.

### 3.8 Transaction ID

A new `xid` comes from `net_random()` each time discovery starts
(`start_selecting()`); REQUESTING, the renewals and RELEASE reuse it.  The
old client used its own LCG with a fixed seed, so every device picked the
same first `xid`.  `net_random()` is seeded from the MAC by `net_init()`;
an application with a real entropy source mixes it in with
`net_random_seed()`.

---

## 4. DHCPv4 Server

### 4.1 Design Rationale

The server is **stateless and single-client**.  It always offers the same
pre-configured IP regardless of which MAC sent the DISCOVER.  This is the
correct model for a USB/CDC-ECM device where exactly one peer will ever
connect.  There is no lease table, no lease expiry, no timers and no ARP
conflict detection.

### 4.2 Configuration and State

```c
typedef struct {
  uint32_t server_ip;    /* our IP (= the DHCP server's address)        */
  uint32_t offered_ip;   /* IP to offer and assign to the client        */
  uint32_t subnet_mask;  /* option 1                                    */
  uint32_t gateway;      /* option 3  — 0 = not included                */
  uint32_t dns;          /* option 6  — 0 = not included                */
  uint32_t lease_time_s; /* option 51 — 0 = infinite (0xFFFFFFFF sent)  */
} dhcpv4_server_cfg_t;

typedef struct {
  const dhcpv4_server_cfg_t *cfg;    /* application-owned, const in flash */
  dhcpv4_server_event_fn_t on_event; /* may be NULL */
  void *evt_ctx;
} dhcpv4_server_t;

net_err_t dhcpv4_server_init(dhcpv4_server_t *s, const net_t *net,
                             const dhcpv4_server_cfg_t *cfg,
                             dhcpv4_server_event_fn_t on_event, void *evt_ctx);
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len);  /* from the port-67 handler */
```

`dhcpv4_server_input()` is pure stimulus/response: one message in, at
most one reply out, then the event (`DHCPV4_SRV_EVT_OFFER`, `_ACK` or
`_NAK`).

### 4.3 Message Handling

A message is considered if it has at least 244 bytes, `op` = BOOTREQUEST
and the magic cookie.

| Incoming | Condition | Response | Sent to |
|---|---|---|---|
| DISCOVER | always | OFFER | broadcast |
| REQUEST | requested address (option 50, else `ciaddr`) = `offered_ip` | ACK | client (below) |
| REQUEST | otherwise | NAK | broadcast |
| INFORM | always | ACK without a lease | client (below) |
| RELEASE, anything else | — | none (no lease table) | — |

"Broadcast" is 255.255.255.255 at the broadcast MAC.  "Client" is the
same, unless the request had `ciaddr` set and the broadcast flag clear:
then the reply is unicast to `ciaddr` at the request's source MAC
(RFC 2131 §4.1).  The Server Identifier in a REQUEST is not checked —
with one peer there is no other server to have chosen.

Every reply (`send_reply()`) echoes `xid` and `chaddr`, sets the
broadcast flag and carries the message type (53) and the Server
Identifier (54, `server_ip`).  The rest follows RFC 2131 Table 3 and
§4.3.5:

| | OFFER | ACK to a REQUEST | ACK to an INFORM | NAK |
|---|---|---|---|---|
| `ciaddr` | 0 | the request's | the request's | 0 |
| `yiaddr` | `offered_ip` | `offered_ip` | 0 | 0 |
| `siaddr` | `server_ip` | `server_ip` | `server_ip` | 0 |
| Lease time (51): `lease_time_s`, or 0xFFFFFFFF (infinite) for 0 | ✓ | ✓ | — | — |
| Subnet mask (1); router (3), DNS (6) when configured | ✓ | ✓ | ✓ | — |

A NAK carries no lease and no configuration: it only refuses.  The ACK
to an INFORM configures a client that already has its address, so it
assigns none and carries no lease time (`put_parameters()` adds the
lease only with an address).  A reply is sent from `server_ip` via
`udp_send_inplace_from()`, whatever `net->ipv4_addr` is.

---

## 5. Buffer Requirements

- **TX:** both roles build messages in place and need
  `UDP_PAYLOAD_OFFSET` + 300 = **342 bytes** (`DHCPV4_CLIENT_TX_MIN`,
  `DHCPV4_SERVER_TX_MIN`).
- **RX:** the whole incoming frame must fit in `net->rx.buf`;
  `net_poll()` truncates a longer frame and IPv4 then drops it.  DHCP
  messages are at least 300 bytes (a 342-byte frame), and RFC 2131 §2
  requires a client to be prepared for a 576-byte IP datagram (a 590-byte
  frame) from a server — the most a server may send a client that did
  not announce a larger Maximum DHCP Message Size, which this client never
  does.  The client needs **590 bytes** (`DHCPV4_CLIENT_RX_MIN`); the
  server **342** (`DHCPV4_SERVER_RX_MIN`), and drops a longer request.

`dhcpv4_client_init()` and `dhcpv4_server_init()` take the `net_t` and
return `NET_ERR_BUF_TOO_SMALL` for smaller buffers (REQ-DHCPv4-050, 051,
078).  They used to return nothing and check nothing: a TX buffer too
small left every message unsent, silently, and an RX buffer under 590
bytes dropped the longer replies a server may send.

---

## 6. Timers

The client needs `dhcpv4_client_tick(net, c, elapsed_ms)` from the same
main loop that calls `net_tick()`; the server has no timers.  The client
has two clocks, each used in its own states:

| Clock | Fields | States | Counts | Compared with |
|---|---|---|---|---|
| Retransmission | `timer_ms` | SELECTING, REQUESTING | Milliseconds down to 0 (`net_countdown()`); at 0 the DISCOVER or REQUEST is sent again | — |
| Lease | `since_s`, `sec_ms` | REQUESTING, BOUND, RENEWING, REBINDING, unless the lease is infinite | Whole seconds up from the first REQUEST for the lease, the remainder carried in `sec_ms` (`net_whole_seconds()`) | `t1`, `t2`, `next_request_s`, `lease_time` |

The lease clock counts seconds because leases are long.  32-bit
milliseconds wrap after 49.7 days (4,294,967 s), and a lease time may be
up to 136 years; when the client armed its T1 as `t1 × 1000` ms, a longer
T1 wrapped and the renewal came early — an infinite lease's after 49.7
days.  In seconds every lease time, T1, T2 and wait fits in 32 bits, and
the halving is a shift: no multiplication and no division.

---

## 7. Deviations and Not Implemented

| Item | Notes |
|---|---|
| First OFFER taken; offers not collected or compared | Simplicity |
| No ARP probe of the offered address, no DECLINE | Size |
| Option Overload (52), `sname`/`file` options | Not parsed |
| `secs` field always 0 | — |
| Server: replies always set the broadcast flag and leave `giaddr` 0, where RFC 2131 Table 3 copies the client's `flags` and `giaddr` | No relay agent on a point-to-point link; the flag only allows a broadcast reply |
| Server: no lease table, same address for every MAC | By design (§4.1) |

---

## 8. Zero-Allocation Guarantee

Neither `dhcpv4_client.c` nor `dhcpv4_server.c` calls `malloc`, `calloc`,
or `realloc`, and neither keeps a message on the stack: all state is in
application-owned structs, messages are built in `net->tx.buf` and read in
place from `net->rx.buf`.

---

## 9. Tests

| Suite | Tests | Covers |
|---|---|---|
| `tests/unit/test_dhcpv4.c` | 26 | Client: init, DISCOVER format and destination, OFFER → REQUEST, ACK → BOUND, default T1/T2, NAK, option handlers, NULL table, DISCOVER retransmission, back-off and its randomization, REQUESTING giving up, RENEWING and REBINDING through a whole lease, a renewal restarting the lease, infinite and 30,000,000 s leases.  Server: OFFER, ACK, NAK, RELEASE, bad `op`, bad magic, the NAK's bare fields and options, the ACK to an INFORM, `ciaddr` in a renewal's ACK |
| `tests/blackbox/test_dhcpv4_conform.py` | 8 | `dhcp_echo_demo` against a Scapy server: DISCOVER, OFFER → REQUEST, ACK binds, NAK → DISCOVER, wrong-xid OFFER ignored, `ciaddr` 0, retransmission, Server ID in REQUEST |
