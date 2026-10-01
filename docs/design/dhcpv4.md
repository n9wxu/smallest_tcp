# DHCPv4 Design

**Protocol:** Dynamic Host Configuration Protocol v4 (RFC 2131, options RFC 2132)  
**Files:** `include/dhcpv4_client.h`, `src/dhcpv4_client.c`,
           `include/dhcpv4_server.h`, `src/dhcpv4_server.c`,
           `src/dhcpv4_wire.h` (private, shared)  
**Requirements:** [dhcpv4.md](../requirements/dhcpv4.md)  
**Last updated:** 2026-10-01

---

## 1. Overview and Split Design

DHCPv4 is two independent libraries — a client and a minimal
single-client server.  An application links only what it needs:

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
| `dhcp_next_option(msg, end, &pos, &data, &olen)` | The next option of one field (start with `pos` at the field, `end` its end), with its value and length; `DHCP_OPT_END` at End, at `end`, or on an option whose length runs past it |
| `dhcp_walk_begin(&w, msg, len)`, `dhcp_walk_next(&w, &data, &olen)` | Every option of the message, field after field (below) |
| `dhcp_option(msg, len, code, &value, buf, cap)` | Option `code` whole — its parts joined — and its length; `value` NULL if absent |
| `dhcp_message_type(msg, len)` | Option 53, or 0 if absent |
| `dhcp_option_u32(msg, len, code, absent)` | A 4-byte option in host order (the first 4 bytes of a list), or `absent` |

Pad options are skipped; a truncated option ends its field instead of
being read out of bounds.

**Option Overload** (RFC 2131 §4.1, RFC 2132 §9.3).  A server short of
room in the options field may carry options in the `file` (128 bytes)
and `sname` (64 bytes) fields, and says so with option 52: 1 `file`, 2
`sname`, 3 both.  `dhcp_walk_begin()` reads option 52 from the options
field — where it must be — and `dhcp_walk_next()` walks the options
field, then `file`, then `sname`, each up to its own End or its end (an
option never crosses a field).  That is RFC 2131 §4.1's order of
interpretation and RFC 3396 §5's aggregate option buffer.  Without option
52 the two fields are a server name and a boot file name, never read as
options.  They used to be ignored always, so a lease time moved there was
lost and the ACK dropped as granting no lease.

**Split options** (RFC 3396 §7).  An option may appear more than once:
its parts, in the aggregate buffer's order, are one value — a server
splits an option longer than 255 bytes, and may split any other at any
byte.  `dhcp_option()` joins them: one part is returned in place (no
copy), several are copied into the caller's buffer, of which the caller
says the size; the returned length is the whole value's, so a caller sees
when its buffer held only the start.  The 4-byte helpers use a 4-byte
buffer: a lease time split 2 + 2 is read whole, a router list split
anywhere gives its first router.  Each instance used to be taken as a
whole option: the first part of a split lease time was too short and
dropped, the second taken alone.

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
| INIT | `dhcpv4_client_init()`, `dhcpv4_client_release()`, `dhcpv4_client_start()`, a DECLINE | — | after start, the start-up wait; after a DECLINE, 10 s | its end → SELECTING |
| SELECTING | start, NAK, lease expiry, REQUESTING's give-up (`start_selecting()`: new xid) | DISCOVER, broadcast | back-off (below) | first OFFER that names its server → REQUESTING |
| REQUESTING | OFFER | REQUEST, broadcast | back-off (below) | ACK → CHECKING; NAK → SELECTING (`DHCPV4_EVT_NAK`); four retransmissions unanswered → SELECTING (`DHCPV4_EVT_TIMEOUT`) |
| CHECKING | ACK in REQUESTING | an ARP Probe of the address | `DHCPV4_PROBE_WAIT_MS` (1 s); lease clock | quiet → BOUND (`DHCPV4_EVT_BOUND`); address in use → DECLINE, INIT (`DHCPV4_EVT_DECLINED`) |
| BOUND | the probe passed, ACK in RENEWING or REBINDING | — | lease clock | T1 → RENEWING |
| RENEWING | T1 | REQUEST to the server's IP; again after half the time left until T2, at least 60 s later | lease clock | ACK → BOUND (`DHCPV4_EVT_RENEWED`); NAK → SELECTING; T2 → REBINDING |
| REBINDING | T2 | REQUEST, broadcast; again after half the time left until the lease ends, at least 60 s later | lease clock | ACK → BOUND (`DHCPV4_EVT_RENEWED`); NAK → SELECTING; lease end → `DHCPV4_EVT_EXPIRED`, SELECTING |

A NAK or an expired lease clears `net->ipv4_addr`, `subnet_mask` and
`gateway_ipv4` and restarts discovery with a new transaction ID
(`lose_address()`).

**Checking the address** (RFC 2131 §3.1 step 5, §4.4.1; RFC 5227
§2.1.1).  The ACK of a new lease is not used at once: another host may
already have its address — a static one, or a lease the server lost
track of.  The client applies the mask, router and lease, keeps the
address in `offered_ip`, and enters CHECKING (`start_probe()`): it sends
an ARP Probe — an ARP request for the address with our MAC as sender
and 0.0.0.0 as sender address (RFC 2131 §4.4.1: "to avoid confusing ARP
caches"), target MAC zero — and sets `net->arp_probe_ip`, which
`arp_input()` watches ([arp-resolution.md §4](arp-resolution.md#4-what-arp_input-does)):
an ARP packet from the address, or another host's probe for it, sets
`net->arp_probe_conflict`.  `probe_tick()` gives the verdict:

- **In use**: the client MUST send a DHCPDECLINE (`decline()`).  It goes
  broadcast from 0.0.0.0 with the Requested IP Address (50) and the
  Server Identifier (54) and no other option (RFC 2131 Table 5: the
  others MUST NOT; flags, `ciaddr` 0; §4.4.4: broadcast).  The address is
  never configured, the mask and router are cleared, `DHCPV4_EVT_DECLINED`
  fires, and discovery restarts after 10 s in INIT — §3.1's "SHOULD wait
  a minimum of ten seconds ... to avoid excessive network traffic in
  case of looping", against a server that offers the same address again.
- **Quiet for `DHCPV4_PROBE_WAIT_MS`** (default 1000): the address
  becomes `net->ipv4_addr` (`bind_address()`), BOUND, `DHCPV4_EVT_BOUND`.

One probe and one second, not RFC 5227 §2.1.1's three probes 1–2 s apart
and a 2 s wait after the last (about 7 s): a device that boots over DHCP
should not take that long, and a host that holds the address answers its
first probe within a round trip.  The full timing is not required: RFC
2131 says only that the client SHOULD check.  `DHCPV4_PROBE_WAIT_MS`
lengthens the wait.  The probe goes through `arp_request()`, whose
sender address is `net->ipv4_addr` — 0 here, since
`dhcpv4_client_start()` clears the address and the client has no lease
in REQUESTING.  Neither the announcement after the probe (§4.4.1:
"SHOULD broadcast an ARP reply") nor defence of the address later is
done.  A renewal's ACK is not probed: the address is already in use by
us.  `dhcpv4_client_release()` in CHECKING stops the probe and sends no
RELEASE — the address was never used, and the client has none to send
from.  The client used to use the address of every ACK at once.

**The start-up wait.**  `dhcpv4_client_start()` does not send the first
DISCOVER at once: it waits in INIT a random time of one to ten seconds
(`timer_ms`, counted down by `dhcpv4_client_tick()`), as RFC 2131 §4.4.1
says the client SHOULD, "to desynchronize the use of DHCP at startup" —
devices powered up together would otherwise all ask at once.
`DHCPV4_START_DELAY_MAX_MS` (`dhcpv4_client.h`, default 10000) sets the
upper end; 0 sends the DISCOVER at once, as the client used to.  Discovery
restarted later — after a NAK, an unanswered REQUEST or a lost lease —
does not wait.

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
  uint32_t offered_ip;     /* yiaddr of the OFFER, then of the ACK */
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
  uint32_t timer_ms;       /* INIT: until the first DISCOVER;
                              SELECTING, REQUESTING: until the next
                              retransmission; CHECKING: the probe's end */

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
void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c);   /* clears the address; DISCOVER in 1-10 s */
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
| DECLINE | `decline()` | — | 0 | 53, 50, 54 | 0.0.0.0 → 255.255.255.255 | broadcast |

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

- **OFFER**, in SELECTING only: the first one that names its server is
  taken (`take_offer()`) — `yiaddr` becomes `offered_ip`, option 54
  `server_ip` — and the client enters REQUESTING.  An OFFER without a
  Server Identifier, which RFC 2131 Table 3 requires, is dropped: the
  REQUEST that selects an offer MUST name its server (§3.1 step 3).  Such
  an OFFER used to be taken, and its REQUEST named 0.0.0.0 — or the
  server of an earlier exchange.
- **ACK**, in REQUESTING, RENEWING or REBINDING, if it grants a lease
  (`grants_a_lease()`): RFC 2131 Table 3 requires the lease time (51) in
  an ACK to a REQUEST, and one without it — or with a lease of 0 s — is
  dropped, and the client keeps retransmitting.  Such an ACK used to be
  taken, and a lease time of 0 counted as infinite, so the client stayed
  bound for good.  Then `take_lease()` applies
  the lease and restarts the lease clock, and the frame's source MAC
  becomes `server_mac`.  After REQUESTING the address is checked first
  (CHECKING, §3.1); after RENEWING or REBINDING the client enters BOUND
  and `DHCPV4_EVT_RENEWED` fires.
- **NAK**, in the same states, from the server asked
  (`nak_from_server_asked()`): its Server Identifier must be the server's
  the client selected (REQUESTING) or holds its lease from (RENEWING); a
  rebinding client asked every server, so any may refuse it.  A NAK
  without a Server Identifier — which RFC 2131 Table 3 requires — is
  dropped.  Then `DHCPV4_EVT_NAK`, address cleared, discovery restarts.
  Any NAK with our `xid` used to be taken, so another server's refusal
  of a request it was not asked cost the client its lease.

**`take_lease()`** reads the ACK's options whole (`dhcp_option_u32()`,
§2.1: from `file` and `sname` too, split ones joined): `yiaddr` →
`net->ipv4_addr`; 1 → `net->subnet_mask`; 3 → `net->gateway_ipv4` (the
first router; a different gateway also clears `gateway_mac_valid`: its
MAC is resolved anew,
[arp-resolution.md §3](arp-resolution.md#3-resolving-a-mac-for-an-active-open));
51, 58, 59, 54 → the client's lease time, T1, T2 and server; the mask,
router and server only when present with at least 4 bytes, else they
keep their values.  Then the option handlers run
(`run_option_handlers()`).  T1 and T2 default to 0.5 and 0.875 of the
lease (RFC 2131 §4.4.5).  The first REQUEST is due at T1.

**T1 < T2 < the end of the lease** (RFC 2131 §4.4.5: "T1 MUST be
earlier than T2, which, in turn, MUST be earlier than the time at which
the client's lease will expire").  `set_renewal_times()` takes the ACK's
T1 and T2, or the default for one it lacks, and if the two are not in
that order replaces both with the defaults, which always are.  Both, not
just the one out of place: a server's T2 below half the lease and a T1
past it would otherwise give a default T1 still later than T2.  The
times used to be taken as sent: a T1 after T2 skipped renewing and went
straight to rebinding, and a T2 past the end of the lease never
rebound.

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

- Each entry's handler is called once for every ACK — renewals included
  — that carries its option, in the order of the table.  Offers are not
  passed to handlers.
- `data` is the option's value (no code or length byte), whole: the
  parts of a split option joined (RFC 3396 §7), from `file` and `sname`
  too when option 52 says they hold options.  An option in one part
  points into `net->rx.buf`; a split one is joined in a buffer of
  `DHCPV4_SPLIT_OPTION_MAX` bytes (`dhcpv4_client.h`, default 255) on the
  stack of `dhcpv4_client_input()`.  Valid during the call only.  A split
  option longer than that buffer — or than 255 bytes, which `len` cannot
  say — is not delivered at all: given in pieces, each would be taken for
  the whole (RFC 3396 §7 forbids it).  The receive buffer is read-only
  to parsers ([coding-rules.md §3](coding-rules.md#3-parsing-received-data)),
  so the parts are not joined in place.  Handlers used to be called once
  per instance, each with one part.
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
| `DHCPV4_EVT_BOUND` | The ARP probe of the ACK's address passed (1 s after the ACK in REQUESTING) | Address, mask and gateway set (mask and gateway keep their previous values if the ACK lacks options 1 and 3); handlers called at the ACK |
| `DHCPV4_EVT_DECLINED` | The ARP probe found the address in use; DECLINE sent | No address, mask or gateway; a DISCOVER follows in 10 s |
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

The server is **single-client**: one pre-configured address for one
peer.  This is the model for a USB/CDC-ECM device where one peer at a
time connects.  There is no lease table, no lease expiry, no timers and
no ARP conflict detection of its own.

**Its one client.**  RFC 2131 §4.2: without a Client Identifier "the
server MUST use the contents of the 'chaddr' field to identify the
client".  The server keeps one record — the chaddr of the client it
offered the address to (`client_mac`, `has_client`) — so that a second
peer is not given an address the first holds.  The first DISCOVER fixes
it; the address is free again when that client releases it (§4.3.4), or
selects another server (§3.1 step 4: its REQUEST declines our offer), or
when the application calls `dhcpv4_server_init()` again — for a new peer
on the link, say.  A lease that runs out is not noticed: there is no
timer, and the one peer normally renews.  A Client Identifier (option
61) is not used to identify the client (out of scope): one that sends
it is still known by its chaddr.  The server used to keep no record and
offer the address to every client that asked.

### 4.2 Configuration and State

```c
typedef struct {
  uint32_t server_ip;    /* our IP: net->ipv4_addr (the server's)       */
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
  uint8_t client_mac[6];             /* the client's chaddr ... */
  uint8_t has_client;                /* ... if 1 */
  uint8_t declined;                  /* 1: the address is in use */
} dhcpv4_server_t;

net_err_t dhcpv4_server_init(dhcpv4_server_t *s, const net_t *net,
                             const dhcpv4_server_cfg_t *cfg,
                             dhcpv4_server_event_fn_t on_event, void *evt_ctx);
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len);  /* from the port-67 handler */
```

`dhcpv4_server_input()` is stimulus/response: one message in, at most
one reply out, then the event (`DHCPV4_SRV_EVT_OFFER`, `_ACK` or
`_NAK`; `_DECLINE` with no reply).

### 4.3 Message Handling

A message is considered if it has at least 244 bytes, `op` = BOOTREQUEST
and the magic cookie.

| Incoming | Condition | Response |
|---|---|---|
| DISCOVER | no client yet, or from it | OFFER; the sender becomes the client |
| DISCOVER | from another | none: nothing to offer |
| REQUEST | naming another server | none; from our client, the address is free again |
| REQUEST | not ours to answer (below) | none |
| REQUEST | requested address (option 50, else `ciaddr`) = `offered_ip`, from our client or with none yet | ACK; the sender becomes the client |
| REQUEST | otherwise | NAK |
| RELEASE | from our client, `ciaddr` = `offered_ip` | none; the address is free again |
| DECLINE | Requested IP = `offered_ip`, our Server Identifier | none; the address is not available (below), `DHCPV4_SRV_EVT_DECLINE` |
| INFORM | always | ACK without a lease |
| anything else | — | none |

**A declined address** (RFC 2131 §4.3.3).  A DECLINE says the client
found the address in use by another host (its ARP probe was answered):
"The server MUST mark the network address as not available and SHOULD
notify the local system administrator".  The server sets `declined`,
forgets its client and fires `DHCPV4_SRV_EVT_DECLINE`.  With its one
address unavailable it has nothing to offer: DISCOVERs get no reply, and
a REQUEST for the address it answers gets a NAK.  An INFORM is still
answered.  The application decides what to do — find the host that has
the address, change `offered_ip` — and calls `dhcpv4_server_init()`
again to offer it once more; the server has no timer to retry on its
own.  It used to ignore DECLINEs and offer the address again at once.

**Which REQUESTs it answers** (`ours_to_answer()`, RFC 2131 §4.3.2).  A
REQUEST with a Server Identifier selects an offer: the server answers it
if the identifier is its own; one that names another server is the
client's notice that it "has declined that server's offer" (§3.1 step
4), and is not answered — a NAK would be one server refusing what
another granted.  A REQUEST without one verifies (INIT-REBOOT, `ciaddr`
0) or extends (RENEWING, REBINDING) a lease: the server answers its own
client, and stays silent for one it has no record of — §4.3.2: "If the
DHCP server has no record of this client, then it MUST remain silent".
One exception: a renewing or rebinding client whose `ciaddr` is the
server's address while it has no client — the server was initialised
again, by a reboot of the device, while the peer kept its lease — is
taken back, and its lease extended.  The server used to ignore the
Server Identifier and answer every REQUEST, NAKing any for another
address.

**Where a reply goes** (`reply_destination()`, RFC 2131 §4.1), in order:

| The request | The reply goes to |
|---|---|
| came through a relay agent (`giaddr` set) | `giaddr` at the frame's source MAC (the relay agent), UDP port **67** |
| — and the reply is a NAK | 255.255.255.255 at the broadcast MAC |
| has `ciaddr` set | `ciaddr` at the frame's source MAC |
| has the broadcast flag | 255.255.255.255 at the broadcast MAC |
| none of these | the address it is given (`yiaddr`) at `chaddr` |

The server used to broadcast every reply but those to a client with an
address and no broadcast flag, and to leave out the relay agent.

Every reply (`send_reply()`) echoes `xid` and `chaddr`, copies the
request's `flags` and `giaddr` — a NAK through a relay also sets the
broadcast flag, so the relay broadcasts it to a client that may have no
usable address (§4.3.2) — and carries the message type (53) and the
Server Identifier (54, `server_ip`).  The rest follows RFC 2131 Table 3
and §4.3.5:

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
`udp_send_inplace_from()`.  That is the host's own address:
`dhcpv4_server_init()` refuses a `server_ip` other than `net->ipv4_addr`
(`NET_ERR_INVALID_PARAM`), as UDP sends only from the host's address
(RFC 1122 §4.1.3.6, REQ-UDP-041).  Replies used to go out from
`server_ip` whatever `net->ipv4_addr` was.

**The order of the options** (`put_parameters()`).  RFC 2132 §9.8: the
server "MUST try to insert the requested options in the order requested
by the client".  The parameters the server has — lease time (51), subnet
mask (1), router (3), DNS server (6) — go first in the order of the
request's Parameter Request List (all its parts, RFC 3396), then those
it was not asked for, in that order.  `put_parameter()` puts each once,
however often it is asked for, and leaves out one it has no value for
(no router or DNS server configured) or does not know (RFC 2131 §4.3.1).
One exception to the client's order: RFC 2132 §3.3 — "If both the subnet
mask and the router option are specified in a DHCP reply, the subnet
mask option MUST be first" — so a router asked for before the mask
brings the mask with it.  The options used to go in one fixed order,
whatever was asked.

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
| Retransmission | `timer_ms` | INIT, SELECTING, REQUESTING, CHECKING | Milliseconds down to 0 (`net_countdown()`); at 0 the first DISCOVER goes, the DISCOVER or REQUEST is sent again, or the probe ends | — |
| Lease | `since_s`, `sec_ms` | REQUESTING, CHECKING, BOUND, RENEWING, REBINDING, unless the lease is infinite | Whole seconds up from the first REQUEST for the lease, the remainder carried in `sec_ms` (`net_whole_seconds()`) | `t1`, `t2`, `next_request_s`, `lease_time` |

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
| One ARP probe and a 1 s wait, not RFC 5227's timing; no announcement or defence of the address | §3.1 |
| `secs` field always 0 | — |
| Server: one address for one client, known by chaddr; no lease expiry; a Client Identifier (61) not used | By design (§4.1) |

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
| `tests/integration/itest_dhcpv4.c` | 30 | Black box, through the API and the wire with the test's own DHCP codec.  Client: the ARP probe of an ACK's address, DECLINE on a conflict (a reply from it, another host's probe, not our own echoed), release while probing, an OFFER without a Server Identifier, options in `file` and `sname`, split options joined (also across fields; one too long for a handler not delivered), T1/T2 out of order, the REQUEST's `secs` and destination, reserved flag bits, unicast to the Server Identifier, Table 5 options of DISCOVER, REQUEST and RELEASE, randomized backoff.  Server: a declined address, a REQUEST for another server, an unknown INIT-REBOOT client, the address kept for its client, options in the requested order and each once, Table 3 options, mask before router, vendor options ignored, the Server Identifier, the ACK to an INFORM |
| `tests/unit/test_dhcpv4.c` | 38 | Client: init and its buffer checks, the 1-10 s start-up wait, DISCOVER format and destination, OFFER → REQUEST, ACK → BOUND, default T1/T2 and their fuzz, NAK and its source, an ACK without a lease time, option handlers, NULL table, DISCOVER retransmission, back-off and its randomization, REQUESTING giving up (with `DHCPV4_EVT_TIMEOUT`), RENEWING and REBINDING through a whole lease, the Server Identifier only when selecting, renewals and RELEASE to the server's MAC, the lease timed from the REQUEST, a renewal restarting the lease, infinite and 30,000,000 s leases, the gateway's MAC invalidated and resolved by ARP.  Server: init and its buffer checks, OFFER, ACK, NAK, RELEASE, bad `op`, bad magic, the NAK's bare fields and options, the ACK to an INFORM, `ciaddr` in a renewal's ACK, replies routed as RFC 2131 §4.1 says with `flags` and `giaddr` copied |
| `tests/blackbox/test_dhcpv4_conform.py` | 8 | `dhcp_echo_demo` against a Scapy server: DISCOVER, OFFER → REQUEST, ACK binds, NAK → DISCOVER, wrong-xid OFFER ignored, `ciaddr` 0, retransmission, Server ID in REQUEST |
