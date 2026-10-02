# Timer and Event Model — Design

**Files:** `include/net.h` (`net_tick()`, `net_countdown()`,
`net_countdown16()`, `net_whole_seconds()`), `src/net.c`; each module's
`*_tick()`

## 1. Entry points

The stack does nothing on its own.  The application drives it from one
thread, through two calls:

| Call | Does |
|---|---|
| `net_poll(net)` | Receives and dispatches at most one frame ([mac-hal.md §3](mac-hal.md#3-the-receive-lifecycle-net_poll)).  Returns its length, 0 if none, < 0 on a driver error. |
| `net_tick(net, elapsed_ms)` | Advances the stack's own timers by the milliseconds that have passed since the previous call. |

`net_tick()` is, depending on the configuration:

```c
void net_tick(net_t *net, uint32_t elapsed_ms) {
#if NET_USE_IPV4
  arp_tick(net, elapsed_ms);   /* the gateway MAC's age, the request rate */
  ipv4_tick(net, elapsed_ms);  /* reassembly, IGMP */
#endif
#if NET_USE_TCP
  tcp_tick(net, elapsed_ms);   /* every connection in net->tcp_conns */
#endif
#if NET_USE_IPV6
  ipv6_tick(net, elapsed_ms);  /* lifetimes, ICMPv6 rate limit, MLD, NDP */
#endif
}
```

`ipv4_tick()` reaches reassembly and IGMP through `net->reasm_ops` and
`net->igmp_ops`, which `ipv4_set_reassembly()` and `igmp_join()` install: a
program that calls neither links neither.  ICMP and UDP have no timers.

**Application-owned modules keep their own ticks.**  The DHCP clients, the
TFTP client, the mDNS responder and the HTTP server are structures the
application declares; `net_t` has no pointer to them, so `net_tick()` cannot
reach them.  The application calls each module's `*_tick()` next to
`net_tick()`, with the same `elapsed_ms`
([integrating-modules.md](../integrating-modules.md)).  A registration list in
`net_t` would remove those calls at the cost of a list, a registration API and
a common module interface; the application already knows which modules it
has.

| Tick | Driven by |
|---|---|
| `arp_tick()` | `net_tick()` |
| `ipv4_tick()` → reassembly's and IGMP's ticks | `net_tick()` |
| `tcp_tick()` | `net_tick()` |
| `ipv6_tick()` → `icmpv6_tick()`, `mld_tick()`, `ndp_tick()` | `net_tick()` |
| `dhcpv4_client_tick(net, c, ms)` | the application |
| `dhcpv6_client_tick(net, c, ms)` | the application |
| `tftp_client_tick(net, c, ms)` | the application |
| `mdns_tick(m, ms)` | the application |
| `http_server_tick(s, ms)` | the application (and `http_server_poll(s)` every loop, which is not a timer) |
| `dtls_tick(d, ms)` | the application, for each DTLS connection (it retransmits flights: send what `dtls_pending()` then returns) |

The DHCPv4 server and TLS have no timers.

`arp_tick()`, `ipv4_tick()`, `tcp_tick()` and `ipv6_tick()` are public, but
an application that calls `net_tick()` must not call them as well, or those
timers run twice as fast.

## 2. Timer representation

Every timer is a countdown field in the structure that owns it, in
milliseconds.  Usually **0 means stopped**; where a separate state already
says the timer is running — a TENTATIVE IPv6 address, Router Solicitations
still to send, an mDNS responder that is probing, a TCP connection in
TIME-WAIT — 0 means "due now".  Two helpers count down without underflow:

```c
/* 1 once it has run out (and leaves it at 0) */
static inline int net_countdown(uint32_t *ms_left, uint32_t elapsed_ms);
static inline int net_countdown16(uint16_t *ms_left, uint32_t elapsed_ms);
```

A typical tick is `if (t->timer_ms && net_countdown(&t->timer_ms, ms))
act(t);` — the action usually re-arms the timer.  The 16-bit variant keeps the
IPv6 per-address and MLD state small; it still accepts a 32-bit elapsed time.
ARP's and IGMP's 16-bit countdowns, and reassembly's (kept in the
application's buffer), do the same subtraction in place.

Lifetimes measured in seconds (IPv6 address and router lifetimes, MLDv1
compatibility, the ARP-learned gateway MAC, DHCP leases and T1/T2) are
counted in whole seconds.
`net_whole_seconds(&carry_ms, elapsed_ms)` returns the whole seconds in
`carry_ms + elapsed_ms` and keeps the remainder in the 16-bit carry, so no
fraction is lost between calls.  It subtracts 1000 in a loop instead of
dividing (Cortex-M0 has no divide instruction —
[coding-rules.md](coding-rules.md)), so its cost grows with the elapsed time:
one iteration per second.

## 3. The timers

| Owner | Field(s) | Values | On expiry |
|---|---|---|---|
| ARP | `gateway_mac_s`, `arp_carry_ms`; `arp_recent[].ms_left` | `NET_ARP_GATEWAY_TIMEOUT_MS` (5 min) from the gateway's last reply; 1 s per target requested | `gateway_mac_valid` = 0; the target may be requested again |
| IPv4 reassembly | 32 bits in the reassembly buffer | `IPV4_REASM_TIMEOUT_MS` (60 s) from a datagram's first fragment | Discard the partial datagram; ICMP Time Exceeded if fragment zero came |
| IGMP | `igmp_delay_ms[]` per group, `igmp_v1_ms` | random in (0, the query's Max Response Time]; 400 s after an IGMPv1 query | Membership Report for the group; IGMPv2 messages again |
| TCP connection | `timer_ms` (`timer` = retransmit), `rto_ms`, `retransmits` | RTO starts at `NET_DEFAULT_TCP_RTO_INIT_MS` (1 s), doubles per expiry up to `NET_DEFAULT_TCP_RTO_MAX_MS` (60 s); 3 s for data once a SYN had to be retransmitted | Resend the SYN, the data from SND.UNA, or the FIN; the third reports `TCP_EVT_SOFT_ERROR`; the expiry after the R2-th retransmission (8, or `tcp_set_max_retransmits()`) sends RST and reports `TCP_EVT_ERROR` — a passive open returns to LISTEN instead |
| TCP connection, TIME-WAIT | `timer_ms` (`timer` = TIME-WAIT) | 2 × `NET_DEFAULT_TCP_MSL_MS` (4 min) | CLOSED, `TCP_EVT_CLOSED` |
| TCP connection, zero window | `timer_ms` (`timer` = persist), `persist_ms` | from 1 s, doubling to 60 s | Send a one-byte window probe |
| IPv6 address | `dad_timer_ms` | random 0–1 s before the link-local probe; 1 s between probes | Next DAD probe, or the address becomes PREFERRED |
| IPv6 router discovery | `router_solicit_ms`, `router_solicits_left` | random 0–1 s, then 4 s; up to 3 | Next Router Solicitation |
| MLD | `query_reply_ms`, `report_repeat_ms`, `v1_querier_left_s` | random within the query's maximum response delay; 1 s; 260 s | Report; repeat a change report; leave MLDv1 mode |
| IPv6 lifetimes | `valid_s`, `preferred_s`, `router.lifetime_s` | seconds from RAs / DHCPv6 | Address deprecated or removed; router forgotten |
| DHCPv4 client | `timer_ms`, `since_s`, `next_request_s` | start-up wait 1–10 s; retransmit 4 s doubling to 64 s, ±1 s; 1 s for the ARP probe of an acknowledged address, 10 s after a DECLINE; T1, T2, lease | First DISCOVER; retransmit (the REQUEST for an offer is given up after 4); address taken or declined; RENEWING; REBINDING; lease expired (address cleared) |
| DHCPv6 client | `timer_ms`, `rt_ms`, `since_s` | RFC 8415 §15 back-off with ±10 % jitter; T1, T2, lifetimes | Retransmit; Renew; Rebind; expired |
| TFTP client | `timer_ms`, `rto_ms` | 3 s at first, then from the measured round trip (1–16 s), doubled per retransmission; 5 retries | Resend the RRQ or the last ACK; give up |
| mDNS | `timer_ms`, `pending.timer_ms`, `second_ms`, `quiet_ms` | probes 250 ms apart, announcements 1 s apart; shared-record answers delayed 20–120 ms; a record multicast at most once a second; conflicts forgotten after 10 s | Next probe or announcement; send the aggregated answers |
| DTLS connection | `timer_ms`, `rto_ms` | 1 s, doubling to 60 s; 6 retransmissions | Retransmit the flight; give up |
| HTTP slot | `timer_ms` | 10 s to receive a request, 10 s to respond | Abort the connection, re-listen |

A TCP connection runs one of its three timers at a time, in one countdown
([tcp.md §5](tcp.md#5-timers)).  `tcp_tick()` also advances `net->tcp_clock`
by 250 per millisecond, the 4 µs clock of initial sequence numbers
([tcp.md §4.6](tcp.md#46-initial-sequence-numbers)); it is a clock, not a
timer, and never fires.

TCP has no delayed-ACK timer (an ACK goes out as soon as data arrives) and no
round-trip-time estimator: the RTO is not measured (RFC 6298's smoothed RTT is
not implemented), and once doubled it stays doubled for the life of the
connection.

## 4. Semantics of `elapsed_ms`

- **Measure real time.**  Pass the milliseconds since the previous call,
  from a monotonic clock.  Any call rate works; calling with 0 is harmless.
  The demos tick every 10 ms or more.  A timer's resolution is the interval
  between ticks.
- **At most one expiry per call.**  Each countdown fires once per call, then
  re-arms from its full interval.  After a long gap (a device that slept, a
  debugger halt) missed periods collapse into one: a TCP connection whose RTO
  passed long ago retransmits once and doubles its RTO once.  Lifetimes, by
  contrast, subtract every whole second that passed.
- **Callbacks and sends happen inside ticks.**  Timers send frames (built in
  `net->tx.buf`) and fire callbacks: `on_event` of a TCP connection
  (`TCP_EVT_ERROR`, `TCP_EVT_CLOSED` when TIME-WAIT ends), DHCP events,
  TFTP completion.  The same rules apply as inside `net_poll()`: keep
  callbacks short and do not re-enter the stack from TCP's `on_event`.

## 5. Concurrency

The stack is not reentrant.  `net_poll()`, `net_tick()`, the module ticks and
every API call that sends must run in one thread, or be serialized by the
application.  Do not call them from an interrupt handler: let the MAC
interrupt set a flag, and poll from the main loop or a network task.

## 6. Execution models

| Model | `net_poll()` | Ticks |
|---|---|---|
| Bare-metal loop | Every iteration, until it returns 0 | When the millisecond counter has advanced by the chosen period |
| Bare-metal with a MAC interrupt | When the interrupt's flag is set | From a periodic timer flag, in the main loop |
| RTOS | One network task blocks on the MAC event with a timeout of the tick period, then polls | In the same task, after each wake-up |
| Linux / macOS | `select()`/`poll()` on the driver's descriptor with a timeout of the tick period | After each wake-up |

## 7. Tickless operation (not implemented)

There is no `net_next_event_ms()`: a device must wake at its tick period
even when nothing is due.

Adding it would take:

1. `net_next_event_ms(net)`: the minimum over every running TCP timer
   (one `timer_ms` per connection), the ARP rate-limit slots, the reassembly
   and IGMP timers, the IPv6 DAD, router-solicitation and MLD timers, and —
   whenever any second-granularity lifetime is finite — the time to the next
   whole second (`1000 - lifetime_carry_ms`, `1000 - arp_carry_ms`);
   `UINT32_MAX` if nothing runs.
2. A matching `*_next_event_ms()` in every module with a timer (DHCPv4,
   DHCPv6, TFTP, mDNS, DTLS, HTTP), because the stack cannot see their
   state; the application takes the minimum over all of them.
3. The application sleeps until that deadline or a MAC interrupt, then calls
   `net_tick()` and the module ticks with the time actually elapsed.

Because every timer is already a plain countdown field, each function is a
scan over existing state; no timer representation has to change.
