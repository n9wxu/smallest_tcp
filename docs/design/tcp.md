# TCP — Design

**Protocol:** Transmission Control Protocol (RFC 9293)  
**Supporting:** RFC 6298 (retransmission timer), RFC 6528 (initial sequence numbers), RFC 6691 (MSS), RFC 1122 §4.2  
**Files:** `include/tcp.h`, `src/tcp.c`; buffers in `include/tcp_buf.h`, `src/tcp_buf_saw.c` — see [tcp-buffer.md](tcp-buffer.md)  
**Requirements:** [docs/requirements/tcp.md](../requirements/tcp.md) (REQ-TCP-001..155)  
**Status:** V1 implemented — IPv4 and IPv6, passive and active open, one segment in flight  
**Last updated:** 2026-09-27

Section numbers with § refer to RFC 9293 unless another document is named; "section N" refers to this document.

---

## 1. Scope and V1 decisions

`tcp.c` is the smallest TCP that interoperates with full stacks for
device-sized traffic: web pages, TLS records, a firmware download.  It keeps
one segment in flight, delivers in-order data only, and owns no memory: the
application provides every connection, its buffers and the table that binds
them.  `tcp.c` has no static data.

| Decision | V1 choice | Requirement |
|---|---|---|
| Segments in flight | One — the stop-and-wait buffers (`tcp_buf_saw.c`) | REQ-TCP-145 |
| Congestion control | Satisfied by one segment in flight; there is no cwnd or ssthresh | REQ-TCP-108 (in place of 101..107) |
| Acknowledgements | Immediate: every data segment is acknowledged at once; no delayed ACK | REQ-TCP-128 |
| Nagle | None: `tcp_send()` sends at once.  `tcp_write()` + `tcp_output()` build one segment from several pieces | REQ-TCP-131 |
| Out-of-order data | Dropped — no reassembly queue; the ACK asks for RCV.NXT again | REQ-TCP-067 |
| Options | MSS sent on every SYN and read from the peer's; every other option skipped by its length.  No SACK, window scale or timestamps | REQ-TCP-076..081, 109..117 |
| Urgent data | URG flag and urgent pointer ignored; the pointer is sent as 0 | REQ-TCP-063 |
| Retransmission timeout | Starts at `NET_DEFAULT_TCP_RTO_INIT_MS`, doubles per expiry up to `NET_DEFAULT_TCP_RTO_MAX_MS`; no RTT measurement | REQ-TCP-092, 094..098 |
| Initial sequence number | `net_random()` (section 4.6) | REQ-TCP-028 |

Stop-and-wait is what keeps the sender small.  With one segment outstanding,
no congestion window can be smaller than what is in flight (RFC 5681's
minimum, the loss window, is one segment), a retransmission resends that one
segment, and the TX buffer is the retransmission queue.  The receive side is
independent of it: it takes whatever in-order data fits the RX buffer.  The
cost is throughput — one segment per round trip
([tcp-buffer.md](tcp-buffer.md) §4).

---

## 2. Connections and how the application binds them

### 2.1 The connection

`tcp_conn_t` is the whole transmission control block: 96 bytes on Cortex-M0,
116 with IPv6.

| Fields | Contents |
|---|---|
| `state`, `local_port`, `remote_port`, `remote_ip` | The connection; the remote port and address are 0 while listening |
| `remote_mac`, `mac_valid` | Where frames go — the peer, or the gateway for an off-link peer |
| `ip_ver`, `remote_ip6`, `local_slot` | IPv6 builds only (section 7) |
| `iss`, `snd_una`, `snd_nxt`, `snd_wnd`, `snd_wl1`, `snd_wl2` | Send sequence space (§3.3.1) |
| `snd_mss` | Largest segment we send: the peer's MSS, at most `our_mss` |
| `irs`, `rcv_nxt`, `rcv_wnd` | Receive sequence space; `rcv_wnd` is the RX buffer's free space as last advertised |
| `our_mss` | The MSS we advertise (section 4.4) |
| `timer_ms`, `rto_ms`, `retransmits`, `persist_timer_ms`, `persist_ms` | Timers (section 5) |
| `txbuf_ops`/`txbuf_ctx`, `rxbuf_ops`/`rxbuf_ctx` | The two buffers ([tcp-buffer.md](tcp-buffer.md)) |
| `on_event` | Event callback (section 6), may be NULL |

Invariants the code relies on:

- SND.UNA ≤ SND.NXT.  Once the SYN is acknowledged, the TX buffer's oldest
  byte has sequence number SND.UNA.  Neither our SYN nor our FIN is ever in
  the TX buffer: they exist only in SND.UNA/SND.NXT (the SYN at ISS, the FIN
  at SND.NXT − 1 once sent).
- `rcv_wnd` ≤ the RX buffer's `available()`.  It is recomputed from
  `available()` whenever data or a FIN is taken, and only `tcp_recv()` makes
  `available()` grow — so data trimmed to `rcv_wnd` always fits.
- Both windows fit 16 bits (no window scaling); `rcv_wnd` is a `uint16_t`.
- `snd_mss` ≤ `our_mss`, so every segment fits the TX frame buffer.

### 2.2 Binding connections

`tcp_set_connections(net, conns, count)` gives the stack the application's
array of connection pointers; it is kept in `net_t` (`tcp_conns`,
`tcp_conn_count`) and must stay valid as long as `net` is used.  `find_conn()`
matches received segments against it and `tcp_tick()` runs the timers of every
entry.  NULL entries are skipped.

A `tcp_conn_t` is one connection.  `tcp_listen()` makes it wait for a SYN,
and the first SYN turns that same structure into the connection.  There is no
accept queue: to serve several clients at once, bind several connections
listening on the same port (the HTTP server does).  Table order decides which
free listener takes a SYN; a SYN that finds none is answered with RST.

The buffers are chosen per connection by the ops tables passed to
`tcp_conn_init()`.  To reuse a connection — after CLOSED, or to recycle it out
of TIME-WAIT — re-initialise its buffers and call `tcp_conn_init()` again
before `tcp_listen()` or `tcp_connect()`.  `tcp_listen()` alone resets only the
state, the ports, the remote IPv4 address and the retransmission timer.

`tcp_connect()` needs the MAC address already resolved: the peer's, or the
gateway's for an off-link peer.  TCP never resolves addresses; a passive
connection keeps the source MAC of the peer's SYN.  The application also picks
the local port — there is no ephemeral port allocation.

Segments reach TCP through `net_poll()` (→ `eth_input()` → `ipv4_input()` /
`ipv6_input()` → `tcp_input()` / `tcp6_input()`); `net_tick()` calls
`tcp_tick()`.

### 2.3 Quick start

An echo server on port 7 with the stop-and-wait buffers:

```c
#include "tcp.h"
#include <string.h>

static uint8_t frame_rx[1514], frame_tx[1514]; /* net_t's frame buffers */
static net_t net;

static uint8_t tx_mem[1024], rx_mem[1024];     /* this connection's data */
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *const conns[] = {&conn};

static uint8_t pending;                        /* events, for the main loop */
static uint8_t echo_buf[128];
static uint16_t echo_len;

static void on_event(tcp_conn_t *c, uint8_t events) {
  (void)c;
  pending |= events; /* note it only: no tcp_send() or tcp_close() here */
}

static void echo_listen(void) {
  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof tx_mem);
  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof rx_mem);
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_event);
  tcp_listen(&conn, 7);
  echo_len = 0;
}

static void echo_serve(void) {
  int n;
  if (echo_len == 0) {
    echo_len = tcp_recv(&conn, echo_buf, sizeof echo_buf);
    tcp_window_update(&net, &conn); /* advertise the space just freed */
  }
  if (echo_len > 0 && (n = tcp_send(&net, &conn, echo_buf, echo_len)) > 0) {
    echo_len = (uint16_t)(echo_len - n);
    memmove(echo_buf, echo_buf + n, echo_len);
  }
  if (tcp_status(&conn) == TCP_CLOSE_WAIT && echo_len == 0 &&
      tcp_tx_idle(&conn))
    tcp_close(&net, &conn); /* the peer has closed and has everything */
}

void app_init(const net_mac_t *driver, void *driver_ctx, uint32_t entropy) {
  net_init(&net, frame_rx, sizeof frame_rx, frame_tx, sizeof frame_tx, NULL,
           driver, driver_ctx);
  net_random_seed(&net, entropy); /* initial sequence numbers */
  tcp_set_connections(&net, conns, 1);
  echo_listen();
}

void app_poll(uint32_t elapsed_ms) {
  net_poll(&net);              /* one received frame, if any */
  net_tick(&net, elapsed_ms);  /* retransmission, probe, TIME-WAIT timers */
  if (tcp_status(&conn) == TCP_CLOSED) {
    echo_listen();             /* reset, error, or the close completed */
  } else if (pending) {
    pending = 0;
    echo_serve();
  }
}
```

Four rules show up here:

- The callback only records events; the main loop acts (section 6).
- `tcp_window_update()` follows `tcp_recv()`, because reading cannot transmit
  (section 4.5).
- `tcp_close()` waits for `tcp_tx_idle()`, because the FIN is sent at once and
  does not wait for queued data (section 4.7).
- The loop checks for CLOSED itself instead of relying on an event, since some
  closes are not reported (section 6).

`tcp_send()` returns 0 while a segment is in flight; the rest of `echo_buf`
goes out after the next `TCP_EVT_WRITABLE`.

### 2.4 API

| Function | Effect | States |
|---|---|---|
| `tcp_conn_init()` | Zero the connection, attach buffers and callback; CLOSED | any |
| `tcp_listen()` | LISTEN on a port | any (normally CLOSED) |
| `tcp_connect()`, `tcp6_connect()` | Send the SYN now; SYN-SENT.  An error if the SYN cannot be sent, or (IPv6) no source address is usable | CLOSED |
| `tcp_write()` | Queue data; returns bytes accepted — 0 while the stop-and-wait buffer has a segment in flight | ESTABLISHED, CLOSE-WAIT (else < 0) |
| `tcp_output()` | Send one segment of queued data | ESTABLISHED, CLOSE-WAIT |
| `tcp_send()` | `tcp_write()`, then `tcp_output()` if anything was accepted | ESTABLISHED, CLOSE-WAIT |
| `tcp_tx_idle()` | True when the buffer's `queued()` is 0 and SND.UNA = SND.NXT: everything written — and any SYN or FIN — has been sent and acknowledged | any |
| `tcp_recv()` | Copy received data out | any |
| `tcp_window_update()` | ACK the space freed by reading, if it is worth advertising | ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 |
| `tcp_close()` | Send our FIN: ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK.  Does nothing in any other state | ESTABLISHED, CLOSE-WAIT |
| `tcp_abort()` | RST if the peer's MAC is known; CLOSED; `TCP_EVT_RESET` | any |
| `tcp_status()` | The state (CLOSED for NULL) | any |

---

## 3. Receiving a segment

```
tcp_input() / tcp6_input()      tcp_ep_t: the sender, and our address it used
  segment_input()
    parse_segment()             header and checksum checks → tcp_seg_t
    find_conn()                 4-tuple, else a listener   → none: send_reset_reply()
    by state:
      LISTEN      listen_input()          §3.10.7.2
      SYN-SENT    syn_sent_input()        §3.10.7.3
      the rest    synchronized_input()    §3.10.7.4
                    in_window()           step 1  sequence number check
                    rst_input()           step 2  RST
                    —                     step 3  security (not implemented)
                    SYN check             step 4
                    ack_input()           step 5  → take_ack(), update_send_window()
                    —                     step 6  URG (not implemented)
                    data_input()          step 7  segment text
                    fin_input()           step 8  FIN
```

### 3.1 Parsing

`parse_segment()` drops a segment shorter than 20 bytes, one whose data offset
is below 5 or past its end, and one with a bad checksum (REQ-TCP-018..022).
The checksum's pseudo-header uses the addresses the packet actually carried —
IPv4 source and destination, or IPv6 source and destination — which
`tcp_input()`/`tcp6_input()` put in the `tcp_ep_t`.  The result, `tcp_seg_t`,
points into the received frame; nothing is copied.  SEG.LEN counts the data
plus one each for SYN and FIN.

Only `listen_input()` and `syn_sent_input()` read options, through
`peer_mss()`: EOL ends the list, NOP is skipped, any other kind is skipped by
its length byte, and a length below 2 or running past the header ends the walk.
An MSS option of length 4 and non-zero value is taken; otherwise the default
applies — 536 over IPv4, 1220 over IPv6 (REQ-TCP-079, 080).

### 3.2 Finding the connection

`find_conn()` scans the table for the destination port.  A connection that is
neither CLOSED nor LISTEN matches when its remote port and address (same
family) equal the segment's source; such an exact match wins wherever it is in
the table.  Otherwise the first listener on the port takes the segment
(REQ-TCP-148, 149).  Our local address is not compared: there is one IPv4
address, and over IPv6 a peer keeps using the address it connected to.  A
CLOSED connection matches nothing, so a segment for it is answered like any
segment with no connection (§3.10.7.1).

### 3.3 No connection: `send_reset_reply()`

The reset generation rules of §3.5.2 (REQ-TCP-072..075): nothing in reply to a
RST; to a segment with ACK, `<SEQ=SEG.ACK><CTL=RST>`; otherwise
`<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`.  The reply goes to the segment's
source MAC and address, from the address the segment was sent to.  The same
function answers the non-synchronized cases of §3.5.2: an ACK arriving in
LISTEN, and an unacceptable ACK in SYN-SENT or SYN-RECEIVED.

### 3.4 LISTEN: `listen_input()`

A RST is ignored; an ACK draws a RST; anything without SYN is dropped.  A SYN
opens the connection (REQ-TCP-030..035): `remember_peer()` records the peer's
address, port, MAC and family (and, over IPv6, which of our addresses it used);
`our_mss` and `snd_mss` are set; `take_peer_syn()` sets IRS,
RCV.NXT = SEG.SEQ + 1, SND.WND = SEG.WND and RCV.WND = `available()`;
SND.WL1/WL2 are taken from the SYN; the ISS is drawn; SND.UNA = ISS,
SND.NXT = ISS + 1, and the RTO is reset.
The connection enters SYN-RECEIVED, sends SYN,ACK and starts the retransmission
timer.

Data or a FIN on the SYN is not taken: RCV.NXT covers only the SYN, so the
peer sends them again.  A SYN-RECEIVED connection that is reset or times out
goes to CLOSED, not back to LISTEN (REQ-TCP-046 asks for LISTEN); the
application listens again.

### 3.5 SYN-SENT: `syn_sent_input()`

An ACK is acceptable when SND.UNA < SEG.ACK ≤ SND.NXT (`acks_our_syn()`; in
SYN-SENT SND.UNA = ISS, so this is §3.10.7.3's test).  An unacceptable ACK
draws a RST.  A RST closes the connection with `TCP_EVT_RESET` if its ACK was
acceptable and is ignored otherwise.  A segment without SYN is dropped.

A SYN sets `snd_mss` and the receive side (`take_peer_syn()`).  With an
acceptable ACK (a SYN,ACK) the connection is ESTABLISHED: SND.UNA = SEG.ACK,
SND.WL1/WL2 set, retransmission timer stopped, ACK sent, `TCP_EVT_CONNECTED`,
then `flush()`.  Without one it is a simultaneous open (REQ-TCP-004, 039): the
connection enters SYN-RECEIVED and `send_syn()`, which chooses by state, now
sends SYN,ACK with the same ISS.

The SYN's sequence number lives only in SND.UNA and SND.NXT.  The TX buffer
never holds it, so its `ack()` is never called for it.  Data on a SYN,ACK is
not taken.

### 3.6 Synchronized states: `synchronized_input()`

Every state from SYN-RECEIVED on runs the steps of §3.10.7.4 in order; a step
may end the processing of the segment.

**Step 1 — `in_window()`** (REQ-TCP-041..045):

| SEG.LEN | RCV.WND | Acceptable if |
|---|---|---|
| 0 | 0 | SEG.SEQ = RCV.NXT |
| 0 | > 0 | RCV.NXT ≤ SEG.SEQ < RCV.NXT + RCV.WND |
| > 0 | 0 | never |
| > 0 | > 0 | its first or last sequence number is in the window |

An unacceptable segment is answered with an ACK (`<SEQ=SND.NXT><ACK=RCV.NXT>`)
unless it is a RST, and dropped.  This is also how retransmissions of things
already received are acknowledged — the peer's FIN again in CLOSE-WAIT,
LAST-ACK or TIME-WAIT lies before RCV.NXT.  With RCV.WND zero, the ACK field of
an unacceptable segment is not processed (§3.10.7.4 allows for it; this code
does not).

**Step 2 — `rst_input()`** (REQ-TCP-046..049).  A RST anywhere in the window is
accepted; the exact-match test and challenge ACK of RFC 5961 §3 are not
implemented (REQ-TCP-154).  The connection goes to CLOSED, reporting
`TCP_EVT_RESET` from SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 and
CLOSE-WAIT, and nothing from CLOSING, LAST-ACK and TIME-WAIT, where the
application has already closed.

**Step 3** — the security check — is skipped (REQ-TCP-050).

**Step 4 — SYN.**  A SYN in the window resets the connection
(`reset_connection()`: RST, CLOSED) and raises `TCP_EVT_ERROR` (REQ-TCP-051).
A SYN outside the window has already drawn an ACK in step 1.  The challenge ACK
§3.10.7.4 recommends for every SYN (RFC 5961 §4, REQ-TCP-052) is not
implemented, and a SYN cannot reopen a connection in TIME-WAIT.

**Step 5 — `ack_input()`** (REQ-TCP-053..062).  A segment without ACK is
dropped.  Then by state:

- SYN-RECEIVED: if the ACK covers our SYN (`acks_our_syn()`), SND.UNA, SND.WND,
  SND.WL1 and SND.WL2 are set, the retransmission timer stops, the connection
  is ESTABLISHED and `TCP_EVT_CONNECTED` is raised; steps 7 and 8 continue on
  the same segment.  Otherwise a RST is sent and the segment dropped.
- TIME-WAIT: the 2×MSL timer restarts and an ACK is sent.  Only an acceptable
  segment gets here; a retransmitted FIN does not (step 1 answers it and the
  timer runs on).
- SEG.ACK > SND.NXT acknowledges something not yet sent: ACK and drop.
- SEG.ACK > SND.UNA: `take_ack()`.  A duplicate ACK changes nothing, and the
  segment goes on to steps 7 and 8.
- SEG.ACK ≥ SND.NXT means everything, our FIN included, is acknowledged:
  FIN-WAIT-1 → FIN-WAIT-2, CLOSING → TIME-WAIT, LAST-ACK → CLOSED with
  `TCP_EVT_CLOSED` (processing ends).

`take_ack()` passes SEG.ACK − SND.UNA to the TX buffer's `ack()` — a count that
includes our FIN when the FIN is acknowledged, so buffers clamp it — and
advances SND.UNA.  The retransmission timer restarts (if running) while
anything, data or FIN, is still unacknowledged, and stops otherwise
(REQ-TCP-097, 098).  Then `update_send_window()`, `flush()` in ESTABLISHED and
CLOSE-WAIT, and `TCP_EVT_WRITABLE` if the buffer has room.

`update_send_window()` is §3.10.7.4's SND.WL1/SND.WL2 rule (REQ-TCP-058): the
window is taken from a segment newer than the last update (SEG.SEQ > SND.WL1),
or the same one with an equal or newer ACK, so a reordered old segment cannot
change it.  It is called only from `take_ack()`: a segment that does not
advance SND.UNA does not update the window (section 8.2).

**Step 7 — `data_input()`** (REQ-TCP-064..067), in ESTABLISHED, FIN-WAIT-1 and
FIN-WAIT-2 only.  There is no reassembly queue:

- a segment starting after RCV.NXT (a gap) delivers nothing;
- bytes before RCV.NXT were taken already (a retransmission with different
  boundaries) and are skipped;
- what remains is trimmed to RCV.WND and passed to `deliver()`; RCV.NXT
  advances by what the buffer took, RCV.WND is recomputed from `available()`,
  and `TCP_EVT_DATA` is raised if anything was taken.

Every segment with data is acknowledged at once, including a duplicate or one
after a gap: the ACK tells the peer where to resume.

**Step 8 — `fin_input()`** (REQ-TCP-068..071).  A FIN counts only if it
directly follows the segment's data and all of that data was taken, i.e.
SEG.SEQ + data length = RCV.NXT after step 7.  Otherwise it is ignored; a bare
FIN is acknowledged here, one with data by step 7.  An accepted FIN advances
RCV.NXT, is acknowledged, and moves the connection:

- ESTABLISHED → CLOSE-WAIT, `TCP_EVT_CLOSED`;
- FIN-WAIT-1 → CLOSING.  A FIN that also acknowledges our FIN finds the
  connection already in FIN-WAIT-2 (step 5 ran first) and goes to TIME-WAIT —
  §3.10.7.4's "if our FIN has been ACKed" case;
- FIN-WAIT-2 → TIME-WAIT;
- otherwise nothing changes.

### 3.7 State transitions

| From | Event | To | Where |
|---|---|---|---|
| CLOSED | `tcp_listen()` | LISTEN | `tcp_listen()` |
| CLOSED | `tcp_connect()` / `tcp6_connect()`: SYN sent | SYN-SENT | `open_to()` |
| LISTEN | SYN: SYN,ACK sent | SYN-RECEIVED | `listen_input()` |
| SYN-SENT | SYN,ACK: ACK sent | ESTABLISHED | `syn_sent_input()` |
| SYN-SENT | SYN: SYN,ACK sent | SYN-RECEIVED | `syn_sent_input()` |
| SYN-RECEIVED | ACK of our SYN | ESTABLISHED | `ack_input()` |
| ESTABLISHED | `tcp_close()`: FIN sent | FIN-WAIT-1 | `tcp_close()` |
| ESTABLISHED | FIN | CLOSE-WAIT | `fin_input()` |
| FIN-WAIT-1 | ACK of our FIN | FIN-WAIT-2 | `ack_input()` |
| FIN-WAIT-1 | FIN, ours unacknowledged | CLOSING | `fin_input()` |
| FIN-WAIT-2 | FIN | TIME-WAIT | `fin_input()` |
| CLOSE-WAIT | `tcp_close()`: FIN sent | LAST-ACK | `tcp_close()` |
| CLOSING | ACK of our FIN | TIME-WAIT | `ack_input()` |
| LAST-ACK | ACK of our FIN | CLOSED | `ack_input()` |
| TIME-WAIT | 2×MSL | CLOSED | `conn_tick()` |
| SYN-SENT | RST with acceptable ACK | CLOSED | `syn_sent_input()` |
| synchronized | RST in window | CLOSED | `rst_input()` |
| synchronized | SYN in window; retransmissions exhausted | CLOSED, RST sent | `reset_connection()` |
| any | `tcp_abort()` | CLOSED, RST sent if the peer is known | `reset_connection()` |

---

## 4. Sending

### 4.1 Frames

The stack has one TX frame buffer, `net->tx`.  `frame_start()` writes the
Ethernet header to the endpoint's MAC and returns where the TCP header goes,
leaving room for the IP header; the caller writes the TCP header and payload;
`frame_send()` computes the checksum over the pseudo-header, writes the IPv4
or IPv6 header and calls `net_transmit()`.  The payload is copied once, from
the TX buffer into the frame.  The checksum is always computed in software.

### 4.2 Segments

`send_segment()` sends every segment of a connection and fixes what they
share: SEG.ACK = RCV.NXT (its callers set the ACK flag on every segment but
the SYN of an active open); SEG.WND = `rcv_wnd`, or 0 on a RST; and a SYN
always carries the MSS option, the only option ever sent (REQ-TCP-076, 082,
116).  PSH is never set.

| Function | Sends |
|---|---|
| `send_ack()` | `<SEQ=SND.NXT><CTL=ACK>` |
| `send_syn()` | `<SEQ=ISS>`: SYN in SYN-SENT, SYN,ACK in SYN-RECEIVED — one function opens, answers and retransmits |
| `send_fin()` | FIN,ACK at a given sequence number: SND.NXT when first sent, SND.NXT − 1 when retransmitted |
| `reset_connection()` | RST,ACK at SND.NXT if the peer's MAC is known, then CLOSED.  It raises no event; its callers add `TCP_EVT_RESET` (`tcp_abort()`) or `TCP_EVT_ERROR` |
| `send_reset_reply()` | A RST built from the received segment alone, without a connection (section 3.3) |

### 4.3 Data: `flush()`

`flush()` sends one segment of queued data (REQ-TCP-084):

1. The limit is min(SND.WND, `snd_mss`).
2. If it is zero, the persist timer starts (unless it or the retransmission
   timer is running) and nothing is sent (section 5.2).
3. Otherwise the persist timer stops, `next_segment()` supplies up to the limit,
   the segment goes out at SND.NXT, SND.NXT advances and the retransmission
   timer starts.

It runs from `tcp_send()` and `tcp_output()`, from `take_ack()` in ESTABLISHED
and CLOSE-WAIT, on reaching ESTABLISHED by active open, and from a
retransmission timeout.

The limit ignores bytes already in flight — the usable window is really
SND.UNA + SND.WND − SND.NXT — and data is sent at SND.NXT.  Both are right only
because `next_segment()` returns nothing while a segment is in flight, so
SND.NXT = SND.UNA whenever it returns data.  A buffer that allows several
segments in flight needs `flush()` changed first
([tcp-buffer.md](tcp-buffer.md) §5).

### 4.4 Segment size

`our_mss` = min(TX frame buffer − Ethernet header − IP header − 20, 1460), for
the connection's address family (REQ-TCP-077).  It is advertised in our SYN and
caps `snd_mss`, which is the peer's MSS option (or the family's default) —
so every segment fits `net->tx`.

`our_mss` is derived from the TX frame buffer but tells the peer what we can
*receive*.  The RX frame buffer must therefore be at least as large as the TX
one: `net_poll()` truncates a longer frame and the IP layer drops it.  The 1460
cap is the Ethernet value for IPv4; with IPv6 a 1514-byte frame buffer already
limits `our_mss` to 1440.

### 4.5 Receive window

`rcv_wnd` is the RX buffer's free space.  It is advertised in every segment and
recomputed when data or a FIN is taken (REQ-TCP-082, 083).  `tcp_recv()` frees
space but cannot send — it has no `net_t` — so the application calls
`tcp_window_update()` after reading.  That sends an ACK only when the window
has grown by at least min(buffer size / 2, `our_mss`), where the buffer size is
`available()` + `readable()`: receiver silly-window avoidance, §3.8.6.2.2
(REQ-TCP-088).  A smaller increase is advertised by the next ACK for data
(`data_input()` recomputes `rcv_wnd` without the threshold).  Without
`tcp_window_update()`, a peer facing a zero window learns of the space only
through its own window probes.

### 4.6 Initial sequence numbers

`listen_input()` and `open_to()` draw the ISS from `net_random()`, the
stack's one generator (xorshift32, state in `net_t`).  `net_init()` seeds it
from the last four bytes of the MAC address, which differ per device but are
public; the application should mix in real entropy with `net_random_seed()`
at start-up (REQ-TCP-028, 153).  The previous ISS counter was seeded from
`time()` on hosted builds only and was a fixed constant on embedded targets.

Two limits remain.  xorshift32 returns its whole state, so anyone who sees one
output can compute the ones that follow: the ISS of a SYN,ACK the device sent
them, or a DHCPv4 transaction ID, which is a full 32-bit output.  And RFC
6528's construction — a clock plus a keyed hash of the connection's addresses
and ports — is not implemented.  An attacker who can open one connection to
the device can predict the ISS of the next.

### 4.7 Closing

`tcp_close()` sends the FIN at once at SND.NXT, advances SND.NXT past it and
starts the retransmission timer.  It does not queue the FIN behind data that
is written but not yet sent, as §3.10.4 requires: such data would follow the
FIN, and `flush()` no longer runs once the state has left ESTABLISHED and
CLOSE-WAIT, so it is never sent.  Call `tcp_close()` when `tcp_tx_idle()` is
true, as the HTTP server does before it ends a response.  In LISTEN, SYN-SENT
and SYN-RECEIVED `tcp_close()` does nothing; use `tcp_abort()`.

---

## 5. Timers

`tcp_tick(net, elapsed_ms)` runs `conn_tick()` on every bound connection.  Each
timer is a countdown in milliseconds, stopped at 0; `net_countdown()` expires
it at most once per tick, however large `elapsed_ms` is.

| Field | Meaning |
|---|---|
| `timer_ms` | The retransmission timer; in TIME-WAIT, the 2×MSL wait |
| `rto_ms` | The retransmission timeout |
| `retransmits` | Consecutive expiries without everything being acknowledged |
| `persist_timer_ms` | Until the next zero-window probe |
| `persist_ms` | The probe interval |

The retransmission timer is always stopped in TIME-WAIT, so one countdown
serves both purposes.  The persist timer has its own (section 5.2).

### 5.1 Retransmission (REQ-TCP-090..098)

The timer starts (at `rto_ms`) whenever something that occupies sequence space
is sent — a SYN or SYN,ACK, a data segment in `flush()`, the FIN in
`tcp_close()` — except a zero-window probe (section 5.2).  A new ACK restarts a
running timer while anything is still unacknowledged and stops it otherwise;
stopping clears `retransmits`.  It also stops on reaching ESTABLISHED, CLOSED
or TIME-WAIT.

On expiry `retransmission_timeout()`:

1. stops the timer if nothing is outstanding — no data in flight
   (`in_flight()`), no unacknowledged FIN, not in SYN-SENT or SYN-RECEIVED;
2. gives up after `TCP_MAX_RETRANSMITS` (8) retransmissions: the next expiry
   resets the connection and raises `TCP_EVT_ERROR`;
3. doubles `rto_ms`, up to `NET_DEFAULT_TCP_RTO_MAX_MS`, and restarts the timer
   with it (REQ-TCP-096);
4. resends the earliest unacknowledged segment (REQ-TCP-095):
   - the SYN or SYN,ACK (`send_syn()`);
   - data: SND.NXT goes back to SND.UNA, `mark_retransmit()` makes the buffer
     offer the in-flight bytes again, and `flush()` sends them with their
     original sequence numbers.  If our FIN had already followed the data,
     SND.NXT is then restored so the FIN keeps its sequence number.  The FIN
     is not resent with the data: when the data is acknowledged the timer is
     still running for the FIN, and the next expiry resends it;
   - otherwise the FIN alone, at SND.NXT − 1.

`conn_tick()` sets `timer_ms` back to `rto_ms` before calling
`retransmission_timeout()`, and step 3 sets the doubled value before anything
is resent.  So `flush()` called from a retransmission sees the timer running and
does not start the persist timer, even when the window is zero.

With the defaults (1 s initial RTO, 60 s maximum) the waits are 1, 2, 4, 8, 16,
32, 60, 60 and 60 s: a connection whose peer has gone is reset about four
minutes after the original transmission, within §3.8.3's R2 (at least 100 s,
three minutes for a SYN).  There is no RTT measurement (REQ-TCP-091, 099, 100),
so `rto_ms` starts at `NET_DEFAULT_TCP_RTO_INIT_MS` for every connection and
never decreases: after a loss the backed-off value stays for the rest of the
connection.

### 5.2 Zero-window probing (REQ-TCP-085..087)

`flush()` starts the persist timer when the peer's window is zero and neither
timer is running; the first interval is `NET_DEFAULT_TCP_RTO_INIT_MS`.  It
stops when `flush()` finds the window open, and in `tcp_abort()`.
`conn_tick()` runs it only in ESTABLISHED and CLOSE-WAIT and only while the
retransmission timer is stopped.

On expiry `probe_zero_window()` sends one byte past the window (§3.8.6.1).  If a
previous probe is still unacknowledged, SND.NXT goes back to SND.UNA and
`mark_retransmit()` makes the buffer offer the same byte, so a probe is the same
byte at the same sequence number until it is acknowledged.  If nothing is
queued the timer stops.  The interval then doubles, up to the maximum RTO.  A
probe that cannot be sent is marked for retransmission and goes with the next.

A peer that has opened its window accepts the byte; its ACK advances SND.UNA,
so `take_ack()` takes the new window and `flush()` resumes sending.  A peer
still at zero sends a duplicate ACK, which changes nothing.

The persist timer is a separate countdown because it can be pending while the
retransmission timer runs: when `tcp_close()` sends a FIN while the peer's
window is zero, the FIN's retransmission timer runs and the persist countdown
is left as it was, not serviced.  A probe also starts no retransmission timer
and does not count toward `TCP_MAX_RETRANSMITS`, so probing continues as long
as the window stays zero — RFC 1122 §4.2.2.17 requires this while the peer
answers, and no limit is implemented for a peer that has stopped answering.

### 5.3 TIME-WAIT

`enter_time_wait()` stops the retransmission timer and sets `timer_ms` to
2×MSL (`NET_DEFAULT_TCP_MSL_MS` is 2 minutes, so 4 minutes; REQ-TCP-008, 009).
An acceptable segment with ACK restarts it (section 3.6, step 5).  On expiry
the connection is CLOSED and `TCP_EVT_CLOSED` is raised.  An application that
closes first may recycle the connection before then; [http.md](http.md) §7
describes the trade-off.

### 5.4 Timers not implemented

No delayed-ACK timer, no keep-alive (REQ-TCP-132..134), no FIN-WAIT-2 timeout:
a connection in FIN-WAIT-2 waits for the peer's FIN indefinitely, and the
application's own timeout must cover a peer that never sends it.

---

## 6. Events and the callback rule

`on_event(conn, events)` receives a bitmask of `TCP_EVT_*`.  Each call
currently carries one event.

| Event | Raised by | When |
|---|---|---|
| `TCP_EVT_CONNECTED` | `syn_sent_input()`, `ack_input()` | ESTABLISHED reached |
| `TCP_EVT_DATA` | `data_input()` | Bytes stored in the RX buffer |
| `TCP_EVT_WRITABLE` | `take_ack()` | An ACK advanced SND.UNA and the TX buffer has room |
| `TCP_EVT_CLOSED` | `fin_input()` | The peer closed: ESTABLISHED → CLOSE-WAIT |
| | `ack_input()` | Our FIN acknowledged in LAST-ACK: CLOSED |
| | `conn_tick()` | TIME-WAIT ended: CLOSED |
| `TCP_EVT_RESET` | `rst_input()`, `syn_sent_input()` | RST received (sections 3.5 and 3.6) |
| | `tcp_abort()` | Always, whatever the state |
| `TCP_EVT_ERROR` | `synchronized_input()` | SYN in the window; RST sent |
| | `retransmission_timeout()` | Retransmissions exhausted; RST sent |

`TCP_EVT_CLOSED` has two meanings; `tcp_status()` tells them apart.  Not every
change is reported.  A RST in CLOSING, LAST-ACK or TIME-WAIT closes the
connection silently, and FIN-WAIT-2 → TIME-WAIT and CLOSING → TIME-WAIT raise
nothing — an active closer hears `TCP_EVT_CLOSED` only when TIME-WAIT ends.  An
application that must notice every close polls the state with `tcp_status()`;
the HTTP server polls the state rather than relying on events.

**The callback must not send or close.**  It runs inside `net_poll()` (segment
input) and `net_tick()` (timers), and from `tcp_abort()`, while `tcp.c` is
part-way through the connection: `data_input()` raises `TCP_EVT_DATA` and then
sends its ACK, `fin_input()` may still run on the same segment, and
`syn_sent_input()` raises `TCP_EVT_CONNECTED` before its own `flush()`.  A
callback that sent, closed, aborted or re-initialised the connection would
change SND.NXT, the state or the buffers under the code that called it.  The
application records the event and acts from its main loop.

---

## 7. Dual-stack endpoints

Everything that depends on the address family goes through `tcp_ep_t`: the
other end of a segment (IPv4 `ip4`, or IPv6 `ip6`, and `mac`) and our address
it uses (`local_ip4` or `local6`).  `ip6` non-NULL means IPv6.
`tcp_input()` and `tcp6_input()` fill it from the received packet;
`conn_endpoint()` fills it from a connection, with our IPv4 address
(`net->ipv4_addr`) or our IPv6 address in slot `local_slot`.  It drives the
checksum's pseudo-header, the EtherType and IP header in `frame_start()` and
`frame_send()`, the header size in `our_mss`, and the default MSS
(536 / 1220).

A connection records its family in `ip_ver`, and `is_peer()` compares only
addresses of that family.  A listener has none until its SYN arrives, so it
accepts IPv4 and IPv6 peers alike.  Over IPv6 our address is the one the SYN
was sent to (passive open) or the one `ipv6_src_for()` picks — link-local for a
link-local peer, else a preferred global address, else a deprecated one
(active open; `tcp6_connect()` fails if none is usable).  It is stored as a slot
index, so the connection sends from whatever address that slot holds.
`tcp6_input()` drops segments sent to a multicast address.

With `NET_USE_IPV6` 0 the IPv6 members and branches compile out.

---

## 8. Not implemented and known gaps

### 8.1 Not implemented in V1

| Feature | Requirement | Instead |
|---|---|---|
| Delayed ACK | REQ-TCP-125 (SHOULD) | Immediate ACK (REQ-TCP-128), which also meets 126 and 127 |
| Nagle; sender silly-window avoidance | REQ-TCP-129, 089 (SHOULD) | `tcp_write()` + `tcp_output()` (REQ-TCP-131) |
| Slow start, congestion avoidance, fast retransmit | REQ-TCP-101..107 | One segment in flight (REQ-TCP-108) |
| RTT measurement, computed RTO, Karn's rule, 1 s minimum | REQ-TCP-091, 093, 099, 100 | Fixed initial RTO with backoff (section 5.1) |
| Reassembly of out-of-order segments | — | Dropped; the peer retransmits |
| SACK, window scale, timestamps | REQ-TCP-113, 114, 117..124 | Options skipped by length |
| Urgent data | REQ-TCP-063 (MAY) | Ignored |
| Security/compartment check | REQ-TCP-050 (MAY) | Skipped |
| Keep-alive | REQ-TCP-132 (MAY) | None (so off by default, REQ-TCP-133) |
| Challenge ACKs, RST rate limiting (RFC 5961) | REQ-TCP-052, 154, 155 | RST and SYN accepted anywhere in the window (section 3.6) |
| ICMP errors for TCP | REQ-TCP-135..138 | Not delivered to TCP |
| Checksum offload | REQ-TCP-141 | Always software |
| RFC 6528 initial sequence numbers | REQ-TCP-028, 153 | `net_random()` (section 4.6) |
| Data or FIN on a SYN | — | Not taken; the peer resends |

### 8.2 Behaviour that differs from RFC 9293

- RST in SYN-RECEIVED goes to CLOSED, not back to LISTEN (REQ-TCP-046).
- The send window is updated only by an ACK that advances SND.UNA; §3.10.7.4
  step 5 also takes it from SEG.ACK = SND.UNA.  A pure window update from a
  peer that had advertised zero is ignored, and sending resumes at the next
  zero-window probe — up to `NET_DEFAULT_TCP_RTO_MAX_MS` later once the probe
  interval has backed off.
- With RCV.WND zero the ACK field of a segment carrying data is not processed.
- `tcp_close()` does not queue the FIN behind unsent data (section 4.7),
  and does nothing in LISTEN, SYN-SENT or SYN-RECEIVED.
- A retransmitted FIN in TIME-WAIT is acknowledged but does not restart the
  2×MSL timer (section 3.6, step 5).
- A SYN cannot reopen a connection in TIME-WAIT; an in-window SYN resets it.
- `TCP_MAX_RETRANSMITS` is fixed at compile time and the application is not
  told of repeated retransmissions before the connection is given up (§3.8.3's
  R1).

### 8.3 Known gaps

- **Partial ACK.**  After an ACK that covers only part of a segment, the
  stop-and-wait buffer offers the remaining bytes again (they are at
  SND.UNA), but `flush()` sends them at SND.NXT: the peer receives them under
  the wrong sequence numbers.  Peers seldom acknowledge part of a segment, but
  nothing prevents it.
- **Transmit failure.**  If the driver fails to send a data segment in
  `flush()`, the buffer still counts the bytes as in flight, SND.NXT has not
  advanced and no timer starts: nothing ever resends them.  (A failed probe is
  handled.)
- **IPv4 broadcast and multicast.**  `ipv4_input()` passes TCP segments sent to
  a broadcast or joined multicast address, and `tcp_input()`, unlike
  `tcp6_input()`, does not drop them.  A SYN to such an address is accepted by
  a listener, and a segment with no connection draws a RST whose source
  address is the broadcast or multicast address.  RFC 1122 §4.2.3.10 says to
  discard them.

---

## 9. Tests and files

- **Unit:** `tests/unit/test_tcp.c` (45 tests: handshakes, `tcp_write()` /
  `tcp_output()`, in-order delivery with gaps, overlaps, duplicates and FIN
  placement, window updates, active and passive close, RST, retransmission of
  SYN, data and FIN, TIME-WAIT, MSS, persist), `tests/unit/test_tcp6.c` (18:
  IPv6, dual-stack listeners, source address), `tests/unit/test_tcp_buf.c`
  (20: the stop-and-wait buffers).
- **Black-box:** `tests/blackbox/test_tcp_conform.py` (RFC 9293 conformance
  against a live stack over raw frames) and `tests/blackbox/test_tcp_fuzz.py`.

```
include/tcp.h, src/tcp.c             — the protocol
include/tcp_buf.h, src/tcp_buf_saw.c — buffer interface, stop-and-wait buffers
docs/requirements/tcp.md             — REQ-TCP-001..155
```
