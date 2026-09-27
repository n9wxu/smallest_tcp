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
| Initial sequence number | RFC 6528: a 4 µs clock plus a keyed hash of the addresses and ports (section 4.6) | REQ-TCP-028, 153 |

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
| `snd_mss` | Largest segment we send: the peer's MSS (or the family's default), at most what the TX frame buffer carries (section 4.4) |
| `fin_sent` | Our FIN has been sent and is SND.NXT − 1.  Until then a closing connection's FIN waits behind the data queued before it (section 4.7) |
| `irs`, `rcv_nxt`, `rcv_wnd` | Receive sequence space; `rcv_wnd` is the RX buffer's free space as last advertised |
| `our_mss` | The MSS we advertise: what the RX frame buffer takes (section 4.4) |
| `timer_ms`, `timer`, `rto_ms`, `retransmits`, `persist_ms` | One timer at a time — retransmission, zero-window probe or TIME-WAIT (section 5) |
| `txbuf_ops`/`txbuf_ctx`, `rxbuf_ops`/`rxbuf_ctx` | The two buffers ([tcp-buffer.md](tcp-buffer.md)) |
| `on_event` | Event callback (section 6), may be NULL |

Invariants the code relies on:

- SND.UNA ≤ SND.NXT.  Once the SYN is acknowledged, the TX buffer's oldest
  byte has sequence number SND.UNA, and the bytes it has in flight
  (`in_flight()`) follow it.  Neither our SYN nor our FIN is ever in the TX
  buffer: they exist only in SND.UNA/SND.NXT (the SYN at ISS, the FIN at
  SND.NXT − 1 once `fin_sent` is set).
- `rcv_wnd` ≤ the RX buffer's `available()`.  It is recomputed from
  `available()` whenever data or a FIN is taken, and only `tcp_recv()` makes
  `available()` grow — so data trimmed to `rcv_wnd` always fits.
- Both windows fit 16 bits (no window scaling); `rcv_wnd` is a `uint16_t`.
- `snd_mss` ≤ `segment_room(tx.capacity)`, so every data segment fits the TX
  frame buffer.  It does not depend on `our_mss`, which comes from the RX
  frame buffer.

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
state, the ports, the remote IPv4 address and the timer.

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
  if (tcp_status(&conn) == TCP_CLOSE_WAIT && echo_len == 0)
    tcp_close(&net, &conn); /* the peer has closed; our FIN follows the echo */
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
- `tcp_close()` can follow the last `tcp_send()` at once: the FIN is queued
  behind the data not yet sent (section 4.7).  `echo_len == 0` means the TX
  buffer has taken all of it.
- The loop checks for CLOSED itself instead of relying on an event, since some
  closes are not reported (section 6).

`tcp_send()` returns 0 while a segment is in flight; the rest of `echo_buf`
goes out after the next `TCP_EVT_WRITABLE`.

### 2.4 API

| Function | Effect | States |
|---|---|---|
| `tcp_conn_init()` | Zero the connection, attach buffers and callback; CLOSED | any |
| `tcp_listen()` | LISTEN on a port | any (normally CLOSED) |
| `tcp_connect()`, `tcp6_connect()` | Send the SYN now; SYN-SENT.  An error, and still CLOSED, if the SYN cannot be sent (`NET_ERR_BUSY` from a busy driver), or (IPv6) no source address is usable | CLOSED |
| `tcp_write()` | Queue data; returns bytes accepted — 0 while the stop-and-wait buffer has a segment in flight | ESTABLISHED, CLOSE-WAIT (else < 0) |
| `tcp_output()` | Send one segment of the data not yet sent, as the window allows | ESTABLISHED, CLOSE-WAIT |
| `tcp_send()` | `tcp_write()`, then `tcp_output()` if anything was accepted | ESTABLISHED, CLOSE-WAIT |
| `tcp_tx_idle()` | True when the buffer's `queued()` is 0 and SND.UNA = SND.NXT: everything written — and any SYN or FIN — has been sent and acknowledged | any |
| `tcp_recv()` | Copy received data out | any |
| `tcp_window_update()` | ACK the space freed by reading, if it is worth advertising | ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 |
| `tcp_close()` | ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK; our FIN goes once the data queued before it has been sent (section 4.7).  Does nothing in any other state | ESTABLISHED, CLOSE-WAIT |
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
                    ack_input()           step 5  → send_side_ack(): take_ack(),
                                                    update_send_window(), flush()
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
`start_send_sequence()` sets `our_mss`, the ISS (section 4.6), SND.UNA = ISS
and SND.NXT = ISS + 1, clears `fin_sent` and resets the RTO — the same
function an active open uses, once the addresses and ports that key the ISS
are known; `take_peer_mss()` sets `snd_mss`; `take_peer_syn()` sets IRS,
RCV.NXT = SEG.SEQ + 1, SND.WND = SEG.WND and RCV.WND = `available()`; and
SND.WL1/WL2 are taken from the SYN.  The connection enters SYN-RECEIVED, sends
SYN,ACK and starts the retransmission timer.

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
- SND.UNA ≤ SEG.ACK ≤ SND.NXT: `send_side_ack()`.  An older ACK
  (SEG.ACK < SND.UNA) is a duplicate and changes nothing (REQ-TCP-057).
  Either way the segment goes on to steps 7 and 8.
- Our FIN is acknowledged when it has been sent (`fin_sent`) and
  SEG.ACK ≥ SND.NXT: FIN-WAIT-1 → FIN-WAIT-2, CLOSING → TIME-WAIT, LAST-ACK →
  CLOSED with `TCP_EVT_CLOSED` (processing ends).  `fin_sent` is needed
  because the FIN can be queued behind data (section 4.7): until it is sent,
  SEG.ACK = SND.NXT acknowledges the data only, and the state stays.

`send_side_ack()` is §3.10.7.4's processing of an acceptable ACK.  If it
acknowledges new data (SEG.ACK > SND.UNA), `take_ack()` passes
SEG.ACK − SND.UNA to the TX buffer's `ack()` — a count that includes our FIN
when the FIN is acknowledged, so the buffer caps it at the bytes it sent — and
advances SND.UNA.  The retransmission timer then restarts (if running) while
SND.UNA < SND.NXT — data or FIN still unacknowledged — and stops otherwise
(REQ-TCP-097, 098).  For every acceptable ACK, new data or not,
`update_send_window()` follows, then `flush()` (section 4.3), then
`TCP_EVT_WRITABLE` if new data was acknowledged and the buffer has room.

`update_send_window()` is §3.10.7.4's SND.WL1/SND.WL2 rule (REQ-TCP-058): the
window is taken from a segment newer than the last update (SEG.SEQ > SND.WL1),
or the same one with an equal or newer ACK, so a reordered old segment cannot
change it.  An ACK of nothing new (SEG.ACK = SND.UNA) is included, as
§3.10.7.4 asks: it is how a peer that advertised a zero window says it has
room again, and the `flush()` after it resumes sending at once instead of at
the next zero-window probe, which could be up to `NET_DEFAULT_TCP_RTO_MAX_MS`
away once the probe interval has backed off.

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
| ESTABLISHED | `tcp_close()`: FIN queued, sent after the data | FIN-WAIT-1 | `tcp_close()` |
| ESTABLISHED | FIN | CLOSE-WAIT | `fin_input()` |
| FIN-WAIT-1 | ACK of our FIN | FIN-WAIT-2 | `ack_input()` |
| FIN-WAIT-1 | FIN, ours unacknowledged | CLOSING | `fin_input()` |
| FIN-WAIT-2 | FIN | TIME-WAIT | `fin_input()` |
| CLOSE-WAIT | `tcp_close()`: FIN queued, sent after the data | LAST-ACK | `tcp_close()` |
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
What `net_transmit()` returns matters only for the first SYN of an active
open, which `tcp_connect()` and `tcp6_connect()` report.  Any other segment
the driver did not take is treated as lost on the wire: a SYN or SYN,ACK,
data, a FIN or a probe is sent again by its timer (section 4.3), and an ACK
or RST is answered again when the peer retransmits.

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
| `send_fin()` | FIN,ACK at a given sequence number: SND.NXT when first sent (`send_queued_fin()`), SND.NXT − 1 when retransmitted |
| `reset_connection()` | RST,ACK at SND.NXT if the peer's MAC is known, then CLOSED.  It raises no event; its callers add `TCP_EVT_RESET` (`tcp_abort()`) or `TCP_EVT_ERROR` |
| `send_reset_reply()` | A RST built from the received segment alone, without a connection (section 3.3) |

### 4.3 Output: `flush()` and `send_data()`

`flush()` is what sends: data, then our FIN once it is due.  It acts in
ESTABLISHED and CLOSE-WAIT, and in FIN-WAIT-1, CLOSING and LAST-ACK while our
FIN is still queued (`fin_queued()`); in every other state it does nothing.
It calls `send_data()`, then, if the FIN is queued and `all_data_sent()` —
the buffer's `queued()` equals its `in_flight()` — sends the FIN
(`send_queued_fin()`, section 4.7).

`send_data()` sends one segment of the data not yet sent (REQ-TCP-084):

1. The limit is min(SND.WND, `snd_mss`).
2. If it is zero, nothing is sent; the persist timer starts if data is waiting
   and no timer is running (section 5.2).
3. Otherwise the persist timer stops, `next_segment()` supplies up to the
   limit — nothing while a segment is in flight — and the segment goes out at
   SND.NXT.  SND.NXT advances by its length whatever `net_transmit()`
   returned.
4. If SND.UNA < SND.NXT, the retransmission timer is started unless it is
   already running (`retransmit_timer_run()`, RFC 6298 §5.1).

`flush()` runs from `tcp_send()` and `tcp_output()`, from `send_side_ack()`
for every acceptable ACK, on reaching ESTABLISHED by active open, and from
`tcp_close()`.  A retransmission timeout does not go through `flush()`: it
resends the bytes in flight itself (section 5.1).

**A frame the driver did not take is a lost segment.**  `net_transmit()`
reports a busy driver (`NET_ERR_BUSY`) or a failed one (`NET_ERR_NO_FRAME`),
and `send_data()` ignores both: the bytes are in flight and SND.NXT is past
them, exactly as if the frame had been lost on the wire, and the
retransmission timer — which runs whenever SND.UNA < SND.NXT — sends them
again.  Recovery needs no path of its own, and nothing can be left in flight
without a timer.  The price is that a driver busy for longer than the
retransmission back-off (section 5.1) costs the connection, as a dead link
would.

The limit ignores bytes already in flight — the usable window is really
SND.UNA + SND.WND − SND.NXT — and data is sent at SND.NXT.  Both are right only
because `next_segment()` returns nothing while a segment is in flight, so
SND.NXT = SND.UNA whenever it returns data.  A buffer that allows several
segments in flight needs `send_data()` changed first
([tcp-buffer.md](tcp-buffer.md) §5).

### 4.4 Segment size

`segment_room(capacity, ep)` is the largest segment a frame buffer of
`capacity` bytes holds, to or from the endpoint's address family, within one
Ethernet frame: min(capacity, 14 + `ETH_MTU`) − 14 − IP header − 20, where
`ETH_MTU` (`eth.h`) is 1500.  That is at most 1460 over IPv4 and 1440 over
IPv6 (REQ-TCP-077).  Each direction uses its own buffer:

- `our_mss` = `receive_mss()` = `segment_room(rx.capacity)`.  It is advertised
  in our SYN and tells the peer what we can *receive*, so it comes from the
  RX frame buffer: a longer frame would be truncated by `net_poll()` and
  dropped by the IP layer.
- `snd_mss` = `send_mss()` = min(the peer's MSS option, or the family's
  default until one arrives, `segment_room(tx.capacity)`), so every data
  segment fits `net->tx` (RFC 9293 §3.7.1: the peer's MSS limits what we
  send, our own buffer limits it too).

The two buffers can therefore differ in size either way.  The advertised MSS
used to come from the TX buffer: an RX buffer smaller than the TX one invited
segments `net_poll()` truncated, so the RX buffer had to be at least as large;
and with a frame buffer larger than a frame, IPv6 advertised 1460, 20 bytes
more than an Ethernet frame carries after the IPv6 header.

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

`start_send_sequence()`, called by `listen_input()` and `open_to()` once the
peer's address and ports are known, computes the ISS as RFC 6528 describes
(REQ-TCP-028, 153):

ISS = M + F(local address, remote address, local port, remote port)

- **M** is `net->tcp_clock`, a 32-bit count of 4 µs ticks.  `tcp_tick()`
  advances it by `elapsed_ms` × 250; modulo 2^32 that is the same as a
  4 µs clock, read at the resolution of the ticks.
- **F** is `net_hash()`: HalfSipHash-2-4 under the stack's secret key
  ([architecture.md §9](../architecture.md#9-randomness)) of the connection
  id in network byte order — local address, remote address, local port,
  remote port: 4 + 4 + 2 + 2 bytes over IPv4, 16 + 16 + 2 + 2 over IPv6.

The clock gives each connection id a sequence space that moves forward: a
new connection between the same addresses and ports starts beyond where the
old one was, so stray segments of the old incarnation are unlikely to fall in
the new one's window (§3.4.1).  The keyed hash gives every connection id a
different, secret offset: an attacker who opens a connection of his own learns
M + F for his own id and nothing about F for anyone else's.  The random ISS
this code used before (`net_random()`) lacked the first property, and
xorshift32, the generator then, did not give it the second: every output was
its whole state, so one SYN,ACK was enough to predict the next ISS.

Three things follow:

- The key is only as secret as its seed.  `net_init()` seeds it from the
  MAC address, which is public; seed it with real entropy through
  `net_random_seed()` before the first connection (the quick start does).
- Seeding later changes F for every connection id, so a connection opened
  after a new seed no longer starts beyond its predecessor.
- M advances only through `tcp_tick()`, normally from `net_tick()`.  An
  application that does not tick gives a reopened connection id the same ISS
  as before.

### 4.7 Closing

`tcp_close()` only changes the state — ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT →
LAST-ACK — and calls `flush()`.  §3.10.4 queues the FIN until everything
written before the CLOSE has been sent, and so does this code: while the FIN
is queued (`fin_queued()`: FIN-WAIT-1, CLOSING or LAST-ACK without
`fin_sent`), `flush()` keeps sending data as ACKs arrive, just as in
ESTABLISHED, and sends the FIN as soon as `all_data_sent()` — at once if
nothing is waiting, or in the same `flush()` as the last segment.
`send_queued_fin()` sends it at SND.NXT, advances SND.NXT past it, sets
`fin_sent` and runs the retransmission timer.  The application can therefore
call `tcp_close()` right after its last `tcp_send()` or `tcp_write()`; it
cannot write after it, since `tcp_write()` needs ESTABLISHED or CLOSE-WAIT.

The FIN is sent whatever the peer's window; it carries no data.  A receiver
that applies §3.10.7.4's step 1 strictly takes nothing into a zero window
(section 3.6); against such a peer the FIN is resent by the retransmission
timer rather than probed for, and counts toward `TCP_MAX_RETRANSMITS`.

The FIN is acknowledged only when `fin_sent` is set and SEG.ACK ≥ SND.NXT
(section 3.6, step 5).  In LISTEN, SYN-SENT and SYN-RECEIVED `tcp_close()` does
nothing; use `tcp_abort()`.

---

## 5. Timers

`tcp_tick(net, elapsed_ms)` advances `net->tcp_clock` (section 4.6) and runs
`conn_tick()` on every bound connection; `conn_tick()` skips a CLOSED one.

A connection runs one timer at a time.  `timer` says which —
`TCP_TIMER_RETRANSMIT`, `TCP_TIMER_PERSIST` or `TCP_TIMER_TIME_WAIT` — and
`timer_ms` counts down to it in milliseconds, 0 meaning stopped;
`net_countdown()` expires it at most once per tick, however large
`elapsed_ms` is.

| Field | Meaning |
|---|---|
| `timer_ms` | Until the running timer fires; 0 = stopped |
| `timer` | Which timer it is |
| `rto_ms` | The retransmission timeout |
| `retransmits` | Consecutive retransmission timeouts |
| `persist_ms` | The zero-window probe interval |

One countdown is enough because the three never need to run at once.
TIME-WAIT has nothing to send.  The persist timer starts only when nothing is
running, and while it runs the only byte in flight is its own probe, which it
resends itself.  Starting the retransmission timer replaces a pending probe
(`retransmit_timer_start()`), and entering TIME-WAIT replaces either.

### 5.1 Retransmission (REQ-TCP-090..098)

The retransmission timer covers everything that occupies sequence space and
is unacknowledged:

- A SYN or SYN,ACK starts it at `rto_ms` (`open_to()`, `listen_input()`, the
  simultaneous-open branch of `syn_sent_input()`).
- `send_data()` and `send_queued_fin()` start it if SND.UNA < SND.NXT and it
  is not already running (`retransmit_timer_run()`): RFC 6298 §5.1 starts the
  timer when a segment is sent and it is not running, and does not restart it
  for each segment.
- An ACK of new data restarts it (if running) while SND.UNA < SND.NXT and
  stops it otherwise (RFC 6298 §5.2, 5.3); stopping clears `retransmits`.
- Reaching ESTABLISHED or CLOSED stops it; entering TIME-WAIT replaces it.

A zero-window probe does not start it (section 5.2).  Because it follows
SND.NXT and not the driver's return value, a frame the driver did not take is
resent like one lost on the wire (section 4.3).

On expiry `retransmission_timeout()`:

1. stops the timer if nothing is outstanding — no data in flight
   (`in_flight()`), no unacknowledged FIN (`fin_sent` and SND.UNA < SND.NXT),
   not in SYN-SENT or SYN-RECEIVED;
2. gives up after `TCP_MAX_RETRANSMITS` (8) retransmissions: the next expiry
   resets the connection and raises `TCP_EVT_ERROR`;
3. doubles `rto_ms`, up to `NET_DEFAULT_TCP_RTO_MAX_MS`, and restarts the timer
   with it (REQ-TCP-096);
4. resends the earliest unacknowledged segment (REQ-TCP-095):
   - the SYN or SYN,ACK (`send_syn()`);
   - data: `resend_in_flight()` has `mark_retransmit()` offer the in-flight
     bytes again and sends exactly those, from SND.UNA with their original
     sequence numbers, **whatever the window**.  The peer's window accepted
     them once; if it has shrunk since — typically a partial ACK that also
     advertises zero — the retransmission serves as the probe (Linux does
     the same).  SND.NXT does not move, so a FIN already sent after the data
     keeps its sequence number.  The FIN is not resent with the data: when
     the data is acknowledged the timer is still running for the FIN, and
     the next expiry resends it;
   - otherwise the FIN alone, at SND.NXT − 1.

A peer that keeps its window at zero while data is in flight answers each
retransmission with an ACK of nothing new, which does not reset
`retransmits`, so the connection is given up after `TCP_MAX_RETRANSMITS`
like an unresponsive one.  Unsent data behind a zero window is different:
it is probed by the persist timer (section 5.2), which never gives up.

A partial ACK — one that covers only the first part of the segment in flight —
releases those bytes and restarts the timer.  The rest stay in flight at their
sequence numbers and are resent at the next expiry, from SND.UNA; the
stop-and-wait buffer never offers them as new data (it used to, and `flush()`
then sent them at SND.NXT, under the wrong sequence numbers).  Waiting costs a
timeout; peers seldom acknowledge part of a segment.

With the defaults (1 s initial RTO, 60 s maximum) the waits are 1, 2, 4, 8, 16,
32, 60, 60 and 60 s: a connection whose peer has gone is reset about four
minutes after the original transmission, within §3.8.3's R2 (at least 100 s,
three minutes for a SYN).  There is no RTT measurement (REQ-TCP-091, 099, 100),
so `rto_ms` starts at `NET_DEFAULT_TCP_RTO_INIT_MS` for every connection and
never decreases: after a loss the backed-off value stays for the rest of the
connection.

### 5.2 Zero-window probing (REQ-TCP-085..087)

`send_data()` starts the persist timer when min(SND.WND, `snd_mss`) is zero,
data is waiting to be sent and no timer is running; the first interval is
`NET_DEFAULT_TCP_RTO_INIT_MS`.  It stops when `send_data()` finds the window
open, when a probe finds nothing left to send, and whenever the connection
goes to CLOSED (`tcp_abort()`, a RST); the retransmission timer and TIME-WAIT
replace it.
It runs in whatever state it was started in: ESTABLISHED and CLOSE-WAIT, and
FIN-WAIT-1, CLOSING and LAST-ACK while data is still queued ahead of our FIN.

On expiry `probe_zero_window()` sends one byte past the window (§3.8.6.1).  If a
previous probe is still unacknowledged, SND.NXT goes back to SND.UNA and
`mark_retransmit()` makes the buffer offer the same byte, so a probe is the same
byte at the same sequence number until it is acknowledged.  If nothing is
queued the timer stops.  SND.NXT moves past the byte whether or not the driver
took the frame; the next probe sends it again.  The interval then doubles, up
to the maximum RTO: 1, 2, 4 … 60 s with the defaults.

A peer that has opened its window accepts the byte; its ACK advances SND.UNA,
and `send_side_ack()` takes the new window and flushes.  A peer that opens its
window without taking the byte sends a window update (SEG.ACK = SND.UNA): the
`flush()` after it stops the persist timer, finds the byte still in flight and
starts the retransmission timer, which resends it at the head of the next
segment.  A peer still at zero sends a duplicate ACK, which leaves the persist
timer running.

A probe starts no retransmission timer and does not count toward
`TCP_MAX_RETRANSMITS`, so probing continues as long as the window stays zero —
RFC 1122 §4.2.2.17 requires this while the peer answers, and no limit is
implemented for a peer that has stopped answering.  Our FIN is not probed
for: it is sent whatever the window and retransmitted like data
(section 4.7).

### 5.3 TIME-WAIT

`enter_time_wait()` replaces whatever timer was running with the 2×MSL wait
(`NET_DEFAULT_TCP_MSL_MS` is 2 minutes, so 4 minutes; REQ-TCP-008, 009).
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
| `TCP_EVT_WRITABLE` | `send_side_ack()` | An ACK acknowledged new data and the TX buffer has room |
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
`frame_send()`, the header size in `segment_room()` and so in both MSS values,
the default MSS (536 / 1220), and the connection id hashed into the ISS
(section 4.6).

A connection records its family in `ip_ver`, and `is_peer()` compares only
addresses of that family.  A listener has none until its SYN arrives, so it
accepts IPv4 and IPv6 peers alike.  Over IPv6 our address is the one the SYN
was sent to (passive open) or the one `ipv6_src_for()` picks — link-local for a
link-local peer, else a preferred global address, else a deprecated one
(active open; `tcp6_connect()` fails if none is usable).  It is stored as a slot
index, so the connection sends from whatever address that slot holds.
TCP is unicast only: `tcp_input()` drops a segment not sent to our IPv4
address (a broadcast or a joined group), and `tcp6_input()` one sent to a
multicast address (RFC 1122 §4.2.3.10).

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
| Data or FIN on a SYN | — | Not taken; the peer resends |

### 8.2 Behaviour that differs from RFC 9293

- RST in SYN-RECEIVED goes to CLOSED, not back to LISTEN (REQ-TCP-046).
- With RCV.WND zero the ACK field of a segment carrying data is not processed.
- `tcp_close()` does nothing in LISTEN, SYN-SENT or SYN-RECEIVED.
- A retransmitted FIN in TIME-WAIT is acknowledged but does not restart the
  2×MSL timer (section 3.6, step 5).
- A SYN cannot reopen a connection in TIME-WAIT; an in-window SYN resets it.
- `TCP_MAX_RETRANSMITS` is fixed at compile time and the application is not
  told of repeated retransmissions before the connection is given up (§3.8.3's
  R1).

### 8.3 Known gaps

- **A zero window after our FIN.**  The FIN is sent whatever the peer's
  window, and counts toward `TCP_MAX_RETRANSMITS`: a peer that holds its
  window at zero and drops the FIN has the connection reset after about four
  minutes, where unsent data in ESTABLISHED would be probed indefinitely.

---

## 9. Tests and files

- **Unit:** `tests/unit/test_tcp.c` (57 tests: handshakes, `tcp_write()` /
  `tcp_output()`, in-order delivery with gaps, overlaps, duplicates and FIN
  placement, window updates including pure ones, active and passive close,
  the FIN queued behind unsent data, RST, retransmission of SYN, data and FIN,
  partial ACKs, frames the driver did not send, TIME-WAIT, MSS from the RX
  and TX buffers, RFC 6528 initial sequence numbers, persist),
  `tests/unit/test_tcp6.c` (19: IPv6, dual-stack listeners, source address,
  MSS within the Ethernet MTU), `tests/unit/test_tcp_buf.c` (22: the
  stop-and-wait buffers).
- **Black-box:** `tests/blackbox/test_tcp_conform.py` (RFC 9293 conformance
  against a live stack over raw frames) and `tests/blackbox/test_tcp_fuzz.py`.

```
include/tcp.h, src/tcp.c             — the protocol
include/tcp_buf.h, src/tcp_buf_saw.c — buffer interface, stop-and-wait buffers
docs/requirements/tcp.md             — REQ-TCP-001..155
```
