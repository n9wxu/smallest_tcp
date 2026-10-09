# TCP Buffers — Design

**Files:** `include/tcp_buf.h` (the interface, stop-and-wait declarations), `src/tcp_buf_saw.c`  
**Requirements:** REQ-TCP-142..147 ([docs/requirements/tcp.md](../requirements/tcp.md))  
**Status:** stop-and-wait implemented; the ring and packet-list designs (section 5) are not

The protocol side is described in [tcp.md](tcp.md).  Section numbers with §
refer to RFC 9293.

---

## 1. Why an interface

A connection needs memory in two places: data it has sent, kept until the
peer acknowledges it (TX), and data it has received, kept until the
application reads it (RX).  What a target can afford differs by orders of
magnitude, and the best structure differs with it.  So `tcp.c` never manages
buffer memory (REQ-TCP-142).  Each connection is given two operation tables
and their contexts by `tcp_conn_init()`, and `tcp.c` goes through them for
everything it stores or fetches.  The implementation is chosen per
connection; each lives in its own source file, so a build links only the ones
it uses.

There is one implementation, stop-and-wait (`tcp_buf_saw.c`, REQ-TCP-145).
The ring buffer (REQ-TCP-146) and packet list (REQ-TCP-147) in section 5 are
designs only: `tcp_buf.h` declares neither.

---

## 2. Transmit: `tcp_txbuf_ops_t`

```c
typedef struct {
  uint16_t (*write)(void *ctx, const uint8_t *data, uint16_t len);
  uint16_t (*next_segment)(void *ctx, const uint8_t **data, uint16_t mss);
  void (*ack)(void *ctx, uint32_t bytes_acked);
  uint16_t (*in_flight)(const void *ctx);
  uint16_t (*queued)(const void *ctx);
  uint16_t (*writable)(const void *ctx);
  void (*mark_retransmit)(void *ctx);
  uint16_t (*copy_segment)(void *ctx, uint8_t *dst, uint16_t mss); /* optional */
} tcp_txbuf_ops_t;
```

Sequence numbers are not part of the interface.  `tcp.c` keeps SND.UNA and
SND.NXT, the buffer keeps bytes, and the two stay in step by these rules:

- The buffer's oldest byte is at SND.UNA.  `ack(n)` releases the n oldest
  bytes — never more than are in flight — and `tcp.c` advances SND.UNA by n.
- `next_segment()` returns the bytes after those already handed out, and
  `tcp.c` sends them at SND.NXT.  They stay in flight until acknowledged or
  until `mark_retransmit()`; the buffer never offers them again by itself.
- `mark_retransmit()` makes `next_segment()` start again at the oldest byte;
  `tcp.c` has set SND.NXT back to SND.UNA first.
- Our SYN and FIN occupy sequence numbers but are never in the buffer.

| Operation | Called by | Contract |
|---|---|---|
| `write` | `tcp_write()`, in ESTABLISHED and CLOSE-WAIT, with `len` > 0 | Copy in what fits; return the count, which may be less than `len` or 0 |
| `next_segment` | `send_data()` with min(SND.WND, `snd_mss`); `resend_in_flight()` with min(`in_flight()`, `snd_mss`), after `mark_retransmit`; `probe_zero_window()` with 1 | Return up to `mss` bytes, or 0 if nothing is ready; they are then in flight.  `*data` points into buffer memory and must stay valid until the next call into the buffer — `tcp.c` copies it into the frame at once |
| `ack` | `take_ack()`, when SEG.ACK advances SND.UNA; `bytes_acked` = SEG.ACK − SND.UNA | Release that many of the oldest bytes, capped at the bytes in flight: the count includes our FIN once the FIN is acknowledged, and bytes not yet sent must never be released.  Never called for the SYN |
| `in_flight` | `retransmission_timeout()`, `resend_in_flight()`, `probe_zero_window()`, `all_data_sent()` | Bytes handed out and not yet acknowledged.  `tcp.c` reads > 0 as "there is data to resend", and `in_flight()` = `queued()` as "all data has been sent" (the queued FIN may go) |
| `queued` | `tcp_tx_idle()`, `all_data_sent()` | Bytes written and not yet acknowledged, sent or not |
| `writable` | `send_side_ack()`, which raises `TCP_EVT_WRITABLE` when new data was acknowledged and it is > 0 | Room for `write` |
| `mark_retransmit` | `resend_in_flight()` (a retransmission timeout), `probe_zero_window()` (a probe still unacknowledged) | The next `next_segment()` returns the in-flight bytes again, from the oldest (REQ-TCP-095) |
| `copy_segment` (optional; NULL in a table without it) | In place of `next_segment`, wherever that is called (`take_segment()`) | As `next_segment`, but the bytes are copied to `dst` — the payload's place in the TX frame — instead of pointed at.  `next_segment` may then be NULL |

**A buffer whose data is not one contiguous run** (REQ-TCP-185).
`next_segment()` returns one pointer and one length, so a ring buffer can
offer only the bytes up to the end of its memory: every wrap makes a short
segment, and with one segment in flight each short segment is a round trip
— a 2,048-byte ring alternated segments of 1,460 and 588 bytes for the
whole of a download
([issue 4](https://github.com/n9wxu/smallest_tcp/issues/4)).  Such a
buffer gives `copy_segment()` instead: `tcp.c` hands it the place of the
payload in `net->tx.buf` and the buffer copies up to `mss` bytes there, in
as many pieces as it holds them.  The count of copies is unchanged — the
bytes went from the buffer into the frame before, too — and
`send_segment()` leaves the payload where it is.  Everything else in the
contract is the same: what is copied is in flight, `mark_retransmit()`
starts again at the oldest byte, and nothing is offered while anything is
in flight (below).  A table written positionally, without the new member,
still compiles (the member is NULL), though `-Wextra` warns of the missing
initializer.

One more rule, which comes from `tcp.c` rather than the interface:
**`next_segment()` must return 0 while anything is in flight.**  `send_data()`
limits a segment to min(SND.WND, MSS) without subtracting bytes in flight, and
sends at SND.NXT; both are right only when SND.NXT = SND.UNA
([tcp.md](tcp.md) section 4.3).  A buffer that allows more needs the `tcp.c`
changes listed in section 5.1.

`tcp.c` calls every operation without a NULL check.  `tcp_saw_tx_ops` is
initialised by position, so the order of the members matters; a new table is
safer with designated initialisers.

---

## 3. Receive: `tcp_rxbuf_ops_t`

```c
typedef struct {
  uint16_t (*deliver)(void *ctx, const uint8_t *data, uint16_t len);
  uint16_t (*read)(void *ctx, uint8_t *dst, uint16_t maxlen);
  uint16_t (*readable)(const void *ctx);
  uint16_t (*available)(const void *ctx);
} tcp_rxbuf_ops_t;
```

| Operation | Called by | Contract |
|---|---|---|
| `deliver` | `data_input()` | Store bytes; return the count taken.  They are always the next in-order bytes: `tcp.c` has skipped what was already received, trimmed to RCV.WND, and never offers data after a gap.  `data` points into the received frame and is valid only during the call.  RCV.NXT advances by the return value |
| `read` | `tcp_recv()` | Copy out up to `maxlen` bytes; return the count |
| `readable` | `open_window()` (from `data_input()` and `tcp_window_update()`) | Bytes waiting to be read |
| `available` | Connection set-up (`take_peer_syn()`, `open_to()`), `open_window()` | Free space: what the receive window is opened to (REQ-TCP-083) |

RCV.WND is never more than `available()` ([tcp.md](tcp.md) section 4.5),
which puts three constraints on an implementation:

- It shrinks only in `deliver()`, by what `deliver()` took.  The right edge of
  the advertised window then never moves back (§3.8.6 discourages shrinking
  the window), and `tcp.c` can rely on data trimmed to the last advertised
  window fitting.
- `available()` + `readable()` is the buffer size.  `open_window()` uses the
  sum for its silly-window step, min(buffer / 2, MSS) (§3.8.6.2.2).
- It is at most 65535: the window field is 16 bits and window scaling is not
  implemented.

---

## 4. Stop-and-wait: `tcp_buf_saw.c`

The application provides the memory and a context for each side and
initialises them with `tcp_saw_tx_init()` and `tcp_saw_rx_init()`; the shared
tables are `tcp_saw_tx_ops` and `tcp_saw_rx_ops` (quick start in
[tcp.md](tcp.md) section 2.3).  Each context is 12 bytes on Cortex-M0.

### 4.1 Transmit: one linear buffer

`tcp_saw_tx_ctx_t` holds `buf`, `capacity`, `data_len` (written, not yet
acknowledged) and `sent_len` (of those, the bytes sent: in flight).  The data
always starts at `buf[0]`, which is SND.UNA; the first `sent_len` bytes are in
flight and the rest are not yet sent.

- `write` returns 0 while anything is in flight (`sent_len` > 0); otherwise it
  appends up to `capacity − data_len`.
- `next_segment` returns nothing while anything is in flight or the buffer is
  empty; otherwise `buf` and min(`data_len`, `mss`), and sets `sent_len` to
  that length.  When the data exceeds the MSS or the window, only the first
  part is in flight; the rest is the next segment.
- `in_flight` is `sent_len`.
- `ack(n)` releases min(n, `sent_len`) bytes: `data_len` and `sent_len` shrink
  by that much and what is left moves to the front of the buffer.  n counts
  our FIN once it is acknowledged, and capping at `sent_len` means unsent
  data is never dropped.  When the whole segment is acknowledged and more
  data waits, that is the next segment, and the `flush()` that follows the
  ACK sends it at once.
- An ACK that covers only part of the segment in flight leaves the rest in
  flight (`sent_len` > 0), so `next_segment` still returns nothing: the rest
  is sent again only after `mark_retransmit`, at its original sequence
  numbers ([tcp.md](tcp.md) section 5.1).
- `mark_retransmit` sets `sent_len` to 0, so the same bytes, from `buf[0]`, are
  offered again.
- `queued` is `data_len`; `writable` is 0 while anything is in flight, else
  `capacity − data_len`.

Counting the bytes sent, rather than flagging that something was, is what
keeps the buffer in step with SND.NXT.  A flag would cover the whole buffer
and be cleared by any ACK: after a partial ACK the buffer would offer the
rest as a new segment, and `tcp.c` would send it at SND.NXT — past the bytes'
real sequence numbers — corrupting the stream.

The buffer is linear rather than a ring because the unacknowledged data then
always starts at `buf[0]`: `next_segment` returns one contiguous pointer with
no wrap to handle.  The price is a `memmove` of the remaining bytes when an ACK
releases part of the buffer.

### 4.2 Receive: a ring buffer

Nothing about the receive side is stop-and-wait: `tcp_saw_rx_ctx_t` (`buf`,
`capacity`, `write_pos`, `read_pos`, `data_len`) is a ring that takes any
number of segments up to its free space.  `capacity` is the largest window
advertised.

- `deliver` clamps to the free space and copies in at most two pieces: to the
  end of `buf`, then from its start.  `read` does the same in reverse.
- `ring_advance()` wraps a position with one comparison and subtraction.  The
  obvious `%` would link a library divide on Cortex-M0, which has no divide
  instruction ([size-comparison.md](size-comparison.md): 460 bytes).
- `available` is `capacity − data_len` and `readable` is `data_len`; their sum
  is `capacity`, as `tcp_window_update()` expects.

### 4.3 RAM and throughput

A connection costs its `tcp_conn_t` (104 bytes on Cortex-M0, 120 with IPv6),
two 12-byte contexts, and the TX and RX memory.  The frame buffers in `net_t`
are separate and shared by every connection.

**Sending** is one segment per round trip.  A segment is at most
min(TX capacity, the peer's MSS, what the TX frame buffer carries, the peer's
window) ([tcp.md](tcp.md) section 4.4), and the next one
leaves only when the previous one is acknowledged.  The round trip includes the
peer's ACK delay: with only one segment outstanding, a peer that delays
acknowledgements (§3.8.6.3 allows up to 500 ms; common stacks use tens to
hundreds of milliseconds) may hold every ACK for its full delayed-ACK time.  A
TX buffer larger than one segment lets the application hand over more at once;
the rest follows a segment per round trip, and the application can write again
once it has all been acknowledged (or sending stops at a zero window).

**Receiving** is not stop-and-wait.  Every segment is acknowledged at once, so
the peer can keep a whole receive window in flight — up to the RX capacity per
round trip, if the application reads promptly and calls
`tcp_window_update()`.  But out-of-order segments are dropped, so one lost
segment costs the peer a retransmission of everything it sent after it.

| TX / RX memory | RAM per connection (Cortex-M0, IPv4) | Sending, per round trip | Receiving, per round trip |
|---|---|---|---|
| 536 / 536 | 1,200 B | ≤ 536 B | ≤ 536 B |
| 1460 / 4096 | 5,684 B | ≤ 1,460 B | ≤ 4,096 B |

The trade: the smallest RAM of any design, at the cost of send throughput on
links with a long round trip.  For a device page, a TLS handshake or a
configuration API it is rarely the bottleneck; for bulk upload from the device
it is.

---

## 5. Future designs — not implemented

Nothing in this section exists in the code.  `tcp_buf.h` declares only the
stop-and-wait buffers.

### 5.1 Ring buffer (REQ-TCP-146)

- **TX:** a ring with three positions: the oldest unacknowledged byte
  (SND.UNA), the next byte to send (SND.NXT) and the end of the written data.
  `write` appends at the end, and keeps accepting while data is in flight;
  `next_segment` returns up to `mss` bytes from the send position (only up to
  the physical end of the ring, or it must copy); `ack` advances the oldest
  position; `mark_retransmit` moves the send position back to it.
- **RX:** the stop-and-wait receive ring (section 4.2) already is this.
- **Memory:** TX and RX capacity, chosen freely.  **Throughput:** limited by
  the peer's window and the congestion window rather than by one segment.

The buffer is the easy part.  Several segments in flight need `tcp.c` to
change first:

- `send_data()` must use the usable window, SND.UNA + SND.WND − SND.NXT, and
  keep sending while it and the buffer allow.
- Congestion control (RFC 5681: congestion window, slow start, congestion
  avoidance, REQ-TCP-101..105), which REQ-TCP-108 stands in for only with
  one segment in flight; fast retransmit and recovery (REQ-TCP-106, 107)
  need duplicate-ACK counting.
- Sender silly-window avoidance (REQ-TCP-089) and, with it, Nagle
  (REQ-TCP-129).
- Partial acknowledgements become normal.  The stop-and-wait buffer leaves the
  rest of a partly acknowledged segment in flight until a timeout; a ring must
  go on sending new bytes at SND.NXT, from its send position, while older ones
  are in flight, and go back to the oldest byte only on `mark_retransmit()`.
- Retransmission on a timeout: `resend_in_flight()` asks `next_segment()`
  for at most `in_flight()` bytes after `mark_retransmit()`, one segment from
  SND.UNA; a ring holding several segments in flight would resend only the
  first (or all of them, go-back-N) and must stop short of a FIN already
  sent.
- `probe_zero_window()` rewinds SND.NXT to SND.UNA whenever `in_flight()` is
  non-zero, which is right only when the one byte in flight is the probe.

The FIN already waits behind unsent data (§3.10.4, [tcp.md](tcp.md)
section 4.7): `all_data_sent()` compares `queued()` with `in_flight()`, which
works for any buffer.

### 5.2 Packet list (REQ-TCP-147)

- **TX:** the application provides a pool of nodes `{data pointer, length,
  next}`.  `write` queues a node that points at the application's own data,
  so constant pages in flash go out without a copy into RAM; that data must
  then stay valid until it is acknowledged.  `next_segment` returns a node, or
  part of one, up to `mss`; `ack` frees whole nodes and must handle an ACK that
  ends inside one; `mark_retransmit` goes back to the oldest node.
- **RX:** the same structure, or the ring.
- **Memory:** the node pool, sized by the application.  **Throughput:** as the
  ring.

It needs the same `tcp.c` changes as the ring.

---

## 6. Writing another implementation

- Fill every member of both tables.
- Keep the sequence rules of section 2; cap `ack()` at the bytes in flight.
- Return 0 from `next_segment()` while anything is in flight, until `tcp.c`
  supports more (section 5.1).
- Shrink `available()` only in `deliver()`, keep `available()` + `readable()`
  constant, and stay within 65535.
- Run `tests/integration/itest_tcp.c` with the new tables
  (`itest_tcp_142_buffers_through_their_operations` drives the stack with
  buffers of its own), and write the equivalent of
  `tests/unit/test_tcp_buf.c` for the buffer itself.
