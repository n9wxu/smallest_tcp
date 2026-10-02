# TFTP Client Design

**Protocol:** RFC 1350 (TFTP revision 2), RFC 2347 (option extension), RFC 2348 (blksize option), RFC 1123 §4.2 (host requirements)  
**Files:** `include/tftp.h`, `src/tftp.c`; `net_text.h` / `net_text.c` for the ASCII helpers  
**Requirements:** [tftp.md](../requirements/tftp.md)  
**Status:** Implemented (read requests over IPv4)

---

## 1. Scope

The primary use is a bootloader or firmware updater fetching an image:
the file arrives one block at a time through a callback that can write it
straight to flash, so the stack never holds more than one block.

| Feature | Status |
|---|---|
| Read request (RRQ), `octet` mode | ✅ |
| `netascii` mode (`tftp_client_set_mode()`), converted to local newlines | ✅ |
| blksize option (RFC 2348), sized to the RX buffer | ✅ |
| Server transfer ID (port) tracking, ERROR 5 to a stray datagram's source | ✅ |
| Duplicate blocks re-acknowledged, block-number wrap | ✅ |
| Malformed packets dropped: truncated DATA and ERROR, DATA longer than a block, an OACK with an unterminated string | ✅ |
| Retransmission of RRQ and last ACK with an adaptive timeout (RFC 1123), give-up after 5 | ✅ |
| Write request (WRQ) | — |
| tsize and timeout options (RFC 2349), windowsize (RFC 7440) | — |
| IPv6 | — |
| TFTP server | — |

---

## 2. Integration and Memory

The client is integrated like every protocol module
([integrating-modules.md](../integrating-modules.md)): an
application-owned `tftp_client_t`, `tftp_client_init()` with the local UDP
port and two callbacks, a UDP handler on that port that passes its
payload pointer to `tftp_client_input()`, `tftp_client_get()` to start a
transfer, and `tftp_client_tick()` from the main loop.

```c
static tftp_client_t tftp;

static void on_data(uint16_t block, const uint8_t *data, uint16_t len, void *ctx) {
  flash_write(block, data, len);          /* data is valid during the call only */
}
static void on_done(uint8_t ok, uint16_t err_code, const char *msg, void *ctx) { ... }

static void tftp_udp(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *payload, uint16_t len) {
  tftp_client_input(n, &tftp, src_ip, src_mac, src_port, payload, len);
}
static const udp_port_entry_t udp_ports[] = {{50000, tftp_udp}};

udp_set_ports(&net, udp_ports, 1);
tftp_client_init(&tftp, 50000, on_data, on_done, NULL);
tftp_client_get(&net, &tftp, server_ip, server_mac, "firmware.bin", 1);
/* main loop: net_poll(), net_tick(), tftp_client_tick(&net, &tftp, elapsed_ms) */
```

`tftp_client_t` is 188 bytes on a 32-bit target, 128 of them the copy of
the file name (`TFTP_MAX_FILENAME`; a longer name is cut to 127
characters).  There is no other state and no allocation.

The server's MAC is passed in, already resolved (REQ-TFTP-035; see
[arp-resolution.md §3](arp-resolution.md#3-resolving-a-mac-for-an-active-open)):
the client does no ARP of its own, and every packet it sends to the server
goes to that MAC, including those to the server's transfer port — which is
the same host (REQ-TFTP-036).  The one packet for another host, ERROR 5 for
a stray datagram (§6), goes to the source MAC of the frame it answers, which
is why `tftp_client_input()` takes `src_mac`.

---

## 3. Protocol Flow

Without options (`blksize_opt` = 0, or the RX buffer gives exactly 512):

```
Client (local_port)                         Server
  RRQ "file" "octet"          ──► port 69
                              ◄── DATA 1 [512 bytes]     from the server's TID
  ACK 1                       ──► TID
                              ◄── DATA 2 [512 bytes]
  ACK 2                       ──►
   …
                              ◄── DATA n [0..511 bytes]   shorter than blksize: last
  ACK n                       ──►                          on_done(ok = 1)
```

With the blksize option (RFC 2347, RFC 2348):

```
  RRQ "file" "octet" "blksize" "<N>"  ──► port 69
                                      ◄── OACK "blksize" "<M>"    M ≤ N
  ACK 0                               ──► TID
                                      ◄── DATA 1 [M bytes]
  ACK 1                               ──►
   …
```

An OACK without `blksize` declines it, and the blocks are 512 bytes.  An
OACK that raises the block size, lowers it below 8, or answers a
`blksize` the RRQ did not ask for is refused (§5):

```
  RRQ "file" "octet" "blksize" "<N>"  ──► port 69
                                      ◄── OACK "blksize" "<M>"    M > N or M < 8
  ERROR 8 "Bad blksize"               ──► TID                      on_done(ok = 0, 8, "Bad blksize")
```

A server that does not support options ignores them and answers with
DATA 1; the client then falls back to 512-byte blocks (REQ-TFTP-031).  A
server that refuses the transfer answers with ERROR, which ends it:

```
  RRQ "nofile" "octet"        ──► port 69
                              ◄── ERROR 1 "File not found"   on_done(ok = 0, 1, "File not found")
```

An ERROR (or DATA) shorter than 4 bytes, too short for its code (or block
number), is dropped before it counts for anything (`truncated()`) — it
does not fix the server's transfer ID or restart the timer.  Taking it
for ERROR 0 would repair a malformed packet, and the coding rules say
"reject, don't repair"
([coding-rules.md §3](coding-rules.md#3-parsing-received-data)).

`on_done` receives the server's message only if its NUL lies within the
datagram (`error_message()`, REQ-TFTP-017); otherwise it receives `""`.
The message is a pointer into the receive buffer, so an unterminated one
would send the application reading past the datagram — and the client
cannot terminate it in place, because the receive buffer is read-only to
parsers ([coding-rules.md §3](coding-rules.md#3-parsing-received-data)).

---

## 4. State Machine

```
IDLE ── tftp_client_get() ──► REQUESTING ── OACK (sends ACK 0) ──► RECEIVING
                                   │        DATA (512-byte blocks) ──►   │
                                   │                                     │ short DATA block
                                   │                                     ▼
                                   │                                    DONE
                                   ├── OACK refused (sends ERROR 8) ──► ERROR
                                   └── ERROR, or 5 retransmissions ──► ERROR ◄── (same, from RECEIVING)
```

`finish()` enters DONE or ERROR, stops the timer and calls `on_done`.
Input and ticks are ignored outside REQUESTING and RECEIVING: once the
last block is acknowledged the client answers nothing more, so it does
not dally to repeat a lost final ACK (RFC 1350 §6, REQ-TFTP-043).
`tftp_client_get()` refuses (`NET_ERR_INVALID_PARAM`) while a transfer is
running and restarts from IDLE, DONE or ERROR.

---

## 5. Block Size

**Requested size.**  With `blksize_opt` = 1, `largest_blksize()` asks for
the largest block the **RX** buffer holds: `net->rx.capacity` minus the
Ethernet, IPv4, UDP and 4-byte TFTP DATA headers (46 bytes), clamped to
8 … 1468.  1468 is the largest DATA payload in one 1500-byte Ethernet
frame; 8 is the RFC 2348 minimum.  The RX buffer decides, not the TX
buffer: DATA blocks arrive in the RX buffer, and a block that does not
fit it is lost (`net_poll()` truncates the frame, and IPv4 drops it).

The option is sent only when the size differs from 512, so a 558-byte RX
buffer sends a plain RRQ.  A smaller RX buffer makes the client ask for
*smaller* blocks — which is why `blksize_opt` = 1 is the right choice for
any buffer below 558 bytes: with `blksize_opt` = 0 the RX buffer must
hold a 512-byte block, 558 bytes.

**Formatting.**  The size is written in decimal by `net_u32_to_dec()`
(`net_text.c`), which subtracts powers of ten instead of dividing:
Cortex-M0 has no divide instruction, and `%` or `/` would link a software
division routine.

**OACK.**  `oack_input()` starts from a block size of 512.  An OACK
lists only the options the server accepted (RFC 2347), so one without
`blksize` declines it, and the server sends 512-byte blocks.  Keeping
the requested size instead would make the first 512-byte block look
short: the transfer would end after it, truncated but reported as a
success.

It then walks the name/value pairs to the end of the datagram
(`next_string()` returns NULL for a string without its NUL).  An OACK
whose last name or value is unterminated, or whose last name has no
value, is malformed: it is dropped whole — no block size set, no ACK 0,
the state unchanged — like every malformed packet.  An option named
`blksize` — compared in full and case-insensitively with
`net_equal_nocase()` — sets the block size if `acceptable_blksize()`: at
least 8, and no more than the size requested.  `parse_decimal()` takes a
value only if it is all digits: anything else — "512abc", an empty
string, a leading space — reads as 0 and is refused.  Digits past 65464
stop the reading, so a long string cannot overflow, and read as 0 too.
Any other option is refused with ERROR 8 "Option not requested":
RFC 2347 lets a server acknowledge only the options the client
requested, and this one requests blksize alone.  With every pair taken,
the client sets the block size, enters RECEIVING and sends ACK 0.

Any other `blksize` — larger, below 8, empty or not a number (which
reads as 0), or one the RRQ did not ask for — is refused by
`refuse_oack()`.  The RRQ asks only for a size other than 512
(`blksize_requested()`); when it did not ask, the size requested counts
as 0, so every `blksize` is refused: RFC 2347 lets the server
acknowledge only the options the client requested.  A refusal is
ERROR 8 "Bad blksize" to the server, as RFC 2347 prescribes for an OACK
the client does not accept, and
`on_done(0, TFTP_ERR_OPTION_NEGOTIATION, "Bad blksize")`.  RFC 2348
lets the server only lower the size; a larger block might not fit the RX
buffer, which is what the size requested was chosen for.  Ignoring a bad
value and keeping the requested size is worse than refusing it: the
server sends blocks of the size it announced, and the first one shorter
than the client expects ends the transfer as if it were the last.

**Repeated OACK.**  If ACK 0 is lost, the server sends its OACK again.
In RECEIVING, an OACK that arrives while `next_block` is still 1 — no
DATA yet — is answered with ACK 0 again; its options are not parsed a
second time.  The retransmission timer would resend ACK 0 too, but only
when it runs out (§8); answering the repeat gets the transfer going a
timeout sooner.  The repeated ACK 0 makes the next round trip ambiguous,
so it is not measured (§8, Karn's rule).  Once DATA 1 has arrived, an
OACK is ignored.

**Fallback.**  DATA in REQUESTING means the server ignored the option:
the block size returns to 512 and the block is processed as usual
(REQ-TFTP-031).

The block size is what decides the last block: a DATA payload shorter
than it ends the transfer.  A DATA payload longer than it is not a block
and is dropped (§7).

---

## 6. Transfer IDs

A TFTP transfer is identified by the two UDP ports (RFC 1350 §4).  Ours is
the fixed `local_port` given to `tftp_client_init()`.  The server's is
unknown until it answers from a new port:

- `server_port()` returns port 69 until then, the server's port after.
  The RRQ always goes to 69; ACKs and ERROR 8 go to `server_port()`
  (REQ-TFTP-015).
- The first DATA, OACK or ERROR from the server's IP fixes
  `server_tid` (REQ-TFTP-006).
- A datagram from port 0 is dropped outright.  Port 0 says no reply is
  wanted (RFC 768), so it cannot be a transfer ID — and `server_tid` uses 0
  for "none yet", so a TID of 0 would look like a server that had not
  answered: its ACKs would go to port 69 and any later port would become
  its TID.  It gets no ERROR 5 either, having asked for no reply.
- Any other datagram — another IP, another port, or, before the server
  has answered, an opcode that cannot be its answer — is a stray
  (`from_server_tid()` is false).  `reject_stray()` sends ERROR 5
  "Unknown transfer ID" back to its source — its IP, port, and the source
  MAC of its frame — and nothing else changes: the transfer continues
  and the timer is not restarted (RFC 1350 §4, REQ-TFTP-018).  Sending
  it to the server's port instead would end a good transfer: a stray
  port typically comes from a duplicate RRQ that the server answered
  twice, and the server treats an ERROR on the transfer's port as fatal.
- A stray ERROR is dropped without an answer: two peers that each took
  the other's packets for strays would otherwise exchange ERRORs
  forever.

---

## 7. Data Blocks

`data_input()` handles DATA of at least 4 bytes:

- **More than a block** (REQ-TFTP-041): a payload longer than the block
  size in force — 512 while the RRQ is unanswered, then the OACK's — is
  dropped: not delivered, not acknowledged, the state unchanged.
  `on_data` therefore never sees more than `blksize` bytes, which an
  application may have sized a sector buffer by.
- **The expected block** (`next_block`, starting at 1): `on_data` is
  called with the payload (a pointer into `net->rx.buf`, valid during the
  call), then the ACK is sent — after the callback, so the application
  may use `net->tx.buf` inside it.  A payload shorter than the block
  size ends the transfer with `on_done(1, 0, "")`; a file whose size is a
  multiple of the block size ends with an empty block, and `on_data` is
  called with `len` 0 for it (in octet mode; netascii delivers no empty
  piece).
- **The previous block**: the server did not get our ACK and sent the
  block again; the ACK is repeated and nothing is delivered twice
  (REQ-TFTP-013).
- **Any other block number**: dropped.

**netascii** (REQ-TFTP-004, RFC 1350 §2, RFC 1123 §4.2.4).
`tftp_client_set_mode(c, TFTP_MODE_NETASCII)`, after `tftp_client_init()`
and before `tftp_client_get()`, asks for `netascii` instead of `octet`
and converts the text to local newlines on the way to `on_data`, with no
buffer: `deliver_netascii()` hands over each run of plain bytes as it
is, then CR LF as `'\n'`, CR NUL as `'\r'` and a bare CR (which a
correct server never sends) as itself, so `on_data` may be called
several times for one block.  A CR that ends a block is held
(`cr_pending`) until the next block's first byte decides it — or, at the
end of the file, delivered as it is.

**Wrap.**  `next_block` is a `uint16_t` and wraps from 65535 to 0, the
common convention; RFC 1350 leaves it undefined, and a server that wraps
to 1 instead stalls a file of more than 65535 blocks (32 MB at 512
bytes).  "Previous block" and the retransmitted ACK are computed modulo
2¹⁶ as well, so after the wrap a duplicate of block 65535 is still
recognised and the last ACK resent is 65535.

---

## 8. Messages and Retransmission

RRQ, ACK and ERROR are built in place at `UDP_PAYLOAD_OFFSET` in
`net->tx.buf` and sent with `udp_send_inplace()` (IP TTL
`NET_DEFAULT_TTL`), with no buffer of their own on the stack.

| Message | Function | Size | TX buffer needed |
|---|---|---|---|
| RRQ | `send_rrq()` | 2 + name + 1 + mode + 1 [+ 8 + digits + 1] | at most 194 bytes (127-char name, `netascii`, blksize option) |
| ACK | `send_ack()` | 4 | 46 bytes |
| ERROR | `put_error()`, sent by `reject_stray()` and `refuse_oack()` | 5 + text (a constant: "Unknown transfer ID", "Bad blksize", "Option not requested") | at most 67 bytes |

Each checks its own size: `send_rrq()` and `send_ack()` return
`NET_ERR_BUF_TOO_SMALL` instead of sending, and an ERROR that does not
fit (`put_error()` returns 0) is not sent.  `tftp_client_get()` returns
the result of the first RRQ, but the transfer is REQUESTING either way,
so a failed first send is retried by the timer.

**Retransmission** (`tftp_client_tick()`).  One timer runs in
REQUESTING and RECEIVING.  Progress restarts it and clears the retry
count (`made_progress()`): an OACK the client takes, or the DATA block it
expects next.  Nothing else from the server does — a duplicate block
(answered with its ACK again), a repeated OACK, an opcode the client
ignores — so a server that keeps resending what it has sent, never
getting our ACK, is given up on like a silent one.
When it runs out, REQUESTING resends the RRQ and RECEIVING resends the
last ACK (`next_block − 1`, which is ACK 0 after an OACK); after
`TFTP_MAX_RETRIES` (5) retransmissions without an answer the transfer
ends with `on_done(0, 0, "Timeout")`.
The server's own retransmissions drive a lock-step transfer forward just
as well: the client answers each duplicate block.

**The timeout adapts** (RFC 1123 §4.2.3.2: "A TFTP implementation MUST
use an adaptive timeout ... At least an exponential backoff of
retransmission timeout is necessary").  `rto_ms` follows the round
trips measured, as RFC 6298 §2 does for TCP:

- **A round trip** is the time from sending the RRQ or an ACK to the
  progress it brings — the OACK or DATA 1, the next DATA block —
  `rto_ms − timer_ms` when it arrives, since the timer counts down from
  `rto_ms`.  Karn's rule: it counts only if what it answers went once
  (`resent` clear); an answer to a packet sent twice — by the timer, or
  an ACK repeated for a duplicate block or OACK — could be to either.
- **The estimate** (`rtt_sample()`): SRTT and RTTVAR with RFC 6298's
  gains of 1/8 and 1/4, kept scaled — `srtt8` = 8 × SRTT, `rttvar4` = 4 ×
  RTTVAR, in milliseconds, as BSD keeps them — so each update is a shift
  and a subtraction, with no division (Cortex-M0 has none,
  [coding-rules.md §4](coding-rules.md#4-no-run-time-division)).  The
  first sample sets SRTT to it and RTTVAR to half of it.  RTO = SRTT +
  max(G, 4 × RTTVAR) — `srtt8 >> 3` plus `rttvar4`, at least G = 100 ms
  over SRTT, RFC 6298's clock granularity, so a perfectly steady round
  trip does not meet its own timeout — then held within
  `TFTP_RTO_MIN_MS` (1 s, RFC 6298's minimum) and `TFTP_RTO_MAX_MS`
  (16 s).
- **Backoff**: each retransmission doubles `rto_ms`, up to
  `TFTP_RTO_MAX_MS` (RFC 6298 §5.5); the next valid round trip sets it
  from the estimate again.
- **Start**: each transfer starts from `TFTP_TIMEOUT_MS` (3 s) and no
  estimate (RFC 6298 §2.1); a server's round trips are not carried over.

On a LAN the timeout falls to 1 s after the first round trip, so a lost
block costs a second, not three.  A server slower than 3 s draws one
retransmitted RRQ, then a timeout above its round trip: 4 s round trips
give 12 s, then less as RTTVAR settles.  A silent server is given up on
after 3 + 6 + 12 + 16 + 16 + 16 = 69 s (5 retransmissions); a smaller
`TFTP_RTO_MAX_MS` lowers that.  A fixed 3 s timeout would be slower
than needed on a LAN, and on a path whose round trip exceeds 3 s it
would send every block twice.

---

## 9. Deviations and Known Limitations

| Item | Notes |
|---|---|
| Fixed local port for every transfer (REQ-TFTP-042) | RFC 1350 §4 asks for a random TID per transfer; a late datagram from a previous transfer's server port can be taken as the next transfer's first answer |
| No dallying after the final ACK (REQ-TFTP-043) | RFC 1350 §6 encourages the receiver to stay a while and repeat the final ACK if the last block comes again; the client is DONE on sending it and answers nothing more.  The file is complete either way; a server that missed the ACK repeats the last block until it gives up |
| A file name of more than 127 characters is cut | `tftp_client_get()` copies at most `TFTP_MAX_FILENAME` − 1 characters and requests that name |
| No tsize, timeout or windowsize options; no WRQ | Scope (§1).  Without WRQ the client never sends DATA, so RFC 1123 §4.2.3.1's Sorcerer's Apprentice fix (REQ-TFTP-040: never resend DATA on a duplicate ACK) has nothing to apply to |
| IPv4 only | `tftp_client_input()` and the send path take IPv4 addresses |

---

## 10. Tests

`tests/integration/itest_tftp.c` (black box, through `tftp_client_*` and
a server on the scripted wire) verifies every implemented row of
[tftp.md](../requirements/tftp.md): the RRQ byte for byte, to port 69 at
the server's MAC, and one too long for the TX buffer; netascii with a CR
at a block boundary; DATA 1 fixing the server's port and every ACK going
there; a short or empty last block; only the next block taken, across
the wrap of the block number; a duplicate block acknowledged and not
delivered; DATA longer than a block dropped; ERROR with each code of
RFC 1350, an unterminated message, truncated packets; port 0; ERROR 5 to
a stray port or host, none for a stray ERROR; the timeout doubling to
its ceiling, falling to 1 s for a fast server, growing past a slow
server's round trip, restarted by progress alone; the give-up after 5
retransmissions; the blksize asked for by RX buffer size; an OACK
acknowledged with ACK 0, repeated, refused (larger, below 8, not a
number, not requested, another option), without blksize, malformed; the
fallback when the server ignores the option.

`demo/tftp_client` fetches a file from a real server (e.g. dnsmasq with
`--enable-tftp`) with blksize negotiation.
