# TFTP Client Design

**Protocol:** RFC 1350 (TFTP revision 2), RFC 2347 (option extension), RFC 2348 (blksize option)  
**Files:** `include/tftp.h`, `src/tftp.c`; `net_text.h` / `net_text.c` for the ASCII helpers  
**Requirements:** [tftp.md](../requirements/tftp.md)  
**Status:** Implemented (read requests over IPv4)  
**Last updated:** 2026-09-27

---

## 1. Scope

The primary use is a bootloader or firmware updater fetching an image:
the file arrives one block at a time through a callback that can write it
straight to flash, so the stack never holds more than one block.

| Feature | Status |
|---|---|
| Read request (RRQ), `octet` mode | ✅ |
| blksize option (RFC 2348), sized to the RX buffer | ✅ |
| Server transfer ID (port) tracking, ERROR 5 to a stray datagram's source | ✅ |
| Duplicate blocks re-acknowledged, block-number wrap | ✅ |
| Retransmission of RRQ and last ACK, give-up after 5 | ✅ |
| Write request (WRQ), `netascii` mode | — |
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

`tftp_client_t` is 172 bytes on a 32-bit target, 128 of them the copy of
the file name (`TFTP_MAX_FILENAME`, longer names are truncated).  There
is no other state and no allocation.

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

With the blksize option (RFC 2347 §4, RFC 2348):

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
Input and ticks are ignored outside REQUESTING and RECEIVING.
`tftp_client_get()` refuses (`NET_ERR_INVALID_PARAM`) while a transfer is
running and restarts from IDLE, DONE or ERROR.

---

## 5. Block Size

**Requested size.**  With `blksize_opt` = 1, `largest_blksize()` asks for
the largest block the **RX** buffer holds: `net->rx.capacity` minus the
Ethernet, IPv4, UDP and 4-byte TFTP DATA headers (46 bytes), clamped to
8 … 1468.  1468 is the largest DATA payload in one 1500-byte Ethernet
frame; 8 is the RFC 2348 minimum.  It used to be derived from the TX
capacity, a latent bug: DATA blocks arrive in the RX buffer, and a
device with a large TX and a small RX buffer asked for blocks it then
could not receive (`net_poll()` truncates a frame that does not fit, and
IPv4 drops it).

The option is sent only when the size differs from 512, so a 558-byte RX
buffer sends a plain RRQ.  A smaller RX buffer makes the client ask for
*smaller* blocks — which is why `blksize_opt` = 1 is the right choice for
any buffer below 558 bytes: with `blksize_opt` = 0 the RX buffer must
hold a 512-byte block, 558 bytes.

**Formatting.**  The size is written in decimal by `net_u32_to_dec()`
(`net_text.c`), which subtracts powers of ten instead of dividing:
Cortex-M0 has no divide instruction, and `%` or `/` would link a software
division routine.

**OACK.**  `oack_input()` first sets the block size to 512.  An OACK
lists only the options the server accepted (RFC 2347), so one without
`blksize` declines it, and the server sends 512-byte blocks.  Keeping
the requested size instead would make the first 512-byte block look
short: the transfer would end after it, truncated but reported as a
success.

It then walks the name/value pairs (`next_string()` stops at the first
unterminated string).  An option named `blksize` — compared in full and
case-insensitively with `net_equal_nocase()`; the old parser looked only
at the first two letters — sets the block size if
`acceptable_blksize()`: at least 8, and no more than the size requested.
`parse_decimal()` takes a value only if it is all digits: anything else
— "512abc", an empty string, a leading space — reads as 0 and is refused;
it used to read the digits in front and ignore the rest, so "512abc" was
512.  Digits past 65464 stop the reading, so a long string cannot
overflow, and read as 0 too.  Other options are ignored.  The client then enters
RECEIVING and sends ACK 0.

Any other `blksize` — larger, below 8, empty or not a number (which
reads as 0), or one the RRQ did not ask for — is refused by
`refuse_oack()`.  The RRQ asks only for a size other than 512
(`blksize_requested()`); when it did not ask, the size requested counts
as 0, so every `blksize` is refused: RFC 2347 lets the server
acknowledge only the options the client requested.  A refusal is
ERROR 8 "Bad blksize" to the server, as RFC 2347 prescribes for an OACK
the client does not accept, and
`on_done(0, TFTP_ERR_OPTION_NEGOTIATION, "Bad blksize")`.  RFC 2348 §2
lets the server only lower the size; a larger block might not fit the RX
buffer, which is what the size requested was chosen for.  Ignoring a bad
value and keeping the requested size, as the client once did for one
below 8, is worse than refusing it: the server sends blocks of the size
it announced, and the first one shorter than the client expects ends the
transfer as if it were the last.

**Repeated OACK.**  If ACK 0 is lost, the server sends its OACK again.
In RECEIVING, an OACK that arrives while `next_block` is still 1 — no
DATA yet — is answered with ACK 0 again; its options are not parsed a
second time.  Answering matters even though the retransmission timer
would resend ACK 0 on its own: every datagram from the server restarts
that timer (§8), so a server that repeats its OACK more often than
every 3 s would otherwise never hear ACK 0, and the transfer would stall
until the server gave up.  Once DATA 1 has arrived, an OACK is ignored.

**Fallback.**  DATA in REQUESTING means the server ignored the option:
the block size returns to 512 and the block is processed as usual.

The block size is what decides the last block: a DATA payload shorter
than it ends the transfer.

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

- **The expected block** (`next_block`, starting at 1): `on_data` is
  called with the payload (a pointer into `net->rx.buf`, valid during the
  call), then the ACK is sent — after the callback, so the application
  may use `net->tx.buf` inside it.  A payload shorter than the block
  size ends the transfer with `on_done(1, 0, "")`; a file whose size is a
  multiple of the block size ends with an empty block, and `on_data` is
  called with `len` 0 for it.
- **The previous block**: the server did not get our ACK and sent the
  block again; the ACK is repeated and nothing is delivered twice
  (REQ-TFTP-013).
- **Any other block number**: dropped.

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
`NET_DEFAULT_TTL`); they used to be built in stack buffers of up to 256
bytes and copied.

| Message | Function | Size | TX buffer needed |
|---|---|---|---|
| RRQ | `send_rrq()` | 2 + name + 1 + 6 [+ 8 + digits + 1] | at most 191 bytes (127-char name, blksize option) |
| ACK | `send_ack()` | 4 | 46 bytes |
| ERROR | `put_error()`, sent by `reject_stray()` | 5 + text (at most 119 characters) | 66 bytes for "Unknown transfer ID" |

Each checks its own size: `send_rrq()` and `send_ack()` return
`NET_ERR_BUF_TOO_SMALL` instead of sending, and an ERROR that does not
fit (`put_error()` returns 0) is not sent.  `tftp_client_get()` returns
the result of the first RRQ, but the transfer is REQUESTING either way,
so a failed first send is retried by the timer.

**Retransmission** (`tftp_client_tick()`).  One timer of `TFTP_TIMEOUT_MS`
(3 s) runs in REQUESTING and RECEIVING; every datagram from the server's
transfer ID (§6), any opcode, restarts it and clears the retry count.
When it runs out, REQUESTING resends the RRQ and RECEIVING resends the
last ACK (`next_block − 1`, which is ACK 0 after an OACK); after
`TFTP_MAX_RETRIES` (5) retransmissions without an answer the transfer
ends with `on_done(0, 0, "Timeout")` — 18 s of silence in all.
The server's own retransmissions drive a lock-step transfer forward just
as well: the client answers each duplicate block.

---

## 9. Deviations and Known Limitations

| Item | Notes |
|---|---|
| Fixed local port for every transfer | RFC 1350 asks for a random TID per transfer; a late datagram from a previous transfer's server port can be taken as the next transfer's first answer |
| No tsize, timeout or windowsize options; no WRQ; no netascii | Scope (§1) |
| IPv4 only | `tftp_client_input()` and the send path take IPv4 addresses |

---

## 10. Tests

`tests/unit/test_tftp.c` (24 tests): RRQ format and default block size,
DATA 1 → ACK 1 to the server's port, full block not last, short block
ends the transfer, duplicate block re-acknowledged, ERROR aborts with
its message and an unterminated message is reported as `""`, ERROR 5
to a stray port or host and none for a stray ERROR, OACK sets the block
size and draws ACK 0, a repeated OACK draws ACK 0 again until DATA 1,
an OACK blksize above the one requested, below 8 or not requested at
all, or not a number ("512abc"), draws ERROR 8 and ends the transfer, an OACK without blksize means
512-byte blocks, fallback when the server ignores the option, blksize
option in the RRQ, RRQ and ACK retransmission, give-up after the maximum
retries, timer restart on DATA.

`demo/tftp_client` fetches a file from a real server (e.g. dnsmasq with
`--enable-tftp`) with blksize negotiation.
