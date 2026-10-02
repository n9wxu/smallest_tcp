# DTLS 1.3 — Design

**Protocol:** Datagram Transport Layer Security 1.3 (RFC 9147)  
**Builds on:** [tls.md](tls.md) — the TLS 1.3 handshake, key schedule and crypto backend  
**Files:**

| File | Contents |
|---|---|
| `include/dtls.h`, `src/dtls.c` | The datagram record layer: `dtls_conn_t`, `dtls_init()`, datagrams in and out, epochs, record number encryption, replay protection, handshake fragmentation and reassembly, flights, the retransmission timer, ACKs, KeyUpdate, the API |
| `src/tls_common.c` | What the TLS stream layer (`tls.c`) and the DTLS datagram layer share: handshake message framing, the record-layer interface, installing traffic keys, post-handshake messages, alerts received, failing a connection |
| `src/tls_server.c`, `src/tls_client.c` | The handshake of each role, for both protocols |
| `include/tls_crypto.h` | The crypto backend, with one addition for DTLS: `aes_block` |

**Requirements:** [docs/requirements/dtls.md](../requirements/dtls.md) (REQ-DTLS-001..073)  
**Interoperates with:** wolfSSL 5.9.4, in both roles

---

## 1. Scope

DTLS 1.3 is TLS 1.3 over datagrams: the same handshake messages, key
schedule and cipher suite, with a record layer that survives loss,
reordering and duplication.  Its uses here are the constrained-device ones —
CoAP over DTLS (CoAPS, UDP port 5684), secure telemetry, device-to-device
links — where a TCP connection per peer costs more than the device can give.

| | |
|---|---|
| Version | DTLS 1.3 only (RFC 9147).  A DTLS 1.2 peer gets `protocol_version`, as a TLS 1.2 peer does |
| Everything TLS 1.3 negotiates | As [tls.md §1](tls.md#1-scope): `TLS_AES_128_GCM_SHA256`, x25519 and secp256r1 with HelloRetryRequest, ECDSA P-256 and RSA-PSS certificates, pre-shared keys (psk_dhe_ke, psk_ke), max_fragment_length, KeyUpdate, close_notify |
| Roles | Client and server; as with TLS, a build links only the roles it calls |
| Records | DTLSPlaintext for epoch 0; DTLSCiphertext with the unified header and record number encryption for the rest; several records per datagram |
| Reliability | Flights, a retransmission timer (1 s doubling to 60 s), ACKs, handshake fragmentation to the datagram size and reassembly of overlapping fragments |
| DoS | The server's cookie exchange, on by default |
| Transport | Anything that carries datagrams; the application moves them (`dtls_input()`, `dtls_pending()`), as it moves TLS ciphertext |

Not implemented: Connection IDs (RFC 9146, and the `connection_id`
extension a client SHOULD offer), 0-RTT (epoch 1), DTLS 1.2, issuing
session tickets, post-handshake client authentication, retransmitting only
the part of a flight an ACK leaves unacknowledged (the timer resends the
flight), backing off to smaller records when the PMTU is unknown, and a
retransmission timer that follows the measured round-trip time.
Everything TLS 1.3 leaves out ([tls.md §1](tls.md#1-scope)) DTLS leaves
out too.

---

## 2. What changes from TLS, and what does not

RFC 9147 §5: "With these exceptions, the DTLS message formats, flows, and
logic are the same as those of TLS 1.3."  The exceptions, and where each
lives:

| Difference | RFC 9147 | Where |
|---|---|---|
| Record layer: epochs, explicit sequence numbers, the unified header, record number encryption, replay window, several records per datagram, invalid records silently dropped | §4 | `dtls.c` |
| Handshake header: `message_seq`, `fragment_offset`, `fragment_length`; fragmentation and reassembly | §5.2, §5.5 | `dtls.c` — the transcript is over the TLS-style header, so the roles and the transcript do not change |
| Flights, retransmission timer, ACK content type | §5.7, §5.8, §7 | `dtls.c` |
| KeyUpdate: acknowledged, new keys only after the ACK | §8 | `dtls.c` |
| HKDF label prefix `"dtls13"` instead of `"tls13 "` | §5.9 | `tls_keys.c`, a parameter |
| ClientHello: `legacy_version` {254, 253}, a `legacy_cookie` field; version 0xfefc in supported_versions; ServerHello `legacy_version` 0xfefd; the server does not echo `legacy_session_id`; no change_cipher_spec | §5, §5.3, §5.4 | `tls_server.c`, `tls_client.c`, a few branches |
| Cookie exchange in a HelloRetryRequest | §5.1 | `tls_server.c` (the client echoes a cookie under TLS too) |

Everything else — parsing and refusing hellos, PSK binders, certificates,
CertificateVerify, Finished, the key schedule, KeyUpdate's secrets — is the
TLS code, unchanged.

---

## 3. Structure

```
┌───────────────────────────────────────────────────────────────────────────┐
│ Application                                                               │
│   TLS: tls_rx_commit() / tls_tx_pending()    DTLS: dtls_input() /         │
│        tls_read() / tls_write()                    dtls_pending() /       │
│                                                    dtls_read() / _write() │
├──────────────────────────────┬────────────────────────────────────────────┤
│ tls.c — stream records       │ dtls.c — datagram records, epochs, flights,│
│   (TCP)                      │   timer, ACKs, reassembly                  │
├──────────────────────────────┴────────────────────────────────────────────┤
│ tls_common.c — hs framing, keys, post-handshake messages, alerts, failing │
│   → t->rl  (the record layer)          → t->role (the handshake)          │
│ tls_server.c   tls_client.c            tls_keys.c                         │
├───────────────────────────────────────────────────────────────────────────┤
│ tls_crypto_t — SHA-256, HMAC, HKDF, AES-GCM, (EC)DHE, signatures,         │
│                certificates, random; AES block (DTLS record numbers)      │
└───────────────────────────────────────────────────────────────────────────┘
```

### 3.1 The record-layer interface

The helpers the roles call (`tls_hs_begin()`, `tls_hs_end()`, `tls_fail()` …)
are in `tls_common.c`, apart from either record layer, and the few that
depend on the record layer call it through a pointer in the connection, as
the handshake is reached through `t->role`:

```c
typedef struct tls_rl_s {
  uint8_t dtls;                                     /* 1: DTLS 1.3 */
  uint8_t *(*hs_begin)(tls_conn_t *t, size_t max);  /* room for a message */
  void (*hs_flush)(tls_conn_t *t);                  /* messages written so far may go */
  int (*ccs)(tls_conn_t *t);                        /* TLS only: the dummy change_cipher_spec */
  void (*alert)(tls_conn_t *t, uint8_t level, uint8_t desc); /* queue an alert (tls_fail) */
  void (*set_keys)(tls_conn_t *t, int write);       /* install t->wsec's or t->rsec's keys */
  void (*wipe)(tls_conn_t *t);                      /* key material the layer keeps itself */
} tls_rl_t;
```

`tls_init()` sets `tls_stream_rl` (`tls.c`), `dtls_init()` DTLS's (`dtls.c`,
static).  No shared code names either record layer, so a TLS-only device
does not link `dtls.c` and a DTLS-only device does not link `tls.c` — the
argument of [tls.md §2.1](tls.md#21-the-role-interface), one level down.
The cost to TLS is the pointer in `tls_conn_t` and an indirect call in place
of a direct one.

`tls_common.c` holds:

- the helpers the roles share (`tls_next_extension()`, the group
  helpers, `tls_cert_verify_content()`, `tls_hrr_random`, `tls_notify()`);
- `tls_hs_begin()` → `rl->hs_begin`; `tls_hs_end()` (header, transcript —
  the same for both); `tls_hs_flush()` → `rl->hs_flush`;
  `tls_queue_ccs()` → `rl->ccs`;
- `tls_set_keys(t, write)` → `rl->set_keys`: the roles install keys only
  through it, so DTLS sees each epoch begin;
- `tls_fail()`: `rl->alert`, then the state, alert, wipe and event;
- `tls_wipe_keys()`, with `rl->wipe` for DTLS's own key sets;
- `tls_on_handshake()`: whole messages to the role, or once connected
  KeyUpdate (its keys through `tls_set_keys()`), NewSessionTicket
  (ignored by a client) and `unexpected_message` for anything else;
- `tls_alert_received()`: close_notify, user_canceled, fatal;
- `tls_psk_used()`.

The KeyUpdate we owe is each record layer's own: TLS sends it and changes
keys at once; DTLS changes keys only when it is acknowledged (section 9).

### 3.2 Building without DTLS

`TLS_USE_DTLS` (`tls.h`; CMake `SMALLEST_TCP_DTLS`, on by default) set to 0
makes `tls_is_dtls()` a constant 0: the roles lose their DTLS branches
(the hello formats, the cookie) and `dtls.c` refuses to build.  A TLS-only
device pays nothing for DTLS but the record-layer interface (section 12).

### 3.3 The label prefix

RFC 9147 §5.9 replaces `"tls13 "` by `"dtls13"` in every HKDF-Expand-Label
— both six bytes, so only the constant changes.  The key-schedule functions
that expand labels (`tls_expand_label()`, `tls_derive_secret()`,
`tls_next_secret()`, `tls_traffic_keys()`, `tls_finished_mac()`,
`tls_psk_binder()`, `tls_update_secret()`) take a `dtls` flag after the
backend; the roles pass `tls_is_dtls(t)`.  They stay pure functions over a
`tls_crypto_t`, and the RFC 8448 tests pass 0.

### 3.4 The roles

`tls_is_dtls(t)` (`t->rl->dtls`) selects:

| | TLS | DTLS |
|---|---|---|
| Hello `legacy_version` | 0x0303 | 0xfefd |
| supported_versions | 0x0304 | 0xfefc |
| ClientHello after the session id | — | `legacy_cookie`, empty; a server refuses any other with `illegal_parameter` (REQ-DTLS-003) |
| Server: the client's `legacy_session_id` | echoed; a non-empty one means compatibility mode and the dummy change_cipher_spec | not echoed, not kept — so no change_cipher_spec either (`sid_len` stays 0) |
| Server: first ClientHello | — | HelloRetryRequest with a cookie, unless `cfg->dtls_no_cookie` (section 8) |

`client_hello()`'s fixed part grows by the one `legacy_cookie` byte.
`pump_client()` reserves its empty Certificate and Finished together; the
DTLS flight store keeps TLS-format messages, so reserving two at once is
fine (section 6.1).

---

## 4. The connection

`dtls_conn_t` (`dtls.h`) starts with a `tls_conn_t`, so `dtls.c` gets from
one to the other by a cast, and the roles and `tls_common.c` see an
ordinary connection.  What it adds:

| Fields | |
|---|---|
| `r`, `w`, `r_prev`, `w_prev` (`dtls_keys_t`: key, IV, record number, record-number key, replay window) | The current receive and send epochs' keys and the epoch before each.  `tls.rkeys` / `tls.wkeys` are not used: `tls_set_keys()` hands DTLS the new secret through `rl->set_keys`, which moves the current keys to `*_prev` and derives the next epoch's |
| `repoch`, `wepoch` | 0, then 2, 3, 4 …; never wrap |
| `pseq`, `mtu` | Our next epoch-0 record number; the largest datagram we send |
| `fl_seq`, `fl_split`, `fl_ep[2]`, `fl_pos`, `fl_idx`, `fl_frag`, `fl_state` | The flight in `tls.tx` and the transmission's cursor (section 6) |
| `pass`, `retries`, `pass_lost`, `sent[]`, `sent_n`, `rto_ms`, `timer_ms` | Transmissions of the flight, the records each used (for ACKs), the timer |
| `rx_seq`, `hs_have` | The next `message_seq` expected; bytes of it reassembled |
| `acks[]`, `ack_n`, `ack_owed` | The peer's records to acknowledge |
| `bad_records`, `dg_len` | Records that failed to open; the datagram waiting in `tls.tx` |

`tls.hs_off`, `hs_len` and `rx_len` describe the receive buffer (section
5.4); `tls.tx_len` is the end of the flight store (section 6.1).

---

## 5. Records

### 5.1 Formats (RFC 9147 §4)

```
DTLSPlaintext (epoch 0):
  type(1) | legacy_record_version {254,253} (2) | epoch = 0 (2) | sequence_number (6) | length (2) | fragment

DTLSCiphertext (epochs 2, 3, ...):
  0 0 1 C S L E E | [CID] | seq (1 or 2) | [length (2)] | encrypted_record
```

We send DTLSCiphertext with C = 0, S = 1 (16-bit sequence number), L = 1
(length present) — five header bytes — so a datagram may carry several
records.  We receive any combination of S and L; a record without a length
takes the rest of the datagram.  A record with C set is dropped: no CID was
negotiated (REQ-DTLS-013).

**Demultiplexing** (§4.1): first byte 21, 22 or 26 → DTLSPlaintext;
`001xxxxx` → DTLSCiphertext; anything else → the rest of the datagram is
dropped (its length cannot be known).

### 5.2 Protection

Sealing a record of epoch *e* with keys *K*:

1. Header `0x2C | (e & 3)`, `K.k.seq & 0xFFFF`, length = content + 1 + 16.
2. AES-128-GCM over DTLSInnerPlaintext (content, type, no padding) with
   the nonce `K.k.iv` XOR the 64-bit sequence number (the epoch is not in
   the nonce) and the five header bytes as additional data — the header
   *before* record number encryption (§4).
3. Record number encryption (§4.2.3): mask = AES-ECB(`K.sn`,
   ciphertext[0..15]); the two sequence-number bytes of the header XOR
   mask[0..1].  The ciphertext is at least 17 bytes (type + tag), so no
   padding is ever needed.
4. `K.k.seq++`.

Opening one:

1. Epoch: the two E bits must match the current read epoch or the one
   before (§4.2.2); during the handshake the bits are unambiguous.  No
   keys for it (e.g. epoch 2 before the ServerHello) → dropped.
2. Ciphertext shorter than 16 bytes → dropped (§4.2.3).
3. Unmask the sequence bits; reconstruct the full number as the one
   closest to `k.seq` (highest received + 1) with those low bits (§4.2.2).
4. Open with the header as it was before masking; failure → dropped, and
   `bad_records` counts it.
5. Replay (§4.5.1), after deprotection so a discard is no timing channel:
   a number at or below `k.seq - 33`, or one whose bit is set, is a
   duplicate → dropped.  Otherwise the window moves or the bit is set.
6. Strip padding; the inner content type decides (section 5.3).

`aes_block` is the one primitive DTLS adds to `tls_crypto_t`:

```c
  /** AES-128 of one block (DTLS record number encryption, RFC 9147 §4.2.3). */
  void (*aes_block)(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
```

It goes last in the struct, so a TLS-only backend leaves it NULL, and
`dtls_init()` refuses a configuration whose backend lacks it.
`sn_key = HKDF-Expand-Label(secret, "sn", "", 16)` is derived with the
traffic key and IV whenever an epoch begins.

### 5.3 Receiving

`dtls_input(d, datagram, len)` walks the records of one datagram, which
stays in the caller's buffer (it may be the frame buffer the UDP handler
was given):

| Record | Accepted when | Then |
|---|---|---|
| Plaintext handshake | A fragment of a new message only while the peer's records are not yet protected (ClientHello, ServerHello, HelloRetryRequest) — afterwards one can only be forged; any time as a duplicate (section 6.4) | Fragments copied straight from the datagram into the reassembly area |
| Plaintext alert | While the peer's records are not yet protected | As TLS |
| Plaintext ACK | Never (it would be unauthenticated) | Dropped |
| Protected | Keys for its epoch, authentic, not replayed | Decrypted into rx: handshake fragments → reassembly; alert → as TLS; application data → the read queue, once `CONNECTED`; ACK → section 7; any other type → `unexpected_message` (it is authentic, so not spoofed) |

Anything malformed — a header or length that does not fit, a fragment
running past its message — is **dropped silently** (§4.5.2): an alert is
what a forger would probe for.  Handshake failures of authentic messages
(a bad Finished, a refused ClientHello) are still fatal alerts, as in TLS.

`bad_records` counts every record that fails to open — a failed
authentication, less than 16 bytes of ciphertext, a replay — for the
connection as a whole, and ends the connection (`bad_record_mac`) if it
ever reaches 2^32 − 1; RFC 9147 §4.5.3 allows 2^36 failed authentications
per key for AES-128-GCM, so this is stricter (REQ-DTLS-023).

### 5.4 The receive buffer

```
rx: 0         hs_off                  rx_len                         rx_cap
    | kept msg | message being        | read queue: [len16|data]...  | free:
    |          | reassembled (reserved|                              | scratch for a
    |          | to its full length)  |                              | protected record
```

- A protected handshake, alert or ACK record is decrypted into scratch at
  the end of rx, then its fragments are copied to the reassembly area.
- Application data is decrypted straight into the read queue, behind a
  two-byte length; `dtls_read()` copies out one record per call (the
  datagram's boundary is the record's).
- A new message's area is reserved to its full length in front of the read
  queue, which moves up to make room — a KeyUpdate arriving behind unread
  data is taken at once.  If rx cannot hold both until the reader takes
  some data, the fragment is dropped and not acknowledged; the peer sends
  it again.
- A message that cannot fit even in an empty rx ends the connection with
  `record_overflow`, as in TLS.

---

## 6. The handshake over datagrams

### 6.1 Sending: the flight store

`tls_hs_begin()` reserves room for a message in the **flight store** — the
front of tx — and `tls_hs_end()` finishes it exactly as for TLS: the
four-byte TLS header, the transcript, the length.  The store therefore holds
TLS-format messages, and the DTLS framing is added when they are sent:

```
tx: 0                         fl_split                    tx_len        tx_cap
    | messages of fl_ep[0]    | messages of fl_ep[1]      | datagram   | free |
      (e.g. ServerHello, 0)     (EE, Cert, CV, Fin — 2)     (dg_len)
```

- A flight has at most two epochs — the server's (0 then 2), the client's
  last (2), a KeyUpdate (the current one) — so `fl_split` and `fl_ep[2]`
  describe it; `hs_begin` records the write epoch of each message it
  starts.
- `message_seq` is not stored: the first message has `fl_seq` and the rest
  follow on.
- A new flight can be written once the old one is acknowledged (section
  6.3): `flight_done()` then empties the store and moves `fl_seq` past the
  old flight's messages.  Until then `hs_begin` returns NULL.
- The datagram being handed to the transport sits after the store; nothing
  is written to the store while it waits (`hs_begin` returns NULL, and the
  role tries again after `dtls_sent()`, as a TLS role waits for tx room).
- A store too small for a flight even when empty fails the handshake with
  `internal_error`, as a too-small TLS tx does.

### 6.2 Transmissions

A **transmission** walks the store from the start (or, for a flight just
written, from its first message) and cuts it into datagrams of at most
`mtu` bytes:

- Consecutive messages of one epoch share a record; a new record starts at
  `fl_split`, and a new datagram when the current one is full.
- Each piece of a message is a DTLS handshake fragment: the TLS header's
  type and length, `message_seq`, `fragment_offset`, `fragment_length`,
  then the bytes.  A message that does not fit in the datagram's remaining
  room is split there, unless the room is too small to be worth a
  fragment, in which case the datagram ends.
- A record is sealed with the keys of its epoch: plaintext for 0, `w` or
  `w_prev` for the others (§4.2.1: retransmissions use the original
  epoch).  Every record gets a new record number, so a retransmitted
  message goes in new records (§5.2).
- The record numbers of the flight's transmissions are kept in `sent[]`
  for matching ACKs — `DTLS_SENT_MAX`, 10, in all (also the most records
  one transmission should carry, §5.8.3, which is not enforced:
  REQ-DTLS-041).  A transmission whose records are not all in `sent[]`
  (`pass_lost`) cannot be answered by an ACK of its own records.
- When the last piece has been handed to the transport the retransmission
  timer starts.

`dtls_pending(d, &buf)` builds the next datagram when none is waiting — an
owed ACK first, then the transmission's next pieces — and returns it;
`dtls_sent(d)` releases it.  `dtls_write()` seals one record of application
data into the same slot.  One datagram waits at a time, so tx needs the
flight plus one datagram.

### 6.3 Flights and the timer (§5.7, §5.8)

| Event | What happens |
|---|---|
| We write a flight | Its first transmission; `rto_ms` = `DTLS_RTO_INITIAL_MS` (1000); `retries` = 0 |
| Timer expires | After `DTLS_MAX_RETRANSMITS` (6) retransmissions by the timer — 1 + 2 + 4 + 8 + 16 + 32 + 60 s, about two minutes — the connection fails: `ERROR`, `alert` = `DTLS_TIMEOUT`, `TLS_EVT_ERROR`, no alert sent.  Otherwise `rto_ms` doubles (at most `DTLS_RTO_MAX_MS`, 60 000) and the whole flight is sent again |
| A fragment of the next message expected — any record of the peer's next flight | Our flight is acknowledged implicitly (§7.2): the timer stops |
| ACKs that between them name every record of one of the flight's transmissions | Acknowledged explicitly: the timer stops (for our KeyUpdate, the new keys take over — section 9) |
| A duplicate of the peer's previous flight while ours is unacknowledged | The peer has not seen ours: send it again now (§5.8.1).  This does not count against the timer's retransmissions |

`dtls_tick(d, elapsed_ms)` runs the timer; the application calls it from
its main loop, as it calls `net_tick()`, and sends what `dtls_pending()`
then returns.  The timer does not adapt to the round-trip time (§5.8.2
SHOULD); each flight starts again from one second.

The server keeps no timer before its first flight.  Its HelloRetryRequest
is a flight like any other, so a client that stops answering after one is
given up on like any other.

### 6.4 Receiving: reassembly (§5.2, §5.5)

For each handshake fragment in a record:

| `message_seq` | |
|---|---|
| below `rx_seq` | A duplicate: nothing to process.  During the handshake it may mean the peer lost our flight (section 6.3); a server that has finished answers a duplicate of the client's last flight by acknowledging it again (§5.8.1, REQ-DTLS-039) |
| above `rx_seq` | A later message: dropped (§5.2 MAY), and an ACK is owed for what has arrived of the flight so far (§7.1) |
| `rx_seq` | Placed |

The message being reassembled has its TLS header written at `rx + hs_off`
from the first fragment seen, and its area reserved to the full length.
Fragments may arrive in any order and overlap (§5.5 MUST): one that starts
at or before `hs_have` extends it; one that starts beyond is dropped, and an
ACK owed.  Bytes that overlap ones already placed must be identical, else
`illegal_parameter` (§5.5 SHOULD).  A fragment whose type or total length
differs from the message's is dropped.

A message whose last byte arrives goes to `tls_on_handshake()` exactly as
under TLS — `HS_KEYS`, `HS_KEEP` and `HS_RELEASE` mean the same, the client
keeps the server's Certificate in rx for CertificateVerify — and `rx_seq`
moves on.  If further fragments follow in the record after a message that
changed keys, that is `unexpected_message`, as in TLS (a key change falls on
a record boundary).

---

## 7. ACKs (§7)

```
ACK: record_numbers<0..2^16-1>, each { uint64 epoch; uint64 sequence_number; }
```

**Sending.**  `acks[]` lists the records of the peer's current flight that
carried fragments we placed, noted as the first fragment of a record is
placed — before the message it completes can start a flight of ours.  A
record none of whose fragments was placed is never listed (§7 MUST NOT);
one whose first fragment was placed stays listed even if a later message in
it then finds no room behind unread data, which can only be a
NewSessionTicket after a shorter one (REQ-DTLS-051).  The list is cleared
when a handshake flight of ours begins: the peer's records after that
belong to its next flight.  After the handshake, flights each way are
independent (§5.8.4) and the list is not cleared; when full, its oldest
entry makes way.  An ACK is owed:

- by a server when the client's last flight is complete (its Finished) —
  mandatory, since nothing else answers that flight;
- after a post-handshake message — KeyUpdate, NewSessionTicket — is
  processed (§7.1: a client that ignores the ticket still acknowledges it);
- again, by a finished server, for each duplicate of the client's last
  flight (§5.8.1);
- when a fragment is dropped for arriving out of order (§7.1 SHOULD); such
  an ACK may be empty.

ACKs go in a record of the highest write epoch (§7), and only once we have
write keys — a client that has not processed the ServerHello does not send
an empty plaintext ACK.  An ACK lists as many records as its datagram
holds, the newest ones (`DTLS_ACK_MAX`, 8, at most).  An ACK is sent once,
not retransmitted.

**Receiving.**  Only a protected ACK is believed.  Each record number that
matches one in `sent[]` — the records of every transmission of the flight,
each with its transmission's number — is marked (§7.2: a record named in
any ACK is acknowledged); when every record of some transmission is marked,
the flight is acknowledged.  A partial ACK changes nothing: the timer
resends the whole flight (§7.2 SHOULD resend only the rest — not
implemented, a flight is a few datagrams).

---

## 8. The cookie (§5.1)

A server that receives a first ClientHello answers with a HelloRetryRequest
carrying a cookie — 16 random bytes kept in `tls.sid`, which DTLS does not
otherwise use on a server — and selecting a group too if the client's share
is not usable.  The second ClientHello must carry the same cookie
(`illegal_parameter` otherwise, §5.1 MUST); only then does the server send
its flight.  The cookie shows the client can receive at its address before
the server sends a Certificate flight many times the size of a ClientHello
— the amplification §5.1 is about.

The cookie is kept in the connection, not packed statelessly into the HRR:
a device already gives each peer its own `dtls_conn_t` when the first
ClientHello arrives.  The resource side of the attack — ClientHellos from
forged addresses tying up those connections — is the application's to
bound, and it can: `dtls_peer_verified(d)` is 1 once the cookie has come
back, so a server short of connections can reuse one still waiting for its
cookie before refusing a verified peer.  `cfg->dtls_no_cookie` (a server
setting in `tls_config_t`) skips the exchange where amplification is no
concern (§5.1 MAY), e.g. PSK-only links on a private network.

---

## 9. KeyUpdate (§8)

- **Sending.**  `dtls_key_update()`, or 2^24 records under one key, owes a
  KeyUpdate; it is written as a one-message flight in the current epoch as
  soon as no other flight is waiting for its ACK.  Records keep using the
  current keys until the peer acknowledges it — then `wsec` moves on, `w`
  becomes `w_prev` and the next epoch begins (REQ-DTLS-060).  No second
  KeyUpdate is written before that.  Unlike TLS, `dtls_write()` is never
  held back by an owed KeyUpdate.
- **Receiving.**  The peer's next secret and keys go in `r`, the old ones
  in `r_prev`: its records may arrive in either epoch until it has our ACK,
  and the RFC requires the old keys to be kept until a record under the new
  ones decrypts (REQ-DTLS-061).  The record is acknowledged; a request is
  answered with our own KeyUpdate (not requesting).
- The epoch is 16 bits here.  At epoch 65 535 a KeyUpdate of ours is not
  sent, and the peer's request for one not answered (§8); a KeyUpdate from
  the peer that would take its epoch past 65 535 ends the connection with
  `internal_error` (the RFC forbids wrapping, §6.1).

---

## 10. API

```c
int dtls_init(dtls_conn_t *d, const tls_config_t *cfg, uint8_t *rx,
              size_t rx_cap, uint8_t *tx, size_t tx_cap, size_t mtu);
int dtls_accept(dtls_conn_t *d);                     /* tls_accept() */
int dtls_connect(dtls_conn_t *d, const char *host);  /* tls_connect() */
int dtls_input(dtls_conn_t *d, const uint8_t *dgram, size_t len);
size_t dtls_pending(dtls_conn_t *d, const uint8_t **dgram);
void dtls_sent(dtls_conn_t *d);
void dtls_tick(dtls_conn_t *d, uint32_t elapsed_ms);
int dtls_write(dtls_conn_t *d, const uint8_t *data, size_t len);
size_t dtls_read(dtls_conn_t *d, uint8_t *buf, size_t len);
int dtls_key_update(dtls_conn_t *d, int request);
int dtls_close(dtls_conn_t *d);
void dtls_release(dtls_conn_t *d);
int dtls_peer_verified(const dtls_conn_t *d);
size_t dtls_max_data(const dtls_conn_t *d);          /* largest dtls_write() */
tls_state_t dtls_state(const dtls_conn_t *d);
```

| Call | |
|---|---|
| `dtls_init()` | As `tls_init()`, plus `mtu`: the largest datagram to send — what the transport can carry without IP fragmentation (for UDP over Ethernet 1472 on IPv4, 1452 on IPv6; smaller if the frame buffers are).  At least 128.  −1 also if the backend has no `aes_block` |
| `dtls_accept()`, `dtls_connect()` | As `tls_accept()`, `tls_connect()` |
| `dtls_input()` | One received datagram, from the peer this connection belongs to (the application demultiplexes by address and port).  Returns 0, or the negated alert (or `DTLS_TIMEOUT`) that ended the connection.  Never alerts in answer to a bad datagram |
| `dtls_pending()`, `dtls_sent()` | The next datagram to send, and "sent".  Call them until `dtls_pending()` returns 0 after `dtls_input()`, `dtls_tick()`, `dtls_write()`, `dtls_key_update()`, `dtls_close()` |
| `dtls_tick()` | The retransmission timer |
| `dtls_write()` | One record of application data, one datagram: `len`, 0 while the previous datagram has not been taken, −1 when not open for writing or `len` > `dtls_max_data()` — a datagram is never split |
| `dtls_read()` | One record's data per call, as `tls_read()` |
| `dtls_key_update()`, `dtls_close()`, `dtls_release()` | As the TLS calls (section 9 for KeyUpdate).  close_notify is sent once and not retransmitted (§5.10) |

Events and states are TLS's.  After `CLOSED` (the peer's close_notify)
received records are ignored, which covers §5.10's rule that data after a
close_notify is ignored.

**Over UDP** (the demos): the UDP handler looks the peer up by
address and port, calls `dtls_input()`, then sends every `dtls_pending()`
datagram with `udp_send()` to that peer's address and MAC.  A client
resolves the server's MAC first, as `tls_client_demo` does for TCP
([arp-resolution.md §3](arp-resolution.md#3-resolving-a-mac-for-an-active-open)).

---

## 11. Sizing

| Buffer | Must hold | Typical |
|---|---|---|
| tx | The largest flight this side sends, plus one datagram | Server with the 481-byte test certificate: about 750 bytes of flight + `mtu`.  Client: its ClientHello (about 200 bytes, more with a PSK) + `mtu` |
| rx | The largest handshake message it receives, plus the largest record (scratch), plus unread application data | Client: the server's Certificate + CertificateVerify + one datagram; server: the ClientHello + one datagram |
| `mtu` | ≤ the transport's datagram limit | 1200 is a safe default where the path is unknown |

---

## 12. Size and memory

Cortex-M0 `.text` (`make arm-size-tls`, `make arm-size-dtls`; `-Os -mthumb`,
`NET_DEBUG=0`):

| Object | TLS only (`TLS_USE_DTLS` 0) | With DTLS |
|---|---:|---:|
| `tls_common.c` | 766 | 770 |
| `tls_keys.c` | 1,086 | 1,086 |
| `tls_server.c` | 3,126 | 3,554 |
| `tls_client.c` | 3,612 | 3,800 |
| `tls.c` (stream records) | 2,498 | 2,498 |
| `dtls.c` (datagram records) | — | 5,861 |
| **Server only** | **7,476** (TLS) | **11,271** (DTLS) |
| **Client and server** | **11,088** (TLS) | **15,071** (DTLS) |

A device with both protocols and both roles carries all six objects: 17,569
bytes.  The DTLS branches cost the roles 428 bytes (server: the cookie, the
hello formats) and 188 (client).  The crypto backend is extra, as for TLS,
and adds only `aes_block`.  `make arm-check-links` checks that the DTLS
objects reference nothing only `tls.c` defines, and the TLS-only objects
nothing only `dtls.c` defines (REQ-DTLS-072).

| | Cortex-M0 | Notes |
|---|---:|---|
| `dtls_conn_t` | 904 B | Its `tls_conn_t` (448 B), four epochs' keys with their record-number keys and windows (256 B), the records of the flight (80 B) and of the peer's to acknowledge (64 B), the flight's cursor and the timer |
| `tls_config_t` | 44 B | Shared with TLS |
| rx, tx | section 11 | Application owned |
| Stack | 104 B deepest frame in `dtls.c` | `dtls_record_open()`.  The longest chain — input, fragments, the handshake, the key schedule — is about 740 bytes, plus the backend's |

`dtls.c` has no `.data` or `.bss`, and no divide routine is linked.

## 13. Testing

**Integration** (`itest_dtls`, 48 tests, CMake with `SMALLEST_TCP_TLS` and
`SMALLEST_TCP_DTLS`): the server and the client through the API in
`dtls.h`.  The peer is the tests' own (`tests/integration/tls_peer.c`),
written from RFC 9147 on Mbed TLS's primitives: it builds and opens
DTLSPlaintext and DTLSCiphertext records itself — the unified header,
record number encryption, the additional data and nonce — cuts and
reassembles handshake fragments, writes and reads ACKs, and runs the PSK
handshake, with the `"dtls13"` labels, as client and as server.
Certificate handshakes, loss, duplication and reordering run the stack's
two roles against each other over a network of the test's.  The suite is
linked without the stack's core: the test moves every datagram
(REQ-DTLS-073).  Line coverage of `dtls.c` by this suite: 96 %.

**Unit** (`test_dtls`, 57 tests, CMake with `SMALLEST_TCP_TLS` and
`SMALLEST_TCP_DTLS`; plus `test_tls_crypto`'s AES block against FIPS-197
and `test_tls_keys`'s `"dtls13"` labels against `tests/tls/gen_dtls13.py`):

- Records: our records rebuilt from the backend's primitives as RFC 9147
  describes them; both sequence-number lengths, with and without a length;
  CIDs and other versions refused; short ciphertext, tampering, padding;
  sequence reconstruction (with its tie); the replay window.
- Our client and our server over a memory network that can lose, repeat
  and reorder datagrams: the formats on the wire; each datagram of the
  handshake lost in turn; everything twice; everything reversed; small
  MTUs; a retransmission cut differently from the first transmission;
  fragments in any order, overlapping, and changed bytes refused; the timer
  and its give-up; the ACK of the last flight, lost and resent; the Finished
  lost; an ACK when a later fragment comes first; the cookie refused,
  missing and switched off; a HelloRetryRequest for a group; PSK;
  max_fragment_length; bad records and forged plaintext ignored; buffers
  too small.
- After the handshake: data both ways a datagram per record; data before
  the Finished not taken; KeyUpdate — acknowledged before use, its ACK
  lost, requested both ways, at the record limit, behind unread data,
  waiting for an unanswered flight, at the last epoch — and a late record
  of the old epoch; close_notify; `dtls_release()`; a NewSessionTicket
  acknowledged.

**Blackbox and interop** (27 tests; Linux TAP and raw socket, macOS feth;
CI job `blackbox-dtls`).  The peer is wolfSSL 5.9.4, built by
`tests/blackbox/build_wolfssl.sh` from its pinned release:

| Suite | Tests | |
|---|---:|---|
| `test_dtls_conform.py` | 19 | wolfSSL's client against `dtls_echo_demo`: P-256, x25519, a HelloRetryRequest for the group, KeyUpdate from the client, PSK (psk_dhe_ke, psk_ke), three clients at once, the server's flight in 300-byte fragments, no cookie; hand-built datagrams: the cookie HelloRetryRequest, the same answer to a repeated ClientHello, a wrong cookie, a legacy_cookie and DTLS 1.2 refused with their alerts, silence towards four kinds of garbage |
| `test_dtls_client_conform.py` | 8 | `dtls_client_demo` against wolfSSL's server: 3000 bytes echoed, the server's cookie, KeyUpdate from either side, 300-byte datagrams, PSK, a wrong name and an untrusted chain refused |
