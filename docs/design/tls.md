# TLS 1.3 — Design

**Protocol:** Transport Layer Security 1.3 (RFC 8446)  
**Supporting:** RFC 6066 (server_name, max_fragment_length), RFC 8448 (test vectors)  
**Files:**

| File | Contents |
|---|---|
| `include/tls.h` | The connection API: `tls_config_t`, `tls_conn_t`, `tls_init()`, `tls_accept()`, `tls_connect()`, records in and out, `tls_read()` / `tls_write()`, `tls_key_update()`, `tls_close()` |
| `include/tls_keys.h`, `src/tls_keys.c` | Key schedule (RFC 8446 §7) and record protection (§5.2): pure functions over a `tls_crypto_t`, checked against RFC 8448 |
| `src/tls_internal.h` | Private to the library: the `F_*` flags, the handshake steps `ST_*`, the `HS_*` results, the `rd_t` reader, `tls_next_extension()`, the role interface `tls_role_t`, the record-layer interface `tls_rl_t`, and the declarations of what `tls_common.c` defines |
| `src/tls_common.c` | What the TLS record layer shares with DTLS's ([dtls.md](dtls.md)) and with the roles: handshake message framing, installing traffic keys, post-handshake messages, alerts received, `tls_fail()` |
| `src/tls.c` | The stream record layer: records in and out, receive processing, the KeyUpdate we owe, the public API |
| `src/tls_server.c` | `tls_accept()` and the server handshake (`tls_server_role`) |
| `src/tls_client.c` | `tls_connect()` and the client handshake (`tls_client_role`) |
| `include/tls_tcp.h`, `src/tls_tcp.c` | `tls_tcp_carry()`, `tls_tcp_idle()`: moving records between a `tls_conn_t` and a `tcp_conn_t` |
| `include/tls_crypto.h` | The crypto backend interface, `tls_crypto_t` |
| `include/tls_crypto_mbedtls.h`, `src/tls_crypto_mbedtls.c`, `include/tls_mbedtls_user_config.h` | The Mbed TLS 3.6 backend and its build configuration |

**Requirements:** [docs/requirements/tls.md](../requirements/tls.md) (REQ-TLS-001..069)

---

## 1. Scope

smallest_tcp speaks TLS 1.3 itself — records, handshake, key schedule — and
takes every cryptographic primitive from a backend the application supplies
through a vtable, the way it takes Ethernet from a `net_mac_t` driver.  The
project ships one backend, on Mbed TLS 3.6 (its crypto and X.509 modules
only; Mbed TLS's own TLS code is not used).

| | |
|---|---|
| Version | TLS 1.3 only — a TLS 1.2 peer gets `protocol_version` (REQ-TLS-001) |
| Cipher suite | `TLS_AES_128_GCM_SHA256` (REQ-TLS-002) |
| Key exchange | x25519 and secp256r1 (REQ-TLS-004/005); either can be switched off (`tls_config_t.groups`); HelloRetryRequest sent by the server and answered by the client |
| Authentication | Certificates: ECDSA P-256 (`ecdsa_secp256r1_sha256`) and RSA (`rsa_pss_rsae_sha256`) — the server signs, the client verifies chain, name and CertificateVerify.  Pre-shared keys: `psk_dhe_ke` and `psk_ke`, external or resumption, with binders (REQ-TLS-023..025) |
| Roles | Server (`tls_accept()`) and client (`tls_connect()`); a build links only the roles it calls (section 2) |
| Extensions | server_name, supported_versions, supported_groups, signature_algorithms, key_share, cookie (the client echoes one), pre_shared_key, psk_key_exchange_modes, max_fragment_length (REQ-TLS-031) |
| After the handshake | Application data, KeyUpdate both ways (and by itself after 2^24 records), close_notify; a client ignores NewSessionTicket |
| Signatures offered | A client's signature_algorithms lists `ecdsa_secp256r1_sha256` and `rsa_pss_rsae_sha256`; not `rsa_pkcs1_sha256`, though the backend verifies certificates signed that way (REQ-TLS-063) |
| Middlebox compatibility | The server answers a client that sent a session id with the dummy change_cipher_spec; both sides drop one received before the peer's Finished |

Not implemented: other cipher suites (AES-256-GCM and ChaCha20-Poly1305 are
REQ-TLS-003, a SHOULD), client certificates (a client asked for one sends an
empty Certificate), 0-RTT early data, issuing or storing session tickets (a
client can still use a resumption PSK obtained some other way,
`psk_resumption`), post-handshake authentication, signature_algorithms_cert
and a server's reading of server_name (REQ-TLS-064), record_size_limit
(RFC 8449), certificate compression.

---

## 2. Structure

```
┌────────────────────────────────────────────────────────────────────┐
│ Application: tls_read() / tls_write() / tls_close() / tls_state()  │
├────────────────────────────────────────────────────────────────────┤
│ tls.c — records in and out; tls_common.c — handshake framing,      │
│   alerts, KeyUpdate; the handshake through tls->role:              │
│           tls_server.c (tls_accept)   tls_client.c (tls_connect)   │
│ tls_keys.c — key schedule and record protection                    │
├─────────────────────────────────┬──────────────────────────────────┤
│ tls_crypto_t (vtable)           │ Application buffers:             │
│   tls_crypto_mbedtls.c          │   rx (records in), tx (out)      │
│   → Mbed TLS 3.6 crypto + X.509 │                                  │
├─────────────────────────────────┴──────────────────────────────────┤
│ Transport, moved by the application — for TCP, tls_tcp.c:          │
│   tcp_recv() → tls_rx_space() / tls_rx_commit()                    │
│   tls_tx_pending() / tls_tx_done() → tcp_write() + tcp_output()    │
└────────────────────────────────────────────────────────────────────┘
```

The protocol code — `tls.c`, `tls_keys.c` and the two role files — contains
no cryptography (REQ-TLS-006), allocates no memory and knows nothing of TCP.
The application gives each connection a receive and a transmit buffer;
ciphertext is moved between those buffers and the transport by the
application, or by `tls_tcp_carry()` (`tls_tcp.c`) for one of the stack's TCP
connections (section 10).

### 2.1 The role interface

The record layer is the same for both roles; the handshake is not.  `tls.c`
reaches the handshake only through the connection's role:

```c
typedef struct tls_role_s {
  int (*on_message)(tls_conn_t *t, const uint8_t *m, size_t mlen); /* a whole handshake message */
  int (*pump)(tls_conn_t *t);                                      /* write the output owed */
} tls_role_t;

extern const tls_role_t tls_server_role;   /* tls_server.c */
extern const tls_role_t tls_client_role;   /* tls_client.c */
```

`tls_accept()`, in `tls_server.c`, sets `tls->role = &tls_server_role`;
`tls_connect()`, in `tls_client.c`, sets `&tls_client_role`.  Nothing in
`tls.c` names either role, so the only reference to a role's code is its own
entry function.  An application that calls `tls_accept()` and never
`tls_connect()` does not reference `tls_client.o`, and the linker leaves it
out — a server-only device does not carry the client (and vice versa).  A
`switch` on the role inside `tls.c` would have referenced both handshakes
from every build.

Cortex-M0 `.text` (`make arm-size-tls`, `-Os -mthumb`, `NET_DEBUG=0`,
`TLS_USE_DTLS` 0 — with DTLS built in the roles are larger, [dtls.md §12](dtls.md#12-size-and-memory)):

| Object | Bytes |
|---|---:|
| `tls_common.c` | 766 |
| `tls.c` | 2,498 |
| `tls_keys.c` | 1,086 |
| `tls_server.c` | 3,126 |
| `tls_client.c` | 3,612 |
| **Server only** (`tls_common.c` + `tls.c` + `tls_keys.c` + `tls_server.c`) | **7,476** |
| **Client and server** | **11,088** |

A client-only build is `tls_common.c` + `tls.c` + `tls_keys.c` + `tls_client.c`, 7,962 bytes
by the same objects.  These are object sizes; the crypto backend is extra
(section 3).  No object calls a library divide (`make arm-check-division`).

What the two role files share is in `tls_internal.h` and `tls_common.c`:
the builders (`tls_hs_begin()`, `tls_hs_end()`, `tls_hs_flush()`,
`tls_queue_ccs()`), `tls_set_keys()`, `tls_fail()`, `tls_notify()`, the
reader and `tls_next_extension()`, the group helpers,
`tls_cert_verify_content()`, and `tls_hrr_random` (the HelloRetryRequest
marker, defined once because the server writes it and the client looks for
it).

### 2.2 The record-layer interface

The roles and `tls_common.c` reach the record layer the way `tls.c` reaches
the handshake: through a pointer in the connection, `tls->rl`, which
`tls_init()` sets to `tls_stream_rl` (`tls.c`) and `dtls_init()` to DTLS's
datagram layer.  Its operations are the few that differ — room for a
handshake message, letting written messages go, the dummy
change_cipher_spec, queueing an alert, installing traffic keys — so a
TLS-only build does not link DTLS's record layer, nor a DTLS-only build
this one ([dtls.md §3.1](dtls.md#31-the-record-layer-interface)).

### 2.3 CMake targets

| Target | Sources | Links |
|---|---|---|
| `smallest_tcp::tls` | `tls_common.c`, `tls.c`, `tls_keys.c`, `tls_server.c`, `tls_client.c`, and `dtls.c` with `SMALLEST_TCP_DTLS` | nothing — bring a `tls_crypto_t` |
| `smallest_tcp::tls_tcp` | `tls_tcp.c` | `tls`, the core (needs `SMALLEST_TCP_TCP`) |
| `smallest_tcp::https` | `http_tls.c` | `http`, `tls_tcp` ([http.md](http.md)) |
| `smallest_tcp::tls_mbedtls` | `tls_crypto_mbedtls.c` | Mbed TLS (`SMALLEST_TCP_TLS`) |

`smallest_tcp::tls` is one static library, so the linker still picks the
role objects individually as above.

---

## 3. The crypto backend

```c
typedef struct tls_crypto_s {
  void (*hash_init)(tls_hash_t *h);                   /* SHA-256 */
  void (*hash_update)(tls_hash_t *h, const uint8_t *data, size_t len);
  void (*hash_peek)(const tls_hash_t *h, uint8_t out[32]); /* h goes on */
  void (*hmac)(key, key_len, data, len, out[32]);      /* HMAC-SHA-256 */
  void (*hkdf_extract)(salt, salt_len, ikm, ikm_len, prk[32]);
  void (*hkdf_expand)(prk[32], info, info_len, out, out_len);
  void (*aead_seal)(key16, nonce12, aad, aad_len, in, len, out, tag16);
  int  (*aead_open)(key16, nonce12, aad, aad_len, in, len, tag16, out);
  int  (*kx_keygen)(ctx, group, priv, pub, &pub_len);  /* x25519, P-256 */
  int  (*kx_shared)(ctx, group, priv, peer, peer_len, shared[32]);
  int  (*sign)(ctx, key, scheme, msg, len, sig, &sig_len, sig_cap);
  int  (*verify)(ctx, cert_der, cert_len, scheme, msg, len, sig, sig_len);
  int  (*verify_chain)(ctx, certs[], lens[], count, hostname);
  int  (*random)(ctx, out, len);
  void *ctx;
  void (*aes_block)(key16, in16, out16);            /* DTLS only */
} tls_crypto_t;
```

(Abbreviated; `tls_crypto.h` has the full prototypes.)

- The transcript hash is a running SHA-256 whose state lives in the
  connection (`tls_hash_t`, `TLS_HASH_STATE_SIZE` = 128 bytes, opaque to the
  protocol code; the backend checks at compile time that its context fits).
  `hash_peek` reads the digest so far without ending it — the handshake needs
  the transcript at many points.
- `kx_shared` must reject invalid peer shares (x25519's all-zero result,
  P-256 points not on the curve); the handshake answers `illegal_parameter`.
- `sign` and `verify` take the whole CertificateVerify content and hash it
  themselves.  `key` is whatever the backend's key type is (an
  `mbedtls_pk_context *` here).
- `verify_chain` returns 0 or the alert to send — `unknown_ca`,
  `certificate_expired`, `certificate_revoked`, `bad_certificate`.  An
  address literal as `hostname` matches an iPAddress subjectAltName; NULL
  skips the name check.

**The Mbed TLS backend.**  With `SMALLEST_TCP_TLS` on (the default for a
top-level build) CMake fetches Mbed TLS 3.6.7 from its release tarball,
pinned by SHA-256, and passes it `tls_mbedtls_user_config.h` as
`MBEDTLS_USER_CONFIG_FILE`.  `tls_mbedtls_init()` seeds a CTR-DRBG from the
platform entropy source and fills a `tls_crypto_t`; `tls_mbedtls_set_ca()`
adds trust anchors; `tls_mbedtls_parse_key()` loads a private key.  The user
configuration enables `MBEDTLS_MEMORY_BUFFER_ALLOC_C`, so
`tls_mbedtls_use_arena()` can serve Mbed TLS's bignum allocations from a
static array instead of the heap.  Another library — wolfSSL, BearSSL, PSA
drivers, a hardware engine — needs only these fourteen functions for TLS,
and `aes_block` as well for DTLS, whose record numbers are encrypted with
the AES block cipher alone (RFC 9147 §4.2.3; [dtls.md](dtls.md)).

---

## 4. Using it

```c
static tls_config_t cfg = {
    .crypto = &crypto,                        /* filled by tls_mbedtls_init() */
    .cert = chain, .cert_len = chain_len, .cert_count = 1,
    .key = &key, .sig_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256,  /* server */
    .psk = psk, .psk_len = 32, .psk_id = (const uint8_t *)"device-1",
    .psk_id_len = 8, .psk_modes = TLS_PSK_DHE_KE,               /* optional */
    .groups = 0,           /* 0: x25519 and secp256r1 */
    .max_fragment = 0,     /* client: TLS_MFL_512 .. TLS_MFL_4096 */
};
static uint8_t rx[TLS_RECORD_HDR + TLS_MAX_CIPHERTEXT + 512], tx[4096];
static tls_conn_t tls;

/* once the TCP connection is ESTABLISHED: */
tls_init(&tls, &cfg, rx, sizeof rx, tx, sizeof tx);
tls_accept(&tls);                          /* or tls_connect(&tls, "name") */

/* every time round the main loop, after net_poll(): */
tls_tcp_carry(&net, &conn, &tls);          /* ciphertext both ways */
if (tls_state(&tls) == TLS_STATE_CONNECTED) {
  n = tls_read(&tls, buf, sizeof buf);     /* plaintext in */
  if (reply_len && tls_write(&tls, reply, reply_len) > 0)   /* one record */
    tls_tcp_carry(&net, &conn, &tls);      /* ... on its way */
}
```

| Call | |
|---|---|
| `tls_init(tls, cfg, rx, rx_cap, tx, tx_cap)` | Zero the connection and attach the stream record layer, the configuration and buffers (each at least 256 bytes; above 65,534 the rest is unused).  Call it again to reuse the connection |
| `tls_accept(tls)` | Server: wait for a ClientHello.  −1 unless the connection is `IDLE` and the configuration has a certificate chain with its key and scheme, a complete PSK, or both |
| `tls_connect(tls, host)` | Client: queue the ClientHello.  `host` is checked against the certificate and sent as server_name (not for an address literal); NULL skips the name check; it must stay valid for the handshake.  −1 for a connection that is not `IDLE`, an incomplete PSK, a host name over 255 characters, a backend that gives no random bytes or key pair, or a ClientHello that does not fit in tx |
| `tls_rx_space()` + `tls_rx_commit()` | Ciphertext in, written straight into rx (`tls_tcp_carry()` passes the space to `tcp_recv()`).  Returns 0 or the negated alert that ended the connection |
| `tls_input()` | The same, copying from the caller's buffer; returns the bytes taken |
| `tls_tx_pending()` + `tls_tx_done()` | Ciphertext out |
| `tls_write()` | Seal up to one record of plaintext; returns the bytes taken — 0 when tx has no room (a KeyUpdate we owe goes first), −1 when the connection is not open for writing |
| `tls_read()` | Copy out received plaintext — from one record per call; call again for more |
| `tls_key_update(tls, request)` | New write keys; `request` asks the peer to update too |
| `tls_close(tls)` | Queue close_notify; nothing more may be written |
| `tls_release(tls)` | Done with the connection, however it ended: wipe the secrets, record keys and key share, and both buffers (they held plaintext); it is left `IDLE` with the same configuration, buffers, callback and user pointer, ready for `tls_accept()` or `tls_connect()` |
| `tls_state()`, `tls->alert`, `tls->group`, `tls_psk_used()`, `tls->max_frag` | Status: state, the fatal alert, the key-exchange group (0 with psk_ke), whether a PSK authenticated the handshake, the negotiated record size (0: 2^14) |
| `tls->on_event` | Optional callback: `TLS_EVT_CONNECTED`, `TLS_EVT_CLOSED` (close_notify received), `TLS_EVT_ERROR` (REQ-TLS-038..040).  It runs inside the call that made the progress — usually `tls_rx_commit()`, also `tls_tx_done()` or `tls_read()` |

States: `IDLE` → `HANDSHAKE` (`tls_accept()` / `tls_connect()`) →
`CONNECTED` (Finished) → `CLOSED` (the peer's close_notify; we may still
write until our own `tls_close()`), or `ERROR` from any of them (an alert
sent or received; secrets and keys wiped).  After `CLOSED` or `ERROR`, received
bytes are discarded.

The demos: `tls_echo_demo` (an echo server on port 4433), `https_demo`
(`http.c` over TLS on port 443, [http.md](http.md)), `tls_client_demo`.
`demo/common/demo_tls.h` loads their credentials and an optional PSK from
the environment.

---

## 5. Buffers

### 5.1 Layout

```
rx:  0          hs_off              hs_len                          rx_len      rx_cap
     | kept msg | handshake bytes   | records not yet processed     | free       |
                  awaiting a whole
                  message

tx:  0              tx_sent                         rec_start               tx_len   tx_cap
     | sent          | sealed records, not yet sent | record being built    | free   |
```

- **rx** holds handshake bytes at the front and raw records behind them.  A
  record's handshake content is moved down to the handshake area as the
  record is processed, so messages split across records, or several
  messages in one record, look the same to the handshake.  The client keeps
  the server's Certificate at the front (`hs_off`) until CertificateVerify
  has been checked with its key (section 8).  Application data is opened in
  place and read from there (`app_off`, `app_len`, `app_rec`).
- **tx** holds records in the order they go out.  `tls_tx_pending()` returns
  the unsent part; `tls_tx_done()` advances `tx_sent`.  When everything has
  been taken tx is empty again at once; otherwise the space is reclaimed
  (`tx_compact()`) the next time a record is started.  A record
  is built in place at `rec_start`: content first, then the header and
  protection when it is closed.

### 5.2 Sizing

`TLS_RECORD_OVERHEAD` (`tls_keys.h`) is what a protected record adds to its
content: the 5-byte header, the inner content type and the 16-byte tag — 22
bytes.  A plaintext record (ClientHello, ServerHello, HelloRetryRequest)
adds only its 5-byte header.

| Buffer | Must hold | Typical |
|---|---|---|
| rx | The largest record the peer sends, plus any partial handshake message before it.  A record larger than the space after the handshake bytes, or a message larger than rx, ends the connection with `record_overflow` | A peer may send records of 2^14 + 256 + 5 = 16,645 bytes; the demos use 16,645 + 512.  A client that asks for max_fragment_length 512 gets records of at most 512 bytes of content; with one ECDSA certificate its handshake fits in about 700 bytes, and the tests run such a client with an 800-byte rx |
| tx | The largest message this side sends, reserved at its maximum size, plus the overhead of each record it is split into | Server: its Certificate (494 bytes with the 481-byte test certificate) + 22; a CertificateVerify reserves 72 signature bytes for ECDSA, 512 for RSA.  Client: its ClientHello — 125 bytes plus the host name with an x25519 share, 158 with P-256, more with a PSK identity and binder, and after a HelloRetryRequest the server's cookie.  The server tests send the whole flight through a 600-byte tx; the small-buffer client test uses a 256-byte tx |

A connection whose handshake cannot make progress because tx is too small
even when empty fails with `internal_error` rather than waiting forever.

### 5.3 Memory

| | Cortex-M0 | Notes |
|---|---:|---|
| `tls_conn_t` | 448 B | 128 of them the backend's SHA-256 state; three 32-byte secrets; two `tls_keys_t` (key, IV, sequence number) |
| `tls_config_t` | 44 B | Shared by any number of connections; it and everything it points to must outlive them |
| rx, tx | section 5.2 | Application owned |
| Stack | 360 B deepest frame | The client's message handler, with the handlers inlined into it; the server's is 352 B (the ephemeral key pair and shared secret live in the connection, not here).  The longest chain through the TLS code — commit, process, handler, key schedule — is about 640 bytes, plus whatever the backend uses below it (Mbed TLS's ECDH and signatures are the heaviest).  Measured with `-fstack-usage` for Cortex-M0 |

The TLS objects have no `.data` or `.bss`.

---

## 6. Receiving

`tls_rx_commit(n)` accounts for `n` new bytes and calls `process()`:

```
process():
  repeat:
    stop unless HANDSHAKE or CONNECTED
    stop while application data is unread           (the reader goes first)
    each whole handshake message in rx → tls_on_handshake()
    5 bytes of the next record header?  check it:
      content type 20..23                    else unexpected_message
      length ≤ 2^14 (2^14 + 256 for type 23)  else record_overflow
      record fits the space after hs_len      else record_overflow
    whole record?  on_record()
then pump()                                          (section 7.2)
```

A header is checked as soon as its five bytes are in, so a peer that is not
speaking TLS is refused at once instead of after a body that never comes.

**Records** (`on_record()`):

| Record | Accepted when | Then |
|---|---|---|
| change_cipher_spec | `F_CCS_OK` (after the first ClientHello, before the peer's Finished — RFC 8446 §5), exactly the byte 0x01 | Dropped |
| Plaintext alert | Before the peer's records are protected, or at any time during the handshake (a peer that failed before it had our keys) | `on_alert()` |
| Plaintext handshake | Before the peer's records are protected; not zero-length | Content appended to the handshake area |
| application_data (type 23) | Only once the peer's records are protected (`F_RPROT`) | Opened in place with `tls_record_open()` — `bad_record_mac` if it fails (REQ-TLS-027..030) |

Everything else is `unexpected_message`.  Inside a protected record the inner
content type decides: handshake content (not zero-length) is appended to the
handshake area; an alert goes to `on_alert()`; application data is accepted
only in `CONNECTED` and only between whole handshake messages, and waits in
rx until `tls_read()` has taken all of it — later records wait behind it.  A
zero-length application-data record is dropped; a protected
change_cipher_spec is `unexpected_message`.

**Handshake messages.**  Each whole message goes to `tls_on_handshake()`: during
the handshake to the role's `on_message()`; once `CONNECTED`, a KeyUpdate
changes the peer's keys (section 9), a client ignores NewSessionTicket, and
anything else is `unexpected_message`.  The handler returns:

| Result | Meaning | `tls.c` then |
|---|---|---|
| 0 | Done with the message | Drops it |
| `HS_KEYS` | Keys change after this message | Drops it; if handshake bytes remain, fails with `unexpected_message` — a key change must fall on a record boundary (RFC 8446 §5.1) |
| `HS_KEEP` | Keep it (the client's copy of the server's Certificate) | Leaves it in place, `hs_off` past it |
| `HS_RELEASE` | Done with it and with the kept message | Drops both |
| < 0 | Failed (the handler has called `tls_fail()`) | Stops |

After each message it drops, `pump()` runs, so a reply can be written before
the next message is looked at.  Because messages are handled one at a time and
records are opened one at a time, the keys a message installs are in place
before the next record is opened.

**Alerts** (`on_alert()`, then `tls_alert_received()` in `tls_common.c`): the
body must be two bytes (`decode_error`; `unexpected_message` if there is
none at all, RFC 8446 §5.4).
close_notify moves to `CLOSED` and reports `TLS_EVT_CLOSED`; user_canceled is
ignored (close_notify follows it); any other alert, whatever its level, moves
to `ERROR`, wipes the keys, reports `TLS_EVT_ERROR`, and `tls_rx_commit()`
returns its negated code.

---

## 7. Sending

### 7.1 Building records

- `rec_room(t, type, need)` returns room for `need` content bytes.  If a
  record of the same type is open and the bytes fit both it (within the
  fragment limit) and tx, they are appended to it — consecutive handshake
  messages share a record.  Otherwise the open record is closed, sent bytes
  are compacted away, and a new record is started with room reserved for the
  content and for the header and tag of every extra record the content will
  need.  NULL means tx has no room yet.
- `rec_close(t)` finishes the open record: if its content is longer than
  the fragment limit (`max_frag`, else 2^14) it moves the pieces, last first,
  to the places reserved for them, then writes each header and seals it
  (`tls_record_seal()` once our records are protected).
- `tls_hs_begin(t, max)` reserves a handshake message of at most `max`
  bytes; the handler writes the body; `tls_hs_end()` writes the four-byte
  header, adds the message to the transcript and commits its length.
- `tls_write()` seals one application-data record of at most the fragment
  limit and what tx can hold, once any KeyUpdate we owe has gone (section 9).

### 7.2 `pump()`

`pump()` produces whatever output is due, as far as tx allows.  It runs
after every received handshake message that is dropped, at the end of
`tls_rx_commit()`,
after `tls_tx_done()` frees space, after `tls_read()` empties a record, and
from `tls_key_update()` / `tls_write()` when a KeyUpdate is owed:

1. during the handshake, the role's `pump()` — the server's flight a message
   at a time, or the client's Finished;
2. a KeyUpdate we owe (section 9);
3. close the open record, so it can be sent;
4. if a handshake step still owes output and tx is entirely empty, the
   message cannot ever fit: `internal_error`.

Writing a message at a time is what lets a small tx carry a large flight:
when the next message does not fit, the step waits for `tls_tx_done()`.

### 7.3 Failing

`tls_fail(t, alert)` drops a half-built record, queues the fatal alert
(protected if our keys are active, and only if tx has room), sets `ERROR`
and `tls->alert`, wipes the secrets, record keys and the client's key share,
reports `TLS_EVT_ERROR`, and returns the negated alert, which the callers
pass up to `tls_rx_commit()`.

---

## 8. The handshake

Both roles keep a running transcript hash in the connection.  Sent messages
are added by `tls_hs_end()`; received ones by their handler, after it has
checked them (a Finished is checked against the transcript before it is
added).  `tls->step` records where the handshake is.

### 8.1 Server (`tls_server.c`)

```
Client                                  Server
ClientHello           ──────────►  ST_WAIT_CH    on_client_hello()
                      ◄──────────                HelloRetryRequest (stays in ST_WAIT_CH, once)
ClientHello           ──────────►  ST_WAIT_CH
                      ◄──────────                ServerHello                    plaintext
                                                 ── handshake keys ──
                      ◄──────────  ST_SEND_CCS   [change_cipher_spec]           client sent a session id
                      ◄──────────  ST_SEND_EE    EncryptedExtensions
                      ◄──────────  ST_SEND_CERT  Certificate                    not with a PSK
                      ◄──────────  ST_SEND_CV    CertificateVerify              not with a PSK
                      ◄──────────  ST_SEND_FIN   Finished → our application keys
Finished              ──────────►  ST_WAIT_FIN   → the client's application keys, CONNECTED
```

**ClientHello.**  `parse_client_hello()` reads it strictly: lengths, the
null compression method only (`illegal_parameter`), a repeated extension
(`illegal_parameter`, via `tls_next_extension()`), pre_shared_key last
(`illegal_parameter`), a session id of at most 32 bytes (echoed later).  A
valid max_fragment_length request is granted there and then.  Then
`on_client_hello()` decides, in this order:

1. `supported_versions` must offer TLS 1.3 → else `protocol_version`;
   `TLS_AES_128_GCM_SHA256` must be offered → else `handshake_failure`;
   supported_groups and key_share must come together, both or neither →
   else `missing_extension` (RFC 8446 §9.2).
2. The share (chosen while parsing): x25519 preferred over secp256r1, among
   the groups `tls_config_t.groups` allows; after a HelloRetryRequest only
   the group it asked for.
3. A pre_shared_key needs psk_key_exchange_modes (`missing_extension`) and a
   well-formed identity list (`decode_error`); the first identity equal to
   ours is picked.  The mode is psk_dhe_ke if both sides allow it and step 2
   found a usable share, else psk_ke if both allow it (the server's default
   is psk_dhe_ke only).
4. No PSK mode and no usable share, but the client sent a key_share
   extension (possibly empty), a group in supported_groups is one we allow,
   and the handshake needs (EC)DHE (psk_dhe_ke possible, or certificates
   configured — then signature_algorithms must be present and include our
   scheme): a **HelloRetryRequest** for that group — once; a second
   ClientHello still without a usable share is `illegal_parameter`.
   `send_hello_retry()` adds ClientHello1 to the transcript and replaces it
   by message_hash (`tls_transcript_hrr()`, RFC 8446 §4.4.1), writes the HRR
   (selected group, supported_versions, the echoed session id) and, for a
   client with a session id, the dummy change_cipher_spec.
5. Otherwise certificates: without a certificate the answer is
   `unknown_psk_identity` (a PSK was offered) or `handshake_failure`;
   key_share, signature_algorithms and supported_groups are required
   (`missing_extension`), and signature_algorithms must include our scheme
   and a share must be usable (`handshake_failure`).
6. The share must be exactly 32 (x25519) or 65 (P-256) bytes
   (`illegal_parameter`).
7. The Early Secret: from the PSK, whose binder must check out
   (`take_early_secret()`: the ClientHello up to its binders goes into the
   transcript, the binder is computed and compared in constant time —
   `decrypt_error`; then the rest is added), or from zeros.
8. Our key pair and the shared secret (`kx_shared` refusing the peer's share
   is `illegal_parameter`).  The private key is kept in `kx_priv` and wiped
   as soon as the secret is computed, and the secret is computed into
   `rsec`, which the client's handshake traffic secret then replaces:
   neither is ever on the stack, and a backend that fails after writing
   part of either leaves nothing behind, since `tls_fail()` wipes both.

ServerHello carries pre_shared_key, key_share and supported_versions — the
order of RFC 8448, so with the RFC's randomness our ServerHello to its
ClientHello is the RFC's byte for byte.  `enter_handshake_keys()` then
derives the Handshake Secret and both handshake traffic keys, and
`on_client_hello()` returns `HS_KEYS`.

**The flight.**  `pump_server()` writes one message per step, each waiting
for room: the dummy change_cipher_spec (only for a client in compatibility
mode that did not already get one after a HelloRetryRequest),
EncryptedExtensions (max_fragment_length when granted), Certificate (each
DER certificate of `cfg->cert`, no extensions) and CertificateVerify (the
backend signs the content of RFC 8446 §4.4.3 with `cfg->key`) unless a PSK
authenticated the handshake, and Finished.  Once Finished is written, our
records switch to the server application keys.

**The client's Finished** is checked in constant time (`decrypt_error`);
then the peer's records switch to the client application keys, the
connection is `CONNECTED` and `TLS_EVT_CONNECTED` is reported.  The server
sends no application data before that (no 0.5-RTT data).

### 8.2 Client (`tls_client.c`)

```
Client                                         Server
tls_connect(): ClientHello   ──────────►
ST_C_WAIT_SH                 ◄──────────  HelloRetryRequest → a second ClientHello (once)
ST_C_WAIT_SH                 ◄──────────  ServerHello → handshake keys
ST_C_WAIT_EE                 ◄──────────  EncryptedExtensions
ST_C_WAIT_CERT               ◄──────────  [CertificateRequest] Certificate     not with a PSK
ST_C_WAIT_CV                 ◄──────────  CertificateVerify                    not with a PSK
ST_C_WAIT_FIN                ◄──────────  Finished → server application keys
ST_C_SEND_FIN: [empty Certificate] Finished ──► our application keys, CONNECTED
```

**ClientHello.**  It offers exactly what the client implements: TLS 1.3,
the one suite, an empty legacy session id (no compatibility mode — the
client keeps its random in `tls->sid` for a second ClientHello), server_name
(unless `host` is NULL or an address literal), both signature schemes, the
allowed groups with one share — x25519 if allowed, else secp256r1; neither
for a client configured for psk_ke only — max_fragment_length if configured,
and the PSK last: psk_key_exchange_modes, one identity, and its binder
computed over the ClientHello up to the binders under the PSK's Early
Secret.  The private key waits in `tls->kx_priv` until the ServerHello.

**HelloRetryRequest** (a ServerHello whose random is `tls_hrr_random`) is
accepted once (`unexpected_message` the second time).  It must echo the
empty session id and our suite, carry only supported_versions (TLS 1.3),
key_share (the selected group) and a non-empty cookie (anything else is
refused, see below; `protocol_version` without supported_versions), and
change something: a selected group that is allowed
and different from our share's, or a cookie (`illegal_parameter`).  The
transcript restarts as message_hash of ClientHello1 plus the HRR, and the
second ClientHello keeps the same random, has a fresh key pair (of the
selected group, if one was selected), echoes the cookie and carries a new
binder over message_hash + HRR + itself.

**ServerHello** must echo the session id (empty), select our suite, and carry
only supported_versions (TLS 1.3 — without it the server is TLS 1.2 or
older: `protocol_version`), key_share for the group we sent a share of, and
pre_shared_key selecting identity 0 if we offered one.  An extension that
has no place in the message it came in is refused by `refuse_extension()`
(RFC 8446 §4.2): `illegal_parameter` if it is one the client knows from
another message, `unsupported_extension` if it answers nothing the client
sent.  Without a key_share the
server may only have chosen psk_ke, and only if we offered it
(`illegal_parameter` if it took the PSK, RFC 8446 §4.2.11; else
`missing_extension`).  The shared secret is computed into `rsec` (as on
the server, it never touches the stack, and the server's handshake traffic
secret replaces it), `kx_priv` is wiped, and the Handshake Secret is
derived — from the PSK's Early Secret if the server took the PSK, else from
zeros.

**EncryptedExtensions** may answer only what the ClientHello carried (RFC
8446 §4.2): an empty server_name if we sent one, the max_fragment_length we
asked for (the same code, `illegal_parameter` otherwise; `max_frag` is set
from it) and supported_groups if we sent that.  One of the three that we
did not send is `unsupported_extension`; an extension that belongs to
another message (key_share, say) is `illegal_parameter` (§4.3.1); anything
unknown is `unsupported_extension`.  With a PSK the next message is
Finished.

**Certificates.**  One CertificateRequest may come first (an empty context);
it is answered later with an empty Certificate.  The Certificate's chain —
at most six certificates (`bad_certificate` beyond) — goes to the backend's
`verify_chain` with `host` at once, and the message is **kept in rx**
(`HS_KEEP`, `leaf_off` / `leaf_len`) so that CertificateVerify can be checked
with the leaf's key without copying the leaf anywhere.  CertificateVerify
must use one of the two schemes we offered (`illegal_parameter`) and verify
(`decrypt_error`); then both messages are released (`HS_RELEASE`).

**Finished.**  The server's Finished is checked in constant time; the
Master Secret gives both application secrets, and the peer's records switch
to the server application keys (`HS_KEYS`).  `pump_client()` then writes the
empty Certificate if one was requested and our Finished in one record,
switches our records to the client application keys, and reports
`TLS_EVT_CONNECTED`.

---

## 9. After the handshake

- **KeyUpdate** (RFC 8446 §4.6.3).  A received KeyUpdate (one byte, 0 or 1;
  `decode_error` / `illegal_parameter` otherwise) moves the peer's traffic
  secret one generation on and installs its keys; it must end its record
  (`HS_KEYS`).  If it asks for an update, we owe one as an answer
  (`F_KU_OWED`, `F_KU_ANS`).  `tls_key_update(tls, request)` owes one too,
  asking the peer to follow if `request` (`F_KU_REQ`).  However many are
  owed, one KeyUpdate goes, and an answer is update_not_requested even when
  the application asked as well: the peer's sending keys have just changed,
  which is all the request wanted, and asking back could keep the two sides
  updating each other (§4.6.3).  A request of ours still waiting to go is
  dropped, too, when the peer's KeyUpdate arrives with update_not_requested:
  the peer's sending keys have changed since we asked, and asking anyway —
  allowed, but pointless — would cost it a KeyUpdate more.  `pump()` sends
  an owed KeyUpdate as soon as tx has room, then moves our secret on and
  installs the new keys.  Until it
  has gone, `tls_write()` accepts nothing, so no data goes out under the key
  it retires.
- **The record limit.**  `tls_write()` owes a KeyUpdate itself once
  `TLS_KEY_UPDATE_RECORDS` (2^24) records have been sealed under one key
  (RFC 8446 §5.5 allows 2^24.5 for AES-GCM).
- **close_notify.**  `tls_close()` queues it (a warning-level alert) and
  sets `F_WCLOSED`; no KeyUpdate or data follows it.  A received
  close_notify moves to `CLOSED`, in which we may still write until we close.
  Once it has gone both ways — the second of the two, sent or received —
  no key is used again, and they are wiped.
- **The end.**  A connection that ends without an alert or a close — the
  TCP connection reset, the application giving up — would keep its keys
  until the next `tls_init()`; `tls_release()` wipes them and the buffers at
  once.  The HTTPS transport calls it whenever a slot listens again
  ([http.md §7](http.md#7-transports)), and the demos when a session ends.
- **NewSessionTicket** is ignored by a client (there is no ticket store) and
  is `unexpected_message` to a server, as is any other handshake message.

---

## 10. Over TCP: `tls_tcp.c`

```c
void tls_tcp_carry(net_t *net, tcp_conn_t *tcp, tls_conn_t *tls);
int  tls_tcp_idle(const tcp_conn_t *tcp, tls_conn_t *tls);
```

`tls_tcp_carry()` moves ciphertext both ways and transmits:

1. **In:** while TLS has room and TCP has data, `tcp_recv()` straight into
   `tls_rx_space()`, `tls_rx_commit()`, then `tcp_window_update()` so the
   peer learns of the freed window.  Received data is copied once, from the
   TCP receive buffer into TLS's rx, and decrypted in place there.
2. **Out:** while TLS has records pending and TCP takes bytes,
   `tcp_write()` from `tls_tx_pending()`, then `tls_tx_done()`.
3. `tcp_output()`.

Call it after `net_poll()` and after `tls_write()` — whenever either side may
have progressed.  It ignores `tls_rx_commit()`'s result; watch
`tls_state()`.

`tls_tcp_idle()` is true when TLS has nothing pending and TCP has sent and
had acknowledged everything (`tcp_tx_idle()`).  Closing is therefore:
`tls_close()`, keep carrying, and `tcp_close()` once `tls_tcp_idle()` — so the
close_notify and everything before it is delivered before our FIN
(`tls_echo_demo`, `tls_client_demo` and the HTTPS transport all do this).
A `CLOSED` state (the peer's close_notify) is answered with `tls_close()`
the same way.

`tls_tcp.c` is the whole coupling: nothing in `tls.c` knows about TCP, and
another transport uses the same four calls.

---

## 11. Key schedule (`tls_keys.c`)

Pure functions over a `tls_crypto_t`, tested against RFC 8448.  Those that
expand labels take a `dtls` flag: 0 for TLS's prefix `"tls13 "`, 1 for
DTLS 1.3's `"dtls13"` (RFC 9147 §5.9):
`tls_expand_label()` (HKDF-Expand-Label), `tls_derive_secret()`,
`tls_early_secret()` (with a PSK, or with zeros), `tls_next_secret()` (Early →
Handshake with the (EC)DHE secret, Handshake → Master with none),
`tls_traffic_keys()` (key and IV of a traffic secret, sequence 0),
`tls_finished_mac()`, `tls_psk_binder()` ("ext binder" or "res binder"),
`tls_transcript_hrr()`, `tls_update_secret()` ("traffic upd"),
`tls_record_seal()` / `tls_record_open()` (AAD = the record header, nonce =
IV XOR the 64-bit sequence number, the inner content type after the content,
padding stripped on receipt), `tls_equal()` (constant-time comparison) and
`tls_wipe()` (a zeroing the compiler cannot drop).  No early traffic secrets
are derived: there is no 0-RTT.

A connection keeps three secrets and two sets of record keys:

| Moment | `secret` | `rsec` (the peer's) | `wsec` (ours) |
|---|---|---|---|
| Client, ClientHello with a PSK | Early Secret (for the binder) | — | — |
| Server in the ClientHello / client in the ServerHello, before the Handshake Secret | Early Secret | the (EC)DHE shared secret | — |
| Server after ClientHello / client after ServerHello | Handshake Secret | peer's handshake traffic secret | our handshake traffic secret |
| Server after sending Finished | client application secret, not yet in use | client handshake | server application |
| Server after the client's Finished | wiped | client application | server application |
| Client after the server's Finished | client application secret, not yet in use | server application | client handshake |
| Client after sending Finished | wiped | server application | client application |
| KeyUpdate | — | next generation, when received | next generation, when sent |

`rkeys` and `wkeys` are derived from `rsec` and `wsec` whenever those change.
The Master Secret exists only on the stack for the moment it is used.

---

## 12. Security notes

- Finished MACs and PSK binders are compared in constant time (`tls_equal()`).
- Secrets, traffic keys and ephemeral private keys are wiped as soon as they
  are done with — the client's (`kx_priv`) once the ServerHello has been
  processed — and all of them on any fatal error or fatal alert, when
  `tls_connect()` fails, and once close_notify has gone both ways.
  `tls_release()` wipes them, and the plaintext in the buffers, however the
  connection ended.
- The client verifies the chain, the name (DNS or IP) and CertificateVerify
  before it sends its Finished — before that it has sent only its
  ClientHello — and refuses any extension it did not offer.
- No 0-RTT, no renegotiation, no compression, no downgrade path (TLS 1.3
  only).
- Randomness — hello randoms, key pairs, signatures — comes only from the
  backend.

---

## 13. Testing

**Integration (`itest_tls`, CMake with `SMALLEST_TCP_TLS`):** the
server and the client through the API in `tls.h`, against a peer of the
tests' own (`tests/integration/tls_peer.c`) written from RFC 8446 on
Mbed TLS's SHA-256, AES-GCM, X25519 and ECDSA — its own HKDF labels, key
schedule, hellos, Finished, CertificateVerify and record protection, none
of the stack's TLS code.  It is a PSK client and server and a certificate
server; certificate handshakes with the stack's server run the stack's two
roles against each other.  Two tests carry the records over the stack's TCP
on the scripted link with `tls_tcp_carry()`.  Every test names the
requirements it verifies ([requirements](../requirements/tls.md)).  Line
coverage of the TLS sources by this suite and `itest_dtls`: `tls.c` 97 %,
`tls_common.c` 99 %, `tls_keys.c` 96 %, `tls_server.c` 96 %, `tls_client.c`
94 %, `tls_tcp.c` 100 %.

**Unit (CMake with `SMALLEST_TCP_TLS`):**

| Suite | |
|---|---|
| `test_tls_crypto` | The backend: SHA-256, HMAC (RFC 4231), HKDF (RFC 5869), AES-GCM, the AES block (FIPS-197), X25519 (RFC 7748), P-256, ECDSA, RSA-PSS, chains (alerts, IP names, other anchors), random |
| `test_tls_keys` | Key schedule and records against RFC 8448 §3 (every secret, key, IV, both Finished, all eight protected records byte for byte), §4 (resumption PSK binder, PSK + DHE schedule), §5 (HelloRetryRequest transcript); malformed records; DTLS 1.3's `"dtls13"` labels and `"sn"` key (`tests/tls/gen_dtls13.py`, an independent HKDF) |
| `test_tls_server` | A scripted client checks every message.  With the RFC 8448 server's randomness, our ServerHello to the RFC's ClientHello is the RFC's byte for byte (§3 and the PSK case of §4).  Refusals for every malformed or unacceptable ClientHello, PSK selection, HRR, max_fragment_length (splitting, a tx canary), the flight through a 600-byte tx, KeyUpdate, alerts, a backend failing the key exchange after writing part of its output |
| `test_tls_client` | The client against our server over memory (both certificate types, byte at a time, small buffers, trust and name failures, PSK, HRR, max_fragment_length with an 800-byte rx, KeyUpdate, keys wiped after close_notify both ways and by `tls_release()`) and against a scripted server that gets each message wrong on purpose |

`tests/tls/gen_rfc8448.py` extracts the RFC 8448 traces into
`tests/unit/tls_rfc8448.h`, checking every value's stated length;
`tests/tls/gen_dtls13.py` computes the DTLS labels' values into
`tests/unit/tls_dtls13.h`, after checking its HKDF reproduces RFC 8448;
`tests/tls/gen_test_certs.sh` makes the test certificates in `tests/tls`
(for testing only).

**Blackbox (TAP and the raw-socket driver on Linux, feth on
macOS; CI job `blackbox-tls`):**

| Suite | Peers |
|---|---|
| `test_tls_conform.py` | Python ssl and openssl s_client against `tls_echo_demo`: handshake, 40 kB and 16 kB-record echoes, close_notify, refusals (TLS 1.2, group, suite, signature), KeyUpdate, a tampered record, a ClientHello in 7-byte segments, coalesced records, HRR, max_fragment_length, PSK (openssl, Python 3.13+), IPv6 |
| `test_tls_client_conform.py` | Python ssl and openssl s_server against `tls_client_demo`: SNI, 30 kB echo, RSA-PSS, name and trust failures, a TLS 1.2 server, client-certificate requests, HRR, max_fragment_length, KeyUpdate, PSK (psk_dhe_ke, psk_ke, certificate-less servers) |
| `test_https_conform.py` | Python and curl against `https_demo` |

The CI job runs them with Ubuntu's OpenSSL, Python and curl; the suites
accept the wording of OpenSSL 3.0 and later.
