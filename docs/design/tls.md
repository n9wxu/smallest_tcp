# TLS 1.3 — Design (Milestone 13)

**Protocol:** Transport Layer Security 1.3 (RFC 8446)  
**Supporting:** RFC 6066 (server_name, max_fragment_length), RFC 8448 (test vectors)  
**Files:** `include/tls.h` + `src/tls.c` (the protocol), `include/tls_crypto.h` (the crypto interface), `include/tls_crypto_mbedtls.h` + `src/tls_crypto_mbedtls.c` (the Mbed TLS backend)  
**Status:** implemented (Milestone 13) — stages 13.1 (crypto interface, Mbed TLS backend), 13.2 (key schedule, record protection), 13.3 (server), 13.4 (client), 13.5 (pre-shared keys), 13.6 (HelloRetryRequest, max_fragment_length, KeyUpdate, HTTPS demo).  `tls.c` is 10.3 KB on Cortex-M0 for both roles (`make arm-size-tls`); a connection is 440 bytes plus its buffers.  
**Last updated:** 2026-09-26

---

## 1. Scope

smallest_tcp speaks TLS 1.3 itself — records, handshake, key schedule — and
takes every cryptographic primitive from a backend the application supplies
through a vtable, the way it takes Ethernet from a `net_mac_t` driver.  The
project ships one backend, on Mbed TLS 3.6 (crypto and X.509 only; Mbed
TLS's own TLS code is not used).

| | |
|---|---|
| Version | TLS 1.3 only — a TLS 1.2 peer gets `protocol_version` (REQ-TLS-001) |
| Cipher suite | `TLS_AES_128_GCM_SHA256` (REQ-TLS-002) |
| Key exchange | x25519 and secp256r1 (REQ-TLS-004/005); either can be switched off (`groups`); HelloRetryRequest both ways |
| Authentication | Certificates: ECDSA P-256 (`ecdsa_secp256r1_sha256`) and RSA (`rsa_pss_rsae_sha256`) — the server signs, the client verifies chain, name and CertificateVerify.  Pre-shared keys: `psk_dhe_ke` and `psk_ke`, external or resumption, with binders (REQ-TLS-023..025) |
| Roles | Server (`tls_accept`) and client (`tls_connect`) |
| Extensions | server_name, supported_versions, supported_groups, signature_algorithms, key_share, cookie (client echoes), pre_shared_key, psk_key_exchange_modes, max_fragment_length (REQ-TLS-031) |
| After the handshake | Application data, KeyUpdate both ways (and by itself after 2^24 records), close_notify, NewSessionTicket ignored by the client |
| Middlebox compatibility | The server answers a client's session id with the dummy change_cipher_spec (after its ServerHello or HelloRetryRequest); both sides drop one received before the peer's Finished |

Not implemented: other cipher suites (ChaCha20-Poly1305 is REQ-TLS-003,
a SHOULD), client certificates (a client asked for one sends an empty
Certificate), 0-RTT early data, issuing session tickets (a client can still
use a resumption PSK it got elsewhere, `psk_resumption`), post-handshake
authentication, record_size_limit (RFC 8449), certificate compression.

---

## 2. Architecture

```
┌───────────────────────────────────────────────────────────────┐
│ Application:  tls_read() / tls_write() / tls_close()          │
├───────────────────────────────────────────────────────────────┤
│ tls.c — handshake state machine, key schedule, record layer   │
│         no cryptography, no allocation, no transport          │
├──────────────────────────────┬────────────────────────────────┤
│ tls_crypto_t (vtable)        │  application buffers:          │
│   tls_crypto_mbedtls.c       │  rx (records in), tx (out)     │
│   → Mbed TLS 3.6 crypto+X.509│                                │
├──────────────────────────────┴────────────────────────────────┤
│ Transport, moved by the application — tcp.c:                  │
│   tcp_recv() → tls_rx_space()/tls_rx_commit()                 │
│   tls_tx_pending()/tls_tx_done() → tcp_write() + tcp_output() │
└───────────────────────────────────────────────────────────────┘
```

`tls.c` knows nothing of TCP.  The application moves ciphertext between
the socket and the connection's two buffers; `tcp_recv()` can write
straight into the TLS receive buffer, so received data is copied once.
The demos' glue is ten lines (`demo_tls_carry()` in
`demo/common/demo_tls.h`).

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
} tls_crypto_t;
```

- The transcript hash is a running SHA-256 whose state lives in the
  connection (`tls_hash_t`, 128 bytes, opaque); `hash_peek` reads the
  digest without ending it.
- `kx_shared` must reject invalid peer shares (x25519's all-zero result,
  P-256 points not on the curve); tls.c answers `illegal_parameter`.
- `sign`/`verify` take the whole CertificateVerify content and hash it
  themselves.  `key` is whatever the backend's key type is (an
  `mbedtls_pk_context *` here).
- `verify_chain` returns 0 or the alert to send — `unknown_ca`,
  `certificate_expired`, `certificate_revoked`, `bad_certificate`.  An
  address literal as `hostname` matches an iPAddress subjectAltName.

**Mbed TLS backend.**  CMake fetches Mbed TLS 3.6.7 (LTS) from its release
tarball, pinned by SHA-256, when `SMALLEST_TCP_TLS` is on (the default for
a top-level build); `tls.c` itself (`smallest_tcp_tls`) has no dependency.
`tls_mbedtls_init()` seeds a CTR-DRBG from the platform entropy source;
`tls_mbedtls_set_ca()` adds trust anchors; `tls_mbedtls_parse_key()` loads
a private key.  With `MBEDTLS_MEMORY_BUFFER_ALLOC_C` (in the bundled user
config) `tls_mbedtls_use_arena()` serves Mbed TLS's bignum allocations from
a static array instead of the heap.  Another library — wolfSSL, BearSSL,
PSA drivers, a hardware engine — needs only these fourteen functions.

---

## 4. Using it

```c
static tls_config_t cfg = {
    .crypto = &crypto,                        /* tls_mbedtls_init() */
    .cert = chain, .cert_len = chain_len, .cert_count = 1,
    .key = &key, .sig_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256,  /* server */
    .psk = psk, .psk_len = 32, .psk_id = (const uint8_t *)"device-1",
    .psk_id_len = 8, .psk_modes = TLS_PSK_DHE_KE,               /* optional */
    .groups = 0,           /* x25519 and secp256r1 */
    .max_fragment = 0,     /* client: TLS_MFL_512 .. TLS_MFL_4096 */
};
static uint8_t rx[16 * 1024 + 512], tx[4096];
static tls_conn_t tls;

tls_init(&tls, &cfg, rx, sizeof rx, tx, sizeof tx);
tls_accept(&tls);                          /* or tls_connect(&tls, "name") */
for (;;) {                                 /* the main loop */
  uint8_t *p; size_t n = tls_rx_space(&tls, &p);
  tls_rx_commit(&tls, tcp_recv(&conn, p, n));        /* ciphertext in */
  const uint8_t *q; while ((n = tls_tx_pending(&tls, &q)))
    tls_tx_done(&tls, tcp_write(&conn, q, n));       /* ciphertext out */
  tcp_output(&net, &conn);
  if (tls_state(&tls) == TLS_STATE_CONNECTED) {
    n = tls_read(&tls, buf, sizeof buf);             /* plaintext */
    tls_write(&tls, reply, reply_len);               /* one record */
  }
}
```

| Call | |
|---|---|
| `tls_init(tls, cfg, rx, rx_cap, tx, tx_cap)` | Buffers of 256 B .. 64 KiB |
| `tls_accept(tls)` / `tls_connect(tls, host)` | Server / client.  `host` is checked against the certificate and sent as server_name (not for an address literal); NULL skips the name check |
| `tls_rx_space()` + `tls_rx_commit()` / `tls_input()` | Ciphertext in; returns 0 or the negated alert that ended the connection |
| `tls_tx_pending()` + `tls_tx_done()` | Ciphertext out |
| `tls_read()` / `tls_write()` | Plaintext; `tls_write` seals up to one record, returns bytes taken (0: tx full) |
| `tls_key_update(tls, request)` | New write keys; `request` asks the peer to follow |
| `tls_close(tls)` | close_notify |
| `tls_state()`, `tls->alert`, `tls->group`, `tls_psk_used()`, `tls->max_frag` | Status |
| `tls->on_event` | Optional callback: `TLS_EVT_CONNECTED`, `TLS_EVT_CLOSED` (close_notify received), `TLS_EVT_ERROR` (REQ-TLS-038..040) |

States: `IDLE` → `HANDSHAKE` → `CONNECTED` → `CLOSED` (the peer's
close_notify; writing is still allowed until our own) or `ERROR` (an alert
sent or received; keys wiped).

The demos: `tls_echo_demo` (port 4433), `https_demo` (HTTP/1.0 on 443,
using http.c's parser and formatter), `tls_client_demo`.

---

## 5. Record layer (RFC 8446 §5)

- **Receiving.**  rx holds `[handshake bytes awaiting a whole message |
  records not yet processed]`.  A record's header is checked as soon as
  its five bytes are in — the content type must be one of the four, the
  length within 2^14 (plaintext) or 2^14 + 256 (protected) and within the
  buffer — so a non-TLS peer is refused at once, not after a body that
  never comes.  Protected records are opened in place (AAD = the header,
  nonce = IV XOR sequence number, padding stripped; `bad_record_mac` on
  failure, REQ-TLS-027..030) and their handshake content is appended to the
  handshake area, so messages split over records, or records carrying
  several messages, are all the same to the parser.  Application data
  stays in rx until `tls_read()` takes it, and later records wait behind it.
- **Rules enforced.**  A key change must fall on a record boundary; no
  other record may come between the fragments of a handshake message;
  zero-length handshake fragments and protected CCS are refused; a
  plaintext alert is accepted during the handshake (a peer that failed
  before it had our keys).
- **Sending.**  Handshake messages are built in place in tx, one step at a
  time, and hashed as they are finished; consecutive messages share a
  record.  If tx has no room for the next message the step waits for
  `tls_tx_done()` — the server's flight goes out through a 600-byte tx.  A
  message larger than the negotiated fragment length is written into one
  record region and split into several records when it is sealed (room
  for each extra header and tag is reserved first).
- **Alerts.**  A fatal error drops a half-built record, sends the alert
  (protected if our keys are active, if tx has room), sets `ERROR` and
  wipes every secret and key.  `close_notify` and `user_canceled` are not
  errors.

---

## 6. Handshake

**Server** (`tls_accept`).  The ClientHello is parsed strictly (lengths,
duplicate extensions, pre_shared_key last) and then decided in this order:

1. `supported_versions` must offer TLS 1.3 → else `protocol_version`;
   `TLS_AES_128_GCM_SHA256` must be offered → else `handshake_failure`.
2. Our PSK: the first identity that matches, if the modes allow — psk_dhe_ke
   when there is a usable share, else psk_ke; its binder must check out
   (`decrypt_error`).
3. The share: x25519 preferred over secp256r1, among `cfg->groups`.
4. No usable share but a group in common, and the handshake needs (EC)DHE:
   a **HelloRetryRequest** for it (once; ClientHello1 becomes message_hash,
   RFC 8446 §4.4.1).
5. Otherwise certificates: signature_algorithms must include our scheme.

Then ServerHello (pre_shared_key, key_share, supported_versions — RFC
8448's order), the dummy CCS for a compatibility-mode client,
EncryptedExtensions (max_fragment_length when asked), Certificate and
CertificateVerify (not with a PSK), Finished; the client's Finished is
checked in constant time.

**Client** (`tls_connect`).  The ClientHello offers exactly what we do:
TLS 1.3, the suite, a share of the first configured group (none for a
psk_ke-only client), both signature schemes, server_name, and the PSK with
its binder.  The ServerHello must echo the (empty) session id, select our
suite and a group we sent a share for, and carry only what we offered.  A
**HelloRetryRequest** is answered once with the same random, a share of the
requested group, the cookie echoed and a fresh binder over message_hash +
HRR.  The server's Certificate is verified against the backend's trust
anchors and `host` and **kept in rx** until CertificateVerify has been
checked with its key, so the client never copies the leaf.  A
CertificateRequest is answered with an empty Certificate.  With a PSK the
server sends no certificates.

**After the handshake.**  KeyUpdate: the peer's next keys; when asked, ours
follow after a KeyUpdate of our own.  `tls_write()` updates by itself after
2^24 records under one key (RFC 8446 §5.5) and sends nothing more under the
old key while there is no room for the KeyUpdate.  NewSessionTicket is
ignored (no resumption store).

---

## 7. Key schedule (RFC 8446 §7)

Pure functions, tested against RFC 8448: `tls_expand_label()`,
`tls_derive_secret()`, `tls_early_secret()` (with or without a PSK),
`tls_next_secret()` (Early → Handshake → Master), `tls_traffic_keys()`,
`tls_finished_mac()`, `tls_psk_binder()`, `tls_transcript_hrr()`,
`tls_update_secret()`, `tls_record_seal()` / `tls_record_open()`.  A
connection keeps three secrets: the schedule secret (Handshake Secret, then
the peer's pending application secret), ours and the peer's current
traffic secret.

---

## 8. Security notes

- Finished MACs and binders are compared in constant time (`tls_equal`).
- Every secret, key and ephemeral private key is wiped when it is done
  with and on any fatal error.
- The client verifies the chain, the name (DNS or IP) and CertificateVerify
  before anything is encrypted to the server, and refuses anything it did
  not offer.
- No 0-RTT, no renegotiation, no compression, no downgrade path.
- Randomness (ClientHello/ServerHello random, key shares, signatures) comes
  only from the backend.

---

## 9. Buffers and memory

| | Size | Notes |
|---|---|---|
| `tls_conn_t` | 440 B | 128 of them the backend's SHA-256 state |
| `tls_config_t` | 40 B | shared by any number of connections |
| rx | largest record + a partial handshake message | A peer may send 16,645-byte records; the handshake needs room for its largest message (the client: the server's Certificate plus CertificateVerify, ~700 B with one ECDSA certificate).  With max_fragment_length 512 a client's rx of 800 bytes takes any amount of data |
| tx | largest message we send + 22 | The server's Certificate (one ECDSA P-256 certificate: 494 B) |
| Stack | ~360 B per deepest frame in tls.c | plus the backend's (Mbed TLS ECDH and signatures are the heaviest) |

---

## 10. Size (Cortex-M0, `-Os -mthumb`)

| | .text |
|---|---:|
| Key schedule + records (stage 13.2) | 911 B |
| + server handshake (13.3) | 5,024 B |
| + client (13.4) | 7,448 B |
| + PSK (13.5) | 8,602 B |
| + HelloRetryRequest, groups (13.6a) | 9,832 B |
| + max_fragment_length, KeyUpdate API (13.6b) | 10,360 B |
| `make arm-size-tls` (the benchmark flags: function sections, `NET_DEBUG=0`) | **10,323 B** |

The stages were measured with a plain `-Os -mthumb -mcpu=cortex-m0` compile.
No division helpers are pulled in.  The crypto backend is extra and depends
entirely on its configuration (Mbed TLS with x25519/P-256, AES-GCM, SHA-256
and X.509 is several times the size of tls.c); a PSK-only (psk_ke) build
needs no ECC or X.509 at all.

---

## 11. Testing

**Unit (208 tests, CMake):**

| Suite | Tests | |
|---|---:|---|
| `test_tls_crypto` | 22 | The backend: SHA-256, HMAC (RFC 4231), HKDF (RFC 5869), AES-GCM, X25519 (RFC 7748), P-256, ECDSA, RSA-PSS, chains (alerts, IP names, other anchors), random |
| `test_tls_keys` | 34 | Key schedule and records against RFC 8448 §3 (every secret, key, IV, both Finished, all eight protected records byte for byte), §4 (resumption PSK binder, PSK + DHE schedule), §5 (HelloRetryRequest transcript); malformed records |
| `test_tls_server` | 103 | A scripted client checks every message.  With the RFC 8448 server's randomness, our ServerHello to the RFC's ClientHello is the RFC's byte for byte (§3 and the PSK case of §4).  Refusals for every malformed or unacceptable ClientHello, PSK selection, HRR, max_fragment_length (splitting, a tx canary), KeyUpdate, alerts |
| `test_tls_client` | 49 | The client against our server over memory (both certificate types, byte at a time, small buffers, trust and name failures, PSK, HRR, max_fragment_length, KeyUpdate) and against a scripted server that gets each message wrong on purpose |

`tests/tls/gen_rfc8448.py` extracts the RFC 8448 traces into
`tests/unit/tls_rfc8448.h`, checking every value's stated length.  Each
stage was mutation-tested: every conditional in tls.c was broken in turn
and the suites had to fail; the survivors became tests.

**Blackbox (55 tests; TAP and the raw-socket driver on Linux, feth on
macOS; CI job `blackbox-tls`):**

| Suite | Tests | Peers |
|---|---:|---|
| `test_tls_conform.py` | 29 | Python ssl and openssl s_client against `tls_echo_demo`: handshake, 40 kB and 16 kB-record echoes, close_notify, refusals (TLS 1.2, group, suite, signature), KeyUpdate, a tampered record, a ClientHello in 7-byte segments, coalesced records, HRR, max_fragment_length, PSK (openssl, Python 3.13+), IPv6 |
| `test_tls_client_conform.py` | 17 | Python ssl and openssl s_server against `tls_client_demo`: SNI, 30 kB echo, RSA-PSS, name and trust failures, a TLS 1.2 server, client-certificate requests, HRR, max_fragment_length, KeyUpdate, PSK (psk_dhe_ke, psk_ke, certificate-less servers) |
| `test_https_conform.py` | 9 | Python and curl against `https_demo` |

Interop: OpenSSL 3.0 (CI), 3.5 (Debian 13), 3.6 (macOS); Python 3.12–3.14;
curl (Linux OpenSSL, macOS system).  The TLS suites also found a TCP bug:
segments were delivered without checking their sequence number against
RCV.NXT, so a retransmission with new boundaries duplicated bytes — fixed
in tcp.c (in-order delivery) before stage 13.3 was committed.
