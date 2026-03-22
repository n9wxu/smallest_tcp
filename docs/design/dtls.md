# DTLS 1.3 Design

**Protocol:** Datagram Transport Layer Security 1.3  
**Files:** `include/dtls.h`, `src/dtls.c`  
**Shared:** `include/tls_crypto.h` (same backend vtable as TLS)  
**Milestone:** 13  
**Last updated:** 2026-03-21  
**Status:** Preliminary / Pre-implementation

---

## 1. Scope and Philosophy

DTLS provides the same security guarantees as TLS — encryption, integrity,
authentication — but over **unreliable, unordered UDP datagrams** rather than a
TCP stream.  Use cases include:

- **CoAP over DTLS** — constrained device messaging (IoT sensors, actuators)
- **RADIUS/EAP** — 802.1X network access authentication  
- **SIP signalling** — VoIP setup over UDP  
- **Secure UDP tunnels** between embedded devices

The DTLS design follows the same principles as the rest of the stack:

- **Zero `malloc()`** — all state in application-owned structs
- **DTLS 1.3 only** (RFC 9147) — avoids the complexity of DTLS 1.2 cookie
  exchange and epoch management while retaining full security
- **Same `tls_crypto_t` backend** as TLS — one crypto library serves both;
  link only `dtls.c` (not `tls.c`) if you only need DTLS
- **Pluggable transport** — DTLS sits above `udp.c` but is not coupled to it;
  the application wires sends and receives

---

## 2. Architecture

```
┌──────────────────────────────────────────────┐
│                Application                    │
│  dtls_send(dtls, buf, len)                   │
│  dtls_input(dtls, src_ip, src_port,          │
│             data, len, plain_out, plen_out)  │
├──────────────────────────────────────────────┤
│  dtls.c — DTLS record layer + Handshake SM   │
│  Adds: epoch, seq, retransmit, anti-replay   │
│  (no crypto — pure protocol framing/state)   │
├──────────────────────────────────────────────┤
│  tls_crypto.h — shared crypto vtable         │
│  (same backend as tls.c — link once)         │
├──────────────────────────────────────────────┤
│  udp.c — datagram transport                  │
└──────────────────────────────────────────────┘
```

DTLS re-uses the `tls_crypto_t` vtable directly; both modules can reference the
same statically-allocated backend instance.

---

## 3. Key Differences from TLS

| Concern | TLS (stream) | DTLS (datagram) |
|---|---|---|
| Transport | TCP (reliable, ordered) | UDP (unreliable, unordered) |
| Record header | 5 bytes | 13 bytes (adds epoch + seq) |
| Handshake retransmit | N/A (TCP handles it) | Flight-based retransmit timer |
| Out-of-order records | Impossible | Anti-replay window |
| Fragmentation | TCP stream | DTLS handshake fragmentation |
| Max record size | 2^14 + 256 B | MTU − headers (typ. ~1200 B) |
| RFC | 8446 | 9147 |

---

## 4. DTLS Record Header

```
Byte  0      : unified_hdr byte
               Bit 7     : 1 (fixed)
               Bit 6     : C = connection ID present
               Bit 5     : S = sequence_number length (0=8-bit, 1=16-bit)
               Bit 4     : L = length present
               Bits 3–0  : epoch (low 4 bits)
Bytes 1–2    : sequence_number (8 or 16 bits depending on S)
Bytes 3–4    : length (present if L=1)
Bytes 5+     : encrypted payload (AEAD ciphertext + 16-byte tag)
```

DTLS 1.3 uses a compact unified header (RFC 9147 §4.3).  The epoch number
prevents replay of records from a previous handshake.  The sequence number is
per-epoch and monotonically increasing within an epoch.

---

## 5. Anti-Replay Window

DTLS must discard duplicate or replayed records.  A 64-bit sliding window is
maintained per epoch:

```c
typedef struct {
    uint64_t top;       /* highest sequence number seen in this epoch */
    uint64_t window;    /* bitmask: bit N = received seq (top - N)    */
} dtls_replay_t;
```

A record with sequence number `seq` is accepted if:
- `seq > top` (advance the window), OR
- `seq` is within the window (`top - 63 ≤ seq ≤ top`) AND the corresponding
  bit is clear (not already received)

Records older than the window (i.e. `seq < top - 63`) are discarded silently.

---

## 6. Handshake Retransmit Timer

DTLS handshake messages are sent in **flights** (groups of messages that must
all be received before the peer responds).  Because UDP can lose datagrams, DTLS
retransmits entire flights on timeout.

```c
typedef struct {
    uint8_t  *flight_buf;     /* application-provided buffer for saved flight */
    uint16_t  flight_len;     /* bytes in flight_buf                           */
    uint32_t  rto_ms;         /* current retransmit timeout (ms)               */
    uint32_t  timer_ms;       /* countdown                                     */
    uint8_t   retries;        /* retransmit count (abort after MAX_RETRIES)    */
} dtls_flight_t;
```

The retransmit timer follows RFC 9147 §5.8: initial RTO = 1000 ms, doubling on
each retransmit, maximum `NET_DTLS_MAX_RTO_MS` (configurable, default 60000 ms).
After `NET_DTLS_MAX_RETRANSMITS` failures, the handshake aborts with
`DTLS_EVT_ERROR`.

`dtls_tick(dtls, elapsed_ms)` drives the retransmit timer and must be called
from the application's main loop alongside `tcp_tick` and DHCP timers.

---

## 7. DTLS Connection State Structure

```c
typedef struct {
    uint8_t            state;          /* DTLS_IDLE … DTLS_ERROR        */
    uint8_t            is_server;

    /* Current epoch keys (write = encrypt outbound, read = decrypt inbound) */
    tls_keys_t         write_keys;
    tls_keys_t         read_keys;
    uint16_t           write_epoch;
    uint16_t           read_epoch;

    /* Anti-replay window per epoch */
    dtls_replay_t      replay;

    /* Handshake flight retransmit */
    dtls_flight_t      flight;

    /* Peer address (for response routing) */
    uint32_t           peer_ip;
    uint16_t           peer_port;

    /* Handshake transcript (SHA-256 running hash, same as TLS) */
    uint8_t            transcript[32];

    /* ECDH ephemeral state */
    uint8_t            ecdh_priv[32];
    uint8_t            ecdh_pub[32];

    /* RX reassembly for fragmented handshake messages */
    uint8_t           *hs_buf;         /* application-provided buffer   */
    uint16_t           hs_buf_len;
    uint16_t           hs_pending;

    const tls_crypto_t *crypto;        /* shared with tls.c if both used */
    const tls_cert_t   *cert;

    dtls_event_fn_t    on_event;
    void              *evt_ctx;
} dtls_conn_t;
```

---

## 8. Handshake Fragmentation

Handshake messages (especially Certificate) may exceed the UDP MTU.  DTLS
handles this via message_seq, fragment_offset, and fragment_length fields in the
DTLS handshake header.  The implementation reassembles fragments into the
application-provided `hs_buf` before processing.  If `hs_buf` is too small, the
handshake aborts with `DTLS_EVT_ERROR`.

---

## 9. API

```c
/* Initialise. */
void dtls_init(dtls_conn_t        *dtls,
               const tls_crypto_t *crypto,
               const tls_cert_t   *cert,
               uint8_t            *hs_buf,    uint16_t hs_buf_len,
               uint8_t            *flight_buf, uint16_t flight_buf_len,
               dtls_event_fn_t     on_event,  void *evt_ctx);

/* Begin client handshake to a specific peer. */
net_err_t dtls_connect(dtls_conn_t *dtls,
                       uint32_t peer_ip, uint16_t peer_port,
                       uint8_t *tx_out, uint16_t *tx_len_out);

/* Begin server handshake (waits for ClientHello via dtls_input). */
net_err_t dtls_accept(dtls_conn_t *dtls);

/* Feed an incoming UDP datagram.
   src_ip / src_port: sender's address (for response routing).
   plain_out / plain_len_out: decrypted application data if CONNECTED.
   tx_out / tx_len_out: any handshake response to send back. */
net_err_t dtls_input(dtls_conn_t *dtls,
                     uint32_t src_ip, uint16_t src_port,
                     const uint8_t *data, uint16_t len,
                     uint8_t *plain_out,  uint16_t *plain_len_out,
                     uint8_t *tx_out,     uint16_t *tx_len_out);

/* Encrypt one application datagram. */
net_err_t dtls_send(dtls_conn_t *dtls,
                    const uint8_t *data, uint16_t len,
                    uint8_t *record_out, uint16_t *record_len_out);

/* Drive retransmit timer — call with elapsed ms from main loop.
   tx_out / tx_len_out: retransmitted flight to send if timer fired. */
net_err_t dtls_tick(dtls_conn_t *dtls, uint32_t ms,
                    uint8_t *tx_out, uint16_t *tx_len_out);

/* Send close_notify and transition to CLOSED. */
net_err_t dtls_close(dtls_conn_t *dtls,
                     uint8_t *record_out, uint16_t *record_len_out);
```

---

## 10. Integration Example

```c
/* UDP port handler — feed received datagrams into DTLS: */
static void on_udp_coap(net_t *net, uint32_t src_ip, uint16_t src_port,
                        const uint8_t *src_mac,
                        const uint8_t *data, uint16_t len) {
    uint8_t  plain[256], tx[512];
    uint16_t plain_len, tx_len;

    dtls_input(&dtls, src_ip, src_port, data, len,
               plain, &plain_len, tx, &tx_len);

    if (tx_len)
        udp_send(net, src_ip, src_mac, COAP_PORT, src_port, tx, tx_len);
    if (plain_len)
        coap_handle(plain, plain_len);
}

/* In the main loop: */
dtls_tick(&dtls, elapsed_ms, tx_buf, &tx_len);
if (tx_len)
    udp_send(&net, dtls.peer_ip, peer_mac, COAP_PORT, dtls.peer_port,
             tx_buf, tx_len);
```

---

## 11. Shared Crypto Backend

DTLS uses exactly the same `tls_crypto_t` vtable as TLS.  If an application
uses both TLS (for HTTPS) and DTLS (for CoAP), it links a single crypto backend
instance and passes the same pointer to both `tls_init()` and `dtls_init()`.
This keeps flash usage minimal.

---

## 12. Zero-Allocation Guarantee

`dtls.c` calls no dynamic allocation functions.  All state is in the
application-owned `dtls_conn_t`.  Reassembly and flight buffers are provided by
the application at init time.  DTLS records are built in-place in the
application's transmit buffer.
