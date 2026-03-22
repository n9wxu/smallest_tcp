# TLS 1.3 Design

**Protocol:** Transport Layer Security 1.3  
**Files:** `include/tls.h`, `src/tls.c`, `include/tls_crypto.h`  
**Milestone:** 12  
**Last updated:** 2026-03-21  
**Status:** Preliminary / Pre-implementation

---

## 1. Scope and Philosophy

TLS provides encryption, integrity, and authentication for TCP streams.  For
**smallest_tcp**, the design priorities are identical to the rest of the stack:

- **Zero `malloc()`** — all state in application-owned structs
- **TLS 1.3 only** — TLS 1.2 and earlier are deprecated and more complex; no
  version negotiation downgrade path
- **Single mandatory cipher suite** — `TLS_AES_128_GCM_SHA256`; AES-128-GCM is
  mandatory in RFC 8446 and fits in small MCU flash
- **Pluggable crypto backend** — the TLS layer provides state machine and record
  framing; all cryptographic primitives (ECDH, HKDF, AES-GCM, SHA-256,
  signature verification) are delegated to an external library via a
  `tls_crypto_t` vtable, following the same pattern as `net_mac_t`

This means **smallest_tcp does not implement cryptography**.  The application
links a crypto backend (mbedTLS, wolfSSL, BearSSL, or a custom implementation)
and provides it to the TLS layer at init time.

---

## 2. Architecture

```
┌──────────────────────────────────────────────┐
│                Application                    │
│  tls_write(tls, buf, len)                    │
│  tls_read(tls, buf, len)                     │
├──────────────────────────────────────────────┤
│  tls.c — Record layer + Handshake SM         │
│  (no crypto — pure protocol framing/state)   │
├─────────────────┬────────────────────────────┤
│  tls_crypto.h   │  tls_cert.h                │
│  (crypto vtable)│  (cert/key storage)        │
│  mbedTLS driver │  PSK table / DER cert buf  │
├─────────────────┴────────────────────────────┤
│  tcp.c — reliable stream transport           │
└──────────────────────────────────────────────┘
```

The TLS layer sits above `tcp.c`.  It consumes and produces raw bytes that the
application feeds in from the TCP receive callback or pushes out through the TCP
send path.  There is no direct coupling between `tls.c` and `tcp.c` — the
application wires them together.

---

## 3. Pluggable Crypto Backend

```c
/**
 * TLS crypto backend vtable.
 * The application provides a concrete implementation (mbedTLS, wolfSSL, etc.)
 * and passes it to tls_init().  The TLS layer calls these functions for all
 * cryptographic operations.  All functions return 0 on success, non-zero on
 * error.
 */
typedef struct {
    /* ── Key exchange (ECDHE x25519 or P-256) ───────────────────────── */
    int (*ecdh_keygen)(void *ctx, uint8_t *pubkey_out, uint8_t *privkey_out);
    int (*ecdh_shared)(void *ctx,
                       const uint8_t *peer_pubkey,
                       const uint8_t *our_privkey,
                       uint8_t *shared_secret_out);

    /* ── Key derivation (HKDF-SHA-256, RFC 8446 §7) ─────────────────── */
    int (*hkdf_extract)(void *ctx,
                        const uint8_t *salt, uint8_t salt_len,
                        const uint8_t *ikm,  uint8_t ikm_len,
                        uint8_t *prk_out);           /* 32-byte output */
    int (*hkdf_expand_label)(void *ctx,
                             const uint8_t *secret, uint8_t secret_len,
                             const char    *label,
                             const uint8_t *context, uint8_t context_len,
                             uint8_t *out, uint8_t out_len);

    /* ── AEAD (AES-128-GCM) ──────────────────────────────────────────── */
    int (*aead_encrypt)(void *ctx,
                        const uint8_t *key,   /* 16 bytes */
                        const uint8_t *nonce, /* 12 bytes */
                        const uint8_t *aad,   uint16_t aad_len,
                        const uint8_t *plain, uint16_t plain_len,
                        uint8_t *cipher_out,
                        uint8_t *tag_out);    /* 16 bytes */
    int (*aead_decrypt)(void *ctx,
                        const uint8_t *key,
                        const uint8_t *nonce,
                        const uint8_t *aad,    uint16_t aad_len,
                        const uint8_t *cipher, uint16_t cipher_len,
                        const uint8_t *tag,
                        uint8_t *plain_out);

    /* ── Signature / certificate (optional — PSK mode skips these) ──── */
    int (*verify_cert_chain)(void *ctx,
                             const uint8_t *cert_der, uint16_t cert_len,
                             const uint8_t *ca_der,   uint16_t ca_len);
    int (*verify_sig)(void *ctx,
                      const uint8_t *msg,    uint16_t msg_len,
                      const uint8_t *sig,    uint16_t sig_len,
                      const uint8_t *pubkey, uint16_t key_len);

    /* ── Random ──────────────────────────────────────────────────────── */
    int (*random_bytes)(void *ctx, uint8_t *out, uint8_t len);

    void *ctx;   /* opaque pointer passed to every function */
} tls_crypto_t;
```

---

## 4. TLS 1.3 Handshake State Machine

```
Client                                    Server

IDLE
  │── tls_connect() ──────────────────►  IDLE
  │                                         │── tls_accept() ──►  IDLE
  ▼                                         ▼
CLIENT_HELLO_SENT                       SERVER_WAIT_CH
  │── ClientHello ──────────────────►
  │   (key_share, supported_versions,
  │    signature_algorithms)
  │                                    ◄── ServerHello
  │                                    ◄── {EncryptedExtensions}
  │                                    ◄── {Certificate}         (if cert auth)
  │                                    ◄── {CertificateVerify}   (if cert auth)
  │                                    ◄── {Finished}
  ▼
SERVER_HELLO_RECEIVED
  │── {Finished} ─────────────────────►
  ▼
CONNECTED                               CONNECTED

Application data (encrypted records)
  │── {ApplicationData} ◄─────────────►
  ▼
(tls_close_notify)
CLOSED                                  CLOSED
```

States: `TLS_IDLE`, `TLS_CLIENT_HELLO_SENT`, `TLS_SERVER_WAIT_CH`,
`TLS_SERVER_HELLO_RCVD`, `TLS_CONNECTED`, `TLS_CLOSING`, `TLS_CLOSED`,
`TLS_ERROR`.

---

## 5. TLS Connection State Structure

```c
/* Key material for one traffic direction */
typedef struct {
    uint8_t key[16];     /* AES-128 key         */
    uint8_t iv[12];      /* per-record base IV  */
    uint64_t seq;        /* record sequence number (XOR'd into IV) */
} tls_keys_t;

typedef struct {
    uint8_t            state;          /* TLS_IDLE … TLS_ERROR          */
    uint8_t            is_server;      /* 0 = client, 1 = server        */
    tls_keys_t         write_keys;     /* encrypt outbound              */
    tls_keys_t         read_keys;      /* decrypt inbound               */

    /* Handshake transcript hash (SHA-256 running hash, no malloc) */
    uint8_t            transcript[32]; /* updated after each HS message */

    /* Key exchange ephemeral state */
    uint8_t            ecdh_priv[32];  /* our ephemeral private key     */
    uint8_t            ecdh_pub[32];   /* our ephemeral public key      */

    /* TLS record reassembly (application's buffer, zero-copy) */
    uint8_t           *rx_buf;         /* application-provided RX buffer */
    uint16_t           rx_buf_len;
    uint16_t           rx_pending;     /* bytes of partial record in buf */

    const tls_crypto_t *crypto;        /* pluggable backend vtable      */
    const tls_cert_t   *cert;          /* our certificate / PSK config  */

    tls_event_fn_t     on_event;       /* CONNECTED, CLOSED, ERROR      */
    void              *evt_ctx;
} tls_conn_t;
```

All fields are in the application-owned `tls_conn_t`.  No dynamic allocation.

---

## 6. TLS Record Layer

TLS 1.3 record format:
```
Byte  0      : ContentType (0x17 = application_data, 0x16 = handshake,
                             0x15 = alert, 0x14 = change_cipher_spec)
Bytes 1–2    : legacy_record_version (0x03 0x03 always)
Bytes 3–4    : length (big-endian, max 2^14 + 256 bytes per RFC 8446)
Bytes 5+     : encrypted payload (after handshake complete)
```

After the handshake, every record is encrypted with AES-128-GCM.  The AEAD
additional data (AAD) is the 5-byte record header.  The nonce is the write
key's base IV XOR'd with the 64-bit sequence number (big-endian, zero-padded
to 12 bytes).

**Buffer sizing constraint:** The application's buffer must hold at least one
maximum-size TLS record (2^14 + 256 = 16,640 bytes).  On small MCUs where this
is too large, the maximum fragment size can be negotiated via the
`max_fragment_length` extension (RFC 6066) — values of 512, 1024, 2048, or 4096
bytes.  This is controlled by a compile-time `#define` in `net_config.h`.

---

## 7. Certificate and PSK Configuration

```c
typedef struct {
    /* Certificate-based auth */
    const uint8_t *cert_der;      /* our certificate in DER format        */
    uint16_t       cert_der_len;
    const uint8_t *privkey_der;   /* our private key in DER format        */
    uint16_t       privkey_der_len;
    const uint8_t *ca_cert_der;   /* CA cert to verify peer (client auth) */
    uint16_t       ca_cert_der_len;

    /* Pre-shared key (PSK) — simpler, good for device-to-device          */
    const uint8_t *psk_identity;  /* identity label                       */
    uint8_t        psk_id_len;
    const uint8_t *psk_key;       /* raw PSK bytes                        */
    uint8_t        psk_key_len;

    uint8_t        auth_mode;     /* TLS_AUTH_CERT, TLS_AUTH_PSK           */
} tls_cert_t;
```

For MCU-to-MCU scenarios, PSK mode is strongly preferred: no certificate chain
parsing, no asymmetric signature verification, dramatically lower code and RAM
footprint.

---

## 8. API

```c
/* Initialise — must be called before tls_connect/tls_accept. */
void tls_init(tls_conn_t *tls,
              const tls_crypto_t *crypto,
              const tls_cert_t   *cert,
              uint8_t            *rx_buf,  uint16_t rx_buf_len,
              tls_event_fn_t      on_event, void *evt_ctx);

/* Begin client handshake (call tls_input() to feed server responses). */
net_err_t tls_connect(tls_conn_t *tls, const char *server_name /* SNI, may be NULL */);

/* Begin server handshake (call tls_input() to feed client messages). */
net_err_t tls_accept(tls_conn_t *tls);

/* Feed received TCP bytes into the TLS engine (called from TCP rx callback). */
net_err_t tls_input(tls_conn_t *tls, const uint8_t *data, uint16_t len,
                    uint8_t *plain_out, uint16_t *plain_len_out);

/* Encrypt and output application data.
   Returns encrypted record bytes in tls->tx_record (app sends via tcp_send). */
net_err_t tls_write(tls_conn_t *tls,
                    const uint8_t *data, uint16_t len,
                    uint8_t *record_out, uint16_t *record_len_out);

/* Send close_notify alert; graceful shutdown. */
net_err_t tls_close(tls_conn_t *tls,
                    uint8_t *record_out, uint16_t *record_len_out);
```

The application wires `tls_input`/`tls_write` to the TCP connection's receive
callback and send path.  No thread or task model is assumed.

---

## 9. Integration Example

```c
/* In the TCP receive callback: */
static void on_tcp_recv(tcp_conn_t *conn, const uint8_t *data, uint16_t len) {
    uint8_t  plain[256];
    uint16_t plain_len;
    if (tls_input(&tls, data, len, plain, &plain_len) == NET_OK && plain_len)
        app_handle_data(plain, plain_len);
}

/* Sending application data: */
static void send_https_response(const uint8_t *body, uint16_t blen) {
    uint8_t  record[300];
    uint16_t record_len;
    tls_write(&tls, body, blen, record, &record_len);
    tcp_send(&tcp_conn, record, record_len);
}
```

---

## 10. Zero-Allocation Guarantee

`tls.c` calls no dynamic allocation functions.  All state is in the
application-owned `tls_conn_t`.  Record buffers are provided by the application
at init time.  Handshake message buffers are built in-place in the application's
transmit buffer.

---

## 11. Relationship to DTLS

TLS and DTLS share the same `tls_crypto_t` backend vtable.  The DTLS layer
(`dtls.c`) handles the datagram-specific concerns (epoch, sequence, retransmit,
anti-replay) and delegates all cryptography to the same pluggable backend.  An
application that links both TLS and DTLS therefore links only one crypto backend.
See [`docs/design/dtls.md`](dtls.md).
