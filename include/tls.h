/**
 * @file tls.h
 * @brief TLS 1.3 (RFC 8446) — record protection and key schedule.
 *
 * The protocol is smallest_tcp's own; every cryptographic primitive comes
 * from the application's tls_crypto_t backend (REQ-TLS-006).  One cipher
 * suite, TLS_AES_128_GCM_SHA256, so every secret and hash is 32 bytes.
 *
 * The building blocks — the key schedule of RFC 8446 §7 and the protected
 * records of §5.2 — are pure functions, tested against the RFC 8448 traces.
 * On them sits the connection: a handshake state machine that consumes and
 * produces ciphertext in application buffers, with no knowledge of the
 * transport (the application moves the bytes, e.g. to and from TCP).
 *
 *   tls_init(&tls, &cfg, rx, sizeof rx, tx, sizeof tx);
 *   tls_accept(&tls);
 *   loop:
 *     n = tcp_recv(&conn, p, tls_rx_space(&tls, &p));  tls_rx_commit(&tls, n);
 *     while ((n = tls_tx_pending(&tls, &q)))  tls_tx_done(&tls,
 *                                               tcp_send(net, &conn, q, n));
 *     tls_read() / tls_write() once tls_state() is TLS_STATE_CONNECTED
 */

#ifndef TLS_H
#define TLS_H

#include "tls_crypto.h"

#include <stddef.h>
#include <stdint.h>

/* ── Record layer (RFC 8446 §5) ──────────────────────────────────────── */

/* ContentType */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT 21
#define TLS_CT_HANDSHAKE 22
#define TLS_CT_APPLICATION_DATA 23

#define TLS_RECORD_HDR 5 /**< type, legacy_record_version, length */
/** Bytes a protected record adds to its content: header, type, tag. */
#define TLS_RECORD_OVERHEAD (TLS_RECORD_HDR + 1 + TLS_AEAD_TAG_LEN)
#define TLS_MAX_PLAINTEXT 16384u /**< 2^14 */
#define TLS_MAX_CIPHERTEXT (TLS_MAX_PLAINTEXT + 256u)

/* AlertDescription (RFC 8446 §6) */
#define TLS_ALERT_CLOSE_NOTIFY 0
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_BAD_RECORD_MAC 20
#define TLS_ALERT_RECORD_OVERFLOW 22
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_BAD_CERTIFICATE 42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define TLS_ALERT_CERTIFICATE_REVOKED 44
#define TLS_ALERT_CERTIFICATE_EXPIRED 45
#define TLS_ALERT_CERTIFICATE_UNKNOWN 46
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_UNKNOWN_CA 48
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_DECRYPT_ERROR 51
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INSUFFICIENT_SECURITY 71
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_MISSING_EXTENSION 109
#define TLS_ALERT_UNSUPPORTED_EXTENSION 110
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY 115

/** @brief The keys protecting one direction of records (RFC 8446 §7.3). */
typedef struct {
  uint8_t key[TLS_AEAD_KEY_LEN];
  uint8_t iv[TLS_AEAD_IV_LEN];
  uint64_t seq; /**< Records protected so far; XORed into the nonce */
} tls_keys_t;

/**
 * Protect one record in place (RFC 8446 §5.2).
 *
 * @p rec[TLS_RECORD_HDR ..] holds @p len bytes of content of type @p type;
 * the record needs @p len + TLS_RECORD_OVERHEAD bytes.  Writes the header
 * (opaque_type application_data), the inner content type and the tag, and
 * advances @p k->seq.
 * @return The length of the whole record.
 */
size_t tls_record_seal(const tls_crypto_t *c, tls_keys_t *k, uint8_t type,
                       uint8_t *rec, size_t len);

/**
 * Remove the protection of one record in place.  @p rec is the whole record
 * (header included, @p rec_len bytes).  On success the content is at
 * @p rec + TLS_RECORD_HDR, @p type receives its content type (the padding is
 * stripped) and @p k->seq advances.
 * @return The content length, or the negated alert to send:
 *         -TLS_ALERT_BAD_RECORD_MAC, -TLS_ALERT_RECORD_OVERFLOW,
 *         -TLS_ALERT_DECODE_ERROR or -TLS_ALERT_UNEXPECTED_MESSAGE.
 */
int tls_record_open(const tls_crypto_t *c, tls_keys_t *k, uint8_t *rec,
                    size_t rec_len, uint8_t *type);

/* ── Key schedule (RFC 8446 §7.1) ────────────────────────────────────── */

/**
 * HKDF-Expand-Label(@p secret, "tls13 " + @p label, @p context, @p out_len).
 * @p label is at most 12 characters and @p context at most 32 bytes (the
 * longest TLS 1.3 uses).
 */
void tls_expand_label(const tls_crypto_t *c, const uint8_t *secret,
                      const char *label, const uint8_t *context,
                      size_t context_len, uint8_t *out, size_t out_len);

/**
 * Derive-Secret(@p secret, @p label, Messages) where @p hash is
 * Transcript-Hash(Messages), or NULL for the hash of no messages.
 */
void tls_derive_secret(const tls_crypto_t *c, const uint8_t *secret,
                       const char *label, const uint8_t *hash,
                       uint8_t out[TLS_HASH_LEN]);

/**
 * The Early Secret: HKDF-Extract(0, @p psk), or of 32 zero bytes when
 * @p psk is NULL (no PSK).
 */
void tls_early_secret(const tls_crypto_t *c, const uint8_t *psk,
                      size_t psk_len, uint8_t out[TLS_HASH_LEN]);

/**
 * Step the schedule to its next secret in place:
 * HKDF-Extract(Derive-Secret(@p secret, "derived", ""), @p ikm) — Early to
 * Handshake Secret with the (EC)DHE shared secret, Handshake to Master
 * Secret with @p ikm NULL (32 zero bytes).
 */
void tls_next_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN],
                     const uint8_t *ikm, size_t ikm_len);

/** The write key and IV of traffic secret @p secret; the sequence is 0. */
void tls_traffic_keys(const tls_crypto_t *c, const uint8_t *secret,
                      tls_keys_t *k);

/**
 * Finished verify_data (RFC 8446 §4.4.4): HMAC(finished_key, @p hash) with
 * finished_key = HKDF-Expand-Label(@p base, "finished", "", 32).
 */
void tls_finished_mac(const tls_crypto_t *c, const uint8_t *base,
                      const uint8_t hash[TLS_HASH_LEN],
                      uint8_t out[TLS_HASH_LEN]);

/**
 * PSK binder (RFC 8446 §4.2.11.2): HMAC under the binder key of the PSK's
 * Early Secret @p early — "res binder" for a @p resumption PSK (from a
 * ticket), "ext binder" for an external one — over @p hash, the transcript
 * hash of the ClientHello up to its binders.
 */
void tls_psk_binder(const tls_crypto_t *c, const uint8_t *early,
                    int resumption, const uint8_t hash[TLS_HASH_LEN],
                    uint8_t out[TLS_HASH_LEN]);

/**
 * After a HelloRetryRequest (RFC 8446 §4.4.1): @p transcript, so far the
 * hash of ClientHello1, restarts as the hash of the message_hash message
 * that stands for it.
 */
void tls_transcript_hrr(const tls_crypto_t *c, tls_hash_t *transcript);

/** KeyUpdate (RFC 8446 §7.2): the next generation of a traffic secret. */
void tls_update_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN]);

/** Constant-time comparison: 1 if equal. */
int tls_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* ── Connections ─────────────────────────────────────────────────────── */

/* HandshakeType (RFC 8446 §4) */
#define TLS_HS_CLIENT_HELLO 1
#define TLS_HS_SERVER_HELLO 2
#define TLS_HS_NEW_SESSION_TICKET 4
#define TLS_HS_ENCRYPTED_EXTENSIONS 8
#define TLS_HS_CERTIFICATE 11
#define TLS_HS_CERTIFICATE_REQUEST 13
#define TLS_HS_CERTIFICATE_VERIFY 15
#define TLS_HS_FINISHED 20
#define TLS_HS_KEY_UPDATE 24

/* ExtensionType */
#define TLS_EXT_SERVER_NAME 0
#define TLS_EXT_MAX_FRAGMENT_LENGTH 1
#define TLS_EXT_SUPPORTED_GROUPS 10
#define TLS_EXT_SIGNATURE_ALGORITHMS 13
#define TLS_EXT_PRE_SHARED_KEY 41
#define TLS_EXT_SUPPORTED_VERSIONS 43
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES 45
#define TLS_EXT_KEY_SHARE 51

#define TLS_AES_128_GCM_SHA256 0x1301

/* max_fragment_length (RFC 6066 §4), tls_config_t.max_fragment */
#define TLS_MFL_512 1
#define TLS_MFL_1024 2
#define TLS_MFL_2048 3
#define TLS_MFL_4096 4

/** Records protected under one key before a KeyUpdate replaces it (RFC
 *  8446 §5.5 allows 2^24.5 for AES-GCM). */
#define TLS_KEY_UPDATE_RECORDS (1ul << 24)

/* Key-exchange groups to use, tls_config_t.groups (0: both) */
#define TLS_GROUPS_X25519 0x01
#define TLS_GROUPS_SECP256R1 0x02

/* PSK key-exchange modes, tls_config_t.psk_modes (RFC 8446 §4.2.9) */
#define TLS_PSK_KE 0x01     /**< psk_ke: the PSK alone, no (EC)DHE */
#define TLS_PSK_DHE_KE 0x02 /**< psk_dhe_ke: PSK with (EC)DHE */

/** Connection state, tls_state(). */
typedef enum {
  TLS_STATE_IDLE = 0,  /**< Initialised; tls_accept() not yet called */
  TLS_STATE_HANDSHAKE, /**< Handshake in progress */
  TLS_STATE_CONNECTED, /**< Application data may flow */
  TLS_STATE_CLOSED,    /**< The peer sent close_notify */
  TLS_STATE_ERROR      /**< Fatal alert sent or received (tls->alert) */
} tls_state_t;

/* Events passed to tls_conn_t.on_event */
#define TLS_EVT_CONNECTED 0x01u
#define TLS_EVT_CLOSED 0x02u /**< close_notify received */
#define TLS_EVT_ERROR 0x04u

/**
 * @brief What an endpoint presents and accepts; shared by any number of
 * connections, application owned.
 */
typedef struct {
  const tls_crypto_t *crypto;

  /* Certificate authentication (a server's own chain) */
  const uint8_t *const *cert; /**< DER certificates, leaf first */
  const uint16_t *cert_len;
  uint8_t cert_count;
  const void *key;     /**< Private key, as the backend's sign() takes it */
  uint16_t sig_scheme; /**< TLS_SIG_* that @ref key signs with */
  uint8_t groups;      /**< TLS_GROUPS_* for (EC)DHE; 0: both (x25519
                            preferred) */
  uint8_t max_fragment; /**< Client: TLS_MFL_* to ask the server for (records
                             of at most 512 .. 4096 bytes, so a small rx
                             buffer suffices); 0: none.  A server grants
                             what a client asks. */

  /* A pre-shared key (RFC 8446 §2.2; SHA-256).  A client offers it, a
   * server takes it when the identity matches and the binder checks out,
   * and neither side then uses certificates (REQ-TLS-023/024). */
  const uint8_t *psk;      /**< NULL: none */
  uint16_t psk_len;
  const uint8_t *psk_id;   /**< Its identity */
  uint16_t psk_id_len;
  uint8_t psk_modes;       /**< TLS_PSK_KE and/or TLS_PSK_DHE_KE (0: DHE) */
  uint8_t psk_resumption;  /**< 1: from a ticket ("res binder") */
} tls_config_t;

/**
 * @brief One TLS connection.  The transport (TCP) is the application's:
 * it moves ciphertext between the connection's buffers and the socket.
 */
typedef struct tls_conn_s {
  const tls_config_t *cfg;
  uint8_t state;  /**< tls_state_t */
  uint8_t alert;  /**< The fatal alert sent or received */
  uint8_t step;   /**< Handshake step (internal) */
  uint16_t flags; /**< (internal) */
  uint16_t group; /**< Negotiated key-exchange group */
  uint16_t max_frag; /**< Negotiated record size limit (0: 2^14) */
  uint8_t sid_len;
  uint8_t sid[32]; /**< Server: the client's legacy_session_id, echoed;
                        client: its random, for a second ClientHello */
  uint8_t kx_priv[TLS_KX_PRIV_MAX]; /**< Client: our key share, until the
                                         ServerHello */
  const char *host; /**< Client: the name the certificate must carry */

  /* Key schedule */
  uint8_t secret[TLS_HASH_LEN]; /**< Handshake Secret, then the peer's
                                     next traffic secret (internal) */
  uint8_t rsec[TLS_HASH_LEN];   /**< The peer's traffic secret */
  uint8_t wsec[TLS_HASH_LEN];   /**< Our traffic secret */
  tls_hash_t transcript;
  tls_keys_t rkeys, wkeys;

  /* Receive buffer: [handshake bytes | records not yet processed] */
  uint8_t *rx;
  uint16_t rx_cap, rx_len;
  uint16_t hs_len;   /**< Handshake bytes awaiting a whole message */
  uint16_t hs_off;   /**< .. after a kept message (client: the
                          Certificate, until CertificateVerify) */
  uint16_t leaf_off, leaf_len; /**< Client: the server's certificate */
  uint16_t app_off;  /**< Unread application data: offset .. */
  uint16_t app_len;  /**< .. and length */
  uint16_t app_rec;  /**< Length of the record holding it */

  /* Transmit buffer: [sent | unsent records | record being built] */
  uint8_t *tx;
  uint16_t tx_cap, tx_len, tx_sent;
  uint16_t rec_start; /**< Offset of the record being built (internal) */
  uint8_t rec_type;   /**< Its content type (internal) */

  void (*on_event)(struct tls_conn_s *tls, uint8_t events); /**< Optional */
  void *user; /**< Application context */
} tls_conn_t;

/**
 * Initialise a connection over application buffers.  @p rx must hold the
 * largest record the peer sends plus any partial handshake message (a
 * peer may send records of up to 16 KiB; ClientHellos reach 2 KiB);
 * @p tx the largest message this side sends (the Certificate) plus
 * TLS_RECORD_OVERHEAD.  Buffers of up to 64 KiB are used.
 * @return 0, or -1 for a bad argument.
 */
int tls_init(tls_conn_t *tls, const tls_config_t *cfg, uint8_t *rx,
             size_t rx_cap, uint8_t *tx, size_t tx_cap);

/** Server: wait for a ClientHello. */
int tls_accept(tls_conn_t *tls);

/**
 * Client: queue a ClientHello (send it with tls_tx_pending()).  The
 * server's certificate chain must lead to one of the backend's trust
 * anchors and name @p host (a DNS name, sent as server_name, or an
 * address literal); NULL skips the name check.  @p host must stay valid
 * for the handshake.
 * @return 0, or -1 (bad state, or no room in tx).
 */
int tls_connect(tls_conn_t *tls, const char *host);

/**
 * Space for received ciphertext: copy up to the returned number of bytes
 * to @p *buf (e.g. with tcp_recv()), then call tls_rx_commit().
 */
size_t tls_rx_space(tls_conn_t *tls, uint8_t **buf);

/**
 * Process @p n bytes placed by tls_rx_space().
 * @return 0, or the negated alert that ended the connection.
 */
int tls_rx_commit(tls_conn_t *tls, size_t n);

/** Copy-in form of tls_rx_space() + tls_rx_commit(); returns bytes taken
 *  (fewer than @p len when the buffer is full or on error). */
size_t tls_input(tls_conn_t *tls, const uint8_t *data, size_t len);

/** Ciphertext waiting for the transport: returns its length, @p *buf. */
size_t tls_tx_pending(tls_conn_t *tls, const uint8_t **buf);

/** The transport took @p n bytes from tls_tx_pending(). */
void tls_tx_done(tls_conn_t *tls, size_t n);

/**
 * Encrypt application data into one record.
 * @return Bytes accepted (0 when the transmit buffer is full), or -1 if
 *         the connection is not open for writing.
 */
int tls_write(tls_conn_t *tls, const uint8_t *data, size_t len);

/** Copy out received application data; returns the byte count. */
size_t tls_read(tls_conn_t *tls, uint8_t *buf, size_t len);

/**
 * KeyUpdate (RFC 8446 §4.6.3): our next keys; with @p request, the peer's
 * too.  It also happens by itself after TLS_KEY_UPDATE_RECORDS records.
 * @return 0, or -1 if the connection is not open for writing.
 */
int tls_key_update(tls_conn_t *tls, int request);

/** Send close_notify; nothing more may be written. */
int tls_close(tls_conn_t *tls);

static inline tls_state_t tls_state(const tls_conn_t *tls) {
  return (tls_state_t)tls->state;
}

/** 1 if the pre-shared key authenticated the handshake (no certificate). */
int tls_psk_used(const tls_conn_t *tls);

#endif /* TLS_H */
