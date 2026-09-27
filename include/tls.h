/**
 * @file tls.h
 * @brief TLS 1.3 (RFC 8446) connections, client and server, over any
 *        transport: the application moves ciphertext between the
 *        connection's buffers and the transport (tls_tcp.h does it for
 *        TCP).  One cipher suite, TLS_AES_128_GCM_SHA256; every
 *        cryptographic primitive comes from a tls_crypto_t backend
 *.  See docs/design/tls.md.
 */

#ifndef TLS_H
#define TLS_H

#include "tls_keys.h"

#include <stddef.h>
#include <stdint.h>

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
#define TLS_EXT_COOKIE 44
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
  const void *key;      /**< Private key, as the backend's sign() takes it */
  uint16_t sig_scheme;  /**< TLS_SIG_* that @ref key signs with */
  uint8_t groups;       /**< TLS_GROUPS_* for (EC)DHE; 0: both (x25519
                             preferred) */
  uint8_t max_fragment; /**< Client: TLS_MFL_* to ask the server for (records
                             of at most 512 .. 4096 bytes, so a small rx
                             buffer suffices); 0: none.  A server grants
                             what a client asks. */

  /* A pre-shared key (RFC 8446 §2.2; SHA-256).  A client offers it, a
   * server takes it when the identity matches and the binder checks out,
   * and neither side then uses certificates. */
  const uint8_t *psk; /**< NULL: none */
  uint16_t psk_len;
  const uint8_t *psk_id; /**< Its identity */
  uint16_t psk_id_len;
  uint8_t psk_modes;      /**< TLS_PSK_KE and/or TLS_PSK_DHE_KE (0: DHE) */
  uint8_t psk_resumption; /**< 1: from a ticket ("res binder") */
} tls_config_t;

/**
 * @brief One TLS connection.  The transport (TCP) is the application's:
 * it moves ciphertext between the connection's buffers and the socket.
 */
struct tls_role_s;
struct tls_rl_s;

typedef struct tls_conn_s {
  const tls_config_t *cfg;
  const struct tls_role_s *role; /**< Server or client (internal) */
  const struct tls_rl_s *rl;     /**< Record layer: TLS or DTLS (internal) */
  uint8_t state;                 /**< tls_state_t */
  uint8_t alert;                 /**< The fatal alert sent or received */
  uint8_t step;                  /**< Handshake step (internal) */
  uint16_t flags;                /**< (internal) */
  uint16_t group;                /**< Negotiated key-exchange group */
  uint16_t max_frag;             /**< Negotiated record size limit (0: 2^14) */
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
  uint16_t hs_len;             /**< Handshake bytes awaiting a whole message */
  uint16_t hs_off;             /**< .. after a kept message (client: the
                                    Certificate, until CertificateVerify) */
  uint16_t leaf_off, leaf_len; /**< Client: the server's certificate */
  uint16_t app_off;            /**< Unread application data: offset .. */
  uint16_t app_len;            /**< .. and length */
  uint16_t app_rec;            /**< Length of the record holding it */

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
 * @return Bytes accepted (0 while tx has no room for them, or for a
 *         KeyUpdate that must go first), or -1 if the connection is not
 *         open for writing.
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

/** Send close_notify; nothing more may be written.  Once close_notify has
 *  gone both ways, the keys are wiped. */
int tls_close(tls_conn_t *tls);

/**
 * Done with the connection, however it ended — closed, failed, or given
 * up: wipe its secrets, record keys and key share and both buffers (which
 * held plaintext).  It is left IDLE with the same configuration, buffers,
 * callback and user pointer, ready for tls_accept() or tls_connect().
 */
void tls_release(tls_conn_t *tls);

static inline tls_state_t tls_state(const tls_conn_t *tls) {
  return (tls_state_t)tls->state;
}

/** 1 if the pre-shared key authenticated the handshake (no certificate). */
int tls_psk_used(const tls_conn_t *tls);

#endif /* TLS_H */
