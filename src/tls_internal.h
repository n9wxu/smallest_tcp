/**
 * @file tls_internal.h
 * @brief What the record layers (tls.c, dtls.c) share with the handshake
 *        of each role, tls_server.c and tls_client.c.  Private to the
 *        library.
 */

#ifndef TLS_INTERNAL_H
#define TLS_INTERNAL_H

#include "net_endian.h"
#include "tls.h"

#include <string.h>

/* tls_conn_t.flags */
#define F_SERVER 0x01u
#define F_RPROT 0x02u    /* records from the peer are protected */
#define F_WPROT 0x04u    /* our records are protected */
#define F_CCS_OK 0x08u   /* a dummy change_cipher_spec may arrive */
#define F_WCLOSED 0x10u  /* we sent close_notify */
#define F_KU_OWED 0x20u  /* we owe a KeyUpdate */
#define F_CERT_REQ 0x40u /* client: the server asked for our certificate */
#define F_PSK 0x80u      /* a PSK authenticates the handshake */
#define F_HRR 0x100u     /* a HelloRetryRequest was sent (received) */
#define F_KU_REQ 0x200u  /* tls_key_update() asked for the peer's too */
#define F_KU_ANS 0x400u  /* the owed KeyUpdate answers the peer's request */

/* tls_conn_t.step: where the handshake is */
enum {
  ST_NONE,
  ST_WAIT_CH,  /* server: ClientHello */
  ST_SEND_CCS, /* server: its flight after ServerHello, a message per */
  ST_SEND_EE,  /*   step so a small TX buffer can send it in parts */
  ST_SEND_CERT,
  ST_SEND_CV,
  ST_SEND_FIN,
  ST_WAIT_FIN, /* server: the client's Finished */
  ST_DONE,
  ST_C_WAIT_SH,   /* client: ServerHello */
  ST_C_WAIT_EE,   /* EncryptedExtensions */
  ST_C_WAIT_CERT, /* CertificateRequest or Certificate */
  ST_C_WAIT_CV,   /* CertificateVerify */
  ST_C_WAIT_FIN,  /* the server's Finished */
  ST_C_SEND_FIN   /* our (empty Certificate and) Finished */
};

/* Steps that owe the peer output */
#define SENDING(s)                                                             \
  (((s) >= ST_SEND_CCS && (s) <= ST_SEND_FIN) || (s) == ST_C_SEND_FIN)

/* What a handshake message handler says about the message it took */
#define HS_KEYS 1    /* keys change after it: it must end its record */
#define HS_KEEP 2    /* keep it (the Certificate, for CertificateVerify) */
#define HS_RELEASE 3 /* done with it and with the kept one */

#define HS_HDR 4  /* msg_type, length (24 bits) */
#define EXT_HDR 4 /* extension_type, length */
#define TLS_RANDOM_LEN 32
#define SESSION_ID_MAX 32

/** The handshake of one role. */
typedef struct tls_role_s {
  /** A whole handshake message during the handshake: HS_*, 0, or < 0. */
  int (*on_message)(tls_conn_t *t, const uint8_t *m, size_t mlen);
  /** Write the output the handshake owes, as far as tx allows. */
  int (*pump)(tls_conn_t *t);
} tls_role_t;

extern const tls_role_t tls_server_role;
extern const tls_role_t tls_client_role;

/** ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3). */
extern const uint8_t tls_hrr_random[TLS_RANDOM_LEN];

/* Reading messages: a cursor that turns "bad" instead of overrunning */

typedef struct {
  const uint8_t *p;
  size_t n;
  uint8_t bad; /* ran past the end */
} rd_t;

static inline uint32_t rd_uint(rd_t *r, size_t width) {
  uint32_t v = 0;
  if (r->n < width) {
    r->bad = 1;
    r->n = 0;
    return 0;
  }
  r->n -= width;
  while (width--)
    v = (v << 8) | *r->p++;
  return v;
}

static inline const uint8_t *rd_take(rd_t *r, size_t len) {
  const uint8_t *p = r->p;
  if (r->n < len) {
    r->bad = 1;
    r->n = 0;
    return NULL;
  }
  r->p += len;
  r->n -= len;
  return p;
}

/** A vector with a @p width byte length prefix, as its own reader. */
static inline rd_t rd_vec(rd_t *r, size_t width) {
  rd_t v;
  size_t len = rd_uint(r, width);
  v.p = rd_take(r, len);
  v.n = v.p ? len : 0;
  v.bad = r->bad;
  return v;
}

/** The body of the handshake message @p m. */
static inline rd_t rd_body(const uint8_t *m, size_t mlen) {
  rd_t r;
  r.p = m + HS_HDR;
  r.n = mlen - HS_HDR;
  r.bad = 0;
  return r;
}

/**
 * The next extension of @p exts: its type and data.
 * @return 0, or the alert for a malformed or repeated extension.
 */
int tls_next_extension(rd_t *exts, uint32_t seen[2], uint16_t *type,
                       rd_t *data);

/* The record layer (tls.c for TLS, dtls.c for DTLS) */

/**
 * What the shared code (tls_common.c, the roles) needs of the record
 * layer a connection runs over.  Reached only through tls_conn_t.rl, so a
 * build links only the record layers it initialises connections with.
 */
typedef struct tls_rl_s {
  uint8_t dtls; /**< 1: DTLS 1.3 (RFC 9147) */
  /** Room for a handshake message of at most @p max bytes, header
   *  included; NULL when there is none yet. */
  uint8_t *(*hs_begin)(tls_conn_t *t, size_t max);
  /** The messages written so far may go (TLS: close the record). */
  void (*hs_flush)(tls_conn_t *t);
  /** TLS: the dummy change_cipher_spec; 0, or -1 if tx has no room. */
  int (*ccs)(tls_conn_t *t);
  /** Queue an alert if there is room, dropping any half-built record. */
  void (*alert)(tls_conn_t *t, uint8_t level, uint8_t desc);
  /** New traffic keys from t->wsec (@p write) or t->rsec. */
  void (*set_keys)(tls_conn_t *t, int write);
  /** Wipe key material the record layer keeps itself (may be NULL). */
  void (*wipe)(tls_conn_t *t);
} tls_rl_t;

extern const tls_rl_t tls_stream_rl;

static inline int tls_is_dtls(const tls_conn_t *t) { return t->rl->dtls; }

#define ALERT_WARNING 1
#define ALERT_FATAL 2

/* Shared by both record layers and both roles (tls_common.c) */

/** A handshake message of at most @p max bytes, header included. */
uint8_t *tls_hs_begin(tls_conn_t *t, size_t max);

/** Finish the message at @p m: header, transcript. */
void tls_hs_end(tls_conn_t *t, uint8_t *m, uint8_t type, size_t body);

/** The messages written so far may be sent. */
void tls_hs_flush(tls_conn_t *t);

/** A dummy change_cipher_spec record (middlebox compatibility, RFC 8446
 *  D.4); 0, or -1 if tx has no room.  TLS only. */
int tls_queue_ccs(tls_conn_t *t);

/** Install the traffic keys of t->wsec (@p write) or of t->rsec. */
void tls_set_keys(tls_conn_t *t, int write);

/** End the connection with a fatal alert; returns -alert. */
int tls_fail(tls_conn_t *t, int alert);

/** Wipe every secret, key and key share. */
void tls_wipe_keys(tls_conn_t *t);

/** Wipe the keys if close_notify has gone both ways: none is used again. */
void tls_wipe_keys_if_closed(tls_conn_t *t);

/** A whole handshake message: to the role during the handshake, else a
 *  post-handshake message.  HS_*, 0, or < 0 (the connection failed). */
int tls_on_handshake(tls_conn_t *t, const uint8_t *m, size_t mlen);

/** An alert from the peer: 0 (close_notify, user_canceled), or the
 *  negated fatal alert that ended the connection. */
int tls_alert_received(tls_conn_t *t, uint8_t desc);

void tls_notify(tls_conn_t *t, uint8_t events);

/** The key-exchange groups the configuration allows (TLS_GROUPS_*). */
uint8_t tls_groups(const tls_config_t *cfg);

/** @p group is one the configuration allows. */
int tls_group_allowed(const tls_config_t *cfg, uint32_t group);

/** The content a server's CertificateVerify signs (RFC 8446 §4.4.3). */
#define TLS_CV_CONTENT_LEN (64 + 34 + TLS_HASH_LEN)
void tls_cert_verify_content(const tls_conn_t *t,
                             uint8_t out[TLS_CV_CONTENT_LEN]);

#endif /* TLS_INTERNAL_H */
