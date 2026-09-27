/**
 * @file dtls.h
 * @brief DTLS 1.3 (RFC 9147): TLS 1.3 over datagrams.  The handshake, key
 *        schedule and crypto backend are TLS's (tls.h); this adds the
 *        datagram record layer.  See docs/design/dtls.md.
 */

#ifndef DTLS_H
#define DTLS_H

#include "tls.h"

#include <stddef.h>
#include <stdint.h>

#define DTLS_CT_ACK 26 /**< The ACK content type (RFC 9147 §7) */

/** The DTLSCiphertext header we send: 001 C=0 S=1 L=1 EE, a 16-bit
 *  sequence number, the length. */
#define DTLS_RECORD_HDR 5
/** Bytes a protected record adds to its content: header, type, tag. */
#define DTLS_RECORD_OVERHEAD (DTLS_RECORD_HDR + 1 + TLS_AEAD_TAG_LEN)

/* ── Records (RFC 9147 §4) ── */

/** The keys of one epoch in one direction. */
typedef struct {
  tls_keys_t k;                 /**< Key, IV; seq: the next record number to
                                     send, or the highest received + 1 */
  uint8_t sn[TLS_AEAD_KEY_LEN]; /**< Record number key (§4.2.3) */
  uint32_t window; /**< Receiving: bit i set = record k.seq - 1 - i taken */
} dtls_keys_t;

/** A DTLSCiphertext header, as dtls_record_parse() reads it. */
typedef struct {
  uint8_t hlen;  /**< Header bytes */
  uint8_t epoch; /**< The epoch's two low bits */
  uint16_t len;  /**< Bytes of encrypted record after the header */
} dtls_rec_t;

/** An epoch's keys from its traffic secret: key, IV and the record number
 *  key, under the "dtls13" label prefix; record number 0. */
void dtls_keys_derive(const tls_crypto_t *c, const uint8_t secret[TLS_HASH_LEN],
                      dtls_keys_t *k);

/**
 * Protect one record in place: @p rec[DTLS_RECORD_HDR ..] holds @p len
 * bytes of content of type @p type; the record needs @p len +
 * DTLS_RECORD_OVERHEAD bytes.  Writes the header (the low bits of
 * @p epoch, the record number masked), the inner type and the tag;
 * advances @p k->k.seq.
 * @return The length of the whole record.
 */
size_t dtls_record_seal(const tls_crypto_t *c, dtls_keys_t *k, uint16_t epoch,
                        uint8_t type, uint8_t *rec, size_t len);

/**
 * Read the DTLSCiphertext header at @p in, which has @p avail bytes left
 * in its datagram.
 * @return 0, or -1 if this is not a record we can read (no DTLS 1.3
 *         ciphertext, a Connection ID, a header or length past the end) —
 *         and then nothing after it in the datagram can be read either.
 */
int dtls_record_parse(const uint8_t *in, size_t avail, dtls_rec_t *r);

/**
 * Remove the protection of the record at @p in (header @p r) with the keys
 * of its epoch, into @p out (@p r->len bytes of room): unmask and
 * reconstruct the record number, authenticate, refuse a replay, strip the
 * padding.  Only a record that opens moves the window.
 * @return The content length (its type in @p type, the full record number
 *         in @p seq), or -1: drop the record.
 */
int dtls_record_open(const tls_crypto_t *c, dtls_keys_t *k, const uint8_t *in,
                     const dtls_rec_t *r, uint8_t *out, uint8_t *type,
                     uint64_t *seq);

/** The record number whose low @p nbits bits are @p bits and which is
 *  closest to @p next, the one expected (RFC 9147 §4.2.2). */
uint64_t dtls_seq_expand(uint64_t next, uint32_t bits, unsigned nbits);

/* ── Connections ── */

/* Retransmission (RFC 9147 §5.8.2): 1 s, doubling, at most 60 s; a flight
 * sent this many times more without an answer ends the connection. */
#ifndef DTLS_RTO_INITIAL_MS
#define DTLS_RTO_INITIAL_MS 1000u
#endif
#ifndef DTLS_RTO_MAX_MS
#define DTLS_RTO_MAX_MS 60000u
#endif
#ifndef DTLS_MAX_RETRANSMITS
#define DTLS_MAX_RETRANSMITS 6
#endif

#define DTLS_SENT_MAX 10 /**< Records of a flight tracked for its ACK */
#define DTLS_ACK_MAX 8   /**< Peer records an ACK lists */
#define DTLS_MTU_MIN 128 /**< Smallest datagram dtls_init() accepts */

/** tls->alert when the connection ended because the peer stopped
 *  answering (no alert was sent or received). */
#define DTLS_TIMEOUT 255

/** A record, in an ACK: its epoch and record number. */
typedef struct {
  uint32_t seq;
  uint16_t epoch;
  uint8_t pass;  /**< Our records: the transmission that sent it */
  uint8_t acked; /**< Our records: an ACK named it */
} dtls_recno_t;

/**
 * @brief One DTLS connection: a TLS connection (the handshake runs on it)
 * with the datagram record layer's state.  Application owned.
 */
typedef struct dtls_conn_s {
  tls_conn_t tls;             /**< First: the roles work on this */
  dtls_keys_t r, w;           /**< The current receive and send epochs */
  dtls_keys_t r_prev, w_prev; /**< The epoch before each */
  uint16_t repoch, wepoch;    /**< 0, then 2, 3, ... (RFC 9147 §6.1) */
  uint16_t pseq;              /**< Next epoch-0 record number to send */
  uint16_t mtu;               /**< Largest datagram to send */

  /* The flight: tls.tx[0 .. tls.tx_len), TLS-format messages */
  uint16_t fl_seq;   /**< message_seq of its first message */
  uint16_t fl_split; /**< Where its second epoch begins; 0xFFFF: none */
  uint16_t fl_ep[2]; /**< Its epochs */
  uint16_t fl_pos;   /**< Transmission: the next message's offset, */
  uint16_t fl_idx;   /**<   its index in the flight, */
  uint16_t fl_frag;  /**<   and how much of it has gone */
  uint8_t fl_state;  /**< (internal) */
  uint8_t pass;      /**< Transmissions of the flight so far, less one */
  uint8_t retries;   /**< .. of them the timer's */
  uint8_t pass_lost; /**< Bit i: transmission i's records not all tracked */
  uint8_t sent_n;
  dtls_recno_t sent[DTLS_SENT_MAX]; /**< Records the flight went in */
  uint32_t rto_ms, timer_ms;        /**< Timer; timer_ms 0: stopped */

  /* Receiving */
  uint16_t rx_seq;  /**< Next message_seq expected */
  uint16_t hs_have; /**< Bytes of the message being reassembled */
  uint8_t ack_n, ack_owed;
  dtls_recno_t acks[DTLS_ACK_MAX]; /**< Peer records to acknowledge */
  uint32_t bad_records;            /**< Records that failed to open */

  uint16_t dg_len; /**< The datagram waiting at tls.tx + tls.tx_len */
} dtls_conn_t;

/**
 * Initialise a connection over application buffers (as tls_init()): @p tx
 * holds this side's largest flight plus a datagram, @p rx the largest
 * message and record it receives (docs/design/dtls.md §11).  @p mtu is the
 * largest datagram to send — what the transport carries without IP
 * fragmentation.
 * @return 0, or -1 for a bad argument (also a backend without aes_block).
 */
int dtls_init(dtls_conn_t *d, const tls_config_t *cfg, uint8_t *rx,
              size_t rx_cap, uint8_t *tx, size_t tx_cap, size_t mtu);

/** Server: wait for a ClientHello. */
static inline int dtls_accept(dtls_conn_t *d) { return tls_accept(&d->tls); }

/** Client: start the handshake (as tls_connect()); send what dtls_pending()
 *  returns. */
int dtls_connect(dtls_conn_t *d, const char *host);

/**
 * One datagram received from the connection's peer.  Records that do not
 * open, parse or belong are dropped without an alert (RFC 9147 §4.5.2).
 * @return 0, or the negated alert (or DTLS_TIMEOUT) that ended the
 *         connection.
 */
int dtls_input(dtls_conn_t *d, const uint8_t *dgram, size_t len);

/** The next datagram to send: its length (0: none), and @p *dgram.  Call
 *  dtls_sent() once it has gone (or been given up). */
size_t dtls_pending(dtls_conn_t *d, const uint8_t **dgram);

/** The datagram dtls_pending() returned is done with. */
void dtls_sent(dtls_conn_t *d);

/** Advance the retransmission timer by @p elapsed_ms. */
void dtls_tick(dtls_conn_t *d, uint32_t elapsed_ms);

/**
 * Send @p len bytes of application data as one record in one datagram.
 * @return @p len; 0 while the previous datagram waits; -1 if the
 *         connection is not open for writing or @p len > dtls_max_data().
 */
int dtls_write(dtls_conn_t *d, const uint8_t *data, size_t len);

/** Copy out received application data, one record per call (a record not
 *  taken whole is continued by the next call). */
size_t dtls_read(dtls_conn_t *d, uint8_t *buf, size_t len);

/** The most dtls_write() takes now. */
size_t dtls_max_data(const dtls_conn_t *d);

/** KeyUpdate: new sending keys once the peer acknowledges it (RFC 9147
 *  §8); with @p request the peer's too.  0, or -1 if not open for writing. */
int dtls_key_update(dtls_conn_t *d, int request);

/** Send close_notify (once, not retransmitted).  0, or -1. */
int dtls_close(dtls_conn_t *d);

/** Done with the connection, however it ended: wipe keys and buffers; it
 *  is left IDLE with the same configuration, buffers, MTU and callback. */
void dtls_release(dtls_conn_t *d);

/** Server: the peer has shown it receives at its address — its cookie came
 *  back, or the handshake completed. */
int dtls_peer_verified(const dtls_conn_t *d);

static inline tls_state_t dtls_state(const dtls_conn_t *d) {
  return tls_state(&d->tls);
}

#endif /* DTLS_H */
