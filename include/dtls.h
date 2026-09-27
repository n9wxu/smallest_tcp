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

#define DTLS_VERSION_13 0xfefc     /**< In supported_versions */
#define DTLS_LEGACY_VERSION 0xfefd /**< In hellos and plaintext records */
#define DTLS_CT_ACK 26             /**< The ACK content type (RFC 9147 §7) */

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

#endif /* DTLS_H */
