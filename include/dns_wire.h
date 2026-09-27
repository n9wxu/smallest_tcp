/**
 * @file dns_wire.h
 * @brief DNS wire-format helpers (RFC 1035 §3-4) shared by mDNS and DNS.
 *
 * Writing: a dns_writer_t builds a message in a caller-provided buffer
 * (normally the UDP payload area of net->tx.buf — zero copy).  Names are
 * written from dotted C strings with RFC 1035 §4.1.4 name compression.
 *
 * Reading: all readers work on a complete message in memory and bounds-check
 * every access.  Compression pointers are followed with a hop limit, so a
 * malicious pointer loop cannot hang the parser.
 *
 * Names are given as dotted strings ("pyro-dead01.local", trailing dot
 * optional).  Labels may contain any byte except '.', so DNS-SD instance
 * names such as "Pyro Unit 1" work; a literal dot inside a label is not
 * supported.  Name comparison is ASCII case-insensitive (RFC 1035 §2.3.3).
 */

#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include "net_config.h"
#include <stdint.h>

/* Header layout */
#define DNS_HDR_SIZE 12
#define DNS_OFF_ID 0
#define DNS_OFF_FLAGS 2
#define DNS_OFF_QDCOUNT 4
#define DNS_OFF_ANCOUNT 6
#define DNS_OFF_NSCOUNT 8
#define DNS_OFF_ARCOUNT 10

#define DNS_FLAG_QR 0x8000     /**< Response */
#define DNS_FLAG_AA 0x0400     /**< Authoritative answer */
#define DNS_FLAG_TC 0x0200     /**< Truncated */
#define DNS_OPCODE_MASK 0x7800 /**< Opcode field (0 = standard query) */

/* Record types and classes */
#define DNS_TYPE_A 1
#define DNS_TYPE_PTR 12
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_SRV 33
#define DNS_TYPE_NSEC 47
#define DNS_TYPE_ANY 255

#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255
#define DNS_CLASS_MASK 0x7FFF
/** Top bit of the class field: QU (question) / cache-flush (record) in mDNS */
#define DNS_CLASS_TOPBIT 0x8000

/* Limits */
#define DNS_MAX_LABEL 63
#define DNS_MAX_NAME 255 /**< Wire length including length bytes + root */

/** Label offsets remembered per writer for compression targets. */
#ifndef DNS_COMPRESS_MAX
#define DNS_COMPRESS_MAX 16
#endif

/* Writer */
typedef struct {
  uint8_t *buf;     /**< Start of the DNS message */
  uint16_t cap;     /**< Buffer capacity */
  uint16_t len;     /**< Bytes written so far */
  uint8_t overflow; /**< Sticky: set when a write did not fit */
  uint8_t n_offsets;
  uint16_t offsets[DNS_COMPRESS_MAX]; /**< Label starts usable as pointers */
} dns_writer_t;

/** Saved writer position for rolling back a partially written record. */
typedef struct {
  uint16_t len;
  uint8_t n_offsets;
} dns_writer_mark_t;

void dns_writer_init(dns_writer_t *w, uint8_t *buf, uint16_t cap);

/** Write bytes / big-endian integers.  Return 0, or -1 on overflow. */
int dns_write_bytes(dns_writer_t *w, const uint8_t *data, uint16_t n);
int dns_write_u16(dns_writer_t *w, uint16_t v);
int dns_write_u32(dns_writer_t *w, uint32_t v);

/**
 * Write a dotted name, compressed against names already in the message.
 * @return 0 on success, -1 on overflow, -2 if the name is invalid
 *         (empty label, label > 63 bytes, or wire length > 255).
 */
int dns_write_name(dns_writer_t *w, const char *name);

/** Two dotted names are the same name (case-insensitive, trailing dot
 *  optional). */
int dns_dotted_equal(const char *a, const char *b);

/**
 * Validate a dotted name.
 * @return Its wire length (1..255), or -2 if it is invalid.
 */
int dns_name_wire_len(const char *name);

/** Write the 12-byte header (message must be empty). */
int dns_write_header(dns_writer_t *w, uint16_t id, uint16_t flags,
                     uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                     uint16_t arcount);

/** Overwrite the four section counts of an already written header. */
void dns_set_counts(uint8_t *msg, uint16_t qdcount, uint16_t ancount,
                    uint16_t nscount, uint16_t arcount);

dns_writer_mark_t dns_writer_mark(const dns_writer_t *w);
void dns_writer_rollback(dns_writer_t *w, dns_writer_mark_t mark);

/* Reader */
typedef struct {
  uint16_t name_off; /**< Offset of QNAME */
  uint16_t type;
  uint16_t class_; /**< Raw class including DNS_CLASS_TOPBIT (QU) */
} dns_question_t;

typedef struct {
  uint16_t name_off; /**< Offset of owner name */
  uint16_t type;
  uint16_t class_; /**< Raw class including DNS_CLASS_TOPBIT (cache flush) */
  uint32_t ttl;
  uint16_t rdlen;
  uint16_t rdata_off; /**< Offset of RDATA */
} dns_rr_t;

/**
 * Skip over the name at @p off.
 * @return Offset of the first byte after the name, or -1 if malformed.
 */
int dns_name_skip(const uint8_t *msg, uint16_t len, uint16_t off);

/**
 * Compare the wire name at @p off with a dotted name (case-insensitive).
 * @return 1 if equal, 0 if different or malformed.
 */
int dns_name_equals(const uint8_t *msg, uint16_t len, uint16_t off,
                    const char *name);

/**
 * Decode the wire name at @p off into a dotted string (no trailing dot;
 * the root name decodes to "").
 * @return String length, or -1 if malformed or @p out is too small.
 */
int dns_name_decode(const uint8_t *msg, uint16_t len, uint16_t off, char *out,
                    uint16_t out_len);

/** Parse a question at @p off.  @return next offset, or -1 if malformed. */
int dns_read_question(const uint8_t *msg, uint16_t len, uint16_t off,
                      dns_question_t *q);

/** Parse a resource record at @p off.  @return next offset, or -1. */
int dns_read_rr(const uint8_t *msg, uint16_t len, uint16_t off, dns_rr_t *rr);

#endif /* DNS_WIRE_H */
