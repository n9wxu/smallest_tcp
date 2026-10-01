/**
 * @file dhcpv4_wire.h
 * @brief DHCPv4 message format (RFC 2131, RFC 2132), shared by the client
 *        and the server.  Private to the library.
 */

#ifndef DHCPV4_WIRE_H
#define DHCPV4_WIRE_H

#include "net.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_OFF_OP 0
#define DHCP_OFF_HTYPE 1
#define DHCP_OFF_HLEN 2
#define DHCP_OFF_XID 4
#define DHCP_OFF_FLAGS 10
#define DHCP_OFF_CIADDR 12
#define DHCP_OFF_YIADDR 16
#define DHCP_OFF_SIADDR 20
#define DHCP_OFF_GIADDR 24
#define DHCP_OFF_CHADDR 28
#define DHCP_OFF_SNAME 44
#define DHCP_OFF_FILE 108
#define DHCP_OFF_MAGIC 236
#define DHCP_OFF_OPTIONS 240
/** Messages are padded to this length (RFC 2131 §2); every message this
 *  library builds fits in it — a frame of DHCPV4_CLIENT_TX_MIN or
 *  DHCPV4_SERVER_TX_MIN bytes. */
#define DHCP_MIN_LEN 300

#define DHCP_MAGIC 0x63825363u
#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY 2
#define DHCP_HTYPE_ETHERNET 1
#define DHCP_FLAG_BROADCAST 0x8000u

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_REQUEST 3
#define DHCP_MSG_DECLINE 4
#define DHCP_MSG_ACK 5
#define DHCP_MSG_NAK 6
#define DHCP_MSG_RELEASE 7
#define DHCP_MSG_INFORM 8

#define DHCP_OPT_PAD 0
#define DHCP_OPT_SUBNET_MASK 1
#define DHCP_OPT_ROUTER 3
#define DHCP_OPT_DNS 6
#define DHCP_OPT_REQUESTED_IP 50
#define DHCP_OPT_LEASE_TIME 51
#define DHCP_OPT_OVERLOAD 52
#define DHCP_OPT_MSG_TYPE 53
#define DHCP_OPT_SERVER_ID 54
#define DHCP_OPT_PARAM_REQ 55
#define DHCP_OPT_T1 58
#define DHCP_OPT_T2 59
#define DHCP_OPT_END 255

#define DHCP_LEASE_INFINITE 0xFFFFFFFFu /* RFC 2131 §3.3 */

/* Option Overload values (RFC 2132 §9.3): the fields that hold options */
#define DHCP_OVERLOAD_FILE 1u
#define DHCP_OVERLOAD_SNAME 2u

/**
 * The next option after @p *pos, before @p msg_len, in @p msg: its code,
 * with @p *data and @p *len set; DHCP_OPT_END at End, at @p msg_len, or on
 * an option that runs past it.  The options of one field; dhcp_walk_*()
 * walk them all.
 */
static inline uint8_t dhcp_next_option(const uint8_t *msg, uint16_t msg_len,
                                       uint16_t *pos, const uint8_t **data,
                                       uint8_t *len) {
  uint8_t code;
  while (*pos < msg_len && msg[*pos] == DHCP_OPT_PAD)
    (*pos)++;
  if (*pos >= msg_len || msg[*pos] == DHCP_OPT_END ||
      (uint32_t)*pos + 2 > msg_len ||
      (uint32_t)*pos + 2 + msg[*pos + 1] > msg_len)
    return DHCP_OPT_END;
  code = msg[*pos];
  *len = msg[*pos + 1];
  *data = msg + *pos + 2;
  *pos = (uint16_t)(*pos + 2 + *len);
  return code;
}

/** A walk through the options of a message: the options field, then
 *  'file' and 'sname' if the Option Overload option says they hold options
 *  — RFC 3396 §5's aggregate option buffer, in RFC 2131 §4.1's order. */
typedef struct {
  const uint8_t *msg;
  uint16_t pos, end; /* within the field walked */
  uint8_t more;      /* fields left: DHCP_OVERLOAD_* */
} dhcp_walk_t;

/** Start a walk of the options of @p msg, @p len bytes (at least
 *  DHCP_OFF_OPTIONS): the options field is read first for option 52. */
static inline void dhcp_walk_begin(dhcp_walk_t *w, const uint8_t *msg,
                                   uint16_t len) {
  uint16_t pos = DHCP_OFF_OPTIONS;
  const uint8_t *v;
  uint8_t code, olen;
  w->msg = msg;
  w->pos = DHCP_OFF_OPTIONS;
  w->end = len;
  w->more = 0;
  while ((code = dhcp_next_option(msg, len, &pos, &v, &olen)) != DHCP_OPT_END)
    if (code == DHCP_OPT_OVERLOAD && olen == 1 && v[0] <= 3u)
      w->more = v[0];
}

/** The walk's next option, as dhcp_next_option(); DHCP_OPT_END after the
 *  last field. */
static inline uint8_t dhcp_walk_next(dhcp_walk_t *w, const uint8_t **data,
                                     uint8_t *len) {
  uint8_t code;
  while ((code = dhcp_next_option(w->msg, w->end, &w->pos, data, len)) ==
             DHCP_OPT_END &&
         w->more) {
    if (w->more & DHCP_OVERLOAD_FILE) {
      w->more &= (uint8_t)~DHCP_OVERLOAD_FILE;
      w->pos = DHCP_OFF_FILE;
      w->end = DHCP_OFF_MAGIC;
    } else {
      w->more = 0;
      w->pos = DHCP_OFF_SNAME;
      w->end = DHCP_OFF_FILE;
    }
  }
  return code;
}

/**
 * Option @p code of @p msg, its parts joined in order (RFC 3396 §7): its
 * length, with @p *value at it — in place when it is in one part, else in
 * @p buf, which receives its first @p cap bytes.  *value is NULL if the
 * option is absent.
 */
static inline uint16_t dhcp_option(const uint8_t *msg, uint16_t msg_len,
                                   uint8_t code, const uint8_t **value,
                                   uint8_t *buf, uint16_t cap) {
  dhcp_walk_t w;
  const uint8_t *v;
  uint8_t c, n;
  uint16_t total = 0;
  *value = NULL;
  dhcp_walk_begin(&w, msg, msg_len);
  while ((c = dhcp_walk_next(&w, &v, &n)) != DHCP_OPT_END) {
    if (c != code)
      continue;
    if (total < cap)
      memcpy(buf + total, v, n < cap - total ? n : (uint16_t)(cap - total));
    *value = *value ? buf : v;
    total = (uint16_t)(total + n);
  }
  return total;
}

/** Message Type option of @p msg, 0 if absent. */
static inline uint8_t dhcp_message_type(const uint8_t *msg, uint16_t len) {
  uint8_t b;
  const uint8_t *t;
  return dhcp_option(msg, len, DHCP_OPT_MSG_TYPE, &t, &b, 1) >= 1 ? t[0] : 0;
}

/** A 4-byte option of @p msg (the first 4 bytes of a list), or
 *  @p absent. */
static inline uint32_t dhcp_option_u32(const uint8_t *msg, uint16_t len,
                                       uint8_t code, uint32_t absent) {
  uint8_t b[4];
  const uint8_t *v;
  return dhcp_option(msg, len, code, &v, b, 4) >= 4 ? net_read32be(v) : absent;
}

/**
 * Start a message in place, in the UDP payload of net->tx.buf: the fixed
 * fields zeroed but for @p op, @p xid, our hardware address @p chaddr and
 * the magic cookie.  NULL if the TX buffer is too small.
 */
static inline uint8_t *dhcp_begin(net_t *net, uint8_t op, uint32_t xid,
                                  const uint8_t *chaddr) {
  uint8_t *msg = net->tx.buf + UDP_PAYLOAD_OFFSET;
  if (net->tx.capacity < UDP_PAYLOAD_OFFSET + DHCP_MIN_LEN)
    return NULL;
  memset(msg, 0, DHCP_MIN_LEN);
  msg[DHCP_OFF_OP] = op;
  msg[DHCP_OFF_HTYPE] = DHCP_HTYPE_ETHERNET;
  msg[DHCP_OFF_HLEN] = 6;
  net_write32be(msg + DHCP_OFF_XID, xid);
  memcpy(msg + DHCP_OFF_CHADDR, chaddr, 6);
  net_write32be(msg + DHCP_OFF_MAGIC, DHCP_MAGIC);
  return msg;
}

static inline uint16_t dhcp_put_u8(uint8_t *msg, uint16_t pos, uint8_t code,
                                   uint8_t v) {
  msg[pos] = code;
  msg[pos + 1] = 1;
  msg[pos + 2] = v;
  return (uint16_t)(pos + 3);
}

static inline uint16_t dhcp_put_u32(uint8_t *msg, uint16_t pos, uint8_t code,
                                    uint32_t v) {
  msg[pos] = code;
  msg[pos + 1] = 4;
  net_write32be(msg + pos + 2, v);
  return (uint16_t)(pos + 6);
}

/** Close the options: the End option; the message's length. */
static inline uint16_t dhcp_end(uint8_t *msg, uint16_t pos) {
  msg[pos++] = DHCP_OPT_END;
  return pos < DHCP_MIN_LEN ? DHCP_MIN_LEN : pos;
}

#endif /* DHCPV4_WIRE_H */
