/**
 * @file tftp.c
 * @brief TFTP client (RFC 1350) with the blksize option (RFC 2348).
 *        REQ-TFTP-001..038.
 */

#include "tftp.h"
#include "net_endian.h"
#include "net_text.h"
#include "udp.h"
#include <string.h>

#define TFTP_DATA_HDR_SIZE 4
#define TFTP_MIN_BLKSIZE 8u         /* RFC 2348 §2 */
#define TFTP_MAX_BLKSIZE 65464u     /* RFC 2348 §2 */
#define TFTP_ETHERNET_BLKSIZE 1468u /* the largest DATA in one frame */
#define TFTP_ERROR_MSG_MAX 119u

/* The largest block the RX buffer holds (REQ-TFTP-037, 038) */
static uint16_t largest_blksize(const net_t *net) {
  uint32_t room =
      net->rx.capacity > UDP_PAYLOAD_OFFSET + TFTP_DATA_HDR_SIZE
          ? net->rx.capacity - UDP_PAYLOAD_OFFSET - TFTP_DATA_HDR_SIZE
          : TFTP_DEFAULT_BLKSIZE;
  if (room < TFTP_MIN_BLKSIZE)
    room = TFTP_MIN_BLKSIZE;
  return (uint16_t)(room > TFTP_ETHERNET_BLKSIZE ? TFTP_ETHERNET_BLKSIZE
                                                 : room);
}

/* Once the server has answered, to its transfer port (REQ-TFTP-015) */
static uint16_t server_port(const tftp_client_t *c) {
  return c->server_tid ? c->server_tid : TFTP_SERVER_PORT;
}

static int from_server_tid(const tftp_client_t *c, uint32_t ip, uint16_t port) {
  return ip == c->server_ip && port == c->server_tid;
}

static net_err_t send_payload(net_t *net, tftp_client_t *c, uint16_t len) {
  return udp_send_inplace(net, c->server_ip, c->server_mac, c->local_port,
                          server_port(c), len, NET_DEFAULT_TTL);
}

static uint16_t put_string(uint8_t *msg, uint16_t pos, const char *s) {
  size_t len = strlen(s) + 1;
  memcpy(msg + pos, s, len);
  return (uint16_t)(pos + len);
}

/* REQ-TFTP-001..003, 025, 026: filename, "octet", and blksize unless it
 * is the default */
static net_err_t send_rrq(net_t *net, tftp_client_t *c) {
  uint8_t *msg = net->tx.buf + UDP_PAYLOAD_OFFSET;
  int with_blksize = c->blksize_opt && c->blksize != TFTP_DEFAULT_BLKSIZE;
  char blksize[NET_U32_DEC_MAX];
  uint8_t digits = net_u32_to_dec(blksize, c->blksize);
  uint32_t len = 2 + strlen(c->filename) + 1 + sizeof("octet") +
                 (with_blksize ? sizeof("blksize") + digits + 1u : 0u);
  uint16_t pos = 2;

  if (UDP_PAYLOAD_OFFSET + len > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;
  net_write16be(msg, TFTP_OP_RRQ);
  pos = put_string(msg, pos, c->filename);
  pos = put_string(msg, pos, "octet");
  if (with_blksize) {
    pos = put_string(msg, pos, "blksize");
    pos = put_string(msg, pos, blksize);
  }
  return udp_send_inplace(net, c->server_ip, c->server_mac, c->local_port,
                          TFTP_SERVER_PORT, pos, NET_DEFAULT_TTL);
}

/* REQ-TFTP-009, 014 */
static net_err_t send_ack(net_t *net, tftp_client_t *c, uint16_t block) {
  uint8_t *msg = net->tx.buf + UDP_PAYLOAD_OFFSET;
  if (net->tx.capacity < UDP_PAYLOAD_OFFSET + 4)
    return NET_ERR_BUF_TOO_SMALL;
  net_write16be(msg, TFTP_OP_ACK);
  net_write16be(msg + 2, block);
  return send_payload(net, c, 4);
}

/* An ERROR at UDP_PAYLOAD_OFFSET; its length, or 0 if it does not fit */
static uint16_t put_error(net_t *net, uint16_t code, const char *text) {
  uint8_t *msg = net->tx.buf + UDP_PAYLOAD_OFFSET;
  size_t len = strlen(text);
  if (len > TFTP_ERROR_MSG_MAX)
    len = TFTP_ERROR_MSG_MAX;
  if (net->tx.capacity < UDP_PAYLOAD_OFFSET + 5 + len)
    return 0;
  net_write16be(msg, TFTP_OP_ERROR);
  net_write16be(msg + 2, code);
  memcpy(msg + 4, text, len);
  msg[4 + len] = '\0';
  return (uint16_t)(5 + len);
}

/* REQ-TFTP-018: to the stray datagram's own source (RFC 1350 §4) */
static void reject_stray(net_t *net, const tftp_client_t *c, uint32_t ip,
                         const uint8_t *mac, uint16_t port) {
  uint16_t len = put_error(net, TFTP_ERR_UNKNOWN_TID, "Unknown transfer ID");
  if (len)
    udp_send_inplace(net, ip, mac, c->local_port, port, len, NET_DEFAULT_TTL);
}

static void finish(tftp_client_t *c, uint8_t ok, uint16_t code,
                   const char *msg) {
  c->state = ok ? TFTP_STATE_DONE : TFTP_STATE_ERROR;
  c->timer_ms = 0;
  if (c->on_done)
    c->on_done(ok, code, msg, c->cb_ctx);
}

/* A NUL-terminated string at @p *p before @p end; NULL if unterminated */
static const char *next_string(const uint8_t **p, const uint8_t *end) {
  const char *s = (const char *)*p;
  while (*p < end && **p != '\0')
    (*p)++;
  if (*p >= end)
    return NULL;
  (*p)++;
  return s;
}

static uint32_t parse_decimal(const char *s) {
  uint32_t v = 0;
  while (*s >= '0' && *s <= '9' && v <= TFTP_MAX_BLKSIZE)
    v = v * 10u + (uint32_t)(*s++ - '0');
  return v;
}

/* RFC 2348 §2: the server may lower the size requested, never raise it */
static int acceptable_blksize(const tftp_client_t *c, uint32_t v) {
  return v >= TFTP_MIN_BLKSIZE && v <= c->blksize;
}

/* RFC 2347: ERROR 8 to the server, and the transfer ends */
static void refuse_oack(net_t *net, tftp_client_t *c) {
  uint16_t len = put_error(net, TFTP_ERR_OPTION_NEGOTIATION, "Bad blksize");
  if (len)
    send_payload(net, c, len);
  finish(c, 0, TFTP_ERR_OPTION_NEGOTIATION, "Bad blksize");
}

/* REQ-TFTP-027, 028, 038: the server's blksize, acknowledged with ACK(0) */
static void oack_input(net_t *net, tftp_client_t *c, const uint8_t *data,
                       uint16_t len) {
  const uint8_t *p = data + 2, *end = data + len;
  const char *name, *value;
  while ((name = next_string(&p, end)) && (value = next_string(&p, end))) {
    uint32_t v = parse_decimal(value);
    if (!net_equal_nocase(name, "blksize"))
      continue;
    if (!acceptable_blksize(c, v)) {
      refuse_oack(net, c);
      return;
    }
    c->blksize = (uint16_t)v;
  }
  c->state = TFTP_STATE_RECEIVING;
  send_ack(net, c, 0);
}

/* REQ-TFTP-009..015, 031 */
static void data_input(net_t *net, tftp_client_t *c, const uint8_t *data,
                       uint16_t len) {
  uint16_t block, block_len;
  if (len < TFTP_DATA_HDR_SIZE)
    return;
  block = net_read16be(data + 2);
  block_len = (uint16_t)(len - TFTP_DATA_HDR_SIZE);
  if (c->state == TFTP_STATE_REQUESTING) { /* blksize option ignored */
    c->blksize = TFTP_DEFAULT_BLKSIZE;
    c->state = TFTP_STATE_RECEIVING;
  }
  if (block == c->next_block) {
    if (c->on_data)
      c->on_data(block, data + TFTP_DATA_HDR_SIZE, block_len, c->cb_ctx);
    send_ack(net, c, block);
    if (block_len < c->blksize) { /* the last block is short */
      finish(c, 1, 0, "");
      return;
    }
    c->next_block++; /* wraps from 65535 to 0 */
  } else if (block == (uint16_t)(c->next_block - 1u)) {
    send_ack(net, c, block); /* the server missed our ACK */
  }
}

void tftp_client_init(tftp_client_t *c, uint16_t local_port,
                      tftp_data_fn_t on_data, tftp_done_fn_t on_done,
                      void *ctx) {
  memset(c, 0, sizeof(*c));
  c->state = TFTP_STATE_IDLE;
  c->local_port = local_port;
  c->blksize = TFTP_DEFAULT_BLKSIZE;
  c->on_data = on_data;
  c->on_done = on_done;
  c->cb_ctx = ctx;
}

/* REQ-TFTP-001..006, 035 */
net_err_t tftp_client_get(net_t *net, tftp_client_t *c, uint32_t server_ip,
                          const uint8_t *server_mac, const char *filename,
                          uint8_t blksize_opt) {
  size_t name_len = strlen(filename);
  if (c->state == TFTP_STATE_REQUESTING || c->state == TFTP_STATE_RECEIVING)
    return NET_ERR_INVALID_PARAM;
  if (name_len >= TFTP_MAX_FILENAME)
    name_len = TFTP_MAX_FILENAME - 1u;
  memcpy(c->filename, filename, name_len);
  c->filename[name_len] = '\0';
  c->server_ip = server_ip;
  memcpy(c->server_mac, server_mac, 6);
  c->server_tid = 0;
  c->next_block = 1;
  c->blksize_opt = blksize_opt;
  c->blksize = blksize_opt ? largest_blksize(net) : TFTP_DEFAULT_BLKSIZE;
  c->state = TFTP_STATE_REQUESTING;
  c->retries = 0;
  c->timer_ms = TFTP_TIMEOUT_MS;
  return send_rrq(net, c);
}

/* REQ-TFTP-006, 016..018 */
void tftp_client_input(net_t *net, tftp_client_t *c, uint32_t src_ip,
                       const uint8_t *src_mac, uint16_t src_port,
                       const uint8_t *data, uint16_t len) {
  uint16_t opcode;
  if ((c->state != TFTP_STATE_REQUESTING && c->state != TFTP_STATE_RECEIVING) ||
      len < 2)
    return;
  opcode = net_read16be(data);

  /* The first answer from the server's IP fixes its transfer ID (port) */
  if (c->server_tid == 0 && src_ip == c->server_ip &&
      (opcode == TFTP_OP_DATA || opcode == TFTP_OP_OACK ||
       opcode == TFTP_OP_ERROR))
    c->server_tid = src_port;
  if (!from_server_tid(c, src_ip, src_port)) {
    if (opcode != TFTP_OP_ERROR) /* an ERROR for an ERROR could loop */
      reject_stray(net, c, src_ip, src_mac, src_port);
    return;
  }
  c->timer_ms = TFTP_TIMEOUT_MS;
  c->retries = 0;

  switch (opcode) {
  case TFTP_OP_ERROR:
    finish(c, 0, len >= 4 ? net_read16be(data + 2) : 0,
           len > 4 ? (const char *)(data + 4) : "");
    break;
  case TFTP_OP_OACK:
    if (c->state == TFTP_STATE_REQUESTING)
      oack_input(net, c, data, len);
    else if (c->next_block == 1)
      send_ack(net, c, 0); /* the server missed our ACK 0 */
    break;
  case TFTP_OP_DATA:
    data_input(net, c, data, len);
    break;
  default:
    break;
  }
}

/* REQ-TFTP-020..024 */
void tftp_client_tick(net_t *net, tftp_client_t *c, uint32_t ms) {
  if ((c->state != TFTP_STATE_REQUESTING && c->state != TFTP_STATE_RECEIVING) ||
      !net_countdown(&c->timer_ms, ms))
    return;
  if (c->retries >= TFTP_MAX_RETRIES) {
    finish(c, 0, 0, "Timeout");
    return;
  }
  c->retries++;
  c->timer_ms = TFTP_TIMEOUT_MS;
  if (c->state == TFTP_STATE_REQUESTING)
    send_rrq(net, c);
  else
    send_ack(net, c, (uint16_t)(c->next_block - 1u)); /* the last ACK */
}
