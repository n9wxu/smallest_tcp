/**
 * @file tftp.c
 * @brief TFTP client — RFC 1350 with optional blksize option (RFC 2348).
 *
 * Implements REQ-TFTP-001 through REQ-TFTP-038.
 *
 * Protocol flow (RRQ, no options):
 *   Client → Server  RRQ "filename" "octet"         port 69
 *   Server → Client  DATA block=1 [0..512 bytes]    from server TID
 *   Client → Server  ACK block=1                    to server TID
 *   Server → Client  DATA block=2 [0..512 bytes]
 *   ...
 *   Server → Client  DATA block=N [0..blksize-1]   (last block < blksize)
 *   Client → Server  ACK block=N
 *   Transfer complete.
 *
 * With blksize option (RFC 2348):
 *   Client → Server  RRQ "filename" "octet" "blksize" "<N>"
 *   Server → Client  OACK "blksize" "<M>"   (M ≤ N, or M = N)
 *   Client → Server  ACK block=0
 *   Server → Client  DATA block=1 [0..M bytes]
 *   ...
 */

#include "tftp.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

/* ── Forward declarations ─────────────────────────────────────────── */

static net_err_t send_rrq(net_t *net, tftp_client_t *c);
static net_err_t send_ack(net_t *net, tftp_client_t *c, uint16_t block);
static net_err_t send_error(net_t *net, tftp_client_t *c, uint16_t code,
                            const char *msg);
static void finish(tftp_client_t *c, uint8_t ok, uint16_t code,
                   const char *msg);

/* ── Init ─────────────────────────────────────────────────────────── */

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

/* ── Get (RRQ) ────────────────────────────────────────────────────── */

net_err_t tftp_client_get(net_t *net, tftp_client_t *c, uint32_t server_ip,
                          const uint8_t *server_mac, const char *filename,
                          uint8_t blksize_opt) {
  /* Allow re-starting from terminal states */
  if (c->state != TFTP_STATE_IDLE && c->state != TFTP_STATE_DONE &&
      c->state != TFTP_STATE_ERROR) {
    return NET_ERR_INVALID_PARAM;
  }

  /* REQ-TFTP-037,038: compute max blksize from tx buffer.
   * tx capacity − ETH(14) − IP(20) − UDP(8) − TFTP DATA header(4). */
  uint16_t max_blk = TFTP_DEFAULT_BLKSIZE;
  if (net->tx.capacity > (14u + 20u + 8u + 4u)) {
    max_blk = (uint16_t)(net->tx.capacity - 14u - 20u - 8u - 4u);
  }
  if (max_blk < 8u)
    max_blk = 8u; /* REQ-TFTP-038 */
  if (max_blk > 1468u)
    max_blk = 1468u; /* RFC 2348 max for Ethernet */

  c->server_ip = server_ip;
  memcpy(c->server_mac, server_mac, 6);
  c->server_tid = 0;
  c->next_block = 1;
  c->blksize_opt = blksize_opt;
  c->blksize = blksize_opt ? max_blk : TFTP_DEFAULT_BLKSIZE;

  /* REQ-TFTP-001: save filename */
  {
    size_t flen = strlen(filename);
    if (flen >= TFTP_MAX_FILENAME)
      flen = TFTP_MAX_FILENAME - 1u;
    memcpy(c->filename, filename, flen);
    c->filename[flen] = '\0';
  }

  c->state = TFTP_STATE_REQUESTING;
  c->retries = 0;
  c->timer_ms = TFTP_TIMEOUT_MS;

  return send_rrq(net, c);
}

/* ── Input ────────────────────────────────────────────────────────── */

void tftp_client_input(net_t *net, tftp_client_t *c, uint32_t src_ip,
                       uint16_t src_port, const uint8_t *data, uint16_t len) {
  if (c->state != TFTP_STATE_REQUESTING && c->state != TFTP_STATE_RECEIVING) {
    return;
  }

  /* Only accept packets from our server's IP */
  if (src_ip != c->server_ip)
    return;

  if (len < 2)
    return;

  uint16_t opcode = net_read16be(data);

  /* REQ-TFTP-006: record server TID from the first valid packet */
  if (c->server_tid == 0) {
    if (opcode == TFTP_OP_DATA || opcode == TFTP_OP_OACK ||
        opcode == TFTP_OP_ERROR) {
      c->server_tid = src_port;
    }
  }

  /* REQ-TFTP-018: packet from unexpected TID → ERROR(5), keep going */
  if (c->server_tid != 0 && src_port != c->server_tid) {
    send_error(net, c, TFTP_ERR_UNKNOWN_TID, "Unknown TID");
    return;
  }

  /* Any valid packet resets the retransmit timer */
  c->timer_ms = TFTP_TIMEOUT_MS;
  c->retries = 0;

  /* ── ERROR ─────────────────────────────────────────────────────── */
  if (opcode == TFTP_OP_ERROR) {
    /* REQ-TFTP-016,017 */
    uint16_t code = (len >= 4u) ? net_read16be(data + 2) : 0u;
    const char *msg = (len > 4u) ? (const char *)(data + 4) : "";
    finish(c, 0, code, msg);
    return;
  }

  /* ── OACK ──────────────────────────────────────────────────────── */
  if (opcode == TFTP_OP_OACK && c->state == TFTP_STATE_REQUESTING) {
    /* REQ-TFTP-028: walk option pairs and extract blksize */
    const uint8_t *p = data + 2;
    const uint8_t *end = data + len;
    while (p < end) {
      const char *name = (const char *)p;
      while (p < end && *p != '\0')
        p++;
      if (p >= end)
        break;
      p++; /* skip NUL after name */

      const char *value = (const char *)p;
      while (p < end && *p != '\0')
        p++;
      if (p >= end)
        break;
      p++; /* skip NUL after value */

      /* REQ-TFTP-028: parse "blksize" (case-insensitive first char) */
      if ((name[0] == 'b' || name[0] == 'B') &&
          (name[1] == 'l' || name[1] == 'L')) {
        uint32_t v = 0;
        const char *s = value;
        while (*s >= '0' && *s <= '9') {
          v = v * 10u + (uint32_t)(*s++ - '0');
        }
        if (v >= 8u && v <= 65464u) {
          c->blksize = (uint16_t)v;
        }
      }
    }
    /* REQ-TFTP-027: acknowledge OACK with ACK block 0 */
    c->state = TFTP_STATE_RECEIVING;
    send_ack(net, c, 0);
    return;
  }

  /* ── DATA ──────────────────────────────────────────────────────── */
  if (opcode == TFTP_OP_DATA) {
    if (len < 4u)
      return;

    uint16_t block = net_read16be(data + 2);
    uint16_t data_len = (uint16_t)(len - 4u);
    const uint8_t *payload = data + 4;

    if (c->state == TFTP_STATE_REQUESTING) {
      /* REQ-TFTP-031: server sent DATA(1) without OACK — fall back */
      c->blksize = TFTP_DEFAULT_BLKSIZE;
      c->state = TFTP_STATE_RECEIVING;
    }

    if (block == c->next_block) {
      /* REQ-TFTP-012: deliver data to application */
      if (c->on_data) {
        c->on_data(block, payload, data_len, c->cb_ctx);
      }

      /* REQ-TFTP-009,014,015: send ACK to server TID */
      send_ack(net, c, block);

      /* REQ-TFTP-010: last block has data_len < blksize */
      if (data_len < c->blksize) {
        finish(c, 1, 0, "");
        return;
      }

      /* Advance; handle block number wrap at 65535 → 0 */
      c->next_block =
          (c->next_block == 0xFFFFu) ? 0u : (uint16_t)(c->next_block + 1u);

    } else if (block == (uint16_t)(c->next_block - 1u)) {
      /* REQ-TFTP-013: duplicate (retransmit from server) — re-ACK */
      send_ack(net, c, block);
    }
    /* Unexpected block numbers are silently discarded */
  }
}

/* ── Tick ─────────────────────────────────────────────────────────── */

void tftp_client_tick(net_t *net, tftp_client_t *c, uint32_t ms) {
  if (c->state != TFTP_STATE_REQUESTING && c->state != TFTP_STATE_RECEIVING) {
    return;
  }

  if (ms >= c->timer_ms) {
    c->timer_ms = 0;
  } else {
    c->timer_ms -= ms;
  }

  if (c->timer_ms > 0)
    return;

  /* REQ-TFTP-023: abort after max retries */
  if (c->retries >= TFTP_MAX_RETRIES) {
    finish(c, 0, 0, "Timeout"); /* REQ-TFTP-024 */
    return;
  }

  c->retries++;
  c->timer_ms = TFTP_TIMEOUT_MS;

  if (c->state == TFTP_STATE_REQUESTING) {
    /* REQ-TFTP-021: retransmit RRQ */
    send_rrq(net, c);
  } else {
    /* REQ-TFTP-020: retransmit last ACK */
    uint16_t last_acked =
        (c->next_block == 0) ? 0xFFFFu : (uint16_t)(c->next_block - 1u);
    send_ack(net, c, last_acked);
  }
}

/* ── Internal helpers ─────────────────────────────────────────────── */

static net_err_t send_rrq(net_t *net, tftp_client_t *c) {
  /* RRQ: opcode(2) + filename(\0) + "octet"(\0) [+ blksize option] */
  uint8_t buf[256];
  uint16_t pos = 0;

  net_write16be(buf, TFTP_OP_RRQ);
  pos = 2;

  /* REQ-TFTP-001,003: filename + NUL + "octet" + NUL */
  {
    size_t flen = strlen(c->filename);
    memcpy(buf + pos, c->filename, flen);
    pos += (uint16_t)flen;
    buf[pos++] = '\0';
  }
  memcpy(buf + pos, "octet", 5);
  pos += 5;
  buf[pos++] = '\0';

  /* REQ-TFTP-025,026: blksize option (only when != default) */
  if (c->blksize_opt && c->blksize != TFTP_DEFAULT_BLKSIZE) {
    memcpy(buf + pos, "blksize", 7);
    pos += 7;
    buf[pos++] = '\0';

    /* Convert blksize to decimal ASCII */
    {
      char tmp[8];
      uint8_t ti = 0;
      uint16_t v = c->blksize;
      uint8_t start;
      if (v == 0) {
        tmp[ti++] = '0';
      } else {
        start = ti;
        while (v > 0) {
          tmp[ti++] = (char)('0' + (v % 10u));
          v /= 10u;
        }
        /* reverse the digits */
        {
          uint8_t lo = start, hi = (uint8_t)(ti - 1u);
          while (lo < hi) {
            char t = tmp[lo];
            tmp[lo] = tmp[hi];
            tmp[hi] = t;
            lo++;
            hi--;
          }
        }
      }
      memcpy(buf + pos, tmp, ti);
      pos += ti;
      buf[pos++] = '\0';
    }
  }

  /* REQ-TFTP-002: send to server port 69 */
  return udp_send(net, c->server_ip, c->server_mac, c->local_port,
                  TFTP_SERVER_PORT, buf, pos);
}

static net_err_t send_ack(net_t *net, tftp_client_t *c, uint16_t block) {
  /* REQ-TFTP-014: ACK = opcode(4) + block(2) */
  uint8_t buf[4];
  net_write16be(buf, TFTP_OP_ACK);
  net_write16be(buf + 2, block);

  /* REQ-TFTP-015: send to server TID, not port 69 */
  uint16_t dst = (c->server_tid != 0) ? c->server_tid : TFTP_SERVER_PORT;
  return udp_send(net, c->server_ip, c->server_mac, c->local_port, dst, buf, 4);
}

static net_err_t send_error(net_t *net, tftp_client_t *c, uint16_t code,
                            const char *msg) {
  uint8_t buf[128];
  net_write16be(buf, TFTP_OP_ERROR);
  net_write16be(buf + 2, code);
  {
    size_t mlen = msg ? strlen(msg) : 0u;
    if (mlen > 119u)
      mlen = 119u;
    memcpy(buf + 4, msg, mlen);
    buf[4 + mlen] = '\0';
    uint16_t dst = (c->server_tid != 0) ? c->server_tid : TFTP_SERVER_PORT;
    return udp_send(net, c->server_ip, c->server_mac, c->local_port, dst, buf,
                    (uint16_t)(5u + mlen));
  }
}

static void finish(tftp_client_t *c, uint8_t ok, uint16_t code,
                   const char *msg) {
  c->state = ok ? TFTP_STATE_DONE : TFTP_STATE_ERROR;
  c->timer_ms = 0;
  if (c->on_done) {
    c->on_done(ok, code, msg, c->cb_ctx);
  }
}
