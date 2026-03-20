/**
 * @file tcp.c
 * @brief TCP — Transmission Control Protocol (RFC 9293).
 *
 * Implements REQ-TCP-001 through REQ-TCP-155.
 * RFC 9293 supersedes RFC 793. Section numbers reference RFC 9293.
 *
 * Design: application-managed connections, vtable-based buffer injection,
 * zero-copy header parsing/building, no dynamic allocation.
 *
 * Key decisions for V1:
 *   - Immediate ACK (no delayed ACK, per REQ-TCP-128 MAY)
 *   - No Nagle (per REQ-TCP-131 MAY)
 *   - Congestion control inherently satisfied by stop-and-wait (REQ-TCP-108)
 *   - URG parsed but ignored (REQ-TCP-063 MAY)
 *   - No SACK (REQ-TCP-117 MAY)
 *   - No Window Scale (REQ-TCP-118 MAY)
 */

#include "tcp.h"
#include "eth.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <stddef.h>
#include <string.h>

/* ── Sequence number comparison (REQ-TCP-026, REQ-TCP-027) ──────────
 *
 * Wrapping 32-bit arithmetic: cast the unsigned difference to int32_t.
 * This correctly handles wrap-around: e.g. SEQ_GT(0x00000001, 0xFFFFFFFF)
 * evaluates as (int32_t)(0x00000001 - 0xFFFFFFFF) = (int32_t)(2) > 0 = true.
 */
#define SEQ_LT(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define SEQ_LE(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define SEQ_GT(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)
#define SEQ_GE(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)

/* ── MSS option header (SYN segments add 4 bytes) ───────────────── */
#define TCP_HDRLEN_WITH_MSS 6u /* data offset value (6 × 4 = 24 bytes) */
#define TCP_HDR_SIZE_WITH_MSS 24u

/* ── Default MSS per RFC 9293 §3.7.1 ────────────────────────────── */
#define TCP_DEFAULT_MSS_IPV4 536u

/* ── Max consecutive retransmits before aborting ─────────────────── */
#define TCP_MAX_RETRANSMITS 8u

/* ── Global connection table (application sets this) ─────────────── */
tcp_conn_table_t tcp_connections = {NULL, 0};

/* ══════════════════════════════════════════════════════════════════
 * ISS Generation (REQ-TCP-028, REQ-TCP-029)
 * ══════════════════════════════════════════════════════════════════ */

/* Simple counter-based ISS. On hosted platforms, seeded once from clock.
 * On embedded, starts from a compile-time constant.
 * Incremented by a prime to spread values.
 */
static uint32_t iss_counter = 0x12345678u;

#if defined(__linux__) || defined(__APPLE__)
#include <time.h>
static uint8_t iss_seeded = 0;
#endif

static uint32_t tcp_generate_iss(void) {
#if defined(__linux__) || defined(__APPLE__)
  if (!iss_seeded) {
    iss_counter = (uint32_t)time(NULL) ^ 0xDEADBEEFu;
    iss_seeded = 1;
  }
#endif
  iss_counter += 64000u; /* Increment by ~64K per RFC 793 guidance */
  return iss_counter;
}

/* ══════════════════════════════════════════════════════════════════
 * Checksum (REQ-TCP-018, REQ-TCP-019, REQ-TCP-139)
 * ══════════════════════════════════════════════════════════════════ */

uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *tcp_seg,
                      uint16_t tcp_len) {
  net_cksum_t c;
  net_cksum_init(&c);

  /* IPv4 pseudo-header: src(4) + dst(4) + 0x00 + proto=6(1) + tcp_len(2) */
  net_cksum_add_u32(&c, src_ip);
  net_cksum_add_u32(&c, dst_ip);
  net_cksum_add_u16(&c, 0x0006u); /* zero + protocol 6 */
  net_cksum_add_u16(&c, tcp_len);

  /* TCP header + data */
  net_cksum_add(&c, tcp_seg, tcp_len);

  return net_cksum_finalize(&c);
}

/* ══════════════════════════════════════════════════════════════════
 * Internal: Send a TCP segment
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Build and send a TCP segment.
 *
 * @param net            Network context.
 * @param conn           Connection (provides remote_ip, remote_mac, ports).
 * @param flags          TCP flags byte.
 * @param seq            Sequence number (host byte order).
 * @param ack            Acknowledgment number (host byte order).
 * @param data           Payload data (NULL if none).
 * @param data_len       Payload length.
 * @param include_mss    1 = append MSS option (use in SYN/SYN-ACK only).
 * @param window         Window size to advertise (host byte order).
 * @return NET_OK or error.
 */
static net_err_t tcp_send_segment(net_t *net, tcp_conn_t *conn, uint8_t flags,
                                  uint32_t seq, uint32_t ack,
                                  const uint8_t *data, uint16_t data_len,
                                  uint8_t include_mss, uint16_t window) {
  uint8_t hdr_words = include_mss ? TCP_HDRLEN_WITH_MSS : 5u;
  uint16_t hdr_len = (uint16_t)hdr_words * 4u;
  uint16_t tcp_len = hdr_len + data_len;
  uint16_t total = ETH_HDR_SIZE + IPV4_HDR_SIZE + tcp_len;

  if (total > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *buf = net->tx.buf;

  /* ── Ethernet header ──────────────────────────────────────────── */
  uint8_t *ip_hdr = eth_build(buf, net->tx.capacity, conn->remote_mac, net->mac,
                              NET_ETHERTYPE_IPV4);
  if (!ip_hdr)
    return NET_ERR_BUF_TOO_SMALL;

  /* ── TCP header ───────────────────────────────────────────────── */
  uint8_t *tcp_hdr = ip_hdr + IPV4_HDR_SIZE;

  net_write16be(tcp_hdr + TCP_OFF_SPORT, conn->local_port);
  net_write16be(tcp_hdr + TCP_OFF_DPORT, conn->remote_port);
  net_write32be(tcp_hdr + TCP_OFF_SEQ, seq);
  net_write32be(tcp_hdr + TCP_OFF_ACK, ack);
  tcp_hdr[TCP_OFF_DOFF] = (uint8_t)(hdr_words << 4);
  tcp_hdr[TCP_OFF_FLAGS] = flags;
  net_write16be(tcp_hdr + TCP_OFF_WINDOW, window);
  net_write16be(tcp_hdr + TCP_OFF_CKSUM, 0x0000u);
  net_write16be(tcp_hdr + TCP_OFF_URG, 0x0000u);

  /* ── MSS option (Kind=2, Len=4, value=our_mss) ────────────────── */
  if (include_mss) {
    tcp_hdr[TCP_OFF_OPT + 0] = TCP_OPT_MSS;
    tcp_hdr[TCP_OFF_OPT + 1] = 4u;
    net_write16be(tcp_hdr + TCP_OFF_OPT + 2, conn->our_mss);
  }

  /* ── Payload (if any) ─────────────────────────────────────────── */
  if (data && data_len > 0) {
    memcpy(tcp_hdr + hdr_len, data, data_len);
  }

  /* ── TCP checksum ─────────────────────────────────────────────── */
  uint16_t cksum =
      tcp_checksum(net->ipv4_addr, conn->remote_ip, tcp_hdr, tcp_len);
  net_write16be(tcp_hdr + TCP_OFF_CKSUM, cksum);

  /* ── IPv4 header ──────────────────────────────────────────────── */
  ipv4_build(ip_hdr, tcp_len, IPV4_PROTO_TCP, net->ipv4_addr, conn->remote_ip);

  /* ── Send ─────────────────────────────────────────────────────── */
  int r = net->mac_driver->send(net->mac_ctx, buf, total);
  return (r >= 0) ? NET_OK : NET_ERR_NO_FRAME;
}

/**
 * Send a pure ACK (no data, no options).
 */
static net_err_t tcp_send_ack(net_t *net, tcp_conn_t *conn) {
  uint16_t wnd = (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
  return tcp_send_segment(net, conn, TCP_FLAG_ACK, conn->snd_nxt, conn->rcv_nxt,
                          NULL, 0, 0, wnd);
}

/**
 * Send a RST segment in response to an unacceptable segment.
 *
 * REQ-TCP-072, REQ-TCP-073, REQ-TCP-074.
 *
 * @param net        Network context.
 * @param src_ip     Segment source IP (becomes our dst).
 * @param src_mac    Segment source MAC.
 * @param src_port   Segment source port (becomes our dst port).
 * @param dst_port   Segment destination port (becomes our src port).
 * @param seg_flags  Flags of the triggering segment.
 * @param seg_seq    SEG.SEQ of the triggering segment.
 * @param seg_ack    SEG.ACK of the triggering segment.
 * @param seg_len    SEG.LEN of the triggering segment (data + SYN/FIN).
 */
static void tcp_send_rst_noconn(net_t *net, uint32_t src_ip,
                                const uint8_t *src_mac, uint16_t src_port,
                                uint16_t dst_port, uint8_t seg_flags,
                                uint32_t seg_seq, uint32_t seg_ack,
                                uint16_t seg_len) {
  /* REQ-TCP-075: never send RST in response to RST */
  if (seg_flags & TCP_FLAG_RST)
    return;

  uint16_t total = ETH_HDR_SIZE + IPV4_HDR_SIZE + TCP_HDR_SIZE;
  if (total > net->tx.capacity)
    return;

  uint8_t *buf = net->tx.buf;
  uint8_t *ip_hdr =
      eth_build(buf, net->tx.capacity, src_mac, net->mac, NET_ETHERTYPE_IPV4);
  if (!ip_hdr)
    return;

  uint8_t *tcp_hdr = ip_hdr + IPV4_HDR_SIZE;
  uint32_t rst_seq, rst_ack;
  uint8_t rst_flags;

  /* REQ-TCP-073, REQ-TCP-074: RST seq/ack depend on triggering segment */
  if (seg_flags & TCP_FLAG_ACK) {
    /* If ACK set: SEG.SEQ = SEG.ACK of triggering segment */
    rst_seq = seg_ack;
    rst_ack = 0;
    rst_flags = TCP_FLAG_RST;
  } else {
    /* If no ACK: SEQ = 0, ACK = SEG.SEQ + SEG.LEN, set ACK bit */
    rst_seq = 0;
    rst_ack = seg_seq + seg_len;
    rst_flags = TCP_FLAG_RST | TCP_FLAG_ACK;
  }

  net_write16be(tcp_hdr + TCP_OFF_SPORT, dst_port);
  net_write16be(tcp_hdr + TCP_OFF_DPORT, src_port);
  net_write32be(tcp_hdr + TCP_OFF_SEQ, rst_seq);
  net_write32be(tcp_hdr + TCP_OFF_ACK, rst_ack);
  tcp_hdr[TCP_OFF_DOFF] = (5u << 4);
  tcp_hdr[TCP_OFF_FLAGS] = rst_flags;
  net_write16be(tcp_hdr + TCP_OFF_WINDOW, 0);
  net_write16be(tcp_hdr + TCP_OFF_CKSUM, 0);
  net_write16be(tcp_hdr + TCP_OFF_URG, 0);

  uint16_t cksum = tcp_checksum(net->ipv4_addr, src_ip, tcp_hdr, TCP_HDR_SIZE);
  net_write16be(tcp_hdr + TCP_OFF_CKSUM, cksum);

  ipv4_build(ip_hdr, TCP_HDR_SIZE, IPV4_PROTO_TCP, net->ipv4_addr, src_ip);
  net->mac_driver->send(net->mac_ctx, buf, total);
}

/**
 * Send RST on an existing connection and move to CLOSED.
 * REQ-TCP-016.
 */
static void tcp_send_rst_conn(net_t *net, tcp_conn_t *conn) {
  /* REQ-TCP-075 */
  if (!conn->mac_valid)
    return;
  uint16_t wnd = 0;
  tcp_send_segment(net, conn, TCP_FLAG_RST | TCP_FLAG_ACK, conn->snd_nxt,
                   conn->rcv_nxt, NULL, 0, 0, wnd);
  conn->state = TCP_CLOSED;
  conn->rto_active = 0;
}

/* ══════════════════════════════════════════════════════════════════
 * Retransmit timer helpers
 * ══════════════════════════════════════════════════════════════════ */

static void rto_start(tcp_conn_t *conn) {
  conn->rto_remaining_ms = conn->rto_ms;
  conn->rto_active = 1;
}

static void rto_stop(tcp_conn_t *conn) {
  conn->rto_active = 0;
  conn->rto_remaining_ms = 0;
  conn->retransmit_count = 0;
}

static void rto_restart(tcp_conn_t *conn) {
  conn->rto_remaining_ms = conn->rto_ms;
}

/* ══════════════════════════════════════════════════════════════════
 * Internal: flush outbound data from the TX buffer
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Try to send any pending data from the TX buffer.
 * Respects peer's window (snd_wnd).
 * Called after tcp_send() queues data and after receiving ACKs.
 */
static void tcp_do_flush(net_t *net, tcp_conn_t *conn) {
  const uint8_t *seg_data = NULL;
  uint16_t mss = conn->snd_mss;

  /* Honor peer's window (REQ-TCP-084) */
  uint16_t can_send =
      (conn->snd_wnd < (uint32_t)mss) ? (uint16_t)conn->snd_wnd : mss;
  if (can_send == 0)
    return; /* peer zero-window — persist handled by tcp_tick */

  uint16_t seg_len =
      conn->txbuf_ops->next_segment(conn->txbuf_ctx, &seg_data, can_send);
  if (seg_len == 0)
    return;

  uint16_t wnd = (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
  uint8_t flags = TCP_FLAG_ACK;

  net_err_t err = tcp_send_segment(net, conn, flags, conn->snd_nxt,
                                   conn->rcv_nxt, seg_data, seg_len, 0, wnd);
  if (err == NET_OK) {
    conn->snd_nxt += seg_len;
    rto_start(conn);
  }
}

/* ══════════════════════════════════════════════════════════════════
 * Option parsing helpers
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Parse TCP options from a received SYN or SYN-ACK.
 * Extracts MSS option (Kind=2). Ignores all other options.
 * REQ-TCP-109..REQ-TCP-115.
 *
 * @param opt_ptr  Pointer to options area.
 * @param opt_len  Length of options area (header_len - 20).
 * @param mss_out  Output: peer's MSS (set to TCP_DEFAULT_MSS_IPV4 if not
 * found).
 */
static void tcp_parse_options(const uint8_t *opt_ptr, uint16_t opt_len,
                              uint16_t *mss_out) {
  *mss_out = TCP_DEFAULT_MSS_IPV4; /* REQ-TCP-079: default if not present */

  uint16_t i = 0;
  while (i < opt_len) {
    uint8_t kind = opt_ptr[i];

    if (kind == TCP_OPT_EOL) /* REQ-TCP-110 */
      break;

    if (kind == TCP_OPT_NOP) { /* REQ-TCP-111 */
      i++;
      continue;
    }

    /* All other options have a length byte */
    if (i + 1 >= opt_len)
      break;
    uint8_t len = opt_ptr[i + 1];
    if (len < 2 || (i + len) > opt_len) /* REQ-TCP-115: skip unknown */
      break;

    if (kind == TCP_OPT_MSS && len == 4) { /* REQ-TCP-112 */
      *mss_out = net_read16be(opt_ptr + i + 2);
      if (*mss_out == 0)
        *mss_out = TCP_DEFAULT_MSS_IPV4;
    }
    /* REQ-TCP-115: unknown options — skip by length */
    i += len;
  }
}

/* ══════════════════════════════════════════════════════════════════
 * Acceptability check (RFC 9293 §3.10.7.4 Step 1, REQ-TCP-041..045)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Check if a segment is acceptable (within receive window).
 * REQ-TCP-041..045.
 *
 * @param rcv_nxt  RCV.NXT
 * @param rcv_wnd  RCV.WND
 * @param seg_seq  SEG.SEQ
 * @param seg_len  SEG.LEN (data bytes + SYN/FIN count)
 * @return 1 if acceptable, 0 if not.
 */
static int tcp_seg_acceptable(uint32_t rcv_nxt, uint32_t rcv_wnd,
                              uint32_t seg_seq, uint32_t seg_len) {
  if (seg_len == 0) {
    if (rcv_wnd == 0)
      return (seg_seq == rcv_nxt); /* REQ-TCP-043 */
    else
      return SEQ_GE(seg_seq, rcv_nxt) &&
             SEQ_LT(seg_seq, rcv_nxt + rcv_wnd); /* REQ-TCP-044 */
  } else {
    if (rcv_wnd == 0)
      return 0; /* REQ-TCP-045: no room */
    /* REQ-TCP-045: start or end of segment must be in window */
    uint32_t seg_end = seg_seq + seg_len - 1u;
    int start_ok =
        SEQ_GE(seg_seq, rcv_nxt) && SEQ_LT(seg_seq, rcv_nxt + rcv_wnd);
    int end_ok = SEQ_GE(seg_end, rcv_nxt) && SEQ_LT(seg_end, rcv_nxt + rcv_wnd);
    return start_ok || end_ok;
  }
}

/* ══════════════════════════════════════════════════════════════════
 * Connection matching (REQ-TCP-023, REQ-TCP-148, REQ-TCP-149)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Find the best matching connection for an incoming segment.
 *
 * Priority: full 4-tuple match first, then LISTEN match.
 *
 * @param local_ip    Destination IP from the IP header (our IP).
 * @param local_port  Destination port from TCP header.
 * @param remote_ip   Source IP from IP header.
 * @param remote_port Source port from TCP header.
 * @return Matching tcp_conn_t or NULL.
 */
static tcp_conn_t *tcp_find_conn(uint32_t local_ip, uint16_t local_port,
                                 uint32_t remote_ip, uint16_t remote_port) {
  tcp_conn_t *listen_match = NULL;
  uint8_t i;

  (void)local_ip; /* not used for matching in V1 (single interface) */

  for (i = 0; i < tcp_connections.count; i++) {
    tcp_conn_t *c = tcp_connections.conns[i];
    if (!c)
      continue;

    if (c->local_port != local_port)
      continue;

    /* Full 4-tuple match (REQ-TCP-148) */
    if (c->state != TCP_CLOSED && c->state != TCP_LISTEN) {
      if (c->remote_ip == remote_ip && c->remote_port == remote_port) {
        return c;
      }
    }

    /* LISTEN match (REQ-TCP-149): any remote */
    if (c->state == TCP_LISTEN && !listen_match)
      listen_match = c;
  }

  return listen_match;
}

/* ══════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════ */

net_err_t tcp_conn_init(tcp_conn_t *conn, const tcp_txbuf_ops_t *tx_ops,
                        void *tx_ctx, const tcp_rxbuf_ops_t *rx_ops,
                        void *rx_ctx, void (*on_event)(tcp_conn_t *, uint8_t)) {
  if (!conn || !tx_ops || !tx_ctx || !rx_ops || !rx_ctx)
    return NET_ERR_INVALID_PARAM;

  memset(conn, 0, sizeof(*conn));
  conn->state = TCP_CLOSED;
  conn->txbuf_ops = tx_ops;
  conn->txbuf_ctx = tx_ctx;
  conn->rxbuf_ops = rx_ops;
  conn->rxbuf_ctx = rx_ctx;
  conn->on_event = on_event;
  conn->rto_ms = NET_DEFAULT_TCP_RTO_INIT_MS;
  conn->snd_mss = TCP_DEFAULT_MSS_IPV4;

  return NET_OK;
}

net_err_t tcp_listen(tcp_conn_t *conn, uint16_t local_port) {
  if (!conn || local_port == 0)
    return NET_ERR_INVALID_PARAM;

  conn->state = TCP_LISTEN;
  conn->local_port = local_port;
  conn->remote_ip = 0;
  conn->remote_port = 0;
  conn->rto_active = 0;

  NET_LOG("tcp: listen on port %u", local_port);
  return NET_OK;
}

net_err_t tcp_connect(net_t *net, tcp_conn_t *conn, uint32_t remote_ip,
                      const uint8_t *remote_mac, uint16_t remote_port,
                      uint16_t local_port) {
  if (!net || !conn || !remote_mac || remote_port == 0 || local_port == 0)
    return NET_ERR_INVALID_PARAM;

  /* Compute our MSS from the TX buffer capacity (REQ-TCP-077) */
  uint16_t mss_from_buf = NET_TCP_MSS_IPV4(net->tx.capacity);
  conn->our_mss = mss_from_buf < 1460u ? mss_from_buf : 1460u;
  conn->snd_mss = TCP_DEFAULT_MSS_IPV4; /* until peer tells us */

  conn->local_port = local_port;
  conn->remote_port = remote_port;
  conn->remote_ip = remote_ip;
  memcpy(conn->remote_mac, remote_mac, 6);
  conn->mac_valid = 1;

  conn->iss = tcp_generate_iss();
  conn->snd_una = conn->iss;
  conn->snd_nxt = conn->iss + 1u; /* SYN consumes 1 sequence number */
  conn->rcv_nxt = 0;
  conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
  conn->rto_ms = NET_DEFAULT_TCP_RTO_INIT_MS;
  conn->rto_active = 0;

  conn->state = TCP_SYN_SENT;

  /* Send SYN with MSS option (REQ-TCP-076) */
  uint16_t wnd = (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
  net_err_t err =
      tcp_send_segment(net, conn, TCP_FLAG_SYN, conn->iss, 0, NULL, 0, 1, wnd);
  if (err != NET_OK) {
    conn->state = TCP_CLOSED;
    return err;
  }

  rto_start(conn);
  NET_LOG("tcp: connect from port %u to %u.%u.%u.%u:%u", local_port,
          (remote_ip >> 24) & 0xFF, (remote_ip >> 16) & 0xFF,
          (remote_ip >> 8) & 0xFF, remote_ip & 0xFF, remote_port);
  return NET_OK;
}

tcp_state_t tcp_status(const tcp_conn_t *conn) {
  return conn ? conn->state : TCP_CLOSED;
}

int tcp_send(net_t *net, tcp_conn_t *conn, const uint8_t *data, uint16_t len) {
  if (!net || !conn)
    return (int)NET_ERR_INVALID_PARAM;

  if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)
    return (int)NET_ERR_INVALID_PARAM;

  if (len == 0)
    return 0;

  /* Write into TX buffer via the injected ops */
  uint16_t accepted = conn->txbuf_ops->write(conn->txbuf_ctx, data, len);

  /* Immediately try to send (no Nagle, REQ-TCP-131 MAY) */
  if (accepted > 0)
    tcp_do_flush(net, conn);

  return (int)accepted;
}

uint16_t tcp_recv(tcp_conn_t *conn, uint8_t *buf, uint16_t maxlen) {
  if (!conn || !buf)
    return 0;
  return conn->rxbuf_ops->read(conn->rxbuf_ctx, buf, maxlen);
}

net_err_t tcp_close(net_t *net, tcp_conn_t *conn) {
  if (!net || !conn)
    return NET_ERR_INVALID_PARAM;

  switch (conn->state) {
  case TCP_ESTABLISHED:
    /* Active close: ESTABLISHED → FIN_WAIT_1 (REQ-TCP-005) */
    conn->state = TCP_FIN_WAIT_1;
    {
      uint16_t wnd =
          (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
      tcp_send_segment(net, conn, TCP_FLAG_FIN | TCP_FLAG_ACK, conn->snd_nxt,
                       conn->rcv_nxt, NULL, 0, 0, wnd);
      conn->snd_nxt++;
      rto_start(conn);
    }
    break;

  case TCP_CLOSE_WAIT:
    /* Passive close: CLOSE_WAIT → LAST_ACK (REQ-TCP-006) */
    conn->state = TCP_LAST_ACK;
    {
      uint16_t wnd =
          (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
      tcp_send_segment(net, conn, TCP_FLAG_FIN | TCP_FLAG_ACK, conn->snd_nxt,
                       conn->rcv_nxt, NULL, 0, 0, wnd);
      conn->snd_nxt++;
      rto_start(conn);
    }
    break;

  default:
    /* Already closed or in closing sequence */
    break;
  }

  return NET_OK;
}

net_err_t tcp_abort(net_t *net, tcp_conn_t *conn) {
  if (!conn)
    return NET_ERR_INVALID_PARAM;

  if (conn->state != TCP_CLOSED && conn->mac_valid)
    tcp_send_rst_conn(net, conn);
  else
    conn->state = TCP_CLOSED;

  rto_stop(conn);

  if (conn->on_event)
    conn->on_event(conn, TCP_EVT_RESET);

  return NET_OK;
}

/* ══════════════════════════════════════════════════════════════════
 * tcp_input — Main receive path (RFC 9293 §3.10.7)
 * ══════════════════════════════════════════════════════════════════ */

void tcp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  uint8_t *seg = ip->payload;
  uint16_t seg_avail = ip->payload_len;

  /* ── Validate minimum header (REQ-TCP-021) ────────────────────── */
  if (seg_avail < TCP_HDR_SIZE)
    return;

  uint8_t doff_byte = seg[TCP_OFF_DOFF];
  uint8_t data_off = (doff_byte >> 4) & 0x0Fu;

  if (data_off < 5u) /* REQ-TCP-021 */
    return;

  uint16_t hdr_len = (uint16_t)data_off * 4u;

  if (hdr_len > seg_avail) /* REQ-TCP-022 */
    return;

  /* ── Verify checksum (REQ-TCP-018) ────────────────────────────── */
  {
    uint16_t tcp_len = seg_avail; /* use IP payload length per REQ-TCP-019 */
    /* Standard verification: include the stored checksum in the computation.
     * A valid TCP segment produces 0xFFFF when the ones-complement sum is
     * taken over pseudo-header + TCP segment (checksum field included). */
    uint16_t computed = tcp_checksum(ip->src_ip, ip->dst_ip, seg, tcp_len);
    /* net_cksum_finalize returns ~sum; a valid packet sums to 0xFFFF
     * before complement, so the finalized result is 0x0000. */
    if (computed != 0x0000u) {
      NET_LOG("tcp_input: bad checksum");
      return;
    }
  }

  /* ── Extract segment fields ───────────────────────────────────── */
  uint16_t src_port = net_read16be(seg + TCP_OFF_SPORT);
  uint16_t dst_port = net_read16be(seg + TCP_OFF_DPORT);
  uint32_t seg_seq = net_read32be(seg + TCP_OFF_SEQ);
  uint32_t seg_ack = net_read32be(seg + TCP_OFF_ACK);
  uint8_t seg_flags = seg[TCP_OFF_FLAGS];
  uint16_t seg_wnd = net_read16be(seg + TCP_OFF_WINDOW);

  uint8_t *data_ptr = seg + hdr_len;
  uint16_t data_len = seg_avail - hdr_len;

  /* SEG.LEN = data bytes + SYN flag + FIN flag (consume sequence space) */
  uint32_t seg_len = (uint32_t)data_len +
                     ((seg_flags & TCP_FLAG_SYN) ? 1u : 0u) +
                     ((seg_flags & TCP_FLAG_FIN) ? 1u : 0u);

  /* Options */
  uint8_t *opt_ptr = seg + TCP_HDR_SIZE;
  uint16_t opt_len = (hdr_len > TCP_HDR_SIZE) ? (hdr_len - TCP_HDR_SIZE) : 0;

  NET_LOG("tcp_input: %u.%u.%u.%u:%u -> :%u flags=0x%02x seq=%lu ack=%lu "
          "len=%u",
          (ip->src_ip >> 24) & 0xFF, (ip->src_ip >> 16) & 0xFF,
          (ip->src_ip >> 8) & 0xFF, ip->src_ip & 0xFF, src_port, dst_port,
          seg_flags, (unsigned long)seg_seq, (unsigned long)seg_ack, data_len);

  /* ── Find matching connection (REQ-TCP-023) ───────────────────── */
  tcp_conn_t *conn = tcp_find_conn(ip->dst_ip, dst_port, ip->src_ip, src_port);

  /* ── No match → send RST (REQ-TCP-072) ───────────────────────── */
  if (!conn) {
    NET_LOG("tcp_input: no connection for port %u → RST", dst_port);
    tcp_send_rst_noconn(net, ip->src_ip, eth->src_mac, src_port, dst_port,
                        seg_flags, seg_seq, seg_ack, (uint16_t)seg_len);
    return;
  }

  /* ════════════════════════════════════════════════════════════════
   * LISTEN state (RFC 9293 §3.10.7.2)
   * REQ-TCP-030..REQ-TCP-035
   * ════════════════════════════════════════════════════════════════ */
  if (conn->state == TCP_LISTEN) {
    /* REQ-TCP-030: if RST, ignore */
    if (seg_flags & TCP_FLAG_RST)
      return;

    /* REQ-TCP-031: if ACK, send RST */
    if (seg_flags & TCP_FLAG_ACK) {
      tcp_send_rst_noconn(net, ip->src_ip, eth->src_mac, src_port, dst_port,
                          seg_flags, seg_seq, seg_ack, (uint16_t)seg_len);
      return;
    }

    /* REQ-TCP-032: if SYN, start connection */
    if (seg_flags & TCP_FLAG_SYN) {
      /* REQ-TCP-033: record remote identity */
      conn->remote_ip = ip->src_ip;
      conn->remote_port = src_port;
      memcpy(conn->remote_mac, eth->src_mac, 6);
      conn->mac_valid = 1;

      /* REQ-TCP-034: set IRS, RCV.NXT */
      conn->irs = seg_seq;
      conn->rcv_nxt = seg_seq + 1u;

      /* Parse options: peer's MSS (REQ-TCP-078, REQ-TCP-079) */
      uint16_t peer_mss;
      tcp_parse_options(opt_ptr, opt_len, &peer_mss);
      conn->snd_mss = peer_mss;

      /* Compute our MSS from TX buffer (REQ-TCP-077) */
      uint16_t our = NET_TCP_MSS_IPV4(net->tx.capacity);
      conn->our_mss = (our < 1460u) ? our : 1460u;

      /* Generate ISS (REQ-TCP-028) */
      conn->iss = tcp_generate_iss();
      conn->snd_una = conn->iss;
      conn->snd_nxt = conn->iss + 1u; /* SYN consumes 1 */
      conn->snd_wnd = seg_wnd;
      conn->snd_wl1 = seg_seq;
      conn->snd_wl2 = seg_ack;

      /* Advertise window from RX buffer */
      conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);

      /* REQ-TCP-032: transition to SYN_RECEIVED */
      conn->state = TCP_SYN_RECEIVED;
      conn->rto_ms = NET_DEFAULT_TCP_RTO_INIT_MS;

      /* REQ-TCP-035: send SYN,ACK */
      uint16_t wnd =
          (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
      tcp_send_segment(net, conn, TCP_FLAG_SYN | TCP_FLAG_ACK, conn->iss,
                       conn->rcv_nxt, NULL, 0, 1, wnd); /* include MSS option */
      rto_start(conn);

      NET_LOG("tcp: SYN from %u.%u.%u.%u:%u → SYN_RECEIVED, ISS=%lu",
              (ip->src_ip >> 24) & 0xFF, (ip->src_ip >> 16) & 0xFF,
              (ip->src_ip >> 8) & 0xFF, ip->src_ip & 0xFF, src_port,
              (unsigned long)conn->iss);
    }
    return;
  }

  /* ════════════════════════════════════════════════════════════════
   * SYN_SENT state (RFC 9293 §3.10.7.3)
   * REQ-TCP-036..REQ-TCP-040
   * ════════════════════════════════════════════════════════════════ */
  if (conn->state == TCP_SYN_SENT) {
    /* REQ-TCP-040: check ACK acceptability */
    int ack_ok = (seg_flags & TCP_FLAG_ACK) && SEQ_GT(seg_ack, conn->snd_una) &&
                 SEQ_LE(seg_ack, conn->snd_nxt);

    /* REQ-TCP-036: unacceptable ACK → RST */
    if ((seg_flags & TCP_FLAG_ACK) && !ack_ok) {
      tcp_send_rst_noconn(net, ip->src_ip, eth->src_mac, src_port, dst_port,
                          seg_flags, seg_seq, seg_ack, (uint16_t)seg_len);
      return;
    }

    /* REQ-TCP-037: RST with valid ACK → abort */
    if (seg_flags & TCP_FLAG_RST) {
      if (ack_ok) {
        conn->state = TCP_CLOSED;
        rto_stop(conn);
        if (conn->on_event)
          conn->on_event(conn, TCP_EVT_RESET);
      }
      return;
    }

    /* REQ-TCP-038: SYN,ACK → ESTABLISHED */
    if ((seg_flags & TCP_FLAG_SYN) && ack_ok) {
      uint16_t peer_mss;
      tcp_parse_options(opt_ptr, opt_len, &peer_mss);
      conn->snd_mss = peer_mss;

      conn->irs = seg_seq;
      conn->rcv_nxt = seg_seq + 1u;
      conn->snd_una = seg_ack;
      conn->snd_wnd = seg_wnd;
      conn->snd_wl1 = seg_seq;
      conn->snd_wl2 = seg_ack;

      /* ACK the in-flight SYN */
      conn->txbuf_ops->ack(conn->txbuf_ctx, seg_ack - conn->iss);

      conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
      conn->state = TCP_ESTABLISHED;
      rto_stop(conn);
      tcp_send_ack(net, conn);

      NET_LOG("tcp: ESTABLISHED (active open)");
      if (conn->on_event)
        conn->on_event(conn, TCP_EVT_CONNECTED);

      /* Send any queued data (REQ-TCP-014) */
      tcp_do_flush(net, conn);
      return;
    }

    /* REQ-TCP-039: SYN without ACK → simultaneous open → SYN_RECEIVED */
    if (seg_flags & TCP_FLAG_SYN) {
      uint16_t peer_mss;
      tcp_parse_options(opt_ptr, opt_len, &peer_mss);
      conn->snd_mss = peer_mss;

      conn->irs = seg_seq;
      conn->rcv_nxt = seg_seq + 1u;
      conn->snd_wnd = seg_wnd;
      conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
      conn->state = TCP_SYN_RECEIVED;

      /* Send SYN,ACK */
      uint16_t wnd =
          (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
      tcp_send_segment(net, conn, TCP_FLAG_SYN | TCP_FLAG_ACK, conn->iss,
                       conn->rcv_nxt, NULL, 0, 1, wnd);
      rto_start(conn);
      NET_LOG("tcp: simultaneous open → SYN_RECEIVED");
      return;
    }

    return; /* no SYN and no RST — drop */
  }

  /* ════════════════════════════════════════════════════════════════
   * All other states: ESTABLISHED, SYN_RECEIVED, FIN_WAIT_*,
   * CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
   * RFC 9293 §3.10.7.4 Steps 1–8
   * ════════════════════════════════════════════════════════════════ */

  /* ── Step 1: Sequence number acceptability (REQ-TCP-041..045) ─── */
  if (!tcp_seg_acceptable(conn->rcv_nxt, conn->rcv_wnd, seg_seq, seg_len)) {
    /* REQ-TCP-042: send ACK (unless RST), discard */
    if (!(seg_flags & TCP_FLAG_RST))
      tcp_send_ack(net, conn);
    return;
  }

  /* ── Step 2: RST processing (REQ-TCP-046..049) ───────────────── */
  if (seg_flags & TCP_FLAG_RST) {
    /* REQ-TCP-049: RST seq must be in window (already checked above) */
    switch (conn->state) {
    case TCP_SYN_RECEIVED:
      /* REQ-TCP-046: if passive open → LISTEN; if active → CLOSED */
      conn->state = TCP_CLOSED; /* simplified: go to CLOSED */
      rto_stop(conn);
      if (conn->on_event)
        conn->on_event(conn, TCP_EVT_RESET);
      return;

    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_CLOSE_WAIT:
      /* REQ-TCP-047: abort connection */
      conn->state = TCP_CLOSED;
      rto_stop(conn);
      if (conn->on_event)
        conn->on_event(conn, TCP_EVT_RESET);
      return;

    case TCP_CLOSING:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
      /* REQ-TCP-048: close connection */
      conn->state = TCP_CLOSED;
      rto_stop(conn);
      return;

    default:
      break;
    }
  }

  /* ── Step 3: Security — skip (REQ-TCP-050 MAY) ───────────────── */

  /* ── Step 4: SYN in established state (REQ-TCP-051) ─────────── */
  if (seg_flags & TCP_FLAG_SYN) {
    /* Error: SYN received in non-SYN states */
    tcp_send_rst_conn(net, conn);
    if (conn->on_event)
      conn->on_event(conn, TCP_EVT_ERROR);
    return;
  }

  /* ── Step 5: ACK processing (REQ-TCP-053..062) ───────────────── */
  if (!(seg_flags & TCP_FLAG_ACK)) {
    /* REQ-TCP-053: if ACK not set, discard */
    return;
  }

  switch (conn->state) {
  case TCP_SYN_RECEIVED:
    /* REQ-TCP-054: ACK in SYN_RECEIVED → ESTABLISHED */
    if (SEQ_GT(seg_ack, conn->snd_una) && SEQ_LE(seg_ack, conn->snd_nxt)) {
      /* Acknowledge the SYN */
      conn->txbuf_ops->ack(conn->txbuf_ctx,
                           (uint32_t)(seg_ack - conn->snd_una));
      conn->snd_una = seg_ack;
      conn->snd_wnd = seg_wnd;
      conn->snd_wl1 = seg_seq;
      conn->snd_wl2 = seg_ack;
      conn->state = TCP_ESTABLISHED;
      rto_stop(conn);
      NET_LOG("tcp: ESTABLISHED (passive open)");
      if (conn->on_event)
        conn->on_event(conn, TCP_EVT_CONNECTED);
    } else {
      /* Invalid ACK in SYN_RECEIVED */
      tcp_send_rst_noconn(net, ip->src_ip, eth->src_mac, src_port, dst_port,
                          seg_flags, seg_seq, seg_ack, (uint16_t)seg_len);
      return;
    }
    break;

  case TCP_ESTABLISHED:
  case TCP_FIN_WAIT_1:
  case TCP_FIN_WAIT_2:
  case TCP_CLOSE_WAIT:
  case TCP_CLOSING:
    /* REQ-TCP-055: advance SND.UNA */
    if (SEQ_GT(seg_ack, conn->snd_una) && SEQ_LE(seg_ack, conn->snd_nxt)) {
      uint32_t newly_acked = seg_ack - conn->snd_una;
      conn->txbuf_ops->ack(conn->txbuf_ctx, newly_acked);
      conn->snd_una = seg_ack;

      /* REQ-TCP-097: restart timer if new data ACKed */
      if (conn->txbuf_ops->in_flight(conn->txbuf_ctx) > 0)
        rto_restart(conn);
      else
        rto_stop(conn); /* REQ-TCP-098 */

      /* REQ-TCP-058: update SND.WND */
      if (SEQ_LT(conn->snd_wl1, seg_seq) ||
          (conn->snd_wl1 == seg_seq && SEQ_LE(conn->snd_wl2, seg_ack))) {
        conn->snd_wnd = seg_wnd;
        conn->snd_wl1 = seg_seq;
        conn->snd_wl2 = seg_ack;
      }

      /* Send any queued data (window may have opened) */
      if (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)
        tcp_do_flush(net, conn);

      /* Notify application that TX space is available */
      if (conn->txbuf_ops->writable(conn->txbuf_ctx) > 0)
        if (conn->on_event)
          conn->on_event(conn, TCP_EVT_WRITABLE);
    } else if (SEQ_GT(seg_ack, conn->snd_nxt)) {
      /* REQ-TCP-056: ACK for something not yet sent → send ACK, discard */
      tcp_send_ack(net, conn);
      return;
    }
    /* REQ-TCP-057: duplicate ACK (seg_ack <= snd_una) — ignore */

    /* FIN-WAIT state transitions from ACK (REQ-TCP-059..062) */
    if (conn->state == TCP_FIN_WAIT_1) {
      if (SEQ_GE(seg_ack, conn->snd_nxt)) {
        /* REQ-TCP-059: our FIN is ACKed */
        conn->state = TCP_FIN_WAIT_2;
        NET_LOG("tcp: FIN_WAIT_1 → FIN_WAIT_2");
      }
    }
    if (conn->state == TCP_CLOSING) {
      if (SEQ_GE(seg_ack, conn->snd_nxt)) {
        /* REQ-TCP-061: our FIN ACKed while in CLOSING → TIME_WAIT */
        conn->state = TCP_TIME_WAIT;
        conn->timewait_remaining_ms = 2u * NET_DEFAULT_TCP_MSL_MS;
        rto_stop(conn);
        NET_LOG("tcp: CLOSING → TIME_WAIT");
      }
    }
    break;

  case TCP_LAST_ACK:
    /* REQ-TCP-062: our FIN ACKed → CLOSED */
    if (SEQ_GE(seg_ack, conn->snd_nxt)) {
      conn->state = TCP_CLOSED;
      rto_stop(conn);
      NET_LOG("tcp: LAST_ACK → CLOSED");
      if (conn->on_event)
        conn->on_event(conn, TCP_EVT_CLOSED);
      return; /* no further processing */
    }
    break;

  case TCP_TIME_WAIT:
    /* REQ-TCP-008: restart TIME_WAIT timer on any segment */
    conn->timewait_remaining_ms = 2u * NET_DEFAULT_TCP_MSL_MS;
    tcp_send_ack(net, conn);
    return;

  default:
    break;
  }

  /* ── Step 6: URG — ignore (REQ-TCP-063 MAY) ─────────────────── */

  /* ── Step 7: Segment data processing (REQ-TCP-064..067) ─────── */
  if (data_len > 0 &&
      (conn->state == TCP_ESTABLISHED || conn->state == TCP_FIN_WAIT_1 ||
       conn->state == TCP_FIN_WAIT_2)) {

    /* REQ-TCP-067: trim data to receive window */
    uint16_t trimmed = data_len;
    if ((uint32_t)trimmed > conn->rcv_wnd)
      trimmed = (uint16_t)conn->rcv_wnd;

    if (trimmed > 0) {
      /* REQ-TCP-064: deliver to RX buffer */
      uint16_t delivered =
          conn->rxbuf_ops->deliver(conn->rxbuf_ctx, data_ptr, trimmed);
      /* REQ-TCP-065: advance RCV.NXT */
      conn->rcv_nxt += delivered;

      /* Update our window */
      conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);

      /* Notify application (REQ-TCP-064) */
      if (delivered > 0 && conn->on_event)
        conn->on_event(conn, TCP_EVT_DATA);
    }

    /* REQ-TCP-066: send ACK */
    tcp_send_ack(net, conn);
  }

  /* ── Step 8: FIN processing (REQ-TCP-068..071) ───────────────── */
  if (seg_flags & TCP_FLAG_FIN) {
    /* FIN only meaningful in states that can receive data */
    switch (conn->state) {
    case TCP_CLOSED:
    case TCP_LISTEN:
    case TCP_SYN_SENT:
      return; /* do not process FIN in these states */
    default:
      break;
    }

    /* REQ-TCP-068: advance RCV.NXT over the FIN */
    conn->rcv_nxt++;
    conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
    tcp_send_ack(net, conn);

    /* REQ-TCP-069..071: state transitions */
    switch (conn->state) {
    case TCP_SYN_RECEIVED:
    case TCP_ESTABLISHED:
      /* REQ-TCP-069: → CLOSE_WAIT */
      conn->state = TCP_CLOSE_WAIT;
      NET_LOG("tcp: ESTABLISHED → CLOSE_WAIT");
      if (conn->on_event)
        conn->on_event(conn, TCP_EVT_CLOSED);
      break;

    case TCP_FIN_WAIT_1:
      /* REQ-TCP-070: if our FIN also ACKed → TIME_WAIT; else → CLOSING */
      if (SEQ_GE(seg_ack, conn->snd_nxt)) {
        conn->state = TCP_TIME_WAIT;
        conn->timewait_remaining_ms = 2u * NET_DEFAULT_TCP_MSL_MS;
        rto_stop(conn);
        NET_LOG("tcp: FIN_WAIT_1 → TIME_WAIT");
      } else {
        conn->state = TCP_CLOSING;
        NET_LOG("tcp: FIN_WAIT_1 → CLOSING");
      }
      break;

    case TCP_FIN_WAIT_2:
      /* REQ-TCP-071: → TIME_WAIT */
      conn->state = TCP_TIME_WAIT;
      conn->timewait_remaining_ms = 2u * NET_DEFAULT_TCP_MSL_MS;
      rto_stop(conn);
      NET_LOG("tcp: FIN_WAIT_2 → TIME_WAIT");
      break;

    default:
      /* CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT: re-ACK, stay */
      break;
    }
  }
}

/* ══════════════════════════════════════════════════════════════════
 * tcp_tick — Timer management (REQ-TCP-090..100, REQ-TCP-008)
 * ══════════════════════════════════════════════════════════════════ */

void tcp_tick(net_t *net, uint32_t elapsed_ms) {
  uint8_t i;

  for (i = 0; i < tcp_connections.count; i++) {
    tcp_conn_t *conn = tcp_connections.conns[i];
    if (!conn)
      continue;

    /* ── TIME-WAIT expiry (REQ-TCP-008) ────────────────────────── */
    if (conn->state == TCP_TIME_WAIT) {
      if (conn->timewait_remaining_ms <= elapsed_ms) {
        conn->timewait_remaining_ms = 0;
        conn->state = TCP_CLOSED;
        NET_LOG("tcp: TIME_WAIT expired → CLOSED");
        if (conn->on_event)
          conn->on_event(conn, TCP_EVT_CLOSED);
      } else {
        conn->timewait_remaining_ms -= elapsed_ms;
      }
      continue;
    }

    /* ── Retransmit timer (REQ-TCP-090..100) ──────────────────── */
    if (!conn->rto_active || conn->state == TCP_CLOSED)
      continue;

    if (conn->rto_remaining_ms <= elapsed_ms) {
      conn->rto_remaining_ms = 0;

      /* REQ-TCP-095: retransmit earliest unacknowledged segment */
      if (conn->txbuf_ops->in_flight(conn->txbuf_ctx) > 0 ||
          conn->state == TCP_SYN_SENT || conn->state == TCP_SYN_RECEIVED) {

        conn->retransmit_count++;

        if (conn->retransmit_count > TCP_MAX_RETRANSMITS) {
          /* Give up — abort connection */
          NET_LOG("tcp: max retransmits reached, aborting");
          tcp_send_rst_conn(net, conn);
          if (conn->on_event)
            conn->on_event(conn, TCP_EVT_ERROR);
          continue;
        }

        /* REQ-TCP-096: double RTO (exponential backoff) */
        conn->rto_ms *= 2u;
        if (conn->rto_ms > NET_DEFAULT_TCP_RTO_MAX_MS)
          conn->rto_ms = NET_DEFAULT_TCP_RTO_MAX_MS;

        NET_LOG("tcp: retransmit (count=%u, rto=%lums)", conn->retransmit_count,
                (unsigned long)conn->rto_ms);

        /* Mark buffer for retransmit and re-send */
        if (conn->txbuf_ops->in_flight(conn->txbuf_ctx) > 0)
          conn->txbuf_ops->mark_retransmit(conn->txbuf_ctx);

        if (conn->state == TCP_SYN_SENT) {
          /* Retransmit SYN */
          uint16_t wnd =
              (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
          tcp_send_segment(net, conn, TCP_FLAG_SYN, conn->iss, 0, NULL, 0, 1,
                           wnd);
        } else if (conn->state == TCP_SYN_RECEIVED) {
          /* Retransmit SYN-ACK */
          uint16_t wnd =
              (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
          tcp_send_segment(net, conn, TCP_FLAG_SYN | TCP_FLAG_ACK, conn->iss,
                           conn->rcv_nxt, NULL, 0, 1, wnd);
        } else if (conn->state == TCP_FIN_WAIT_1 ||
                   conn->state == TCP_LAST_ACK) {
          /* Retransmit FIN */
          uint16_t wnd =
              (uint16_t)(conn->rcv_wnd > 0xFFFFu ? 0xFFFFu : conn->rcv_wnd);
          tcp_send_segment(net, conn, TCP_FLAG_FIN | TCP_FLAG_ACK,
                           conn->snd_nxt - 1u, conn->rcv_nxt, NULL, 0, 0, wnd);
        } else {
          /* Retransmit data */
          tcp_do_flush(net, conn);
        }

        /* Restart timer with doubled RTO */
        conn->rto_remaining_ms = conn->rto_ms;
      } else {
        rto_stop(conn);
      }
    } else {
      conn->rto_remaining_ms -= elapsed_ms;
    }
  }
}
