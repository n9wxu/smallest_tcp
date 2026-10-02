/**
 * @file tcp.c
 * @brief TCP (RFC 9293).  REQ-TCP-001..182; design in docs/design/tcp.md.
 *
 * Section numbers refer to RFC 9293.
 */

#include "tcp.h"
#include "eth.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <stddef.h>
#include <string.h>

#if NET_USE_IPV4
#include "icmp.h"
#include "ipv4.h"
#endif
#if NET_USE_IPV6
#include "ipv6.h"
#endif

/* Sequence-number order, modulo 2^32 (REQ-TCP-026, 027) */
#define SEQ_LT(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define SEQ_LE(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define SEQ_GT(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)
#define SEQ_GE(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)

#define TCP_MSS_OPTION_LEN 4
#define TCP_DEFAULT_MSS_IPV4 536u  /* §3.7.1 */
#define TCP_DEFAULT_MSS_IPV6 1220u /* 1280 - 40 - 20 */
#define TCP_MAX_RETRANSMITS 8u     /* R2 by default */
#define TCP_R1 3u /* retransmissions reported (RFC 1122 4.2.3.5) */
#define TCP_RTO_AFTER_SYN_TIMEOUT_MS 3000u /* RFC 6298 5.7 */
#define TCP_TIME_WAIT_MS (2u * NET_DEFAULT_TCP_MSL_MS)

/* ── Endpoints: the other end of a segment, over IPv4 or IPv6 ── */

typedef struct {
  const uint8_t *mac; /* its MAC */
#if NET_USE_IPV4
  uint32_t ip4;       /* IPv4 peer, host byte order */
  uint32_t local_ip4; /* our IPv4 address it uses */
  uint8_t tos;
#endif
#if NET_USE_IPV6
  const uint8_t *ip6;    /* IPv6 peer; NULL for IPv4 in a dual stack */
  const uint8_t *local6; /* our IPv6 address it uses */
#endif
} tcp_ep_t;

/*
 * @p v4 or @p v6, for @p ep's address family.  A single-stack build keeps
 * only its own family's expression: the other's names need not exist.
 */
#if NET_USE_IPV4 && NET_USE_IPV6
#define BY_FAMILY(ep, v4, v6) ((ep)->ip6 ? (v6) : (v4))
#elif NET_USE_IPV6
#define BY_FAMILY(ep, v4, v6) ((void)(ep), (v6))
#else
#define BY_FAMILY(ep, v4, v6) ((void)(ep), (v4))
#endif

static int conn_is_ipv6(const tcp_conn_t *conn) {
#if NET_USE_IPV6
  return conn->ip_ver == 6;
#else
  (void)conn;
  return 0;
#endif
}

static void conn_endpoint(const net_t *net, const tcp_conn_t *conn,
                          tcp_ep_t *ep) {
  ep->mac = conn->remote_mac;
#if NET_USE_IPV4
  ep->ip4 = conn->remote_ip;
  ep->local_ip4 = conn->local_ip;
  ep->tos = conn->tos;
#endif
#if NET_USE_IPV6
  ep->ip6 = conn_is_ipv6(conn) ? conn->remote_ip6 : NULL;
  ep->local6 = net->ip6.addr[conn->local_slot].addr;
#else
  (void)net;
#endif
}

static uint16_t ip_header_size(const tcp_ep_t *ep) {
  return BY_FAMILY(ep, IPV4_HDR_SIZE, IPV6_HDR_SIZE);
}

static uint16_t default_mss(const tcp_ep_t *ep) {
  return BY_FAMILY(ep, TCP_DEFAULT_MSS_IPV4, TCP_DEFAULT_MSS_IPV6);
}

/* REQ-TCP-077, REQ-IPv4-063: the largest segment a frame buffer of
 * @p capacity holds, to or from @p ep, within the link's MTU */
static uint16_t segment_room(const net_t *net, uint16_t capacity,
                             const tcp_ep_t *ep) {
  uint16_t headers = ETH_HDR_SIZE + ip_header_size(ep) + TCP_HDR_SIZE;
  capacity = eth_frame_room(net, capacity);
  return capacity > headers ? (uint16_t)(capacity - headers) : 0u;
}

static uint16_t receive_mss(const net_t *net, const tcp_ep_t *ep) {
  return segment_room(net, net->rx.capacity, ep);
}

/* @p mss, but no more than our TX frame buffer and the MTU carry */
static uint16_t send_mss(const net_t *net, const tcp_ep_t *ep, uint16_t mss) {
  uint16_t room = segment_room(net, net->tx.capacity, ep);
  return mss < room ? mss : room;
}

/* The checksum of a segment we send to @p peer, or (@p from_peer) one it
 * sent us */
static uint16_t checksum(const tcp_ep_t *peer, int from_peer,
                         const uint8_t *seg, uint16_t len) {
  return from_peer ? BY_FAMILY(peer,
                               ipv4_cksum(peer->ip4, peer->local_ip4,
                                          IPV4_PROTO_TCP, seg, len),
                               ipv6_cksum(peer->ip6, peer->local6, IPV6_NH_TCP,
                                          seg, len))
                   : BY_FAMILY(peer,
                               ipv4_cksum(peer->local_ip4, peer->ip4,
                                          IPV4_PROTO_TCP, seg, len),
                               ipv6_cksum(peer->local6, peer->ip6, IPV6_NH_TCP,
                                          seg, len));
}

/* ── Sending ── */

/* Where the TCP header goes in a frame to @p ep, or NULL if too big */
static uint8_t *frame_start(net_t *net, const tcp_ep_t *ep, uint16_t tcp_len) {
  uint16_t ip_len = ip_header_size(ep);
  if ((uint32_t)ETH_HDR_SIZE + ip_len + tcp_len > net->tx.capacity)
    return NULL;
  eth_build(net->tx.buf, net->tx.capacity, ep->mac, net->mac,
            BY_FAMILY(ep, NET_ETHERTYPE_IPV4, NET_ETHERTYPE_IPV6));
  return net->tx.buf + ETH_HDR_SIZE + ip_len;
}

/* Checksum the finished segment, add the IP header, send (REQ-TCP-139) */
static void frame_send(net_t *net, const tcp_ep_t *ep, uint8_t *tcp_hdr,
                       uint16_t tcp_len) {
  uint8_t *ip_hdr = net->tx.buf + ETH_HDR_SIZE;
  net_write16be(tcp_hdr + TCP_OFF_CKSUM, 0);
  net_write16be(tcp_hdr + TCP_OFF_CKSUM, checksum(ep, 0, tcp_hdr, tcp_len));
  BY_FAMILY(ep,
            ipv4_build_tos(ip_hdr, tcp_len, IPV4_PROTO_TCP, ep->local_ip4,
                           ep->ip4, NET_DEFAULT_TTL, ep->tos),
            ipv6_build(ip_hdr, tcp_len, IPV6_NH_TCP, ep->local6, ep->ip6,
                       net->ip6.hop_limit));
  net_transmit(net, (uint16_t)(ETH_HDR_SIZE + ip_header_size(ep) + tcp_len));
}

static void write_header(uint8_t *hdr, uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack, uint8_t flags,
                         uint16_t hdr_len, uint16_t window) {
  net_write16be(hdr + TCP_OFF_SPORT, src_port);
  net_write16be(hdr + TCP_OFF_DPORT, dst_port);
  net_write32be(hdr + TCP_OFF_SEQ, seq);
  net_write32be(hdr + TCP_OFF_ACK, ack);
  hdr[TCP_OFF_DOFF] = (uint8_t)((hdr_len / 4u) << 4);
  hdr[TCP_OFF_FLAGS] = flags;
  net_write16be(hdr + TCP_OFF_WINDOW, window);
  net_write16be(hdr + TCP_OFF_URG, 0);
}

/* REQ-TCP-171: the host still has the connection's local address */
static int address_kept(const net_t *net, const tcp_conn_t *conn) {
#if NET_USE_IPV4
  return conn_is_ipv6(conn) || conn->local_ip == net->ipv4_addr;
#else
  (void)net;
  (void)conn;
  return 1;
#endif
}

/*
 * A segment on @p conn acknowledging RCV.NXT and advertising our window
 * (none on a RST).  A SYN carries our MSS (REQ-TCP-076).  One the driver
 * does not take is lost, as on the wire (docs/design/tcp.md §4.1).  None
 * goes from an address the host no longer has.
 */
static void send_segment(net_t *net, tcp_conn_t *conn, uint8_t flags,
                         uint32_t seq, const uint8_t *data, uint16_t data_len) {
  uint16_t hdr_len =
      TCP_HDR_SIZE + ((flags & TCP_FLAG_SYN) ? TCP_MSS_OPTION_LEN : 0);
  uint16_t tcp_len = (uint16_t)(hdr_len + data_len);
  uint8_t *hdr;
  tcp_ep_t ep;

  if (!address_kept(net, conn))
    return;
  conn_endpoint(net, conn, &ep);
  if (!(hdr = frame_start(net, &ep, tcp_len)))
    return;
  write_header(hdr, conn->local_port, conn->remote_port, seq, conn->rcv_nxt,
               flags, hdr_len, (flags & TCP_FLAG_RST) ? 0 : conn->rcv_wnd);
  if (flags & TCP_FLAG_SYN) {
    hdr[TCP_OFF_OPT] = TCP_OPT_MSS;
    hdr[TCP_OFF_OPT + 1] = TCP_MSS_OPTION_LEN;
    net_write16be(hdr + TCP_OFF_OPT + 2, conn->our_mss);
  }
  if (data_len > 0)
    memcpy(hdr + hdr_len, data, data_len);
  frame_send(net, &ep, hdr, tcp_len);
}

static void send_ack(net_t *net, tcp_conn_t *conn) {
  send_segment(net, conn, TCP_FLAG_ACK, conn->snd_nxt, NULL, 0);
}

/* Our SYN (SYN-SENT) or SYN,ACK (SYN-RECEIVED) */
static void send_syn(net_t *net, tcp_conn_t *conn) {
  uint8_t flags =
      conn->state == TCP_SYN_SENT ? TCP_FLAG_SYN : TCP_FLAG_SYN | TCP_FLAG_ACK;
  send_segment(net, conn, flags, conn->iss, NULL, 0);
}

/* Our FIN, which occupies the sequence number @p seq */
static void send_fin(net_t *net, tcp_conn_t *conn, uint32_t seq) {
  send_segment(net, conn, TCP_FLAG_FIN | TCP_FLAG_ACK, seq, NULL, 0);
}

/* ── Timers ── */

static void timer_start(tcp_conn_t *conn, uint8_t timer, uint32_t ms) {
  conn->timer = timer;
  conn->timer_ms = ms;
}

static int timer_running(const tcp_conn_t *conn, uint8_t timer) {
  return conn->timer_ms != 0 && conn->timer == timer;
}

/* Starting the retransmission timer replaces a zero-window probe */
static void retransmit_timer_start(tcp_conn_t *conn) {
  timer_start(conn, TCP_TIMER_RETRANSMIT, conn->rto_ms);
}

/* RFC 6298 §5.1: started by a segment sent while it is not running */
static void retransmit_timer_run(tcp_conn_t *conn) {
  if (!timer_running(conn, TCP_TIMER_RETRANSMIT))
    retransmit_timer_start(conn);
}

static void retransmit_timer_restart_if_running(tcp_conn_t *conn) {
  if (timer_running(conn, TCP_TIMER_RETRANSMIT))
    conn->timer_ms = conn->rto_ms;
}

static void retransmit_timer_stop(tcp_conn_t *conn) {
  if (conn->timer == TCP_TIMER_RETRANSMIT)
    conn->timer_ms = 0;
  conn->retransmits = 0;
}

/* REQ-TCP-085..087 */
static void persist_start(tcp_conn_t *conn) {
  conn->persist_ms = NET_DEFAULT_TCP_RTO_INIT_MS;
  timer_start(conn, TCP_TIMER_PERSIST, conn->persist_ms);
}

static void persist_stop(tcp_conn_t *conn) {
  if (conn->timer == TCP_TIMER_PERSIST)
    conn->timer_ms = 0;
  conn->persist_ms = 0;
}

static uint32_t doubled_up_to_rto_max(uint32_t ms) {
  ms *= 2u;
  return ms > NET_DEFAULT_TCP_RTO_MAX_MS ? NET_DEFAULT_TCP_RTO_MAX_MS : ms;
}

/* ── State changes ── */

static void notify(tcp_conn_t *conn, uint8_t events) {
  if (conn->on_event)
    conn->on_event(conn, events);
}

/* To CLOSED, telling the application @p events (0: nothing) */
static void close_with(tcp_conn_t *conn, uint8_t events) {
  conn->state = TCP_CLOSED;
  conn->timer_ms = 0;
  conn->retransmits = 0;
  conn->persist_ms = 0;
  if (events)
    notify(conn, events);
}

/* REQ-TCP-008 */
static void enter_time_wait(tcp_conn_t *conn) {
  conn->state = TCP_TIME_WAIT;
  conn->retransmits = 0;
  timer_start(conn, TCP_TIMER_TIME_WAIT, TCP_TIME_WAIT_MS);
}

/* REQ-TCP-016: RST on the connection, then CLOSED */
static void reset_connection(net_t *net, tcp_conn_t *conn) {
  if (conn->mac_valid)
    send_segment(net, conn, TCP_FLAG_RST | TCP_FLAG_ACK, conn->snd_nxt, NULL,
                 0);
  close_with(conn, 0);
}

/* The states in which the peer holds the connection open and the
 * application has not closed it: a RST received is reported, and ABORT
 * sends one (§3.10.5, §3.10.7.4 step 2) */
static int peer_has_it_open(const tcp_conn_t *conn) {
  return conn->state == TCP_SYN_RECEIVED || conn->state == TCP_ESTABLISHED ||
         conn->state == TCP_FIN_WAIT_1 || conn->state == TCP_FIN_WAIT_2 ||
         conn->state == TCP_CLOSE_WAIT;
}

/* A connection opened by tcp_listen() and still in SYN-RECEIVED */
static int passive_opening(const tcp_conn_t *conn) {
  return conn->state == TCP_SYN_RECEIVED && conn->passive;
}

static void listen_on(tcp_conn_t *conn, uint16_t local_port) {
  close_with(conn, 0); /* no timer, nothing retransmitted */
  conn->state = TCP_LISTEN;
  conn->passive = 1;
  conn->close_queued = 0;
  conn->local_port = local_port;
#if NET_USE_IPV4
  conn->remote_ip = 0;
#endif
  conn->remote_port = 0;
  conn->mac_valid = 0; /* no RST to the last peer from here */
}

/* REQ-TCP-046: a passive open that fails listens again, the application
 * none the wiser — unless it has closed it meanwhile */
static void listen_again(tcp_conn_t *conn) {
  if (conn->close_queued)
    close_with(conn, 0);
  else
    listen_on(conn, conn->local_port);
}

/* REQ-TCP-137: a hard error ends the connection — a passive open listens
 * again */
static void abort_on_error(tcp_conn_t *conn) {
  if (passive_opening(conn))
    listen_again(conn);
  else
    close_with(conn, TCP_EVT_ERROR);
}

/* REQ-TCP-173: a soft error, reported (RFC 1122 §4.2.4.1) */
static void soft_error(tcp_conn_t *conn, uint16_t error) {
  conn->last_error = error;
  notify(conn, TCP_EVT_SOFT_ERROR);
}

/* ── Output ── */

static int all_data_sent(const tcp_conn_t *conn) {
  return conn->txbuf_ops->queued(conn->txbuf_ctx) ==
         conn->txbuf_ops->in_flight(conn->txbuf_ctx);
}

/* Closing, with our FIN still behind queued data (§3.10.4) */
static int fin_queued(const tcp_conn_t *conn) {
  return !conn->fin_sent &&
         (conn->state == TCP_FIN_WAIT_1 || conn->state == TCP_CLOSING ||
          conn->state == TCP_LAST_ACK);
}

/* PSH on the segment that leaves nothing unsent (REQ-TCP-180) */
static uint8_t data_flags(const tcp_conn_t *conn) {
  return all_data_sent(conn) ? TCP_FLAG_ACK | TCP_FLAG_PSH : TCP_FLAG_ACK;
}

/* REQ-TCP-084, 085: one segment of unsent data, as the peer's window
 * allows; a zero window starts the persist timer instead.  A frame the
 * driver did not take is a lost segment, which the retransmission timer
 * recovers. */
static void send_data(net_t *net, tcp_conn_t *conn) {
  uint16_t room =
      conn->snd_wnd < conn->snd_mss ? (uint16_t)conn->snd_wnd : conn->snd_mss;
  const uint8_t *data = NULL;
  uint16_t len;

  if (room == 0) {
    if (!all_data_sent(conn) && !conn->timer_ms)
      persist_start(conn);
    return;
  }
  persist_stop(conn);
  len = conn->txbuf_ops->next_segment(conn->txbuf_ctx, &data, room);
  if (len > 0) {
    send_segment(net, conn, data_flags(conn), conn->snd_nxt, data, len);
    conn->snd_nxt += len;
  }
  if (SEQ_LT(conn->snd_una, conn->snd_nxt))
    retransmit_timer_run(conn);
}

static void send_queued_fin(net_t *net, tcp_conn_t *conn) {
  send_fin(net, conn, conn->snd_nxt);
  conn->snd_nxt++;
  conn->fin_sent = 1;
  retransmit_timer_run(conn);
}

/* Data, then a queued FIN once all the data has been sent.  A connection
 * whose local address the host no longer has is aborted (REQ-TCP-171). */
static void flush(net_t *net, tcp_conn_t *conn) {
  if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT &&
      !fin_queued(conn))
    return;
  if (!address_kept(net, conn)) {
    close_with(conn, TCP_EVT_ERROR);
    return;
  }
  send_data(net, conn);
  if (fin_queued(conn) && all_data_sent(conn))
    send_queued_fin(net, conn);
}

/* ── Input ── */

/** A received segment, parsed */
typedef struct {
  uint16_t src_port, dst_port;
  uint32_t seq, ack;
  uint8_t flags;
  uint16_t window;
  const uint8_t *options;
  uint16_t options_len;
  const uint8_t *data;
  uint16_t data_len;
  uint32_t len; /* SEG.LEN: data + SYN + FIN */
} tcp_seg_t;

static int has(const tcp_seg_t *s, uint8_t flag) {
  return (s->flags & flag) != 0;
}

/* REQ-TCP-018, 019, 021, 022 */
static int parse_segment(const tcp_ep_t *from, const uint8_t *seg, uint16_t len,
                         tcp_seg_t *s) {
  uint16_t hdr_len;
  if (len < TCP_HDR_SIZE)
    return 0;
  hdr_len = (uint16_t)((seg[TCP_OFF_DOFF] >> 4) * 4u);
  if (hdr_len < TCP_HDR_SIZE || hdr_len > len ||
      checksum(from, 1, seg, len) != 0)
    return 0;
  s->src_port = net_read16be(seg + TCP_OFF_SPORT);
  s->dst_port = net_read16be(seg + TCP_OFF_DPORT);
  s->seq = net_read32be(seg + TCP_OFF_SEQ);
  s->ack = net_read32be(seg + TCP_OFF_ACK);
  s->flags = seg[TCP_OFF_FLAGS];
  s->window = net_read16be(seg + TCP_OFF_WINDOW);
  s->options = seg + TCP_HDR_SIZE;
  s->options_len = (uint16_t)(hdr_len - TCP_HDR_SIZE);
  s->data = seg + hdr_len;
  s->data_len = (uint16_t)(len - hdr_len);
  s->len = s->data_len + (has(s, TCP_FLAG_SYN) ? 1u : 0u) +
           (has(s, TCP_FLAG_FIN) ? 1u : 0u);
  return 1;
}

/* REQ-TCP-078, 079, 109..115: the peer's MSS option, else the default */
static uint16_t peer_mss(const tcp_seg_t *s, uint16_t default_mss) {
  const uint8_t *opt = s->options;
  uint16_t i = 0, mss = default_mss;
  while (i < s->options_len && opt[i] != TCP_OPT_EOL) {
    uint8_t len;
    if (opt[i] == TCP_OPT_NOP) {
      i++;
      continue;
    }
    if (i + 1 >= s->options_len)
      break;
    len = opt[i + 1];
    if (len < 2 || i + len > s->options_len)
      break;
    if (opt[i] == TCP_OPT_MSS && len == TCP_MSS_OPTION_LEN &&
        net_read16be(opt + i + 2) != 0)
      mss = net_read16be(opt + i + 2);
    i = (uint16_t)(i + len);
  }
  return mss;
}

static void take_peer_mss(const net_t *net, tcp_conn_t *conn,
                          const tcp_ep_t *from, const tcp_seg_t *s) {
  conn->snd_mss = send_mss(net, from, peer_mss(s, default_mss(from)));
}

/* REQ-TCP-072..075: a RST answering @p s, from nowhere we have a
 * connection (never to a RST) */
static void send_reset_reply(net_t *net, const tcp_ep_t *to,
                             const tcp_seg_t *s) {
  uint8_t *hdr;
  if (has(s, TCP_FLAG_RST) || !(hdr = frame_start(net, to, TCP_HDR_SIZE)))
    return;
  if (has(s, TCP_FLAG_ACK))
    write_header(hdr, s->dst_port, s->src_port, s->ack, 0, TCP_FLAG_RST,
                 TCP_HDR_SIZE, 0);
  else
    write_header(hdr, s->dst_port, s->src_port, 0, s->seq + s->len,
                 TCP_FLAG_RST | TCP_FLAG_ACK, TCP_HDR_SIZE, 0);
  frame_send(net, to, hdr, TCP_HDR_SIZE);
}

/* The segment's addresses are the connection's: the peer's, and ours it
 * was sent to */
static int is_peer(const net_t *net, const tcp_conn_t *c,
                   const tcp_ep_t *from) {
  if (conn_is_ipv6(c) != BY_FAMILY(from, 0, 1))
    return 0; /* the other family */
#if !NET_USE_IPV6
  (void)net;
#endif
  return BY_FAMILY(
      from, c->remote_ip == from->ip4 && c->local_ip == from->local_ip4,
      memcmp(c->remote_ip6, from->ip6, 16) == 0 &&
          memcmp(net->ip6.addr[c->local_slot].addr, from->local6, 16) == 0);
}

/* REQ-TCP-023, 148, 149: the connection — both addresses and both ports —
 * else a listener on the port */
static tcp_conn_t *find_conn(const net_t *net, const tcp_ep_t *from,
                             const tcp_seg_t *s) {
  tcp_conn_t *listener = NULL;
  uint8_t i;
  for (i = 0; i < net->tcp_conn_count; i++) {
    tcp_conn_t *c = net->tcp_conns[i];
    if (!c || c->local_port != s->dst_port)
      continue;
    if (c->state == TCP_LISTEN) {
      if (!listener)
        listener = c;
    } else if (c->state != TCP_CLOSED && c->remote_port == s->src_port &&
               is_peer(net, c, from)) {
      return c;
    }
  }
  return listener;
}

static void remember_peer(net_t *net, tcp_conn_t *conn, const tcp_ep_t *from,
                          uint16_t port) {
  conn->remote_port = port;
  memcpy(conn->remote_mac, from->mac, 6);
  conn->mac_valid = 1;
#if NET_USE_IPV4
  conn->remote_ip = from->ip4;      /* 0 from an IPv6 peer */
  conn->local_ip = from->local_ip4; /* REQ-TCP-171 */
#endif
#if NET_USE_IPV6
  conn->ip_ver = BY_FAMILY(from, 4, 6);
  if (conn_is_ipv6(conn)) {
    memcpy(conn->remote_ip6, from->ip6, 16);
    conn->local_slot = (uint8_t)ipv6_addr_slot(net, from->local6);
  }
#else
  (void)net;
#endif
}

/* The peer's SYN: its sequence space and window */
static void take_peer_syn(tcp_conn_t *conn, const tcp_seg_t *s) {
  conn->irs = s->seq;
  conn->rcv_nxt = s->seq + 1u;
  conn->snd_wnd = s->window;
  conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
}

/* RFC 6528, REQ-TCP-028: a 4 µs clock plus a keyed hash of the addresses
 * and ports, so a connection's successor starts beyond it and no one
 * without the secret can guess where */
static uint32_t initial_sequence_number(const net_t *net,
                                        const tcp_conn_t *conn) {
  uint8_t id[16 + 16 + 2 + 2];
  uint16_t n = 0;
  tcp_ep_t ep;
  conn_endpoint(net, conn, &ep);
#if NET_USE_IPV6
  if (conn_is_ipv6(conn)) {
    memcpy(id, ep.local6, 16);
    memcpy(id + 16, ep.ip6, 16);
    n = 32;
  }
#endif
#if NET_USE_IPV4
  if (!conn_is_ipv6(conn)) {
    net_write32be(id, ep.local_ip4);
    net_write32be(id + 4, ep.ip4);
    n = 8;
  }
#endif
  net_write16be(id + n, conn->local_port);
  net_write16be(id + n + 2, conn->remote_port);
  return net->tcp_clock + net_hash(net, id, (uint16_t)(n + 4u));
}

/* Our side of a new connection, the peer's address and ports known */
static void start_send_sequence(net_t *net, tcp_conn_t *conn) {
  tcp_ep_t ep;
  conn_endpoint(net, conn, &ep);
  conn->our_mss = receive_mss(net, &ep);
  conn->iss = initial_sequence_number(net, conn);
  conn->snd_una = conn->iss;
  conn->snd_nxt = conn->iss + 1u;
  conn->fin_sent = 0;
  conn->close_queued = 0;
  conn->rto_ms = NET_DEFAULT_TCP_RTO_INIT_MS;
  conn->last_error = 0;
}

/* REQ-TCP-181 (RFC 6298 5.7): the handshake is done; if a SYN timed out
 * with an RTO under 3 s, data starts with 3 s */
static void handshake_done(tcp_conn_t *conn) {
  if (conn->retransmits > 0 &&
      NET_DEFAULT_TCP_RTO_INIT_MS < TCP_RTO_AFTER_SYN_TIMEOUT_MS)
    conn->rto_ms = TCP_RTO_AFTER_SYN_TIMEOUT_MS;
  retransmit_timer_stop(conn);
}

/* §3.10.7.2, REQ-TCP-030..035: a SYN opens the connection */
static void listen_input(net_t *net, tcp_conn_t *conn, const tcp_ep_t *from,
                         const tcp_seg_t *s) {
  if (has(s, TCP_FLAG_RST))
    return;
  if (has(s, TCP_FLAG_ACK)) {
    send_reset_reply(net, from, s);
    return;
  }
  if (!has(s, TCP_FLAG_SYN))
    return;
  remember_peer(net, conn, from, s->src_port);
  start_send_sequence(net, conn);
  take_peer_mss(net, conn, from, s);
  take_peer_syn(conn, s);
  conn->snd_wl1 = s->seq;
  conn->snd_wl2 = s->ack;
  conn->state = TCP_SYN_RECEIVED;
  send_syn(net, conn);
  retransmit_timer_start(conn);
}

static int acks_our_syn(const tcp_conn_t *conn, const tcp_seg_t *s) {
  return has(s, TCP_FLAG_ACK) && SEQ_GT(s->ack, conn->snd_una) &&
         SEQ_LE(s->ack, conn->snd_nxt);
}

/* §3.10.7.3, REQ-TCP-036..040 */
static void syn_sent_input(net_t *net, tcp_conn_t *conn, const tcp_ep_t *from,
                           const tcp_seg_t *s) {
  int ack_ok = acks_our_syn(conn, s);
  if (has(s, TCP_FLAG_ACK) && !ack_ok) {
    send_reset_reply(net, from, s);
    return;
  }
  if (has(s, TCP_FLAG_RST)) {
    if (ack_ok)
      close_with(conn, TCP_EVT_RESET);
    return;
  }
  if (!has(s, TCP_FLAG_SYN))
    return;
  take_peer_mss(net, conn, from, s);
  take_peer_syn(conn, s);
  if (ack_ok) {
    conn->snd_una = s->ack;
    conn->snd_wl1 = s->seq;
    conn->snd_wl2 = s->ack;
    conn->state = TCP_ESTABLISHED;
    handshake_done(conn);
    send_ack(net, conn);
    notify(conn, TCP_EVT_CONNECTED);
    flush(net, conn);
  } else { /* simultaneous open */
    conn->state = TCP_SYN_RECEIVED;
    send_syn(net, conn);
    retransmit_timer_start(conn);
  }
}

/* §3.10.7.4 step 1, REQ-TCP-041..045: the segment is in the window.  With
 * the window zero, only an empty segment at RCV.NXT is — or a RST there,
 * data or not (REQ-TCP-160, MUST-66) */
static int in_window(const tcp_conn_t *conn, const tcp_seg_t *s) {
  uint32_t nxt = conn->rcv_nxt, wnd = conn->rcv_wnd;
  uint32_t last = s->seq + s->len - 1u;
  if (wnd == 0)
    return s->seq == nxt && (s->len == 0 || has(s, TCP_FLAG_RST));
  if (s->len == 0)
    return SEQ_GE(s->seq, nxt) && SEQ_LT(s->seq, nxt + wnd);
  return (SEQ_GE(s->seq, nxt) && SEQ_LT(s->seq, nxt + wnd)) ||
         (SEQ_GE(last, nxt) && SEQ_LT(last, nxt + wnd));
}

/* Step 2, REQ-TCP-046..049 (the RST is in the window) */
static void rst_input(tcp_conn_t *conn) {
  if (passive_opening(conn))
    listen_again(conn);
  else
    close_with(conn, peer_has_it_open(conn) ? TCP_EVT_RESET : 0);
}

/* REQ-TCP-058: a newer segment, or a newer ACK of the same one */
static void update_send_window(tcp_conn_t *conn, const tcp_seg_t *s) {
  if (SEQ_LT(conn->snd_wl1, s->seq) ||
      (conn->snd_wl1 == s->seq && SEQ_LE(conn->snd_wl2, s->ack))) {
    conn->snd_wnd = s->window;
    conn->snd_wl1 = s->seq;
    conn->snd_wl2 = s->ack;
  }
}

/* REQ-TCP-055, 097, 098: SND.UNA advances; the retransmission timer runs
 * while anything — data or our FIN — is unacknowledged.  Retransmissions
 * are counted per segment (§3.8.3), so the next one starts from none. */
static void take_ack(tcp_conn_t *conn, const tcp_seg_t *s) {
  conn->txbuf_ops->ack(conn->txbuf_ctx, s->ack - conn->snd_una);
  conn->snd_una = s->ack;
  conn->retransmits = 0;
  if (SEQ_LT(conn->snd_una, conn->snd_nxt))
    retransmit_timer_restart_if_running(conn);
  else
    retransmit_timer_stop(conn);
}

/* REQ-TCP-055..058: SND.UNA <= SEG.ACK <= SND.NXT.  New data acknowledged
 * or a window update, even of an ACK of nothing new, can let more go.
 * REQ-TCP-086: while the peer answers with a zero window, what we resend
 * into it is a window probe, and probing never gives up (RFC 1122
 * §4.2.2.17). */
static void send_side_ack(net_t *net, tcp_conn_t *conn, const tcp_seg_t *s) {
  int acked_new = SEQ_GT(s->ack, conn->snd_una);
  if (acked_new)
    take_ack(conn, s);
  update_send_window(conn, s);
  if (conn->snd_wnd == 0)
    conn->retransmits = 0;
  flush(net, conn);
  if (acked_new && conn->txbuf_ops->writable(conn->txbuf_ctx) > 0)
    notify(conn, TCP_EVT_WRITABLE);
}

/* Step 5, REQ-TCP-053..062.  Returns 0 if the segment is done with. */
static int ack_input(net_t *net, tcp_conn_t *conn, const tcp_ep_t *from,
                     const tcp_seg_t *s) {
  int fin_acked;
  if (!has(s, TCP_FLAG_ACK))
    return 0;
  if (conn->state == TCP_SYN_RECEIVED) {
    if (!acks_our_syn(conn, s)) {
      send_reset_reply(net, from, s);
      return 0;
    }
    conn->snd_una = s->ack;
    conn->snd_wnd = s->window;
    conn->snd_wl1 = s->seq;
    conn->snd_wl2 = s->ack;
    handshake_done(conn);
    if (conn->close_queued) { /* closed already: our FIN now */
      conn->state = TCP_FIN_WAIT_1;
      flush(net, conn);
    } else {
      conn->state = TCP_ESTABLISHED;
      notify(conn, TCP_EVT_CONNECTED);
    }
    return 1;
  }
  if (conn->state == TCP_TIME_WAIT) { /* REQ-TCP-008: in the window */
    conn->timer_ms = TCP_TIME_WAIT_MS;
    send_ack(net, conn);
    return 0;
  }
  if (SEQ_GT(s->ack, conn->snd_nxt)) { /* REQ-TCP-056: not sent yet */
    send_ack(net, conn);
    return 0;
  }
  if (SEQ_GE(s->ack, conn->snd_una)) /* REQ-TCP-057: else a duplicate */
    send_side_ack(net, conn, s);

  fin_acked = conn->fin_sent && SEQ_GE(s->ack, conn->snd_nxt);
  switch (conn->state) {
  case TCP_FIN_WAIT_1:
    if (fin_acked)
      conn->state = TCP_FIN_WAIT_2;
    break;
  case TCP_CLOSING:
    if (fin_acked)
      enter_time_wait(conn);
    break;
  case TCP_LAST_ACK:
    if (fin_acked) {
      close_with(conn, TCP_EVT_CLOSED);
      return 0;
    }
    break;
  default:
    break;
  }
  return 1;
}

static int can_receive(const tcp_conn_t *conn) {
  return conn->state == TCP_ESTABLISHED || conn->state == TCP_FIN_WAIT_1 ||
         conn->state == TCP_FIN_WAIT_2;
}

/* Step 7, REQ-TCP-064..067: in-order data only — there is no reassembly
 * queue.  Bytes before RCV.NXT (a retransmission with new boundaries)
 * were taken already; a segment after a gap is dropped. */
static void data_input(net_t *net, tcp_conn_t *conn, const tcp_seg_t *s) {
  uint32_t seen = conn->rcv_nxt - s->seq;
  uint16_t new_len = 0, delivered;

  if (s->data_len == 0 || !can_receive(conn))
    return;
  if (!SEQ_GT(s->seq, conn->rcv_nxt) && seen < s->data_len)
    new_len = (uint16_t)(s->data_len - seen);
  if (new_len > conn->rcv_wnd)
    new_len = conn->rcv_wnd;
  if (new_len > 0) {
    delivered =
        conn->rxbuf_ops->deliver(conn->rxbuf_ctx, s->data + seen, new_len);
    conn->rcv_nxt += delivered;
    conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
    if (delivered > 0)
      notify(conn, TCP_EVT_DATA);
  }
  send_ack(net, conn);
}

/* Step 8, REQ-TCP-068..071 */
static void fin_input(net_t *net, tcp_conn_t *conn, const tcp_seg_t *s) {
  if (!has(s, TCP_FLAG_FIN))
    return;
  if (s->seq + s->data_len != conn->rcv_nxt) {
    /* Data before the FIN is missing: ask for RCV.NXT (step 7 did, if
     * the segment had data) */
    if (s->data_len == 0)
      send_ack(net, conn);
    return;
  }
  conn->rcv_nxt++;
  conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
  send_ack(net, conn);
  switch (conn->state) {
  case TCP_ESTABLISHED: /* (SYN-RECEIVED has become it, in step 5) */
    conn->state = TCP_CLOSE_WAIT;
    notify(conn, TCP_EVT_CLOSED);
    break;
  case TCP_FIN_WAIT_1: /* our FIN is not acknowledged yet (step 5) */
    conn->state = TCP_CLOSING;
    break;
  case TCP_FIN_WAIT_2:
    enter_time_wait(conn);
    break;
  default: /* the FIN again: acknowledged, nothing changes */
    break;
  }
}

/* §3.10.7.4: every state from SYN-RECEIVED on */
static void synchronized_input(net_t *net, tcp_conn_t *conn,
                               const tcp_ep_t *from, const tcp_seg_t *s) {
  if (!in_window(conn, s)) {
    if (!has(s, TCP_FLAG_RST)) /* REQ-TCP-042 */
      send_ack(net, conn);
    return;
  }
  if (has(s, TCP_FLAG_RST)) {
    rst_input(conn);
    return;
  }
  if (has(s, TCP_FLAG_SYN)) { /* step 4, REQ-TCP-051 */
    if (passive_opening(conn)) {
      listen_again(conn);
      return;
    }
    reset_connection(net, conn);
    notify(conn, TCP_EVT_ERROR);
    return;
  }
  if (!ack_input(net, conn, from, s))
    return;
  data_input(net, conn, s); /* step 6, URG, is not supported (-063) */
  fin_input(net, conn, s);
}

static void segment_input(net_t *net, const tcp_ep_t *from, const uint8_t *seg,
                          uint16_t len) {
  tcp_conn_t *conn;
  tcp_seg_t s;

  if (!parse_segment(from, seg, len, &s))
    return;
  conn = find_conn(net, from, &s);
  if (!conn) { /* REQ-TCP-072 */
    send_reset_reply(net, from, &s);
    return;
  }
  switch (conn->state) {
  case TCP_LISTEN:
    listen_input(net, conn, from, &s);
    break;
  case TCP_SYN_SENT:
    syn_sent_input(net, conn, from, &s);
    break;
  default:
    synchronized_input(net, conn, from, &s);
    break;
  }
}

#if NET_USE_IPV4
/* REQ-TCP-176, 177: unicast only, and from a host — not 0.0.0.0 */
void tcp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  tcp_ep_t from;
  if (ip->dst_ip != net->ipv4_addr || ip->src_ip == 0)
    return;
  memset(&from, 0, sizeof(from));
  from.ip4 = ip->src_ip;
  from.local_ip4 = ip->dst_ip;
  from.mac = eth->src_mac;
  segment_input(net, &from, ip->payload, ip->payload_len);
}
#endif

#if NET_USE_IPV4
/* The connection a quoted segment of ours belongs to */
static tcp_conn_t *quoted_conn(const net_t *net, const uint8_t *quote,
                               const uint8_t *seg) {
  uint8_t i;
  for (i = 0; i < net->tcp_conn_count; i++) {
    tcp_conn_t *c = net->tcp_conns[i];
    if (c && c->state != TCP_CLOSED && c->state != TCP_LISTEN &&
        !conn_is_ipv6(c) &&
        c->local_port == net_read16be(seg + TCP_OFF_SPORT) &&
        c->remote_port == net_read16be(seg + TCP_OFF_DPORT) &&
        c->local_ip == net_read32be(quote + IPV4_OFF_SRC) &&
        c->remote_ip == net_read32be(quote + IPV4_OFF_DST))
      return c;
  }
  return NULL;
}

/* REQ-TCP-135..137, 173, REQ-ICMPv4-013, 014, 016, 044: an error about a
 * segment in flight (SND.UNA <= SEG.SEQ < SND.NXT, RFC 5927 §4.1).
 * Fragmentation Needed with a next-hop MTU lowers the segment size, and the
 * retransmission timer resends in smaller pieces (RFC 1191); Protocol and
 * Port Unreachable, and Fragmentation Needed without a usable MTU, are
 * hard; the rest is reported */
void tcp_icmp_error(net_t *net, uint8_t type, uint8_t code, uint16_t mtu,
                    const uint8_t *quote, uint16_t quote_len) {
  uint16_t ihl = (uint16_t)((quote[IPV4_OFF_VER_IHL] & 0x0F) * 4);
  const uint8_t *seg = quote + ihl;
  tcp_conn_t *conn;
  uint32_t seq;

  if (quote_len < ihl + 8u || !(conn = quoted_conn(net, quote, seg)))
    return;
  seq = net_read32be(seg + TCP_OFF_SEQ);
  if (SEQ_LT(seq, conn->snd_una) || SEQ_GE(seq, conn->snd_nxt))
    return;
  if (type == ICMP_TYPE_DEST_UNREACH && code == ICMP_CODE_FRAG_NEEDED &&
      mtu >= IPV4_MIN_MTU) {
    uint16_t mss = (uint16_t)(mtu - IPV4_HDR_SIZE - TCP_HDR_SIZE);
    if (mss < conn->snd_mss)
      conn->snd_mss = mss;
    return;
  }
  conn->last_error = (uint16_t)(type << 8 | code);
  if (type == ICMP_TYPE_DEST_UNREACH &&
      (code == ICMP_CODE_PROTO_UNREACH || code == ICMP_CODE_PORT_UNREACH ||
       code == ICMP_CODE_FRAG_NEEDED))
    abort_on_error(conn);
  else
    notify(conn, TCP_EVT_SOFT_ERROR);
}
#endif

#if NET_USE_IPV6
void tcp6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  tcp_ep_t from;
  if (ipv6_is_multicast(ip->dst) || ipv6_is_unspecified(ip->src))
    return; /* REQ-TCP-176, 177 */
  memset(&from, 0, sizeof(from));
  from.mac = eth->src_mac;
  from.ip6 = ip->src;
  from.local6 = ip->dst;
  segment_input(net, &from, ip->payload, ip->payload_len);
}
#endif

/* ── Timers ── */

static int fin_unacked(const tcp_conn_t *conn) {
  return conn->fin_sent && SEQ_LT(conn->snd_una, conn->snd_nxt);
}

/* The data in flight again, from SND.UNA, whatever the window: the peer's
 * window took it once, and a window shrunk since makes it a probe.  SND.NXT
 * stays, past a FIN already sent — unless the segment size has shrunk
 * (RFC 1191): then what does not fit is unsent again, a FIN sent after it
 * too. */
static void resend_in_flight(net_t *net, tcp_conn_t *conn) {
  uint16_t in_flight = conn->txbuf_ops->in_flight(conn->txbuf_ctx);
  const uint8_t *data = NULL;
  uint16_t len;
  conn->txbuf_ops->mark_retransmit(conn->txbuf_ctx);
  len = conn->txbuf_ops->next_segment(
      conn->txbuf_ctx, &data,
      in_flight < conn->snd_mss ? in_flight : conn->snd_mss);
  if (len < in_flight) {
    conn->snd_nxt = conn->snd_una + len;
    conn->fin_sent = 0;
  }
  send_segment(net, conn, data_flags(conn), conn->snd_una, data, len);
}

/* REQ-TCP-090..100, 162..165: the earliest unacknowledged segment again,
 * with the timeout doubled.  The application hears at R1 retransmissions;
 * the connection is given up after R2 — for a SYN, never before
 * TCP_MAX_RETRANSMITS, which the default RTOs stretch past 3 minutes */
static void retransmission_timeout(net_t *net, tcp_conn_t *conn) {
  int data_unacked = conn->txbuf_ops->in_flight(conn->txbuf_ctx) > 0;
  int fin = fin_unacked(conn);
  int syn = conn->state == TCP_SYN_SENT || conn->state == TCP_SYN_RECEIVED;
  uint8_t r2 = conn->r2 ? conn->r2 : TCP_MAX_RETRANSMITS;

  if (!data_unacked && !fin && !syn) {
    retransmit_timer_stop(conn);
    return;
  }
  if (syn && r2 < TCP_MAX_RETRANSMITS)
    r2 = TCP_MAX_RETRANSMITS;
  if (++conn->retransmits > r2) {
    NET_LOG("tcp: retransmissions exhausted, aborting");
    if (passive_opening(conn)) {
      listen_again(conn);
      return;
    }
    reset_connection(net, conn);
    notify(conn, TCP_EVT_ERROR);
    return;
  }
  conn->rto_ms = doubled_up_to_rto_max(conn->rto_ms);
  conn->timer_ms = conn->rto_ms;
  if (conn->retransmits == TCP_R1)
    soft_error(conn, TCP_SOFT_RETRANSMITTING);

  if (syn) {
    send_syn(net, conn);
  } else if (data_unacked) {
    resend_in_flight(net, conn); /* a FIN follows once it is acknowledged */
  } else {
    send_fin(net, conn, conn->snd_nxt - 1u);
  }
}

/* REQ-TCP-086, 087: one byte past the peer's zero window, the same byte
 * until it is acknowledged, at doubling intervals */
static void probe_zero_window(net_t *net, tcp_conn_t *conn) {
  const uint8_t *byte = NULL;
  if (conn->txbuf_ops->in_flight(conn->txbuf_ctx) > 0) {
    conn->snd_nxt = conn->snd_una;
    conn->txbuf_ops->mark_retransmit(conn->txbuf_ctx);
  }
  if (conn->txbuf_ops->next_segment(conn->txbuf_ctx, &byte, 1) == 0) {
    persist_stop(conn); /* nothing left to send */
    return;
  }
  send_segment(net, conn, TCP_FLAG_ACK, conn->snd_nxt, byte, 1);
  conn->snd_nxt += 1u;
  conn->persist_ms = doubled_up_to_rto_max(conn->persist_ms);
  timer_start(conn, TCP_TIMER_PERSIST, conn->persist_ms);
}

/* REQ-TCP-171, 180: a connection whose address went is aborted; data
 * written but not sent goes (never buffered indefinitely); then the timer */
static void conn_tick(net_t *net, tcp_conn_t *conn, uint32_t elapsed_ms) {
  if (conn->state == TCP_CLOSED || conn->state == TCP_LISTEN)
    return;
  if (!address_kept(net, conn)) {
    abort_on_error(conn);
    return;
  }
  if (!all_data_sent(conn))
    flush(net, conn);
  if (!conn->timer_ms || !net_countdown(&conn->timer_ms, elapsed_ms))
    return;
  switch (conn->timer) {
  case TCP_TIMER_RETRANSMIT:
    retransmission_timeout(net, conn);
    break;
  case TCP_TIMER_PERSIST:
    probe_zero_window(net, conn);
    break;
  default: /* TCP_TIMER_TIME_WAIT */
    close_with(conn, TCP_EVT_CLOSED);
    break;
  }
}

void tcp_tick(net_t *net, uint32_t elapsed_ms) {
  uint8_t i;
  net->tcp_clock += elapsed_ms * 250u;
  for (i = 0; i < net->tcp_conn_count; i++) {
    if (net->tcp_conns[i])
      conn_tick(net, net->tcp_conns[i], elapsed_ms);
  }
}

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
#if NET_USE_IPV6
  conn->ip_ver = NET_USE_IPV4 ? 4 : 6;
#endif
  return NET_OK;
}

/* REQ-TCP-013, 168: an OPEN is for a connection not in use (§3.10.1) */
static int in_use(const tcp_conn_t *conn) {
  return conn->state != TCP_CLOSED && conn->state != TCP_LISTEN;
}

/* REQ-TCP-168: a connection in use is not turned into a listener */
net_err_t tcp_listen(tcp_conn_t *conn, uint16_t local_port) {
  if (!conn || local_port == 0)
    return NET_ERR_INVALID_PARAM;
  if (in_use(conn))
    return NET_ERR_BUSY;
  listen_on(conn, local_port);
  return NET_OK;
}

/* Active open, once the peer's address is in @p conn.  A SYN the driver
 * did not take is lost like any other segment: its timer resends it. */
static void open_to(net_t *net, tcp_conn_t *conn, const uint8_t *remote_mac,
                    uint16_t remote_port, uint16_t local_port) {
  tcp_ep_t peer;

  conn->local_port = local_port;
  conn->remote_port = remote_port;
  memcpy(conn->remote_mac, remote_mac, 6);
  conn->mac_valid = 1;
  conn->passive = 0;
  conn_endpoint(net, conn, &peer);
  start_send_sequence(net, conn);
  conn->snd_mss = send_mss(net, &peer, default_mss(&peer)); /* until told */
  conn->rcv_nxt = 0;
  conn->rcv_wnd = conn->rxbuf_ops->available(conn->rxbuf_ctx);
  conn->state = TCP_SYN_SENT;
  send_syn(net, conn);
  retransmit_timer_start(conn);
}

#if NET_USE_IPV4
/* REQ-TCP-171, 172: to a single host, from our address */
net_err_t tcp_connect(net_t *net, tcp_conn_t *conn, uint32_t remote_ip,
                      const uint8_t *remote_mac, uint16_t remote_port,
                      uint16_t local_port) {
  if (!net || !conn || !remote_mac || remote_port == 0 || local_port == 0 ||
      !ipv4_is_host(net, remote_ip) || net->ipv4_addr == 0)
    return NET_ERR_INVALID_PARAM;
  if (in_use(conn))
    return NET_ERR_BUSY;
  conn->remote_ip = remote_ip;
  conn->local_ip = net->ipv4_addr;
#if NET_USE_IPV6
  conn->ip_ver = 4;
#endif
  open_to(net, conn, remote_mac, remote_port, local_port);
  return NET_OK;
}
#endif

#if NET_USE_IPV6
net_err_t tcp6_connect(net_t *net, tcp_conn_t *conn, const uint8_t *remote_ip,
                       const uint8_t *remote_mac, uint16_t remote_port,
                       uint16_t local_port) {
  const uint8_t *src = net && remote_ip ? ipv6_src_for(net, remote_ip) : NULL;
  if (!src)
    return NET_ERR_INVALID_PARAM;
  return tcp6_connect_from(net, conn, src, remote_ip, remote_mac, remote_port,
                           local_port);
}

/* REQ-TCP-170..172: from one of our addresses, to a unicast one */
net_err_t tcp6_connect_from(net_t *net, tcp_conn_t *conn, const uint8_t *src,
                            const uint8_t *remote_ip, const uint8_t *remote_mac,
                            uint16_t remote_port, uint16_t local_port) {
  if (!net || !conn || !src || !remote_ip || !remote_mac || remote_port == 0 ||
      local_port == 0 || ipv6_is_multicast(remote_ip) ||
      ipv6_is_unspecified(remote_ip) || !ipv6_is_ours(net, src))
    return NET_ERR_INVALID_PARAM;
  if (in_use(conn))
    return NET_ERR_BUSY;
  conn->ip_ver = 6;
  conn->local_slot = (uint8_t)ipv6_addr_slot(net, src);
#if NET_USE_IPV4
  conn->remote_ip = 0;
#endif
  memcpy(conn->remote_ip6, remote_ip, 16);
  open_to(net, conn, remote_mac, remote_port, local_port);
  return NET_OK;
}
#endif

tcp_state_t tcp_status(const tcp_conn_t *conn) {
  return conn ? conn->state : TCP_CLOSED;
}

static int can_send(const tcp_conn_t *conn) {
  return conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT;
}

int tcp_write(tcp_conn_t *conn, const uint8_t *data, uint16_t len) {
  if (!conn || !can_send(conn))
    return (int)NET_ERR_INVALID_PARAM;
  if (len == 0)
    return 0;
  return (int)conn->txbuf_ops->write(conn->txbuf_ctx, data, len);
}

void tcp_output(net_t *net, tcp_conn_t *conn) {
  if (net && conn && can_send(conn))
    flush(net, conn);
}

/* No Nagle (REQ-TCP-131 MAY): what is written goes at once */
int tcp_send(net_t *net, tcp_conn_t *conn, const uint8_t *data, uint16_t len) {
  int accepted;
  if (!net)
    return (int)NET_ERR_INVALID_PARAM;
  accepted = tcp_write(conn, data, len);
  if (accepted > 0)
    flush(net, conn);
  return accepted;
}

int tcp_tx_idle(const tcp_conn_t *conn) {
  return conn && conn->txbuf_ops->queued(conn->txbuf_ctx) == 0 &&
         conn->snd_una == conn->snd_nxt;
}

uint16_t tcp_recv(tcp_conn_t *conn, uint8_t *buf, uint16_t maxlen) {
  if (!conn || !buf)
    return 0;
  return conn->rxbuf_ops->read(conn->rxbuf_ctx, buf, maxlen);
}

void tcp_window_update(net_t *net, tcp_conn_t *conn) {
  uint16_t avail, threshold;
  uint32_t buffer;
  if (!net || !conn || !can_receive(conn))
    return;
  avail = conn->rxbuf_ops->available(conn->rxbuf_ctx);
  if (avail <= conn->rcv_wnd)
    return;
  buffer = (uint32_t)avail + conn->rxbuf_ops->readable(conn->rxbuf_ctx);
  threshold = (uint16_t)(buffer / 2u);
  if (conn->our_mss && conn->our_mss < threshold)
    threshold = conn->our_mss;
  if ((uint16_t)(avail - conn->rcv_wnd) < threshold)
    return;
  conn->rcv_wnd = avail;
  send_ack(net, conn);
}

uint16_t tcp_last_error(const tcp_conn_t *conn) {
  return conn ? conn->last_error : 0;
}

/* REQ-TCP-174 */
net_err_t tcp_set_tos(tcp_conn_t *conn, uint8_t tos) {
  if (!conn)
    return NET_ERR_INVALID_PARAM;
  conn->tos = tos;
  return NET_OK;
}

/* REQ-TCP-165 */
net_err_t tcp_set_max_retransmits(tcp_conn_t *conn, uint8_t r2) {
  if (!conn || r2 == 0)
    return NET_ERR_INVALID_PARAM;
  conn->r2 = r2;
  return NET_OK;
}

/* REQ-TCP-015, RFC 9293 §3.10.4 */
net_err_t tcp_close(net_t *net, tcp_conn_t *conn) {
  if (!net || !conn)
    return NET_ERR_INVALID_PARAM;
  switch (conn->state) {
  case TCP_LISTEN:
  case TCP_SYN_SENT: /* nothing to tell the peer */
    close_with(conn, 0);
    return NET_OK;
  case TCP_SYN_RECEIVED: /* the FIN once our SYN is acknowledged */
    conn->close_queued = 1;
    return NET_OK;
  case TCP_ESTABLISHED:
    conn->state = TCP_FIN_WAIT_1;
    break;
  case TCP_CLOSE_WAIT:
    conn->state = TCP_LAST_ACK;
    break;
  default:
    return NET_OK; /* closed or closing already */
  }
  flush(net, conn);
  return NET_OK;
}

net_err_t tcp_abort(net_t *net, tcp_conn_t *conn) {
  if (!conn)
    return NET_ERR_INVALID_PARAM;
  if (peer_has_it_open(conn))
    reset_connection(net, conn);
  else
    close_with(conn, 0);
  notify(conn, TCP_EVT_RESET);
  return NET_OK;
}
