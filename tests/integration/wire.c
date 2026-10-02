/**
 * @file wire.c
 * @brief The scripted link and the peer's frame codec (see wire.h).
 */

#include "wire.h"
#include <ctype.h>
#include <string.h>

const uint8_t peer_mac[6] = {0x02, 0x50, 0x45, 0x45, 0x52, 0x01};
const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ── Big-endian fields ── */

uint16_t peer_get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

uint32_t peer_get32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}

void peer_put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

void peer_put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

/* ── The driver ── */

static int w_init(void *ctx) {
  (void)ctx;
  return 0;
}

static int w_send(void *ctx, const uint8_t *frame, uint16_t len) {
  wire_t *w = (wire_t *)ctx;
  if (w->tx_count < WIRE_TX_SLOTS && len <= WIRE_FRAME_MAX) {
    memcpy(w->tx[w->tx_count].data, frame, len);
    w->tx[w->tx_count].len = len;
  }
  w->tx_count++;
  return (int)len;
}

static int w_poll(void *ctx) {
  wire_t *w = (wire_t *)ctx;
  return w->rx_count ? (int)w->rx[0].len : 0;
}

static int w_peek(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len) {
  wire_t *w = (wire_t *)ctx;
  if (!w->rx_count)
    return -1;
  if (offset >= w->rx[0].len)
    return 0;
  if (len > w->rx[0].len - offset)
    len = (uint16_t)(w->rx[0].len - offset);
  memcpy(buf, w->rx[0].data + offset, len);
  return (int)len;
}

static void w_discard(void *ctx) {
  wire_t *w = (wire_t *)ctx;
  if (!w->rx_count)
    return;
  memmove(&w->rx[0], &w->rx[1], sizeof(w->rx[0]) * (w->rx_count - 1u));
  w->rx_count--;
}

static void w_close(void *ctx) { (void)ctx; }

const net_mac_t wire_driver = {w_init, w_send,    w_poll,
                               w_peek, w_discard, w_close};

net_err_t itest_up(itest_t *t, uint16_t rx_size, uint16_t tx_size) {
  net_err_t err;
  memset(t, 0, sizeof(*t));
  err = net_init(&t->net, t->rx_buf, rx_size, t->tx_buf, tx_size, NULL,
                 &wire_driver, &t->wire);
  if (err == NET_OK)
    wire_driver.init(&t->wire);
  return err;
}

void wire_deliver(itest_t *t, const uint8_t *frame, uint16_t len) {
  wire_t *w = &t->wire;
  if (w->rx_count < WIRE_RX_SLOTS && len <= WIRE_FRAME_MAX) {
    memcpy(w->rx[w->rx_count].data, frame, len);
    w->rx[w->rx_count].len = len;
    w->rx_count++;
  }
}

void itest_poll(itest_t *t) {
  while (t->wire.rx_count) {
    net_poll(&t->net);
    if (t->service)
      t->service(t);
  }
  if (t->service)
    t->service(t);
}

void itest_receive(itest_t *t, const uint8_t *frame, uint16_t len) {
  wire_deliver(t, frame, len);
  itest_poll(t);
}

void itest_advance(itest_t *t, uint32_t ms, uint32_t step) {
  while (ms) {
    uint32_t n = ms < step ? ms : step;
    net_tick(&t->net, n);
    ms -= n;
  }
}

void wire_clear(itest_t *t) { t->wire.tx_count = 0; }

const wire_frame_t *wire_sent(const itest_t *t, uint16_t i) {
  if (i >= t->wire.tx_count || i >= WIRE_TX_SLOTS)
    return NULL;
  return &t->wire.tx[i];
}

/* ── The peer's codec ── */

static uint32_t sum16(uint32_t sum, const uint8_t *p, uint16_t len) {
  while (len > 1) {
    sum += peer_get16(p);
    p += 2;
    len -= 2;
  }
  if (len)
    sum += (uint32_t)p[0] << 8;
  return sum;
}

static uint16_t fold(uint32_t sum) {
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

uint16_t peer_cksum(const void *data, uint16_t len) {
  return fold(sum16(0, (const uint8_t *)data, len));
}

/* The IPv4 pseudo-header and @p len bytes of a transport segment */
static uint16_t transport_cksum(uint32_t src, uint32_t dst, uint8_t proto,
                                const uint8_t *seg, uint16_t len) {
  uint8_t ph[12];
  peer_put32(ph, src);
  peer_put32(ph + 4, dst);
  ph[8] = 0;
  ph[9] = proto;
  peer_put16(ph + 10, len);
  return fold(sum16(sum16(0, ph, 12), seg, len));
}

peer_ip_t peer_ip(uint32_t src, uint32_t dst, uint8_t proto) {
  peer_ip_t ip;
  memset(&ip, 0, sizeof(ip));
  ip.src = src;
  ip.dst = dst;
  ip.proto = proto;
  ip.ttl = 64;
  return ip;
}

uint16_t peer_ipv4_frame(uint8_t *frame, const uint8_t dst_mac[6],
                         const uint8_t src_mac[6], const peer_ip_t *ip,
                         const void *payload, uint16_t len) {
  uint8_t *h = frame + 14;
  uint8_t hlen = (uint8_t)(20u + ip->options_len);
  uint16_t frag = (uint16_t)(ip->frag_offset / 8u);
  memcpy(frame, dst_mac, 6);
  memcpy(frame + 6, src_mac, 6);
  peer_put16(frame + 12, 0x0800);
  h[0] = (uint8_t)(0x40 | hlen / 4u);
  h[1] = ip->tos;
  peer_put16(h + 2, (uint16_t)(hlen + len));
  peer_put16(h + 4, ip->id);
  peer_put16(h + 6,
             (uint16_t)((ip->df ? 0x4000 : 0) | (ip->mf ? 0x2000 : 0) | frag));
  h[8] = ip->ttl;
  h[9] = ip->proto;
  peer_put16(h + 10, 0);
  peer_put32(h + 12, ip->src);
  peer_put32(h + 16, ip->dst);
  if (ip->options_len)
    memcpy(h + 20, ip->options, ip->options_len);
  peer_put16(h + 10, peer_cksum(h, hlen));
  if (len)
    memcpy(h + hlen, payload, len);
  return (uint16_t)(14u + hlen + len);
}

uint16_t peer_udp(uint8_t *out, const peer_ip_t *ip, uint16_t sport,
                  uint16_t dport, const void *data, uint16_t len) {
  uint16_t ulen = (uint16_t)(8u + len);
  uint16_t ck;
  peer_put16(out, sport);
  peer_put16(out + 2, dport);
  peer_put16(out + 4, ulen);
  peer_put16(out + 6, 0);
  if (len)
    memcpy(out + 8, data, len);
  ck = transport_cksum(ip->src, ip->dst, 17, out, ulen);
  peer_put16(out + 6, ck ? ck : 0xFFFF);
  return ulen;
}

uint16_t peer_icmp(uint8_t *out, uint8_t type, uint8_t code,
                   const uint8_t rest[4], const void *data, uint16_t len) {
  out[0] = type;
  out[1] = code;
  peer_put16(out + 2, 0);
  if (rest)
    memcpy(out + 4, rest, 4);
  else
    memset(out + 4, 0, 4);
  if (len)
    memcpy(out + 8, data, len);
  peer_put16(out + 2, peer_cksum(out, (uint16_t)(8u + len)));
  return (uint16_t)(8u + len);
}

uint16_t peer_udp_frame(uint8_t *frame, const net_t *net, uint32_t src,
                        uint32_t dst, uint16_t sport, uint16_t dport,
                        const void *data, uint16_t len) {
  static uint8_t seg[WIRE_FRAME_MAX];
  peer_ip_t ip = peer_ip(src, dst, 17);
  uint16_t n = peer_udp(seg, &ip, sport, dport, data, len);
  return peer_ipv4_frame(frame, net->mac, peer_mac, &ip, seg, n);
}

uint16_t peer_arp_frame(uint8_t *frame, const uint8_t eth_dst[6], uint16_t op,
                        const uint8_t sha[6], uint32_t spa,
                        const uint8_t tha[6], uint32_t tpa) {
  uint8_t *a = frame + 14;
  memcpy(frame, eth_dst, 6);
  memcpy(frame + 6, sha, 6);
  peer_put16(frame + 12, 0x0806);
  peer_put16(a, 1);
  peer_put16(a + 2, 0x0800);
  a[4] = 6;
  a[5] = 4;
  peer_put16(a + 6, op);
  memcpy(a + 8, sha, 6);
  peer_put32(a + 14, spa);
  memcpy(a + 18, tha, 6);
  peer_put32(a + 24, tpa);
  return 14 + 28;
}

int peer_parse_ipv4(const wire_frame_t *f, peer_ip_t *ip) {
  const uint8_t *h = f->data + 14;
  uint16_t flags;
  memset(ip, 0, sizeof(*ip));
  if (f->len < 34 || peer_get16(f->data + 12) != 0x0800 || (h[0] >> 4) != 4)
    return 0;
  ip->ihl_bytes = (uint8_t)((h[0] & 0x0F) * 4u);
  ip->tos = h[1];
  ip->total_len = peer_get16(h + 2);
  ip->id = peer_get16(h + 4);
  flags = peer_get16(h + 6);
  ip->df = (flags & 0x4000) != 0;
  ip->mf = (flags & 0x2000) != 0;
  ip->frag_offset = (uint16_t)((flags & 0x1FFF) * 8u);
  ip->ttl = h[8];
  ip->proto = h[9];
  ip->src = peer_get32(h + 12);
  ip->dst = peer_get32(h + 16);
  if (ip->ihl_bytes < 20 || 14u + ip->total_len > f->len ||
      ip->total_len < ip->ihl_bytes)
    return 0;
  ip->header_cksum_ok = peer_cksum(h, ip->ihl_bytes) == 0;
  ip->options = h + 20;
  ip->options_len = (uint8_t)(ip->ihl_bytes - 20u);
  ip->payload = h + ip->ihl_bytes;
  ip->payload_len = (uint16_t)(ip->total_len - ip->ihl_bytes);
  return 1;
}

int peer_parse_udp(const peer_ip_t *ip, peer_udp_t *udp) {
  const uint8_t *u = ip->payload;
  memset(udp, 0, sizeof(*udp));
  if (ip->proto != 17 || ip->payload_len < 8)
    return 0;
  udp->sport = peer_get16(u);
  udp->dport = peer_get16(u + 2);
  udp->len = peer_get16(u + 4);
  udp->cksum = peer_get16(u + 6);
  if (udp->len < 8 || udp->len > ip->payload_len)
    return 0;
  udp->cksum_ok = udp->cksum == 0 ||
                  transport_cksum(ip->src, ip->dst, 17, u, udp->len) == 0;
  udp->data = u + 8;
  udp->data_len = (uint16_t)(udp->len - 8u);
  return 1;
}

int peer_parse_icmp(const peer_ip_t *ip, peer_icmp_t *icmp) {
  const uint8_t *m = ip->payload;
  memset(icmp, 0, sizeof(*icmp));
  if (ip->proto != 1 || ip->payload_len < 8)
    return 0;
  icmp->type = m[0];
  icmp->code = m[1];
  icmp->cksum_ok = peer_cksum(m, ip->payload_len) == 0;
  icmp->rest = m + 4;
  icmp->data = m + 8;
  icmp->data_len = (uint16_t)(ip->payload_len - 8u);
  return 1;
}

int peer_parse_arp(const wire_frame_t *f, peer_arp_t *arp) {
  const uint8_t *a = f->data + 14;
  memset(arp, 0, sizeof(*arp));
  if (f->len < 42 || peer_get16(f->data + 12) != 0x0806 || peer_get16(a) != 1 ||
      peer_get16(a + 2) != 0x0800 || a[4] != 6 || a[5] != 4)
    return 0;
  arp->op = peer_get16(a + 6);
  arp->sha = a + 8;
  arp->spa = peer_get32(a + 14);
  arp->tha = a + 18;
  arp->tpa = peer_get32(a + 24);
  return 1;
}

uint16_t peer_tcp_frame(uint8_t *frame, const net_t *net, uint32_t src,
                        const peer_tcp_seg_t *seg) {
  static uint8_t buf[WIRE_FRAME_MAX];
  peer_ip_t ip = peer_ip(src, net->ipv4_addr, 6);
  uint8_t hlen = seg->mss ? 24 : 20;
  uint16_t total = (uint16_t)(hlen + seg->len);
  memset(buf, 0, hlen);
  peer_put16(buf, seg->sport);
  peer_put16(buf + 2, seg->dport);
  peer_put32(buf + 4, seg->seq);
  peer_put32(buf + 8, seg->ack);
  buf[12] = (uint8_t)((hlen / 4u) << 4);
  buf[13] = seg->flags;
  peer_put16(buf + 14, seg->window);
  if (seg->mss) {
    buf[20] = 2;
    buf[21] = 4;
    peer_put16(buf + 22, seg->mss);
  }
  if (seg->len)
    memcpy(buf + hlen, seg->data, seg->len);
  peer_put16(buf + 16, transport_cksum(ip.src, ip.dst, 6, buf, total));
  return peer_ipv4_frame(frame, net->mac, peer_mac, &ip, buf, total);
}

int peer_parse_tcp(const peer_ip_t *ip, peer_tcp_t *tcp) {
  const uint8_t *s = ip->payload;
  uint8_t hlen, i;
  memset(tcp, 0, sizeof(*tcp));
  if (ip->proto != 6 || ip->payload_len < 20)
    return 0;
  hlen = (uint8_t)((s[12] >> 4) * 4u);
  if (hlen < 20 || hlen > ip->payload_len)
    return 0;
  tcp->sport = peer_get16(s);
  tcp->dport = peer_get16(s + 2);
  tcp->seq = peer_get32(s + 4);
  tcp->ack = peer_get32(s + 8);
  tcp->flags = s[13];
  tcp->window = peer_get16(s + 14);
  tcp->cksum_ok = transport_cksum(ip->src, ip->dst, 6, s, ip->payload_len) == 0;
  for (i = 20; i + 1u < hlen;) {
    if (s[i] == 0)
      break;
    if (s[i] == 1) {
      i++;
      continue;
    }
    if (s[i] == 2 && s[i + 1] == 4 && i + 4u <= hlen)
      tcp->mss = peer_get16(s + i + 2);
    if (s[i + 1] < 2)
      break;
    i = (uint8_t)(i + s[i + 1]);
  }
  tcp->data = s + hlen;
  tcp->data_len = (uint16_t)(ip->payload_len - hlen);
  return 1;
}

int wire_find_tcp(const itest_t *t, uint16_t from, peer_ip_t *ip,
                  peer_tcp_t *tcp) {
  uint16_t i;
  for (i = from; wire_sent(t, i); i++) {
    if (peer_parse_ipv4(wire_sent(t, i), ip) && peer_parse_tcp(ip, tcp))
      return i;
  }
  return -1;
}

/* ── The peer as a TCP client ── */

static void client_segment(itest_t *t, peer_client_t *c, uint8_t flags,
                           const void *data, uint16_t len) {
  static uint8_t f[WIRE_FRAME_MAX];
  peer_tcp_seg_t s;
  memset(&s, 0, sizeof(s));
  s.sport = c->sport;
  s.dport = c->dport;
  s.seq = c->snd_nxt;
  s.ack = c->rcv_nxt;
  s.flags = flags;
  s.window = 8192;
  s.mss = (flags & TCPF_SYN) ? 1460 : 0;
  s.data = data;
  s.len = len;
  c->snd_nxt += len + ((flags & (TCPF_SYN | TCPF_FIN)) ? 1u : 0u);
  itest_receive(t, f, peer_tcp_frame(f, &t->net, PEER_IP, &s));
}

int peer_connect(itest_t *t, peer_client_t *c, uint16_t sport, uint16_t dport) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  int i;
  memset(c, 0, sizeof(*c));
  c->sport = sport;
  c->dport = dport;
  c->snd_nxt = 100000;
  wire_clear(t);
  client_segment(t, c, TCPF_SYN, NULL, 0);
  i = wire_find_tcp(t, 0, &ip, &tcp);
  if (i < 0 || tcp.flags != (TCPF_SYN | TCPF_ACK) || tcp.dport != sport)
    return 0;
  c->rcv_nxt = tcp.seq + 1u;
  wire_clear(t);
  client_segment(t, c, TCPF_ACK, NULL, 0);
  c->connected = 1;
  peer_collect(t, c);
  return 1;
}

void peer_collect(itest_t *t, peer_client_t *c) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  int rounds;
  for (rounds = 0; rounds < 1000; rounds++) {
    int i, acked = 0;
    for (i = c->seen; (i = wire_find_tcp(t, (uint16_t)i, &ip, &tcp)) >= 0;
         i++) {
      c->seen = (uint16_t)(i + 1);
      if (tcp.dport != c->sport)
        continue;
      if (tcp.flags & TCPF_RST) {
        c->rst = 1;
        return;
      }
      if (tcp.seq == c->rcv_nxt && tcp.data_len) {
        uint16_t room = (uint16_t)(sizeof(c->data) - c->len);
        uint16_t n = tcp.data_len < room ? tcp.data_len : room;
        memcpy(c->data + c->len, tcp.data, n);
        c->len = (uint16_t)(c->len + n);
        c->rcv_nxt += tcp.data_len;
        acked = 1;
      }
      if ((tcp.flags & TCPF_FIN) && tcp.seq + tcp.data_len == c->rcv_nxt) {
        c->rcv_nxt++;
        c->fin = 1;
        acked = 1;
      }
    }
    if (!acked)
      return;
    wire_clear(t);
    c->seen = 0;
    client_segment(t, c, TCPF_ACK, NULL, 0);
  }
}

void peer_send(itest_t *t, peer_client_t *c, const void *data, uint16_t len) {
  wire_clear(t);
  c->seen = 0;
  client_segment(t, c, TCPF_PSH | TCPF_ACK, data, len);
  peer_collect(t, c);
}

void peer_close(itest_t *t, peer_client_t *c) {
  wire_clear(t);
  c->seen = 0;
  client_segment(t, c, TCPF_FIN | TCPF_ACK, NULL, 0);
  peer_collect(t, c);
}

/* ── DNS ── */

uint16_t peer_dns_name(uint8_t *out, const char *name) {
  uint16_t n = 0;
  while (*name) {
    const char *dot = strchr(name, '.');
    uint16_t l = (uint16_t)(dot ? (uint16_t)(dot - name) : strlen(name));
    out[n++] = (uint8_t)l;
    memcpy(out + n, name, l);
    n = (uint16_t)(n + l);
    name += l;
    if (*name == '.')
      name++;
  }
  out[n++] = 0;
  return n;
}

void peer_dns_begin(peer_dns_t *m, uint16_t id, uint16_t flags) {
  memset(m, 0, sizeof(*m));
  peer_put16(m->buf, id);
  peer_put16(m->buf + 2, flags);
  m->len = 12;
}

void peer_dns_question(peer_dns_t *m, const char *name, uint16_t type,
                       uint16_t class_) {
  m->len = (uint16_t)(m->len + peer_dns_name(m->buf + m->len, name));
  peer_put16(m->buf + m->len, type);
  peer_put16(m->buf + m->len + 2, class_);
  m->len = (uint16_t)(m->len + 4);
  m->qd++;
}

void peer_dns_rr(peer_dns_t *m, int section, const char *name, uint16_t type,
                 uint16_t class_, uint32_t ttl, const void *rdata,
                 uint16_t rdlen) {
  m->len = (uint16_t)(m->len + peer_dns_name(m->buf + m->len, name));
  peer_put16(m->buf + m->len, type);
  peer_put16(m->buf + m->len + 2, class_);
  peer_put32(m->buf + m->len + 4, ttl);
  peer_put16(m->buf + m->len + 8, rdlen);
  memcpy(m->buf + m->len + 10, rdata, rdlen);
  m->len = (uint16_t)(m->len + 10 + rdlen);
  if (section == 0)
    m->an++;
  else if (section == 1)
    m->ns++;
  else
    m->ar++;
}

void peer_dns_end(peer_dns_t *m) {
  peer_put16(m->buf + 4, m->qd);
  peer_put16(m->buf + 6, m->an);
  peer_put16(m->buf + 8, m->ns);
  peer_put16(m->buf + 10, m->ar);
}

/* The name at @p off; @return the offset after it in the message, 0 if
 * malformed.  Follows compression pointers (at most 64). */
static uint16_t read_name(const uint8_t *msg, uint16_t len, uint16_t off,
                          char *out) {
  uint16_t end = 0, n = 0;
  int jumps = 0;
  out[0] = 0;
  for (;;) {
    uint8_t l;
    if (off >= len)
      return 0;
    l = msg[off];
    if ((l & 0xC0) == 0xC0) {
      if (off + 1u >= len || ++jumps > 64)
        return 0;
      if (!end)
        end = (uint16_t)(off + 2);
      off = (uint16_t)(((l & 0x3F) << 8) | msg[off + 1]);
      continue;
    }
    if (l == 0) {
      if (!end)
        end = (uint16_t)(off + 1);
      out[n] = 0;
      return end;
    }
    if (off + 1u + l > len || n + l + 2u > 255)
      return 0;
    if (n)
      out[n++] = '.';
    memcpy(out + n, msg + off + 1, l);
    n = (uint16_t)(n + l);
    off = (uint16_t)(off + 1 + l);
  }
}

int peer_dns_read_name(const peer_dns_msg_t *m, uint16_t off, char *out) {
  return read_name(m->msg, m->len, off, out) != 0;
}

int peer_dns_parse(const uint8_t *msg, uint16_t len, peer_dns_msg_t *out) {
  uint16_t off = 12, i, total;
  char name[256];
  memset(out, 0, sizeof(*out));
  if (len < 12)
    return 0;
  out->msg = msg;
  out->len = len;
  out->id = peer_get16(msg);
  out->flags = peer_get16(msg + 2);
  out->qd = peer_get16(msg + 4);
  out->an = peer_get16(msg + 6);
  out->ns = peer_get16(msg + 8);
  out->ar = peer_get16(msg + 10);
  for (i = 0; i < out->qd; i++) {
    off = read_name(msg, len, off, name);
    if (!off || off + 4u > len)
      return 0;
    if (i == 0) {
      strcpy(out->qname, name);
      out->qtype = peer_get16(msg + off);
    }
    off = (uint16_t)(off + 4);
  }
  total = (uint16_t)(out->an + out->ns + out->ar);
  for (i = 0; i < total; i++) {
    peer_rr_t *r = &out->rr[out->n_rr < 32 ? out->n_rr : 31];
    off = read_name(msg, len, off, r->name);
    if (!off || off + 10u > len)
      return 0;
    r->type = peer_get16(msg + off);
    r->class_ = peer_get16(msg + off + 2);
    r->ttl = peer_get32(msg + off + 4);
    r->rdlen = peer_get16(msg + off + 8);
    r->rdata_off = (uint16_t)(off + 10);
    r->rdata = msg + off + 10;
    r->section = i < out->an ? 0 : i < out->an + out->ns ? 1 : 2;
    if (off + 10u + r->rdlen > len)
      return 0;
    off = (uint16_t)(off + 10 + r->rdlen);
    if (out->n_rr < 32)
      out->n_rr++;
  }
  return 1;
}

static int same_name(const char *a, const char *b) {
  size_t la = strlen(a), lb = strlen(b);
  if (la && a[la - 1] == '.')
    la--;
  if (lb && b[lb - 1] == '.')
    lb--;
  if (la != lb)
    return 0;
  while (la--) {
    if (tolower((unsigned char)*a++) != tolower((unsigned char)*b++))
      return 0;
  }
  return 1;
}

const peer_rr_t *peer_dns_find(const peer_dns_msg_t *m, int section,
                               const char *name, uint16_t type) {
  uint16_t i;
  for (i = 0; i < m->n_rr; i++) {
    const peer_rr_t *r = &m->rr[i];
    if (r->section == section && r->type == type && same_name(r->name, name))
      return r;
  }
  return NULL;
}

/* ── IPv6 ── */

const uint8_t peer6_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                              0,    0,    0, 0, 0, 0, 0, 0x99};
const uint8_t router6_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                0,    0,    0, 0, 0, 0, 0, 1};
const uint8_t router6_mac[6] = {0x02, 0x52, 0x4F, 0x55, 0x54, 0x01};
const uint8_t prefix6[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 0,
                             0,    0,    0,    0,    0, 0, 0, 0};
const uint8_t offlink6[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 9, 0, 0,
                              0,    0,    0,    0,    0, 0, 0, 9};
const uint8_t all_nodes6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                0,    0,    0, 0, 0, 0, 0, 1};
const uint8_t all_routers6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                  0,    0,    0, 0, 0, 0, 0, 2};

peer_ip6_t peer_ip6(const uint8_t *src, const uint8_t *dst, uint8_t nh) {
  peer_ip6_t ip;
  memset(&ip, 0, sizeof(ip));
  ip.src = src;
  ip.dst = dst;
  ip.nh = nh;
  ip.hop_limit = 64;
  return ip;
}

uint16_t peer_ipv6_frame(uint8_t *frame, const uint8_t dst_mac[6],
                         const uint8_t src_mac[6], const peer_ip6_t *ip,
                         const void *payload, uint16_t len) {
  uint8_t *h = frame + 14;
  memcpy(frame, dst_mac, 6);
  memcpy(frame + 6, src_mac, 6);
  peer_put16(frame + 12, 0x86DD);
  peer_put32(h,
             0x60000000u | (uint32_t)ip->tclass << 20 | (ip->flow & 0xFFFFFu));
  peer_put16(h + 4, (uint16_t)(ip->ext_len + len));
  h[6] = ip->nh;
  h[7] = ip->hop_limit;
  memcpy(h + 8, ip->src, 16);
  memcpy(h + 24, ip->dst, 16);
  if (ip->ext_len)
    memcpy(h + 40, ip->ext, ip->ext_len);
  if (len)
    memcpy(h + 40 + ip->ext_len, payload, len);
  return (uint16_t)(14u + 40u + ip->ext_len + len);
}

void peer_mcast6_mac(const uint8_t *group, uint8_t mac[6]) {
  mac[0] = 0x33;
  mac[1] = 0x33;
  memcpy(mac + 2, group + 12, 4);
}

void peer_solicited_node(const uint8_t *addr, uint8_t group[16]) {
  memset(group, 0, 16);
  group[0] = 0xFF;
  group[1] = 0x02;
  group[11] = 0x01;
  group[12] = 0xFF;
  memcpy(group + 13, addr + 13, 3);
}

void peer_link_local(const uint8_t mac[6], uint8_t addr[16]) {
  memset(addr, 0, 16);
  addr[0] = 0xFE;
  addr[1] = 0x80;
  addr[8] = (uint8_t)(mac[0] ^ 0x02);
  addr[9] = mac[1];
  addr[10] = mac[2];
  addr[11] = 0xFF;
  addr[12] = 0xFE;
  memcpy(addr + 13, mac + 3, 3);
}

uint16_t peer_cksum6(const uint8_t *src, const uint8_t *dst, uint8_t nh,
                     const uint8_t *data, uint16_t len) {
  uint8_t ph[40];
  memcpy(ph, src, 16);
  memcpy(ph + 16, dst, 16);
  peer_put32(ph + 32, len);
  peer_put32(ph + 36, nh);
  return fold(sum16(sum16(0, ph, 40), data, len));
}

uint16_t peer_icmp6(uint8_t *out, const peer_ip6_t *ip, uint8_t type,
                    uint8_t code, const uint8_t rest[4], const void *body,
                    uint16_t len) {
  out[0] = type;
  out[1] = code;
  peer_put16(out + 2, 0);
  if (rest)
    memcpy(out + 4, rest, 4);
  else
    memset(out + 4, 0, 4);
  if (len)
    memcpy(out + 8, body, len);
  peer_put16(out + 2,
             peer_cksum6(ip->src, ip->dst, 58, out, (uint16_t)(8u + len)));
  return (uint16_t)(8u + len);
}

uint16_t peer_icmp6_frame(uint8_t *frame, const uint8_t dst_mac[6],
                          const peer_ip6_t *ip, uint8_t type, uint8_t code,
                          const uint8_t rest[4], const void *body,
                          uint16_t len) {
  static uint8_t msg[WIRE_FRAME_MAX];
  uint16_t n = peer_icmp6(msg, ip, type, code, rest, body, len);
  return peer_ipv6_frame(frame, dst_mac, peer_mac, ip, msg, n);
}

uint16_t peer_nd_lla(uint8_t *out, uint8_t type, const uint8_t mac[6]) {
  out[0] = type;
  out[1] = 1;
  memcpy(out + 2, mac, 6);
  return 8;
}

uint16_t peer_nd_prefix(uint8_t *out, const uint8_t prefix[16],
                        uint8_t prefix_len, uint8_t flags, uint32_t valid_s,
                        uint32_t preferred_s) {
  memset(out, 0, 32);
  out[0] = 3;
  out[1] = 4;
  out[2] = prefix_len;
  out[3] = flags;
  peer_put32(out + 4, valid_s);
  peer_put32(out + 8, preferred_s);
  memcpy(out + 16, prefix, 16);
  return 32;
}

uint16_t peer_udp6(uint8_t *out, const peer_ip6_t *ip, uint16_t sport,
                   uint16_t dport, const void *data, uint16_t len) {
  uint16_t ulen = (uint16_t)(8u + len);
  uint16_t ck;
  peer_put16(out, sport);
  peer_put16(out + 2, dport);
  peer_put16(out + 4, ulen);
  peer_put16(out + 6, 0);
  if (len)
    memcpy(out + 8, data, len);
  ck = peer_cksum6(ip->src, ip->dst, 17, out, ulen);
  peer_put16(out + 6, ck ? ck : 0xFFFF);
  return ulen;
}

uint16_t peer_tcp6(uint8_t *out, const peer_ip6_t *ip,
                   const peer_tcp_seg_t *seg) {
  uint8_t hlen = seg->mss ? 24 : 20;
  uint16_t total = (uint16_t)(hlen + seg->len);
  memset(out, 0, hlen);
  peer_put16(out, seg->sport);
  peer_put16(out + 2, seg->dport);
  peer_put32(out + 4, seg->seq);
  peer_put32(out + 8, seg->ack);
  out[12] = (uint8_t)((hlen / 4u) << 4);
  out[13] = seg->flags;
  peer_put16(out + 14, seg->window);
  if (seg->mss) {
    out[20] = 2;
    out[21] = 4;
    peer_put16(out + 22, seg->mss);
  }
  if (seg->len)
    memcpy(out + hlen, seg->data, seg->len);
  peer_put16(out + 16, peer_cksum6(ip->src, ip->dst, 6, out, total));
  return total;
}

int peer_parse_ipv6(const wire_frame_t *f, peer_ip6_t *ip) {
  const uint8_t *h = f->data + 14;
  uint32_t off = 40, end;
  uint8_t nh;
  memset(ip, 0, sizeof(*ip));
  if (f->len < 54 || peer_get16(f->data + 12) != 0x86DD || (h[0] >> 4) != 6)
    return 0;
  ip->tclass = (uint8_t)(peer_get32(h) >> 20);
  ip->flow = peer_get32(h) & 0xFFFFFu;
  ip->plen = peer_get16(h + 4);
  ip->nh = h[6];
  ip->hop_limit = h[7];
  ip->src = h + 8;
  ip->dst = h + 24;
  end = 40u + ip->plen;
  if (14u + end > f->len)
    return 0;
  for (nh = ip->nh; nh == 0 || nh == 43 || nh == 60;) {
    if (off + 2 > end)
      return 0;
    nh = h[off];
    off += (h[off + 1] + 1u) * 8u;
    if (off > end)
      return 0;
  }
  ip->ext = h + 40;
  ip->ext_len = (uint16_t)(off - 40u);
  ip->proto = nh;
  ip->payload = h + off;
  ip->payload_len = (uint16_t)(end - off);
  return 1;
}

int peer_parse_icmp6(const peer_ip6_t *ip, peer_icmp_t *icmp) {
  const uint8_t *m = ip->payload;
  memset(icmp, 0, sizeof(*icmp));
  if (ip->proto != 58 || ip->payload_len < 8)
    return 0;
  icmp->type = m[0];
  icmp->code = m[1];
  icmp->cksum_ok = peer_cksum6(ip->src, ip->dst, 58, m, ip->payload_len) == 0;
  icmp->rest = m + 4;
  icmp->data = m + 8;
  icmp->data_len = (uint16_t)(ip->payload_len - 8u);
  return 1;
}

int peer_parse_udp6(const peer_ip6_t *ip, peer_udp_t *udp) {
  const uint8_t *u = ip->payload;
  memset(udp, 0, sizeof(*udp));
  if (ip->proto != 17 || ip->payload_len < 8)
    return 0;
  udp->sport = peer_get16(u);
  udp->dport = peer_get16(u + 2);
  udp->len = peer_get16(u + 4);
  udp->cksum = peer_get16(u + 6);
  if (udp->len < 8 || udp->len > ip->payload_len)
    return 0;
  udp->cksum_ok =
      udp->cksum != 0 && peer_cksum6(ip->src, ip->dst, 17, u, udp->len) == 0;
  udp->data = u + 8;
  udp->data_len = (uint16_t)(udp->len - 8u);
  return 1;
}

int peer_parse_tcp6(const peer_ip6_t *ip, peer_tcp_t *tcp) {
  peer_ip_t as4;
  memset(&as4, 0, sizeof(as4));
  as4.proto = ip->proto;
  as4.payload = ip->payload;
  as4.payload_len = ip->payload_len;
  if (!peer_parse_tcp(&as4, tcp))
    return 0;
  tcp->cksum_ok =
      peer_cksum6(ip->src, ip->dst, 6, ip->payload, ip->payload_len) == 0;
  return 1;
}

const uint8_t *peer_nd_option(const uint8_t *opts, uint16_t len, uint8_t type) {
  while (len >= 2) {
    uint16_t olen = (uint16_t)(opts[1] * 8u);
    if (olen == 0 || olen > len)
      return NULL;
    if (opts[0] == type)
      return opts;
    opts += olen;
    len = (uint16_t)(len - olen);
  }
  return NULL;
}

int wire_find_icmp6(const itest_t *t, uint16_t from, uint8_t type,
                    peer_ip6_t *ip, peer_icmp_t *icmp) {
  uint16_t i;
  for (i = from; wire_sent(t, i); i++) {
    if (peer_parse_ipv6(wire_sent(t, i), ip) && peer_parse_icmp6(ip, icmp) &&
        icmp->type == type)
      return i;
  }
  return -1;
}

int wire_count_icmp6(const itest_t *t, uint8_t type) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  int n = 0, i = 0;
  while ((i = wire_find_icmp6(t, (uint16_t)i, type, &ip, &icmp)) >= 0) {
    n++;
    i++;
  }
  return n;
}
