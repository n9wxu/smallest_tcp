/**
 * @file dhcpv4_client.c
 * @brief DHCPv4 client state machine — RFC 2131.
 *
 * Implements REQ-DHCPv4-001..059.
 * Zero dynamic allocation; all state lives in the caller-owned dhcpv4_client_t.
 */

#include "dhcpv4_client.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

/* ── DHCP wire offsets ────────────────────────────────────────────── */
#define DHCP_OFF_OP 0
#define DHCP_OFF_HTYPE 1
#define DHCP_OFF_HLEN 2
#define DHCP_OFF_HOPS 3
#define DHCP_OFF_XID 4
#define DHCP_OFF_SECS 8
#define DHCP_OFF_FLAGS 10
#define DHCP_OFF_CIADDR 12
#define DHCP_OFF_YIADDR 16
#define DHCP_OFF_SIADDR 20
#define DHCP_OFF_GIADDR 24
#define DHCP_OFF_CHADDR 28
#define DHCP_OFF_MAGIC 236
#define DHCP_OFF_OPTIONS 240
#define DHCP_MIN_LEN 300 /* RFC 2131 §2 recommended minimum */

#define DHCP_MAGIC 0x63825363u
#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY 2

/* DHCP message type values */
#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_REQUEST 3
#define DHCP_MSG_ACK 5
#define DHCP_MSG_NAK 6
#define DHCP_MSG_RELEASE 7

/* DHCP option codes */
#define OPT_SUBNET_MASK 1
#define OPT_ROUTER 3
#define OPT_DNS 6
#define OPT_REQUESTED_IP 50
#define OPT_LEASE_TIME 51
#define OPT_MSG_TYPE 53
#define OPT_SERVER_ID 54
#define OPT_PARAM_REQ 55
#define OPT_T1 58
#define OPT_T2 59
#define OPT_END 255
#define OPT_PAD 0

/* Retransmit backoff: initial 4 s, max 64 s — REQ-DHCPv4-045 */
#define RETRY_INIT_MS 4000u
#define RETRY_MAX_MS 64000u

static const uint8_t BCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint32_t BCAST_IP = 0xFFFFFFFFu;

/* ── Internal helpers ─────────────────────────────────────────────── */

static void fire_event(dhcpv4_client_t *c, uint8_t evt) {
  if (c->on_event)
    c->on_event(evt, c->evt_ctx);
}

/* Very small LCG — good enough for XID randomness. REQ-DHCPv4-009 */
static uint32_t s_seed = 0x12345678u;
static uint32_t rand_xid(void) {
  s_seed = s_seed * 1664525u + 1013904223u;
  return s_seed;
}

static uint32_t next_retry_ms(uint8_t retry_count) {
  uint32_t t = RETRY_INIT_MS;
  for (uint8_t i = 0; i < retry_count && t < RETRY_MAX_MS; i++)
    t *= 2u;
  return (t > RETRY_MAX_MS) ? RETRY_MAX_MS : t;
}

/* Build the fixed 240-byte DHCP header + magic cookie into buf[0..239].
   Returns DHCP_OFF_OPTIONS (240) — caller appends options starting there. */
static uint16_t build_header(uint8_t *buf, uint32_t xid, uint32_t ciaddr,
                             const uint8_t *chaddr) {
  memset(buf, 0, DHCP_MIN_LEN);
  buf[DHCP_OFF_OP] = DHCP_OP_REQUEST;
  buf[DHCP_OFF_HTYPE] = 1; /* Ethernet */
  buf[DHCP_OFF_HLEN] = 6;
  net_write32be(buf + DHCP_OFF_XID, xid);
  net_write16be(buf + DHCP_OFF_FLAGS, 0x8000u); /* broadcast flag */
  net_write32be(buf + DHCP_OFF_CIADDR, ciaddr);
  memcpy(buf + DHCP_OFF_CHADDR, chaddr, 6);
  net_write32be(buf + DHCP_OFF_MAGIC, DHCP_MAGIC);
  return DHCP_OFF_OPTIONS;
}

static uint16_t opt_byte(uint8_t *buf, uint16_t pos, uint8_t code, uint8_t v) {
  buf[pos++] = code;
  buf[pos++] = 1;
  buf[pos++] = v;
  return pos;
}

static uint16_t opt_u32(uint8_t *buf, uint16_t pos, uint8_t code, uint32_t v) {
  buf[pos++] = code;
  buf[pos++] = 4;
  net_write32be(buf + pos, v);
  return pos + 4;
}

/* Build Parameter Request List (option 55). REQ-DHCPv4-059 */
static uint16_t build_prl(uint8_t *buf, uint16_t pos,
                          const dhcpv4_opt_table_t *opts) {
  /* mandatory built-ins: subnet mask, router, lease time */
  uint8_t codes[35];
  uint8_t n = 0;
  codes[n++] = OPT_SUBNET_MASK;
  codes[n++] = OPT_ROUTER;
  codes[n++] = OPT_LEASE_TIME;
  if (opts) {
    for (uint8_t i = 0; i < opts->count && n < (uint8_t)sizeof(codes); i++)
      codes[n++] = opts->entries[i].option;
  }
  buf[pos++] = OPT_PARAM_REQ;
  buf[pos++] = n;
  memcpy(buf + pos, codes, n);
  return pos + n;
}

/* Send DHCPDISCOVER — REQ-DHCPv4-002, 008..017 */
static void send_discover(net_t *net, dhcpv4_client_t *c) {
  uint8_t msg[DHCP_MIN_LEN + 16];
  uint16_t pos = build_header(msg, c->xid, 0u, net->mac);
  pos = opt_byte(msg, pos, OPT_MSG_TYPE, DHCP_MSG_DISCOVER);
  pos = build_prl(msg, pos, c->opt_table);
  msg[pos++] = OPT_END;
  uint16_t len = (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;

  /* REQ-DHCPv4-015: src_ip must be 0.0.0.0 before address assignment */
  uint32_t saved = net->ipv4_addr;
  net->ipv4_addr = 0u;
  udp_send(net, BCAST_IP, BCAST_MAC, 68, 67, msg, len);
  net->ipv4_addr = saved;
}

/* Send DHCPREQUEST — REQ-DHCPv4-022..027 */
static void send_request(net_t *net, dhcpv4_client_t *c) {
  uint8_t msg[DHCP_MIN_LEN + 24];
  uint32_t ciaddr = 0u;
  uint32_t dst_ip = BCAST_IP;
  const uint8_t *dst_mac = BCAST_MAC;

  if (c->state == DHCPV4_CLI_RENEWING) {
    /* REQ-DHCPv4-026: unicast to server; ciaddr = current IP */
    ciaddr = net->ipv4_addr;
    dst_ip = c->server_ip;
  } else if (c->state == DHCPV4_CLI_REBINDING) {
    /* REQ-DHCPv4-027: broadcast; ciaddr = current IP */
    ciaddr = net->ipv4_addr;
  }

  uint16_t pos = build_header(msg, c->xid, ciaddr, net->mac);
  pos = opt_byte(msg, pos, OPT_MSG_TYPE, DHCP_MSG_REQUEST);
  pos = opt_u32(msg, pos, OPT_SERVER_ID, c->server_ip); /* REQ-DHCPv4-023 */
  if (c->state == DHCPV4_CLI_REQUESTING) {
    /* REQ-DHCPv4-024,025: include Requested IP; ciaddr must stay 0 */
    pos = opt_u32(msg, pos, OPT_REQUESTED_IP, c->offered_ip);
  }
  pos = build_prl(msg, pos, c->opt_table);
  msg[pos++] = OPT_END;
  uint16_t len = (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;

  uint32_t saved = net->ipv4_addr;
  if (c->state == DHCPV4_CLI_REQUESTING)
    net->ipv4_addr = 0u;
  udp_send(net, dst_ip, dst_mac, 68, 67, msg, len);
  if (c->state == DHCPV4_CLI_REQUESTING)
    net->ipv4_addr = saved;
}

/* Parse DHCPACK options, apply to net_t, invoke app handlers.
   REQ-DHCPv4-028..036, REQ-DHCPv4-053..055 */
static void process_ack_options(net_t *net, dhcpv4_client_t *c,
                                const uint8_t *opts, uint16_t len) {
  uint16_t i = 0;
  while (i < len) {
    uint8_t code = opts[i++];
    if (code == OPT_END)
      break;
    if (code == OPT_PAD)
      continue;
    if (i >= len)
      break;
    uint8_t olen = opts[i++];
    if (i + olen > len)
      break;

    switch (code) {
    case OPT_SUBNET_MASK:
      if (olen >= 4)
        net->subnet_mask = net_read32be(opts + i);
      break;
    case OPT_ROUTER:
      if (olen >= 4)
        net->gateway_ipv4 = net_read32be(opts + i);
      break;
    case OPT_LEASE_TIME:
      if (olen >= 4)
        c->lease_time = net_read32be(opts + i);
      break;
    case OPT_T1:
      if (olen >= 4)
        c->t1 = net_read32be(opts + i);
      break;
    case OPT_T2:
      if (olen >= 4)
        c->t2 = net_read32be(opts + i);
      break;
    case OPT_SERVER_ID:
      if (olen >= 4)
        c->server_ip = net_read32be(opts + i);
      break;
    default:
      break;
    }

    /* Invoke registered app handler — REQ-DHCPv4-053, 056 */
    if (c->opt_table) {
      for (uint8_t j = 0; j < c->opt_table->count; j++) {
        if (c->opt_table->entries[j].option == code) {
          c->opt_table->entries[j].handler(code, opts + i, olen,
                                           c->opt_table->entries[j].ctx);
          break;
        }
      }
    }
    i += olen;
  }

  /* REQ-DHCPv4-035: default T1 = 0.5 × lease */
  if (c->t1 == 0 && c->lease_time > 0)
    c->t1 = c->lease_time / 2u;
  /* REQ-DHCPv4-036: default T2 = 0.875 × lease (= lease - lease/8) */
  if (c->t2 == 0 && c->lease_time > 0)
    c->t2 = c->lease_time - (c->lease_time / 8u);
}

/* Transition to BOUND, arm T1 timer */
static void enter_bound(net_t *net, dhcpv4_client_t *c, uint8_t renewal) {
  (void)net;
  c->state = DHCPV4_CLI_BOUND;
  c->retries = 0;
  c->timer_ms = (uint32_t)c->t1 * 1000u;
  fire_event(c, renewal ? DHCPV4_EVT_RENEWED : DHCPV4_EVT_BOUND);
}

/* Deconfigure IP and restart discovery */
static void restart_init(net_t *net, dhcpv4_client_t *c) {
  net->ipv4_addr = 0u;
  net->subnet_mask = 0u;
  net->gateway_ipv4 = 0u;
  c->xid = rand_xid();
  c->state = DHCPV4_CLI_SELECTING;
  c->retries = 0;
  send_discover(net, c);
  c->timer_ms = RETRY_INIT_MS;
}

/* ════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════ */

void dhcpv4_client_init(dhcpv4_client_t *c, dhcpv4_event_fn_t on_event,
                        void *evt_ctx, const dhcpv4_opt_table_t *opts) {
  memset(c, 0, sizeof(*c));
  c->on_event = on_event;
  c->evt_ctx = evt_ctx;
  c->opt_table = opts;
}

void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c) {
  c->xid = rand_xid();
  c->state = DHCPV4_CLI_SELECTING;
  c->retries = 0;
  c->timer_ms = 0;
  send_discover(net, c);
  c->timer_ms = RETRY_INIT_MS;
}

void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms) {
  if (c->state == DHCPV4_CLI_INIT || c->timer_ms == 0)
    return;

  if (ms >= c->timer_ms) {
    c->timer_ms = 0;
  } else {
    c->timer_ms -= ms;
    return;
  }

  switch (c->state) {

  case DHCPV4_CLI_SELECTING:
    /* REQ-DHCPv4-045: retransmit DISCOVER with exponential backoff */
    c->xid = rand_xid();
    send_discover(net, c);
    c->timer_ms = next_retry_ms(c->retries);
    if (c->retries < 255u)
      c->retries++;
    break;

  case DHCPV4_CLI_REQUESTING:
    send_request(net, c);
    c->timer_ms = next_retry_ms(c->retries);
    if (c->retries < 255u)
      c->retries++;
    break;

  case DHCPV4_CLI_BOUND:
    /* REQ-DHCPv4-005: T1 expired → start RENEWING */
    c->state = DHCPV4_CLI_RENEWING;
    c->retries = 0;
    /* Arm timer for half of remaining time (T2-T1)/2 */
    c->timer_ms = ((c->t2 > c->t1) ? (c->t2 - c->t1) : 1u) / 2u * 1000u;
    if (c->timer_ms == 0)
      c->timer_ms = 1000u;
    send_request(net, c);
    break;

  case DHCPV4_CLI_RENEWING:
    /* REQ-DHCPv4-006: T2 expired → REBINDING */
    c->state = DHCPV4_CLI_REBINDING;
    c->retries = 0;
    c->timer_ms =
        ((c->lease_time > c->t2) ? (c->lease_time - c->t2) : 1u) / 2u * 1000u;
    if (c->timer_ms == 0)
      c->timer_ms = 1000u;
    send_request(net, c);
    break;

  case DHCPV4_CLI_REBINDING:
    /* REQ-DHCPv4-007: lease expired */
    fire_event(c, DHCPV4_EVT_EXPIRED);
    restart_init(net, c);
    break;

  default:
    break;
  }
}

void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *data, uint16_t len) {
  (void)src_ip;

  /* REQ-DHCPv4-018: validate op, magic, xid */
  if (len < (uint16_t)(DHCP_OFF_OPTIONS + 4))
    return;
  if (data[DHCP_OFF_OP] != DHCP_OP_REPLY)
    return;
  if (net_read32be(data + DHCP_OFF_MAGIC) != DHCP_MAGIC)
    return;
  if (net_read32be(data + DHCP_OFF_XID) != c->xid)
    return;

  /* Extract message type from options — REQ-DHCPv4-041..044 */
  uint8_t msg_type = 0;
  uint16_t i = DHCP_OFF_OPTIONS;
  while (i < len) {
    uint8_t code = data[i++];
    if (code == OPT_END)
      break;
    if (code == OPT_PAD)
      continue;
    if (i >= len)
      break;
    uint8_t olen = data[i++];
    if (code == OPT_MSG_TYPE && olen >= 1)
      msg_type = data[i];
    i += olen;
  }
  if (msg_type == 0)
    return;

  uint32_t yiaddr = net_read32be(data + DHCP_OFF_YIADDR);

  switch (msg_type) {

  case DHCP_MSG_OFFER:
    /* REQ-DHCPv4-019..021: accept first offer in SELECTING */
    if (c->state != DHCPV4_CLI_SELECTING)
      return;
    c->offered_ip = yiaddr;
    /* Extract server ID */
    {
      uint16_t j = DHCP_OFF_OPTIONS;
      while (j < len) {
        uint8_t code = data[j++];
        if (code == OPT_END)
          break;
        if (code == OPT_PAD)
          continue;
        if (j >= len)
          break;
        uint8_t olen2 = data[j++];
        if (code == OPT_SERVER_ID && olen2 >= 4)
          c->server_ip = net_read32be(data + j);
        j += olen2;
      }
    }
    c->state = DHCPV4_CLI_REQUESTING;
    c->retries = 0;
    send_request(net, c);
    c->timer_ms = RETRY_INIT_MS;
    break;

  case DHCP_MSG_ACK:
    /* REQ-DHCPv4-028..036 */
    if (c->state != DHCPV4_CLI_REQUESTING && c->state != DHCPV4_CLI_RENEWING &&
        c->state != DHCPV4_CLI_REBINDING)
      return;
    net->ipv4_addr = yiaddr; /* REQ-DHCPv4-029 */
    c->t1 = c->t2 = 0;
    process_ack_options(net, c, data + DHCP_OFF_OPTIONS,
                        len - DHCP_OFF_OPTIONS);
    {
      uint8_t renewal =
          (c->state == DHCPV4_CLI_RENEWING || c->state == DHCPV4_CLI_REBINDING);
      enter_bound(net, c, renewal);
    }
    break;

  case DHCP_MSG_NAK:
    /* REQ-DHCPv4-037..038 */
    if (c->state != DHCPV4_CLI_REQUESTING && c->state != DHCPV4_CLI_RENEWING &&
        c->state != DHCPV4_CLI_REBINDING)
      return;
    fire_event(c, DHCPV4_EVT_NAK);
    restart_init(net, c);
    break;

  default:
    break;
  }
}

void dhcpv4_client_release(net_t *net, dhcpv4_client_t *c) {
  if (c->state != DHCPV4_CLI_BOUND && c->state != DHCPV4_CLI_RENEWING &&
      c->state != DHCPV4_CLI_REBINDING)
    return;

  /* REQ-DHCPv4-039..040: unicast DHCPRELEASE to server */
  uint8_t msg[DHCP_MIN_LEN + 8];
  uint16_t pos = build_header(msg, c->xid, net->ipv4_addr, net->mac);
  net_write16be(msg + DHCP_OFF_FLAGS, 0u); /* no broadcast flag */
  pos = opt_byte(msg, pos, OPT_MSG_TYPE, DHCP_MSG_RELEASE);
  pos = opt_u32(msg, pos, OPT_SERVER_ID, c->server_ip);
  msg[pos++] = OPT_END;
  uint16_t len = (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;

  udp_send(net, c->server_ip, BCAST_MAC, 68, 67, msg, len);

  net->ipv4_addr = 0u;
  net->subnet_mask = 0u;
  net->gateway_ipv4 = 0u;
  c->state = DHCPV4_CLI_INIT;
  c->timer_ms = 0u;
}
