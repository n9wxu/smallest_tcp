/**
 * @file dhcpv4_client.c
 * @brief DHCPv4 client (RFC 2131).  REQ-DHCPv4-001..059.
 */

#include "dhcpv4_client.h"
#include "dhcpv4_wire.h"
#include "ipv4.h"

/* REQ-DHCPv4-045, 046: 4, 8, 16, 32, then 64 s, each ±1 s (RFC 2131 §4.1) */
#define RETRANSMIT_FIRST_MS 4000u
#define RETRANSMIT_MAX_MS 64000u
#define RETRANSMIT_JITTER_MS 1000u
/* RFC 2131 §3.1, §4.4.1: then discovery starts again */
#define REQUEST_RETRANSMITS 4u
/* RFC 2131 §4.4.5: the least wait between renewing or rebinding REQUESTs */
#define EXTEND_WAIT_MIN_S 60u

#define PARAM_REQUEST_MAX 35

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static void fire_event(dhcpv4_client_t *c, uint8_t evt) {
  if (c->on_event)
    c->on_event(evt, c->evt_ctx);
}

static uint32_t retransmit_wait_ms(net_t *net, uint8_t retries) {
  uint32_t ms = RETRANSMIT_FIRST_MS;
  while (retries-- > 0 && ms < RETRANSMIT_MAX_MS)
    ms *= 2u;
  return ms - RETRANSMIT_JITTER_MS +
         net_random_below(net, 2u * RETRANSMIT_JITTER_MS + 1u);
}

/* REQ-DHCPv4-059: the built-in parameters, then the application's */
static uint16_t put_param_request_list(uint8_t *msg, uint16_t pos,
                                       const dhcpv4_opt_table_t *opts) {
  uint8_t n = 0, i;
  msg[pos] = DHCP_OPT_PARAM_REQ;
  msg[pos + 2 + n++] = DHCP_OPT_SUBNET_MASK;
  msg[pos + 2 + n++] = DHCP_OPT_ROUTER;
  msg[pos + 2 + n++] = DHCP_OPT_LEASE_TIME;
  for (i = 0; opts && i < opts->count && n < PARAM_REQUEST_MAX; i++)
    msg[pos + 2 + n++] = opts->entries[i].option;
  msg[pos + 1] = n;
  return (uint16_t)(pos + 2 + n);
}

static int holds_lease(const dhcpv4_client_t *c) {
  return c->state == DHCPV4_CLI_BOUND || c->state == DHCPV4_CLI_RENEWING ||
         c->state == DHCPV4_CLI_REBINDING;
}

/* Our address as a DHCP message source: none until the server ACKs it */
static uint32_t client_address(const net_t *net, const dhcpv4_client_t *c) {
  return holds_lease(c) ? net->ipv4_addr : 0u;
}

/* REQ-DHCPv4-002, 008..017 */
static void send_discover(net_t *net, dhcpv4_client_t *c) {
  uint8_t *msg = dhcp_begin(net, DHCP_OP_REQUEST, c->xid, net->mac);
  uint16_t pos = DHCP_OFF_OPTIONS;
  if (!msg)
    return;
  net_write16be(msg + DHCP_OFF_FLAGS, DHCP_FLAG_BROADCAST);
  pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, DHCP_MSG_DISCOVER);
  pos = put_param_request_list(msg, pos, c->opt_table);
  udp_send_inplace_from(net, 0u, IPV4_BROADCAST, broadcast_mac,
                        DHCP_CLIENT_PORT, DHCP_SERVER_PORT, dhcp_end(msg, pos),
                        NET_DEFAULT_TTL);
}

/* REQ-DHCPv4-022..027: selecting an offer (broadcast, naming the server and
 * the address), or extending the lease — to our server (RENEWING) or any
 * (REBINDING), naming neither (RFC 2131 §4.3.2) */
static void send_request(net_t *net, dhcpv4_client_t *c) {
  uint8_t *msg = dhcp_begin(net, DHCP_OP_REQUEST, c->xid, net->mac);
  uint16_t pos = DHCP_OFF_OPTIONS;
  uint32_t src = client_address(net, c);
  int to_server = c->state == DHCPV4_CLI_RENEWING;
  if (!msg)
    return;
  net_write16be(msg + DHCP_OFF_FLAGS, DHCP_FLAG_BROADCAST);
  net_write32be(msg + DHCP_OFF_CIADDR, src);
  pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, DHCP_MSG_REQUEST);
  if (c->state == DHCPV4_CLI_REQUESTING) {
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, c->server_ip);
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_REQUESTED_IP, c->offered_ip);
  }
  pos = put_param_request_list(msg, pos, c->opt_table);
  udp_send_inplace_from(net, src, to_server ? c->server_ip : IPV4_BROADCAST,
                        to_server ? c->server_mac : broadcast_mac,
                        DHCP_CLIENT_PORT, DHCP_SERVER_PORT, dhcp_end(msg, pos),
                        NET_DEFAULT_TTL);
}

/* REQ-DHCPv4-053..056 */
static void run_option_handlers(const dhcpv4_client_t *c, uint8_t code,
                                const uint8_t *data, uint8_t len) {
  uint8_t i;
  for (i = 0; c->opt_table && i < c->opt_table->count; i++) {
    const dhcpv4_opt_entry_t *e = &c->opt_table->entries[i];
    if (e->option == code) {
      e->handler(code, data, len, e->ctx);
      return;
    }
  }
}

/* REQ-DHCPv4-028..036: the lease's parameters, applied to net_t */
static void take_lease(net_t *net, dhcpv4_client_t *c, const uint8_t *msg,
                       uint16_t len) {
  uint16_t pos = DHCP_OFF_OPTIONS;
  const uint8_t *v;
  uint8_t code, olen;

  net->ipv4_addr = net_read32be(msg + DHCP_OFF_YIADDR);
  c->t1 = c->t2 = 0;
  while ((code = dhcp_next_option(msg, len, &pos, &v, &olen)) != DHCP_OPT_END) {
    uint32_t value = olen >= 4 ? net_read32be(v) : 0;
    if (olen >= 4) {
      switch (code) {
      case DHCP_OPT_SUBNET_MASK:
        net->subnet_mask = value;
        break;
      case DHCP_OPT_ROUTER:
        net->gateway_ipv4 = value;
        break;
      case DHCP_OPT_LEASE_TIME:
        c->lease_time = value;
        break;
      case DHCP_OPT_T1:
        c->t1 = value;
        break;
      case DHCP_OPT_T2:
        c->t2 = value;
        break;
      case DHCP_OPT_SERVER_ID:
        c->server_ip = value;
        break;
      default:
        break;
      }
    }
    run_option_handlers(c, code, v, olen);
  }
  if (c->t1 == 0) /* REQ-DHCPv4-035: 0.5 × lease */
    c->t1 = c->lease_time / 2u;
  if (c->t2 == 0) /* REQ-DHCPv4-036: 0.875 × lease */
    c->t2 = c->lease_time - c->lease_time / 8u;
  c->since_s = 0u;
  c->sec_ms = 0u;
  c->next_request_s = c->t1;
}

static void clear_address(net_t *net) {
  net->ipv4_addr = 0u;
  net->subnet_mask = 0u;
  net->gateway_ipv4 = 0u;
}

/* The state's DISCOVER or REQUEST, and the wait for an answer */
static void transmit(net_t *net, dhcpv4_client_t *c) {
  if (c->state == DHCPV4_CLI_SELECTING)
    send_discover(net, c);
  else
    send_request(net, c);
  c->timer_ms = retransmit_wait_ms(net, c->retries);
}

static void begin_exchange(net_t *net, dhcpv4_client_t *c, uint8_t state) {
  c->state = state;
  c->retries = 0;
  transmit(net, c);
}

static void start_selecting(net_t *net, dhcpv4_client_t *c) {
  c->xid = net_random(net);
  begin_exchange(net, c, DHCPV4_CLI_SELECTING);
}

/* REQ-DHCPv4-045 */
static void retransmit(net_t *net, dhcpv4_client_t *c) {
  if (c->state == DHCPV4_CLI_REQUESTING && c->retries == REQUEST_RETRANSMITS) {
    start_selecting(net, c);
    return;
  }
  if (c->retries < 255u)
    c->retries++;
  transmit(net, c);
}

/* REQ-DHCPv4-007, 037, 038 */
static void lose_address(net_t *net, dhcpv4_client_t *c, uint8_t evt) {
  fire_event(c, evt);
  clear_address(net);
  start_selecting(net, c);
}

/* An infinite lease (RFC 2131 §3.3), or one of unknown length */
static int lease_is_endless(const dhcpv4_client_t *c) {
  return c->lease_time == DHCP_LEASE_INFINITE || c->lease_time == 0u;
}

/* The state the lease's age calls for (RFC 2131 §4.4.5) */
static uint8_t lease_phase(const dhcpv4_client_t *c) {
  if (c->since_s >= c->t2)
    return DHCPV4_CLI_REBINDING;
  return c->since_s >= c->t1 ? DHCPV4_CLI_RENEWING : DHCPV4_CLI_BOUND;
}

/* REQ-DHCPv4-026, 027: again after half the time left, at least 60 s later
 * (RFC 2131 §4.4.5) */
static void request_extension(net_t *net, dhcpv4_client_t *c) {
  uint32_t deadline_s = c->state == DHCPV4_CLI_RENEWING ? c->t2 : c->lease_time;
  uint32_t left_s = deadline_s - c->since_s;
  uint32_t wait_s =
      left_s / 2u > EXTEND_WAIT_MIN_S ? left_s / 2u : EXTEND_WAIT_MIN_S;
  send_request(net, c);
  c->next_request_s = wait_s < left_s ? c->since_s + wait_s : deadline_s;
}

static void lease_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms) {
  uint8_t phase;
  c->since_s += net_whole_seconds(&c->sec_ms, ms);
  if (c->since_s >= c->lease_time) {
    lose_address(net, c, DHCPV4_EVT_EXPIRED);
    return;
  }
  phase = lease_phase(c);
  if (phase != c->state || c->since_s >= c->next_request_s) {
    c->state = phase;
    request_extension(net, c);
  }
}

/* REQ-DHCPv4-050, 051 */
net_err_t dhcpv4_client_init(dhcpv4_client_t *c, const net_t *net,
                             dhcpv4_client_event_fn_t on_event, void *evt_ctx,
                             const dhcpv4_opt_table_t *opts) {
  if (!c || !net)
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < DHCPV4_CLIENT_TX_MIN ||
      net->rx.capacity < DHCPV4_CLIENT_RX_MIN)
    return NET_ERR_BUF_TOO_SMALL;
  memset(c, 0, sizeof(*c));
  c->on_event = on_event;
  c->evt_ctx = evt_ctx;
  c->opt_table = opts;
  return NET_OK;
}

void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c) {
  start_selecting(net, c);
}

/* REQ-DHCPv4-005..007, 045..047 */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms) {
  if (c->state == DHCPV4_CLI_SELECTING || c->state == DHCPV4_CLI_REQUESTING) {
    if (net_countdown(&c->timer_ms, ms))
      retransmit(net, c);
  } else if (holds_lease(c) && !lease_is_endless(c)) {
    lease_tick(net, c, ms);
  }
}

static int awaiting_ack(const dhcpv4_client_t *c) {
  return c->state == DHCPV4_CLI_REQUESTING || c->state == DHCPV4_CLI_RENEWING ||
         c->state == DHCPV4_CLI_REBINDING;
}

/* REQ-DHCPv4-018..038, 041..044 */
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  (void)src_ip;
  if (len < DHCP_OFF_OPTIONS + 4 || data[DHCP_OFF_OP] != DHCP_OP_REPLY ||
      net_read32be(data + DHCP_OFF_MAGIC) != DHCP_MAGIC ||
      net_read32be(data + DHCP_OFF_XID) != c->xid)
    return;

  switch (dhcp_message_type(data, len)) {
  case DHCP_MSG_OFFER: /* the first offer is taken */
    if (c->state != DHCPV4_CLI_SELECTING)
      return;
    c->offered_ip = net_read32be(data + DHCP_OFF_YIADDR);
    c->server_ip = dhcp_option_u32(data, len, DHCP_OPT_SERVER_ID, c->server_ip);
    begin_exchange(net, c, DHCPV4_CLI_REQUESTING);
    break;
  case DHCP_MSG_ACK:
    if (awaiting_ack(c)) {
      int renewal = c->state != DHCPV4_CLI_REQUESTING;
      take_lease(net, c, data, len);
      memcpy(c->server_mac, src_mac, 6);
      c->state = DHCPV4_CLI_BOUND;
      fire_event(c, renewal ? DHCPV4_EVT_RENEWED : DHCPV4_EVT_BOUND);
    }
    break;
  case DHCP_MSG_NAK:
    if (awaiting_ack(c))
      lose_address(net, c, DHCPV4_EVT_NAK);
    break;
  default:
    break;
  }
}

/* REQ-DHCPv4-039, 040 */
void dhcpv4_client_release(net_t *net, dhcpv4_client_t *c) {
  uint8_t *msg;
  uint16_t pos = DHCP_OFF_OPTIONS;
  if (!holds_lease(c))
    return;
  msg = dhcp_begin(net, DHCP_OP_REQUEST, c->xid, net->mac);
  if (msg) {
    net_write32be(msg + DHCP_OFF_CIADDR, net->ipv4_addr);
    pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, DHCP_MSG_RELEASE);
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, c->server_ip);
    udp_send_inplace(net, c->server_ip, c->server_mac, DHCP_CLIENT_PORT,
                     DHCP_SERVER_PORT, dhcp_end(msg, pos), NET_DEFAULT_TTL);
  }
  clear_address(net);
  c->state = DHCPV4_CLI_INIT;
}
