/**
 * @file dhcpv4_client.c
 * @brief DHCPv4 client (RFC 2131).  REQ-DHCPv4-001..059.
 */

#include "dhcpv4_client.h"
#include "dhcpv4_wire.h"
#include "ipv4.h"

/* REQ-DHCPv4-045: retransmissions back off from 4 s to 64 s */
#define RETRY_INIT_MS 4000u
#define RETRY_MAX_MS 64000u

#define PARAM_REQUEST_MAX 35

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static void fire_event(dhcpv4_client_t *c, uint8_t evt) {
  if (c->on_event)
    c->on_event(evt, c->evt_ctx);
}

static uint32_t retry_interval_ms(uint8_t retries) {
  uint32_t t = RETRY_INIT_MS;
  while (retries-- > 0 && t < RETRY_MAX_MS)
    t *= 2u;
  return t > RETRY_MAX_MS ? RETRY_MAX_MS : t;
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

/* Our address as a DHCP message source: none until the server ACKs it */
static uint32_t client_address(const net_t *net, const dhcpv4_client_t *c) {
  int have_lease =
      c->state == DHCPV4_CLI_RENEWING || c->state == DHCPV4_CLI_REBINDING;
  return have_lease ? net->ipv4_addr : 0u;
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

/* REQ-DHCPv4-022..027: selecting an offer (broadcast, Requested IP), or
 * extending the lease — to our server (RENEWING) or any (REBINDING) */
static void send_request(net_t *net, dhcpv4_client_t *c) {
  uint8_t *msg = dhcp_begin(net, DHCP_OP_REQUEST, c->xid, net->mac);
  uint16_t pos = DHCP_OFF_OPTIONS;
  uint32_t src = client_address(net, c);
  uint32_t dst =
      c->state == DHCPV4_CLI_RENEWING ? c->server_ip : IPV4_BROADCAST;
  if (!msg)
    return;
  net_write16be(msg + DHCP_OFF_FLAGS, DHCP_FLAG_BROADCAST);
  net_write32be(msg + DHCP_OFF_CIADDR, src);
  pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, DHCP_MSG_REQUEST);
  pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, c->server_ip);
  if (c->state == DHCPV4_CLI_REQUESTING)
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_REQUESTED_IP, c->offered_ip);
  pos = put_param_request_list(msg, pos, c->opt_table);
  udp_send_inplace_from(net, src, dst, broadcast_mac, DHCP_CLIENT_PORT,
                        DHCP_SERVER_PORT, dhcp_end(msg, pos), NET_DEFAULT_TTL);
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
}

static void clear_address(net_t *net) {
  net->ipv4_addr = 0u;
  net->subnet_mask = 0u;
  net->gateway_ipv4 = 0u;
}

static void start_selecting(net_t *net, dhcpv4_client_t *c) {
  c->xid = net_random(net);
  c->state = DHCPV4_CLI_SELECTING;
  c->retries = 0;
  send_discover(net, c);
  c->timer_ms = RETRY_INIT_MS;
}

static void enter_state(net_t *net, dhcpv4_client_t *c, uint8_t state,
                        uint32_t timer_ms) {
  c->state = state;
  c->retries = 0;
  c->timer_ms = timer_ms;
  if (state == DHCPV4_CLI_REQUESTING || state == DHCPV4_CLI_RENEWING ||
      state == DHCPV4_CLI_REBINDING)
    send_request(net, c);
}

/* Half the time left until @p until_s, from @p since_s (RFC 2131 §4.4.5),
 * at least a second */
static uint32_t half_remaining_ms(uint32_t since_s, uint32_t until_s) {
  uint32_t ms = (until_s > since_s ? until_s - since_s : 1u) / 2u * 1000u;
  return ms ? ms : 1000u;
}

void dhcpv4_client_init(dhcpv4_client_t *c, dhcpv4_client_event_fn_t on_event,
                        void *evt_ctx, const dhcpv4_opt_table_t *opts) {
  memset(c, 0, sizeof(*c));
  c->on_event = on_event;
  c->evt_ctx = evt_ctx;
  c->opt_table = opts;
}

void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c) {
  start_selecting(net, c);
}

/* REQ-DHCPv4-005..007, 045..047 */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms) {
  if (c->state == DHCPV4_CLI_INIT || c->timer_ms == 0 ||
      !net_countdown(&c->timer_ms, ms))
    return;

  switch (c->state) {
  case DHCPV4_CLI_SELECTING: /* the xid stays for the retransmissions */
  case DHCPV4_CLI_REQUESTING:
    if (c->state == DHCPV4_CLI_SELECTING)
      send_discover(net, c);
    else
      send_request(net, c);
    c->timer_ms = retry_interval_ms(c->retries);
    if (c->retries < 255u)
      c->retries++;
    break;
  case DHCPV4_CLI_BOUND: /* T1 */
    enter_state(net, c, DHCPV4_CLI_RENEWING, half_remaining_ms(c->t1, c->t2));
    break;
  case DHCPV4_CLI_RENEWING: /* T2 */
    enter_state(net, c, DHCPV4_CLI_REBINDING,
                half_remaining_ms(c->t2, c->lease_time));
    break;
  case DHCPV4_CLI_REBINDING: /* the lease ran out */
    fire_event(c, DHCPV4_EVT_EXPIRED);
    clear_address(net);
    start_selecting(net, c);
    break;
  default:
    break;
  }
}

static int awaiting_ack(const dhcpv4_client_t *c) {
  return c->state == DHCPV4_CLI_REQUESTING || c->state == DHCPV4_CLI_RENEWING ||
         c->state == DHCPV4_CLI_REBINDING;
}

/* REQ-DHCPv4-018..038, 041..044 */
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *data, uint16_t len) {
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
    enter_state(net, c, DHCPV4_CLI_REQUESTING, RETRY_INIT_MS);
    break;
  case DHCP_MSG_ACK:
    if (awaiting_ack(c)) {
      int renewal = c->state != DHCPV4_CLI_REQUESTING;
      take_lease(net, c, data, len);
      enter_state(net, c, DHCPV4_CLI_BOUND, c->t1 * 1000u);
      fire_event(c, renewal ? DHCPV4_EVT_RENEWED : DHCPV4_EVT_BOUND);
    }
    break;
  case DHCP_MSG_NAK:
    if (awaiting_ack(c)) {
      fire_event(c, DHCPV4_EVT_NAK);
      clear_address(net);
      start_selecting(net, c);
    }
    break;
  default:
    break;
  }
}

/* REQ-DHCPv4-039, 040 */
void dhcpv4_client_release(net_t *net, dhcpv4_client_t *c) {
  uint8_t *msg;
  uint16_t pos = DHCP_OFF_OPTIONS;
  if (c->state != DHCPV4_CLI_BOUND && c->state != DHCPV4_CLI_RENEWING &&
      c->state != DHCPV4_CLI_REBINDING)
    return;
  msg = dhcp_begin(net, DHCP_OP_REQUEST, c->xid, net->mac);
  if (msg) {
    net_write32be(msg + DHCP_OFF_CIADDR, net->ipv4_addr);
    pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, DHCP_MSG_RELEASE);
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, c->server_ip);
    udp_send_inplace(net, c->server_ip, broadcast_mac, DHCP_CLIENT_PORT,
                     DHCP_SERVER_PORT, dhcp_end(msg, pos), NET_DEFAULT_TTL);
  }
  clear_address(net);
  c->state = DHCPV4_CLI_INIT;
  c->timer_ms = 0u;
}
