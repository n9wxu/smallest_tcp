/**
 * @file dhcpv4_server.c
 * @brief DHCPv4 server for a single client (RFC 2131): one address for one
 *        client, no timers.  REQ-DHCPv4-060..078, 085..087, 090, 096..100.
 */

#include "dhcpv4_server.h"
#include "dhcpv4_wire.h"
#include "ipv4.h"

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* A request, its length, and the source MAC of its frame */
typedef struct {
  const uint8_t *msg;
  uint16_t len;
  const uint8_t *src_mac;
} request_t;

typedef struct {
  uint32_t ip;
  const uint8_t *mac;
  uint16_t port;
} destination_t;

static void fire_event(const dhcpv4_server_t *s, uint8_t evt) {
  if (s->on_event)
    s->on_event(evt, s->evt_ctx);
}

/* The parameters a reply may carry: a bit each, and their values (0: not
 * configured, left out — but for the mask, always sent) */
static uint8_t parameter_bit(uint8_t code) {
  switch (code) {
  case DHCP_OPT_LEASE_TIME:
    return 1u;
  case DHCP_OPT_SUBNET_MASK:
    return 2u;
  case DHCP_OPT_ROUTER:
    return 4u;
  case DHCP_OPT_DNS:
    return 8u;
  default:
    return 0u;
  }
}

static uint32_t parameter_value(const dhcpv4_server_cfg_t *cfg, uint8_t code) {
  switch (code) {
  case DHCP_OPT_LEASE_TIME:
    return cfg->lease_time_s ? cfg->lease_time_s : DHCP_LEASE_INFINITE;
  case DHCP_OPT_SUBNET_MASK:
    return cfg->subnet_mask;
  case DHCP_OPT_ROUTER:
    return cfg->gateway;
  default:
    return cfg->dns;
  }
}

/* REQ-DHCPv4-097, 098: parameter @p code if the server has it and it is
 * not in yet (@p *put) — the Subnet Mask first if it is the Router (RFC
 * 2132 §3.3) */
static uint16_t put_parameter(uint8_t *msg, uint16_t pos,
                              const dhcpv4_server_cfg_t *cfg, uint8_t code,
                              uint8_t *put) {
  uint8_t bit = parameter_bit(code);
  uint32_t v = parameter_value(cfg, code);
  if (code == DHCP_OPT_ROUTER)
    pos = put_parameter(msg, pos, cfg, DHCP_OPT_SUBNET_MASK, put);
  if (!bit || (*put & bit) || (v == 0u && code != DHCP_OPT_SUBNET_MASK))
    return pos;
  *put |= bit;
  return dhcp_put_u32(msg, pos, code, v);
}

/* REQ-DHCPv4-065..067, 090: the parameters the client asked for, in the
 * order of its Parameter Request List (RFC 2132 §9.8, its parts joined),
 * then the rest; the lease only with an address (RFC 2131 §4.3.5) */
static uint16_t put_parameters(uint8_t *msg, uint16_t pos,
                               const dhcpv4_server_cfg_t *cfg,
                               const request_t *rq, int with_lease) {
  static const uint8_t all[] = {DHCP_OPT_LEASE_TIME, DHCP_OPT_SUBNET_MASK,
                                DHCP_OPT_ROUTER, DHCP_OPT_DNS};
  uint8_t put = with_lease ? 0u : parameter_bit(DHCP_OPT_LEASE_TIME);
  dhcp_walk_t w;
  const uint8_t *v;
  uint8_t code, n, i;
  dhcp_walk_begin(&w, rq->msg, rq->len);
  while ((code = dhcp_walk_next(&w, &v, &n)) != DHCP_OPT_END)
    for (i = 0; code == DHCP_OPT_PARAM_REQ && i < n; i++)
      pos = put_parameter(msg, pos, cfg, v[i], &put);
  for (i = 0; i < sizeof(all); i++)
    pos = put_parameter(msg, pos, cfg, all[i], &put);
  return pos;
}

/* REQ-DHCPv4-076, 077; RFC 2131 §4.1: through the relay agent that
 * forwarded the request, on the server port; else a NAK to everyone; else
 * to the client's address, the broadcast address if it asked for it, or
 * the address it is given, at its hardware address */
static destination_t reply_destination(const request_t *rq, uint8_t msg_type,
                                       uint32_t yiaddr) {
  destination_t d = {IPV4_BROADCAST, broadcast_mac, DHCP_CLIENT_PORT};
  uint32_t giaddr = net_read32be(rq->msg + DHCP_OFF_GIADDR);
  uint32_t ciaddr = net_read32be(rq->msg + DHCP_OFF_CIADDR);
  int asked_broadcast =
      (net_read16be(rq->msg + DHCP_OFF_FLAGS) & DHCP_FLAG_BROADCAST) != 0;
  if (giaddr) {
    d.ip = giaddr;
    d.mac = rq->src_mac;
    d.port = DHCP_SERVER_PORT;
  } else if (msg_type == DHCP_MSG_NAK) {
    /* broadcast */
  } else if (ciaddr) {
    d.ip = ciaddr;
    d.mac = rq->src_mac;
  } else if (!asked_broadcast && yiaddr) {
    d.ip = yiaddr;
    d.mac = rq->msg + DHCP_OFF_CHADDR;
  }
  return d;
}

/* REQ-DHCPv4-071, 074, 075: the fields and options of RFC 2131 Table 3 —
 * the request's flags and giaddr copied; §4.3.2: a NAK through a relay
 * asks it to broadcast, since the client may have no usable address */
static void send_reply(net_t *net, const dhcpv4_server_cfg_t *cfg,
                       const request_t *rq, uint8_t msg_type,
                       uint32_t yiaddr) {
  const uint8_t *req = rq->msg;
  uint8_t *msg =
      dhcp_begin(net, DHCP_OP_REPLY, net_read32be(req + DHCP_OFF_XID),
                 req + DHCP_OFF_CHADDR);
  uint16_t pos = DHCP_OFF_OPTIONS;
  uint16_t flags = net_read16be(req + DHCP_OFF_FLAGS);
  destination_t to = reply_destination(rq, msg_type, yiaddr);
  if (!msg)
    return;
  if (msg_type == DHCP_MSG_NAK && to.port == DHCP_SERVER_PORT)
    flags |= DHCP_FLAG_BROADCAST;
  net_write16be(msg + DHCP_OFF_FLAGS, flags);
  memcpy(msg + DHCP_OFF_GIADDR, req + DHCP_OFF_GIADDR, 4);
  pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, msg_type);
  pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, cfg->server_ip);
  if (msg_type != DHCP_MSG_NAK) {
    if (msg_type == DHCP_MSG_ACK)
      memcpy(msg + DHCP_OFF_CIADDR, req + DHCP_OFF_CIADDR, 4);
    net_write32be(msg + DHCP_OFF_YIADDR, yiaddr);
    net_write32be(msg + DHCP_OFF_SIADDR, cfg->server_ip);
    pos = put_parameters(msg, pos, cfg, rq, yiaddr != 0u);
  }
  udp_send_inplace_from(net, cfg->server_ip, to.ip, to.mac, DHCP_SERVER_PORT,
                        to.port, dhcp_end(msg, pos), NET_DEFAULT_TTL);
}

/* REQ-DHCPv4-078 */
net_err_t dhcpv4_server_init(dhcpv4_server_t *s, const net_t *net,
                             const dhcpv4_server_cfg_t *cfg,
                             dhcpv4_server_event_fn_t on_event, void *evt_ctx) {
  if (!s || !net || !cfg || cfg->server_ip != net->ipv4_addr)
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < DHCPV4_SERVER_TX_MIN ||
      net->rx.capacity < DHCPV4_SERVER_RX_MIN)
    return NET_ERR_BUF_TOO_SMALL;
  memset(s, 0, sizeof(*s));
  s->cfg = cfg;
  s->on_event = on_event;
  s->evt_ctx = evt_ctx;
  return NET_OK;
}

/* REQ-DHCPv4-060: the client the address is kept for, known by its
 * chaddr (RFC 2131 §4.2) */
static int is_our_client(const dhcpv4_server_t *s, const uint8_t *msg) {
  return s->has_client && net_mac_equal(s->client_mac, msg + DHCP_OFF_CHADDR);
}

/* The address is available (REQ-DHCPv4-085), and free or this client's */
static int may_have_address(const dhcpv4_server_t *s, const uint8_t *msg) {
  return !s->declined && (!s->has_client || is_our_client(s, msg));
}

static void keep_client(dhcpv4_server_t *s, const uint8_t *msg) {
  memcpy(s->client_mac, msg + DHCP_OFF_CHADDR, 6);
  s->has_client = 1;
}

/* REQ-DHCPv4-086, 087; RFC 2131 §4.3.2: a REQUEST is ours to answer if it
 * selects us, or comes from our client — or renews our address while it
 * is no one's (the server was initialised again).  An INIT-REBOOT client
 * the server has no record of "MUST remain silent". */
static int ours_to_answer(const dhcpv4_server_t *s, const uint8_t *msg,
                          uint32_t server_id, uint32_t ciaddr) {
  if (server_id)
    return server_id == s->cfg->server_ip;
  return is_our_client(s, msg) ||
         (ciaddr == s->cfg->offered_ip && !s->has_client);
}

/* REQ-DHCPv4-068, 069, 086, 087 */
static void request_input(net_t *net, dhcpv4_server_t *s, const request_t *rq) {
  const dhcpv4_server_cfg_t *cfg = s->cfg;
  uint16_t len = rq->len;
  uint32_t server_id = dhcp_option_u32(rq->msg, len, DHCP_OPT_SERVER_ID, 0u);
  uint32_t ciaddr = net_read32be(rq->msg + DHCP_OFF_CIADDR);
  uint32_t requested =
      dhcp_option_u32(rq->msg, len, DHCP_OPT_REQUESTED_IP, ciaddr);
  if (server_id && server_id != cfg->server_ip && is_our_client(s, rq->msg))
    s->has_client = 0; /* it declined our offer: the address is free */
  if (!ours_to_answer(s, rq->msg, server_id, ciaddr))
    return;
  if (requested == cfg->offered_ip && may_have_address(s, rq->msg)) {
    keep_client(s, rq->msg);
    send_reply(net, cfg, rq, DHCP_MSG_ACK, cfg->offered_ip);
    fire_event(s, DHCPV4_SRV_EVT_ACK);
  } else {
    send_reply(net, cfg, rq, DHCP_MSG_NAK, 0u);
    fire_event(s, DHCPV4_SRV_EVT_NAK);
  }
}

/* REQ-DHCPv4-085; RFC 2131 §4.3.3: a client found the address in use —
 * "The server MUST mark the network address as not available" — and the
 * application is told, as the administrator SHOULD be */
static void decline_input(dhcpv4_server_t *s, const uint8_t *msg,
                          uint16_t len) {
  if (dhcp_option_u32(msg, len, DHCP_OPT_REQUESTED_IP, 0u) !=
          s->cfg->offered_ip ||
      dhcp_option_u32(msg, len, DHCP_OPT_SERVER_ID, 0u) != s->cfg->server_ip)
    return;
  s->declined = 1;
  s->has_client = 0;
  fire_event(s, DHCPV4_SRV_EVT_DECLINE);
}

/* REQ-DHCPv4-070; RFC 2131 §4.3.4: our client's address is free again */
static void release_input(dhcpv4_server_t *s, const uint8_t *msg) {
  if (is_our_client(s, msg) &&
      net_read32be(msg + DHCP_OFF_CIADDR) == s->cfg->offered_ip)
    s->has_client = 0;
}

/* REQ-DHCPv4-060, 064, 068..073 */
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  const dhcpv4_server_cfg_t *cfg = s->cfg;
  request_t rq;
  (void)src_ip;

  if (len < DHCP_OFF_OPTIONS + 4 || data[DHCP_OFF_OP] != DHCP_OP_REQUEST ||
      net_read32be(data + DHCP_OFF_MAGIC) != DHCP_MAGIC)
    return;
  rq.msg = data;
  rq.len = len;
  rq.src_mac = src_mac;

  switch (dhcp_message_type(data, len)) {
  case DHCP_MSG_DISCOVER: /* another client's address: nothing to offer */
    if (may_have_address(s, data)) {
      keep_client(s, data);
      send_reply(net, cfg, &rq, DHCP_MSG_OFFER, cfg->offered_ip);
      fire_event(s, DHCPV4_SRV_EVT_OFFER);
    }
    break;
  case DHCP_MSG_REQUEST:
    request_input(net, s, &rq);
    break;
  case DHCP_MSG_DECLINE:
    decline_input(s, data, len);
    break;
  case DHCP_MSG_RELEASE:
    release_input(s, data);
    break;
  case DHCP_MSG_INFORM: /* no address, so no lease */
    send_reply(net, cfg, &rq, DHCP_MSG_ACK, 0u);
    fire_event(s, DHCPV4_SRV_EVT_ACK);
    break;
  default:
    break;
  }
}
