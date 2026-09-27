/**
 * @file dhcpv4_server.c
 * @brief DHCPv4 server for a single, fixed client (RFC 2131): no lease
 *        table, no timers.  REQ-DHCPv4-060..078.
 */

#include "dhcpv4_server.h"
#include "dhcpv4_wire.h"
#include "ipv4.h"

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* A request, and the source MAC of its frame */
typedef struct {
  const uint8_t *msg;
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

/* REQ-DHCPv4-065..067: the lease — only with an address (RFC 2131 §4.3.5)
 * — and the configuration */
static uint16_t put_parameters(uint8_t *msg, uint16_t pos,
                               const dhcpv4_server_cfg_t *cfg, int with_lease) {
  if (with_lease)
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_LEASE_TIME,
                       cfg->lease_time_s ? cfg->lease_time_s
                                         : DHCP_LEASE_INFINITE);
  pos = dhcp_put_u32(msg, pos, DHCP_OPT_SUBNET_MASK, cfg->subnet_mask);
  if (cfg->gateway)
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_ROUTER, cfg->gateway);
  if (cfg->dns)
    pos = dhcp_put_u32(msg, pos, DHCP_OPT_DNS, cfg->dns);
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
    pos = put_parameters(msg, pos, cfg, yiaddr != 0u);
  }
  udp_send_inplace_from(net, cfg->server_ip, to.ip, to.mac, DHCP_SERVER_PORT,
                        to.port, dhcp_end(msg, pos), NET_DEFAULT_TTL);
}

/* REQ-DHCPv4-078 */
net_err_t dhcpv4_server_init(dhcpv4_server_t *s, const net_t *net,
                             const dhcpv4_server_cfg_t *cfg,
                             dhcpv4_server_event_fn_t on_event, void *evt_ctx) {
  if (!s || !net || !cfg)
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < DHCPV4_SERVER_TX_MIN ||
      net->rx.capacity < DHCPV4_SERVER_RX_MIN)
    return NET_ERR_BUF_TOO_SMALL;
  s->cfg = cfg;
  s->on_event = on_event;
  s->evt_ctx = evt_ctx;
  return NET_OK;
}

/* REQ-DHCPv4-064, 068..073 */
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  const dhcpv4_server_cfg_t *cfg = s->cfg;
  request_t rq;
  uint32_t requested;
  (void)src_ip;

  if (len < DHCP_OFF_OPTIONS + 4 || data[DHCP_OFF_OP] != DHCP_OP_REQUEST ||
      net_read32be(data + DHCP_OFF_MAGIC) != DHCP_MAGIC)
    return;
  rq.msg = data;
  rq.src_mac = src_mac;

  switch (dhcp_message_type(data, len)) {
  case DHCP_MSG_DISCOVER:
    send_reply(net, cfg, &rq, DHCP_MSG_OFFER, cfg->offered_ip);
    fire_event(s, DHCPV4_SRV_EVT_OFFER);
    break;
  case DHCP_MSG_REQUEST: /* renewing: the address is in ciaddr */
    requested = dhcp_option_u32(data, len, DHCP_OPT_REQUESTED_IP,
                                net_read32be(data + DHCP_OFF_CIADDR));
    if (requested == cfg->offered_ip) {
      send_reply(net, cfg, &rq, DHCP_MSG_ACK, cfg->offered_ip);
      fire_event(s, DHCPV4_SRV_EVT_ACK);
    } else {
      send_reply(net, cfg, &rq, DHCP_MSG_NAK, 0u);
      fire_event(s, DHCPV4_SRV_EVT_NAK);
    }
    break;
  case DHCP_MSG_INFORM: /* no address, so no lease */
    send_reply(net, cfg, &rq, DHCP_MSG_ACK, 0u);
    fire_event(s, DHCPV4_SRV_EVT_ACK);
    break;
  default: /* RELEASE needs nothing without a lease table */
    break;
  }
}
