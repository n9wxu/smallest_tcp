/**
 * @file dhcpv4_server.c
 * @brief DHCPv4 server for a single, fixed client (RFC 2131): no lease
 *        table, no timers.  REQ-DHCPv4-060..078.
 */

#include "dhcpv4_server.h"
#include "dhcpv4_wire.h"
#include "ipv4.h"

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

typedef struct {
  const uint8_t *request;
  uint32_t dst_ip;
  const uint8_t *dst_mac;
} reply_to_t;

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

/* REQ-DHCPv4-071, 074, 075: the fields and options of RFC 2131 Table 3 */
static void send_reply(net_t *net, const dhcpv4_server_cfg_t *cfg,
                       const reply_to_t *to, uint8_t msg_type,
                       uint32_t yiaddr) {
  const uint8_t *req = to->request;
  uint8_t *msg =
      dhcp_begin(net, DHCP_OP_REPLY, net_read32be(req + DHCP_OFF_XID),
                 req + DHCP_OFF_CHADDR);
  uint16_t pos = DHCP_OFF_OPTIONS;
  if (!msg)
    return;
  net_write16be(msg + DHCP_OFF_FLAGS, DHCP_FLAG_BROADCAST);
  pos = dhcp_put_u8(msg, pos, DHCP_OPT_MSG_TYPE, msg_type);
  pos = dhcp_put_u32(msg, pos, DHCP_OPT_SERVER_ID, cfg->server_ip);
  if (msg_type != DHCP_MSG_NAK) {
    if (msg_type == DHCP_MSG_ACK)
      memcpy(msg + DHCP_OFF_CIADDR, req + DHCP_OFF_CIADDR, 4);
    net_write32be(msg + DHCP_OFF_YIADDR, yiaddr);
    net_write32be(msg + DHCP_OFF_SIADDR, cfg->server_ip);
    pos = put_parameters(msg, pos, cfg, yiaddr != 0u);
  }
  udp_send_inplace_from(net, cfg->server_ip, to->dst_ip, to->dst_mac,
                        DHCP_SERVER_PORT, DHCP_CLIENT_PORT, dhcp_end(msg, pos),
                        NET_DEFAULT_TTL);
}

void dhcpv4_server_init(dhcpv4_server_t *s, const dhcpv4_server_cfg_t *cfg,
                        dhcpv4_server_event_fn_t on_event, void *evt_ctx) {
  s->cfg = cfg;
  s->on_event = on_event;
  s->evt_ctx = evt_ctx;
}

/* REQ-DHCPv4-064, 068..073, 076, 077 */
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  const dhcpv4_server_cfg_t *cfg = s->cfg;
  reply_to_t to, broadcast;
  uint32_t ciaddr, requested;
  (void)src_ip;

  if (len < DHCP_OFF_OPTIONS + 4 || data[DHCP_OFF_OP] != DHCP_OP_REQUEST ||
      net_read32be(data + DHCP_OFF_MAGIC) != DHCP_MAGIC)
    return;

  ciaddr = net_read32be(data + DHCP_OFF_CIADDR);
  broadcast.request = data;
  broadcast.dst_ip = IPV4_BROADCAST;
  broadcast.dst_mac = broadcast_mac;
  to = broadcast; /* unicast only to a client that has its address */
  if (!(net_read16be(data + DHCP_OFF_FLAGS) & DHCP_FLAG_BROADCAST) && ciaddr) {
    to.dst_ip = ciaddr;
    to.dst_mac = src_mac;
  }

  switch (dhcp_message_type(data, len)) {
  case DHCP_MSG_DISCOVER:
    send_reply(net, cfg, &broadcast, DHCP_MSG_OFFER, cfg->offered_ip);
    fire_event(s, DHCPV4_SRV_EVT_OFFER);
    break;
  case DHCP_MSG_REQUEST: /* renewing: the address is in ciaddr */
    requested = dhcp_option_u32(data, len, DHCP_OPT_REQUESTED_IP, ciaddr);
    if (requested == cfg->offered_ip) {
      send_reply(net, cfg, &to, DHCP_MSG_ACK, cfg->offered_ip);
      fire_event(s, DHCPV4_SRV_EVT_ACK);
    } else {
      send_reply(net, cfg, &broadcast, DHCP_MSG_NAK, 0u);
      fire_event(s, DHCPV4_SRV_EVT_NAK);
    }
    break;
  case DHCP_MSG_INFORM: /* no address, so no lease */
    send_reply(net, cfg, &to, DHCP_MSG_ACK, 0u);
    fire_event(s, DHCPV4_SRV_EVT_ACK);
    break;
  default: /* RELEASE needs nothing without a lease table */
    break;
  }
}
