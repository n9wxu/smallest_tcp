/**
 * @file dhcpv4_server.c
 * @brief DHCPv4 stateless single-client server — RFC 2131.
 *
 * Implements REQ-DHCPv4-060..078.
 * Always offers the same pre-configured IP. No lease table. No timers.
 * Zero dynamic allocation.
 */

#include "dhcpv4_server.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

/* ── DHCP wire offsets (same as client) ──────────────────────────── */
#define DHCP_OFF_OP 0
#define DHCP_OFF_XID 4
#define DHCP_OFF_FLAGS 10
#define DHCP_OFF_CIADDR 12
#define DHCP_OFF_YIADDR 16
#define DHCP_OFF_SIADDR 20
#define DHCP_OFF_CHADDR 28
#define DHCP_OFF_MAGIC 236
#define DHCP_OFF_OPTIONS 240
#define DHCP_MIN_LEN 300

#define DHCP_MAGIC 0x63825363u
#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY 2

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_REQUEST 3
#define DHCP_MSG_RELEASE 7
#define DHCP_MSG_INFORM 8
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_ACK 5
#define DHCP_MSG_NAK 6

#define OPT_SUBNET_MASK 1
#define OPT_ROUTER 3
#define OPT_DNS 6
#define OPT_REQUESTED_IP 50
#define OPT_LEASE_TIME 51
#define OPT_MSG_TYPE 53
#define OPT_SERVER_ID 54
#define OPT_END 255
#define OPT_PAD 0

static const uint8_t BCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint32_t BCAST_IP = 0xFFFFFFFFu;

/* ── Build and send one server reply ─────────────────────────────── */

static void send_reply(net_t *net, const dhcpv4_server_cfg_t *cfg, uint32_t xid,
                       uint32_t yiaddr, uint8_t msg_type, uint32_t dst_ip,
                       const uint8_t *dst_mac, const uint8_t *chaddr) {
  uint8_t msg[DHCP_MIN_LEN + 32];
  memset(msg, 0, sizeof(msg));

  /* Fixed header — REQ-DHCPv4-074 */
  msg[DHCP_OFF_OP] = DHCP_OP_REPLY;
  msg[1] = 1; /* htype = Ethernet */
  msg[2] = 6; /* hlen */
  net_write32be(msg + DHCP_OFF_XID, xid);
  net_write16be(msg + DHCP_OFF_FLAGS, 0x8000u); /* broadcast flag */
  net_write32be(msg + DHCP_OFF_YIADDR, yiaddr);
  net_write32be(msg + DHCP_OFF_SIADDR, cfg->server_ip);
  memcpy(msg + DHCP_OFF_CHADDR, chaddr, 6);
  net_write32be(msg + DHCP_OFF_MAGIC, DHCP_MAGIC);

  /* Options */
  uint16_t pos = DHCP_OFF_OPTIONS;

  /* Message type */
  msg[pos++] = OPT_MSG_TYPE;
  msg[pos++] = 1;
  msg[pos++] = msg_type;

  /* Server identifier — REQ-DHCPv4-065 */
  msg[pos++] = OPT_SERVER_ID;
  msg[pos++] = 4;
  net_write32be(msg + pos, cfg->server_ip);
  pos += 4;

  /* Lease time — REQ-DHCPv4-065 */
  uint32_t lt = (cfg->lease_time_s > 0) ? cfg->lease_time_s : 0xFFFFFFFFu;
  msg[pos++] = OPT_LEASE_TIME;
  msg[pos++] = 4;
  net_write32be(msg + pos, lt);
  pos += 4;

  /* Subnet mask — REQ-DHCPv4-065 */
  msg[pos++] = OPT_SUBNET_MASK;
  msg[pos++] = 4;
  net_write32be(msg + pos, cfg->subnet_mask);
  pos += 4;

  /* Router — REQ-DHCPv4-066 */
  if (cfg->gateway) {
    msg[pos++] = OPT_ROUTER;
    msg[pos++] = 4;
    net_write32be(msg + pos, cfg->gateway);
    pos += 4;
  }

  /* DNS — REQ-DHCPv4-067 */
  if (cfg->dns) {
    msg[pos++] = OPT_DNS;
    msg[pos++] = 4;
    net_write32be(msg + pos, cfg->dns);
    pos += 4;
  }

  msg[pos++] = OPT_END;
  uint16_t len = (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;

  /* Temporarily set net->ipv4_addr to server IP for IP/UDP header */
  uint32_t saved = net->ipv4_addr;
  net->ipv4_addr = cfg->server_ip;
  udp_send(net, dst_ip, dst_mac, 67, 68, msg, len);
  net->ipv4_addr = saved;
}

/* ── Extract message type from options ───────────────────────────── */

static uint8_t extract_msg_type(const uint8_t *data, uint16_t len) {
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
      return data[i];
    i += olen;
  }
  return 0;
}

/* ── Extract Requested IP Address option (50) ────────────────────── */

static uint32_t extract_requested_ip(const uint8_t *data, uint16_t len) {
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
    if (code == OPT_REQUESTED_IP && olen >= 4)
      return net_read32be(data + i);
    i += olen;
  }
  return 0u;
}

/* ════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════ */

void dhcpv4_server_init(dhcpv4_server_t *s, const dhcpv4_server_cfg_t *cfg,
                        dhcpv4_event_fn_t on_event, void *evt_ctx) {
  s->cfg = cfg;
  s->on_event = on_event;
  s->evt_ctx = evt_ctx;
}

void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  (void)src_ip;

  /* REQ-DHCPv4-073: validate op=BOOTREQUEST and magic cookie */
  if (len < (uint16_t)(DHCP_OFF_OPTIONS + 4))
    return;
  if (data[DHCP_OFF_OP] != DHCP_OP_REQUEST)
    return;
  if (net_read32be(data + DHCP_OFF_MAGIC) != DHCP_MAGIC)
    return;

  uint32_t xid = net_read32be(data + DHCP_OFF_XID);
  const uint8_t *chaddr = data + DHCP_OFF_CHADDR;
  uint32_t ciaddr = net_read32be(data + DHCP_OFF_CIADDR);
  uint16_t flags = net_read16be(data + DHCP_OFF_FLAGS);
  uint8_t mtype = extract_msg_type(data, len);

  if (mtype == 0)
    return; /* REQ-DHCPv4-072: ignore messages without type */

  /* REQ-DHCPv4-076,077: determine reply destination */
  uint32_t dst_ip;
  const uint8_t *dst_mac;
  if ((flags & 0x8000u) || ciaddr == 0u) {
    dst_ip = BCAST_IP;
    dst_mac = BCAST_MAC;
  } else {
    dst_ip = ciaddr; /* REQ-DHCPv4-077: unicast to ciaddr */
    dst_mac = src_mac;
  }

  switch (mtype) {

  case DHCP_MSG_DISCOVER:
    /* REQ-DHCPv4-064,065,066,067 */
    send_reply(net, s->cfg, xid, s->cfg->offered_ip, DHCP_MSG_OFFER, BCAST_IP,
               BCAST_MAC, chaddr);
    if (s->on_event)
      s->on_event(DHCPV4_SRV_EVT_OFFER, s->evt_ctx);
    break;

  case DHCP_MSG_REQUEST: {
    /* REQ-DHCPv4-068,069 */
    uint32_t req_ip = extract_requested_ip(data, len);
    if (req_ip == 0u && ciaddr != 0u)
      req_ip = ciaddr; /* renewal: ciaddr is the address */

    if (req_ip == s->cfg->offered_ip) {
      /* REQ-DHCPv4-068: correct IP → ACK */
      send_reply(net, s->cfg, xid, s->cfg->offered_ip, DHCP_MSG_ACK, dst_ip,
                 dst_mac, chaddr);
      if (s->on_event)
        s->on_event(DHCPV4_SRV_EVT_ACK, s->evt_ctx);
    } else {
      /* REQ-DHCPv4-069: wrong IP → NAK (always broadcast) */
      send_reply(net, s->cfg, xid, 0u, DHCP_MSG_NAK, BCAST_IP, BCAST_MAC,
                 chaddr);
      if (s->on_event)
        s->on_event(DHCPV4_SRV_EVT_NAK, s->evt_ctx);
    }
    break;
  }

  case DHCP_MSG_RELEASE:
    /* REQ-DHCPv4-070: silently ignore — no lease table */
    break;

  case DHCP_MSG_INFORM:
    /* REQ-DHCPv4-071: ACK with options, yiaddr = 0 */
    send_reply(net, s->cfg, xid, 0u, DHCP_MSG_ACK, dst_ip, dst_mac, chaddr);
    if (s->on_event)
      s->on_event(DHCPV4_SRV_EVT_ACK, s->evt_ctx);
    break;

  default:
    /* REQ-DHCPv4-072: ignore all other message types */
    break;
  }
}
