/**
 * @file dhcpv6_client.c
 * @brief DHCPv6 client (RFC 8415): stateless and stateful.
 *
 * Implements REQ-DHCPv6-001..044.  Messages are built in net->tx.buf and
 * sent to All_DHCP_Relay_Agents_and_Servers (ff02::1:2) from the
 * link-local address.  Retransmission per RFC 8415 §15 without division
 * (Cortex-M0): a tenth is (v × 205) >> 11.
 */

#include "dhcpv6_client.h"
#include "ipv6.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

#define SOL_MAX_DELAY_MS 1000u /* and INF_MAX_DELAY */
#define SOL_TIMEOUT_MS 1000u
#define SOL_MAX_RT_MS 3600000u
#define REQ_TIMEOUT_MS 1000u
#define REQ_MAX_RT_MS 30000u
#define REQ_MAX_RC 10u
#define REN_TIMEOUT_MS 10000u
#define REN_MAX_RT_MS 600000u
#define REB_TIMEOUT_MS 10000u
#define REB_MAX_RT_MS 600000u
#define INF_TIMEOUT_MS 1000u
#define INF_MAX_RT_MS 3600000u

#define INFO_REFRESH_DEFAULT_S 86400u /* RFC 8415 §21.23 */
#define INFO_REFRESH_MIN_S 600u

#define OPT_SOL_MAX_RT 82
#define OPT_INF_MAX_RT 83

#define DUID_LL_LEN 10
#define IA_NA_LEN 12 /* IAID, T1, T2 */
#define IAADDR_LEN 24

static const uint8_t all_dhcp[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 1, 0, 2};
static const uint8_t all_dhcp_mac[6] = {0x33, 0x33, 0, 1, 0, 2};

/** About a tenth of v, for any 32-bit v. */
static uint32_t tenth(uint32_t v) {
  return v < 10000000u ? (v * 205u) >> 11 : (v >> 11) * 205u;
}

/**
 * base ± a tenth of @p of (RFC 8415 §15 RAND in [-0.1, 0.1]); with
 * @p positive, RAND in (0, 0.1] — the first Solicit must wait longer
 * than IRT.
 */
static uint32_t jitter(net_t *net, uint32_t base, uint32_t of, int positive) {
  uint32_t j = tenth(of); /* <= 8,640,000 for SOL_MAX_RT = 86400 s */
  uint32_t r = net_random(net) & 0xFFu;
  uint32_t span = 2u * j + 1u;
  if (positive)
    return base + 1u + ((r * j) >> 8);
  /* r × span must stay within 32 bits */
  return base - j + (span < 0x01000000u ? (r * span) >> 8 : r * (span >> 8));
}

static uint8_t msg_type(uint8_t state) {
  switch (state) {
  case DHCPV6_CLI_INFO_REQUEST:
    return DHCPV6_INFORMATION_REQUEST;
  case DHCPV6_CLI_SOLICIT:
    return DHCPV6_SOLICIT;
  case DHCPV6_CLI_REQUEST:
    return DHCPV6_REQUEST;
  case DHCPV6_CLI_RENEW:
    return DHCPV6_RENEW;
  default:
    return DHCPV6_REBIND;
  }
}

/** IRT and MRT of the message the state sends. */
static void rt_params(const dhcpv6_client_t *c, uint32_t *irt, uint32_t *mrt) {
  switch (c->state) {
  case DHCPV6_CLI_INFO_REQUEST:
    *irt = INF_TIMEOUT_MS;
    *mrt = c->inf_max_rt_ms;
    break;
  case DHCPV6_CLI_SOLICIT:
    *irt = SOL_TIMEOUT_MS;
    *mrt = c->sol_max_rt_ms;
    break;
  case DHCPV6_CLI_REQUEST:
    *irt = REQ_TIMEOUT_MS;
    *mrt = REQ_MAX_RT_MS;
    break;
  case DHCPV6_CLI_RENEW:
    *irt = REN_TIMEOUT_MS;
    *mrt = REN_MAX_RT_MS;
    break;
  default:
    *irt = REB_TIMEOUT_MS;
    *mrt = REB_MAX_RT_MS;
    break;
  }
}

static uint8_t *put_opt(uint8_t *p, uint16_t code, uint16_t len) {
  net_write16be(p, code);
  net_write16be(p + 2, len);
  return p + 4;
}

/** IAID: the low four bytes of the MAC. */
static uint32_t iaid(const net_t *net) {
  return (uint32_t)net->mac[2] << 24 | (uint32_t)net->mac[3] << 16 |
         (uint32_t)net->mac[4] << 8 | net->mac[5];
}

static void send_msg(net_t *net, dhcpv6_client_t *c, uint8_t type) {
  uint8_t *m = net->tx.buf + UDP6_PAYLOAD_OFFSET;
  uint8_t *p;

  if (net->tx.capacity < UDP6_PAYLOAD_OFFSET + 128u)
    return;
  m[0] = type;
  m[1] = (uint8_t)(c->xid >> 16);
  m[2] = (uint8_t)(c->xid >> 8);
  m[3] = (uint8_t)c->xid;
  p = m + 4;

  /* REQ-DHCPv6-004,014,033..035: Client Identifier, DUID-LL */
  p = put_opt(p, DHCPV6_OPT_CLIENTID, DUID_LL_LEN);
  net_write16be(p, 3);     /* DUID-LL */
  net_write16be(p + 2, 1); /* Ethernet */
  memcpy(p + 4, net->mac, 6);
  p += DUID_LL_LEN;

  if (type == DHCPV6_REQUEST || type == DHCPV6_RENEW ||
      type == DHCPV6_RELEASE) { /* REQ-DHCPv6-024 */
    p = put_opt(p, DHCPV6_OPT_SERVERID, c->server_id_len);
    memcpy(p, c->server_id, c->server_id_len);
    p += c->server_id_len;
  }

  /* REQ-DHCPv6-006,016: Elapsed Time, hundredths of a second */
  p = put_opt(p, DHCPV6_OPT_ELAPSED_TIME, 2);
  uint32_t cs = tenth(c->elapsed_ms);
  net_write16be(p, (uint16_t)(cs > 0xFFFFu ? 0xFFFFu : cs));
  p += 2;

  if (type != DHCPV6_RELEASE) { /* REQ-DHCPv6-005,017: what we want */
    /* RFC 8415 §21.23..25: Information-requests must ask for the refresh
     * time and INF_MAX_RT, the others for SOL_MAX_RT */
    int info = type == DHCPV6_INFORMATION_REQUEST;
    p = put_opt(p, DHCPV6_OPT_ORO, info ? 8 : 6);
    net_write16be(p, DHCPV6_OPT_DNS_SERVERS);
    net_write16be(p + 2, DHCPV6_OPT_DOMAIN_LIST);
    if (info) {
      net_write16be(p + 4, DHCPV6_OPT_INFO_REFRESH_TIME);
      net_write16be(p + 6, OPT_INF_MAX_RT);
      p += 8;
    } else {
      net_write16be(p + 4, OPT_SOL_MAX_RT);
      p += 6;
    }
  }

  if (type != DHCPV6_INFORMATION_REQUEST) { /* REQ-DHCPv6-015,026 */
    int with_addr = type != DHCPV6_SOLICIT;
    p = put_opt(p, DHCPV6_OPT_IA_NA,
                (uint16_t)(IA_NA_LEN + (with_addr ? 4 + IAADDR_LEN : 0)));
    net_write32be(p, iaid(net));
    net_write32be(p + 4, 0); /* T1, T2: the server decides */
    net_write32be(p + 8, 0);
    p += IA_NA_LEN;
    if (with_addr) {
      p = put_opt(p, DHCPV6_OPT_IAADDR, IAADDR_LEN);
      memcpy(p, c->addr, 16);
      net_write32be(p + 16, 0);
      net_write32be(p + 20, 0);
      p += IAADDR_LEN;
    }
  }

  /* REQ-DHCPv6-002,003,013,023: multicast, 546 → 547 */
  udp6_send_inplace(net, all_dhcp, all_dhcp_mac, DHCPV6_CLIENT_PORT,
                    DHCPV6_SERVER_PORT, (uint16_t)(p - m), net->ip6.hop_limit);
}

/** Send the state's message now and set the next retransmission. */
static void transmit(net_t *net, dhcpv6_client_t *c) {
  uint32_t irt, mrt;

  send_msg(net, c, msg_type(c->state));
  rt_params(c, &irt, &mrt);
  if (c->rc == 0) {
    c->rt_ms = jitter(net, irt, irt, c->state == DHCPV6_CLI_SOLICIT);
  } else {
    c->rt_ms = jitter(net, 2u * c->rt_ms, c->rt_ms, 0);
    if (c->rt_ms > mrt)
      c->rt_ms = jitter(net, mrt, mrt, 0);
  }
  c->rc++;
  c->timer_ms = c->rt_ms;
}

/** The random wait before an exchange's first message (REQ-DHCPv6-048,
 *  055): 1 ms to SOL_MAX_DELAY = INF_MAX_DELAY = 1 s. */
static uint32_t start_delay(net_t *net) {
  return net_random_below(net, SOL_MAX_DELAY_MS) + 1u;
}

/** A new message exchange: new transaction ID (REQ-DHCPv6-039). */
static void begin(net_t *net, dhcpv6_client_t *c, uint8_t state,
                  uint32_t delay_ms) {
  c->state = state;
  c->xid = net_random(net) & 0xFFFFFFu;
  c->rc = 0;
  c->elapsed_ms = 0;
  c->timer_ms = delay_ms;
  if (delay_ms == 0)
    transmit(net, c);
}

/** Every option fits the message (REQ-DHCPv6-042,043). */
static int options_valid(const uint8_t *p, uint16_t len) {
  while (len >= 4) {
    uint16_t olen = net_read16be(p + 2);
    if ((uint32_t)olen + 4u > len)
      return 0;
    p += 4 + olen;
    len = (uint16_t)(len - 4 - olen);
  }
  return len == 0;
}

/** First option @p code in validated options, or NULL; *olen its length. */
static const uint8_t *find(const uint8_t *p, uint16_t len, uint16_t code,
                           uint16_t *olen) {
  while (len >= 4) {
    uint16_t l = net_read16be(p + 2);
    if (net_read16be(p) == code) {
      *olen = l;
      return p + 4;
    }
    p += 4 + l;
    len = (uint16_t)(len - 4 - l);
  }
  return NULL;
}

/** Status Code option in these options says success (or is absent). */
static int status_ok(const uint8_t *p, uint16_t len) {
  uint16_t l;
  const uint8_t *s = find(p, len, DHCPV6_OPT_STATUS_CODE, &l);
  return !s || l < 2 || net_read16be(s) == DHCPV6_STATUS_SUCCESS;
}

/** A lease offered in an IA_NA (REQ-DHCPv6-021,028..030,044). */
typedef struct {
  uint32_t t1, t2, preferred, valid;
  const uint8_t *addr;
} lease_t;

static int ia_na_lease(const net_t *net, const uint8_t *ia, uint16_t len,
                       lease_t *out) {
  if (len < IA_NA_LEN || net_read32be(ia) != iaid(net))
    return 0;
  const uint8_t *sub = ia + IA_NA_LEN;
  uint16_t sub_len = (uint16_t)(len - IA_NA_LEN);
  if (!options_valid(sub, sub_len) || !status_ok(sub, sub_len))
    return 0; /* NoAddrsAvail, NoBinding, ... */
  out->t1 = net_read32be(ia + 4);
  out->t2 = net_read32be(ia + 8);
  while (sub_len >= 4) {
    uint16_t l = net_read16be(sub + 2);
    if (net_read16be(sub) == DHCPV6_OPT_IAADDR && l >= IAADDR_LEN) {
      out->addr = sub + 4;
      out->preferred = net_read32be(sub + 20);
      out->valid = net_read32be(sub + 24);
      if (out->valid > 0 && out->preferred <= out->valid)
        return 1;
    }
    sub += 4 + l;
    sub_len = (uint16_t)(sub_len - 4 - l);
  }
  return 0;
}

static void run_handlers(const dhcpv6_client_t *c, const uint8_t *p,
                         uint16_t len) {
  uint8_t i;
  if (!c->opt_table)
    return;
  while (len >= 4) {
    uint16_t code = net_read16be(p), l = net_read16be(p + 2);
    for (i = 0; i < c->opt_table->count; i++) {
      if (c->opt_table->entries[i].option == code)
        c->opt_table->entries[i].handler(code, p + 4, l,
                                         c->opt_table->entries[i].ctx);
    }
    p += 4 + l;
    len = (uint16_t)(len - 4 - l);
  }
}

static void event(dhcpv6_client_t *c, uint8_t e) {
  if (c->on_event)
    c->on_event(e, c->evt_ctx);
}

/** Install or refresh the leased address and restart the lease clock. */
static void bind(net_t *net, dhcpv6_client_t *c, const lease_t *l) {
  memcpy(c->addr, l->addr, 16);
  c->preferred_s = l->preferred;
  c->valid_s = l->valid;
  /* RFC 8415 §21.4: T1/T2 of 0 leave them to us — 0.5 and ~0.8 of the
   * preferred lifetime (shifts, not division) */
  c->t1_s = l->t1 ? l->t1 : l->preferred >> 1;
  c->t2_s =
      l->t2 ? l->t2
            : (l->preferred >> 1) + (l->preferred >> 2) + (l->preferred >> 4);
  c->since_s = 0;
  c->sec_ms = 0;

  int slot = ipv6_addr_slot(net, c->addr);
  if (slot < 0)
    ipv6_addr_add(net, c->addr, l->valid, l->preferred); /* DAD */
  else
    ipv6_addr_set_lifetimes(net, (uint8_t)slot, l->valid, l->preferred);
  c->state = DHCPV6_CLI_BOUND;
}

void dhcpv6_client_init(dhcpv6_client_t *c, dhcpv6_event_fn_t on_event,
                        void *evt_ctx, const dhcpv6_opt_table_t *opts) {
  memset(c, 0, sizeof(*c));
  c->on_event = on_event;
  c->evt_ctx = evt_ctx;
  c->opt_table = opts;
  c->sol_max_rt_ms = SOL_MAX_RT_MS;
  c->inf_max_rt_ms = INF_MAX_RT_MS;
}

void dhcpv6_client_start(net_t *net, dhcpv6_client_t *c, uint8_t mode) {
  c->mode = mode;
  begin(net, c,
        mode == DHCPV6_MODE_STATEFUL ? DHCPV6_CLI_SOLICIT
                                     : DHCPV6_CLI_INFO_REQUEST,
        start_delay(net));
}

void dhcpv6_client_tick(net_t *net, dhcpv6_client_t *c, uint32_t ms) {
  if (c->state == DHCPV6_CLI_IDLE)
    return;

  if (c->state == DHCPV6_CLI_INFORMED || c->state >= DHCPV6_CLI_BOUND) {
    c->since_s += net_whole_seconds(&c->sec_ms, ms);

    if (c->state == DHCPV6_CLI_INFORMED) {
      if (c->since_s >= c->t1_s) /* information refresh */
        begin(net, c, DHCPV6_CLI_INFO_REQUEST, start_delay(net));
      return;
    }
    if (c->valid_s != NET_IP6_INFINITE && c->since_s >= c->valid_s) {
      /* REQ-DHCPv6-038: nobody renewed it */
      ipv6_addr_remove(net, c->addr);
      event(c, DHCPV6_EVT_EXPIRED);
      begin(net, c, DHCPV6_CLI_SOLICIT, 0);
      return;
    }
    if (c->state == DHCPV6_CLI_BOUND) {
      if (c->t1_s != NET_IP6_INFINITE && c->since_s >= c->t1_s)
        begin(net, c, DHCPV6_CLI_RENEW, 0); /* REQ-DHCPv6-036 */
      return;
    }
    if (c->state == DHCPV6_CLI_RENEW && c->t2_s != NET_IP6_INFINITE &&
        c->since_s >= c->t2_s) {
      begin(net, c, DHCPV6_CLI_REBIND, 0); /* REQ-DHCPv6-037 */
      return;
    }
  }

  /* Retransmission (REQ-DHCPv6-039..041) */
  if (c->rc && c->elapsed_ms < 655350u) /* Elapsed Time tops out at 0xFFFF */
    c->elapsed_ms += ms;
  if (c->timer_ms > ms) {
    c->timer_ms -= ms;
    return;
  }
  if (c->state == DHCPV6_CLI_REQUEST && c->rc >= REQ_MAX_RC)
    begin(net, c, DHCPV6_CLI_SOLICIT, 0); /* give up on this server */
  else
    transmit(net, c);
}

void dhcpv6_client_input(net_t *net, dhcpv6_client_t *c, const uint8_t *src_ip,
                         const uint8_t *data, uint16_t len) {
  uint16_t l;
  lease_t lease;
  (void)src_ip;

  if (len < 4 || c->state == DHCPV6_CLI_IDLE ||
      c->state == DHCPV6_CLI_INFORMED || c->state == DHCPV6_CLI_BOUND)
    return;
  /* REQ-DHCPv6-019,027: this exchange's transaction ID */
  uint32_t xid = (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];
  if (xid != c->xid)
    return;
  const uint8_t *opts = data + 4;
  uint16_t opts_len = (uint16_t)(len - 4);
  if (!options_valid(opts, opts_len))
    return;

  /* RFC 8415 §16.10: our Client Identifier, and a Server Identifier */
  const uint8_t *cid = find(opts, opts_len, DHCPV6_OPT_CLIENTID, &l);
  if (!cid || l != DUID_LL_LEN || net_read16be(cid) != 3 ||
      memcmp(cid + 4, net->mac, 6) != 0)
    return;
  const uint8_t *sid = find(opts, opts_len, DHCPV6_OPT_SERVERID, &l);
  if (!sid || l == 0 || l > DHCPV6_MAX_DUID)
    return;
  uint16_t sid_len = l;
  if (!status_ok(opts, opts_len))
    return;

  /* SOL_MAX_RT / INF_MAX_RT from the server (60..86400 s, §21.24/25) */
  const uint8_t *mrt = find(opts, opts_len, OPT_SOL_MAX_RT, &l);
  if (mrt && l == 4 && net_read32be(mrt) >= 60u && net_read32be(mrt) <= 86400u)
    c->sol_max_rt_ms = net_read32be(mrt) * 1000u;
  mrt = find(opts, opts_len, OPT_INF_MAX_RT, &l);
  if (mrt && l == 4 && net_read32be(mrt) >= 60u && net_read32be(mrt) <= 86400u)
    c->inf_max_rt_ms = net_read32be(mrt) * 1000u;

  const uint8_t *ia = find(opts, opts_len, DHCPV6_OPT_IA_NA, &l);
  int have_lease = ia && ia_na_lease(net, ia, l, &lease);

  if (data[0] == DHCPV6_ADVERTISE && c->state == DHCPV6_CLI_SOLICIT) {
    /* REQ-DHCPv6-020..022: take the first usable offer */
    if (!have_lease)
      return;
    memcpy(c->addr, lease.addr, 16);
    memcpy(c->server_id, sid, sid_len);
    c->server_id_len = (uint8_t)sid_len;
    begin(net, c, DHCPV6_CLI_REQUEST, 0);
    return;
  }
  if (data[0] != DHCPV6_REPLY)
    return;

  if (c->state == DHCPV6_CLI_INFO_REQUEST) {
    /* REQ-DHCPv6-007,008: stateless configuration */
    const uint8_t *refresh =
        find(opts, opts_len, DHCPV6_OPT_INFO_REFRESH_TIME, &l);
    c->t1_s = INFO_REFRESH_DEFAULT_S;
    if (refresh && l == 4)
      c->t1_s = net_read32be(refresh) < INFO_REFRESH_MIN_S
                    ? INFO_REFRESH_MIN_S
                    : net_read32be(refresh);
    c->state = DHCPV6_CLI_INFORMED;
    c->since_s = 0;
    c->sec_ms = 0;
    run_handlers(c, opts, opts_len);
    event(c, DHCPV6_EVT_INFO);
    return;
  }

  /* Reply to Request, Renew or Rebind */
  if (!have_lease || (c->state != DHCPV6_CLI_REQUEST &&
                      !ipv6_addr_equal(lease.addr, c->addr))) {
    if (c->state == DHCPV6_CLI_REQUEST)
      begin(net, c, DHCPV6_CLI_SOLICIT, 0);
    return; /* Renew/Rebind: keep trying until T2 / expiry */
  }
  uint8_t was = c->state;
  memcpy(c->server_id, sid, sid_len); /* a Rebind may reach another server */
  c->server_id_len = (uint8_t)sid_len;
  bind(net, c, &lease);
  run_handlers(c, opts, opts_len);
  event(c, was == DHCPV6_CLI_REQUEST ? DHCPV6_EVT_BOUND : DHCPV6_EVT_RENEWED);
}

void dhcpv6_client_release(net_t *net, dhcpv6_client_t *c) {
  if (c->state >= DHCPV6_CLI_BOUND) {
    /* One Release (RFC 8415 allows up to REL_MAX_RC = 5 transmissions) */
    c->xid = net_random(net) & 0xFFFFFFu;
    c->elapsed_ms = 0;
    send_msg(net, c, DHCPV6_RELEASE);
    ipv6_addr_remove(net, c->addr);
  }
  c->state = DHCPV6_CLI_IDLE;
}
