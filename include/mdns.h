/**
 * @file mdns.h
 * @brief Multicast DNS responder (RFC 6762) with DNS-SD advertising (RFC 6763).
 *
 * The application owns the record table and the mdns_t state.  The responder
 * probes for its unique names, announces, answers queries on 224.0.0.251:5353
 * and sends goodbye packets on shutdown.  Zero allocation: responses are
 * built directly in net->tx.buf.
 *
 * Typical use:
 *
 *   static const char *const txt[] = {"txtvers=1", "fw=1.2.3", NULL};
 *   static const mdns_record_t records[] = {
 *     {.type = DNS_TYPE_A,   .ttl = MDNS_TTL_HOST,  .name = "pyro-dead01.local",
 *      .rdata.a = 0},                               // 0 = net->ipv4_addr
 *     {.type = DNS_TYPE_PTR, .ttl = MDNS_TTL_OTHER, .name = "_pyro._tcp.local",
 *      .rdata.ptr = "Pyro Unit 1._pyro._tcp.local"},
 *     {.type = DNS_TYPE_SRV, .ttl = MDNS_TTL_HOST,
 *      .name = "Pyro Unit 1._pyro._tcp.local",
 *      .rdata.srv = {0, 0, 80, "pyro-dead01.local"}},
 *     {.type = DNS_TYPE_TXT, .ttl = MDNS_TTL_HOST,
 *      .name = "Pyro Unit 1._pyro._tcp.local", .rdata.txt = txt},
 *   };
 *   static mdns_t mdns;
 *
 *   mdns_init(&mdns, &net, records, 4, on_conflict, NULL);
 *   mdns_start(&mdns);                  // after the IP address is known
 *   // UDP handler for MDNS_PORT: peek the payload, then
 *   mdns_input(&mdns, src_ip, src_mac, src_port, payload, len);
 *   // main loop:
 *   mdns_tick(&mdns, elapsed_ms);
 *   // shutdown:
 *   mdns_stop(&mdns);
 *
 * PTR records are shared (DNS-SD service enumeration); A, SRV and TXT records
 * are unique and are probed for before use.
 *
 * Queries for a type one of our unique names does not have are answered
 * with an NSEC record (RFC 6762 §6.1, restricted form) — without it a
 * dual-stack lookup of the host name waits seconds for an AAAA answer.
 *
 * Dual stack (NET_USE_IPV6): the responder also listens on ff02::fb (feed
 * datagrams from the udp6 port-5353 handler to mdns_input6()), advertises
 * AAAA records (.rdata.aaaa = NULL: every usable IPv6 address), probes,
 * announces and says goodbye on both families, and answers a query on the
 * family it came on.  An answer with A records carries the name's AAAA
 * records as additionals and vice versa (RFC 6762 §6.2).
 *
 * Not implemented: querier/browser, the simultaneous-probe tiebreak
 * (RFC 6762 §8.2) and multi-packet known-answer lists.
 */

#ifndef MDNS_H
#define MDNS_H

#include "dns_wire.h"
#include "net.h"
#include <stdint.h>

#define MDNS_PORT 5353
#define MDNS_GROUP 0xE00000FBu /**< 224.0.0.251 */
#if NET_USE_IPV6
extern const uint8_t mdns_group6[16]; /**< ff02::fb */
#endif
#define MDNS_IP_TTL 255        /**< RFC 6762 §11: IP TTL of every mDNS packet */

#define MDNS_TTL_HOST 120   /**< A / SRV / TXT record TTL (RFC 6762 §10) */
#define MDNS_TTL_OTHER 4500 /**< PTR record TTL (RFC 6762 §10) */
#define MDNS_LEGACY_TTL_MAX 10 /**< TTL cap in legacy unicast responses */

/** DNS-SD service type enumeration name (RFC 6763 §9). */
#define MDNS_META_QUERY "_services._dns-sd._udp.local"

/** Records per responder (bitmask width). */
#define MDNS_MAX_RECORDS 32

#define MDNS_PROBE_WAIT_MS 250    /**< Max initial delay + probe spacing */
#define MDNS_PROBE_COUNT 3        /**< RFC 6762 §8.1 */
#define MDNS_ANNOUNCE_COUNT 2     /**< RFC 6762 §8.3 */
#define MDNS_ANNOUNCE_WAIT_MS 1000
#define MDNS_RESP_DELAY_MIN_MS 20 /**< Shared-record response delay (§6) */
#define MDNS_RESP_DELAY_MAX_MS 120

/* ── States ───────────────────────────────────────────────────────── */

#define MDNS_STATE_STOPPED 0
#define MDNS_STATE_PROBING 1
#define MDNS_STATE_ANNOUNCING 2
#define MDNS_STATE_RUNNING 3
#define MDNS_STATE_CONFLICT 4

/* ── Records ──────────────────────────────────────────────────────── */

/**
 * One resource record.  Names are dotted strings in the .local. domain;
 * labels may contain spaces but not dots.
 */
typedef struct {
  uint16_t type;    /**< DNS_TYPE_A, _AAAA (IPv6 builds), _PTR, _SRV, _TXT */
  uint32_t ttl;     /**< Seconds (MDNS_TTL_HOST / MDNS_TTL_OTHER) */
  const char *name; /**< Owner name */
  union {
    uint32_t a;      /**< IPv4, host byte order; 0 = use net->ipv4_addr */
    /** IPv6 address (16 bytes); NULL = every usable IPv6 address of the
     *  interface — one AAAA RR each (RFC 6762 §6.2) */
    const uint8_t *aaaa;
    const char *ptr; /**< PTR target (service instance name) */
    struct {
      uint16_t priority;
      uint16_t weight;
      uint16_t port;
      const char *target; /**< Host name with an A record */
    } srv;
    /** NULL-terminated "key=value" strings; NULL or empty = no metadata
     *  (sent as a single zero byte, RFC 6763 §6.1). */
    const char *const *txt;
  } rdata;
} mdns_record_t;

/* ── Responder state ──────────────────────────────────────────────── */

typedef struct mdns_s mdns_t;

/**
 * Called when another host claims one of our unique names.  The responder
 * is then in MDNS_STATE_CONFLICT and silent; to recover, change the name in
 * the record table (e.g. "pyro-dead01-2.local") and call mdns_start().
 * @param record_index  Index of the conflicting record in the table.
 */
typedef void (*mdns_conflict_fn_t)(mdns_t *m, uint8_t record_index,
                                   void *ctx);

struct mdns_s {
  net_t *net;
  const mdns_record_t *records;
  mdns_conflict_fn_t on_conflict;
  void *ctx;
  uint32_t timer_ms;      /**< Countdown to next probe / announcement */
  uint32_t resp_timer_ms; /**< Countdown to delayed multicast response */
  uint32_t resp_answers;  /**< Records owed in the delayed response */
  uint32_t resp_meta;     /**< Service types owed to a meta-query */
  uint32_t resp_nsec;     /**< Names owed a negative (NSEC) answer */
  uint32_t rng;           /**< xorshift32 state for RFC 6762 jitter */
  uint8_t count;
  uint8_t state; /**< MDNS_STATE_* */
  uint8_t step;  /**< Probes / announcements sent in the current state */
#if NET_USE_IPV6
  uint8_t resp_fam; /**< Families owed the delayed response (bit 0 v4, 1 v6) */
  uint8_t ann_fam;  /**< Families announcements go to */
#endif
};

/* ── API ──────────────────────────────────────────────────────────── */

/**
 * Initialise a responder (state STOPPED).  Sends nothing.
 * @return NET_ERR_INVALID_PARAM if @p count is 0 or > MDNS_MAX_RECORDS.
 */
net_err_t mdns_init(mdns_t *m, net_t *net, const mdns_record_t *records,
                    uint8_t count, mdns_conflict_fn_t on_conflict, void *ctx);

/**
 * Join 224.0.0.251 (IGMP) and start probing after a random 0-250 ms delay.
 * Call again after a conflict, a link-up or an address change
 * (REQ-MDNS-024) to re-probe and re-announce.
 */
void mdns_start(mdns_t *m);

/** Advance timers: probes, announcements, delayed responses. */
void mdns_tick(mdns_t *m, uint32_t elapsed_ms);

/**
 * Process one mDNS message received on UDP port 5353.
 * @param src_port  Querier's source port; not 5353 = legacy unicast query.
 */
void mdns_input(mdns_t *m, uint32_t src_ip, const uint8_t *src_mac,
                uint16_t src_port, const uint8_t *msg, uint16_t len);

#if NET_USE_IPV6
/** As mdns_input(), for a message that arrived over IPv6 (ff02::fb or
 *  unicast); @p src_ip is the sender's 16-byte address. */
void mdns_input6(mdns_t *m, const uint8_t *src_ip, const uint8_t *src_mac,
                 uint16_t src_port, const uint8_t *msg, uint16_t len);

/**
 * Our IPv6 addresses changed (e.g. SLAAC or DHCPv6 added one): announce
 * again over IPv6 (RFC 6762 §8.4), without re-probing.  While running,
 * over IPv6 only; while still announcing, the announcement sequence starts
 * over with IPv6 added.  No-op while probing (the announcements to come
 * include the new addresses).
 */
void mdns_readdress6(mdns_t *m);
#endif

/**
 * Withdraw all records: goodbye packet (TTL 0) if they were announced,
 * then leave 224.0.0.251 (and ff02::fb).  State becomes STOPPED.
 */
void mdns_stop(mdns_t *m);

static inline uint8_t mdns_state(const mdns_t *m) { return m->state; }

#endif /* MDNS_H */
