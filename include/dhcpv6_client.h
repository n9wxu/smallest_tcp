/**
 * @file dhcpv6_client.h
 * @brief DHCPv6 client (RFC 8415): stateless configuration
 *        (Information-Request) and stateful address assignment
 *        (Solicit/Advertise/Request/Reply, Renew, Rebind, Release).
 *
 * Usage (mirrors dhcpv4_client.h):
 *   1. Declare a dhcpv6_client_t and call dhcpv6_client_init().
 *   2. Register a udp6 port-546 handler that calls dhcpv6_client_input().
 *   3. Once the link-local address is usable, call dhcpv6_client_start()
 *      — stateful if the Router Advertisement had M set
 *      (net->ip6.ra_flags & NDP_RA_MANAGED), stateless for O
 *      (NDP_RA_OTHER).
 *   4. Call dhcpv6_client_tick() from the main loop.
 *
 * Addresses are installed with ipv6_addr_add() (DAD included); options
 * such as DNS servers (23) reach the application through the option
 * handler table.  Zero allocation; messages are built in net->tx.buf.
 */

#ifndef DHCPV6_CLIENT_H
#define DHCPV6_CLIENT_H

#include "net.h"
#include <stdint.h>

/* Protocol constants (RFC 8415 §7) */
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

#define DHCPV6_SOLICIT 1
#define DHCPV6_ADVERTISE 2
#define DHCPV6_REQUEST 3
#define DHCPV6_RENEW 5
#define DHCPV6_REBIND 6
#define DHCPV6_REPLY 7
#define DHCPV6_RELEASE 8
#define DHCPV6_INFORMATION_REQUEST 11

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_IAADDR 5
#define DHCPV6_OPT_ORO 6
#define DHCPV6_OPT_ELAPSED_TIME 8
#define DHCPV6_OPT_STATUS_CODE 13
#define DHCPV6_OPT_DNS_SERVERS 23 /* RFC 3646 */
#define DHCPV6_OPT_DOMAIN_LIST 24 /* RFC 3646 */
#define DHCPV6_OPT_INFO_REFRESH_TIME 32

#define DHCPV6_STATUS_SUCCESS 0

/** Largest server DUID kept (RFC 8415 allows 128; real servers send
 *  DUID-LLT, 14 bytes, or DUID-EN/UUID, up to 18). */
#ifndef DHCPV6_MAX_DUID
#define DHCPV6_MAX_DUID 20
#endif

/* Client states and events */
#define DHCPV6_CLI_IDLE 0
#define DHCPV6_CLI_INFO_REQUEST 1 /**< Stateless: Information-Request sent */
#define DHCPV6_CLI_INFORMED 2     /**< Stateless: configuration received */
#define DHCPV6_CLI_SOLICIT 3      /**< Solicit sent, waiting for Advertise */
#define DHCPV6_CLI_REQUEST 4      /**< Request sent */
#define DHCPV6_CLI_BOUND 5        /**< Address assigned */
#define DHCPV6_CLI_RENEW 6        /**< T1 passed: Renew to our server */
#define DHCPV6_CLI_REBIND 7       /**< T2 passed: Rebind to any server */

#define DHCPV6_MODE_STATELESS 0
#define DHCPV6_MODE_STATEFUL 1

#define DHCPV6_EVT_INFO 1    /**< Stateless configuration received */
#define DHCPV6_EVT_BOUND 2   /**< Address assigned */
#define DHCPV6_EVT_RENEWED 3 /**< Lease extended (Renew or Rebind) */
#define DHCPV6_EVT_EXPIRED 4 /**< Lease ran out; soliciting again */

/* Option handlers (as DHCPv4) */

/**
 * Called for each top-level option of a Reply the application asked for.
 * @param data  Option data (no code/length), valid during the call.
 */
typedef void (*dhcpv6_opt_handler_t)(uint16_t option, const uint8_t *data,
                                     uint16_t len, void *ctx);

typedef struct {
  uint16_t option;
  dhcpv6_opt_handler_t handler;
  void *ctx;
} dhcpv6_opt_entry_t;

typedef struct {
  const dhcpv6_opt_entry_t *entries;
  uint8_t count;
} dhcpv6_opt_table_t;

typedef void (*dhcpv6_event_fn_t)(uint8_t event, void *ctx);

/* Client state (application owns) */
typedef struct {
  uint8_t state; /**< DHCPV6_CLI_* */
  uint8_t mode;  /**< DHCPV6_MODE_* */
  uint8_t rc;    /**< Transmissions of the current message */
  uint8_t server_id_len;
  uint8_t server_id[DHCPV6_MAX_DUID];
  uint32_t xid;           /**< Transaction ID (24 bits) */
  uint32_t timer_ms;      /**< Until the next transmission */
  uint32_t rt_ms;         /**< Current retransmission timeout */
  uint32_t elapsed_ms;    /**< Since this exchange began (Elapsed Time) */
  uint8_t addr[16];       /**< Leased (or offered) address */
  uint32_t t1_s;          /**< Renew time after the Reply (stateful), or
                               the information refresh time (stateless) */
  uint32_t t2_s;          /**< Rebind time after the Reply */
  uint32_t valid_s;       /**< Valid lifetime of the lease */
  uint32_t preferred_s;   /**< Preferred lifetime of the lease */
  uint32_t since_s;       /**< Seconds since the last Reply */
  uint16_t sec_ms;        /**< ms toward the next second */
  uint32_t sol_max_rt_ms; /**< SOL_MAX_RT (a server may change it) */
  uint32_t inf_max_rt_ms; /**< INF_MAX_RT (a server may change it) */
  const dhcpv6_opt_table_t *opt_table;
  dhcpv6_event_fn_t on_event;
  void *evt_ctx;
} dhcpv6_client_t;

void dhcpv6_client_init(dhcpv6_client_t *c, dhcpv6_event_fn_t on_event,
                        void *evt_ctx, const dhcpv6_opt_table_t *opts);

/**
 * Start stateless (Information-request) or stateful (Solicit) operation
 * after a random delay of up to 1 s (RFC 8415 §18.2.1, §18.2.6).  Needs a
 * usable link-local address.
 */
void dhcpv6_client_start(net_t *net, dhcpv6_client_t *c, uint8_t mode);

/** Drive retransmissions and T1/T2/lifetime timers. */
void dhcpv6_client_tick(net_t *net, dhcpv6_client_t *c, uint32_t ms);

/** Feed a received UDP payload (port 546) to the client. */
void dhcpv6_client_input(net_t *net, dhcpv6_client_t *c, const uint8_t *src_ip,
                         const uint8_t *data, uint16_t len);

/** Release the lease (stateful): one Release, address removed, IDLE. */
void dhcpv6_client_release(net_t *net, dhcpv6_client_t *c);

static inline uint8_t dhcpv6_client_state(const dhcpv6_client_t *c) {
  return c->state;
}

#endif /* DHCPV6_CLIENT_H */
