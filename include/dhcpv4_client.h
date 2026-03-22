/**
 * @file dhcpv4_client.h
 * @brief DHCPv4 client — RFC 2131 state machine with option handler callbacks.
 *
 * Usage:
 *   1. Declare a dhcpv4_client_t (static or stack).
 *   2. Call dhcpv4_client_init() with your event callback and optional option
 *      handler table.
 *   3. Register port-68 handler in your udp_port_table_t that calls
 *      dhcpv4_client_input().
 *   4. Call dhcpv4_client_start() once to begin discovery.
 *   5. Call dhcpv4_client_tick() every main-loop iteration with elapsed ms.
 *
 * Zero allocation: all state lives in the application-owned dhcpv4_client_t.
 * The DHCP message is built directly in net->tx_buf.
 *
 * REQ-DHCPv4-001..059
 */

#ifndef DHCPV4_CLIENT_H
#define DHCPV4_CLIENT_H

#include "net.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── DHCP client states ───────────────────────────────────────────── */

#define DHCPV4_CLI_INIT 0       /**< No address; will send DISCOVER */
#define DHCPV4_CLI_SELECTING 1  /**< DISCOVER sent, waiting for OFFER */
#define DHCPV4_CLI_REQUESTING 2 /**< OFFER received, REQUEST sent */
#define DHCPV4_CLI_BOUND 3      /**< ACK received, IP configured */
#define DHCPV4_CLI_RENEWING 4   /**< T1 expired; unicast REQUEST to server */
#define DHCPV4_CLI_REBINDING 5  /**< T2 expired; broadcast REQUEST */

/* ── Client event codes ───────────────────────────────────────────── */

#define DHCPV4_EVT_BOUND 1 /**< IP address configured (BOUND entered) */
#define DHCPV4_EVT_RENEWED                                                     \
  2                          /**< Lease renewed (re-BOUND after renew/rebind)  \
                              */
#define DHCPV4_EVT_EXPIRED 3 /**< Lease expired; IP cleared, INIT restarted */
#define DHCPV4_EVT_NAK 4     /**< Server rejected request; INIT restarted */

/* ── Option handler callback ──────────────────────────────────────── */

/**
 * Application callback invoked for each DHCP option found in DHCPACK.
 *
 * @param option  DHCP option code (e.g. 3=Router, 6=DNS, 42=NTP).
 * @param data    Pointer to raw TLV value bytes (NOT including type or length).
 *                Points into the DHCP receive buffer — do NOT retain past
 * return.
 * @param len     Number of value bytes.
 * @param ctx     Application context from the registration entry.
 *
 * REQ-DHCPv4-052..057
 */
typedef void (*dhcpv4_opt_handler_t)(uint8_t option, const uint8_t *data,
                                     uint8_t len, void *ctx);

/**
 * @brief One entry in the application's option handler table.
 * REQ-DHCPv4-052
 */
typedef struct {
  uint8_t option;               /**< DHCP option code to watch */
  dhcpv4_opt_handler_t handler; /**< Callback when option is found */
  void *ctx;                    /**< Passed unchanged to handler */
} dhcpv4_opt_entry_t;

/**
 * @brief Table of option handlers supplied by the application.
 * REQ-DHCPv4-052, REQ-DHCPv4-058
 */
typedef struct {
  const dhcpv4_opt_entry_t *entries;
  uint8_t count;
} dhcpv4_opt_table_t;

/* ── Event callback ──────────────────────────────────────────────── */

/**
 * Application callback fired on client or server state transitions.
 * Shared by dhcpv4_client.h and dhcpv4_server.h — defined only once.
 *
 * @param event   One of DHCPV4_EVT_* or DHCPV4_SRV_EVT_*.
 * @param ctx     Application context pointer.
 */
#ifndef DHCPV4_EVENT_FN_T_DEFINED
#define DHCPV4_EVENT_FN_T_DEFINED
typedef void (*dhcpv4_event_fn_t)(uint8_t event, void *ctx);
#endif

/* ── Client state (application owns) ─────────────────────────────── */

/**
 * @brief DHCPv4 client state.  Zero-initialise before calling _init().
 * REQ-DHCPv4-001
 */
typedef struct {
  uint8_t state;       /**< DHCPV4_CLI_* */
  uint32_t xid;        /**< Current transaction ID (random) */
  uint32_t offered_ip; /**< IP offered by server (yiaddr) */
  uint32_t server_ip;  /**< Server Identifier option (54) */
  uint32_t lease_time; /**< IP Address Lease Time, seconds */
  uint32_t t1;         /**< Renewal time, seconds */
  uint32_t t2;         /**< Rebinding time, seconds */
  uint32_t timer_ms;   /**< Countdown to next action, ms */
  uint8_t retries;     /**< Retransmit counter */

  const dhcpv4_opt_table_t *opt_table; /**< Application option handlers */
  dhcpv4_event_fn_t on_event;          /**< State change callback */
  void *evt_ctx;                       /**< Passed to on_event */
} dhcpv4_client_t;

/* ── API ──────────────────────────────────────────────────────────── */

/**
 * Initialise client state.  Call before dhcpv4_client_start().
 *
 * @param c         Application-owned client state.
 * @param on_event  Called on BOUND/RENEWED/EXPIRED/NAK (may be NULL).
 * @param evt_ctx   Opaque pointer passed to on_event.
 * @param opts      Option handler table (may be NULL — REQ-DHCPv4-058).
 *
 * REQ-DHCPv4-052, REQ-DHCPv4-057, REQ-DHCPv4-058
 */
void dhcpv4_client_init(dhcpv4_client_t *c, dhcpv4_event_fn_t on_event,
                        void *evt_ctx, const dhcpv4_opt_table_t *opts);

/**
 * Begin DHCP discovery.  Sends DHCPDISCOVER and starts the retransmit timer.
 * net->ipv4_addr should be 0 (will be overwritten on BOUND).
 *
 * REQ-DHCPv4-002, REQ-DHCPv4-008..017
 */
void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c);

/**
 * Drive all DHCP timers.  Call with elapsed milliseconds from the main loop.
 *
 * REQ-DHCPv4-045..047
 */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms);

/**
 * Feed an incoming UDP payload (port 68) to the client.
 * Call from the application's port-68 UDP handler.
 *
 * REQ-DHCPv4-018..038, REQ-DHCPv4-041..044
 */
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *data, uint16_t len);

/**
 * Voluntarily release the lease.  Sends DHCPRELEASE and clears net->ipv4_addr.
 *
 * REQ-DHCPv4-039..040
 */
void dhcpv4_client_release(net_t *net, dhcpv4_client_t *c);

/**
 * Return current client state (DHCPV4_CLI_*).
 */
static inline uint8_t dhcpv4_client_state(const dhcpv4_client_t *c) {
  return c->state;
}

#ifdef __cplusplus
}
#endif

#endif /* DHCPV4_CLIENT_H */
