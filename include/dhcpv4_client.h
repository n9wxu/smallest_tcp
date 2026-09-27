/**
 * @file dhcpv4_client.h
 * @brief DHCPv4 client — RFC 2131 state machine with option handler callbacks.
 *
 * Integrated like every protocol module (docs/integrating-modules.md):
 * dhcpv4_client_init(), a UDP port-68 handler calling
 * dhcpv4_client_input(), dhcpv4_client_start(), dhcpv4_client_tick().
 * Messages are built in net->tx.buf; they need a TX buffer of at least
 * 342 bytes.
 */

#ifndef DHCPV4_CLIENT_H
#define DHCPV4_CLIENT_H

#include "net.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DHCP client states */
#define DHCPV4_CLI_INIT 0       /**< No address; will send DISCOVER */
#define DHCPV4_CLI_SELECTING 1  /**< DISCOVER sent, waiting for OFFER */
#define DHCPV4_CLI_REQUESTING 2 /**< OFFER received, REQUEST sent */
#define DHCPV4_CLI_BOUND 3      /**< ACK received, IP configured */
#define DHCPV4_CLI_RENEWING 4   /**< T1 expired; unicast REQUEST to server */
#define DHCPV4_CLI_REBINDING 5  /**< T2 expired; broadcast REQUEST */

/* Client event codes */
#define DHCPV4_EVT_BOUND 1   /**< IP address configured (BOUND entered) */
#define DHCPV4_EVT_RENEWED 2 /**< Lease extended by a renew or rebind */
#define DHCPV4_EVT_EXPIRED 3 /**< Lease expired; IP cleared, INIT restarted */
#define DHCPV4_EVT_NAK 4     /**< Server rejected request; INIT restarted */

/* Option handler callback */

/**
 * Application callback invoked for each DHCP option found in DHCPACK.
 *
 * @param option  DHCP option code (e.g. 3=Router, 6=DNS, 42=NTP).
 * @param data    Pointer to raw TLV value bytes (NOT including type or length).
 *                Points into the DHCP receive buffer — do NOT retain past
 * return.
 * @param len     Number of value bytes.
 * @param ctx     Application context from the registration entry.
 */
typedef void (*dhcpv4_opt_handler_t)(uint8_t option, const uint8_t *data,
                                     uint8_t len, void *ctx);

/**
 * @brief One entry in the application's option handler table.
 */
typedef struct {
  uint8_t option;               /**< DHCP option code to watch */
  dhcpv4_opt_handler_t handler; /**< Callback when option is found */
  void *ctx;                    /**< Passed unchanged to handler */
} dhcpv4_opt_entry_t;

/**
 * @brief Table of option handlers supplied by the application.
 */
typedef struct {
  const dhcpv4_opt_entry_t *entries;
  uint8_t count;
} dhcpv4_opt_table_t;

/** Called on DHCPV4_EVT_* with the context given to dhcpv4_client_init(). */
typedef void (*dhcpv4_client_event_fn_t)(uint8_t event, void *ctx);

/* Client state (application owns) */

/**
 * @brief DHCPv4 client state.  Zero-initialise before calling _init().
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
  dhcpv4_client_event_fn_t on_event;   /**< State change callback */
  void *evt_ctx;                       /**< Passed to on_event */
} dhcpv4_client_t;

/**
 * Initialise client state.  Call before dhcpv4_client_start().
 *
 * @param c         Application-owned client state.
 * @param on_event  Called on BOUND/RENEWED/EXPIRED/NAK (may be NULL).
 * @param evt_ctx   Opaque pointer passed to on_event.
 * @param opts      Option handler table (may be NULL).
 */
void dhcpv4_client_init(dhcpv4_client_t *c, dhcpv4_client_event_fn_t on_event,
                        void *evt_ctx, const dhcpv4_opt_table_t *opts);

/**
 * Begin DHCP discovery.  Sends DHCPDISCOVER and starts the retransmit timer.
 * net->ipv4_addr should be 0 (will be overwritten on BOUND).
 */
void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c);

/**
 * Drive all DHCP timers.  Call with elapsed milliseconds from the main loop.
 */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms);

/**
 * Feed an incoming UDP payload (port 68) to the client.
 * Call from the application's port-68 UDP handler.
 */
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *data, uint16_t len);

/**
 * Voluntarily release the lease.  Sends DHCPRELEASE and clears net->ipv4_addr.
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
