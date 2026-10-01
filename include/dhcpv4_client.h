/**
 * @file dhcpv4_client.h
 * @brief DHCPv4 client — RFC 2131 state machine with option handler callbacks.
 *
 * Integrated like every protocol module (docs/integrating-modules.md):
 * dhcpv4_client_init(), a UDP port-68 handler calling
 * dhcpv4_client_input(), dhcpv4_client_start(), dhcpv4_client_tick().
 * Messages are built in net->tx.buf; dhcpv4_client_init() checks that the
 * frame buffers are large enough.
 */

#ifndef DHCPV4_CLIENT_H
#define DHCPV4_CLIENT_H

#include "ipv4.h" /* an IPv4 protocol: needs NET_USE_IPV4 */
#include "net.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The smallest frame buffers the client works with: TX a 300-byte
 *  message (RFC 2131 §2) after the Ethernet, IPv4 and UDP headers; RX the
 *  576-byte datagram a server may send a client that did not announce a
 *  larger Maximum DHCP Message Size (this one never does). */
#define DHCPV4_CLIENT_TX_MIN 342
#define DHCPV4_CLIENT_RX_MIN 590

/** The first DISCOVER after dhcpv4_client_start() waits a random time of
 *  one second to this many milliseconds — RFC 2131 §4.4.1's one to ten
 *  seconds, so devices powered up together do not all ask at once.  0
 *  sends it at once; otherwise 1000..65535. */
#ifndef DHCPV4_START_DELAY_MAX_MS
#define DHCPV4_START_DELAY_MAX_MS 10000
#endif

/** After the ACK of a new lease the client probes the address with ARP
 *  and waits this long for another host to show it is in use before using
 *  it (RFC 2131 §4.4.1; RFC 5227 §2.1.1 waits longer, with 3 probes). */
#ifndef DHCPV4_PROBE_WAIT_MS
#define DHCPV4_PROBE_WAIT_MS 1000
#endif

/** A split option (RFC 3396) is joined for its handler in a buffer of this
 *  many bytes, on the stack of dhcpv4_client_input(); a longer one is not
 *  delivered.  An option in one part is passed in place, whatever its
 *  length.  1..255 (a handler's length is 8 bits). */
#ifndef DHCPV4_SPLIT_OPTION_MAX
#define DHCPV4_SPLIT_OPTION_MAX 255
#endif

/* DHCP client states */
#define DHCPV4_CLI_INIT 0       /**< No address; after dhcpv4_client_start(),
                                     waiting to send the first DISCOVER */
#define DHCPV4_CLI_SELECTING 1  /**< DISCOVER sent, waiting for OFFER */
#define DHCPV4_CLI_REQUESTING 2 /**< OFFER received, REQUEST sent */
#define DHCPV4_CLI_BOUND 3      /**< ACK received, IP configured */
#define DHCPV4_CLI_RENEWING 4   /**< T1 expired; unicast REQUEST to server */
#define DHCPV4_CLI_REBINDING 5  /**< T2 expired; broadcast REQUEST */
/** ACK received; its address probed with ARP before it is used */
#define DHCPV4_CLI_CHECKING 6

/* Client event codes */
#define DHCPV4_EVT_BOUND 1   /**< IP address configured (BOUND entered) */
#define DHCPV4_EVT_RENEWED 2 /**< Lease extended by a renew or rebind */
#define DHCPV4_EVT_EXPIRED 3 /**< Lease expired; IP cleared, INIT restarted */
#define DHCPV4_EVT_NAK 4     /**< Server rejected request; INIT restarted */
#define DHCPV4_EVT_TIMEOUT 5 /**< No answer to the REQUEST for an offer;
                                  discovery restarts (RFC 2131 §3.1) */
/** The address of the ACK is in use (ARP): DHCPDECLINE sent, discovery
 *  restarts in 10 s (RFC 2131 §3.1) */
#define DHCPV4_EVT_DECLINED 6

/* Option handler callback */

/**
 * Application callback invoked once per DHCPACK that carries its option.
 *
 * @param option  DHCP option code (e.g. 3=Router, 6=DNS, 42=NTP).
 * @param data    The option's value (no code or length byte): the parts of
 *                an option split in several (RFC 3396) joined, from the
 *                'file' and 'sname' fields too when they hold options.
 *                Valid during the call only — do NOT retain past return.
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
  uint8_t state;           /**< DHCPV4_CLI_* */
  uint8_t retries;         /**< Retransmissions of the DISCOVER or REQUEST */
  uint16_t sec_ms;         /**< ms toward the next second of since_s */
  uint32_t xid;            /**< Current transaction ID (random) */
  uint32_t offered_ip;     /**< yiaddr of the OFFER, then of the ACK */
  uint32_t server_ip;      /**< Server Identifier option (54) */
  uint8_t server_mac[6];   /**< Where the ACK came from: the server, or the
                                relay agent on the way to it */
  uint32_t lease_time;     /**< Lease time, seconds; 0xFFFFFFFF = infinite */
  uint32_t t1;             /**< Renewal time, seconds into the lease */
  uint32_t t2;             /**< Rebinding time, seconds into the lease */
  uint32_t since_s;        /**< The lease clock: seconds since the lease was
                                requested (from the first REQUEST) */
  uint32_t request_s;      /**< since_s when the first REQUEST of the state
                                went: a lease its ACK grants starts then */
  uint32_t next_request_s; /**< since_s of the next REQUEST: T1, then the
                                RENEWING and REBINDING retransmissions */
  uint32_t timer_ms;       /**< Until the first DISCOVER (INIT), the next
                                DISCOVER or REQUEST retransmission
                                (SELECTING, REQUESTING), or the end of the
                                ARP probe (CHECKING) */

  const dhcpv4_opt_table_t *opt_table; /**< Application option handlers */
  dhcpv4_client_event_fn_t on_event;   /**< State change callback */
  void *evt_ctx;                       /**< Passed to on_event */
} dhcpv4_client_t;

/**
 * Initialise client state.  Call before dhcpv4_client_start().
 *
 * @param c         Application-owned client state.
 * @param net       The interface, whose frame buffers must hold
 *                  DHCPV4_CLIENT_TX_MIN and DHCPV4_CLIENT_RX_MIN bytes.
 * @param on_event  Called on DHCPV4_EVT_* (may be NULL).
 * @param evt_ctx   Opaque pointer passed to on_event.
 * @param opts      Option handler table (may be NULL).
 * @return NET_OK, NET_ERR_INVALID_PARAM, or NET_ERR_BUF_TOO_SMALL.
 */
net_err_t dhcpv4_client_init(dhcpv4_client_t *c, const net_t *net,
                             dhcpv4_client_event_fn_t on_event, void *evt_ctx,
                             const dhcpv4_opt_table_t *opts);

/**
 * Begin DHCP discovery: the first DHCPDISCOVER goes after a random wait
 * (DHCPV4_START_DELAY_MAX_MS), counted by dhcpv4_client_tick().
 * net->ipv4_addr, subnet_mask and gateway_ipv4 are cleared until BOUND.
 */
void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c);

/**
 * Drive all DHCP timers.  Call with elapsed milliseconds from the main loop.
 */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms);

/**
 * Feed an incoming UDP payload (port 68) to the client.
 * Call from the application's port-68 UDP handler.
 * @param src_mac  Source MAC of its frame (6 bytes): an ACK's is where
 *                 renewals and the RELEASE are unicast.
 */
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len);

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
