/**
 * @file dhcpv4_server.h
 * @brief DHCPv4 stateless single-client server.
 *
 * Designed for USB/CDC-ECM devices that must assign a fixed IP to one peer.
 * Always offers the same pre-configured IP regardless of client MAC.
 * No lease table. No timers. No dynamic allocation.
 *
 * Integrated like every protocol module (docs/integrating-modules.md):
 * dhcpv4_server_init(), and a UDP port-67 handler that calls
 * dhcpv4_server_input().
 */

#ifndef DHCPV4_SERVER_H
#define DHCPV4_SERVER_H

#include "ipv4.h" /* an IPv4 protocol: needs NET_USE_IPV4 */
#include "net.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Server event codes */
#define DHCPV4_SRV_EVT_OFFER 1 /**< DHCPOFFER sent */
#define DHCPV4_SRV_EVT_ACK 2   /**< DHCPACK sent */
#define DHCPV4_SRV_EVT_NAK 3   /**< DHCPNAK sent */

/** Called on DHCPV4_SRV_EVT_* with the context given to
 *  dhcpv4_server_init(). */
typedef void (*dhcpv4_server_event_fn_t)(uint8_t event, void *ctx);

/* Server configuration (application owns, typically const in flash) */

/**
 * @brief All server parameters provided at init time.
 */
typedef struct {
  uint32_t server_ip;    /**< Our IP (= DHCP server address) */
  uint32_t offered_ip;   /**< IP to offer and assign to the client */
  uint32_t subnet_mask;  /**< Subnet mask option (1) */
  uint32_t gateway;      /**< Default router option (3); 0 = omit */
  uint32_t dns;          /**< DNS server option (6); 0 = omit */
  uint32_t lease_time_s; /**< Lease time option (51); 0 = infinite */
} dhcpv4_server_cfg_t;

/* Server state (application owns) */

/**
 * @brief DHCPv4 server state.  No dynamic state — pure stimulus/response.
 */
typedef struct {
  const dhcpv4_server_cfg_t *cfg;    /**< Application configuration */
  dhcpv4_server_event_fn_t on_event; /**< May be NULL */
  void *evt_ctx;                     /**< Passed to on_event */
} dhcpv4_server_t;

/**
 * Initialise the server.  cfg must remain valid for the server's lifetime.
 *
 * @param s         Application-owned server state.
 * @param cfg       Server configuration (const in flash, owned by caller).
 * @param on_event  Called on OFFER/ACK/NAK (may be NULL).
 * @param evt_ctx   Passed to on_event.
 */
void dhcpv4_server_init(dhcpv4_server_t *s, const dhcpv4_server_cfg_t *cfg,
                        dhcpv4_server_event_fn_t on_event, void *evt_ctx);

/**
 * Feed an incoming UDP payload (port 67) to the server.
 * Processes one DHCP message and may send one reply from net->tx.buf.
 * Call from the application's port-67 UDP handler.
 *
 * @param net      Network context.
 * @param s        Server state.
 * @param src_ip   Client's source IPv4 (host byte order; may be 0 pre-lease).
 * @param src_mac  Client's source MAC (6 bytes); used for broadcast/unicast.
 * @param data     UDP payload bytes.
 * @param len      UDP payload length.
 */
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s, uint32_t src_ip,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* DHCPV4_SERVER_H */
