/**
 * @file net.h
 * @brief Core network types, error codes, and factory methods.
 *
 * The application owns all memory. The stack provides type definitions
 * and factory/init functions to validate and initialize state.
 */

#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <string.h>

#include "net_config.h"
#include "net_endian.h"
#include "net_mac.h"

/* ── Error codes ──────────────────────────────────────────────────── */

typedef enum {
  NET_OK = 0,
  NET_ERR_BUF_TOO_SMALL = -1,
  NET_ERR_INVALID_PARAM = -2,
  NET_ERR_NO_FRAME = -3,
} net_err_t;

/* ── Compile-time size macros ─────────────────────────────────────── */

#define NET_ETH_HDR_SIZE 14
#define NET_IPV4_HDR_SIZE 20
#define NET_UDP_HDR_SIZE 8
#define NET_TCP_HDR_SIZE 20

#define NET_MIN_BUF_ETH NET_ETH_HDR_SIZE
#define NET_MIN_BUF_IPV4 (NET_ETH_HDR_SIZE + NET_IPV4_HDR_SIZE)
#define NET_MIN_BUF_UDP                                                        \
  (NET_ETH_HDR_SIZE + NET_IPV4_HDR_SIZE + NET_UDP_HDR_SIZE)
#define NET_MIN_BUF_TCP                                                        \
  (NET_ETH_HDR_SIZE + NET_IPV4_HDR_SIZE + NET_TCP_HDR_SIZE)
#define NET_MIN_BUF_DHCP 576

#define NET_IPV6_HDR_SIZE 40
#define NET_TCP_MSS_IPV6(buf)                                                  \
  ((buf) - NET_ETH_HDR_SIZE - NET_IPV6_HDR_SIZE - NET_TCP_HDR_SIZE)

#define NET_TCP_MSS_IPV4(buf)                                                  \
  ((buf) - NET_ETH_HDR_SIZE - NET_IPV4_HDR_SIZE - NET_TCP_HDR_SIZE)
#define NET_UDP_MAX_IPV4(buf)                                                  \
  ((buf) - NET_ETH_HDR_SIZE - NET_IPV4_HDR_SIZE - NET_UDP_HDR_SIZE)

#define NET_MAX_FRAME_SIZE 1514 /* Max Ethernet II frame without FCS */

/* ── EtherType constants ──────────────────────────────────────────── */

#define NET_ETHERTYPE_IPV4 0x0800
#define NET_ETHERTYPE_ARP 0x0806
#define NET_ETHERTYPE_IPV6 0x86DD

/* ── Broadcast MAC ────────────────────────────────────────────────── */

#define NET_MAC_BROADCAST {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

/* ── Network buffer ───────────────────────────────────────────────── */

/**
 * @brief Wraps an application-provided byte array.
 */
typedef struct {
  uint8_t *buf;       /**< Pointer to application's buffer */
  uint16_t capacity;  /**< Buffer size (set at init, never changes) */
  uint16_t frame_len; /**< Current frame length (0 = empty) */
} net_buf_t;

/* ── IPv6 address slot ────────────────────────────────────────────── */

#if NET_USE_IPV6
/* Address states (RFC 4862 §2).  Only PREFERRED and DEPRECATED addresses
 * send and receive ordinary traffic. */
#define NET_IP6_NONE 0       /**< Slot unused */
#define NET_IP6_TENTATIVE 1  /**< Duplicate Address Detection running */
#define NET_IP6_PREFERRED 2  /**< Unique; use freely */
#define NET_IP6_DEPRECATED 3 /**< Valid, but not for new connections */
#define NET_IP6_DUPLICATE 4  /**< DAD found another owner: never used */

#define NET_IP6_INFINITE 0xFFFFFFFFu /**< Lifetime that never runs out */

/**
 * @brief One IPv6 address of the interface (network byte order).
 */
typedef struct {
  uint8_t addr[16];
  uint8_t state;        /**< NET_IP6_* */
  uint8_t dad_left;     /**< DAD Neighbor Solicitations still to send */
  uint16_t timer_ms;    /**< Until the next DAD step */
  uint32_t valid_s;     /**< Valid lifetime left (NET_IP6_INFINITE) */
  uint32_t preferred_s; /**< Preferred lifetime left (NET_IP6_INFINITE) */
} net_ip6_addr_t;
#endif

/* ── Network context ──────────────────────────────────────────────── */

/**
 * @brief One per network interface. Application owns this struct.
 */
typedef struct {
  net_buf_t rx;
  net_buf_t tx;
  uint32_t ipv4_addr; /**< Host byte order. 0 = unconfigured */
  uint8_t mac[6];
  const net_mac_t *mac_driver;
  void *mac_ctx;
  uint32_t gateway_ipv4; /**< Host byte order */
  uint8_t gateway_mac[6];
  uint8_t gateway_mac_valid;
  uint32_t subnet_mask; /**< Host byte order */
  uint16_t arp_retry_ms;
  uint8_t arp_max_retries;
#if NET_MAX_MCAST_GROUPS > 0
  /** Joined IPv4 multicast groups, host byte order (0 = free slot).
   *  Managed by ipv4_mcast_join() / ipv4_mcast_leave(). */
  uint32_t mcast_groups[NET_MAX_MCAST_GROUPS];
#endif
#if NET_USE_IPV6
  /** [0] link-local (formed by ipv6_start()), [1..] global. */
  net_ip6_addr_t ip6[NET_IPV6_ADDRS];
  uint8_t ip6_hop_limit; /**< For outgoing packets (Cur Hop Limit) */
  uint32_t ip6_rng;      /**< xorshift32 state for protocol jitter */
  uint8_t ip6_router[16];     /**< Default router (link-local address) */
  uint8_t ip6_router_mac[6];  /**< Its MAC */
  uint16_t ip6_router_life_s; /**< Router lifetime left; 0 = no router */
  uint8_t ip6_ra_flags;       /**< M (0x80) / O (0x40) of the last RA */
  uint8_t ip6_rs_left;        /**< Router Solicitations still to send */
  uint16_t ip6_rs_timer_ms;   /**< Until the next Router Solicitation */
  uint16_t ip6_sec_ms;        /**< ms toward the next lifetime second */
#if NET_MAX_MCAST6_GROUPS > 0
  /** Joined IPv6 groups (ipv6_mcast_join()); all-zero = free slot */
  uint8_t mcast6_groups[NET_MAX_MCAST6_GROUPS][16];
#endif
  uint16_t mld_query_ms; /**< Until we answer an MLD query; 0 = none */
  uint16_t mld_unsol_ms; /**< Until the unsolicited report is repeated */
  uint16_t mld_v1_s;     /**< MLDv1 querier seen: seconds of v1 mode left */
#endif
} net_t;

/* ── Factory methods ──────────────────────────────────────────────── */

/**
 * Initialize a network context. Validates buffer sizes, sets defaults
 * from net_config.h, and connects the MAC driver.
 *
 * @param net         Pointer to application-owned net_t.
 * @param rx_buf      Application-owned receive buffer.
 * @param rx_size     Size of receive buffer.
 * @param tx_buf      Application-owned transmit buffer.
 * @param tx_size     Size of transmit buffer.
 * @param mac         6-byte MAC address (NULL to use NET_DEFAULT_MAC).
 * @param driver      Pointer to MAC driver vtable.
 * @param driver_ctx  Pointer to driver-specific context.
 * @return NET_OK on success, or error code.
 */
net_err_t net_init(net_t *net, uint8_t *rx_buf, uint16_t rx_size,
                   uint8_t *tx_buf, uint16_t tx_size, const uint8_t mac[6],
                   const net_mac_t *driver, void *driver_ctx);

/**
 * Poll for one incoming Ethernet frame.
 *
 * Calls mac_driver->poll(). If a frame is available, copies it into
 * net->rx.buf via peek() and sets net->rx.frame_len, then calls
 * discard() to release the MAC's RX slot.
 *
 * The frame is accessible via net->rx.buf and net->rx.frame_len after
 * this call returns a positive value.
 *
 * @param net  Network context.
 * @return Frame length in bytes (>0) if a frame was received,
 *         0 if no frame was available, <0 on driver error.
 */
int net_poll(net_t *net);

/* ── Debug / Assert ───────────────────────────────────────────────── */

#if NET_DEBUG
#include <stdio.h>
static inline void net_log_noop(const char *fmt, ...) { (void)fmt; }
#define NET_LOG(...) fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#else
static inline void net_log_noop(const char *fmt, ...) { (void)fmt; }
#define NET_LOG(...) net_log_noop(__VA_ARGS__)
#endif

#if NET_ASSERT_ENABLED
#include <assert.h>
#define NET_ASSERT(cond) assert(cond)
#else
#define NET_ASSERT(cond) ((void)0)
#endif

/* ── Utility: compare MAC addresses ───────────────────────────────── */

static inline int net_mac_equal(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

static inline int net_mac_is_broadcast(const uint8_t *mac) {
  return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF && mac[3] == 0xFF &&
         mac[4] == 0xFF && mac[5] == 0xFF;
}

static inline int net_mac_is_multicast(const uint8_t *mac) {
  return (mac[0] & 0x01) != 0;
}

#endif /* NET_H */
