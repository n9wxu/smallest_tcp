/**
 * @file net.h
 * @brief The network interface (net_t) and the stack's entry points:
 *        net_poll() for received frames, net_tick() for timers.
 *
 * The application owns all memory; net_init() checks and initialises it.
 */

#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <string.h>

#include "net_config.h"
#include "net_endian.h"
#include "net_mac.h"

typedef enum {
  NET_OK = 0,
  NET_ERR_BUF_TOO_SMALL = -1,
  NET_ERR_INVALID_PARAM = -2,
  NET_ERR_NO_FRAME = -3,
  NET_ERR_BUSY = -4,
} net_err_t;

/** An application-provided frame buffer. */
typedef struct {
  uint8_t *buf;
  uint16_t capacity;
} net_buf_t;

#if NET_USE_IPV6
/* Address states (RFC 4862 §2).  Only PREFERRED and DEPRECATED addresses
 * send and receive ordinary traffic. */
#define NET_IP6_NONE 0      /**< Slot unused */
#define NET_IP6_TENTATIVE 1 /**< Duplicate Address Detection running */
#define NET_IP6_PREFERRED 2
#define NET_IP6_DEPRECATED 3 /**< Valid, but not for new connections */
#define NET_IP6_DUPLICATE 4  /**< DAD found another owner: never used */

#define NET_IP6_INFINITE 0xFFFFFFFFu /**< Lifetime that never runs out */

/** One IPv6 address of the interface (network byte order). */
typedef struct {
  uint8_t addr[16];
  uint8_t state; /**< NET_IP6_* */
  uint8_t dad_probes_left;
  uint16_t dad_timer_ms; /**< Until the next DAD step */
  uint32_t valid_s;      /**< Seconds, or NET_IP6_INFINITE */
  uint32_t preferred_s;  /**< Seconds, or NET_IP6_INFINITE */
} net_ip6_addr_t;

/** The default router, from Router Advertisements. */
typedef struct {
  uint8_t addr[16]; /**< Its link-local address */
  uint8_t mac[6];
  uint16_t lifetime_s; /**< 0: no default router */
} net_ip6_router_t;

/** Multicast Listener Discovery timers (mld.c). */
typedef struct {
  uint16_t query_reply_ms;    /**< Until a query is answered; 0: none due */
  uint16_t report_repeat_ms;  /**< Until a change report is repeated */
  uint16_t v1_querier_left_s; /**< MLDv1 compatibility mode left */
} net_mld_t;

/** The interface's IPv6 state (ipv6.c, ndp.c, mld.c). */
typedef struct {
  net_ip6_addr_t addr[NET_IPV6_ADDRS]; /**< [0] link-local, [1..] global */
  uint8_t hop_limit;                   /**< For outgoing packets */
  uint8_t ra_flags;                    /**< NDP_RA_MANAGED / NDP_RA_OTHER */
  net_ip6_router_t router;
  uint8_t router_solicits_left;
  uint16_t router_solicit_ms; /**< Until the next one */
  uint16_t lifetime_carry_ms; /**< Toward the next lifetime second */
  net_mld_t mld;
} net_ip6_t;
#endif

struct udp_port_entry_s;
struct udp6_port_entry_s;
struct tcp_conn_s;

/** One per network interface. */
typedef struct {
  net_buf_t rx;
  net_buf_t tx;
  uint8_t mac[6];
  uint16_t mtu; /**< The link MTU: datagrams sent are no longer */
  const net_mac_t *mac_driver;
  void *mac_ctx;
  uint32_t secret[2];    /**< net_hash() key */
  uint32_t random_count; /**< net_random() outputs so far */

#if NET_USE_IPV4
  /* IPv4, host byte order; 0 = unconfigured */
  uint32_t ipv4_addr;
  uint32_t subnet_mask;
  uint32_t gateway_ipv4;
  uint8_t gateway_mac[6];
  uint8_t gateway_mac_valid;
  /** Seconds until an ARP-learned gateway MAC is out of date; 0: never (a
   *  MAC set by hand) */
  uint16_t gateway_mac_s;
  uint16_t arp_carry_ms;
  /** Recent ARP requests: none again within a second */
  struct {
    uint32_t ip;
    uint16_t ms_left;
  } arp_recent[NET_ARP_RATE_SLOTS];
#if NET_MAX_MCAST_GROUPS > 0
  uint32_t mcast_groups[NET_MAX_MCAST_GROUPS]; /**< Joined; 0 = free */
#endif
#endif

#if NET_USE_IPV6
  net_ip6_t ip6; /**< Reset by ipv6_start() */
#if NET_MAX_MCAST6_GROUPS > 0
  uint8_t mcast6_groups[NET_MAX_MCAST6_GROUPS][16]; /**< Joined; :: = free */
#endif
#endif

  /* Where received segments and datagrams go (udp_set_ports(),
   * tcp_set_connections()) */
#if NET_USE_UDP
#if NET_USE_IPV4
  const struct udp_port_entry_s *udp_ports;
  uint32_t udp_rx_dst; /**< In a handler: udp_rx_dst_ip() */
  /** udp_set_error_handler()'s udp_error_handler_t (udp.h), kept as the
   *  generic function pointer type and converted back to be called */
  void (*udp_error_handler)(void);
  uint8_t udp_port_count;
#endif
#if NET_USE_IPV6
  const struct udp6_port_entry_s *udp6_ports;
  uint8_t udp6_port_count;
#endif
#endif
#if NET_USE_TCP
  struct tcp_conn_s *const *tcp_conns;
  uint8_t tcp_conn_count;
  uint32_t tcp_clock; /**< 4 µs ticks, for initial sequence numbers */
#endif
} net_t;

/**
 * Initialise a network context: buffers, MAC address (NULL for
 * NET_DEFAULT_MAC), MAC driver, and the net_config.h identity defaults
 * (the IPv4 address, mask and gateway, with IPv4 compiled in).
 * The RX and TX buffers must not overlap.
 * @return NET_OK, NET_ERR_INVALID_PARAM (also: overlapping buffers), or
 *         NET_ERR_BUF_TOO_SMALL for a buffer smaller than TCP_MIN_FRAME
 *         (tcp.h) with TCP compiled in, else than an Ethernet header.
 */
net_err_t net_init(net_t *net, uint8_t *rx_buf, uint16_t rx_size,
                   uint8_t *tx_buf, uint16_t tx_size, const uint8_t mac[6],
                   const net_mac_t *driver, void *driver_ctx);

/**
 * Receive and process one frame, if the MAC has one: it is read into
 * net->rx.buf, dispatched through the protocol layers, and released.
 * @return The frame's length, 0 if none was waiting, < 0 on driver error.
 */
int net_poll(net_t *net);

/** Advance the stack's own timers (TCP, IPv6) by @p elapsed_ms. */
void net_tick(net_t *net, uint32_t elapsed_ms);

/**
 * Send the frame of @p frame_len bytes built in net->tx.buf.
 * @return NET_OK, NET_ERR_BUSY if the driver had no room for it, or
 *         NET_ERR_NO_FRAME if the driver failed.
 */
net_err_t net_transmit(net_t *net, uint16_t frame_len);

/* Randomness: HalfSipHash-2-4 under a secret key, so no output gives
 * away the key or any other output */

/**
 * Mix @p len bytes of @p entropy into the secret, every byte of it.
 * net_init() seeds it from the MAC address, which differs per device but is
 * public: seed it from a true random source where one exists — 8 bytes or
 * more fill the 64-bit key (TCP initial sequence numbers and DHCP
 * transaction IDs depend on it).  Seeds add up.
 */
void net_random_seed(net_t *net, const uint8_t *entropy, uint16_t len);

/** HalfSipHash-2-4 of @p data under the secret. */
uint32_t net_hash(const net_t *net, const uint8_t *data, uint16_t len);

/** The hash of a count of the outputs so far. */
uint32_t net_random(net_t *net);

/** Uniform in [0, @p n) for n <= 65536, by scaling. */
uint32_t net_random_below(net_t *net, uint32_t n);

/* Timers */

/** Count @p *ms_left down by @p elapsed_ms; 1 once it has run out. */
static inline int net_countdown(uint32_t *ms_left, uint32_t elapsed_ms) {
  if (*ms_left > elapsed_ms) {
    *ms_left -= elapsed_ms;
    return 0;
  }
  *ms_left = 0;
  return 1;
}

static inline int net_countdown16(uint16_t *ms_left, uint32_t elapsed_ms) {
  if (*ms_left > elapsed_ms) {
    *ms_left = (uint16_t)(*ms_left - elapsed_ms);
    return 0;
  }
  *ms_left = 0;
  return 1;
}

/** Whole seconds in @p *carry_ms + @p elapsed_ms; the rest stays in carry. */
uint32_t net_whole_seconds(uint16_t *carry_ms, uint32_t elapsed_ms);

/* Debug log */

#if NET_DEBUG
#include <stdio.h>
#define NET_LOG(...) fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#else
static inline void net_log_noop(const char *fmt, ...) { (void)fmt; }
#define NET_LOG(...) net_log_noop(__VA_ARGS__)
#endif

/* MAC addresses */
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
