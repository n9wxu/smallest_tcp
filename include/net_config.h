/**
 * @file net_config.h
 * @brief Default configuration for development/testing on hosted platforms.
 *
 * Each target/application provides its own net_config.h on the include path.
 * This is the default for Linux TAP / macOS feth+BPF development.
 */

#ifndef NET_CONFIG_H
#define NET_CONFIG_H

/* ── Hardware capabilities (software MAC, no offload) ─────────────── */
#define NET_MAC_CAP_TX_CKSUM_IPV4 0
#define NET_MAC_CAP_TX_CKSUM_TCP 0
#define NET_MAC_CAP_TX_CKSUM_UDP 0
#define NET_MAC_CAP_RX_CKSUM_OK 0

/* ── Protocol inclusion ───────────────────────────────────────────── */
#define NET_USE_IPV4 1
#define NET_USE_IPV6 0
#define NET_USE_TCP 1
#define NET_USE_UDP 1
#define NET_USE_DHCPV4 0
#define NET_USE_DHCPV6 0
#define NET_USE_DNS 0
#define NET_USE_TFTP 0
#define NET_USE_HTTP 0

/* ── Architecture ─────────────────────────────────────────────────── */
#define NET_8BIT_TARGET 0

/* ── Debug ────────────────────────────────────────────────────────── */
#ifndef NET_DEBUG
#define NET_DEBUG 1
#endif
#ifndef NET_ASSERT_ENABLED
#define NET_ASSERT_ENABLED 1
#endif

/* ── Network identity defaults ────────────────────────────────────── */
#define NET_IPV4(a, b, c, d)                                                   \
  ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 |            \
   (uint32_t)(d))

#define NET_DEFAULT_IPV4_ADDR NET_IPV4(10, 0, 0, 2)
#define NET_DEFAULT_SUBNET_MASK NET_IPV4(255, 255, 255, 0)
#define NET_DEFAULT_GATEWAY NET_IPV4(10, 0, 0, 1)
#define NET_DEFAULT_DNS_SERVER NET_IPV4(0, 0, 0, 0)

#define NET_DEFAULT_MAC {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

/* ── ARP tuning ───────────────────────────────────────────────────── */
#define NET_DEFAULT_ARP_RETRY_MS 1000
#define NET_DEFAULT_ARP_MAX_RETRIES 3

/* ── TCP tuning (for future use) ──────────────────────────────────── */
#define NET_DEFAULT_TCP_RTO_INIT_MS 1000
#define NET_DEFAULT_TCP_RTO_MIN_MS 200
#define NET_DEFAULT_TCP_RTO_MAX_MS 60000
#define NET_DEFAULT_TCP_MSL_MS 120000
#define NET_DEFAULT_TCP_DELAYED_ACK_MS 200

#endif /* NET_CONFIG_H */
