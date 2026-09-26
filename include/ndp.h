/**
 * @file ndp.h
 * @brief Neighbor Discovery for IPv6 (RFC 4861) and Duplicate Address
 *        Detection (RFC 4862 §5.4).
 *
 * Distributed-cache model, as ARP: no neighbour cache.  Solicitations for
 * our addresses are answered to the MAC they came from.
 */

#ifndef NDP_H
#define NDP_H

#include "eth.h"
#include "ipv6.h"
#include "net.h"
#include <stdint.h>

#define NDP_HOP_LIMIT 255 /* all ND messages (RFC 4861 §6.1, §7.1) */

/* ── Message layout (offsets in the ICMPv6 message) ───────────────── */

#define NDP_OFF_FLAGS 4   /* NA: R|S|O flags */
#define NDP_OFF_TARGET 8  /* NS, NA: target address */
#define NDP_NS_NA_LEN 24  /* NS/NA without options */

#define NDP_NA_FLAG_R 0x80 /* Router */
#define NDP_NA_FLAG_S 0x40 /* Solicited */
#define NDP_NA_FLAG_O 0x20 /* Override */

/* ── Options (TLV, length in units of 8 bytes) ────────────────────── */

#define NDP_OPT_SLLA 1   /* Source Link-Layer Address */
#define NDP_OPT_TLLA 2   /* Target Link-Layer Address */
#define NDP_OPT_PREFIX 3 /* Prefix Information */
#define NDP_OPT_MTU 5
#define NDP_OPT_LLA_LEN 8 /* type, length, 6-byte MAC */

/* ── Protocol constants (RFC 4861 §10) ────────────────────────────── */

#define NDP_RETRANS_TIMER_MS 1000
#define NDP_MAX_RTR_SOLICITATION_DELAY_MS 1000

/* ── Functions ────────────────────────────────────────────────────── */

/**
 * Process a Neighbor Discovery message (ICMPv6 types 133-137) whose
 * checksum icmpv6_input() has verified.
 */
void ndp_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth);

/**
 * Send a Neighbor Solicitation for @p target.
 * @param dad  1: Duplicate Address Detection probe (source ::, no Source
 *             Link-Layer Address option); 0: address resolution.
 */
net_err_t ndp_send_ns(net_t *net, const uint8_t *target, int dad);

/** Start DAD on address slot @p slot (state becomes TENTATIVE). */
void ndp_dad_start(net_t *net, uint8_t slot, uint16_t delay_ms);

/** Advance DAD timers by @p elapsed_ms (called by ipv6_tick()). */
void ndp_tick(net_t *net, uint32_t elapsed_ms);

#endif /* NDP_H */
