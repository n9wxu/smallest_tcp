/**
 * @file eth.h
 * @brief Ethernet II framing (RFC 894), parsed and built in place.
 */

#ifndef ETH_H
#define ETH_H

#include "net.h"
#include <stdint.h>

#define ETH_OFF_DST 0
#define ETH_OFF_SRC 6
#define ETH_OFF_TYPE 12
#define ETH_HDR_SIZE 14
#define ETH_MTU 1500 /**< The largest payload a frame carries */

/** The longest frame a buffer of @p capacity sends or takes on this link:
 *  no more than the header and the interface's MTU (net->mtu) */
static inline uint16_t eth_frame_room(const net_t *net, uint16_t capacity) {
  uint32_t link = (uint32_t)ETH_HDR_SIZE + net->mtu;
  return capacity < link ? capacity : (uint16_t)link;
}

#define NET_ETHERTYPE_IPV4 0x0800
#define NET_ETHERTYPE_ARP 0x0806
#define NET_ETHERTYPE_IPV6 0x86DD

/** Type fields up to this value are IEEE 802.3 lengths, not EtherTypes. */
#define ETH_MAX_8023_LENGTH 0x05DC

/** A received frame; the pointers point into it. */
typedef struct {
  const uint8_t *dst_mac;
  const uint8_t *src_mac;
  uint16_t ethertype;
  uint8_t *payload;
  uint16_t payload_len;
} eth_frame_t;

/**
 * Parse an Ethernet II header.
 * @return NET_OK, or NET_ERR_INVALID_PARAM for a runt or an 802.3 frame.
 */
net_err_t eth_parse(uint8_t *frame, uint16_t frame_len, eth_frame_t *out);

/**
 * Write an Ethernet II header at @p buf.
 * @return Where the payload goes (buf + 14), or NULL if it does not fit.
 */
uint8_t *eth_build(uint8_t *buf, uint16_t buf_capacity, const uint8_t *dst_mac,
                   const uint8_t *src_mac, uint16_t ethertype);

/**
 * Accept a received frame addressed to us (our MAC, broadcast, or a
 * joined multicast group) and dispatch it by EtherType.
 */
void eth_input(net_t *net, uint8_t *frame, uint16_t len);

#endif /* ETH_H */
