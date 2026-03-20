/**
 * @file eth.c
 * @brief Ethernet II frame parsing and building — zero-copy, in-place.
 *
 * Implements REQ-ETH-001 through REQ-ETH-020.
 */

#include "eth.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_IPV4
#include "arp.h"
#include "ipv4.h"
#endif

/* ── Parse ────────────────────────────────────────────────────────── */

net_err_t eth_parse(uint8_t *frame, uint16_t frame_len, eth_frame_t *out) {
  /* REQ-ETH-009: discard frames shorter than 14 bytes */
  if (frame_len < ETH_HDR_SIZE) {
    return NET_ERR_INVALID_PARAM;
  }

  /* REQ-ETH-004: parse EtherType at offset 12 as big-endian uint16 */
  uint16_t ethertype = net_read16be(frame + ETH_OFF_TYPE);

  /* REQ-ETH-017: reject 802.3 length-encoded frames (EtherType <= 0x05DC) */
  if (ethertype <= 0x05DC) {
    return NET_ERR_INVALID_PARAM;
  }

  /* REQ-ETH-019: parse headers in-place — pointers into original buffer */
  out->dst_mac = frame + ETH_OFF_DST;
  out->src_mac = frame + ETH_OFF_SRC;
  out->ethertype = ethertype;
  out->payload = frame + ETH_HDR_SIZE;
  /* REQ-ETH-018: payload length = frame_len - 14 */
  out->payload_len = frame_len - ETH_HDR_SIZE;

  return NET_OK;
}

/* ── Build ────────────────────────────────────────────────────────── */

uint8_t *eth_build(uint8_t *buf, uint16_t buf_capacity, const uint8_t *dst_mac,
                   const uint8_t *src_mac, uint16_t ethertype) {
  /* Need at least 14 bytes for the header */
  if (buf_capacity < ETH_HDR_SIZE) {
    return (void *)0; /* NULL */
  }

  /* REQ-ETH-011: write destination MAC, source MAC, EtherType */
  /* REQ-ETH-020: build headers in-place in application buffer */
  memcpy(buf + ETH_OFF_DST, dst_mac, 6); /* REQ-ETH-011 */
  memcpy(buf + ETH_OFF_SRC, src_mac, 6); /* REQ-ETH-012: source = our MAC */
  net_write16be(buf + ETH_OFF_TYPE, ethertype); /* REQ-ETH-013/014/015 */

  return buf + ETH_HDR_SIZE;
}

/* ── Input processing ─────────────────────────────────────────────── */

void eth_input(net_t *net, uint8_t *frame, uint16_t len) {
  eth_frame_t eth;

  if (eth_parse(frame, len, &eth) != NET_OK) {
    NET_LOG("eth_input: parse failed (len=%u)", len);
    return;
  }

  /* REQ-ETH-001, REQ-ETH-002, REQ-ETH-003: MAC filtering */
  if (!net_mac_equal(eth.dst_mac, net->mac) &&
      !net_mac_is_broadcast(eth.dst_mac)) {
    /* Not for us and not broadcast — discard silently */
    return;
  }

  /* Dispatch by EtherType */
  switch (eth.ethertype) {
#if NET_USE_IPV4
  case NET_ETHERTYPE_ARP:
    /* REQ-ETH-006: dispatch 0x0806 to ARP */
    arp_input(net, &eth);
    break;
  case NET_ETHERTYPE_IPV4:
    /* REQ-ETH-005: dispatch 0x0800 to IPv4 */
    ipv4_input(net, &eth);
    break;
#endif
#if NET_USE_IPV6
  case NET_ETHERTYPE_IPV6:
    /* REQ-ETH-007: dispatch 0x86DD to IPv6 */
    NET_LOG("eth_input: IPv6 frame (%u bytes payload)", eth.payload_len);
    /* TODO: ipv6_input(net, &eth) */
    break;
#endif
  default:
    /* REQ-ETH-008: silently discard unrecognized EtherType */
    NET_LOG("eth_input: unknown EtherType 0x%04x, discarding", eth.ethertype);
    break;
  }
}
