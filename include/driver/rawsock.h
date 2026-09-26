/**
 * @file driver/rawsock.h
 * @brief Linux raw-socket (AF_PACKET) network driver for the MAC HAL.
 *
 * Sends and receives raw Ethernet frames on an existing interface — a real
 * NIC (eth0, a USB adapter) or one end of a veth pair — without
 * /dev/net/tun.  Needs root or CAP_NET_RAW.
 *
 * The stack has its own MAC address, so the driver puts the interface in
 * promiscuous mode while the socket is open (the kernel undoes it on close).
 * Frames the driver sends are not read back.
 *
 * Checksum offload: frames the local kernel sends (from the veth peer, or
 * to a local tap) can carry a partial TCP/UDP checksum that "hardware" was
 * meant to finish.  The driver finishes it, the way the NIC would have.
 * Frames larger than a full Ethernet frame (GRO/GSO super-frames) are
 * dropped and counted in rx_dropped.
 *
 * veth test pair (the SUT end has no IP configuration of its own):
 *   sudo ip link add veth-test type veth peer name veth-sut
 *   sudo sysctl -w net.ipv6.conf.veth-sut.disable_ipv6=1
 *   sudo ip addr add 10.0.0.100/24 dev veth-test
 *   sudo ip link set veth-sut up && sudo ip link set veth-test up
 *   sudo ./build/demo/tcp_echo_demo raw:veth-sut
 */

#ifndef DRIVER_RAWSOCK_H
#define DRIVER_RAWSOCK_H

#include "net_mac.h"
#include <stdint.h>

/**
 * @brief Raw-socket driver context. Application allocates this.
 */
typedef struct {
  int fd;                 /**< AF_PACKET socket */
  int ifindex;            /**< Index of the bound interface */
  char ifname[16];        /**< Interface name (e.g., "eth0") */
  uint8_t rx_frame[1514]; /**< Internal read buffer for peek support */
  uint16_t rx_len;        /**< Bytes currently in rx_frame */
  uint32_t rx_dropped;    /**< Oversize / segmentation-offload frames dropped */
} rawsock_ctx_t;

#ifdef __linux__
/**
 * @brief MAC driver vtable for the Linux raw socket.
 *
 * Usage:
 *   rawsock_ctx_t raw;
 *   rawsock_ctx_init(&raw, "veth-sut");
 *   rawsock_mac_ops.init(&raw);
 */
extern const net_mac_t rawsock_mac_ops;

/**
 * Initialize a raw-socket context with default values.
 * @param ctx     Context to initialize.
 * @param ifname  Interface to bind (e.g., "eth0"). NULL for default "eth0".
 */
void rawsock_ctx_init(rawsock_ctx_t *ctx, const char *ifname);
#endif

/**
 * Finish a transport checksum left partial by checksum offload, as the NIC
 * would: the checksum field at csum_start + csum_offset holds the folded
 * pseudo-header sum; the Internet checksum of frame[csum_start..len)
 * replaces it.  Portable (no socket) so it can be unit-tested anywhere.
 *
 * @param frame        Ethernet frame, modified in place.
 * @param len          Frame length.
 * @param csum_start   Offset of the checksummed region (the L4 header).
 * @param csum_offset  Offset of the checksum field within that region.
 * @return 0 on success, -1 if the checksum field lies outside the frame.
 */
int rawsock_csum_complete(uint8_t *frame, uint16_t len, uint16_t csum_start,
                          uint16_t csum_offset);

#endif /* DRIVER_RAWSOCK_H */
