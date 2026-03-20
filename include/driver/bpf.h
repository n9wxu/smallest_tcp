/**
 * @file driver/bpf.h
 * @brief macOS BPF (Berkeley Packet Filter) network driver for the MAC HAL.
 *
 * Uses /dev/bpfN bound to an feth interface to send/receive
 * raw Ethernet frames in userspace on macOS.
 *
 * Setup (run once before using):
 *   sudo ifconfig feth0 create
 *   sudo ifconfig feth1 create
 *   sudo ifconfig feth0 peer feth1
 *   sudo ifconfig feth0 10.0.0.1/24 up
 *   sudo ifconfig feth1 up
 *
 * The SUT opens feth1 via BPF; the host stack uses feth0.
 */

#ifndef DRIVER_BPF_H
#define DRIVER_BPF_H

#include "net_mac.h"
#include <stdint.h>

/** Maximum BPF read buffer size */
#define BPF_READ_BUF_SIZE 4096

/**
 * @brief BPF driver context. Application allocates this.
 */
typedef struct {
  int fd;                              /**< BPF file descriptor */
  char ifname[16];                     /**< Interface name (e.g., "feth1") */
  uint8_t read_buf[BPF_READ_BUF_SIZE]; /**< BPF read buffer (may contain
                                          multiple frames) */
  uint16_t read_len;                   /**< Bytes currently in read_buf */
  uint16_t read_offset;                /**< Current parse offset in read_buf */
  uint8_t cur_frame[1514]; /**< Current frame extracted from BPF buffer */
  uint16_t cur_frame_len;  /**< Length of current frame */
} bpf_ctx_t;

/**
 * @brief MAC driver vtable for macOS BPF.
 *
 * Usage:
 *   bpf_ctx_t bpf;
 *   bpf_ctx_init(&bpf, "feth1");
 *   bpf_mac_ops.init(&bpf);
 */
extern const net_mac_t bpf_mac_ops;

/**
 * Initialize BPF context with default values.
 * @param ctx     BPF context to initialize.
 * @param ifname  Interface name (e.g., "feth1"). NULL for default "feth1".
 */
void bpf_ctx_init(bpf_ctx_t *ctx, const char *ifname);

#endif /* DRIVER_BPF_H */
