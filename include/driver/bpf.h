/**
 * @file driver/bpf.h
 * @brief macOS MAC driver: BPF on an interface such as one end of a feth
 *        pair (see the README for creating one).
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
