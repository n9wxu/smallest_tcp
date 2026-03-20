/**
 * @file net_mac.h
 * @brief MAC Hardware Abstraction Layer — vtable interface.
 *
 * Each MAC driver (TAP, BPF, ENC28J60, CDC-ECM) provides a static
 * instance of net_mac_t with function pointers implementing this interface.
 * The application allocates the driver-specific context struct and passes
 * it as void *ctx to all operations.
 *
 * Key design: peek() + discard() enables fast ARP/NDP filtering on
 * hardware MACs without reading full frames via SPI.
 */

#ifndef NET_MAC_H
#define NET_MAC_H

#include <stdint.h>

/**
 * @brief MAC driver operations vtable.
 *
 * All functions receive a driver-specific context pointer (void *ctx)
 * that was allocated and initialized by the application.
 */
typedef struct {
  /**
   * Initialize hardware, bring link up.
   * @return 0 on success, <0 on error.
   */
  int (*init)(void *ctx);

  /**
   * Transmit a complete Ethernet frame.
   * @param frame  Pointer to complete Ethernet frame (14-byte header +
   * payload).
   * @param len    Frame length in bytes.
   * @return bytes sent, or <0 on error.
   */
  int (*send)(void *ctx, const uint8_t *frame, uint16_t len);

  /**
   * Non-blocking receive into caller's buffer.
   * @param frame   Buffer to receive frame into.
   * @param maxlen  Buffer capacity.
   * @return bytes received, 0 if no frame available, <0 on error.
   */
  int (*recv)(void *ctx, uint8_t *frame, uint16_t maxlen);

  /**
   * Read bytes from current RX frame at offset without consuming.
   * For software MACs (TAP/BPF): memcpy from internal buffer.
   * For hardware MACs (ENC28J60): SPI read at offset.
   * @param offset  Byte offset into the current frame.
   * @param buf     Destination buffer.
   * @param len     Number of bytes to read.
   * @return bytes copied, or <0 on error.
   */
  int (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);

  /**
   * Skip/drop current RX frame without full read.
   * For software MACs: may be a no-op (frame already consumed by recv).
   * For hardware MACs: advance RX pointer.
   */
  void (*discard)(void *ctx);

  /**
   * Shutdown interface, release resources.
   */
  void (*close)(void *ctx);
} net_mac_t;

#endif /* NET_MAC_H */
