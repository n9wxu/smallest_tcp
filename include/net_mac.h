/**
 * @file net_mac.h
 * @brief The MAC driver interface: how the stack reaches the hardware.
 *
 * A driver may cache the current received frame in RAM or read it from
 * the hardware on each peek(); the stack cannot tell.  See
 * docs/design/mac-hal.md.
 */

#ifndef NET_MAC_H
#define NET_MAC_H

#include "net_config.h"
#include <stdint.h>

/**
 * One const instance per driver type; all mutable state lives in the
 * context passed as @p ctx.
 */
typedef struct {
  /** Open the interface.  @return 0, or < 0 on error. */
  int (*init)(void *ctx);

  /**
   * Transmit a complete Ethernet frame; @p frame need only stay valid
   * during the call.
   * @return Bytes sent, 0 if busy, < 0 on error.
   */
  int (*send)(void *ctx, const uint8_t *frame, uint16_t len);

  /**
   * Make the next received frame current, without blocking; the same
   * frame stays current until discard().
   * @return Its length, 0 if none is waiting, < 0 on error.
   */
  int (*poll)(void *ctx);

  /**
   * Copy @p len bytes from @p offset of the current frame.  The stack
   * reads from offset 0.
   * @return Bytes copied (fewer past the end), < 0 if there is none; for
   *         an @p offset at or past the end, 0 or < 0.
   */
  int (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);

  /** Release the current frame. */
  void (*discard)(void *ctx);

  /** Close the interface. */
  void (*close)(void *ctx);
} net_mac_t;

#endif /* NET_MAC_H */
