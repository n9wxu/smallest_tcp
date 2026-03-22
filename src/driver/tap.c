/**
 * @file driver/tap.c
 * @brief Linux TAP network driver for the MAC HAL.
 *
 * Uses /dev/net/tun with IFF_TAP | IFF_NO_PI.
 * Only compiled on Linux.
 *
 * Driver model: CACHING.
 * poll() reads the next frame from the TAP fd into the driver's
 * internal rx_frame[] buffer.  All subsequent peek() calls read from
 * that buffer.  discard() clears the buffer, allowing the next poll()
 * to read a new frame.  The caller never receives a pointer to the
 * driver's internal buffer — data is accessed exclusively via peek().
 */

#ifdef __linux__

#include "driver/tap.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ── Context init ─────────────────────────────────────────────────── */

void tap_ctx_init(tap_ctx_t *ctx, const char *ifname) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = -1;
  if (ifname) {
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);
  } else {
    strncpy(ctx->ifname, "tap0", sizeof(ctx->ifname) - 1);
  }
}

/* ── MAC operations ───────────────────────────────────────────────── */

static int tap_init(void *ctx) {
  tap_ctx_t *tap = (tap_ctx_t *)ctx;
  struct ifreq ifr;

  tap->fd = open("/dev/net/tun", O_RDWR);
  if (tap->fd < 0) {
    perror("tap_init: open /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, tap->ifname, IFNAMSIZ - 1);

  if (ioctl(tap->fd, TUNSETIFF, &ifr) < 0) {
    perror("tap_init: ioctl TUNSETIFF");
    close(tap->fd);
    tap->fd = -1;
    return -1;
  }

  /* Set non-blocking for poll() */
  int flags = fcntl(tap->fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(tap->fd, F_SETFL, flags | O_NONBLOCK);
  }

  tap->rx_len = 0;
  fprintf(stderr, "[TAP] Opened %s (fd=%d)\n", tap->ifname, tap->fd);
  return 0;
}

static int tap_send(void *ctx, const uint8_t *frame, uint16_t len) {
  tap_ctx_t *tap = (tap_ctx_t *)ctx;
  ssize_t n = write(tap->fd, frame, len);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
  return (int)n;
}

/**
 * poll() — Check for a new RX frame.
 *
 * Reads the next Ethernet frame from the TAP fd into the driver's
 * internal rx_frame[] buffer.  Non-blocking: returns 0 immediately
 * if no frame is pending.
 *
 * @return Frame length in bytes if a frame was read, 0 if no frame
 *         is available, <0 on error.
 */
static int tap_poll(void *ctx) {
  tap_ctx_t *tap = (tap_ctx_t *)ctx;

  /* If a frame is already buffered (discard() not yet called), return
   * its length — poll() is idempotent until discard() is called. */
  if (tap->rx_len > 0) {
    return tap->rx_len;
  }

  ssize_t n = read(tap->fd, tap->rx_frame, sizeof(tap->rx_frame));
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0; /* No frame available — not an error */
    }
    return -1;
  }
  if (n == 0) {
    return 0;
  }

  tap->rx_len = (uint16_t)n;
  return (int)tap->rx_len;
}

static int tap_peek(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len) {
  tap_ctx_t *tap = (tap_ctx_t *)ctx;

  if (tap->rx_len == 0) {
    return -1; /* No frame available */
  }
  if (offset >= tap->rx_len) {
    return -1; /* Offset past end of frame */
  }

  uint16_t avail = tap->rx_len - offset;
  uint16_t copy_len = (len < avail) ? len : avail;
  memcpy(buf, tap->rx_frame + offset, copy_len);

  return (int)copy_len;
}

static void tap_discard(void *ctx) {
  tap_ctx_t *tap = (tap_ctx_t *)ctx;
  /* Clear the internal buffer — the next poll() will read a new frame. */
  tap->rx_len = 0;
}

static void tap_close(void *ctx) {
  tap_ctx_t *tap = (tap_ctx_t *)ctx;
  if (tap->fd >= 0) {
    close(tap->fd);
    tap->fd = -1;
  }
  tap->rx_len = 0;
}

const net_mac_t tap_mac_ops = {
    .init = tap_init,
    .send = tap_send,
    .poll = tap_poll,
    .peek = tap_peek,
    .discard = tap_discard,
    .close = tap_close,
};

#endif /* __linux__ */
