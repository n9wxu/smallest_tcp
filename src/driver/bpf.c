/**
 * @file driver/bpf.c
 * @brief macOS BPF (Berkeley Packet Filter) network driver for the MAC HAL.
 *
 * Uses /dev/bpfN bound to an feth interface.
 * Only compiled on macOS (Darwin).
 */

#ifdef __APPLE__

#include "driver/bpf.h"
#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ── Context init ─────────────────────────────────────────────────── */

void bpf_ctx_init(bpf_ctx_t *ctx, const char *ifname) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = -1;
  if (ifname) {
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);
  } else {
    strncpy(ctx->ifname, "feth1", sizeof(ctx->ifname) - 1);
  }
}

/* ── Find and open an available /dev/bpfN ─────────────────────────── */

static int bpf_open_dev(void) {
  char path[16];
  int fd;
  int i;

  for (i = 0; i < 256; i++) {
    snprintf(path, sizeof(path), "/dev/bpf%d", i);
    fd = open(path, O_RDWR);
    if (fd >= 0) {
      return fd;
    }
    if (errno != EBUSY) {
      /* Not EBUSY means a different error — stop trying */
      break;
    }
  }
  return -1;
}

/* ── MAC operations ───────────────────────────────────────────────── */

static int bpf_mac_init(void *ctx) {
  bpf_ctx_t *bpf = (bpf_ctx_t *)ctx;
  struct ifreq ifr;
  unsigned int imm = 1;
  unsigned int hdr_complete = 1;
  unsigned int buf_len;

  bpf->fd = bpf_open_dev();
  if (bpf->fd < 0) {
    perror("bpf_init: open /dev/bpfN");
    return -1;
  }

  /* Bind to interface */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, bpf->ifname, IFNAMSIZ - 1);
  if (ioctl(bpf->fd, BIOCSETIF, &ifr) < 0) {
    perror("bpf_init: BIOCSETIF");
    close(bpf->fd);
    bpf->fd = -1;
    return -1;
  }

  /* Enable immediate mode (don't buffer reads) */
  if (ioctl(bpf->fd, BIOCIMMEDIATE, &imm) < 0) {
    perror("bpf_init: BIOCIMMEDIATE");
  }

  /* We provide complete Ethernet headers on write */
  if (ioctl(bpf->fd, BIOCSHDRCMPLT, &hdr_complete) < 0) {
    perror("bpf_init: BIOCSHDRCMPLT");
  }

  /* Enable promiscuous mode to see all traffic on the interface */
  if (ioctl(bpf->fd, BIOCPROMISC, NULL) < 0) {
    perror("bpf_init: BIOCPROMISC");
  }

  /* Get the kernel's required BPF buffer length */
  if (ioctl(bpf->fd, BIOCGBLEN, &buf_len) < 0) {
    perror("bpf_init: BIOCGBLEN");
  }

  /* Set non-blocking */
  int flags = fcntl(bpf->fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(bpf->fd, F_SETFL, flags | O_NONBLOCK);
  }

  bpf->read_len = 0;
  bpf->read_offset = 0;
  bpf->cur_frame_len = 0;

  fprintf(stderr, "[BPF] Opened /dev/bpf (fd=%d) bound to %s\n", bpf->fd,
          bpf->ifname);
  return 0;
}

static int bpf_mac_send(void *ctx, const uint8_t *frame, uint16_t len) {
  bpf_ctx_t *bpf = (bpf_ctx_t *)ctx;
  ssize_t n = write(bpf->fd, frame, len);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
  return (int)n;
}

/**
 * Extract the next frame from the BPF read buffer.
 * BPF reads may return multiple frames, each prefixed with a bpf_hdr.
 * Returns 1 if a frame was extracted, 0 if no more frames.
 */
static int bpf_extract_next_frame(bpf_ctx_t *bpf) {
  while (bpf->read_offset < bpf->read_len) {
    /* BPF header is at read_offset */
    if (bpf->read_offset + sizeof(struct bpf_hdr) > bpf->read_len) {
      break; /* Incomplete BPF header */
    }

    struct bpf_hdr *hdr = (struct bpf_hdr *)(bpf->read_buf + bpf->read_offset);
    uint32_t caplen = hdr->bh_caplen;
    uint32_t hdrlen = hdr->bh_hdrlen;
    uint32_t total = BPF_WORDALIGN(hdrlen + caplen);

    if (bpf->read_offset + hdrlen + caplen > bpf->read_len) {
      break; /* Incomplete frame data */
    }

    /* Copy frame data (without BPF header) to cur_frame */
    uint16_t copy_len = (uint16_t)caplen;
    if (copy_len > sizeof(bpf->cur_frame)) {
      copy_len = sizeof(bpf->cur_frame);
    }
    memcpy(bpf->cur_frame, bpf->read_buf + bpf->read_offset + hdrlen, copy_len);
    bpf->cur_frame_len = copy_len;

    /* Advance to next frame in buffer */
    bpf->read_offset += total;

    return 1; /* Frame extracted */
  }

  /* No more frames in buffer */
  bpf->read_len = 0;
  bpf->read_offset = 0;
  bpf->cur_frame_len = 0;
  return 0;
}

static int bpf_mac_recv(void *ctx, uint8_t *frame, uint16_t maxlen) {
  bpf_ctx_t *bpf = (bpf_ctx_t *)ctx;

  /* Try to extract from existing buffer first */
  if (!bpf_extract_next_frame(bpf)) {
    /* Need to read more from BPF */
    ssize_t n = read(bpf->fd, bpf->read_buf, sizeof(bpf->read_buf));
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return 0;
      }
      return -1;
    }
    if (n == 0) {
      return 0;
    }
    bpf->read_len = (uint16_t)n;
    bpf->read_offset = 0;

    if (!bpf_extract_next_frame(bpf)) {
      return 0;
    }
  }

  /* Copy current frame to caller's buffer */
  uint16_t copy_len = bpf->cur_frame_len;
  if (copy_len > maxlen) {
    copy_len = maxlen;
  }
  memcpy(frame, bpf->cur_frame, copy_len);

  return (int)copy_len;
}

static int bpf_mac_peek(void *ctx, uint16_t offset, uint8_t *buf,
                        uint16_t len) {
  bpf_ctx_t *bpf = (bpf_ctx_t *)ctx;

  if (bpf->cur_frame_len == 0) {
    return -1;
  }
  if (offset >= bpf->cur_frame_len) {
    return -1;
  }

  uint16_t avail = bpf->cur_frame_len - offset;
  uint16_t copy_len = (len < avail) ? len : avail;
  memcpy(buf, bpf->cur_frame + offset, copy_len);

  return (int)copy_len;
}

static void bpf_mac_discard(void *ctx) {
  bpf_ctx_t *bpf = (bpf_ctx_t *)ctx;
  bpf->cur_frame_len = 0;
}

static void bpf_mac_close(void *ctx) {
  bpf_ctx_t *bpf = (bpf_ctx_t *)ctx;
  if (bpf->fd >= 0) {
    close(bpf->fd);
    bpf->fd = -1;
  }
  bpf->read_len = 0;
  bpf->read_offset = 0;
  bpf->cur_frame_len = 0;
}

const net_mac_t bpf_mac_ops = {
    .init = bpf_mac_init,
    .send = bpf_mac_send,
    .recv = bpf_mac_recv,
    .peek = bpf_mac_peek,
    .discard = bpf_mac_discard,
    .close = bpf_mac_close,
};

#endif /* __APPLE__ */
