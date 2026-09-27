/**
 * @file driver/rawsock.c
 * @brief Linux MAC driver: an AF_PACKET socket.
 *
 * A caching driver on an existing interface — a NIC or a veth end
 * (docs/design/mac-hal.md).  The kernel may hand over frames this host
 * sent with the transport checksum left to offload; it is completed
 * before the stack sees them.  rawsock_csum_complete() is portable.
 */

#include "driver/rawsock.h"
#include "net_cksum.h"
#include <string.h>

int rawsock_csum_complete(uint8_t *frame, uint16_t len, uint16_t csum_start,
                          uint16_t csum_offset) {
  uint32_t field = (uint32_t)csum_start + csum_offset;

  if (field + 2u > len) {
    return -1;
  }
  /* The field already holds the pseudo-header sum, so the checksum of
   * the region including it is the finished checksum. */
  uint16_t c = net_cksum(frame + csum_start, (uint16_t)(len - csum_start));
  frame[field] = (uint8_t)(c >> 8);
  frame[field + 1] = (uint8_t)c;
  return 0;
}

#ifdef __linux__

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

void rawsock_ctx_init(rawsock_ctx_t *ctx, const char *ifname) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = -1;
  strncpy(ctx->ifname, ifname ? ifname : "eth0", sizeof(ctx->ifname) - 1);
}

static int rawsock_init(void *ctx) {
  rawsock_ctx_t *rs = (rawsock_ctx_t *)ctx;
  int one = 1;
  const char *step;

  rs->ifindex = (int)if_nametoindex(rs->ifname);
  if (rs->ifindex == 0) {
    fprintf(stderr, "rawsock_init: no interface %s\n", rs->ifname);
    return -1;
  }

  /* Protocol 0 receives nothing until bind() names the interface, so no
   * frame from another interface can be queued first. */
  rs->fd = socket(AF_PACKET, SOCK_RAW, 0);
  if (rs->fd < 0) {
    perror("rawsock_init: socket (needs root or CAP_NET_RAW)");
    return -1;
  }

  step = "PACKET_VNET_HDR";
  if (setsockopt(rs->fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) < 0) {
    goto fail;
  }
#ifdef PACKET_IGNORE_OUTGOING
  /* Linux 4.20+: don't even queue our own sends.  poll() filters them
   * too, for older kernels. */
  (void)setsockopt(rs->fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one,
                   sizeof(one));
#endif

  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = rs->ifindex;
  step = "bind";
  if (bind(rs->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    goto fail;
  }

  /* The stack answers to its own MAC, not the interface's.  The kernel
   * drops this promiscuous-mode reference when the socket closes. */
  struct packet_mreq mr;
  memset(&mr, 0, sizeof(mr));
  mr.mr_ifindex = rs->ifindex;
  mr.mr_type = PACKET_MR_PROMISC;
  step = "PACKET_MR_PROMISC";
  if (setsockopt(rs->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) <
      0) {
    goto fail;
  }

  rs->rx_len = 0;
  fprintf(stderr, "[RAW] Opened %s (fd=%d)\n", rs->ifname, rs->fd);
  return 0;

fail:
  fprintf(stderr, "rawsock_init: %s on %s: %s\n", step, rs->ifname,
          strerror(errno));
  close(rs->fd);
  rs->fd = -1;
  return -1;
}

static int rawsock_send(void *ctx, const uint8_t *frame, uint16_t len) {
  rawsock_ctx_t *rs = (rawsock_ctx_t *)ctx;
  struct virtio_net_hdr vh;
  struct iovec iov[2];
  struct msghdr msg;

  memset(&vh, 0, sizeof(vh));
  memset(&msg, 0, sizeof(msg));
  iov[0].iov_base = &vh;
  iov[0].iov_len = sizeof(vh);
  iov[1].iov_base = (void *)frame;
  iov[1].iov_len = len;
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  ssize_t n = sendmsg(rs->fd, &msg, 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
      return 0; /* device queue full: dropped, as on a busy wire */
    }
    return -1;
  }
  return (int)(n - (ssize_t)sizeof(vh));
}

/* Our own sends are skipped, and frames too big for rx_frame[] dropped
 * whole (never truncated) */
static int rawsock_poll(void *ctx) {
  rawsock_ctx_t *rs = (rawsock_ctx_t *)ctx;

  /* the same frame until discard() */
  if (rs->rx_len > 0) {
    return rs->rx_len;
  }

  for (;;) {
    struct virtio_net_hdr vh;
    struct sockaddr_ll from;
    struct iovec iov[2];
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));
    iov[0].iov_base = &vh;
    iov[0].iov_len = sizeof(vh);
    iov[1].iov_base = rs->rx_frame;
    iov[1].iov_len = sizeof(rs->rx_frame);
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    /* MSG_TRUNC: return the frame's real length even if it didn't fit. */
    ssize_t n = recvmsg(rs->fd, &msg, MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 0; /* No frame available — not an error */
      }
      return -1;
    }
    if (from.sll_pkttype == PACKET_OUTGOING || n <= (ssize_t)sizeof(vh)) {
      continue;
    }
    n -= (ssize_t)sizeof(vh);
    if (n > (ssize_t)sizeof(rs->rx_frame) ||
        vh.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
      rs->rx_dropped++;
      continue;
    }
    if ((vh.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
        rawsock_csum_complete(rs->rx_frame, (uint16_t)n, vh.csum_start,
                              vh.csum_offset) != 0) {
      rs->rx_dropped++;
      continue;
    }
    rs->rx_len = (uint16_t)n;
    return (int)rs->rx_len;
  }
}

static int rawsock_peek(void *ctx, uint16_t offset, uint8_t *buf,
                        uint16_t len) {
  rawsock_ctx_t *rs = (rawsock_ctx_t *)ctx;

  if (rs->rx_len == 0) {
    return -1; /* No frame available */
  }
  if (offset >= rs->rx_len) {
    return -1; /* Offset past end of frame */
  }

  uint16_t avail = rs->rx_len - offset;
  uint16_t copy_len = (len < avail) ? len : avail;
  memcpy(buf, rs->rx_frame + offset, copy_len);

  return (int)copy_len;
}

static void rawsock_discard(void *ctx) {
  rawsock_ctx_t *rs = (rawsock_ctx_t *)ctx;
  /* Clear the internal buffer — the next poll() will read a new frame. */
  rs->rx_len = 0;
}

static void rawsock_close(void *ctx) {
  rawsock_ctx_t *rs = (rawsock_ctx_t *)ctx;
  if (rs->fd >= 0) {
    close(rs->fd);
    rs->fd = -1;
  }
  rs->rx_len = 0;
}

const net_mac_t rawsock_mac_ops = {
    .init = rawsock_init,
    .send = rawsock_send,
    .poll = rawsock_poll,
    .peek = rawsock_peek,
    .discard = rawsock_discard,
    .close = rawsock_close,
};

#endif /* __linux__ */
