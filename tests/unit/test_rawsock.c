/**
 * @file test_rawsock.c
 * @brief Tests for the Linux raw-socket (AF_PACKET) MAC driver.
 *
 * Three tiers:
 *   - checksum completion (portable, runs everywhere);
 *   - context/peek behaviour without a socket (Linux);
 *   - live tests on a veth pair (Linux, root only — skipped otherwise).
 *     CI runs them with sudo; they create and delete rsk-drv/rsk-peer.
 */

#define _DEFAULT_SOURCE

#include "driver/rawsock.h"
#include "net_cksum.h"
#include "test_main.h"
#include <string.h>

/* ── Frame building ───────────────────────────────────────────────── */

#define SRC_IP 0x0A000064u /* 10.0.0.100 */
#define DST_IP 0x0A000002u /* 10.0.0.2 */

static void put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static uint16_t get16(const uint8_t *p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}

/** Ethernet + IPv4 + an L4 header of hdr_len bytes + payload. */
static uint16_t build_frame(uint8_t *f, uint8_t proto, uint16_t hdr_len,
                            const char *payload) {
  uint16_t plen = (uint16_t)strlen(payload);
  uint16_t l4len = (uint16_t)(hdr_len + plen);
  memset(f, 0, 14 + 20 + l4len);
  memset(f, 0xFF, 6);
  f[6] = 0x02;
  put16(f + 12, 0x0800);
  uint8_t *ip = f + 14;
  ip[0] = 0x45;
  put16(ip + 2, (uint16_t)(20 + l4len));
  ip[8] = 64;
  ip[9] = proto;
  put16(ip + 12, (uint16_t)(SRC_IP >> 16));
  put16(ip + 14, (uint16_t)SRC_IP);
  put16(ip + 16, (uint16_t)(DST_IP >> 16));
  put16(ip + 18, (uint16_t)DST_IP);
  uint8_t *l4 = ip + 20;
  put16(l4, 40000);
  put16(l4 + 2, 7);
  if (proto == 17) {
    put16(l4 + 4, l4len);
  } else {
    l4[12] = 0x50; /* data offset 5 */
    l4[13] = 0x18; /* PSH|ACK */
    put16(l4 + 14, 1024);
  }
  memcpy(l4 + hdr_len, payload, plen);
  return (uint16_t)(14 + 20 + l4len);
}

/** Checksum over pseudo-header + L4 of an IPv4 frame, stored or not. */
static uint16_t l4_sum(const uint8_t *f) {
  const uint8_t *ip = f + 14;
  uint16_t ihl = (uint16_t)((ip[0] & 0x0F) * 4);
  uint16_t l4len = (uint16_t)(get16(ip + 2) - ihl);
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add(&c, ip + 12, 8);
  net_cksum_add_u16(&c, ip[9]);
  net_cksum_add_u16(&c, l4len);
  net_cksum_add(&c, ip + ihl, l4len);
  return net_cksum_finalize(&c);
}

/** What a stack using checksum offload leaves in the field. */
static uint16_t pseudo_partial(const uint8_t *f) {
  const uint8_t *ip = f + 14;
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add(&c, ip + 12, 8);
  net_cksum_add_u16(&c, ip[9]);
  net_cksum_add_u16(&c, (uint16_t)(get16(ip + 2) - 20));
  return (uint16_t)~net_cksum_finalize(&c);
}

/* ── Checksum completion (portable) ──────────────────────────────── */

TEST(test_csum_complete_udp) {
  uint8_t f[128];
  uint16_t len = build_frame(f, 17, 8, "hello");
  uint16_t expect = l4_sum(f); /* field is zero: this is the checksum */
  put16(f + 34 + 6, pseudo_partial(f));
  ASSERT_EQ(rawsock_csum_complete(f, len, 34, 6), 0);
  ASSERT_EQ(get16(f + 34 + 6), expect);
  ASSERT_EQ(l4_sum(f), 0); /* now verifies */
}

TEST(test_csum_complete_tcp_odd_length) {
  uint8_t f[128];
  uint16_t len = build_frame(f, 6, 20, "odd-len"); /* 27-byte segment */
  uint16_t expect = l4_sum(f);
  put16(f + 34 + 16, pseudo_partial(f));
  ASSERT_EQ(rawsock_csum_complete(f, len, 34, 16), 0);
  ASSERT_EQ(get16(f + 34 + 16), expect);
  ASSERT_EQ(l4_sum(f), 0);
}

TEST(test_csum_complete_field_in_last_bytes) {
  /* Region is just the 2-byte field: result is its complement. */
  uint8_t f[40] = {0};
  put16(f + 38, 0x1234);
  ASSERT_EQ(rawsock_csum_complete(f, 40, 38, 0), 0);
  ASSERT_EQ(get16(f + 38), 0xEDCB);
}

TEST(test_csum_complete_field_outside_frame) {
  uint8_t f[128];
  uint16_t len = build_frame(f, 17, 8, "hello");
  uint8_t copy[128];
  memcpy(copy, f, len);
  ASSERT_EQ(rawsock_csum_complete(f, len, 34, (uint16_t)(len - 34 - 1)), -1);
  ASSERT_EQ(rawsock_csum_complete(f, len, (uint16_t)(len + 4), 0), -1);
  ASSERT_EQ(rawsock_csum_complete(f, len, 0xFFFF, 0xFFFF), -1);
  ASSERT_MEM_EQ(f, copy, len); /* untouched */
}

#ifdef __linux__

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ── Context behaviour without a socket (Linux) ──────────────────── */

TEST(test_ctx_init_defaults) {
  rawsock_ctx_t c;
  memset(&c, 0xA5, sizeof(c));
  rawsock_ctx_init(&c, NULL);
  ASSERT_EQ(c.fd, -1);
  ASSERT_EQ(c.rx_len, 0);
  ASSERT_EQ(c.rx_dropped, 0u);
  ASSERT_TRUE(strcmp(c.ifname, "eth0") == 0);
}

TEST(test_ctx_init_truncates_long_name) {
  rawsock_ctx_t c;
  rawsock_ctx_init(&c, "a-very-long-interface-name");
  ASSERT_EQ(strlen(c.ifname), sizeof(c.ifname) - 1);
}

TEST(test_peek_without_frame) {
  rawsock_ctx_t c;
  uint8_t b[4];
  rawsock_ctx_init(&c, "lo");
  ASSERT_EQ(rawsock_mac_ops.peek(&c, 0, b, sizeof(b)), -1);
}

/* ── Live tests on a veth pair (root) ────────────────────────────── */

#define DRV_IF "rsk-drv"
#define PEER_IF "rsk-peer"
#define PEER_IP 0x0AE70001u /* 10.231.0.1 — rsk-peer's address */
#define FAKE_IP 0x0AE70002u /* 10.231.0.2 — "the SUT", no stack behind it */

static const uint8_t fake_mac[6] = {0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC};
static int peer_fd = -1;

static int sh(const char *cmd) { return system(cmd) == 0; }

static void msleep(int ms) {
  struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
  nanosleep(&ts, NULL);
}

static int veth_up(void) {
  sh("ip link del " PEER_IF " 2>/dev/null");
  return sh("ip link add " PEER_IF " type veth peer name " DRV_IF) &&
         sh("sysctl -qw net.ipv6.conf." DRV_IF ".disable_ipv6=1") &&
         sh("sysctl -qw net.ipv6.conf." PEER_IF ".disable_ipv6=1") &&
         sh("ip addr add 10.231.0.1/24 dev " PEER_IF) &&
         sh("ip neigh replace 10.231.0.2 lladdr 02:00:00:aa:bb:cc dev " PEER_IF
            " nud permanent") &&
         sh("ip link set " DRV_IF " up") && sh("ip link set " PEER_IF " up");
}

static void veth_down(void) { sh("ip link del " PEER_IF " 2>/dev/null"); }

/** Plain AF_PACKET socket on the peer end: what "the wire" sees. */
static int peer_open(void) {
  int fd = socket(AF_PACKET, SOCK_RAW, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = (int)if_nametoindex(PEER_IF);
  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int peer_send(const uint8_t *f, size_t len) {
  return send(peer_fd, f, len, 0) == (ssize_t)len;
}

/** Next frame arriving at the peer (not one it sent), or 0 on timeout. */
static int peer_recv(uint8_t *buf, size_t cap, int ms) {
  for (; ms > 0; ms--) {
    struct sockaddr_ll from;
    socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(peer_fd, buf, cap, MSG_DONTWAIT,
                         (struct sockaddr *)&from, &fl);
    if (n > 0 && from.sll_pkttype != PACKET_OUTGOING)
      return (int)n;
    if (n <= 0)
      msleep(1);
  }
  return 0;
}

static void peer_drain(void) {
  uint8_t b[2048];
  while (recv(peer_fd, b, sizeof(b), MSG_DONTWAIT) > 0) {
  }
}

static int drv_poll_wait(rawsock_ctx_t *c, int ms) {
  for (; ms > 0; ms--) {
    int n = rawsock_mac_ops.poll(c);
    if (n != 0)
      return n;
    msleep(1);
  }
  return 0;
}

static int drv_open(rawsock_ctx_t *c) {
  rawsock_ctx_init(c, DRV_IF);
  return rawsock_mac_ops.init(c);
}

/** A test frame with a local-experimental EtherType (0x88B5). */
static uint16_t test_frame(uint8_t *f, const uint8_t *dst, size_t len,
                           uint8_t fill) {
  memset(f, fill, len);
  memcpy(f, dst, 6);
  memcpy(f + 6, fake_mac, 6);
  f[6] = 0x06; /* distinct source */
  put16(f + 12, 0x88B5);
  return (uint16_t)len;
}

TEST(test_live_init_missing_iface) {
  rawsock_ctx_t c;
  rawsock_ctx_init(&c, "rsk-nope");
  ASSERT_EQ(rawsock_mac_ops.init(&c), -1);
  ASSERT_EQ(c.fd, -1);
}

TEST(test_live_send_reaches_peer) {
  rawsock_ctx_t c;
  static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t f[60], got[2048];
  ASSERT_EQ(drv_open(&c), 0);
  peer_drain();
  test_frame(f, bcast, sizeof(f), 0x5A);
  ASSERT_EQ(rawsock_mac_ops.send(&c, f, sizeof(f)), (int)sizeof(f));
  int n = peer_recv(got, sizeof(got), 1000);
  rawsock_mac_ops.close(&c);
  ASSERT_EQ(n, (int)sizeof(f));
  ASSERT_MEM_EQ(got, f, sizeof(f));
}

TEST(test_live_receives_foreign_unicast) {
  /* Promiscuous: a frame for the stack's own MAC, not the interface's. */
  rawsock_ctx_t c;
  uint8_t f[60], b[60];
  ASSERT_EQ(drv_open(&c), 0);
  test_frame(f, fake_mac, sizeof(f), 0x3C);
  ASSERT_TRUE(peer_send(f, sizeof(f)));
  int n = drv_poll_wait(&c, 1000);
  ASSERT_EQ(n, (int)sizeof(f));
  ASSERT_EQ(rawsock_mac_ops.peek(&c, 0, b, sizeof(b)), (int)sizeof(f));
  ASSERT_MEM_EQ(b, f, sizeof(f));
  ASSERT_EQ(rawsock_mac_ops.peek(&c, 50, b, 20), 10); /* clipped at end */
  ASSERT_EQ(rawsock_mac_ops.peek(&c, 60, b, 1), -1);  /* past end */
  ASSERT_EQ(rawsock_mac_ops.poll(&c), (int)sizeof(f)); /* idempotent */
  rawsock_mac_ops.discard(&c);
  ASSERT_EQ(rawsock_mac_ops.poll(&c), 0);
  rawsock_mac_ops.close(&c);
  ASSERT_EQ(c.fd, -1);
}

TEST(test_live_ignores_outgoing_frames) {
  /* The stack sees what arrives on the wire, not what this host sends
   * out of the interface: neither its own frames nor another sender's. */
  rawsock_ctx_t c;
  uint8_t f[60], got[2048];
  ASSERT_EQ(drv_open(&c), 0);
  int other = socket(AF_PACKET, SOCK_RAW, 0);
  ASSERT_TRUE(other >= 0);
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = c.ifindex;
  test_frame(f, fake_mac, sizeof(f), 0x77);
  ssize_t sent = sendto(other, f, sizeof(f), 0, (struct sockaddr *)&sll,
                        sizeof(sll));
  close(other);
  ASSERT_EQ(rawsock_mac_ops.send(&c, f, sizeof(f)), (int)sizeof(f));
  int n = drv_poll_wait(&c, 200);
  rawsock_mac_ops.close(&c);
  int on_wire = peer_recv(got, sizeof(got), 200);
  peer_drain();
  ASSERT_EQ(sent, (ssize_t)sizeof(f));
  ASSERT_EQ(on_wire, (int)sizeof(f)); /* the frames did go out */
  ASSERT_EQ(n, 0);
}

/** IFF_PROMISC as the kernel reports it for the driver's interface. */
static int drv_if_promisc(void) {
  FILE *fp = fopen("/sys/class/net/" DRV_IF "/flags", "r");
  unsigned flags = 0;
  if (fp) {
    if (fscanf(fp, "%x", &flags) != 1)
      flags = 0;
    fclose(fp);
  }
  return (flags & 0x100u) != 0;
}

TEST(test_live_promiscuous_while_open) {
  /* veth delivers every frame anyway; a real NIC filters on its own MAC,
   * so the driver must hold the interface promiscuous — and let go. */
  rawsock_ctx_t c;
  ASSERT_FALSE(drv_if_promisc());
  ASSERT_EQ(drv_open(&c), 0);
  int during = drv_if_promisc();
  rawsock_mac_ops.close(&c);
  ASSERT_TRUE(during);
  ASSERT_FALSE(drv_if_promisc());
}

TEST(test_live_oversize_frame_dropped) {
  /* A 2000-byte frame must be dropped whole, not truncated into the
   * 1514-byte buffer; the frame behind it is delivered. */
  rawsock_ctx_t c;
  static uint8_t big[2000];
  uint8_t f[60];
  ASSERT_TRUE(sh("ip link set " DRV_IF " mtu 4000") &&
              sh("ip link set " PEER_IF " mtu 4000"));
  ASSERT_EQ(drv_open(&c), 0);
  test_frame(big, fake_mac, sizeof(big), 0x11);
  test_frame(f, fake_mac, sizeof(f), 0x22);
  ASSERT_TRUE(peer_send(big, sizeof(big)));
  ASSERT_TRUE(peer_send(f, sizeof(f)));
  int n = drv_poll_wait(&c, 1000);
  uint32_t dropped = c.rx_dropped;
  rawsock_mac_ops.close(&c);
  sh("ip link set " DRV_IF " mtu 1500");
  sh("ip link set " PEER_IF " mtu 1500");
  ASSERT_EQ(n, (int)sizeof(f));
  ASSERT_EQ(dropped, 1u);
}

/** Wait for the kernel's IPv4 frame to FAKE_IP with this protocol. */
static int drv_wait_ipv4(rawsock_ctx_t *c, uint8_t proto, uint8_t *f) {
  for (int tries = 0; tries < 20; tries++) {
    int n = drv_poll_wait(c, 100);
    if (n <= 0)
      continue;
    rawsock_mac_ops.peek(c, 0, f, (uint16_t)n);
    rawsock_mac_ops.discard(c);
    if (n >= 34 && get16(f + 12) == 0x0800 && f[23] == proto &&
        get16(f + 30) == (uint16_t)(FAKE_IP >> 16) &&
        get16(f + 32) == (uint16_t)FAKE_IP)
      return n;
  }
  return 0;
}

TEST(test_live_kernel_udp_checksum_valid) {
  /* The kernel leaves a partial checksum for the "NIC" (veth); the driver
   * must hand the stack a frame whose UDP checksum verifies. */
  rawsock_ctx_t c;
  uint8_t f[1514];
  ASSERT_EQ(drv_open(&c), 0);
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(s >= 0);
  struct sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_port = htons(9);
  to.sin_addr.s_addr = htonl(FAKE_IP);
  ssize_t sent = sendto(s, "offload?", 8, 0, (struct sockaddr *)&to,
                        sizeof(to));
  close(s);
  int n = drv_wait_ipv4(&c, 17, f);
  rawsock_mac_ops.close(&c);
  ASSERT_EQ(sent, 8);
  ASSERT_TRUE(n > 0);
  ASSERT_NE(get16(f + 34 + 6), 0); /* checksum present */
  ASSERT_EQ(l4_sum(f), 0);
}

TEST(test_live_kernel_tcp_checksum_valid) {
  rawsock_ctx_t c;
  uint8_t f[1514];
  ASSERT_EQ(drv_open(&c), 0);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_TRUE(s >= 0);
  struct sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_port = htons(9);
  to.sin_addr.s_addr = htonl(FAKE_IP);
  struct timeval tv = {0, 300000};
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  (void)connect(s, (struct sockaddr *)&to, sizeof(to)); /* sends a SYN */
  int n = drv_wait_ipv4(&c, 6, f);
  close(s);
  rawsock_mac_ops.close(&c);
  ASSERT_TRUE(n > 0);
  ASSERT_EQ(l4_sum(f), 0);
}

static int live_tests(void) {
  if (geteuid() != 0) {
    fprintf(stderr, "  SKIP: live veth tests (need root)\n");
    return 0;
  }
  if (!veth_up() || (peer_fd = peer_open()) < 0) {
    veth_down();
    fprintf(stderr, "  FAIL: could not set up the %s/%s veth pair\n", DRV_IF,
            PEER_IF);
    return 1;
  }
  RUN_TEST(test_live_init_missing_iface);
  RUN_TEST(test_live_send_reaches_peer);
  RUN_TEST(test_live_receives_foreign_unicast);
  RUN_TEST(test_live_ignores_outgoing_frames);
  RUN_TEST(test_live_promiscuous_while_open);
  RUN_TEST(test_live_oversize_frame_dropped);
  RUN_TEST(test_live_kernel_udp_checksum_valid);
  RUN_TEST(test_live_kernel_tcp_checksum_valid);
  close(peer_fd);
  veth_down();
  return 0;
}

#endif /* __linux__ */

int main(void) {
  int setup_failed = 0;
  fprintf(stderr, "=== Raw-socket driver tests ===\n");
  RUN_TEST(test_csum_complete_udp);
  RUN_TEST(test_csum_complete_tcp_odd_length);
  RUN_TEST(test_csum_complete_field_in_last_bytes);
  RUN_TEST(test_csum_complete_field_outside_frame);
#ifdef __linux__
  RUN_TEST(test_ctx_init_defaults);
  RUN_TEST(test_ctx_init_truncates_long_name);
  RUN_TEST(test_peek_without_frame);
  setup_failed = live_tests();
#endif
  TEST_REPORT();
  return test_failures + setup_failed;
}
