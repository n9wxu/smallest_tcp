#define _POSIX_C_SOURCE 199309L

/**
 * @file demo/echo_server/main.c
 * @brief UDP echo server + ICMP ping responder demo.
 *
 * Runs the full stack: Ethernet → ARP → IPv4 → ICMP + UDP.
 * - Responds to ARP requests for our IP
 * - Responds to ICMP echo (ping) requests
 * - UDP echo server on port 7 (echoes data back to sender)
 *
 * On macOS:
 *   # Terminal 1: Create interface pair
 *   sudo ifconfig feth0 create
 *   sudo ifconfig feth1 create
 *   sudo ifconfig feth0 peer feth1
 *   sudo ifconfig feth0 10.0.0.1/24 up
 *   sudo ifconfig feth1 up
 *
 *   # Terminal 2: Run echo server
 *   sudo ./build/demo/echo_server
 *
 *   # Terminal 3: Test it
 *   ping 10.0.0.2                        # ICMP ping
 *   echo "Hello" | nc -u -w1 10.0.0.2 7  # UDP echo
 *
 *   # Cleanup
 *   sudo ifconfig feth0 destroy
 *   sudo ifconfig feth1 destroy
 *
 * On Linux:
 *   sudo ip tuntap add dev tap0 mode tap
 *   sudo ip addr add 10.0.0.1/24 dev tap0
 *   sudo ip link set tap0 up
 *   sudo ./build/demo/echo_server
 *   # Then: ping 10.0.0.2 / echo "Hello" | nc -u -w1 10.0.0.2 7
 */

#include "eth.h"
#include "net.h"
#include "net_endian.h"
#include "udp.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include "driver/tap.h"
#elif defined(__APPLE__)
#include "driver/bpf.h"
#endif

/* ── UDP Echo Handler (port 7) ────────────────────────────────────── */

static void udp_echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac, const uint8_t *data,
                             uint16_t data_len) {
  printf("  UDP echo: %u.%u.%u.%u:%u -> port 7, %u bytes\n",
         (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF,
         src_ip & 0xFF, src_port, data_len);

  /* Echo the data back to sender */
  net_err_t err = udp_send(n, src_ip, src_mac, 7, src_port, data, data_len);
  if (err != NET_OK) {
    printf("  UDP echo send failed: %d\n", err);
  } else {
    printf("  UDP echo: sent %u bytes back\n", data_len);
  }
}

/* Port handler table */
static const udp_port_entry_t echo_ports[] = {
    {7, udp_echo_handler},
};

/* ── Globals ──────────────────────────────────────────────────────── */

static volatile int running = 1;

static void sigint_handler(int sig) {
  (void)sig;
  running = 0;
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  /* Application-owned buffers */
  static uint8_t rx_buf[1514];
  static uint8_t tx_buf[1514];
  static net_t net;

  static const uint8_t mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  /* Platform-specific driver setup */
#ifdef __linux__
  static tap_ctx_t drv_ctx;
  tap_ctx_init(&drv_ctx, "tap0");
  const net_mac_t *drv_ops = &tap_mac_ops;
#elif defined(__APPLE__)
  static bpf_ctx_t drv_ctx;
  bpf_ctx_init(&drv_ctx, "feth1");
  const net_mac_t *drv_ops = &bpf_mac_ops;
#else
#error "Unsupported platform"
#endif

  /* Initialize network context */
  net_err_t err = net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf),
                           mac, drv_ops, &drv_ctx);
  if (err != NET_OK) {
    fprintf(stderr, "net_init failed: %d\n", err);
    return 1;
  }

  /* Register UDP port handlers */
  udp_ports.entries = echo_ports;
  udp_ports.count = 1;

  /* Initialize MAC driver */
  if (drv_ops->init(&drv_ctx) < 0) {
    fprintf(stderr, "MAC driver init failed\n");
    return 1;
  }

  printf("=== UDP Echo Server ===\n");
  printf("  MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n", net.mac[0], net.mac[1],
         net.mac[2], net.mac[3], net.mac[4], net.mac[5]);
  printf("  IPv4: %u.%u.%u.%u\n", (net.ipv4_addr >> 24) & 0xFF,
         (net.ipv4_addr >> 16) & 0xFF, (net.ipv4_addr >> 8) & 0xFF,
         net.ipv4_addr & 0xFF);
  printf("  Mask: %u.%u.%u.%u\n", (net.subnet_mask >> 24) & 0xFF,
         (net.subnet_mask >> 16) & 0xFF, (net.subnet_mask >> 8) & 0xFF,
         net.subnet_mask & 0xFF);
  printf("  GW:   %u.%u.%u.%u\n", (net.gateway_ipv4 >> 24) & 0xFF,
         (net.gateway_ipv4 >> 16) & 0xFF, (net.gateway_ipv4 >> 8) & 0xFF,
         net.gateway_ipv4 & 0xFF);
  printf("\nListening on UDP port 7 (echo) + ICMP ping...\n");
  printf("Press Ctrl+C to stop.\n\n");

  signal(SIGINT, sigint_handler);

  /* Main receive loop */
  while (running) {
    int n = drv_ops->recv(&drv_ctx, rx_buf, sizeof(rx_buf));
    if (n <= 0) {
      struct timespec ts = {0, 1000000}; /* 1ms */
      nanosleep(&ts, NULL);
      continue;
    }

    /* Dispatch through the full stack */
    eth_input(&net, rx_buf, (uint16_t)n);
  }

  printf("\nShutting down...\n");
  drv_ops->close(&drv_ctx);
  return 0;
}
