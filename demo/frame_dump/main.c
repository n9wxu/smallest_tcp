#define _POSIX_C_SOURCE 199309L

/**
 * @file demo/frame_dump/main.c
 * @brief Milestone 1 demo: open MAC interface, hex-dump received frames.
 *
 * On Linux:  Uses TAP interface (tap0).
 * On macOS: Uses BPF bound to feth1.
 *
 * This demo initializes the network stack, sends a hardcoded ARP-like
 * frame, then loops receiving and hex-dumping any incoming frames.
 *
 * Build: make demo  (or compile directly — see Makefile)
 * Run:   sudo ./build/demo/frame_dump
 */

#include "eth.h"
#include "net.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include "driver/tap.h"
#elif defined(__APPLE__)
#include "driver/bpf.h"
#endif

/* ── Hex dump helper ──────────────────────────────────────────────── */

static void hex_dump(const uint8_t *data, uint16_t len) {
  uint16_t i;
  for (i = 0; i < len; i++) {
    if (i > 0 && (i % 16) == 0) {
      printf("\n");
    }
    printf("%02x ", data[i]);
  }
  printf("\n");
}

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

  /* Initialize MAC driver */
  if (drv_ops->init(&drv_ctx) < 0) {
    fprintf(stderr, "MAC driver init failed\n");
    return 1;
  }

  printf("Network stack initialized.\n");
  printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", net.mac[0], net.mac[1],
         net.mac[2], net.mac[3], net.mac[4], net.mac[5]);
  printf("  IPv4: %u.%u.%u.%u\n", (net.ipv4_addr >> 24) & 0xFF,
         (net.ipv4_addr >> 16) & 0xFF, (net.ipv4_addr >> 8) & 0xFF,
         net.ipv4_addr & 0xFF);
  printf("Listening for frames... (Ctrl+C to stop)\n\n");

  /* Install signal handler for clean exit */
  signal(SIGINT, sigint_handler);

  /* Main receive loop */
  while (running) {
    int n = drv_ops->recv(&drv_ctx, rx_buf, sizeof(rx_buf));
    if (n <= 0) {
      /* No frame available — brief sleep to avoid busy loop */
      struct timespec ts = {0, 10000000}; /* 10ms */
      nanosleep(&ts, NULL);
      continue;
    }

    printf("=== Frame received: %d bytes ===\n", n);
    hex_dump(rx_buf, (uint16_t)n);

    /* Parse and dispatch through Ethernet layer */
    eth_input(&net, rx_buf, (uint16_t)n);
    printf("\n");
  }

  printf("\nShutting down...\n");
  drv_ops->close(&drv_ctx);
  return 0;
}
