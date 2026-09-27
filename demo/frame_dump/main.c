/**
 * @file demo/frame_dump/main.c
 * @brief Hex dump of every frame received (and the stack's answers to
 *        ARP and ping).
 *
 *   sudo ./frame_dump [tap0 | raw:<ifname> | feth1]
 */

#include "net.h"
#include <stdio.h>

#include "demo_loop.h"

static net_t net;
static demo_mac_t nic;

static void hex_dump(const uint8_t *data, int len) {
  int i;
  for (i = 0; i < len; i++)
    printf((i & 15) == 15 || i == len - 1 ? "%02x\n" : "%02x ", data[i]);
}

int main(int argc, char *argv[]) {
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "frame_dump") != 0)
    return 1;
  printf("Listening on ");
  demo_print_ipv4(net.ipv4_addr);
  printf(" (Ctrl+C to stop)\n\n");

  while (demo_running) {
    int n = net_poll(&net); /* the frame stays in net.rx.buf afterwards */
    if (n > 0) {
      printf("=== Frame received: %d bytes ===\n", n);
      hex_dump(net.rx.buf, n);
      printf("\n");
    } else {
      struct timespec idle = {0, 10000000}; /* 10 ms */
      nanosleep(&idle, NULL);
    }
  }

  printf("\nShutting down...\n");
  demo_net_close(&nic);
  return 0;
}
