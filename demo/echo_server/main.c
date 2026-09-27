/**
 * @file demo/echo_server/main.c
 * @brief The smallest demo: UDP echo on port 7, and ping.
 *
 *   sudo ./echo_server [tap0 | raw:<ifname> | feth1]
 *   ping 10.0.0.2;  echo Hello | nc -u -w1 10.0.0.2 7
 *
 * Creating the interface: see the README (TAP on Linux, a feth pair on
 * macOS).
 */

#include "net.h"
#include "udp.h"
#include <stdio.h>

#include "demo_loop.h"

#define ECHO_PORT 7u

static net_t net;
static demo_mac_t nic;

static void udp_echo(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *payload,
                     uint16_t len) {
  printf("  UDP echo: ");
  demo_print_ipv4(src_ip);
  printf(":%u, %u bytes\n", (unsigned)src_port, (unsigned)len);
  udp_send(n, src_ip, src_mac, ECHO_PORT, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {{ECHO_PORT, udp_echo}};

int main(int argc, char *argv[]) {
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "echo_server") != 0)
    return 1;
  udp_set_ports(&net, udp_ports, 1);
  printf("=== UDP echo server on ");
  demo_print_ipv4(net.ipv4_addr);
  printf(" port %u (and ping); Ctrl+C stops ===\n", ECHO_PORT);
  fflush(stdout);

  demo_run(&net, "echo_server", NULL);

  printf("\nShutting down...\n");
  demo_net_close(&nic);
  return 0;
}
