/**
 * @file demo/dhcp_echo/main.c
 * @brief tcp_echo's TCP and UDP echo on port 7, with the IPv4 address
 *        from DHCP.  The SUT of the DHCPv4 blackbox suite.
 *
 *   sudo ./dhcp_echo_demo [tap0 | raw:<ifname> | feth1]
 */

#include "dhcpv4_client.h"
#include "net.h"
#include "tcp.h"
#include "udp.h"
#include <stdio.h>

#include "demo_echo.h"
#include "demo_loop.h"

#define ECHO_PORT 7u
#define DHCP_CLIENT_PORT 68u

static net_t net;
static demo_mac_t nic;
static demo_echo_t echo;
static dhcpv4_client_t dhcp;
static int bound;

static void on_dhcp_event(uint8_t event, void *ctx) {
  (void)ctx;
  switch (event) {
  case DHCPV4_EVT_BOUND:
    bound = 1;
    printf("[DHCP] BOUND: ");
    demo_print_ipv4(net.ipv4_addr);
    printf("\n");
    break;
  case DHCPV4_EVT_RENEWED:
    printf("[DHCP] RENEWED\n");
    break;
  case DHCPV4_EVT_EXPIRED:
    bound = 0;
    printf("[DHCP] EXPIRED — restarting\n");
    break;
  case DHCPV4_EVT_NAK:
    printf("[DHCP] NAK — restarting\n");
    break;
  case DHCPV4_EVT_TIMEOUT:
    printf("[DHCP] no answer to the REQUEST — restarting\n");
    break;
  case DHCPV4_EVT_DECLINED:
    printf("[DHCP] address in use (ARP) — declined, restarting in 10 s\n");
    break;
  default:
    break;
  }
  fflush(stdout);
}

static void dhcp_input(net_t *n, uint32_t src_ip, uint16_t src_port,
                       const uint8_t *src_mac, const uint8_t *payload,
                       uint16_t len) {
  (void)src_port;
  dhcpv4_client_input(n, &dhcp, src_ip, src_mac, payload, len);
}

static void udp_echo(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *payload,
                     uint16_t len) {
  udp_send(n, src_ip, src_mac, ECHO_PORT, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {
    {ECHO_PORT, udp_echo},
    {DHCP_CLIENT_PORT, dhcp_input},
};

static void tick(uint32_t elapsed_ms) {
  dhcpv4_client_tick(&net, &dhcp, elapsed_ms);
}

static void service(void) { demo_echo_service(&net, &echo); }

int main(int argc, char *argv[]) {
  const demo_hooks_t hooks = {tick, service, NULL};

  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "dhcp_echo") != 0)
    return 1;
  udp_set_ports(&net, udp_ports, 2);
  if (dhcpv4_client_init(&dhcp, &net, on_dhcp_event, NULL, NULL) != NET_OK)
    return 1;
  dhcpv4_client_start(&net, &dhcp);
  printf("[DHCP] Discovery started\n");
  fflush(stdout);
  demo_echo_start(&net, &echo, ECHO_PORT, "tcp_echo");

  demo_run(&net, "dhcp_echo", &hooks);

  printf("[dhcp_echo] shutting down\n");
  demo_echo_stop(&net, &echo);
  if (bound)
    dhcpv4_client_release(&net, &dhcp);
  demo_net_close(&nic);
  return 0;
}
