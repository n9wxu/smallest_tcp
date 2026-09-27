/**
 * @file demo/tcp_echo/main.c
 * @brief TCP and UDP echo on port 7; over IPv6 too, with DHCPv6 started
 *        when a Router Advertisement asks for it.  Builds IPv6-only.
 *
 *   sudo ./tcp_echo_demo [tap0 | raw:<ifname> | feth1]
 *   nc 10.0.0.2 7
 *
 * The SUT of most blackbox suites (TCP, UDP, ICMP, IPv4, IPv6, ARP).
 */

#include "net.h"
#include "tcp.h"
#include "udp.h"
#include <stdio.h>
#include <string.h>

#include "demo_echo.h"
#include "demo_loop.h"

#if NET_USE_IPV6
#include "dhcpv6_client.h"
#include "ndp.h"
#endif

#define ECHO_PORT 7u

static net_t net;
static demo_mac_t nic;
static demo_echo_t echo;

#if NET_USE_IPV4
static void udp_echo(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *payload,
                     uint16_t len) {
  udp_send(n, src_ip, src_mac, ECHO_PORT, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {{ECHO_PORT, udp_echo}};
#endif

#if NET_USE_IPV6
static dhcpv6_client_t dhcp6;
static int dhcp6_started;

static void udp6_echo(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                      const uint8_t *src_mac, const uint8_t *payload,
                      uint16_t len) {
  udp6_send(n, src_ip, src_mac, ECHO_PORT, src_port, payload, len);
}

static void dhcp6_input(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                        const uint8_t *src_mac, const uint8_t *payload,
                        uint16_t len) {
  (void)src_port;
  (void)src_mac;
  dhcpv6_client_input(n, &dhcp6, src_ip, payload, len);
}

static void on_dns6(uint16_t option, const uint8_t *data, uint16_t len,
                    void *ctx) {
  uint16_t i;
  (void)option;
  (void)ctx;
  for (i = 0; i + 16 <= len; i += 16) {
    printf("[tcp_echo] DHCPv6 DNS server ");
    demo_ipv6_print_addr(data + i);
    printf("\n");
  }
  fflush(stdout);
}

static const dhcpv6_opt_entry_t dhcp6_opt_entries[] = {
    {DHCPV6_OPT_DNS_SERVERS, on_dns6, NULL},
};
static const dhcpv6_opt_table_t dhcp6_opts = {dhcp6_opt_entries, 1};

static void on_dhcp6_event(uint8_t event, void *ctx) {
  static const char *const names[] = {"", "configured", "bound", "renewed",
                                      "expired"};
  (void)ctx;
  printf("[tcp_echo] DHCPv6 %s\n", event <= 4 ? names[event] : "?");
  fflush(stdout);
}

static const udp6_port_entry_t udp6_ports[] = {
    {ECHO_PORT, udp6_echo},
    {DHCPV6_CLIENT_PORT, dhcp6_input},
};

/* RFC 4861 §4.2: an RA with M asks for DHCPv6 addresses, with O for other
 * configuration (DNS) only */
static void dhcp6_tick(uint32_t elapsed_ms) {
  dhcpv6_client_tick(&net, &dhcp6, elapsed_ms);
  if (!dhcp6_started && net.ip6.ra_flags) {
    dhcp6_started = 1;
    dhcpv6_client_start(&net, &dhcp6,
                        (net.ip6.ra_flags & NDP_RA_MANAGED)
                            ? DHCPV6_MODE_STATEFUL
                            : DHCPV6_MODE_STATELESS);
  }
}
#endif

static void service(void) { demo_echo_service(&net, &echo); }

int main(int argc, char *argv[]) {
  demo_hooks_t hooks = {NULL, service, NULL};

  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "tcp_echo") != 0)
    return 1;
#if NET_USE_IPV4
  udp_set_ports(&net, udp_ports, 1);
#endif
#if NET_USE_IPV6
  udp6_set_ports(&net, udp6_ports, 2);
  dhcpv6_client_init(&dhcp6, on_dhcp6_event, NULL, &dhcp6_opts);
  hooks.tick = dhcp6_tick;
#endif
  printf("[tcp_echo] IP: ");
  demo_print_ip(&net);
  printf("\n");
  demo_echo_start(&net, &echo, ECHO_PORT, "tcp_echo");

  demo_run(&net, "tcp_echo", &hooks);

  printf("[tcp_echo] shutting down\n");
  demo_echo_stop(&net, &echo);
#if NET_USE_IPV6
  dhcpv6_client_release(&net, &dhcp6);
#endif
  demo_net_close(&nic);
  return 0;
}
