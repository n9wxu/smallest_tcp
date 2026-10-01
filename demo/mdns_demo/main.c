/**
 * @file demo/mdns_demo/main.c
 * @brief mDNS + DNS-SD demo — advertises a host name and a service.
 *
 * Announces "pyro-dead01.local" (A record for the stack's IP) and the DNS-SD
 * service "Pyro Unit 1._pyro._tcp.local" on port 80, where it runs a TCP
 * echo server so the advertised service is real.  On a name conflict the
 * demo renames itself ("pyro-dead01-2.local", "Pyro Unit 1 (2)") and probes
 * again.  SIGINT / SIGTERM sends goodbye packets before exiting.
 *
 * Also the SUT for tests/blackbox/test_mdns_conform.py.
 *
 * Linux:  sudo ip tuntap add dev tap0 mode tap
 *         sudo ip addr add 10.0.0.100/24 dev tap0 && sudo ip link set tap0 up
 *         sudo ./build/demo/mdns_demo
 *         avahi-resolve -n pyro-dead01.local ; avahi-browse -rt _pyro._tcp
 *         raw socket on an existing interface (NIC or veth end):
 *           sudo ./build/demo/mdns_demo raw:veth-sut
 * macOS:  (feth pair, see the README) sudo ./build/demo/mdns_demo feth1
 *         dns-sd -B _pyro._tcp local
 */

#include "mdns.h"
#include "net.h"
#include "udp.h"
#include <stdio.h>

#include "demo_echo.h"
#include "demo_loop.h"

#define SERVICE_PORT 80u

static net_t net;
static demo_mac_t nic;
static demo_echo_t echo;

/* The names are buffers so that a conflict can rename them */
static char host[64] = "pyro-dead01.local";
static char inst[96] = "Pyro Unit 1._pyro._tcp.local";
static int host_n = 1, inst_n = 1;

static const char *const txt[] = {"txtvers=1", "fw=1.2.3", "serial=DEAD01",
                                  NULL};

static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A, .ttl = MDNS_TTL_HOST, .name = host, .rdata.a = 0},
#if NET_USE_IPV6
    {.type = DNS_TYPE_AAAA,
     .ttl = MDNS_TTL_HOST,
     .name = host,
     .rdata.aaaa = NULL}, /* our IPv6 addresses */
#endif
    {.type = DNS_TYPE_PTR,
     .ttl = MDNS_TTL_OTHER,
     .name = "_pyro._tcp.local",
     .rdata.ptr = inst},
    {.type = DNS_TYPE_SRV,
     .ttl = MDNS_TTL_HOST,
     .name = inst,
     .rdata.srv = {0, 0, SERVICE_PORT, host}},
    {.type = DNS_TYPE_TXT,
     .ttl = MDNS_TTL_OTHER, /* no host name in it (RFC 6762 §10) */
     .name = inst,
     .rdata.txt = txt},
};

static mdns_t mdns;
static volatile int want_restart;

/* The bit of the instance's PTR record in the table */
static uint32_t ptr_bit(void) {
  uint8_t i = 0;
  while (records[i].type != DNS_TYPE_PTR)
    i++;
  return 1u << i;
}

/* RFC 6762 §9 / RFC 6763 §8: pick a new name and probe again */
static void on_conflict(mdns_t *m, uint8_t index, void *ctx) {
  (void)ctx;
  if (records[index].name == host) {
    snprintf(host, sizeof(host), "pyro-dead01-%d.local", ++host_n);
    printf("[mdns] conflict on host name, renamed to %s\n", host);
  } else {
    /* RFC 6762 §8.4: renaming changes the PTR's rdata — a goodbye for the
     * old first */
    mdns_withdraw(m, ptr_bit());
    snprintf(inst, sizeof(inst), "Pyro Unit 1 (%d)._pyro._tcp.local", ++inst_n);
    printf("[mdns] conflict on service name, renamed to %s\n", inst);
  }
  fflush(stdout);
  want_restart = 1;
}

static void mdns_udp_input(net_t *n, uint32_t src_ip, uint16_t src_port,
                           const uint8_t *src_mac, const uint8_t *payload,
                           uint16_t len) {
  (void)n;
  mdns_input(&mdns, src_ip, src_mac, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {{MDNS_PORT, mdns_udp_input}};

#if NET_USE_IPV6
static void mdns_udp6_input(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                            const uint8_t *src_mac, const uint8_t *payload,
                            uint16_t len) {
  (void)n;
  mdns_input6(&mdns, src_ip, src_mac, src_port, payload, len);
}

static const udp6_port_entry_t udp6_ports[] = {{MDNS_PORT, mdns_udp6_input}};

/* RFC 6762 §8.4: announce the addresses usable now */
static void ipv6_address_ready(void) { mdns_readdress6(&mdns); }
#endif

static const char *state_name(uint8_t s) {
  switch (s) {
  case MDNS_STATE_PROBING:
    return "probing";
  case MDNS_STATE_ANNOUNCING:
    return "announcing";
  case MDNS_STATE_RUNNING:
    return "running";
  case MDNS_STATE_CONFLICT:
    return "conflict";
  default:
    return "stopped";
  }
}

static void tick(uint32_t elapsed_ms) { mdns_tick(&mdns, elapsed_ms); }

static void service(void) {
  static uint8_t last_state = MDNS_STATE_STOPPED;
  if (want_restart) {
    want_restart = 0;
    mdns_start(&mdns);
  }
  if (mdns_state(&mdns) != last_state) {
    last_state = mdns_state(&mdns);
    printf("[mdns] %s (%s)\n", state_name(last_state), host);
    fflush(stdout);
  }
  demo_echo_service(&net, &echo);
}

int main(int argc, char *argv[]) {
  demo_hooks_t hooks = {tick, service, NULL};

  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "mdns") != 0)
    return 1;
  udp_set_ports(&net, udp_ports, 1);
#if NET_USE_IPV6
  udp6_set_ports(&net, udp6_ports, 1);
  hooks.ipv6_address_ready = ipv6_address_ready;
#endif
  demo_echo_start(&net, &echo, SERVICE_PORT, "mdns");
  if (mdns_init(&mdns, &net, records, sizeof(records) / sizeof(records[0]),
                on_conflict, NULL) != NET_OK) {
    fprintf(stderr, "[mdns] invalid record table\n");
    return 1;
  }
  printf("[mdns] %s -> ", host);
  demo_print_ipv4(net.ipv4_addr);
  printf(", service \"%s\" port %u\n", inst, SERVICE_PORT);
  fflush(stdout);
  mdns_start(&mdns);

  demo_run(&net, "mdns", &hooks);

  printf("[mdns] shutting down: sending goodbye\n");
  fflush(stdout);
  mdns_stop(&mdns);
  demo_echo_stop(&net, &echo);
  demo_net_close(&nic);
  return 0;
}
