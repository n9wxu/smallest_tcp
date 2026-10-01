/**
 * @file demo/common/demo_ipv6.h
 * @brief Report a demo's IPv6 address changes on stdout.
 *
 * Call demo_ipv6_report() after ipv6_tick(): it prints a line when an
 * address becomes usable or fails Duplicate Address Detection, e.g.
 *   [tcp_echo] IPv6 fe80:0:0:0:0:ff:fede:ad01 preferred
 * and returns 1 if an address became usable or stopped being usable (mDNS
 * demos re-announce, RFC 6762 §8.4).
 * The blackbox tests wait for these lines.
 */

#ifndef DEMO_IPV6_H
#define DEMO_IPV6_H

#include "net.h"
#include <stdio.h>

#if NET_USE_IPV6
#include "ipv6.h"

static inline void demo_ipv6_print_addr(const uint8_t *a) {
  int i;
  for (i = 0; i < 16; i += 2)
    printf(i ? ":%x" : "%x", (unsigned)(a[i] << 8 | a[i + 1]));
}

static inline int demo_ipv6_usable(uint8_t state) {
  return state == NET_IP6_PREFERRED || state == NET_IP6_DEPRECATED;
}

static inline int demo_ipv6_report(const net_t *net, const char *tag) {
  static uint8_t last[NET_IPV6_ADDRS];
  int i, changed = 0;
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    uint8_t state = net->ip6.addr[i].state;
    if (state == last[i])
      continue;
    if (demo_ipv6_usable(state) != demo_ipv6_usable(last[i]))
      changed = 1;
    last[i] = state;
    if (state != NET_IP6_PREFERRED && state != NET_IP6_DUPLICATE)
      continue;
    printf("[%s] IPv6 ", tag);
    demo_ipv6_print_addr(net->ip6.addr[i].addr);
    printf(state == NET_IP6_PREFERRED ? " preferred\n"
                                      : " duplicate (DAD failed), not used\n");
    fflush(stdout);
  }
  return changed;
}
#endif

#endif /* DEMO_IPV6_H */
