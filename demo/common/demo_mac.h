/**
 * @file demo/common/demo_mac.h
 * @brief Pick a demo's platform MAC driver from its interface argument.
 *
 *   Linux:  "tap0", "tap:tap0"  TAP device (default tap0)
 *           "raw:eth0"          raw socket (AF_PACKET) on an existing
 *                               interface — a NIC or a veth end
 *   macOS:  "feth1"             BPF on an feth interface (default feth1)
 *
 * Usage:
 *   demo_mac_t mac;
 *   if (demo_mac_select(&mac, argc > 1 ? argv[1] : NULL) != 0) ...
 *   net_init(&net, ..., mac.ops, &mac.ctx);
 *   mac.ops->init(&mac.ctx);
 */

#ifndef DEMO_MAC_H
#define DEMO_MAC_H

#include "net_mac.h"
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include "driver/rawsock.h"
#include "driver/tap.h"
#elif defined(__APPLE__)
#include "driver/bpf.h"
#endif

typedef struct {
  const net_mac_t *ops;
  union {
#if defined(__linux__)
    tap_ctx_t tap;
    rawsock_ctx_t raw;
#elif defined(__APPLE__)
    bpf_ctx_t bpf;
#endif
    int none;
  } ctx;
} demo_mac_t;

/**
 * Select and initialise (but not open) the driver named by spec.
 * @param spec  Interface argument as above; NULL for the platform default.
 * @return 0, or -1 if this platform has no driver.
 */
static inline int demo_mac_select(demo_mac_t *m, const char *spec) {
#if defined(__linux__)
  if (spec && strncmp(spec, "raw:", 4) == 0) {
    rawsock_ctx_init(&m->ctx.raw, spec + 4);
    m->ops = &rawsock_mac_ops;
    return 0;
  }
  if (spec && strncmp(spec, "tap:", 4) == 0) {
    spec += 4;
  }
  tap_ctx_init(&m->ctx.tap, spec);
  m->ops = &tap_mac_ops;
  return 0;
#elif defined(__APPLE__)
  bpf_ctx_init(&m->ctx.bpf, spec);
  m->ops = &bpf_mac_ops;
  return 0;
#else
  (void)spec;
  m->ops = NULL;
  fprintf(stderr, "Platform not supported\n");
  return -1;
#endif
}

#endif /* DEMO_MAC_H */
