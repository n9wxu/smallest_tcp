/**
 * @file demo/common/demo_loop.h
 * @brief What every demo's main() does: open the network interface named
 *        on the command line (demo_mac.h), then receive frames and run
 *        timers until SIGINT or SIGTERM.
 */

#ifndef DEMO_LOOP_H
#define DEMO_LOOP_H

#include "net.h"
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "demo_ipv6.h"
#include "demo_mac.h"

#define DEMO_FRAME_SIZE 1514u
#define DEMO_TICK_MS 10u

static volatile sig_atomic_t demo_running = 1;

static void demo_on_signal(int sig) {
  (void)sig;
  demo_running = 0;
}

static inline uint32_t demo_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static inline void demo_print_ipv4(uint32_t ip) {
  printf("%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 0xFF),
         (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
}

/**
 * Open the interface named by @p spec and initialise @p net on it: frame
 * buffers of DEMO_FRAME_SIZE, the default MAC and addresses, random
 * numbers seeded, IPv6 started.  SIGINT and SIGTERM will end demo_run().
 * @return 0, or -1 (reported on stderr with @p tag).
 */
static inline int demo_net_open(net_t *net, demo_mac_t *nic, const char *spec,
                                const char *tag) {
  static uint8_t rx[DEMO_FRAME_SIZE], tx[DEMO_FRAME_SIZE];
  signal(SIGINT, demo_on_signal);
  signal(SIGTERM, demo_on_signal);
  if (demo_mac_select(nic, spec) != 0)
    return -1;
  if (net_init(net, rx, sizeof(rx), tx, sizeof(tx), NULL, nic->ops,
               &nic->ctx) != NET_OK ||
      nic->ops->init(&nic->ctx) != 0) {
    fprintf(stderr, "[%s] cannot open the network interface\n", tag);
    return -1;
  }
  net_random_seed(net, (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16));
#if NET_USE_IPV6
  ipv6_start(net);
#endif
  return 0;
}

static inline void demo_net_close(demo_mac_t *nic) {
  nic->ops->close(&nic->ctx);
}

/** What a demo adds to the loop; any may be NULL. */
typedef struct {
  void (*tick)(uint32_t elapsed_ms); /**< Every DEMO_TICK_MS, after net_tick */
  void (*service)(void);             /**< Every time round the loop */
  void (*ipv6_address_ready)(void);  /**< An IPv6 address became usable */
} demo_hooks_t;

/**
 * One time round: a received frame processed, if one was waiting, and
 * the timers run when DEMO_TICK_MS have passed since @p *last_tick.
 * @return 1 if a frame was processed.
 */
static inline int demo_step(net_t *net, uint32_t *last_tick, const char *tag,
                            const demo_hooks_t *hooks) {
  int got = net_poll(net);
  uint32_t now = demo_now_ms(), elapsed = now - *last_tick;
  (void)tag;
  if (elapsed >= DEMO_TICK_MS) {
    net_tick(net, elapsed);
    if (hooks && hooks->tick)
      hooks->tick(elapsed);
#if NET_USE_IPV6
    if (demo_ipv6_report(net, tag) && hooks && hooks->ipv6_address_ready)
      hooks->ipv6_address_ready();
#endif
    *last_tick = now;
  }
  if (hooks && hooks->service)
    hooks->service();
  return got > 0;
}

/** Run until SIGINT or SIGTERM (or demo_running is cleared). */
static inline void demo_run(net_t *net, const char *tag,
                            const demo_hooks_t *hooks) {
  uint32_t last_tick = demo_now_ms();
  while (demo_running) {
    if (!demo_step(net, &last_tick, tag, hooks)) {
      struct timespec idle = {0, 500000}; /* 0.5 ms */
      nanosleep(&idle, NULL);
    }
  }
}

#endif /* DEMO_LOOP_H */
