/**
 * @file demo/tftp_client/main.c
 * @brief TFTP client demo — fetches a file from a TFTP server.
 *
 * Demonstrates Task 9: the TFTP client module (REQ-TFTP-001..038).
 *
 * Usage (Linux, requires root):
 *   sudo ip tuntap add dev tap0 mode tap user $(whoami)
 *   sudo ip link set tap0 up
 *   sudo ip addr add 10.0.0.100/24 dev tap0
 *   sudo ./build/demo/tftp_client_demo [iface] [our_ip] [server_ip] \
 *                                      [server_mac] [filename] [output]
 *
 * Defaults:
 *   iface      = tap0 on Linux (raw:<if> for a raw socket), feth1 on macOS
 *   our_ip     = 10.0.0.2
 *   server_ip  = 10.0.0.1
 *   server_mac = ff:ff:ff:ff:ff:ff  (broadcast — works on a local LAN)
 *   filename   = test.bin
 *   output     = (none — write to stdout)
 *
 * Example:
 *   # Set up dnsmasq as TFTP server on tap0
 *   dnsmasq --enable-tftp --tftp-root=/srv/tftp --no-daemon &
 *   # Run the demo
 *   sudo ./build/demo/tftp_client_demo tap0 10.0.0.2 10.0.0.1 \
 *        $(arp -n 10.0.0.1 | awk '/HWaddress/{print $3}') \
 *        hello.txt /tmp/hello_received.txt
 */

#include "eth.h"
#include "net.h"
#include "tftp.h"
#include "udp.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "demo_mac.h"

/* ── Configuration ───────────────────────────────────────────────── */
#define TFTP_CLIENT_PORT 6900u
#define NET_BUF_SIZE 1514u

/* ── Global state ────────────────────────────────────────────────── */

static uint8_t net_rx_mem[NET_BUF_SIZE];
static uint8_t net_tx_mem[NET_BUF_SIZE];
static net_t net;

static tftp_client_t tftp;
static volatile int running = 1;

static FILE *outfile = NULL; /* NULL = write to stdout */
static uint32_t bytes_received = 0;
static int transfer_done = 0;

static void sig_handler(int s) {
  (void)s;
  running = 0;
}

/* ── TFTP callbacks ──────────────────────────────────────────────── */

static void on_tftp_data(uint16_t block, const uint8_t *data, uint16_t len,
                         void *ctx) {
  (void)ctx;
  FILE *f = outfile ? outfile : stdout;
  if (len > 0) {
    fwrite(data, 1, len, f);
    bytes_received += len;
  }
  fprintf(stderr, "[TFTP] Block %u  (%u bytes, total %lu)\n", block, len,
          (unsigned long)bytes_received);
}

static void on_tftp_done(uint8_t ok, uint16_t err_code, const char *msg,
                         void *ctx) {
  (void)ctx;
  if (ok) {
    if (outfile)
      fflush(outfile);
    fprintf(stderr, "[TFTP] Transfer complete — %lu bytes received.\n",
            (unsigned long)bytes_received);
  } else {
    fprintf(stderr, "[TFTP] Transfer failed: code %u \"%s\"\n",
            (unsigned)err_code, msg);
  }
  transfer_done = 1;
  running = 0;
}

/* ── TFTP UDP port handler ───────────────────────────────────────── */

static void tftp_udp_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac, uint16_t payload_offset,
                             uint16_t payload_len) {
  (void)src_mac;
  uint8_t buf[NET_BUF_SIZE];
  uint16_t copy = (payload_len < (uint16_t)sizeof(buf)) ? payload_len
                                                        : (uint16_t)sizeof(buf);
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, copy);
  tftp_client_input(n, &tftp, src_ip, src_port, buf, copy);
}

/* ── UDP port table ──────────────────────────────────────────────── */

static const udp_port_entry_t udp_handlers[] = {
    {TFTP_CLIENT_PORT, tftp_udp_handler},
};

/* ── MAC address parsing ─────────────────────────────────────────── */

static int parse_mac(const char *s, uint8_t mac[6]) {
  unsigned int v[6];
  if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4],
             &v[5]) != 6)
    return -1;
  uint8_t i;
  for (i = 0; i < 6; i++)
    mac[i] = (uint8_t)v[i];
  return 0;
}

static uint32_t parse_ip(const char *s) {
  unsigned int a, b, c, d;
  if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    return 0;
  return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) |
         (uint32_t)d;
}

/* ── Monotonic ms clock ──────────────────────────────────────────── */

static uint32_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* CLI arg defaults */
  const char *ifname = NULL; /* platform default */
  const char *our_ip_s = "10.0.0.2";
  const char *srv_ip_s = "10.0.0.1";
  const char *srv_mac_s = "ff:ff:ff:ff:ff:ff";
  const char *filename = "test.bin";
  const char *outpath = NULL;

  if (argc > 1)
    ifname = argv[1];
  if (argc > 2)
    our_ip_s = argv[2];
  if (argc > 3)
    srv_ip_s = argv[3];
  if (argc > 4)
    srv_mac_s = argv[4];
  if (argc > 5)
    filename = argv[5];
  if (argc > 6)
    outpath = argv[6];

  uint32_t our_ip = parse_ip(our_ip_s);
  uint32_t srv_ip = parse_ip(srv_ip_s);
  uint8_t srv_mac[6];
  if (parse_mac(srv_mac_s, srv_mac) != 0) {
    fprintf(stderr, "Invalid server MAC: %s\n", srv_mac_s);
    return 1;
  }

  if (outpath) {
    outfile = fopen(outpath, "wb");
    if (!outfile) {
      perror("fopen");
      return 1;
    }
  }

  /* ── Platform MAC driver: argv[1] names the interface ───────── */
  demo_mac_t nic;
  if (demo_mac_select(&nic, ifname) != 0) {
    return 1;
  }
  const net_mac_t *drv = nic.ops;

  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, drv, &nic.ctx);
  net.ipv4_addr = our_ip;

  if (drv->init(&nic.ctx) != 0) {
    fprintf(stderr, "[tftp_client] Failed to open MAC driver\n");
    return 1;
  }
  fprintf(stderr, "[tftp] our IP %s\n", our_ip_s);

  /* ── Register UDP port handler ───────────────────────────────── */
  udp_ports.entries = udp_handlers;
  udp_ports.count = 1;

  /* ── Start TFTP GET ───────────────────────────────────────────── */
  tftp_client_init(&tftp, TFTP_CLIENT_PORT, on_tftp_data, on_tftp_done, NULL);

  net_err_t err = tftp_client_get(&net, &tftp, srv_ip, srv_mac, filename,
                                  1 /* negotiate blksize */);
  if (err != NET_OK) {
    fprintf(stderr, "[TFTP] Failed to send RRQ: %d\n", (int)err);
    drv->close(&nic.ctx);
    return 1;
  }
  fprintf(stderr, "[TFTP] RRQ sent: \"%s\" from %s port %u\n", filename,
          srv_ip_s, TFTP_CLIENT_PORT);

  /* ── Main event loop ─────────────────────────────────────────── */
  uint32_t last_tick = now_ms();

  while (running) {
    if (net_poll(&net) > 0)
      eth_input(&net, net.rx.buf, net.rx.frame_len);

    uint32_t now = now_ms();
    uint32_t delta = now - last_tick;
    if (delta >= 10u) {
      tftp_client_tick(&net, &tftp, delta);
      last_tick = now;
    }
  }

  drv->close(&nic.ctx);
  if (outfile)
    fclose(outfile);

  return transfer_done ? 0 : 1;
}
