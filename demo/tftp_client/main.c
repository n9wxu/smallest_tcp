/**
 * @file demo/tftp_client/main.c
 * @brief Fetch one file from a TFTP server.
 *
 *   sudo ./tftp_client_demo [iface] [our_ip] [server_ip] [server_mac] \
 *                           [filename] [output]
 *
 * Defaults: the platform interface, 10.0.0.2, 10.0.0.1, ff:ff:ff:ff:ff:ff
 * (broadcast — works on a local LAN), test.bin, stdout.  For example, with
 * dnsmasq serving /srv/tftp on tap0:
 *   dnsmasq --enable-tftp --tftp-root=/srv/tftp --no-daemon &
 *   sudo ./build/demo/tftp_client_demo tap0 10.0.0.2 10.0.0.1 \
 *        $(arp -n 10.0.0.1 | awk '/HWaddress/{print $3}') hello.txt out.txt
 */

#include "net.h"
#include "tftp.h"
#include "udp.h"
#include <stdio.h>

#include "demo_loop.h"

#define TFTP_CLIENT_PORT 6900u

static net_t net;
static demo_mac_t nic;
static tftp_client_t tftp;
static FILE *out;
static uint32_t bytes_received;
static int succeeded;

static void on_block(uint16_t block, const uint8_t *data, uint16_t len,
                     void *ctx) {
  (void)ctx;
  fwrite(data, 1, len, out);
  bytes_received += len;
  fprintf(stderr, "[TFTP] Block %u  (%u bytes, total %lu)\n", block, len,
          (unsigned long)bytes_received);
}

static void on_done(uint8_t ok, uint16_t err_code, const char *msg, void *ctx) {
  (void)ctx;
  fflush(out);
  if (ok)
    fprintf(stderr, "[TFTP] Transfer complete — %lu bytes received.\n",
            (unsigned long)bytes_received);
  else
    fprintf(stderr, "[TFTP] Transfer failed: code %u \"%s\"\n",
            (unsigned)err_code, msg);
  succeeded = ok;
  demo_running = 0;
}

static void tftp_input(net_t *n, uint32_t src_ip, uint16_t src_port,
                       const uint8_t *src_mac, const uint8_t *payload,
                       uint16_t len) {
  tftp_client_input(n, &tftp, src_ip, src_mac, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {{TFTP_CLIENT_PORT, tftp_input}};

static void tick(uint32_t elapsed_ms) {
  tftp_client_tick(&net, &tftp, elapsed_ms);
}

static int parse_ip(const char *s, uint32_t *ip) {
  unsigned a, b, c, d;
  if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    return -1;
  *ip = (uint32_t)a << 24 | (uint32_t)b << 16 | (uint32_t)c << 8 | d;
  return 0;
}

static int parse_mac(const char *s, uint8_t mac[6]) {
  unsigned v[6], i;
  if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4],
             &v[5]) != 6)
    return -1;
  for (i = 0; i < 6; i++)
    mac[i] = (uint8_t)v[i];
  return 0;
}

static const char *arg(int argc, char *argv[], int i, const char *dflt) {
  return argc > i ? argv[i] : dflt;
}

int main(int argc, char *argv[]) {
  const demo_hooks_t hooks = {tick, NULL, NULL};
  const char *filename = arg(argc, argv, 5, "test.bin");
  const char *out_path = arg(argc, argv, 6, NULL);
  uint32_t our_ip, server_ip;
  uint8_t server_mac[6];

  if (parse_ip(arg(argc, argv, 2, "10.0.0.2"), &our_ip) != 0 ||
      parse_ip(arg(argc, argv, 3, "10.0.0.1"), &server_ip) != 0 ||
      parse_mac(arg(argc, argv, 4, "ff:ff:ff:ff:ff:ff"), server_mac) != 0) {
    fprintf(stderr,
            "usage: %s [iface] [our_ip] [server_ip] [server_mac] "
            "[filename] [output]\n",
            argv[0]);
    return 1;
  }
  out = out_path ? fopen(out_path, "wb") : stdout;
  if (!out) {
    perror(out_path);
    return 1;
  }
  if (demo_net_open(&net, &nic, arg(argc, argv, 1, NULL), "tftp") != 0)
    return 1;
  net.ipv4_addr = our_ip;
  udp_set_ports(&net, udp_ports, 1);

  tftp_client_init(&tftp, TFTP_CLIENT_PORT, on_block, on_done, NULL);
  if (tftp_client_get(&net, &tftp, server_ip, server_mac, filename, 1) !=
      NET_OK) {
    fprintf(stderr, "[TFTP] Failed to send RRQ\n");
    demo_net_close(&nic);
    return 1;
  }
  fprintf(stderr, "[TFTP] RRQ sent: \"%s\" from port %u\n", filename,
          TFTP_CLIENT_PORT);

  demo_run(&net, "tftp", &hooks);

  demo_net_close(&nic);
  if (out != stdout)
    fclose(out);
  return succeeded ? 0 : 1;
}
