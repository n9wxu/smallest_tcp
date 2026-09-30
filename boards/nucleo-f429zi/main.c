/**
 * @file boards/nucleo-f429zi/main.c
 * @brief tcp_echo_demo firmware: TCP and UDP echo on port 7 at 10.0.0.2
 *        (NET_DEFAULT_IPV4_ADDR), over IPv6 too in a dual-stack build —
 *        the SUT of the hardware fuzz job (.github/workflows/fuzz.yml).
 *
 * The console (the ST-LINK's virtual COM port, 115200 8N1) says "ready"
 * once the Ethernet link is up; LD1 shows the link.
 */

#include "board.h"
#include "driver/stm32f4_eth.h"
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"

#if NET_USE_IPV6
#include "ipv6.h"
#endif

#define ECHO_PORT 7u
#define LINK_POLL_MS 500u
#define FRAME_SIZE 1514u
#define ECHO_BUF 1024u
#define RELISTEN_MS 50u /* the pacing the blackbox TCP suite was tuned to */

static uint8_t rx_frame[FRAME_SIZE], tx_frame[FRAME_SIZE];
static net_t net;
static stm32f4_eth_ctx_t eth; /* in SRAM (.bss), where the DMA reaches */

static tcp_conn_t conn;
static tcp_saw_tx_ctx_t tcp_tx_ctx;
static tcp_saw_rx_ctx_t tcp_rx_ctx;
static uint8_t tcp_tx_mem[ECHO_BUF], tcp_rx_mem[ECHO_BUF];
static tcp_conn_t *const conn_table[] = {&conn};
static volatile uint8_t tcp_events; /* set by the callback, acted on later */

static void on_tcp_event(tcp_conn_t *c, uint8_t events) {
  (void)c;
  tcp_events |= events;
}

static void listen_again(void) {
  tcp_saw_tx_init(&tcp_tx_ctx, tcp_tx_mem, sizeof(tcp_tx_mem));
  tcp_saw_rx_init(&tcp_rx_ctx, tcp_rx_mem, sizeof(tcp_rx_mem));
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tcp_tx_ctx, &tcp_saw_rx_ops,
                &tcp_rx_ctx, on_tcp_event);
  tcp_listen(&conn, ECHO_PORT);
  tcp_events = 0;
}

static void udp_echo(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *payload,
                     uint16_t len) {
  udp_send(n, src_ip, src_mac, ECHO_PORT, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {{ECHO_PORT, udp_echo}};

#if NET_USE_IPV6
static void udp6_echo(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                      const uint8_t *src_mac, const uint8_t *payload,
                      uint16_t len) {
  udp6_send(n, src_ip, src_mac, ECHO_PORT, src_port, payload, len);
}

static const udp6_port_entry_t udp6_ports[] = {{ECHO_PORT, udp6_echo}};
#endif

/* Everything received goes back; what the stop-and-wait buffer cannot take
 * now is dropped, as in the hosted demo */
static void echo_data(void) {
  uint8_t buf[256];
  uint16_t n;
  while ((n = tcp_recv(&conn, buf, sizeof(buf))) > 0)
    tcp_send(&net, &conn, buf, n);
}

/* Echo, close when the client does, and listen again a moment after the
 * connection is gone */
static void tcp_service(uint32_t now) {
  static uint32_t gone_since;
  static int gone;
  uint8_t events = tcp_events;
  tcp_events = 0;
  if (events & TCP_EVT_DATA)
    echo_data();
  if ((events & TCP_EVT_CLOSED) && conn.state == TCP_CLOSE_WAIT)
    tcp_close(&net, &conn); /* our FIN answers theirs */
  if (!gone && (conn.state == TCP_CLOSED || conn.state == TCP_TIME_WAIT)) {
    gone = 1;
    gone_since = now;
  }
  if (gone && now - gone_since >= RELISTEN_MS) {
    gone = 0;
    listen_again();
  }
}

static void link_service(uint8_t *link_up, int *announced) {
  int up = stm32f4_eth_link_poll(&eth);
  if (up != *link_up) {
    *link_up = (uint8_t)up;
    board_led(up);
    board_puts(up ? "link up\r\n" : "link down\r\n");
  }
  if (up && !*announced) {
    *announced = 1;
    board_puts("ready\r\n");
  }
}

int main(void) {
  uint8_t entropy[16];
  uint32_t last_tick, last_link;
  uint8_t link_up = 0;
  int announced = 0;

  board_init();
  board_puts("\r\nsmallest_tcp tcp_echo_demo, NUCLEO-F429ZI\r\n");
  if (net_init(&net, rx_frame, sizeof(rx_frame), tx_frame, sizeof(tx_frame),
               NULL, &stm32f4_eth_ops, &eth) != NET_OK)
    return 1;
  stm32f4_eth_ctx_init(&eth, net.mac, BOARD_PHY_ADDR, BOARD_HCLK_HZ);
  if (stm32f4_eth_ops.init(&eth) != 0) {
    board_puts("Ethernet failed: no clock from the PHY\r\n");
    return 1;
  }
  if (!board_entropy(entropy, sizeof(entropy)))
    board_puts("no random numbers: seeded from the unique ID\r\n");
  net_random_seed(&net, entropy, sizeof(entropy));
  udp_set_ports(&net, udp_ports, 1);
#if NET_USE_IPV6
  udp6_set_ports(&net, udp6_ports, 1);
  ipv6_start(&net);
#endif
  tcp_set_connections(&net, conn_table, 1);
  listen_again();

  last_tick = last_link = board_millis();
  for (;;) {
    uint32_t now;
    while (net_poll(&net) > 0) { /* drain the receive ring first */
    }
    now = board_millis();
    if (now != last_tick) {
      net_tick(&net, now - last_tick);
      last_tick = now;
    }
    if (now - last_link >= LINK_POLL_MS) {
      last_link = now;
      link_service(&link_up, &announced);
    }
    tcp_service(now);
  }
}
