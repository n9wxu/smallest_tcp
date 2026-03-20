/**
 * @file bench/size_measure.c
 * @brief Minimal bare-metal application for ARM code size measurement.
 *
 * This file exercises all implemented stack layers so the linker keeps them.
 * No OS dependencies (no stdio, no malloc, no syscalls).
 *
 * Compile with: arm-none-eabi-gcc -Os -mthumb -mcpu=cortex-m0 -ffreestanding
 *               -nostdlib -Iinclude -c bench/size_measure.c
 *
 * Or use: make arm-size
 */

#include "arp.h"
#include "driver/stub.h"
#include "eth.h"
#include "icmp.h"
#include "ipv4.h"
#include "net.h"
#include "udp.h"

/* Application-owned memory (typical small MCU sizes) */
static uint8_t rx_buf[300];
static uint8_t tx_buf[300];
static net_t net;

/* UDP handler — echoes back */
static void echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  udp_send(n, src_ip, src_mac, 7, src_port, data, len);
}

static const udp_port_entry_t ports[] = {{7, echo_handler}};

/* Prevent the compiler from optimizing away the entire program */
volatile int dummy;

void app_main(void) {
  static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), mac,
           &stub_mac_ops, (void *)0);

  udp_ports.entries = ports;
  udp_ports.count = 1;

  /* Simulate receiving a frame */
  int n = stub_mac_ops.recv((void *)0, rx_buf, sizeof(rx_buf));
  if (n > 0) {
    eth_input(&net, rx_buf, (uint16_t)n);
  }

  /* Simulate sending a UDP packet */
  static const uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  static const uint8_t payload[] = "hello";
  udp_send(&net, 0x0A000001, dst_mac, 7, 1234, payload, 5);

  /* Force ARP request to be linked */
  arp_request(&net, 0x0A000001);

  dummy = n;
}

/* Bare-metal entry point — no libc startup */
void _start(void) {
  app_main();
  while (1) {
  }
}

/* ARM vector table minimum — reset vector only */
__attribute__((section(".vectors"))) void (*const vectors[])(void) = {
    (void (*)(void))0x20001000, /* Initial SP (4KB RAM) */
    _start,                     /* Reset handler */
};
