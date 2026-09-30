/**
 * @file boards/nucleo-f429zi/board.h
 * @brief NUCLEO-F429ZI: STM32F429ZI at 168 MHz from the HSI, SysTick
 *        milliseconds, USART3 on the ST-LINK virtual COM port, the RMII
 *        pins of the on-board LAN8742A PHY, and LED LD1.
 */

#ifndef BOARD_H
#define BOARD_H

#include <stdint.h>

#define BOARD_HCLK_HZ 168000000u
#define BOARD_PHY_ADDR 0 /* the LAN8742A's PHYAD0 strap */

/** Clocks, SysTick, the console, the Ethernet pins, the LED. */
void board_init(void);

/** Milliseconds since board_init(); wraps after 49.7 days. */
uint32_t board_millis(void);

/** Write @p s to the console (115200 8N1). */
void board_puts(const char *s);

/** LD1 (green) on or off. */
void board_led(int on);

/** @p len bytes for net_random_seed() from the hardware random number
 *  generator: 1.  0 if it failed, and the bytes are the device's unique ID
 *  and the SysTick count instead. */
int board_entropy(uint8_t *buf, uint16_t len);

#endif /* BOARD_H */
