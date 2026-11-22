/**
 * @file boards/sam4e-xplained-pro/board.h
 * @brief SAM4E Xplained Pro: ATSAM4E16E at 120 MHz from the 12 MHz
 *        crystal, SysTick milliseconds, UART0 on the EDBG virtual COM
 *        port, the MII pins of the on-board KSZ8081MNX PHY, and LED0.
 */

#ifndef BOARD_H
#define BOARD_H

#include <stdint.h>

#define BOARD_MCK_HZ 120000000u
#define BOARD_PHY_ADDR 0 /* the KSZ8081's PHYAD straps */

/** The watchdog off, clocks, SysTick, the console, the Ethernet pins, the
 *  LED. */
void board_init(void);

/** Milliseconds since board_init(); wraps after 49.7 days. */
uint32_t board_millis(void);

/** Write @p s to the console (115200 8N1). */
void board_puts(const char *s);

/** LED0 (yellow) on or off. */
void board_led(int on);

/** @p len bytes for net_random_seed().  The SAM4E has no random number
 *  generator: the bytes are the chip's identity and the SysTick counter at
 *  the moment of the call, so call it again when something outside the
 *  board has set the time — the link coming up.  Always 0: not random. */
int board_entropy(uint8_t *buf, uint16_t len);

#endif /* BOARD_H */
