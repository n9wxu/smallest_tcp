/**
 * @file boards/sam4e-xplained-pro/board.c
 * @brief SAM4E Xplained Pro bring-up (SAM4E datasheet, the board's user
 *        guide): the watchdog off, PLLA from the 12 MHz crystal to
 *        120 MHz, SysTick at 1 kHz, UART0 (PA9/PA10, the EDBG virtual COM
 *        port), the MII pins (PD0 to PD16), LED0 (PD22).
 */

#include "board.h"
#include <stdint.h>

#define REG(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

#define PMC_PCER0 REG(0x400E0410u)
#define CKGR_MOR REG(0x400E0420u)
#define CKGR_PLLAR REG(0x400E0428u)
#define PMC_MCKR REG(0x400E0430u)
#define PMC_SR REG(0x400E0468u)
#define EFC_FMR REG(0x400E0A00u)
#define WDT_MR REG(0x400E1854u)
#define CHIPID_CIDR REG(0x400E0740u)
#define CHIPID_EXID REG(0x400E0744u)
#define SYST_CSR REG(0xE000E010u)
#define SYST_RVR REG(0xE000E014u)
#define SYST_CVR REG(0xE000E018u)
#define UART0_CR REG(0x400E0600u)
#define UART0_MR REG(0x400E0604u)
#define UART0_SR REG(0x400E0614u)
#define UART0_THR REG(0x400E061Cu)
#define UART0_BRGR REG(0x400E0620u)

#define PIOA 0x400E0E00u
#define PIOD 0x400E1400u
#define PIO_PER 0x00u /* the pin is the PIO's */
#define PIO_PDR 0x04u /* the pin is a peripheral's */
#define PIO_OER 0x10u
#define PIO_SODR 0x30u
#define PIO_CODR 0x34u
#define PIO_ABCDSR1 0x70u /* with ABCDSR2: which peripheral; 0, 0 is A */
#define PIO_ABCDSR2 0x74u

#define PID_UART0 (1u << 7)
#define PID_PIOA (1u << 9)
#define PID_PIOD (1u << 12)
#define CKGR_MOR_KEY (0x37u << 16)
#define CKGR_MOR_MOSCXTEN (1u << 0)
#define CKGR_MOR_MOSCRCEN (1u << 3)
#define CKGR_MOR_MOSCXTST (0xFFu << 8) /* start-up time: 62 ms */
#define CKGR_MOR_MOSCSEL (1u << 24)
#define CKGR_PLLAR_ONE (1u << 29)
#define PMC_MCKR_CSS_MASK 3u
#define PMC_MCKR_CSS_MAIN 1u
#define PMC_MCKR_CSS_PLLA 2u
#define PMC_MCKR_PRES_MASK (7u << 4)
#define PMC_MCKR_PRES_DIV2 (1u << 4)
#define PMC_SR_MOSCXTS (1u << 0)
#define PMC_SR_LOCKA (1u << 1)
#define PMC_SR_MCKRDY (1u << 3)
#define PMC_SR_MOSCSELS (1u << 16)
#define EFC_FMR_FWS_5 (5u << 8) /* six cycles a read: up to 123 MHz */
#define WDT_MR_WDDIS (1u << 15)
#define UART_CR_RESET 0xACu /* RSTRX, RSTTX, RXDIS, TXDIS */
#define UART_CR_RXEN (1u << 4)
#define UART_CR_TXEN (1u << 6)
#define UART_MR_NO_PARITY (4u << 9)
#define UART_SR_TXRDY (1u << 1)

#define CONSOLE_BAUD 115200u
#define CONSOLE_PINS (1u << 9 | 1u << 10) /* PA9 URXD0, PA10 UTXD0 */
#define MII_PINS 0x1FFFFu                 /* PD0 to PD16 */
#define LED_PIN (1u << 22)                /* PD22, lit when low */

static volatile uint32_t millis;

void systick_handler(void) { millis++; }

static void wait_status(uint32_t bit) {
  while (!(PMC_SR & bit)) {
  }
}

/* The 12 MHz crystal as the main clock; PLLA at 12 MHz x 20 = 240 MHz;
 * the master clock PLLA / 2 = 120 MHz.  The prescaler is set before the
 * source, each change waited for, as the datasheet's sequence has it. */
static void clock_init(void) {
  EFC_FMR = EFC_FMR_FWS_5;
  CKGR_MOR =
      CKGR_MOR_KEY | CKGR_MOR_MOSCXTST | CKGR_MOR_MOSCRCEN | CKGR_MOR_MOSCXTEN;
  wait_status(PMC_SR_MOSCXTS);
  CKGR_MOR = CKGR_MOR_KEY | CKGR_MOR_MOSCXTST | CKGR_MOR_MOSCRCEN |
             CKGR_MOR_MOSCXTEN | CKGR_MOR_MOSCSEL;
  wait_status(PMC_SR_MOSCSELS);
  PMC_MCKR = (PMC_MCKR & ~PMC_MCKR_CSS_MASK) | PMC_MCKR_CSS_MAIN;
  wait_status(PMC_SR_MCKRDY);
  CKGR_PLLAR = CKGR_PLLAR_ONE | (20u - 1u) << 16 | 0x3Fu << 8 | 1u;
  wait_status(PMC_SR_LOCKA);
  PMC_MCKR = (PMC_MCKR & ~PMC_MCKR_PRES_MASK) | PMC_MCKR_PRES_DIV2;
  wait_status(PMC_SR_MCKRDY);
  PMC_MCKR = (PMC_MCKR & ~PMC_MCKR_CSS_MASK) | PMC_MCKR_CSS_PLLA;
  wait_status(PMC_SR_MCKRDY);
}

static void systick_init(void) {
  SYST_RVR = BOARD_MCK_HZ / 1000u - 1u;
  SYST_CVR = 0;
  SYST_CSR = 7u; /* the processor clock, interrupt, enable */
}

/* @p pins of the port at @p port given to its peripheral A */
static void pins_peripheral_a(uint32_t port, uint32_t pins) {
  REG(port + PIO_ABCDSR1) &= ~pins;
  REG(port + PIO_ABCDSR2) &= ~pins;
  REG(port + PIO_PDR) = pins;
}

/* UART0 on PA9 (RX) and PA10 (TX), wired to the EDBG's virtual COM port */
static void console_init(void) {
  pins_peripheral_a(PIOA, CONSOLE_PINS);
  UART0_CR = UART_CR_RESET;
  UART0_MR = UART_MR_NO_PARITY;
  UART0_BRGR = (BOARD_MCK_HZ / 16u + CONSOLE_BAUD / 2u) / CONSOLE_BAUD;
  UART0_CR = UART_CR_RXEN | UART_CR_TXEN;
}

static void led_init(void) {
  REG(PIOD + PIO_PER) = LED_PIN;
  REG(PIOD + PIO_SODR) = LED_PIN; /* off */
  REG(PIOD + PIO_OER) = LED_PIN;
}

void board_init(void) {
  WDT_MR = WDT_MR_WDDIS; /* it resets the chip after 16 s otherwise */
  clock_init();
  systick_init();
  PMC_PCER0 = PID_UART0 | PID_PIOA | PID_PIOD;
  /* The KSZ8081MNX on MII, all on peripheral A: GTXCK PD0, GTXEN PD1,
   * GTX0..1 PD2..3, GRXDV PD4, GRX0..1 PD5..6, GRXER PD7, GMDC PD8,
   * GMDIO PD9, GCRS PD10, GRX2..3 PD11..12, GCOL PD13, GRXCK PD14,
   * GTX2..3 PD15..16 */
  pins_peripheral_a(PIOD, MII_PINS);
  console_init();
  led_init();
}

uint32_t board_millis(void) { return millis; }

void board_puts(const char *s) {
  for (; *s; s++) {
    while (!(UART0_SR & UART_SR_TXRDY)) {
    }
    UART0_THR = (uint8_t)*s;
  }
}

void board_led(int on) { REG(PIOD + (on ? PIO_CODR : PIO_SODR)) = LED_PIN; }

int board_entropy(uint8_t *buf, uint16_t len) {
  uint16_t i;
  for (i = 0; i < len; i++) {
    uint32_t word =
        (i & 4u) ? CHIPID_CIDR ^ CHIPID_EXID << 8 : SYST_CVR ^ millis << 16;
    buf[i] = (uint8_t)(word >> 8u * (i & 3u));
  }
  return 0;
}
