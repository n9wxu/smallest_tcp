/**
 * @file boards/nucleo-f429zi/board.c
 * @brief NUCLEO-F429ZI bring-up (RM0090, UM1974): the PLL from the 16 MHz
 *        HSI to 168 MHz, SysTick at 1 kHz, USART3 (PD8/PD9, the ST-LINK
 *        virtual COM port), the RMII pins, LD1 (PB0), the random number
 *        generator.
 */

#include "board.h"
#include <stdint.h>

#define REG(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

#define RCC_CR REG(0x40023800u)
#define RCC_PLLCFGR REG(0x40023804u)
#define RCC_CFGR REG(0x40023808u)
#define RCC_AHB1ENR REG(0x40023830u)
#define RCC_AHB2ENR REG(0x40023834u)
#define RCC_APB1ENR REG(0x40023840u)
#define FLASH_ACR REG(0x40023C00u)
#define PWR_CR REG(0x40007000u)
#define SYST_CSR REG(0xE000E010u)
#define SYST_RVR REG(0xE000E014u)
#define SYST_CVR REG(0xE000E018u)
#define USART3_SR REG(0x40004800u)
#define USART3_DR REG(0x40004804u)
#define USART3_BRR REG(0x40004808u)
#define USART3_CR1 REG(0x4000480Cu)
#define UID(i) REG(0x1FFF7A10u + 4u * (i))
#define RNG_CR REG(0x50060800u)
#define RNG_SR REG(0x50060804u)
#define RNG_DR REG(0x50060808u)

#define GPIOA 0x40020000u
#define GPIOB 0x40020400u
#define GPIOC 0x40020800u
#define GPIOD 0x40020C00u
#define GPIOG 0x40021800u
#define GPIO_MODER 0x00u
#define GPIO_OSPEEDR 0x08u
#define GPIO_PUPDR 0x0Cu
#define GPIO_BSRR 0x18u
#define GPIO_AFRL 0x20u

#define RCC_CR_PLLON (1u << 24)
#define RCC_CR_PLLRDY (1u << 25)
#define RCC_PLLCFGR_FIELDS 0x0F437FFFu /* PLLM, PLLN, PLLP, PLLSRC, PLLQ */
#define RCC_CFGR_SW_PLL 2u
#define RCC_CFGR_SWS_MASK (3u << 2)
#define RCC_CFGR_SWS_PLL (2u << 2)
#define RCC_CFGR_PPRE1_DIV4 (5u << 10)
#define RCC_CFGR_PPRE2_DIV2 (4u << 13)
#define RCC_CFGR_BUS_MASK 0xFCF3u /* HPRE, PPRE1, PPRE2, SW */
#define RCC_AHB1_GPIOA (1u << 0)
#define RCC_AHB1_GPIOB (1u << 1)
#define RCC_AHB1_GPIOC (1u << 2)
#define RCC_AHB1_GPIOD (1u << 3)
#define RCC_AHB1_GPIOG (1u << 6)
#define RCC_AHB2_RNG (1u << 6)
#define RCC_APB1_USART3 (1u << 18)
#define RCC_APB1_PWR (1u << 28)
#define FLASH_ACR_5WS 5u           /* 150 to 168 MHz at 2.7 to 3.6 V */
#define FLASH_ACR_CACHES (7u << 8) /* prefetch, instruction, data */
#define PWR_CR_VOS_SCALE1 (3u << 14)
#define RNG_CR_RNGEN (1u << 2)
#define RNG_SR_DRDY (1u << 0)
#define RNG_SR_ERRORS (3u << 1) /* CECS, SECS */
#define RNG_TRIES 100000u       /* a word takes 40 of its 48 MHz clocks */
#define USART_SR_TXE (1u << 7)
#define USART_CR1_UE (1u << 13)
#define USART_CR1_TE (1u << 3)
#define USART_CR1_RE (1u << 2)

#define APB1_HZ (BOARD_HCLK_HZ / 4u)
#define CONSOLE_BAUD 115200u
#define AF_ETH 11
#define AF_USART3 7

static volatile uint32_t millis;

void systick_handler(void) { millis++; }

/* VCO input 2 MHz (HSI / 8), VCO 336 MHz; SYSCLK = VCO / 2 = 168 MHz, and
 * VCO / 7 = 48 MHz for the USB and SDIO clock; APB1 42 MHz, APB2 84 MHz */
static void clock_init(void) {
  RCC_APB1ENR |= RCC_APB1_PWR;
  (void)RCC_APB1ENR;
  PWR_CR |= PWR_CR_VOS_SCALE1;
  RCC_PLLCFGR = (RCC_PLLCFGR & ~RCC_PLLCFGR_FIELDS) | 8u | 168u << 6 |
                0u << 16 /* P = 2 */ | 0u << 22 /* HSI */ | 7u << 24;
  RCC_CR |= RCC_CR_PLLON;
  while (!(RCC_CR & RCC_CR_PLLRDY)) {
  }
  FLASH_ACR = FLASH_ACR_5WS | FLASH_ACR_CACHES;
  while ((FLASH_ACR & 0xFu) != FLASH_ACR_5WS) {
  }
  /* the bus prescalers first, so APB1 and APB2 stay within their limits
   * when SYSCLK rises */
  RCC_CFGR = (RCC_CFGR & ~RCC_CFGR_BUS_MASK) | RCC_CFGR_PPRE1_DIV4 |
             RCC_CFGR_PPRE2_DIV2;
  RCC_CFGR |= RCC_CFGR_SW_PLL;
  while ((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL) {
  }
}

static void systick_init(void) {
  SYST_RVR = BOARD_HCLK_HZ / 1000u - 1u;
  SYST_CVR = 0;
  SYST_CSR = 7u; /* the processor clock, interrupt, enable */
}

/* @p pin of the port at @p port: alternate function @p af, fast, no pull */
static void pin_af(uint32_t port, uint8_t pin, uint8_t af) {
  uint32_t shift2 = 2u * pin, shift4 = 4u * (pin & 7u);
  volatile uint32_t *afr = &REG(port + GPIO_AFRL + (pin >= 8 ? 4u : 0u));
  REG(port + GPIO_MODER) =
      (REG(port + GPIO_MODER) & ~(3u << shift2)) | (2u << shift2);
  REG(port + GPIO_OSPEEDR) |= 3u << shift2;
  REG(port + GPIO_PUPDR) &= ~(3u << shift2);
  *afr = (*afr & ~(0xFu << shift4)) | ((uint32_t)af << shift4);
}

/* UM1974 §6.11: the LAN8742A on RMII — REF_CLK PA1, MDIO PA2, CRS_DV PA7,
 * TXD1 PB13, MDC PC1, RXD0 PC4, RXD1 PC5, TX_EN PG11, TXD0 PG13 */
static void ethernet_pins_init(void) {
  pin_af(GPIOA, 1, AF_ETH);
  pin_af(GPIOA, 2, AF_ETH);
  pin_af(GPIOA, 7, AF_ETH);
  pin_af(GPIOB, 13, AF_ETH);
  pin_af(GPIOC, 1, AF_ETH);
  pin_af(GPIOC, 4, AF_ETH);
  pin_af(GPIOC, 5, AF_ETH);
  pin_af(GPIOG, 11, AF_ETH);
  pin_af(GPIOG, 13, AF_ETH);
}

/* USART3 on PD8 (TX) and PD9 (RX), wired to the ST-LINK's virtual COM port */
static void console_init(void) {
  pin_af(GPIOD, 8, AF_USART3);
  pin_af(GPIOD, 9, AF_USART3);
  RCC_APB1ENR |= RCC_APB1_USART3;
  (void)RCC_APB1ENR;
  USART3_BRR = (APB1_HZ + CONSOLE_BAUD / 2u) / CONSOLE_BAUD;
  USART3_CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

/* LD1 on PB0, a push-pull output */
static void led_init(void) {
  REG(GPIOB + GPIO_MODER) = (REG(GPIOB + GPIO_MODER) & ~3u) | 1u;
}

void board_init(void) {
  clock_init();
  systick_init();
  RCC_AHB1ENR |= RCC_AHB1_GPIOA | RCC_AHB1_GPIOB | RCC_AHB1_GPIOC |
                 RCC_AHB1_GPIOD | RCC_AHB1_GPIOG;
  (void)RCC_AHB1ENR;
  ethernet_pins_init();
  console_init();
  led_init();
}

uint32_t board_millis(void) { return millis; }

void board_puts(const char *s) {
  for (; *s; s++) {
    while (!(USART3_SR & USART_SR_TXE)) {
    }
    USART3_DR = (uint8_t)*s;
  }
}

void board_led(int on) { REG(GPIOB + GPIO_BSRR) = on ? 1u : 1u << 16; }

/* A word from the RNG; *ok cleared if it reports an error or none comes */
static uint32_t rng_word(int *ok) {
  uint32_t tries;
  for (tries = 0; tries < RNG_TRIES && !(RNG_SR & RNG_SR_ERRORS); tries++) {
    if (RNG_SR & RNG_SR_DRDY)
      return RNG_DR;
  }
  *ok = 0;
  return 0;
}

/* RM0090 §24: the true random number generator, clocked at 48 MHz from
 * PLLQ.  Its first word is kept only to compare with the next, and each
 * with the one before (FIPS 140-2's continuous test).  Should it fail, the
 * unique ID and the SysTick count stand in, poor as they are. */
int board_entropy(uint8_t *buf, uint16_t len) {
  uint32_t word = 0, prev;
  uint16_t i;
  int ok = 1;
  RCC_AHB2ENR |= RCC_AHB2_RNG;
  (void)RCC_AHB2ENR;
  RNG_CR |= RNG_CR_RNGEN;
  prev = rng_word(&ok);
  for (i = 0; i < len && ok; i++) {
    if ((i & 3u) == 0) {
      word = rng_word(&ok);
      ok = ok && word != prev;
      prev = word;
    }
    buf[i] = (uint8_t)(word >> 8u * (i & 3u));
  }
  RNG_CR &= ~RNG_CR_RNGEN;
  for (i = 0; i < len && !ok; i++) {
    word = i < 12u ? UID(i >> 2) : SYST_CVR ^ millis << 16;
    buf[i] = (uint8_t)(word >> 8u * (i & 3u));
  }
  return ok;
}
