/**
 * @file driver/stm32f4_eth.c
 * @brief STM32F4 MAC driver: the ETH peripheral (RM0090 §33) with its DMA,
 *        RMII to the PHY, the PHY's standard registers over MDIO.
 *
 * Polled, no interrupts.  Chained rings of normal descriptors; each RX
 * buffer takes a whole frame, so a frame is always in one buffer.  Every
 * checksum stays in software (no offload).  The PHY is set to
 * auto-negotiate, and stm32f4_eth_link_poll() gives the MAC the result.
 */

#include "driver/stm32f4_eth.h"
#include <stdint.h>
#include <string.h>

#define REG(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

/* RCC and SYSCFG: the MAC's clocks, reset and RMII selection */
#define RCC_AHB1RSTR REG(0x40023810u)
#define RCC_AHB1ENR REG(0x40023830u)
#define RCC_APB2ENR REG(0x40023844u)
#define SYSCFG_PMC REG(0x40013804u)
#define RCC_AHB1_ETHMAC (1u << 25)
#define RCC_AHB1_ETHMAC_ALL (7u << 25) /* MAC, TX and RX clocks */
#define RCC_APB2_SYSCFG (1u << 14)
#define SYSCFG_PMC_RMII (1u << 23)

/* The ETH peripheral: MAC registers, then DMA registers at 0x1000 */
#define ETH_BASE 0x40028000u
#define MACCR REG(ETH_BASE + 0x0000u)
#define MACFFR REG(ETH_BASE + 0x0004u)
#define MACMIIAR REG(ETH_BASE + 0x0010u)
#define MACMIIDR REG(ETH_BASE + 0x0014u)
#define MACA0HR REG(ETH_BASE + 0x0040u)
#define MACA0LR REG(ETH_BASE + 0x0044u)
#define DMABMR REG(ETH_BASE + 0x1000u)
#define DMATPDR REG(ETH_BASE + 0x1004u)
#define DMARPDR REG(ETH_BASE + 0x1008u)
#define DMARDLAR REG(ETH_BASE + 0x100Cu)
#define DMATDLAR REG(ETH_BASE + 0x1010u)
#define DMASR REG(ETH_BASE + 0x1014u)
#define DMAOMR REG(ETH_BASE + 0x1018u)

#define MACCR_KEEP 0xFF20810Fu /* reserved bits, TE and RE */
#define MACCR_FES (1u << 14)   /* 100 Mbit/s */
#define MACCR_DM (1u << 11)    /* full duplex */
#define MACCR_RD (1u << 9)     /* no retry after a collision */
#define MACCR_TE (1u << 3)
#define MACCR_RE (1u << 2)
#define MACFFR_PAM (1u << 4) /* pass all multicast: the stack filters */
#define MACMIIAR_CR_MASK (7u << 2)
#define MACMIIAR_MW (1u << 1)
#define MACMIIAR_MB (1u << 0)
#define DMABMR_AAB (1u << 25)
#define DMABMR_USP (1u << 23)
#define DMABMR_RDP_32 (32u << 17)
#define DMABMR_FB (1u << 16)
#define DMABMR_PBL_32 (32u << 8)
#define DMABMR_SR (1u << 0)
#define DMASR_RBUS (1u << 7)
#define DMASR_TBUS (1u << 2)
#define DMAOMR_KEEP 0xF8DE3F23u /* reserved bits, ST, SR and OSF */
#define DMAOMR_RSF (1u << 25)   /* receive store and forward */
#define DMAOMR_TSF (1u << 21)   /* transmit store and forward */
#define DMAOMR_FTF (1u << 20)   /* flush transmit FIFO */
#define DMAOMR_ST (1u << 13)
#define DMAOMR_OSF (1u << 2)
#define DMAOMR_SR (1u << 1)

/* Descriptor bits (RM0090 §33.6.7, §33.6.8) */
#define TDES0_OWN (1u << 31)
#define TDES0_LS (1u << 29)
#define TDES0_FS (1u << 28)
#define TDES0_TCH (1u << 20)
#define TDES1_TBS1 0x1FFFu
#define RDES0_OWN (1u << 31)
#define RDES0_FL_SHIFT 16
#define RDES0_FL 0x3FFFu /* after the shift */
#define RDES0_ES (1u << 15)
#define RDES0_FS (1u << 9)
#define RDES0_LS (1u << 8)
#define RDES1_RCH (1u << 14)

/* PHY registers every IEEE 802.3 PHY has (clause 22) */
#define PHY_BCR 0
#define PHY_BSR 1
#define PHY_ANAR 4
#define PHY_ANLPAR 5
#define BCR_RESET 0x8000u
#define BCR_ANEG_ENABLE 0x1000u
#define BCR_ANEG_RESTART 0x0200u
#define BSR_ANEG_DONE 0x0020u
#define BSR_LINK 0x0004u
#define AN_100FD 0x0100u
#define AN_100HD 0x0080u
#define AN_10FD 0x0040u

#define CRC_LEN 4
#define SETTLE_SPINS 2000u    /* some µs at up to 180 MHz */
#define TIMEOUT_SPINS 5000000 /* about a second */

/* Descriptors and buffers are shared with the DMA: our writes to them
 * must be complete before the DMA is told to look */
static void dma_barrier(void) { __asm__ volatile("dmb" ::: "memory"); }

static void spin(uint32_t n) {
  volatile uint32_t i;
  for (i = 0; i < n; i++) {
  }
}

/* RM0090 §33.8.1 and ST's HAL: a MAC or DMA register written twice in a
 * row may miss the second write unless four TX_CLK/RX_CLK cycles pass
 * between, so a configuration write is read back and repeated after a
 * pause */
static void reg_write(volatile uint32_t *reg, uint32_t value) {
  *reg = value;
  (void)*reg;
  spin(SETTLE_SPINS);
  *reg = value;
}

static int wait_clear(volatile uint32_t *reg, uint32_t bits) {
  uint32_t n;
  for (n = 0; n < TIMEOUT_SPINS; n++) {
    if (!(*reg & bits))
      return 0;
  }
  return -1;
}

static uint16_t mdio_read(const stm32f4_eth_ctx_t *ctx, uint8_t reg) {
  MACMIIAR = (uint32_t)ctx->phy_addr << 11 | (uint32_t)reg << 6 |
             (uint32_t)ctx->mdc_div << 2 | MACMIIAR_MB;
  if (wait_clear(&MACMIIAR, MACMIIAR_MB) != 0)
    return 0;
  return (uint16_t)MACMIIDR;
}

static int mdio_write(const stm32f4_eth_ctx_t *ctx, uint8_t reg,
                      uint16_t value) {
  MACMIIDR = value;
  MACMIIAR = (uint32_t)ctx->phy_addr << 11 | (uint32_t)reg << 6 |
             (uint32_t)ctx->mdc_div << 2 | MACMIIAR_MW | MACMIIAR_MB;
  return wait_clear(&MACMIIAR, MACMIIAR_MB);
}

/* RM0090 §33.8.1: MDC at most 2.5 MHz, the divider chosen by HCLK range */
static uint8_t mdc_divider(uint32_t hclk_hz) {
  if (hclk_hz >= 150000000u)
    return 4; /* HCLK / 102 */
  if (hclk_hz >= 100000000u)
    return 1; /* / 62 */
  if (hclk_hz >= 60000000u)
    return 0; /* / 42 */
  if (hclk_hz >= 35000000u)
    return 3; /* / 26 */
  return 2;   /* / 16 */
}

void stm32f4_eth_ctx_init(stm32f4_eth_ctx_t *ctx, const uint8_t mac[6],
                          uint8_t phy_addr, uint32_t hclk_hz) {
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->mac, mac, 6);
  ctx->phy_addr = phy_addr;
  ctx->mdc_div = mdc_divider(hclk_hz);
}

/* Clocks on, RMII chosen while the MAC is held in reset, then the DMA's
 * own reset — which completes only with the PHY's 50 MHz REF_CLK */
static int peripheral_reset(void) {
  RCC_APB2ENR |= RCC_APB2_SYSCFG;
  (void)RCC_APB2ENR;
  RCC_AHB1RSTR |= RCC_AHB1_ETHMAC;
  SYSCFG_PMC |= SYSCFG_PMC_RMII;
  RCC_AHB1ENR |= RCC_AHB1_ETHMAC_ALL;
  (void)RCC_AHB1ENR;
  RCC_AHB1RSTR &= ~RCC_AHB1_ETHMAC;
  DMABMR |= DMABMR_SR;
  return wait_clear(&DMABMR, DMABMR_SR);
}

/* A PHY reset takes up to half a second (ST's HAL waits 255 ms); then
 * auto-negotiation, whose outcome stm32f4_eth_link_poll() picks up */
static int phy_start(const stm32f4_eth_ctx_t *ctx) {
  uint32_t n;
  if (mdio_write(ctx, PHY_BCR, BCR_RESET) != 0)
    return -1;
  for (n = 0; n < 10000u && (mdio_read(ctx, PHY_BCR) & BCR_RESET); n++)
    spin(SETTLE_SPINS);
  return mdio_write(ctx, PHY_BCR, BCR_ANEG_ENABLE | BCR_ANEG_RESTART);
}

/* MAC address register 0: bytes 0..3 in the low word, 4..5 in the high */
static void set_address(const uint8_t *mac) {
  reg_write(&MACA0HR, (uint32_t)mac[5] << 8 | mac[4]);
  reg_write(&MACA0LR, (uint32_t)mac[3] << 24 | (uint32_t)mac[2] << 16 |
                          (uint32_t)mac[1] << 8 | mac[0]);
}

/* Chained rings: every RX descriptor the DMA's, every TX one ours */
static void rings_init(stm32f4_eth_ctx_t *ctx) {
  uint8_t i;
  for (i = 0; i < STM32F4_ETH_RX_DESCS; i++) {
    stm32f4_eth_desc_t *d = &ctx->rx_desc[i];
    uint8_t next = (uint8_t)(i + 1u < STM32F4_ETH_RX_DESCS ? i + 1u : 0u);
    d->des1 = RDES1_RCH | STM32F4_ETH_BUF_SIZE;
    d->des2 = (uint32_t)(uintptr_t)ctx->rx_buf[i];
    d->des3 = (uint32_t)(uintptr_t)&ctx->rx_desc[next];
    d->des0 = RDES0_OWN;
  }
  for (i = 0; i < STM32F4_ETH_TX_DESCS; i++) {
    stm32f4_eth_desc_t *d = &ctx->tx_desc[i];
    uint8_t next = (uint8_t)(i + 1u < STM32F4_ETH_TX_DESCS ? i + 1u : 0u);
    d->des0 = TDES0_TCH;
    d->des1 = 0;
    d->des2 = (uint32_t)(uintptr_t)ctx->tx_buf[i];
    d->des3 = (uint32_t)(uintptr_t)&ctx->tx_desc[next];
  }
  ctx->rx_idx = ctx->tx_idx = 0;
  dma_barrier();
  DMARDLAR = (uint32_t)(uintptr_t)ctx->rx_desc;
  DMATDLAR = (uint32_t)(uintptr_t)ctx->tx_desc;
}

/* The MAC set to a speed and duplex (100 Mbit/s full until the PHY says),
 * its transmitter and receiver off meanwhile, as ST's HAL does on a link
 * change */
static void set_mode(int speed_100, int full_duplex) {
  uint32_t enabled = MACCR & (MACCR_TE | MACCR_RE);
  uint32_t v = (MACCR & MACCR_KEEP & ~enabled) | MACCR_RD;
  if (speed_100)
    v |= MACCR_FES;
  if (full_duplex)
    v |= MACCR_DM;
  reg_write(&MACCR, v);
  if (enabled)
    reg_write(&MACCR, v | enabled);
}

static int eth_init(void *vctx) {
  stm32f4_eth_ctx_t *ctx = (stm32f4_eth_ctx_t *)vctx;
  if (peripheral_reset() != 0)
    return -1; /* no REF_CLK: no PHY, or the RMII pins not set */
  MACMIIAR = (uint32_t)ctx->mdc_div << 2;
  if (phy_start(ctx) != 0)
    return -1;
  set_mode(1, 1);
  reg_write(&MACFFR, MACFFR_PAM);
  set_address(ctx->mac);
  rings_init(ctx);
  reg_write(&DMABMR, DMABMR_AAB | DMABMR_USP | DMABMR_RDP_32 | DMABMR_FB |
                         DMABMR_PBL_32);
  reg_write(&DMAOMR,
            (DMAOMR & DMAOMR_KEEP) | DMAOMR_RSF | DMAOMR_TSF | DMAOMR_OSF);
  /* start: the MAC's transmitter and receiver, then the DMA's */
  reg_write(&MACCR, MACCR | MACCR_TE);
  reg_write(&MACCR, MACCR | MACCR_RE);
  reg_write(&DMAOMR, DMAOMR | DMAOMR_FTF);
  reg_write(&DMAOMR, DMAOMR | DMAOMR_ST);
  reg_write(&DMAOMR, DMAOMR | DMAOMR_SR);
  ctx->link_up = 0;
  return 0;
}

int stm32f4_eth_link_poll(stm32f4_eth_ctx_t *ctx) {
  uint16_t bsr, common;
  int up;
  (void)mdio_read(ctx, PHY_BSR); /* the link bit latches low: read again */
  bsr = mdio_read(ctx, PHY_BSR);
  up = (bsr & BSR_LINK) && (bsr & BSR_ANEG_DONE);
  if (up && !ctx->link_up) {
    /* The best mode both ends advertised; none in common means the
     * partner does not negotiate, and parallel detection found 100
     * Mbit/s half duplex */
    common = (uint16_t)(mdio_read(ctx, PHY_ANAR) & mdio_read(ctx, PHY_ANLPAR));
    if (common & AN_100FD)
      set_mode(1, 1);
    else if (common & AN_100HD)
      set_mode(1, 0);
    else if (common & AN_10FD)
      set_mode(0, 1);
    else if (common)
      set_mode(0, 0);
    else
      set_mode(1, 0);
  }
  ctx->link_up = (uint8_t)up;
  return up;
}

static int eth_send(void *vctx, const uint8_t *frame, uint16_t len) {
  stm32f4_eth_ctx_t *ctx = (stm32f4_eth_ctx_t *)vctx;
  stm32f4_eth_desc_t *d = &ctx->tx_desc[ctx->tx_idx];
  if (len > STM32F4_ETH_BUF_SIZE - CRC_LEN)
    return -1;
  if (d->des0 & TDES0_OWN)
    return 0; /* busy: the DMA still has it */
  memcpy(ctx->tx_buf[ctx->tx_idx], frame, len);
  d->des1 = len & TDES1_TBS1;
  dma_barrier();
  d->des0 = TDES0_OWN | TDES0_FS | TDES0_LS | TDES0_TCH;
  dma_barrier();
  if (DMASR & DMASR_TBUS) /* the DMA had found the ring empty: wake it */
    DMASR = DMASR_TBUS;
  DMATPDR = 0;
  if (++ctx->tx_idx == STM32F4_ETH_TX_DESCS)
    ctx->tx_idx = 0;
  return (int)len;
}

/* The current RX descriptor back to the DMA, and the next one current */
static void rx_release(stm32f4_eth_ctx_t *ctx) {
  ctx->rx_desc[ctx->rx_idx].des0 = RDES0_OWN;
  dma_barrier();
  if (++ctx->rx_idx == STM32F4_ETH_RX_DESCS)
    ctx->rx_idx = 0;
  if (DMASR & DMASR_RBUS) { /* the DMA had run out of buffers: resume */
    DMASR = DMASR_RBUS;
    DMARPDR = 0;
  }
}

/* The current frame's length without its CRC, 0 if there is none */
static uint16_t rx_frame_len(const stm32f4_eth_ctx_t *ctx) {
  uint32_t s = ctx->rx_desc[ctx->rx_idx].des0;
  uint32_t len = (s >> RDES0_FL_SHIFT) & RDES0_FL;
  if (s & RDES0_OWN)
    return 0;
  return len > CRC_LEN ? (uint16_t)(len - CRC_LEN) : 0u;
}

/* A frame in one buffer (always: a buffer takes a whole frame) and without
 * errors becomes current; anything else goes back to the DMA */
static int eth_poll(void *vctx) {
  stm32f4_eth_ctx_t *ctx = (stm32f4_eth_ctx_t *)vctx;
  for (;;) {
    uint32_t s = ctx->rx_desc[ctx->rx_idx].des0;
    if (s & RDES0_OWN)
      return 0;
    if ((s & (RDES0_FS | RDES0_LS)) == (RDES0_FS | RDES0_LS) &&
        !(s & RDES0_ES) && rx_frame_len(ctx) > 0)
      return rx_frame_len(ctx);
    rx_release(ctx);
  }
}

static int eth_peek(void *vctx, uint16_t offset, uint8_t *buf, uint16_t len) {
  stm32f4_eth_ctx_t *ctx = (stm32f4_eth_ctx_t *)vctx;
  uint16_t frame_len = rx_frame_len(ctx);
  if (frame_len == 0)
    return -1;
  if (offset >= frame_len)
    return 0;
  if (len > frame_len - offset)
    len = (uint16_t)(frame_len - offset);
  memcpy(buf, (const uint8_t *)ctx->rx_buf[ctx->rx_idx] + offset, len);
  return (int)len;
}

static void eth_discard(void *vctx) {
  stm32f4_eth_ctx_t *ctx = (stm32f4_eth_ctx_t *)vctx;
  if (!(ctx->rx_desc[ctx->rx_idx].des0 & RDES0_OWN))
    rx_release(ctx);
}

static void eth_close(void *vctx) {
  (void)vctx;
  reg_write(&DMAOMR, DMAOMR & ~(DMAOMR_ST | DMAOMR_SR));
  reg_write(&MACCR, MACCR & ~(MACCR_TE | MACCR_RE));
}

const net_mac_t stm32f4_eth_ops = {
    .init = eth_init,
    .send = eth_send,
    .poll = eth_poll,
    .peek = eth_peek,
    .discard = eth_discard,
    .close = eth_close,
};
