/**
 * @file driver/sam4e_gmac.c
 * @brief SAM4E MAC driver: the GMAC peripheral (SAM4E datasheet §41) with
 *        its DMA, MII to the PHY, the PHY's standard registers over MDIO.
 *
 * Polled, no interrupts.  Rings of descriptors, the last of each marked as
 * the wrap; each RX buffer takes a whole frame, so a frame is always in
 * one buffer.  Every checksum stays in software (no offload).  The PHY is
 * set to auto-negotiate, and sam4e_gmac_link_poll() gives the MAC the
 * result.
 */

#include "driver/sam4e_gmac.h"
#include <stdint.h>
#include <string.h>

#define REG(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

/* PMC: the peripheral's clock (identifier 44, in the second register) */
#define PMC_PCER1 REG(0x400E0500u)
#define PMC_PCDR1 REG(0x400E0504u)
#define PMC_PID_GMAC (1u << (44 - 32))

#define GMAC_BASE 0x40034000u
#define GMAC_NCR REG(GMAC_BASE + 0x000u)
#define GMAC_NCFGR REG(GMAC_BASE + 0x004u)
#define GMAC_NSR REG(GMAC_BASE + 0x008u)
#define GMAC_UR REG(GMAC_BASE + 0x00Cu)
#define GMAC_DCFGR REG(GMAC_BASE + 0x010u)
#define GMAC_TSR REG(GMAC_BASE + 0x014u)
#define GMAC_RBQB REG(GMAC_BASE + 0x018u)
#define GMAC_TBQB REG(GMAC_BASE + 0x01Cu)
#define GMAC_RSR REG(GMAC_BASE + 0x020u)
#define GMAC_ISR REG(GMAC_BASE + 0x024u)
#define GMAC_IDR REG(GMAC_BASE + 0x02Cu)
#define GMAC_MAN REG(GMAC_BASE + 0x034u)
#define GMAC_HRB REG(GMAC_BASE + 0x080u)
#define GMAC_HRT REG(GMAC_BASE + 0x084u)
#define GMAC_SAB1 REG(GMAC_BASE + 0x088u)
#define GMAC_SAT1 REG(GMAC_BASE + 0x08Cu)

#define NCR_RXEN (1u << 2)
#define NCR_TXEN (1u << 3)
#define NCR_MPE (1u << 4) /* the MDIO port */
#define NCR_CLRSTAT (1u << 5)
#define NCR_TSTART (1u << 9)
#define NCFGR_SPD (1u << 0)    /* 100 Mbit/s */
#define NCFGR_FD (1u << 1)     /* full duplex */
#define NCFGR_MTIHEN (1u << 6) /* multicast by the hash: all of it */
#define NCFGR_RFCS (1u << 17)  /* frames are stored without their CRC */
#define NCFGR_CLK_SHIFT 18
#define NSR_IDLE (1u << 2) /* the MDIO shift is done */
#define TSR_TXGO (1u << 3) /* the transmitter is at work */
#define UR_MII (1u << 0)
#define DCFGR_FBLDO_INCR4 4u
#define DCFGR_RXBMS_FULL (3u << 8)
#define DCFGR_TXPBMS (1u << 10)
#define DCFGR_DRBS_SHIFT 16 /* receive buffer size, in units of 64 bytes */
#define MAN_CLAUSE22 (1u << 30)
#define MAN_WRITE (1u << 28)
#define MAN_READ (2u << 28)
#define MAN_PHYA_SHIFT 23
#define MAN_REGA_SHIFT 18
#define MAN_WTN (2u << 16)
#define STATUS_ALL 0xFFFFFFFFu /* TSR, RSR: a bit is cleared by writing 1 */

/* Descriptor bits (datasheet §41.6.3: the receive and transmit buffer
 * descriptor entries) */
#define RX_OWN (1u << 0)  /* in the address word: a frame is in the buffer */
#define RX_WRAP (1u << 1) /* in the address word: the last descriptor */
#define RX_LEN 0x1FFFu
#define RX_SOF (1u << 14)
#define RX_EOF (1u << 15)
#define TX_LEN 0x3FFFu
#define TX_LAST (1u << 15)
#define TX_WRAP (1u << 30)
#define TX_USED (1u << 31) /* ours: the MAC has sent it, or never had it */

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

#define SETTLE_SPINS 2000u    /* some µs at up to 240 MHz */
#define TIMEOUT_SPINS 5000000 /* about a second */

/* Descriptors and buffers are shared with the DMA: our writes to them
 * must be complete before the DMA is told to look */
static void dma_barrier(void) { __asm__ volatile("dmb" ::: "memory"); }

static void spin(uint32_t n) {
  volatile uint32_t i;
  for (i = 0; i < n; i++) {
  }
}

static int mdio_wait(void) {
  uint32_t n;
  for (n = 0; n < TIMEOUT_SPINS; n++) {
    if (GMAC_NSR & NSR_IDLE)
      return 0;
  }
  return -1;
}

uint16_t sam4e_gmac_phy_read(uint8_t phy_addr, uint8_t reg) {
  GMAC_MAN = MAN_CLAUSE22 | MAN_READ | (uint32_t)phy_addr << MAN_PHYA_SHIFT |
             (uint32_t)reg << MAN_REGA_SHIFT | MAN_WTN;
  if (mdio_wait() != 0)
    return 0xFFFFu;
  return (uint16_t)GMAC_MAN;
}

static uint16_t mdio_read(const sam4e_gmac_ctx_t *ctx, uint8_t reg) {
  return sam4e_gmac_phy_read(ctx->phy_addr, reg);
}

static int mdio_write(const sam4e_gmac_ctx_t *ctx, uint8_t reg,
                      uint16_t value) {
  GMAC_MAN = MAN_CLAUSE22 | MAN_WRITE |
             (uint32_t)ctx->phy_addr << MAN_PHYA_SHIFT |
             (uint32_t)reg << MAN_REGA_SHIFT | MAN_WTN | value;
  return mdio_wait();
}

/* MDC at most 2.5 MHz: the divider's code for the range MCK is in */
static uint8_t mdc_divider(uint32_t mck_hz) {
  if (mck_hz > 160000000u)
    return 5; /* MCK / 96 */
  if (mck_hz > 120000000u)
    return 4; /* / 64 */
  if (mck_hz > 80000000u)
    return 3; /* / 48 */
  if (mck_hz > 40000000u)
    return 2; /* / 32 */
  if (mck_hz > 20000000u)
    return 1; /* / 16 */
  return 0;   /* / 8 */
}

void sam4e_gmac_ctx_init(sam4e_gmac_ctx_t *ctx, const uint8_t mac[6],
                         uint8_t phy_addr, uint32_t mck_hz) {
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->mac, mac, 6);
  ctx->phy_addr = phy_addr;
  ctx->mdc_div = mdc_divider(mck_hz);
}

/* A PHY reset takes up to half a second; then auto-negotiation, whose
 * outcome sam4e_gmac_link_poll() picks up */
static int phy_start(const sam4e_gmac_ctx_t *ctx) {
  uint32_t n;
  if (mdio_write(ctx, PHY_BCR, BCR_RESET) != 0)
    return -1;
  for (n = 0; n < 10000u && (mdio_read(ctx, PHY_BCR) & BCR_RESET); n++)
    spin(SETTLE_SPINS);
  return mdio_write(ctx, PHY_BCR, BCR_ANEG_ENABLE | BCR_ANEG_RESTART);
}

/* Specific address 1: bytes 0..3 in the bottom register, 4..5 in the top.
 * Writing the bottom disables the match and writing the top enables it. */
static void set_address(const uint8_t *mac) {
  GMAC_SAB1 = (uint32_t)mac[3] << 24 | (uint32_t)mac[2] << 16 |
              (uint32_t)mac[1] << 8 | mac[0];
  GMAC_SAT1 = (uint32_t)mac[5] << 8 | mac[4];
}

/* Every RX descriptor the MAC's, every TX one ours */
static void rings_init(sam4e_gmac_ctx_t *ctx) {
  uint8_t i;
  for (i = 0; i < SAM4E_GMAC_RX_DESCS; i++) {
    ctx->rx_desc[i].status = 0;
    ctx->rx_desc[i].addr = (uint32_t)(uintptr_t)ctx->rx_buf[i] |
                           (i + 1u == SAM4E_GMAC_RX_DESCS ? RX_WRAP : 0u);
  }
  for (i = 0; i < SAM4E_GMAC_TX_DESCS; i++) {
    ctx->tx_desc[i].addr = (uint32_t)(uintptr_t)ctx->tx_buf[i];
    ctx->tx_desc[i].status =
        TX_USED | (i + 1u == SAM4E_GMAC_TX_DESCS ? TX_WRAP : 0u);
  }
  ctx->rx_idx = ctx->tx_idx = 0;
  dma_barrier();
  GMAC_RBQB = (uint32_t)(uintptr_t)ctx->rx_desc;
  GMAC_TBQB = (uint32_t)(uintptr_t)ctx->tx_desc;
}

/* The MAC set to a speed and duplex (100 Mbit/s full until the PHY says) */
static void set_mode(int speed_100, int full_duplex) {
  uint32_t v = GMAC_NCFGR & ~(NCFGR_SPD | NCFGR_FD);
  if (speed_100)
    v |= NCFGR_SPD;
  if (full_duplex)
    v |= NCFGR_FD;
  GMAC_NCFGR = v;
}

static int gmac_init(void *vctx) {
  sam4e_gmac_ctx_t *ctx = (sam4e_gmac_ctx_t *)vctx;
  PMC_PCER1 = PMC_PID_GMAC;
  GMAC_NCR = 0; /* transmitter and receiver off, the queue pointers reset */
  GMAC_IDR = STATUS_ALL;
  (void)GMAC_ISR;
  GMAC_NCR = NCR_CLRSTAT;
  GMAC_TSR = STATUS_ALL;
  GMAC_RSR = STATUS_ALL;
  GMAC_UR = UR_MII;
  /* our address, broadcast and all multicast (every hash bit set): the
   * stack filters the rest */
  GMAC_NCFGR = (uint32_t)ctx->mdc_div << NCFGR_CLK_SHIFT | NCFGR_RFCS |
               NCFGR_MTIHEN | NCFGR_SPD | NCFGR_FD;
  GMAC_HRB = 0xFFFFFFFFu;
  GMAC_HRT = 0xFFFFFFFFu;
  GMAC_DCFGR = (uint32_t)(SAM4E_GMAC_BUF_SIZE / 64u) << DCFGR_DRBS_SHIFT |
               DCFGR_TXPBMS | DCFGR_RXBMS_FULL | DCFGR_FBLDO_INCR4;
  set_address(ctx->mac);
  rings_init(ctx);
  GMAC_NCR = NCR_MPE;
  if (phy_start(ctx) != 0)
    return -1; /* MDIO never idle: no clock to the peripheral */
  GMAC_NCR = NCR_MPE | NCR_RXEN | NCR_TXEN;
  ctx->link_up = 0;
  return 0;
}

int sam4e_gmac_link_poll(sam4e_gmac_ctx_t *ctx) {
  uint16_t bsr, common;
  int up;
  (void)mdio_read(ctx, PHY_BSR); /* the link bit latches low: read again */
  bsr = mdio_read(ctx, PHY_BSR);
  up = bsr != 0xFFFFu && (bsr & BSR_LINK) && (bsr & BSR_ANEG_DONE);
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

/* The MAC stops at a descriptor it finds used, and one given to it at
 * that moment — the second of two frames sent back to back, an ACK and
 * the data behind it — stays unsent, the start bit written while the
 * transmitter was still going having done nothing.  So whenever a frame
 * waits and the transmitter is idle, it is started again: from send() and
 * from poll(), which the main loop calls all the time. */
static void tx_kick(const sam4e_gmac_ctx_t *ctx) {
  uint8_t last =
      (uint8_t)(ctx->tx_idx ? ctx->tx_idx - 1u : SAM4E_GMAC_TX_DESCS - 1u);
  if (!(ctx->tx_desc[last].status & TX_USED) && !(GMAC_TSR & TSR_TXGO))
    GMAC_NCR |= NCR_TSTART;
}

/* The MAC pads a short frame and appends the CRC.  It stops at a
 * descriptor it has used and waits there, so the two rings stay in step
 * with tx_idx. */
static int gmac_send(void *vctx, const uint8_t *frame, uint16_t len) {
  sam4e_gmac_ctx_t *ctx = (sam4e_gmac_ctx_t *)vctx;
  sam4e_gmac_desc_t *d = &ctx->tx_desc[ctx->tx_idx];
  if (len == 0 || len > SAM4E_GMAC_BUF_SIZE)
    return -1;
  if (!(d->status & TX_USED)) {
    tx_kick(ctx);
    return 0; /* busy: the MAC still has it */
  }
  memcpy(ctx->tx_buf[ctx->tx_idx], frame, len);
  dma_barrier();
  d->status = (d->status & TX_WRAP) | TX_LAST | (len & TX_LEN);
  dma_barrier();
  GMAC_NCR |= NCR_TSTART;
  if (++ctx->tx_idx == SAM4E_GMAC_TX_DESCS)
    ctx->tx_idx = 0;
  return (int)len;
}

/* The current RX descriptor back to the MAC, and the next one current.
 * A MAC that had run out of buffers takes the next frame by itself. */
static void rx_release(sam4e_gmac_ctx_t *ctx) {
  ctx->rx_desc[ctx->rx_idx].addr &= ~RX_OWN;
  dma_barrier();
  if (++ctx->rx_idx == SAM4E_GMAC_RX_DESCS)
    ctx->rx_idx = 0;
  GMAC_RSR = STATUS_ALL;
}

/* The current frame's length (stored without its CRC), 0 if there is none */
static uint16_t rx_frame_len(const sam4e_gmac_ctx_t *ctx) {
  const sam4e_gmac_desc_t *d = &ctx->rx_desc[ctx->rx_idx];
  if (!(d->addr & RX_OWN))
    return 0;
  return (uint16_t)(d->status & RX_LEN);
}

/* A frame in one buffer (always: a buffer takes a whole frame) becomes
 * current; anything else goes back to the MAC, which stores no frame with
 * an error.  The MAC may finish a frame at any moment: the descriptor is
 * ours only once its address word says so, and its status is read after
 * that, not before. */
static int gmac_poll(void *vctx) {
  sam4e_gmac_ctx_t *ctx = (sam4e_gmac_ctx_t *)vctx;
  tx_kick(ctx);
  for (;;) {
    const sam4e_gmac_desc_t *d = &ctx->rx_desc[ctx->rx_idx];
    uint32_t status;
    if (!(d->addr & RX_OWN))
      return 0;
    status = d->status;
    if ((status & (RX_SOF | RX_EOF)) == (RX_SOF | RX_EOF) &&
        (status & RX_LEN) > 0 && (status & RX_LEN) <= SAM4E_GMAC_BUF_SIZE)
      return (int)(status & RX_LEN);
    rx_release(ctx);
  }
}

static int gmac_peek(void *vctx, uint16_t offset, uint8_t *buf, uint16_t len) {
  sam4e_gmac_ctx_t *ctx = (sam4e_gmac_ctx_t *)vctx;
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

static void gmac_discard(void *vctx) {
  sam4e_gmac_ctx_t *ctx = (sam4e_gmac_ctx_t *)vctx;
  if (ctx->rx_desc[ctx->rx_idx].addr & RX_OWN)
    rx_release(ctx);
}

static void gmac_close(void *vctx) {
  (void)vctx;
  GMAC_NCR = 0;
  PMC_PCDR1 = PMC_PID_GMAC;
}

const net_mac_t sam4e_gmac_ops = {
    .init = gmac_init,
    .send = gmac_send,
    .poll = gmac_poll,
    .peek = gmac_peek,
    .discard = gmac_discard,
    .close = gmac_close,
};
