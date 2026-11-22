/**
 * @file driver/sam4e_gmac.h
 * @brief SAM4E MAC driver: the GMAC peripheral's DMA over MII, with the
 *        PHY on MDIO.
 *
 * The context holds the DMA descriptors and the frame buffers.  The board
 * sets the master clock and the MII pins before init(); the driver enables
 * the peripheral's clock and brings up the peripheral and the PHY.  A DMA
 * driver (docs/design/mac-hal.md §6): poll() and peek() read the frame in
 * the DMA buffer, discard() hands the buffer back.
 */

#ifndef DRIVER_SAM4E_GMAC_H
#define DRIVER_SAM4E_GMAC_H

#include "net_rename.h" /* NET_API_PREFIX */

#include "net_mac.h"
#include <stdint.h>

#define SAM4E_GMAC_RX_DESCS 4
#define SAM4E_GMAC_TX_DESCS 2
/** A frame with a VLAN tag and its CRC, in the 64-byte units the GMAC
 *  counts receive buffers in */
#define SAM4E_GMAC_BUF_SIZE 1536

/** A DMA descriptor: the buffer's address (with the receive side's flags
 *  in its low bits), then status and control. */
typedef struct {
  volatile uint32_t addr, status;
} sam4e_gmac_desc_t;

/** The driver's state, owned by the application. */
typedef struct {
  uint8_t mac[6];   /**< Our address, for the MAC's address filter */
  uint8_t phy_addr; /**< The PHY's MDIO address */
  uint8_t mdc_div;  /**< MDIO clock divider, from MCK */
  uint8_t link_up;
  uint8_t rx_idx, tx_idx;
  sam4e_gmac_desc_t rx_desc[SAM4E_GMAC_RX_DESCS];
  sam4e_gmac_desc_t tx_desc[SAM4E_GMAC_TX_DESCS];
  uint32_t rx_buf[SAM4E_GMAC_RX_DESCS][SAM4E_GMAC_BUF_SIZE / 4];
  uint32_t tx_buf[SAM4E_GMAC_TX_DESCS][SAM4E_GMAC_BUF_SIZE / 4];
} sam4e_gmac_ctx_t;

extern const net_mac_t sam4e_gmac_ops;

/**
 * Prepare the context: our MAC address (e.g. net->mac after net_init()),
 * the PHY's MDIO address, and the master clock in Hz (up to 240 MHz), from
 * which the MDIO clock is divided.
 */
void sam4e_gmac_ctx_init(sam4e_gmac_ctx_t *ctx, const uint8_t mac[6],
                         uint8_t phy_addr, uint32_t mck_hz);

/**
 * Check the link — every half second or so from the main loop.  When it
 * comes up, the MAC takes the speed and duplex the PHY negotiated.
 * @return 1 while the link is up.
 */
int sam4e_gmac_link_poll(sam4e_gmac_ctx_t *ctx);

/**
 * Read register @p reg of the PHY at MDIO address @p phy_addr, after
 * init(): for a board that looks for its PHY.
 * @return The register, or 0xFFFF where no PHY answers.
 */
uint16_t sam4e_gmac_phy_read(uint8_t phy_addr, uint8_t reg);

#endif /* DRIVER_SAM4E_GMAC_H */
