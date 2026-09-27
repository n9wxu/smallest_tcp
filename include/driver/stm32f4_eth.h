/**
 * @file driver/stm32f4_eth.h
 * @brief STM32F4 MAC driver: the ETH peripheral's DMA over RMII, with the
 *        PHY on MDIO.
 *
 * The context holds the DMA descriptors and the frame buffers, so it must
 * live where the ETH DMA can reach it: SRAM, not the core-coupled RAM.
 * The board sets the system clock and the RMII pins before init(); the
 * driver brings up the peripheral and the PHY.  A DMA driver
 * (docs/design/mac-hal.md §6): poll() and peek() read the frame in the DMA
 * buffer, discard() hands the buffer back.
 */

#ifndef DRIVER_STM32F4_ETH_H
#define DRIVER_STM32F4_ETH_H

#include "net_mac.h"
#include <stdint.h>

#define STM32F4_ETH_RX_DESCS 4
#define STM32F4_ETH_TX_DESCS 2
/** A frame with a VLAN tag and its CRC, rounded to a word */
#define STM32F4_ETH_BUF_SIZE 1524

/** A DMA descriptor in the normal format (RM0090 §33.6.7, §33.6.8): status,
 *  buffer sizes, buffer, next descriptor. */
typedef struct {
  volatile uint32_t des0, des1, des2, des3;
} stm32f4_eth_desc_t;

/** The driver's state, owned by the application (in SRAM, see above). */
typedef struct {
  uint8_t mac[6];   /**< Our address, for the MAC's address filter */
  uint8_t phy_addr; /**< The PHY's MDIO address (0 on Nucleo-144 boards) */
  uint8_t mdc_div;  /**< MDIO clock range, from HCLK */
  uint8_t link_up;
  uint8_t rx_idx, tx_idx;
  stm32f4_eth_desc_t rx_desc[STM32F4_ETH_RX_DESCS];
  stm32f4_eth_desc_t tx_desc[STM32F4_ETH_TX_DESCS];
  uint32_t rx_buf[STM32F4_ETH_RX_DESCS][STM32F4_ETH_BUF_SIZE / 4];
  uint32_t tx_buf[STM32F4_ETH_TX_DESCS][STM32F4_ETH_BUF_SIZE / 4];
} stm32f4_eth_ctx_t;

extern const net_mac_t stm32f4_eth_ops;

/**
 * Prepare the context: our MAC address (e.g. net->mac after net_init()),
 * the PHY's MDIO address, and HCLK in Hz (20 to 180 MHz), from which the
 * MDIO clock is divided.
 */
void stm32f4_eth_ctx_init(stm32f4_eth_ctx_t *ctx, const uint8_t mac[6],
                          uint8_t phy_addr, uint32_t hclk_hz);

/**
 * Check the link — every half second or so from the main loop.  When it
 * comes up, the MAC takes the speed and duplex the PHY negotiated.
 * @return 1 while the link is up.
 */
int stm32f4_eth_link_poll(stm32f4_eth_ctx_t *ctx);

#endif /* DRIVER_STM32F4_ETH_H */
