/**
 * @file api_prefix_app.c
 * @brief The stack built with NET_API_PREFIX=stcp_ linked into a program
 *        that has a net_init(), net_poll(), tcp_write() and udp_send() of
 *        its own (api_prefix_own.c): both sets exist, and each call
 *        reaches its own.  Exits 0 if so.
 */

#include "driver/stub.h"
#include "net.h"

/* The stack's functions by the names the linker has for them: declared
 * here, a missing one fails the link */
net_err_t stcp_net_init(net_t *net, uint8_t *rx_buf, uint16_t rx_size,
                        uint8_t *tx_buf, uint16_t tx_size, const uint8_t mac[6],
                        const net_mac_t *mac_driver, void *mac_ctx);
int stcp_net_poll(net_t *net);

/* The application's, called from a file that includes the stack's headers:
 * there the plain names are the stack's, so its own go by another name */
int own_net_init(void);
int own_net_poll(void);
extern int own_calls;

static net_t net;
static uint8_t rx[600], tx[600];

int main(void) {
  /* through the headers, the plain name is the stack's */
  if (net_init(&net, rx, sizeof(rx), tx, sizeof(tx), 0, &stub_mac_ops, 0) !=
      NET_OK)
    return 1;
  if (stcp_net_init(&net, rx, sizeof(rx), tx, sizeof(tx), 0, &stub_mac_ops,
                    0) != NET_OK)
    return 2;
  if (stcp_net_poll(&net) != 0)
    return 3;
  if (own_calls != 0)
    return 4;
  if (own_net_init() != 1 || own_net_poll() != 2)
    return 5;
  return 0;
}
