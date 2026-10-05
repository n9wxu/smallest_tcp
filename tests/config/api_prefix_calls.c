/**
 * @file api_prefix_calls.c
 * @brief The application's own net_init() and net_poll(), called from a
 *        file that does not include the stack's headers.
 */

int net_init(void);
int net_poll(void);

int own_net_init(void) { return net_init(); }
int own_net_poll(void) { return net_poll(); }
