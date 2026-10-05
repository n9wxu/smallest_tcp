/**
 * @file api_prefix_own.c
 * @brief An application's own functions under names the stack also uses:
 *        this file includes none of the stack's headers, as the code of a
 *        project that had these names first.
 */

int own_calls;

int net_init(void) { return ++own_calls; }
int net_poll(void) { return ++own_calls; }
int tcp_write(const char *text) { return text ? ++own_calls : 0; }
int udp_send(void) { return ++own_calls; }
