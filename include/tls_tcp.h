/**
 * @file tls_tcp.h
 * @brief A TLS connection carried over one of the stack's TCP connections.
 */

#ifndef TLS_TCP_H
#define TLS_TCP_H

#include "tcp.h"
#include "tls.h"

/**
 * Move ciphertext both ways: what TCP received into the TLS receive
 * buffer (advertising the freed window), what TLS has to send into the
 * TCP transmit buffer, then transmit.  Call it whenever either side may
 * have progressed — after net_poll(), and after tls_write().
 */
void tls_tcp_carry(net_t *net, tcp_conn_t *tcp, tls_conn_t *tls);

/** Everything TLS produced has been sent and acknowledged. */
int tls_tcp_idle(const tcp_conn_t *tcp, tls_conn_t *tls);

#endif /* TLS_TCP_H */
