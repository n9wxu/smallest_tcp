/**
 * @file http_tls.h
 * @brief HTTPS: the HTTP server's slots carried over TLS 1.3.
 */

#ifndef HTTP_TLS_H
#define HTTP_TLS_H

#include "http.h"
#include "tls.h"

/**
 * Serve slot @p c over TLS: @p tls, set up with tls_init() and its
 * server configuration, is re-initialised for each client.
 */
void http_conn_use_tls(http_conn_t *c, tls_conn_t *tls);

#endif /* HTTP_TLS_H */
