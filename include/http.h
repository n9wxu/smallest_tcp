/**
 * @file http.h
 * @brief Minimal HTTP/1.0 server (RFC 9110 semantics, RFC 9112 syntax).
 *
 * GET, HEAD and POST against an application route table; every response
 * is sent with Connection: close.  The application owns all memory: one
 * http_conn_t per simultaneous connection, each with its TCP buffers and a
 * request buffer.  The server is driven from the main loop (see
 * docs/design/http.md):
 *
 *   http_conn_init(&conns[i], tx[i], sizeof tx[i], rx[i], sizeof rx[i],
 *                  req[i], sizeof req[i]);
 *   conn_table[i] = http_conn_tcp(&conns[i]);   // register with TCP
 *   http_server_init(&srv, &net, 80, routes, n_routes, conns, n_conns);
 *
 *   loop:  net_poll + eth_input;  http_server_poll(&srv);
 *          every ~10 ms: tcp_tick(&net, ms); http_server_tick(&srv, ms);
 */

#ifndef HTTP_H
#define HTTP_H

#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include <stdint.h>

/* ── Methods (bitmask, also used for route permissions) ───────────── */

#define HTTP_GET 0x01
#define HTTP_HEAD 0x02 /**< Allowed automatically on GET routes */
#define HTTP_POST 0x04

/* ── Tunables ─────────────────────────────────────────────────────── */

/** Largest response header block (formatted on the stack). */
#ifndef HTTP_HDR_MAX
#define HTTP_HDR_MAX 192
#endif
/** Time allowed to receive a complete request. */
#ifndef HTTP_REQUEST_TIMEOUT_MS
#define HTTP_REQUEST_TIMEOUT_MS 10000u
#endif
/** Time allowed to send the response and finish closing. */
#ifndef HTTP_RESPONSE_TIMEOUT_MS
#define HTTP_RESPONSE_TIMEOUT_MS 10000u
#endif

/* ── Handler API ──────────────────────────────────────────────────── */

typedef struct {
  uint8_t method;       /**< HTTP_GET, HTTP_HEAD or HTTP_POST */
  uint8_t version;      /**< 10 (HTTP/1.0) or 11 (HTTP/1.1) */
  const char *path;     /**< NUL-terminated, without the query */
  const char *query;    /**< Text after '?', or "" */
  const uint8_t *body;  /**< POST body (NULL if none) */
  uint16_t body_len;
  uint32_t remote_ip;   /**< Client IPv4, host byte order (0 over IPv6) */
#if NET_USE_IPV6
  const uint8_t *remote_ip6; /**< Client IPv6 address, NULL over IPv4 */
#endif
} http_request_t;

typedef struct {
  uint16_t status;          /**< Preset to 200 */
  const char *content_type; /**< Preset to "text/html" */
  const uint8_t *body;      /**< Must stay valid until the response is sent */
  uint32_t body_len;
  uint8_t *scratch;         /**< Free space for a generated body */
  uint16_t scratch_size;
} http_response_t;

/** @return 0 to send the response, < 0 to send 500 instead. */
typedef int (*http_handler_t)(const http_request_t *req,
                              http_response_t *resp, void *ctx);

typedef struct {
  const char *path;       /**< Exact path, e.g. "/api/status" */
  uint8_t methods;        /**< HTTP_GET and/or HTTP_POST */
  http_handler_t handler;
  void *ctx;
} http_route_t;

/* ── Parser / formatter (used by the server; public for testing) ──── */

#define HTTP_PARSE_OK 0

/**
 * Offset just past the blank line that ends the header block, or 0 if it
 * has not arrived yet.  CRLF and bare LF line endings are both accepted.
 */
uint16_t http_header_end(const char *buf, uint16_t len);

/**
 * Parse the request line and headers in place: path and query are
 * NUL-terminated inside @p buf.  @p hdr_len is http_header_end()'s result.
 * @param content_length  Out: Content-Length, 0 if absent.
 * @return HTTP_PARSE_OK, or the status to answer with (400, 501, 505).
 */
uint16_t http_parse_request(char *buf, uint16_t hdr_len, http_request_t *req,
                            uint32_t *content_length);

/** Reason phrase for @p status, or "" if unknown. */
const char *http_reason(uint16_t status);

/**
 * Format a response header block, ending with the blank line.
 * Content-Type and Content-Length are omitted for 204 and 304.
 * @param allow  Methods for an Allow header (405), 0 for none.
 * @return Length written, or 0 if it does not fit in @p cap.
 */
uint16_t http_format_header(char *out, uint16_t cap, uint16_t status,
                            const char *content_type, uint32_t content_length,
                            uint8_t allow);

/* ── Server ───────────────────────────────────────────────────────── */

/** One connection slot.  Initialise with http_conn_init(). */
typedef struct {
  tcp_conn_t tcp; /**< The slot's TCP connection (register it) */
  tcp_saw_tx_ctx_t tx_ctx;
  tcp_saw_rx_ctx_t rx_ctx;
  uint8_t *tx_mem;
  uint8_t *rx_mem;
  uint16_t tx_size;
  uint16_t rx_size;
  char *req;          /**< Request buffer */
  uint16_t req_size;
  uint16_t req_len;   /**< Bytes received so far */
  uint16_t hdr_len;   /**< End of the header block, 0 until complete */
  uint32_t content_length;
  http_request_t request; /**< Parsed request (valid once hdr_len != 0) */
  uint32_t timer_ms;
  uint8_t state;
  uint8_t head_only;  /**< HEAD: send the header block only */
  uint8_t allow;      /**< Allow header for 405 */
  uint16_t status;
  const char *content_type;
  const uint8_t *body;
  uint32_t body_len;
  uint16_t resp_hdr_len; /**< Length of the formatted response header */
  uint32_t sent;      /**< Header + body bytes accepted by TCP */
} http_conn_t;

typedef struct {
  net_t *net;
  uint16_t port;
  const http_route_t *routes;
  uint8_t n_routes;
  http_conn_t *conns;
  uint8_t n_conns;
} http_server_t;

/**
 * Prepare a slot: its TCP TX/RX buffers and its request buffer (which also
 * bounds the largest request line, header block and POST body).
 */
net_err_t http_conn_init(http_conn_t *c, uint8_t *tx_mem, uint16_t tx_size,
                         uint8_t *rx_mem, uint16_t rx_size, char *req_buf,
                         uint16_t req_size);

/** The slot's TCP connection, for the application's tcp_connections table. */
static inline tcp_conn_t *http_conn_tcp(http_conn_t *c) { return &c->tcp; }

/** Put every slot in LISTEN on @p port. */
net_err_t http_server_init(http_server_t *s, net_t *net, uint16_t port,
                           const http_route_t *routes, uint8_t n_routes,
                           http_conn_t *conns, uint8_t n_conns);

/** Read requests, run handlers, send responses, recycle closed slots. */
void http_server_poll(http_server_t *s);

/** Advance request/response timeouts. */
void http_server_tick(http_server_t *s, uint32_t elapsed_ms);

#endif /* HTTP_H */
