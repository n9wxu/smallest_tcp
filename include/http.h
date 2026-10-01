/**
 * @file http.h
 * @brief Minimal HTTP/1.0 server (RFC 9110 semantics, RFC 9112 syntax).
 *
 * GET, HEAD and POST against an application route table; every response
 * is sent with Connection: close.  The application owns all memory: one
 * http_conn_t per simultaneous connection, each with its TCP buffers and a
 * request buffer; http_server_poll() and http_server_tick() run from the
 * main loop.  Over TLS too (http_tls.h).  See docs/design/http.md.
 */

#ifndef HTTP_H
#define HTTP_H

#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include <stdint.h>

/* Methods (bitmask, also used for route permissions) */
#define HTTP_GET 0x01
#define HTTP_HEAD 0x02 /**< Allowed automatically on GET routes */
#define HTTP_POST 0x04

/* Tunables */

/** Largest response header block (formatted on the stack). */
#ifndef HTTP_HDR_MAX
#define HTTP_HDR_MAX 224
#endif
/** Time allowed to receive a complete request. */
#ifndef HTTP_REQUEST_TIMEOUT_MS
#define HTTP_REQUEST_TIMEOUT_MS 10000u
#endif
/** Time allowed to send the response and finish closing. */
#ifndef HTTP_RESPONSE_TIMEOUT_MS
#define HTTP_RESPONSE_TIMEOUT_MS 10000u
#endif

/* What the header section asked for (http_request_t.flags) */
#define HTTP_RQ_HTTPS 0x01       /**< An https target in absolute-form */
#define HTTP_RQ_CONTINUE 0x02    /**< HTTP/1.1 with Expect: 100-continue */
#define HTTP_RQ_IF_MATCH 0x04    /**< If-Match with entity tags */
#define HTTP_RQ_IF_NONE_ANY 0x08 /**< If-None-Match: * */

/* Handler API */
typedef struct {
  uint8_t method;    /**< HTTP_GET, HTTP_HEAD or HTTP_POST */
  uint8_t version;   /**< 10 (HTTP/1.0) or 11 (HTTP/1.1) */
  uint8_t flags;     /**< HTTP_RQ_* */
  const char *path;  /**< NUL-terminated, without the query */
  const char *query; /**< Text after '?', or "" */
  /** The target's host, without the port and not NUL-terminated: from
   *  the absolute-form target, else from Host; NULL if neither */
  const char *host;
  uint16_t host_len;
  const uint8_t *body; /**< POST body (NULL if none) */
  uint16_t body_len;
#if NET_USE_IPV4
  uint32_t remote_ip; /**< Client IPv4, host byte order (0 over IPv6) */
#endif
#if NET_USE_IPV6
  const uint8_t *remote_ip6; /**< Client IPv6 address, NULL over IPv4 */
#endif
} http_request_t;

typedef struct {
  /** Preset to 200.  A final status, 200..599 — but not 206, 401 or 426,
   *  which need fields the server cannot add (Content-Range,
   *  WWW-Authenticate, Upgrade); a 1xx or any of those is answered with
   *  500 instead.  A 204, 205 or 304 is sent without content; a 405 with
   *  the route's methods in Allow. */
  uint16_t status;
  /** Preset to "text/html"; NULL for none.  A control character in it
   *  (CR, LF, ...) is answered with 500. */
  const char *content_type;
  const uint8_t *body;      /**< Must stay valid until the response is sent */
  uint32_t body_len;
  uint8_t *scratch; /**< Free space for a generated body */
  uint16_t scratch_size;
} http_response_t;

/** @return 0 to send the response, < 0 to send 500 instead. */
typedef int (*http_handler_t)(const http_request_t *req, http_response_t *resp,
                              void *ctx);

typedef struct {
  const char *path; /**< Exact path, e.g. "/api/status" */
  uint8_t methods;  /**< HTTP_GET and/or HTTP_POST */
  http_handler_t handler;
  void *ctx;
} http_route_t;

/* Parser / formatter (used by the server; public for testing) */
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
 * @return HTTP_PARSE_OK, or the status to answer with (400, 421, 501, 505).
 */
uint16_t http_parse_request(char *buf, uint16_t hdr_len, http_request_t *req,
                            uint32_t *content_length);

/** Reason phrase for @p status, or "" if unknown. */
const char *http_reason(uint16_t status);

/**
 * Format a response header block, ending with the blank line.
 * Content-Type and Content-Length are omitted for 204 and 304.
 * @param allow  Methods for an Allow header (405), 0 for none.
 * @param date   Seconds since 1970-01-01 UTC for a Date field, 0 for none.
 * @return Length written, or 0 if it does not fit in @p cap.
 */
uint16_t http_format_header(char *out, uint16_t cap, uint16_t status,
                            const char *content_type, uint32_t content_length,
                            uint8_t allow, uint32_t date);

/* Server */

struct http_conn_s;

/**
 * How a slot's bytes travel: plain TCP (the default) or TLS carried over
 * TCP (http_conn_use_tls(), http_tls.h).  The server keeps the TCP
 * connection itself; the transport moves the request and response.
 */
typedef struct {
  /** A client connected: start the stream (e.g. a TLS handshake). */
  void (*accepted)(net_t *net, struct http_conn_s *c);
  /** Request bytes, if any have arrived. */
  uint16_t (*read)(net_t *net, struct http_conn_s *c, uint8_t *buf,
                   uint16_t len);
  /** Queue response bytes; returns how many were taken. */
  uint16_t (*write)(struct http_conn_s *c, const uint8_t *data, uint16_t len);
  /** Send what was queued. */
  void (*flush)(net_t *net, struct http_conn_s *c);
  /** The response is complete: end the stream (e.g. close_notify). */
  void (*finish)(net_t *net, struct http_conn_s *c);
  /** The client can send nothing more. */
  int (*client_done)(const struct http_conn_s *c);
  /** Everything queued has reached the client. */
  int (*delivered)(struct http_conn_s *c);
  /** The client is gone — closed, reset or timed out — and the slot
   *  listens again: forget the stream (e.g. wipe TLS secrets).  May be
   *  NULL. */
  void (*release)(struct http_conn_s *c);
  /** 1: the stream is secured (TLS), so requests are for https
   *  resources (RFC 9110 §4.2.2); 0: plain, for http ones */
  uint8_t secure;
} http_transport_t;

/** One connection slot.  Initialise with http_conn_init(). */
typedef struct http_conn_s {
  tcp_conn_t tcp; /**< The slot's TCP connection (register it) */
  tcp_saw_tx_ctx_t tx_ctx;
  tcp_saw_rx_ctx_t rx_ctx;
  const http_transport_t *transport;
  void *transport_ctx; /**< E.g. the slot's tls_conn_t */
  char *req;           /**< Request buffer */
  uint16_t req_size;
  uint16_t req_len; /**< Bytes received so far */
  uint16_t hdr_len; /**< End of the header block, 0 until complete */
  uint32_t content_length;
  http_request_t request; /**< Parsed request (valid once hdr_len != 0) */
  uint32_t timer_ms;
  uint8_t state;
  uint8_t head_only; /**< HEAD: send the header block only */
  uint8_t allow;     /**< Allow header for 405 */
  uint16_t status;
  const char *content_type;
  const uint8_t *body;
  uint32_t body_len;
  uint16_t resp_hdr_len; /**< Length of the formatted response header */
  uint32_t sent;         /**< Header + body bytes the transport took */
  uint32_t date;         /**< The response's Date (s since 1970), 0: none */
} http_conn_t;

typedef struct {
  net_t *net;
  uint16_t port;
  const http_route_t *routes;
  uint8_t n_routes;
  http_conn_t *conns;
  uint8_t n_conns;

  /* Optional; http_server_init() clears them, set them after it. */

  /** The current time, in seconds since 1970-01-01 00:00:00 UTC, for the
   *  Date field (RFC 9110 §6.6.1); 0 while the time is not known.  NULL:
   *  the device has no clock, and responses carry no Date. */
  uint32_t (*clock)(void);
  /** Over TLS: the hosts the certificate is valid for — its DNS names and
   *  IP addresses, as a URI writes them (a.example, 192.0.2.1,
   *  [2001:db8::1]).  A request over TLS for any other host is refused
   *  with 421 (RFC 9110 §7.4).  NULL: hosts are not checked, which meets
   *  RFC 9110 §7.4 only if the certificate is valid for every name
   *  clients can use. */
  const char *const *https_hosts;
  uint8_t n_https_hosts;
} http_server_t;

/**
 * Prepare a slot: its TCP TX/RX buffers and its request buffer (which also
 * bounds the largest request line, header block and POST body).
 */
net_err_t http_conn_init(http_conn_t *c, uint8_t *tx_mem, uint16_t tx_size,
                         uint8_t *rx_mem, uint16_t rx_size, char *req_buf,
                         uint16_t req_size);

/** The slot's TCP connection, for tcp_set_connections(). */
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
