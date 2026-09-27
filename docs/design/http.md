# HTTP Server — Design

**Protocol:** HTTP/1.0 server semantics (RFC 9110, RFC 9112)  
**Files:** `include/http.h`, `src/http.c` (parser, formatter, server, the TCP transport); `include/http_tls.h`, `src/http_tls.c` (the TLS transport)  
**Requirements:** [docs/requirements/http.md](../requirements/http.md) (REQ-HTTP-001..041 implemented; 042, 043 — chunked coding, MAY — not)  
**Status:** implemented (Milestone 11; over TLS since Milestone 13)  
**Last updated:** 2026-09-27

---

## 1. Motivation

A device page at `http://pyro-dead01.local/` — status readouts, configuration
forms, a JSON API — is the most convenient user interface a network device
can offer.  mDNS + DNS-SD makes the device discoverable
([mdns.md](mdns.md)); this server serves the page, over plain TCP or over
TLS 1.3 ([tls.md](tls.md)).

---

## 2. Scope

| Feature | Implemented | Not yet |
|---|---|---|
| GET, HEAD (automatic for GET routes), POST | ✅ | |
| Exact-path route table, query string passed to the handler | ✅ | |
| Content-Length request bodies (POST) up to the request buffer | ✅ | |
| Static and generated responses of any length (streamed) | ✅ | |
| `Connection: close` after every response (HTTP/1.0 semantics) | ✅ | |
| Several simultaneous connections (one slot each) | ✅ | |
| IPv4 and IPv6 clients | ✅ | |
| HTTPS: any slot over TLS 1.3 (`http_conn_use_tls()`) | ✅ | |
| Persistent connections (keep-alive), pipelining | | ✅ |
| Chunked transfer coding (requests or responses) | | ✅ |
| Percent-decoding, path parameters | | ✅ |

The server answers `HTTP/1.0`.  A server may answer a 1.1 request with a 1.0
response (RFC 9110 §2.5), and claiming 1.1 would oblige it to accept chunked
request bodies.

---

## 3. Memory

Everything is application-owned.  One `http_conn_t` is one connection slot:
it embeds its `tcp_conn_t` and the contexts of its stop-and-wait TCP buffers,
and points at a **request buffer** that holds the request line, the headers
and any POST body.

```c
#define SLOTS 2
static uint8_t tx[SLOTS][600], rx[SLOTS][600];  /* each slot's TCP buffers */
static char req[SLOTS][512];                    /* each slot's request buffer */
static http_conn_t conns[SLOTS];
static tcp_conn_t *conn_table[SLOTS];
static const http_route_t routes[] = {
    {"/",            HTTP_GET,  page_index,  NULL},
    {"/api/status",  HTTP_GET,  api_status,  NULL},
    {"/api/config",  HTTP_POST, api_config,  NULL},
};
static http_server_t http;

for (i = 0; i < SLOTS; i++) {
  http_conn_init(&conns[i], tx[i], sizeof tx[i], rx[i], sizeof rx[i],
                 req[i], sizeof req[i]);
  conn_table[i] = http_conn_tcp(&conns[i]);
}
tcp_set_connections(&net, conn_table, SLOTS);  /* the table may hold other connections too */
http_server_init(&http, &net, 80, routes, 3, conns, SLOTS);  /* every slot listens */
```

The stack keeps no connection table of its own: `tcp_set_connections()`
binds the application's array of `tcp_conn_t` pointers to `net`
([tcp.md §2.2](tcp.md#22-binding-connections)).  All slots listen on the
same port, and each SYN takes the first free listener in table order; a SYN
that finds none is refused with RST.

| | Cortex-M0 |
|---|---:|
| `http_conn_t` | 200 B (224 dual stack) |
| `http_server_t` | 24 B |

plus each slot's TCP buffers and request buffer (and, for HTTPS, a
`tls_conn_t` with its record buffers, section 7.2).  The request buffer
bounds the largest request line, header block and POST body; what is left
of it after the request is the handler's scratch space.  `http_conn_init()`
requires at least 32 bytes.

---

## 4. Handler API

```c
typedef struct {
  uint8_t method;          /* HTTP_GET / HTTP_HEAD / HTTP_POST */
  uint8_t version;         /* 10 or 11 */
  const char *path;        /* "/api/status" — NUL-terminated, no query */
  const char *query;       /* "a=1&b=2" or "" */
  const uint8_t *body;     /* POST body (in the request buffer), NULL if none */
  uint16_t body_len;
  uint32_t remote_ip;      /* client IPv4, host order (0 over IPv6) */
  const uint8_t *remote_ip6; /* NET_USE_IPV6 only: client IPv6, NULL over IPv4 */
} http_request_t;

typedef struct {
  uint16_t status;           /* preset 200 */
  const char *content_type;  /* preset "text/html" */
  const uint8_t *body;       /* must stay valid until the response is sent */
  uint32_t body_len;
  uint8_t *scratch;          /* free space in this slot's request buffer */
  uint16_t scratch_size;
} http_response_t;

typedef int (*http_handler_t)(const http_request_t *req,
                              http_response_t *resp, void *ctx);
```

- Constant pages point `body` at flash; nothing is copied until the
  transport takes it.
- Generated pages can be written into `scratch` (the unused tail of the
  request buffer, after the request), then pointed to by `body`.  Nothing
  else touches it until the response is done.
- A handler returning < 0 produces **500**.
- A HEAD request calls the GET handler and sends only the headers, with the
  same Content-Length (RFC 9110 §9.3.2).

---

## 5. Request handling

```
bytes arrive (transport read → request buffer)
  └─ header end found? ("\r\n\r\n", bare "\n\n" also accepted, RFC 9112 §2.2)
       no  → buffer full? → 414 (no line end yet) / 431 (in the headers)
             client can send no more? → end the stream without an answer
       yes → parse (in place, NUL-terminating path and query)
              └─ Content-Length body complete?  no → keep reading (or end the
                                                     stream if the client is done)
                                                  too big for the buffer → 413
                 → route lookup → handler → response
```

| Condition | Status |
|---|---|
| Request line not `METHOD SP target SP HTTP/x.y`, header line without `:`, obsolete line folding, bad or conflicting Content-Length | 400 |
| HTTP/1.1 request without `Host` (RFC 9112 §3.2) | 400 |
| Method other than GET, HEAD, POST (RFC 9110 §15.6.2) | 501 |
| `Transfer-Encoding` in the request (chunked not supported) | 501 |
| Version other than HTTP/1.0 or HTTP/1.1 | 505 |
| Path not in the route table | 404 |
| Path known, method not allowed for it (with `Allow:`) | 405 |
| Body larger than the request buffer | 413 |
| Request line longer than the request buffer | 414 |
| Headers larger than the request buffer (RFC 6585) | 431 |
| Handler returned < 0, or the response header does not fit `HTTP_HDR_MAX` | 500 |

RFC 9110 reserves 405 for a method the *resource* does not allow and uses 501
for methods the server does not implement; 431 is the status for headers too
large.

Absolute-form targets (`GET http://host/path`) are reduced to their path.
Paths are compared exactly (no percent-decoding).  Headers other than
Content-Length, Transfer-Encoding and Host are ignored.

---

## 6. Response sending

```
HTTP/1.0 200 OK\r\n
Content-Type: text/html\r\n
Content-Length: 1234\r\n
Connection: close\r\n
\r\n
<body>
```

The header is formatted into a buffer on the C stack (`HTTP_HDR_MAX`, 192
bytes) without `printf` or division; it is formatted again on each send
call rather than kept, and only its unsent part is written.  Header and body
go to the transport's `write()` in as large pieces as it takes, then
`flush()` sends them — over TCP, `tcp_write()` fills the TCP transmit buffer
and `tcp_output()` sends it as one segment, so a small response is one
segment.  Each later poll that finds room writes the next part of the body.
The response is streamed straight from the handler's `body` pointer, so it
can be much larger than any buffer.  Error responses carry the reason phrase
as a `text/plain` body.  Content-Type and Content-Length are omitted for 204
and 304.

---

## 7. Transports

The server keeps each slot's TCP connection itself — it listens, watches the
TCP state, closes and recycles — and reaches the byte stream through the
slot's transport:

```c
typedef struct {
  void (*accepted)(net_t *net, struct http_conn_s *c);    /* a client connected */
  uint16_t (*read)(net_t *net, struct http_conn_s *c, uint8_t *buf, uint16_t len);
  uint16_t (*write)(struct http_conn_s *c, const uint8_t *data, uint16_t len);
  void (*flush)(net_t *net, struct http_conn_s *c);       /* send what was queued */
  void (*finish)(net_t *net, struct http_conn_s *c);      /* the response is complete */
  int (*client_done)(const struct http_conn_s *c);        /* the client can send no more */
  int (*delivered)(struct http_conn_s *c);                /* everything queued reached the client */
} http_transport_t;
```

`http_conn_init()` sets the plain TCP transport; `http_conn_use_tls(c, tls)`
switches a slot to TLS.  `http_conn_t.transport_ctx` is the transport's own
state (the slot's `tls_conn_t`).

### 7.1 TCP (`http.c`)

| Operation | Does |
|---|---|
| `accepted` | Nothing |
| `read` | `tcp_recv()`; when it returns less than asked (the RX buffer is empty), `tcp_window_update()` advertises the freed window |
| `write` | `tcp_write()` into the TCP transmit buffer |
| `flush` | `tcp_output()` |
| `finish` | Nothing: the FIN ends an HTTP/1.0 response |
| `client_done` | TCP is in CLOSE-WAIT (the client's FIN arrived) |
| `delivered` | `tcp_tx_idle()`: everything written has been sent and acknowledged |

### 7.2 TLS (`http_tls.c`)

`http_conn_use_tls(c, tls)` takes a `tls_conn_t` already set up with
`tls_init()`, its server configuration and its record buffers; the transport
re-initialises it for each client with the same configuration and buffers.

| Operation | Does |
|---|---|
| `accepted` | `tls_init()` again, then `tls_accept()` |
| `read` | `tls_tcp_carry()` (ciphertext both ways; this is also what runs the handshake), then `tls_read()` |
| `write` | `tls_write()`: one record per call, 0 while the TLS transmit buffer is full |
| `flush` | `tls_tcp_carry()` |
| `finish` | `tls_close()` (close_notify), then `tls_tcp_carry()` |
| `client_done` | TCP in CLOSE-WAIT, or the TLS connection `CLOSED` (the client's close_notify) or in `ERROR` |
| `delivered` | `tls_tcp_idle()`: no TLS records pending and TCP idle |

The TLS handshake happens while the slot is in `S_RECV` (section 8), so it
counts against the request timeout.  A failed handshake makes `client_done`
true, and the slot ends the stream — the alert goes out — and closes.

An HTTPS slot needs a `tls_conn_t` (440 B on Cortex-M0) and TLS receive and
transmit buffers sized as in [tls.md §5.2](tls.md#52-sizing), besides its
TCP buffers.  The HTTPS demo (`demo/https_demo/main.c`) serves one slot on
port 443 with a 1,460-byte TCP TX buffer, a 4,096-byte TCP RX buffer, a
2,048-byte request buffer, and TLS buffers of 17,157 (rx) and 4,096 (tx)
bytes.  CMake: link `smallest_tcp::https` (which brings `::http` and
`::tls_tcp`) and a crypto backend such as `::tls_mbedtls`.

---

## 8. Connection lifecycle

`http_server_poll()` drives every slot from the main loop.  TCP event
callbacks must not call back into TCP, so the server polls each slot's TCP
state instead of using callbacks.

| State | Meaning | Leaves when |
|---|---|---|
| `S_LISTEN` | TCP listening or in its handshake | TCP reaches ESTABLISHED (or CLOSE-WAIT): the transport's `accepted()` runs, the request timer starts, and the slot goes straight on to `S_RECV` in the same poll.  A handshake that ends in CLOSED (e.g. a RST) re-arms the listener |
| `S_RECV` | Reading the request into the request buffer | A complete request (or an error) is answered: `S_SEND`.  If the client can send no more before the request is complete: the stream is ended (`S_FINISHING`) without an answer |
| `S_SEND` | Streaming the response; anything more the client sends is read and discarded | All of it is written and `delivered()`: `end_stream()` |
| `S_FINISHING` | `end_stream()` has called the transport's `finish()` (TLS: close_notify); still discarding input | `close_when_delivered()`: once `delivered()`, `tcp_close()` sends our FIN → `S_CLOSING` |
| `S_CLOSING` | Our FIN sent; waiting for the close to complete, still discarding input | TCP reaches TIME-WAIT, CLOSING or CLOSED: the slot is recycled |

In every state but `S_LISTEN` and `S_CLOSING`, a TCP connection that is no
longer ESTABLISHED or CLOSE-WAIT (a RST, an unexpected close) recycles the
slot at once.  Recycling (`slot_listen()`) re-initialises the slot's TCP
buffers and connection and listens again.

**Why `delivered()` gates the FIN.**  `tcp_close()` queues the FIN behind the
data in the TCP transmit buffer ([tcp.md §4.7](tcp.md#47-closing)), but not
behind data the transport has yet to write into it: over TLS, records and
the close_notify can still be waiting in TLS's own buffer.  So the server
closes only when the transport reports that everything, the close_notify
included, has been sent and acknowledged.  For plain TCP the wait is longer
than the FIN needs, since `tcp_close()` would queue it, but one rule serves
both transports.

**Recycling out of TIME-WAIT.**  An HTTP/1.0 server closes first, which
leaves its TCP side in TIME-WAIT for 2×MSL = 240 s.  With one or two slots
that would make the device unreachable for minutes after each page.  Once
the slot reaches TIME-WAIT, both FINs have been exchanged and ours has been
acknowledged, so the server re-initialises it and listens again at once.
The only cost: if our final ACK is lost, the client's retransmitted FIN
meets a listener and draws a RST.  The response has already been delivered,
so that is harmless.  Small embedded stacks commonly make this trade.

**Simultaneous close.**  Clients such as curl close as soon as they have the
body, so their FIN usually crosses ours and TCP lands in CLOSING rather than
FIN-WAIT-2 → TIME-WAIT.  Both sides have closed and the response was
acknowledged, so CLOSING is recycled at once too.

**Lingering close** (RFC 9112 §9.6).  After a response — especially an error
for an oversized request — the client may still be sending.  In `S_SEND`,
`S_FINISHING` and `S_CLOSING` the server keeps reading and discarding, and
the TCP transport's `read()` advertises the freed window, so a client that
saw a zero window can finish sending and close.  Without it a 414 left the
slot stuck until the timeout.

**Timeouts** (`http_server_tick()`): a half-open TCP handshake
(SYN-RECEIVED) has `HTTP_REQUEST_TIMEOUT_MS` (10 s) to complete; an accepted
connection then has `HTTP_REQUEST_TIMEOUT_MS` again to deliver a complete
request — over TLS, the TLS handshake included — and
`HTTP_RESPONSE_TIMEOUT_MS` (10 s) for each of sending the response, ending
the stream and completing the close.  An expired slot is aborted (RST) and
recycled.  Without them one idle client could hold the only slot forever.
An idle listener's timer does not run.

---

## 9. Main loop

```c
for (;;) {
  uint32_t now = board_millis(), elapsed = now - last;
  while (net_poll(&net) > 0) {          /* receive and dispatch every waiting frame */
  }
  http_server_poll(&http);              /* read requests, run handlers, send, recycle */
  if (elapsed >= 10) {
    last = now;
    net_tick(&net, elapsed);            /* TCP timers */
    http_server_tick(&http, elapsed);   /* request and response timeouts */
  }
}
```

`net_poll()` reads one frame into `net->rx.buf`, dispatches it and releases
it ([mac-hal.md §3](mac-hal.md#3-the-receive-lifecycle-net_poll));
`net_tick()` runs the TCP timers of every connection in the
`tcp_set_connections()` table ([timer-model.md](timer-model.md)).
`http_server_tick()` runs only the server's own time-outs.  See
[integrating-modules.md](../integrating-modules.md) for the server added to a
complete program.

---

## 10. Tests

- **Unit, parser and formatter** (`test_http.c`, 22): header end, request
  line, versions, methods, absolute-form, query split, headers
  (Content-Length, Host, Transfer-Encoding), LF-only lines, leading empty
  lines, every error status, reason phrases, header formatting (Allow, 204).
- **Unit, server** (`test_http.c`, 23): a simulated client drives the real
  TCP stack with injected segments: GET/HEAD/POST, 404/405/501/400/413/414/431/500,
  responses larger than the TX buffer, requests arriving in pieces, the
  header and first body bytes in one segment, a half-closed request, slot
  recycling from TIME-WAIT and CLOSING (simultaneous close), draining after
  an error, timeouts, RST mid-request, two slots at once, init checks.
- **Blackbox** (`tests/blackbox/test_http_conform.py`, 22): the host kernel is
  the client (Python `http.client` and raw sockets) against `http_demo` over
  TAP, the raw-socket driver or feth: every status above, large responses,
  trickled requests, 30 back-to-back requests (no TIME-WAIT stall),
  concurrent connections, idle-client timeout, a GET over IPv6.
- **HTTPS** (`tests/blackbox/test_https_conform.py`, 9): Python and curl
  against `https_demo`: pages, a 20,000-byte response (many records and
  segments), HEAD, 404, 405, the certificate's IP address name without SNI,
  sequential connections.
- **Interop**: `http_interop.sh` (Avahi + nss-mdns + curl, in CI) and
  `http_interop_macos.sh` (`dns-sd` + curl) fetch `http://pyro-dead01.local/`
  by name — `http_demo` also advertises `_http._tcp` — and bound the lookup
  time.

---

## 11. Files

```
include/http.h, src/http.c           parser, formatter, server, TCP transport
include/http_tls.h, src/http_tls.c   TLS transport (http_conn_use_tls)
demo/http_demo/main.c                pages, JSON API, POST echo, advertised over mDNS
demo/https_demo/main.c               the same server over TLS 1.3 on port 443
tests/unit/test_http.c
tests/blackbox/test_http_conform.py, test_https_conform.py
```
