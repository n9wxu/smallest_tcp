# HTTP Server Design

**Protocol:** HTTP/1.0 server semantics (RFC 9110, RFC 9112)  
**Milestone:** 11  
**Status:** In progress  
**Last updated:** 2026-09-26

---

## 1. Motivation

A device page at `http://pyro-dead01.local/` — status readouts, configuration forms, a JSON API — is the most convenient user interface a network device can offer.  Milestone 10 made the device discoverable (mDNS + DNS-SD); this milestone serves the page.

---

## 2. Scope for V1

| Feature | V1 | Later |
|---|---|---|
| GET, HEAD (automatic for GET routes), POST | ✅ | |
| Exact-path route table, query string passed to the handler | ✅ | |
| Content-Length request bodies (POST) up to the request buffer | ✅ | |
| Static and generated responses of any length (streamed over TCP) | ✅ | |
| `Connection: close` after every response (HTTP/1.0 semantics) | ✅ | |
| Several simultaneous connections (one slot each) | ✅ | |
| Persistent connections (keep-alive), pipelining | | ✅ |
| Chunked transfer coding (requests or responses) | | ✅ |
| Percent-decoding, path parameters, TLS | | ✅ |

The server answers `HTTP/1.0`.  A server may answer a 1.1 request with a 1.0 response (RFC 9110 §2.5), and claiming 1.1 would oblige it to accept chunked request bodies.

---

## 3. Memory Model

Everything is application-owned.  One `http_conn_t` is one connection slot:

```c
static uint8_t tx[2][600], rx[2][600], req[2][512];
static http_conn_t conns[2];
static const http_route_t routes[] = {
    {"/",            HTTP_GET,  page_index,  NULL},
    {"/api/status",  HTTP_GET,  api_status,  NULL},
    {"/api/config",  HTTP_POST, api_config,  NULL},
};
static http_server_t http;

for (i = 0; i < 2; i++) {
  http_conn_init(&conns[i], tx[i], sizeof tx[i], rx[i], sizeof rx[i],
                 req[i], sizeof req[i]);
  conn_table[i] = http_conn_tcp(&conns[i]);   /* register with the TCP layer */
}
tcp_connections.conns = conn_table;
tcp_connections.count = 2;
http_server_init(&http, &net, 80, routes, 3, conns, 2);   /* all slots LISTEN */
```

Per slot: the TCP TX and RX buffers (stop-and-wait), plus a **request buffer** that holds the request line, headers and any POST body.  With several slots listening on the same port, each new SYN takes the first free listener (`tcp_find_conn()` already works this way).

---

## 4. Handler API

```c
typedef struct {
  uint8_t method;          /* HTTP_GET / HTTP_HEAD / HTTP_POST */
  uint8_t version;         /* 10 or 11 */
  const char *path;        /* "/api/status" — NUL-terminated, no query */
  const char *query;       /* "a=1&b=2" or "" */
  const uint8_t *body;     /* POST body (in the request buffer) */
  uint16_t body_len;
  uint32_t remote_ip;
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

- Constant pages point `body` at flash; nothing is copied until TCP takes it.
- Generated pages can be written into `scratch` (the unused tail of the request buffer, after the request), then pointed to by `body`.  Nothing else touches it until the response is done.
- A handler returning < 0 produces **500**.
- A HEAD request calls the GET handler and sends only the headers, with the same Content-Length (RFC 9110 §9.3.2).

---

## 5. Request Handling

```
bytes arrive (tcp_recv → request buffer)
  └─ header end found? ("\r\n\r\n", bare "\n\n" also accepted, RFC 9112 §2.2)
       no  → buffer full? → 414 (still in the request line) / 431 (in headers)
       yes → parse (in place, NUL-terminating path and query)
              └─ Content-Length body complete?  no → keep reading
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
| Handler returned < 0 | 500 |

> The requirements doc said 405 for unsupported methods; RFC 9110 reserves 405 for a method the *resource* does not allow and uses 501 for methods the server does not implement.  It also asked only to "limit" header size; 431 is the status for that.

Absolute-form targets (`GET http://host/path`) are reduced to their path.  Paths are compared exactly (no percent-decoding in V1).  Headers other than Content-Length, Transfer-Encoding and Host are ignored.

---

## 6. Response Sending

```
HTTP/1.0 200 OK\r\n
Content-Type: text/html\r\n
Content-Length: 1234\r\n
Connection: close\r\n
\r\n
<body>
```

The header is formatted into a small stack buffer (`HTTP_HDR_MAX`, 192 bytes) and copied into the TCP TX buffer together with as much of the body as fits, then pushed as **one segment**.  That needs a TCP change: today `tcp_send()` transmits on every call, and with stop-and-wait TX a second call is refused until the first segment is ACKed.  The TCP layer gains:

```c
int  tcp_write(tcp_conn_t *conn, const uint8_t *data, uint16_t len); /* buffer only */
void tcp_output(net_t *net, tcp_conn_t *conn);                        /* push a segment */
/* tcp_send() == tcp_write() + tcp_output() */
```

Each later poll that finds the TX buffer free writes the next part of the body.  The response is streamed straight from the handler's `body` pointer, so it can be much larger than the TX buffer.  Error responses carry a one-line `text/plain` body.

---

## 7. Connection Lifecycle

The server is driven from the main loop.  TCP event callbacks must not call back into TCP, so the server polls each slot's TCP state instead of using callbacks:

```
LISTEN ──SYN──► (TCP handshake) ──ESTABLISHED──► RECV ──request complete──► SEND
                                                   │                          │
                                     timeout / RST / peer closed      all data ACKed
                                                   ▼                          ▼
                                                recycle ◄──TIME_WAIT/CLOSED── CLOSING (tcp_close)
```

**Recycling out of TIME_WAIT.**  An HTTP/1.0 server closes first, which leaves its TCP side in TIME_WAIT for 2×MSL = 240 s.  With one or two slots that would make the device unreachable for minutes after each page.  Once the slot reaches TIME_WAIT, both FINs have been exchanged and ours has been ACKed, so the server re-initialises it and listens again at once.  The only cost: if our final ACK is lost, the client's retransmitted FIN meets a listener and draws a RST.  The response has already been delivered, so that is harmless.  Small embedded stacks commonly make this trade.

**Timeouts** (`http_server_tick()`): a slot that has not received a complete request within `HTTP_REQUEST_TIMEOUT_MS` (10 s), or has not finished sending and closing within `HTTP_RESPONSE_TIMEOUT_MS` (10 s), is aborted with a RST and recycled.  Without them one idle client could hold the only slot forever.

---

## 8. Main Loop

```c
while (running) {
  if (net_poll(&net) > 0)
    eth_input(&net, net.rx.buf, net.rx.frame_len);
  http_server_poll(&http);              /* read requests, run handlers, send */
  if (elapsed >= 10) {
    tcp_tick(&net, elapsed);
    http_server_tick(&http, elapsed);   /* timeouts */
  }
}
```

---

## 9. Tests

- **Unit, TCP** (`test_tcp.c`): `tcp_write()` buffers without sending; `tcp_output()` sends everything written in one segment; `tcp_write()` is refused while a segment is in flight.
- **Unit, parser + formatter** (`test_http.c`): request line, versions, methods, absolute-form, query split, headers (Content-Length, Host, Transfer-Encoding), LF-only lines, every error status, status lines and reason phrases, header formatting.
- **Unit, server** (`test_http.c`): a simulated client drives the real TCP stack with injected segments: GET/HEAD/POST, 404/405/501/413/414/431, responses larger than the TX buffer, requests arriving in pieces, the header and first body bytes in one segment, slot recycling from TIME_WAIT, timeouts, RST mid-request, two slots at once.
- **Blackbox** (`tests/blackbox/test_http_conform.py`): the host kernel is the client (Python `http.client` and raw sockets) against `http_demo` over TAP or feth: every status above, large responses, trickled requests, 20 back-to-back requests (no TIME_WAIT stall), concurrent connections, idle-client timeout.
- **Interop**: `curl` fetches `http://pyro-dead01.local/`, with the name resolved by mDNS, because `http_demo` also advertises `_http._tcp`.

---

## 10. Files

```
include/http.h, src/http.c         — parser, formatter, server
include/tcp.h, src/tcp.c           — + tcp_write(), tcp_output()
demo/http_demo/main.c              — pages + JSON API, advertised over mDNS
tests/unit/test_http.c
tests/blackbox/test_http_conform.py
```
