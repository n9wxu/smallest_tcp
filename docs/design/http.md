# HTTP Server — Design

**Protocol:** HTTP/1.0 server semantics (RFC 9110, RFC 9112)  
**Files:** `include/http.h`, `src/http.c` (parser, formatter, server, the TCP transport); `include/http_tls.h`, `src/http_tls.c` (the TLS transport)  
**Requirements:** [docs/requirements/http.md](../requirements/http.md) (REQ-HTTP-001..065 implemented, but for 030, 042 and 043 — persistent connections and the chunked coding, all MAY)  
**Status:** implemented, over plain TCP and over TLS 1.3

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
http.clock = rtc_seconds;  /* optional: seconds since 1970 UTC, 0 if not known yet */
```

Two optional fields, cleared by `http_server_init()`, are set after it:
`clock` — the device's clock, for the Date field (section 6) — and, for
HTTPS, `https_hosts` (section 7.2).

The stack keeps no connection table of its own: `tcp_set_connections()`
binds the application's array of `tcp_conn_t` pointers to `net`
([tcp.md §2.2](tcp.md#22-binding-connections)).  All slots listen on the
same port, and each SYN takes the first free listener in table order; a SYN
that finds none is refused with RST.

| | Cortex-M0 |
|---|---:|
| `http_conn_t` | 220 B (240 dual stack) |
| `http_server_t` | 36 B |

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
  uint8_t flags;           /* HTTP_RQ_*: what the header section asked for */
  const char *path;        /* "/api/status" — NUL-terminated, no query */
  const char *query;       /* "a=1&b=2" or "" */
  const char *host;        /* the target's host, no port, not NUL-terminated; NULL if none */
  uint16_t host_len;
  const uint8_t *body;     /* POST body (in the request buffer), NULL if none */
  uint16_t body_len;
  uint32_t remote_ip;      /* NET_USE_IPV4 only: client IPv4, host order (0 over IPv6) */
  const uint8_t *remote_ip6; /* NET_USE_IPV6 only: client IPv6, NULL over IPv4 */
} http_request_t;

typedef struct {
  uint16_t status;           /* preset 200; 200..599, not 206, 401, 426 */
  const char *content_type;  /* preset "text/html"; NULL: none; no control characters */
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
- A handler returning < 0 produces **500**.  So does a response the
  server cannot send whole and valid (RFC 9110 §2.2: a sender must not
  generate protocol elements outside the grammar): a status outside
  200..599 — a 1xx included, since this HTTP/1.0 server sends one final
  response and never a 1xx (§15.2) — a 206, 401 or 426, which require a
  field the server cannot add (Content-Range, WWW-Authenticate, Upgrade:
  §15.3.7.1, §15.5.2, §15.5.22), or a content type with a control
  character (a CR or LF in it would end the field early).
- A handler's 405 gets an `Allow` field listing its route's methods
  (§15.5.6).
- A HEAD request calls the GET handler and sends only the headers, with the
  same Content-Length (RFC 9110 §9.3.2).  Every response to HEAD is headers
  only, an error too: whether the request is HEAD is read from the request
  line itself, so a 400, 414, 431 or 505 about a request that could not be
  parsed has no body either.
- A 204, 205 or 304 is sent without the body the handler gave (RFC 9110
  §15.3.5, §15.3.6, §15.4.5) — a 205 with `Content-Length: 0`, the others
  without Content-Type and Content-Length.

---

## 5. Request handling

```
bytes arrive (transport read → request buffer)
  └─ header end found? ("\r\n\r\n", bare "\n\n" also accepted, RFC 9112 §2.2)
       no  → buffer full? → 414 (no line end yet) / 431 (in the headers)
             client can send no more? → end the stream without an answer
       yes → parse (in place, NUL-terminating path and query) → 400/421/501/505
              └─ admit() — what the header section alone decides, at once:
                 too big for the buffer → 413, misdirected → 421,
                 route lookup → 404 / 405, preconditions → 412 / 304,
                 Expect: 100-continue and no content yet → 417
                 └─ Content-Length body complete?  no → keep reading (or end the
                                                     stream if the client is done)
                    → handler → response
```

The header section decides as much as it can before any content is read, so
a client sending a large body learns of a 404, 405 or 413 at once (and what
it still sends is discarded, section 8).

**Preconditions** (RFC 9110 §13).  If-Match and If-None-Match are evaluated
before the handler runs, and only for a request that would otherwise
succeed — a 400, 404, 405, 413 or 421 takes precedence (§13.2.1) — If-Match
first (§13.2.2).  The server sends no entity tags, so a list of tags in
If-Match never matches: 412 (Precondition Failed); one in If-None-Match
never matches either, so the request proceeds.  `*` names any current
representation, which a route has: `If-Match: *` proceeds, `If-None-Match:
*` gets 304 (Not Modified) for GET and HEAD and 412 for POST.
If-Modified-Since and If-Unmodified-Since are ignored, as RFC 9110
§13.1.3–4 requires of a resource with no modification date.

**Expect: 100-continue** (RFC 9110 §10.1.1).  A client that sends it may
hold back the content until it sees 100 (Continue), and the server must
not wait for the content first: it must answer at once, with 100 or with
a final status.  An HTTP/1.0 server cannot send 100 (HTTP/1.0 has no 1xx,
§15.2), so an HTTP/1.1 request carrying the expectation, with content
announced and none of it arrived yet, gets whatever final status the
header section decides (404, 405, 412, 413, …) or else 417 (Expectation
Failed) — the status for an expectation the server cannot meet (§15.5.18),
on which a client SHOULD repeat the request without it.  If
content has begun to arrive, the client did not wait, and the request is
processed.  An HTTP/1.0 request's expectation is ignored, as §10.1.1
requires.

| Condition | Status |
|---|---|
| Request line not `METHOD SP target SP HTTP/x.y`, header line without `:`, obsolete line folding, bad or conflicting Content-Length | 400 |
| A control octet (a bare CR, a NUL, …) in the target, or a bare CR or a NUL in a field value (RFC 9112 §2.2, RFC 9110 §5.5) — rejected rather than handed to the application | 400 |
| An http or https target in absolute-form with an empty host (RFC 9110 §4.2.1, §4.2.2) | 400 |
| HTTP/1.1 request without `Host`, or any request with more than one `Host` line, or with a `Host` value that is not `uri-host [":" port]` — an empty one is valid (RFC 9112 §3.2) | 400 |
| Method other than GET, HEAD, POST (RFC 9110 §15.6.2) | 501 |
| `Transfer-Encoding` whose last coding is not chunked — the length cannot be determined (RFC 9112 §6.3) — or any `Transfer-Encoding` in an HTTP/1.0 request, whose framing is then faulty (§6.1) | 400 |
| `Transfer-Encoding` ending in chunked, in an HTTP/1.1 request (chunked request bodies are not implemented, RFC 9112 §6.1) | 501 |
| Version other than HTTP/1.0 or HTTP/1.1 | 505 |
| If-Match with entity tags (none can match), or `If-None-Match: *` on a POST (RFC 9110 §13.1.1, §13.1.2) | 412 |
| `If-None-Match: *` on a GET or HEAD (RFC 9110 §13.1.2) | 304 |
| HTTP/1.1 with `Expect: 100-continue`, content announced, none arrived (RFC 9110 §10.1.1) | 417 |
| Path not in the route table | 404 |
| Path known, method not allowed for it (with `Allow:`, empty for a route that allows nothing — RFC 9110 §15.5.6) | 405 |
| Header section and announced content together larger than the request buffer | 413 |
| Request line longer than the request buffer | 414 |
| Headers larger than the request buffer (RFC 6585) | 431 |
| An absolute-form target whose scheme is not http or https (RFC 9110 §15.5.20); an https target on a plain TCP slot; over TLS, a host the certificate is not valid for (section 7.2, RFC 9110 §7.4) | 421 |
| Handler returned < 0, or a status or content type it cannot send (section 4), or the response header does not fit `HTTP_HDR_MAX` | 500 |

RFC 9110 reserves 405 for a method the *resource* does not allow and uses 501
for methods the server does not implement; 431 is the status for headers too
large.

Absolute-form targets (`GET http://host/path?query`, `https://` too) are
reduced to their path (`/` if empty) and query, and their authority's host
— not Host's, which an origin server ignores then (RFC 9112 §3.2.2) — is
the request's `host`; otherwise `host` is Host's, without the port.  Paths
are compared exactly (no percent-decoding).  Header fields other than
Content-Length, Transfer-Encoding, Host, Expect, If-Match and If-None-Match
are ignored.  Host's value must
be a host (an IP-literal in brackets, or a reg-name — percent-encoded
octets, letters, digits, `-._~!$&'()*+,;=` — which an IPv4 address also
is) and an optional port of digits.

---

## 6. Response sending

```
HTTP/1.0 200 OK\r\n
Date: Thu, 01 Oct 2026 12:34:56 GMT\r\n
Content-Type: text/html\r\n
Content-Length: 1234\r\n
Connection: close\r\n
\r\n
<body>
```

The header is formatted into a buffer on the C stack (`HTTP_HDR_MAX`, 224
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

**Date.**  An origin server with a clock must send Date in its 2xx, 3xx and
4xx responses, and one without a clock must not (RFC 9110 §6.6.1).  The
application says which it is: `http_server_t.clock` returns the time in
seconds since 1970-01-01 UTC (from SNTP or an RTC), or 0 while it does not
know it; NULL means no clock.  The server reads it once per response and
sends the time as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, RFC 9110
§5.6.7) in every response, 5xx included (which the RFC allows).  The date
is computed without a run-time division: days, hours and minutes by
shift-and-subtract (`take()`), the year and month by subtracting their
lengths, valid until the 32-bit seconds run out in 2106 (2100 is the one
year divisible by 4 in that span that is not a leap year).  It is kept in
the slot (`http_conn_t.date`), since the header is formatted again on each
send call.

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
  void (*release)(struct http_conn_s *c);                 /* the client is gone; may be NULL */
  uint8_t secure;                                         /* 1: TLS — requests are for https resources */
} http_transport_t;
```

`http_conn_init()` sets the plain TCP transport; `http_conn_use_tls(c, tls)`
switches a slot to TLS.  `http_conn_t.transport_ctx` is the transport's own
state (the slot's `tls_conn_t`).  `release` runs whenever a slot listens
again — after a response, a reset, a timeout, and once at
`http_server_init()` — so a transport can forget the last client however
its connection ended.

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
| `release` | None (NULL) |
| `secure` | 0: a request for an https resource is misdirected (421) |

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
| `release` | `tls_release()`: the client's secrets, record keys and the plaintext left in the TLS buffers are wiped at once, not at the next client's `tls_init()` |
| `secure` | 1 |

**Which hosts a TLS slot answers for.**  RFC 9110 §7.4 has an origin
server reject (421 Misdirected Request) a request for an https resource
unless it came over a connection secured with a certificate valid for the
target's host.  The server cannot read the names out of the certificate
(the crypto backend holds it), so the application lists them alongside it:
`http_server_t.https_hosts`, the DNS names and IP addresses the
certificate carries, as a URI writes them (`device.example`, `10.0.0.2`,
`[2001:db8::1]`).  A request over TLS whose host — the absolute-form
target's, else Host's, without the port, compared ignoring case — is not
one of them, or that names no host at all, gets 421.  Without the list
(NULL, the default) hosts are not checked: the requirement is then met
only if the certificate is valid for every name a client can reach the
device by (the deviation recorded at REQ-HTTP-056).  The HTTPS demo
(`demo/https_demo/main.c`) sets no list — its certificate is loaded from a
file at run time, so the program does not know its names — and the host
check is inactive there: it answers a request over TLS whatever host the
request names.

The TLS handshake happens while the slot is in `S_RECV` (section 8), so it
counts against the request timeout.  A failed handshake makes `client_done`
true, and the slot ends the stream — the alert goes out — and closes.

An HTTPS slot needs a `tls_conn_t` (448 B on Cortex-M0) and TLS receive and
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
| `S_LISTEN` | TCP listening or in its handshake | TCP reaches ESTABLISHED (or CLOSE-WAIT): the transport's `accepted()` runs, the request timer starts, and the slot goes straight on to `S_RECV` in the same poll.  A handshake that fails (a RST, no ACK) goes back to LISTEN in TCP itself ([tcp.md](tcp.md)); a slot found CLOSED all the same is armed again |
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
saw a zero window can finish sending and close.  Without it, a client
stalled on a zero window after a 414 would hold the slot until the timeout.

**Timeouts** (`http_server_tick()`): a half-open TCP handshake
(SYN-RECEIVED) has `HTTP_REQUEST_TIMEOUT_MS` (10 s) to complete; an accepted
connection then has `HTTP_REQUEST_TIMEOUT_MS` again to deliver a complete
request — over TLS, the TLS handshake included — and
`HTTP_RESPONSE_TIMEOUT_MS` (10 s) for each of sending the response, ending
the stream and completing the close — a client that has the response but
never closes its own side holds the slot, in `S_CLOSING`, for that long.
An expired slot is aborted (RST) and recycled.  Without them one idle
client could hold the only slot forever.  An idle listener's timer does
not run.

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

- **Integration** (`tests/integration/itest_http.c`, 49; 51 with
  `SMALLEST_TCP_TLS`): a client on the scripted wire (`peer_client_t`)
  talks to the server over the stack's TCP, traced to the requirements:
  the request line, field lines, the end of the header section however the
  segments cut it, GET, HEAD (errors too), POST, what the handler is given
  and what it answers, every status and reason phrase, content types,
  204/205 without content, Allow, Host (one, valid), bare CR and NUL,
  Transfer-Encoding, absolute-form, Date from a clock (leap years, 2100,
  2106), Expect: 100-continue, If-Match / If-None-Match, invalid and
  incomplete Content-Length, 413/414/431 at the request buffer's bounds,
  field whitespace, obs-fold, octet parsing, always HTTP/1.0, never
  Transfer-Encoding, responses larger than the TX buffer, one response per
  connection whatever Connection asks, one slot serving client after
  client (a request with its FIN, a simultaneous close), two slots at
  once, reading on after an error, and the slot freed by a reset, an early
  close and each timeout, with the transport released.  With
  `SMALLEST_TCP_TLS` also over TLS 1.3 (the client's TLS is the stack's own
  TLS client with a PSK, only the transport): https absolute-form, and the
  421 for a host the certificate is not valid for.
- **Unit, parser and formatter** (`tests/unit/test_http.c`, 22): the
  public `http_header_end()`, `http_parse_request()`, `http_reason()` and
  `http_format_header()`: header end, request line, versions, methods,
  query split, headers (Content-Length, Host), LF-only lines, leading
  empty lines, reason phrases, header formatting (Allow, 204, a block that
  does not fit).
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
tests/integration/itest_http.c
tests/unit/test_http.c
tests/blackbox/test_http_conform.py, test_https_conform.py
```
