# HTTP Requirements

**Protocol:** Hypertext Transfer Protocol — Minimal Server  
**Primary RFC:** RFC 9110 — HTTP Semantics  
**Supporting:** RFC 9112 — HTTP/1.1, RFC 7230 (obsoleted by RFC 9112)  
**Supersession:** RFC 9110/9112 supersede RFC 7230-7235; RFC 9110 supersedes RFC 2616  
**Scope:** V1 (IPv4), V2 (IPv6)  
**Last updated:** 2026-10-01 (REQ-HTTP-044..064: the RFC 9110/9112 MUSTs the rows left out; REQ-HTTP-004, 041 are MUSTs; REQ-HTTP-020 as RFC 9110 §8.6 has it)

## Overview

This stack implements a minimal HTTP/1.0 server (with optional HTTP/1.1 support). The server handles one request at a time per TCP connection with `Connection: close` semantics. The application provides request handlers that map URLs to responses. This is intended for device configuration pages, status readouts, and firmware upload.

## Requirements

### Request Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-001 | MUST | Parse HTTP request line: Method SP Request-Target SP HTTP-Version CRLF | RFC 9112 §3 | TEST-HTTP-001 |
| REQ-HTTP-002 | MUST | Support GET method | RFC 9110 §9.3.1 | TEST-HTTP-002 |
| REQ-HTTP-003 | SHOULD | Support POST method | RFC 9110 §9.3.3 | TEST-HTTP-003 |
| REQ-HTTP-004 | MUST | Support HEAD method (respond with headers only, no body): every general-purpose server supports GET and HEAD | RFC 9110 §9.1, §9.3.2 | TEST-HTTP-004 |
| REQ-HTTP-005 | MUST | Parse Request-Target (path component) | RFC 9112 §3.2 | TEST-HTTP-005 |
| REQ-HTTP-006 | MUST | Extract HTTP version from request line (HTTP/1.0 or HTTP/1.1) | RFC 9112 §2.3 | TEST-HTTP-006 |
| REQ-HTTP-007 | MUST | Parse headers as field-name ":" field-value CRLF | RFC 9110 §5.1, RFC 9112 §5 | TEST-HTTP-007 |
| REQ-HTTP-008 | MUST | Detect end of headers: empty line (CRLF CRLF) | RFC 9112 §5 | TEST-HTTP-008 |
| REQ-HTTP-009 | SHOULD | Extract Content-Length header (for POST body) | RFC 9110 §8.6 | TEST-HTTP-009 |
| REQ-HTTP-010 | MUST | Respond 400 (Bad Request) to an HTTP/1.1 request without a Host header, and to any request with more than one Host header line | RFC 9112 §3.2 | TEST-HTTP-010 |
| REQ-HTTP-011 | MUST | Tolerate missing Host header for HTTP/1.0 requests | RFC 9112 §3.3 | TEST-HTTP-011 |
| REQ-HTTP-012 | SHOULD | Handle requests with unknown/unsupported headers by ignoring them | RFC 9110 §5.1 | TEST-HTTP-012 |
| REQ-HTTP-044 | MUST | Reject with 400 (Bad Request) a request with a bare CR (one not followed by LF) or a NUL in its request line or in a field value, rather than hand either to the application (an LF always ends the line) | RFC 9112 §2.2, RFC 9110 §5.5 | TEST-HTTP-044 |
| REQ-HTTP-045 | MUST | Respond 400 (Bad Request) to any request whose Host field value is invalid — not `uri-host [ ":" port ]`; an empty value is valid | RFC 9112 §3.2, RFC 9110 §7.2 | TEST-HTTP-045 |
| REQ-HTTP-047 | MUST | Accept a request target in absolute-form: an "http" or "https" URI is reduced to its path and query, and its authority names the host, the Host field being ignored; an "http" or "https" URI with an empty host is rejected as invalid (400); any other scheme names an origin the server does not serve (421 Misdirected Request) | RFC 9112 §3.2.2, RFC 9110 §4.2.1, §4.2.2, §15.5.20 | TEST-HTTP-047 |
| REQ-HTTP-059 | MUST | Respond 400 (Bad Request) to a request with whitespace between a field name and its colon; exclude the whitespace before and after a field value from it | RFC 9112 §5.1, RFC 9110 §5.5 | TEST-HTTP-059 |
| REQ-HTTP-060 | MUST | Respond 400 (Bad Request) to a request with obsolete line folding, or with whitespace between the request line and the first field line | RFC 9112 §5.2, §2.2 | TEST-HTTP-060 |
| REQ-HTTP-061 | MUST NOT | Apply a request to the target resource (call its handler) before the entire header section has been received | RFC 9110 §5.3 | TEST-HTTP-061 |
| REQ-HTTP-062 | MUST | Parse a request as a sequence of octets in a superset of US-ASCII, not as Unicode text: an LF octet always ends a line, and other octets (UTF-8, obs-text) are opaque | RFC 9112 §2.2 | TEST-HTTP-062 |

### Request Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-013 | MUST | Dispatch requests to application-provided handler based on method + path | Architecture | TEST-HTTP-013 |
| REQ-HTTP-014 | MUST | Application handler receives: method, path, headers (optional), body pointer (for POST) | Architecture | TEST-HTTP-014 |
| REQ-HTTP-015 | MUST | Application handler returns: status code, content-type, body pointer, body length | Architecture | TEST-HTTP-015 |

### Response Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-016 | MUST | Generate status line: HTTP-Version SP Status-Code SP Reason-Phrase CRLF | RFC 9112 §4 | TEST-HTTP-016 |
| REQ-HTTP-017 | MUST | Support status codes: 200 (OK), 404 (Not Found), 400 (Bad Request), 500 (Internal Server Error) | RFC 9110 §15 | TEST-HTTP-017 |
| REQ-HTTP-018 | SHOULD | Support status codes: 204 (No Content), 301 (Moved Permanently), 405 (Method Not Allowed) | RFC 9110 §15 | TEST-HTTP-018 |
| REQ-HTTP-019 | MUST | Include Content-Type header in response | RFC 9110 §8.3 | TEST-HTTP-019 |
| REQ-HTTP-020 | MUST | Include Content-Length in a response — but never in a 1xx or 204 response; in a response to HEAD only the value a GET of the same request gets (in a 304 the server sends none) | RFC 9110 §8.6 | TEST-HTTP-020 |
| REQ-HTTP-021 | MUST | Include Connection: close header for HTTP/1.0 semantics | RFC 9112 §9.6 | TEST-HTTP-021 |
| REQ-HTTP-022 | MUST | Send response headers followed by CRLF CRLF followed by body | RFC 9112 §6 | TEST-HTTP-022 |
| REQ-HTTP-023 | MUST | For HEAD requests, send response headers but no body — error responses included | RFC 9110 §9.3.2 | TEST-HTTP-023 |
| REQ-HTTP-048 | MUST | With a clock (the application's `http_server_t.clock`), send a Date field, as an IMF-fixdate, in every 2xx, 3xx and 4xx response (and in 5xx, which the RFC allows); without one — or while it does not know the time — send none | RFC 9110 §6.6.1, §5.6.7 | TEST-HTTP-048 |
| REQ-HTTP-049 | MUST NOT | Generate a status line or field that does not match the grammar: a handler's status outside 100..599, or a content type with a control character (CR, LF, …), is answered with 500 instead | RFC 9110 §2.2, §15, §5.5 | TEST-HTTP-049 |
| REQ-HTTP-050 | MUST NOT | Send a 1xx response to an HTTP/1.0 client: the server answers HTTP/1.0 with one final response only, so a handler's 1xx is answered with 500 | RFC 9110 §15.2 | TEST-HTTP-050 |
| REQ-HTTP-051 | MUST NOT | Generate content in a 205 (Reset Content) response, whatever the handler gave | RFC 9110 §15.3.6 | TEST-HTTP-051 |
| REQ-HTTP-052 | MUST | Send a 206 only with Content-Range, a 401 only with WWW-Authenticate, a 426 only with Upgrade: the server cannot add these fields, so a handler's 206, 401 or 426 is answered with 500 | RFC 9110 §15.3.7.1, §15.5.2, §15.5.22 | TEST-HTTP-052 |
| REQ-HTTP-063 | MUST NOT | Send a protocol version the server does not conform to: every response is HTTP/1.0, whatever the request's version | RFC 9110 §6.2 | TEST-HTTP-063 |
| REQ-HTTP-064 | MUST NOT | Send Transfer-Encoding — so never in a 1xx or 204 response, to an HTTP/1.0 request, or beside Content-Length: responses are framed by Content-Length and the close | RFC 9112 §6.1, §6.2 | TEST-HTTP-064 |

### Method Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-024 | MUST | Return 501 (Not Implemented) for methods the server does not implement, and 405 (Method Not Allowed, with an Allow header) for a known method the resource does not allow | RFC 9110 §15.5.6, §15.6.2 | TEST-HTTP-024 |
| REQ-HTTP-025 | MUST | Return 404 (Not Found) for unregistered paths | RFC 9110 §15.5.5 | TEST-HTTP-025 |
| REQ-HTTP-026 | SHOULD | Return 400 (Bad Request) for malformed request lines | RFC 9110 §15.5.1 | TEST-HTTP-026 |
| REQ-HTTP-027 | MUST | Return 500 (Internal Server Error) if handler fails | RFC 9110 §15.6.1 | TEST-HTTP-027 |

### Expectations and Preconditions

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-053 | MUST | Answer an HTTP/1.1 request with "Expect: 100-continue" whose content has not begun to arrive at once, never waiting for the content: with the final status the method, target and header fields decide (404, 405, 412, 304), else 417 (Expectation Failed) — this HTTP/1.0 server cannot send 100 (Continue), and 417 tells the client to repeat the request without the expectation; content already arriving is processed; an HTTP/1.0 request's expectation is ignored | RFC 9110 §10.1.1, §15.5.18 | TEST-HTTP-053 |
| REQ-HTTP-054 | MUST | Evaluate If-Match before performing the method, after the checks that take precedence (400, 404, 405, 421): `*` is true for a route; a list of entity tags is false — the server sends no ETags — and answered with 412 (Precondition Failed) | RFC 9110 §13.1.1, §13.2 | TEST-HTTP-054 |
| REQ-HTTP-055 | MUST | Evaluate If-None-Match before performing the method, after the checks that take precedence: `*` is false for a route — 304 (Not Modified) for GET and HEAD, 412 (Precondition Failed) for other methods; a list of entity tags is true (none can match) | RFC 9110 §13.1.2, §13.2 | TEST-HTTP-055 |

### Connection Management

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-028 | MUST | Process one request per TCP connection (HTTP/1.0 style) | Architecture | TEST-HTTP-028 |
| REQ-HTTP-029 | MUST | Close TCP connection after sending response | Architecture | TEST-HTTP-029 |
| REQ-HTTP-030 | MAY | Support HTTP/1.1 persistent connections (keep-alive) as optional enhancement | RFC 9112 §9.3 | TEST-HTTP-030 |
| REQ-HTTP-031 | MUST | If persistent connections supported, correctly handle Connection: close from client | RFC 9112 §9.6 | TEST-HTTP-031 |

### POST Body Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-032 | SHOULD | Read POST body based on Content-Length header | RFC 9110 §8.6 | TEST-HTTP-032 |
| REQ-HTTP-033 | MUST | Limit POST body to available buffer space | Architecture | TEST-HTTP-033 |
| REQ-HTTP-034 | SHOULD | Return 413 (Content Too Large) if Content-Length exceeds buffer | RFC 9110 §15.5.14 | TEST-HTTP-034 |
| REQ-HTTP-046 | MUST | Respond 400 (Bad Request), then close, to a request whose Transfer-Encoding does not end in chunked (its length cannot be determined), and to an HTTP/1.0 request with any Transfer-Encoding (its framing is faulty); one ending in chunked gets 501 (Not Implemented), then the close: RFC 9112 §6.1 has a server answer a coding it does not implement with 501 (SHOULD), and this HTTP/1.0 server does not implement chunked (REQ-HTTP-043) | RFC 9112 §6.3, §6.1 | TEST-HTTP-046 |
| REQ-HTTP-057 | MUST | Respond 400 (Bad Request), then close, to a request with an invalid Content-Length — not decimal digits, several values, conflicting lines — parsing large numerals without overflow (more than 32 bits is invalid) | RFC 9112 §6.3, RFC 9110 §8.6 | TEST-HTTP-057 |
| REQ-HTTP-058 | MUST | Consider a request incomplete, and close the connection without processing it, when the client closes or the request times out before Content-Length octets of content arrived | RFC 9112 §6.3 | TEST-HTTP-058 |

### Content Types

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-035 | MUST | Support Content-Type: text/html | RFC 9110 §8.3 | TEST-HTTP-035 |
| REQ-HTTP-036 | SHOULD | Support Content-Type: text/plain | RFC 9110 §8.3 | TEST-HTTP-036 |
| REQ-HTTP-037 | SHOULD | Support Content-Type: application/json | RFC 9110 §8.3 | TEST-HTTP-037 |
| REQ-HTTP-038 | MAY | Support Content-Type: application/octet-stream (for firmware upload) | RFC 9110 §8.3 | TEST-HTTP-038 |

### Security

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-039 | MUST | Limit request line length to prevent buffer overflow | Architecture | TEST-HTTP-039 |
| REQ-HTTP-040 | MUST | Limit total header size to prevent buffer overflow; respond 431 (Request Header Fields Too Large) | Architecture, RFC 6585 §5 | TEST-HTTP-040 |
| REQ-HTTP-041 | MUST | Respond 414 (URI Too Long) to a request target longer than the server parses (the request buffer) | RFC 9112 §3, RFC 9110 §15.5.15 | TEST-HTTP-041 |
| REQ-HTTP-056 | MUST | Reject with 421 (Misdirected Request) a request for an "https" resource not received over TLS with a certificate valid for its host: an https target on a plain TCP slot, and over TLS a target host (the absolute-form authority, else Host; none at all counts as another) not among the names the application lists for its certificate (`http_server_t.https_hosts` — the server cannot read them from the certificate, so the requirement holds only when the application supplies the list) | RFC 9110 §7.4, §4.2.2, §15.5.20 | TEST-HTTP-056 |

### Streaming / Chunked Responses (Optional)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-042 | MAY | Support chunked transfer encoding for responses that don't know Content-Length upfront | RFC 9112 §7 | TEST-HTTP-042 |
| REQ-HTTP-043 | MAY | Support chunked encoding for POST request bodies (RFC 9112 §6.1's "a recipient MUST be able to parse the chunked transfer coding" binds a server that claims HTTP/1.1; this one answers HTTP/1.0, and responds 501, REQ-HTTP-046) | RFC 9112 §7, §6.1 | TEST-HTTP-043 |

## Notes

- **HTTP/1.0 only for V1:** Connection: close after each request. This keeps the implementation simple and avoids pipelining complexity.
- **HTTPS is optional:** any slot can be carried over TLS 1.3 (`http_conn_use_tls()`, `http_tls.h`). It is left out of builds that cannot afford it: TLS needs a crypto backend and kilobytes of record buffers per slot, too much for PIC16-class targets.
- **Application-driven:** The HTTP server is a thin dispatch layer. The application provides handlers that generate responses. This keeps the HTTP code generic.
- **Streaming large responses:** The handler is called once per request and returns a pointer to the whole body (constant data, or its scratch space); the server streams it from there in as many segments as it takes, so a response can be far larger than the TX buffer.
- **Content-Length known at call time:** For simple responses (status pages, JSON), the application knows the full body at handler call time. Content-Length is mandatory in HTTP/1.0 without chunked encoding.
