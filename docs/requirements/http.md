# HTTP Requirements

**Protocol:** Hypertext Transfer Protocol — Minimal Server  
**Primary RFC:** RFC 9110 — HTTP Semantics  
**Supporting:** RFC 9112 — HTTP/1.1, RFC 7230 (obsoleted by RFC 9112)  
**Supersession:** RFC 9110/9112 supersede RFC 7230-7235; RFC 9110 supersedes RFC 2616  
**Scope:** over IPv4 and IPv6  
**Design:** [docs/design/http.md](../design/http.md)

## Overview

This stack implements a minimal HTTP/1.0 server. It accepts HTTP/1.0 and HTTP/1.1 requests and answers each with one HTTP/1.0 response and `Connection: close`: one request per TCP connection, over plain TCP or over TLS 1.3. The application provides request handlers that map paths to responses. This is intended for device configuration pages, status readouts, and firmware upload. Persistent connections and the chunked transfer coding (REQ-HTTP-030, 042, 043 — all MAY) are not implemented.

## Requirements

### Request Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-001 | MUST | Parse HTTP request line: Method SP Request-Target SP HTTP-Version CRLF | RFC 9112 §3 | itest_http_001_request_line |
| REQ-HTTP-002 | MUST | Support GET method | RFC 9110 §9.3.1 | itest_http_002_get, test_http_001_get_root, test_http_022_get_over_ipv6, test_https_001_index, test_https_007_by_address |
| REQ-HTTP-003 | SHOULD | Support POST method | RFC 9110 §9.3.3 | itest_http_014_handler_gets_the_request, test_http_005_post_echo |
| REQ-HTTP-004 | MUST | Support HEAD method (respond with headers only, no body): every general-purpose server supports GET and HEAD | RFC 9110 §9.1, §9.3.2 | itest_http_023_head_never_has_a_body, test_http_002_head, test_https_004_head |
| REQ-HTTP-005 | MUST | Parse Request-Target (path component) | RFC 9112 §3.2 | itest_http_001_request_line |
| REQ-HTTP-006 | MUST | Extract HTTP version from request line (HTTP/1.0 or HTTP/1.1) | RFC 9112 §2.3 | itest_http_001_request_line, test_http_003_http11_client_gets_http10, test_http_014_version_not_supported |
| REQ-HTTP-007 | MUST | Parse headers as field-name ":" field-value CRLF | RFC 9110 §5.1, RFC 9112 §5 | itest_http_007_field_lines, test_http_013_bad_requests |
| REQ-HTTP-008 | MUST | Detect end of headers: empty line (CRLF CRLF) | RFC 9112 §5 | itest_http_008_end_of_the_header_section, test_http_009_trickled_request |
| REQ-HTTP-009 | SHOULD | Extract Content-Length header (for POST body) | RFC 9110 §8.6 | itest_http_007_field_lines |
| REQ-HTTP-010 | MUST | Respond 400 (Bad Request) to an HTTP/1.1 request without a Host header, and to any request with more than one Host header line | RFC 9112 §3.2 | itest_http_010_one_host_line, test_http_003_http11_client_gets_http10, test_http_013_bad_requests |
| REQ-HTTP-011 | MUST | Tolerate missing Host header for HTTP/1.0 requests | RFC 9112 §3.2 | itest_http_002_get |
| REQ-HTTP-012 | SHOULD | Handle requests with unknown/unsupported headers by ignoring them | RFC 9110 §5.1 | itest_http_007_field_lines |
| REQ-HTTP-044 | MUST | Reject with 400 (Bad Request) a request with a bare CR (one not followed by LF) or a NUL in its request line or in a field value, rather than hand either to the application (an LF always ends the line) | RFC 9112 §2.2, RFC 9110 §5.5 | itest_http_044_bare_cr_and_nul_rejected |
| REQ-HTTP-045 | MUST | Respond 400 (Bad Request) to any request whose Host field value is invalid — not `uri-host [ ":" port ]`; an empty value is valid | RFC 9112 §3.2, RFC 9110 §7.2 | itest_http_045_invalid_host_value |
| REQ-HTTP-047 | MUST | Accept a request target in absolute-form: an "http" or "https" URI is reduced to its path and query, and its authority names the host, the Host field being ignored; an "http" or "https" URI with an empty host is rejected as invalid (400); any other scheme names an origin the server does not serve (421 Misdirected Request) | RFC 9112 §3.2.2, RFC 9110 §4.2.1, §4.2.2, §15.5.20 | itest_http_047_absolute_form, itest_http_047_https_absolute_form_over_tls, test_http_004_absolute_form |
| REQ-HTTP-059 | MUST | Respond 400 (Bad Request) to a request with whitespace between a field name and its colon; exclude the whitespace before and after a field value from it | RFC 9112 §5.1, RFC 9110 §5.5 | itest_http_059_field_whitespace |
| REQ-HTTP-060 | MUST | Respond 400 (Bad Request) to a request with obsolete line folding, or with whitespace between the request line and the first field line | RFC 9112 §5.2, §2.2 | itest_http_060_folding_and_leading_whitespace |
| REQ-HTTP-061 | MUST NOT | Apply a request to the target resource (call its handler) before the entire header section has been received | RFC 9110 §5.3 | itest_http_061_whole_header_section_first, itest_http_008_end_of_the_header_section, test_http_009_trickled_request |
| REQ-HTTP-062 | MUST | Parse a request as a sequence of octets in a superset of US-ASCII, not as Unicode text: an LF octet always ends a line, and other octets (UTF-8, obs-text) are opaque | RFC 9112 §2.2 | itest_http_062_parsed_as_octets |

### Request Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-013 | MUST | Dispatch requests to application-provided handler based on method + path | Architecture | itest_http_002_get, itest_http_014_handler_gets_the_request, itest_http_028_a_connection_per_slot |
| REQ-HTTP-014 | MUST | Application handler receives: method, version, path, query, the target's host, the content (for POST), the client's address — and the route's own context | Architecture | itest_http_014_handler_gets_the_request, test_http_007_json_status |
| REQ-HTTP-015 | MUST | Application handler returns: status code, content-type, body pointer, body length | Architecture | itest_http_014_handler_gets_the_request, test_http_007_json_status, test_https_002_status |

### Response Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-016 | MUST | Generate status line: HTTP-Version SP Status-Code SP Reason-Phrase CRLF | RFC 9112 §4 | itest_http_016_status_line_fields_body, test_http_001_get_root |
| REQ-HTTP-017 | MUST | Support status codes: 200 (OK), 404 (Not Found), 400 (Bad Request), 500 (Internal Server Error) | RFC 9110 §15 | itest_http_016_status_line_fields_body |
| REQ-HTTP-018 | SHOULD | Support status codes: 204 (No Content), 301 (Moved Permanently), 405 (Method Not Allowed) | RFC 9110 §15 | itest_http_020_204_without_content, itest_http_016_status_line_fields_body |
| REQ-HTTP-019 | SHOULD | Include Content-Type in a response with content: the handler's (preset `text/html`; it may set none), `text/plain` in the server's own error responses | RFC 9110 §8.3 | itest_http_016_status_line_fields_body, itest_http_019_content_type, test_http_001_get_root, test_https_001_index |
| REQ-HTTP-020 | MUST | Include Content-Length in a response — but never in a 1xx or 204 response; in a response to HEAD only the value a GET of the same request gets (in a 304 the server sends none) | RFC 9110 §8.6 | itest_http_002_get, itest_http_020_204_without_content, itest_http_020_head_length_is_gets, itest_http_022_response_of_any_length, test_http_001_get_root, test_http_008_large_response, test_https_001_index |
| REQ-HTTP-021 | MUST | Send the "close" connection option (`Connection: close`) in every response: the server does not support persistent connections | RFC 9112 §9.6 | itest_http_016_status_line_fields_body, itest_http_031_closes_after_one_response, test_http_001_get_root |
| REQ-HTTP-022 | MUST | Send response headers followed by CRLF CRLF followed by body | RFC 9112 §6 | itest_http_016_status_line_fields_body, itest_http_022_response_of_any_length, test_http_001_get_root, test_http_008_large_response, test_https_003_big, test_https_008_curl |
| REQ-HTTP-023 | MUST | For HEAD requests, send response headers but no body — error responses included | RFC 9110 §9.3.2 | itest_http_023_head_never_has_a_body, itest_http_023_head_414_without_a_body, test_http_002_head, test_https_004_head |
| REQ-HTTP-048 | MUST | With a clock (the application's `http_server_t.clock`), send a Date field, as an IMF-fixdate, in every 2xx, 3xx and 4xx response (and in 5xx, which the RFC allows); without one — or while it does not know the time — send none | RFC 9110 §6.6.1, §5.6.7 | itest_http_048_date_from_the_clock |
| REQ-HTTP-049 | MUST NOT | Generate a status line or field that does not match the grammar: a handler's status outside 100..599, or a content type with a control character (CR, LF, …), is answered with 500 instead | RFC 9110 §2.2, §15, §5.5 | itest_http_049_status_and_type_follow_the_grammar, itest_http_027_handler_failure_500 |
| REQ-HTTP-050 | MUST NOT | Send a 1xx response to an HTTP/1.0 client: the server answers HTTP/1.0 with one final response only, so a handler's 1xx is answered with 500 | RFC 9110 §15.2 | itest_http_050_no_1xx |
| REQ-HTTP-051 | MUST NOT | Generate content in a 205 (Reset Content) response, whatever the handler gave | RFC 9110 §15.3.6 | itest_http_051_205_without_content |
| REQ-HTTP-052 | MUST | Send a 206 only with Content-Range, a 401 only with WWW-Authenticate, a 426 only with Upgrade: the server cannot add these fields, so a handler's 206, 401 or 426 is answered with 500 | RFC 9110 §15.3.7.1, §15.5.2, §15.5.22 | itest_http_052_statuses_needing_fields |
| REQ-HTTP-063 | MUST NOT | Send a protocol version the server does not conform to: every response is HTTP/1.0, whatever the request's version | RFC 9110 §6.2 | itest_http_063_always_http_1_0 |
| REQ-HTTP-064 | MUST NOT | Send Transfer-Encoding — so never in a 1xx or 204 response, to an HTTP/1.0 request, or beside Content-Length: responses are framed by Content-Length and the close | RFC 9112 §6.1, §6.2 | itest_http_064_never_transfer_encoding |

### Method Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-024 | MUST | Generate an Allow field in every 405 (Method Not Allowed) response, listing the methods the route supports — in the server's own 405 and in a handler's.  The server answers 405 to a method it implements that the route does not allow, and 501 (Not Implemented) to a method it does not implement (both SHOULD, §9.1) | RFC 9110 §15.5.6, §9.1, §15.6.2 | itest_http_024_405_always_has_allow, itest_http_024_handler_405_lists_the_routes_methods, itest_http_024_unimplemented_method_501, test_http_011_method_not_allowed, test_http_012_not_implemented, test_https_006_post_not_allowed |
| REQ-HTTP-025 | MUST | Return 404 (Not Found) for unregistered paths | RFC 9110 §15.5.5 | itest_http_025_unknown_path_404, test_http_010_not_found, test_https_005_not_found |
| REQ-HTTP-026 | SHOULD | Return 400 (Bad Request) for malformed request lines | RFC 9112 §3, RFC 9110 §15.5.1 | itest_http_001_request_line, test_http_013_bad_requests |
| REQ-HTTP-027 | MUST | Return 500 (Internal Server Error) if handler fails | RFC 9110 §15.6.1 | itest_http_027_handler_failure_500 |

### Expectations and Preconditions

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-053 | MUST | Answer an HTTP/1.1 request with "Expect: 100-continue" whose content has not begun to arrive at once, never waiting for the content: with the final status the method, target and header fields decide (404, 405, 412, 304), else 417 (Expectation Failed) — this HTTP/1.0 server cannot send 100 (Continue), and 417 tells the client to repeat the request without the expectation; content already arriving is processed; an HTTP/1.0 request's expectation is ignored | RFC 9110 §10.1.1, §15.5.18 | itest_http_053_expect_100_continue |
| REQ-HTTP-054 | MUST | Evaluate If-Match before performing the method, after the checks that take precedence (400, 404, 405, 421): `*` is true for a route; a list of entity tags is false — the server sends no ETags — and answered with 412 (Precondition Failed) | RFC 9110 §13.1.1, §13.2 | itest_http_054_if_match |
| REQ-HTTP-055 | MUST | Evaluate If-None-Match before performing the method, after the checks that take precedence: `*` is false for a route — 304 (Not Modified) for GET and HEAD, 412 (Precondition Failed) for other methods; a list of entity tags is true (none can match) | RFC 9110 §13.1.2, §13.2 | itest_http_055_if_none_match |

### Connection Management

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-028 | MUST | Process one request per TCP connection (HTTP/1.0 style) | Architecture | itest_http_031_closes_after_one_response, itest_http_028_one_slot_client_after_client, itest_http_028_a_connection_per_slot, test_http_019_back_to_back_requests, test_http_020_two_concurrent_connections, test_https_009_sequential |
| REQ-HTTP-029 | MUST | Close TCP connection after sending response | Architecture | itest_http_002_get, itest_http_031_closes_after_one_response, itest_http_028_one_slot_client_after_client, itest_http_029_reads_on_after_the_response, test_http_001_get_root, test_http_019_back_to_back_requests, test_https_008_curl, test_https_009_sequential |
| REQ-HTTP-030 | MAY | Support HTTP/1.1 persistent connections (keep-alive) | RFC 9112 §9.3 | — (not implemented) |
| REQ-HTTP-031 | MUST | Initiate closure of the connection after the final response to a request with the "close" connection option, and after any response that itself carries "close" — every response does — and process no further request on that connection | RFC 9112 §9.6 | itest_http_031_closes_after_one_response |
| REQ-HTTP-065 | MUST | Free a slot for the next client when its client is gone or idle: a reset, a close before the request is complete, a TCP handshake or a request not completed within `HTTP_REQUEST_TIMEOUT_MS`, a response not delivered within `HTTP_RESPONSE_TIMEOUT_MS` (the connection is reset).  The slot's transport is told (`release()`), so that TLS wipes the client's secrets | Architecture | itest_http_029_reads_on_after_the_response, itest_http_065_reset_frees_the_slot, itest_http_065_early_close_frees_the_slot, itest_http_065_timeouts_free_the_slot, itest_http_065_transport_released_with_the_slot, test_http_021_idle_connection_times_out |

### POST Body Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-032 | SHOULD | Read POST body based on Content-Length header | RFC 9110 §8.6 | itest_http_008_end_of_the_header_section, itest_http_033_content_bounded_by_the_request_buffer, test_http_005_post_echo, test_http_006_post_body_in_pieces |
| REQ-HTTP-033 | MUST | Limit POST body to available buffer space | Architecture | itest_http_033_content_bounded_by_the_request_buffer, test_http_017_body_too_large |
| REQ-HTTP-034 | SHOULD | Return 413 (Content Too Large) if Content-Length exceeds buffer | RFC 9110 §15.5.14 | itest_http_033_content_bounded_by_the_request_buffer, test_http_017_body_too_large |
| REQ-HTTP-046 | MUST | Respond 400 (Bad Request), then close, to a request whose Transfer-Encoding does not end in chunked (its length cannot be determined), and to an HTTP/1.0 request with any Transfer-Encoding (its framing is faulty); one ending in chunked gets 501 (Not Implemented), then the close: RFC 9112 §6.1 has a server answer a coding it does not implement with 501 (SHOULD), and this HTTP/1.0 server does not implement chunked (REQ-HTTP-043) | RFC 9112 §6.3, §6.1 | itest_http_046_transfer_encoding, test_http_018_transfer_encoding_not_implemented |
| REQ-HTTP-057 | MUST | Respond 400 (Bad Request), then close, to a request with an invalid Content-Length — not decimal digits, several values, conflicting lines — parsing large numerals without overflow (more than 32 bits is invalid) | RFC 9112 §6.3, RFC 9110 §8.6 | itest_http_057_invalid_content_length |
| REQ-HTTP-058 | MUST | Consider a request incomplete, and close the connection without processing it, when the client closes or the request times out before Content-Length octets of content arrived | RFC 9112 §6.3 | itest_http_058_incomplete_content, itest_http_065_early_close_frees_the_slot |

### Content Types

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-035 | MUST | Support Content-Type: text/html | RFC 9110 §8.3 | itest_http_019_content_type, test_http_001_get_root |
| REQ-HTTP-036 | SHOULD | Support Content-Type: text/plain | RFC 9110 §8.3 | itest_http_019_content_type, test_http_005_post_echo |
| REQ-HTTP-037 | SHOULD | Support Content-Type: application/json | RFC 9110 §8.3 | itest_http_019_content_type, test_http_007_json_status, test_https_002_status |
| REQ-HTTP-038 | MAY | Support Content-Type: application/octet-stream (for firmware upload) | RFC 9110 §8.3 | itest_http_019_content_type, itest_http_022_response_of_any_length |

### Security

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-039 | MUST | Limit request line length to prevent buffer overflow | Architecture | itest_http_023_head_414_without_a_body, itest_http_040_request_larger_than_the_buffer, test_http_015_uri_too_long |
| REQ-HTTP-040 | MUST | Limit total header size to prevent buffer overflow; respond 431 (Request Header Fields Too Large) | Architecture, RFC 6585 §5 | itest_http_040_request_larger_than_the_buffer, test_http_016_headers_too_large |
| REQ-HTTP-041 | MUST | Respond 414 (URI Too Long) to a request target longer than the server parses (the request buffer) | RFC 9112 §3, RFC 9110 §15.5.15 | itest_http_023_head_414_without_a_body, itest_http_040_request_larger_than_the_buffer, test_http_015_uri_too_long |
| REQ-HTTP-056 | MUST | Reject with 421 (Misdirected Request) a request for an "https" resource not received over TLS with a certificate valid for its host: an https target on a plain TCP slot, and over TLS a target host (the absolute-form authority, else Host; none at all counts as another) not among the names the application lists for its certificate (`http_server_t.https_hosts`) — **deviation:** without the list (NULL, the default; `demo/https_demo` sets none) hosts are not checked over TLS: the server cannot read the names from the certificate, which the crypto backend holds | RFC 9110 §7.4, §4.2.2, §15.5.20 | itest_http_056_https_target_over_plain_tcp, itest_http_056_host_not_in_the_certificate |

### Streaming / Chunked Responses (Optional)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-042 | MAY | Support chunked transfer encoding for responses that don't know Content-Length upfront | RFC 9112 §7 | — (not implemented) |
| REQ-HTTP-043 | MAY | Support chunked encoding for POST request bodies (RFC 9112 §6.1's "a recipient MUST be able to parse the chunked transfer coding" binds a server that claims HTTP/1.1; this one answers HTTP/1.0, and responds 501, REQ-HTTP-046) | RFC 9112 §7, §6.1 | — (not implemented; the 501: itest_http_046_transfer_encoding, test_http_018_transfer_encoding_not_implemented) |

## Notes

- **HTTP/1.0 responses only:** `Connection: close` after each response. This keeps the implementation simple and avoids pipelining complexity; a server may answer an HTTP/1.1 request with an HTTP/1.0 response (RFC 9110 §2.5).
- **HTTPS is optional:** any slot can be carried over TLS 1.3 (`http_conn_use_tls()`, `http_tls.h`). It is left out of builds that cannot afford it: TLS needs a crypto backend and kilobytes of record buffers per slot, too much for PIC16-class targets.
- **Application-driven:** The HTTP server is a thin dispatch layer. The application provides handlers that generate responses. This keeps the HTTP code generic.
- **Streaming large responses:** The handler is called once per request and returns a pointer to the whole body (constant data, or its scratch space); the server streams it from there in as many segments as it takes, so a response can be far larger than the TX buffer.
- **Content-Length known at call time:** For simple responses (status pages, JSON), the application knows the full body at handler call time. Content-Length is mandatory in HTTP/1.0 without chunked encoding.
