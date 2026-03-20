# HTTP Requirements

**Protocol:** Hypertext Transfer Protocol — Minimal Server  
**Primary RFC:** RFC 9110 — HTTP Semantics  
**Supporting:** RFC 9112 — HTTP/1.1, RFC 7230 (obsoleted by RFC 9112)  
**Supersession:** RFC 9110/9112 supersede RFC 7230-7235; RFC 9110 supersedes RFC 2616  
**Scope:** V1 (IPv4), V2 (IPv6)  
**Last updated:** 2026-03-19

## Overview

This stack implements a minimal HTTP/1.0 server (with optional HTTP/1.1 support). The server handles one request at a time per TCP connection with `Connection: close` semantics. The application provides request handlers that map URLs to responses. This is intended for device configuration pages, status readouts, and firmware upload.

## Requirements

### Request Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-001 | MUST | Parse HTTP request line: Method SP Request-Target SP HTTP-Version CRLF | RFC 9112 §3 | TEST-HTTP-001 |
| REQ-HTTP-002 | MUST | Support GET method | RFC 9110 §9.3.1 | TEST-HTTP-002 |
| REQ-HTTP-003 | SHOULD | Support POST method | RFC 9110 §9.3.3 | TEST-HTTP-003 |
| REQ-HTTP-004 | SHOULD | Support HEAD method (respond with headers only, no body) | RFC 9110 §9.3.2 | TEST-HTTP-004 |
| REQ-HTTP-005 | MUST | Parse Request-Target (path component) | RFC 9112 §3.2 | TEST-HTTP-005 |
| REQ-HTTP-006 | MUST | Extract HTTP version from request line (HTTP/1.0 or HTTP/1.1) | RFC 9112 §2.3 | TEST-HTTP-006 |
| REQ-HTTP-007 | MUST | Parse headers as field-name ":" field-value CRLF | RFC 9110 §5.1, RFC 9112 §5 | TEST-HTTP-007 |
| REQ-HTTP-008 | MUST | Detect end of headers: empty line (CRLF CRLF) | RFC 9112 §5 | TEST-HTTP-008 |
| REQ-HTTP-009 | SHOULD | Extract Content-Length header (for POST body) | RFC 9110 §8.6 | TEST-HTTP-009 |
| REQ-HTTP-010 | SHOULD | Extract Host header (required in HTTP/1.1) | RFC 9110 §7.2 | TEST-HTTP-010 |
| REQ-HTTP-011 | MUST | Tolerate missing Host header for HTTP/1.0 requests | RFC 9112 §3.3 | TEST-HTTP-011 |
| REQ-HTTP-012 | SHOULD | Handle requests with unknown/unsupported headers by ignoring them | RFC 9110 §5.1 | TEST-HTTP-012 |

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
| REQ-HTTP-020 | MUST | Include Content-Length header in response | RFC 9110 §8.6 | TEST-HTTP-020 |
| REQ-HTTP-021 | MUST | Include Connection: close header for HTTP/1.0 semantics | RFC 9112 §9.6 | TEST-HTTP-021 |
| REQ-HTTP-022 | MUST | Send response headers followed by CRLF CRLF followed by body | RFC 9112 §6 | TEST-HTTP-022 |
| REQ-HTTP-023 | MUST | For HEAD requests, send response headers but no body | RFC 9110 §9.3.2 | TEST-HTTP-023 |

### Method Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-024 | MUST | Return 405 (Method Not Allowed) for unsupported methods | RFC 9110 §15.5.6 | TEST-HTTP-024 |
| REQ-HTTP-025 | MUST | Return 404 (Not Found) for unregistered paths | RFC 9110 §15.5.5 | TEST-HTTP-025 |
| REQ-HTTP-026 | SHOULD | Return 400 (Bad Request) for malformed request lines | RFC 9110 §15.5.1 | TEST-HTTP-026 |
| REQ-HTTP-027 | MUST | Return 500 (Internal Server Error) if handler fails | RFC 9110 §15.6.1 | TEST-HTTP-027 |

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
| REQ-HTTP-040 | MUST | Limit total header size to prevent buffer overflow | Architecture | TEST-HTTP-040 |
| REQ-HTTP-041 | SHOULD | Reject requests with excessively long URIs (414 URI Too Long) | RFC 9110 §15.5.15 | TEST-HTTP-041 |

### Streaming / Chunked Responses (Optional)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-HTTP-042 | MAY | Support chunked transfer encoding for responses that don't know Content-Length upfront | RFC 9112 §7 | TEST-HTTP-042 |
| REQ-HTTP-043 | MAY | Support chunked encoding for POST request bodies | RFC 9112 §7 | TEST-HTTP-043 |

## Notes

- **HTTP/1.0 only for V1:** Connection: close after each request. This keeps the implementation simple and avoids pipelining complexity.
- **No TLS:** HTTPS is out of scope. The overhead of TLS (code size + RAM for handshake) is too large for PIC16/STM32-class targets.
- **Application-driven:** The HTTP server is a thin dispatch layer. The application provides handlers that generate responses. This keeps the HTTP code generic.
- **Streaming large responses:** For responses larger than the TX buffer (e.g., large HTML pages), the application handler can be called multiple times to fill successive TCP segments. This requires the handler to maintain position state.
- **Content-Length known at call time:** For simple responses (status pages, JSON), the application knows the full body at handler call time. Content-Length is mandatory in HTTP/1.0 without chunked encoding.
