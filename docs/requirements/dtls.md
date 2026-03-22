# DTLS 1.3 Requirements

**Protocol:** Datagram Transport Layer Security 1.3  
**Primary RFC:** RFC 9147 — The Datagram Transport Layer Security (DTLS) Protocol Version 1.3  
**Supporting:** RFC 8446 — TLS 1.3 (handshake and key derivation)  
**Scope:** V1 (UDP security layer, Milestone 13)  
**Last updated:** 2026-03-21  
**Status:** Preliminary — requirements captured pre-implementation

## Overview

DTLS 1.3 provides the same security guarantees as TLS 1.3 (encryption, integrity,
authentication) but operates over UDP datagrams rather than a TCP stream.  It is
the foundation for **CoAP over DTLS**, secure UDP tunnels, and other datagram
protocols that require confidentiality without a reliable transport.

DTLS shares the `tls_crypto_t` pluggable crypto backend with TLS — a device that
uses both TLS and DTLS links only one crypto library.  DTLS adds the
datagram-specific concerns:

- **Compact record header** with epoch and sequence number
- **Flight-based handshake retransmit** (UDP cannot rely on TCP retransmission)
- **Anti-replay window** (UDP delivers duplicates and out-of-order records)
- **Handshake message fragmentation** (large messages may exceed MTU)

Key design constraints:
- **DTLS 1.3 only** (RFC 9147) — no DTLS 1.2 support
- **Zero `malloc()`** — all state in application-owned `dtls_conn_t` structs
- **Same `tls_crypto_t` vtable as TLS** — one crypto backend for both protocols
- **DTLS 1.3 only** — eliminates DTLS 1.2 HelloVerifyRequest cookie exchange complexity

See [docs/design/dtls.md](../design/dtls.md) for the full design.

## Requirements

### Version and Cipher Suite

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-001 | MUST | Implement DTLS 1.3 only (RFC 9147); reject peers advertising only DTLS 1.2 or earlier | RFC 9147 §5.3 | TEST-DTLS-001 |
| REQ-DTLS-002 | MUST | Support cipher suite `TLS_AES_128_GCM_SHA256` (mandatory in RFC 8446, inherited by DTLS 1.3) | RFC 8446 Appendix B.4 | TEST-DTLS-002 |
| REQ-DTLS-003 | SHOULD | Support cipher suite `TLS_CHACHA20_POLY1305_SHA256` as optional compile-time addition | RFC 8446 Appendix B.4 | TEST-DTLS-003 |
| REQ-DTLS-004 | MUST | Support key exchange via ECDHE with x25519 curve | RFC 8446 §4.2.7 | TEST-DTLS-004 |

### Pluggable Crypto Backend

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DTLS-005 | MUST | All cryptographic operations MUST be performed through the shared `tls_crypto_t` vtable; `dtls.c` MUST NOT contain any cryptographic implementations | Architecture | TEST-DTLS-005 |
| REQ-DTLS-006 | MUST | `dtls.c` MUST NOT call `malloc`, `calloc`, or `realloc` | Architecture | TEST-DTLS-006 |
| REQ-DTLS-007 | MUST | All connection state MUST reside in the application-provided `dtls_conn_t` struct | Architecture | TEST-DTLS-007 |
| REQ-DTLS-008 | MUST | If both TLS and DTLS are used in the same application, a single `tls_crypto_t` instance MAY be shared between `tls_init()` and `dtls_init()` | Architecture | TEST-DTLS-008 |

### Record Format

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-009 | MUST | Use the DTLS 1.3 unified record header (RFC 9147 §4.3); set the fixed header bit (bit 7 = 1) | RFC 9147 §4.3 | TEST-DTLS-009 |
| REQ-DTLS-010 | MUST | Include epoch (low 4 bits of header byte 0) and per-epoch sequence number in every record | RFC 9147 §4.3 | TEST-DTLS-010 |
| REQ-DTLS-011 | MUST | Encrypt post-handshake records with AES-128-GCM; AAD = the unified record header bytes | RFC 9147 §4.3.3 | TEST-DTLS-011 |
| REQ-DTLS-012 | MUST | Nonce = base IV XOR'd with the 64-bit per-epoch sequence number (zero-padded to 12 bytes) | RFC 8446 §5.3, RFC 9147 §4.3.3 | TEST-DTLS-012 |
| REQ-DTLS-013 | MUST | Limit record payload to MTU − UDP header − IP header − DTLS header (typically ≤ 1200 bytes) | RFC 9147 §4.1 | TEST-DTLS-013 |

### Handshake — Client Role

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-014 | MUST | Client MUST send ClientHello with `supported_versions` advertising DTLS 1.3 | RFC 9147 §5.3 | TEST-DTLS-014 |
| REQ-DTLS-015 | MUST | ClientHello MUST include `key_share` extension with ECDHE public key | RFC 8446 §4.2.8 | TEST-DTLS-015 |
| REQ-DTLS-016 | MUST | Client MUST verify server Finished MAC | RFC 8446 §4.4.4 | TEST-DTLS-016 |
| REQ-DTLS-017 | MUST | Client MUST send Finished after verifying server Finished | RFC 8446 §4.4.4 | TEST-DTLS-017 |

### Handshake — Server Role

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-018 | MUST | Server MUST send ServerHello confirming DTLS 1.3 | RFC 9147 §5.3 | TEST-DTLS-018 |
| REQ-DTLS-019 | MUST | Server MUST send EncryptedExtensions, Certificate (if cert mode), CertificateVerify (if cert mode), Finished | RFC 8446 §4.4 | TEST-DTLS-019 |
| REQ-DTLS-020 | MUST | Server MUST verify client Finished MAC | RFC 8446 §4.4.4 | TEST-DTLS-020 |

### PSK Mode

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-021 | MUST | Support PSK-only handshake mode (same as TLS: `pre_shared_key` + `psk_key_exchange_modes` extensions) | RFC 8446 §2.2 | TEST-DTLS-021 |
| REQ-DTLS-022 | MUST | In PSK mode, Certificate and CertificateVerify MUST NOT be sent or required | RFC 8446 §2.2 | TEST-DTLS-022 |

### Handshake Retransmit (Flights)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-023 | MUST | Group handshake messages into flights and save the most recent flight in the application-provided `flight_buf` | RFC 9147 §5.8 | TEST-DTLS-023 |
| REQ-DTLS-024 | MUST | On handshake retransmit timeout, resend the entire saved flight | RFC 9147 §5.8 | TEST-DTLS-024 |
| REQ-DTLS-025 | MUST | Initial retransmit timeout = 1000 ms; double on each retry | RFC 9147 §5.8 | TEST-DTLS-025 |
| REQ-DTLS-026 | MUST | Maximum retransmit timeout = `NET_DTLS_MAX_RTO_MS` (compile-time, default 60000 ms) | RFC 9147 §5.8 | TEST-DTLS-026 |
| REQ-DTLS-027 | MUST | After `NET_DTLS_MAX_RETRANSMITS` failures (compile-time, default 5), abort with `DTLS_EVT_ERROR` | RFC 9147 §5.8 | TEST-DTLS-027 |
| REQ-DTLS-028 | MUST | `dtls_tick(dtls, elapsed_ms, tx_out, tx_len_out)` drives retransmit timer; application MUST call this from its main loop | Architecture | TEST-DTLS-028 |

### Anti-Replay Window

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-029 | MUST | Maintain a per-epoch 64-bit sliding anti-replay window | RFC 9147 §4.5.1 | TEST-DTLS-029 |
| REQ-DTLS-030 | MUST | Discard records with sequence numbers already seen within the window | RFC 9147 §4.5.1 | TEST-DTLS-030 |
| REQ-DTLS-031 | MUST | Discard records with sequence numbers older than `top − 63` (below the window) | RFC 9147 §4.5.1 | TEST-DTLS-031 |
| REQ-DTLS-032 | MUST | Reset the anti-replay window when the epoch increments | RFC 9147 §4.5.1 | TEST-DTLS-032 |

### Handshake Message Fragmentation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-033 | MUST | Reassemble fragmented handshake messages (message_seq, fragment_offset, fragment_length) into the application-provided `hs_buf` before processing | RFC 9147 §5.6 | TEST-DTLS-033 |
| REQ-DTLS-034 | MUST | Fragment outgoing handshake messages that exceed the record MTU limit | RFC 9147 §5.6 | TEST-DTLS-034 |
| REQ-DTLS-035 | MUST | If `hs_buf` is too small to reassemble an incoming handshake message, abort with `DTLS_EVT_ERROR` | Architecture | TEST-DTLS-035 |
| REQ-DTLS-036 | MUST | Include `message_seq` in DTLS handshake header; increment for each distinct handshake message | RFC 9147 §5.2 | TEST-DTLS-036 |

### Alert Protocol

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-037 | MUST | Send `close_notify` alert on graceful shutdown | RFC 8446 §6.1 | TEST-DTLS-037 |
| REQ-DTLS-038 | MUST | On receiving a fatal alert, transition to DTLS_ERROR and notify application via event callback | RFC 8446 §6 | TEST-DTLS-038 |
| REQ-DTLS-039 | MUST | Send appropriate fatal alert on protocol errors | RFC 8446 §6 | TEST-DTLS-039 |

### Event Notification

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DTLS-040 | MUST | Fire `DTLS_EVT_CONNECTED` when handshake completes | Architecture | TEST-DTLS-040 |
| REQ-DTLS-041 | MUST | Fire `DTLS_EVT_CLOSED` on clean shutdown | Architecture | TEST-DTLS-041 |
| REQ-DTLS-042 | MUST | Fire `DTLS_EVT_ERROR` on fatal alert, protocol error, or retransmit exhaustion | Architecture | TEST-DTLS-042 |

### Buffer Requirements

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DTLS-043 | MUST | Application provides `hs_buf` (handshake reassembly buffer) at `dtls_init()`; minimum size should accommodate the largest expected handshake message (≥ 2048 bytes recommended for certificate mode) | Architecture | TEST-DTLS-043 |
| REQ-DTLS-044 | MUST | Application provides `flight_buf` (retransmit buffer) at `dtls_init()`; minimum size = largest flight to be retransmitted | Architecture | TEST-DTLS-044 |
| REQ-DTLS-045 | MUST | `dtls_send()` output buffer must be sized by application to hold one DTLS record: plaintext + 1 byte content type + 16-byte tag + DTLS header | Architecture | TEST-DTLS-045 |

## Notes

- **DTLS vs TLS: both can coexist.** An application that needs HTTPS (TLS) and CoAP (DTLS) links both `tls.c` and `dtls.c` with a single shared `tls_crypto_t` backend.
- **DTLS 1.3 only.** DTLS 1.2 required a HelloVerifyRequest cookie exchange (to prevent amplification attacks) which adds complexity. DTLS 1.3 solves this differently and is simpler overall.
- **MTU discovery.** The stack does not implement PMTUD. The application sets `NET_DTLS_MAX_RECORD_PAYLOAD` at compile time. 1200 bytes is a conservative safe default (avoids fragmentation on most networks).
- **Connection ID extension** (RFC 9146) is tracked in the record header design (the `C` bit) but is not required in the initial implementation. It would be needed for NAT traversal / middlebox compatibility in future.
- **PSK strongly preferred for constrained devices.** Certificate mode requires ASN.1 DER parsing and asymmetric signature verification, adding significant code and latency.
