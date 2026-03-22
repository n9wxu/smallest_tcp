# TLS 1.3 Requirements

**Protocol:** Transport Layer Security 1.3  
**Primary RFC:** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3  
**Supporting:** RFC 6066 — TLS Extensions (SNI, max_fragment_length)  
**Scope:** V1 (TCP security layer, Milestone 12)  
**Last updated:** 2026-03-21  
**Status:** Preliminary — requirements captured pre-implementation

## Overview

TLS 1.3 provides encryption, integrity, and mutual or server-only authentication
for TCP connections.  The smallest_tcp TLS layer provides the record protocol and
handshake state machine; **all cryptographic primitives are delegated to a
pluggable `tls_crypto_t` backend** supplied by the application (mbedTLS, wolfSSL,
BearSSL, or custom).

Key design constraints:
- **TLS 1.3 only** — no negotiation down to TLS 1.2 or earlier
- **Zero `malloc()`** — all state in application-owned `tls_conn_t` structs
- **Single mandatory cipher suite** — `TLS_AES_128_GCM_SHA256` (RFC 8446 Appendix B.4)
- **PSK mode preferred for MCU-to-MCU** — eliminates certificate chain parsing

See [docs/design/tls.md](../design/tls.md) for the full design.

## Requirements

### Version and Cipher Suite

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-001 | MUST | Implement TLS 1.3 only (RFC 8446); reject connection attempts from peers offering only TLS 1.2 or earlier | RFC 8446 §4.2.1 | TEST-TLS-001 |
| REQ-TLS-002 | MUST | Support cipher suite `TLS_AES_128_GCM_SHA256` (mandatory in RFC 8446) | RFC 8446 Appendix B.4 | TEST-TLS-002 |
| REQ-TLS-003 | SHOULD | Support cipher suite `TLS_CHACHA20_POLY1305_SHA256` as optional compile-time addition | RFC 8446 Appendix B.4 | TEST-TLS-003 |
| REQ-TLS-004 | MUST | Support key exchange via ECDHE with x25519 curve (mandatory in RFC 8446) | RFC 8446 §4.2.7 | TEST-TLS-004 |
| REQ-TLS-005 | SHOULD | Support key exchange via ECDHE with P-256 curve | RFC 8446 §4.2.7 | TEST-TLS-005 |

### Pluggable Crypto Backend

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-TLS-006 | MUST | All cryptographic operations (ECDH, HKDF, AES-GCM, SHA-256, signature verify) MUST be performed through the `tls_crypto_t` vtable; `tls.c` MUST NOT contain any cryptographic implementations | Architecture | TEST-TLS-006 |
| REQ-TLS-007 | MUST | `tls_crypto_t` MUST be provided by the application at `tls_init()` time and remain valid for the lifetime of the connection | Architecture | TEST-TLS-007 |
| REQ-TLS-008 | MUST | `tls.c` MUST NOT call `malloc`, `calloc`, or `realloc` | Architecture | TEST-TLS-008 |
| REQ-TLS-009 | MUST | All connection state MUST reside in the application-provided `tls_conn_t` struct | Architecture | TEST-TLS-009 |

### Handshake — Client Role

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-010 | MUST | Client MUST send ClientHello with `supported_versions` extension advertising TLS 1.3 only | RFC 8446 §4.1.2 | TEST-TLS-010 |
| REQ-TLS-011 | MUST | ClientHello MUST include `key_share` extension with ECDHE public key | RFC 8446 §4.2.8 | TEST-TLS-011 |
| REQ-TLS-012 | MUST | ClientHello MUST include `signature_algorithms` extension | RFC 8446 §4.2.3 | TEST-TLS-012 |
| REQ-TLS-013 | SHOULD | ClientHello SHOULD include `server_name` (SNI) extension when a hostname is provided | RFC 6066 §3 | TEST-TLS-013 |
| REQ-TLS-014 | MUST | Client MUST verify server certificate chain against the configured CA certificate (in CERT auth mode) | RFC 8446 §4.4.2 | TEST-TLS-014 |
| REQ-TLS-015 | MUST | Client MUST verify server CertificateVerify signature | RFC 8446 §4.4.3 | TEST-TLS-015 |
| REQ-TLS-016 | MUST | Client MUST verify server Finished MAC | RFC 8446 §4.4.4 | TEST-TLS-016 |
| REQ-TLS-017 | MUST | Client MUST send Finished after verifying server Finished | RFC 8446 §4.4.4 | TEST-TLS-017 |

### Handshake — Server Role

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-018 | MUST | Server MUST send ServerHello with `supported_versions` extension confirming TLS 1.3 | RFC 8446 §4.1.3 | TEST-TLS-018 |
| REQ-TLS-019 | MUST | Server MUST send EncryptedExtensions after ServerHello | RFC 8446 §4.3.1 | TEST-TLS-019 |
| REQ-TLS-020 | MUST | Server MUST send Certificate and CertificateVerify in CERT auth mode | RFC 8446 §4.4.2, §4.4.3 | TEST-TLS-020 |
| REQ-TLS-021 | MUST | Server MUST send Finished | RFC 8446 §4.4.4 | TEST-TLS-021 |
| REQ-TLS-022 | MUST | Server MUST verify client Finished MAC | RFC 8446 §4.4.4 | TEST-TLS-022 |

### PSK Mode (Pre-Shared Key)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-023 | MUST | Support PSK-only handshake mode via `pre_shared_key` and `psk_key_exchange_modes` extensions | RFC 8446 §2.2, §4.2.9, §4.2.11 | TEST-TLS-023 |
| REQ-TLS-024 | MUST | In PSK mode, Certificate and CertificateVerify MUST NOT be sent or required | RFC 8446 §2.2 | TEST-TLS-024 |
| REQ-TLS-025 | MUST | PSK identity and key MUST be provided via `tls_cert_t` by the application; no hardcoded keys | Architecture | TEST-TLS-025 |

### Record Protocol

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-026 | MUST | Use TLS 1.3 record format: 5-byte header (ContentType + legacy_version + length) | RFC 8446 §5.1 | TEST-TLS-026 |
| REQ-TLS-027 | MUST | Encrypt all post-handshake records with AES-128-GCM; AAD = 5-byte record header | RFC 8446 §5.2 | TEST-TLS-027 |
| REQ-TLS-028 | MUST | Nonce = base IV XOR'd with the 64-bit record sequence number (zero-padded to 12 bytes) | RFC 8446 §5.3 | TEST-TLS-028 |
| REQ-TLS-029 | MUST | Increment record sequence number for each encrypted record sent or received | RFC 8446 §5.3 | TEST-TLS-029 |
| REQ-TLS-030 | MUST | Abort connection on AEAD decryption failure (send alert `bad_record_mac`) | RFC 8446 §5.2 | TEST-TLS-030 |
| REQ-TLS-031 | MUST | Support `max_fragment_length` extension (RFC 6066) to limit record size for small buffers; minimum supported value: 512 bytes | RFC 6066 §4 | TEST-TLS-031 |

### Key Derivation (RFC 8446 §7)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-032 | MUST | Derive handshake and application traffic secrets using HKDF-SHA-256 as specified in RFC 8446 §7.1 | RFC 8446 §7.1 | TEST-TLS-032 |
| REQ-TLS-033 | MUST | Derive write key (16 bytes) and write IV (12 bytes) for each traffic direction from the traffic secret | RFC 8446 §7.3 | TEST-TLS-033 |
| REQ-TLS-034 | MUST | Maintain a running SHA-256 transcript hash over all handshake messages | RFC 8446 §4.4.1 | TEST-TLS-034 |

### Alert Protocol

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-035 | MUST | Send `close_notify` alert on graceful shutdown | RFC 8446 §6.1 | TEST-TLS-035 |
| REQ-TLS-036 | MUST | On receiving a fatal alert, transition to TLS_ERROR and notify application via event callback | RFC 8446 §6 | TEST-TLS-036 |
| REQ-TLS-037 | MUST | Send appropriate fatal alert on detected errors (e.g. `decrypt_error`, `bad_record_mac`, `illegal_parameter`) | RFC 8446 §6 | TEST-TLS-037 |

### Event Notification

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-TLS-038 | MUST | Fire `TLS_EVT_CONNECTED` event when handshake completes successfully | Architecture | TEST-TLS-038 |
| REQ-TLS-039 | MUST | Fire `TLS_EVT_CLOSED` event on clean shutdown (close_notify received) | Architecture | TEST-TLS-039 |
| REQ-TLS-040 | MUST | Fire `TLS_EVT_ERROR` event on fatal alert or protocol error | Architecture | TEST-TLS-040 |

### Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-041 | MUST | Application provides RX buffer at `tls_init()`; minimum size = maximum negotiated record length + 5-byte header + 16-byte AEAD tag | RFC 8446 §5.1 | TEST-TLS-041 |
| REQ-TLS-042 | MUST | Verify RX buffer is sufficient at `tls_init()`; return error if too small | Architecture | TEST-TLS-042 |
| REQ-TLS-043 | MUST | `tls_write()` output buffer must be sized by application to hold the encrypted record (plaintext + 1 content-type byte + 16-byte tag + 5-byte header) | Architecture | TEST-TLS-043 |

## Notes

- **No TLS 1.2 downgrade.** TLS 1.3 removes the version negotiation vulnerability. Rejecting 1.2 avoids the complexity of supporting two different key derivation paths and cipher suites.
- **PSK preferred for IoT.** Certificate-based authentication requires parsing ASN.1 DER and verifying an asymmetric signature. PSK reduces flash footprint by ~10–20 KB depending on the crypto library.
- **The crypto backend is not part of smallest_tcp.** The project does not depend on any specific crypto library. Tested backends: mbedTLS 3.x, wolfSSL, BearSSL.
- **SNI is optional** — useful when connecting to cloud services, not needed for direct MCU-to-MCU connections.
- **No session tickets** in the initial implementation — they would require storing session state across reboots (e.g., in flash). May be added in a future revision.
