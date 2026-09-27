# TLS 1.3 Requirements

**Protocol:** Transport Layer Security 1.3  
**Primary RFC:** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3  
**Supporting:** RFC 6066 — TLS Extensions (SNI, max_fragment_length)  
**Scope:** V1 (TCP security layer, Milestone 13)  
**Last updated:** 2026-09-26  
**Status:** Implemented (Milestone 13) — every MUST, and REQ-TLS-005 and -013; REQ-TLS-003 (ChaCha20-Poly1305, SHOULD) is not.  See the traceability table at the end.

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
- **The crypto backend is not part of smallest_tcp's protocol code.** `tls.c` depends on no crypto library; the project ships one backend, on Mbed TLS 3.6 (`tls_crypto_mbedtls.c`).  Another (wolfSSL, BearSSL, a hardware engine) needs only the `tls_crypto_t` functions.
- **SNI is optional** — useful when connecting to cloud services, not needed for direct MCU-to-MCU connections.
- **No session tickets** — they would require storing session state across reboots (e.g., in flash).  The server issues none; the client ignores NewSessionTicket, but can use a resumption PSK obtained elsewhere (`psk_resumption`).
- **As implemented:** the configuration struct is `tls_config_t` (crypto backend, certificate chain and key, PSK, groups, max_fragment_length) rather than `tls_cert_t`, and it carries the `tls_crypto_t` pointer (REQ-TLS-007, -025).  `tls_init()` refuses buffers under 256 bytes; since a record's size is only known when it arrives, a record too large for the receive buffer ends the connection with `record_overflow` (REQ-TLS-041/042).

## Traceability

Unit tests are in `tests/unit/test_tls_{crypto,keys,server,client}.c`, blackbox tests in `tests/blackbox/test_tls{,_client}_conform.py` and `test_https_conform.py`.

| Requirement | Status | Tests |
|---|---|---|
| REQ-TLS-001 | ✅ | `test_refuse_no_supported_versions`, `test_refuse_tls12_only`; client: scripted `no_versions`; `test_tls_010_tls12_refused`, `test_tls_c12_tls12_server` |
| REQ-TLS-002 | ✅ | RFC 8448 records (`test_seal_*`); `test_refuse_no_common_suite`; `test_tls_033_nothing_in_common[chacha20,aes256]` |
| REQ-TLS-003 | — | not implemented (SHOULD) |
| REQ-TLS-004 | ✅ | `test_ecdhe_shared_secret`, `test_handshake_ecdsa`; `test_tls_030_groups[X25519]` |
| REQ-TLS-005 | ✅ | `test_p256_shared_secret`, `test_handshake_p256`, `test_hrr_p256_only_server`, `test_p256_client`; `test_tls_030_groups[P-256]`, `test_tls_c31_hello_retry` |
| REQ-TLS-006 | ✅ | tls.c, tls_keys.c, tls_server.c and tls_client.c contain no cryptography (their Cortex-M0 objects reference only each other, `mem*`/`strlen` and libgcc's switch helpers); the fixed-randomness backends in `test_tls_server` show every random value comes through the vtable |
| REQ-TLS-007 | ✅ | `tls_config_t.crypto`; `test_init_and_accept_checks` |
| REQ-TLS-008 | ✅ | no allocator calls in tls.c (same object check) |
| REQ-TLS-009 | ✅ | all state in `tls_conn_t`; client and server connections run side by side in `test_tls_client` |
| REQ-TLS-010..012 | ✅ | `test_client_hello_contents` |
| REQ-TLS-013 | ✅ | `test_client_hello_contents` (DNS names only); `test_tls_c01_echo` (the server sees it) |
| REQ-TLS-014 | ✅ | `test_refuse_wrong_name`, `test_refuse_wrong_address`, `test_refuse_untrusted_chain`, `test_refuse_without_trust_anchors`; `test_tls_c10_wrong_name`, `test_tls_c11_untrusted` |
| REQ-TLS-015 | ✅ | `test_scripted_refusals_certificate_verify` |
| REQ-TLS-016 | ✅ | `test_scripted_refusals_finished` |
| REQ-TLS-017 | ✅ | `client_flight_ok()` in `test_scripted_handshake` |
| REQ-TLS-018..021 | ✅ | the scripted client's checks in every server handshake test (`peer_read_sh`, `peer_read_flight`); `test_rfc8448_server_hello` |
| REQ-TLS-022 | ✅ | `test_bad_client_finished`, `test_refuse_long_finished` |
| REQ-TLS-023 | ✅ | `test_psk_dhe`, `test_psk_ke`, `test_psk_*` (server and client), `test_rfc8448_psk_server_hello`; `test_tls_050..053`, `test_tls_c40..c43` |
| REQ-TLS-024 | ✅ | PSK flights without Certificate (`peer_read_flight`); scripted `psk_cert` refused |
| REQ-TLS-025 | ✅ | `tls_config_t.psk`, `psk_id` |
| REQ-TLS-026..029 | ✅ | `test_seal_*`, `test_open_*`, `test_nonce_uses_all_sequence_bytes`, `test_open_wrong_sequence` |
| REQ-TLS-030 | ✅ | `test_open_tampered`, `test_bad_record_mac`; `test_tls_012_tampered_record` |
| REQ-TLS-031 | ✅ | `test_mfl_*`, `test_mfl_small_rx_buffer`, `test_scripted_mfl`; `test_tls_036_max_fragment_length`, `test_tls_c05_max_fragment_length` |
| REQ-TLS-032..034 | ✅ | `test_tls_keys` against RFC 8448 §3–§5 |
| REQ-TLS-035 | ✅ | `test_close_notify_both_ways`, `test_close_notify_from_client`; `test_tls_005_close_notify` |
| REQ-TLS-036 | ✅ | `test_fatal_alert_from_client`, `test_client_alert_in_handshake` |
| REQ-TLS-037 | ✅ | every refusal test checks the alert sent |
| REQ-TLS-038..040 | ✅ | event checks in `handshake()`, `refused()`, `test_close_notify_both_ways` |
| REQ-TLS-041..042 | ✅ (as noted) | `test_init_and_accept_checks`, `test_refuse_record_larger_than_buffer` |
| REQ-TLS-043 | ✅ | `test_write_partial_when_tx_full`, `test_write_needs_room_for_a_byte` |
