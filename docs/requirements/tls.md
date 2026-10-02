# TLS 1.3 Requirements

**Protocol:** Transport Layer Security 1.3  
**Primary RFC:** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3  
**Supporting:** RFC 6066 — TLS Extensions (server_name, max_fragment_length)  
**Scope:** V1 (the security layer over TCP)  
**Status:** Implemented, client and server.  Deviations are marked in their rows: REQ-TLS-003 (ChaCha20-Poly1305), REQ-TLS-063 (rsa_pkcs1_sha256 not advertised), REQ-TLS-064 (signature_algorithms_cert, the server's server_name).

## Overview

TLS 1.3 provides encryption, integrity, and mutual or server-only authentication
for TCP connections.  The smallest_tcp TLS layer provides the record protocol and
handshake state machine; **all cryptographic primitives are delegated to a
pluggable `tls_crypto_t` backend** supplied by the application (mbedTLS, wolfSSL,
BearSSL, or custom).

Key design constraints:
- **TLS 1.3 only** — no negotiation down to TLS 1.2 or earlier
- **Zero `malloc()`** — all state in application-owned `tls_conn_t` structs
- **Single mandatory cipher suite** — `TLS_AES_128_GCM_SHA256` (RFC 8446 §9.1)
- **PSK mode preferred for MCU-to-MCU** — eliminates certificate chain parsing

See [docs/design/tls.md](../design/tls.md) for the full design.

The Test ID column names the tests that verify each row: `itest_tls_*` in
`tests/integration/itest_tls.c` (the stack through its API, against a peer
written from the RFC), `test_*` in `tests/unit/test_tls_{crypto,keys,server,client}.c`,
and `test_tls_0xx` / `test_tls_cxx` in `tests/blackbox/test_tls{,_client}_conform.py`
(OpenSSL and Python's ssl against the demos).

## Requirements

### Version and Cipher Suite

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-001 | MUST | Implement TLS 1.3 only (RFC 8446): a server refuses a ClientHello that does not offer TLS 1.3 in `supported_versions` with `protocol_version`; a client refuses a ServerHello without `supported_versions` with `protocol_version`, and one selecting a version it did not offer with `illegal_parameter` | RFC 8446 §4.2.1, Architecture | itest_tls_001_tls12_client_refused, itest_tls_001_tls12_server_refused, test_refuse_no_supported_versions, test_tls_010_tls12_refused, test_tls_c12_tls12_server |
| REQ-TLS-002 | MUST | Support cipher suite `TLS_AES_128_GCM_SHA256`; a ClientHello that does not offer it is refused with `handshake_failure` | RFC 8446 §9.1, §4.1.1 | itest_tls_018_server_flight_with_a_psk, itest_tls_037_alert_says_what_was_wrong, test_refuse_no_common_suite, test_tls_001_handshake, test_tls_033_nothing_in_common |
| REQ-TLS-003 | SHOULD | Support cipher suites `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` — **deviation:** `TLS_AES_128_GCM_SHA256` is the only suite; one suite keeps the backend interface to one hash and one AEAD | RFC 8446 §9.1 | — (deviation) |
| REQ-TLS-004 | SHOULD | Support key exchange with X25519 | RFC 8446 §9.1, §4.2.7 | itest_tls_004_psk_with_x25519, itest_tls_011_client_key_share_used, test_tls_030_groups |
| REQ-TLS-005 | MUST | Support key exchange with secp256r1 (NIST P-256) | RFC 8446 §9.1, §4.2.7 | itest_tls_005_secp256r1, test_tls_030_groups, test_tls_c31_hello_retry |
| REQ-TLS-063 | MUST | Support digital signatures with `rsa_pkcs1_sha256` (for certificates), `rsa_pss_rsae_sha256` (for CertificateVerify and certificates) and `ecdsa_secp256r1_sha256` — **deviation:** `signature_algorithms` lists `ecdsa_secp256r1_sha256` and `rsa_pss_rsae_sha256` only; the Mbed TLS backend still verifies a chain whose certificates are signed with RSA PKCS #1 v1.5, but the client does not advertise it | RFC 8446 §9.1 | itest_tls_010_client_hello, itest_tls_014_certificate_chain_and_name |
| REQ-TLS-064 | MUST | Implement the extensions `supported_versions`, `cookie`, `signature_algorithms`, `signature_algorithms_cert`, `supported_groups`, `key_share` and `server_name` — **deviation:** `signature_algorithms_cert` is neither sent nor read (`signature_algorithms` covers certificates too, as §4.2.3 allows), and a server does not read `server_name`: it has one identity | RFC 8446 §9.2 | itest_tls_010_client_hello, itest_tls_049_hello_retry_request_answered |

### Pluggable Crypto Backend

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-TLS-006 | MUST | All cryptographic operations (hashing, HMAC, HKDF, AES-GCM, ECDH, signing and verifying, the certificate chain check, random numbers) are performed through the `tls_crypto_t` vtable; the protocol code contains no cryptographic implementations | Architecture | itest_tls_006_cryptography_from_the_backend, itest_tls_006_backend_failure_ends_the_handshake |
| REQ-TLS-007 | MUST | The application provides the `tls_crypto_t` in the `tls_config_t` given to `tls_init()`, which refuses a configuration without one; it remains valid for the lifetime of the connection | Architecture | itest_tls_041_receive_buffer_holds_a_record, test_init_and_accept_checks |
| REQ-TLS-008 | MUST NOT | Call `malloc`, `calloc` or `realloc` from the protocol code | Architecture | — (not observable: an allocation that never happens shows neither in the API nor on the wire; the Cortex-M0 objects of the TLS sources reference no allocator) |
| REQ-TLS-009 | MUST | All connection state resides in the application-provided `tls_conn_t` struct and its two buffers | Architecture | itest_tls_009_state_in_the_connection |
| REQ-TLS-065 | MUST | `tls_release()` ends a connection in any state: it wipes the connection's secrets and keys and both buffers, and leaves the connection idle with its configuration, buffers and callback, ready for the next handshake | Architecture | itest_tls_065_release_wipes_and_readies |
| REQ-TLS-066 | MUST | A call the connection's state does not allow — `tls_accept()` or `tls_connect()` unless idle, an incomplete server configuration, `tls_write()` or `tls_key_update()` unless open for writing, `tls_close()` before a handshake or after an error — returns an error and changes nothing | Architecture | itest_tls_066_calls_out_of_place_refused |

### Handshake — Client Role

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-010 | MUST | Client sends ClientHello with `legacy_version` 0x0303 and a `supported_versions` extension advertising TLS 1.3 only | RFC 8446 §4.1.2, §4.2.1 | itest_tls_010_client_hello, test_client_hello_contents |
| REQ-TLS-011 | MUST | ClientHello includes a `key_share` extension with an (EC)DHE public key, and `supported_groups` — unless the client is configured to use its PSK without (EC)DHE | RFC 8446 §4.2.8, §9.2 | itest_tls_010_client_hello, itest_tls_011_client_key_share_used, test_client_hello_contents |
| REQ-TLS-012 | MUST | ClientHello includes the `signature_algorithms` extension | RFC 8446 §4.2.3 | itest_tls_010_client_hello, test_client_hello_contents |
| REQ-TLS-013 | SHOULD | ClientHello includes `server_name` (SNI) when a host name is provided; a literal IPv4 or IPv6 address is not sent as one | RFC 6066 §3 | itest_tls_010_client_hello, test_client_hello_contents |
| REQ-TLS-014 | MUST | Client verifies the server's certificate chain against its trust anchors, and the name it connected to, before completing the handshake (certificate authentication) | RFC 8446 §4.4.2 | itest_tls_014_certificate_from_the_peer, itest_tls_014_certificate_chain_and_name, test_refuse_wrong_name, test_tls_c10_wrong_name, test_tls_c11_untrusted |
| REQ-TLS-015 | MUST | Client verifies the server's CertificateVerify signature; if it fails, `decrypt_error` | RFC 8446 §4.4.3 | itest_tls_014_certificate_from_the_peer, itest_tls_062_server_certificate_checked, itest_tls_015_certificate_verify_checked, test_scripted_refusals_certificate_verify |
| REQ-TLS-016 | MUST | Client verifies the server's Finished MAC; if it fails, `decrypt_error` | RFC 8446 §4.4.4 | itest_tls_016_client_finished_after_the_servers, itest_tls_016_wrong_server_finished_refused, test_scripted_refusals_finished, itest_tls_014_certificate_from_the_peer |
| REQ-TLS-017 | MUST | Client sends its Finished after verifying the server's Finished | RFC 8446 §4.4.4 | itest_tls_016_client_finished_after_the_servers, itest_tls_014_certificate_from_the_peer |
| REQ-TLS-046 | MUST | A server echoes the ClientHello's `legacy_session_id`; a client refuses a ServerHello whose `legacy_session_id_echo` is not what it sent with `illegal_parameter` | RFC 8446 §4.1.3 | itest_tls_046_session_id_echoed, itest_tls_046_session_id_echo_checked, test_tls_031_default_client_hello, itest_tls_046_hello_retry_in_compatibility_mode |
| REQ-TLS-049 | MUST | A client answers a HelloRetryRequest with a second ClientHello carrying the HelloRetryRequest's cookie in a `cookie` extension; it aborts with `illegal_parameter` if the HelloRetryRequest would change nothing in the ClientHello or selects a group it already sent a share of or did not offer, and with `unexpected_message` on a second HelloRetryRequest | RFC 8446 §4.1.4, §4.2.2, §4.2.8 | itest_tls_049_hello_retry_request_answered, itest_tls_049_hello_retry_request_must_change_something, test_tls_c31_hello_retry |
| REQ-TLS-053 | MUST | No extension appears twice in one extension block (`illegal_parameter`); a client aborts with `unsupported_extension` on an extension in a ServerHello, HelloRetryRequest or EncryptedExtensions that answers none it sent, and with `illegal_parameter` on an extension it knows in a message it is not specified for | RFC 8446 §4.2, §4.3.1 | itest_tls_037_alert_says_what_was_wrong, itest_tls_053_extension_not_offered_refused, itest_tls_053_encrypted_extension_not_offered_refused, itest_tls_053_extension_in_the_wrong_message |
| REQ-TLS-060 | MUST | A client checks a ServerHello that selects its PSK: the selected identity is one it offered, and a `key_share` is present if the modes it offered require one; otherwise `illegal_parameter` | RFC 8446 §4.2.11 | itest_tls_060_psk_server_hello_consistent |
| REQ-TLS-062 | MUST | A client aborts with `decode_error` on an empty server Certificate, and with `illegal_parameter` on a CertificateVerify whose signature scheme it did not offer | RFC 8446 §4.4.2.4, §4.4.3 | itest_tls_062_server_certificate_checked, test_scripted_refusals_certificate, test_scripted_refusals_certificate_verify |
| REQ-TLS-067 | MUST | A client that the server asks for a certificate (CertificateRequest) and that has none sends a Certificate message with an empty `certificate_list`, then its Finished | RFC 8446 §4.4.2 | itest_tls_067_certificate_request_answered_with_none, test_tls_c20_certificate_request_optional |

### Handshake — Server Role

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-018 | MUST | Server sends ServerHello with `legacy_version` 0x0303 and a `supported_versions` extension selecting TLS 1.3 | RFC 8446 §4.1.3 | itest_tls_018_server_flight_with_a_psk, itest_tls_018_handshake_over_tcp, test_tls_001_handshake, itest_tls_037_server_hello_refusals |
| REQ-TLS-019 | MUST | Server sends EncryptedExtensions immediately after ServerHello, under the handshake keys | RFC 8446 §4.3.1 | itest_tls_018_server_flight_with_a_psk, test_tls_001_handshake |
| REQ-TLS-020 | MUST | Server sends Certificate and CertificateVerify when it authenticates with a certificate | RFC 8446 §4.4.2, §4.4.3 | itest_tls_014_certificate_chain_and_name, test_handshake_ecdsa, test_tls_001_handshake, itest_tls_020_flight_through_a_small_transmit_buffer |
| REQ-TLS-021 | MUST | Server sends Finished | RFC 8446 §4.4.4 | itest_tls_018_server_flight_with_a_psk, test_tls_001_handshake |
| REQ-TLS-022 | MUST | Server verifies the client's Finished MAC; if it fails, `decrypt_error` | RFC 8446 §4.4.4 | itest_tls_022_client_finished_completes_the_handshake, itest_tls_022_wrong_client_finished_refused, test_bad_client_finished, itest_tls_022_only_finished_after_the_flight |
| REQ-TLS-050 | MUST | A server refuses a ClientHello whose `legacy_compression_methods` is not exactly one zero byte with `illegal_parameter` | RFC 8446 §4.1.2 | itest_tls_037_alert_says_what_was_wrong |
| REQ-TLS-052 | MUST | A server aborts with `missing_extension` on a ClientHello that has no `pre_shared_key` and lacks `signature_algorithms` or `supported_groups`, or that has one of `supported_groups` and `key_share` without the other | RFC 8446 §9.2 | itest_tls_052_mandatory_extensions, itest_tls_052_groups_and_key_share_together |
| REQ-TLS-054 | MUST | Validate the peer's key share: a secp256r1 point not on the curve, or an X25519 share giving the all-zero secret, aborts the handshake (`illegal_parameter`) | RFC 8446 §4.2.8.2, §7.4.2 | itest_tls_037_alert_says_what_was_wrong, test_p256_rejects_point_off_curve |
| REQ-TLS-061 | MUST | A server that shares a group with the client but received no usable `key_share` for it answers with a HelloRetryRequest selecting the group; a second ClientHello still without that share is `illegal_parameter` | RFC 8446 §4.1.1, §4.1.4 | itest_tls_061_hello_retry_request_sent, itest_tls_005_secp256r1, test_tls_035_hello_retry, itest_tls_046_hello_retry_in_compatibility_mode |
| REQ-TLS-068 | MUST | A server that does not accept early data ignores the `early_data` extension, answers with the usual handshake, and skips early-data records only up to the amount it allowed — none: no PSK of this server permits early data, so a record after the ClientHello that fails deprotection ends the connection with `bad_record_mac` | RFC 8446 §4.2.10 | itest_tls_068_early_data_not_accepted |
| REQ-TLS-069 | MUST | A server ignores the cipher suites, the extensions and the `supported_versions` entries of a ClientHello that it does not recognize | RFC 8446 §4.1.2, §4.2.1 | itest_tls_018_server_flight_with_a_psk, test_skips_unknown_share |

### PSK Mode (Pre-Shared Key)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-023 | MUST | Support handshakes authenticated by a pre-shared key, with (EC)DHE (`psk_dhe_ke`) and without (`psk_ke`), via the `pre_shared_key` and `psk_key_exchange_modes` extensions | RFC 8446 §2.2, §4.2.9, §4.2.11; Architecture | itest_tls_018_server_flight_with_a_psk, itest_tls_004_psk_with_x25519, itest_tls_023_client_offers_the_psk, itest_tls_023_psk_between_our_roles, test_tls_050_psk_openssl, test_tls_c42_psk_ke_openssl |
| REQ-TLS-024 | MUST | In PSK mode, Certificate and CertificateVerify are neither sent nor accepted | RFC 8446 §2.2, §4.4.2 | itest_tls_018_server_flight_with_a_psk, itest_tls_024_no_certificate_after_a_psk, test_tls_050_psk_openssl |
| REQ-TLS-025 | MUST | The PSK and its identity are provided by the application in `tls_config_t`; no key is built in | Architecture | itest_tls_025_psk_from_the_configuration, itest_tls_023_client_offers_the_psk |
| REQ-TLS-051 | MUST | A server aborts the handshake on a `pre_shared_key` that is not the last extension of the ClientHello (`illegal_parameter`), one offered without `psk_key_exchange_modes` (`missing_extension`), and one whose binder for the selected identity does not validate (`decrypt_error`) | RFC 8446 §4.2.9, §4.2.11 | itest_tls_037_alert_says_what_was_wrong, test_tls_051_psk_wrong_key |

### Record Protocol

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-026 | MUST | Use the TLS 1.3 record format: a 5-byte header (ContentType, `legacy_record_version` 0x0303, length); a receiver ignores the version field | RFC 8446 §5.1 | itest_tls_026_records_both_ways, itest_tls_010_client_hello, itest_tls_018_handshake_over_tcp, test_seal_server_application_records |
| REQ-TLS-027 | MUST | Protect every record after the hellos with AES-128-GCM: the outer type `application_data`, the content followed by its real type, additional data = the 5-byte record header | RFC 8446 §5.2 | itest_tls_026_records_both_ways, itest_tls_030_record_that_fails_authentication, test_seal_server_application_records |
| REQ-TLS-028 | MUST | Nonce = the write IV XORed with the 64-bit record sequence number, padded on the left to 12 bytes | RFC 8446 §5.3 | itest_tls_026_records_both_ways, test_open_wrong_sequence |
| REQ-TLS-029 | MUST | The sequence number starts at 0 for each key and is incremented for each record sent or received under it | RFC 8446 §5.3 | itest_tls_026_records_both_ways, itest_tls_030_record_that_fails_authentication, test_open_wrong_sequence |
| REQ-TLS-030 | MUST | Terminate the connection with `bad_record_mac` when a record fails AEAD decryption | RFC 8446 §5.2 | itest_tls_030_record_that_fails_authentication, test_bad_record_mac, test_tls_012_tampered_record |
| REQ-TLS-031 | MUST | Support the `max_fragment_length` extension to limit record size for small buffers, down to 512 bytes: a server grants a valid request and refuses any other value with `illegal_parameter`; a client refuses an answer that differs from its request with `illegal_parameter`; neither side then sends a record with more content | RFC 6066 §4, Architecture | itest_tls_031_max_fragment_length_granted, itest_tls_031_max_fragment_length_asked, test_tls_036_max_fragment_length, test_tls_c05_max_fragment_length, itest_tls_031_long_message_in_small_records |
| REQ-TLS-045 | MUST | Drop an unprotected `change_cipher_spec` record holding the single byte 0x01 received after the first ClientHello and before the peer's Finished; any other `change_cipher_spec` aborts the handshake with `unexpected_message` | RFC 8446 §5 | itest_tls_045_change_cipher_spec_only_in_the_handshake, itest_tls_046_session_id_echoed, test_tls_031_default_client_hello |
| REQ-TLS-047 | MUST | Terminate with `record_overflow` on a record whose length exceeds 2^14 (2^14 + 256 for a protected one), and with `unexpected_message` on a record of an unknown content type | RFC 8446 §5, §5.1, §5.2 | itest_tls_047_record_too_long_or_unknown, test_tls_011_not_tls, itest_tls_047_plaintext_too_long, itest_tls_057_records_out_of_place |
| REQ-TLS-056 | MUST | A handshake message before a key change ends its record; if it does not, `unexpected_message` | RFC 8446 §5.1 | itest_tls_044_key_update_malformed |
| REQ-TLS-057 | MUST | A handshake message split across records is not interleaved with records of another type, and application data is not accepted before the handshake completes; either is `unexpected_message` | RFC 8446 §5.1, §4.4.4 | itest_tls_057_no_data_inside_a_handshake_message, itest_tls_057_records_out_of_place |
| REQ-TLS-059 | MUST | Strip the zero padding of a decrypted record; a record with no non-zero byte (no content type), and a handshake or alert record with no content, are `unexpected_message` | RFC 8446 §5.4 | itest_tls_059_padding_and_no_content_type, itest_tls_059_empty_alert_record, itest_tls_057_records_out_of_place |

### Key Derivation (RFC 8446 §7)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-032 | MUST | Derive handshake and application traffic secrets using HKDF-SHA-256 as specified in RFC 8446 §7.1 | RFC 8446 §7.1 | itest_tls_004_psk_with_x25519, itest_tls_011_client_key_share_used, test_handshake_traffic_secrets, test_application_traffic_secrets |
| REQ-TLS-033 | MUST | Derive the write key (16 bytes) and write IV (12 bytes) for each traffic direction from its traffic secret | RFC 8446 §7.3 | itest_tls_026_records_both_ways, test_traffic_keys |
| REQ-TLS-034 | MUST | Maintain a running SHA-256 transcript hash over all handshake messages, a HelloRetryRequest's first ClientHello replaced by its `message_hash` | RFC 8446 §4.4.1 | itest_tls_018_server_flight_with_a_psk, itest_tls_016_client_finished_after_the_servers, itest_tls_061_hello_retry_request_sent, test_hrr_transcript |

### Key Update

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-044 | MUST | A received KeyUpdate moves the receiving keys to the next generation; if it says `update_requested`, a KeyUpdate with `update_not_requested` is sent before the next application data record, and the sending keys move on after it; a `request_update` that is neither value is `illegal_parameter` | RFC 8446 §4.6.3, §7.2 | itest_tls_044_key_update_requested_by_the_peer, itest_tls_044_key_update_of_ours, itest_tls_044_key_update_malformed, test_tls_034_key_update, test_tls_c06_key_update, itest_tls_044_key_update_waits_for_room |
| REQ-TLS-058 | SHOULD | Update the sending keys before the AEAD's limit of records under one key (2^24.5 for AES-GCM) | RFC 8446 §5.5 | test_key_update_by_itself |

### Alert Protocol

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TLS-035 | MUST | Send a `close_notify` alert before closing the write side of the connection (`tls_close()`) | RFC 8446 §6.1 | itest_tls_035_close_notify, itest_tls_035_close_notify_before_fin, test_tls_005_close_notify |
| REQ-TLS-036 | MUST | Treat every received alert other than `close_notify` and `user_canceled` as fatal, whatever its level: the connection moves to `TLS_STATE_ERROR` and the application is notified through the event callback | RFC 8446 §6, §6.2 | itest_tls_036_fatal_alert_received, itest_tls_039_client_told_of_close_and_alert |
| REQ-TLS-037 | MUST | Send the fatal alert RFC 8446 names for a detected error (e.g. `decode_error`, `decrypt_error`, `bad_record_mac`, `illegal_parameter`) | RFC 8446 §6.2 | itest_tls_037_alert_says_what_was_wrong, itest_tls_022_wrong_client_finished_refused, itest_tls_030_record_that_fails_authentication, itest_tls_037_server_hello_refusals, itest_tls_037_new_session_ticket |
| REQ-TLS-048 | MUST | Ignore data received after a closure alert | RFC 8446 §6.1 | itest_tls_035_close_notify |
| REQ-TLS-055 | MUST | After sending or receiving a fatal alert, close the connection at once — nothing more is sent or read — and forget its secrets and keys | RFC 8446 §6.2 | itest_tls_036_fatal_alert_received |

### Event Notification

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-TLS-038 | MUST | Fire `TLS_EVT_CONNECTED` when the handshake completes successfully | Architecture | itest_tls_022_client_finished_completes_the_handshake, itest_tls_016_client_finished_after_the_servers |
| REQ-TLS-039 | MUST | Fire `TLS_EVT_CLOSED` on clean shutdown (`close_notify` received) | Architecture | itest_tls_035_close_notify, itest_tls_039_client_told_of_close_and_alert |
| REQ-TLS-040 | MUST | Fire `TLS_EVT_ERROR` on a fatal alert, sent or received | Architecture | itest_tls_022_wrong_client_finished_refused, itest_tls_036_fatal_alert_received, itest_tls_037_alert_says_what_was_wrong |

### Buffer Requirements

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-TLS-041 | MUST | The application provides the receive buffer at `tls_init()`; it holds a whole record — the 5-byte header, the content, the content type byte and the 16-byte tag.  A record or handshake message it cannot hold ends the connection with `record_overflow` | Architecture | itest_tls_041_receive_buffer_holds_a_record, test_refuse_record_larger_than_buffer, test_tls_004_full_size_record |
| REQ-TLS-042 | MUST | `tls_init()` returns an error for a receive or transmit buffer under 256 bytes | Architecture | itest_tls_041_receive_buffer_holds_a_record, test_init_and_accept_checks |
| REQ-TLS-043 | MUST | `tls_write()` takes only as much plaintext as fits the transmit buffer as a record: the plaintext, the 5-byte header, the content type byte and the 16-byte tag | Architecture | itest_tls_043_write_within_the_transmit_buffer, test_write_partial_when_tx_full, test_write_needs_room_for_a_byte |

## Notes

- **No TLS 1.2 downgrade.** TLS 1.3 removes the version negotiation vulnerability. Rejecting 1.2 avoids the complexity of supporting two different key derivation paths and cipher suites.
- **PSK preferred for IoT.** Certificate-based authentication requires parsing ASN.1 DER and verifying an asymmetric signature. PSK reduces flash footprint by ~10–20 KB depending on the crypto library.
- **The crypto backend is not part of smallest_tcp's protocol code.** `tls.c` depends on no crypto library; the project ships one backend, on Mbed TLS 3.6 (`tls_crypto_mbedtls.c`).  Another (wolfSSL, BearSSL, a hardware engine) needs only the `tls_crypto_t` functions.
- **SNI is optional** — useful when connecting to cloud services, not needed for direct MCU-to-MCU connections.
- **No session tickets** — they would require storing session state across reboots (e.g., in flash).  The server issues none; the client ignores NewSessionTicket, but can use a resumption PSK obtained elsewhere (`psk_resumption`).
- **No 0-RTT, no client certificates, no post-handshake authentication.**  A client asked for a certificate answers with an empty Certificate; a server never asks.
- **Buffers.**  The configuration struct is `tls_config_t` (crypto backend, certificate chain and key, PSK, groups, max_fragment_length).  A record's size is only known when it arrives, so `tls_init()` checks only the 256-byte floor, and a record too large for the receive buffer ends the connection with `record_overflow` (REQ-TLS-041, -042).
