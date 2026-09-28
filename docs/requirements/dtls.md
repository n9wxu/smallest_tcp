# DTLS 1.3 Requirements

**Protocol:** Datagram Transport Layer Security 1.3  
**Primary RFC:** RFC 9147 — The Datagram Transport Layer Security (DTLS) Protocol Version 1.3  
**Supporting:** RFC 8446 (TLS 1.3, whose handshake DTLS reuses); [tls.md](tls.md) (REQ-TLS-*), which applies to DTLS except where this document says otherwise  
**Scope:** V1 (datagram security layer, Milestone 14)  
**Last updated:** 2026-09-27  
**Status:** Implemented (Milestone 14) — every MUST; REQ-DTLS-058 (SHOULD) is not.  Interoperates with wolfSSL 5.9.4.  See the traceability table at the end.

## Overview

DTLS 1.3 secures datagrams — CoAP, telemetry, device-to-device links over
UDP — with the TLS 1.3 handshake and a record layer that tolerates loss,
reordering and duplication.  smallest_tcp's DTLS shares the TLS handshake
code, key schedule and `tls_crypto_t` backend, and adds the datagram record
layer, reliability for the handshake, and ACKs.

Key design constraints:
- **DTLS 1.3 only** — no DTLS 1.2
- **Zero `malloc()`** — all state in the application-owned `dtls_conn_t` and its buffers
- **One handshake** — the TLS 1.3 roles, with the few differences RFC 9147 makes
- **The application moves datagrams** — no coupling to `udp.c`

See [docs/design/dtls.md](../design/dtls.md) for the design.

## Requirements

### Version and Handshake Format

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-001 | MUST | Implement DTLS 1.3 only: offer and accept only 0xfefc in `supported_versions`; refuse a peer without it with `protocol_version` | RFC 9147 §5.3 | TEST-DTLS-001 |
| REQ-DTLS-002 | MUST | ClientHello: `legacy_version` {254, 253}, an empty `legacy_session_id`, an empty `legacy_cookie` | RFC 9147 §5.3 | TEST-DTLS-002 |
| REQ-DTLS-003 | MUST | A server receiving a ClientHello whose `legacy_cookie` is not empty aborts with `illegal_parameter` | RFC 9147 §5.3 | TEST-DTLS-003 |
| REQ-DTLS-004 | MUST | ServerHello and HelloRetryRequest: `legacy_version` 0xfefd; the server does not echo `legacy_session_id` | RFC 9147 §5, §5.4 | TEST-DTLS-004 |
| REQ-DTLS-005 | MUST | No middlebox compatibility mode: no change_cipher_spec is sent | RFC 9147 §5 | TEST-DTLS-005 |
| REQ-DTLS-006 | MUST | HKDF-Expand-Label uses the label prefix "dtls13" | RFC 9147 §5.9 | TEST-DTLS-006 |
| REQ-DTLS-007 | MUST | The transcript is computed over TLS 1.3-style handshake messages, without `message_seq`, `fragment_offset` and `fragment_length` | RFC 9147 §5.2 | TEST-DTLS-007 |

### Record Layer

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-010 | MUST | Epoch-0 records are DTLSPlaintext: `legacy_record_version` {254, 253}, epoch 0, a 48-bit sequence number | RFC 9147 §4 | TEST-DTLS-010 |
| REQ-DTLS-011 | MUST | Protected records are DTLSCiphertext with the unified header (fixed bits 001, C, S, L, two epoch bits) | RFC 9147 §4 | TEST-DTLS-011 |
| REQ-DTLS-012 | MUST | Receive 8- and 16-bit sequence numbers, with and without the length field (a record without one takes the rest of the datagram) | RFC 9147 §4 | TEST-DTLS-012 |
| REQ-DTLS-013 | MUST | Without a negotiated Connection ID, reject records that carry one | RFC 9147 §9.1 | TEST-DTLS-013 |
| REQ-DTLS-014 | MUST | Demultiplex by the first byte: 21, 22, 26 → DTLSPlaintext; `001xxxxx` → DTLSCiphertext; anything else rejected as a record failing deprotection | RFC 9147 §4.1 | TEST-DTLS-014 |
| REQ-DTLS-015 | MUST | AEAD: the additional data is the header as sent before record number encryption; the nonce uses the 64-bit sequence number, not the epoch | RFC 9147 §4 | TEST-DTLS-015 |
| REQ-DTLS-016 | MUST | Record number encryption: mask = AES-ECB(sn_key, ciphertext[0..15]), sn_key = HKDF-Expand-Label(Secret, "sn", "", key_length); records with less than 16 bytes of ciphertext are rejected | RFC 9147 §4.2.3 | TEST-DTLS-016 |
| REQ-DTLS-017 | SHOULD | Reconstruct the sequence number as the one closest to the highest deprotected one plus one; the epoch from its low bits — the current one, else the most recent past epoch | RFC 9147 §4.2.2 | TEST-DTLS-017 |
| REQ-DTLS-018 | MUST | Epochs: 0 unprotected, 2 handshake, 3 the first application keys, one more for each KeyUpdate; never wrap | RFC 9147 §6.1, §4.2.1 | TEST-DTLS-018 |
| REQ-DTLS-019 | MUST | Every record fits in one datagram; several records may share one; the first byte of a datagram starts a record | RFC 9147 §4.3 | TEST-DTLS-019 |
| REQ-DTLS-020 | SHOULD | Size records to fit the PMTU estimate (the application's `mtu`) | RFC 9147 §4.3, §4.4 | TEST-DTLS-020 |
| REQ-DTLS-021 | SHOULD | Anti-replay: a sliding window per epoch, checked after deprotection and updated only for a record that deprotected | RFC 9147 §4.5.1 | TEST-DTLS-021 |
| REQ-DTLS-022 | SHOULD | Silently discard invalid records — bad format, length, MAC, unknown epoch, replay — without an alert | RFC 9147 §4.5.2 | TEST-DTLS-022 |
| REQ-DTLS-023 | MUST | Count received records that fail authentication; close the connection before the AEAD's limit (2^36 for AES-128-GCM) | RFC 9147 §4.5.3 | TEST-DTLS-023 |
| REQ-DTLS-024 | SHOULD | Update keys before protecting more records than the AEAD allows | RFC 9147 §4.5.3 | TEST-DTLS-024 |

### Handshake Reliability

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-030 | MUST | Handshake messages carry `message_seq`, `fragment_offset` and `fragment_length` | RFC 9147 §5.2 | TEST-DTLS-030 |
| REQ-DTLS-031 | MUST | Each side's first message has `message_seq` 0 and each new message the next value; a retransmission reuses its `message_seq` in new records | RFC 9147 §5.2 | TEST-DTLS-031 |
| REQ-DTLS-032 | MUST | Discard messages whose `message_seq` is below the next expected; queue or discard later ones | RFC 9147 §5.2 | TEST-DTLS-032 |
| REQ-DTLS-033 | MUST | Fragment handshake messages that do not fit a datagram into non-overlapping ranges, each in one datagram | RFC 9147 §5.5 | TEST-DTLS-033 |
| REQ-DTLS-034 | MUST | Reassemble fragments, including overlapping ranges; SHOULD abort with `illegal_parameter` if a retransmitted byte differs | RFC 9147 §5.5 | TEST-DTLS-034 |
| REQ-DTLS-035 | MUST | Do not change handshake message bytes when retransmitting | RFC 9147 §5.5 | TEST-DTLS-035 |
| REQ-DTLS-036 | MUST | Retransmit lost messages with the epoch and keys of the original transmission | RFC 9147 §4.2.1 | TEST-DTLS-036 |
| REQ-DTLS-037 | SHOULD | Retransmission timer: 1000 ms initially, doubling on each retransmission, up to no less than 60 s | RFC 9147 §5.8.2 | TEST-DTLS-037 |
| REQ-DTLS-038 | MUST | Retransmit the flight when the timer expires, and when the peer's retransmitted flight shows ours was not received | RFC 9147 §5.8.1 | TEST-DTLS-038 |
| REQ-DTLS-039 | MUST | A server that has finished answers a retransmission of the client's final flight with its ACK again | RFC 9147 §5.8.1 | TEST-DTLS-039 |
| REQ-DTLS-040 | MUST | Discard or buffer application data of epoch 3 and above until the peer's Finished has been received | RFC 9147 §5.8.1 | TEST-DTLS-040 |
| REQ-DTLS-041 | SHOULD | Send no more than 10 records in one transmission | RFC 9147 §5.8.3 | TEST-DTLS-041 |
| REQ-DTLS-042 | MUST | A client answers a HelloRetryRequest's cookie by echoing it in its second ClientHello | RFC 9147 §5.1 | TEST-DTLS-042 |
| REQ-DTLS-043 | SHOULD | A server performs a cookie exchange for every new handshake by default; it MAY be configured not to | RFC 9147 §5.1 | TEST-DTLS-043 |
| REQ-DTLS-044 | MUST | A server receiving a ClientHello with an invalid cookie aborts with `illegal_parameter` | RFC 9147 §5.1 | TEST-DTLS-044 |
| REQ-DTLS-045 | MUST | A client aborts with `unexpected_message` on a second HelloRetryRequest | RFC 9147 §5.1 | TEST-DTLS-045 |
| REQ-DTLS-046 | MUST | Alerts are not retransmitted | RFC 9147 §5.10 | TEST-DTLS-046 |
| REQ-DTLS-047 | MUST | Data received after a valid close_notify is ignored | RFC 9147 §5.10 | TEST-DTLS-047 |

### ACK

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-050 | MUST | ACK is content type 26, a list of RecordNumbers (64-bit epoch, 64-bit sequence number) in increasing order | RFC 9147 §7 | TEST-DTLS-050 |
| REQ-DTLS-051 | MUST | Never acknowledge a record whose handshake fragments were not processed or buffered | RFC 9147 §7 | TEST-DTLS-051 |
| REQ-DTLS-052 | MUST | Acknowledge the client's final flight and post-handshake messages (KeyUpdate, NewSessionTicket) | RFC 9147 §5.7, §7.1 | TEST-DTLS-052 |
| REQ-DTLS-053 | MUST | Send ACKs in an epoch no lower than that of the records acknowledged — after the handshake the highest | RFC 9147 §7 | TEST-DTLS-053 |
| REQ-DTLS-054 | MUST | Never acknowledge records of other content types, or records that cannot be deprotected | RFC 9147 §7.1 | TEST-DTLS-054 |
| REQ-DTLS-055 | SHOULD | Send an ACK when the incoming flight is disrupted (a message or fragment out of order) | RFC 9147 §7.1 | TEST-DTLS-055 |
| REQ-DTLS-056 | MUST | Cancel retransmission of a flight once all its messages are acknowledged, explicitly or by the peer's next flight | RFC 9147 §7.2 | TEST-DTLS-056 |
| REQ-DTLS-057 | MUST | Treat a record as acknowledged if it appears in any ACK | RFC 9147 §7.2 | TEST-DTLS-057 |
| REQ-DTLS-058 | SHOULD | After a partial ACK, retransmit only what is unacknowledged | RFC 9147 §7.2 | — |

### Key Update

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-060 | MUST | A KeyUpdate is acknowledged; no records with the new keys, and no further KeyUpdate, before its ACK | RFC 9147 §8 | TEST-DTLS-060 |
| REQ-DTLS-061 | MUST | Keep the peer's previous keys until a record under its new keys has been deprotected | RFC 9147 §8 | TEST-DTLS-061 |
| REQ-DTLS-062 | MUST | Never let the sending epoch exceed its limit; do not answer an update request that would | RFC 9147 §8 | TEST-DTLS-062 |

### Architecture

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DTLS-070 | MUST | DTLS and TLS share the handshake, the key schedule and the `tls_crypto_t` backend; the protocol code contains no cryptography (REQ-TLS-006) — the AES block for record numbers comes from the backend | Architecture | TEST-DTLS-070 |
| REQ-DTLS-071 | MUST | No dynamic allocation; all state in the application's `dtls_conn_t` and buffers | Architecture | TEST-DTLS-071 |
| REQ-DTLS-072 | MUST | A TLS-only build does not link the DTLS record layer, nor a DTLS-only build the TLS one | Architecture | TEST-DTLS-072 |
| REQ-DTLS-073 | MUST | The application moves datagrams; nothing in the DTLS code depends on `udp.c` | Architecture | TEST-DTLS-073 |

### Not Supported

Connection IDs (RFC 9146; the "connection_id" extension RFC 9147 §5.1 says a
client SHOULD offer), 0-RTT (epoch 1), DTLS 1.2, NewSessionTicket issuing,
post-handshake client authentication, backing off to smaller records after
retransmissions when the PMTU is unknown (§4.4 SHOULD), and retransmitting
only the unacknowledged part of a flight (REQ-DTLS-058).

## Traceability

Unit tests are in `tests/unit/test_dtls.c` (and the label prefix in
`test_tls_keys.c`, the AES block in `test_tls_crypto.c`); blackbox and
interop tests with wolfSSL in `tests/blackbox/test_dtls_conform.py` and
`test_dtls_client_conform.py` (the `test_dtls_0xx` and `test_dtls_cxx`
names below).

| Requirement | Status | Tests |
|---|---|---|
| REQ-DTLS-001 | ✅ | `test_refuse_dtls12`, `test_client_hello_format`, `test_server_hello_format`; `test_dtls_024_dtls12_refused`, every wolfSSL handshake |
| REQ-DTLS-002 | ✅ | `test_client_hello_format` |
| REQ-DTLS-003 | ✅ | `test_refuse_legacy_cookie`; `test_dtls_023_legacy_cookie_refused` |
| REQ-DTLS-004 | ✅ | `test_server_hello_format`; `test_dtls_020_cookie` |
| REQ-DTLS-005 | ✅ | `test_server_hello_format` (no change_cipher_spec in either direction) |
| REQ-DTLS-006 | ✅ | `test_dtls13_labels` (against `tests/tls/gen_dtls13.py`), `test_keys_from_secret` |
| REQ-DTLS-007 | ✅ | every handshake: both Finished MACs check out over the TLS-form transcript |
| REQ-DTLS-010 | ✅ | `test_client_hello_format` |
| REQ-DTLS-011 | ✅ | `test_seal_as_rfc_describes`, `test_epochs` |
| REQ-DTLS-012 | ✅ | `test_open_short_header`, `test_parse_uses_the_length` |
| REQ-DTLS-013 | ✅ | `test_parse_refuses` |
| REQ-DTLS-014 | ✅ | `test_parse_refuses`, `test_bad_records_dropped` |
| REQ-DTLS-015 | ✅ | `test_seal_as_rfc_describes` (the record rebuilt from the backend's primitives) |
| REQ-DTLS-016 | ✅ | `test_seal_as_rfc_describes`, `test_seal_masks_the_record_number`, `test_open_refuses_short_ciphertext` |
| REQ-DTLS-017 | ✅ | `test_seq_expand`, `test_open_reconstructs_the_number`, `test_late_record_of_old_epoch` |
| REQ-DTLS-018 | ✅ | `test_epochs`, `test_key_update` |
| REQ-DTLS-019 | ✅ | `test_small_mtu`, `test_epochs` (the ServerHello and a protected record in one datagram) |
| REQ-DTLS-020 | ✅ | `test_small_mtu`, `test_max_data` |
| REQ-DTLS-021 | ✅ | `test_replay_window`, `test_open_refuses_tampering` |
| REQ-DTLS-022 | ✅ | `test_bad_records_dropped`, `test_open_refuses_tampering`; `test_dtls_030_ignored` |
| REQ-DTLS-023 | ✅ | `bad_records` counted (`test_bad_records_dropped`); the connection ends at 2^32 − 1, below the RFC's 2^36 |
| REQ-DTLS-024 | ✅ | `test_key_update_at_record_limit` |
| REQ-DTLS-030, -031 | ✅ | `test_client_hello_format`, `test_timer` (a retransmission: the same message_seq, a new record) |
| REQ-DTLS-032 | ✅ | `test_duplicates`, `test_fragments_in_any_order`; later messages are dropped (the MAY) |
| REQ-DTLS-033 | ✅ | `test_small_mtu`; `test_dtls_008_fragmented_flight`, `test_dtls_c05_small_datagrams` |
| REQ-DTLS-034 | ✅ | `test_fragments_in_any_order`, `test_retransmission_cut_differently`, `test_refuse_changed_bytes` |
| REQ-DTLS-035 | ✅ | `test_timer` (the retransmitted message byte for byte) |
| REQ-DTLS-036 | ✅ | `test_each_datagram_lost`, `test_finished_lost` (the Finished resent under the handshake keys after the application keys took over) |
| REQ-DTLS-037 | ✅ | `test_timer` |
| REQ-DTLS-038 | ✅ | `test_timer`, `test_each_datagram_lost`, `test_finished_lost`; `test_dtls_021_same_hello_same_cookie` |
| REQ-DTLS-039 | ✅ | `test_ack_lost`, `test_key_update_ack_lost` |
| REQ-DTLS-040 | ✅ | `test_data_before_finished_dropped` |
| REQ-DTLS-041 | ✅ | `test_records_per_transmission` |
| REQ-DTLS-042 | ✅ | `test_handshake` (every handshake has the cookie exchange); `test_dtls_c02_cookie` (wolfSSL's cookie) |
| REQ-DTLS-043 | ✅ | `test_server_hello_format`, `test_no_cookie`; `test_dtls_020_cookie`, `test_dtls_009_no_cookie` |
| REQ-DTLS-044 | ✅ | `test_refuse_wrong_cookie`; `test_dtls_022_wrong_cookie_refused` |
| REQ-DTLS-045 | ✅ | the TLS client's rule (a second HelloRetryRequest is `unexpected_message`, `test_tls_client`) |
| REQ-DTLS-046 | ✅ | `test_alert_not_retransmitted`, `test_close_notify` |
| REQ-DTLS-047 | ✅ | `test_close_notify` |
| REQ-DTLS-050 | ✅ | `test_last_flight_acknowledged`, `test_new_session_ticket_acknowledged` (the ACK opened and read) |
| REQ-DTLS-051 | ✅ | only records whose fragments were placed are noted (`note_record()`); `test_plaintext_after_keys_ignored` |
| REQ-DTLS-052 | ✅ | `test_last_flight_acknowledged`, `test_new_session_ticket_acknowledged`, `test_key_update` |
| REQ-DTLS-053 | ✅ | `test_last_flight_acknowledged` (epoch 3), `test_ack_on_disruption` (epoch 2) |
| REQ-DTLS-054 | ✅ | only handshake records are noted |
| REQ-DTLS-055 | ✅ | `test_ack_on_disruption` |
| REQ-DTLS-056 | ✅ | `test_last_flight_acknowledged`, `test_each_datagram_lost` (every flight answered) |
| REQ-DTLS-057 | ✅ | `test_key_update_waits_for_flight` (an ACK of the first transmission, late) |
| REQ-DTLS-058 | — | not implemented (SHOULD): the timer resends the whole flight |
| REQ-DTLS-060 | ✅ | `test_key_update`, `test_key_update_ack_lost`, `test_key_update_waits_for_flight`; `test_dtls_004_key_update_from_client`, `test_dtls_c03`, `test_dtls_c04` |
| REQ-DTLS-061 | ✅ | `test_late_record_of_old_epoch`, `test_key_update` |
| REQ-DTLS-062 | ✅ | `test_last_epoch` |
| REQ-DTLS-070 | ✅ | `dtls.c` calls only the backend; `test_init_checks` (a backend without `aes_block` refused) |
| REQ-DTLS-071 | ✅ | no allocator calls in `dtls.c` |
| REQ-DTLS-072 | ✅ | `make arm-check-links` (in `arm-size-all`, CI job `arm-size`); `SMALLEST_TCP_DTLS=OFF` builds and passes |
| REQ-DTLS-073 | ✅ | `dtls.c` includes no network header |
