# DTLS 1.3 Requirements

**Protocol:** Datagram Transport Layer Security 1.3  
**Primary RFC:** RFC 9147 — The Datagram Transport Layer Security (DTLS) Protocol Version 1.3  
**Supporting:** RFC 8446 (TLS 1.3, whose handshake DTLS reuses); [tls.md](tls.md) (REQ-TLS-*), which applies to DTLS except where this document says otherwise  
**Scope:** V1 (the security layer over datagrams)  
**Status:** Implemented, client and server; interoperates with wolfSSL 5.9.4.  Deviations are marked in their rows: REQ-DTLS-008 (no `connection_id`), REQ-DTLS-025 (no back-off to smaller records), REQ-DTLS-041 (no limit of records per transmission), REQ-DTLS-048 (the timer does not follow the round-trip time), REQ-DTLS-051 (one case of a record acknowledged in part) and REQ-DTLS-058 (a partial ACK does not narrow the retransmission).

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

The Test ID column names the tests that verify each row: `itest_dtls_*` in
`tests/integration/itest_dtls.c` (the stack through its API, against a peer
written from the RFC, and its two roles over a lossy network), `test_*` in
`tests/unit/test_dtls.c` and `test_tls_keys.c`, and `test_dtls_0xx` /
`test_dtls_cxx` in `tests/blackbox/test_dtls{,_client}_conform.py` (wolfSSL
against the demos).

## Requirements

### Version and Handshake Format

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-001 | MUST | Implement DTLS 1.3 only: offer and accept only 0xfefc in `supported_versions`; a server refuses a ClientHello without it with `protocol_version`, a client a ServerHello selecting another version with `illegal_parameter` | RFC 9147 §5.3, RFC 8446 §4.2.1 | itest_dtls_001_dtls12_client_refused, itest_dtls_001_dtls12_server_refused, itest_dtls_002_client_hello, itest_dtls_004_handshake_with_the_server, test_refuse_dtls12, test_dtls_024_dtls12_refused |
| REQ-DTLS-002 | MUST | ClientHello: `legacy_version` {254, 253}, an empty `legacy_session_id`, an empty `legacy_cookie` | RFC 9147 §5.3 | itest_dtls_002_client_hello, test_client_hello_format |
| REQ-DTLS-003 | MUST | A server receiving a ClientHello whose `legacy_cookie` is not empty aborts with `illegal_parameter` | RFC 9147 §5.3 | itest_dtls_003_legacy_cookie_refused, test_refuse_legacy_cookie, test_dtls_023_legacy_cookie_refused |
| REQ-DTLS-004 | MUST | ServerHello and HelloRetryRequest: `legacy_version` 0xfefd; the server does not echo `legacy_session_id` | RFC 9147 §5, §5.4 | itest_dtls_004_handshake_with_the_server, test_server_hello_format, test_dtls_020_cookie |
| REQ-DTLS-005 | MUST NOT | Send change_cipher_spec (there is no middlebox compatibility mode) | RFC 9147 §5 | itest_dtls_004_handshake_with_the_server, test_server_hello_format |
| REQ-DTLS-006 | MUST | HKDF-Expand-Label uses the label prefix "dtls13" | RFC 9147 §5.9 | itest_dtls_004_handshake_with_the_server, itest_dtls_042_cookie_echoed, test_dtls13_labels |
| REQ-DTLS-007 | MUST | The transcript is computed over TLS 1.3-style handshake messages, without `message_seq`, `fragment_offset` and `fragment_length` | RFC 9147 §5.2 | itest_dtls_004_handshake_with_the_server, itest_dtls_042_cookie_echoed |
| REQ-DTLS-008 | SHOULD | A client that does not want a Connection ID still offers the `connection_id` extension — **deviation:** the extension is not offered; Connection IDs (RFC 9146) are not supported | RFC 9147 §5.1 | — (deviation) |

### Record Layer

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-010 | MUST | Epoch-0 records are DTLSPlaintext: `legacy_record_version` {254, 253} (ignored on receipt), epoch 0, a 48-bit sequence number | RFC 9147 §4 | itest_dtls_002_client_hello, itest_dtls_004_handshake_with_the_server, test_client_hello_format |
| REQ-DTLS-011 | MUST | Protected records are DTLSCiphertext with the unified header (fixed bits 001, C, S, L, two epoch bits) | RFC 9147 §4 | itest_dtls_011_application_data_record, itest_dtls_004_handshake_with_the_server, test_seal_as_rfc_describes |
| REQ-DTLS-012 | MUST | Receive 8- and 16-bit sequence numbers, with and without the length field (a record without one takes the rest of the datagram) | RFC 9147 §4 | itest_dtls_012_short_header_received, test_open_short_header |
| REQ-DTLS-013 | MUST | Without a negotiated Connection ID, reject records that carry one | RFC 9147 §9.1 | itest_dtls_022_invalid_records_dropped_silently, test_parse_refuses |
| REQ-DTLS-014 | MUST | Demultiplex by the first byte: 21, 22, 26 → DTLSPlaintext; `001xxxxx` → DTLSCiphertext; anything else rejected as a record failing deprotection | RFC 9147 §4.1 | itest_dtls_022_invalid_records_dropped_silently, test_parse_refuses, test_dtls_030_ignored |
| REQ-DTLS-015 | MUST | AEAD: the additional data is the header as sent before record number encryption; the nonce uses the 64-bit sequence number, not the epoch | RFC 9147 §4 | itest_dtls_011_application_data_record, itest_dtls_004_handshake_with_the_server, test_seal_as_rfc_describes |
| REQ-DTLS-016 | MUST | Record number encryption: mask = AES-ECB(sn_key, ciphertext[0..15]), sn_key = HKDF-Expand-Label(Secret, "sn", "", key_length); records with less than 16 bytes of ciphertext are rejected | RFC 9147 §4.2.3 | itest_dtls_011_application_data_record, itest_dtls_022_invalid_records_dropped_silently, test_seal_as_rfc_describes, test_open_refuses_short_ciphertext |
| REQ-DTLS-017 | SHOULD | Reconstruct the sequence number as the one closest to the highest deprotected one plus one; the epoch from its low bits — the current one, else the most recent past epoch | RFC 9147 §4.2.2 | itest_dtls_012_short_header_received, test_seq_expand |
| REQ-DTLS-018 | MUST | Epochs: 0 unprotected, 2 handshake, 3 the first application keys, one more for each KeyUpdate; never wrap | RFC 9147 §6.1, §4.2.1 | itest_dtls_004_handshake_with_the_server, itest_dtls_060_key_update_of_ours, test_epochs |
| REQ-DTLS-019 | MUST | Every record fits in one datagram; several records may share one; the first byte of a datagram starts a record | RFC 9147 §4.3 | itest_dtls_004_handshake_with_the_server, itest_dtls_033_flight_in_fragments, itest_dtls_012_short_header_received, itest_dtls_073_datagrams_moved_by_the_application, test_small_mtu |
| REQ-DTLS-020 | SHOULD | Size records to fit the PMTU estimate (the application's `mtu`) | RFC 9147 §4.3, §4.4 | itest_dtls_033_flight_in_fragments, itest_dtls_034_fragments_in_reverse_order, test_small_mtu |
| REQ-DTLS-021 | MUST | Anti-replay: a record whose sequence number duplicates one already received in its epoch is not accepted; the receive window (a sliding window per epoch, checked after deprotection — both SHOULD) is updated only for a record that deprotected | RFC 9147 §4.5.1 | itest_dtls_021_replayed_record_dropped, itest_dtls_039_ack_again_for_a_repeated_finished, itest_dtls_032_every_datagram_twice, test_replay_window |
| REQ-DTLS-022 | SHOULD | Silently discard invalid records — bad format, length, MAC, unknown epoch, replay — without an alert | RFC 9147 §4.5.2 | itest_dtls_022_invalid_records_dropped_silently, test_bad_records_dropped, test_dtls_030_ignored, itest_dtls_022_malformed_fragments_and_acks_dropped |
| REQ-DTLS-023 | MUST | Count received records that fail authentication; close the connection (SHOULD) before the AEAD's limit, 2^36 for AES-128-GCM — the count is one for the connection, and ends it at 2^32 − 1 | RFC 9147 §4.5.3 | itest_dtls_022_invalid_records_dropped_silently, test_bad_records_dropped |
| REQ-DTLS-024 | SHOULD | Update keys before protecting more records than the AEAD allows | RFC 9147 §4.5.3 | test_key_update_at_record_limit |
| REQ-DTLS-025 | SHOULD | When retransmissions go unanswered and the PMTU is unknown, back off to a smaller record size — **deviation:** every transmission uses the application's `mtu` | RFC 9147 §4.4 | — (deviation) |

### Handshake Reliability

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-030 | MUST | Handshake messages carry `message_seq`, `fragment_offset` and `fragment_length` | RFC 9147 §5.2 | itest_dtls_002_client_hello, itest_dtls_004_handshake_with_the_server, test_client_hello_format |
| REQ-DTLS-031 | MUST | Each side's first message has `message_seq` 0 and each new message the next value; a retransmission reuses its `message_seq` in new records | RFC 9147 §5.2 | itest_dtls_002_client_hello, itest_dtls_004_handshake_with_the_server, itest_dtls_042_cookie_echoed, itest_dtls_038_flight_retransmitted_by_the_timer, test_timer |
| REQ-DTLS-032 | MUST | Discard messages whose `message_seq` is below the next expected; queue or discard later ones (they are discarded) | RFC 9147 §5.2 | itest_dtls_038_flight_again_for_a_repeated_client_hello, itest_dtls_039_ack_again_for_a_repeated_finished, itest_dtls_032_every_datagram_twice, test_duplicates |
| REQ-DTLS-033 | MUST | Fragment handshake messages that do not fit a datagram into non-overlapping ranges, each in one datagram | RFC 9147 §5.5 | itest_dtls_033_flight_in_fragments, test_small_mtu, test_dtls_008_fragmented_flight |
| REQ-DTLS-034 | MUST | Reassemble fragments, including overlapping ranges; SHOULD abort with `illegal_parameter` if a retransmitted byte differs | RFC 9147 §5.5 | itest_dtls_034_fragments_reassembled, itest_dtls_034_fragments_in_reverse_order, test_fragments_in_any_order, test_refuse_changed_bytes |
| REQ-DTLS-035 | MUST NOT | Change handshake message bytes when retransmitting | RFC 9147 §5.5 | itest_dtls_038_flight_retransmitted_by_the_timer, test_timer |
| REQ-DTLS-036 | MUST | Retransmit lost messages with the epoch and keys of the original transmission | RFC 9147 §4.2.1 | itest_dtls_038_flight_retransmitted_by_the_timer, itest_dtls_036_finished_resent_under_its_own_keys, test_each_datagram_lost |
| REQ-DTLS-037 | SHOULD | Retransmission timer: 1000 ms initially, doubling on each retransmission, up to no less than 60 s | RFC 9147 §5.8.2 | itest_dtls_038_flight_retransmitted_by_the_timer, test_timer |
| REQ-DTLS-038 | MUST | Retransmit the flight when the timer expires, and when the peer's retransmitted flight shows ours was not received | RFC 9147 §5.8.1 | itest_dtls_038_flight_retransmitted_by_the_timer, itest_dtls_038_flight_again_for_a_repeated_client_hello, itest_dtls_038_each_datagram_lost_once, itest_dtls_036_finished_resent_under_its_own_keys, test_finished_lost |
| REQ-DTLS-039 | MUST | A server that has finished answers a retransmission of the client's final flight with its ACK again | RFC 9147 §5.8.1 | itest_dtls_039_ack_again_for_a_repeated_finished, itest_dtls_038_each_datagram_lost_once, test_ack_lost |
| REQ-DTLS-040 | MUST | Discard or buffer application data of epoch 3 and above until the peer's Finished has been received (it is discarded) | RFC 9147 §5.8.1 | itest_dtls_040_no_application_data_before_finished, test_data_before_finished_dropped |
| REQ-DTLS-041 | SHOULD NOT | Send more than 10 records in one transmission — **deviation:** no limit is enforced; a transmission is the whole flight, which is within 10 records unless a long flight (an RSA chain) is cut for a very small MTU | RFC 9147 §5.8.3 | itest_dtls_033_flight_in_fragments, test_records_per_transmission |
| REQ-DTLS-042 | MUST | A client answers a HelloRetryRequest's cookie by echoing it in its second ClientHello | RFC 9147 §5.1 | itest_dtls_042_cookie_echoed, itest_dtls_042_cookie_and_group_in_one_hello_retry, test_dtls_c02_cookie |
| REQ-DTLS-043 | SHOULD | A server performs a cookie exchange for every new handshake by default; it MAY be configured not to | RFC 9147 §5.1 | itest_dtls_043_cookie_exchange_by_default, itest_dtls_004_handshake_with_the_server, test_no_cookie, test_dtls_009_no_cookie |
| REQ-DTLS-044 | MUST | A server receiving a ClientHello with an invalid cookie aborts with `illegal_parameter` | RFC 9147 §5.1 | itest_dtls_044_wrong_cookie_refused, test_refuse_wrong_cookie, test_dtls_022_wrong_cookie_refused |
| REQ-DTLS-045 | MUST | A client aborts with `unexpected_message` on a second HelloRetryRequest | RFC 9147 §5.1 | itest_dtls_045_second_hello_retry_refused |
| REQ-DTLS-046 | MUST NOT | Retransmit alerts | RFC 9147 §5.10 | itest_dtls_046_alert_not_retransmitted, itest_dtls_047_close_notify, test_alert_not_retransmitted |
| REQ-DTLS-047 | MUST | Data received after a valid close_notify is ignored | RFC 9147 §5.10 | itest_dtls_047_close_notify, test_close_notify, itest_dtls_047_close_notify_ends_retransmission |
| REQ-DTLS-048 | SHOULD | Keep the timer value until a message is acknowledged without retransmission, then set it to 1.5 times the measured round-trip time — **deviation:** the round-trip time is not measured; every flight starts from 1000 ms | RFC 9147 §5.8.2 | — (deviation) |

### ACK

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-050 | MUST | ACK is content type 26, a list of RecordNumbers (64-bit epoch, 64-bit sequence number) in increasing order | RFC 9147 §7 | itest_dtls_052_final_flight_acknowledged, itest_dtls_039_ack_again_for_a_repeated_finished, test_last_flight_acknowledged, itest_dtls_050_ack_lists_what_fits |
| REQ-DTLS-051 | MUST NOT | Acknowledge a record whose handshake fragments were not processed or buffered — **deviation:** a record is acknowledged once its first fragment has been taken; if a later message of the same record then finds no room behind unread application data, the record stays acknowledged.  This arises only for a NewSessionTicket that follows a shorter one in its record, and a client ignores tickets | RFC 9147 §7 | itest_dtls_051_only_records_taken_are_acknowledged, itest_dtls_051_record_with_a_fragment_not_taken, itest_dtls_051_record_acknowledged_in_part |
| REQ-DTLS-052 | MUST | Acknowledge the client's final flight and post-handshake messages (KeyUpdate, NewSessionTicket) | RFC 9147 §5.7, §7.1 | itest_dtls_052_final_flight_acknowledged, itest_dtls_054_only_handshake_records_acknowledged, itest_dtls_061_key_update_from_the_peer, test_new_session_ticket_acknowledged |
| REQ-DTLS-053 | MUST | Send ACKs in an epoch no lower than that of the records acknowledged — after the handshake the highest | RFC 9147 §7 | itest_dtls_052_final_flight_acknowledged, itest_dtls_051_only_records_taken_are_acknowledged, itest_dtls_061_key_update_from_the_peer, test_last_flight_acknowledged |
| REQ-DTLS-054 | MUST NOT | Acknowledge records of other content types, or records that cannot be deprotected | RFC 9147 §7.1 | itest_dtls_054_only_handshake_records_acknowledged, itest_dtls_022_invalid_records_dropped_silently |
| REQ-DTLS-055 | SHOULD | Send an ACK when the incoming flight is disrupted (a message or fragment out of order) | RFC 9147 §7.1 | itest_dtls_051_only_records_taken_are_acknowledged, test_ack_on_disruption |
| REQ-DTLS-056 | MUST | Cancel retransmission of a flight once all its messages are acknowledged — explicitly, or implicitly by any record of the peer's next flight | RFC 9147 §7.2 | itest_dtls_052_final_flight_acknowledged, itest_dtls_057_record_acknowledged_by_any_ack, itest_dtls_056_flight_answered_by_a_fragment_of_the_next, itest_dtls_038_each_datagram_lost_once, itest_dtls_036_finished_resent_under_its_own_keys |
| REQ-DTLS-057 | MUST | Treat a record as acknowledged if it appears in any ACK | RFC 9147 §7.2 | itest_dtls_057_record_acknowledged_by_any_ack, itest_dtls_060_key_update_of_ours |
| REQ-DTLS-058 | SHOULD | After a partial ACK, retransmit only what is unacknowledged — **deviation:** the timer resends the whole flight; a flight is a few datagrams | RFC 9147 §7.2 | — (deviation) |

### Key Update

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DTLS-060 | MUST | A KeyUpdate is acknowledged; no records with the new keys, and no further KeyUpdate, before its ACK | RFC 9147 §8, §5.8.4 | itest_dtls_060_key_update_of_ours, itest_dtls_061_key_update_from_the_peer, test_key_update_waits_for_flight, test_dtls_004_key_update_from_client, itest_dtls_060_key_update_waits_for_the_flight |
| REQ-DTLS-061 | MUST | Keep the peer's previous keys until a record under its new keys has been deprotected | RFC 9147 §8 | itest_dtls_061_key_update_from_the_peer, test_late_record_of_old_epoch |
| REQ-DTLS-062 | MUST NOT | Let the sending epoch exceed its limit (the 16 bits kept here); an update request that would is not answered | RFC 9147 §8 | test_last_epoch |

### Architecture

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DTLS-070 | MUST | DTLS and TLS share the handshake, the key schedule and the `tls_crypto_t` backend; the protocol code contains no cryptography (REQ-TLS-006) — the AES block for record numbers comes from the backend, and `dtls_init()` refuses a backend without it | Architecture | itest_dtls_070_cryptography_from_the_backend, itest_dtls_070_fragment_limit_and_psk, itest_dtls_070_untrusted_chain_refused, itest_dtls_070_authentic_but_wrong, itest_dtls_070_alert_from_a_refusing_server |
| REQ-DTLS-071 | MUST | No dynamic allocation; all state in the application's `dtls_conn_t` and buffers | Architecture | itest_dtls_071_state_in_the_connection, itest_dtls_071_buffers_too_small, itest_dtls_071_api_checks |
| REQ-DTLS-072 | MUST NOT | Link the DTLS record layer into a TLS-only build, or the TLS one into a DTLS-only build | Architecture | — (not observable: what a build links shows in no call and no datagram; `make arm-check-links` checks the Cortex-M0 objects) |
| REQ-DTLS-073 | MUST | The application moves datagrams; nothing in the DTLS code depends on `udp.c` | Architecture | itest_dtls_073_datagrams_moved_by_the_application |

### Not Supported

Connection IDs (RFC 9146; REQ-DTLS-008), 0-RTT (epoch 1), DTLS 1.2,
NewSessionTicket issuing, post-handshake client authentication, backing off
to smaller records after retransmissions when the PMTU is unknown
(REQ-DTLS-025), a timer that follows the round-trip time (REQ-DTLS-048), and
retransmitting only the unacknowledged part of a flight (REQ-DTLS-058).
