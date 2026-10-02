# TCP Requirements

**Protocol:** Transmission Control Protocol  
**Primary RFC:** RFC 9293 — Transmission Control Protocol (TCP) [2022]  
**Supporting:**  
- RFC 5681 — TCP Congestion Control  
- RFC 6298 — Computing TCP's Retransmission Timer  
- RFC 7323 — TCP Extensions for High Performance (Window Scale, Timestamps)  
- RFC 1122 — Requirements for Internet Hosts (§4.2)  
- RFC 6528 — Defending against Sequence Number Attacks  
- RFC 5961 — Improving TCP's Robustness to Blind In-Window Attacks  
- RFC 1191 — Path MTU Discovery  
- RFC 8200 §8.1 — IPv6 Upper-Layer Checksum  

**Scope:** IPv4 and IPv6 (the same TCP, another pseudo-header)

## Overview

TCP provides reliable, ordered, byte-stream delivery over IP. This stack implements TCP per the consolidated specification in RFC 9293 with application-managed connection state, a pluggable buffer abstraction layer, and minimal memory footprint.

## Segment Format

```
Offset  Size  Field
  0      2    Source Port
  2      2    Destination Port
  4      4    Sequence Number
  8      4    Acknowledgment Number
 12      4b   Data Offset (header length in 32-bit words, minimum 5)
 12      4b   Reserved (must be zero)
 13      1b   CWR flag
 13      1b   ECE flag
 13      1b   URG flag
 13      1b   ACK flag
 13      1b   PSH flag
 13      1b   RST flag
 13      1b   SYN flag
 13      1b   FIN flag
 14      2    Window Size
 16      2    Checksum
 18      2    Urgent Pointer
 20     0-40  Options (if Data Offset > 5)
```

Minimum header: 20 bytes (Data Offset = 5). Maximum header: 60 bytes (Data Offset = 15).

## Requirements

RFC 9293's requirement numbers (MUST-n, SHLD-n, MAY-n) are given in
brackets.  A requirement the stack leaves out on purpose keeps its RFC
level and says so (**deviation**); its test verifies what the stack does
instead.

### Connection State Machine (RFC 9293 §3.3.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-001 | MUST | Implement the TCP state machine with states: CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT | RFC 9293 §3.3.2 | itest_tcp_002_passive_open, itest_tcp_003_active_open, itest_tcp_005_active_close, itest_tcp_006_passive_close, itest_tcp_007_simultaneous_close |
| REQ-TCP-002 | MUST | Support passive open (LISTEN → SYN-RECEIVED → ESTABLISHED) | RFC 9293 §3.5 | itest_tcp_002_passive_open, test_tcp_003_three_way_handshake |
| REQ-TCP-003 | MUST | Support active open (CLOSED → SYN-SENT → ESTABLISHED) | RFC 9293 §3.5 | itest_tcp_003_active_open |
| REQ-TCP-004 | MUST | Support simultaneous open (SYN-SENT → SYN-RECEIVED → ESTABLISHED) [MUST-10] | RFC 9293 §3.5 | itest_tcp_004_simultaneous_open |
| REQ-TCP-005 | MUST | Support graceful close via FIN exchange (ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT → CLOSED) | RFC 9293 §3.6 | itest_tcp_005_active_close, test_tcp_005_graceful_close_active |
| REQ-TCP-006 | MUST | Support passive close (ESTABLISHED → CLOSE-WAIT → LAST-ACK → CLOSED) | RFC 9293 §3.6 | itest_tcp_006_passive_close, test_tcp_006_fin_ack_correct_seq |
| REQ-TCP-007 | MUST | Support simultaneous close (FIN-WAIT-1 → CLOSING → TIME-WAIT → CLOSED) | RFC 9293 §3.6 | itest_tcp_007_simultaneous_close |
| REQ-TCP-008 | MUST | TIME-WAIT lasts 2 × MSL (Maximum Segment Lifetime) [MUST-13] | RFC 9293 §3.6.1 | itest_tcp_005_active_close |
| REQ-TCP-009 | SHOULD | MSL is 2 minutes (`NET_DEFAULT_TCP_MSL_MS`; a build may shorten it) | RFC 9293 §3.4.2, Architecture | itest_tcp_005_active_close |

### Connection Management — Application Interface

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-010 | MUST | Application provides `tcp_conn_t` structure for each connection (application-managed) | Architecture | itest_tcp_002_passive_open |
| REQ-TCP-011 | MUST | Provide `tcp_conn_init()`, which validates its arguments and leaves the connection CLOSED | Architecture | itest_tcp_011_conn_init_validates |
| REQ-TCP-012 | MUST | `tcp_listen()` — put connection in LISTEN state on specified port | RFC 9293 §3.9.1.1, §3.10.1 | itest_tcp_002_passive_open, itest_tcp_011_conn_init_validates |
| REQ-TCP-013 | MUST | `tcp_connect()` — initiate active open to specified IP:port; on a connection in use — neither CLOSED nor LISTEN — it is refused ("connection already exists": `NET_ERR_BUSY`) | RFC 9293 §3.9.1.1, §3.10.1 | itest_tcp_003_active_open, itest_tcp_013_connect_on_a_live_connection, itest_tcp_011_conn_init_validates |
| REQ-TCP-014 | MUST | `tcp_send()` — queue data for transmission, in ESTABLISHED and CLOSE-WAIT; before the connection is open it is refused, not queued | RFC 9293 §3.9.1.2, §3.10.2 | itest_tcp_014_send_and_receive, test_tcp_014_data_echo_seq_ack |
| REQ-TCP-015 | MUST | `tcp_close()` — initiate graceful close | RFC 9293 §3.9.1.4, §3.10.4 | itest_tcp_015_close_in_listen, itest_tcp_015_close_in_syn_sent, itest_tcp_015_close_in_syn_received, itest_tcp_005_active_close, itest_tcp_006_passive_close |
| REQ-TCP-016 | MUST | `tcp_abort()` — send RST where the peer holds the connection open, and close at once | RFC 9293 §3.9.1.6, §3.10.5 | itest_tcp_016_abort_before_open_sends_nothing, itest_tcp_016_abort_in_syn_received_sends_rst |
| REQ-TCP-017 | MUST | `tcp_status()` — return current connection state | RFC 9293 §3.9.1.5, §3.10.6 | itest_tcp_011_conn_init_validates |

### Segment Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-018 | MUST | Verify TCP checksum (pseudo-header + header + data); discard on failure [MUST-3] | RFC 9293 §3.1, RFC 1122 §4.2.2.7 | itest_tcp_018_bad_checksum_dropped, test_tcp_018_bad_checksum_silently_dropped |
| REQ-TCP-019 | MUST | IPv4 pseudo-header: src IP (4) + dst IP (4) + zero (1) + protocol 6 (1) + TCP length (2) | RFC 9293 §3.1 | itest_tcp_018_bad_checksum_dropped |
| REQ-TCP-020 | MUST | IPv6 pseudo-header: src IP (16) + dst IP (16) + TCP length (4) + zeros (3) + next header 6 (1) | RFC 8200 §8.1 | itest_tcp_020_ipv6_checksum_and_default_mss |
| REQ-TCP-021 | MUST | Verify Data Offset ≥ 5 (minimum 20-byte header) | RFC 9293 §3.1 | itest_tcp_021_bad_data_offset_dropped |
| REQ-TCP-022 | MUST | Verify Data Offset × 4 ≤ segment length | RFC 9293 §3.1 | itest_tcp_021_bad_data_offset_dropped |
| REQ-TCP-023 | MUST | Match incoming segments to connections by (local IP, local port, remote IP, remote port) | RFC 9293 §3.4.1, §3.10.7 | itest_tcp_023_matched_by_addresses_and_ports, itest_tcp_023_local_address_ipv6 |

### Sequence Number Handling (RFC 9293 §3.4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-024 | MUST | Maintain Send Sequence Variables: SND.UNA, SND.NXT, SND.WND, SND.WL1, SND.WL2, ISS — no SND.UP: urgent data is not supported (REQ-TCP-063) | RFC 9293 §3.3.1 | itest_tcp_014_send_and_receive |
| REQ-TCP-025 | MUST | Maintain Receive Sequence Variables: RCV.NXT, RCV.WND, IRS — no RCV.UP (REQ-TCP-063) | RFC 9293 §3.3.1 | itest_tcp_014_send_and_receive |
| REQ-TCP-026 | MUST | Use 32-bit unsigned arithmetic with wrap-around for sequence number comparisons | RFC 9293 §3.4 | itest_tcp_026_sequence_numbers_wrap |
| REQ-TCP-027 | MUST | Correctly handle sequence number wrap-around (comparison using signed difference) | RFC 9293 §3.4 | itest_tcp_026_sequence_numbers_wrap |
| REQ-TCP-028 | MUST | Select the Initial Sequence Number with a clock-driven generator — M, a 4 µs clock [MUST-8] — and an offset F() that cannot be computed from outside the host [MUST-9] | RFC 9293 §3.4.1, RFC 6528 | itest_tcp_028_iss_clock_driven, itest_tcp_153_iss_depends_on_every_seed_byte |
| REQ-TCP-029 | SHOULD | ISN = M + F(local address, local port, remote address, remote port, secret key), F a pseudo-random function [SHLD-1] | RFC 9293 §3.4.1, RFC 6528 | itest_tcp_028_iss_clock_driven |

### Segment Processing — LISTEN State (RFC 9293 §3.10.7.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-030 | MUST | In LISTEN: if RST received, ignore | RFC 9293 §3.10.7.2 | itest_tcp_030_listen_rst_and_ack |
| REQ-TCP-031 | MUST | In LISTEN: if ACK received, send RST | RFC 9293 §3.10.7.2 | itest_tcp_030_listen_rst_and_ack, test_tcp_031_ack_to_listen_generates_rst |
| REQ-TCP-032 | MUST | In LISTEN: if SYN received, transition to SYN-RECEIVED, send SYN,ACK | RFC 9293 §3.10.7.2 | itest_tcp_002_passive_open, test_tcp_002_synack_ack_equals_our_syn_plus_one |
| REQ-TCP-033 | MUST | In LISTEN: record remote IP and port from the received SYN | RFC 9293 §3.10.7.2 | itest_tcp_002_passive_open |
| REQ-TCP-034 | MUST | In LISTEN: set RCV.NXT = SEG.SEQ + 1, IRS = SEG.SEQ | RFC 9293 §3.10.7.2 | itest_tcp_002_passive_open, test_tcp_002_synack_ack_equals_our_syn_plus_one |
| REQ-TCP-035 | MUST | SYN,ACK response: SEG.SEQ = ISS, SEG.ACK = RCV.NXT | RFC 9293 §3.10.7.2 | itest_tcp_002_passive_open, test_tcp_002_synack_ack_equals_our_syn_plus_one |

### Segment Processing — SYN-SENT State (RFC 9293 §3.10.7.3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-036 | MUST | In SYN-SENT: if ACK received with unacceptable ACK number, send RST (unless the segment is a RST) | RFC 9293 §3.10.7.3 | itest_tcp_036_syn_sent_unacceptable_ack |
| REQ-TCP-037 | MUST | In SYN-SENT: if RST received with an acceptable ACK, the connection is refused: CLOSED, the application told; a RST without ACK is dropped | RFC 9293 §3.10.7.3 | itest_tcp_037_syn_sent_reset |
| REQ-TCP-038 | MUST | In SYN-SENT: if SYN,ACK received with acceptable ACK, transition to ESTABLISHED and acknowledge it | RFC 9293 §3.10.7.3 | itest_tcp_003_active_open |
| REQ-TCP-039 | MUST | In SYN-SENT: if SYN received (without ACK), transition to SYN-RECEIVED and send SYN,ACK (simultaneous open) | RFC 9293 §3.10.7.3 | itest_tcp_004_simultaneous_open |
| REQ-TCP-040 | MUST | Acceptable ACK in SYN-SENT: SND.UNA < SEG.ACK ≤ SND.NXT | RFC 9293 §3.10.7.3 | itest_tcp_036_syn_sent_unacceptable_ack |

### Segment Processing — General (RFC 9293 §3.10.7.4)

#### Step 1: Sequence Number Check

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-041 | MUST | Check segment acceptability based on RCV.NXT, RCV.WND, SEG.SEQ, SEG.LEN | RFC 9293 §3.10.7.4 Step 1 | itest_tcp_041_acceptability, test_tcp_041_out_of_window_segment_gets_ack |
| REQ-TCP-042 | MUST | If segment not acceptable, send ACK (unless RST) and discard | RFC 9293 §3.10.7.4 Step 1 | itest_tcp_041_acceptability, test_tcp_041_out_of_window_segment_gets_ack |
| REQ-TCP-043 | MUST | Zero-length segment with zero window: acceptable if SEG.SEQ = RCV.NXT | RFC 9293 §3.10.7.4 Step 1 | itest_tcp_043_zero_window_acceptability |
| REQ-TCP-044 | MUST | Zero-length segment with non-zero window: acceptable if RCV.NXT ≤ SEG.SEQ < RCV.NXT+RCV.WND | RFC 9293 §3.10.7.4 Step 1 | itest_tcp_041_acceptability |
| REQ-TCP-045 | MUST | Non-zero-length segment: check start and end of segment against receive window | RFC 9293 §3.10.7.4 Step 1 | itest_tcp_041_acceptability |

#### Step 2: RST Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-046 | MUST | In SYN-RECEIVED: if RST received, return to LISTEN (if passive open) or CLOSED (if active open) [MUST-11] | RFC 9293 §3.10.7.4 Step 2 | itest_tcp_046_rst_in_syn_received_listens_again, itest_tcp_046_rst_in_active_syn_received_closes |
| REQ-TCP-047 | MUST | In ESTABLISHED/FIN-WAIT-1/FIN-WAIT-2/CLOSE-WAIT: if RST, abort connection and tell the application | RFC 9293 §3.10.7.4 Step 2 | itest_tcp_047_rst_aborts, test_tcp_047_rst_closes_established |
| REQ-TCP-048 | MUST | In CLOSING/LAST-ACK/TIME-WAIT: if RST, close connection | RFC 9293 §3.10.7.4 Step 2 | itest_tcp_048_rst_after_both_closed |
| REQ-TCP-049 | MUST | RST validation: SEG.SEQ must be in receive window | RFC 9293 §3.5.3, §3.10.7.4 Step 2 | itest_tcp_047_rst_aborts, test_tcp_047_rst_closes_established |

#### Step 3: Security/Compartment Check

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-050 | MAY | Skip security/compartment check (not applicable for this implementation) | RFC 9293 §3.10.7.4 Step 3 | — (not implemented: there is no security compartment) |

#### Step 4: SYN Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-051 | MUST | If SYN received in the window of a synchronized connection, this is an error: send RST, close, tell the application (RFC 793's behaviour; a passive open in SYN-RECEIVED returns to LISTEN) | RFC 9293 §3.10.7.4 Step 4 | itest_tcp_051_syn_in_established, itest_tcp_051_syn_in_syn_received_listens_again, test_tcp_051_syn_in_established_causes_error |
| REQ-TCP-052 | SHOULD | Send challenge ACK for a SYN in a synchronized state, whatever its sequence number (RFC 5961 mitigation) — **deviation:** not implemented: an in-window SYN resets the connection (REQ-TCP-051) | RFC 9293 §3.10.7.4 Step 4, RFC 5961 §4 | — |

#### Step 5: ACK Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-053 | MUST | If ACK bit not set, discard segment | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_053_no_ack_dropped |
| REQ-TCP-054 | MUST | In SYN-RECEIVED: if ACK acceptable, transition to ESTABLISHED | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_002_passive_open, test_tcp_003_three_way_handshake |
| REQ-TCP-055 | MUST | In ESTABLISHED: process ACK — advance SND.UNA, remove acknowledged data from retransmit queue | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_014_send_and_receive, test_tcp_014_data_echo_seq_ack |
| REQ-TCP-056 | MUST | In ESTABLISHED: if ACK acknowledges something not yet sent (SEG.ACK > SND.NXT), send ACK and discard | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_056_ack_of_unsent_and_old_ack |
| REQ-TCP-057 | MAY | Ignore a duplicate ACK (SEG.ACK < SND.UNA); the segment's data is still processed | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_056_ack_of_unsent_and_old_ack |
| REQ-TCP-058 | MUST | Update SND.WND from segments with SND.UNA ≤ SEG.ACK ≤ SND.NXT that advance SND.WL1/SND.WL2 — including an ACK of nothing new (a window update) | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_058_send_window |
| REQ-TCP-059 | MUST | In FIN-WAIT-1: if our FIN is ACKed, transition to FIN-WAIT-2 | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_005_active_close, test_tcp_005_graceful_close_active |
| REQ-TCP-060 | MUST | In FIN-WAIT-2: remain in FIN-WAIT-2 waiting for remote FIN | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_005_active_close |
| REQ-TCP-061 | MUST | In CLOSING: if our FIN is ACKed, transition to TIME-WAIT | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_007_simultaneous_close |
| REQ-TCP-062 | MUST | In LAST-ACK: if our FIN is ACKed, transition to CLOSED | RFC 9293 §3.10.7.4 Step 5 | itest_tcp_006_passive_close |

#### Step 6: URG Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-063 | MUST | Support the urgent mechanism: urgent data of any length, the Urgent Pointer pointing at the octet after it, the application told when one arrives and how much urgent data remains [MUST-30, 31, 32, 33, 62] — **deviation:** the URG flag and Urgent Pointer are ignored and the data delivered in line; RFC 9293 tells applications not to use urgent data [SHLD-13] | RFC 9293 §3.8.5, §3.10.7.4 Step 6 | itest_tcp_063_urgent_data_in_line |

#### Step 7: Segment Text (Data) Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-064 | MUST | In ESTABLISHED/FIN-WAIT-1/FIN-WAIT-2: deliver segment data to receive buffer | RFC 9293 §3.10.7.4 Step 7 | itest_tcp_014_send_and_receive, itest_tcp_005_active_close, test_tcp_014_data_echo_seq_ack |
| REQ-TCP-065 | MUST | Advance RCV.NXT by the amount of data accepted | RFC 9293 §3.10.7.4 Step 7 | itest_tcp_014_send_and_receive, test_tcp_014_data_echo_seq_ack |
| REQ-TCP-066 | MUST | Send ACK after accepting data | RFC 9293 §3.10.7.4 Step 7 | itest_tcp_014_send_and_receive, itest_tcp_127_ack_not_delayed, test_tcp_014_data_echo_seq_ack |
| REQ-TCP-067 | MUST | Trim segment data to fit receive window (discard data outside window); bytes before RCV.NXT were received already and are skipped; a segment starting after RCV.NXT (a gap) is not delivered — there is no reassembly queue [SHLD-31 is not followed] — and its ACK asks for RCV.NXT again | RFC 9293 §3.10.7.4 Step 7 | itest_tcp_041_acceptability, itest_tcp_067_trimmed_to_window |

#### Step 8: FIN Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-068 | MUST | If FIN received in sequence (all data before it accepted), advance RCV.NXT over the FIN, send ACK; a FIN after missing data is not processed | RFC 9293 §3.10.7.4 Step 8 | itest_tcp_068_fin_in_sequence, itest_tcp_006_passive_close, test_tcp_006_fin_ack_correct_seq |
| REQ-TCP-069 | MUST | In SYN-RECEIVED or ESTABLISHED: transition to CLOSE-WAIT on FIN | RFC 9293 §3.10.7.4 Step 8 | itest_tcp_006_passive_close, test_tcp_006_fin_ack_correct_seq |
| REQ-TCP-070 | MUST | In FIN-WAIT-1: if our FIN also ACKed, transition to TIME-WAIT; else transition to CLOSING | RFC 9293 §3.10.7.4 Step 8 | itest_tcp_007_simultaneous_close |
| REQ-TCP-071 | MUST | In FIN-WAIT-2: transition to TIME-WAIT on FIN | RFC 9293 §3.10.7.4 Step 8 | itest_tcp_005_active_close, test_tcp_005_graceful_close_active |

### RST Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-072 | MUST | Send RST when receiving segment for non-existent connection | RFC 9293 §3.5.2, §3.10.7.1 | itest_tcp_072_reset_for_no_connection, itest_tcp_015_close_in_listen, test_tcp_072_syn_unknown_port_gets_rst |
| REQ-TCP-073 | MUST | RST segment: if triggered by ACK, SEG.SEQ = SEG.ACK of triggering segment | RFC 9293 §3.5.2 | itest_tcp_072_reset_for_no_connection, itest_tcp_030_listen_rst_and_ack, test_tcp_031_ack_to_listen_generates_rst |
| REQ-TCP-074 | MUST | RST segment: if triggered by non-ACK, SEQ = 0, ACK = SEG.SEQ + SEG.LEN, ACK bit set | RFC 9293 §3.5.2 | itest_tcp_072_reset_for_no_connection |
| REQ-TCP-075 | MUST NOT | MUST NOT send RST in response to RST | RFC 9293 §3.5.2 | itest_tcp_072_reset_for_no_connection, itest_tcp_030_listen_rst_and_ack, test_tcp_075_rst_to_listen_is_silent |

### Maximum Segment Size (MSS)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-076 | MUST | Implement sending and receiving the MSS option [MUST-14]; it is sent in every SYN and SYN,ACK [MAY-3] | RFC 9293 §3.7.1 | itest_tcp_116_options_only_in_syn, itest_tcp_002_passive_open, test_tcp_076_synack_contains_mss_option |
| REQ-TCP-077 | MUST | The MSS we advertise is what the RX frame buffer takes: min(rx buffer capacity, 14 + the MTU) − Ethernet, IP and TCP headers — at most 1460 over IPv4, 1440 over IPv6 with the default MTU; never more than MMS_R − 20 [MUST-67] | RFC 9293 §3.7.1 | itest_tcp_077_mss_from_the_frame_buffers, itest_tcp_077_mtu_bounds_segments, test_tcp_076_synack_contains_mss_option |
| REQ-TCP-078 | MUST | If peer sends MSS option, limit outbound segment size to peer's MSS [MUST-16] | RFC 9293 §3.7.1 | itest_tcp_078_peer_mss_and_options, test_tcp_078_sut_honors_our_mss |
| REQ-TCP-079 | MUST | If peer does not send MSS option, assume default MSS = 536 (IPv4) [MUST-15] | RFC 9293 §3.7.1 | itest_tcp_078_peer_mss_and_options |
| REQ-TCP-080 | MUST | IPv6 default MSS (no option) = 1220 [MUST-15] | RFC 9293 §3.7.1 | itest_tcp_020_ipv6_checksum_and_default_mss |
| REQ-TCP-081 | MUST | Never send segments larger than the peer's MSS (or the default), nor larger than the TX frame buffer carries [MUST-16] | RFC 9293 §3.7.1 | itest_tcp_077_mss_from_the_frame_buffers, itest_tcp_078_peer_mss_and_options, test_tcp_078_sut_honors_our_mss |

### Window Management

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-082 | MUST | Advertise receive window (RCV.WND) in every outbound segment but a RST | RFC 9293 §3.1 | itest_tcp_082_window_advertised, test_tcp_082_window_nonzero_in_synack |
| REQ-TCP-083 | MUST | Receive window reflects available space in RX buffer abstraction | RFC 9293 §3.8.6 | itest_tcp_082_window_advertised, itest_tcp_043_zero_window_acceptability, itest_tcp_067_trimmed_to_window, test_tcp_082_window_nonzero_in_synack |
| REQ-TCP-084 | MUST | Honor peer's advertised window — do not send more data than SND.WND allows | RFC 9293 §3.8.6 | itest_tcp_058_send_window, itest_tcp_089_small_window_small_segment |
| REQ-TCP-085 | MUST | When peer advertises zero window, stop sending data (enter persist mode) | RFC 9293 §3.8.6.1 | itest_tcp_085_zero_window_probe, test_tcp_085_persist_probe_on_zero_window |
| REQ-TCP-086 | MUST | Probe a zero window [MUST-36]: the first probe after the retransmission timeout, later ones at exponentially growing intervals [SHLD-29, 30] | RFC 9293 §3.8.6.1 | itest_tcp_085_zero_window_probe, test_tcp_085_persist_probe_on_zero_window |
| REQ-TCP-087 | MUST | Window probe: send 1-byte segment to elicit window update | RFC 9293 §3.8.6.1 | itest_tcp_085_zero_window_probe, test_tcp_085_persist_probe_on_zero_window |
| REQ-TCP-088 | MUST | Avoid Silly Window Syndrome as a receiver [MUST-39]: the right window edge stays where it was advertised until the free space beyond it is min(half the receive buffer, the MSS) | RFC 9293 §3.8.6.2.2, RFC 1122 §4.2.3.3 | itest_tcp_088_receiver_silly_window_avoidance |
| REQ-TCP-089 | MUST | Avoid Silly Window Syndrome as a sender [MUST-38] — **deviation:** not implemented: a segment as large as the peer's window and the MSS allow goes at once, however small; with one segment in flight (REQ-TCP-108) the next waits for its ACK | RFC 9293 §3.8.6.2.1, RFC 1122 §4.2.3.4 | itest_tcp_089_small_window_small_segment |

### Retransmission (RFC 6298)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-090 | MUST | Maintain retransmission timer for unacknowledged segments | RFC 9293 §3.8.1, RFC 6298 §5 | itest_tcp_090_retransmission_schedule, itest_tcp_090_syn_received_given_up_listens_again, test_tcp_090_syn_retransmit_on_timeout |
| REQ-TCP-091 | MUST | Compute RTO from SRTT and RTTVAR using Jacobson's algorithm [MUST-18] — **deviation:** no round-trip time is measured: the RTO starts at `NET_DEFAULT_TCP_RTO_INIT_MS` (1 s), doubles at each timeout, and keeps its backed-off value for the rest of the connection | RFC 9293 §3.8.1, RFC 6298 §2 | itest_tcp_091_rto_not_measured |
| REQ-TCP-092 | SHOULD | Initial RTO = 1 second (before any RTT measurement) | RFC 6298 §2.1 | itest_tcp_090_retransmission_schedule, itest_tcp_179_retransmit_not_early |
| REQ-TCP-093 | SHOULD | Minimum RTO = 1 second | RFC 6298 §2.4 | itest_tcp_091_rto_not_measured |
| REQ-TCP-094 | MAY | Bound the RTO, by no less than 60 seconds (`NET_DEFAULT_TCP_RTO_MAX_MS`: 60 s) | RFC 6298 §2.5 | itest_tcp_090_retransmission_schedule |
| REQ-TCP-095 | SHOULD | On timeout: retransmit earliest unacknowledged segment | RFC 6298 §5.4 | itest_tcp_090_retransmission_schedule, test_tcp_090_syn_retransmit_on_timeout |
| REQ-TCP-096 | MUST | On timeout: double RTO (exponential backoff) [MUST-19] | RFC 6298 §5.5, RFC 9293 §3.8.2 | itest_tcp_090_retransmission_schedule, test_tcp_090_syn_retransmit_on_timeout |
| REQ-TCP-097 | SHOULD | On ACK for new data: restart retransmission timer | RFC 6298 §5.3 | itest_tcp_097_ack_restarts_or_stops_the_timer, test_tcp_097_rto_resets_on_new_ack |
| REQ-TCP-098 | SHOULD | When all data acknowledged, stop retransmission timer | RFC 6298 §5.2 | itest_tcp_097_ack_restarts_or_stops_the_timer, test_tcp_097_rto_resets_on_new_ack |
| REQ-TCP-099 | MUST | Measure RTT per RFC 6298: at least one measurement per RTT (unless Karn's algorithm prevents it) — **deviation:** none is taken (REQ-TCP-091) | RFC 6298 §3 | itest_tcp_091_rto_not_measured |
| REQ-TCP-100 | MUST NOT | MUST NOT measure RTT for retransmitted segments (Karn's algorithm) — no segment's round trip is measured (REQ-TCP-099) | RFC 6298 §3, RFC 9293 §3.8.1 | itest_tcp_091_rto_not_measured |

### Congestion Control (RFC 5681)

The stop-and-wait buffer — the only one — keeps one segment in flight.
That is never more than RFC 5681 allows (its smallest window, the loss
window, is one segment), so the sender is never more aggressive than slow
start and congestion avoidance; the algorithms themselves, and their
variables, are not implemented.

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-101 | MUST | Implement slow start: initialize cwnd to IW (Initial Window) [MUST-19] — **deviation:** no cwnd; one segment in flight (REQ-TCP-108) | RFC 5681 §3.1, RFC 9293 §3.8.2 | itest_tcp_108_one_segment_in_flight |
| REQ-TCP-102 | MUST | IW = min(4 × MSS, max(2 × MSS, 4380)) per RFC 5681 (or 10 × MSS per RFC 6928 if opted in) as an upper bound — **deviation:** no cwnd; one segment is below every bound (REQ-TCP-108) | RFC 5681 §3.1, RFC 6928 | itest_tcp_108_one_segment_in_flight |
| REQ-TCP-103 | MUST | Slow start: increase cwnd by at most MSS per ACK of new data when cwnd < ssthresh — **deviation:** no cwnd; nothing grows (REQ-TCP-108) | RFC 5681 §3.1 | itest_tcp_108_one_segment_in_flight |
| REQ-TCP-104 | MUST | Congestion avoidance: when cwnd ≥ ssthresh, increase cwnd by ~MSS per RTT — **deviation:** no cwnd; nothing grows (REQ-TCP-108) | RFC 5681 §3.1 | itest_tcp_108_one_segment_in_flight |
| REQ-TCP-105 | MUST | On timeout: set ssthresh = max(FlightSize/2, 2×MSS), set cwnd = 1 × MSS (loss window) — **deviation:** no cwnd or ssthresh; a timeout resends the one segment (REQ-TCP-108) | RFC 5681 §3.1 | itest_tcp_108_one_segment_in_flight |
| REQ-TCP-106 | SHOULD | Implement fast retransmit: on 3 duplicate ACKs, retransmit without waiting for timeout — **deviation:** not implemented: loss is repaired by the retransmission timer | RFC 5681 §3.2 | — |
| REQ-TCP-107 | SHOULD | After fast retransmit: set ssthresh = max(FlightSize/2, 2×MSS), enter fast recovery — **deviation:** not implemented (REQ-TCP-106) | RFC 5681 §3.2 | — |
| REQ-TCP-108 | MAY | For single-segment stop-and-wait buffer mode, congestion control is inherently limited to 1 MSS in flight | Architecture | itest_tcp_108_one_segment_in_flight |

### TCP Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-109 | MUST | Parse TCP options in received SYN/SYN-ACK segments [MUST-4] | RFC 9293 §3.1 | itest_tcp_078_peer_mss_and_options |
| REQ-TCP-110 | MUST | Support End of Option List (Kind 0) | RFC 9293 §3.1, §3.2 | itest_tcp_078_peer_mss_and_options |
| REQ-TCP-111 | MUST | Support No-Operation (Kind 1) for padding | RFC 9293 §3.1, §3.2 | itest_tcp_078_peer_mss_and_options |
| REQ-TCP-112 | MUST | Support MSS option (Kind 2, Length 4) | RFC 9293 §3.2, §3.7.1 | itest_tcp_078_peer_mss_and_options |
| REQ-TCP-113 | MAY | Support Window Scale option (Kind 3, Length 3) in SYN segments | RFC 7323 §2 | — (not implemented) |
| REQ-TCP-114 | MAY | Support Timestamps option (Kind 8, Length 10) | RFC 7323 §3 | — (not implemented) |
| REQ-TCP-115 | MUST | Ignore unknown TCP options (skip using Length field) [MUST-6] | RFC 9293 §3.1 | itest_tcp_078_peer_mss_and_options, test_fuzz_004_tcp_options |
| REQ-TCP-116 | MUST NOT | Send the MSS option in a segment without SYN [MUST-65]; it is the only option sent | RFC 9293 §3.2 | itest_tcp_116_options_only_in_syn |
| REQ-TCP-117 | MAY | Support SACK Permitted (Kind 4) and SACK (Kind 5) options | RFC 2018 | — (not implemented) |

### Window Scale (RFC 7323 §2) — not implemented

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-118 | MAY | Send Window Scale option in SYN if RX buffer > 65535 bytes | RFC 7323 §2 | — (not implemented) |
| REQ-TCP-119 | MUST | Only negotiate Window Scale if both sides include it in SYN: we never include it, so a peer's offer is not taken up and its window is read unscaled | RFC 7323 §2 | itest_tcp_119_window_scale_not_negotiated |
| REQ-TCP-120 | MUST | If negotiated, apply scale factor when interpreting peer's window | RFC 7323 §2 | — (not observable: window scaling is never negotiated, REQ-TCP-119) |
| REQ-TCP-121 | MUST | Scale factor maximum = 14 (window up to 2^30) | RFC 7323 §2 | — (not observable: window scaling is never negotiated, REQ-TCP-119) |

### Timestamps (RFC 7323 §3) — not implemented

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-122 | MAY | Send Timestamps option for RTTM (Round-Trip Time Measurement) | RFC 7323 §3 | — (not implemented) |
| REQ-TCP-123 | MUST | If timestamps negotiated, include TSopt in every segment | RFC 7323 §3.2 | — (not observable: timestamps are never negotiated — our SYN carries the MSS option alone, REQ-TCP-116) |
| REQ-TCP-124 | MUST | TSecr (timestamp echo reply) MUST reflect most recent TSval received | RFC 7323 §3.2 | — (not observable: timestamps are never negotiated, REQ-TCP-116) |

### Delayed ACK

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-125 | SHOULD | Implement delayed ACK [SHLD-18] — **deviation:** not implemented: every data segment is acknowledged as it arrives (REQ-TCP-128) | RFC 9293 §3.8.6.3, RFC 1122 §4.2.3.2 | itest_tcp_127_ack_not_delayed |
| REQ-TCP-126 | SHOULD | ACK at least every second full-sized segment [SHLD-19] | RFC 9293 §3.8.6.3, RFC 5681 §4.2 | itest_tcp_127_ack_not_delayed |
| REQ-TCP-127 | MUST | An ACK is delayed by less than 0.5 seconds [MUST-40] | RFC 9293 §3.8.6.3, RFC 1122 §4.2.3.2 | itest_tcp_127_ack_not_delayed |
| REQ-TCP-128 | MAY | Disable delayed ACK (send ACK immediately on every segment) for simplicity | Architecture | itest_tcp_127_ack_not_delayed |

### Nagle Algorithm

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-129 | SHOULD | Implement Nagle algorithm: if unACKed data in flight, buffer small segments [SHLD-7] — **deviation:** not implemented: `tcp_send()` sends at once; `tcp_write()` + `tcp_output()` gather pieces into one segment | RFC 9293 §3.7.4, RFC 1122 §4.2.3.4 | — |
| REQ-TCP-130 | MUST | Let the application disable the Nagle algorithm on a connection [MUST-17]: there is none to disable — a small write on an idle connection goes at once (while a segment is in flight the stop-and-wait buffer takes no more: REQ-TCP-108) | RFC 9293 §3.7.4, RFC 1122 §4.2.3.4 | itest_tcp_108_one_segment_in_flight |
| REQ-TCP-131 | MAY | Omit Nagle for simplicity in minimal configurations | Architecture | itest_tcp_108_one_segment_in_flight |

### Keep-Alive — not implemented

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-132 | MAY | Implement TCP keep-alive probes [MAY-5] | RFC 9293 §3.8.4, RFC 1122 §4.2.3.6 | — (not implemented) |
| REQ-TCP-133 | MUST | Keep-alive MUST be disabled by default (only enabled by application) [MUST-25]: none is ever sent | RFC 9293 §3.8.4, RFC 1122 §4.2.3.6 | itest_tcp_133_no_keep_alive |
| REQ-TCP-134 | MUST | Keep-alive interval MUST be configurable, default ≥ 2 hours [MUST-27, 28] | RFC 9293 §3.8.4, RFC 1122 §4.2.3.6 | — (not observable: no keep-alive is ever sent, REQ-TCP-133) |

### ICMP Error Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-135 | MUST | Act on an ICMP error message, directing it to the connection that created the error [MUST-54] — Fragmentation Needed lowers the connection's segment size to fit the next-hop MTU (RFC 1191) — **not met over IPv6:** ICMPv6 errors, Packet Too Big among them, do not reach TCP: `icmpv6_input()` drops them (REQ-ICMPv6-011, 018) | RFC 1122 §4.2.3.9, RFC 9293 §3.9.2.2, RFC 1191 | itest_tcp_135_unreachable_in_syn_sent, itest_tcp_135_fragmentation_needed_lowers_mss |
| REQ-TCP-136 | MUST NOT | Abort a connection on a soft error — Destination Unreachable codes 0, 1, 5, Time Exceeded, Parameter Problem [MUST-56]; report it to the application instead [SHLD-25] | RFC 1122 §4.2.3.9, RFC 9293 §3.9.2.2 | itest_tcp_136_soft_errors_do_not_abort |
| REQ-TCP-137 | SHOULD | Treat Destination Unreachable codes 2–4 (Protocol, Port Unreachable; Fragmentation Needed without a usable MTU) as hard errors and abort the connection [SHLD-26] | RFC 1122 §4.2.3.9, RFC 9293 §3.9.2.2 | itest_tcp_137_hard_errors_abort |
| REQ-TCP-138 | MAY | Abort a connection attempt after repeated soft errors | RFC 5461 | — (not implemented: a soft error never aborts; retransmissions reaching R2 do, REQ-TCP-162) |

### Checksum

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-139 | MUST | Compute TCP checksum over pseudo-header + TCP header + data on transmission [MUST-2] | RFC 9293 §3.1 | itest_tcp_139_checksum_sent, itest_tcp_020_ipv6_checksum_and_default_mss |
| REQ-TCP-140 | MUST | Verify TCP checksum on reception; discard on mismatch [MUST-3] | RFC 9293 §3.1 | itest_tcp_018_bad_checksum_dropped, test_tcp_018_bad_checksum_silently_dropped |
| REQ-TCP-141 | MUST | Support hardware checksum offload (write 0x0000, let MAC compute) — **deviation:** not implemented: the checksum is always computed in software | Architecture | itest_tcp_139_checksum_sent |

### Buffer Abstraction Layer

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-142 | MUST | TCP implementation MUST NOT directly access buffer memory — use buffer ops vtable | Architecture | itest_tcp_142_buffers_through_their_operations |
| REQ-TCP-143 | MUST | TX buffer ops: write, next_segment, ack (never releasing more than is in flight), in_flight (bytes sent and unacknowledged), queued, writable, mark_retransmit | Architecture | itest_tcp_142_buffers_through_their_operations, test_saw_tx_ack_beyond_sent_keeps_unsent, test_saw_tx_mark_retransmit |
| REQ-TCP-144 | MUST | RX buffer ops: deliver, read, readable, available (for window advertisement) | Architecture | itest_tcp_142_buffers_through_their_operations, test_saw_rx_window_tracks_available |
| REQ-TCP-145 | MUST | Provide stop-and-wait buffer implementation (1 segment in flight) | Architecture | itest_tcp_108_one_segment_in_flight, test_saw_tx_no_segment_when_in_flight |
| REQ-TCP-146 | SHOULD | Provide circular buffer implementation (streaming window) — **deviation:** not implemented ([tcp-buffer.md](../design/tcp-buffer.md) §5) | Architecture | — |
| REQ-TCP-147 | MAY | Provide packet-list buffer implementation (scatter-gather) | Architecture | — (not implemented) |

### Connection Identification and Matching

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-148 | MUST | Match segments to connections using full 4-tuple: (local IP, local port, remote IP, remote port) | RFC 9293 §3.4.1 | itest_tcp_023_matched_by_addresses_and_ports, itest_tcp_023_local_address_ipv6 |
| REQ-TCP-149 | MUST | LISTEN connections match on (local IP [any], local port, remote IP [any], remote port [any]) | RFC 9293 §3.9.1.1 | itest_tcp_023_matched_by_addresses_and_ports |
| REQ-TCP-150 | MUST | Application provides array/list of connections for the stack to scan | Architecture | itest_tcp_023_matched_by_addresses_and_ports |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-151 | MUST | Parse TCP header in-place in application buffer | Architecture | itest_tcp_142_buffers_through_their_operations |
| REQ-TCP-152 | MUST | Build TCP header in-place in application buffer | Architecture | itest_tcp_139_checksum_sent |

### Security Considerations

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-153 | MUST | Prevent sequence number prediction attacks: the ISS of one connection, or of any number of them, reveals nothing about the ISS of a connection with another address or port (RFC 6528's keyed hash, under a secret seeded from real entropy) | RFC 9293 §3.4.1, RFC 6528 | itest_tcp_153_iss_depends_on_every_seed_byte, test_tcp_153_iss_differs_across_connections |
| REQ-TCP-154 | SHOULD | Implement challenge ACK for in-window SYN/RST (RFC 5961 blind attack mitigation) — **deviation:** not implemented: a RST anywhere in the window resets (REQ-TCP-049), an in-window SYN too (REQ-TCP-051) | RFC 5961 §3, §4, RFC 9293 §3.10.7.4 | — |
| REQ-TCP-155 | SHOULD | Throttle challenge ACKs (RFC 5961 §7) — **deviation:** not implemented: there are no challenge ACKs (REQ-TCP-154), and RSTs are not rate-limited | RFC 5961 §7 | — |

### Further MUSTs of RFC 9293, RFC 1122 and RFC 6298

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-156 | MUST | Treat the window as an unsigned number [MUST-1] | RFC 9293 §3.1 | itest_tcp_156_window_unsigned |
| REQ-TCP-157 | MUST | Receive a TCP option in any segment, not only a SYN [MUST-5] | RFC 9293 §3.1 | itest_tcp_157_options_in_any_segment |
| REQ-TCP-158 | MUST | Handle an illegal option length (e.g. zero) without harm [MUST-7] | RFC 9293 §3.1 | itest_tcp_158_illegal_option_length |
| REQ-TCP-159 | MUST | Process options that do not start on a word boundary [MUST-64] | RFC 9293 §3.2 | itest_tcp_157_options_in_any_segment |
| REQ-TCP-160 | MUST | Process the RST field of every incoming segment, even with the receive window zero — a RST carrying data included [MUST-66]; URG: REQ-TCP-063 | RFC 9293 §3.4 | itest_tcp_160_rst_into_zero_window |
| REQ-TCP-161 | MUST | Tell the application whether a connection closed normally or was aborted [MUST-12] | RFC 9293 §3.6 | itest_tcp_161_closed_or_aborted |
| REQ-TCP-162 | MUST | Handle excessive retransmissions: at R1, report a soft error to the application (REQ-TCP-173); at R2, close the connection [MUST-20] — **deviation:** no negative advice to the IP layer at R1: there is no gateway choice to advise (REQ-IPv4-075) | RFC 9293 §3.8.3, RFC 1122 §4.2.3.5 | itest_tcp_162_r1_and_r2, itest_tcp_090_retransmission_schedule |
| REQ-TCP-163 | MUST | Handle SYN retransmissions like data retransmissions, the application notified when they end [MUST-22] | RFC 9293 §3.8.3 | itest_tcp_164_syn_retransmitted_three_minutes |
| REQ-TCP-164 | MUST | Retransmit a SYN for at least 3 minutes before giving up [MUST-23], whatever R2 the application chose | RFC 9293 §3.8.3, RFC 1122 §4.2.3.5 | itest_tcp_164_syn_retransmitted_three_minutes |
| REQ-TCP-165 | MUST | Let the application set R2 for a connection [MUST-21] (`tcp_set_max_retransmits()`) | RFC 9293 §3.8.3, RFC 1122 §4.2.3.5 | itest_tcp_162_r1_and_r2 |
| REQ-TCP-166 | MUST | Be robust against the peer shrinking its window [MUST-34] | RFC 9293 §3.8.6 | itest_tcp_166_window_shrunk |
| REQ-TCP-167 | MUST | Keep a connection open while the peer advertises a zero window and answers probes [MUST-37] | RFC 9293 §3.8.6.1, RFC 1122 §4.2.2.17 | itest_tcp_167_zero_window_kept_open |
| REQ-TCP-168 | MUST NOT | Let a LISTEN affect a connection record already in use (`tcp_listen()` refuses a connection that is not CLOSED or LISTEN) [MUST-41] | RFC 9293 §3.9.1.1 | itest_tcp_168_listen_on_a_live_connection |
| REQ-TCP-169 | MUST | Allow LISTEN on a port while another connection on it is in SYN-SENT or SYN-RECEIVED [MUST-42] | RFC 9293 §3.9.1.1 | itest_tcp_169_listen_beside_an_open |
| REQ-TCP-170 | MUST | Support the optional local IP address parameter of OPEN [MUST-43]: over IPv4 the host has one address; over IPv6, `tcp6_connect_from()` names one of the host's addresses for an active open, and a listener takes a SYN to any of them, answering from the address it was sent to | RFC 9293 §3.9.1.1 | itest_tcp_170_local_address, itest_tcp_170_local_address_ipv6 |
| REQ-TCP-171 | MUST | Ask the IP layer for a local address before sending the first SYN [MUST-44], and use it for the connection's whole life [MUST-45] — if the host's address changes, the connection is aborted rather than continued from another | RFC 9293 §3.9.1.1 | itest_tcp_171_same_local_address |
| REQ-TCP-172 | MUST | Refuse an OPEN to a broadcast or multicast remote address [MUST-46] | RFC 9293 §3.9.1.1 | itest_tcp_172_open_to_broadcast_refused, itest_tcp_170_local_address_ipv6 |
| REQ-TCP-173 | MUST | Report soft errors to the application — ICMP errors that do not abort, and R1 reached [MUST-47]: `TCP_EVT_SOFT_ERROR`, `tcp_last_error()` | RFC 9293 §3.9.1.8, RFC 1122 §4.2.4.1 | itest_tcp_136_soft_errors_do_not_abort, itest_tcp_162_r1_and_r2 |
| REQ-TCP-174 | MUST | Let the application set the DSCP (TOS) of a connection's segments [MUST-48] (`tcp_set_tos()`) | RFC 9293 §3.9.1.9 | itest_tcp_174_tos |
| REQ-TCP-175 | MUST | Make the TTL of TCP segments configurable [MUST-49] (`NET_DEFAULT_TTL`, at build time; the IPv6 hop limit comes from the router) | RFC 9293 §3.9.2 | itest_tcp_175_ttl |
| REQ-TCP-176 | MUST | Silently discard a SYN addressed to a broadcast or multicast address [MUST-57] | RFC 9293 §3.9.2.3 | itest_tcp_176_syn_to_broadcast_dropped |
| REQ-TCP-177 | MUST | Ignore a SYN with an invalid source address — 0.0.0.0 included [MUST-63] | RFC 9293 §3.9.2.3 | itest_tcp_177_syn_from_unspecified_ignored |
| REQ-TCP-178 | MUST | Aggregate ACKs, processing every queued segment before acknowledging [MUST-58, 59] — met trivially: `net_poll()` hands TCP one segment at a time, and each is acknowledged as it is processed | RFC 9293 §3.10.7.4 | — (not observable: no queue of segments forms) |
| REQ-TCP-179 | MUST NOT | Retransmit a segment less than one RTO after its previous transmission, or more aggressively than RFC 6298 allows | RFC 6298 §1, §5 | itest_tcp_179_retransmit_not_early |
| REQ-TCP-180 | MUST | Set PSH on the last buffered segment — the one that empties the send buffer [MUST-61]; never buffer data indefinitely [MUST-60] | RFC 9293 §3.9.1.2, RFC 1122 §4.2.2.2 | itest_tcp_180_push_and_no_indefinite_buffering |
| REQ-TCP-181 | MUST | After a SYN timed out with an RTO under 3 s, start data transmission with an RTO of 3 s | RFC 6298 §5 (5.7) | itest_tcp_181_rto_three_seconds_after_syn_timeout |
| REQ-TCP-182 | MUST | Pass IP options to and from TCP, and support source routes: save a received return route, let the application give one [MUST-50, 51, 52, 53] — **deviation:** source-routed datagrams are dropped (REQ-IPv4-067); other IP options on a segment are ignored, not passed up, and none can be sent | RFC 9293 §3.9.2.1, RFC 1122 §4.2.3.8 | itest_tcp_182_ip_options |

## Notes

- **RFC 9293 consolidates RFC 793:** the requirements cite RFC 9293 as the primary source; section numbers are its own.
- **Congestion control:** RFC 9293 requires slow start and congestion avoidance (MUST-19). The stack has one buffer implementation, stop-and-wait, which keeps one segment in flight: never more than RFC 5681's smallest congestion window, so the sender cannot be more aggressive than the algorithms allow, though it implements none of them (REQ-TCP-101..105, deviations; REQ-TCP-108). A buffer with several segments in flight needs them first ([tcp-buffer.md](../design/tcp-buffer.md) §5).
- **No round-trip time measurement:** the retransmission timeout is not computed from the path (REQ-TCP-091, 099, deviations): it starts at 1 s, doubles at each timeout up to 60 s, and stays backed off for the rest of the connection.
- **Urgent data not supported:** a deviation from RFC 9293 MUST-30..33 and 62 (REQ-TCP-063): the URG flag and Urgent Pointer are ignored and urgent data delivered in line.  RFC 9293 §3.8.5 asks implementations to keep supporting it but applications not to use it (SHLD-13).
- **No SACK, window scale or timestamps:** all three are MAYs. With one segment in flight and in-order delivery only, SACK has nothing to report; the 16-bit window field covers every buffer up to 65535 bytes.
- **ICMP errors reach TCP over IPv4 only** (REQ-TCP-135): over IPv6 a Packet Too Big does not lower the segment size, so a path whose MTU is below the link's stalls a connection that sends full-sized segments.
- **Active open** serves TCP clients (the TLS client, an HTTP client); a server-only application does not call it.
