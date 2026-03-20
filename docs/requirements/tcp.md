# TCP Requirements

**Protocol:** Transmission Control Protocol  
**Primary RFC:** RFC 9293 — Transmission Control Protocol (TCP) [2022]  
**Supporting:**  
- RFC 5681 — TCP Congestion Control  
- RFC 6298 — Computing TCP's Retransmission Timer  
- RFC 7323 — TCP Extensions for High Performance (Window Scale, Timestamps)  
- RFC 1122 — Requirements for Internet Hosts (§4.2)  
- RFC 6691 — TCP Options and Maximum Segment Size (MSS)  
- RFC 8200 §8.1 — IPv6 Upper-Layer Checksum  

**Supersession:** RFC 9293 supersedes RFC 793 (original TCP specification)  
**Scope:** V1 (IPv4), V2 (IPv6 — same TCP, different pseudo-header)  
**Last updated:** 2026-03-19

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

### Connection State Machine (RFC 9293 §3.3.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-001 | MUST | Implement the TCP state machine with states: CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT | RFC 9293 §3.3.2 | TEST-TCP-001 |
| REQ-TCP-002 | MUST | Support passive open (LISTEN → SYN-RECEIVED → ESTABLISHED) | RFC 9293 §3.3.2 | TEST-TCP-002 |
| REQ-TCP-003 | MUST | Support active open (CLOSED → SYN-SENT → ESTABLISHED) | RFC 9293 §3.3.2 | TEST-TCP-003 |
| REQ-TCP-004 | MUST | Support simultaneous open (SYN-SENT → SYN-RECEIVED → ESTABLISHED) | RFC 9293 §3.3.2 | TEST-TCP-004 |
| REQ-TCP-005 | MUST | Support graceful close via FIN exchange (ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT → CLOSED) | RFC 9293 §3.3.2 | TEST-TCP-005 |
| REQ-TCP-006 | MUST | Support passive close (ESTABLISHED → CLOSE-WAIT → LAST-ACK → CLOSED) | RFC 9293 §3.3.2 | TEST-TCP-006 |
| REQ-TCP-007 | MUST | Support simultaneous close (FIN-WAIT-1 → CLOSING → TIME-WAIT → CLOSED) | RFC 9293 §3.3.2 | TEST-TCP-007 |
| REQ-TCP-008 | MUST | TIME-WAIT state MUST last 2 × MSL (Maximum Segment Lifetime) | RFC 9293 §3.4.2 | TEST-TCP-008 |
| REQ-TCP-009 | SHOULD | MSL SHOULD be 2 minutes (RFC), but MAY be reduced for embedded systems | RFC 9293 §3.4.2, Architecture | TEST-TCP-009 |

### Connection Management — Application Interface

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-010 | MUST | Application provides `tcp_conn_t` structure for each connection (application-managed) | Architecture | TEST-TCP-010 |
| REQ-TCP-011 | MUST | Provide `tcp_conn_init()` factory method that validates and initializes connection state | Architecture | TEST-TCP-011 |
| REQ-TCP-012 | MUST | `tcp_listen()` — put connection in LISTEN state on specified port | RFC 9293 §3.8.1 (OPEN) | TEST-TCP-012 |
| REQ-TCP-013 | MUST | `tcp_connect()` — initiate active open to specified IP:port | RFC 9293 §3.8.1 (OPEN) | TEST-TCP-013 |
| REQ-TCP-014 | MUST | `tcp_send()` — queue data for transmission | RFC 9293 §3.8.2 (SEND) | TEST-TCP-014 |
| REQ-TCP-015 | MUST | `tcp_close()` — initiate graceful close | RFC 9293 §3.8.4 (CLOSE) | TEST-TCP-015 |
| REQ-TCP-016 | MUST | `tcp_abort()` — send RST and immediately close | RFC 9293 §3.8.5 (ABORT) | TEST-TCP-016 |
| REQ-TCP-017 | MUST | `tcp_status()` — return current connection state | RFC 9293 §3.8.6 (STATUS) | TEST-TCP-017 |

### Segment Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-018 | MUST | Verify TCP checksum (pseudo-header + header + data); discard on failure | RFC 9293 §3.1, RFC 1122 §4.2.2.7 | TEST-TCP-018 |
| REQ-TCP-019 | MUST | IPv4 pseudo-header: src IP (4) + dst IP (4) + zero (1) + protocol 6 (1) + TCP length (2) | RFC 9293 §3.1 | TEST-TCP-019 |
| REQ-TCP-020 | MUST | IPv6 pseudo-header: src IP (16) + dst IP (16) + TCP length (4) + zeros (3) + next header 6 (1) | RFC 8200 §8.1 | TEST-TCP-020 |
| REQ-TCP-021 | MUST | Verify Data Offset ≥ 5 (minimum 20-byte header) | RFC 9293 §3.1 | TEST-TCP-021 |
| REQ-TCP-022 | MUST | Verify Data Offset × 4 ≤ segment length | RFC 9293 §3.1 | TEST-TCP-022 |
| REQ-TCP-023 | MUST | Match incoming segments to connections by (local IP, local port, remote IP, remote port) | RFC 9293 §3.3.4 | TEST-TCP-023 |

### Sequence Number Handling (RFC 9293 §3.4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-024 | MUST | Maintain Send Sequence Variables: SND.UNA, SND.NXT, SND.WND, SND.UP, SND.WL1, SND.WL2, ISS | RFC 9293 §3.4.1 | TEST-TCP-024 |
| REQ-TCP-025 | MUST | Maintain Receive Sequence Variables: RCV.NXT, RCV.WND, RCV.UP, IRS | RFC 9293 §3.4.1 | TEST-TCP-025 |
| REQ-TCP-026 | MUST | Use 32-bit unsigned arithmetic with wrap-around for sequence number comparisons | RFC 9293 §3.4.1 | TEST-TCP-026 |
| REQ-TCP-027 | MUST | Correctly handle sequence number wrap-around (comparison using signed difference) | RFC 9293 §3.4.1 | TEST-TCP-027 |
| REQ-TCP-028 | MUST | Initial Sequence Number (ISS) MUST NOT be predictable (SHOULD be randomized) | RFC 9293 §3.4.1, RFC 6528 | TEST-TCP-028 |
| REQ-TCP-029 | SHOULD | ISS generation SHOULD use a combination of clock and randomness | RFC 9293 §3.4.1 | TEST-TCP-029 |

### Segment Processing — LISTEN State (RFC 9293 §3.10.7.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-030 | MUST | In LISTEN: if RST received, ignore | RFC 9293 §3.10.7.2 | TEST-TCP-030 |
| REQ-TCP-031 | MUST | In LISTEN: if ACK received, send RST | RFC 9293 §3.10.7.2 | TEST-TCP-031 |
| REQ-TCP-032 | MUST | In LISTEN: if SYN received, transition to SYN-RECEIVED, send SYN,ACK | RFC 9293 §3.10.7.2 | TEST-TCP-032 |
| REQ-TCP-033 | MUST | In LISTEN: record remote IP, port, ISS from received SYN | RFC 9293 §3.10.7.2 | TEST-TCP-033 |
| REQ-TCP-034 | MUST | In LISTEN: set RCV.NXT = SEG.SEQ + 1, IRS = SEG.SEQ | RFC 9293 §3.10.7.2 | TEST-TCP-034 |
| REQ-TCP-035 | MUST | SYN,ACK response: SEG.SEQ = ISS, SEG.ACK = RCV.NXT | RFC 9293 §3.10.7.2 | TEST-TCP-035 |

### Segment Processing — SYN-SENT State (RFC 9293 §3.10.7.3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-036 | MUST | In SYN-SENT: if ACK received with unacceptable ACK number, send RST | RFC 9293 §3.10.7.3 | TEST-TCP-036 |
| REQ-TCP-037 | MUST | In SYN-SENT: if RST received (with valid ACK), abort connection | RFC 9293 §3.10.7.3 | TEST-TCP-037 |
| REQ-TCP-038 | MUST | In SYN-SENT: if SYN,ACK received with acceptable ACK, transition to ESTABLISHED | RFC 9293 §3.10.7.3 | TEST-TCP-038 |
| REQ-TCP-039 | MUST | In SYN-SENT: if SYN received (without ACK), transition to SYN-RECEIVED (simultaneous open) | RFC 9293 §3.10.7.3 | TEST-TCP-039 |
| REQ-TCP-040 | MUST | Acceptable ACK in SYN-SENT: SND.UNA < SEG.ACK ≤ SND.NXT | RFC 9293 §3.10.7.3 | TEST-TCP-040 |

### Segment Processing — General (RFC 9293 §3.10.7.4)

#### Step 1: Sequence Number Check

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-041 | MUST | Check segment acceptability based on RCV.NXT, RCV.WND, SEG.SEQ, SEG.LEN | RFC 9293 §3.10.7.4 Step 1 | TEST-TCP-041 |
| REQ-TCP-042 | MUST | If segment not acceptable, send ACK (unless RST) and discard | RFC 9293 §3.10.7.4 Step 1 | TEST-TCP-042 |
| REQ-TCP-043 | MUST | Zero-length segment with zero window: acceptable if SEG.SEQ = RCV.NXT | RFC 9293 §3.10.7.4 Step 1 | TEST-TCP-043 |
| REQ-TCP-044 | MUST | Zero-length segment with non-zero window: acceptable if RCV.NXT ≤ SEG.SEQ < RCV.NXT+RCV.WND | RFC 9293 §3.10.7.4 Step 1 | TEST-TCP-044 |
| REQ-TCP-045 | MUST | Non-zero-length segment: check start and end of segment against receive window | RFC 9293 §3.10.7.4 Step 1 | TEST-TCP-045 |

#### Step 2: RST Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-046 | MUST | In SYN-RECEIVED: if RST received, return to LISTEN (if passive open) or CLOSED (if active open) | RFC 9293 §3.10.7.4 Step 2 | TEST-TCP-046 |
| REQ-TCP-047 | MUST | In ESTABLISHED/FIN-WAIT-1/FIN-WAIT-2/CLOSE-WAIT: if RST, abort connection | RFC 9293 §3.10.7.4 Step 2 | TEST-TCP-047 |
| REQ-TCP-048 | MUST | In CLOSING/LAST-ACK/TIME-WAIT: if RST, close connection | RFC 9293 §3.10.7.4 Step 2 | TEST-TCP-048 |
| REQ-TCP-049 | MUST | RST validation: SEG.SEQ must be in receive window | RFC 9293 §3.10.7.4 Step 2 | TEST-TCP-049 |

#### Step 3: Security/Compartment Check

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-050 | MAY | Skip security/compartment check (not applicable for this implementation) | RFC 9293 §3.10.7.4 Step 3 | TEST-TCP-050 |

#### Step 4: SYN Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-051 | MUST | If SYN received in ESTABLISHED/FIN-WAIT states, this is an error; send RST or challenge ACK | RFC 9293 §3.10.7.4 Step 4 | TEST-TCP-051 |
| REQ-TCP-052 | SHOULD | Send challenge ACK for in-window SYN (RFC 5961 mitigation) | RFC 9293 §3.10.7.4 Step 4, RFC 5961 | TEST-TCP-052 |

#### Step 5: ACK Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-053 | MUST | If ACK bit not set, discard segment | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-053 |
| REQ-TCP-054 | MUST | In SYN-RECEIVED: if ACK acceptable, transition to ESTABLISHED | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-054 |
| REQ-TCP-055 | MUST | In ESTABLISHED: process ACK — advance SND.UNA, remove acknowledged data from retransmit queue | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-055 |
| REQ-TCP-056 | MUST | In ESTABLISHED: if ACK acknowledges something not yet sent (SEG.ACK > SND.NXT), send ACK and discard | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-056 |
| REQ-TCP-057 | MUST | In ESTABLISHED: if duplicate ACK (SEG.ACK ≤ SND.UNA), it can be ignored | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-057 |
| REQ-TCP-058 | MUST | Update SND.WND from segments that advance SND.WL1/SND.WL2 | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-058 |
| REQ-TCP-059 | MUST | In FIN-WAIT-1: if our FIN is ACKed, transition to FIN-WAIT-2 | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-059 |
| REQ-TCP-060 | MUST | In FIN-WAIT-2: remain in FIN-WAIT-2 waiting for remote FIN | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-060 |
| REQ-TCP-061 | MUST | In CLOSING: if our FIN is ACKed, transition to TIME-WAIT | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-061 |
| REQ-TCP-062 | MUST | In LAST-ACK: if our FIN is ACKed, transition to CLOSED | RFC 9293 §3.10.7.4 Step 5 | TEST-TCP-062 |

#### Step 6: URG Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-063 | MAY | Ignore URG flag and Urgent Pointer (urgent data not supported) | RFC 9293 §3.10.7.4 Step 6, Architecture | TEST-TCP-063 |

#### Step 7: Segment Text (Data) Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-064 | MUST | In ESTABLISHED/FIN-WAIT-1/FIN-WAIT-2: deliver segment data to receive buffer | RFC 9293 §3.10.7.4 Step 7 | TEST-TCP-064 |
| REQ-TCP-065 | MUST | Advance RCV.NXT by the amount of data accepted | RFC 9293 §3.10.7.4 Step 7 | TEST-TCP-065 |
| REQ-TCP-066 | MUST | Send ACK after accepting data | RFC 9293 §3.10.7.4 Step 7 | TEST-TCP-066 |
| REQ-TCP-067 | MUST | Trim segment data to fit receive window (discard data outside window) | RFC 9293 §3.10.7.4 Step 7 | TEST-TCP-067 |

#### Step 8: FIN Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-068 | MUST | If FIN received, advance RCV.NXT over the FIN, send ACK | RFC 9293 §3.10.7.4 Step 8 | TEST-TCP-068 |
| REQ-TCP-069 | MUST | In SYN-RECEIVED or ESTABLISHED: transition to CLOSE-WAIT on FIN | RFC 9293 §3.10.7.4 Step 8 | TEST-TCP-069 |
| REQ-TCP-070 | MUST | In FIN-WAIT-1: if our FIN also ACKed, transition to TIME-WAIT; else transition to CLOSING | RFC 9293 §3.10.7.4 Step 8 | TEST-TCP-070 |
| REQ-TCP-071 | MUST | In FIN-WAIT-2: transition to TIME-WAIT on FIN | RFC 9293 §3.10.7.4 Step 8 | TEST-TCP-071 |

### RST Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-072 | MUST | Send RST when receiving segment for non-existent connection | RFC 9293 §3.5.1 | TEST-TCP-072 |
| REQ-TCP-073 | MUST | RST segment: if triggered by ACK, SEG.SEQ = SEG.ACK of triggering segment | RFC 9293 §3.5.1 | TEST-TCP-073 |
| REQ-TCP-074 | MUST | RST segment: if triggered by non-ACK, SEQ = 0, ACK = SEG.SEQ + SEG.LEN, ACK bit set | RFC 9293 §3.5.1 | TEST-TCP-074 |
| REQ-TCP-075 | MUST NOT | MUST NOT send RST in response to RST | RFC 9293 §3.5.1 | TEST-TCP-075 |

### Maximum Segment Size (MSS)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-076 | MUST | Send MSS option in SYN and SYN,ACK segments | RFC 9293 §3.7.1, RFC 6691 | TEST-TCP-076 |
| REQ-TCP-077 | MUST | Outbound MSS = min(tx buffer capacity - headers, 1460) for IPv4 | RFC 6691 §3 | TEST-TCP-077 |
| REQ-TCP-078 | MUST | If peer sends MSS option, limit outbound segment size to peer's MSS | RFC 9293 §3.7.1 | TEST-TCP-078 |
| REQ-TCP-079 | MUST | If peer does not send MSS option, assume default MSS = 536 (IPv4) | RFC 9293 §3.7.1 | TEST-TCP-079 |
| REQ-TCP-080 | MUST | IPv6 default MSS (no option) = 1220 | RFC 9293 §3.7.1 | TEST-TCP-080 |
| REQ-TCP-081 | MUST | Never send segments larger than min(our MSS, peer MSS) | RFC 9293 §3.7.1 | TEST-TCP-081 |

### Window Management

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-082 | MUST | Advertise receive window (RCV.WND) in every outbound segment | RFC 9293 §3.1 | TEST-TCP-082 |
| REQ-TCP-083 | MUST | Receive window reflects available space in RX buffer abstraction | RFC 9293 §3.4 | TEST-TCP-083 |
| REQ-TCP-084 | MUST | Honor peer's advertised window — do not send more data than SND.WND allows | RFC 9293 §3.8.6.2.1 | TEST-TCP-084 |
| REQ-TCP-085 | MUST | When peer advertises zero window, stop sending data (enter persist mode) | RFC 9293 §3.8.6.1 | TEST-TCP-085 |
| REQ-TCP-086 | MUST | Send window probe when peer's window is zero (persist timer) | RFC 9293 §3.8.6.1 | TEST-TCP-086 |
| REQ-TCP-087 | MUST | Window probe: send 1-byte segment to elicit window update | RFC 9293 §3.8.6.1 | TEST-TCP-087 |
| REQ-TCP-088 | SHOULD | Avoid Silly Window Syndrome (SWS): receiver SHOULD NOT advertise small window increments | RFC 9293 §3.8.6.2.2, RFC 1122 §4.2.3.3 | TEST-TCP-088 |
| REQ-TCP-089 | SHOULD | SWS avoidance (sender): do not send small segments when large window available | RFC 9293 §3.8.6.2.1, RFC 1122 §4.2.3.4 | TEST-TCP-089 |

### Retransmission (RFC 6298)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-090 | MUST | Maintain retransmission timer for unacknowledged segments | RFC 9293 §3.8.1, RFC 6298 | TEST-TCP-090 |
| REQ-TCP-091 | MUST | Compute RTO from SRTT and RTTVAR using Jacobson's algorithm | RFC 6298 §2 | TEST-TCP-091 |
| REQ-TCP-092 | MUST | Initial RTO = 1 second (before any RTT measurement) | RFC 6298 §2.1 | TEST-TCP-092 |
| REQ-TCP-093 | MUST | Minimum RTO = 1 second | RFC 6298 §2.4 | TEST-TCP-093 |
| REQ-TCP-094 | SHOULD | Maximum RTO SHOULD be at least 60 seconds | RFC 6298 §2.5 | TEST-TCP-094 |
| REQ-TCP-095 | MUST | On timeout: retransmit earliest unacknowledged segment | RFC 9293 §3.8.1, RFC 6298 §5.4 | TEST-TCP-095 |
| REQ-TCP-096 | MUST | On timeout: double RTO (exponential backoff) | RFC 6298 §5.5 | TEST-TCP-096 |
| REQ-TCP-097 | MUST | On ACK for new data: restart retransmission timer | RFC 6298 §5.3 | TEST-TCP-097 |
| REQ-TCP-098 | MUST | When all data acknowledged, stop retransmission timer | RFC 6298 §5.2 | TEST-TCP-098 |
| REQ-TCP-099 | MUST | Measure RTT per RFC 6298 (at most one measurement per RTT) | RFC 6298 §3 | TEST-TCP-099 |
| REQ-TCP-100 | MUST NOT | MUST NOT measure RTT for retransmitted segments (Karn's algorithm) | RFC 6298 §3, RFC 9293 §3.8.1 | TEST-TCP-100 |

### Congestion Control (RFC 5681)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-101 | MUST | Implement slow start: initialize cwnd to IW (Initial Window) | RFC 5681 §3.1 | TEST-TCP-101 |
| REQ-TCP-102 | MUST | IW = min(4 × MSS, max(2 × MSS, 4380)) per RFC 5681 (or 10 × MSS per RFC 6928 if opted in) | RFC 5681 §3.1, RFC 6928 | TEST-TCP-102 |
| REQ-TCP-103 | MUST | Slow start: increase cwnd by at most MSS per ACK of new data when cwnd < ssthresh | RFC 5681 §3.1 | TEST-TCP-103 |
| REQ-TCP-104 | MUST | Congestion avoidance: when cwnd ≥ ssthresh, increase cwnd by ~MSS per RTT | RFC 5681 §3.1 | TEST-TCP-104 |
| REQ-TCP-105 | MUST | On timeout: set ssthresh = max(FlightSize/2, 2×MSS), set cwnd = 1 × MSS (loss window) | RFC 5681 §3.1 | TEST-TCP-105 |
| REQ-TCP-106 | SHOULD | Implement fast retransmit: on 3 duplicate ACKs, retransmit without waiting for timeout | RFC 5681 §3.2 | TEST-TCP-106 |
| REQ-TCP-107 | SHOULD | After fast retransmit: set ssthresh = max(FlightSize/2, 2×MSS), enter fast recovery | RFC 5681 §3.2 | TEST-TCP-107 |
| REQ-TCP-108 | MAY | For single-segment stop-and-wait buffer mode, congestion control is inherently limited to 1 MSS in flight | Architecture | TEST-TCP-108 |

### TCP Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-109 | MUST | Parse TCP options in received SYN/SYN-ACK segments | RFC 9293 §3.7 | TEST-TCP-109 |
| REQ-TCP-110 | MUST | Support End of Option List (Kind 0) | RFC 9293 §3.7 | TEST-TCP-110 |
| REQ-TCP-111 | MUST | Support No-Operation (Kind 1) for padding | RFC 9293 §3.7 | TEST-TCP-111 |
| REQ-TCP-112 | MUST | Support MSS option (Kind 2, Length 4) | RFC 9293 §3.7.1 | TEST-TCP-112 |
| REQ-TCP-113 | MAY | Support Window Scale option (Kind 3, Length 3) in SYN segments | RFC 7323 §2 | TEST-TCP-113 |
| REQ-TCP-114 | MAY | Support Timestamps option (Kind 8, Length 10) | RFC 7323 §3 | TEST-TCP-114 |
| REQ-TCP-115 | MUST | Ignore unknown TCP options (skip using Length field) | RFC 9293 §3.7 | TEST-TCP-115 |
| REQ-TCP-116 | MUST | Options MUST only be sent in SYN segments unless option spec says otherwise | RFC 9293 §3.7 | TEST-TCP-116 |
| REQ-TCP-117 | MAY | Support SACK Permitted (Kind 4) and SACK (Kind 5) options | RFC 2018 | TEST-TCP-117 |

### Window Scale (RFC 7323 §2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-118 | MAY | Send Window Scale option in SYN if RX buffer > 65535 bytes | RFC 7323 §2 | TEST-TCP-118 |
| REQ-TCP-119 | MUST | Only negotiate Window Scale if both sides include it in SYN | RFC 7323 §2 | TEST-TCP-119 |
| REQ-TCP-120 | MUST | If negotiated, apply scale factor when interpreting peer's window | RFC 7323 §2 | TEST-TCP-120 |
| REQ-TCP-121 | MUST | Scale factor maximum = 14 (window up to 2^30) | RFC 7323 §2 | TEST-TCP-121 |

### Timestamps (RFC 7323 §3) — Optional

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-122 | MAY | Send Timestamps option for RTTM (Round-Trip Time Measurement) | RFC 7323 §3 | TEST-TCP-122 |
| REQ-TCP-123 | MUST | If timestamps negotiated, include TSopt in every segment | RFC 7323 §3.2 | TEST-TCP-123 |
| REQ-TCP-124 | MUST | TSecr (timestamp echo reply) MUST reflect most recent TSval received | RFC 7323 §3.2 | TEST-TCP-124 |

### Delayed ACK

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-125 | SHOULD | Implement delayed ACK: defer ACK for up to 500ms to piggyback on data | RFC 9293 §3.8.6.3, RFC 1122 §4.2.3.2 | TEST-TCP-125 |
| REQ-TCP-126 | MUST | ACK at least every second full-sized segment | RFC 9293 §3.8.6.3, RFC 5681 §4.2 | TEST-TCP-126 |
| REQ-TCP-127 | MUST | Delayed ACK timer MUST NOT exceed 500ms | RFC 1122 §4.2.3.2 | TEST-TCP-127 |
| REQ-TCP-128 | MAY | Disable delayed ACK (send ACK immediately on every segment) for simplicity | Architecture | TEST-TCP-128 |

### Nagle Algorithm

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-129 | SHOULD | Implement Nagle algorithm: if unACKed data in flight, buffer small segments | RFC 9293 §3.7.4, RFC 1122 §4.2.3.4 | TEST-TCP-129 |
| REQ-TCP-130 | MAY | Provide option to disable Nagle (TCP_NODELAY equivalent) | RFC 1122 §4.2.3.4 | TEST-TCP-130 |
| REQ-TCP-131 | MAY | Omit Nagle for simplicity in minimal configurations | Architecture | TEST-TCP-131 |

### Keep-Alive — Optional

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-132 | MAY | Implement TCP keep-alive probes | RFC 1122 §4.2.3.6 | TEST-TCP-132 |
| REQ-TCP-133 | MUST | Keep-alive MUST be disabled by default (only enabled by application) | RFC 1122 §4.2.3.6 | TEST-TCP-133 |
| REQ-TCP-134 | MUST | Keep-alive interval MUST be configurable, default ≥ 2 hours | RFC 1122 §4.2.3.6 | TEST-TCP-134 |

### ICMP Error Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-135 | MUST | Process ICMP Destination Unreachable for TCP connections | RFC 1122 §4.2.3.9 | TEST-TCP-135 |
| REQ-TCP-136 | SHOULD | Treat soft ICMP errors (e.g., Network Unreachable) as advisory, not connection-fatal | RFC 1122 §4.2.3.9 | TEST-TCP-136 |
| REQ-TCP-137 | MUST | Treat ICMP Host Unreachable/Protocol Unreachable as soft errors | RFC 1122 §4.2.3.9 | TEST-TCP-137 |
| REQ-TCP-138 | SHOULD | After multiple soft errors without successful data exchange, abort connection | RFC 1122 §4.2.3.9 | TEST-TCP-138 |

### Checksum

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-139 | MUST | Compute TCP checksum over pseudo-header + TCP header + data on transmission | RFC 9293 §3.1 | TEST-TCP-139 |
| REQ-TCP-140 | MUST | Verify TCP checksum on reception; discard on mismatch | RFC 9293 §3.1 | TEST-TCP-140 |
| REQ-TCP-141 | MUST | Support hardware checksum offload (write 0x0000, let MAC compute) | Architecture | TEST-TCP-141 |

### Buffer Abstraction Layer

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-142 | MUST | TCP implementation MUST NOT directly access buffer memory — use buffer ops vtable | Architecture | TEST-TCP-142 |
| REQ-TCP-143 | MUST | TX buffer ops: write, next_segment, ack, in_flight, window | Architecture | TEST-TCP-143 |
| REQ-TCP-144 | MUST | RX buffer ops: deliver, consume, available (for window advertisement) | Architecture | TEST-TCP-144 |
| REQ-TCP-145 | MUST | Provide stop-and-wait buffer implementation (1 segment in flight) | Architecture | TEST-TCP-145 |
| REQ-TCP-146 | SHOULD | Provide circular buffer implementation (streaming window) | Architecture | TEST-TCP-146 |
| REQ-TCP-147 | MAY | Provide packet-list buffer implementation (scatter-gather) | Architecture | TEST-TCP-147 |

### Connection Identification and Matching

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-148 | MUST | Match segments to connections using full 4-tuple: (local IP, local port, remote IP, remote port) | RFC 9293 §3.3.4 | TEST-TCP-148 |
| REQ-TCP-149 | MUST | LISTEN connections match on (local IP [any], local port, remote IP [any], remote port [any]) | RFC 9293 §3.3.4 | TEST-TCP-149 |
| REQ-TCP-150 | MUST | Application provides array/list of connections for the stack to scan | Architecture | TEST-TCP-150 |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-151 | MUST | Parse TCP header in-place in application buffer | Architecture | TEST-TCP-151 |
| REQ-TCP-152 | MUST | Build TCP header in-place in application buffer | Architecture | TEST-TCP-152 |

### Security Considerations

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TCP-153 | MUST | Randomize ISS to prevent sequence number prediction attacks | RFC 9293 §3.4.1, RFC 6528 | TEST-TCP-153 |
| REQ-TCP-154 | SHOULD | Implement challenge ACK for in-window SYN/RST (RFC 5961 blind attack mitigation) | RFC 5961, RFC 9293 §3.10.7.4 | TEST-TCP-154 |
| REQ-TCP-155 | SHOULD | Rate-limit RST generation to mitigate RST attacks | RFC 5961, RFC 9293 | TEST-TCP-155 |

## Notes

- **RFC 9293 consolidates RFC 793:** All TCP requirements now reference RFC 9293 as the primary source. Section numbers refer to RFC 9293.
- **Congestion control is mandatory:** RFC 5681 compliance is required. However, for the stop-and-wait buffer mode (1 segment in flight), congestion control is inherently satisfied since cwnd ≥ 1 MSS.
- **Urgent data not supported:** The URG flag and Urgent Pointer are parsed but the urgent mechanism is not implemented. This is acceptable per RFC 9293 §3.8.6 which notes urgent data is rarely used.
- **No SACK in V1:** SACK (RFC 2018) is a MAY. The stop-and-wait and circular buffer modes don't benefit from SACK since they handle loss via retransmit timeout.
- **Window Scale and Timestamps are optional:** For small MCUs with < 64 KB buffers, the 16-bit window field is sufficient. Window Scale is only needed if RX buffer exceeds 65535 bytes.
- **Active open needed for:** TCP clients (HTTP client, future TFTP-over-TCP, etc.). Not needed for server-only use cases but included for completeness.
