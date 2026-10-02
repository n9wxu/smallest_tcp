# Checksum Requirements

**Protocol:** Internet Checksum  
**Primary RFC:** RFC 1071 — Computing the Internet Checksum  
**Supporting:** RFC 1624 — Computation of the Internet Checksum via Incremental Update  
**Scope:** IPv4 and IPv6: the IPv4 header, ICMPv4, IGMP, ICMPv6, UDP and TCP  
**Design:** [checksum.md](../design/checksum.md)

## Overview

The Internet checksum is the one's complement sum of the 16-bit words in the data, with the result complemented. It is used in IPv4 headers, ICMPv4, IGMP, ICMPv6, UDP, and TCP. This stack provides an incremental checksum API that supports streaming computation and pseudo-header inclusion. Every checksum is computed and verified in software; hardware checksum offload is not implemented.

## Algorithm

1. Sum all 16-bit words in the data (treating the data as an array of `uint16_t` in network byte order).
2. If the data has an odd number of bytes, pad the last byte with a zero byte and include it.
3. Fold any carry bits from the high 16 bits into the low 16 bits, repeatedly until no carry.
4. Take the one's complement (bitwise NOT) of the result.
5. A result of 0x0000 over data that includes its checksum field means the data verified correctly.

## Requirements

### Core Computation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-001 | MUST | Compute Internet checksum per RFC 1071: one's complement sum of 16-bit words, then complement | RFC 1071 §1 | itest_cksum_001_rfc1071_example |
| REQ-CKSUM-002 | MUST | Handle odd-length data by logically padding a zero byte | RFC 1071 §1 | itest_cksum_006_pieces_of_any_length, test_cksum_odd_byte |
| REQ-CKSUM-003 | MUST | Fold carry bits until result fits in 16 bits | RFC 1071 §1 | itest_cksum_001_rfc1071_example, test_cksum_carry_folding |
| REQ-CKSUM-004 | MUST | Send a UDP checksum that computes to 0x0000 as 0xFFFF: a UDP checksum field of 0 means "no checksum" (`net_cksum_finalize()` itself returns the computed value) | RFC 768 | itest_cksum_004_udp_zero_sent_as_ffff |

### Incremental API

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-005 | MUST | Support incremental (streaming) computation: init → add(data, len) → ... → add(data, len) → finalize | RFC 1071 §2 (A) | itest_cksum_006_pieces_of_any_length |
| REQ-CKSUM-006 | MUST | Incremental computation MUST produce the same result as computing over the entire data at once, wherever the data is cut — a piece of odd length included | RFC 1071 §2 (A) | itest_cksum_006_pieces_of_any_length, test_cksum_incremental_equals_oneshot |
| REQ-CKSUM-007 | MUST | Support adding individual uint16 values (for pseudo-header fields) | RFC 1071 §2 (A) | itest_cksum_006_pieces_of_any_length, test_cksum_add_u16 |
| REQ-CKSUM-008 | MUST | `net_cksum_init()` MUST zero the accumulator | Architecture | itest_cksum_006_pieces_of_any_length, test_cksum_init |
| REQ-CKSUM-009 | MUST | `net_cksum_finalize()` MUST fold carries and complement | RFC 1071 §1 | itest_cksum_001_rfc1071_example |

### Verification

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-010 | MUST | Verifying a checksum: compute checksum over data including the checksum field; result MUST be 0x0000 (the sum 0xFFFF before complement) | RFC 1071 §1 | itest_cksum_010_verify, test_cksum_known_ipv4_header |
| REQ-CKSUM-011 | MUST | Provide a convenience function `net_cksum_verify(data, len)` that returns true if checksum verifies | Architecture | itest_cksum_010_verify |

### Incremental Update (RFC 1624)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-012 | MAY | Support incremental checksum update when modifying a single field (e.g., TTL decrement) | RFC 1624 | test_cksum_update_ttl_decrement |
| REQ-CKSUM-013 | MAY | `net_cksum_update(old_cksum, old_val, new_val)` returns updated checksum without recomputing over entire header | RFC 1624 §3 | test_cksum_update_ttl_decrement |

### Protocol-Specific Usage

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-014 | MUST | IPv4 header checksum covers only the IP header (20–60 bytes), not the payload | RFC 791 §3.1 | itest_cksum_014_ipv4_header_only |
| REQ-CKSUM-015 | MUST | ICMPv4 checksum covers the ICMP header and data | RFC 792 | itest_icmpv4_001_echo_reply_code_zero |
| REQ-CKSUM-016 | MUST | UDP checksum covers pseudo-header + UDP header + UDP data | RFC 768 | itest_cksum_016_udp_pseudo_header |
| REQ-CKSUM-017 | MUST | TCP checksum covers pseudo-header + TCP header + TCP data | RFC 9293 §3.1 | itest_cksum_017_tcp_pseudo_header |
| REQ-CKSUM-018 | MUST | IPv4 pseudo-header: src IP (4) + dst IP (4) + zero (1) + protocol (1) + length (2) = 12 bytes | RFC 768, RFC 9293 §3.1 | itest_cksum_016_udp_pseudo_header, itest_cksum_017_tcp_pseudo_header |
| REQ-CKSUM-019 | MUST | IPv6 pseudo-header: src IP (16) + dst IP (16) + length (4) + zeros (3) + next header (1) = 40 bytes | RFC 8200 §8.1 | itest_cksum_019_ipv6_pseudo_header |
| REQ-CKSUM-020 | MUST | UDP checksum is mandatory for IPv6 (MUST NOT be zero) | RFC 8200 §8.1 | itest_cksum_019_ipv6_pseudo_header |
| REQ-CKSUM-021 | MAY | UDP checksum for IPv4 MAY be zero (indicates "no checksum computed"): accepted on reception, never sent | RFC 768 | itest_cksum_016_udp_pseudo_header |

### Hardware Checksum Offload

Not implemented: the MAC driver interface has no capability flags, and every checksum is computed and verified in software ([checksum.md §7](../design/checksum.md#7-hardware-offload-not-implemented)). The rows record what offload support would have to do.

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-022 | MAY | MAC HAL MAY report TX checksum offload capability via capability flags | Architecture | — (not implemented) |
| REQ-CKSUM-023 | MUST | If MAC reports TX checksum offload for a protocol, the protocol layer MUST write 0x0000 in the checksum field and let the MAC fill it in | Architecture | — (not implemented) |
| REQ-CKSUM-024 | MAY | MAC HAL MAY report RX checksum verified flag | Architecture | — (not implemented) |
| REQ-CKSUM-025 | MAY | If MAC reports RX checksum verified, the protocol layer MAY skip software checksum verification | Architecture | — (not implemented) |
| REQ-CKSUM-026 | MUST | Software checksum MUST always be available as fallback when hardware offload is not present | Architecture | itest_cksum_001_rfc1071_example |

### Performance

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-027 | SHOULD | Accumulator SHOULD use uint32 to defer carry folding (reduces folds to finalize only) | RFC 1071 §2 (1) | — |
| REQ-CKSUM-028 | SHOULD | Inner loop SHOULD add one 16-bit word per step; each word is composed from two bytes, so the result does not depend on the host's byte order | Architecture | — |
| REQ-CKSUM-029 | SHOULD | Handle unaligned data pointers correctly on architectures requiring alignment | Architecture | itest_cksum_006_pieces_of_any_length |

## Notes

- **ICMP echo replies** are checksummed in full: the reply is built in the TX buffer and its ICMP and IP header checksums computed there. `net_cksum_update()` (RFC 1624) is provided for applications that patch a field of a prebuilt frame; the stack does not use it.
- **8-bit targets (PIC16):** the inner loop reads byte pairs. The uint32 accumulator cannot overflow before about 131 KB have been added, well beyond any frame.
- **Testing strategy:** the integration tests check the API against RFC 1071's own example and against the test harness's independent implementation (`peer_cksum()`), and every checksum on the wire against the same.
