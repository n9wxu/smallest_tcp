# Checksum Requirements

**Protocol:** Internet Checksum  
**Primary RFC:** RFC 1071 — Computing the Internet Checksum  
**Supporting:** RFC 1624 — Computation of the Internet Checksum via Incremental Update  
**Scope:** V1 (IPv4), also used by V2 (IPv6) protocols  
**Last updated:** 2026-03-19

## Overview

The Internet checksum is the one's complement sum of the 16-bit words in the data, with the result complemented. It is used in IPv4 headers, ICMPv4, ICMPv6, UDP, and TCP. This stack provides an incremental checksum API that supports streaming computation, pseudo-header inclusion, and integration with hardware checksum offload.

## Algorithm

1. Sum all 16-bit words in the data (treating the data as an array of `uint16_t` in network byte order).
2. If the data has an odd number of bytes, pad the last byte with a zero byte and include it.
3. Fold any carry bits from the high 16 bits into the low 16 bits, repeatedly until no carry.
4. Take the one's complement (bitwise NOT) of the result.
5. A checksum of 0x0000 in a computed result means the data verified correctly.

## Requirements

### Core Computation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-001 | MUST | Compute Internet checksum per RFC 1071: one's complement sum of 16-bit words, then complement | RFC 1071 §1 | TEST-CKSUM-001 |
| REQ-CKSUM-002 | MUST | Handle odd-length data by logically padding a zero byte | RFC 1071 §1 | TEST-CKSUM-002 |
| REQ-CKSUM-003 | MUST | Fold carry bits until result fits in 16 bits | RFC 1071 §1 | TEST-CKSUM-003 |
| REQ-CKSUM-004 | MUST | Return 0xFFFF (not 0x0000) when computed checksum is zero (UDP special case: 0 means "no checksum") | RFC 768, RFC 1071 | TEST-CKSUM-004 |

### Incremental API

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-005 | MUST | Support incremental (streaming) computation: init → add(data, len) → ... → add(data, len) → finalize | RFC 1071 §2 | TEST-CKSUM-005 |
| REQ-CKSUM-006 | MUST | Incremental computation MUST produce the same result as computing over the entire data at once | RFC 1071 §2 | TEST-CKSUM-006 |
| REQ-CKSUM-007 | MUST | Support adding individual uint16 values (for pseudo-header fields) | RFC 1071 §2 | TEST-CKSUM-007 |
| REQ-CKSUM-008 | MUST | `net_cksum_init()` MUST zero the accumulator | Architecture | TEST-CKSUM-008 |
| REQ-CKSUM-009 | MUST | `net_cksum_finalize()` MUST fold carries and complement | RFC 1071 §1 | TEST-CKSUM-009 |

### Verification

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-010 | MUST | Verifying a checksum: compute checksum over data including the checksum field; result MUST be 0x0000 (or 0xFFFF before complement) | RFC 1071 §1 | TEST-CKSUM-010 |
| REQ-CKSUM-011 | MUST | Provide a convenience function `net_cksum_verify(data, len)` that returns true if checksum verifies | Architecture | TEST-CKSUM-011 |

### Incremental Update (RFC 1624)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-012 | MAY | Support incremental checksum update when modifying a single field (e.g., TTL decrement) | RFC 1624 | TEST-CKSUM-012 |
| REQ-CKSUM-013 | MAY | `net_cksum_update(old_cksum, old_val, new_val)` returns updated checksum without recomputing over entire header | RFC 1624 §3 | TEST-CKSUM-013 |

### Protocol-Specific Usage

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-014 | MUST | IPv4 header checksum covers only the IP header (20–60 bytes), not the payload | RFC 791 §3.1 | TEST-CKSUM-014 |
| REQ-CKSUM-015 | MUST | ICMPv4 checksum covers the ICMP header and data | RFC 792 | TEST-CKSUM-015 |
| REQ-CKSUM-016 | MUST | UDP checksum covers pseudo-header + UDP header + UDP data | RFC 768 | TEST-CKSUM-016 |
| REQ-CKSUM-017 | MUST | TCP checksum covers pseudo-header + TCP header + TCP data | RFC 9293 §3.1 | TEST-CKSUM-017 |
| REQ-CKSUM-018 | MUST | IPv4 pseudo-header: src IP (4) + dst IP (4) + zero (1) + protocol (1) + length (2) = 12 bytes | RFC 768, RFC 9293 | TEST-CKSUM-018 |
| REQ-CKSUM-019 | MUST | IPv6 pseudo-header: src IP (16) + dst IP (16) + length (4) + zeros (3) + next header (1) = 40 bytes | RFC 8200 §8.1 | TEST-CKSUM-019 |
| REQ-CKSUM-020 | MUST | UDP checksum is mandatory for IPv6 (MUST NOT be zero) | RFC 8200 §8.1 | TEST-CKSUM-020 |
| REQ-CKSUM-021 | MAY | UDP checksum for IPv4 MAY be zero (indicates "no checksum computed") | RFC 768 | TEST-CKSUM-021 |

### Hardware Checksum Offload

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-022 | MAY | MAC HAL MAY report TX checksum offload capability via capability flags | Architecture | TEST-CKSUM-022 |
| REQ-CKSUM-023 | MUST | If MAC reports TX checksum offload for a protocol, the protocol layer MUST write 0x0000 in the checksum field and let the MAC fill it in | Architecture | TEST-CKSUM-023 |
| REQ-CKSUM-024 | MAY | MAC HAL MAY report RX checksum verified flag | Architecture | TEST-CKSUM-024 |
| REQ-CKSUM-025 | MUST | If MAC reports RX checksum verified, the protocol layer MAY skip software checksum verification | Architecture | TEST-CKSUM-025 |
| REQ-CKSUM-026 | MUST | Software checksum MUST always be available as fallback when hardware offload is not present | Architecture | TEST-CKSUM-026 |

### Performance

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-CKSUM-027 | SHOULD | Accumulator SHOULD use uint32 to defer carry folding (reduces folds to finalize only) | RFC 1071 §2(B) | TEST-CKSUM-027 |
| REQ-CKSUM-028 | SHOULD | Inner loop SHOULD process 16-bit words, not individual bytes, for speed | RFC 1071 §2(C) | TEST-CKSUM-028 |
| REQ-CKSUM-029 | SHOULD | Handle unaligned data pointers correctly on architectures requiring alignment | Architecture | TEST-CKSUM-029 |

## Notes

- **ICMP echo reply optimization:** When building an ICMP echo reply by swapping src/dst in place, the IP header checksum can be updated incrementally (RFC 1624) instead of recomputed. The ICMP checksum remains unchanged if only IP fields changed.
- **8-bit targets (PIC16):** The checksum inner loop on 8-bit targets processes byte pairs. The uint32 accumulator prevents overflow for frames up to ~128 KB (well beyond any frame we'll see).
- **Testing strategy:** Checksum tests should use known-good vectors from RFC 1071 examples and from captured real-world packets.
