# Ethernet Requirements

**Protocol:** Ethernet II (DIX) Framing  
**Primary RFC:** RFC 894 — A Standard for the Transmission of IP Datagrams over Ethernet Networks  
**Supporting:** IEEE 802.3, RFC 1122 §2.3.3  
**Scope:** V1 (IPv4)  
**Last updated:** 2026-03-19

## Overview

Ethernet II framing is the data link layer encapsulation used for IP traffic on Ethernet networks. This document covers frame structure, validation, and dispatch requirements. IEEE 802.3 LLC/SNAP framing is out of scope — only Ethernet II (DIX) is supported.

## Frame Format

```
Offset  Size  Field
  0      6    Destination MAC address
  6      6    Source MAC address
 12      2    EtherType (big-endian)
 14     46-1500  Payload
```

Minimum frame: 64 bytes (with FCS) = 60 bytes (without FCS). Maximum frame: 1518 bytes (with FCS) = 1514 bytes (without FCS). The MAC hardware typically strips and verifies the FCS, so the stack sees frames without FCS (14-byte header + 46–1500 byte payload).

## Requirements

### Frame Reception

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-001 | MUST | Accept frames with our unicast MAC as destination | RFC 894, IEEE 802.3 | TEST-ETH-001 |
| REQ-ETH-002 | MUST | Accept frames with broadcast MAC (FF:FF:FF:FF:FF:FF) as destination | RFC 894, IEEE 802.3 | TEST-ETH-002 |
| REQ-ETH-003 | MUST | Discard frames not addressed to our MAC or broadcast (unless promiscuous) | IEEE 802.3 | TEST-ETH-003 |
| REQ-ETH-004 | MUST | Parse EtherType field at offset 12 as big-endian uint16 | RFC 894 | TEST-ETH-004 |
| REQ-ETH-005 | MUST | Dispatch EtherType 0x0800 to IPv4 input | RFC 894 | TEST-ETH-005 |
| REQ-ETH-006 | MUST | Dispatch EtherType 0x0806 to ARP input | RFC 894 | TEST-ETH-006 |
| REQ-ETH-007 | MUST | Dispatch EtherType 0x86DD to IPv6 input (when IPv6 linked) | RFC 2464 §3 | TEST-ETH-007 |
| REQ-ETH-008 | MUST | Silently discard frames with unrecognized EtherType | RFC 1122 §2.3.3 | TEST-ETH-008 |
| REQ-ETH-009 | MUST | Silently discard frames shorter than 14 bytes (no valid header) | IEEE 802.3 | TEST-ETH-009 |
| REQ-ETH-010 | SHOULD | Accept multicast frames for subscribed multicast groups (e.g., IPv6 solicited-node) | IEEE 802.3 | TEST-ETH-010 |

### Frame Transmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-011 | MUST | Build Ethernet header with correct destination MAC, source MAC, and EtherType | RFC 894 | TEST-ETH-011 |
| REQ-ETH-012 | MUST | Source MAC in transmitted frames MUST be our own MAC address | IEEE 802.3 | TEST-ETH-012 |
| REQ-ETH-013 | MUST | EtherType MUST be 0x0800 for IPv4 payloads | RFC 894 | TEST-ETH-013 |
| REQ-ETH-014 | MUST | EtherType MUST be 0x0806 for ARP payloads | RFC 894 | TEST-ETH-014 |
| REQ-ETH-015 | MUST | EtherType MUST be 0x86DD for IPv6 payloads | RFC 2464 §3 | TEST-ETH-015 |
| REQ-ETH-016 | SHOULD | Pad frames shorter than 60 bytes (minimum Ethernet frame without FCS) to 60 bytes | IEEE 802.3 §3.2.8 | TEST-ETH-016 |

### Frame Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-017 | MUST | Reject frames where EtherType ≤ 0x05DC as IEEE 802.3 length-encoded (not supported) | RFC 894, IEEE 802.3 | TEST-ETH-017 |
| REQ-ETH-018 | MUST | Frame payload length derived from `frame_len - 14` | RFC 894 | TEST-ETH-018 |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-019 | MUST | Parse headers in-place — do not copy frame data | Architecture | TEST-ETH-019 |
| REQ-ETH-020 | MUST | Build headers in-place in application buffer | Architecture | TEST-ETH-020 |

## Notes

- FCS (Frame Check Sequence, 4-byte CRC32) is handled by MAC hardware and not visible to the stack. Requirements assume FCS has been stripped on RX and will be appended on TX by the MAC.
- VLAN tagging (802.1Q) is not supported in V1. If a VLAN tag is present, EtherType at offset 12 will be 0x8100, which will be discarded per REQ-ETH-008.
- Jumbo frames are not supported. Maximum frame length is 1514 bytes (without FCS).
