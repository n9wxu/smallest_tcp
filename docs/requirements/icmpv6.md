# ICMPv6 Requirements

**Protocol:** Internet Control Message Protocol for IPv6  
**Primary RFC:** RFC 4443 — Internet Control Message Protocol (ICMPv6) for IPv6 Specification  
**Supporting:** RFC 8200 §4 (IPv6 requires ICMPv6), RFC 4861 (NDP uses ICMPv6), RFC 4862 (SLAAC uses ICMPv6)  
**Supersession:** RFC 4443 supersedes RFC 2463  
**Scope:** V2 (IPv6 — required component; ICMPv6 is mandatory for any IPv6 implementation)  
**Last updated:** 2026-03-19

## Overview

ICMPv6 is the control protocol for IPv6, providing error reporting, diagnostics (ping), and serving as the transport for Neighbor Discovery Protocol (NDP). Unlike ICMPv4, ICMPv6 is **mandatory** for all IPv6 nodes. ICMPv6 uses IPv6 Next Header value 58.

## Message Format

```
Offset  Size  Field
  0      1    Type
  1      1    Code
  2      2    Checksum (mandatory, covers pseudo-header + ICMPv6 message)
  4      4    Type-specific data (varies)
  8+     var  Message body (varies)
```

ICMPv6 Types are divided into:
- **Error messages:** Type 1-127 (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem)
- **Informational messages:** Type 128-255 (Echo Request/Reply, NDP messages)

## Requirements

### Checksum (Mandatory for ICMPv6)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-001 | MUST | Compute ICMPv6 checksum over IPv6 pseudo-header + ICMPv6 header + body | RFC 4443 §2.3 | TEST-ICMPv6-001 |
| REQ-ICMPv6-002 | MUST | Verify checksum on all received ICMPv6 messages; discard on failure | RFC 4443 §2.3 | TEST-ICMPv6-002 |
| REQ-ICMPv6-003 | MUST | IPv6 pseudo-header for checksum: src (16) + dst (16) + ICMPv6 length (4) + zeros (3) + next header 58 (1) | RFC 8200 §8.1 | TEST-ICMPv6-003 |

### Echo (Ping) — Request and Reply

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-004 | MUST | Respond to Echo Request (Type 128, Code 0) with Echo Reply (Type 129, Code 0) | RFC 4443 §4.1, §4.2 | TEST-ICMPv6-004 |
| REQ-ICMPv6-005 | MUST | Echo Reply MUST contain same Identifier and Sequence Number as request | RFC 4443 §4.2 | TEST-ICMPv6-005 |
| REQ-ICMPv6-006 | MUST | Echo Reply MUST contain same data as request | RFC 4443 §4.2 | TEST-ICMPv6-006 |
| REQ-ICMPv6-007 | MUST | Echo Reply Source Address MUST be our address (unicast address the request was sent to) | RFC 4443 §4.2 | TEST-ICMPv6-007 |
| REQ-ICMPv6-008 | MUST | Echo Reply Destination Address MUST be the Source Address of the request | RFC 4443 §4.2 | TEST-ICMPv6-008 |
| REQ-ICMPv6-009 | MUST | If Echo Request sent to multicast, reply MUST use unicast source | RFC 4443 §4.2 | TEST-ICMPv6-009 |
| REQ-ICMPv6-010 | MAY | Support sending Echo Requests (ping6 client) | RFC 4443 §4.1 | TEST-ICMPv6-010 |

### Destination Unreachable (Type 1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-011 | MUST | Process received Destination Unreachable and pass to upper layer | RFC 4443 §3.1 | TEST-ICMPv6-011 |
| REQ-ICMPv6-012 | MUST | Code 0: No route to destination | RFC 4443 §3.1 | TEST-ICMPv6-012 |
| REQ-ICMPv6-013 | MUST | Code 1: Communication with destination administratively prohibited | RFC 4443 §3.1 | TEST-ICMPv6-013 |
| REQ-ICMPv6-014 | MUST | Code 3: Address unreachable | RFC 4443 §3.1 | TEST-ICMPv6-014 |
| REQ-ICMPv6-015 | MUST | Code 4: Port unreachable — pass to upper layer (TCP/UDP) | RFC 4443 §3.1 | TEST-ICMPv6-015 |
| REQ-ICMPv6-016 | SHOULD | Generate Destination Unreachable Code 4 for UDP datagrams to closed ports | RFC 4443 §3.1 | TEST-ICMPv6-016 |
| REQ-ICMPv6-017 | MUST | Extract as much of the invoking packet as possible (without exceeding minimum IPv6 MTU 1280) | RFC 4443 §3.1 | TEST-ICMPv6-017 |

### Packet Too Big (Type 2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-018 | MUST | Process received Packet Too Big messages | RFC 4443 §3.2 | TEST-ICMPv6-018 |
| REQ-ICMPv6-019 | MUST | Extract MTU field (bytes 4-7) for Path MTU Discovery | RFC 4443 §3.2 | TEST-ICMPv6-019 |
| REQ-ICMPv6-020 | SHOULD | Pass MTU to upper layer for future packet sizing | RFC 4443 §3.2 | TEST-ICMPv6-020 |
| REQ-ICMPv6-021 | MUST NOT | MUST NOT generate Packet Too Big (only routers generate this) | RFC 4443 §3.2 | TEST-ICMPv6-021 |

### Time Exceeded (Type 3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-022 | MUST | Process received Time Exceeded messages and pass to upper layer | RFC 4443 §3.3 | TEST-ICMPv6-022 |
| REQ-ICMPv6-023 | MUST NOT | MUST NOT generate Time Exceeded Code 0 (Hop Limit exceeded) — only routers | RFC 4443 §3.3 | TEST-ICMPv6-023 |
| REQ-ICMPv6-024 | MAY | Generate Time Exceeded Code 1 (Fragment reassembly exceeded) when discarding fragments | RFC 4443 §3.3 | TEST-ICMPv6-024 |

### Parameter Problem (Type 4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-025 | MUST | Process received Parameter Problem messages | RFC 4443 §3.4 | TEST-ICMPv6-025 |
| REQ-ICMPv6-026 | MUST | Code 1 (Unrecognized Next Header): generate when receiving unknown Next Header in extension chain | RFC 4443 §3.4, RFC 8200 §4 | TEST-ICMPv6-026 |
| REQ-ICMPv6-027 | MUST | Pointer field (bytes 4-7) indicates offset of the erroneous field | RFC 4443 §3.4 | TEST-ICMPv6-027 |

### ICMPv6 Error Message Rules

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-028 | MUST NOT | MUST NOT send ICMPv6 error in response to an ICMPv6 error message | RFC 4443 §2.4(e) | TEST-ICMPv6-028 |
| REQ-ICMPv6-029 | MUST NOT | MUST NOT send ICMPv6 error in response to a multicast destination packet (exceptions: Packet Too Big, Parameter Problem Code 2) | RFC 4443 §2.4(e) | TEST-ICMPv6-029 |
| REQ-ICMPv6-030 | MUST NOT | MUST NOT send ICMPv6 error in response to a packet with multicast source | RFC 4443 §2.4(e) | TEST-ICMPv6-030 |
| REQ-ICMPv6-031 | MUST NOT | MUST NOT send ICMPv6 error in response to a packet with unspecified source (::) | RFC 4443 §2.4(e) | TEST-ICMPv6-031 |
| REQ-ICMPv6-032 | MUST | ICMPv6 error body MUST include as much of invoking packet as fits in minimum MTU (1280 bytes) | RFC 4443 §2.4(c) | TEST-ICMPv6-032 |
| REQ-ICMPv6-033 | SHOULD | Rate-limit ICMPv6 error message generation | RFC 4443 §2.4(f) | TEST-ICMPv6-033 |

### NDP Messages (Dispatched to NDP)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-034 | MUST | Dispatch Type 133 (Router Solicitation) to NDP handler | RFC 4861 | TEST-ICMPv6-034 |
| REQ-ICMPv6-035 | MUST | Dispatch Type 134 (Router Advertisement) to NDP handler | RFC 4861 | TEST-ICMPv6-035 |
| REQ-ICMPv6-036 | MUST | Dispatch Type 135 (Neighbor Solicitation) to NDP handler | RFC 4861 | TEST-ICMPv6-036 |
| REQ-ICMPv6-037 | MUST | Dispatch Type 136 (Neighbor Advertisement) to NDP handler | RFC 4861 | TEST-ICMPv6-037 |
| REQ-ICMPv6-038 | MUST | Dispatch Type 137 (Redirect) to NDP handler | RFC 4861 | TEST-ICMPv6-038 |

### General

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-039 | MUST | Silently discard ICMPv6 informational messages with unknown Type | RFC 4443 §2.4(b) | TEST-ICMPv6-039 |
| REQ-ICMPv6-040 | MUST | Pass unrecognized ICMPv6 error messages to upper layer | RFC 4443 §2.4(a) | TEST-ICMPv6-040 |
| REQ-ICMPv6-041 | MUST | Parse ICMPv6 messages in-place (zero-copy) | Architecture | TEST-ICMPv6-041 |

## Notes

- **ICMPv6 is mandatory for IPv6.** Unlike ICMPv4 which is practically required, ICMPv6 is an absolute requirement — NDP (address resolution, router discovery) cannot function without it.
- **NDP runs over ICMPv6.** Types 133-137 are NDP messages. The ICMPv6 layer validates the checksum and dispatches to the NDP handler.
- **MLD (Multicast Listener Discovery):** Types 130-132. Not implemented in V2 unless multicast group management is needed beyond the implicit groups (all-nodes, solicited-node).
- **Error message size:** ICMPv6 error messages should include as much of the original packet as possible without exceeding 1280 bytes total.
