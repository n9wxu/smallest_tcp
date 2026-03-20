# ICMPv4 Requirements

**Protocol:** Internet Control Message Protocol (v4)  
**Primary RFC:** RFC 792 — Internet Control Message Protocol  
**Supporting:** RFC 1122 — Requirements for Internet Hosts (§3.2.2), RFC 1812 §4.3 (router reference)  
**Scope:** V1 (IPv4)  
**Last updated:** 2026-03-19

## Overview

ICMPv4 provides error reporting and diagnostic functions for IPv4. It is encapsulated directly in IPv4 (Protocol = 1). The primary functions for a minimal host are Echo Reply (ping response) and processing of error messages from the network.

## Header Format

```
Offset  Size  Field
  0      1    Type
  1      1    Code
  2      2    Checksum
  4      4    Type-specific data (varies)
  8+     var  Message body (varies)
```

Minimum: 8 bytes (header only, no additional data).

## ICMP Message Types

| Type | Code | Name | Direction |
|---|---|---|---|
| 0 | 0 | Echo Reply | Outbound (response to ping) |
| 3 | 0-15 | Destination Unreachable | Inbound (error) / Outbound (generated) |
| 4 | 0 | Source Quench (deprecated) | Inbound (ignore) |
| 5 | 0-3 | Redirect | Inbound (routing hint) |
| 8 | 0 | Echo Request | Inbound (ping) |
| 11 | 0-1 | Time Exceeded | Inbound (error) / Outbound (generated) |
| 12 | 0 | Parameter Problem | Inbound (error) |

## Requirements

### Echo (Ping) — Request and Reply

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-001 | MUST | Respond to Echo Request (Type 8, Code 0) with Echo Reply (Type 0, Code 0) | RFC 792, RFC 1122 §3.2.2.6 | TEST-ICMPv4-001 |
| REQ-ICMPv4-002 | MUST | Echo Reply MUST contain the same Identifier and Sequence Number as the Echo Request | RFC 792, RFC 1122 §3.2.2.6 | TEST-ICMPv4-002 |
| REQ-ICMPv4-003 | MUST | Echo Reply MUST contain the same data as the Echo Request | RFC 792, RFC 1122 §3.2.2.6 | TEST-ICMPv4-003 |
| REQ-ICMPv4-004 | MUST | Echo Reply Source Address MUST be our IP address | RFC 792 | TEST-ICMPv4-004 |
| REQ-ICMPv4-005 | MUST | Echo Reply Destination Address MUST be the Source Address of the Echo Request | RFC 792 | TEST-ICMPv4-005 |
| REQ-ICMPv4-006 | MUST | Compute correct ICMP checksum for Echo Reply | RFC 792 | TEST-ICMPv4-006 |
| REQ-ICMPv4-007 | SHOULD | Process Echo Request in-place: swap src/dst IP, change Type 8→0, update checksums | Architecture (zero-copy) | TEST-ICMPv4-007 |
| REQ-ICMPv4-008 | MUST | If Echo Request data is too large for TX buffer, silently discard (do not truncate) | Architecture | TEST-ICMPv4-008 |
| REQ-ICMPv4-009 | MUST NOT | MUST NOT respond to Echo Requests sent to broadcast/multicast unless explicitly enabled | RFC 1122 §3.2.2.6 | TEST-ICMPv4-009 |
| REQ-ICMPv4-010 | MAY | Support sending Echo Requests (ping client) for application use | RFC 792 | TEST-ICMPv4-010 |

### Destination Unreachable (Type 3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-011 | MUST | Process received Destination Unreachable messages | RFC 792, RFC 1122 §3.2.2.1 | TEST-ICMPv4-011 |
| REQ-ICMPv4-012 | MUST | Extract original IP header + first 8 bytes of original payload from ICMP error body | RFC 792 | TEST-ICMPv4-012 |
| REQ-ICMPv4-013 | MUST | Pass Destination Unreachable to upper layer (TCP/UDP) for connection error handling | RFC 1122 §3.2.2.1 | TEST-ICMPv4-013 |
| REQ-ICMPv4-014 | MUST | Code 2 (Protocol Unreachable): report to upper layer | RFC 792, RFC 1122 §3.2.2.1 | TEST-ICMPv4-014 |
| REQ-ICMPv4-015 | MUST | Code 3 (Port Unreachable): report to upper layer | RFC 792, RFC 1122 §3.2.2.1 | TEST-ICMPv4-015 |
| REQ-ICMPv4-016 | MUST | Code 4 (Fragmentation Needed + DF Set): report to upper layer with Next-Hop MTU | RFC 792, RFC 1122 §3.2.2.1 | TEST-ICMPv4-016 |
| REQ-ICMPv4-017 | SHOULD | Generate Destination Unreachable Code 2 (Protocol Unreachable) for unsupported IP protocols | RFC 1122 §3.2.2.1 | TEST-ICMPv4-017 |
| REQ-ICMPv4-018 | SHOULD | Generate Destination Unreachable Code 3 (Port Unreachable) for UDP packets to closed ports | RFC 1122 §3.2.2.1 | TEST-ICMPv4-018 |

### Redirect (Type 5)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-019 | SHOULD | Process received ICMP Redirect messages | RFC 792, RFC 1122 §3.2.2.2 | TEST-ICMPv4-019 |
| REQ-ICMPv4-020 | SHOULD | On Redirect, update the next-hop MAC for the specified destination if applicable | RFC 1122 §3.2.2.2 | TEST-ICMPv4-020 |
| REQ-ICMPv4-021 | MUST | Validate Redirect: new gateway must be on the same subnet | RFC 1122 §3.2.2.2 | TEST-ICMPv4-021 |
| REQ-ICMPv4-022 | MAY | Ignore Redirect if in "gateway-only" mode | Architecture | TEST-ICMPv4-022 |
| REQ-ICMPv4-023 | MUST NOT | MUST NOT generate ICMP Redirect (only routers generate redirects) | RFC 792 | TEST-ICMPv4-023 |

### Time Exceeded (Type 11)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-024 | MUST | Process received Time Exceeded messages and pass to upper layer | RFC 792, RFC 1122 §3.2.2.1 | TEST-ICMPv4-024 |
| REQ-ICMPv4-025 | MAY | Generate Time Exceeded Code 1 (Fragment Reassembly Time Exceeded) when discarding received fragments | RFC 792, RFC 1122 §3.3.2 | TEST-ICMPv4-025 |
| REQ-ICMPv4-026 | MUST NOT | MUST NOT generate Time Exceeded Code 0 (TTL Exceeded in Transit) — only routers do this | RFC 792 | TEST-ICMPv4-026 |

### Source Quench (Type 4) — Deprecated

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-027 | MUST NOT | MUST NOT generate Source Quench messages | RFC 6633 §1 (deprecates RFC 1122 §3.2.2.3) | TEST-ICMPv4-027 |
| REQ-ICMPv4-028 | MUST | Silently discard received Source Quench messages | RFC 6633 §1 | TEST-ICMPv4-028 |

**Note:** RFC 6633 supersedes RFC 1122 §3.2.2.3 — Source Quench is deprecated and MUST NOT be generated. Received Source Quench MUST be silently ignored.

### Parameter Problem (Type 12)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-029 | MUST | Process received Parameter Problem messages and pass to upper layer | RFC 792, RFC 1122 §3.2.2.5 | TEST-ICMPv4-029 |
| REQ-ICMPv4-030 | MAY | Generate Parameter Problem for received packets with erroneous headers | RFC 792 | TEST-ICMPv4-030 |

### Checksum

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-031 | MUST | Verify ICMP checksum on all received ICMP messages; discard on failure | RFC 792 | TEST-ICMPv4-031 |
| REQ-ICMPv4-032 | MUST | Compute correct ICMP checksum on all transmitted ICMP messages | RFC 792 | TEST-ICMPv4-032 |
| REQ-ICMPv4-033 | MUST | ICMP checksum covers Type + Code + Checksum + type-specific header + data | RFC 792 | TEST-ICMPv4-033 |

### ICMP Error Message Rules

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-034 | MUST NOT | MUST NOT send ICMP error in response to an ICMP error message | RFC 792, RFC 1122 §3.2.2 | TEST-ICMPv4-034 |
| REQ-ICMPv4-035 | MUST NOT | MUST NOT send ICMP error in response to a broadcast/multicast packet | RFC 1122 §3.2.2 | TEST-ICMPv4-035 |
| REQ-ICMPv4-036 | MUST NOT | MUST NOT send ICMP error in response to a packet with broadcast/multicast source | RFC 1122 §3.2.2 | TEST-ICMPv4-036 |
| REQ-ICMPv4-037 | MUST NOT | MUST NOT send ICMP error in response to a fragment (offset ≠ 0) | RFC 1122 §3.2.2 | TEST-ICMPv4-037 |
| REQ-ICMPv4-038 | MUST | ICMP error body MUST include original IP header + first 8 bytes of original datagram payload | RFC 792, RFC 1122 §3.2.2 | TEST-ICMPv4-038 |
| REQ-ICMPv4-039 | SHOULD | Rate-limit ICMP error message generation | RFC 1122 §3.2.2 | TEST-ICMPv4-039 |

### General

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-040 | MUST | Silently discard ICMP messages with unknown Type | RFC 1122 §3.2.2 | TEST-ICMPv4-040 |
| REQ-ICMPv4-041 | MUST | Parse ICMP messages in-place (zero-copy) | Architecture | TEST-ICMPv4-041 |

## Notes

- **Echo reply optimization:** The most efficient implementation swaps src/dst IP in-place, changes Type 8→0, and incrementally updates the IP header checksum (the ICMP checksum changes only due to the Type field change, which can be done with an incremental update per RFC 1624).
- **ICMP as error channel:** TCP and UDP use ICMP errors to detect unreachable destinations. The stack must route these errors to the appropriate upper-layer connection.
- **No ICMP rate limiting required for echo replies** — rate limiting applies to error messages only.
