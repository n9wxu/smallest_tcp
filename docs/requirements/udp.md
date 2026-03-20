# UDP Requirements

**Protocol:** User Datagram Protocol  
**Primary RFC:** RFC 768 — User Datagram Protocol  
**Supporting:** RFC 1122 — Requirements for Internet Hosts (§4.1), RFC 8200 §8.1 (IPv6 UDP checksum)  
**Scope:** V1 (IPv4), V2 (IPv6 — checksum requirements differ)  
**Last updated:** 2026-03-19

## Overview

UDP provides a simple, connectionless, unreliable datagram service. It adds port-based multiplexing and an optional (IPv4) or mandatory (IPv6) checksum on top of IP. UDP is used by DHCP, DNS, TFTP, and other protocols.

## Header Format

```
Offset  Size  Field
  0      2    Source Port
  2      2    Destination Port
  4      2    Length (header + data, minimum 8)
  6      2    Checksum
  8+     var  Data
```

Minimum: 8 bytes (header only, zero-length data).

## Requirements

### Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-001 | MUST | Parse UDP header at IP payload offset | RFC 768 | TEST-UDP-001 |
| REQ-UDP-002 | MUST | Verify UDP Length ≥ 8 | RFC 768 | TEST-UDP-002 |
| REQ-UDP-003 | MUST | Verify UDP Length ≤ IP payload length | RFC 768, RFC 1122 §4.1.3.4 | TEST-UDP-003 |
| REQ-UDP-004 | MUST | Use UDP Length (not IP payload length) to determine data length | RFC 768 | TEST-UDP-004 |
| REQ-UDP-005 | MUST | Silently discard datagrams with invalid length | RFC 768, RFC 1122 §4.1.3.4 | TEST-UDP-005 |

### Checksum — IPv4

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-006 | MUST | If received UDP checksum ≠ 0, verify checksum over pseudo-header + header + data | RFC 768, RFC 1122 §4.1.3.4 | TEST-UDP-006 |
| REQ-UDP-007 | MUST | Silently discard datagrams with checksum mismatch (when checksum is non-zero) | RFC 1122 §4.1.3.4 | TEST-UDP-007 |
| REQ-UDP-008 | MUST | If received UDP checksum = 0 over IPv4, accept without verification (checksum was not computed) | RFC 768 | TEST-UDP-008 |
| REQ-UDP-009 | SHOULD | Compute and include UDP checksum on transmitted IPv4 datagrams | RFC 1122 §4.1.3.4 | TEST-UDP-009 |
| REQ-UDP-010 | MAY | Transmit with checksum = 0 over IPv4 (no checksum) if application explicitly requests | RFC 768 | TEST-UDP-010 |

### Checksum — IPv6

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-011 | MUST | Compute and include UDP checksum on all transmitted IPv6 datagrams (checksum MUST NOT be zero) | RFC 8200 §8.1 | TEST-UDP-011 |
| REQ-UDP-012 | MUST | Verify UDP checksum on all received IPv6 datagrams | RFC 8200 §8.1 | TEST-UDP-012 |
| REQ-UDP-013 | MUST | Silently discard IPv6 UDP datagrams with checksum = 0 | RFC 8200 §8.1 | TEST-UDP-013 |

### Checksum — Pseudo-Header

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-014 | MUST | IPv4 pseudo-header for checksum: src IP (4) + dst IP (4) + zero (1) + protocol 17 (1) + UDP length (2) | RFC 768 | TEST-UDP-014 |
| REQ-UDP-015 | MUST | IPv6 pseudo-header for checksum: src IP (16) + dst IP (16) + UDP length (4) + zeros (3) + next header 17 (1) | RFC 8200 §8.1 | TEST-UDP-015 |

### Port Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-016 | MUST | Dispatch received datagrams by Destination Port to registered handler | RFC 768 | TEST-UDP-016 |
| REQ-UDP-017 | MUST | If no handler registered for Destination Port, generate ICMP Port Unreachable (Type 3, Code 3) | RFC 1122 §4.1.3.1 | TEST-UDP-017 |
| REQ-UDP-018 | MUST | Port handler registration is static (application provides port→callback mapping at init) | Architecture | TEST-UDP-018 |
| REQ-UDP-019 | MUST | Support simultaneous handlers on multiple ports | Architecture | TEST-UDP-019 |
| REQ-UDP-020 | MUST | Provide Source Port and Source IP to handler callback | RFC 768 | TEST-UDP-020 |

### Transmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-021 | MUST | Build UDP header with Source Port, Destination Port, Length, Checksum | RFC 768 | TEST-UDP-021 |
| REQ-UDP-022 | MUST | UDP Length = 8 + data length | RFC 768 | TEST-UDP-022 |
| REQ-UDP-023 | MUST | Pass assembled datagram to IP layer for header building and transmission | RFC 768 | TEST-UDP-023 |
| REQ-UDP-024 | MUST | Source Port MAY be 0 if no reply is expected; otherwise SHOULD be a valid port | RFC 768 | TEST-UDP-024 |

### Address Resolution Integration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-025 | MUST | Before sending, determine destination MAC: on-subnet → ARP target IP; off-subnet → use gateway MAC | RFC 1122 §3.3.1.1, Architecture | TEST-UDP-025 |
| REQ-UDP-026 | MAY | Support `udp_peer_t` structure that caches resolved MAC for persistent UDP associations | Architecture | TEST-UDP-026 |
| REQ-UDP-027 | MAY | In "gateway-only" mode, always use gateway MAC regardless of destination | Architecture | TEST-UDP-027 |

### Broadcast and Multicast

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-028 | MUST | Support receiving UDP datagrams sent to broadcast IP | RFC 1122 §4.1.3.3 | TEST-UDP-028 |
| REQ-UDP-029 | MUST | Support sending UDP datagrams to broadcast IP (255.255.255.255) | RFC 1122 §4.1.3.3 | TEST-UDP-029 |
| REQ-UDP-030 | MUST | When sending to broadcast, use broadcast MAC (FF:FF:FF:FF:FF:FF) | RFC 894 | TEST-UDP-030 |
| REQ-UDP-031 | MUST NOT | MUST NOT generate ICMP Port Unreachable for UDP datagrams received via broadcast/multicast | RFC 1122 §4.1.3.4 | TEST-UDP-031 |

### Buffer and Size Limits

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-032 | MUST | Maximum UDP payload = tx buffer capacity - ETH header (14) - IP header (20) - UDP header (8) | Architecture | TEST-UDP-032 |
| REQ-UDP-033 | MUST | Reject application send requests that exceed maximum UDP payload for the buffer | Architecture | TEST-UDP-033 |
| REQ-UDP-034 | MUST | If received datagram data exceeds rx buffer capacity, truncate or discard (implementation choice) | Architecture | TEST-UDP-034 |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-035 | MUST | Parse UDP header in-place in application buffer | Architecture | TEST-UDP-035 |
| REQ-UDP-036 | MUST | Build UDP header in-place in application buffer | Architecture | TEST-UDP-036 |
| REQ-UDP-037 | MUST | Handler callback receives pointer to payload data in rx buffer (no copy) | Architecture | TEST-UDP-037 |

### ICMP Integration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-038 | SHOULD | Process ICMP Destination Unreachable directed at a UDP flow (match by port + IP from ICMP error body) | RFC 1122 §4.1.3.3 | TEST-UDP-038 |
| REQ-UDP-039 | SHOULD | Report ICMP errors to application handler if applicable | RFC 1122 §4.1.3.3 | TEST-UDP-039 |

## Notes

- **UDP is connectionless:** Each datagram is independent. There is no connection state to manage.
- **DHCP uses UDP:** DHCP operates on ports 67/68 with broadcast. The stack must support receiving UDP on broadcast IP before an address is configured (REQ-IPv4-012).
- **DNS uses UDP:** DNS queries on port 53. The DNS resolver will register a handler.
- **TFTP uses UDP:** TFTP uses port 69 for initial contact, then ephemeral ports for data transfer.
