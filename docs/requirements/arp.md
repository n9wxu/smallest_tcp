# ARP Requirements

**Protocol:** Address Resolution Protocol  
**Primary RFC:** RFC 826 — An Ethernet Address Resolution Protocol  
**Supporting:** RFC 1122 §2.3.2.1, RFC 5227 (ARP Conflict Detection), RFC 1122 §3.3.1  
**Scope:** V1 (IPv4 only — IPv6 uses NDP, see ndp.md)  
**Last updated:** 2026-03-19

## Overview

ARP maps IPv4 addresses to Ethernet (link-layer) MAC addresses. This stack uses a distributed ARP model: no global ARP cache table. Instead, resolved MAC addresses are stored in the application's connection structures (TCP connections, UDP peers, gateway, etc.).

## Packet Format

```
Offset  Size  Field
  0      2    Hardware Type (1 = Ethernet)
  2      2    Protocol Type (0x0800 = IPv4)
  4      1    Hardware Address Length (6)
  5      1    Protocol Address Length (4)
  6      2    Operation (1 = Request, 2 = Reply)
  8      6    Sender Hardware Address (MAC)
 14      4    Sender Protocol Address (IPv4)
 18      6    Target Hardware Address (MAC)
 24      4    Target Protocol Address (IPv4)
```

Total: 28 bytes. Encapsulated in Ethernet frame with EtherType 0x0806.

## Requirements

### Inbound ARP Request Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-001 | MUST | Respond to ARP requests where Target Protocol Address matches our IPv4 address | RFC 826, RFC 1122 §2.3.2.1 | TEST-ARP-001 |
| REQ-ARP-002 | MUST | ARP reply MUST contain our MAC in Sender Hardware Address and our IP in Sender Protocol Address | RFC 826 | TEST-ARP-002 |
| REQ-ARP-003 | MUST | ARP reply destination MUST be the requester's MAC (unicast), not broadcast | RFC 826 | TEST-ARP-003 |
| REQ-ARP-004 | MUST | Silently discard ARP requests where Target Protocol Address does not match our IPv4 address | RFC 826 | TEST-ARP-004 |
| REQ-ARP-005 | MUST | Validate Hardware Type = 1 (Ethernet) and Protocol Type = 0x0800 (IPv4) | RFC 826 | TEST-ARP-005 |
| REQ-ARP-006 | MUST | Validate HLEN = 6 and PLEN = 4 | RFC 826 | TEST-ARP-006 |
| REQ-ARP-007 | MUST | Silently discard ARP packets with invalid Hardware Type, Protocol Type, HLEN, or PLEN | RFC 826 | TEST-ARP-007 |
| REQ-ARP-008 | SHOULD | Fast-path filter: check Target Protocol Address at fixed offset (byte 38 in Ethernet frame) before full parse | Architecture (performance) | TEST-ARP-008 |
| REQ-ARP-009 | SHOULD | On hardware MACs, use `peek()` to read Target IP without reading full frame; use `discard()` if not for us | Architecture (performance) | TEST-ARP-009 |

### Inbound ARP Reply Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-010 | MUST | When an ARP reply is received, check Sender Protocol Address against active connections awaiting resolution | RFC 826 | TEST-ARP-010 |
| REQ-ARP-011 | MUST | If a matching connection is found, store Sender Hardware Address as the connection's resolved MAC | RFC 826 | TEST-ARP-011 |
| REQ-ARP-012 | MUST | Mark the connection's MAC as valid after storing it | Architecture | TEST-ARP-012 |
| REQ-ARP-013 | SHOULD | Silently discard ARP replies that don't match any pending resolution | Architecture | TEST-ARP-013 |
| REQ-ARP-014 | MUST | Validate Operation = 2 (Reply) before processing as a reply | RFC 826 | TEST-ARP-014 |

### Outbound ARP Request Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-015 | MUST | Send ARP request when sending to an IP with `mac_valid == 0` | RFC 826 | TEST-ARP-015 |
| REQ-ARP-016 | MUST | ARP request MUST be sent to broadcast MAC (FF:FF:FF:FF:FF:FF) | RFC 826 | TEST-ARP-016 |
| REQ-ARP-017 | MUST | ARP request Target Protocol Address MUST be the destination IP (or gateway IP if off-subnet) | RFC 826, RFC 1122 §3.3.1 | TEST-ARP-017 |
| REQ-ARP-018 | MUST | Defer data packet transmission until ARP reply is received | RFC 826 | TEST-ARP-018 |
| REQ-ARP-019 | MUST | ARP request Sender Hardware Address MUST be our MAC | RFC 826 | TEST-ARP-019 |
| REQ-ARP-020 | MUST | ARP request Sender Protocol Address MUST be our IPv4 address | RFC 826 | TEST-ARP-020 |

### ARP Timeout and Retry

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-021 | MUST | Retransmit ARP request if no reply received within timeout | RFC 1122 §2.3.2.1 | TEST-ARP-021 |
| REQ-ARP-022 | SHOULD | ARP request timeout SHOULD be approximately 1 second | RFC 1122 §2.3.2.1 | TEST-ARP-022 |
| REQ-ARP-023 | MUST | Limit ARP retransmissions (SHOULD NOT exceed ~5 retries) | RFC 1122 §2.3.2.1 | TEST-ARP-023 |
| REQ-ARP-024 | MUST | Report failure to upper layer after ARP resolution timeout | RFC 1122 §2.3.2.1 | TEST-ARP-024 |

### Routing and Gateway

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-025 | MUST | For destinations on the local subnet (per subnet mask), ARP the destination IP directly | RFC 1122 §3.3.1.1 | TEST-ARP-025 |
| REQ-ARP-026 | MUST | For destinations off-subnet, ARP the gateway IP instead of the destination IP | RFC 1122 §3.3.1.1 | TEST-ARP-026 |
| REQ-ARP-027 | MUST | Store gateway MAC in `net_t` (not in per-connection state) | Architecture | TEST-ARP-027 |
| REQ-ARP-028 | MAY | Support "gateway-only" mode where ALL packets are sent to gateway MAC regardless of subnet | Architecture (minimal config) | TEST-ARP-028 |

### Distributed Cache Model

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-029 | MUST | No global ARP cache table — MAC addresses stored in application's connection structures | Architecture | TEST-ARP-029 |
| REQ-ARP-030 | MUST | Each TCP connection stores `{remote_mac[6], mac_valid}` for its peer | Architecture | TEST-ARP-030 |
| REQ-ARP-031 | MAY | UDP peers optionally store `{remote_mac[6], mac_valid}` for persistent associations | Architecture | TEST-ARP-031 |
| REQ-ARP-032 | SHOULD | Provide callback/scan mechanism for ARP reply handler to find matching connections | Architecture | TEST-ARP-032 |

### Gratuitous ARP

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-033 | MAY | Send gratuitous ARP on IP address configuration (announce our presence) | RFC 5227 §3 | TEST-ARP-033 |
| REQ-ARP-034 | MAY | Process received gratuitous ARP to update connection MACs if sender IP matches | RFC 5227 | TEST-ARP-034 |
| REQ-ARP-035 | SHOULD | Silently discard gratuitous ARP if no matching connection exists | Architecture | TEST-ARP-035 |

### Security Considerations

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-036 | MUST NOT | MUST NOT update MAC for a connection based on unsolicited ARP request sender information (ARP cache poisoning defense) | Architecture (security) | TEST-ARP-036 |
| REQ-ARP-037 | SHOULD | Only update MACs from ARP replies that match a pending resolution | Architecture (security) | TEST-ARP-037 |

## Notes

- **ARP storm handling:** On a busy network, the MAC RX buffer can overflow with broadcast ARP requests from other devices. The fast-path filter (REQ-ARP-008, REQ-ARP-009) is critical for draining these frames quickly on hardware MACs.
- **IPv6:** Does not use ARP. IPv6 address resolution uses Neighbor Discovery Protocol (NDP, RFC 4861). See `docs/requirements/ndp.md`.
- **No ARP Probe/Announce (RFC 5227):** Full Address Conflict Detection is a MAY. We support gratuitous ARP for announcing but do not implement the full probe/detect/defend sequence.
