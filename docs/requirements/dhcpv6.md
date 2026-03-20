# DHCPv6 Requirements

**Protocol:** Dynamic Host Configuration Protocol for IPv6  
**Primary RFC:** RFC 8415 — Dynamic Host Configuration Protocol for IPv6 (DHCPv6)  
**Supporting:** RFC 4861 §4.2 (M/O flags), RFC 3646 — DNS Configuration Options for DHCPv6  
**Supersession:** RFC 8415 supersedes RFC 3315, RFC 3633, RFC 3736  
**Scope:** V2 (IPv6)  
**Last updated:** 2026-03-19

## Overview

DHCPv6 provides IPv6 address assignment (when RA M flag = 1) and other configuration such as DNS servers (when RA O flag = 1). Unlike DHCPv4, DHCPv6 uses UDP on ports 546 (client) and 547 (server), and communication is via link-local multicast rather than broadcast. This stack implements a DHCPv6 client in stateless mode (Information-Request for DNS/config) and optionally stateful mode (Solicit/Advertise/Request for address assignment).

## Message Format

```
Offset  Size  Field
  0      1    msg-type
  1      3    transaction-id
  4     var   options (TLV: option-code (2) + option-len (2) + option-data (var))
```

## Message Types

| Type | Name | Direction |
|---|---|---|
| 1 | SOLICIT | Client → Server (multicast) |
| 2 | ADVERTISE | Server → Client |
| 3 | REQUEST | Client → Server (multicast) |
| 4 | CONFIRM | Client → Server (multicast) |
| 5 | RENEW | Client → Server (unicast or multicast) |
| 6 | REBIND | Client → Server (multicast) |
| 7 | REPLY | Server → Client |
| 8 | RELEASE | Client → Server (unicast or multicast) |
| 11 | INFORMATION-REQUEST | Client → Server (multicast) |

## Requirements

### Stateless DHCPv6 (Information-Request — RA O flag)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-001 | MUST | Support stateless DHCPv6: send INFORMATION-REQUEST (type 11) when RA O flag = 1 | RFC 8415 §6.1, §18.2.6 | TEST-DHCPv6-001 |
| REQ-DHCPv6-002 | MUST | INFORMATION-REQUEST sent to All_DHCP_Relay_Agents_and_Servers (ff02::1:2) | RFC 8415 §7.1 | TEST-DHCPv6-002 |
| REQ-DHCPv6-003 | MUST | Source port = 546, destination port = 547 | RFC 8415 §7.2 | TEST-DHCPv6-003 |
| REQ-DHCPv6-004 | MUST | Include Client Identifier option (option 1) with DUID | RFC 8415 §18.2.6 | TEST-DHCPv6-004 |
| REQ-DHCPv6-005 | MUST | Include Option Request option (option 6) listing desired options (DNS servers, etc.) | RFC 8415 §18.2.6 | TEST-DHCPv6-005 |
| REQ-DHCPv6-006 | MUST | Include Elapsed Time option (option 8) | RFC 8415 §18.2.6 | TEST-DHCPv6-006 |
| REQ-DHCPv6-007 | MUST | Process REPLY (type 7) to INFORMATION-REQUEST | RFC 8415 §18.2.10 | TEST-DHCPv6-007 |
| REQ-DHCPv6-008 | MUST | Extract DNS Recursive Name Server option (option 23, RFC 3646) | RFC 3646 §3 | TEST-DHCPv6-008 |
| REQ-DHCPv6-009 | MAY | Extract DNS Domain Search List option (option 24, RFC 3646) | RFC 3646 §4 | TEST-DHCPv6-009 |

### Stateful DHCPv6 (Address Assignment — RA M flag)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-010 | MAY | Support stateful DHCPv6 for address assignment when RA M flag = 1 | RFC 8415 §6.1 | TEST-DHCPv6-010 |
| REQ-DHCPv6-011 | MUST | SOLICIT → ADVERTISE → REQUEST → REPLY four-message exchange | RFC 8415 §18.2.1 | TEST-DHCPv6-011 |
| REQ-DHCPv6-012 | MAY | Support two-message exchange: SOLICIT (with Rapid Commit) → REPLY | RFC 8415 §18.2.1 | TEST-DHCPv6-012 |

### SOLICIT (Type 1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-013 | MUST | Send SOLICIT to ff02::1:2 on port 547 | RFC 8415 §18.2.1 | TEST-DHCPv6-013 |
| REQ-DHCPv6-014 | MUST | Include Client Identifier (option 1) | RFC 8415 §18.2.1 | TEST-DHCPv6-014 |
| REQ-DHCPv6-015 | MUST | Include IA_NA (Identity Association for Non-temporary Addresses, option 3) | RFC 8415 §18.2.1 | TEST-DHCPv6-015 |
| REQ-DHCPv6-016 | MUST | Include Elapsed Time (option 8) | RFC 8415 §18.2.1 | TEST-DHCPv6-016 |
| REQ-DHCPv6-017 | MUST | Include Option Request (option 6) for desired configuration options | RFC 8415 §18.2.1 | TEST-DHCPv6-017 |
| REQ-DHCPv6-018 | MAY | Include Rapid Commit option (option 14) for two-message exchange | RFC 8415 §18.2.1 | TEST-DHCPv6-018 |

### ADVERTISE Processing (Type 2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-019 | MUST | Validate: transaction-id matches | RFC 8415 §18.2.9 | TEST-DHCPv6-019 |
| REQ-DHCPv6-020 | MUST | Extract Server Identifier (option 2) | RFC 8415 §18.2.9 | TEST-DHCPv6-020 |
| REQ-DHCPv6-021 | MUST | Extract IA_NA with offered IA Address (option 5) | RFC 8415 §18.2.9 | TEST-DHCPv6-021 |
| REQ-DHCPv6-022 | SHOULD | Select first Advertise received (for simplicity) | RFC 8415 §18.2.9 | TEST-DHCPv6-022 |

### REQUEST (Type 3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-023 | MUST | Send REQUEST to ff02::1:2 (multicast, not unicast to server) | RFC 8415 §18.2.2 | TEST-DHCPv6-023 |
| REQ-DHCPv6-024 | MUST | Include Server Identifier from Advertise | RFC 8415 §18.2.2 | TEST-DHCPv6-024 |
| REQ-DHCPv6-025 | MUST | Include Client Identifier | RFC 8415 §18.2.2 | TEST-DHCPv6-025 |
| REQ-DHCPv6-026 | MUST | Include IA_NA with requested address from Advertise | RFC 8415 §18.2.2 | TEST-DHCPv6-026 |

### REPLY Processing (Type 7)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-027 | MUST | Validate transaction-id matches | RFC 8415 §18.2.10 | TEST-DHCPv6-027 |
| REQ-DHCPv6-028 | MUST | Extract assigned address from IA Address (option 5) within IA_NA | RFC 8415 §18.2.10 | TEST-DHCPv6-028 |
| REQ-DHCPv6-029 | MUST | Extract Preferred Lifetime and Valid Lifetime from IA Address | RFC 8415 §18.2.10 | TEST-DHCPv6-029 |
| REQ-DHCPv6-030 | MUST | Extract T1 (renewal time) and T2 (rebind time) from IA_NA | RFC 8415 §18.2.10 | TEST-DHCPv6-030 |
| REQ-DHCPv6-031 | MUST | Configure assigned IPv6 address on interface | RFC 8415 §18.2.10 | TEST-DHCPv6-031 |
| REQ-DHCPv6-032 | MUST | Perform DAD on assigned address before use | RFC 8415 §18.2.10, RFC 4862 §5.4 | TEST-DHCPv6-032 |

### DUID (DHCP Unique Identifier)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-033 | MUST | Generate DUID for Client Identifier | RFC 8415 §11 | TEST-DHCPv6-033 |
| REQ-DHCPv6-034 | SHOULD | Use DUID-LL (DUID based on Link-Layer Address, type 3): simplest, no time needed | RFC 8415 §11.4 | TEST-DHCPv6-034 |
| REQ-DHCPv6-035 | MUST | DUID-LL format: type (2 bytes) = 3, hardware type (2 bytes) = 1, MAC (6 bytes) | RFC 8415 §11.4 | TEST-DHCPv6-035 |

### Renewal and Rebinding

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-036 | MUST | Send RENEW (type 5) at T1 to extend lease | RFC 8415 §18.2.3 | TEST-DHCPv6-036 |
| REQ-DHCPv6-037 | MUST | Send REBIND (type 6) at T2 if RENEW fails | RFC 8415 §18.2.4 | TEST-DHCPv6-037 |
| REQ-DHCPv6-038 | MUST | If Valid Lifetime expires, remove address | RFC 8415 §18.2.10 | TEST-DHCPv6-038 |

### Retransmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-039 | MUST | Retransmit with exponential backoff per RFC 8415 §15 | RFC 8415 §15 | TEST-DHCPv6-039 |
| REQ-DHCPv6-040 | MUST | Initial retransmission timeout (IRT) varies by message type (e.g., SOL_TIMEOUT = 1s) | RFC 8415 §15.2 | TEST-DHCPv6-040 |
| REQ-DHCPv6-041 | MUST | Add randomization (±RAND, range [-0.1, +0.1] of RT) to retransmission | RFC 8415 §15.1 | TEST-DHCPv6-041 |

### Option Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-042 | MUST | Parse options in TLV format: option-code (2 bytes) + option-len (2 bytes) + data | RFC 8415 §21 | TEST-DHCPv6-042 |
| REQ-DHCPv6-043 | MUST | Skip unknown options using option-len | RFC 8415 §21 | TEST-DHCPv6-043 |
| REQ-DHCPv6-044 | MUST | Support nested options (e.g., IA Address inside IA_NA) | RFC 8415 §21.4, §21.6 | TEST-DHCPv6-044 |

## Notes

- **DHCPv6 is link-local multicast, not broadcast.** All client messages go to ff02::1:2 (All_DHCP_Relay_Agents_and_Servers).
- **DHCPv6 does NOT provide gateway/router information.** Default router comes from Router Advertisement only. DHCPv6 provides addresses and DNS.
- **Stateless mode (O flag only)** is much simpler than stateful. Many IPv6 networks use SLAAC for addressing + stateless DHCPv6 for DNS only.
- **DUID-LL is recommended** for embedded devices — it's just the MAC address with a type prefix. No RTC needed (unlike DUID-LLT which includes time).
- **UDP over IPv6:** DHCPv6 uses UDP ports 546/547. UDP checksum is mandatory over IPv6 (REQ-UDP-011).
- **Interaction with SLAAC:** A host may have both a SLAAC-assigned address and a DHCPv6-assigned address. They coexist on the same interface.
