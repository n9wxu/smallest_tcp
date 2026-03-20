# SLAAC Requirements

**Protocol:** IPv6 Stateless Address Autoconfiguration  
**Primary RFC:** RFC 4862 — IPv6 Stateless Address Autoconfiguration  
**Supporting:** RFC 4861 §6 (Router Advertisement), RFC 4291 (address format), RFC 7217 (stable privacy addresses)  
**Scope:** V2 (IPv6)  
**Last updated:** 2026-03-19

## Overview

SLAAC allows an IPv6 host to configure a global unicast address automatically using Router Advertisement prefix information, without a DHCPv6 server. The host combines a network prefix (from RA) with an interface identifier (from MAC or random) to form a complete address. SLAAC also includes Duplicate Address Detection (DAD) to verify address uniqueness on the link.

## Address Formation

```
Global unicast address = Prefix (from RA, typically /64) + Interface Identifier (64 bits)

Interface Identifier options:
  - Modified EUI-64 from MAC: insert FF:FE, flip U/L bit
    MAC 00:11:22:33:44:55 → IID 0211:22FF:FE33:4455
  - Stable privacy address (RFC 7217): hash-based, non-trackable
  - Random (RFC 4941 temporary addresses): for privacy
```

## Requirements

### Link-Local Address Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-001 | MUST | Generate link-local address (fe80:: + interface identifier) on interface initialization | RFC 4862 §5.3 | TEST-SLAAC-001 |
| REQ-SLAAC-002 | MUST | Interface identifier: Modified EUI-64 from MAC (or stable privacy per RFC 7217) | RFC 4862 §5.3, RFC 4291 Appendix A | TEST-SLAAC-002 |
| REQ-SLAAC-003 | MUST | Modified EUI-64: insert FF:FE in middle of MAC, flip U/L bit (bit 6 of first byte) | RFC 4291 Appendix A | TEST-SLAAC-003 |
| REQ-SLAAC-004 | MUST | Perform DAD on link-local address before using it | RFC 4862 §5.4 | TEST-SLAAC-004 |

### Duplicate Address Detection (DAD) — RFC 4862 §5.4

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-005 | MUST | Send Neighbor Solicitation for DAD: Source = :: (unspecified), Target = tentative address | RFC 4862 §5.4.2 | TEST-SLAAC-005 |
| REQ-SLAAC-006 | MUST | NS destination: solicited-node multicast of tentative address | RFC 4862 §5.4.2 | TEST-SLAAC-006 |
| REQ-SLAAC-007 | MUST | Wait DupAddrDetectTransmits × RetransTimer (default: 1 × 1s) for response | RFC 4862 §5.4 | TEST-SLAAC-007 |
| REQ-SLAAC-008 | MUST | If NA received for tentative address, address is duplicate — do not use it | RFC 4862 §5.4.3 | TEST-SLAAC-008 |
| REQ-SLAAC-009 | MUST | If NS received from another host for same tentative address, address is duplicate | RFC 4862 §5.4.3 | TEST-SLAAC-009 |
| REQ-SLAAC-010 | MUST | If no response received during DAD period, address is unique — assign to interface | RFC 4862 §5.4.4 | TEST-SLAAC-010 |
| REQ-SLAAC-011 | MUST | DupAddrDetectTransmits defaults to 1 (one NS probe) | RFC 4862 §5.1 | TEST-SLAAC-011 |
| REQ-SLAAC-012 | MUST | Do not use tentative address as source for any packet (except DAD NS with source ::) | RFC 4862 §5.4 | TEST-SLAAC-012 |
| REQ-SLAAC-013 | MUST | Join solicited-node multicast group for tentative address before DAD | RFC 4862 §5.4.2 | TEST-SLAAC-013 |

### Global Address Configuration from RA

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-014 | MUST | Process Prefix Information option (Type 3) from Router Advertisement | RFC 4862 §5.5.3 | TEST-SLAAC-014 |
| REQ-SLAAC-015 | MUST | Check Autonomous flag (A flag) in Prefix Information — only autoconfigure if A=1 | RFC 4862 §5.5.3 | TEST-SLAAC-015 |
| REQ-SLAAC-016 | MUST | Check prefix length = 64 (standard for SLAAC on Ethernet) | RFC 4862 §5.5.3 | TEST-SLAAC-016 |
| REQ-SLAAC-017 | MUST | Form global address = prefix + interface identifier | RFC 4862 §5.5.3 | TEST-SLAAC-017 |
| REQ-SLAAC-018 | MUST | Perform DAD on newly formed global address | RFC 4862 §5.5.3 | TEST-SLAAC-018 |
| REQ-SLAAC-019 | MUST | Extract Valid Lifetime from Prefix Information | RFC 4862 §5.5.3 | TEST-SLAAC-019 |
| REQ-SLAAC-020 | MUST | Extract Preferred Lifetime from Prefix Information | RFC 4862 §5.5.3 | TEST-SLAAC-020 |
| REQ-SLAAC-021 | MUST | Preferred Lifetime MUST NOT exceed Valid Lifetime | RFC 4862 §5.5.3 | TEST-SLAAC-021 |
| REQ-SLAAC-022 | MUST | When Valid Lifetime expires, deprecate and eventually remove the address | RFC 4862 §5.5.3 | TEST-SLAAC-022 |
| REQ-SLAAC-023 | MUST | When Preferred Lifetime expires, mark address as deprecated (still usable for existing connections) | RFC 4862 §5.5.4 | TEST-SLAAC-023 |

### Prefix Lifetime Updates

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-024 | MUST | If RA with same prefix received, update Valid Lifetime and Preferred Lifetime | RFC 4862 §5.5.3 | TEST-SLAAC-024 |
| REQ-SLAAC-025 | MUST | If new Valid Lifetime > remaining lifetime, update | RFC 4862 §5.5.3(e) | TEST-SLAAC-025 |
| REQ-SLAAC-026 | MUST | If new Valid Lifetime > 2 hours, update | RFC 4862 §5.5.3(e) | TEST-SLAAC-026 |
| REQ-SLAAC-027 | MUST | If new Valid Lifetime < remaining and < 2 hours, set remaining to 2 hours (RFC 4862 safety) | RFC 4862 §5.5.3(e) | TEST-SLAAC-027 |

### Router Discovery Integration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-028 | MUST | Send Router Solicitation on startup (via NDP) | RFC 4862 §5.5.1 | TEST-SLAAC-028 |
| REQ-SLAAC-029 | MUST | Process Router Advertisement to obtain prefix and router information | RFC 4862 §5.5.1 | TEST-SLAAC-029 |
| REQ-SLAAC-030 | MUST | Use router's link-local address as next-hop for off-link destinations | RFC 4861 §6.3.4 | TEST-SLAAC-030 |
| REQ-SLAAC-031 | MUST | Store default router MAC (from RA Source Link-Layer Address option) | Architecture | TEST-SLAAC-031 |

### Privacy Extensions (Optional — RFC 7217, RFC 4941)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-032 | MAY | Support stable privacy addresses (RFC 7217) instead of EUI-64 | RFC 7217 | TEST-SLAAC-032 |
| REQ-SLAAC-033 | MAY | Support temporary addresses (RFC 4941) for privacy | RFC 4941 | TEST-SLAAC-033 |
| REQ-SLAAC-034 | SHOULD | Prefer stable privacy addresses (RFC 7217) over EUI-64 for trackability concerns | RFC 7217 §1 | TEST-SLAAC-034 |

### Interaction with DHCPv6

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-035 | MUST | If RA M flag = 1, initiate DHCPv6 for address assignment (in addition to or instead of SLAAC) | RFC 4861 §4.2 | TEST-SLAAC-035 |
| REQ-SLAAC-036 | MUST | If RA O flag = 1, initiate DHCPv6 for other configuration (DNS, etc.) but use SLAAC for address | RFC 4861 §4.2 | TEST-SLAAC-036 |
| REQ-SLAAC-037 | SHOULD | SLAAC and DHCPv6 can coexist (dual-source address configuration) | RFC 4862 §1 | TEST-SLAAC-037 |

## Notes

- **SLAAC is the simplest way to get an IPv6 global address.** No server needed — just a router sending RAs.
- **DAD is mandatory** but lightweight: one NS probe, 1-second wait. If no conflict, done.
- **EUI-64 exposes the MAC address** in the IPv6 address, which is a privacy concern. RFC 7217 provides an alternative that generates stable but opaque identifiers. For embedded devices that aren't mobile, EUI-64 is often acceptable.
- **Prefix is typically /64** on Ethernet. SLAAC requires at least /64 to generate an address.
- **Small memory footprint:** SLAAC needs to track: link-local address, one or two global addresses (with lifetimes), and the default router. This fits well in the application-managed memory model.
- **No DNS from SLAAC:** SLAAC provides addresses but not DNS servers. DNS comes from DHCPv6 (O flag) or DNS RA option (RFC 8106, RDNSS).
