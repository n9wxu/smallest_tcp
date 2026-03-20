# IPv6 Requirements

**Protocol:** Internet Protocol version 6  
**Primary RFC:** RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification  
**Supporting:** RFC 4291 — IP Version 6 Addressing Architecture, RFC 6724 — Default Address Selection for IPv6, RFC 4443 — ICMPv6, RFC 1122 (host behavior parity)  
**Supersession:** RFC 8200 supersedes RFC 2460  
**Scope:** V2 (IPv6 fast-follow)  
**Last updated:** 2026-03-19

## Overview

IPv6 is the successor to IPv4 with a 128-bit address space, simplified header format, and no fragmentation at intermediate routers. This stack implements IPv6 host behavior. IPv6 requires ICMPv6 (RFC 4443) and Neighbor Discovery (RFC 4861) as mandatory components.

## Header Format

```
Offset  Size  Field
  0      4b   Version (6)
  0      8b   Traffic Class (DSCP + ECN)
  0     20b   Flow Label
  4      2    Payload Length (bytes after header, excludes 40-byte header)
  6      1    Next Header (protocol: 6=TCP, 17=UDP, 58=ICMPv6, 59=No Next, 0/43/44/60=Extension)
  7      1    Hop Limit (equivalent to TTL)
  8     16    Source Address (128 bits)
 24     16    Destination Address (128 bits)
```

Fixed header: 40 bytes (always). Extension headers follow if needed.

## Requirements

### Header Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-001 | MUST | Verify Version field = 6 | RFC 8200 §3 | TEST-IPv6-001 |
| REQ-IPv6-002 | MUST | Verify Payload Length + 40 ≤ actual received frame size | RFC 8200 §3 | TEST-IPv6-002 |
| REQ-IPv6-003 | MUST | Use Payload Length (not frame length) to determine payload boundaries | RFC 8200 §3 | TEST-IPv6-003 |
| REQ-IPv6-004 | MUST | Silently discard packets failing validation | RFC 8200 §4 | TEST-IPv6-004 |
| REQ-IPv6-005 | MUST NOT | IPv6 has no header checksum — MUST NOT compute or expect one | RFC 8200 §3 | TEST-IPv6-005 |

### Destination Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-006 | MUST | Accept packets where Destination Address matches any of our configured unicast addresses | RFC 8200 §3 | TEST-IPv6-006 |
| REQ-IPv6-007 | MUST | Accept packets where Destination Address matches a joined multicast group (e.g., all-nodes ff02::1) | RFC 8200 §3, RFC 4291 §2.7 | TEST-IPv6-007 |
| REQ-IPv6-008 | MUST | Accept packets to solicited-node multicast address (ff02::1:ffXX:XXXX) for our addresses | RFC 4291 §2.7.1 | TEST-IPv6-008 |
| REQ-IPv6-009 | MUST | Accept packets to link-local address (fe80::...) | RFC 4291 §2.5.6 | TEST-IPv6-009 |
| REQ-IPv6-010 | MUST | Silently discard packets not addressed to us or a subscribed group | RFC 8200 §3 | TEST-IPv6-010 |

### Source Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-011 | MUST | Silently discard packets with Source Address = multicast | RFC 8200 §3 | TEST-IPv6-011 |
| REQ-IPv6-012 | MUST | Silently discard packets with Source Address = our own unicast address | Architecture | TEST-IPv6-012 |
| REQ-IPv6-013 | MUST | Accept packets with Source Address = :: (unspecified) only during DAD/SLAAC | RFC 4291 §2.5.2, RFC 4862 | TEST-IPv6-013 |

### Next Header (Protocol) Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-014 | MUST | Dispatch Next Header 58 (ICMPv6) to ICMPv6 input — ICMPv6 is REQUIRED for IPv6 | RFC 8200 §4, RFC 4443 | TEST-IPv6-014 |
| REQ-IPv6-015 | MUST | Dispatch Next Header 6 (TCP) to TCP input (when linked) | RFC 8200 §3 | TEST-IPv6-015 |
| REQ-IPv6-016 | MUST | Dispatch Next Header 17 (UDP) to UDP input (when linked) | RFC 8200 §3 | TEST-IPv6-016 |
| REQ-IPv6-017 | MUST | For unrecognized Next Header, send ICMPv6 Parameter Problem (Type 4, Code 1) | RFC 8200 §4 | TEST-IPv6-017 |

### Extension Headers

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-018 | MUST | Process extension headers in order per RFC 8200 §4.1 | RFC 8200 §4.1 | TEST-IPv6-018 |
| REQ-IPv6-019 | MUST | Support Hop-by-Hop Options Header (Next Header = 0) — process if present | RFC 8200 §4.3 | TEST-IPv6-019 |
| REQ-IPv6-020 | MUST | Skip unknown extension headers using Header Extension Length field | RFC 8200 §4 | TEST-IPv6-020 |
| REQ-IPv6-021 | MUST NOT | MUST NOT generate extension headers in outbound packets (except as required by NDP/SLAAC) | Architecture | TEST-IPv6-021 |
| REQ-IPv6-022 | MUST | Fragment Header (Next Header = 44): silently discard fragments — no reassembly supported | Architecture, RFC 8200 §4.5 | TEST-IPv6-022 |
| REQ-IPv6-023 | SHOULD | On discarding fragment, send ICMPv6 Time Exceeded (Type 3, Code 1) for first fragment | RFC 8200 §4.5 | TEST-IPv6-023 |

**Note:** RFC 8200 §4.5 requires hosts to reassemble fragments. This stack deviates: fragment reassembly is omitted due to memory constraints. IPv6 minimum MTU is 1280 bytes; most traffic will not be fragmented on Ethernet (MTU 1500).

### Header Building (Transmission)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-024 | MUST | Set Version = 6 | RFC 8200 §3 | TEST-IPv6-024 |
| REQ-IPv6-025 | MUST | Set Traffic Class = 0 by default | RFC 8200 §3 | TEST-IPv6-025 |
| REQ-IPv6-026 | MUST | Set Flow Label = 0 by default (MAY use non-zero for flow identification) | RFC 8200 §3, RFC 6437 | TEST-IPv6-026 |
| REQ-IPv6-027 | MUST | Set Payload Length = bytes after the 40-byte header | RFC 8200 §3 | TEST-IPv6-027 |
| REQ-IPv6-028 | MUST | Set Next Header correctly (6=TCP, 17=UDP, 58=ICMPv6) | RFC 8200 §3 | TEST-IPv6-028 |
| REQ-IPv6-029 | MUST | Set Hop Limit to a reasonable value (default 64) | RFC 8200 §3 | TEST-IPv6-029 |
| REQ-IPv6-030 | MUST | Set Source Address = our configured unicast address (selected per RFC 6724 if multiple) | RFC 8200 §3, RFC 6724 | TEST-IPv6-030 |
| REQ-IPv6-031 | MUST | Set Destination Address = target IPv6 address | RFC 8200 §3 | TEST-IPv6-031 |

### Fragmentation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-032 | MUST NOT | MUST NOT fragment outbound packets (source is responsible for PMTU) | RFC 8200 §4.5 | TEST-IPv6-032 |
| REQ-IPv6-033 | MUST | Ensure outbound packets ≤ 1280 bytes (IPv6 minimum MTU) or link MTU if known to be larger | RFC 8200 §5 | TEST-IPv6-033 |
| REQ-IPv6-034 | SHOULD | Use Ethernet MTU (1500) for link-local communication (known MTU) | RFC 8200 §5 | TEST-IPv6-034 |

### IPv6 Addressing (RFC 4291)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-035 | MUST | Support link-local address (fe80::/10 + interface identifier) | RFC 4291 §2.5.6 | TEST-IPv6-035 |
| REQ-IPv6-036 | MUST | Generate link-local address from MAC using Modified EUI-64 format | RFC 4291 §2.5.1, Appendix A | TEST-IPv6-036 |
| REQ-IPv6-037 | SHOULD | Support global unicast address (assigned via SLAAC or DHCPv6) | RFC 4291 §2.5.4 | TEST-IPv6-037 |
| REQ-IPv6-038 | MUST | Support all-nodes multicast (ff02::1) — join implicitly | RFC 4291 §2.7.1 | TEST-IPv6-038 |
| REQ-IPv6-039 | MUST | Support solicited-node multicast (ff02::1:ffXX:XXXX) for each unicast address | RFC 4291 §2.7.1 | TEST-IPv6-039 |
| REQ-IPv6-040 | MUST | Map IPv6 multicast address to Ethernet multicast MAC: 33:33 + low 32 bits | RFC 2464 §7 | TEST-IPv6-040 |

### Address Selection (RFC 6724)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-041 | SHOULD | Implement source address selection per RFC 6724 when multiple addresses available | RFC 6724 §5 | TEST-IPv6-041 |
| REQ-IPv6-042 | MUST | Prefer link-local source for link-local destinations | RFC 6724 §5, Rule 1-2 | TEST-IPv6-042 |
| REQ-IPv6-043 | MUST | Prefer global source for global destinations | RFC 6724 §5, Rule 1-2 | TEST-IPv6-043 |

### Pseudo-Header for Upper Layers

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-044 | MUST | Provide IPv6 pseudo-header for TCP/UDP/ICMPv6 checksum: src (16) + dst (16) + length (4) + zeros (3) + next header (1) = 40 bytes | RFC 8200 §8.1 | TEST-IPv6-044 |
| REQ-IPv6-045 | MUST | Upper-layer checksum is MANDATORY for all protocols over IPv6 (no "checksum=0" allowed for UDP) | RFC 8200 §8.1 | TEST-IPv6-045 |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-046 | MUST | Parse IPv6 header in-place in application buffer | Architecture | TEST-IPv6-046 |
| REQ-IPv6-047 | MUST | Build IPv6 header in-place at offset 14 (after Ethernet header) in application buffer | Architecture | TEST-IPv6-047 |

## Notes

- **IPv6 header is always 40 bytes** (unlike IPv4's variable header). This simplifies parsing.
- **No header checksum:** IPv6 relies entirely on link-layer (Ethernet CRC) and upper-layer (TCP/UDP/ICMPv6) checksums. This saves processing time.
- **ICMPv6 is mandatory:** IPv6 cannot function without ICMPv6 (needed for NDP, PMTUD, error reporting).
- **No fragmentation at routers:** IPv6 routers never fragment. Source must fit packets in path MTU. Minimum MTU is 1280 bytes.
- **Extension header chains:** Most practical IPv6 packets have no extension headers. The stack must skip them correctly but does not need to generate them (except for NDP Router Alert, which is in the Hop-by-Hop header — but NDP over ICMPv6 typically doesn't use this).
- **Modified EUI-64:** MAC 00:11:22:33:44:55 → link-local fe80::0211:22ff:fe33:4455 (flip U/L bit, insert FF:FE in middle).
