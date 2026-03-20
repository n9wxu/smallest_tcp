# IPv4 Requirements

**Protocol:** Internet Protocol version 4  
**Primary RFC:** RFC 791 — Internet Protocol  
**Supporting:** RFC 1122 — Requirements for Internet Hosts (§3.2, §3.3), RFC 6864 — Updated Specification of the IPv4 ID Field, RFC 1812 — Requirements for IP Version 4 Routers (reference only — we are a host)  
**Supersession:** RFC 6864 supersedes RFC 791 regarding the IP Identification field  
**Scope:** V1 (IPv4)  
**Last updated:** 2026-03-19

## Overview

IPv4 is the network layer protocol that provides addressing and routing for IP datagrams. This stack implements IPv4 host (not router) behavior per RFC 791 and the host requirements in RFC 1122 §3.

## Header Format

```
Offset  Size  Field
  0      4b   Version (4)
  0      4b   IHL (Internet Header Length, in 32-bit words, minimum 5)
  1      1    Type of Service (TOS) / DSCP+ECN
  2      2    Total Length (header + payload, in bytes)
  4      2    Identification
  6      3b   Flags (bit 0: reserved, bit 1: DF, bit 2: MF)
  6     13b   Fragment Offset (in 8-byte units)
  8      1    Time to Live (TTL)
  9      1    Protocol (6=TCP, 17=UDP, 1=ICMP)
 10      2    Header Checksum
 12      4    Source Address
 16      4    Destination Address
 20     0-40  Options (if IHL > 5)
```

Minimum header: 20 bytes (IHL=5). Maximum header: 60 bytes (IHL=15).

## Requirements

### Header Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-001 | MUST | Verify Version field = 4 | RFC 791 §3.1, RFC 1122 §3.2.1.1 | TEST-IPv4-001 |
| REQ-IPv4-002 | MUST | Verify IHL ≥ 5 (minimum 20 bytes) | RFC 791 §3.1, RFC 1122 §3.2.1.1 | TEST-IPv4-002 |
| REQ-IPv4-003 | MUST | Verify Total Length ≥ IHL × 4 | RFC 791 §3.1, RFC 1122 §3.2.1.1 | TEST-IPv4-003 |
| REQ-IPv4-004 | MUST | Verify Total Length ≤ actual received frame payload length | RFC 791, RFC 1122 §3.2.1.1 | TEST-IPv4-004 |
| REQ-IPv4-005 | MUST | Verify header checksum; silently discard on failure | RFC 791 §3.1, RFC 1122 §3.2.1.2 | TEST-IPv4-005 |
| REQ-IPv4-006 | MUST | Silently discard packets failing any validation check | RFC 1122 §3.2.1.1 | TEST-IPv4-006 |
| REQ-IPv4-007 | MUST | Use Total Length (not frame length) to determine IP payload length | RFC 791, RFC 1122 §3.2.1.1 | TEST-IPv4-007 |

### Destination Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-008 | MUST | Accept packets where Destination Address matches our configured IPv4 address | RFC 791, RFC 1122 §3.2.1.3 | TEST-IPv4-008 |
| REQ-IPv4-009 | MUST | Accept packets where Destination Address is the limited broadcast (255.255.255.255) | RFC 1122 §3.2.1.3 | TEST-IPv4-009 |
| REQ-IPv4-010 | MUST | Accept packets where Destination Address is the subnet-directed broadcast | RFC 1122 §3.2.1.3 | TEST-IPv4-010 |
| REQ-IPv4-011 | MUST | Silently discard packets not addressed to us, broadcast, or a subscribed multicast group | RFC 1122 §3.2.1.3 | TEST-IPv4-011 |
| REQ-IPv4-012 | SHOULD | Accept packets addressed to 0.0.0.0 during DHCP bootstrap (before address configured) | RFC 1122 §3.2.1.3, RFC 2131 | TEST-IPv4-012 |

### Source Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-013 | MUST | Silently discard packets with Source Address = 255.255.255.255 | RFC 1122 §3.2.1.3 | TEST-IPv4-013 |
| REQ-IPv4-014 | MUST | Silently discard packets with Source Address = our own address (prevent loops) | RFC 1122 §3.2.1.3 | TEST-IPv4-014 |
| REQ-IPv4-015 | SHOULD | Silently discard packets with Source Address = 127.x.x.x (loopback range) | RFC 1122 §3.2.1.3 | TEST-IPv4-015 |
| REQ-IPv4-016 | SHOULD | Silently discard packets with Source Address = 0.0.0.0 except during DHCP | RFC 1122 §3.2.1.3 | TEST-IPv4-016 |

### Protocol Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-017 | MUST | Dispatch Protocol 1 (ICMP) to ICMPv4 input | RFC 791, RFC 1122 §3.2.1.6 | TEST-IPv4-017 |
| REQ-IPv4-018 | MUST | Dispatch Protocol 6 (TCP) to TCP input (when linked) | RFC 791, RFC 1122 §3.2.1.6 | TEST-IPv4-018 |
| REQ-IPv4-019 | MUST | Dispatch Protocol 17 (UDP) to UDP input (when linked) | RFC 791, RFC 1122 §3.2.1.6 | TEST-IPv4-019 |
| REQ-IPv4-020 | MUST | For unrecognized Protocol values, send ICMP Protocol Unreachable (Type 3, Code 2) if ICMP is linked | RFC 1122 §3.2.2.1 | TEST-IPv4-020 |
| REQ-IPv4-021 | MUST | Silently discard packets with unrecognized Protocol if ICMP is not linked | Architecture | TEST-IPv4-021 |

### Fragmentation and Reassembly

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-022 | MUST NOT | MUST NOT fragment outbound packets (DF bit always set) | Architecture (no reassembly buffer) | TEST-IPv4-022 |
| REQ-IPv4-023 | MUST | Set DF (Don't Fragment) flag on all outbound IPv4 packets | RFC 791 §3.1, Architecture | TEST-IPv4-023 |
| REQ-IPv4-024 | MUST | Silently discard received fragments (MF=1 or Fragment Offset≠0) | Architecture (no reassembly buffer) | TEST-IPv4-024 |
| REQ-IPv4-025 | SHOULD | When discarding a fragment, send ICMP Time Exceeded (Type 11, Code 1) for first fragment only | RFC 1122 §3.3.2 | TEST-IPv4-025 |

**Note:** RFC 1122 §3.3.2 says a host MUST be able to reassemble fragments. This stack deviates: fragmentation support is intentionally omitted due to memory constraints. The DF flag is always set to prevent fragmentation by routers. Path MTU Discovery (RFC 1191) is not implemented but DF+ICMP Fragmentation Needed provides equivalent functionality.

### IP Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-026 | MUST | Accept and process packets with IP options (IHL > 5) by skipping options correctly | RFC 791, RFC 1122 §3.2.1.8 | TEST-IPv4-026 |
| REQ-IPv4-027 | MUST | IP payload starts at offset IHL × 4, not at fixed offset 20 | RFC 791 §3.1 | TEST-IPv4-027 |
| REQ-IPv4-028 | MUST NOT | MUST NOT generate IP options in outbound packets | Architecture (simplicity) | TEST-IPv4-028 |
| REQ-IPv4-029 | MAY | Silently ignore all IP option content (do not process Record Route, Timestamp, etc.) | RFC 1122 §3.2.1.8 | TEST-IPv4-029 |

### Header Building (Transmission)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-030 | MUST | Set Version = 4 | RFC 791 §3.1 | TEST-IPv4-030 |
| REQ-IPv4-031 | MUST | Set IHL = 5 (no options) | RFC 791 §3.1, Architecture | TEST-IPv4-031 |
| REQ-IPv4-032 | MUST | Set Total Length = 20 + payload length | RFC 791 §3.1 | TEST-IPv4-032 |
| REQ-IPv4-033 | MUST | Set Identification field: for DF=1 packets, any value is acceptable (RFC 6864) | RFC 6864 §4.1 (supersedes RFC 791) | TEST-IPv4-033 |
| REQ-IPv4-034 | MUST | Set DF=1, MF=0, Fragment Offset=0 | Architecture, RFC 791 §3.1 | TEST-IPv4-034 |
| REQ-IPv4-035 | MUST | Set TTL to a reasonable value (SHOULD be configurable, default 64) | RFC 791 §3.1, RFC 1122 §3.2.1.7 | TEST-IPv4-035 |
| REQ-IPv4-036 | MUST | Set Protocol field correctly (1=ICMP, 6=TCP, 17=UDP) | RFC 791 §3.1 | TEST-IPv4-036 |
| REQ-IPv4-037 | MUST | Compute and set Header Checksum (or write 0x0000 if MAC does TX checksum offload) | RFC 791 §3.1 | TEST-IPv4-037 |
| REQ-IPv4-038 | MUST | Set Source Address = our configured IPv4 address | RFC 791 §3.1 | TEST-IPv4-038 |
| REQ-IPv4-039 | MUST | Set Destination Address = target IPv4 address | RFC 791 §3.1 | TEST-IPv4-039 |

### Type of Service (TOS) / DSCP

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-040 | MUST | Set TOS/DSCP to 0 by default | RFC 791 §3.1 | TEST-IPv4-040 |
| REQ-IPv4-041 | MAY | Allow upper layers to specify TOS/DSCP value | RFC 1122 §3.2.1.6 | TEST-IPv4-041 |
| REQ-IPv4-042 | MUST | Do not discard received packets based on TOS/DSCP value | RFC 1122 §3.2.1.6 | TEST-IPv4-042 |

### TTL Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-043 | MUST NOT | MUST NOT forward packets (we are a host, not a router) | RFC 1122 §3.3.1 | TEST-IPv4-043 |
| REQ-IPv4-044 | MUST | Accept received packets regardless of TTL value (do not discard based on TTL) | RFC 1122 §3.2.1.7 | TEST-IPv4-044 |
| REQ-IPv4-045 | SHOULD | Default outbound TTL SHOULD be 64 | RFC 1122 §3.2.1.7 (recommends ≥ 64) | TEST-IPv4-045 |

### Broadcasting

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-046 | MUST | Support sending to limited broadcast (255.255.255.255) | RFC 1122 §3.3.6 | TEST-IPv4-046 |
| REQ-IPv4-047 | MUST | When sending to broadcast, use broadcast MAC (FF:FF:FF:FF:FF:FF) | RFC 894, RFC 1122 §3.3.6 | TEST-IPv4-047 |
| REQ-IPv4-048 | MUST NOT | MUST NOT send datagrams with Source Address = broadcast | RFC 1122 §3.2.1.3 | TEST-IPv4-048 |
| REQ-IPv4-049 | SHOULD | Support subnet-directed broadcast (host part all-ones) for sending | RFC 1122 §3.3.6 | TEST-IPv4-049 |

### Multicast (Minimal)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-050 | MAY | Support receiving multicast packets (e.g., 224.0.0.1 all-hosts) | RFC 1122 §3.3.7 | TEST-IPv4-050 |
| REQ-IPv4-051 | MAY | Support sending to multicast addresses with appropriate multicast MAC | RFC 1112 §6.4 | TEST-IPv4-051 |
| REQ-IPv4-052 | MAY | Map IPv4 multicast address to Ethernet multicast MAC: 01:00:5E + low 23 bits | RFC 1112 §6.4 | TEST-IPv4-052 |

### ICMP Error Interaction

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-053 | SHOULD | Pass received ICMP Destination Unreachable to upper layer (TCP/UDP) | RFC 1122 §3.2.2.1 | TEST-IPv4-053 |
| REQ-IPv4-054 | SHOULD | Pass received ICMP Redirect to routing layer (update gateway for destination) | RFC 1122 §3.2.2.2 | TEST-IPv4-054 |
| REQ-IPv4-055 | MAY | Ignore ICMP Redirect if "gateway-only" mode is active | Architecture | TEST-IPv4-055 |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-056 | MUST | Parse IPv4 header in-place in application buffer | Architecture | TEST-IPv4-056 |
| REQ-IPv4-057 | MUST | Build IPv4 header in-place at offset 14 (after Ethernet header) in application buffer | Architecture | TEST-IPv4-057 |

## Implementation Notes

- **No IP ID uniqueness requirement for DF=1 packets (RFC 6864):** Since we always set DF, the Identification field can be any value. We use 0 or a simple counter.
- **No IP options generated:** Simplifies header building — always 20-byte header. But inbound packets with options must be accepted.
- **No fragmentation/reassembly:** This is a deliberate deviation from RFC 1122 §3.3.2. Modern networks rarely fragment, and the DF flag prevents it. This saves significant RAM that would be needed for reassembly buffers.
- **MTU assumption:** Ethernet MTU is 1500 bytes. IPv4 Total Length must not exceed 1500. TCP MSS and UDP payload sizes are derived from buffer capacity but capped at MTU - 20.
