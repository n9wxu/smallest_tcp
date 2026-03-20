# DNS Requirements

**Protocol:** Domain Name System — Stub Resolver  
**Primary RFC:** RFC 1035 — Domain Names — Implementation and Specification  
**Supporting:** RFC 1034 — Domain Names — Concepts and Facilities, RFC 6891 — Extension Mechanisms for DNS (EDNS(0)), RFC 1122 §6.1  
**Scope:** V1 (IPv4 A records), V2 (IPv6 AAAA records)  
**Last updated:** 2026-03-19

## Overview

This stack implements a DNS **stub resolver** only — it sends queries to a configured recursive DNS server and processes responses. It does not implement a recursive resolver or DNS server. The primary use case is resolving hostnames to IP addresses for outbound connections (e.g., TFTP server name, HTTP client).

## Message Format

```
Offset  Size  Field
  0      2    ID (transaction identifier)
  2      2    Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
  4      2    QDCOUNT (number of questions)
  6      2    ANCOUNT (number of answers)
  8      2    NSCOUNT (number of authority records)
 10      2    ARCOUNT (number of additional records)
 12     var   Question section
        var   Answer section
        var   Authority section
        var   Additional section
```

## Requirements

### Query Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-001 | MUST | Generate standard query (QR=0, Opcode=0, RD=1) | RFC 1035 §4.1.1 | TEST-DNS-001 |
| REQ-DNS-002 | MUST | Set QDCOUNT=1 (single question per query) | RFC 1035 §4.1.1 | TEST-DNS-002 |
| REQ-DNS-003 | MUST | Generate random ID for each query | RFC 1035 §4.1.1 | TEST-DNS-003 |
| REQ-DNS-004 | MUST | Encode domain name in label format (length-prefixed segments, terminated by zero-length label) | RFC 1035 §4.1.2 | TEST-DNS-004 |
| REQ-DNS-005 | MUST | Support QTYPE A (1) for IPv4 address lookup | RFC 1035 §3.2.2 | TEST-DNS-005 |
| REQ-DNS-006 | MUST | Support QTYPE AAAA (28) for IPv6 address lookup (V2) | RFC 3596 §2 | TEST-DNS-006 |
| REQ-DNS-007 | MUST | Set QCLASS = IN (1) | RFC 1035 §3.2.4 | TEST-DNS-007 |
| REQ-DNS-008 | MUST | Send query over UDP to DNS server on port 53 | RFC 1035 §4.2.1 | TEST-DNS-008 |

### Response Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-009 | MUST | Verify QR=1 (response) | RFC 1035 §4.1.1 | TEST-DNS-009 |
| REQ-DNS-010 | MUST | Verify ID matches our query | RFC 1035 §4.1.1 | TEST-DNS-010 |
| REQ-DNS-011 | MUST | Check RCODE: 0=No Error, 3=Name Error (NXDOMAIN), others=failure | RFC 1035 §4.1.1 | TEST-DNS-011 |
| REQ-DNS-012 | MUST | If TC=1 (truncated), retry over TCP or accept partial answer | RFC 1035 §4.2.1 | TEST-DNS-012 |
| REQ-DNS-013 | MUST | Parse answer section for matching RRs | RFC 1035 §4.1.3 | TEST-DNS-013 |
| REQ-DNS-014 | MUST | Support name compression (pointer labels, top 2 bits = 11) | RFC 1035 §4.1.4 | TEST-DNS-014 |
| REQ-DNS-015 | MUST | Extract IPv4 address from A record (TYPE=1, RDLENGTH=4) | RFC 1035 §3.4.1 | TEST-DNS-015 |
| REQ-DNS-016 | MUST | Extract IPv6 address from AAAA record (TYPE=28, RDLENGTH=16) (V2) | RFC 3596 §2.2 | TEST-DNS-016 |
| REQ-DNS-017 | MUST | Extract TTL from answer RR for cache duration | RFC 1035 §4.1.3 | TEST-DNS-017 |
| REQ-DNS-018 | MUST | Skip RRs with non-matching TYPE (e.g., CNAME in answer section before A record) | RFC 1035 §4.1.3 | TEST-DNS-018 |

### CNAME Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-019 | SHOULD | Follow CNAME chains: if answer contains CNAME, look for A/AAAA record matching CNAME target in same response | RFC 1034 §3.6.2 | TEST-DNS-019 |
| REQ-DNS-020 | MUST | Limit CNAME chain depth (SHOULD NOT exceed 8) to prevent loops | Architecture | TEST-DNS-020 |

### Retransmission and Timeout

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-021 | MUST | Retransmit query if no response within timeout | RFC 1035 §7.2 | TEST-DNS-021 |
| REQ-DNS-022 | SHOULD | Initial timeout ~2 seconds, exponential backoff | RFC 1035 §7.2 | TEST-DNS-022 |
| REQ-DNS-023 | MUST | Limit retransmissions (SHOULD NOT exceed 3-5 retries) | RFC 1035 §7.2 | TEST-DNS-023 |
| REQ-DNS-024 | MUST | Report resolution failure to application after timeout | Architecture | TEST-DNS-024 |

### DNS Server Configuration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-025 | MUST | Support static DNS server configuration | Architecture | TEST-DNS-025 |
| REQ-DNS-026 | SHOULD | Use DNS server provided by DHCP (option 6) when available | RFC 2132 §3.8 | TEST-DNS-026 |
| REQ-DNS-027 | MUST | Store DNS server IP and (optionally) cached MAC for the server | Architecture | TEST-DNS-027 |

### Cache (Minimal)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-028 | MAY | Cache resolved addresses with TTL from response | RFC 1035 §7.2 | TEST-DNS-028 |
| REQ-DNS-029 | MAY | Cache is application-provided (application allocates cache entries) | Architecture | TEST-DNS-029 |
| REQ-DNS-030 | MUST | If caching, honor TTL — expire entries when TTL reaches zero | RFC 1035 §7.2 | TEST-DNS-030 |
| REQ-DNS-031 | MAY | No cache (re-query each time) for minimal memory configurations | Architecture | TEST-DNS-031 |

### Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-032 | MUST | DNS UDP messages limited to 512 bytes (without EDNS(0)) | RFC 1035 §2.3.4 | TEST-DNS-032 |
| REQ-DNS-033 | MAY | Support EDNS(0) (RFC 6891) to allow larger UDP messages | RFC 6891 | TEST-DNS-033 |
| REQ-DNS-034 | MUST | Buffer must be large enough for 512-byte DNS response + UDP/IP/ETH headers | Architecture | TEST-DNS-034 |

### Address Resolution for DNS Server

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-035 | MUST | Resolve DNS server MAC before sending queries | Architecture | TEST-DNS-035 |
| REQ-DNS-036 | SHOULD | Cache DNS server MAC (typically same as gateway in many networks) | Architecture | TEST-DNS-036 |

## Notes

- **Stub resolver only:** This implementation sends queries to a recursive DNS server. It does not perform recursive resolution itself.
- **UDP preferred:** DNS queries use UDP. TCP fallback (for truncated responses) is a MAY for V1 since most A/AAAA responses fit in 512 bytes.
- **DNSSEC not supported:** This is acceptable for a minimal embedded resolver.
- **DNS over TCP:** RFC 1035 says a resolver SHOULD support TCP for truncated responses. For V1, we accept truncated answers (first A record) or report failure.
- **Gateway often is DNS server:** In many SOHO networks, the gateway (router) is also the DNS server. The MAC resolved for the gateway can often be reused for DNS, saving an ARP exchange.
