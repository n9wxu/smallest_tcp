# DNS Requirements

**Protocol:** Domain Name System — Stub Resolver  
**Primary RFC:** RFC 1035 — Domain Names — Implementation and Specification  
**Supporting:** RFC 1034 — Domain Names — Concepts and Facilities, RFC 1123 §6.1 — Requirements for Internet Hosts (DNS), RFC 2181 — Clarifications to the DNS Specification, RFC 3596 — DNS Extensions to Support IPv6, RFC 5452 — Measures for Making DNS More Resilient against Forged Answers, RFC 6891 — Extension Mechanisms for DNS (EDNS(0)), RFC 7766 — DNS Transport over TCP  
**Status:** **Not implemented.** The stack has no DNS resolver: no `dns.c`, no API, no test. Applications address their peers by IP address (the mDNS module is a responder: it answers for this host's names and resolves none).

## Overview

These are the requirements a DNS **stub resolver** on this stack has to meet: it sends queries to a configured recursive DNS server and processes the responses; it is not a recursive resolver or a DNS server. Its use is resolving hostnames to IP addresses for outbound connections (a TFTP server's name, an HTTP client).

None of the rows below is implemented, so none is verified: every Test ID is `— (not implemented)`, and `scripts/trace.py` reports the MUST rows of this document as cited by no test.

The DNS wire format itself is implemented, for the mDNS responder: `src/dns_wire.c` (`include/dns_wire.h`) encodes and decodes names with compression and parses headers, questions and resource records. A resolver shares it. It is specified and tested with mDNS ([mdns.md](mdns.md), [design/mdns.md](../design/mdns.md)), not here.

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
| REQ-DNS-001 | MUST | Generate standard query (QR=0, Opcode=0, RD=1), the unused header fields zero | RFC 1035 §4.1.1, RFC 1123 §6.1.2.3 | — (not implemented) |
| REQ-DNS-002 | MUST | Set QDCOUNT=1 (single question per query) | RFC 1035 §4.1.1 | — (not implemented) |
| REQ-DNS-003 | MUST | Use an unpredictable ID, from the full 16-bit range, and an unpredictable source port for each query | RFC 5452 §9.2 | — (not implemented) |
| REQ-DNS-004 | MUST | Encode domain name in label format (length-prefixed segments, terminated by zero-length label) | RFC 1035 §4.1.2 | — (not implemented) |
| REQ-DNS-005 | MUST | Support QTYPE A (1) for IPv4 address lookup | RFC 1035 §3.2.2 | — (not implemented) |
| REQ-DNS-006 | MUST | Support QTYPE AAAA (28) for IPv6 address lookup (V2) | RFC 3596 §2 | — (not implemented) |
| REQ-DNS-007 | MUST | Set QCLASS = IN (1) | RFC 1035 §3.2.4, RFC 1123 §6.1.2.2 | — (not implemented) |
| REQ-DNS-008 | MUST | Send query over UDP to DNS server on port 53 | RFC 1035 §4.2.1, RFC 1123 §6.1.3.2 | — (not implemented) |

### Response Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-009 | MUST | Verify QR=1 (response) | RFC 1035 §4.1.1 | — (not implemented) |
| REQ-DNS-010 | MUST | Match a response to the query by its ID, its source address and port (the server's), its destination port, and its question (name, class and type); a response that does not match is invalid | RFC 5452 §9.1 | — (not implemented) |
| REQ-DNS-011 | MUST | Check RCODE: 0=No Error, 3=Name Error (NXDOMAIN), others=failure | RFC 1035 §4.1.1 | — (not implemented) |
| REQ-DNS-012 | MUST | If TC=1 (truncated), do not use the response: ask again over TCP (a stub resolver supports TCP) | RFC 2181 §9, RFC 7766 §5, RFC 1123 §6.1.3.2 | — (not implemented) |
| REQ-DNS-013 | MUST | Parse answer section for matching RRs | RFC 1035 §4.1.3 | — (not implemented) |
| REQ-DNS-014 | MUST | Support name compression (pointer labels, top 2 bits = 11) | RFC 1035 §4.1.4 | — (not implemented) |
| REQ-DNS-015 | MUST | Extract IPv4 address from A record (TYPE=1, RDLENGTH=4) | RFC 1035 §3.4.1 | — (not implemented) |
| REQ-DNS-016 | MUST | Extract IPv6 address from AAAA record (TYPE=28, RDLENGTH=16) (V2) | RFC 3596 §2.2 | — (not implemented) |
| REQ-DNS-017 | MUST | Extract TTL from answer RR for cache duration; an RR with a zero TTL is returned to the application and not cached | RFC 1035 §4.1.3, RFC 1123 §6.1.2.1 | — (not implemented) |
| REQ-DNS-018 | MUST | Skip RRs with non-matching TYPE (e.g., CNAME in answer section before A record) | RFC 1035 §4.1.3 | — (not implemented) |

### CNAME Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-019 | SHOULD | Follow CNAME chains: if answer contains CNAME, look for A/AAAA record matching CNAME target in same response | RFC 1034 §3.6.2 | — (not implemented) |
| REQ-DNS-020 | MUST | Limit CNAME chain depth (SHOULD NOT exceed 8) to prevent loops | Architecture | — (not implemented) |

### Retransmission and Timeout

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-021 | MUST | Retransmit query if no response within timeout | RFC 1035 §7.2, RFC 1123 §6.1.3.3 | — (not implemented) |
| REQ-DNS-022 | SHOULD | Exponential backoff of the retry interval, with upper and lower bounds; without a measured round-trip time, a first timeout of no less than 5 seconds | RFC 1123 §6.1.3.3 | — (not implemented) |
| REQ-DNS-023 | MUST | Limit retransmissions: finite bounds on what a single request consumes | RFC 1123 §6.1.3.3 | — (not implemented) |
| REQ-DNS-024 | MUST | Give up after several retransmissions without a response, and report a soft error to the application | RFC 1123 §6.1.3.3 | — (not implemented) |

### DNS Server Configuration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-025 | MUST | Support static DNS server configuration, of redundant recursive servers (at least two) | RFC 1123 §6.1.3.1 | — (not implemented) |
| REQ-DNS-026 | SHOULD | Use DNS server provided by DHCP (option 6) when available | RFC 2132 §3.8 | — (not implemented) |
| REQ-DNS-027 | MUST | Store DNS server IP and (optionally) cached MAC for the server | Architecture | — (not implemented) |

### Cache (Minimal)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-028 | MAY | Cache resolved addresses with TTL from response | RFC 1035 §7.2 | — (not implemented) |
| REQ-DNS-029 | MAY | Cache is application-provided (application allocates cache entries) | Architecture | — (not implemented) |
| REQ-DNS-030 | MUST | If caching, honor TTL — expire entries when TTL reaches zero; never cache a truncated response as if it were complete | RFC 1123 §6.1.3.1, §6.1.3.2 | — (not implemented) |
| REQ-DNS-031 | MAY | No cache (re-query each time) for minimal memory configurations | Architecture | — (not implemented) |

### Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-032 | MUST | DNS UDP messages limited to 512 bytes (without EDNS(0)) | RFC 1035 §2.3.4 | — (not implemented) |
| REQ-DNS-033 | MAY | Support EDNS(0) (RFC 6891) to allow larger UDP messages | RFC 6891 | — (not implemented) |
| REQ-DNS-034 | MUST | Buffer must be large enough for 512-byte DNS response + UDP/IP/ETH headers | Architecture | — (not implemented) |

### Address Resolution for DNS Server

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNS-035 | MUST | Resolve DNS server MAC before sending queries | Architecture | — (not implemented) |
| REQ-DNS-036 | SHOULD | Cache DNS server MAC (typically same as gateway in many networks) | Architecture | — (not implemented) |

## Notes

- **Stub resolver only:** The resolver sends queries to a recursive DNS server. It does not perform recursive resolution itself.
- **UDP first, TCP for truncated responses:** Most A/AAAA responses fit in 512 bytes. RFC 7766 §5 requires TCP of a stub resolver, and RFC 2181 §9 says a truncated response is not used (REQ-DNS-012); a resolver without TCP reports a truncated answer as a failure.
- **DNSSEC not supported:** This is acceptable for a minimal embedded resolver.
- **Gateway often is DNS server:** In many SOHO networks, the gateway (router) is also the DNS server. The MAC resolved for the gateway can often be reused for DNS, saving an ARP exchange.
- **DHCP gives the server's address:** the DHCPv4 client passes option 6 to an application handler (`dhcpv4_opt_handler_t`, [dhcpv4.md](dhcpv4.md) REQ-DHCPv4-032), which is where a resolver gets REQ-DNS-026 from.
