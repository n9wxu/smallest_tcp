# mDNS Requirements

**Protocol:** Multicast DNS  
**Primary RFC:** RFC 6762 — Multicast DNS  
**Supporting:** RFC 1035 §§3–4 (DNS wire format), RFC 6840 (DNSSEC clarifications N/A), RFC 4795 (LLMNR — not used)  
**Scope:** V1 (IPv4 + responder), V2 (IPv6 + querier)  
**Last updated:** 2026-03-23

## Overview

Multicast DNS (mDNS) provides DNS-like hostname resolution and service announcement on a local link without requiring a DNS server or DHCP-assigned DNS option.  It operates on the reserved multicast group **224.0.0.251** (IPv4) / **ff02::fb** (IPv6) using **UDP port 5353**.  Names end with `.local.` and are resolved entirely on the local network segment.

Primary use cases for this stack:
- Announce the device's hostname as `<name>.local` so peers can reach it without knowing its IP
- Expose service records for DNS-SD (RFC 6763) — see `docs/requirements/dns-sd.md`
- Resolve other `.local` hostnames (V2 querier)

## Packet Format

mDNS uses the DNS wire format (RFC 1035 §4) with the following constraints:

| Field | mDNS value |
|---|---|
| ID | 0 for multicast messages (MUST); non-zero for unicast legacy queries (MAY) |
| QR | 0 = query, 1 = response |
| AA | 1 in all responses (mDNS responders are always authoritative for their records) |
| TC | Not used (single-packet records) |
| Multicast src port | 5353 |
| Unicast src port | 5353 (for QU responses) |
| Multicast dst addr | 224.0.0.251 (IPv4) / ff02::fb (IPv6) |

## Requirements

### General

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-001 | MUST | Use UDP port 5353 for all mDNS traffic | RFC 6762 §3 | TEST-MDNS-001 |
| REQ-MDNS-002 | MUST | Join IPv4 multicast group 224.0.0.251 on all active interfaces | RFC 6762 §8 | TEST-MDNS-002 |
| REQ-MDNS-003 | MUST | Use DNS wire format (RFC 1035 §§3–4) for all mDNS messages | RFC 6762 §18 | TEST-MDNS-003 |
| REQ-MDNS-004 | MUST | Set the AA (Authoritative Answer) bit in all response messages | RFC 6762 §18.4 | TEST-MDNS-004 |
| REQ-MDNS-005 | MUST | Set message ID to 0 for all multicast messages | RFC 6762 §18.1 | TEST-MDNS-005 |
| REQ-MDNS-006 | MUST NOT | Send mDNS packets with IP TTL other than 255 | RFC 6762 §11.3 | TEST-MDNS-006 |
| REQ-MDNS-007 | MUST | Limit responses to records for the `.local.` domain | RFC 6762 §3 | TEST-MDNS-007 |

### Record Set (Application-Provided)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-008 | MUST | Accept a static record set from the application at initialisation (no dynamic allocation) | Architecture | TEST-MDNS-008 |
| REQ-MDNS-009 | MUST | Support A records (type 1) for hostname → IPv4 address mapping | RFC 6762 §11, RFC 1035 §3.4.1 | TEST-MDNS-009 |
| REQ-MDNS-010 | MUST | Support PTR records (type 12) for reverse and service enumeration | RFC 6762 §11, RFC 1035 §3.3.12 | TEST-MDNS-010 |
| REQ-MDNS-011 | MUST | Support SRV records (type 33) for service instance host+port | RFC 6762 §11, RFC 2782 | TEST-MDNS-011 |
| REQ-MDNS-012 | MUST | Support TXT records (type 16) for key=value service metadata | RFC 6762 §11, RFC 1035 §3.3.14 | TEST-MDNS-012 |
| REQ-MDNS-013 | SHOULD | Support AAAA records (type 28) for hostname → IPv6 address (V2) | RFC 6762 §11, RFC 3596 | TEST-MDNS-013 |
| REQ-MDNS-014 | MUST | Record TTL for A/AAAA records SHOULD be 120 seconds (2 minutes) | RFC 6762 §11.3 | TEST-MDNS-014 |
| REQ-MDNS-015 | MUST | Record TTL for PTR records SHOULD be 4500 seconds (75 minutes) | RFC 6762 §11.3 | TEST-MDNS-015 |

### Probing (Conflict Detection Before Announcing)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-016 | MUST | Before announcing, probe for uniqueness by sending three Probe queries (QM questions with the intended records in the Authority section) | RFC 6762 §8.1 | TEST-MDNS-016 |
| REQ-MDNS-017 | MUST | First probe delayed by random 0–250 ms after interface up | RFC 6762 §8.1 | TEST-MDNS-017 |
| REQ-MDNS-018 | MUST | Space subsequent probes 250 ms apart | RFC 6762 §8.1 | TEST-MDNS-018 |
| REQ-MDNS-019 | MUST | If a conflict response is received during probing, defer the claim and notify the application | RFC 6762 §8.1 | TEST-MDNS-019 |
| REQ-MDNS-020 | MUST | Application MUST provide a conflict callback to select an alternative name | RFC 6762 §9 | TEST-MDNS-020 |
| REQ-MDNS-021 | MUST | After all three probes pass with no conflict, proceed to announce | RFC 6762 §8.3 | TEST-MDNS-021 |

### Announcing (Gratuitous Responses)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-022 | MUST | After probing succeeds, send at least two announcement (gratuitous) responses separated by 1 second | RFC 6762 §8.3 | TEST-MDNS-022 |
| REQ-MDNS-023 | MUST | Announcements are multicast responses, not queries | RFC 6762 §8.3 | TEST-MDNS-023 |
| REQ-MDNS-024 | MUST | On network re-attachment (link up), re-probe and re-announce all records | RFC 6762 §8.4 | TEST-MDNS-024 |

### Responding to Queries

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-025 | MUST | Listen for mDNS queries on 224.0.0.251:5353 | RFC 6762 §6 | TEST-MDNS-025 |
| REQ-MDNS-026 | MUST | Respond with all matching records from the application's record set | RFC 6762 §6 | TEST-MDNS-026 |
| REQ-MDNS-027 | MUST | Delay multicast responses by 400–500 ms (random) to allow response aggregation | RFC 6762 §6 | TEST-MDNS-027 |
| REQ-MDNS-028 | MUST | If query has QU (Unicast) bit set and responder recently sent the same record, MAY respond via unicast to the querier | RFC 6762 §5.4 | TEST-MDNS-028 |
| REQ-MDNS-029 | MUST | Known-answer suppression: do NOT include answers whose TTL ≤ half the record TTL in a query's Known-Answers section | RFC 6762 §7.1 | TEST-MDNS-029 |
| REQ-MDNS-030 | MUST | Answer only queries for the `.local.` domain; ignore other domains silently | RFC 6762 §3 | TEST-MDNS-030 |
| REQ-MDNS-031 | MUST | Set the AA bit and TTL in all answers | RFC 6762 §18 | TEST-MDNS-031 |

### Goodbye Packets (Record Withdrawal)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-032 | MUST | When a record is withdrawn (interface down, name change), send a Goodbye packet with TTL=0 | RFC 6762 §11.3 | TEST-MDNS-032 |
| REQ-MDNS-033 | MUST | Send at least one Goodbye packet for each withdrawn record | RFC 6762 §11.3 | TEST-MDNS-033 |

### Querier (V2 — optional for V1 responder-only build)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-034 | SHOULD | Support sending mDNS queries to resolve `.local.` names (querier mode) | RFC 6762 §5 | TEST-MDNS-034 |
| REQ-MDNS-035 | SHOULD | Initial query sent once; if no response within 1 s, retransmit with exponential backoff (1 s, 2 s, 4 s, max 60 s) | RFC 6762 §5.2 | TEST-MDNS-035 |
| REQ-MDNS-036 | SHOULD | Cache resolved records for the duration of their TTL | RFC 6762 §12 | TEST-MDNS-036 |
| REQ-MDNS-037 | MUST | Application-provided cache buffer (no malloc) | Architecture | TEST-MDNS-037 |

### IPv6 Support (V2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-038 | SHOULD | Join IPv6 multicast group ff02::fb on active interfaces | RFC 6762 §11 | TEST-MDNS-038 |
| REQ-MDNS-039 | SHOULD | Send mDNS over both IPv4 and IPv6 when both are active | RFC 6762 §11 | TEST-MDNS-039 |

### Interoperability

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-040 | MUST | Respond correctly to queries from macOS, Linux (Avahi), iOS, and Android mDNS implementations | RFC 6762 §6 | TEST-MDNS-040 |
| REQ-MDNS-041 | MUST | Ignore mDNS messages from legacy unicast DNS resolvers (ID ≠ 0 on port 5353) rather than crashing | RFC 6762 §6.7 | TEST-MDNS-041 |

### Buffer and Size

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-042 | MUST | mDNS messages MUST fit within a single UDP datagram; split large record sets across multiple responses | RFC 6762 §17 | TEST-MDNS-042 |
| REQ-MDNS-043 | MUST | DNS name compression MUST be used to reduce response size | RFC 1035 §4.1.4, RFC 6762 §18 | TEST-MDNS-043 |

## Notes

- **No DNS server needed:** mDNS operates entirely on the local link — no configuration, no server, no DHCP dependency.
- **Hostname convention:** By default, the device should use a `<product>-<last4mac>.local` hostname to avoid conflicts (e.g., `pyro-dead01.local`).
- **Shared parser with DNS:** The mDNS wire format is identical to DNS (RFC 1035); the DNS stub-resolver parser can be reused directly.
- **pyro_fw integration:** mDNS is required so that pyro_fw devices can be discovered on the local network without a pre-configured IP.  DNS-SD (RFC 6763) builds on top of mDNS to advertise the service type — see `docs/requirements/dns-sd.md`.
- **Avahi/Bonjour compatibility:** On Linux the reference implementation is Avahi; on macOS/iOS it is Bonjour (mDNSResponder).  Both must be able to resolve the device's `.local` hostname and browse its services.
