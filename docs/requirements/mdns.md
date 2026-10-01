# mDNS Requirements

**Protocol:** Multicast DNS  
**Primary RFC:** RFC 6762 — Multicast DNS  
**Supporting:** RFC 1035 §§3–4 (DNS wire format), RFC 6840 (DNSSEC clarifications N/A), RFC 4795 (LLMNR — not used)  
**Scope:** V1 (IPv4 + responder), V2 (IPv6 + querier)  
**Last updated:** 2026-10-01 (REQ-MDNS-044..079: the RFC 6762 MUSTs the rows left out; REQ-MDNS-016 and 043 corrected to match the RFC)

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
| TC | Never set in our messages (answers are split across packets); a query with it set is answered after 400–500 ms, less the known answers that follow it (RFC 6762 §7.2) |
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

### Message Format

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-044 | MUST | Silently ignore received messages, queries and responses alike, whose OPCODE is not 0 | RFC 6762 §18.3 | TEST-MDNS-044 |
| REQ-MDNS-045 | MUST | Silently ignore received messages, queries and responses alike, whose RCODE is not 0 | RFC 6762 §18.11 | TEST-MDNS-045 |
| REQ-MDNS-046 | MUST | On transmission: QR 1 in responses and 0 in queries (probes); OPCODE, TC, RA, Z, AD, CD and RCODE 0; AA 0 in queries | RFC 6762 §18.2–18.11 | TEST-MDNS-046 |
| REQ-MDNS-047 | MUST | Ignore on reception the AA, RD, RA, Z, AD and CD bits, the TC bit of responses and the ID of multicast responses | RFC 6762 §18.1, §18.4–18.10 | TEST-MDNS-047 |
| REQ-MDNS-048 | MUST | Decode compressed names in questions, in record names, and in the rdata of PTR and SRV records received | RFC 6762 §18.14 | TEST-MDNS-048 |
| REQ-MDNS-049 | MUST NOT | Compress names in the rdata of record types other than NS, CNAME, PTR, DNAME, SOA, MX, AFSDB, RT, KX, RP, PX, SRV and NSEC | RFC 6762 §18.14 | TEST-MDNS-049 |

### Names

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-050 | MUST | Names are precomposed UTF-8 without a byte order mark: `mdns_init()` refuses a name that is not well-formed UTF-8 (RFC 3629), or a label that begins with U+FEFF (anywhere else U+FEFF is a literal zero-width no-break space, §16) — **deviation:** whether the UTF-8 is precomposed (Unicode NFC) is not checked, which would take Unicode tables a responder this small does not carry; the application must give precomposed names | RFC 6762 §16 | TEST-MDNS-050 |
| REQ-MDNS-051 | MUST | Support names of up to 255 bytes on the wire, not counting the terminating zero byte | RFC 6762 App. C | TEST-MDNS-051 |

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
| REQ-MDNS-016 | MUST | Before announcing, probe for uniqueness by sending three Probe queries (QU questions of type ANY, the intended records in the Authority section) | RFC 6762 §8.1 | TEST-MDNS-016 |
| REQ-MDNS-017 | MUST | First probe delayed by random 0–250 ms after interface up | RFC 6762 §8.1 | TEST-MDNS-017 |
| REQ-MDNS-018 | MUST | Space subsequent probes 250 ms apart | RFC 6762 §8.1 | TEST-MDNS-018 |
| REQ-MDNS-019 | MUST | If a conflict response is received during probing, defer the claim and notify the application | RFC 6762 §8.1 | TEST-MDNS-019 |
| REQ-MDNS-020 | MUST | Application MUST provide a conflict callback to select an alternative name | RFC 6762 §9 | TEST-MDNS-020 |
| REQ-MDNS-021 | MUST | After all three probes pass with no conflict, proceed to announce | RFC 6762 §8.3 | TEST-MDNS-021 |
| REQ-MDNS-052 | MUST | Silently ignore apparently conflicting responses received before the first probe is sent | RFC 6762 §8.1 | TEST-MDNS-052 |
| REQ-MDNS-053 | MUST | While probing a name with type ANY questions, treat a response with any record of that name, of any type, as conflicting (a record identical to ours excepted) | RFC 6762 §8.1, §9 | TEST-MDNS-053 |
| REQ-MDNS-054 | MUST | After fifteen conflicts within ten seconds, wait at least five seconds before each further probe attempt | RFC 6762 §8.1 | TEST-MDNS-054 |
| REQ-MDNS-055 | MUST | Simultaneous probe tiebreaking: when another host probes for a name we are probing, compare the records of its Authority section with ours — by class, type, then rdata with names uncompressed, each list sorted, pairwise; if ours are lexicographically earlier, wait one second and probe again; if later, ignore its probe; if identical, there is no conflict | RFC 6762 §8.2, §8.2.1 | TEST-MDNS-055 |
| REQ-MDNS-056 | MUST NOT | Consult a cache of other hosts' records when probing or answering | RFC 6762 §6, §8.1 | — (not observable: the responder keeps no cache) |
| REQ-MDNS-057 | MUST | On a conflict while running, reset the conflicted unique records to probing under the same name; only if that probing fails is the name given up (the conflict callback) and no longer used | RFC 6762 §9 | TEST-MDNS-057 |

### Announcing (Gratuitous Responses)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-022 | MUST | After probing succeeds, send at least two announcement (gratuitous) responses separated by 1 second | RFC 6762 §8.3 | TEST-MDNS-022 |
| REQ-MDNS-023 | MUST | Announcements are multicast responses, not queries | RFC 6762 §8.3 | TEST-MDNS-023 |
| REQ-MDNS-024 | MUST | On network re-attachment (link up), re-probe and re-announce all records | RFC 6762 §8.4 | TEST-MDNS-024 |
| REQ-MDNS-058 | MUST NOT | Send announcements without a change of connectivity: no periodic announcements | RFC 6762 §8.3 | TEST-MDNS-058 |
| REQ-MDNS-059 | MUST | When a record's rdata changes, announce it again; when an address changes, re-announce the address records — `mdns_start()` after an IPv4 or rdata change, `mdns_readdress6()` when an IPv6 address comes or goes | RFC 6762 §8.4 | TEST-MDNS-059 |
| REQ-MDNS-060 | MUST | Before announcing new rdata of a shared record, send a goodbye for the old: a PTR whose instance name is lost in a conflict, and records withdrawn in the CONFLICT state | RFC 6762 §8.4 | TEST-MDNS-060 |

### Responding to Queries

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-025 | MUST | Listen for mDNS queries on 224.0.0.251:5353 | RFC 6762 §6 | TEST-MDNS-025 |
| REQ-MDNS-026 | MUST | Respond with all matching records from the application's record set | RFC 6762 §6 | TEST-MDNS-026 |
| REQ-MDNS-027 | MUST | Send multicast answers for unique records immediately; delay answers containing shared records (e.g. PTR) by a random 20–120 ms to allow aggregation (400–500 ms applies only to queries with the TC bit set) | RFC 6762 §6 | TEST-MDNS-027 |
| REQ-MDNS-028 | MUST | If query has QU (Unicast) bit set and responder recently sent the same record, MAY respond via unicast to the querier | RFC 6762 §5.4 | TEST-MDNS-028 |
| REQ-MDNS-029 | MUST | Known-answer suppression: do NOT send an answer that the query's Answer (known-answer) section already contains with a TTL of at least half the record's TTL | RFC 6762 §7.1 | TEST-MDNS-029 |
| REQ-MDNS-030 | MUST | Answer only queries for the `.local.` domain; ignore other domains silently | RFC 6762 §3 | TEST-MDNS-030 |
| REQ-MDNS-031 | MUST | Set the AA bit and TTL in all answers | RFC 6762 §18 | TEST-MDNS-031 |
| REQ-MDNS-061 | MUST | Silently ignore responses whose source UDP port is not 5353 | RFC 6762 §6 | TEST-MDNS-061 |
| REQ-MDNS-062 | MUST | Accept responses only from the local link: sent to 224.0.0.251 / ff02::fb, or from an on-link source (IPv4: our subnet; IPv6: link-local or an on-link prefix); silently discard others | RFC 6762 §11 | TEST-MDNS-062 |
| REQ-MDNS-063 | MUST NOT | Multicast a record until at least one second after it was last multicast — except to answer a probe, which needs only 250 ms | RFC 6762 §6 | TEST-MDNS-063 |
| REQ-MDNS-064 | MUST | Respond only with a positive, non-null answer, or a negative one for a record known not to exist | RFC 6762 §6 | TEST-MDNS-064 |
| REQ-MDNS-065 | MUST | Answer a query for one of our unique names, for a type the name has no record of, with an NSEC record — an address type for which the interface has no valid address included | RFC 6762 §6, §6.1 | TEST-MDNS-065 |
| REQ-MDNS-066 | MUST NOT | Send NXDOMAIN or any other error response for shared records | RFC 6762 §6 | TEST-MDNS-066 |
| REQ-MDNS-067 | MUST | Generate NSEC records in the restricted form (Next Domain Name = the record's own name, one bitmap block 0 of length 1–32) without the NSEC bit set in the bitmap | RFC 6762 §6.1 | TEST-MDNS-067 |
| REQ-MDNS-068 | MUST | Generate negative responses only for names, types and classes we own: no NSEC for other hosts' names, for shared records, or while probing | RFC 6762 §6.1 | TEST-MDNS-068 |
| REQ-MDNS-069 | MUST NOT | Ignore a whole message because it contains an NSEC record that cannot be parsed | RFC 6762 §6.1 | TEST-MDNS-069 |
| REQ-MDNS-070 | MUST NOT | Put questions in multicast responses; questions in received responses are silently ignored | RFC 6762 §6 | TEST-MDNS-070 |
| REQ-MDNS-071 | MUST | Send responses from port 5353 to port 5353 of 224.0.0.251 / ff02::fb — unicast only to a QU question, a legacy query (to its port) or a direct unicast query | RFC 6762 §6 | TEST-MDNS-071 |
| REQ-MDNS-072 | MUST | Match questions of qtype ANY (255) and qclass ANY (255) by the standard rules, and answer them with all matching records | RFC 6762 §6, §6.5 | TEST-MDNS-072 |
| REQ-MDNS-073 | MUST | Handle queries with more than one question, answering any or all of those we have answers to | RFC 6762 §6.3 | TEST-MDNS-073 |
| REQ-MDNS-074 | MUST | Address records carry all the addresses valid on the interface and no other | RFC 6762 §6.2 | TEST-MDNS-074 |
| REQ-MDNS-075 | MUST | When another host multicasts one of our records with identical rdata and a TTL below half of ours — a goodbye (TTL 0) included — multicast our record | RFC 6762 §6.6 | TEST-MDNS-075 |
| REQ-MDNS-076 | MUST NOT | Set the cache-flush bit in legacy unicast responses | RFC 6762 §6.7, §10.2 | TEST-MDNS-076 |
| REQ-MDNS-077 | MUST | Known answers that follow a truncated query delete an owed answer only if they come from the querying host and no other host has asked for that answer too | RFC 6762 §7.2 | TEST-MDNS-077 |
| REQ-MDNS-078 | MUST | Set the cache-flush bit on every unique record in a response, never on a shared record | RFC 6762 §10.2 | TEST-MDNS-078 |
| REQ-MDNS-079 | MUST | A response with some members of a unique RRSet carries the whole RRSet | RFC 6762 §10.2 | TEST-MDNS-079 |

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
| REQ-MDNS-041 | MUST | Answer legacy unicast queries (source port ≠ 5353) by unicast to the querier's port, repeating its ID and question, with TTL ≤ 10 s; never crash on unexpected IDs or malformed messages | RFC 6762 §6.7 | TEST-MDNS-041 |

### Buffer and Size

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-042 | MUST | mDNS messages MUST fit within a single UDP datagram; split large record sets across multiple responses | RFC 6762 §17 | TEST-MDNS-042 |
| REQ-MDNS-043 | MUST | Compress names to reduce message size (RFC 6762 §18.14 recommends it) — except the target of an SRV record in a legacy unicast response, which MUST NOT be compressed | RFC 1035 §4.1.4, RFC 6762 §18.14 | TEST-MDNS-043 |

## Notes

- **No DNS server needed:** mDNS operates entirely on the local link — no configuration, no server, no DHCP dependency.
- **Hostname convention:** By default, the device should use a `<product>-<last4mac>.local` hostname to avoid conflicts (e.g., `pyro-dead01.local`).
- **Shared parser with DNS:** The mDNS wire format is identical to DNS (RFC 1035); the DNS stub-resolver parser can be reused directly.
- **pyro_fw integration:** mDNS is required so that pyro_fw devices can be discovered on the local network without a pre-configured IP.  DNS-SD (RFC 6763) builds on top of mDNS to advertise the service type — see `docs/requirements/dns-sd.md`.
- **Avahi/Bonjour compatibility:** On Linux the reference implementation is Avahi; on macOS/iOS it is Bonjour (mDNSResponder).  Both must be able to resolve the device's `.local` hostname and browse its services.
