# DNS-SD Requirements

**Protocol:** DNS-Based Service Discovery  
**Primary RFC:** RFC 6763 — DNS-Based Service Discovery  
**Supporting:** RFC 6762 (mDNS transport), RFC 2782 (SRV records), RFC 1035 §§3–4 (DNS wire format)  
**Scope:** V1 (IPv4, advertiser/responder), V2 (querier/browser)  
**Last updated:** 2026-10-01 (REQ-DNSSD-033..038: the RFC 6763 MUSTs the rows left out; REQ-DNSSD-017 and 031 corrected to match RFC 6762)

## Overview

DNS-SD (RFC 6763) is a convention layered on top of DNS (and typically mDNS on the local link) that allows services to advertise their existence and capabilities without prior configuration.  It uses standard DNS record types:

| Record | Purpose |
|---|---|
| PTR | Maps `_service._proto.local.` → `Instance._service._proto.local.` (service enumeration) |
| SRV | Maps instance name → hostname + port |
| TXT | Carries metadata key=value pairs for the instance |
| A / AAAA | Maps hostname → IP address (provided by mDNS) |

Primary use cases for this stack / pyro_fw:
- Advertise the device as `pyro-XXXX._pyro._tcp.local.` (or similar service type) so control software can discover it by browsing `_pyro._tcp.local.`
- Optionally browse for other DNS-SD services on the network (V2)

## Service Instance Naming

An instance name has the format:

```
<Instance>.<Service>.<Proto>.local.
```

For example:
```
Pyro Sensor Unit 1._pyro._tcp.local.
```

| Component | Description | Example |
|---|---|---|
| Instance | Human-readable name; unique on the link | `Pyro Sensor Unit 1` |
| Service | Underscore-prefixed service type | `_pyro` |
| Proto | `_tcp` or `_udp` | `_tcp` |
| Domain | Always `local.` for link-local | `local.` |

## Requirements

### Service Advertisement (Responder — V1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-001 | MUST | Advertise each registered service instance with a PTR record: `_service._proto.local. PTR <Instance>._service._proto.local.` | RFC 6763 §4.1 | TEST-DNSSD-001 |
| REQ-DNSSD-002 | MUST | Advertise each instance with an SRV record: `<Instance>._service._proto.local. SRV <priority> <weight> <port> <hostname>.local.` | RFC 6763 §5, RFC 2782 | TEST-DNSSD-002 |
| REQ-DNSSD-003 | MUST | Advertise each instance with a TXT record: `<Instance>._service._proto.local. TXT <key=value>…` | RFC 6763 §6 | TEST-DNSSD-003 |
| REQ-DNSSD-004 | MUST | The mDNS A record for the hostname (from REQ-MDNS-009) serves as the address record for the SRV; no duplication needed | RFC 6763 §5, RFC 6762 | TEST-DNSSD-004 |
| REQ-DNSSD-005 | MUST | Support at least one service instance per device at V1; multiple instances SHOULD be supported | Architecture | TEST-DNSSD-005 |
| REQ-DNSSD-006 | MUST | All DNS-SD records are included in mDNS responses (no separate transport) | RFC 6763 §4, RFC 6762 | TEST-DNSSD-006 |
| REQ-DNSSD-007 | MUST | When responding to a PTR query for `_service._proto.local.`, include the matching SRV and TXT records in the Additional section | RFC 6763 §12.1 | TEST-DNSSD-007 |
| REQ-DNSSD-008 | MUST | When responding to a SRV query, include the A/AAAA address record in the Additional section | RFC 6763 §12.2 | TEST-DNSSD-008 |
| REQ-DNSSD-033 | MUST NOT | Instance names contain ASCII control characters (0x00–0x1F, 0x7F): `mdns_init()` refuses a name with one | RFC 6763 §4.1.1 | TEST-DNSSD-033 |
| REQ-DNSSD-034 | MUST | Preserve DNS label boundaries when the instance, service and domain parts are joined into one string — **deviation:** names are dotted strings without escapes, so every '.' is a label boundary and an instance name cannot contain a dot, which RFC 6763 §4.1.1 allows; the application must keep dots out of its instance names | RFC 6763 §4.3 | TEST-DNSSD-034 |

### Record Set (Application-Provided)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-009 | MUST | Application provides service records as a static table at initialisation (no dynamic allocation) | Architecture | TEST-DNSSD-009 |
| REQ-DNSSD-010 | MUST | Each service record entry contains: service type, protocol, instance name, port, TXT key=value pairs, priority, weight | RFC 6763 §5–6 | TEST-DNSSD-010 |
| REQ-DNSSD-011 | MUST | TXT record entries are a flat array of `key=value` C-strings, NULL-terminated | Architecture | TEST-DNSSD-011 |
| REQ-DNSSD-012 | MUST | TXT record MUST NOT be empty; if no metadata, send a single-byte TXT record containing `0x00` | RFC 6763 §6.1 | TEST-DNSSD-012 |
| REQ-DNSSD-013 | SHOULD | Support TXT record versioning via a `txtvers=1` key | RFC 6763 §6.4 | TEST-DNSSD-013 |
| REQ-DNSSD-035 | MUST | A TXT key — the string up to its first '=' — is at least one character, all printable US-ASCII (0x20–0x7E): `mdns_init()` refuses a TXT string with an empty key or another byte in it | RFC 6763 §6.4 | TEST-DNSSD-035 |
| REQ-DNSSD-036 | MUST NOT | Repeat the SRV record's target host or port as key/value pairs in the TXT record | RFC 6763 §6.3 | — (application obligation: the TXT strings are the application's) |
| REQ-DNSSD-037 | MUST NOT | Enclose TXT values in quotation marks or similar punctuation | RFC 6763 §6.5 | — (application obligation: the strings are sent as given) |

### Service Type Enumeration (Meta-Query)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-014 | SHOULD | Respond to `_services._dns-sd._udp.local.` PTR queries with all advertised service types | RFC 6763 §9 | TEST-DNSSD-014 |
| REQ-DNSSD-015 | MUST | Each service type returned in the meta-query response is a PTR record pointing to `_service._proto.local.` | RFC 6763 §9 | TEST-DNSSD-015 |

### TTL and Record Lifetime

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-016 | MUST | PTR record TTL SHOULD be 4500 seconds (75 minutes) | RFC 6762 §11.3, RFC 6763 §12 | TEST-DNSSD-016 |
| REQ-DNSSD-017 | SHOULD | SRV record TTL 120 seconds, as for every record with a host name as its name or in its rdata; TXT record TTL 4500 seconds (75 minutes), as for other records | RFC 6762 §10 | TEST-DNSSD-017 |
| REQ-DNSSD-018 | MUST | On service withdrawal, send Goodbye packets (TTL=0) for all associated PTR, SRV, and TXT records | RFC 6762 §11.3, RFC 6763 §8.4 | TEST-DNSSD-018 |

### Conflict Detection and Renaming

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-019 | MUST | If a conflict is detected for an instance name, the application callback (REQ-MDNS-020) selects a new name | RFC 6763 §8 | TEST-DNSSD-019 |
| REQ-DNSSD-020 | SHOULD | Renamed instance appends a numeric suffix: `Instance (2)`, `Instance (3)`, … | RFC 6763 §8 | TEST-DNSSD-020 |
| REQ-DNSSD-038 | MUST NOT | Give an SRV record — a flagship-naming placeholder included — the root label as its target: `mdns_init()` refuses `""` and `"."` | RFC 6763 §8 | TEST-DNSSD-038 |

### Service Browser (V2 — Querier)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-021 | SHOULD | Send a PTR query for `_service._proto.local.` to browse available instances | RFC 6763 §4 | TEST-DNSSD-021 |
| REQ-DNSSD-022 | SHOULD | For each PTR answer received, resolve the instance's SRV and TXT records | RFC 6763 §4 | TEST-DNSSD-022 |
| REQ-DNSSD-023 | SHOULD | Cache discovered instances in an application-provided table | Architecture | TEST-DNSSD-023 |
| REQ-DNSSD-024 | SHOULD | Notify application callback when a new service instance is discovered | Architecture | TEST-DNSSD-024 |
| REQ-DNSSD-025 | SHOULD | Notify application callback when a Goodbye packet removes a known instance | RFC 6762 §11.3 | TEST-DNSSD-025 |

### Interoperability

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-026 | MUST | Advertised services MUST be discoverable by `dns-sd -B _service._tcp local` on macOS | RFC 6763 | TEST-DNSSD-026 |
| REQ-DNSSD-027 | MUST | Advertised services MUST be discoverable by `avahi-browse -r _service._tcp` on Linux | RFC 6763 | TEST-DNSSD-027 |
| REQ-DNSSD-028 | MUST | Advertised services MUST be discoverable by iOS/Android apps using standard Bonjour/NSD APIs | RFC 6763 | TEST-DNSSD-028 |

### Buffer and Size

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-029 | MUST | Instance name + service type + TXT records MUST fit in a single mDNS response UDP datagram | RFC 6762 §17 | TEST-DNSSD-029 |
| REQ-DNSSD-030 | MUST | If PTR + SRV + TXT + A records do not fit in one packet, split into separate responses | RFC 6762 §17, RFC 6763 §12 | TEST-DNSSD-030 |
| REQ-DNSSD-031 | MUST | Labels are at most 63 octets; a name is at most 255 octets on the wire, not counting its terminating zero byte (RFC 6762 App. C) — names of that length accepted, longer ones refused | RFC 1035 §2.3.4, RFC 6762 App. C | TEST-DNSSD-031 |
| REQ-DNSSD-032 | MUST | Each TXT key=value string MUST NOT exceed 255 octets (DNS label limit) | RFC 6763 §6.1, RFC 1035 | TEST-DNSSD-032 |

## Notes

- **Dots in instance names (REQ-DNSSD-034):** RFC 6763 §4.1.1 allows any character in the `<Instance>` label, dots included, and §4.3 asks that label boundaries survive when the three parts are joined into one string.  The record table takes names as dotted strings without escapes, so every `.` ends a label: `"Pyro.Unit._pyro._tcp.local"` is the instance `Pyro` under the subdomain `Unit` — not what was meant.  Instance names must not contain dots; a product that lets users name the device must replace them (with a space or a hyphen, say).
- **Application obligations (REQ-DNSSD-036, 037):** the TXT strings are sent as the application gives them, so it is the application that must not repeat the SRV target or port in them, nor quote the values.
- **DNS-SD is a convention, not a new protocol:** All records are standard DNS types; the mDNS transport handles delivery.  The DNS-SD layer only specifies how to name and structure PTR/SRV/TXT records.
- **pyro_fw service type:** The pyro_fw project should register a service type such as `_pyro._tcp` or `_http._tcp` (if HTTP is used for the control interface).  The instance name should include the device serial number or MAC suffix so each unit has a unique name.
- **Zero configuration:** With mDNS + DNS-SD, a pyro_fw device requires no static IP, no DNS server configuration, and no mDNS proxy — it is fully discoverable on any Ethernet or Wi-Fi LAN.
- **avahi-publish for testing:** During development, `avahi-publish-service` can act as a reference DNS-SD advertiser for interoperability testing.
