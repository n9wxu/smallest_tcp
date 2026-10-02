# DNS-SD Requirements

**Protocol:** DNS-Based Service Discovery  
**Primary RFC:** RFC 6763 — DNS-Based Service Discovery  
**Supporting:** RFC 6762 (mDNS transport), RFC 2782 (SRV records), RFC 1035 §§3–4 (DNS wire format)  
**Scope:** the advertiser (the mDNS responder's records), over IPv4 and IPv6.  The browser (REQ-DNSSD-021..025) is not implemented.  
**Design:** [docs/design/mdns.md](../design/mdns.md)

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
- Browse for other DNS-SD services on the network (the browser: not implemented)

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

### Service Advertisement (Responder)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-001 | MUST | Advertise each registered service instance with a PTR record: `_service._proto.local. PTR <Instance>._service._proto.local.` | RFC 6763 §4.1 | itest_mdns_009_each_record_answered_with_its_rdata, test_mdns_002_ptr_query_additionals |
| REQ-DNSSD-002 | MUST | Advertise each instance with an SRV record: `<Instance>._service._proto.local. SRV <priority> <weight> <port> <hostname>.local.` | RFC 6763 §5, RFC 2782 | itest_mdns_009_each_record_answered_with_its_rdata, test_mdns_003_srv_query |
| REQ-DNSSD-003 | MUST | Advertise each instance with a TXT record: `<Instance>._service._proto.local. TXT <key=value>…` — the table is the application's: `mdns_init()` does not check that an SRV record has a TXT record beside it | RFC 6763 §6 | itest_mdns_009_each_record_answered_with_its_rdata, test_mdns_017_txt_record |
| REQ-DNSSD-004 | MUST | The mDNS A record for the hostname (from REQ-MDNS-009) serves as the address record for the SRV; no duplication needed | RFC 6763 §5, RFC 6762 | itest_mdns_027_unique_at_once_shared_after_20_to_120_ms |
| REQ-DNSSD-005 | MUST | Support several service instances, of one service type or of several: as many as the record table holds (`MDNS_MAX_RECORDS`, 32 records) | Architecture | itest_dnssd_014_service_types_enumerated |
| REQ-DNSSD-006 | MUST | All DNS-SD records are included in mDNS responses (no separate transport) | RFC 6763 §4, RFC 6762 | itest_mdns_009_each_record_answered_with_its_rdata |
| REQ-DNSSD-007 | SHOULD | When responding to a PTR query for `_service._proto.local.`, include the instance's SRV and TXT records and the address records of the SRV's target in the Additional section — as far as the packet has room | RFC 6763 §12.1 | itest_mdns_027_unique_at_once_shared_after_20_to_120_ms, itest_dnssd_007_additionals_as_far_as_they_fit, test_mdns_002_ptr_query_additionals |
| REQ-DNSSD-008 | SHOULD | When responding to a SRV query, include the A/AAAA address record in the Additional section | RFC 6763 §12.2 | itest_mdns_027_unique_at_once_shared_after_20_to_120_ms, itest_mdns6_039_answered_on_the_family_that_asked, test_mdns_003_srv_query |
| REQ-DNSSD-033 | MUST NOT | Instance names contain ASCII control characters (0x00–0x1F, 0x7F): `mdns_init()` refuses a name with one | RFC 6763 §4.1.1 | itest_dnssd_033_instance_name_control_characters_refused |
| REQ-DNSSD-034 | MUST | Preserve DNS label boundaries when the instance, service and domain parts are joined into one string — **deviation:** names are dotted strings without escapes, so every '.' is a label boundary and an instance name cannot contain a dot, which RFC 6763 §4.1.1 allows; the application must keep dots out of its instance names | RFC 6763 §4.3 | itest_dnssd_034_dots_separate_labels |

### Record Set (Application-Provided)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-009 | MUST | Application provides service records as a static table at initialisation (no dynamic allocation) | Architecture | itest_mdns_008_record_table_given_at_init |
| REQ-DNSSD-010 | MUST | A service is three records of the table: a PTR from the service type to the instance, the instance's SRV (priority, weight, port, target host) and its TXT (key=value strings) | RFC 6763 §4.1, §5, §6 | itest_mdns_008_record_table_given_at_init |
| REQ-DNSSD-011 | MUST | TXT record entries are a flat array of `key=value` C-strings, NULL-terminated | Architecture | itest_mdns_009_each_record_answered_with_its_rdata, test_mdns_017_txt_record |
| REQ-DNSSD-012 | MUST | TXT record MUST NOT be empty; if no metadata, send a single-byte TXT record containing `0x00` | RFC 6763 §6.1 | itest_dnssd_012_empty_txt_is_one_zero_byte |
| REQ-DNSSD-013 | SHOULD | Support TXT record versioning via a `txtvers=1` key | RFC 6763 §6.4 | test_mdns_017_txt_record |
| REQ-DNSSD-035 | MUST | A TXT key — the string up to its first '=' — is at least one character, all printable US-ASCII (0x20–0x7E): `mdns_init()` refuses a TXT string with an empty key or another byte in it | RFC 6763 §6.4 | itest_dnssd_035_txt_keys_checked |
| REQ-DNSSD-036 | MUST NOT | Repeat the SRV record's target host or port as key/value pairs in the TXT record — the strings are the application's: the responder sends them as given and adds none | RFC 6763 §6.3 | itest_mdns_009_each_record_answered_with_its_rdata |
| REQ-DNSSD-037 | MUST NOT | Enclose TXT values in quotation marks or similar punctuation — likewise: the strings are sent as the application gives them | RFC 6763 §6.5 | itest_mdns_009_each_record_answered_with_its_rdata |

### Service Type Enumeration (Meta-Query)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-014 | SHOULD | Respond to `_services._dns-sd._udp.local.` PTR queries with all advertised service types | RFC 6763 §9 | itest_dnssd_014_service_types_enumerated, test_mdns_009_meta_query |
| REQ-DNSSD-015 | MUST | Each service type returned in the meta-query response is a PTR record pointing to `_service._proto.local.` | RFC 6763 §9 | itest_dnssd_014_service_types_enumerated, test_mdns_009_meta_query |

### TTL and Record Lifetime

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-016 | SHOULD | PTR record TTL of 4500 seconds (75 minutes) | RFC 6762 §10 | itest_mdns_014_ttls_as_the_table_gives_them, test_mdns_002_ptr_query_additionals |
| REQ-DNSSD-017 | SHOULD | SRV record TTL 120 seconds, as for every record with a host name as its name or in its rdata; TXT record TTL 4500 seconds (75 minutes), as for other records | RFC 6762 §10 | itest_mdns_014_ttls_as_the_table_gives_them |
| REQ-DNSSD-018 | SHOULD | On service withdrawal (`mdns_withdraw()`, `mdns_stop()`), send goodbyes (TTL 0) for its PTR, SRV and TXT records — and for the service type's listing under the meta-query, if no other instance offers the type | RFC 6762 §10.1 | itest_mdns_033_goodbye_includes_the_meta_query_ptr, itest_dnssd_018_withdraw_one_service, itest_dnssd_018_withdraw_one_of_two_instances, itest_dnssd_018_withdraw_while_probing, test_mdns_008_goodbye_on_shutdown |

### Conflict Detection and Renaming

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-019 | MUST | When probing for an instance name fails, cease using the name and reconfigure: the application's conflict callback (REQ-MDNS-020) selects a new one | RFC 6762 §9, RFC 6763 App. D | itest_mdns_060_goodbye_for_old_ptr_rdata_before_renaming, itest_mdns_019_failed_probe_gives_up_the_names |
| REQ-DNSSD-020 | SHOULD | The renamed instance appends a number: `Instance (2)`, `Instance (3)`, … — the application's callback does it (`demo/mdns_demo`) | RFC 6763 App. D | itest_mdns_060_goodbye_for_old_ptr_rdata_before_renaming |
| REQ-DNSSD-038 | MUST NOT | Give an SRV record — a flagship-naming placeholder included — the root label as its target: `mdns_init()` refuses `""` and `"."` | RFC 6763 §8 | itest_dnssd_038_srv_target_never_root |

### Service Browser (not implemented)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-021 | SHOULD | Send a PTR query for `_service._proto.local.` to browse available instances | RFC 6763 §4 | — (not implemented) |
| REQ-DNSSD-022 | SHOULD | For each PTR answer received, resolve the instance's SRV and TXT records | RFC 6763 §4 | — (not implemented) |
| REQ-DNSSD-023 | SHOULD | Cache discovered instances in an application-provided table | Architecture | — (not implemented) |
| REQ-DNSSD-024 | SHOULD | Notify application callback when a new service instance is discovered | Architecture | — (not implemented) |
| REQ-DNSSD-025 | SHOULD | Notify application callback when a Goodbye packet removes a known instance | RFC 6762 §10.1 | — (not implemented) |

### Interoperability

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-026 | MUST | Advertised services are discoverable by `dns-sd -B _service._tcp local` on macOS (mDNSResponder) — run against the responder by `tests/blackbox/mdns_interop_macos.sh` | Interoperability | itest_dnssd_026_browse_and_resolve_as_resolvers_ask |
| REQ-DNSSD-027 | MUST | Advertised services are discoverable by `avahi-browse -r _service._tcp` on Linux — run against the responder, in CI, by `tests/blackbox/mdns_interop.sh` | Interoperability | itest_dnssd_026_browse_and_resolve_as_resolvers_ask |
| REQ-DNSSD-028 | MUST | Advertised services are discoverable by iOS and Android apps using the standard Bonjour / NSD APIs — nothing runs against either; iOS has the mDNSResponder of macOS | Interoperability | itest_dnssd_026_browse_and_resolve_as_resolvers_ask |

### Buffer and Size

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DNSSD-029 | MUST | A record fits one mDNS message in the TX frame buffer — alone with its question, in its name's probe, as its name's NSEC: `mdns_init()` refuses (`NET_ERR_BUF_TOO_SMALL`) a table with a record no message could carry | RFC 6762 §17 | itest_dnssd_029_record_too_big_for_any_packet_refused |
| REQ-DNSSD-030 | MUST | If PTR + SRV + TXT + A records do not fit in one packet, split into separate responses | RFC 6762 §17, RFC 6763 §12 | itest_mdns_042_records_split_across_packets |
| REQ-DNSSD-031 | MUST | Labels are at most 63 octets; a name is at most 255 octets on the wire, not counting its terminating zero byte (RFC 6762 App. C) — names of that length accepted, longer ones refused | RFC 1035 §2.3.4, RFC 6762 App. C | itest_mdns_051_names_of_255_bytes |
| REQ-DNSSD-032 | MUST | Each TXT key=value string MUST NOT exceed 255 octets, what its length byte can say | RFC 6763 §6.1, RFC 1035 §3.3.14 | itest_dnssd_032_txt_strings_of_255_bytes |

## Notes

- **Dots in instance names (REQ-DNSSD-034):** RFC 6763 §4.1.1 allows any character in the `<Instance>` label, dots included, and §4.3 asks that label boundaries survive when the three parts are joined into one string.  The record table takes names as dotted strings without escapes, so every `.` ends a label: `"Pyro.Unit._pyro._tcp.local"` is the instance `Pyro` under the subdomain `Unit` — not what was meant.  Instance names must not contain dots; a product that lets users name the device must replace them (with a space or a hyphen, say).
- **Application obligations (REQ-DNSSD-036, 037):** the TXT strings are sent as the application gives them, so it is the application that must not repeat the SRV target or port in them, nor quote the values.
- **DNS-SD is a convention, not a new protocol:** All records are standard DNS types; the mDNS transport handles delivery.  The DNS-SD layer only specifies how to name and structure PTR/SRV/TXT records.
- **pyro_fw service type:** The pyro_fw project should register a service type such as `_pyro._tcp` or `_http._tcp` (if HTTP is used for the control interface).  The instance name should include the device serial number or MAC suffix so each unit has a unique name.
- **Zero configuration:** With mDNS + DNS-SD, a pyro_fw device requires no static IP, no DNS server configuration, and no mDNS proxy — it is fully discoverable on any Ethernet or Wi-Fi LAN.
- **avahi-publish for testing:** During development, `avahi-publish-service` can act as a reference DNS-SD advertiser for interoperability testing.
