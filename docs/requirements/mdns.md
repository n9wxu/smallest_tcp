# mDNS Requirements

**Protocol:** Multicast DNS  
**Primary RFC:** RFC 6762 — Multicast DNS  
**Supporting:** RFC 1035 §§3–4 (DNS wire format), RFC 6840 (DNSSEC clarifications N/A), RFC 4795 (LLMNR — not used)  
**Scope:** the responder, over IPv4 and IPv6.  The querier (REQ-MDNS-034..037: resolving other hosts' `.local` names, with a cache) is not implemented.  
**Design:** [docs/design/mdns.md](../design/mdns.md)

## Overview

Multicast DNS (mDNS) provides DNS-like hostname resolution and service announcement on a local link without requiring a DNS server or DHCP-assigned DNS option.  It operates on the reserved multicast group **224.0.0.251** (IPv4) / **ff02::fb** (IPv6) using **UDP port 5353**.  Names end with `.local.` and are resolved entirely on the local network segment.

Primary use cases for this stack:
- Announce the device's hostname as `<name>.local` so peers can reach it without knowing its IP
- Expose service records for DNS-SD (RFC 6763) — see `docs/requirements/dns-sd.md`
- Resolve other `.local` hostnames (the querier: not implemented)

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
| REQ-MDNS-001 | MUST | Send every mDNS message from UDP port 5353, and to port 5353 — but a legacy unicast response, which goes to the querier's port (REQ-MDNS-041) | RFC 6762 §5.2, §6 | itest_mdns_001_port_ttl_and_id_of_everything_sent, test_mdns_006_ip_ttl_255 |
| REQ-MDNS-002 | MUST | Join the IPv4 multicast group 224.0.0.251 on the interface when the responder starts (`mdns_start()`: an IGMP report, repeated once), and leave it when it stops (`mdns_stop()`) | RFC 6762 §3, RFC 2236 | itest_mdns_002_group_joined_at_start_left_at_stop, test_mdns_013_igmp_join |
| REQ-MDNS-003 | MUST | Use DNS wire format (RFC 1035 §§3–4) for all mDNS messages | RFC 6762 §18 | itest_mdns_001_port_ttl_and_id_of_everything_sent |
| REQ-MDNS-004 | MUST | Set the AA (Authoritative Answer) bit in all response messages | RFC 6762 §18.4 | itest_mdns_001_port_ttl_and_id_of_everything_sent, test_mdns_004_aa_bit_set |
| REQ-MDNS-005 | MUST | Set the message ID to 0 in every multicast response — and in every multicast query (the probes), which is a SHOULD | RFC 6762 §18.1 | itest_mdns_001_port_ttl_and_id_of_everything_sent, test_mdns_005_id_zero |
| REQ-MDNS-006 | SHOULD | Send every mDNS packet — unicast responses included — with IP TTL (IPv6 Hop Limit) 255 | RFC 6762 §11 | itest_mdns_001_port_ttl_and_id_of_everything_sent, test_mdns_006_ip_ttl_255 |
| REQ-MDNS-007 | MUST | Put in responses only records the responder is authoritative for: those of the application's table — names in `.local.`, or in a link-local reverse-mapping domain (RFC 6762 §4).  The names are the application's: `mdns_init()` does not check their domain | RFC 6762 §6, §3 | itest_mdns_064_only_positive_or_owned_negative_answers |

### Message Format

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-044 | MUST | Silently ignore received messages, queries and responses alike, whose OPCODE is not 0 | RFC 6762 §18.3 | itest_mdns_044_nonzero_opcode_ignored |
| REQ-MDNS-045 | MUST | Silently ignore received messages, queries and responses alike, whose RCODE is not 0 | RFC 6762 §18.11 | itest_mdns_045_nonzero_rcode_ignored |
| REQ-MDNS-046 | MUST | On transmission: QR 1 in responses and 0 in queries (probes); OPCODE, TC, RA, Z, AD, CD and RCODE 0; AA 0 in queries | RFC 6762 §18.2–18.11 | itest_mdns_016_probes_are_qu_any_with_proposed_records, itest_mdns_046_header_bits_on_transmission |
| REQ-MDNS-047 | MUST | Ignore on reception the AA, RD, RA, Z, AD and CD bits, the TC bit of responses and the ID of multicast responses | RFC 6762 §18.1, §18.4–18.10 | itest_mdns_047_header_bits_ignored_on_reception |
| REQ-MDNS-048 | MUST | Decode compressed names in questions, in record names, and in the rdata of PTR and SRV records received | RFC 6762 §18.14 | itest_mdns_048_compressed_names_decoded |
| REQ-MDNS-049 | MUST NOT | Compress names in the rdata of record types other than NS, CNAME, PTR, DNAME, SOA, MX, AFSDB, RT, KX, RP, PX, SRV and NSEC | RFC 6762 §18.14 | itest_mdns_049_no_compression_in_other_rdata |

### Names

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-050 | MUST | Names are precomposed UTF-8 without a byte order mark: `mdns_init()` refuses a name that is not well-formed UTF-8 (RFC 3629), or a label that begins with U+FEFF (anywhere else U+FEFF is a literal zero-width no-break space, §16) — **deviation:** whether the UTF-8 is precomposed (Unicode NFC) is not checked, which would take Unicode tables a responder this small does not carry; the application must give precomposed names | RFC 6762 §16 | itest_mdns_050_names_utf8_without_bom |
| REQ-MDNS-051 | MUST | Support names of up to 255 bytes on the wire, not counting the terminating zero byte | RFC 6762 App. C | itest_mdns_051_names_of_255_bytes |

### Record Set (Application-Provided)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-008 | MUST | Accept a static record set from the application at initialisation (no dynamic allocation) | Architecture | itest_mdns_008_record_table_given_at_init |
| REQ-MDNS-009 | MUST | Support A records (type 1) for hostname → IPv4 address mapping | RFC 6762 §6.2, RFC 1035 §3.4.1 | itest_mdns_009_each_record_answered_with_its_rdata, test_mdns_001_hostname_a_query |
| REQ-MDNS-010 | MUST | Support PTR records (type 12) for service instance enumeration and reverse mapping | RFC 6763 §4.1, RFC 1035 §3.3.12 | itest_mdns_009_each_record_answered_with_its_rdata |
| REQ-MDNS-011 | MUST | Support SRV records (type 33) for service instance host+port | RFC 6763 §5, RFC 2782 | itest_mdns_009_each_record_answered_with_its_rdata |
| REQ-MDNS-012 | MUST | Support TXT records (type 16) for key=value service metadata | RFC 6763 §6, RFC 1035 §3.3.14 | itest_mdns_009_each_record_answered_with_its_rdata |
| REQ-MDNS-013 | SHOULD | Support AAAA records (type 28) for hostname → IPv6 address, in IPv6 builds | RFC 6762 §6.2, RFC 3596 | itest_mdns6_038_both_groups_probed_and_announced, itest_mdns6_039_answered_on_the_family_that_asked, test_mdns_020_aaaa_over_ipv6 |
| REQ-MDNS-014 | SHOULD | TTL of 120 seconds for the records with a host name as their name or in their rdata — A, AAAA, SRV: `MDNS_TTL_HOST`, which the application's table gives them | RFC 6762 §10 | itest_mdns_014_ttls_as_the_table_gives_them, test_mdns_001_hostname_a_query |
| REQ-MDNS-015 | SHOULD | TTL of 4500 seconds (75 minutes) for the other records — a service's PTR, TXT: `MDNS_TTL_OTHER` | RFC 6762 §10 | itest_mdns_014_ttls_as_the_table_gives_them |

### Probing (Conflict Detection Before Announcing)

RFC 6762 §8.1 requires the probe (MUST) and gives its number and timing in prose ("should", in lower case).  REQ-MDNS-016..018 hold them at MUST: the 750 ms another host has to defend its name are counted from them.

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-016 | MUST | Before announcing, probe for uniqueness by sending three Probe queries (QU questions of type ANY, the intended records in the Authority section) | RFC 6762 §8.1 | itest_dnssd_018_withdraw_while_probing, itest_mdns_016_probes_are_qu_any_with_proposed_records, itest_mdns_017_probe_and_announcement_timing, test_mdns_010_probes_on_startup |
| REQ-MDNS-017 | MUST | First probe delayed by a random 0–250 ms after `mdns_start()` | RFC 6762 §8.1 | itest_mdns_017_probe_and_announcement_timing, test_mdns_010_probes_on_startup |
| REQ-MDNS-018 | MUST | Space subsequent probes 250 ms apart | RFC 6762 §8.1 | itest_mdns_017_probe_and_announcement_timing, test_mdns_010_probes_on_startup |
| REQ-MDNS-019 | MUST | If a conflicting response is received during probing, defer to the existing host — use none of the names (state CONFLICT, silent) — and notify the application | RFC 6762 §8.1 | itest_mdns_019_failed_probe_gives_up_the_names, test_mdns_012_conflict_renames |
| REQ-MDNS-020 | MUST | Cease using a name whose probing failed, and reconfigure: the application's conflict callback (`mdns_conflict_fn_t`) selects another name and calls `mdns_start()`; a responder without a callback stays silent | RFC 6762 §9 | itest_mdns_019_failed_probe_gives_up_the_names, itest_mdns_020_callback_renames_and_starts_again, test_mdns_012_conflict_renames |
| REQ-MDNS-021 | MUST | After all three probes pass with no conflict, proceed to announce | RFC 6762 §8.3 | itest_mdns_017_probe_and_announcement_timing, itest_mdns_021_answers_only_once_probing_is_over, test_mdns_011_announcements |
| REQ-MDNS-052 | MUST | Silently ignore apparently conflicting responses received before the first probe is sent | RFC 6762 §8.1 | itest_mdns_052_responses_before_the_first_probe_ignored |
| REQ-MDNS-053 | MUST | While probing a name with type ANY questions, treat a response with any record of that name, of any type, as conflicting (a record identical to ours excepted) | RFC 6762 §8.1, §9 | itest_mdns_053_any_record_of_the_name_conflicts_while_probing, itest_mdns6_053_another_hosts_aaaa_conflicts |
| REQ-MDNS-054 | MUST | After fifteen conflicts within ten seconds, wait at least five seconds before each further probe attempt | RFC 6762 §8.1 | itest_mdns_054_fifteen_conflicts_slow_probing_down |
| REQ-MDNS-055 | MUST | Simultaneous probe tiebreaking: when another host probes for a name we are probing, compare the records of its Authority section with ours — by class, type, then rdata with names uncompressed, each list sorted, pairwise; if ours are lexicographically earlier, wait one second and probe again; if later, ignore its probe; if identical, there is no conflict — **deviation in a build with `MDNS_TIEBREAK` 0**, which leaves the tiebreak out (REQ-MDNS-081) | RFC 6762 §8.2, §8.2.1 | itest_mdns_055_simultaneous_probe_lost_waits_a_second, itest_mdns_055_simultaneous_probe_won_or_tied, itest_mdns_055_sets_sorted_and_the_one_that_runs_out_loses, itest_mdns_055_malformed_probes_ignored |
| REQ-MDNS-081 | MUST | Built with `MDNS_TIEBREAK` 0 — for a link on which no other host can be probing for our names at the same moment, such as a point-to-point USB network gadget's — another host's probe is a query like any other, neither compared nor deferred to, and two hosts that claim a name at once are still told apart, by the conflicts of §8.1 and §9: the one that announces while the other still probes keeps the name; two that announce at the same moment both probe again, after a random 0–250 ms and up to one second more, so that one of them announces first | RFC 6762 §8.1, §9 (in place of §8.2) | itest_mdns_081_another_hosts_probe_is_not_deferred_to, itest_mdns_081_first_to_announce_keeps_the_name, itest_mdns_081_dead_heat_settled_by_probing_again, itest_mdns_081_started_together_one_keeps_the_name |
| REQ-MDNS-056 | MUST NOT | Use records learned from other hosts: none is put in a response, and probing counts only conflicting responses received live — the responder keeps no cache | RFC 6762 §6, §8.1 | itest_mdns_056_other_hosts_records_never_used |
| REQ-MDNS-057 | MUST | On a conflict while running, reset the conflicted unique records to probing under the same name; only if that probing fails is the name given up (the conflict callback) and no longer used | RFC 6762 §9 | itest_mdns_057_conflict_while_running_probes_again, itest_mdns_057_conflict_while_running_undefended_keeps_name, itest_mdns_057_what_is_no_conflict_while_running, itest_mdns_063_announcements_and_corrections_wait_too, itest_mdns6_053_another_hosts_aaaa_conflicts |

### Announcing (Gratuitous Responses)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-022 | MUST | After probing succeeds, send at least two announcement (gratuitous) responses separated by 1 second | RFC 6762 §8.3 | itest_mdns_017_probe_and_announcement_timing, test_mdns_011_announcements |
| REQ-MDNS-023 | MUST | Announcements are multicast responses, not queries | RFC 6762 §8.3 | itest_mdns_017_probe_and_announcement_timing, test_mdns_011_announcements |
| REQ-MDNS-024 | MUST | On a change of connectivity (link up, wake from sleep), probe for and announce all records again: `mdns_start()`, which the application calls then | RFC 6762 §8 | itest_mdns_024_start_again_probes_and_announces_again |
| REQ-MDNS-058 | MUST NOT | Send announcements without a change of connectivity: no periodic announcements | RFC 6762 §8.3 | itest_mdns_058_no_periodic_announcements |
| REQ-MDNS-059 | MUST | When a record's rdata changes, announce it again; when an address changes, re-announce the address records — `mdns_start()` after an IPv4 or rdata change, `mdns_readdress6()` when an IPv6 address comes or goes — **deviation:** once running, `mdns_readdress6()` announces to ff02::fb only (IPv4 and IPv6 are two links to RFC 6762 §20, and the change is on the IPv6 one): a cache that learned the AAAA records over IPv4 keeps the old ones until their TTL (120 s) runs out | RFC 6762 §8.4 | itest_mdns_059_new_ipv4_address_announced, itest_mdns6_059_lost_address_reannounced, itest_mdns6_059_readdressed_before_running, test_mdns_021_announced_over_ipv6 |
| REQ-MDNS-060 | MUST | Before announcing new rdata of a shared record, send a goodbye for the old: a PTR whose instance name is lost in a conflict, and records withdrawn in the CONFLICT state | RFC 6762 §8.4 | itest_mdns_060_goodbye_for_old_ptr_rdata_before_renaming |

### Responding to Queries

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-025 | MUST | Listen for mDNS queries on 224.0.0.251:5353 | RFC 6762 §6 | itest_mdns_002_group_joined_at_start_left_at_stop |
| REQ-MDNS-026 | MUST | Respond with all matching records from the application's record set | RFC 6762 §6 | itest_mdns_009_each_record_answered_with_its_rdata, test_mdns_001_hostname_a_query, test_mdns_018_any_query |
| REQ-MDNS-027 | SHOULD | Send multicast answers of unique records at once; delay answers with shared records (e.g. PTR) by a random 20–120 ms, in which what else is asked joins the response; delay the answer to a query with the TC bit set by 400–500 ms | RFC 6762 §6 | itest_mdns_027_truncated_query_waits_400_to_500ms, itest_mdns_029_known_answers_after_truncated_query, itest_mdns_027_unique_at_once_shared_after_20_to_120_ms |
| REQ-MDNS-028 | SHOULD | Answer a question with the QU (unicast-response) bit by unicast to the querier — **deviation:** always by unicast (by multicast only to a querier without an address yet): the rule to multicast instead a record not multicast within a quarter of its TTL is not applied, as the responder keeps no time of each record's last multicast | RFC 6762 §5.4 | itest_mdns_071_response_destinations, itest_mdns_028_qu_question_answered_by_unicast, itest_mdns6_028_unicast_and_legacy_answers_over_ipv6, test_mdns_015_qu_unicast |
| REQ-MDNS-029 | MUST | Known-answer suppression: do NOT send an answer that the query's Answer (known-answer) section already contains with a TTL of at least half the record's TTL | RFC 6762 §7.1 | itest_mdns_029_known_answers_after_truncated_query, itest_mdns_029_known_answer_suppression, itest_mdns6_029_known_aaaa_and_the_nsec_of_both_families, test_mdns_007_known_answer_suppression |
| REQ-MDNS-030 | MUST | Answer only queries for names of the record table; ignore queries for any other name — other domains included — silently | RFC 6762 §6 | itest_mdns_064_only_positive_or_owned_negative_answers, test_mdns_016_foreign_names_ignored |
| REQ-MDNS-031 | MUST | Set the AA bit and TTL in all answers | RFC 6762 §18.4, §10 | itest_mdns_001_port_ttl_and_id_of_everything_sent, test_mdns_004_aa_bit_set |
| REQ-MDNS-061 | MUST | Silently ignore responses whose source UDP port is not 5353 | RFC 6762 §6 | itest_mdns_061_responses_from_other_ports_ignored |
| REQ-MDNS-062 | MUST | Accept responses only from the local link: sent to 224.0.0.251 / ff02::fb, or from an on-link source (IPv4: our subnet; IPv6: link-local or an on-link prefix); silently discard others | RFC 6762 §11 | itest_mdns_062_responses_only_from_the_local_link, itest_mdns6_062_ipv6_responses_only_from_the_link, itest_mdns_062_group_response_in_the_drivers_own_buffer, itest_mdns6_062_group_response_in_the_drivers_own_buffer |
| REQ-MDNS-080 | MUST | Accept a unicast response only as the answer to a query sent recently that asked for unicast responses — the QU questions of our probes: one that arrives while not probing is silently ignored | RFC 6762 §6 | itest_mdns_080_unicast_responses_only_to_our_probes |
| REQ-MDNS-063 | MUST NOT | Multicast a record until at least one second after it was last multicast — except to answer a probe, which needs only 250 ms | RFC 6762 §6 | itest_mdns_063_record_multicast_at_most_once_a_second, itest_mdns_063_announcements_and_corrections_wait_too |
| REQ-MDNS-064 | MUST | Respond only with a positive, non-null answer, or a negative one for a record known not to exist | RFC 6762 §6 | itest_mdns_064_only_positive_or_owned_negative_answers, test_mdns_016_foreign_names_ignored |
| REQ-MDNS-065 | MUST | Answer a query for one of our unique names, for a type the name has no record of, with an NSEC record — an address type for which the interface has no valid address included | RFC 6762 §6, §6.1 | itest_mdns_065_nsec_for_missing_type, itest_mdns6_065_nsec_for_aaaa_without_an_address, test_mdns_019_nsec_for_missing_type |
| REQ-MDNS-066 | MUST NOT | Send NXDOMAIN or any other error response for shared records | RFC 6762 §6 | itest_mdns_066_no_negative_answer_for_shared_records |
| REQ-MDNS-067 | MUST | Generate NSEC records in the restricted form (Next Domain Name = the record's own name, one bitmap block 0 of length 1–32) without the NSEC bit set in the bitmap | RFC 6762 §6.1 | itest_mdns_067_nsec_restricted_form, itest_mdns6_029_known_aaaa_and_the_nsec_of_both_families, test_mdns_019_nsec_for_missing_type |
| REQ-MDNS-068 | MUST | Generate negative responses only for names, types and classes we own: no NSEC for other hosts' names, for shared records, or while probing | RFC 6762 §6.1 | itest_mdns_068_negative_answers_only_for_owned_names, itest_mdns_021_answers_only_once_probing_is_over |
| REQ-MDNS-069 | MUST NOT | Ignore a whole message because it contains an NSEC record that cannot be parsed | RFC 6762 §6.1 | itest_mdns_069_unparseable_nsec_does_not_hide_the_message |
| REQ-MDNS-070 | MUST NOT | Put questions in multicast responses; questions in received responses are silently ignored | RFC 6762 §6 | itest_mdns_046_header_bits_on_transmission, itest_mdns_070_questions_in_responses_ignored |
| REQ-MDNS-071 | MUST | Send responses from port 5353 to port 5353 of 224.0.0.251 / ff02::fb — unicast only to a QU question, a legacy query (to its port) or a direct unicast query | RFC 6762 §6 | itest_mdns_071_response_destinations, itest_mdns6_039_answered_on_the_family_that_asked |
| REQ-MDNS-072 | MUST | Match questions of qtype ANY (255) and qclass ANY (255) by the standard rules, and answer them with all matching records | RFC 6762 §6, §6.5 | itest_mdns_072_any_type_and_class, test_mdns_018_any_query |
| REQ-MDNS-073 | MUST | Handle queries with more than one question, answering any or all of those we have answers to | RFC 6762 §6.3 | itest_mdns_073_several_questions |
| REQ-MDNS-074 | MUST | Address records carry all the addresses valid on the interface and no other | RFC 6762 §6.2 | itest_mdns_074_only_valid_ipv4_addresses, itest_mdns6_074_aaaa_only_for_usable_addresses |
| REQ-MDNS-075 | MUST | When another host multicasts one of our records with identical rdata and a TTL below half of ours — a goodbye (TTL 0) included — multicast our record | RFC 6762 §6.6 | itest_mdns_075_low_ttl_copy_of_our_record_corrected, itest_mdns_063_announcements_and_corrections_wait_too |
| REQ-MDNS-076 | MUST NOT | Set the cache-flush bit in legacy unicast responses | RFC 6762 §6.7, §10.2 | itest_mdns_076_no_cache_flush_in_legacy_responses, itest_mdns6_028_unicast_and_legacy_answers_over_ipv6, test_mdns_014_legacy_unicast |
| REQ-MDNS-077 | MUST | Known answers that follow a truncated query delete an owed answer only if they come from the querying host and no other host has asked for that answer too | RFC 6762 §7.2 | itest_mdns_077_known_answers_only_from_the_querier |
| REQ-MDNS-078 | MUST | Set the cache-flush bit on every unique record in a response, never on a shared record | RFC 6762 §10.2 | itest_mdns_078_cache_flush_on_unique_records_only, test_mdns_001_hostname_a_query |
| REQ-MDNS-079 | MUST | A response with some members of a unique RRSet carries the whole RRSet | RFC 6762 §10.2 | itest_mdns_079_whole_unique_rrset |

### Goodbye Packets (Record Withdrawal)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-032 | SHOULD | When a record is withdrawn (`mdns_stop()`, `mdns_withdraw()`), send a goodbye: the record with TTL 0 | RFC 6762 §10.1 | itest_mdns_033_goodbye_includes_the_meta_query_ptr, itest_dnssd_018_withdraw_one_service, itest_mdns_032_goodbye_only_for_what_was_announced, itest_mdns6_032_goodbye_on_both_families, test_mdns_008_goodbye_on_shutdown |
| REQ-MDNS-033 | SHOULD | Send a goodbye for each withdrawn record that was sent (announced or answered) — none for a record never sent | RFC 6762 §10.1 | itest_mdns_033_goodbye_includes_the_meta_query_ptr, itest_mdns_032_goodbye_only_for_what_was_announced, itest_mdns6_032_goodbye_on_both_families, test_mdns_008_goodbye_on_shutdown |

### Querier (not implemented)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-034 | SHOULD | Support sending mDNS queries to resolve `.local.` names (querier mode) | RFC 6762 §5 | — (not implemented) |
| REQ-MDNS-035 | SHOULD | Initial query sent once; if no response within 1 s, retransmit with exponential backoff (1 s, 2 s, 4 s, max 60 s) | RFC 6762 §5.2 | — (not implemented) |
| REQ-MDNS-036 | SHOULD | Cache resolved records for the duration of their TTL | RFC 6762 §12 | — (not implemented) |
| REQ-MDNS-037 | MUST | Application-provided cache buffer (no malloc) | Architecture | — (not implemented) |

### IPv6 Support

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-038 | SHOULD | Join the IPv6 multicast group ff02::fb on the interface (IPv6 builds) | RFC 6762 §20 | itest_mdns6_038_both_groups_probed_and_announced, test_mdns_020_aaaa_over_ipv6 |
| REQ-MDNS-039 | SHOULD | Probe, announce and say goodbye over both IPv4 and IPv6 when both are compiled in, and answer on the family a query came over | RFC 6762 §20 | itest_mdns6_038_both_groups_probed_and_announced, itest_mdns6_039_answered_on_the_family_that_asked, itest_mdns6_032_goodbye_on_both_families, test_mdns_020_aaaa_over_ipv6, test_mdns_021_announced_over_ipv6 |

### Interoperability

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-040 | MUST | Respond correctly to the queries of the mDNS implementations of macOS and iOS (mDNSResponder), Linux (Avahi) and Android: QU and QM questions, several questions in a message, known answers.  `tests/blackbox/mdns_interop.sh` (Avahi, in CI) and `mdns_interop_macos.sh` (mDNSResponder) run the real resolvers against the responder; nothing runs against iOS or Android | Interoperability | itest_dnssd_026_browse_and_resolve_as_resolvers_ask |
| REQ-MDNS-041 | MUST | Answer legacy unicast queries (source port ≠ 5353) by unicast to the querier's port, repeating its ID and question, with TTL ≤ 10 s; never crash on unexpected IDs or malformed messages | RFC 6762 §6.7 | itest_mdns_041_legacy_unicast_query_answered, itest_mdns_041_malformed_messages_ignored, itest_mdns_041_malformed_names_ignored, itest_mdns6_028_unicast_and_legacy_answers_over_ipv6, test_mdns_014_legacy_unicast |

### Buffer and Size

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-MDNS-042 | MUST | An mDNS message fits one frame — the TX frame buffer, at most the interface MTU: a record set too large for one message is split across several, and no IP fragments are sent | RFC 6762 §17, §8.3 | itest_dnssd_029_record_too_big_for_any_packet_refused, itest_mdns_042_records_split_across_packets, itest_dnssd_007_additionals_as_far_as_they_fit |
| REQ-MDNS-043 | MUST | Compress names to reduce message size (RFC 6762 §18.14 recommends it) — except the target of an SRV record in a legacy unicast response, which MUST NOT be compressed | RFC 1035 §4.1.4, RFC 6762 §18.14 | itest_mdns_043_legacy_srv_target_uncompressed, itest_mdns_043_names_compressed |

## Notes

- **No DNS server needed:** mDNS operates entirely on the local link — no configuration, no server, no DHCP dependency.
- **Hostname convention:** By default, the device should use a `<product>-<last4mac>.local` hostname to avoid conflicts (e.g., `pyro-dead01.local`).
- **Wire code shared with DNS:** The mDNS wire format is that of DNS (RFC 1035); `dns_wire.c` holds it apart from the responder, for a DNS stub resolver to use.
- **pyro_fw integration:** mDNS is required so that pyro_fw devices can be discovered on the local network without a pre-configured IP.  DNS-SD (RFC 6763) builds on top of mDNS to advertise the service type — see `docs/requirements/dns-sd.md`.
- **Avahi/Bonjour compatibility:** On Linux the reference implementation is Avahi; on macOS/iOS it is Bonjour (mDNSResponder).  Both must be able to resolve the device's `.local` hostname and browse its services.
