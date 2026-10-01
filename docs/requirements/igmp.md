# IGMP Requirements

**Protocol:** Internet Group Management Protocol, version 2 (host side)
**Primary RFC:** RFC 2236 — Internet Group Management Protocol, Version 2
**Supporting:** RFC 1112 — Host Extensions for IP Multicasting, RFC 1122 §3.3.7
**Scope:** V1 (IPv4), built with the multicast group table (`NET_MAX_MCAST_GROUPS` ≥ 1)
**Last updated:** 2026-10-01

## Overview

A host that receives IP multicast tells the routers on its link which groups
it belongs to.  This stack joins groups for its applications (mDNS joins
224.0.0.251), reports them, answers the routers' queries and leaves them.
RFC 1122 §3.3.7 makes IGMP optional for a host, but a host that implements
it follows RFC 2236; the requirements below are what RFC 2236 asks of a
host.  RFC 2236 states its host behaviour mostly in prose without RFC 2119
keywords ("When a host receives a General Query, it sets delay timers…");
those rules are rows here at MUST, as the protocol does not work without
them.

## Requirements

### Messages

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IGMP-001 | MUST | Compute the IGMP checksum over the whole IGMP message on sending | RFC 2236 §2.3 | itest_igmp_001_report_format |
| REQ-IGMP-002 | MUST | Verify the checksum of a received IGMP message before processing it; drop it if wrong | RFC 2236 §2.3, §6 | itest_igmp_002_bad_checksum_ignored |
| REQ-IGMP-003 | MUST | Send IGMP messages with IP TTL 1 and the Router Alert option | RFC 2236 §2 | itest_igmp_001_report_format |
| REQ-IGMP-004 | MUST | Ignore anything past the first 8 octets of a message of a known type (an IGMPv3 query is taken as a v2 query) | RFC 2236 §2.5 | itest_igmp_004_longer_query_answered |
| REQ-IGMP-005 | MUST | Take only valid queries: at least 8 octets, a correct checksum, a group address of 0 (General) or a multicast group (Group-Specific) | RFC 2236 §6 | itest_igmp_002_bad_checksum_ignored |

### Joining and leaving

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IGMP-006 | SHOULD | On joining a group, send an unsolicited Membership Report at once, and repeat it | RFC 2236 §3 | itest_igmp_001_report_format |
| REQ-IGMP-007 | MUST | Send Leave Group to the all-routers group 224.0.0.2 | RFC 2236 §3, §9 | itest_igmp_007_leave_to_all_routers |
| REQ-IGMP-008 | MUST NOT | Report membership of the all-systems group 224.0.0.1 | RFC 2236 §3, §6 | itest_igmp_009_general_query_answered, itest_igmp_008_all_hosts_never_reported |

### Answering queries

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IGMP-009 | MUST | On a General Query, start a delay timer for every group the host belongs to (all-systems excepted), at a random value in (0, Max Response Time]; on a Group-Specific Query, for that group; when a timer expires, multicast a Membership Report for its group with TTL 1 | RFC 2236 §3, §6 | itest_igmp_009_general_query_answered |
| REQ-IGMP-010 | MUST | Reset a running timer to a new random value only if the query's Max Response Time is less than the time it has left | RFC 2236 §3 | itest_igmp_010_shorter_query_resets_timer |
| REQ-IGMP-011 | MUST | Stop the timer and send no Report when another host's Report (version 1 or 2) for the group is heard while it runs | RFC 2236 §3, §5 | itest_igmp_011_report_suppressed |

### IGMPv1 routers

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IGMP-012 | MUST | Interpret a query's Max Response Time of 0 (an IGMPv1 query) as 100 (10 s) | RFC 2236 §4 | itest_igmp_012_v1_querier |
| REQ-IGMP-013 | MUST | Keep the state "an IGMPv1 querier was heard in the last 400 s" (the Version 1 Router Present Timeout), based on v1 queries heard, not on the type of the last query | RFC 2236 §4, §8.11 | itest_igmp_012_v1_querier, itest_igmp_013_v1_state_outlasts_a_v2_query |
| REQ-IGMP-014 | MUST | While that state holds, send Version 1 Membership Reports, solicited and unsolicited, and no IGMPv2 message (Leave Group included) | RFC 2236 §4, §8.11 | itest_igmp_012_v1_querier |

## Notes

- **All-hosts group:** the host belongs to 224.0.0.1 whenever it has a
  multicast group table (REQ-IPv4-050), so it receives General Queries; it
  never reports that group.
- **One interface:** the state of REQ-IGMP-013 is kept per `net_t`.
- **Timers** run from `net_tick()`; the random delays come from
  `net_random_below()` (no division).
