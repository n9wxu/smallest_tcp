# ICMPv6 Requirements

**Protocol:** Internet Control Message Protocol for IPv6  
**Primary RFC:** RFC 4443 — Internet Control Message Protocol (ICMPv6) for IPv6 Specification  
**Supporting:** RFC 8200 §4 (IPv6 requires ICMPv6), RFC 8201 (Path MTU Discovery), RFC 4861 (NDP uses ICMPv6), RFC 4862 (SLAAC uses ICMPv6), RFC 3810 (MLDv2 uses ICMPv6)  
**Supersession:** RFC 4443 supersedes RFC 2463  
**Design:** [ipv6.md](../design/ipv6.md) §5

## Overview

ICMPv6 is the control protocol for IPv6, providing error reporting, diagnostics (ping), and serving as the transport for Neighbor Discovery Protocol (NDP). Unlike ICMPv4, ICMPv6 is **mandatory** for all IPv6 nodes. ICMPv6 uses IPv6 Next Header value 58.

## Message Format

```
Offset  Size  Field
  0      1    Type
  1      1    Code
  2      2    Checksum (mandatory, covers pseudo-header + ICMPv6 message)
  4      4    Type-specific data (varies)
  8+     var  Message body (varies)
```

ICMPv6 Types are divided into:
- **Error messages:** Type 1-127 (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem)
- **Informational messages:** Type 128-255 (Echo Request/Reply, NDP messages, MLD messages)

## Requirements

### Checksum (Mandatory for ICMPv6)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-001 | MUST | Compute ICMPv6 checksum over IPv6 pseudo-header + ICMPv6 header + body | RFC 4443 §2.3 | itest_ipv6_024_header_built, itest_ndp_034_router_solicitations |
| REQ-ICMPv6-002 | MUST | Verify checksum on all received ICMPv6 messages; discard on failure | RFC 4443 §2.3 | itest_icmpv6_002_bad_checksum_dropped, itest_ndp_003_checksum_required, test_ipv6_009_echo_bad_checksum_ignored |
| REQ-ICMPv6-003 | MUST | IPv6 pseudo-header for checksum: src (16) + dst (16) + ICMPv6 length (4) + zeros (3) + next header 58 (1) | RFC 8200 §8.1 | itest_ipv6_024_header_built |

### Echo (Ping) — Request and Reply

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-004 | MUST | Respond to Echo Request (Type 128, Code 0) with Echo Reply (Type 129, Code 0) | RFC 4443 §4.1, §4.2 | itest_icmpv6_004_echo_reply, test_ipv6_007_echo |
| REQ-ICMPv6-005 | MUST | Echo Reply MUST contain same Identifier and Sequence Number as request | RFC 4443 §4.2 | itest_icmpv6_004_echo_reply, test_ipv6_007_echo |
| REQ-ICMPv6-006 | MUST | Echo Reply MUST contain same data as request; a request too large to answer in the TX frame buffer is dropped | RFC 4443 §4.2 | itest_icmpv6_004_echo_reply, test_ipv6_007_echo |
| REQ-ICMPv6-007 | MUST | Echo Reply Source Address MUST be our address (unicast address the request was sent to) | RFC 4443 §4.2 | itest_icmpv6_004_echo_reply, test_ipv6_007_echo |
| REQ-ICMPv6-008 | MUST | Echo Reply Destination Address MUST be the Source Address of the request | RFC 4443 §4.2 | itest_icmpv6_004_echo_reply, test_ipv6_007_echo |
| REQ-ICMPv6-009 | MUST | If Echo Request sent to multicast, reply MUST use unicast source | RFC 4443 §4.2 | itest_icmpv6_009_group_echo_answered_from_unicast, test_ipv6_008_echo_to_all_nodes |
| REQ-ICMPv6-010 | MAY | Support sending Echo Requests (ping6 client) | RFC 4443 §4.1 | — (not implemented; an application can build one and send it with `icmpv6_send()`) |

### Destination Unreachable (Type 1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-011 | MUST | Pass a received Destination Unreachable to the upper-layer protocol that sent the quoted packet: TCP (`tcp6_icmp_error()`) or the UDP application's error handler (`udp6_set_error_handler()`) | RFC 4443 §3.1, §2.4(d) | itest_icmpv6_011_errors_reach_tcp, itest_icmpv6_015_port_unreachable_reaches_tcp |
| REQ-ICMPv6-012 | MUST | Code 0: No route to destination — passed up (a soft error for TCP) | RFC 4443 §3.1 | itest_icmpv6_011_errors_reach_tcp |
| REQ-ICMPv6-013 | MUST | Code 1: Communication with destination administratively prohibited — passed up (a soft error for TCP) | RFC 4443 §3.1 | itest_icmpv6_011_errors_reach_tcp |
| REQ-ICMPv6-014 | MUST | Code 3: Address unreachable — passed up (a soft error for TCP) | RFC 4443 §3.1 | itest_icmpv6_011_errors_reach_tcp |
| REQ-ICMPv6-015 | MUST | Code 4: Port unreachable — passed up; TCP aborts the connection | RFC 4443 §3.1 | itest_icmpv6_015_port_unreachable_reaches_tcp |
| REQ-ICMPv6-016 | SHOULD | Generate Destination Unreachable Code 4 for UDP datagrams to closed ports | RFC 4443 §3.1 | itest_icmpv6_016_port_unreachable, test_ipv6_016_udp_closed_port_unreachable |
| REQ-ICMPv6-017 | MUST | Quote as much of the invoking packet as fits without the error exceeding the minimum IPv6 MTU (1280) — and the TX frame buffer, if that is smaller | RFC 4443 §3.1, §2.4(c) | itest_icmpv6_016_port_unreachable, itest_icmpv6_017_quote_fits_the_tx_buffer |

### Packet Too Big (Type 2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-018 | MUST | Process received Packet Too Big messages: pass them to the upper-layer protocol that sent the quoted packet | RFC 4443 §3.2 | itest_icmpv6_018_packet_too_big_lowers_the_segment_size |
| REQ-ICMPv6-019 | MUST | Take the MTU field (bytes 4-7) as the path's MTU | RFC 4443 §3.2, RFC 8201 §4 | itest_icmpv6_018_packet_too_big_lowers_the_segment_size |
| REQ-ICMPv6-020 | MUST | Pass the MTU to the upper layer: TCP lowers the connection's segment size to MTU − 60; a UDP application's error handler gets it | RFC 4443 §3.2, RFC 8201 §5.2 | itest_icmpv6_018_packet_too_big_lowers_the_segment_size |
| REQ-ICMPv6-021 | MUST NOT | MUST NOT generate Packet Too Big (only routers generate this) | RFC 4443 §3.2 | itest_icmpv6_021_no_router_errors |

### Time Exceeded (Type 3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-022 | MUST | Pass a received Time Exceeded to the upper-layer protocol that sent the quoted packet | RFC 4443 §3.3 | itest_icmpv6_011_errors_reach_tcp |
| REQ-ICMPv6-023 | MUST NOT | MUST NOT generate Time Exceeded Code 0 (Hop Limit exceeded) — only routers; a packet for us is processed whatever its Hop Limit | RFC 4443 §3.3, RFC 8200 §3 | itest_icmpv6_021_no_router_errors |
| REQ-ICMPv6-024 | MAY | Generate Time Exceeded Code 1 (Fragment reassembly exceeded) when discarding fragments — not generated: there is no reassembly (REQ-IPv6-022) | RFC 4443 §3.3 | itest_ipv6_022_fragments_dropped |

### Parameter Problem (Type 4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-025 | MUST | Pass a received Parameter Problem to the upper-layer protocol that sent the quoted packet | RFC 4443 §3.4 | itest_icmpv6_011_errors_reach_tcp |
| REQ-ICMPv6-026 | SHOULD | Code 1 (Unrecognized Next Header): generate when a packet's Next Header is unknown | RFC 4443 §3.4, RFC 8200 §4 | itest_ipv6_017_unknown_next_header, test_ipv6_011_unknown_next_header_parameter_problem |
| REQ-ICMPv6-027 | MUST | Pointer field (bytes 4-7) is the offset of the erroneous field in the invoking packet | RFC 4443 §3.4 | itest_ipv6_017_unknown_next_header, test_ipv6_011_unknown_next_header_parameter_problem |

### ICMPv6 Error Message Rules

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-028 | MUST NOT | MUST NOT send ICMPv6 error in response to an ICMPv6 error message or a Redirect | RFC 4443 §2.4(e.1), (e.2) | itest_icmpv6_028_no_error_about_errors |
| REQ-ICMPv6-029 | MUST NOT | MUST NOT send ICMPv6 error in response to a packet sent to an IPv6 multicast address, or as a link-layer multicast or broadcast (exceptions: Packet Too Big, Parameter Problem Code 2 — neither of which the stack sends) | RFC 4443 §2.4(e.3)–(e.5) | itest_icmpv6_029_no_error_about_group_packets |
| REQ-ICMPv6-030 | MUST NOT | MUST NOT send ICMPv6 error in response to a packet with multicast source | RFC 4443 §2.4(e.6) | itest_ipv6_011_multicast_source_dropped |
| REQ-ICMPv6-031 | MUST NOT | MUST NOT send ICMPv6 error in response to a packet with unspecified source (::) | RFC 4443 §2.4(e.6) | itest_ipv6_013_unspecified_source |
| REQ-ICMPv6-032 | MUST | ICMPv6 error body MUST include as much of invoking packet as fits in minimum MTU (1280 bytes) | RFC 4443 §2.4(c) | itest_icmpv6_016_port_unreachable |
| REQ-ICMPv6-033 | MUST | Limit the rate of ICMPv6 errors sent: a token bucket of `ICMPV6_ERROR_BURST` (10) errors, refilled by one every `ICMPV6_ERROR_INTERVAL_MS` (100 ms) | RFC 4443 §2.4(f) | itest_icmpv6_033_errors_rate_limited |

### NDP Messages (Dispatched to NDP)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-034 | MUST | Type 133 (Router Solicitation): a host silently discards it | RFC 4861 §6.1.1 | itest_ndp_034_router_solicitation_received_ignored |
| REQ-ICMPv6-035 | MUST | Dispatch Type 134 (Router Advertisement) to NDP | RFC 4861 §6.3.4 | itest_ndp_039_default_router_learned |
| REQ-ICMPv6-036 | MUST | Dispatch Type 135 (Neighbor Solicitation) to NDP | RFC 4861 §7.2.3 | itest_ndp_011_solicitation_answered |
| REQ-ICMPv6-037 | MUST | Dispatch Type 136 (Neighbor Advertisement) to NDP | RFC 4861 §7.2.5 | itest_ndp_071_advertisement_validated |
| REQ-ICMPv6-038 | MUST | Type 137 (Redirect): given to NDP, which ignores it (REQ-NDP-049) | RFC 4861 §8 | itest_ndp_049_redirect_ignored |

### General

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv6-039 | MUST | Silently discard ICMPv6 informational messages with unknown Type | RFC 4443 §2.4(b) | itest_icmpv6_039_unknown_informational_dropped |
| REQ-ICMPv6-040 | MUST | Pass ICMPv6 error messages of unknown type to the upper-layer protocol that sent the quoted packet | RFC 4443 §2.4(a) | itest_icmpv6_011_errors_reach_tcp |
| REQ-ICMPv6-041 | MUST | Parse ICMPv6 messages in-place (zero-copy) | Architecture | — (not observable: nothing an echo reply or an error shows tells where the message was parsed) |

## Notes

- **ICMPv6 is mandatory for IPv6.** Unlike ICMPv4 which is practically required, ICMPv6 is an absolute requirement — NDP (address resolution, router discovery) cannot function without it.
- **NDP runs over ICMPv6.** Types 133-137 are NDP messages. The ICMPv6 layer validates the checksum and dispatches to the NDP handler.
- **MLD (Multicast Listener Discovery)** runs over ICMPv6 too: Types 130-132 and 143 go to `mld_input()`; the stack reports its solicited-node groups and the groups joined with `ipv6_mcast_join()` ([ipv6.md](../design/ipv6.md) §9).
- **Error message size:** an ICMPv6 error includes as much of the invoking packet as fits without the error exceeding 1280 bytes in all.
