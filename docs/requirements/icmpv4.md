# ICMPv4 Requirements

**Protocol:** Internet Control Message Protocol (v4)  
**Primary RFC:** RFC 792 — Internet Control Message Protocol  
**Supporting:** RFC 1122 — Requirements for Internet Hosts (§3.2.2), RFC 6633 (Source Quench deprecated), RFC 1191 (next-hop MTU)  
**Scope:** IPv4 host: Echo Reply, errors sent (Destination Unreachable codes 2 and 3, Time Exceeded code 1), errors received passed to UDP and TCP

## Overview

ICMPv4 provides error reporting and diagnostic functions for IPv4. It is encapsulated directly in IPv4 (Protocol = 1). The stack answers Echo Requests, reports datagrams it cannot deliver (unknown protocol, closed UDP port, reassembly timed out), and passes the errors it receives about its own datagrams to UDP and TCP. It has no ping client, and it ignores every other message type.

## Header Format

```
Offset  Size  Field
  0      1    Type
  1      1    Code
  2      2    Checksum
  4      4    Type-specific data (varies)
  8+     var  Message body (varies)
```

Minimum: 8 bytes (header only, no additional data).

## ICMP Message Types

| Type | Code | Name | Direction |
|---|---|---|---|
| 0 | 0 | Echo Reply | Outbound (response to ping); inbound: ignored |
| 3 | 0-15 | Destination Unreachable | Inbound (to the transport) / Outbound (codes 2 and 3) |
| 4 | 0 | Source Quench (deprecated) | Inbound (ignored) |
| 5 | 0-3 | Redirect | Inbound (ignored) |
| 8 | 0 | Echo Request | Inbound (ping) |
| 11 | 0-1 | Time Exceeded | Inbound (to the transport) / Outbound (code 1) |
| 12 | 0-1 | Parameter Problem | Inbound (to the transport) |
| any other | | | Inbound (ignored) |

## Requirements

### Echo (Ping) — Request and Reply

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-001 | MUST | Respond to Echo Request (Type 8, Code 0) with Echo Reply (Type 0, Code 0) | RFC 792, RFC 1122 §3.2.2.6 | itest_icmpv4_001_echo_reply_code_zero, test_icmp_001_ping_reply |
| REQ-ICMPv4-002 | MUST | Echo Reply MUST contain the same Identifier and Sequence Number as the Echo Request | RFC 792, RFC 1122 §3.2.2.6 | itest_icmpv4_001_echo_reply_code_zero, test_icmp_002_id_seq_preserved |
| REQ-ICMPv4-003 | MUST | Echo Reply MUST contain the same data as the Echo Request | RFC 792, RFC 1122 §3.2.2.6 | itest_icmpv4_001_echo_reply_code_zero, test_icmp_003_data_preserved |
| REQ-ICMPv4-004 | MUST | Echo Reply Source Address MUST be the specific-destination address of the Echo Request: our IP address | RFC 792, RFC 1122 §3.2.2.6 | itest_icmpv4_001_echo_reply_code_zero |
| REQ-ICMPv4-005 | MUST | Echo Reply Destination Address MUST be the Source Address of the Echo Request — and no reply goes to a source that names no single host, 0.0.0.0 included (REQ-IPv4-070) | RFC 792, RFC 1122 §3.2.1.3 | itest_ipv4_070_never_to_or_from_unspecified, itest_icmpv4_001_echo_reply_code_zero |
| REQ-ICMPv4-006 | MUST | Compute correct ICMP checksum for Echo Reply | RFC 792 | itest_icmpv4_001_echo_reply_code_zero, test_icmp_004_reply_checksum_valid |
| REQ-ICMPv4-007 | SHOULD | Build the Echo Reply in the TX buffer from the request in the RX buffer — one copy of the message, the Type changed, both checksums computed in full; the received frame is not modified | Architecture | itest_icmpv4_001_echo_reply_code_zero |
| REQ-ICMPv4-008 | MUST | Include all the Echo Request's data in the Echo Reply; if the reply would not fit one frame (the TX buffer or the MTU), truncate it to what fits and send it | RFC 1122 §3.2.2.6 | itest_icmpv4_008_large_echo_truncated |
| REQ-ICMPv4-009 | MAY | Silently discard an Echo Request sent to a broadcast or multicast address: the stack answers none | RFC 1122 §3.2.2.6 | itest_icmpv4_009_no_echo_reply_to_many, test_icmp_006_broadcast_ping_silent |
| REQ-ICMPv4-010 | SHOULD | Provide an application-layer interface for sending an Echo Request and receiving the Echo Reply — **deviation:** there is no ping client; an Echo Reply received is discarded | RFC 1122 §3.2.2.6 | itest_icmpv4_040_unknown_types_discarded |

### Destination Unreachable (Type 3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-011 | MUST | Process received Destination Unreachable messages | RFC 792, RFC 1122 §3.2.2.1 | itest_udp_038_port_unreachable_reported, itest_icmpv4_014_unreachable_codes_reported |
| REQ-ICMPv4-012 | MUST | Take the original IP header and all the octets of the original datagram the error quotes, and pass them up; an error whose quote is not a whole IPv4 header (version 4, a header length of at least 5 words, all of it present) is discarded | RFC 792, RFC 1122 §3.4 | itest_udp_038_port_unreachable_reported, itest_icmpv4_012_quote_must_be_an_ip_header |
| REQ-ICMPv4-013 | MUST | Pass Destination Unreachable to upper layer (TCP/UDP) for connection error handling | RFC 1122 §3.2.2.1 | itest_tcp_135_unreachable_in_syn_sent, itest_icmpv4_014_unreachable_codes_reported |
| REQ-ICMPv4-014 | MUST | Code 2 (Protocol Unreachable): report to upper layer | RFC 792, RFC 1122 §3.2.2.1 | itest_icmpv4_014_unreachable_codes_reported |
| REQ-ICMPv4-015 | MUST | Code 3 (Port Unreachable): report to upper layer | RFC 792, RFC 1122 §3.2.2.1 | itest_udp_038_port_unreachable_reported, itest_icmpv4_014_unreachable_codes_reported |
| REQ-ICMPv4-016 | MUST | Code 4 (Fragmentation Needed + DF Set): report to upper layer with Next-Hop MTU | RFC 792, RFC 1122 §3.2.2.1, RFC 1191 | itest_tcp_135_fragmentation_needed_lowers_mss |
| REQ-ICMPv4-042 | MUST | Demultiplex a received error to the transport protocol the quoted header names | RFC 1122 §3.2.2 | itest_udp_038_port_unreachable_reported, itest_icmpv4_012_quote_must_be_an_ip_header |
| REQ-ICMPv4-043 | MUST | The header and data an error quotes are unchanged from the datagram received | RFC 1122 §3.2.2 | itest_icmpv4_043_quote_unchanged |
| REQ-ICMPv4-044 | MUST | Treat Destination Unreachable only as a hint, never as proof — and never as proof of a dead gateway | RFC 1122 §3.2.2.1 | itest_tcp_136_soft_errors_do_not_abort |
| REQ-ICMPv4-017 | SHOULD | Generate Destination Unreachable Code 2 (Protocol Unreachable) for unsupported IP protocols | RFC 1122 §3.2.2.1 | itest_ipv4_021_unknown_protocol_unreachable, test_ipv4_003_unknown_proto_icmp_unreachable |
| REQ-ICMPv4-018 | SHOULD | Generate Destination Unreachable Code 3 (Port Unreachable) for UDP packets to closed ports | RFC 1122 §3.2.2.1 | itest_icmpv4_018_port_unreachable_to_a_host |

### Redirect (Type 5)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-019 | MUST | Update routing information on a received Redirect — **deviation:** the application chooses next hops (REQ-IPv4-075), so Redirects are ignored | RFC 792, RFC 1122 §3.2.2.2 | itest_icmpv4_019_redirect_ignored |
| REQ-ICMPv4-020 | MUST | Accept both Host and Network Redirects — **deviation:** both are ignored | RFC 1122 §3.2.2.2 | itest_icmpv4_019_redirect_ignored |
| REQ-ICMPv4-021 | SHOULD | Silently discard a Redirect whose new gateway is not on the subnet it arrived through (met: every Redirect is discarded) | RFC 1122 §3.2.2.2 | itest_icmpv4_019_redirect_ignored |
| REQ-ICMPv4-022 | SHOULD | Silently discard a Redirect whose source is not the current first-hop gateway for the destination (met: every Redirect is discarded, and none draws a reply) | RFC 1122 §3.2.2.2 | itest_icmpv4_019_redirect_ignored |
| REQ-ICMPv4-023 | SHOULD NOT | Send an ICMP Redirect (only gateways send Redirects): the stack sends none | RFC 1122 §3.2.2.2 | itest_icmpv4_023_only_host_errors_sent |

### Time Exceeded (Type 11)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-024 | MUST | Process received Time Exceeded messages and pass to upper layer | RFC 792, RFC 1122 §3.2.2.4 | itest_tcp_136_soft_errors_do_not_abort |
| REQ-ICMPv4-025 | MUST | Send Time Exceeded Code 1 (Fragment Reassembly Time Exceeded) when the reassembly timeout discards a datagram whose fragment zero arrived (REQ-IPv4-025) | RFC 792, RFC 1122 §3.3.2 | itest_ipv4_025_reassembly_timeout |
| REQ-ICMPv4-026 | MUST NOT | MUST NOT generate Time Exceeded Code 0 (TTL Exceeded in Transit) — only gateways do; a datagram for us is taken whatever its TTL (REQ-IPv4-044) | RFC 792, RFC 1122 §3.2.1.7 | itest_icmpv4_023_only_host_errors_sent |

### Source Quench (Type 4) — Deprecated

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-027 | MUST NOT | MUST NOT generate Source Quench messages | RFC 6633 §3 (updates RFC 1122 §3.2.2.3) | itest_icmpv4_023_only_host_errors_sent |
| REQ-ICMPv4-028 | MUST | Silently discard received Source Quench messages | RFC 6633 §3, §5, §8 | itest_icmpv4_028_source_quench_changes_nothing, itest_udp_038_errors_of_every_kind_reported |

**Note:** RFC 6633 updates RFC 1122 §3.2.2.3 — Source Quench is deprecated and MUST NOT be generated. The IP layer may discard a received Source Quench, and UDP and TCP must; the stack discards it in ICMP.

### Parameter Problem (Type 12)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-029 | MUST | Process received Parameter Problem messages and pass to upper layer | RFC 792, RFC 1122 §3.2.2.5 | itest_udp_038_errors_of_every_kind_reported |
| REQ-ICMPv4-030 | SHOULD | Generate Parameter Problem for received packets with erroneous headers — **deviation:** none is sent: a datagram with a header error is discarded silently (REQ-IPv4-006), and options are not interpreted | RFC 792, RFC 1122 §3.2.2.5 | itest_icmpv4_023_only_host_errors_sent |

### Checksum

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-031 | MUST | Verify ICMP checksum on all received ICMP messages; discard on failure | RFC 792 | itest_icmpv4_031_bad_checksum_discarded, test_icmp_005_bad_checksum_silently_dropped |
| REQ-ICMPv4-032 | MUST | Compute correct ICMP checksum on all transmitted ICMP messages | RFC 792 | itest_icmpv4_001_echo_reply_code_zero, test_icmp_004_reply_checksum_valid |
| REQ-ICMPv4-033 | MUST | ICMP checksum covers Type + Code + Checksum + type-specific header + data | RFC 792 | itest_icmpv4_001_echo_reply_code_zero, itest_icmpv4_031_bad_checksum_discarded |

### ICMP Error Message Rules

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-034 | MUST NOT | MUST NOT send ICMP error in response to an ICMP error message | RFC 792, RFC 1122 §3.2.2 | itest_icmpv4_034_no_error_about_an_error, test_icmp_007_no_error_for_icmp_error |
| REQ-ICMPv4-035 | MUST NOT | MUST NOT send ICMP error in response to a datagram sent to an IP broadcast or multicast address, or in a link-layer broadcast or multicast frame | RFC 1122 §3.2.2 | itest_icmpv4_035_036_no_error_about_broadcasts_or_unspecified, itest_eth_022_link_broadcast_draws_no_error |
| REQ-ICMPv4-036 | MUST NOT | MUST NOT send ICMP error in response to a packet whose source names no single host (0.0.0.0, loopback, broadcast, multicast, class E) | RFC 1122 §3.2.2 | itest_icmpv4_035_036_no_error_about_broadcasts_or_unspecified |
| REQ-ICMPv4-037 | MUST NOT | MUST NOT send ICMP error in response to a non-initial fragment (offset ≠ 0): fragments draw no error; a reassembled datagram's error quotes fragment zero | RFC 1122 §3.2.2 | itest_icmpv4_037_no_error_about_a_fragment |
| REQ-ICMPv4-038 | MUST | ICMP error body MUST include original IP header + first 8 bytes of original datagram payload | RFC 792, RFC 1122 §3.2.2 | itest_icmpv4_043_quote_unchanged, itest_icmpv4_018_port_unreachable_to_a_host |
| REQ-ICMPv4-039 | MAY | Rate-limit ICMP error message generation — not implemented: every datagram that may draw an error draws one | Architecture (RFC 1812 §4.3.2.8 asks it of routers) | — |

### General

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ICMPv4-040 | MUST | Silently discard ICMP messages with unknown Type | RFC 1122 §3.2.2 | itest_icmpv4_040_unknown_types_discarded |
| REQ-ICMPv4-041 | MUST | Parse ICMP messages in-place (zero-copy) | Architecture | itest_icmpv4_041_error_parsed_in_place |
| REQ-ICMPv4-045 | MUST | Silently ignore received Address Mask Replies, and send none (the host is no address-mask agent) | RFC 1122 §3.2.2.9 | itest_icmpv4_045_address_mask_ignored |
| REQ-ICMPv4-046 | MUST | Return ICMP errors where practical: Protocol Unreachable and Port Unreachable (REQ-ICMPv4-017, 018); header errors are discarded silently, as REQ-IPv4-005/006 require | RFC 1122 §3.3.8 | itest_ipv4_021_unknown_protocol_unreachable |
| REQ-ICMPv4-047 | MUST | Send the unused fields of ICMP messages as zero | RFC 792 | itest_icmpv4_043_quote_unchanged |
| REQ-ICMPv4-048 | MUST NOT | Implement the Source Quench Introduced Delay of RFC 1016: nothing reacts to a Source Quench (REQ-ICMPv4-028) | RFC 6633 §7 | itest_icmpv4_028_source_quench_changes_nothing |

## Notes

- **Echo replies** are built in the TX buffer: the request's ICMP message is copied there, its Type set to 0, and the ICMP and IP header checksums computed in full; `icmp_send()` is shared with the error messages. A request larger than one frame carries is answered truncated (REQ-ICMPv4-008).
- **ICMP as error channel:** an error that quotes a datagram of ours goes to the transport its quoted header names: to the application's handler for UDP (`udp_set_error_handler()`), to the connection for TCP.
- **No rate limiting:** neither Echo Replies nor error messages are rate-limited (REQ-ICMPv4-039).
- **Not implemented:** a ping client, Timestamp, Information Request and Address Mask messages, Redirect processing (REQ-ICMPv4-019), Parameter Problem generation.
