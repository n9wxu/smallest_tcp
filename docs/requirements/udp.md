# UDP Requirements

**Protocol:** User Datagram Protocol  
**Primary RFC:** RFC 768 — User Datagram Protocol  
**Supporting:** RFC 1122 — Requirements for Internet Hosts (§4.1), RFC 8200 §8.1 (IPv6 UDP checksum)  
**Scope:** IPv4 and IPv6 (the checksum rules differ)

## Overview

UDP provides a simple, connectionless, unreliable datagram service. It adds port-based multiplexing and an optional (IPv4) or mandatory (IPv6) checksum on top of IP. UDP is used by DHCP, mDNS, TFTP, DTLS and other protocols.

## Header Format

```
Offset  Size  Field
  0      2    Source Port
  2      2    Destination Port
  4      2    Length (header + data, minimum 8)
  6      2    Checksum
  8+     var  Data
```

Minimum: 8 bytes (header only, zero-length data).

## Requirements

### Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-001 | MUST | Parse UDP header at IP payload offset | RFC 768 | itest_udp_016_dispatched_by_destination_port, test_udp_001_echo_data_returned |
| REQ-UDP-002 | MUST | Verify UDP Length ≥ 8 | RFC 768 | itest_udp_002_length_below_header_dropped, test_udp_007_length_too_small_silently_dropped |
| REQ-UDP-003 | MUST | Verify UDP Length ≤ IP payload length | RFC 768 | itest_udp_003_length_beyond_ip_payload_dropped |
| REQ-UDP-004 | MUST | Use UDP Length (not IP payload length) to determine data length | RFC 768 | itest_udp_004_length_field_bounds_the_data |
| REQ-UDP-005 | MUST | Silently discard datagrams with invalid length | RFC 768 | itest_udp_002_length_below_header_dropped, itest_udp_003_length_beyond_ip_payload_dropped, test_udp_007_length_too_small_silently_dropped |

### Checksum — IPv4

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-006 | MUST | If received UDP checksum ≠ 0, verify checksum over pseudo-header + header + data | RFC 768, RFC 1122 §4.1.3.4 | itest_udp_006_bad_checksum_dropped, test_udp_005_bad_checksum_silently_dropped |
| REQ-UDP-007 | MUST | Silently discard datagrams with checksum mismatch (when checksum is non-zero) | RFC 1122 §4.1.3.4 | itest_udp_006_bad_checksum_dropped, test_udp_005_bad_checksum_silently_dropped |
| REQ-UDP-008 | MUST | If received UDP checksum = 0 over IPv4, accept without verification (checksum was not computed) | RFC 768 | itest_udp_008_zero_checksum_accepted, test_udp_006_zero_checksum_accepted |
| REQ-UDP-009 | MUST | Compute and include UDP checksum on transmitted IPv4 datagrams (RFC 1122: "MUST default to checksumming on"); a computed 0 is sent as 0xFFFF | RFC 768, RFC 1122 §4.1.3.4 | itest_udp_009_datagram_sent, itest_udp_032_one_ethernet_frame_at_most |
| REQ-UDP-010 | MAY | Transmit with checksum = 0 over IPv4 (no checksum) if application explicitly requests | RFC 768, RFC 1122 §4.1.3.4 | — (not implemented: every datagram is checksummed) |

### Checksum — IPv6

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-011 | MUST | Compute and include UDP checksum on all transmitted IPv6 datagrams (checksum MUST NOT be zero) | RFC 8200 §8.1 | itest_udp_011_ipv6_checksum_sent |
| REQ-UDP-012 | MUST | Verify UDP checksum on all received IPv6 datagrams | RFC 8200 §8.1 | itest_udp_012_ipv6_checksum_verified |
| REQ-UDP-013 | MUST | Silently discard IPv6 UDP datagrams with checksum = 0 | RFC 8200 §8.1 | itest_udp_012_ipv6_checksum_verified |

### Checksum — Pseudo-Header

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-014 | MUST | IPv4 pseudo-header for checksum: src IP (4) + dst IP (4) + zero (1) + protocol 17 (1) + UDP length (2) | RFC 768 | itest_udp_009_datagram_sent, itest_udp_032_one_ethernet_frame_at_most |
| REQ-UDP-015 | MUST | IPv6 pseudo-header for checksum: src IP (16) + dst IP (16) + UDP length (4) + zeros (3) + next header 17 (1) | RFC 8200 §8.1 | itest_udp_011_ipv6_checksum_sent, itest_udp_012_ipv6_checksum_verified |

### Port Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-016 | MUST | Dispatch received datagrams by Destination Port to registered handler | RFC 768 | itest_udp_016_dispatched_by_destination_port, test_udp_001_echo_data_returned |
| REQ-UDP-017 | SHOULD | If no handler registered for Destination Port, generate ICMP Port Unreachable (Type 3, Code 3) | RFC 1122 §4.1.3.1 | itest_icmpv4_018_port_unreachable_to_a_host, itest_udp_031_no_port_unreachable_for_broadcast, test_udp_003_unknown_port_icmp_unreachable |
| REQ-UDP-018 | MUST | Port handlers come from a table the application provides (`udp_set_ports()`); nothing is registered inside the stack | Architecture | itest_udp_016_dispatched_by_destination_port |
| REQ-UDP-019 | MUST | Support simultaneous handlers on multiple ports | Architecture | itest_udp_016_dispatched_by_destination_port |
| REQ-UDP-020 | MUST | Provide Source Port and Source IP to handler callback | RFC 768 | itest_udp_016_dispatched_by_destination_port, test_udp_002_echo_ports_swapped |

### Transmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-021 | MUST | Build UDP header with Source Port, Destination Port, Length, Checksum | RFC 768 | itest_udp_009_datagram_sent, test_udp_002_echo_ports_swapped |
| REQ-UDP-022 | MUST | UDP Length = 8 + data length | RFC 768 | itest_udp_009_datagram_sent |
| REQ-UDP-023 | MUST | Pass assembled datagram to IP layer for header building and transmission | RFC 768 | itest_udp_009_datagram_sent |
| REQ-UDP-024 | MAY | Source Port is optional: 0 when it is not used | RFC 768 | itest_udp_009_datagram_sent |

### Address Resolution Integration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-025 | MUST | Send to the next hop: the destination itself on the subnet, the gateway otherwise (`arp_next_hop()`); UDP sends to the MAC its caller resolved — the stack keeps no ARP cache ([arp-resolution.md](../design/arp-resolution.md)) | RFC 1122 §3.3.1.1, Architecture | itest_udp_025_next_hop |
| REQ-UDP-026 | MAY | Support `udp_peer_t` structure that caches resolved MAC for persistent UDP associations | Architecture | — (not implemented) |
| REQ-UDP-027 | MAY | In "gateway-only" mode, always use gateway MAC regardless of destination | Architecture | — (not implemented) |

### Broadcast and Multicast

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-028 | MUST | Support receiving UDP datagrams sent to broadcast IP | RFC 1122 §3.3.6 | itest_udp_028_broadcast_received |
| REQ-UDP-029 | MUST | Support sending UDP datagrams to broadcast IP (255.255.255.255) | RFC 1122 §3.3.6, Architecture (DHCP) | itest_udp_029_broadcast_sent |
| REQ-UDP-030 | SHOULD | When sending to broadcast, use broadcast MAC (FF:FF:FF:FF:FF:FF) — **deviation:** the caller supplies the MAC (`arp_next_hop()` names a broadcast as its own next hop); UDP refuses the broadcast MAC for a destination that is no broadcast or group (RFC 1122 §3.3.6), but sends a broadcast to whatever MAC it is given | RFC 894 | itest_udp_029_broadcast_sent |
| REQ-UDP-031 | MUST NOT | MUST NOT generate ICMP Port Unreachable for UDP datagrams received via broadcast/multicast | RFC 1122 §3.2.2 | itest_udp_031_no_port_unreachable_for_broadcast |

### Buffer and Size Limits

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-032 | MUST | Maximum UDP payload = tx buffer capacity - ETH header (14) - IP header (20) - UDP header (8), and at most the Ethernet MTU less the IP and UDP headers (1472; 1452 over IPv6): nothing is fragmented | Architecture, RFC 1122 §3.3.3 | itest_udp_032_one_ethernet_frame_at_most, itest_udp_032_frame_buffer_limit |
| REQ-UDP-033 | MUST | Reject application send requests that exceed maximum UDP payload for the buffer | Architecture | itest_udp_032_one_ethernet_frame_at_most |
| REQ-UDP-034 | MUST | If received datagram data exceeds rx buffer capacity, truncate or discard (implementation choice): it is discarded | Architecture | itest_udp_034_datagram_beyond_rx_buffer_dropped |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-035 | MUST | Parse UDP header in-place in application buffer | Architecture | itest_udp_016_dispatched_by_destination_port |
| REQ-UDP-036 | MUST | Build UDP header in-place in application buffer | Architecture | itest_udp_036_built_in_place |
| REQ-UDP-037 | MUST | Handler callback receives pointer to payload data in rx buffer (no copy) | Architecture | itest_udp_016_dispatched_by_destination_port |

### ICMP Integration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-038 | MUST | Process ICMP Destination Unreachable directed at a UDP flow (match by port + IP from ICMP error body) | RFC 1122 §4.1.3.3 | itest_udp_038_port_unreachable_reported, itest_udp_038_only_our_datagrams_errors |
| REQ-UDP-039 | MUST | Pass every ICMP error message received about a UDP datagram up to the application (`udp_set_error_handler()`) — **not met over IPv6:** ICMPv6 errors do not reach UDP: there is no IPv6 error handler, and `icmpv6_input()` passes on only those that quote TCP (REQ-ICMPv6-011, 015, 022) | RFC 1122 §4.1.3.3 | itest_udp_038_errors_of_every_kind_reported |

### Application Interface

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-UDP-040 | MUST | Pass the specific destination address of a received datagram up to the application (`udp_rx_dst_ip()` in a handler) | RFC 1122 §4.1.3.5 | itest_udp_040_destination_address_passed_up |
| REQ-UDP-041 | MUST | Let the application choose the source address of a datagram or leave it unspecified (`udp_send_inplace_from()`, `udp_send()`); the source must be one of the host's addresses — or 0.0.0.0 while it acquires one | RFC 1122 §4.1.3.5, §4.1.3.6 | itest_udp_041_source_must_be_ours |
| REQ-UDP-042 | MUST | Pass IP options through, both ways — **deviation:** options are neither passed up nor settable (REQ-IPv4-065, 066) | RFC 1122 §4.1.3.2 | itest_udp_042_ip_options_not_passed_up |
| REQ-UDP-043 | MUST | Provide the IP/transport interface: the source address (`net_t.ipv4_addr`), the maximum sizes (`ipv4_mms_s()`, `ipv4_mms_r()`), ICMP messages (REQ-UDP-039) — **deviation:** no ADVISE_DELIVPROB: there is no gateway choice to advise (REQ-IPv4-075) | RFC 1122 §4.1.4, §3.4 | itest_ipv4_063_mms_s |
| REQ-UDP-044 | MUST | Let the application set the TTL and the TOS of a datagram (`udp_send_inplace_opts()`); IP options: REQ-UDP-042 | RFC 1122 §4.1.4 | itest_udp_044_ttl_and_tos, itest_ipv4_041_tos_settable |

## Notes

- **UDP is connectionless:** Each datagram is independent. There is no connection state to manage.
- **DHCP uses UDP:** DHCP operates on ports 67/68 with broadcast. The stack must support receiving UDP on broadcast IP before an address is configured (REQ-IPv4-012).
- **mDNS uses UDP:** port 5353, to and from the group 224.0.0.251 (ff02::fb over IPv6); the responder's handlers are entries of the application's port tables.
- **TFTP uses UDP:** TFTP uses port 69 for initial contact, then ephemeral ports for data transfer.
