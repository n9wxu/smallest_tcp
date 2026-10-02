# IPv6 Requirements

**Protocol:** Internet Protocol version 6  
**Primary RFC:** RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification  
**Supporting:** RFC 4291 — IP Version 6 Addressing Architecture, RFC 6724 — Default Address Selection for IPv6, RFC 4443 — ICMPv6, RFC 2464 — IPv6 over Ethernet, RFC 8504 — IPv6 Node Requirements  
**Supersession:** RFC 8200 supersedes RFC 2460  
**Design:** [ipv6.md](../design/ipv6.md)

## Overview

IPv6 is the successor to IPv4 with a 128-bit address space, simplified header format, and no fragmentation at intermediate routers. This stack implements IPv6 host behavior. IPv6 requires ICMPv6 (RFC 4443) and Neighbor Discovery (RFC 4861) as mandatory components.

## Header Format

```
Offset  Size  Field
  0      4b   Version (6)
  0      8b   Traffic Class (DSCP + ECN)
  0     20b   Flow Label
  4      2    Payload Length (bytes after header, excludes 40-byte header)
  6      1    Next Header (protocol: 6=TCP, 17=UDP, 58=ICMPv6, 59=No Next, 0/43/44/60=Extension)
  7      1    Hop Limit (equivalent to TTL)
  8     16    Source Address (128 bits)
 24     16    Destination Address (128 bits)
```

Fixed header: 40 bytes (always). Extension headers follow if needed.

## Requirements

### Header Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-001 | MUST | Verify Version field = 6 | RFC 8200 §3 | itest_ipv6_001_version_checked |
| REQ-IPv6-002 | MUST | Verify Payload Length + 40 ≤ actual received frame size | RFC 8200 §3 | itest_ipv6_002_payload_length_checked |
| REQ-IPv6-003 | MUST | Use Payload Length (not frame length) to determine payload boundaries | RFC 8200 §3 | itest_ipv6_003_payload_length_bounds_the_payload |
| REQ-IPv6-004 | MUST | Silently discard packets failing validation | RFC 8200 §3 | itest_ipv6_001_version_checked, itest_ipv6_002_payload_length_checked |
| REQ-IPv6-005 | MUST NOT | IPv6 has no header checksum — MUST NOT compute or expect one | RFC 8200 §3 | itest_ipv6_024_header_built |

### Destination Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-006 | MUST | Accept packets where Destination Address matches any of our assigned unicast addresses | RFC 4291 §2.8 | itest_ipv6_006_destinations_accepted |
| REQ-IPv6-007 | MUST | Accept packets where Destination Address matches a joined multicast group (`ipv6_mcast_join()`) or all-nodes (ff02::1) | RFC 4291 §2.7, §2.8 | itest_ipv6_006_destinations_accepted |
| REQ-IPv6-008 | MUST | Accept packets to the solicited-node multicast address (ff02::1:ffXX:XXXX) of each of our addresses | RFC 4291 §2.7.1, §2.8 | itest_ipv6_006_destinations_accepted |
| REQ-IPv6-009 | MUST | Accept packets to the link-local address (fe80::...) | RFC 4291 §2.5.6, §2.8 | itest_ipv6_006_destinations_accepted |
| REQ-IPv6-010 | MUST | Silently discard packets not addressed to us or a subscribed group — a tentative address is not ours yet | RFC 4291 §2.8, RFC 4862 §5.4 | itest_ipv6_010_other_destinations_dropped |

### Source Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-011 | MUST | Silently discard packets whose Source Address is a multicast address | RFC 4291 §2.7 | itest_ipv6_011_multicast_source_dropped |
| REQ-IPv6-012 | MUST | Silently discard packets whose Source Address is one of our own unicast addresses | Architecture | itest_ipv6_012_own_source_dropped |
| REQ-IPv6-013 | MUST NOT | Send a packet to the unspecified address (::): a packet from :: is accepted — Duplicate Address Detection probes and MLD reports carry it — but draws no echo reply, error or TCP segment, and the application cannot send to :: either | RFC 4291 §2.5.2 | itest_ipv6_013_unspecified_source, itest_ipv6_013_nothing_sent_to_unspecified |

### Next Header (Protocol) Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-014 | MUST | Dispatch Next Header 58 (ICMPv6) to ICMPv6 input — ICMPv6 is REQUIRED for IPv6 | RFC 8200 §4, RFC 4443 §2 | itest_ipv6_014_upper_layers_dispatched |
| REQ-IPv6-015 | MUST | Dispatch Next Header 6 (TCP) to TCP input (when compiled in) | RFC 8200 §3 | itest_ipv6_014_upper_layers_dispatched |
| REQ-IPv6-016 | MUST | Dispatch Next Header 17 (UDP) to UDP input (when compiled in) | RFC 8200 §3 | itest_ipv6_014_upper_layers_dispatched |
| REQ-IPv6-017 | SHOULD | For an unrecognized Next Header — or Hop-by-Hop Options (0) anywhere but straight after the IPv6 header — discard the packet and send ICMPv6 Parameter Problem (Type 4, Code 1) pointing at that Next Header field | RFC 8200 §4 | itest_ipv6_017_unknown_next_header, test_ipv6_011_unknown_next_header_parameter_problem |

### Extension Headers

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-018 | MUST | Process extension headers strictly in the order they appear, in any order and any number of times (Hop-by-Hop only first) | RFC 8200 §4, §4.1 | itest_ipv6_018_extension_headers_walked, test_ipv6_010_echo_behind_hop_by_hop_header |
| REQ-IPv6-019 | MUST | Process the options of Hop-by-Hop and Destination Options headers: act on an unrecognized option as the two high bits of its type say (skip, discard, discard and send Parameter Problem code 2) — **deviation:** both headers are skipped by their length without looking at the options, so a packet with an unrecognized option that asks to be discarded is processed, and no Parameter Problem code 2 is sent; hosts rarely receive options, and none is defined that this stack would act on | RFC 8200 §4.2, §4.3, §4.6 | itest_ipv6_019_options_skipped |
| REQ-IPv6-020 | MUST | Skip the Hop-by-Hop Options, Destination Options and Routing headers by their Hdr Ext Len to reach the upper-layer header; a header that runs past the payload discards the packet | RFC 8200 §4.3, §4.4, §4.6 | itest_ipv6_018_extension_headers_walked |
| REQ-IPv6-048 | MUST | Routing header (of a Routing Type not recognized: the stack processes none): with Segments Left = 0, ignore it and go on to the next header; with Segments Left ≠ 0, discard the packet and send ICMPv6 Parameter Problem, Code 0, pointing at the Routing Type | RFC 8200 §4.4 | itest_ipv6_048_routing_header_with_segments_left, itest_ipv6_018_extension_headers_walked |
| REQ-IPv6-021 | MUST NOT | Generate extension headers in outbound packets — except the Hop-by-Hop Router Alert that MLD messages must carry | Architecture, RFC 3810 §5 | itest_ipv6_021_no_extension_headers_sent |
| REQ-IPv6-022 | MUST | Reassemble fragmented packets of up to 1500 octets — **deviation:** there is no reassembly: a packet with a Fragment header (Next Header 44) is silently discarded, an atomic fragment (offset 0, no more fragments) included; RAM, and hosts on Ethernet rarely see fragments | RFC 8200 §4.5, §5 | itest_ipv6_022_fragments_dropped, test_ipv6_012_fragments_dropped |
| REQ-IPv6-023 | SHOULD | Send ICMPv6 Time Exceeded (Type 3, Code 1) when reassembly times out and the first fragment was received — **deviation:** not sent; fragments are not kept (REQ-IPv6-022) | RFC 8200 §4.5 | itest_ipv6_022_fragments_dropped |

### Header Building (Transmission)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-024 | MUST | Set Version = 6 | RFC 8200 §3 | itest_ipv6_024_header_built |
| REQ-IPv6-025 | MUST | Set Traffic Class = 0: no differentiated service is asked for | Architecture, RFC 8200 §7 | itest_ipv6_024_header_built |
| REQ-IPv6-026 | MUST | Set Flow Label = 0: the stack labels no flows | RFC 8200 §6, RFC 6437 §2 | itest_ipv6_024_header_built |
| REQ-IPv6-027 | MUST | Set Payload Length = bytes after the 40-byte header | RFC 8200 §3 | itest_ipv6_024_header_built |
| REQ-IPv6-028 | MUST | Set Next Header correctly (6=TCP, 17=UDP, 58=ICMPv6) | RFC 8200 §3 | itest_ipv6_024_header_built, itest_ipv6_047_built_in_place |
| REQ-IPv6-029 | MUST | Set Hop Limit to the interface's current hop limit: `NET_IPV6_DEFAULT_HOP_LIMIT` (64) until a Router Advertisement gives another (REQ-NDP-042); 255 for Neighbor Discovery, 1 for MLD | RFC 8200 §3, RFC 4861 §6.3.2 | itest_ipv6_024_header_built |
| REQ-IPv6-030 | MUST | Set Source Address = one of our assigned unicast addresses, selected by the destination (REQ-IPv6-041); a reply comes from the address the request was sent to | RFC 8200 §3, RFC 6724 | itest_ipv6_030_source_selection |
| REQ-IPv6-031 | MUST | Set Destination Address = target IPv6 address | RFC 8200 §3 | itest_ipv6_024_header_built |

### Fragmentation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-032 | MUST NOT | Fragment outbound packets: a datagram that does not fit one frame is refused | Architecture, RFC 8200 §4.5 | itest_ipv6_032_never_fragmented |
| REQ-IPv6-033 | MUST | Send no packet larger than the path MTU: packets fill at most the link MTU (`net->mtu`, 1500 on Ethernet), and a Packet Too Big about a packet of ours goes to its transport (REQ-ICMPv6-018): TCP lowers the connection's segment size — **deviation:** no path MTU is kept per destination: a UDP application is told the MTU and must itself send smaller datagrams | RFC 8200 §5, RFC 8201 §4 | itest_ipv6_032_never_fragmented, itest_icmpv6_018_packet_too_big_lowers_the_segment_size |
| REQ-IPv6-034 | SHOULD | Use the Ethernet MTU (1500) on the link | RFC 2464 §2 | itest_ipv6_032_never_fragmented |

### IPv6 Addressing (RFC 4291)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-035 | MUST | Support a link-local address (fe80::/64 + interface identifier) | RFC 4291 §2.5.6, §2.8 | itest_ipv6_035_link_local_from_the_mac |
| REQ-IPv6-036 | MUST | Generate the link-local address from the MAC in Modified EUI-64 format | RFC 4291 §2.5.1, Appendix A, RFC 2464 §4, §5 | itest_ipv6_035_link_local_from_the_mac |
| REQ-IPv6-037 | SHOULD | Support global unicast addresses (from SLAAC, DHCPv6, or `ipv6_addr_add()`): `NET_IPV6_ADDRS` − 1 of them, one by default | RFC 4291 §2.5.4 | itest_ipv6_006_destinations_accepted |
| REQ-IPv6-038 | MUST | Support all-nodes multicast (ff02::1) — joined implicitly | RFC 4291 §2.7.1, §2.8 | itest_ipv6_006_destinations_accepted, itest_ipv6_038_link_layer_groups |
| REQ-IPv6-039 | MUST | Support the solicited-node multicast address (ff02::1:ffXX:XXXX) of each unicast address | RFC 4291 §2.7.1, §2.8 | itest_ipv6_038_link_layer_groups |
| REQ-IPv6-040 | MUST | Map an IPv6 multicast address to the Ethernet multicast MAC 33:33 + its low 32 bits | RFC 2464 §7 | itest_ipv6_038_link_layer_groups |

### Address Selection (RFC 6724)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-041 | MUST | Select the source address by RFC 6724 — the stack applies rule 2 (appropriate scope) and rule 3 (avoid deprecated addresses) for its one interface; **deviation:** among several preferred global addresses the first slot wins: no labels (rule 6) and no longest matching prefix (rule 8) | RFC 6724 §5, RFC 8504 §6.6 | itest_ipv6_030_source_selection, itest_ipv6_041_deprecated_source_as_last_resort |
| REQ-IPv6-042 | MUST | Prefer the link-local source for link-local destinations (and link-scope multicast) | RFC 6724 §5, Rule 2 | itest_ipv6_030_source_selection |
| REQ-IPv6-043 | MUST | Prefer a global source for global destinations; without one there is no source, and the send fails | RFC 6724 §5, Rule 2 | itest_ipv6_030_source_selection |

### Pseudo-Header for Upper Layers

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-044 | MUST | Include the IPv6 pseudo-header in the TCP, UDP and ICMPv6 checksums: src (16) + dst (16) + upper-layer length (4) + zeros (3) + next header (1) = 40 bytes | RFC 8200 §8.1 | itest_ipv6_044_upper_layer_checksums, itest_ipv6_047_built_in_place |
| REQ-IPv6-045 | MUST | The UDP checksum is mandatory over IPv6: a computed 0 is sent as 0xFFFF, and a received datagram with a zero checksum is discarded | RFC 8200 §8.1 | itest_ipv6_044_upper_layer_checksums, test_ipv6_015_udp_zero_checksum_dropped |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv6-046 | MUST | Parse the IPv6 header in place in the application's RX buffer | Architecture | itest_ipv6_046_parsed_in_place |
| REQ-IPv6-047 | MUST | Build the IPv6 header in place at offset 14 (after the Ethernet header) in the application's TX buffer | Architecture | itest_ipv6_047_built_in_place |

## Notes

- **IPv6 header is always 40 bytes** (unlike IPv4's variable header). This simplifies parsing.
- **No header checksum:** IPv6 relies entirely on link-layer (Ethernet CRC) and upper-layer (TCP/UDP/ICMPv6) checksums. This saves processing time.
- **ICMPv6 is mandatory:** IPv6 cannot function without ICMPv6 (needed for NDP, PMTUD, error reporting).
- **No fragmentation at routers:** IPv6 routers never fragment. Source must fit packets in path MTU. Minimum MTU is 1280 bytes.
- **Extension header chains:** Most practical IPv6 packets have no extension headers. The stack skips them, and generates one only for MLD: the Hop-by-Hop header with the Router Alert option that RFC 3810 requires.
- **Modified EUI-64:** MAC 00:11:22:33:44:55 → link-local fe80::0211:22ff:fe33:4455 (flip U/L bit, insert FF:FE in middle).
