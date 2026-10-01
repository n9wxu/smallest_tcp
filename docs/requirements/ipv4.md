# IPv4 Requirements

**Protocol:** Internet Protocol version 4  
**Primary RFC:** RFC 791 — Internet Protocol  
**Supporting:** RFC 1122 — Requirements for Internet Hosts (§3.2, §3.3), RFC 6864 — Updated Specification of the IPv4 ID Field, RFC 1812 — Requirements for IP Version 4 Routers (reference only — we are a host)  
**Supersession:** RFC 6864 supersedes RFC 791 regarding the IP Identification field  
**Scope:** V1 (IPv4)  
**Last updated:** 2026-10-01 (the RFC MUSTs the document left out added; rows that contradicted their RFC corrected)

## Overview

IPv4 is the network layer protocol that provides addressing and routing for IP datagrams. This stack implements IPv4 host (not router) behavior per RFC 791 and the host requirements in RFC 1122 §3.

## Header Format

```
Offset  Size  Field
  0      4b   Version (4)
  0      4b   IHL (Internet Header Length, in 32-bit words, minimum 5)
  1      1    Type of Service (TOS) / DSCP+ECN
  2      2    Total Length (header + payload, in bytes)
  4      2    Identification
  6      3b   Flags (bit 0: reserved, bit 1: DF, bit 2: MF)
  6     13b   Fragment Offset (in 8-byte units)
  8      1    Time to Live (TTL)
  9      1    Protocol (6=TCP, 17=UDP, 1=ICMP)
 10      2    Header Checksum
 12      4    Source Address
 16      4    Destination Address
 20     0-40  Options (if IHL > 5)
```

Minimum header: 20 bytes (IHL=5). Maximum header: 60 bytes (IHL=15).

## Requirements

### Header Reception and Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-001 | MUST | Verify Version field = 4 | RFC 791 §3.1, RFC 1122 §3.2.1.1 | TEST-IPv4-001 |
| REQ-IPv4-002 | MUST | Verify IHL ≥ 5 (minimum 20 bytes) | RFC 791 §3.1, RFC 1122 §3.2.1.1 | TEST-IPv4-002 |
| REQ-IPv4-003 | MUST | Verify Total Length ≥ IHL × 4 | RFC 791 §3.1, RFC 1122 §3.2.1.1 | TEST-IPv4-003 |
| REQ-IPv4-004 | MUST | Verify Total Length ≤ actual received frame payload length | RFC 791, RFC 1122 §3.2.1.1 | TEST-IPv4-004 |
| REQ-IPv4-005 | MUST | Verify header checksum; silently discard on failure | RFC 791 §3.1, RFC 1122 §3.2.1.2 | TEST-IPv4-005 |
| REQ-IPv4-006 | MUST | Silently discard packets failing any validation check | RFC 1122 §3.2.1.1 | TEST-IPv4-006 |
| REQ-IPv4-007 | MUST | Use Total Length (not frame length) to determine IP payload length | RFC 791, RFC 1122 §3.2.1.1 | TEST-IPv4-007 |

### Destination Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-008 | MUST | Accept packets where Destination Address matches our configured IPv4 address | RFC 791, RFC 1122 §3.2.1.3 | TEST-IPv4-008 |
| REQ-IPv4-009 | MUST | Accept packets where Destination Address is the limited broadcast (255.255.255.255) | RFC 1122 §3.2.1.3 | TEST-IPv4-009 |
| REQ-IPv4-010 | MUST | Accept packets where Destination Address is our own subnet's directed broadcast (not another subnet's; a /31 or /32 has none) | RFC 1122 §3.2.1.3, RFC 3021 | TEST-IPv4-010 |
| REQ-IPv4-011 | MUST | Silently discard packets not addressed to us, broadcast, or a subscribed multicast group | RFC 1122 §3.2.1.3 | TEST-IPv4-011 |
| REQ-IPv4-012 | SHOULD | Accept packets addressed to 0.0.0.0 during DHCP bootstrap (before address configured) | RFC 1122 §3.2.1.3, RFC 2131 | TEST-IPv4-012 |
| REQ-IPv4-059 | MUST | Recognise every standard broadcast form as a destination: the limited broadcast, our subnet's directed broadcast, and the directed and all-subnets-directed broadcast of our (classful) network | RFC 1122 §3.3.6, §3.2.1.3 | itest_ipv4_059_every_broadcast_form, itest_ipv4_059_supernet_has_no_classful_broadcast |

### Source Address Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-013 | MUST | Silently discard packets whose Source Address names no single host: 255.255.255.255, our subnet's broadcast, multicast, class E (240/4) | RFC 1122 §3.2.1.3, RFC 1112 §4 | TEST-IPv4-013 |
| REQ-IPv4-014 | MUST | Silently discard packets with Source Address = our own address (prevent loops) | RFC 1122 §3.2.1.3 | TEST-IPv4-014 |
| REQ-IPv4-015 | SHOULD | Silently discard packets with Source Address = 127.x.x.x (loopback range) | RFC 1122 §3.2.1.3 | TEST-IPv4-015 |
| REQ-IPv4-016 | SHOULD | Silently discard packets with Source Address = 0.0.0.0 except during DHCP | RFC 1122 §3.2.1.3 | TEST-IPv4-016 |

### Protocol Dispatch

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-017 | MUST | Dispatch Protocol 1 (ICMP) to ICMPv4 input | RFC 791, RFC 1122 §3.2.1.6 | TEST-IPv4-017 |
| REQ-IPv4-018 | MUST | Dispatch Protocol 6 (TCP) to TCP input (when linked) | RFC 791, RFC 1122 §3.2.1.6 | TEST-IPv4-018 |
| REQ-IPv4-019 | MUST | Dispatch Protocol 17 (UDP) to UDP input (when linked) | RFC 791, RFC 1122 §3.2.1.6 | TEST-IPv4-019 |
| REQ-IPv4-020 | MUST | For unrecognized Protocol values, send ICMP Protocol Unreachable (Type 3, Code 2) if ICMP is linked | RFC 1122 §3.2.2.1 | TEST-IPv4-020 |
| REQ-IPv4-021 | MUST | Implement ICMP with IP: ICMP is always built with IPv4, so an unrecognised protocol always draws Protocol Unreachable | RFC 1122 §3.1, RFC 792 | itest_ipv4_021_unknown_protocol_unreachable |

### Fragmentation and Reassembly

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-022 | MUST NOT | MUST NOT fragment outbound packets (DF bit always set) | Architecture (no reassembly buffer) | TEST-IPv4-022 |
| REQ-IPv4-023 | MUST | Set DF (Don't Fragment) flag on all outbound IPv4 packets | RFC 791 §3.1, Architecture | TEST-IPv4-023 |
| REQ-IPv4-024 | MUST | Reassemble fragmented datagrams, in any order and with overlaps, into the reassembly buffer the application gives (`ipv4_set_reassembly()`), and deliver them whole; a build without one drops fragments and does not comply | RFC 1122 §3.3.2, RFC 791 §3.2 | itest_ipv4_024_reassembly, itest_ipv4_024_larger_than_a_frame, itest_ipv4_024_too_large_dropped, itest_ipv4_024_one_at_a_time |
| REQ-IPv4-025 | MUST | When the reassembly timeout expires, discard the partial datagram and, if its fragment zero arrived, send ICMP Time Exceeded (Type 11, Code 1) to its source | RFC 1122 §3.3.2 | itest_ipv4_025_reassembly_timeout |
| REQ-IPv4-060 | MUST | Have a fixed reassembly timeout (60 s; RFC 1122 recommends 60–120 s), not one set from the TTL | RFC 1122 §3.3.2 | itest_ipv4_025_reassembly_timeout |
| REQ-IPv4-061 | MUST | EMTU_R ≥ 576: accept datagrams of up to 576 octets — **deviation:** `net_init()` accepts smaller frame buffers for the smallest targets; a build complies only with an RX frame buffer of at least 590 bytes and a reassembly buffer of at least 576 | RFC 1122 §3.3.2, RFC 791 §3.1 | itest_ipv4_061_576_octet_datagrams |
| REQ-IPv4-062 | MUST | Let the transport layer learn MMS_R, the largest message it can receive (EMTU_R − 20): `ipv4_mms_r()` | RFC 1122 §3.3.2, §3.4 | itest_ipv4_062_mms_r |
| REQ-IPv4-063 | MUST | Let the transport layer learn MMS_S, the largest message it can send in one datagram: `ipv4_mms_s()`; the transports never exceed it | RFC 1122 §3.3.3, §3.4 | itest_ipv4_063_mms_s |
| REQ-IPv4-064 | MUST | The MTU of the interface is configurable (`net_t.mtu`, default 1500) | RFC 1122 §3.3.3 | itest_ipv4_064_mtu_configurable |

**Note:** The DF flag is always set: the stack never fragments what it sends (REQ-IPv4-022, 023).  It reassembles what it receives when the application gives it a buffer.

### IP Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-026 | MUST | Accept and process packets with IP options (IHL > 5) by skipping options correctly | RFC 791, RFC 1122 §3.2.1.8 | TEST-IPv4-026 |
| REQ-IPv4-027 | MUST | IP payload starts at offset IHL × 4, not at fixed offset 20 | RFC 791 §3.1 | TEST-IPv4-027 |
| REQ-IPv4-028 | MUST NOT | Generate no IP options, except the Router Alert option IGMP messages carry | RFC 2236 §2, Architecture | itest_ipv4_028_no_options_sent |
| REQ-IPv4-029 | MAY | Silently ignore all IP option content (do not process Record Route, Timestamp, etc.) | RFC 1122 §3.2.1.8 | TEST-IPv4-029 |
| REQ-IPv4-065 | MUST | Let the transport layer send IP options — **deviation:** UDP and TCP send no options (no API for them; source routing, their main use, is not supported — REQ-IPv4-067) | RFC 1122 §3.2.1.8, §3.4 | — (deviation) |
| REQ-IPv4-066 | MUST | Pass the IP options of a received datagram up to the transport layer — **deviation:** options are skipped (REQ-IPv4-026) and not passed up | RFC 1122 §3.2.1.8, §3.4 | itest_ipv4_026_options_skipped |
| REQ-IPv4-067 | MUST | Originate and terminate source routes: a datagram with a completed source route is passed up and its route reversed for replies — **deviation:** a datagram carrying a Loose or Strict Source Route option is dropped, as RFC 6274 §3.13.2.3 and RFC 7126 §4.3–4.4 recommend for security and Linux does by default | RFC 1122 §3.2.1.8c, §3.2.2.6 | itest_ipv4_067_source_routed_dropped |
| REQ-IPv4-068 | MUST | Silently ignore unknown options and the Stream Identifier option; an option length outside the possible range does not crash the IP layer | RFC 1122 §3.2.1.8 | itest_ipv4_068_unknown_and_malformed_options |

### Header Building (Transmission)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-030 | MUST | Set Version = 4 | RFC 791 §3.1 | TEST-IPv4-030 |
| REQ-IPv4-031 | MUST | Set IHL = 5 (no options), or 6 for IGMP's Router Alert option | RFC 791 §3.1, RFC 2236 §2 | itest_ipv4_028_no_options_sent |
| REQ-IPv4-032 | MUST | Set Total Length = header length + payload length | RFC 791 §3.1 | itest_ipv4_028_no_options_sent |
| REQ-IPv4-033 | MUST | Set Identification field: for DF=1 packets, any value is acceptable (RFC 6864) | RFC 6864 §4.1 (supersedes RFC 791) | TEST-IPv4-033 |
| REQ-IPv4-034 | MUST | Set DF=1, MF=0, Fragment Offset=0 | Architecture, RFC 791 §3.1 | TEST-IPv4-034 |
| REQ-IPv4-035 | MUST | Set TTL to a reasonable value, configurable (`NET_DEFAULT_TTL`, default 64) | RFC 791 §3.1, RFC 1122 §3.2.1.7 | itest_ipv4_035_default_ttl |
| REQ-IPv4-082 | MUST | Send the reserved flag bit as zero | RFC 791 §3.1 | itest_ipv4_028_no_options_sent |
| REQ-IPv4-083 | MUST | Use the Identification field for fragmentation and reassembly only, and ignore it in atomic datagrams (DF set, not fragments) | RFC 6864 §4.1 | itest_ipv4_083_atomic_id_ignored |
| REQ-IPv4-036 | MUST | Set Protocol field correctly (1=ICMP, 6=TCP, 17=UDP) | RFC 791 §3.1 | TEST-IPv4-036 |
| REQ-IPv4-037 | MUST | Compute and set Header Checksum (or write 0x0000 if MAC does TX checksum offload) | RFC 791 §3.1 | TEST-IPv4-037 |
| REQ-IPv4-038 | MUST | Set Source Address = our configured IPv4 address | RFC 791 §3.1 | TEST-IPv4-038 |
| REQ-IPv4-039 | MUST | Set Destination Address = target IPv4 address | RFC 791 §3.1 | TEST-IPv4-039 |

### Type of Service (TOS) / DSCP

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-040 | MUST | Set TOS/DSCP to 0 by default | RFC 791 §3.1 | TEST-IPv4-040 |
| REQ-IPv4-041 | MUST | Let the transport layer set the TOS (DSCP) of every datagram it sends | RFC 1122 §3.2.1.6, §3.4 | itest_ipv4_041_tos_settable |
| REQ-IPv4-042 | MUST | Do not discard received packets based on TOS/DSCP value | RFC 1122 §3.2.1.6 | TEST-IPv4-042 |

### TTL Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-043 | MUST NOT | MUST NOT forward packets (we are a host, not a router) | RFC 1122 §3.3.1 | TEST-IPv4-043 |
| REQ-IPv4-044 | MUST | Accept received packets regardless of TTL value (do not discard based on TTL) | RFC 1122 §3.2.1.7 | TEST-IPv4-044 |
| REQ-IPv4-045 | SHOULD | Default outbound TTL SHOULD be 64 | RFC 1122 §3.2.1.7 (recommends ≥ 64) | TEST-IPv4-045 |
| REQ-IPv4-058 | MUST NOT | Never send a datagram with a TTL of 0 | RFC 1122 §3.2.1.7 | itest_ipv4_058_never_ttl_zero |
| REQ-IPv4-069 | MUST | Let the transport layer set the TTL of every datagram it sends | RFC 1122 §3.2.1.7 | itest_ipv4_069_ttl_settable |

### Broadcasting

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-046 | MUST | Support sending to limited broadcast (255.255.255.255) | RFC 1122 §3.3.6 | TEST-IPv4-046 |
| REQ-IPv4-047 | MUST | When sending to broadcast, use broadcast MAC (FF:FF:FF:FF:FF:FF) | RFC 894, RFC 1122 §3.3.6 | TEST-IPv4-047 |
| REQ-IPv4-048 | MUST NOT | MUST NOT send datagrams with Source Address = broadcast | RFC 1122 §3.2.1.3 | TEST-IPv4-048 |
| REQ-IPv4-049 | SHOULD | Support subnet-directed broadcast (host part all-ones) for sending | RFC 1122 §3.3.6 | TEST-IPv4-049 |
| REQ-IPv4-070 | MUST NOT | Send 0.0.0.0 as a destination, or as a source except while acquiring an address (DHCP) | RFC 1122 §3.2.1.3 (a) | itest_ipv4_070_never_to_or_from_unspecified |
| REQ-IPv4-071 | MUST NOT | Send a datagram from or to 127/8 (loopback addresses never appear outside a host) | RFC 1122 §3.2.1.3 (g) | itest_ipv4_071_never_loopback |
| REQ-IPv4-072 | MUST | A datagram sent to the link-layer broadcast address has an IP broadcast or multicast destination | RFC 1122 §3.3.6 | itest_ipv4_072_link_broadcast_needs_ip_broadcast |

### Multicast (Minimal)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-050 | MUST | A host that takes part in IP multicast (a multicast group table, `NET_MAX_MCAST_GROUPS` ≥ 1) belongs to the all-hosts group 224.0.0.1 | RFC 1112 §7.2 | itest_ipv4_050_all_hosts_group |
| REQ-IPv4-073 | MUST | Loop a datagram sent to a group the host has joined back for local delivery, unless the sender inhibits it — **deviation:** loopback is always inhibited: the stack never delivers its own multicast datagrams to itself | RFC 1112 §6.2 | itest_ipv4_073_no_multicast_loopback |
| REQ-IPv4-051 | MAY | Support sending to multicast addresses with appropriate multicast MAC | RFC 1112 §6.4 | TEST-IPv4-051 |
| REQ-IPv4-052 | MAY | Map IPv4 multicast address to Ethernet multicast MAC: 01:00:5E + low 23 bits | RFC 1112 §6.4 | TEST-IPv4-052 |

### ICMP Error Interaction

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-053 | MUST | Pass received ICMP Destination Unreachable to upper layer (TCP/UDP) | RFC 1122 §3.2.2.1 | itest_udp_038_port_unreachable_reported |
| REQ-IPv4-054 | MUST | Pass received ICMP Redirect to the routing layer, which updates its route for the destination — **deviation:** there is no routing layer (REQ-IPv4-075); Redirects are ignored | RFC 1122 §3.2.2.2 | itest_icmpv4_019_redirect_ignored |
| REQ-IPv4-055 | MUST | Handle both Host and Network Redirects — **deviation:** both are ignored (REQ-IPv4-054) | RFC 1122 §3.2.2.2 | itest_icmpv4_019_redirect_ignored |

### Routing

The application chooses each datagram's next hop and passes its MAC with the
send; the stack keeps one gateway, its MAC learned by ARP
([arp-resolution.md](../design/arp-resolution.md)).  The routing MUSTs of
RFC 1122 §3.3.1 assume a host that routes; these are recorded as
deviations.

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-075 | MUST | Keep a route cache mapping destinations to next hops — **deviation:** the application chooses next hops; `arp_next_hop()` gives the subnet rule | RFC 1122 §3.3.1.2 | — (deviation) |
| REQ-IPv4-076 | MUST | Support several default gateways, with a preference, configurable by hand — **deviation:** one gateway (`net_t.gateway_ipv4`), configured by hand or by DHCP | RFC 1122 §3.3.1.2, §3.3.1.6 | — (deviation) |
| REQ-IPv4-077 | MUST | Detect the failure of a next-hop gateway, and select another default gateway — **deviation:** with one gateway there is no other; the application sees the failure as timeouts | RFC 1122 §3.3.1.4, §3.3.1.5 | — (deviation) |
| REQ-IPv4-078 | MUST | Work in a network with no gateways | RFC 1122 §3.3.1.1 | itest_arp_041_broadcast_and_multicast_next_hop |
| REQ-IPv4-079 | MUST NOT | Check a gateway's health by pinging it continuously; ping only while traffic is sent to it | RFC 1122 §3.3.1.4 | itest_ipv4_079_never_pings_the_gateway |
| REQ-IPv4-080 | MUST | Support a statically configured subnet mask; the method of choosing the mask is configurable | RFC 1122 §3.2.2.9 | itest_ipv4_011_point_to_point_masks_have_no_broadcast |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-IPv4-056 | MUST | Parse IPv4 header in-place in application buffer | Architecture | TEST-IPv4-056 |
| REQ-IPv4-057 | MUST | Build IPv4 header in-place at offset 14 (after Ethernet header) in application buffer | Architecture | TEST-IPv4-057 |

## Implementation Notes

- **No IP ID uniqueness requirement for DF=1 packets (RFC 6864):** Since we always set DF, the Identification field can be any value. We use 0 or a simple counter.
- **No IP options generated:** Simplifies header building — always 20-byte header, except IGMP's Router Alert. Inbound packets with options are accepted and the options skipped; source-routed ones are dropped (REQ-IPv4-067).
- **Reassembly, no fragmentation:** what the stack sends always has DF set and fits the MTU; what it receives in fragments is reassembled in a buffer the application gives (`ipv4_set_reassembly()`), one datagram at a time.
- **MTU:** `net_t.mtu`, 1500 by default.  TCP MSS and UDP payload sizes are derived from buffer capacity but capped at the MTU − 20 (MMS_S, `ipv4_mms_s()`).
