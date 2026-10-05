# Ethernet Requirements

**Protocol:** Ethernet II (DIX) Framing  
**Primary RFC:** RFC 894 — A Standard for the Transmission of IP Datagrams over Ethernet Networks  
**Supporting:** IEEE 802.3, RFC 1122 §2.3, §2.4, RFC 2464 (IPv6 over Ethernet)  
**Scope:** IPv4 and IPv6

## Overview

Ethernet II framing is the data link layer encapsulation used for IP traffic on Ethernet networks. This document covers frame structure, validation, and dispatch requirements. IEEE 802.3 LLC/SNAP framing is out of scope — only Ethernet II (DIX) is supported.

## Frame Format

```
Offset  Size  Field
  0      6    Destination MAC address
  6      6    Source MAC address
 12      2    EtherType (big-endian)
 14     46-1500  Payload
```

Minimum frame: 64 bytes (with FCS) = 60 bytes (without FCS). Maximum frame: 1518 bytes (with FCS) = 1514 bytes (without FCS). The MAC hardware strips and verifies the FCS, so the stack sees frames without FCS (14-byte header + payload).

## Requirements

### Frame Reception

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-001 | MUST | Accept frames with our unicast MAC as destination | RFC 894, IEEE 802.3 | itest_eth_001_frames_for_us_taken |
| REQ-ETH-002 | MUST | Accept frames with broadcast MAC (FF:FF:FF:FF:FF:FF) as destination | RFC 894, IEEE 802.3 | itest_eth_001_frames_for_us_taken |
| REQ-ETH-003 | MUST | Discard frames addressed to neither our MAC, the broadcast address, nor the MAC of a joined multicast group | IEEE 802.3 | itest_eth_001_frames_for_us_taken |
| REQ-ETH-004 | MUST | Parse EtherType field at offset 12 as big-endian uint16 | RFC 894 | itest_eth_005_dispatch_by_ethertype |
| REQ-ETH-005 | MUST | Dispatch EtherType 0x0800 to IPv4 input | RFC 894 | itest_eth_005_dispatch_by_ethertype |
| REQ-ETH-006 | MUST | Dispatch EtherType 0x0806 to ARP input | RFC 826 | itest_eth_005_dispatch_by_ethertype |
| REQ-ETH-007 | MUST | Dispatch EtherType 0x86DD to IPv6 input (when IPv6 is compiled in) | RFC 2464 §3 | itest_eth_007_ipv6_ethertype |
| REQ-ETH-008 | MUST | Silently discard frames with unrecognized EtherType | IEEE 802.3, Architecture | itest_eth_005_dispatch_by_ethertype |
| REQ-ETH-009 | MUST | Silently discard frames shorter than 14 bytes (no valid header) | IEEE 802.3 | itest_eth_005_dispatch_by_ethertype, test_eth_parse_too_short |
| REQ-ETH-010 | SHOULD | Accept multicast frames for joined multicast groups (IPv4 groups, the all-hosts group, IPv6 solicited-node and joined groups) | IEEE 802.3 | itest_ipv4_050_all_hosts_group |
| REQ-ETH-022 | MUST | Tell the IP layer whether a frame was addressed to a link-layer broadcast (or multicast) address, so no ICMP error answers it | RFC 1122 §2.4 | itest_eth_022_link_broadcast_draws_no_error |
| REQ-ETH-025 | MUST NOT | Deliver up a multicast or broadcast frame the host itself sent (one the medium loops back: its source MAC is ours); the stack drops every frame whose source MAC is its own | RFC 1112 §7.3 | itest_eth_025_own_frames_not_delivered |

### Frame Transmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-011 | MUST | Build Ethernet header with correct destination MAC, source MAC, and EtherType | RFC 894 | itest_eth_011_header_sent |
| REQ-ETH-012 | MUST | Source MAC in transmitted frames MUST be our own MAC address | IEEE 802.3 | itest_eth_011_header_sent |
| REQ-ETH-013 | MUST | EtherType MUST be 0x0800 for IPv4 payloads | RFC 894 | itest_eth_011_header_sent |
| REQ-ETH-014 | MUST | EtherType MUST be 0x0806 for ARP payloads | RFC 826 | itest_eth_011_header_sent |
| REQ-ETH-015 | MUST | EtherType MUST be 0x86DD for IPv6 payloads | RFC 2464 §3 | itest_eth_007_ipv6_ethertype |
| REQ-ETH-016 | SHOULD | Pad frames shorter than 60 bytes (minimum Ethernet frame without FCS) to 60 bytes — **deviation:** the stack hands the driver the frame at its own length (an ARP packet is 42 bytes); padding is the MAC's: the STM32F4 MAC pads in hardware, and the hosted links (TAP, raw socket, BPF) need none | RFC 894, IEEE 802.3 §3.2.8 | — |
| REQ-ETH-021 | MUST | Send Ethernet II (RFC 894) frames only: trailer encapsulation off, no IEEE 802.2/802.3 framing | RFC 1122 §2.3.1, §2.3.3 | itest_eth_021_ethernet_ii_only |
| REQ-ETH-023 | MUST | The link layer's send interface carries the IP TOS: frames are handed to the driver whole, with the TOS the IP header was built with | RFC 1122 §2.4 | itest_ipv4_041_tos_settable |
| REQ-ETH-024 | MUST NOT | Report Destination Unreachable to IP because no ARP entry exists: there is no ARP cache; sends take the MAC from the caller, and an unanswered ARP request reports nothing | RFC 1122 §2.4 | itest_eth_024_unresolved_address_is_no_error |

### Frame Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-017 | SHOULD | Receive IEEE 802.3 frames in RFC 1042 (LLC/SNAP) encapsulation, intermixed with Ethernet II frames — **deviation:** a frame whose type field is ≤ 0x05DC (an IEEE 802.3 length) is dropped; only Ethernet II is supported | RFC 1122 §2.3.3 | itest_eth_005_dispatch_by_ethertype, test_eth_parse_reject_802_3 |
| REQ-ETH-018 | MUST | Frame payload length derived from `frame_len - 14` | RFC 894 | itest_eth_018_payload_is_the_rest_of_the_frame |

### Zero-Copy

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ETH-019 | MUST | Parse headers in-place — do not copy frame data | Architecture | itest_eth_019_parsed_in_the_rx_buffer, test_eth_parse_zero_copy |
| REQ-ETH-020 | MUST | Build headers in-place in application buffer | Architecture | itest_eth_020_built_in_the_tx_buffer |
| REQ-ETH-026 | MUST | Take a received frame from wherever the driver has it: `eth_input()` may be given a frame in the platform's own memory instead of `net->rx.buf`, and nothing the stack or its protocol modules decide about that frame is read from `net->rx.buf` | Architecture | itest_mdns_062_group_response_in_the_drivers_own_buffer, itest_mdns6_062_group_response_in_the_drivers_own_buffer |

## Notes

- FCS (Frame Check Sequence, 4-byte CRC32) is handled by MAC hardware and not visible to the stack. Requirements assume FCS has been stripped on RX and will be appended on TX by the MAC.
- VLAN tagging (802.1Q) is not supported. If a VLAN tag is present, EtherType at offset 12 is 0x8100, which is discarded per REQ-ETH-008.
- Jumbo frames are not supported. A frame sent is at most 14 bytes plus the interface's MTU (`net_t.mtu`, 1500 by default): 1514 bytes without FCS.
