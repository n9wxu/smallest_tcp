# ARP Requirements

**Protocol:** Address Resolution Protocol  
**Primary RFC:** RFC 826 — An Ethernet Address Resolution Protocol  
**Supporting:** RFC 1122 §2.3.2, §2.3.3, §3.3.1.1, RFC 5227 (IPv4 Address Conflict Detection)  
**Scope:** IPv4 only — IPv6 uses NDP, see ndp.md  
**Design:** [arp-resolution.md](../design/arp-resolution.md)

## Overview

ARP maps IPv4 addresses to Ethernet (link-layer) MAC addresses. This stack uses a distributed ARP model: no ARP cache table. A MAC address is kept where it is used — the gateway's in `net_t`, a TCP peer's in its connection, any other in the application — and every send takes its destination MAC from the caller. The stack answers requests for its address, sends requests when the application asks (`arp_request()`), and learns one MAC from replies: that of the address in `net_t.gateway_ipv4`.

## Packet Format

```
Offset  Size  Field
  0      2    Hardware Type (1 = Ethernet)
  2      2    Protocol Type (0x0800 = IPv4)
  4      1    Hardware Address Length (6)
  5      1    Protocol Address Length (4)
  6      2    Operation (1 = Request, 2 = Reply)
  8      6    Sender Hardware Address (MAC)
 14      4    Sender Protocol Address (IPv4)
 18      6    Target Hardware Address (MAC)
 24      4    Target Protocol Address (IPv4)
```

Total: 28 bytes. Encapsulated in Ethernet frame with EtherType 0x0806.

## Requirements

### Inbound ARP Request Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-001 | MUST | Respond to ARP requests where Target Protocol Address matches our IPv4 address | RFC 826, RFC 1122 §2.3.2.1 | itest_arp_001_request_for_our_address_answered, test_arp_001_who_has_gets_reply |
| REQ-ARP-002 | MUST | ARP reply MUST contain our MAC in Sender Hardware Address and our IP in Sender Protocol Address | RFC 826 | itest_arp_001_request_for_our_address_answered, test_arp_002_reply_fields_correct |
| REQ-ARP-003 | MUST | ARP reply destination MUST be the requester's MAC (unicast), not broadcast | RFC 826 | itest_arp_001_request_for_our_address_answered |
| REQ-ARP-004 | MUST | Silently discard ARP requests where Target Protocol Address does not match our IPv4 address; before an address is configured (0.0.0.0) no request matches | RFC 826 | itest_arp_005_only_ethernet_ipv4_requests_for_us, itest_arp_004_unconfigured_answers_nothing, test_arp_003_who_has_wrong_ip_is_silent |
| REQ-ARP-005 | MUST | Validate Hardware Type = 1 (Ethernet) and Protocol Type = 0x0800 (IPv4) | RFC 826 | itest_arp_005_only_ethernet_ipv4_requests_for_us |
| REQ-ARP-006 | MAY | Validate HLEN = 6 and PLEN = 4 (RFC 826 makes the length checks optional; the stack makes them, its packet layout being fixed) | RFC 826 | itest_arp_005_only_ethernet_ipv4_requests_for_us |
| REQ-ARP-007 | MUST | Silently discard ARP packets with invalid Hardware Type, Protocol Type, HLEN, or PLEN, and packets shorter than 28 bytes | RFC 826 | itest_arp_005_only_ethernet_ipv4_requests_for_us, itest_eth_018_payload_is_the_rest_of_the_frame |
| REQ-ARP-008 | SHOULD | Fast-path filter: check Target Protocol Address at fixed offset (byte 38 in Ethernet frame) before full parse — **deviation:** there is no separate filter: `net_poll()` reads every frame whole and `arp_input()` checks the 28-byte packet's format, then its target | Architecture (performance) | — |
| REQ-ARP-009 | SHOULD | On hardware MACs, use `peek()` to read Target IP without reading full frame; use `discard()` if not for us — **deviation:** `net_poll()` copies every frame whole before any layer sees it ([mac-hal.md §3](../design/mac-hal.md#3-the-receive-lifecycle-net_poll)) | Architecture (performance) | — |

### Inbound ARP Reply Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-010 | MUST | When an ARP reply is received, compare its Sender Protocol Address with the address being resolved: `net_t.gateway_ipv4` | RFC 826 | itest_arp_011_gateway_learned_only_from_the_gateway |
| REQ-ARP-011 | MUST | If it matches, store the Sender Hardware Address as the resolved MAC (`net_t.gateway_mac`) | RFC 826 | itest_arp_011_gateway_learned_only_from_the_gateway |
| REQ-ARP-012 | MUST | Mark the MAC as valid after storing it (`net_t.gateway_mac_valid`) | Architecture | itest_arp_011_gateway_learned_only_from_the_gateway |
| REQ-ARP-013 | SHOULD | Silently discard ARP replies that don't match the address being resolved | Architecture | itest_arp_011_gateway_learned_only_from_the_gateway |
| REQ-ARP-014 | MUST | Validate Operation = 2 (Reply) before processing as a reply | RFC 826 | itest_arp_036_requests_teach_nothing |

### Outbound ARP Request Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-015 | MUST | Send an ARP request when a datagram is to go to an address whose MAC is not known — **deviation:** the stack does not resolve on its own: a send takes its destination MAC from the caller, and the application calls `arp_request()` for a next hop whose MAC it does not hold | RFC 826 | itest_arp_016_request_sent |
| REQ-ARP-016 | MUST | ARP request MUST be sent to broadcast MAC (FF:FF:FF:FF:FF:FF) | RFC 826 | itest_arp_016_request_sent |
| REQ-ARP-017 | MUST | ARP request Target Protocol Address MUST be the address `arp_request()` is given: the destination IP, or the gateway IP if off-subnet (`arp_next_hop()`) | RFC 826, RFC 1122 §3.3.1.1 | itest_arp_016_request_sent |
| REQ-ARP-018 | SHOULD | Save at least the latest packet for an unresolved address and send it once the address is resolved — **deviation:** nothing is queued: a send needs the MAC, so the application resolves first, then sends | RFC 1122 §2.3.2.2 | — |
| REQ-ARP-019 | MUST | ARP request Sender Hardware Address MUST be our MAC | RFC 826 | itest_arp_016_request_sent |
| REQ-ARP-020 | MUST | ARP request Sender Protocol Address MUST be our IPv4 address | RFC 826 | itest_arp_016_request_sent |

### ARP Timeout and Retry

Repeating an unanswered request, and giving up, are the application's: the stack sends a request when `arp_request()` is called and reports the answer in `net_t.gateway_mac_valid`.

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-021 | MAY | Repeat an ARP request that got no reply: the application calls `arp_request()` again | Architecture | — |
| REQ-ARP-022 | SHOULD | Send at most one ARP request per second for the same destination (the recommended maximum rate) | RFC 1122 §2.3.2.1 | itest_arp_039_no_flooding |
| REQ-ARP-023 | MAY | Limit the number of repeated requests: the application stops calling `arp_request()` | Architecture | — |
| REQ-ARP-024 | MAY | Learn that resolution failed: `net_t.gateway_mac_valid` is still 0 when the application stops waiting; the stack reports no error (REQ-ETH-024) | Architecture | — |
| REQ-ARP-038 | MUST | Flush out-of-date entries: the gateway's MAC expires `NET_ARP_GATEWAY_TIMEOUT_MS` after it was learned or last refreshed by the gateway's reply; the timeout is configurable | RFC 1122 §2.3.2.1 | itest_arp_038_gateway_mac_expires |
| REQ-ARP-039 | MUST | Prevent ARP flooding: at most one request per second for the same target address | RFC 1122 §2.3.2.1 | itest_arp_039_no_flooding |

### Routing and Gateway

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-025 | MUST | For destinations on the local subnet (per subnet mask), ARP the destination IP directly | RFC 1122 §3.3.1.1 | itest_arp_041_broadcast_and_multicast_next_hop, itest_arp_016_request_sent |
| REQ-ARP-026 | MUST | For destinations off-subnet, ARP the gateway IP instead of the destination IP | RFC 1122 §3.3.1.1 | itest_arp_041_broadcast_and_multicast_next_hop, itest_arp_016_request_sent |
| REQ-ARP-027 | MUST | Store gateway MAC in `net_t` (not in per-connection state) | Architecture | itest_arp_011_gateway_learned_only_from_the_gateway |
| REQ-ARP-028 | MAY | Support "gateway-only" mode where ALL packets are sent to gateway MAC regardless of subnet: the application's choice of the MAC it passes to each send | Architecture (minimal config) | — |
| REQ-ARP-040 | MUST | Map IP addresses to Ethernet addresses with ARP: the stack provides `arp_request()`, `arp_next_hop()` and the gateway's MAC; the application sequences them ([arp-resolution.md](../design/arp-resolution.md)) | RFC 1122 §2.3.3 | itest_arp_001_request_for_our_address_answered |
| REQ-ARP-041 | MUST | A datagram to the limited broadcast or a multicast group goes straight to the link layer: its next hop is the destination itself, never the gateway | RFC 1122 §3.3.1.1, RFC 1112 §6.2 | itest_arp_041_broadcast_and_multicast_next_hop |

### Distributed Cache Model

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-029 | MUST | No ARP cache table: a reply goes to the MAC the frame it answers came from, with no lookup and no request, and nothing is remembered of it | Architecture | itest_arp_029_replies_need_no_resolution |
| REQ-ARP-030 | MUST | Each TCP connection stores `{remote_mac[6], mac_valid}` for its peer | Architecture | itest_arp_030_connection_keeps_its_peers_mac |
| REQ-ARP-031 | MAY | Keep the MAC of a UDP peer for a persistent association: the application's, which is handed the sender's MAC with every datagram and passes one to every send | Architecture | — |
| REQ-ARP-032 | SHOULD | Provide callback/scan mechanism for ARP reply handler to find matching connections — **deviation:** a reply fills only `net_t.gateway_mac`; to resolve another address the application points `gateway_ipv4` at it ([arp-resolution.md §3](../design/arp-resolution.md#3-resolving-a-mac-for-an-active-open)) | Architecture | — |

### Gratuitous ARP

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-033 | MAY | Send gratuitous ARP to announce an address: the application calls `arp_request(net, net->ipv4_addr)`; the stack sends none on its own | RFC 5227 §3 | itest_arp_016_request_sent |
| REQ-ARP-034 | MAY | Process received gratuitous ARP: a gratuitous ARP *reply* from the gateway's address updates the gateway's MAC; a gratuitous request does not | RFC 5227 | itest_arp_036_requests_teach_nothing |
| REQ-ARP-035 | SHOULD | Silently discard gratuitous ARP from any other address | Architecture | itest_arp_036_requests_teach_nothing |

### Security Considerations

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-ARP-036 | MUST NOT | MUST NOT update a MAC from the sender fields of an ARP request (ARP cache poisoning defense; RFC 826 would merge the sender of any ARP packet into an existing entry — the stack takes replies only) | Architecture (security) | itest_arp_036_requests_teach_nothing |
| REQ-ARP-037 | SHOULD | Only update the MAC from ARP replies whose sender is the address being resolved | Architecture (security) | itest_arp_011_gateway_learned_only_from_the_gateway |

## Notes

- **ARP storms:** on a busy network most frames received are other hosts' broadcast ARP requests. Each is copied whole into the RX buffer by `net_poll()` and dropped by `arp_input()`; the application must poll often enough to drain the MAC ([mac-hal.md §3](../design/mac-hal.md#3-the-receive-lifecycle-net_poll)).
- **Spoofing:** ARP has no authentication. A reply from the gateway's address is accepted whether or not a request is outstanding, so a forged one redirects off-link traffic until the real gateway replies again.
- **IPv6:** Does not use ARP. IPv6 address resolution uses Neighbor Discovery Protocol (NDP, RFC 4861). See `docs/requirements/ndp.md`.
- **Address Conflict Detection (RFC 5227):** the DHCPv4 client probes the address of an ACK before using it: while `net_t.arp_probe_ip` is set, `arp_input()` sets `net_t.arp_probe_conflict` on an ARP packet that shows another host using the address (REQ-DHCPv4-080). There are no announcements, no defence of an address in use, and no probe of a static address.
