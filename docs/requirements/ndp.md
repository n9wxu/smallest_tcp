# NDP Requirements

**Protocol:** Neighbor Discovery Protocol for IPv6  
**Primary RFC:** RFC 4861 — Neighbor Discovery for IP version 6 (IPv6)  
**Supporting:** RFC 4862 — IPv6 Stateless Address Autoconfiguration (SLAAC), RFC 4291 §2.7.1 (solicited-node multicast), RFC 5942 — the IPv6 subnet model (on-link determination), RFC 8504 §5.4 (node requirements)  
**Design:** [ipv6.md](../design/ipv6.md) §6, §7; [arp-resolution.md](../design/arp-resolution.md) §5

## Overview

NDP is the IPv6 equivalent of ARP + ICMP Router Discovery + ICMP Redirect. It provides address resolution (IPv6 → MAC), router discovery, prefix discovery, and redirect functionality. NDP operates over ICMPv6 (Types 133-137) and is mandatory for IPv6 on link layers that support multicast (e.g., Ethernet).

The stack is a host without a neighbour cache: it answers solicitations for its addresses, runs Duplicate Address Detection ([slaac.md](slaac.md)), solicits routers and takes the default router, the hop limit and the prefixes from Router Advertisements. It does not record the answers to its own solicitations, runs no Neighbor Unreachability Detection and ignores Redirects; the rows below that it leaves out say so as deviations.

## Message Types

| ICMPv6 Type | Name | Abbreviation | Direction |
|---|---|---|---|
| 133 | Router Solicitation | RS | Host → Router |
| 134 | Router Advertisement | RA | Router → Host(s) |
| 135 | Neighbor Solicitation | NS | Host → Host/Multicast |
| 136 | Neighbor Advertisement | NA | Host → Host/Multicast |
| 137 | Redirect | — | Router → Host |

All NDP messages are ICMPv6 with Hop Limit = 255 (link-local scope enforcement).

## Requirements

### General NDP Validation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-001 | MUST | Validate Hop Limit = 255 on all received NDP messages; discard if not 255 | RFC 4861 §6.1.2, §7.1.1, §7.1.2 | itest_ndp_001_hop_limit_255_required, test_ipv6_006_ns_hop_limit_not_255_ignored |
| REQ-NDP-002 | MUST | Validate ICMPv6 Code = 0 for all NDP messages; discard otherwise | RFC 4861 §6.1.2, §7.1.1, §7.1.2 | itest_ndp_002_code_zero_required |
| REQ-NDP-003 | MUST | Verify ICMPv6 checksum; discard on failure | RFC 4861 §6.1.2, §7.1.1, §7.1.2, RFC 4443 §2.3 | itest_ndp_003_checksum_required |
| REQ-NDP-004 | MUST | Parse NDP options in TLV format (Type, Length in 8-octet units, Value) | RFC 4861 §4.6 | itest_ndp_004_options_walked |
| REQ-NDP-005 | MUST | Ignore unrecognized options, skipping them by their Length, and process the rest of the message | RFC 4861 §4.6, §6.1.2, §7.1.1 | itest_ndp_004_options_walked |
| REQ-NDP-006 | MUST | Discard a message that contains an option of Length 0 (or one that runs past the end of the message) | RFC 4861 §4.6 | itest_ndp_006_zero_length_option_discards |

### NDP Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-007 | MUST | Parse Source Link-Layer Address option (Type 1) | RFC 4861 §4.6.1 | itest_ndp_004_options_walked |
| REQ-NDP-008 | MUST | Parse Target Link-Layer Address option (Type 2) — **deviation:** the option is validated with the others (REQ-NDP-006) but its address is not recorded: there is no neighbour cache (REQ-NDP-060) | RFC 4861 §4.6.1 | itest_ndp_033_unsolicited_advertisement_ignored |
| REQ-NDP-009 | MUST | Parse Prefix Information option (Type 3) of Router Advertisements | RFC 4861 §4.6.2 | itest_slaac_014_global_address_formed |
| REQ-NDP-010 | SHOULD | Parse MTU option (Type 5) of Router Advertisements — **deviation:** ignored; the link MTU is `net->mtu`, the Ethernet MTU unless the application sets it | RFC 4861 §4.6.4 | itest_ndp_046_mtu_option_ignored |

### Neighbor Solicitation (NS) — Received (RFC 4861 §7.2.3, §7.2.4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-011 | MUST | Respond to a Neighbor Solicitation whose Target Address is one of our assigned unicast addresses; discard one for any other target | RFC 4861 §7.2.3 | itest_ndp_011_solicitation_answered, itest_ndp_011_each_address_of_ours_and_no_other, test_ipv6_005_ns_answered |
| REQ-NDP-012 | MUST | The response is a Neighbor Advertisement with Target = the solicited address, Router flag = 0, Solicited flag = 1, Override flag = 1 | RFC 4861 §7.2.4 | itest_ndp_011_solicitation_answered, test_ipv6_005_ns_answered |
| REQ-NDP-013 | MUST | Include a Target Link-Layer Address option (our MAC) in the advertisement | RFC 4861 §7.2.4 | itest_ndp_011_solicitation_answered, test_ipv6_005_ns_answered |
| REQ-NDP-014 | MUST | Validate NS: ICMPv6 length ≥ 24 octets | RFC 4861 §7.1.1 | itest_ndp_014_solicitation_validated |
| REQ-NDP-015 | MUST | Validate NS: Target Address is not a multicast address | RFC 4861 §7.1.1 | itest_ndp_014_solicitation_validated |
| REQ-NDP-072 | MUST | Validate NS: if the source is the unspecified address, the destination is a solicited-node multicast address and there is no Source Link-Layer Address option | RFC 4861 §7.1.1 | itest_ndp_072_solicitation_from_unspecified_validated |
| REQ-NDP-016 | MUST | If the NS source is :: (another node's DAD probe for our address), send the advertisement to all-nodes (ff02::1) | RFC 4861 §7.2.4 | itest_ndp_016_dad_probe_of_our_address_defended, test_ipv6_004_dad_probe_from_others_defended |
| REQ-NDP-017 | MUST | If the NS source is not ::, unicast the advertisement to that source | RFC 4861 §7.2.4 | itest_ndp_011_solicitation_answered, test_ipv6_005_ns_answered |
| REQ-NDP-018 | MUST | In the advertisement that answers an NS from ::, Solicited flag = 0 | RFC 4861 §7.2.4 | itest_ndp_016_dad_probe_of_our_address_defended, test_ipv6_004_dad_probe_from_others_defended |
| REQ-NDP-019 | SHOULD | Use the solicitation's Source Link-Layer Address option: the advertisement goes to that MAC, or to the frame's source without the option. No Neighbor Cache entry is created (REQ-NDP-060) | RFC 4861 §7.2.3 | itest_ndp_019_answer_to_the_frame_source_without_slla, test_ipv6_005_ns_answered |

### Neighbor Solicitation — Sending (Address Resolution, RFC 4861 §7.2.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-020 | MUST | Send a Neighbor Solicitation to resolve an on-link IPv6 address whose link-layer address is unknown, holding the packet until it is resolved — **deviation:** `ndp_send_ns(net, target, 0)` sends one solicitation when the application calls it; no packet is queued and the answer is not recorded (REQ-NDP-027): the application supplies the peer's MAC to `udp6_send()` and `tcp6_connect()` | RFC 4861 §7.2.2 | itest_ndp_020_solicitation_sent, itest_ndp_027_advertisements_not_recorded |
| REQ-NDP-021 | MUST | NS for address resolution: Target = the address to resolve | RFC 4861 §7.2.2 | itest_ndp_020_solicitation_sent |
| REQ-NDP-022 | MUST | NS destination: the solicited-node multicast address of the target (ff02::1:ffXX:XXXX) | RFC 4861 §7.2.2 | itest_ndp_020_solicitation_sent |
| REQ-NDP-023 | MUST | NS destination MAC: Ethernet multicast 33:33:ff:XX:XX:XX (from the solicited-node address) | RFC 2464 §7 | itest_ndp_020_solicitation_sent |
| REQ-NDP-024 | MUST | Include a Source Link-Layer Address option (our MAC) in an NS sent to a solicited-node address | RFC 4861 §7.2.2 | itest_ndp_020_solicitation_sent |
| REQ-NDP-025 | MUST | Source Address = one of our assigned addresses: the link-local one for a link-local target, else a global one (`ipv6_src_for()`) | RFC 4861 §7.2.2 | itest_ndp_020_solicitation_sent |
| REQ-NDP-026 | MUST | Hop Limit = 255 | RFC 4861 §4.3 | itest_ndp_020_solicitation_sent |

### Neighbor Advertisement (NA) — Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-027 | MUST | Process a received NA: take its Target Address and Target Link-Layer Address option to the target's Neighbor Cache entry — **deviation:** there is no neighbour cache; an NA only matters when it claims a tentative address of ours (REQ-SLAAC-008) | RFC 4861 §7.2.5 | itest_ndp_027_advertisements_not_recorded |
| REQ-NDP-028 | MUST | If the NA answers a pending resolution, record the link-layer address — **deviation:** not recorded (REQ-NDP-027) | RFC 4861 §7.2.5 | itest_ndp_027_advertisements_not_recorded |
| REQ-NDP-029 | MUST | Validate NA: Hop Limit = 255 | RFC 4861 §7.1.2 | itest_ndp_001_hop_limit_255_required |
| REQ-NDP-030 | MUST | Validate NA: Target Address is not a multicast address | RFC 4861 §7.1.2 | — (not observable: no address of ours is multicast, and an advertisement does nothing but mark a tentative address of ours) |
| REQ-NDP-071 | MUST | Validate NA: ICMPv6 length ≥ 24 octets; the Solicited flag is 0 if the destination is a multicast address; every option has a non-zero length | RFC 4861 §7.1.2 | itest_ndp_071_advertisement_validated |
| REQ-NDP-031 | MUST | If the Solicited flag is 1, mark the neighbour REACHABLE — **deviation:** no neighbour state is kept (REQ-NDP-059) | RFC 4861 §7.2.5 | itest_ndp_027_advertisements_not_recorded |
| REQ-NDP-032 | MUST | If the Override flag is 1, replace the cached link-layer address — **deviation:** nothing is cached (REQ-NDP-027) | RFC 4861 §7.2.5 | itest_ndp_027_advertisements_not_recorded |
| REQ-NDP-033 | SHOULD | Silently discard an NA for which no Neighbor Cache entry exists: every NA that does not claim a tentative address of ours is discarded | RFC 4861 §7.2.5 | itest_ndp_033_unsolicited_advertisement_ignored |

### Router Solicitation (RS) — Sending

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-034 | SHOULD | Send Router Solicitations when the interface starts, to find routers without waiting for an unsolicited advertisement | RFC 4861 §6.3.7 | itest_ndp_034_router_solicitations, test_ipv6_022_router_solicitation |
| REQ-NDP-035 | MUST | RS destination: all-routers multicast (ff02::2) | RFC 4861 §6.3.7 | itest_ndp_034_router_solicitations, test_ipv6_022_router_solicitation |
| REQ-NDP-036 | SHOULD | Include a Source Link-Layer Address option (our MAC) in an RS whose source is not ::; the stack solicits from its link-local address | RFC 4861 §6.3.7 | itest_ndp_034_router_solicitations, test_ipv6_022_router_solicitation |
| REQ-NDP-037 | MUST | Hop Limit = 255 | RFC 4861 §4.1 | itest_ndp_034_router_solicitations, test_ipv6_022_router_solicitation |
| REQ-NDP-038 | SHOULD | Send up to MAX_RTR_SOLICITATIONS (3) solicitations, each at least RTR_SOLICITATION_INTERVAL (4 s) after the one before (`NDP_MAX_RTR_SOLICITATIONS`; 0 sends none) | RFC 4861 §6.3.7 | itest_ndp_034_router_solicitations |
| REQ-NDP-073 | MUST | Stop soliciting once a valid Router Advertisement with a non-zero Router Lifetime arrives; the stack stops at any valid advertisement | RFC 4861 §6.3.7 | itest_ndp_073_advertisement_ends_solicitations |

### Router Advertisement (RA) — Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-039 | MUST | Process received Router Advertisements | RFC 4861 §6.3.4, RFC 8504 §5.4 | itest_ndp_039_default_router_learned |
| REQ-NDP-040 | MUST | Validate RA: the source is a link-local address (fe80::/10), the ICMPv6 length is ≥ 16 octets | RFC 4861 §6.1.2 | itest_ndp_040_advertisement_validated |
| REQ-NDP-041 | MUST | Validate RA: Hop Limit = 255 | RFC 4861 §6.1.2 | itest_ndp_001_hop_limit_255_required |
| REQ-NDP-042 | SHOULD | Take a non-zero Cur Hop Limit as the Hop Limit of outgoing packets; zero leaves the value in use unchanged | RFC 4861 §6.3.4 | itest_ndp_042_cur_hop_limit, test_ipv6_024_ra_cur_hop_limit |
| REQ-NDP-043 | MUST | Router Lifetime: non-zero adds the sender as a default router or renews it, for that many seconds; zero from a known router removes it at once | RFC 4861 §6.3.4, §6.3.5 | itest_ndp_043_router_lifetime |
| REQ-NDP-074 | MUST | Retain at least two default routers — **deviation:** one is kept, the last to advertise a non-zero Router Lifetime; 22 bytes of RAM per router, and no reachability state by which to choose between two | RFC 4861 §6.3.4 | itest_ndp_074_one_default_router |
| REQ-NDP-044 | SHOULD | Record the router's link-layer address from the Source Link-Layer Address option of the RA; without the option the stack takes the frame's source MAC | RFC 4861 §6.3.4 | itest_ndp_039_default_router_learned, itest_ndp_044_router_mac_from_the_frame_without_slla |
| REQ-NDP-045 | MUST | Process Prefix Information options for address autoconfiguration ([slaac.md](slaac.md)) | RFC 4861 §6.3.4, RFC 4862 §5.5.3 | itest_slaac_014_global_address_formed, test_ipv6_023_slaac_global_address |
| REQ-NDP-075 | MUST | On-link determination: only the link-local prefix and prefixes advertised with the on-link (L) flag are on-link; configuring an address does not make its prefix on-link — **deviation:** no Prefix List is kept: `ipv6_on_link()` treats the /64 of every configured global address as on-link, whatever the L flag said and whether the address came from SLAAC, DHCPv6 or the application | RFC 4861 §6.3.4, RFC 5942 §4 | itest_slaac_030_next_hop |
| REQ-NDP-046 | SHOULD | Take the MTU option as the link MTU — **deviation:** ignored (REQ-NDP-010) | RFC 4861 §6.3.4 | itest_ndp_046_mtu_option_ignored |
| REQ-NDP-076 | SHOULD | Take non-zero Reachable Time and Retrans Timer fields — **deviation:** ignored: there is no reachability state, and RetransTimer is fixed at 1 s | RFC 4861 §6.3.4 | — |
| REQ-NDP-047 | MAY | Give the M flag (Managed Address Configuration: addresses are available by DHCPv6) to the application: `net->ip6.ra_flags & NDP_RA_MANAGED`, of the last advertisement | RFC 4861 §4.2 | itest_ndp_047_managed_and_other_flags |
| REQ-NDP-048 | MAY | Give the O flag (Other Configuration: other information is available by DHCPv6) to the application: `net->ip6.ra_flags & NDP_RA_OTHER` | RFC 4861 §4.2 | itest_ndp_047_managed_and_other_flags |

### Redirect (Type 137) — Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-049 | SHOULD | Process received Redirect messages — **deviation:** every Redirect is discarded: there are no per-destination routes to update | RFC 4861 §8.3, RFC 8504 §5.4 | itest_ndp_049_redirect_ignored |
| REQ-NDP-050 | MUST | Discard a Redirect whose source is not the current first-hop router for the destination (met by discarding every Redirect) | RFC 4861 §8.1 | itest_ndp_049_redirect_ignored |
| REQ-NDP-051 | MUST | Discard a Redirect whose Hop Limit is not 255 (met by discarding every Redirect) | RFC 4861 §8.1 | itest_ndp_049_redirect_ignored |
| REQ-NDP-052 | SHOULD | Update the next hop for the destination to the Redirect's target — **deviation:** not done (REQ-NDP-049) | RFC 4861 §8.3 | itest_ndp_049_redirect_ignored |
| REQ-NDP-053 | MAY | Ignore Redirects when no per-destination routes are kept | Architecture | itest_ndp_049_redirect_ignored |

### Neighbor Unreachability Detection (NUD) — not implemented

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-054 | MUST | Implement NUD: verify the reachability of the neighbours packets are sent to — **deviation:** not implemented; a neighbour is assumed reachable (REQ-NDP-059), and a peer that goes away shows as TCP retransmission time-outs | RFC 4861 §7.3, RFC 8504 §5.4 | itest_ndp_054_no_unreachability_detection |
| REQ-NDP-055 | SHOULD | Track neighbour states: INCOMPLETE, REACHABLE, STALE, DELAY, PROBE — **deviation:** no states (REQ-NDP-054) | RFC 4861 §7.3.2 | itest_ndp_054_no_unreachability_detection |
| REQ-NDP-056 | MUST | REACHABLE → STALE after ReachableTime — **deviation:** no states (REQ-NDP-054) | RFC 4861 §7.3.2 | itest_ndp_054_no_unreachability_detection |
| REQ-NDP-057 | SHOULD | In STALE: on the next send, DELAY, then PROBE (unicast NS) — **deviation:** no states (REQ-NDP-054) | RFC 4861 §7.3.2 | itest_ndp_054_no_unreachability_detection |
| REQ-NDP-058 | MUST | In PROBE: up to MAX_UNICAST_SOLICIT (3) NS; without an NA the neighbour is unreachable — **deviation:** no probes (REQ-NDP-054) | RFC 4861 §7.3.3 | itest_ndp_054_no_unreachability_detection |
| REQ-NDP-059 | MAY | Simplify NUD: treat every neighbour as reachable (no state tracking) | Architecture (minimal config) | itest_ndp_054_no_unreachability_detection |

### Distributed Cache Model (Matching ARP Architecture)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-060 | MUST | No global neighbour cache: a reply goes to the MAC its request came from | Architecture | itest_ndp_060_no_neighbour_cache |
| REQ-NDP-061 | MUST | Each TCP connection stores `{remote_mac[6], mac_valid}` for its IPv6 peer | Architecture | itest_ndp_061_connection_keeps_the_peer_mac |
| REQ-NDP-062 | MUST | The default router's MAC is stored in `net_t` (`net->ip6.router`, read with `ipv6_router_mac()`) | Architecture | itest_ndp_039_default_router_learned |
| REQ-NDP-063 | SHOULD | Provide a callback/scan mechanism for the NA handler to find matching connections — **deviation:** none; advertisements are not matched against connections (REQ-NDP-027) | Architecture | — |

### Timer Constants (RFC 4861 §10)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-064 | MUST | MAX_RTR_SOLICITATION_DELAY = 1 second | RFC 4861 §10 | itest_ndp_034_router_solicitations |
| REQ-NDP-065 | MUST | RTR_SOLICITATION_INTERVAL = 4 seconds | RFC 4861 §10 | itest_ndp_034_router_solicitations |
| REQ-NDP-066 | MUST | MAX_RTR_SOLICITATIONS = 3 | RFC 4861 §10 | itest_ndp_034_router_solicitations |
| REQ-NDP-067 | MUST | RETRANS_TIMER = 1 second; the stack keeps this default (REQ-NDP-076) | RFC 4861 §10 | itest_slaac_004_link_local_probed, itest_slaac_007_assigned_after_retrans_timer |
| REQ-NDP-068 | MUST | MAX_MULTICAST_SOLICIT = 3 — **deviation:** the stack does not repeat an address-resolution solicitation; each `ndp_send_ns()` call sends one (REQ-NDP-020) | RFC 4861 §10 | itest_ndp_027_advertisements_not_recorded |
| REQ-NDP-069 | MUST | MAX_UNICAST_SOLICIT = 3 — **deviation:** no NUD probes (REQ-NDP-054) | RFC 4861 §10 | itest_ndp_054_no_unreachability_detection |
| REQ-NDP-070 | MUST | REACHABLE_TIME = 30 seconds — **deviation:** no reachability state (REQ-NDP-054) | RFC 4861 §10 | itest_ndp_054_no_unreachability_detection |

## Notes

- **NDP replaces ARP for IPv6.** There is no ARP for IPv6. Address resolution uses Neighbor Solicitation/Advertisement.
- **Hop Limit = 255 validation** is a critical security measure. It ensures NDP messages originate from the link (not forwarded from another network).
- **Solicited-node multicast** is the IPv6 mechanism to avoid broadcast for address resolution. NS for address resolution goes to ff02::1:ff00:0/104, which maps to Ethernet multicast 33:33:ff:XX:XX:XX.
- **Router discovery** via RS/RA replaces IPv4 router configuration. RA provides prefix info for SLAAC and flags for DHCPv6.
- **Distributed cache model** matches the ARP architecture: no global neighbour cache; MACs are stored in connection structures, and the default router's in `net_t`.
- **Opening a conversation with an on-link IPv6 peer** needs its MAC from elsewhere — typically a packet the peer sent first — because the answer to `ndp_send_ns()` is not recorded. Off-link peers are reached through `ipv6_router_mac()`.
