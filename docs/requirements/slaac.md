# SLAAC Requirements

**Protocol:** IPv6 Stateless Address Autoconfiguration  
**Primary RFC:** RFC 4862 — IPv6 Stateless Address Autoconfiguration  
**Supporting:** RFC 4861 §6 (Router Advertisement), RFC 4291 (address format), RFC 7217 (stable privacy addresses)  
**Design:** [ipv6.md](../design/ipv6.md) §3, §6, §7

## Overview

SLAAC allows an IPv6 host to configure a global unicast address automatically using Router Advertisement prefix information, without a DHCPv6 server. The host combines a network prefix (from RA) with an interface identifier (from MAC or random) to form a complete address. SLAAC also includes Duplicate Address Detection (DAD) to verify address uniqueness on the link.

The stack forms its link-local address and its SLAAC addresses from the Modified EUI-64 identifier of the MAC, and runs DAD on every address — link-local, SLAAC, DHCPv6 or added by the application with `ipv6_addr_add()`.

## Address Formation

```
Global unicast address = Prefix (from RA, /64) + Interface Identifier (64 bits)

Interface Identifier:
  Modified EUI-64 from MAC: insert FF:FE, flip U/L bit
    MAC 00:11:22:33:44:55 → IID 0211:22FF:FE33:4455
```

## Requirements

### Link-Local Address Generation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-001 | MUST | Form the link-local address (fe80::/64 + interface identifier) when the interface starts (`ipv6_start()`) | RFC 4862 §5.3 | itest_ipv6_035_link_local_from_the_mac |
| REQ-SLAAC-002 | MUST | Interface identifier: Modified EUI-64 from the MAC | RFC 4862 §5.3, RFC 4291 Appendix A | itest_ipv6_035_link_local_from_the_mac |
| REQ-SLAAC-003 | MUST | Modified EUI-64: insert FF:FE in the middle of the MAC, flip the U/L bit (bit 6 of the first byte) | RFC 4291 Appendix A | itest_ipv6_035_link_local_from_the_mac |
| REQ-SLAAC-004 | MUST | Perform DAD on the link-local address before using it | RFC 4862 §5.4 | itest_slaac_004_link_local_probed, test_ipv6_001_dad_probe_on_start |

### Duplicate Address Detection (DAD) — RFC 4862 §5.4

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-005 | MUST | Send a Neighbor Solicitation for DAD: Source = :: (unspecified), Target = the tentative address | RFC 4862 §5.4.2 | itest_slaac_004_link_local_probed, test_ipv6_001_dad_probe_on_start |
| REQ-SLAAC-006 | MUST | NS destination: the solicited-node multicast address of the tentative address | RFC 4862 §5.4.2 | itest_slaac_004_link_local_probed, test_ipv6_001_dad_probe_on_start |
| REQ-SLAAC-007 | MUST | Wait RetransTimer (1 s) after the last of the DupAddrDetectTransmits solicitations before the address is taken as unique | RFC 4862 §5.4 | itest_slaac_007_assigned_after_retrans_timer |
| REQ-SLAAC-008 | MUST | If a Neighbor Advertisement for the tentative address is received, the address is a duplicate: it is not assigned (`NET_IP6_DUPLICATE`), and never used | RFC 4862 §5.4.4, §5.4.5 | itest_slaac_008_advertisement_means_duplicate, itest_slaac_018_duplicate_global_address, test_ipv6_003_dad_conflict_disables_address |
| REQ-SLAAC-009 | MUST | If a Neighbor Solicitation from :: for the tentative address is received from another node, the address is a duplicate | RFC 4862 §5.4.3 | itest_slaac_009_probe_from_another_means_duplicate |
| REQ-SLAAC-010 | MUST | If nothing is heard during the DAD period, the address is unique: assign it to the interface | RFC 4862 §5.4 | itest_slaac_007_assigned_after_retrans_timer, test_ipv6_002_address_preferred_after_dad |
| REQ-SLAAC-011 | MUST | DupAddrDetectTransmits defaults to 1 (one probe) and is configurable: `NET_IPV6_DAD_TRANSMITS`, at build time | RFC 4862 §5.1 | itest_slaac_004_link_local_probed |
| REQ-SLAAC-012 | MUST | Do not use a tentative address: nothing is sent from it (DAD probes come from ::), packets to it are dropped, and a Neighbor Solicitation for it is not answered | RFC 4862 §5.4, §5.4.3 | itest_slaac_012_tentative_address_not_used, itest_ipv6_010_other_destinations_dropped |
| REQ-SLAAC-013 | MUST | Join the solicited-node multicast group of the tentative address before DAD: the group is received from the moment the address is tentative, and an MLD report precedes the first probe | RFC 4862 §5.4.2 | itest_slaac_004_link_local_probed, itest_slaac_009_probe_from_another_means_duplicate, test_ipv6_028_mld_report_at_start |
| REQ-SLAAC-039 | SHOULD | Delay the first probe (with its MLD report) by a random time up to MAX_RTR_SOLICITATION_DELAY (1 s) when it is the first message from the interface, and when the address comes from a Router Advertisement sent to a multicast address — the link-local address waits so; **deviation:** an address formed from a Router Advertisement is probed at once | RFC 4862 §5.4.2 | itest_slaac_004_link_local_probed |
| REQ-SLAAC-038 | SHOULD | Disable IP operation on the interface when the link-local address formed from the hardware address is a duplicate — **deviation:** IPv6 is not switched off: the link-local address is unused, so link-scope packets have no source and routers are not solicited, but a global address can still be configured and used; `ipv6_addr_state(net, 0)` shows the application the duplicate | RFC 4862 §5.4.5 | — |

### Global Address Configuration from RA

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-014 | MUST | Process the Prefix Information options (Type 3) of Router Advertisements; enabled by default | RFC 4862 §5.5, §5.5.3 | itest_slaac_014_global_address_formed, test_ipv6_023_slaac_global_address |
| REQ-SLAAC-015 | MUST | Ignore a Prefix Information option whose Autonomous flag (A) is not set, or whose prefix is the link-local prefix | RFC 4862 §5.5.3 a), b) | itest_slaac_015_prefixes_not_used |
| REQ-SLAAC-016 | MUST | Ignore the option unless prefix length + interface identifier length = 128: the prefix length must be 64 | RFC 4862 §5.5.3 d) | itest_slaac_015_prefixes_not_used |
| REQ-SLAAC-017 | MUST | Form the global address = prefix + interface identifier, if the prefix is new and its Valid Lifetime is not 0 | RFC 4862 §5.5.3 d) | itest_slaac_014_global_address_formed, test_ipv6_023_slaac_global_address |
| REQ-SLAAC-018 | MUST | Perform DAD on the newly formed global address | RFC 4862 §5.4 | itest_slaac_014_global_address_formed, itest_slaac_018_duplicate_global_address, test_ipv6_023_slaac_global_address |
| REQ-SLAAC-019 | MUST | Take the address's valid lifetime from the Valid Lifetime of the Prefix Information option (0xFFFFFFFF: infinite) | RFC 4862 §5.5.3 d) | itest_slaac_019_lifetimes, itest_slaac_019_infinite_lifetime |
| REQ-SLAAC-020 | MUST | Take the address's preferred lifetime from the Preferred Lifetime of the option | RFC 4862 §5.5.3 d) | itest_slaac_019_lifetimes |
| REQ-SLAAC-021 | MUST | Ignore a Prefix Information option whose Preferred Lifetime is greater than its Valid Lifetime | RFC 4862 §5.5.3 c) | itest_slaac_015_prefixes_not_used |
| REQ-SLAAC-022 | MUST | When the valid lifetime expires the address is invalid: not used as a source, not recognized as a destination | RFC 4862 §5.5.4 | itest_slaac_019_lifetimes |
| REQ-SLAAC-023 | MUST | When the preferred lifetime expires the address is deprecated: packets to it are still accepted and answered from it; it is chosen as the source of a new packet only when no preferred address fits | RFC 4862 §5.5.4 | itest_slaac_019_lifetimes, itest_ipv6_041_deprecated_source_as_last_resort |

### Prefix Lifetime Updates

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-024 | MUST | An advertisement of the prefix of an existing address resets the address's preferred lifetime to the advertised one, whatever happens to the valid lifetime | RFC 4862 §5.5.3 e) | itest_slaac_024_preferred_lifetime_reset |
| REQ-SLAAC-025 | MUST | If the advertised Valid Lifetime is greater than the remaining valid lifetime, take it | RFC 4862 §5.5.3 e) 1 | itest_slaac_025_longer_valid_lifetime_taken |
| REQ-SLAAC-026 | MUST | If the advertised Valid Lifetime is greater than 2 hours, take it | RFC 4862 §5.5.3 e) 1 | itest_slaac_026_valid_lifetime_above_two_hours_taken |
| REQ-SLAAC-027 | MUST | Otherwise — an advertised Valid Lifetime of at most 2 hours and no greater than the remaining one — leave a remaining lifetime of 2 hours or less as it is, and cut a longer one to 2 hours | RFC 4862 §5.5.3 e) 2, 3 | itest_slaac_027_two_hour_rule |

### Router Discovery Integration

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-028 | SHOULD | Send Router Solicitations at start-up to obtain an advertisement quickly ([ndp.md](ndp.md), REQ-NDP-034) | RFC 4862 §5.5.1, RFC 4861 §6.3.7 | itest_ndp_034_router_solicitations |
| REQ-SLAAC-029 | MUST | Process Router Advertisements to obtain prefix and router information | RFC 4862 §5.5.1, §5.5.3 | itest_ndp_039_default_router_learned |
| REQ-SLAAC-030 | MUST | Send packets for off-link destinations to the default router: `ipv6_on_link()` tells the application whether a destination is on the link, and `ipv6_router_mac()` gives the router's MAC for those that are not (NULL without a router) | RFC 4861 §5.2 | itest_slaac_030_next_hop |
| REQ-SLAAC-031 | MUST | Store the default router's MAC (from the RA's Source Link-Layer Address option) | Architecture | itest_ndp_039_default_router_learned |

### Privacy Extensions (RFC 7217, RFC 4941) — not implemented

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-032 | MAY | Support stable privacy addresses (RFC 7217) instead of EUI-64 | RFC 7217 | — (not implemented) |
| REQ-SLAAC-033 | MAY | Support temporary addresses (RFC 4941) for privacy | RFC 4941 | — (not implemented) |
| REQ-SLAAC-034 | SHOULD | Prefer stable privacy addresses (RFC 7217) over EUI-64 — **deviation:** the interface identifier is the Modified EUI-64 of the MAC: no secret key or stable storage is needed, and the address is predictable from the device's label | RFC 7217 §1 | — (not implemented) |

### Interaction with DHCPv6

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-SLAAC-035 | MAY | When an RA has the M flag, obtain an address by DHCPv6: the application sees the flag (REQ-NDP-047) and starts the client, `dhcpv6_client_start(…, DHCPV6_MODE_STATEFUL)` | RFC 4861 §4.2 | itest_ndp_047_managed_and_other_flags |
| REQ-SLAAC-036 | MAY | When an RA has the O flag, obtain other configuration (DNS, …) by DHCPv6: the application sees the flag (REQ-NDP-048) and starts the client, `dhcpv6_client_start(…, DHCPV6_MODE_STATELESS)` | RFC 4861 §4.2 | itest_ndp_047_managed_and_other_flags |
| REQ-SLAAC-037 | SHOULD | SLAAC and DHCPv6 addresses coexist, given address slots: with the default `NET_IPV6_ADDRS` of 2 there is one global slot, and the first address to take it keeps it | RFC 4862 §5.6 | itest_slaac_037_one_global_slot |

## Notes

- **SLAAC is the simplest way to get an IPv6 global address.** No server needed — just a router sending RAs.
- **DAD is mandatory** but lightweight: one NS probe, 1-second wait. If no conflict, done.
- **EUI-64 exposes the MAC address** in the IPv6 address, which is a privacy concern. RFC 7217 provides an alternative that generates stable but opaque identifiers. For embedded devices that aren't mobile, EUI-64 is often acceptable.
- **The prefix must be /64**: the interface identifier is 64 bits.
- **Small memory footprint:** the interface holds `NET_IPV6_ADDRS` addresses (default 2: the link-local address and one global) with their lifetimes, and one default router.
- **A duplicate address keeps its slot** until its valid lifetime runs out (an address with an infinite lifetime: until `ipv6_addr_remove()`); Router Advertisements do not refresh it, so a SLAAC address is formed and probed again only after that.
- **No DNS from SLAAC:** SLAAC provides addresses but not DNS servers. DNS comes from DHCPv6 (O flag); the RDNSS option of RFC 8106 is not parsed.
