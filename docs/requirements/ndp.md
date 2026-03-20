# NDP Requirements

**Protocol:** Neighbor Discovery Protocol for IPv6  
**Primary RFC:** RFC 4861 — Neighbor Discovery for IP version 6 (IPv6)  
**Supporting:** RFC 4862 — IPv6 Stateless Address Autoconfiguration (SLAAC), RFC 4291 §2.7.1 (solicited-node multicast)  
**Scope:** V2 (IPv6 — NDP is required for any IPv6 implementation on Ethernet)  
**Last updated:** 2026-03-19

## Overview

NDP is the IPv6 equivalent of ARP + ICMP Router Discovery + ICMP Redirect. It provides address resolution (IPv6 → MAC), router discovery, prefix discovery, and redirect functionality. NDP operates over ICMPv6 (Types 133-137) and is mandatory for IPv6 on link layers that support multicast (e.g., Ethernet).

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
| REQ-NDP-001 | MUST | Validate Hop Limit = 255 on all received NDP messages; discard if not 255 | RFC 4861 §6.1.1, §6.1.2, §7.1.1, §7.1.2 | TEST-NDP-001 |
| REQ-NDP-002 | MUST | Validate ICMPv6 Code = 0 for all NDP messages; discard otherwise | RFC 4861 §6.1.1, etc. | TEST-NDP-002 |
| REQ-NDP-003 | MUST | Verify ICMPv6 checksum; discard on failure | RFC 4443 §2.3 | TEST-NDP-003 |
| REQ-NDP-004 | MUST | Parse NDP options in TLV format (Type, Length in 8-byte units, Value) | RFC 4861 §4.6 | TEST-NDP-004 |
| REQ-NDP-005 | MUST | Skip unknown NDP options using Length field | RFC 4861 §4.6 | TEST-NDP-005 |
| REQ-NDP-006 | MUST | Discard messages with NDP option Length = 0 (prevents infinite loop) | RFC 4861 §4.6 | TEST-NDP-006 |

### NDP Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-007 | MUST | Parse Source Link-Layer Address option (Type 1) | RFC 4861 §4.6.1 | TEST-NDP-007 |
| REQ-NDP-008 | MUST | Parse Target Link-Layer Address option (Type 2) | RFC 4861 §4.6.1 | TEST-NDP-008 |
| REQ-NDP-009 | MUST | Parse Prefix Information option (Type 3) — used in Router Advertisements | RFC 4861 §4.6.2 | TEST-NDP-009 |
| REQ-NDP-010 | SHOULD | Parse MTU option (Type 5) — used in Router Advertisements | RFC 4861 §4.6.4 | TEST-NDP-010 |

### Neighbor Solicitation (NS) — Address Resolution (RFC 4861 §7.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-011 | MUST | Respond to Neighbor Solicitation where Target Address matches one of our unicast addresses | RFC 4861 §7.2.3 | TEST-NDP-011 |
| REQ-NDP-012 | MUST | Response is Neighbor Advertisement with: Target = solicited address, Solicited flag = 1, Override flag = 1 | RFC 4861 §7.2.3 | TEST-NDP-012 |
| REQ-NDP-013 | MUST | Include Target Link-Layer Address option (our MAC) in NA response | RFC 4861 §7.2.3 | TEST-NDP-013 |
| REQ-NDP-014 | MUST | Validate NS: ICMPv6 length ≥ 24 bytes (4 reserved + 16 target + 4 min option) | RFC 4861 §7.1.1 | TEST-NDP-014 |
| REQ-NDP-015 | MUST | Validate NS: Target Address MUST NOT be multicast | RFC 4861 §7.1.1 | TEST-NDP-015 |
| REQ-NDP-016 | MUST | If NS Source = :: (unspecified), this is a DAD probe; respond to multicast ff02::1 | RFC 4861 §7.2.3 | TEST-NDP-016 |
| REQ-NDP-017 | MUST | If NS Source ≠ ::, respond unicast to Source Address | RFC 4861 §7.2.3 | TEST-NDP-017 |
| REQ-NDP-018 | MUST | NS for DAD: Solicited flag = 0 in NA response | RFC 4861 §7.2.3 | TEST-NDP-018 |
| REQ-NDP-019 | MUST | Extract Source Link-Layer Address option from NS (for neighbor cache update) | RFC 4861 §7.2.3 | TEST-NDP-019 |

### Neighbor Solicitation — Sending (Address Resolution)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-020 | MUST | Send NS to resolve IPv6 address to MAC (equivalent of ARP request) | RFC 4861 §7.2.2 | TEST-NDP-020 |
| REQ-NDP-021 | MUST | NS for address resolution: Target = destination IPv6 address | RFC 4861 §7.2.2 | TEST-NDP-021 |
| REQ-NDP-022 | MUST | NS destination: solicited-node multicast address of target (ff02::1:ffXX:XXXX) | RFC 4861 §7.2.2 | TEST-NDP-022 |
| REQ-NDP-023 | MUST | NS destination MAC: Ethernet multicast 33:33:ff:XX:XX:XX (from solicited-node address) | RFC 2464 §7 | TEST-NDP-023 |
| REQ-NDP-024 | MUST | Include Source Link-Layer Address option (our MAC) in NS | RFC 4861 §7.2.2 | TEST-NDP-024 |
| REQ-NDP-025 | MUST | Source Address = our link-local or global unicast address | RFC 4861 §7.2.2 | TEST-NDP-025 |
| REQ-NDP-026 | MUST | Hop Limit = 255 | RFC 4861 §7.2.2 | TEST-NDP-026 |

### Neighbor Advertisement (NA) — Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-027 | MUST | Process received NA: extract Target Address and Target Link-Layer Address option | RFC 4861 §7.2.5 | TEST-NDP-027 |
| REQ-NDP-028 | MUST | If NA matches a pending resolution (Target Address = IP we're resolving), store the MAC | RFC 4861 §7.2.5 | TEST-NDP-028 |
| REQ-NDP-029 | MUST | Validate NA: Hop Limit = 255 | RFC 4861 §7.1.2 | TEST-NDP-029 |
| REQ-NDP-030 | MUST | Validate NA: Target Address MUST NOT be multicast | RFC 4861 §7.1.2 | TEST-NDP-030 |
| REQ-NDP-031 | MUST | If Solicited flag = 1, this is a response to our NS — mark neighbor as REACHABLE | RFC 4861 §7.2.5 | TEST-NDP-031 |
| REQ-NDP-032 | MUST | If Override flag = 1, update cached MAC even if already resolved | RFC 4861 §7.2.5 | TEST-NDP-032 |
| REQ-NDP-033 | SHOULD | Silently discard unsolicited NA that doesn't match any pending resolution | Architecture | TEST-NDP-033 |

### Router Solicitation (RS) — Sending

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-034 | MUST | Send Router Solicitation on interface startup (to discover routers quickly) | RFC 4861 §6.3.7 | TEST-NDP-034 |
| REQ-NDP-035 | MUST | RS destination: all-routers multicast (ff02::2) | RFC 4861 §6.3.7 | TEST-NDP-035 |
| REQ-NDP-036 | MUST | Include Source Link-Layer Address option (our MAC) in RS (if source ≠ ::) | RFC 4861 §6.3.7 | TEST-NDP-036 |
| REQ-NDP-037 | MUST | Hop Limit = 255 | RFC 4861 §6.3.7 | TEST-NDP-037 |
| REQ-NDP-038 | MUST | Retransmit RS up to MAX_RTR_SOLICITATIONS (3) times with RTR_SOLICITATION_INTERVAL (4s) delay | RFC 4861 §6.3.7 | TEST-NDP-038 |

### Router Advertisement (RA) — Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-039 | MUST | Process received Router Advertisement (RA) | RFC 4861 §6.3.4 | TEST-NDP-039 |
| REQ-NDP-040 | MUST | Validate RA: Source MUST be link-local address (fe80::/10) | RFC 4861 §6.1.2 | TEST-NDP-040 |
| REQ-NDP-041 | MUST | Validate RA: Hop Limit = 255 | RFC 4861 §6.1.2 | TEST-NDP-041 |
| REQ-NDP-042 | MUST | Extract Cur Hop Limit (if non-zero, use as default Hop Limit for outbound packets) | RFC 4861 §6.3.4 | TEST-NDP-042 |
| REQ-NDP-043 | MUST | Extract Router Lifetime: if > 0, add/update default router; if 0, remove default router | RFC 4861 §6.3.4 | TEST-NDP-043 |
| REQ-NDP-044 | MUST | Extract Source Link-Layer Address option from RA (router's MAC) | RFC 4861 §6.3.4 | TEST-NDP-044 |
| REQ-NDP-045 | MUST | Process Prefix Information options for SLAAC (pass to SLAAC handler) | RFC 4861 §6.3.4, RFC 4862 | TEST-NDP-045 |
| REQ-NDP-046 | SHOULD | Extract MTU option (if present, use as link MTU) | RFC 4861 §6.3.4 | TEST-NDP-046 |
| REQ-NDP-047 | MUST | Extract M flag (Managed Address Configuration) — indicates DHCPv6 should be used | RFC 4861 §4.2 | TEST-NDP-047 |
| REQ-NDP-048 | MUST | Extract O flag (Other Configuration) — indicates DHCPv6 for non-address info | RFC 4861 §4.2 | TEST-NDP-048 |

### Redirect (Type 137) — Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-049 | SHOULD | Process received Redirect messages | RFC 4861 §8.3 | TEST-NDP-049 |
| REQ-NDP-050 | MUST | Validate Redirect: Source MUST be current first-hop router for destination | RFC 4861 §8.1 | TEST-NDP-050 |
| REQ-NDP-051 | MUST | Validate Redirect: Hop Limit = 255 | RFC 4861 §8.1 | TEST-NDP-051 |
| REQ-NDP-052 | SHOULD | Update next-hop for the destination to the specified target | RFC 4861 §8.3 | TEST-NDP-052 |
| REQ-NDP-053 | MAY | Ignore Redirect if not tracking per-destination routes | Architecture | TEST-NDP-053 |

### Neighbor Unreachability Detection (NUD)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-054 | SHOULD | Implement NUD: verify reachability of neighbors | RFC 4861 §7.3 | TEST-NDP-054 |
| REQ-NDP-055 | SHOULD | Track neighbor states: INCOMPLETE, REACHABLE, STALE, DELAY, PROBE | RFC 4861 §7.3.2 | TEST-NDP-055 |
| REQ-NDP-056 | MUST | REACHABLE → STALE after ReachableTime expires | RFC 4861 §7.3.2 | TEST-NDP-056 |
| REQ-NDP-057 | SHOULD | In STALE: on next send, transition to DELAY, then PROBE (send unicast NS) | RFC 4861 §7.3.2 | TEST-NDP-057 |
| REQ-NDP-058 | MUST | In PROBE: send up to MAX_UNICAST_SOLICIT (3) NS; if no NA received, declare unreachable | RFC 4861 §7.3.3 | TEST-NDP-058 |
| REQ-NDP-059 | MAY | Simplify NUD: treat all resolved neighbors as permanently reachable (no state tracking) | Architecture (minimal config) | TEST-NDP-059 |

### Distributed Cache Model (Matching ARP Architecture)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-060 | MUST | No global neighbor cache table — resolved MACs stored in application's connection structures | Architecture | TEST-NDP-060 |
| REQ-NDP-061 | MUST | Each TCP connection stores `{remote_mac[6], mac_valid}` for IPv6 peer | Architecture | TEST-NDP-061 |
| REQ-NDP-062 | MUST | Default router MAC stored in `net_t` | Architecture | TEST-NDP-062 |
| REQ-NDP-063 | SHOULD | Provide callback/scan mechanism for NA handler to find matching connections | Architecture | TEST-NDP-063 |

### Timer Constants (RFC 4861 §10)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-NDP-064 | MUST | MAX_RTR_SOLICITATION_DELAY = 1 second | RFC 4861 §10 | TEST-NDP-064 |
| REQ-NDP-065 | MUST | RTR_SOLICITATION_INTERVAL = 4 seconds | RFC 4861 §10 | TEST-NDP-065 |
| REQ-NDP-066 | MUST | MAX_RTR_SOLICITATIONS = 3 | RFC 4861 §10 | TEST-NDP-066 |
| REQ-NDP-067 | MUST | RETRANS_TIMER = 1 second (default, may be updated from RA) | RFC 4861 §10 | TEST-NDP-067 |
| REQ-NDP-068 | MUST | MAX_MULTICAST_SOLICIT = 3 | RFC 4861 §10 | TEST-NDP-068 |
| REQ-NDP-069 | MUST | MAX_UNICAST_SOLICIT = 3 | RFC 4861 §10 | TEST-NDP-069 |
| REQ-NDP-070 | MUST | REACHABLE_TIME = 30 seconds (default, may be updated from RA) | RFC 4861 §10 | TEST-NDP-070 |

## Notes

- **NDP replaces ARP for IPv6.** There is no ARP for IPv6. Address resolution uses Neighbor Solicitation/Advertisement.
- **Hop Limit = 255 validation** is a critical security measure. It ensures NDP messages originate from the link (not forwarded from another network).
- **Solicited-node multicast** is the IPv6 mechanism to avoid broadcast for address resolution. NS for address resolution goes to ff02::1:ff00:0/104, which maps to Ethernet multicast 33:33:ff:XX:XX:XX.
- **Router discovery** via RS/RA replaces IPv4 router configuration. RA provides prefix info for SLAAC and flags for DHCPv6.
- **NUD (Neighbor Unreachability Detection)** is a significant improvement over ARP — it proactively detects when a neighbor becomes unreachable. The minimal implementation may skip NUD and rely on timeout-based revalidation.
- **Distributed cache model** matches the ARP architecture: no global neighbor cache, MACs stored in connection structures.
