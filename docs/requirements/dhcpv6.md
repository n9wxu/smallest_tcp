# DHCPv6 Requirements

**Protocol:** Dynamic Host Configuration Protocol for IPv6  
**Primary RFC:** RFC 8415 — Dynamic Host Configuration Protocol for IPv6 (DHCPv6)  
**Supporting:** RFC 4861 §4.2 (M/O flags), RFC 3646 — DNS Configuration Options for DHCPv6  
**Supersession:** RFC 8415 supersedes RFC 3315, RFC 3633, RFC 3736  
**Design:** [ipv6.md](../design/ipv6.md) §8

## Overview

DHCPv6 provides IPv6 address assignment (when RA M flag = 1) and other configuration such as DNS servers (when RA O flag = 1). Unlike DHCPv4, DHCPv6 uses UDP on ports 546 (client) and 547 (server), and communication is via link-local multicast rather than broadcast. The stack's client (`dhcpv6_client.c`, its own library) runs in stateless mode (Information-request for DNS and other configuration) or stateful mode (Solicit/Advertise/Request/Reply for one non-temporary address, then Renew, Rebind and Release). The application starts it in the mode the Router Advertisement's flags ask for.

## Message Format

```
Offset  Size  Field
  0      1    msg-type
  1      3    transaction-id
  4     var   options (TLV: option-code (2) + option-len (2) + option-data (var))
```

## Message Types

| Type | Name | Direction | Client |
|---|---|---|---|
| 1 | SOLICIT | Client → Server (multicast) | sent |
| 2 | ADVERTISE | Server → Client | processed |
| 3 | REQUEST | Client → Server (multicast) | sent |
| 4 | CONFIRM | Client → Server (multicast) | not sent |
| 5 | RENEW | Client → Server (multicast) | sent |
| 6 | REBIND | Client → Server (multicast) | sent |
| 7 | REPLY | Server → Client | processed |
| 8 | RELEASE | Client → Server (multicast) | sent |
| 9 | DECLINE | Client → Server (multicast) | not sent |
| 10 | RECONFIGURE | Server → Client | ignored |
| 11 | INFORMATION-REQUEST | Client → Server (multicast) | sent |

## Requirements

### Stateless DHCPv6 (Information-Request — RA O flag)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-001 | MUST | Support stateless DHCPv6: send INFORMATION-REQUEST (type 11) when started for other configuration — `dhcpv6_client_start(…, DHCPV6_MODE_STATELESS)`, which the application calls when an RA has the O flag | RFC 8415 §6.1, §18.2.6 | itest_dhcpv6_001_information_request, test_ipv6_027_dhcpv6_stateless |
| REQ-DHCPv6-002 | MUST | INFORMATION-REQUEST sent to All_DHCP_Relay_Agents_and_Servers (ff02::1:2) | RFC 8415 §7.1, §16 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-003 | MUST | Source port = 546, destination port = 547 | RFC 8415 §7.2 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-004 | SHOULD | Include Client Identifier option (option 1) with DUID | RFC 8415 §18.2.6 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-005 | MUST | Include Option Request option (option 6) asking for INF_MAX_RT (83), the Information Refresh Time (32) and the options wanted: DNS servers (23) and the search list (24) | RFC 8415 §18.2.6, §21.23, §21.25 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-006 | MUST | Include Elapsed Time option (option 8) | RFC 8415 §18.2.6 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-007 | MUST | Process REPLY (type 7) to INFORMATION-REQUEST: its top-level options go to the application's option handlers, with `DHCPV6_EVT_INFO` | RFC 8415 §18.2.10.4 | itest_dhcpv6_007_reply_configures, test_ipv6_027_dhcpv6_stateless |
| REQ-DHCPv6-008 | MUST | Give the DNS Recursive Name Server option (option 23) to the application | RFC 3646 §3, RFC 8504 §8.1 | itest_dhcpv6_007_reply_configures |
| REQ-DHCPv6-009 | MAY | Give the Domain Search List option (option 24) to the application | RFC 3646 §4 | itest_dhcpv6_007_reply_configures |
| REQ-DHCPv6-054 | MUST | Refresh the information after the Information Refresh Time of the Reply: IRT_DEFAULT (86400 s) without the option, IRT_MINIMUM (600 s) for a smaller value | RFC 8415 §21.23 | itest_dhcpv6_054_information_refreshed |
| REQ-DHCPv6-055 | MUST | Delay the Information-request that refreshes by a random time between 0 and INF_MAX_DELAY (1 s) | RFC 8415 §21.23 | itest_dhcpv6_055_refresh_delayed_at_random |

### Stateful DHCPv6 (Address Assignment — RA M flag)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-010 | MAY | Support stateful DHCPv6 for address assignment: `dhcpv6_client_start(…, DHCPV6_MODE_STATEFUL)`, which the application calls when an RA has the M flag | RFC 8415 §6.2 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-011 | MUST | SOLICIT → ADVERTISE → REQUEST → REPLY four-message exchange | RFC 8415 §18.2.1, §18.2.2 | itest_dhcpv6_011_address_assigned, test_ipv6_026_dhcpv6_stateful |
| REQ-DHCPv6-012 | MAY | Support two-message exchange: SOLICIT (with Rapid Commit) → REPLY | RFC 8415 §18.2.1 | — (not implemented) |

### SOLICIT (Type 1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-013 | MUST | Send SOLICIT to ff02::1:2 on port 547 | RFC 8415 §18.2.1 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-014 | MUST | Include Client Identifier (option 1) | RFC 8415 §18.2.1 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-015 | MUST | Include IA_NA (Identity Association for Non-temporary Addresses, option 3), without addresses; the IAID is the low four bytes of the MAC | RFC 8415 §18.2.1 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-016 | MUST | Include Elapsed Time (option 8) | RFC 8415 §18.2.1 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-017 | MUST | Include Option Request (option 6) asking for SOL_MAX_RT (82) and the options wanted | RFC 8415 §18.2.1, §21.24 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-018 | MAY | Include Rapid Commit option (option 14) for two-message exchange | RFC 8415 §18.2.1 | — (not implemented) |
| REQ-DHCPv6-048 | MUST | Delay the first Information-request by a random time between 0 and INF_MAX_DELAY (1 s) — and (SHOULD) the first Solicit by one between 0 and SOL_MAX_DELAY (1 s) | RFC 8415 §18.2.6, §18.2.1 | itest_dhcpv6_048_start_delay_at_most_a_second |

### ADVERTISE Processing (Type 2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-019 | MUST | Discard an Advertise whose transaction-id is not the Solicit's | RFC 8415 §16.3 | itest_dhcpv6_021_advertise_offers |
| REQ-DHCPv6-020 | MUST | Take the Server Identifier (option 2) of the Advertise: a DUID of up to `DHCPV6_MAX_DUID` (20) bytes | RFC 8415 §18.2.9 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-021 | MUST | Take the offered address from the IA Address (option 5) in the IA_NA of our IAID; ignore an Advertise that offers no address | RFC 8415 §18.2.9 | itest_dhcpv6_021_advertise_offers, itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-022 | MUST | Collect Advertise messages for the first RT, unless one has a Preference of 255, and choose the server of highest preference — **deviation:** the first Advertise that offers an address is taken at once, and the Preference option is not read: one server's offer needs no memory, and a small device is content with any address | RFC 8415 §18.2.1, §18.2.9 | itest_dhcpv6_022_first_advertise_taken |
| REQ-DHCPv6-052 | MUST | Discard an Advertise or a Reply without a Server Identifier, without a Client Identifier, or whose Client Identifier is not ours | RFC 8415 §16.3, §16.10 | itest_dhcpv6_019_replies_validated, itest_dhcpv6_021_advertise_offers |
| REQ-DHCPv6-053 | MUST | Take SOL_MAX_RT and INF_MAX_RT (60 to 86400 s) from an Advertise or a Reply, even one whose Status Code says failure or that offers no address; ignore values outside that range | RFC 8415 §18.2.9, §18.2.10, §21.24, §21.25 | itest_dhcpv6_053_sol_max_rt_from_a_refusing_server, itest_dhcpv6_053_sol_max_rt_out_of_range_ignored |

### REQUEST (Type 3)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-023 | MUST | Send REQUEST to ff02::1:2 (multicast, not unicast to server) | RFC 8415 §16, §18.2.2 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-024 | MUST | Include Server Identifier from Advertise | RFC 8415 §18.2.2 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-025 | MUST | Include Client Identifier | RFC 8415 §18.2.2 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-026 | MUST | Include IA_NA with requested address from Advertise | RFC 8415 §18.2.2 | itest_dhcpv6_011_address_assigned |

### REPLY Processing (Type 7)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-027 | MUST | Discard a Reply whose transaction-id is not that of the message it answers | RFC 8415 §16.10 | itest_dhcpv6_019_replies_validated, itest_dhcpv6_027_reply_when_bound_ignored |
| REQ-DHCPv6-028 | MUST | Take the assigned address from the IA Address (option 5) within the IA_NA | RFC 8415 §18.2.10.1 | itest_dhcpv6_011_address_assigned, itest_dhcpv6_028_reply_without_a_lease |
| REQ-DHCPv6-029 | MUST | Take the Preferred Lifetime and Valid Lifetime of the IA Address as the address's lifetimes, counted from the Reply — the first, and each Reply to a Renew or Rebind | RFC 8415 §18.2.10.1, §21.6 | itest_dhcpv6_029_reply_to_renew_extends, itest_dhcpv6_029_preferred_lifetime |
| REQ-DHCPv6-030 | MUST | Take T1 (renewal time) and T2 (rebind time) from the IA_NA; where the server left them 0: 0.5 and 0.8125 of the preferred lifetime | RFC 8415 §18.2.10.1, §14.2, §21.4 | itest_dhcpv6_036_renew_at_t1, itest_dhcpv6_030_t1_t2_left_to_the_client |
| REQ-DHCPv6-047 | MUST | Discard an IA_NA whose T1 is greater than its T2 (both greater than 0), and process the message as if it had none | RFC 8415 §21.4 | itest_dhcpv6_047_t1_above_t2_discarded |
| REQ-DHCPv6-031 | MUST | Configure assigned IPv6 address on interface (`ipv6_addr_add()`), with `DHCPV6_EVT_BOUND` | RFC 8415 §18.2.10.1 | itest_dhcpv6_011_address_assigned |
| REQ-DHCPv6-032 | MUST | Perform DAD on assigned address before use | RFC 8415 §18.2.10.1, RFC 4862 §5.4 | itest_dhcpv6_032_leased_address_probed |
| REQ-DHCPv6-046 | MUST | Send a Decline for an address that DAD finds in use — **deviation:** no Decline: the address stays a duplicate, unused, until the lease expires and the client solicits again | RFC 8415 §18.2.10.1, §18.2.8 | itest_dhcpv6_032_leased_address_probed |
| REQ-DHCPv6-045 | MUST NOT | Assume that addresses in the prefix of a leased address are on-link — **deviation:** `ipv6_on_link()` treats the /64 of every configured global address as on-link (REQ-NDP-075) | RFC 8415 §18.2.10.1 | itest_dhcpv6_045_leased_prefix_on_link |

### DUID (DHCP Unique Identifier)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-033 | MUST | Generate DUID for Client Identifier | RFC 8415 §11 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-034 | SHOULD | Use DUID-LL (DUID based on Link-Layer Address, type 3): simplest, no time needed | RFC 8415 §11.4 | itest_dhcpv6_001_information_request |
| REQ-DHCPv6-035 | MUST | DUID-LL format: type (2 bytes) = 3, hardware type (2 bytes) = 1, MAC (6 bytes) | RFC 8415 §11.4 | itest_dhcpv6_001_information_request |

### Renewal, Rebinding and Release

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-036 | MUST | Send RENEW (type 5) at T1 to extend the lease, with the Server Identifier of the server that gave it; its Reply extends the lease (`DHCPV6_EVT_RENEWED`) | RFC 8415 §18.2.4 | itest_dhcpv6_036_renew_at_t1, itest_dhcpv6_029_reply_to_renew_extends |
| REQ-DHCPv6-037 | MUST | Send REBIND (type 6) at T2 if the Renew went unanswered, without a Server Identifier; any server's Reply extends the lease | RFC 8415 §18.2.5 | itest_dhcpv6_037_rebind_at_t2 |
| REQ-DHCPv6-038 | MUST | When the valid lifetime expires, remove the address (`DHCPV6_EVT_EXPIRED`) and solicit again | RFC 8415 §18.2.5 | itest_dhcpv6_038_lease_expires |
| REQ-DHCPv6-049 | MUST | A Release carries the Client Identifier, the Server Identifier, an Elapsed Time and the IA_NA with the address released; the address is removed from the interface, and is not the Release's source (`dhcpv6_client_release()`) | RFC 8415 §18.2.7 | itest_dhcpv6_049_release |
| REQ-DHCPv6-056 | SHOULD | Retransmit a Release that gets no Reply — **deviation:** one Release is sent and the client is idle at once; a lost Release leaves the lease to expire at the server | RFC 8415 §18.2.7 | itest_dhcpv6_049_release |

### Retransmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-039 | MUST | Retransmit an unanswered message: RT doubles each time (RT = 2·RTprev + RAND·RTprev) up to MRT (RT = MRT + RAND·MRT), and a message with a retry limit (Request: REQ_MAX_RC = 10) is given up after it | RFC 8415 §15 | itest_dhcpv6_039_retransmission, itest_dhcpv6_040_request_backoff_capped |
| REQ-DHCPv6-040 | MUST | IRT and MRT by message type: Solicit 1 s / SOL_MAX_RT (3600 s), Request 1 s / 30 s, Renew 10 s / 600 s, Rebind 10 s / 600 s, Information-request 1 s / INF_MAX_RT (3600 s) | RFC 8415 §7.6, §18.2 | itest_dhcpv6_039_retransmission, itest_dhcpv6_040_request_backoff_capped |
| REQ-DHCPv6-041 | MUST | RAND is random, between -0.1 and +0.1 | RFC 8415 §15 | itest_dhcpv6_039_retransmission |
| REQ-DHCPv6-050 | MUST | Each retransmission carries the Elapsed Time since the first transmission of the exchange, in hundredths of a second (0 in the first; 0xFFFF from 655.35 s on) | RFC 8415 §15, §21.9 | itest_dhcpv6_039_retransmission, itest_dhcpv6_050_elapsed_time_of_each_exchange |
| REQ-DHCPv6-051 | MUST | The first Solicit's RT is strictly greater than IRT: RAND greater than 0 | RFC 8415 §18.2.1 | itest_dhcpv6_051_first_solicit_rt_above_irt |

### Option Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv6-042 | MUST | Parse options in TLV format: option-code (2 bytes) + option-len (2 bytes) + data; a message whose options do not fit it exactly is discarded | RFC 8415 §21.1 | itest_dhcpv6_042_options_parsed |
| REQ-DHCPv6-043 | MUST | Skip unknown options using option-len | RFC 8415 §21.1 | itest_dhcpv6_042_options_parsed |
| REQ-DHCPv6-044 | MUST | Support nested options (the IA Address and the Status Code inside the IA_NA) | RFC 8415 §21.4, §21.6 | itest_dhcpv6_021_advertise_offers |

## Notes

- **DHCPv6 is link-local multicast, not broadcast.** All client messages go to ff02::1:2 (All_DHCP_Relay_Agents_and_Servers), from the link-local address.
- **DHCPv6 does NOT provide gateway/router information.** Default router comes from Router Advertisement only. DHCPv6 provides addresses and DNS.
- **Stateless mode (O flag only)** is much simpler than stateful. Many IPv6 networks use SLAAC for addressing + stateless DHCPv6 for DNS only.
- **DUID-LL** suits embedded devices — it's just the MAC address with a type prefix. No RTC needed (unlike DUID-LLT which includes time).
- **UDP over IPv6:** DHCPv6 uses UDP ports 546/547. The UDP checksum is mandatory over IPv6 (REQ-IPv6-045).
- **Interaction with SLAAC:** a SLAAC address and a DHCPv6 address coexist when the interface has a slot for each (REQ-SLAAC-037).
- **Not sent:** Confirm, Decline, and the Rapid Commit and Reconfigure Accept options; a Reconfigure is ignored. A Reply to a Renew or Rebind that carries no usable lease (NoBinding, say) is ignored, and the client keeps trying until T2, then until the lease expires.
- **Interop:** `tests/blackbox/dhcpv6_interop.sh` has dnsmasq configure the `tcp_echo_demo`.
