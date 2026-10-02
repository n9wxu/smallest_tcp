# DHCPv4 Requirements

**Protocol:** Dynamic Host Configuration Protocol (v4)  
**Primary RFC:** RFC 2131 — Dynamic Host Configuration Protocol  
**Supporting:** RFC 2132 — DHCP Options and BOOTP Vendor Extensions, RFC 3396 — Encoding Long Options, RFC 5227 — IPv4 Address Conflict Detection  
**Scope:** IPv4

## Overview

DHCPv4 provides automatic IPv4 address assignment and network configuration.  It
operates over UDP (client port 68, server port 67) using broadcast before an
address is assigned.

This stack provides two independent compilation units:

- **`dhcpv4_client.c`** — the client state machine (DISCOVER → OFFER → REQUEST →
  ACK, the ARP check of the address, renewal, rebinding, lease expiry) plus an
  option handler callback API that lets higher-layer protocols (TFTP, NTP, DNS, …)
  receive option values without the DHCP layer knowing anything about them.  The
  client does not start from a remembered address (INIT-REBOOT) and sends no
  DHCPINFORM; RFC 2131 makes both optional.
- **`dhcpv4_server.c`** — minimal single-client server, designed for
  USB/CDC-ECM devices that must assign an IP address to a single connected peer.

The two files are independent: link only what you need.  See
[docs/design/dhcpv4.md](../design/dhcpv4.md) for the full design rationale and
API reference.

## Message Format

```
Offset  Size  Field
  0      1    op (1=BOOTREQUEST, 2=BOOTREPLY)
  1      1    htype (1=Ethernet)
  2      1    hlen (6 for Ethernet)
  3      1    hops (0 for client)
  4      4    xid (transaction ID)
  8      2    secs (seconds since DHCP process started)
 10      2    flags (bit 0: broadcast flag)
 12      4    ciaddr (client IP, if known)
 16      4    yiaddr (your IP, offered by server)
 20      4    siaddr (server IP for next boot stage)
 24      4    giaddr (relay agent IP)
 28     16    chaddr (client hardware address, padded to 16)
 44     64    sname (server host name, optional)
108    128    file (boot file name, optional)
236      4    magic cookie (99.130.83.99 = 0x63825363)
240    var    options (TLV format)
```

Messages are at least 300 bytes; a client must be prepared to receive one
of up to 576 bytes of IP datagram (RFC 2131 §2).

## Requirements

### Client State Machine (RFC 2131 §4.4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-001 | MUST | Implement DHCP client state machine: INIT → SELECTING → REQUESTING → BOUND → RENEWING → REBINDING | RFC 2131 §4.4 | itest_dhcpv4_002_first_discover_after_one_to_ten_seconds, itest_dhcpv4_004_ack_configures_the_interface, itest_dhcpv4_005_renewing_and_rebinding_through_a_lease |
| REQ-DHCPv4-002 | MUST | INIT → SELECTING: broadcast DHCPDISCOVER — at start-up after a random wait of 1 to 10 s (SHOULD) | RFC 2131 §4.4.1 | itest_dhcpv4_002_first_discover_after_one_to_ten_seconds, test_sut_sends_discover |
| REQ-DHCPv4-003 | MUST | SELECTING → REQUESTING: after receiving DHCPOFFER, broadcast DHCPREQUEST | RFC 2131 §4.4.1 | itest_dhcpv4_003_first_offer_selected, test_offer_triggers_request |
| REQ-DHCPv4-004 | MUST | REQUESTING → BOUND: after receiving DHCPACK, configure IP address | RFC 2131 §4.4.1 | itest_dhcpv4_004_ack_configures_the_interface, test_ack_binds_ip |
| REQ-DHCPv4-005 | MUST | BOUND → RENEWING: at T1 (50% of lease), unicast DHCPREQUEST to server; unanswered, retransmit it after half the time left until T2, at least 60 s later | RFC 2131 §4.4.5 | itest_dhcpv4_005_renewing_and_rebinding_through_a_lease, itest_dhcpv4_005_renewal_starts_the_lease_again_from_its_request, itest_dhcpv4_005_renewal_answered_after_a_retransmission |
| REQ-DHCPv4-006 | MUST | RENEWING → REBINDING: at T2 (87.5% of lease), broadcast DHCPREQUEST; unanswered, retransmit it after half the time left until the lease expires, at least 60 s later | RFC 2131 §4.4.5 | itest_dhcpv4_005_renewing_and_rebinding_through_a_lease |
| REQ-DHCPv4-007 | MUST | If lease expires, transition to INIT and deconfigure IP | RFC 2131 §4.4.5 | itest_dhcpv4_005_renewing_and_rebinding_through_a_lease |

### DHCPDISCOVER (RFC 2131 §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-008 | MUST | Set op=1 (BOOTREQUEST), htype=1, hlen=6, hops=0 | RFC 2131 §4.1 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-009 | MUST | Generate a random xid for the transaction: its DISCOVER, their retransmissions and the REQUEST carry it, and discovery started again takes a new one | RFC 2131 §4.1, §4.4.1 | itest_dhcpv4_009_transaction_id, test_offer_triggers_request, test_discover_retransmit |
| REQ-DHCPv4-010 | MUST | Set ciaddr = 0.0.0.0 (no address yet) | RFC 2131 §4.4.1 | itest_dhcpv4_008_discover_format, test_discover_ciaddr_is_zero |
| REQ-DHCPv4-011 | MUST | Set chaddr = our MAC address | RFC 2131 §4.4.1 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-012 | MUST | Include magic cookie (0x63825363) | RFC 2131 §3 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-013 | MUST | Include DHCP Message Type option (53) = 1 (DISCOVER) | RFC 2132 §9.6 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-014 | SHOULD | Include Parameter Request List option (55) requesting the subnet mask, router and lease time, and each option the application registers a handler for (REQ-DHCPv4-059) — the DNS server (6) among them if it wants it | RFC 2132 §9.8 | itest_dhcpv4_059_parameter_request_list |
| REQ-DHCPv4-015 | MUST | Send to destination IP 255.255.255.255, source IP 0.0.0.0 | RFC 2131 §4.4.1 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-016 | MUST | Send to destination MAC FF:FF:FF:FF:FF:FF | RFC 2131 §4.1 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-017 | MUST | Source port = 68, destination port = 67 | RFC 2131 §4.1 | itest_dhcpv4_008_discover_format, test_sut_sends_discover |
| REQ-DHCPv4-101 | SHOULD | Set the BROADCAST flag in DHCPDISCOVER and in the DHCPREQUEST for an offer: without an address the stack takes no unicast datagram | RFC 2131 §4.1 | itest_dhcpv4_008_discover_format, itest_dhcpv4_101_broadcast_flag_before_an_address |
| REQ-DHCPv4-103 | SHOULD | Include the Maximum DHCP Message Size option (57) — **deviation:** never sent; a server then keeps to 576-byte datagrams, which the client's RX buffer is checked to hold (REQ-DHCPv4-050) | RFC 2131 §3.5 | — |
| REQ-DHCPv4-094 | MUST NOT | Include the Server Identifier option (54) in DHCPDISCOVER — nor once a server is known (after a NAK) | RFC 2131 Table 5 | itest_dhcpv4_094_discover_names_no_server |

### DHCPOFFER Processing (RFC 2131 §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-018 | MUST | Validate op=2 (BOOTREPLY), the magic cookie, and that xid matches our transaction; a message too short for them is dropped | RFC 2131 §4.4.1 | itest_dhcpv4_018_invalid_replies_ignored, test_wrong_xid_offer_ignored |
| REQ-DHCPv4-019 | MUST | Extract offered IP from yiaddr | RFC 2131 §4.4.1 | itest_dhcpv4_003_first_offer_selected |
| REQ-DHCPv4-020 | MUST | Extract Server Identifier option (54); an OFFER without one is dropped — the REQUEST must name the server it selects | RFC 2132 §9.7, RFC 2131 §3.1 step 3, Table 3 | itest_dhcpv4_020_offer_without_server_id_dropped |
| REQ-DHCPv4-021 | SHOULD | Select first offer received (for simplicity) | RFC 2131 §4.4.1 | itest_dhcpv4_003_first_offer_selected |

### DHCPREQUEST (RFC 2131 §4.4.1, §4.3.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-022 | MUST | Include DHCP Message Type option (53) = 3 (REQUEST) | RFC 2132 §9.6 | itest_dhcpv4_003_first_offer_selected |
| REQ-DHCPv4-023 | MUST | Include Server Identifier option (54) with selected server's IP in the REQUEST that selects an offer — and MUST NOT in RENEWING or REBINDING | RFC 2131 §4.3.2 | itest_dhcpv4_024_only_the_selecting_request_names_the_address, test_offer_triggers_request, test_request_contains_server_id |
| REQ-DHCPv4-024 | MUST | Include Requested IP Address option (50) with the offered IP in the REQUEST that selects an offer — and MUST NOT in RENEWING or REBINDING (the address is in ciaddr) | RFC 2131 §4.3.2, Table 4 | itest_dhcpv4_024_only_the_selecting_request_names_the_address, test_offer_triggers_request |
| REQ-DHCPv4-025 | MUST | In SELECTING state: broadcast DHCPREQUEST (ciaddr=0) | RFC 2131 §4.3.2 | itest_dhcpv4_003_first_offer_selected |
| REQ-DHCPv4-026 | MUST | In RENEWING state: unicast DHCPREQUEST to server (ciaddr=current IP) | RFC 2131 §4.3.2 | itest_dhcpv4_005_renewing_and_rebinding_through_a_lease |
| REQ-DHCPv4-027 | MUST | In REBINDING state: broadcast DHCPREQUEST (ciaddr=current IP) | RFC 2131 §4.3.2 | itest_dhcpv4_005_renewing_and_rebinding_through_a_lease |
| REQ-DHCPv4-091 | MUST | The REQUEST that selects an offer has the DISCOVER's 'secs' and goes to the same IP broadcast address | RFC 2131 §3.1 step 3 | itest_dhcpv4_091_request_has_the_discovers_secs_and_destination |

### DHCPACK Processing (RFC 2131 §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-028 | MUST | Validate op=2, xid matches, Message Type = 5 (ACK); an ACK is taken only while one is awaited (REQUESTING, RENEWING, REBINDING) | RFC 2131 §4.4.1 | itest_dhcpv4_018_invalid_replies_ignored, itest_dhcpv4_028_replies_ignored_when_none_is_awaited |
| REQ-DHCPv4-029 | MUST | Configure IP address from yiaddr | RFC 2131 §4.4.1 | itest_dhcpv4_004_ack_configures_the_interface, test_ack_binds_ip |
| REQ-DHCPv4-030 | MUST | Extract and apply Subnet Mask option (1) | RFC 2132 §3.3 | itest_dhcpv4_004_ack_configures_the_interface |
| REQ-DHCPv4-031 | MUST | Extract and apply Router option (3) as default gateway | RFC 2132 §3.5 | itest_dhcpv4_004_ack_configures_the_interface |
| REQ-DHCPv4-032 | SHOULD | Extract DNS Server option (6): passed to the application's option handler, if it registers one (REQ-DHCPv4-053) | RFC 2132 §3.8 | itest_dhcpv4_053_option_handlers |
| REQ-DHCPv4-033 | MUST | Extract IP Address Lease Time option (51); an ACK without it, or with a lease of 0 s, is dropped | RFC 2132 §9.2, RFC 2131 Table 3 | itest_dhcpv4_004_ack_configures_the_interface, itest_dhcpv4_033_ack_without_a_lease_time_dropped |
| REQ-DHCPv4-034 | SHOULD | Extract T1 (Renewal Time, option 58) and T2 (Rebinding Time, option 59) | RFC 2132 §9.11, §9.12 | itest_dhcpv4_034_t1_and_t2_from_the_ack |
| REQ-DHCPv4-035 | MUST | If T1 not provided, default T1 = 0.5 × lease time | RFC 2131 §4.4.5 | itest_dhcpv4_035_default_t1_and_t2 |
| REQ-DHCPv4-036 | MUST | If T2 not provided, default T2 = 0.875 × lease time | RFC 2131 §4.4.5 | itest_dhcpv4_035_default_t1_and_t2 |
| REQ-DHCPv4-079 | SHOULD | T1 and T2 with some random fuzz: both brought forward by the same random share, less than 1/16 | RFC 2131 §4.4.5 | itest_dhcpv4_079_t1_and_t2_fuzzed |
| REQ-DHCPv4-088 | MUST | T1 earlier than T2, T2 earlier than the end of the lease: T1 and T2 (the ACK's, or the defaults for those it lacks) not in that order are both replaced by the defaults (0.5 and 0.875 × lease) | RFC 2131 §4.4.5 | itest_dhcpv4_088_t1_after_t2_replaced_by_defaults, itest_dhcpv4_088_t2_past_lease_replaced_by_defaults |

### Address Conflict (RFC 2131 §3.1, §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-081 | SHOULD | Check the address of an ACK before using it: an ARP Probe — sender MAC ours, sender IP 0, target MAC 0, target IP the address — then 1 s without a conflict (RFC 5227's full timing is not used) | RFC 2131 §4.4.1, RFC 5227 §2.1.1 | itest_dhcpv4_081_ack_probed_before_use, itest_dhcpv4_039_release_while_probing |
| REQ-DHCPv4-102 | SHOULD | After the check, broadcast an ARP reply to announce the new address and clear outdated ARP cache entries — **deviation:** no announcement is sent; a host with an outdated entry learns the address from the next ARP exchange | RFC 2131 §4.4.1 | — |
| REQ-DHCPv4-080 | MUST | An address found in use while it is probed — an ARP packet from it, or another host's ARP Probe for it — is declined with DHCPDECLINE, never used, and configuration restarts — after 10 s (SHOULD) | RFC 2131 §3.1 step 5, §4.4.1, RFC 5227 §2.1.1 | itest_dhcpv4_080_address_in_use_declined, itest_dhcpv4_080_other_probe_or_request_conflicts |
| REQ-DHCPv4-082 | MUST | DHCPDECLINE carries the Requested IP Address (50) and the Server Identifier (54) and no other option but the message type; ciaddr, yiaddr, siaddr, giaddr, secs and flags 0; broadcast from 0.0.0.0 | RFC 2131 Table 5, §4.4.4 | itest_dhcpv4_080_address_in_use_declined |

### DHCPNAK Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-037 | MUST | On DHCPNAK, transition to INIT and restart discovery — a NAK from the server asked (its Server Identifier; any server while REBINDING); one without a Server Identifier is dropped | RFC 2131 §4.4.1, Table 3 | itest_dhcpv4_028_replies_ignored_when_none_is_awaited, itest_dhcpv4_037_nak_only_from_the_server_asked, test_nak_triggers_rediscover |
| REQ-DHCPv4-038 | MUST | On DHCPNAK, deconfigure current IP address | RFC 2131 §4.4.1 | itest_dhcpv4_005_renewing_and_rebinding_through_a_lease, itest_dhcpv4_037_nak_only_from_the_server_asked |

### DHCPRELEASE

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-039 | SHOULD | Send DHCPRELEASE when intentionally relinquishing lease | RFC 2131 §4.4.6 | itest_dhcpv4_039_release_while_probing, itest_dhcpv4_039_release_gives_up_the_address |
| REQ-DHCPv4-040 | MUST | DHCPRELEASE: ciaddr = our IP, unicast to server, at the MAC its ACK came from | RFC 2131 §4.4.6 | itest_dhcpv4_095_release_names_only_the_server, itest_dhcpv4_039_release_gives_up_the_address |
| REQ-DHCPv4-095 | MUST | DHCPRELEASE carries the Server Identifier (54) and no other option but the message type — not the Requested IP Address (50) (MUST NOT), the lease time or a Parameter Request List; flags 0 | RFC 2131 Table 5 | itest_dhcpv4_095_release_names_only_the_server |

### All Client Messages

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-092 | MUST | The reserved bits of 'flags' (all but BROADCAST) are zero | RFC 2131 §2 | itest_dhcpv4_092_reserved_flag_bits_zero |
| REQ-DHCPv4-093 | MUST | Unicast requests to the server go to the address of its Server Identifier option | RFC 2131 §4.1 | itest_dhcpv4_093_unicast_to_the_server_identifier |

### Option Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-041 | MUST | Parse options in TLV format (Type, Length, Value) | RFC 2132 §2 | itest_dhcpv4_041_options_parsed_by_type_and_length, itest_dhcpv4_041_option_past_the_end_of_the_message_not_read |
| REQ-DHCPv4-042 | MUST | Option 255 (End) terminates option parsing | RFC 2132 §3.1 | itest_dhcpv4_041_options_parsed_by_type_and_length |
| REQ-DHCPv4-043 | MUST | Option 0 (Pad) is a single byte (no Length field) | RFC 2132 §3.1 | itest_dhcpv4_041_options_parsed_by_type_and_length, itest_dhcpv4_084_server_reads_overloaded_and_split_options |
| REQ-DHCPv4-044 | MUST | Skip unknown options using Length field | RFC 2132 §2 | itest_dhcpv4_041_options_parsed_by_type_and_length |
| REQ-DHCPv4-084 | MUST | With the Option Overload option (52) — 1 'file', 2 'sname', 3 both — read options from those fields too: the options field first, then 'file', then 'sname' | RFC 2131 §4.1, RFC 2132 §9.3 | itest_dhcpv4_084_options_in_file_and_sname, itest_dhcpv4_084_sname_unread_unless_overloaded, itest_dhcpv4_089_split_across_fields_in_order, itest_dhcpv4_084_server_reads_overloaded_and_split_options |
| REQ-DHCPv4-089 | MUST | An option that appears more than once is one option: its parts joined in order (the options field, 'file', 'sname'), never used part by part | RFC 3396 §5, §7 | itest_dhcpv4_089_split_options_joined, itest_dhcpv4_089_split_across_fields_in_order, itest_dhcpv4_084_server_reads_overloaded_and_split_options |

### Timers and Retransmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-045 | MUST | Retransmit DHCPDISCOVER and DHCPREQUEST with exponential backoff (initial 4s, max 64s); after four unanswered DHCPREQUEST retransmissions, restart discovery and tell the application (`DHCPV4_EVT_TIMEOUT`, SHOULD) | RFC 2131 §4.1, §3.1, §4.4.1 | itest_dhcpv4_046_randomized_exponential_backoff, itest_dhcpv4_045_request_retransmitted_then_discovery_again, test_discover_retransmit |
| REQ-DHCPv4-046 | MUST | Randomize the exponential backoff: each retransmission delay by a uniform ±1 second | RFC 2131 §4.1 | itest_dhcpv4_046_randomized_exponential_backoff |
| REQ-DHCPv4-047 | MUST | Track lease timer, T1 timer, T2 timer, for any 32-bit lease time, from when the REQUEST the ACK answers was first sent; an infinite lease (0xFFFFFFFF) is never renewed and never expires | RFC 2131 §3.3, §4.4.1, §4.4.5 | itest_dhcpv4_005_renewal_starts_the_lease_again_from_its_request, itest_dhcpv4_005_renewal_answered_after_a_retransmission, itest_dhcpv4_047_lease_timed_from_the_request, itest_dhcpv4_047_lease_longer_than_49_days, itest_dhcpv4_047_infinite_lease_never_renewed |

### Gateway ARP Resolution

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-048 | MUST | A lease that changes the gateway, and the loss of the address, invalidate the gateway MAC in `net_t` (`gateway_mac_valid` = 0); the application resolves the new one with `arp_request()` — the stack never resolves on its own ([arp-resolution.md](../design/arp-resolution.md)) | Architecture | itest_dhcpv4_048_new_gateway_needs_its_mac_resolved |
| REQ-DHCPv4-049 | MUST | The gateway's ARP reply stores its MAC in `net_t` for off-subnet traffic | Architecture | itest_dhcpv4_048_new_gateway_needs_its_mac_resolved, itest_arp_011_gateway_learned_only_from_the_gateway |

### Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-050 | MUST | Client frame buffers: TX ≥ 342 bytes (a 300-byte message after the Ethernet, IPv4 and UDP headers), RX ≥ 590 bytes (the 576-byte IP datagram a client must be prepared to receive) | RFC 2131 §2 | itest_dhcpv4_051_client_init_checks_the_frame_buffers, itest_dhcpv4_050_smallest_buffers_take_a_576_byte_datagram |
| REQ-DHCPv4-051 | MUST | `dhcpv4_client_init()` checks the frame buffers of the `net_t` it is given and returns `NET_ERR_BUF_TOO_SMALL` if either is too small | Architecture | itest_dhcpv4_051_client_init_checks_the_frame_buffers |

### Option Handler Callback API (dhcpv4_client.c)

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-052 | MUST | Provide an `dhcpv4_opt_table_t` mechanism: the application registers `{option_code, handler_fn, ctx}` entries, in the table it passes to `dhcpv4_client_init()` | Architecture | itest_dhcpv4_053_option_handlers |
| REQ-DHCPv4-053 | MUST | For each entry of `opt_table` whose option the DHCPACK carries, invoke its `handler_fn(option, data, len, ctx)` once with the option's whole value — the parts of a split option joined (REQ-DHCPv4-089); a split one longer than `DHCPV4_SPLIT_OPTION_MAX` (255 bytes, the most `len` can express) is not delivered | RFC 3396 §7, Architecture | itest_dhcpv4_089_split_options_joined, itest_dhcpv4_053_split_option_too_long_not_delivered, itest_dhcpv4_053_option_handlers |
| REQ-DHCPv4-054 | MUST | If an option is absent from the server's DHCPACK, the corresponding handler MUST NOT be called | Architecture | itest_dhcpv4_053_option_handlers |
| REQ-DHCPv4-055 | MUST | Option handlers MUST be called once per DHCPACK receipt, including renewal ACKs | Architecture | itest_dhcpv4_053_option_handlers |
| REQ-DHCPv4-056 | MUST | The `ctx` pointer from the registration entry MUST be passed unchanged to the handler | Architecture | itest_dhcpv4_053_option_handlers |
| REQ-DHCPv4-057 | MUST | Option handler invocation MUST NOT require dynamic memory allocation | Architecture | — (not observable: a test cannot see an allocation that is not made; the objects reference no allocator) |
| REQ-DHCPv4-058 | MUST | `opt_table` MAY be NULL; if NULL, no option callbacks are made (mandatory options subnet/router/lease are still applied) | Architecture | itest_dhcpv4_004_ack_configures_the_interface |
| REQ-DHCPv4-059 | MUST | When building DHCPDISCOVER and DHCPREQUEST, automatically include Parameter Request List option (55) populated from: (a) mandatory codes {1, 3, 51} and (b) all option codes present in `opt_table` — at most 35 codes in all, so that every message fits 300 bytes; the REQUESTs carry the DISCOVER's list | RFC 2131 §3.5, §4.4.1, Architecture | itest_dhcpv4_059_parameter_request_list, itest_dhcpv4_059_parameter_request_list_of_at_most_35 |

### DHCPv4 Server (dhcpv4_server.c)

#### Server Design Constraints

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-060 | MUST | The server identifies its client by 'chaddr' and keeps one: the first it offers the address to gets it, and no other is offered it, until that client releases it or selects another server, or the application initialises the server again — **deviation:** a client that sends a Client Identifier (option 61) is still identified by its chaddr, where RFC 2131 §4.2 has the server use the identifier; with one peer on the link both name the same client, and the server keeps no identifier | RFC 2131 §4.2 | itest_dhcpv4_086_request_for_another_server_unanswered, itest_dhcpv4_060_address_kept_for_its_client, itest_dhcpv4_060_client_known_by_chaddr_not_identifier |
| REQ-DHCPv4-061 | MUST | The server MUST NOT require dynamic memory allocation | Architecture | — (not observable: a test cannot see an allocation that is not made; the objects reference no allocator) |
| REQ-DHCPv4-062 | MUST | All server configuration (offered IP, subnet, gateway, DNS, lease time) MUST be provided by the application via a `dhcpv4_server_cfg_t` struct at init time | Architecture | itest_dhcpv4_064_discover_answered_with_an_offer, itest_dhcpv4_066_unconfigured_router_and_dns_left_out |
| REQ-DHCPv4-063 | MUST | The server MUST operate as a stimulus/response handler: `dhcpv4_server_input()` processes one message and may send one reply; no timers are needed | Architecture | itest_dhcpv4_064_discover_answered_with_an_offer |

#### Server Message Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-064 | MUST | On DHCPDISCOVER from a client that may have the address (REQ-DHCPv4-060): reply with DHCPOFFER containing the configured `offered_ip` | RFC 2131 §4.3.1 | itest_dhcpv4_064_discover_answered_with_an_offer |
| REQ-DHCPv4-065 | MUST | DHCPOFFER MUST include: yiaddr=offered_ip, Server Identifier option (54), IP Lease Time option (51), Subnet Mask option (1) | RFC 2131 §4.3.1, RFC 2132 | itest_dhcpv4_064_discover_answered_with_an_offer, itest_dhcpv4_066_unconfigured_router_and_dns_left_out |
| REQ-DHCPv4-066 | SHOULD | DHCPOFFER SHOULD include Router option (3) if `gateway != 0` in the server config | RFC 2132 §3.5 | itest_dhcpv4_064_discover_answered_with_an_offer, itest_dhcpv4_066_unconfigured_router_and_dns_left_out |
| REQ-DHCPv4-067 | SHOULD | DHCPOFFER SHOULD include DNS Server option (6) if `dns != 0` in the server config | RFC 2132 §3.8 | itest_dhcpv4_064_discover_answered_with_an_offer, itest_dhcpv4_066_unconfigured_router_and_dns_left_out |
| REQ-DHCPv4-068 | MUST | On a DHCPREQUEST it answers (REQ-DHCPv4-086, 087) with Requested IP (else ciaddr) = offered_ip, from a client that may have it: reply with DHCPACK | RFC 2131 §4.3.2 | itest_dhcpv4_068_request_for_the_address_acked, itest_dhcpv4_068_renewal_after_the_server_was_initialised_again |
| REQ-DHCPv4-069 | MUST | On a DHCPREQUEST it answers for another address, or for one another client has: reply with DHCPNAK, carrying only the Message Type and Server Identifier options, ciaddr = yiaddr = siaddr = 0 | RFC 2131 §4.3.2, Table 3 | itest_dhcpv4_069_request_for_another_address_naked |
| REQ-DHCPv4-070 | MUST | On DHCPRELEASE from the client of the address (its chaddr, ciaddr = offered_ip): the address is free again; no reply to any DHCPRELEASE | RFC 2131 §4.3.4 | itest_dhcpv4_060_address_kept_for_its_client, itest_dhcpv4_070_only_the_clients_release_frees_the_address |
| REQ-DHCPv4-071 | MUST NOT | The DHCPACK to a DHCPINFORM carries no lease time (51); it has yiaddr = 0 (SHOULD NOT fill it in), ciaddr = the client's, and the configuration options | RFC 2131 §4.3.5, Table 3 | itest_dhcpv4_071_inform_answered_without_a_lease, itest_dhcpv4_071_inform_without_an_address_answered_by_broadcast |
| REQ-DHCPv4-072 | MUST | Silently ignore all other DHCP message types | RFC 2131 | itest_dhcpv4_072_other_messages_ignored |
| REQ-DHCPv4-085 | MUST | On DHCPDECLINE of the address (Requested IP = `offered_ip`, our Server Identifier): mark it not available — no OFFER or ACK of it until the application initialises the server again — and tell the application (`DHCPV4_SRV_EVT_DECLINE`, SHOULD) | RFC 2131 §4.3.3 | itest_dhcpv4_085_declined_address_offered_no_more, itest_dhcpv4_085_decline_of_another_address_or_server_ignored |
| REQ-DHCPv4-086 | MUST | A DHCPREQUEST whose Server Identifier is another server's declines our offer: no reply, neither ACK nor NAK | RFC 2131 §3.1 step 4, §4.3.2 | itest_dhcpv4_086_request_for_another_server_unanswered |
| REQ-DHCPv4-087 | MUST | A DHCPREQUEST from an INIT-REBOOT client (no Server Identifier, ciaddr 0) the server has no record of: no reply; a client that renews `offered_ip` (in ciaddr) while the server has no client is taken for its client and answered | RFC 2131 §4.3.2 | itest_dhcpv4_087_unknown_init_reboot_client_unanswered, itest_dhcpv4_068_renewal_after_the_server_was_initialised_again |

#### Server Options

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-096 | MUST | OFFER and ACK carry the Server Identifier (54) and, but for the ACK to a DHCPINFORM, the lease time (51); never the Requested IP Address (50), Parameter Request List (55), Client Identifier (61) or Maximum Message Size (57) | RFC 2131 Table 3 | itest_dhcpv4_096_offer_and_ack_options |
| REQ-DHCPv4-097 | MUST | Each requested parameter at most once; one the server cannot provide — not configured, or unknown to it — left out | RFC 2131 §4.3.1 | itest_dhcpv4_097_requested_parameters_once_or_not_at_all |
| REQ-DHCPv4-090 | MUST | Requested options in the order of the client's Parameter Request List, as far as REQ-DHCPv4-098 allows | RFC 2132 §9.8 | itest_dhcpv4_090_options_in_the_order_requested, itest_dhcpv4_084_server_reads_overloaded_and_split_options |
| REQ-DHCPv4-098 | MUST | In a reply with both, the Subnet Mask (1) before the Router (3) | RFC 2132 §3.3 | itest_dhcpv4_090_options_in_the_order_requested, itest_dhcpv4_098_subnet_mask_before_router |
| REQ-DHCPv4-099 | MUST | Ignore the client's Vendor Specific Information (43) and Vendor Class Identifier (60), which the server cannot interpret | RFC 2132 §8.4, §9.13 | itest_dhcpv4_099_vendor_information_ignored |
| REQ-DHCPv4-100 | MUST | The Server Identifier is an address the client can reach: the server's own on the link (`server_ip`), its replies' IP source | RFC 2131 §4.1 | itest_dhcpv4_100_server_identifier_reachable, itest_dhcpv4_078_server_init_checks |

#### Server Reply Addressing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-073 | MUST | Validate op=1 (BOOTREQUEST) and magic cookie before processing any message; a message too short for them is dropped | RFC 2131 §3 | itest_dhcpv4_072_other_messages_ignored |
| REQ-DHCPv4-074 | MUST | Set op=2 (BOOTREPLY) in all server replies | RFC 2131 §2 | itest_dhcpv4_064_discover_answered_with_an_offer, itest_dhcpv4_068_request_for_the_address_acked |
| REQ-DHCPv4-075 | MUST | Echo the client's xid unchanged in all replies | RFC 2131 §4.1 | itest_dhcpv4_064_discover_answered_with_an_offer, itest_dhcpv4_068_request_for_the_address_acked |
| REQ-DHCPv4-076 | MUST | Copy the request's flags and giaddr into the reply (a NAK through a relay also sets the broadcast flag); send it to giaddr on port 67 if set, else broadcast a NAK, else to ciaddr if set, else broadcast if the broadcast flag is set | RFC 2131 §4.1, §4.3.2, Table 3 | itest_dhcpv4_076_where_replies_go, itest_dhcpv4_071_inform_without_an_address_answered_by_broadcast |
| REQ-DHCPv4-077 | MUST | Otherwise unicast the reply to yiaddr at chaddr | RFC 2131 §4.1 | itest_dhcpv4_076_where_replies_go |

#### Server Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-078 | MUST | `dhcpv4_server_init()` checks that the TX and RX frame buffers hold a 300-byte message (342 bytes) and returns `NET_ERR_BUF_TOO_SMALL` otherwise; a `server_ip` that is not the host's address is refused (`NET_ERR_INVALID_PARAM`) | RFC 2131 §2, Architecture | itest_dhcpv4_078_server_init_checks |

## Notes

- **DHCP uses broadcast before address assignment.** The stack must accept packets to IP 255.255.255.255 and to IP 0.0.0.0 during bootstrap (REQ-IPv4-009, REQ-IPv4-012).
- **DHCP uses UDP.** DHCP messages are UDP datagrams on ports 67 (server) and 68 (client).
- **XID randomization:** The transaction ID should be random to prevent DHCP spoofing.
- **Lease renewal is mandatory** to maintain the IP address assignment. The stack must track timers and renew proactively.
- **Gateway MAC resolution:** After DHCP assigns an IP and gateway, the application ARPs for the gateway MAC (`arp_request()`) before any off-subnet communication; the stack only records the reply.
- **Option 61 (Client Identifier):** optional; the client sends none and is known by its MAC address (chaddr).
- **Client and server are mutually exclusive on a single interface.** A device either gets an IP from a DHCP server (client) or provides one (server); link only the file you need.
- **Option handler raw bytes:** The `data` pointer in a handler callback points into the DHCP receive buffer, or, for an option split in parts, into a buffer on the stack where they are joined. Handlers MUST NOT retain this pointer past their return; copy any data they need into their own storage.
