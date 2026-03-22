# DHCPv4 Requirements

**Protocol:** Dynamic Host Configuration Protocol (v4)  
**Primary RFC:** RFC 2131 — Dynamic Host Configuration Protocol  
**Supporting:** RFC 2132 — DHCP Options and BOOTP Vendor Extensions  
**Scope:** V1 (IPv4)  
**Last updated:** 2026-03-19

## Overview

DHCPv4 provides automatic IPv4 address assignment and network configuration.  It
operates over UDP (client port 68, server port 67) using broadcast before an
address is assigned.

This stack provides two independent compilation units:

- **`dhcpv4_client.c`** — full client state machine (DISCOVER → OFFER → REQUEST →
  ACK, renewal, rebinding, lease expiry) plus an option handler callback API that
  lets higher-layer protocols (TFTP, NTP, DNS, …) receive option values without
  the DHCP layer knowing anything about them.
- **`dhcpv4_server.c`** — minimal stateless single-client server, designed for
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

Minimum message: 300 bytes (576 bytes recommended minimum per RFC 2131 §2).

## Requirements

### Client State Machine (RFC 2131 §4.4)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-001 | MUST | Implement DHCP client state machine: INIT → SELECTING → REQUESTING → BOUND → RENEWING → REBINDING | RFC 2131 §4.4 | TEST-DHCPv4-001 |
| REQ-DHCPv4-002 | MUST | INIT → SELECTING: broadcast DHCPDISCOVER | RFC 2131 §4.4.1 | TEST-DHCPv4-002 |
| REQ-DHCPv4-003 | MUST | SELECTING → REQUESTING: after receiving DHCPOFFER, broadcast DHCPREQUEST | RFC 2131 §4.4.1 | TEST-DHCPv4-003 |
| REQ-DHCPv4-004 | MUST | REQUESTING → BOUND: after receiving DHCPACK, configure IP address | RFC 2131 §4.4.1 | TEST-DHCPv4-004 |
| REQ-DHCPv4-005 | MUST | BOUND → RENEWING: at T1 (50% of lease), unicast DHCPREQUEST to server | RFC 2131 §4.4.5 | TEST-DHCPv4-005 |
| REQ-DHCPv4-006 | MUST | RENEWING → REBINDING: at T2 (87.5% of lease), broadcast DHCPREQUEST | RFC 2131 §4.4.5 | TEST-DHCPv4-006 |
| REQ-DHCPv4-007 | MUST | If lease expires, transition to INIT and deconfigure IP | RFC 2131 §4.4.5 | TEST-DHCPv4-007 |

### DHCPDISCOVER (RFC 2131 §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-008 | MUST | Set op=1 (BOOTREQUEST), htype=1, hlen=6, hops=0 | RFC 2131 §4.1 | TEST-DHCPv4-008 |
| REQ-DHCPv4-009 | MUST | Generate random xid for the transaction | RFC 2131 §4.4.1 | TEST-DHCPv4-009 |
| REQ-DHCPv4-010 | MUST | Set ciaddr = 0.0.0.0 (no address yet) | RFC 2131 §4.4.1 | TEST-DHCPv4-010 |
| REQ-DHCPv4-011 | MUST | Set chaddr = our MAC address | RFC 2131 §4.4.1 | TEST-DHCPv4-011 |
| REQ-DHCPv4-012 | MUST | Include magic cookie (0x63825363) | RFC 2131 §3 | TEST-DHCPv4-012 |
| REQ-DHCPv4-013 | MUST | Include DHCP Message Type option (53) = 1 (DISCOVER) | RFC 2132 §9.6 | TEST-DHCPv4-013 |
| REQ-DHCPv4-014 | SHOULD | Include Parameter Request List option (55) requesting: subnet mask, router, DNS, lease time | RFC 2132 §9.8 | TEST-DHCPv4-014 |
| REQ-DHCPv4-015 | MUST | Send to destination IP 255.255.255.255, source IP 0.0.0.0 | RFC 2131 §4.4.1 | TEST-DHCPv4-015 |
| REQ-DHCPv4-016 | MUST | Send to destination MAC FF:FF:FF:FF:FF:FF | RFC 2131 §4.1 | TEST-DHCPv4-016 |
| REQ-DHCPv4-017 | MUST | Source port = 68, destination port = 67 | RFC 2131 §4.1 | TEST-DHCPv4-017 |

### DHCPOFFER Processing (RFC 2131 §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-018 | MUST | Validate op=2 (BOOTREPLY) and xid matches our transaction | RFC 2131 §4.4.1 | TEST-DHCPv4-018 |
| REQ-DHCPv4-019 | MUST | Extract offered IP from yiaddr | RFC 2131 §4.4.1 | TEST-DHCPv4-019 |
| REQ-DHCPv4-020 | MUST | Extract Server Identifier option (54) | RFC 2132 §9.7 | TEST-DHCPv4-020 |
| REQ-DHCPv4-021 | SHOULD | Select first offer received (for simplicity) | RFC 2131 §4.4.1 | TEST-DHCPv4-021 |

### DHCPREQUEST (RFC 2131 §4.4.1, §4.3.2)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-022 | MUST | Include DHCP Message Type option (53) = 3 (REQUEST) | RFC 2132 §9.6 | TEST-DHCPv4-022 |
| REQ-DHCPv4-023 | MUST | Include Server Identifier option (54) with selected server's IP | RFC 2131 §4.3.2 | TEST-DHCPv4-023 |
| REQ-DHCPv4-024 | MUST | Include Requested IP Address option (50) with offered IP | RFC 2131 §4.3.2 | TEST-DHCPv4-024 |
| REQ-DHCPv4-025 | MUST | In SELECTING state: broadcast DHCPREQUEST (ciaddr=0) | RFC 2131 §4.3.2 | TEST-DHCPv4-025 |
| REQ-DHCPv4-026 | MUST | In RENEWING state: unicast DHCPREQUEST to server (ciaddr=current IP) | RFC 2131 §4.3.2 | TEST-DHCPv4-026 |
| REQ-DHCPv4-027 | MUST | In REBINDING state: broadcast DHCPREQUEST (ciaddr=current IP) | RFC 2131 §4.3.2 | TEST-DHCPv4-027 |

### DHCPACK Processing (RFC 2131 §4.4.1)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-028 | MUST | Validate op=2, xid matches, Message Type = 5 (ACK) | RFC 2131 §4.4.1 | TEST-DHCPv4-028 |
| REQ-DHCPv4-029 | MUST | Configure IP address from yiaddr | RFC 2131 §4.4.1 | TEST-DHCPv4-029 |
| REQ-DHCPv4-030 | MUST | Extract and apply Subnet Mask option (1) | RFC 2132 §3.3 | TEST-DHCPv4-030 |
| REQ-DHCPv4-031 | MUST | Extract and apply Router option (3) as default gateway | RFC 2132 §3.5 | TEST-DHCPv4-031 |
| REQ-DHCPv4-032 | SHOULD | Extract DNS Server option (6) | RFC 2132 §3.8 | TEST-DHCPv4-032 |
| REQ-DHCPv4-033 | MUST | Extract IP Address Lease Time option (51) | RFC 2132 §9.2 | TEST-DHCPv4-033 |
| REQ-DHCPv4-034 | SHOULD | Extract T1 (Renewal Time, option 58) and T2 (Rebinding Time, option 59) | RFC 2132 §9.11, §9.12 | TEST-DHCPv4-034 |
| REQ-DHCPv4-035 | MUST | If T1 not provided, default T1 = 0.5 × lease time | RFC 2131 §4.4.5 | TEST-DHCPv4-035 |
| REQ-DHCPv4-036 | MUST | If T2 not provided, default T2 = 0.875 × lease time | RFC 2131 §4.4.5 | TEST-DHCPv4-036 |

### DHCPNAK Processing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-037 | MUST | On DHCPNAK, transition to INIT and restart discovery | RFC 2131 §4.4.1 | TEST-DHCPv4-037 |
| REQ-DHCPv4-038 | MUST | On DHCPNAK, deconfigure current IP address | RFC 2131 §4.4.1 | TEST-DHCPv4-038 |

### DHCPRELEASE

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-039 | SHOULD | Send DHCPRELEASE when intentionally relinquishing lease | RFC 2131 §4.4.6 | TEST-DHCPv4-039 |
| REQ-DHCPv4-040 | MUST | DHCPRELEASE: ciaddr = our IP, unicast to server | RFC 2131 §4.4.6 | TEST-DHCPv4-040 |

### Option Parsing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-041 | MUST | Parse options in TLV format (Type, Length, Value) | RFC 2132 §2 | TEST-DHCPv4-041 |
| REQ-DHCPv4-042 | MUST | Option 255 (End) terminates option parsing | RFC 2132 §3.1 | TEST-DHCPv4-042 |
| REQ-DHCPv4-043 | MUST | Option 0 (Pad) is a single byte (no Length field) | RFC 2132 §3.1 | TEST-DHCPv4-043 |
| REQ-DHCPv4-044 | MUST | Skip unknown options using Length field | RFC 2132 §2 | TEST-DHCPv4-044 |

### Timers and Retransmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-045 | MUST | Retransmit DHCPDISCOVER with exponential backoff (initial 4s, max 64s) | RFC 2131 §4.1 | TEST-DHCPv4-045 |
| REQ-DHCPv4-046 | SHOULD | Add random jitter (±1 second) to retransmission timer | RFC 2131 §4.1 | TEST-DHCPv4-046 |
| REQ-DHCPv4-047 | MUST | Track lease timer, T1 timer, T2 timer | RFC 2131 §4.4.5 | TEST-DHCPv4-047 |

### Gateway ARP Resolution

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-048 | MUST | After configuring IP and gateway, resolve gateway MAC via ARP | Architecture | TEST-DHCPv4-048 |
| REQ-DHCPv4-049 | MUST | Store gateway MAC in net_t for off-subnet routing | Architecture | TEST-DHCPv4-049 |

### Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-050 | MUST | Minimum buffer size for DHCP: 576 bytes (RFC 2131 §2 minimum message size) | RFC 2131 §2 | TEST-DHCPv4-050 |
| REQ-DHCPv4-051 | MUST | Verify buffer is large enough at DHCP init; return error if too small | Architecture | TEST-DHCPv4-051 |

### Option Handler Callback API (dhcpv4_client.c)

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-052 | MUST | Provide an `dhcpv4_opt_table_t` mechanism: application registers `{option_code, handler_fn, ctx}` entries before calling `dhcpv4_client_start()` | Architecture | TEST-DHCPv4-052 |
| REQ-DHCPv4-053 | MUST | For each option found during DHCPACK parsing, if a matching entry exists in `opt_table`, invoke its `handler_fn(option, data, len, ctx)` with the raw TLV value bytes | Architecture | TEST-DHCPv4-053 |
| REQ-DHCPv4-054 | MUST | If an option is absent from the server's DHCPACK, the corresponding handler MUST NOT be called | Architecture | TEST-DHCPv4-054 |
| REQ-DHCPv4-055 | MUST | Option handlers MUST be called once per DHCPACK receipt, including renewal ACKs | Architecture | TEST-DHCPv4-055 |
| REQ-DHCPv4-056 | MUST | The `ctx` pointer from the registration entry MUST be passed unchanged to the handler | Architecture | TEST-DHCPv4-056 |
| REQ-DHCPv4-057 | MUST | Option handler invocation MUST NOT require dynamic memory allocation | Architecture | TEST-DHCPv4-057 |
| REQ-DHCPv4-058 | MUST | `opt_table` MAY be NULL; if NULL, no option callbacks are made (mandatory options subnet/router/lease are still applied) | Architecture | TEST-DHCPv4-058 |
| REQ-DHCPv4-059 | MUST | When building DHCPDISCOVER and DHCPREQUEST, automatically include Parameter Request List option (55) populated from: (a) mandatory codes {1, 3, 51} and (b) all option codes present in `opt_table` | Architecture | TEST-DHCPv4-059 |

### DHCPv4 Server (dhcpv4_server.c)

#### Server Design Constraints

| ID | Level | Requirement | Source | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-060 | MUST | The server MUST be stateless: it always offers the same pre-configured IP regardless of the client's MAC address | Architecture | TEST-DHCPv4-060 |
| REQ-DHCPv4-061 | MUST | The server MUST NOT require dynamic memory allocation | Architecture | TEST-DHCPv4-061 |
| REQ-DHCPv4-062 | MUST | All server configuration (offered IP, subnet, gateway, DNS, lease time) MUST be provided by the application via a `dhcpv4_server_cfg_t` struct at init time | Architecture | TEST-DHCPv4-062 |
| REQ-DHCPv4-063 | MUST | The server MUST operate as a pure stimulus/response handler: `dhcpv4_server_input()` processes one message and may send one reply; no timers are needed | Architecture | TEST-DHCPv4-063 |

#### Server Message Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-064 | MUST | On DHCPDISCOVER: reply with DHCPOFFER containing the configured `offered_ip` | RFC 2131 §4.3.1 | TEST-DHCPv4-064 |
| REQ-DHCPv4-065 | MUST | DHCPOFFER MUST include: yiaddr=offered_ip, Server Identifier option (54), IP Lease Time option (51), Subnet Mask option (1) | RFC 2131 §4.3.1, RFC 2132 | TEST-DHCPv4-065 |
| REQ-DHCPv4-066 | SHOULD | DHCPOFFER SHOULD include Router option (3) if `gateway != 0` in the server config | RFC 2132 §3.5 | TEST-DHCPv4-066 |
| REQ-DHCPv4-067 | SHOULD | DHCPOFFER SHOULD include DNS Server option (6) if `dns != 0` in the server config | RFC 2132 §3.8 | TEST-DHCPv4-067 |
| REQ-DHCPv4-068 | MUST | On DHCPREQUEST with Requested IP = offered_ip: reply with DHCPACK | RFC 2131 §4.3.2 | TEST-DHCPv4-068 |
| REQ-DHCPv4-069 | MUST | On DHCPREQUEST with Requested IP ≠ offered_ip: reply with DHCPNAK | RFC 2131 §4.3.2 | TEST-DHCPv4-069 |
| REQ-DHCPv4-070 | MUST | On DHCPRELEASE: ignore silently (no lease table) | RFC 2131 §4.3.4 | TEST-DHCPv4-070 |
| REQ-DHCPv4-071 | SHOULD | On DHCPINFORM: reply with DHCPACK containing options, yiaddr = 0 (no IP allocation) | RFC 2131 §4.3.5 | TEST-DHCPv4-071 |
| REQ-DHCPv4-072 | MUST | Silently ignore all other DHCP message types | RFC 2131 | TEST-DHCPv4-072 |

#### Server Reply Addressing

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-073 | MUST | Validate op=1 (BOOTREQUEST) and magic cookie before processing any message | RFC 2131 §3 | TEST-DHCPv4-073 |
| REQ-DHCPv4-074 | MUST | Set op=2 (BOOTREPLY) in all server replies | RFC 2131 §2 | TEST-DHCPv4-074 |
| REQ-DHCPv4-075 | MUST | Echo the client's xid unchanged in all replies | RFC 2131 §4.1 | TEST-DHCPv4-075 |
| REQ-DHCPv4-076 | MUST | If client's broadcast flag (flags bit 0) is set or ciaddr=0, broadcast reply to 255.255.255.255 / FF:FF:FF:FF:FF:FF | RFC 2131 §4.1 | TEST-DHCPv4-076 |
| REQ-DHCPv4-077 | MUST | If ciaddr is set and broadcast flag is clear, unicast reply to ciaddr | RFC 2131 §4.1 | TEST-DHCPv4-077 |

#### Server Buffer Requirements

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-DHCPv4-078 | MUST | Verify tx buffer ≥ 576 bytes at `dhcpv4_server_init()`; return error if too small | RFC 2131 §2, Architecture | TEST-DHCPv4-078 |

## Notes

- **DHCP uses broadcast before address assignment.** The stack must accept packets to IP 255.255.255.255 and to IP 0.0.0.0 during bootstrap (REQ-IPv4-009, REQ-IPv4-012).
- **DHCP uses UDP.** DHCP messages are UDP datagrams on ports 67 (server) and 68 (client).
- **XID randomization:** The transaction ID should be random to prevent DHCP spoofing.
- **Lease renewal is mandatory** to maintain the IP address assignment. The stack must track timers and renew proactively.
- **Gateway MAC resolution:** After DHCP assigns an IP and gateway, the stack must ARP for the gateway MAC before any off-subnet communication is possible.
- **Option 61 (Client Identifier):** Not required but MAY be included for uniqueness beyond MAC address.
- **Client and server are mutually exclusive on a single interface.** A device either gets an IP from a DHCP server (client) or provides one (server); link only the file you need.
- **Option handler raw bytes:** The `data` pointer in a handler callback points into the DHCP receive buffer. Handlers MUST NOT retain this pointer past the return of `dhcpv4_client_input()`; copy any data they need into their own storage.
