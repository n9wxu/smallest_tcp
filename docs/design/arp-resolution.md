# Address Resolution Design

**Last updated:** 2026-03-19

## Architecture

No global ARP/NDP cache. Resolved MAC addresses live in the structures that use them:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   net_t      │     │ tcp_conn_t   │     │ udp_peer_t   │
│              │     │              │     │  (optional)   │
│ gateway_mac  │     │ remote_mac   │     │ remote_mac   │
│ gateway_valid│     │ mac_valid    │     │ mac_valid    │
└──────────────┘     └──────────────┘     └──────────────┘
        ↑                    ↑                    ↑
        └────────────────────┴────────────────────┘
                    ARP/NDP reply handler scans
                    all of these looking for
                    matching IP
```

## Resolution Flow (IPv4/ARP)

1. App calls `tcp_connect()` or `udp_send()` to a destination IP.
2. Stack checks if destination is on-subnet (via `net->subnet_mask`).
   - On-subnet: resolve destination IP.
   - Off-subnet: resolve `net->gateway_ipv4`.
3. Check `mac_valid` in the relevant structure.
4. If valid: send immediately.
5. If not valid: send ARP request, defer data packet.
6. On ARP reply: scan all connection structures for matching IP, fill MAC, set `mac_valid = 1`.
7. On next `net_poll()` or `net_tick()`: retry deferred send.

## Resolution Flow (IPv6/NDP)

Same pattern but using Neighbor Solicitation/Advertisement instead of ARP. The NS goes to the solicited-node multicast address. Router MAC comes from Router Advertisement.

## Scan Mechanism

The application provides an array of connections to the stack. The ARP/NDP reply handler iterates this array:

```c
// Application registers connections with the stack
tcp_conn_t *app_connections[] = { &conn1, &conn2, NULL };
net_set_connections(net, app_connections);

// In arp_input(), on ARP reply:
for (int i = 0; app_connections[i]; i++) {
    if (app_connections[i]->remote_ip == arp_sender_ip) {
        memcpy(app_connections[i]->remote_mac, arp_sender_mac, 6);
        app_connections[i]->mac_valid = 1;
    }
}
```

## Gateway-Only Mode

For the smallest configuration, skip per-destination ARP entirely:
- Set `gateway_mac_valid = 1` (resolved at startup or via DHCP).
- ALL outbound frames use `gateway_mac` as Ethernet destination.
- The gateway forwards on-subnet packets back onto the link (extra hop).
- The gateway MAY send ICMP Redirect (which this mode ignores).

This eliminates all per-connection MAC state. Legal per RFC, just slower.

## Protocol-Layer MAC Caching

| Protocol | Where MAC is Stored | Lifetime |
|---|---|---|
| TCP connections | `tcp_conn_t.remote_mac` | Connection lifetime |
| UDP persistent peers | `udp_peer_t.remote_mac` | Application-managed |
| DHCP server | `dhcp_state_t.server_mac` | Lease lifetime |
| DNS server | `dns_ctx_t.server_mac` | Application-managed |
| Default gateway | `net_t.gateway_mac` | Until changed |
| TFTP server | `tftp_ctx_t.server_mac` | Transfer lifetime |
