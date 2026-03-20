# Timer and Event Model — Design

**Last updated:** 2026-03-19

## Entry Points

The stack has two regular entry points called by the application:

1. **`net_poll(net_t *net)`** — Process pending frames from the MAC. Call when MAC signals data ready or periodically.
2. **`net_tick(net_t *net, uint32_t elapsed_ms)`** — Advance internal timers by `elapsed_ms` milliseconds.

And one query:

3. **`uint32_t net_next_event_ms(net_t *net)`** — Returns milliseconds until the next scheduled timer event. `UINT32_MAX` means nothing is scheduled.

## Timer Usage by Protocol

| Timer | Protocol | Typical Interval | Purpose |
|---|---|---|---|
| ARP retry | ARP/NDP | ~1 second | Retransmit ARP/NS request |
| TCP retransmit | TCP | 1-60 seconds (RTO) | Retransmit unACKed segment |
| TCP TIME-WAIT | TCP | 2 × MSL (~4 min) | TIME-WAIT expiry |
| TCP delayed ACK | TCP | ≤ 500ms | Piggyback ACK on data |
| TCP persist | TCP | 5-60 seconds | Zero-window probe |
| DHCP retransmit | DHCPv4/v6 | 4-64 seconds (backoff) | Retransmit DISCOVER/SOLICIT |
| DHCP lease | DHCPv4/v6 | T1/T2/lease | Renewal and rebinding |
| DNS retry | DNS | 2-30 seconds | Retransmit query |
| TFTP timeout | TFTP | 1-5 seconds | Retransmit ACK/RRQ |

## Internal Timer Representation

Each active timer is a `uint32_t remaining_ms` field in the relevant state structure. `net_tick()` decrements all active timers. When a timer reaches zero, the stack takes action (retransmit, timeout, etc.).

```c
// In tcp_conn_t:
uint32_t rto_remaining_ms;      // retransmission timer
uint32_t timewait_remaining_ms; // TIME-WAIT timer
uint32_t delayed_ack_ms;        // delayed ACK timer
uint32_t persist_ms;            // zero-window probe timer
```

## Execution Models

| Model | `net_poll()` | `net_tick()` | `net_next_event_ms()` |
|---|---|---|---|
| **Bare-metal tight loop** | Call every iteration | Call with 0 (or measured delta) | Not used |
| **Bare-metal + timer IRQ** | Call on MAC IRQ | Call with measured ms since last | Set next timer interrupt to return value |
| **RTOS** | Block on MAC semaphore | Call with timeout duration | Used as semaphore timeout |
| **Linux/macOS** | `select(mac_fd)` | Call with actual elapsed | Used as `select()` timeout |

## Tickless Operation

For maximum power savings, the application:
1. Calls `net_poll()` to drain MAC
2. Calls `net_next_event_ms()` to get sleep duration
3. Sleeps for `min(next_event_ms, mac_wake_event)`
4. On wake: measure actual elapsed time, call `net_tick(actual_ms)`

This allows the MCU to enter deep sleep between network events.
