# Test Plan — smallest_tcp

*Revision: Milestone 6 (TCP core)*

---

## Overview

Three complementary test layers ensure every MUST-level requirement is
verified at both the unit and integration levels:

| Layer | Framework | Location | Trigger |
|---|---|---|---|
| C Unit Tests | Custom `TEST`/`ASSERT` macros (ctest) | `tests/unit/` | Every push/PR |
| Blackbox Conformance | Python / Scapy (pytest) | `tests/blackbox/` | Every push/PR |
| Fuzz / Robustness | Python / Scapy `fuzz()` (pytest) | `tests/blackbox/` | Nightly / manual |

---

## 1. C Unit Tests

### Current Status

**10 test suites, 89 tests total — all passing.**

| Suite | File | Tests | Protocols Covered |
|---|---|---|---|
| `test_endian` | tests/unit/test_endian.c | 6 | Byte-order utilities |
| `test_checksum` | tests/unit/test_checksum.c | 12 | net_cksum (REQ-CKS-*) |
| `test_eth` | tests/unit/test_eth.c | 8 | Ethernet (REQ-ETH-*) |
| `test_net` | tests/unit/test_net.c | 5 | net init/dispatch |
| `test_arp` | tests/unit/test_arp.c | 8 | ARP (REQ-ARP-*) |
| `test_ipv4` | tests/unit/test_ipv4.c | 10 | IPv4 (REQ-IPV4-*) |
| `test_icmp` | tests/unit/test_icmp.c | 4 | ICMPv4 (REQ-ICMP-*) |
| `test_udp` | tests/unit/test_udp.c | 7 | UDP (REQ-UDP-*) |
| `test_tcp_buf` | tests/unit/test_tcp_buf.c | 6 | Stop-and-wait buffer |
| `test_tcp` | tests/unit/test_tcp.c | **23** | TCP (REQ-TCP-*) |

### Running Unit Tests

```sh
# CMake (recommended)
cmake -S . -B build && cmake --build build
ctest --test-dir build --output-on-failure

# Make (quick)
make test
```

### TCP Unit Test Coverage Matrix (REQ-TCP-*)

| REQ | Description | Unit Test | Status |
|---|---|---|---|
| 001 | 11 TCP states defined | test_tcp_passive_open, active_open | ✅ |
| 002 | Passive open (LISTEN) | test_tcp_passive_open_syn_synack_ack | ✅ |
| 003 | Active open (SYN_SENT) | test_tcp_active_open_syn_synack_ack | ✅ |
| 005 | Active close (FIN_WAIT_1) | test_tcp_active_close | ✅ |
| 006 | Passive close (CLOSE_WAIT) | test_tcp_passive_close | ✅ |
| 008 | TIME_WAIT 2×MSL | test_tcp_timewait_expires | ✅ |
| 014 | tcp_send() API | test_tcp_data_send | ✅ |
| 018 | Checksum on TX | test_tcp_checksum_basic | ✅ |
| 019 | Checksum verify on RX | test_tcp_checksum_basic | ✅ |
| 031 | ACK in LISTEN → RST | test_tcp_ack_in_listen_generates_rst | ✅ |
| 041/042 | Out-of-window → ACK only | test_tcp_out_of_window_gets_ack | ✅ |
| 046/047 | RST in ESTABLISHED → CLOSED | test_tcp_rst_in_established_aborts | ✅ |
| 048 | RST in LAST_ACK → CLOSED | test_tcp_rst_in_last_ack_closes | ✅ |
| 051 | SYN in ESTABLISHED → error | test_tcp_syn_in_established_gets_rst | ✅ |
| 053 | No ACK bit → discard | test_tcp_no_ack_bit_discarded | ✅ |
| 054 | ESTABLISHED on ACK to SYN-ACK | test_tcp_passive_open | ✅ |
| 059/071 | FIN exchange | test_tcp_active_close, passive_close | ✅ |
| 072 | Unknown port → RST | test_tcp_rst_sent_for_unknown_port | ✅ |
| 073 | RST.SEQ = ACK from LISTEN | test_tcp_ack_in_listen_generates_rst | ✅ |
| 075 | RST in LISTEN discarded | test_tcp_no_rst_in_listen_for_rst | ✅ |
| 076 | MSS option in SYN-ACK | test_tcp_synack_contains_mss | ✅ |
| 077 | MSS ≤ 1460 | test_tcp_synack_contains_mss | ✅ |
| 078 | Peer MSS stored | test_tcp_peer_mss_stored | ✅ |
| 079 | Default MSS = 536 | test_tcp_default_peer_mss_536 | ✅ |
| 082/083 | Window advertised > 0 | test_tcp_window_advertised_nonzero | ✅ |
| 090 | Retransmit on timeout | test_tcp_retransmit_on_timeout | ✅ |
| 095 | RTO doubles on retry | test_tcp_retransmit_on_timeout | ✅ |
| 097/098 | RTO stops on ACK | test_tcp_rto_resets_on_ack | ✅ |
| 109/111 | NOP/unknown option ignored | test_tcp_options_nop_unknown_ignored | ✅ |
| 112 | MSS parsed from options | test_tcp_options_nop_unknown_ignored | ✅ |
| 115 | Unknown option skipped | test_tcp_options_nop_unknown_ignored | ✅ |
| 085–087 | Zero-window persist timer | — | ⚠️ **NOT IMPLEMENTED** |
| 028/029/153 | ISS non-predictable | (blackbox only) | 🔲 Blackbox |
| 155 | RST rate limiting | (blackbox only) | 🔲 Blackbox |

> **⚠️ Implementation gap**: REQ-TCP-085, 086, 087 (zero-window persist timer)
> are MUST requirements that are **not yet implemented**. These are tracked
> as a future milestone work item.

---

## 2. Blackbox Conformance Tests

### Architecture

All blackbox tests use **Scapy** to craft raw Ethernet+IP+TCP frames.
The **phantom-IP trick** prevents the test host's kernel from interfering:

```
Test harness (Scapy, our_ip=10.0.0.100)
         │  raw AF_PACKET frames
         ▼
  [ Network interface ]
         │
         ▼
  SUT (smallest_tcp, sut_ip=10.0.0.2)
```

- `our_ip` (10.0.0.100) is never assigned to the interface — the kernel
  ignores replies and does not auto-RST hand-crafted connections.
- Scapy's `AF_PACKET` socket captures all L2 traffic regardless of
  destination IP.
- SUT learns `our_ip → our_mac` from the ARP pre-flight and routes all
  replies to our MAC.
- **No iptables rules needed.**

### Files

| File | Purpose |
|---|---|
| `tests/blackbox/conftest.py` | pytest fixtures, CLI options, ARP pre-flight, port allocator |
| `tests/blackbox/helpers.py` | `TcpConn`, `tcp_connect()`, `send_recv()`, `silence()`, frame builders |
| `tests/blackbox/test_tcp_conform.py` | 18 conformance tests (REQ-TCP-002..153) |
| `tests/blackbox/test_tcp_fuzz.py` | 5 fuzz tests (header fields, flags, options, truncation) |
| `tests/blackbox/requirements.txt` | `pytest>=7.0`, `scapy>=2.5` |

### Running Blackbox Tests (Local)

```sh
# Install deps
pip install -r tests/blackbox/requirements.txt

# Start the SUT (e.g. tcp_echo_demo on a TAP interface)
sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip link set tap0 up
sudo ip addr add 10.0.0.100/24 dev tap0
sudo ./build/tcp_echo_demo tap0 10.0.0.2

# In another terminal — run conformance tests
cd tests/blackbox
sudo python3 -m pytest test_tcp_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

# Run fuzz tests (200 iterations, ~60 seconds)
sudo python3 -m pytest test_tcp_fuzz.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
    --fuzz-count 200 -v
```

### Blackbox TCP Conformance Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_tcp_000 | — | ARP pre-flight (SUT reachable) |
| test_tcp_002 | REQ-TCP-035 | SYN-ACK.ACK = our SYN.SEQ + 1 |
| test_tcp_003 | REQ-TCP-054 | Full 3-way handshake completes |
| test_tcp_005 | REQ-TCP-059,071 | Active close: SUT ACKs our FIN |
| test_tcp_006 | REQ-TCP-068,069 | Passive close: FIN seq accounting |
| test_tcp_014 | REQ-TCP-055,064-066 | Echo data, seq/ack accounting |
| test_tcp_018 | REQ-TCP-018,140 | Bad checksum → silent drop |
| test_tcp_031 | REQ-TCP-031,073 | ACK to LISTEN → RST (correct SEQ) |
| test_tcp_041 | REQ-TCP-041,042 | Out-of-window → ACK, no data |
| test_tcp_047 | REQ-TCP-047,049 | RST closes ESTABLISHED |
| test_tcp_051 | REQ-TCP-051 | SYN in ESTABLISHED → error |
| test_tcp_072 | REQ-TCP-072 | Unknown port → RST |
| test_tcp_075 | REQ-TCP-075 | RST to LISTEN → silence |
| test_tcp_076 | REQ-TCP-076,077 | SYN-ACK contains MSS ≤ 1460 |
| test_tcp_078 | REQ-TCP-078,081 | SUT honors peer MSS |
| test_tcp_082 | REQ-TCP-082,083 | Window > 0 in SYN-ACK |
| test_tcp_090 | REQ-TCP-095,096 | SYN-ACK retransmit on RTO |
| test_tcp_097 | REQ-TCP-097,098 | No spurious retransmit after ACK |
| test_tcp_153 | REQ-TCP-153 | ISS different across connections |

### Fuzz Test Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_fuzz_001 | REQ-TCP-018 | All TCP header fields randomized (200+ iters) |
| test_fuzz_002 | robustness | Fuzzed data segments on ESTABLISHED |
| test_fuzz_003 | robustness | All 256 TCP flag combinations |
| test_fuzz_004 | REQ-TCP-115 | Fuzzed TCP options (unknown option skipping) |
| test_fuzz_005 | REQ-TCP-021 | Truncated frames (0..19 bytes into TCP header) |

---

## 3. CI Job Matrix

| Job | Workflow | Runner | Tests | Trigger |
|---|---|---|---|---|
| `make-linux` | ci.yml | ubuntu-latest | make test | push/PR |
| `make-macos` | ci.yml | macos-latest | make test | push/PR |
| `cmake-linux` | ci.yml | ubuntu-latest | ctest | push/PR |
| `cmake-macos` | ci.yml | macos-latest | ctest | push/PR |
| `blackbox-linux` | ci.yml | ubuntu-latest | Scapy conform (TAP) | push/PR |
| `fetchcontent` | ci.yml | ubuntu-latest | Integration build | push/PR |
| `fuzz-tcp-tap` | fuzz.yml | ubuntu-latest | Scapy fuzz (TAP) | Nightly 02:00 UTC |
| `fuzz-tcp-hw` | fuzz.yml | self-hosted, hw-dut | Scapy fuzz (real HW) | Nightly (when enabled) |

---

## 4. Hardware Test Fixture (Recommended)

### Purpose

Validate the stack on real embedded hardware to catch issues that the
TAP-based software tests cannot detect:
- Interrupt-driven Ethernet DMA timing
- Stack/heap exhaustion on small MCUs
- Hardware checksum offload paths
- Real-silicon clock drift affecting RTO

### Recommended BOM

| Component | Recommendation | Role |
|---|---|---|
| **Runner host** | Raspberry Pi 5 (4 GB) or x86 mini-PC | Runs GH Actions self-hosted runner |
| **DUT — Cortex-M4** | STM32F4-Discovery or Nucleo-F446RE | ARM M4 with hardware Ethernet (DP83848) |
| **DUT — Cortex-M0+** | Raspberry Pi Pico W (RP2040) | Smallest MCU target; SPI Ethernet via CYW43 |
| **Switch** | TP-Link TL-SG105 (5-port unmanaged) | Same L2 segment for runner + all DUTs |
| **USB-Serial** | 2× FTDI FT232R or Nucleo on-board | UART flashing / debug output from DUT |
| **SWD programmer** | ST-Link V2 or J-Link EDU Mini | Reliable OpenOCD firmware flashing |
| **Power relay** | Sainsmart 4-ch USB relay board | Hard-reset DUT from runner (GPIO) |

**Estimated cost: ~$150–200 USD**

### Wiring Topology

```
┌────────────────────────────────────────────────────────────────────┐
│  Self-Hosted Runner (RPi 5 / mini-PC)                             │
│                                                                    │
│  eth0 ──── Office LAN ──── Internet (GitHub connectivity)         │
│                                                                    │
│  eth1 ──┬──── 5-port switch ──┬── STM32 Ethernet (SUT-A)         │
│         │                     └── RP2040 SPI-Eth (SUT-B)          │
│         │                                                          │
│  USB ───┼──── ST-Link V2 ─────── SUT-A SWD                        │
│         └──── FTDI FT232R ─────── SUT-A UART                      │
│                                                                    │
│  USB-relay ──────────────────── SUT power rails                   │
└────────────────────────────────────────────────────────────────────┘
```

### GitHub Actions Integration

Add the self-hosted runner with labels `[self-hosted, hw-dut]` to the
repository. Enable hardware fuzz jobs by setting the Actions variable
`HW_DUT_ENABLED = true` in repository settings.

The `fuzz.yml` workflow includes the `fuzz-tcp-hw` job that:
1. Cross-compiles firmware with `arm-none-eabi-gcc`
2. Flashes DUT via OpenOCD
3. Waits for UART boot confirmation
4. Runs full conformance + fuzz suite over `eth1`
5. Power-cycles via USB relay and re-verifies

---

## 5. Open Items / Known Gaps

| # | Requirement(s) | Description | Priority |
|---|---|---|---|
| 1 | REQ-TCP-085/086/087 | Zero-window persist timer **NOT IMPLEMENTED** | High (next milestone) |
| 2 | REQ-TCP-004/007 | Simultaneous open/close | Low (MAY, rare) |
| 3 | REQ-TCP-113/114/117/122-124 | Window Scale, Timestamps, SACK options | Low (MAY) |
| 4 | REQ-TCP-130/132-134 | TCP_NODELAY, Keep-alive | Low (MAY) |
| 5 | Blackbox ETH/ARP/IPv4/ICMPv4/UDP | Retroactive Scapy suites for all pre-TCP protocols | Medium (next sprint) |
| 6 | Hardware fixture | Procure BOM, set up self-hosted runner | Medium |

---

*Last updated: Milestone 6 — TCP core implementation complete.*
