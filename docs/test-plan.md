# Test Plan — Portable Minimal TCP/IP Stack

**Last updated:** 2026-03-19

## 1. Overview

This test plan defines the strategy for verifying the TCP/IP stack against RFC requirements. Tests are **generic** — they test protocol conformance from outside the stack and do not depend on implementation internals. The same test suite can validate any TCP/IP stack accessible via a raw Ethernet interface.

## 2. Test Philosophy

| Principle | Description |
|---|---|
| **RFC-driven** | Every test traces to a requirement ID (`REQ-*`) which traces to an RFC section |
| **Black-box** | Tests interact with the stack via raw Ethernet frames only — no internal API access |
| **Generic** | Tests are stack-agnostic; they validate protocol behavior, not implementation |
| **Automated** | All tests run in CI (GitHub Actions) and locally without manual intervention |
| **Comprehensive** | Every MUST/SHOULD/MAY requirement has at least one test |

## 3. Test Framework

### 3.1 Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Language | Python 3.10+ | Test scripting |
| Packet crafting | Scapy | Build and parse arbitrary protocol packets |
| Test runner | pytest | Test discovery, fixtures, reporting |
| CI platform | GitHub Actions (Linux) | PR validation |
| Local platform | macOS (feth+BPF) | Developer testing |
| Coverage tracking | Custom requirement matrix | Traces TEST-* → REQ-* → RFC |

### 3.2 Test Interface

Tests communicate with the stack under test (SUT) via a raw Ethernet interface:

```
┌──────────────────┐    raw Ethernet frames    ┌──────────────────┐
│                  │  ←────────────────────→   │                  │
│   Test Harness   │                            │   Stack Under    │
│   (Python/Scapy) │    TAP (Linux) or          │   Test (SUT)     │
│                  │    feth+BPF (macOS)        │                  │
└──────────────────┘                            └──────────────────┘
```

- **Linux (CI):** TAP interface. Test harness and SUT share a TAP pair.
- **macOS (local):** feth pair. Test harness on one feth, SUT on the other.
- **The SUT runs as a userspace process** — the demo application linked with the stack.

### 3.3 Test Configuration

```python
# conftest.py — shared fixtures
SUT_MAC  = "02:00:00:00:00:01"  # Stack's MAC address
SUT_IPv4 = "10.0.0.2"           # Stack's IPv4 address
SUT_IPv6 = "fe80::1"            # Stack's IPv6 link-local (derived from MAC)
TEST_MAC = "02:00:00:00:00:02"  # Test harness MAC
TEST_IPv4 = "10.0.0.1"          # Test harness IPv4
TEST_IPv6 = "fe80::2"           # Test harness IPv6
IFACE    = "tap0"               # or "feth1"
SUBNET   = "255.255.255.0"
GATEWAY  = "10.0.0.1"
```

## 4. Test Categories

### 4.1 Conformance Tests

Verify each RFC requirement. Named `TEST-{PROTO}-{NNN}` matching `REQ-{PROTO}-{NNN}`.

**Organization:**
```
tests/
├── conftest.py              # Shared fixtures, SUT management
├── helpers.py               # Common packet builders, validators
├── test_ethernet.py         # TEST-ETH-001 through TEST-ETH-020
├── test_arp.py              # TEST-ARP-001 through TEST-ARP-037
├── test_ipv4.py             # TEST-IPv4-001 through TEST-IPv4-057
├── test_icmpv4.py           # TEST-ICMPv4-001 through TEST-ICMPv4-041
├── test_udp.py              # TEST-UDP-001 through TEST-UDP-039
├── test_tcp.py              # TEST-TCP-001 through TEST-TCP-155
├── test_checksum.py         # TEST-CKSUM-001 through TEST-CKSUM-029
├── test_dhcpv4.py           # TEST-DHCPv4-001 through TEST-DHCPv4-051
├── test_dns.py              # TEST-DNS-001 through TEST-DNS-036
├── test_tftp.py             # TEST-TFTP-001 through TEST-TFTP-038
├── test_http.py             # TEST-HTTP-001 through TEST-HTTP-043
├── test_ipv6.py             # TEST-IPv6-001 through TEST-IPv6-047  (V2)
├── test_icmpv6.py           # TEST-ICMPv6-001 through TEST-ICMPv6-041 (V2)
├── test_ndp.py              # TEST-NDP-001 through TEST-NDP-070  (V2)
├── test_slaac.py            # TEST-SLAAC-001 through TEST-SLAAC-037 (V2)
└── test_dhcpv6.py           # TEST-DHCPv6-001 through TEST-DHCPv6-044 (V2)
```

### 4.2 Interoperability Tests

Validate that the stack works with standard tools:

| Test | Tool | Validates |
|---|---|---|
| Ping | `ping` / `ping6` | ARP + IPv4/IPv6 + ICMP echo |
| ARP resolution | `arping -I tap0 10.0.0.2` | ARP request/reply |
| UDP echo | `nc -u 10.0.0.2 7` | UDP send/receive |
| TCP echo | `nc 10.0.0.2 7` | TCP connection, data, close |
| HTTP browse | `curl http://10.0.0.2/` | TCP + HTTP request/response |
| DHCP | `dnsmasq` (as server) | DHCPv4 full exchange |
| DNS | `dig @10.0.0.1 example.com` (with mock server) | DNS query/response |
| TFTP | `tftpd` (as server) | TFTP file download |

### 4.3 Robustness Tests

Verify correct handling of malformed, malicious, and edge-case inputs:

| Category | Examples |
|---|---|
| Truncated packets | Frames shorter than minimum header |
| Invalid checksums | Corrupted IP/TCP/UDP/ICMP checksums |
| Invalid headers | Bad version, bad IHL, bad offsets |
| Oversized packets | Frames exceeding buffer capacity |
| Broadcast storms | High-rate ARP requests from foreign IPs |
| Sequence number edge cases | Wrap-around, out-of-window, exact boundary |
| TCP state machine abuse | RST in wrong state, SYN on established |
| Zero-length payloads | Empty UDP, empty TCP data |
| Max-length payloads | MTU-sized frames |
| Fragment attacks | Fragments sent to stack that doesn't reassemble |

### 4.4 Performance Tests (Baseline)

Establish baseline metrics — not for gating PRs, but for tracking regressions:

| Metric | Method |
|---|---|
| ARP resolution latency | Time from ARP request to reply |
| Ping RTT | Time for ICMP echo request/reply |
| TCP throughput | Bulk data transfer, measure bytes/second |
| TCP connection setup time | SYN → ESTABLISHED latency |
| UDP throughput | Bulk UDP send, measure packets/second |
| ARP storm drain rate | Frames/second for discard path |

## 5. Test Execution

### 5.1 Local Development (macOS)

```bash
# Setup feth pair
sudo ifconfig feth0 create
sudo ifconfig feth1 create
sudo ifconfig feth0 peer feth1
sudo ifconfig feth0 10.0.0.1/24 up
sudo ifconfig feth1 up

# Start SUT (in background)
./demo/echo_server &

# Run tests
pytest tests/ -v --iface=feth1

# Cleanup
sudo ifconfig feth0 destroy
sudo ifconfig feth1 destroy
```

### 5.2 CI (GitHub Actions — Linux)

```yaml
# .github/workflows/test.yml
name: TCP/IP Stack Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build stack
        run: make
      
      - name: Setup TAP interface
        run: |
          sudo ip tuntap add dev tap0 mode tap
          sudo ip addr add 10.0.0.1/24 dev tap0
          sudo ip link set tap0 up
      
      - name: Start SUT
        run: |
          sudo ./demo/echo_server &
          sleep 1
      
      - name: Install test dependencies
        run: pip install scapy pytest
      
      - name: Run conformance tests
        run: sudo pytest tests/ -v --iface=tap0
      
      - name: Run interop tests
        run: |
          ping -c 3 10.0.0.2
          echo "hello" | nc -u -w1 10.0.0.2 7
```

### 5.3 Local Linux (Physical or VM)

Same as CI but manually on a local machine. Useful for debugging failed CI tests.

## 6. Test Naming Convention

```
TEST-{PROTOCOL}-{NNN}

Where:
  PROTOCOL = ETH, ARP, IPv4, ICMPv4, UDP, TCP, CKSUM, DHCPv4, DNS, TFTP, HTTP,
             IPv6, ICMPv6, NDP, SLAAC, DHCPv6
  NNN      = Three-digit number matching the requirement number
```

Each test function:
```python
def test_arp_001_reply_to_request():
    """REQ-ARP-001: MUST respond to ARP request for our IP."""
    # Send ARP request targeting SUT IP
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=TEST_MAC) / ARP(
        op="who-has", hwsrc=TEST_MAC, psrc=TEST_IPv4, pdst=SUT_IPv4
    )
    sendp(pkt, iface=IFACE, verbose=False)
    
    # Expect ARP reply
    reply = sniff(iface=IFACE, filter="arp", count=1, timeout=2)
    assert len(reply) == 1
    assert reply[0][ARP].op == 2  # is-at
    assert reply[0][ARP].psrc == SUT_IPv4
    assert reply[0][ARP].hwsrc == SUT_MAC
```

## 7. Requirements Traceability Matrix

Maintained in `docs/requirements/` — each requirement file includes Test ID column. Summary matrix:

| Protocol | Requirements | V1 Tests | V2 Tests | Status |
|---|---|---|---|---|
| Ethernet | 20 | 20 | — | Planned |
| ARP | 37 | 37 | — | Planned |
| Checksum | 29 | 29 | — | Planned |
| IPv4 | 57 | 57 | — | Planned |
| ICMPv4 | 41 | 41 | — | Planned |
| UDP | 39 | 39 | — | Planned |
| TCP | 155 | 155 | — | Planned |
| DHCPv4 | 51 | 51 | — | Planned |
| DNS | 36 | 36 | — | Planned |
| TFTP | 38 | 38 | — | Planned |
| HTTP | 43 | 43 | — | Planned |
| IPv6 | 47 | — | 47 | Planned |
| ICMPv6 | 41 | — | 41 | Planned |
| NDP | 70 | — | 70 | Planned |
| SLAAC | 37 | — | 37 | Planned |
| DHCPv6 | 44 | — | 44 | Planned |
| **Total** | **~785** | **~546** | **~239** | |

## 8. Test Priority

Tests are implemented in the same order as the implementation tasks:

| Priority | Protocol | Depends On | Implementation Task |
|---|---|---|---|
| 1 | Ethernet | MAC driver | Task 1-2 |
| 2 | ARP | Ethernet | Task 3 |
| 3 | Checksum | — (unit tests) | Task 2+ |
| 4 | IPv4 + ICMPv4 | Ethernet, ARP | Task 4 |
| 5 | UDP | IPv4 | Task 5 |
| 6 | TCP | IPv4 | Task 6 |
| 7 | Integration | All above | Task 7 |
| 8 | DHCPv4 | UDP | Task 8 |
| 9 | TFTP | UDP | Task 9 |
| 10 | HTTP | TCP | Task 10 |
| 11 | DNS | UDP | Task 8+ |
| 12 | IPv6 family | Ethernet | V2 |
| 13 | DHCPv6 | IPv6, UDP | V2 |

## 9. Reporting

### 9.1 CI Reports

- pytest generates JUnit XML for GitHub Actions
- Test results visible on PR checks
- Failures block merge

### 9.2 Requirement Coverage Report

Script to generate coverage report from test results + requirements files:

```bash
python scripts/req_coverage.py
# Output:
# REQ-ARP-001  MUST    PASS   TEST-ARP-001
# REQ-ARP-002  MUST    PASS   TEST-ARP-002
# REQ-ARP-003  MUST    FAIL   TEST-ARP-003  ← blocks release
# REQ-ARP-033  MAY     SKIP   TEST-ARP-033  ← ok to skip MAY
```

### 9.3 Release Criteria

- All MUST requirements: corresponding tests PASS
- All SHOULD requirements: corresponding tests PASS or documented deviation
- MAY requirements: tests may be SKIP
- All interop tests PASS
- No robustness test crashes (may discard bad packets, must not crash)

## 10. Document Maintenance

This test plan and the requirements documents MUST be kept in sync:
- Adding a new requirement → add corresponding test ID
- Implementing a feature → implement the corresponding tests
- Changing protocol behavior → update requirement, update test
- PR reviews should verify test↔requirement traceability

## 11. Future Considerations

- **Fuzz testing:** Use Scapy's `fuzz()` to generate random protocol packets. The stack must not crash.
- **Long-running stability tests:** Run for hours with continuous traffic. Monitor for memory leaks (relevant for hosted environments; embedded has no dynamic allocation).
- **Multi-platform hardware testing:** When MCU targets are available, run a subset of conformance tests against the actual hardware via a physical Ethernet connection.
- **Wireshark validation:** Capture test traffic and verify with Wireshark's protocol dissectors as a cross-check.
