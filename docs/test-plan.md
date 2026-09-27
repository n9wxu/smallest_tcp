# Test Plan — smallest_tcp

*Revision: Milestone 13 (TLS 1.3) — updated 2026-09-27*

---

## Overview

Three complementary test layers ensure every MUST-level requirement is
verified at both the unit and integration levels:

| Layer | Framework | Location | Trigger |
|---|---|---|---|
| C Unit Tests | Custom `TEST`/`ASSERT` macros (`tests/unit/test_main.h`), run by CTest | `tests/unit/` | Every push/PR |
| Blackbox Conformance | Python / Scapy (pytest) | `tests/blackbox/` | Every push/PR |
| Fuzz / Robustness | Python / Scapy `fuzz()` (pytest) | `tests/blackbox/` | Nightly / manual |

---

## 1. C Unit Tests

### Current Status

**28 test suites — all passing** (CTest, the default dual-stack build with `SMALLEST_TCP_TLS`): **690 tests on macOS; on Linux 693, or 701 as root**.  The difference is `test_rawsock`: 4 portable tests everywhere, 3 more on Linux, and 8 live tests on a veth pair that run only as root (CI runs them with `sudo` in `cmake-linux`; an unprivileged `ctest` skips them).  CMake is the only host build.  The four TLS suites need `SMALLEST_TCP_TLS` (Mbed TLS) and the seven IPv6 suites `SMALLEST_TCP_IPV6`; the IPv4-only CI job (`cmake-ipv4-only`) builds the other 17.

| Suite | File | Tests | Protocols Covered |
|---|---|---|---|
| `test_endian` | tests/unit/test_endian.c | 10 | Byte-order utilities |
| `test_checksum` | tests/unit/test_checksum.c | 12 | net_cksum (REQ-CKS-*) |
| `test_eth` | tests/unit/test_eth.c | 11 | Ethernet (REQ-ETH-*) |
| `test_net` | tests/unit/test_net.c | 8 | net init/dispatch |
| `test_arp` | tests/unit/test_arp.c | 8 | ARP (REQ-ARP-*) |
| `test_ipv4` | tests/unit/test_ipv4.c | 10 | IPv4 (REQ-IPV4-*) |
| `test_icmp` | tests/unit/test_icmp.c | 4 | ICMPv4 (REQ-ICMP-*) |
| `test_udp` | tests/unit/test_udp.c | 7 | UDP (REQ-UDP-*) |
| `test_tcp_buf` | tests/unit/test_tcp_buf.c | 20 | Stop-and-wait TX/RX buffers (incl. RX ring wrap) |
| `test_tcp` | tests/unit/test_tcp.c | **46** | TCP (REQ-TCP-*), incl. data/FIN retransmission, tcp_write/output, window updates, in-order delivery (overlaps trimmed, segments and FINs after a gap not taken), no RST for a broadcast SYN |
| `test_tftp` | tests/unit/test_tftp.c | 15 | TFTP client (REQ-TFTP-*) |
| `test_dhcpv4` | tests/unit/test_dhcpv4.c | 26 | DHCPv4 client + server (REQ-DHCPv4-*) |
| `test_dns_wire` | tests/unit/test_dns_wire.c | 23 | DNS names, compression, parsing (REQ-MDNS-003/043, REQ-DNSSD-031) |
| `test_mcast` | tests/unit/test_mcast.c | 19 | Multicast RX, per-packet TTL, IGMPv2 (REQ-MDNS-002/006) |
| `test_mdns` | tests/unit/test_mdns.c | 49 | mDNS responder + DNS-SD (REQ-MDNS-*, REQ-DNSSD-*), incl. NSEC |
| `test_http` | tests/unit/test_http.c | 45 | HTTP parser, formatter, server driven over the real TCP (REQ-HTTP-*) |
| `test_ipv6` | tests/unit/test_ipv6.c | 55 | IPv6 parse/build + extension headers, EUI-64 / solicited-node / multicast MAC, ICMPv6 echo + errors, NS/NA responder, DAD (REQ-IPv6-*, REQ-ICMPv6-*, REQ-NDP-*, REQ-SLAAC-004..013); built with `NET_USE_IPV6=1` |
| `test_udp6` | tests/unit/test_udp6.c | 14 | UDP over IPv6: `udp6_ports` dispatch, payload offset after extension headers, mandatory checksum (zero dropped, computed 0 sent as 0xFFFF), Port Unreachable, `udp6_send[_inplace]` (REQ-IPv6-044,045, REQ-ICMPv6-016) |
| `test_tcp6` | tests/unit/test_tcp6.c | 18 | TCP over IPv6: passive/active open, data, RSTs, 4-tuple match by IPv6 address, retransmit, close, reply from the address used, one listener for both families, default MSS 1220, send MSS clamped to the TX frame buffer (IPv4 and IPv6) |
| `test_slaac` | tests/unit/test_slaac.c | 26 | Router Solicitation (format, 3 × 4 s, stops at an RA), Router Advertisement (router + MAC, hop limit, M/O, lifetime 0/expiry, validation), SLAAC (A flag, /64, DAD, link-local prefix, duplicate), lifetimes (deprecate, remove, infinite, 2-hour rule, preferred again), `ipv6_addr_add`, on-link test, reply from the global address (REQ-NDP-034..048, REQ-SLAAC-014..031) |
| `test_mld` | tests/unit/test_mld.c | 13 | MLDv2 report before the DAD probe (from ::), repeated once, one group per solicited-node address, `ipv6_mcast_join/leave` (report, frame filter, delivery), general / group queries (delay, validation), MLDv1 compatibility (v1 reports, Done, fallback timeout) — RFC 3810, RFC 2710 |
| `test_mdns6` | tests/unit/test_mdns6.c | 19 | mDNS over IPv6: ff02::fb joined, probes / announcements / goodbyes on both families, AAAA per usable address (not tentative), answers on the query's family, A ↔ AAAA and SRV → AAAA additionals, QU and legacy unicast over IPv6, known-answer suppression, NSEC with AAAA, delayed shared answers, explicit AAAA, conflicts, re-announcing (RFC 6762 §6.2, §8.4, §20) |
| `test_dhcpv6` | tests/unit/test_dhcpv6.c | 20 | DHCPv6 client: Information-Request (DUID-LL, Elapsed Time, ORO), §15 backoff with jitter, stateless Reply → handlers, xid / Client ID / truncated-option checks, Solicit (IA_NA, first RT > IRT), Advertise → Request, Reply → address + DAD, Renew at T1, Rebind at T2, expiry, Request gives up after 10, T1/T2 from the preferred lifetime, Release (REQ-DHCPv6-*) |
| `test_rawsock` | tests/unit/test_rawsock.c | 15 on Linux (4 elsewhere) | Raw-socket driver: offloaded-checksum completion (portable); context and no-frame checks (Linux); live on a veth pair (Linux, root, 8): send/receive, promiscuous mode, own/outgoing frames ignored, oversize frames dropped whole, kernel TCP/UDP checksums finished |
| `test_tls_crypto` | tests/unit/test_tls_crypto.c | 22 | Mbed TLS backend known answers: SHA-256, HMAC (RFC 4231), HKDF (RFC 5869), AES-128-GCM, X25519 (RFC 7748), P-256, ECDSA, RSA-PSS, certificate chains (alerts, IP names), random (REQ-TLS-006) |
| `test_tls_keys` | tests/unit/test_tls_keys.c | 34 | Key schedule and record protection against RFC 8448 §3 (all secrets, keys, IVs, Finished, eight records byte for byte), §4 (PSK binder, PSK + DHE), §5 (HRR transcript); malformed records (REQ-TLS-026..034) |
| `test_tls_server` | tests/unit/test_tls_server.c | 103 | Server handshake against a scripted client: RFC 8448 ServerHellos byte for byte, every refusal, CCS, fragments, small tx, PSK, HelloRetryRequest, max_fragment_length, KeyUpdate, alerts (REQ-TLS-001, 018..025, 030, 031, 035..043) |
| `test_tls_client` | tests/unit/test_tls_client.c | 49 | Client handshake against our server (memory transport) and a scripted server with faults: ClientHello contents, chain/name/CertificateVerify/Finished checks, PSK, HRR, max_fragment_length, KeyUpdate (REQ-TLS-010..017, 023, 031) |

### Running Unit Tests

```sh
cmake -S . -B build && cmake --build build
ctest --test-dir build --output-on-failure

# IPv4 only, without TLS (what the cmake-ipv4-only CI job builds)
cmake -S . -B build-v4 -DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF
cmake --build build-v4 && ctest --test-dir build-v4 --output-on-failure

# The raw-socket driver's live tests (Linux, root)
sudo ./build/tests/test_rawsock
```

The `Makefile` has no host targets: it builds the Cortex-M0 size benchmarks
(`make arm-size-all`, section 3).

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
| 085–087 | Zero-window persist timer | `test_tcp_persist_starts_on_zero_window`, `test_tcp_persist_probe_sent_on_timeout`, `test_tcp_persist_stops_when_window_opens`, `test_tcp_085_persist_probe_on_zero_window` (blackbox) | ✅ pass |
| 028/029/153 | ISS non-predictable | (blackbox only) | 🔲 Blackbox |
| 155 | RST rate limiting | (blackbox only) | 🔲 Blackbox |

> ✅ REQ-TCP-085, 086, 087 (zero-window persist timer) are now implemented and covered by 3 unit tests and 1 blackbox test.

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
| `tests/blackbox/conftest.py` | pytest fixtures, CLI options, ARP pre-flight, port allocator, `sut_settle` autouse fixture |
| `tests/blackbox/helpers.py` | `TcpConn`, `tcp_connect()`, `send_recv()`, `silence()`, ARP/ICMP/UDP/IPv4 frame builders |
| `tests/blackbox/test_arp_conform.py` | 5 conformance tests (REQ-ARP-001..005) |
| `tests/blackbox/test_ipv4_conform.py` | 8 conformance tests (REQ-IPv4-002..044) |
| `tests/blackbox/test_icmp_conform.py` | 7 conformance tests (REQ-ICMPv4-001..034) |
| `tests/blackbox/test_udp_conform.py` | 7 conformance tests (REQ-UDP-001..008) |
| `tests/blackbox/test_tcp_conform.py` | 20 conformance tests (REQ-TCP-002..153) |
| `tests/blackbox/test_tcp_fuzz.py` | 5 fuzz tests (header fields, flags, options, truncation) |
| `tests/blackbox/test_dhcpv4_conform.py` | 8 DHCPv4 client tests (SUT: `dhcp_echo_demo`) |
| `tests/blackbox/test_mdns_conform.py` | 21 mDNS / DNS-SD tests, 19 of them over IPv4 (SUT: dual-stack `mdns_demo`, launched fresh per test) |
| `tests/blackbox/test_http_conform.py` | 22 HTTP tests; the host's own TCP stack is the client, over IPv4 and IPv6 (SUT: `http_demo`) |
| `tests/blackbox/test_ipv6_conform.py` | 29 IPv6 / ICMPv6 / NDP / DAD / UDP / TCP / SLAAC / DHCPv6 / MLD tests (SUT: dual-stack `tcp_echo_demo`, launched fresh per test) |
| `tests/blackbox/test_tls_conform.py` | 29 TLS 1.3 server tests (25 functions, two parametrized) against `tls_echo_demo` |
| `tests/blackbox/test_tls_client_conform.py` | 17 TLS 1.3 client tests: `tls_client_demo` against Python ssl and openssl s_server |
| `tests/blackbox/test_https_conform.py` | 9 HTTPS tests against `https_demo` |
| `tests/blackbox/dhcpv6_interop.sh` | dnsmasq as router + DHCPv6 server: RA with M → lease, DNS option, host ping + TCP echo at the leased address |
| `tests/blackbox/http_interop.sh` | Browse by name on Linux: Avahi finds `_http._tcp`, nss-mdns + curl fetch `http://pyro-dead01.local/`; `curl -6` over the link-local address |
| `tests/blackbox/http_interop_macos.sh` | Browse by name on macOS: `dns-sd` + curl, lookup time bounded |
| `tests/blackbox/mdns_interop.sh` | Avahi interop: resolve (IPv4, and IPv6 when Avahi runs it) + browse the demo, goodbye withdraws the service |
| `tests/blackbox/run_blackbox_macos.sh` | macOS runner over a `feth` pair: every suite + `dns-sd` interop |
| `tests/blackbox/mdns_interop_macos.sh` | mDNSResponder interop: `dns-sd -B/-L/-G`, TCP echo, goodbye removal |
| `tests/blackbox/run_blackbox.sh` | Shell runner: starts `tcp_echo_demo`, runs the core suites (ARP, IPv4, ICMP, UDP, TCP) in order, reports summary; `--dhcp` adds DHCPv4, `--fuzz` the fuzz tests |
| `tests/blackbox/sut_net.sh` | Builds/removes the harness↔SUT link for one Linux driver: `tap` (tap0) or `raw` (veth-test ↔ veth-sut); prints `TEST_IF` / `SUT_IF` |
| `tests/blackbox/requirements.txt` | `pytest>=7.0`, `scapy>=2.5` |

### Running Blackbox Tests (Local)

```sh
# 1. Build the SUT binary
cmake -S . -B build
cmake --build build --target tcp_echo_demo
# Binary is at: build/demo/tcp_echo_demo   ← note the demo/ subdirectory

# 2. Install Python deps
pip install -r tests/blackbox/requirements.txt

# 3. Set up TAP interface (Linux only)
sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip link set tap0 up
sudo ip addr add 10.0.0.100/24 dev tap0
# Drop kernel RSTs so Scapy connections aren't torn down:
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# 4. Start the SUT in the background
sudo ./build/demo/tcp_echo_demo &   # ← build/DEMO/tcp_echo_demo, not build/

# 5. Option A — run the core suites (ARP, IPv4, ICMP, UDP, TCP) via the shell runner
#    (starts SUT, runs each suite, stops SUT, prints ✓/✗ summary)
sudo tests/blackbox/run_blackbox.sh \
    --sut-bin ./build/demo/tcp_echo_demo \
    --setup-tap --teardown-tap -v

# 5. Option B — run a single suite manually
sudo python3 -m pytest tests/blackbox/test_tcp_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

# Run fuzz tests (200 iterations, ~60 seconds)
sudo python3 -m pytest tests/blackbox/test_tcp_fuzz.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
    --fuzz-count 200 -v
```

> ⚠️ **Common mistake:** CMake places the demo binary under
> `build/demo/tcp_echo_demo` (mirroring the `demo/` source subdirectory),
> **not** at `build/tcp_echo_demo`.  Using the wrong path causes `sudo`
> to silently fail, the SUT never starts, and every test ERRORs with
> `ARP timeout: no reply from 10.0.0.2`.  See
> [§6 Troubleshooting](#6-troubleshooting--known-pitfalls) for more.

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
| test_tcp_085 | REQ-TCP-085,086,087 | Zero-window persist: probe sent, window reopened |
| test_tcp_090 | REQ-TCP-095,096 | SYN-ACK retransmit on RTO |
| test_tcp_097 | REQ-TCP-097,098 | No spurious retransmit after ACK |
| test_tcp_153 | REQ-TCP-153 | ISS different across connections |

### Blackbox ARP Conformance Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_arp_001 | REQ-ARP-001 | ARP who-has for SUT IP → reply received |
| test_arp_002 | REQ-ARP-001,002 | Reply hwsrc and sender IP are correct |
| test_arp_003 | REQ-ARP-003 | who-has for unrelated IP → silence |
| test_arp_004 | REQ-ARP-005 | ARP request populates SUT's cache (verified via ICMP) |
| test_arp_005 | REQ-ARP-001 | Repeated who-has → consistent MAC returned |

### Blackbox IPv4 Conformance Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_ipv4_001 | REQ-IPv4-005 | Bad IP header checksum → silent drop |
| test_ipv4_002 | REQ-IPv4-011 | Wrong destination IP → silent drop |
| test_ipv4_003 | REQ-IPv4-020, REQ-ICMPv4-017 | Unknown protocol → ICMP Protocol Unreachable (type 3 code 2) |
| test_ipv4_004 | REQ-IPv4-024 | Non-first fragments (MF=1 or offset≠0) → silent drop |
| test_ipv4_005 | REQ-IPv4-002 | IHL < 5 → silent drop |
| test_ipv4_006 | REQ-IPv4-044 | TTL=1 packet accepted (hosts do not check TTL on RX) |
| test_ipv4_007 | REQ-IPv4-023 | SUT outbound packets have DF=1 |
| test_ipv4_008 | REQ-IPv4-026 | IP options (IHL=6) accepted; payload still processed |

### Blackbox ICMPv4 Conformance Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_icmp_001 | REQ-ICMPv4-001 | Echo Request → Echo Reply (type 0) |
| test_icmp_002 | REQ-ICMPv4-002 | Identifier and Sequence Number preserved in reply |
| test_icmp_003 | REQ-ICMPv4-003 | Payload data preserved verbatim in reply |
| test_icmp_004 | REQ-ICMPv4-006,032 | Echo Reply checksum is valid |
| test_icmp_005 | REQ-ICMPv4-031 | Bad ICMP checksum → silent drop |
| test_icmp_006 | REQ-ICMPv4-009 | Broadcast ping (255.255.255.255) → no reply |
| test_icmp_007 | REQ-ICMPv4-034 | No ICMP error generated in response to ICMP error |

### Blackbox UDP Conformance Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_udp_001 | REQ-UDP-001 | Echo on port 7 — data returned verbatim |
| test_udp_002 | REQ-UDP-003 | Echo reply has src/dst ports correctly swapped |
| test_udp_003 | REQ-UDP-005, REQ-ICMPv4-018 | Unknown port → ICMP Destination Unreachable, Port Unreachable (type 3 code 3) |
| test_udp_004 | REQ-ICMPv4-038 | ICMP Unreachable body contains original IP header + 8 UDP bytes |
| test_udp_005 | REQ-UDP-006 | Bad UDP checksum → silent drop |
| test_udp_006 | REQ-UDP-007 | Zero UDP checksum (disabled) accepted and echoed |
| test_udp_007 | REQ-UDP-008 | UDP Length < 8 → silent drop |

### Blackbox mDNS + DNS-SD Conformance Coverage

Run with `--mdns-sut-bin ./build/demo/mdns_demo`; each test starts a fresh SUT
(IGMP join, probing, announcing and goodbye are start-up / shutdown behaviour).
Skipped when the option is not given.

| Test | REQ | Checks |
|---|---|---|
| test_mdns_001 | REQ-MDNS-009,014,026 | A query → SUT IP, TTL 120, cache-flush |
| test_mdns_002 | REQ-DNSSD-001,007,016 | PTR answer + SRV/TXT/A additionals |
| test_mdns_003 | REQ-DNSSD-002,008 | SRV port 80 → host, A additional |
| test_mdns_004 | REQ-MDNS-004,031 | QR=1, AA=1 on every response |
| test_mdns_005 | REQ-MDNS-005 | ID 0 on multicast responses |
| test_mdns_006 | REQ-MDNS-001,006 | IP TTL 255, source port 5353 |
| test_mdns_007 | REQ-MDNS-029 | Known-answer suppression (fresh vs stale) |
| test_mdns_008 | REQ-MDNS-032,033, REQ-DNSSD-018 | SIGTERM → goodbye, all TTL 0 |
| test_mdns_009 | REQ-DNSSD-014,015 | Service-type meta-query |
| test_mdns_010 | REQ-MDNS-016..018 | 3 probes, 150–450 ms apart, ANY/QU, Authority records |
| test_mdns_011 | REQ-MDNS-021..023 | 2 announcements 0.8–1.5 s apart after probing |
| test_mdns_012 | REQ-MDNS-019,020 | Conflict while probing → rename, old name never announced |
| test_mdns_013 | REQ-MDNS-002 | IGMPv2 report for 224.0.0.251 (TTL 1) |
| test_mdns_014 | REQ-MDNS-041 | Legacy unicast: ID + question echoed, TTL ≤ 10 |
| test_mdns_015 | REQ-MDNS-028 | QU → unicast reply |
| test_mdns_016 | REQ-MDNS-030 | Foreign / unknown names ignored |
| test_mdns_017 | REQ-DNSSD-003,011,013 | TXT key=value strings |
| test_mdns_018 | REQ-MDNS-026 | ANY → SRV + TXT |
| test_mdns_019 | RFC 6762 §6.1 | A type our host lacks (HINFO) → NSEC listing the types we have |
| test_mdns_020 | RFC 6762 §6.2, §20 | AAAA query to ff02::fb → answer over IPv6 (Hop Limit 255) with the link-local address, A as additional |
| test_mdns_021 | RFC 6762 §8.3, §8.4 | Records announced over IPv6 (AAAA and A) once the link-local address is usable |

`tests/blackbox/mdns_interop.sh` then checks REQ-MDNS-040 / REQ-DNSSD-027 with
Avahi (`avahi-resolve`, `avahi-browse`) in the `blackbox-mdns` CI job.

### Blackbox IPv6 Conformance Coverage

Run with `--ipv6-sut-bin ./build/demo/tcp_echo_demo` (dual-stack CMake build);
each test starts a fresh SUT and, except the DAD tests, waits for it to log its
link-local address as preferred.  The harness sends from a phantom link-local
address, `fe80::100`.  Skipped when the option is not given.

| Test | REQ | Checks |
|---|---|---|
| test_ipv6_001 | REQ-SLAAC-004..006 | DAD probe at start-up: NS from `::` to the solicited-node group, Hop Limit 255, no SLLA |
| test_ipv6_002 | REQ-SLAAC-010 | Address preferred after RetransTimer with no conflict |
| test_ipv6_003 | REQ-SLAAC-008 | NA for the tentative address → duplicate, never used |
| test_ipv6_004 | REQ-NDP-016,018 | Another node's DAD probe for our address → NA to all-nodes, S=0 |
| test_ipv6_005 | REQ-NDP-011..013,017,019 | NS → NA: S=1 O=1 R=0, TLLA = SUT MAC, to the SLLA |
| test_ipv6_006 | REQ-NDP-001 | NS with Hop Limit 254 ignored |
| test_ipv6_007 | REQ-ICMPv6-004..008 | Echo reply: id, seq, data, addresses |
| test_ipv6_008 | REQ-ICMPv6-009 | Echo to ff02::1 answered from the unicast address |
| test_ipv6_009 | REQ-ICMPv6-002 | Bad checksum → no reply |
| test_ipv6_010 | REQ-IPv6-018,019 | Echo behind a Hop-by-Hop header |
| test_ipv6_011 | REQ-IPv6-017, REQ-ICMPv6-026,027 | Unknown Next Header → Parameter Problem code 1, pointer 6 |
| test_ipv6_012 | REQ-IPv6-022 | Fragments silently dropped (no reassembly) |
| test_ipv6_013 | RFC 4861 interop | The host's `ping -6` resolves the SUT with NDP and gets replies (skipped without IPv6 on the harness interface) |
| test_ipv6_014 | RFC 768 / 8200 §8.1 | UDP echo over IPv6, valid reply checksum |
| test_ipv6_015 | REQ-IPv6-045 | UDP with a zero checksum dropped |
| test_ipv6_016 | REQ-ICMPv6-016 | Closed port → Destination Unreachable code 4 quoting the datagram |
| test_ipv6_017 | interop | The host's UDP socket gets its echo over IPv6 (offloaded checksums on the raw link) |
| test_ipv6_018 | RFC 9293 / 8200 §8 | SYN-ACK over IPv6: link-local source, MSS 1440, valid checksum |
| test_ipv6_019 | RFC 9293 | Data echoed on an IPv6 connection |
| test_ipv6_020 | REQ-TCP-072 | SYN to a closed port → RST+ACK over IPv6 |
| test_ipv6_021 | interop | The host's TCP stack connects over IPv6 and gets its echo |
| test_ipv6_022 | REQ-NDP-034..037 | Router Solicitation to ff02::2 from the link-local address with SLLA |
| test_ipv6_023 | REQ-SLAAC-014..018 | RA with an autonomous /64 → DAD → global address answers (echo from an off-link peer) |
| test_ipv6_024 | REQ-NDP-042 | RA Cur Hop Limit used on replies |
| test_ipv6_025 | interop | The host (prefix on its interface) pings the SLAAC address and connects to it (Linux) |
| test_ipv6_026 | REQ-DHCPv6-011..032 | RA with M → Solicit (DUID-LL, IA_NA) → Advertise → Request (Server ID, address) → Reply → DAD → the leased address answers |
| test_ipv6_027 | REQ-DHCPv6-001..008 | RA with O → Information-Request (no IA_NA, ORO has 23) → Reply → DNS server reaches the application |
| test_ipv6_028 | RFC 3810, REQ-SLAAC-013 | MLDv2 report at start-up: ff02::16, Hop Limit 1, Router Alert, the solicited-node group, never all-nodes |
| test_ipv6_029 | RFC 3810 §6.2 | A router's general query gets a report of our groups from the link-local address |

### Blackbox HTTP Conformance Coverage

Run with `--http-sut-bin ./build/demo/http_demo`; the SUT is started once for the
module and the client is the test host's TCP stack (no RST-drop iptables rule).

| Test | REQ | Checks |
|---|---|---|
| test_http_001 | REQ-HTTP-002, 016, 019..022, 029 | GET / → 200, headers, body, server closes |
| test_http_002 | REQ-HTTP-004, 023 | HEAD → same Content-Length, no body |
| test_http_003 | REQ-HTTP-006, 010 | HTTP/1.1 + Host works; answered as HTTP/1.0 |
| test_http_004 | RFC 9112 §3.2.2 | Absolute-form target |
| test_http_005 | REQ-HTTP-003, 032, 036 | POST body echoed |
| test_http_006 | REQ-HTTP-032 | Headers and body in separate segments |
| test_http_007 | REQ-HTTP-037 | Generated JSON, query passed through |
| test_http_008 | — | 8000-byte body streamed intact |
| test_http_009 | — | Request trickled one byte per segment |
| test_http_010 | REQ-HTTP-025 | 404 |
| test_http_011 | REQ-HTTP-024 | 405 + Allow |
| test_http_012 | REQ-HTTP-024 | 501 for PUT / DELETE |
| test_http_013 | REQ-HTTP-026, 010 | 400: malformed line, 1.1 without Host, header without ':' |
| test_http_014 | — | 505 for HTTP/2.0 |
| test_http_015 | REQ-HTTP-039, 041 | 414 |
| test_http_016 | REQ-HTTP-040 | 431 |
| test_http_017 | REQ-HTTP-033, 034 | 413 |
| test_http_018 | — | Transfer-Encoding → 501 |
| test_http_019 | REQ-HTTP-028, 029 | 30 back-to-back requests (no TIME_WAIT stall) |
| test_http_020 | — | Two concurrent connections |
| test_http_021 | — | Idle client reset after the 10 s request timeout (`sut_specific`) |
| test_http_022 | RFC 9110 over IPv6 | The status page fetched from the demo's link-local address (Linux; skipped without host IPv6) |

### Blackbox TLS 1.3 and HTTPS Coverage

Run with `--tls-sut-bin ./build/demo/tls_echo_demo`, `--tls-client-bin
./build/demo/tls_client_demo` and `--https-sut-bin ./build/demo/https_demo`
(`--our-ip` is where the client demo finds its servers).  The peers are
production TLS stacks on the test host — Python's ssl module, openssl
s_client/s_server, curl — through the host's TCP to ours.

| Suite | Tests | Checks |
|---|---|---|
| test_tls_conform.py (server) | 29 | Handshake with CA and name checks; 40 kB and full 16 kB-record echoes; close_notify; IP-address name; five in a row; TLS 1.2, plain HTTP and a tampered record refused (protocol_version, unexpected_message, bad_record_mac); half a ClientHello then RST; a ClientHello in 7-byte segments; coalesced records; x25519 and P-256; OpenSSL's default (post-quantum) ClientHello; no middlebox mode; no common group / suite / signature (handshake_failure); KeyUpdate; HelloRetryRequest; max_fragment_length 512; PSK (openssl, Python 3.13+), wrong PSK, unknown identity → certificate; IPv6 |
| test_tls_client_conform.py (client) | 17 | SNI; 30 kB echo; RSA-PSS; no name check; max_fragment_length; KeyUpdate; wrong name (bad_certificate), untrusted chain (unknown_ca), TLS 1.2 server; optional and required client certificates; openssl s_server -rev; HRR from a P-256-only server; PSK against Python and certificate-less s_server (psk_dhe_ke, psk_ke), wrong PSK |
| test_https_conform.py | 9 | GET / JSON / 20000-byte body / HEAD / 404 / 405 + Allow over TLS 1.3; by address; curl by name; five in a row |

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
| `cmake-ipv4-only` | ci.yml | ubuntu-latest | ctest on an IPv4-only build without TLS (`-DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF`); then library-only builds without TCP and without UDP | push/PR |
| `cmake-linux` | ci.yml | ubuntu-latest | ctest (dual stack, TLS) | push/PR |
| `cmake-macos` | ci.yml | macos-latest | ctest (dual stack, TLS) | push/PR |
| `cmake-linux` (root step) | ci.yml | ubuntu-latest | `sudo test_rawsock`: raw-socket driver live tests on a veth pair | push/PR |
| `blackbox-linux` | ci.yml | ubuntu-latest | Linux sanity (arping/ping/nc) + Scapy full conformance via `run_blackbox.sh` — once over TAP, once over the raw socket | push/PR |
| `blackbox-validate` | ci.yml | ubuntu-latest | Same Scapy suites against Linux kernel reference SUT (`socat` echo); `-m "not sut_specific"` | push/PR |
| `blackbox-ipv6` | ci.yml | ubuntu-latest | IPv6 / ICMPv6 / NDP / DAD / UDP / TCP / SLAAC / DHCPv6 suite against dual-stack `tcp_echo_demo`, then DHCPv6 interop with dnsmasq (TAP, raw socket) | push/PR |
| `blackbox-dhcp` | ci.yml | ubuntu-latest | DHCPv4 client suite against `dhcp_echo_demo` (TAP, raw socket) | push/PR |
| `blackbox-mdns` | ci.yml | ubuntu-latest | mDNS/DNS-SD suite against `mdns_demo` (TAP, raw socket), then Avahi interop | push/PR |
| `blackbox-http` | ci.yml | ubuntu-latest | HTTP suite against `http_demo` (TAP, raw socket), then browse-by-name (Avahi + nss-mdns + curl) | push/PR |
| `blackbox-tls` | ci.yml | ubuntu-latest | TLS 1.3 server, client and HTTPS suites against `tls_echo_demo`, `tls_client_demo`, `https_demo` with Python ssl, OpenSSL 3 and curl (TAP, raw socket) | push/PR |
| `arm-size` | ci.yml | ubuntu-latest | `make arm-size-all`: Cortex-M0 size benchmark (UDP, UDP+TCP, UDP+mDNS, UDP+HTTP, dual stack, TLS server-only and both roles), then `arm-check-division` — fails if any object calls a library divide | push/PR |
| `fetchcontent` | ci.yml | ubuntu-latest | Builds and runs `examples/fetchcontent` against the checkout | push/PR |
| `fuzz-tcp-linux` | fuzz.yml | ubuntu-latest | Scapy fuzz + post-fuzz conformance (TAP, raw socket) | Nightly 02:00 UTC |
| `fuzz-tcp-hw` | fuzz.yml | self-hosted, hw-dut | Scapy fuzz (real HW) | Nightly (when enabled) |

The Linux blackbox jobs and the nightly fuzz run as a two-leg matrix,
one leg per MAC driver.  `tests/blackbox/sut_net.sh up tap|raw` builds the
link and exports `TEST_IF` (tap0 / veth-test, for Scapy and the host) and
`SUT_IF` (tap0 / `raw:veth-sut`, the demos' interface argument).  A failure in
one leg only points at that driver or at link-specific behaviour: with the raw
socket, segments from the host kernel arrive with offloaded (partial)
checksums that the driver must finish.

### Two-Job Interpretation

`blackbox-linux` and `blackbox-validate` run the same test files with different SUTs:

- **`blackbox-validate` FAILS** → the test itself is wrong (assertion, timing, operator precedence). Fix the test.
- **`blackbox-validate` PASSES, `blackbox-linux` FAILS** → our SUT has a real RFC compliance bug. Fix the SUT.

Tests marked `@pytest.mark.sut_specific` are excluded from `blackbox-validate` because they depend on `smallest_tcp`'s specific timer values (e.g. its 1 s initial RTO and persist interval), not RFC-mandated behaviour.  See [`docs/ci-debugging.md`](ci-debugging.md) for the full debugging workflow.

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
| 1 | REQ-TCP-085/086/087 | Zero-window persist timer — **IMPLEMENTED, all tests pass** | ✅ Closed |
| 2 | REQ-TCP-004/007 | Simultaneous open/close | Low (MAY, rare) |
| 3 | REQ-TCP-113/114/117/122-124 | Window Scale, Timestamps, SACK options | Low (MAY) |
| 4 | REQ-TCP-130/132-134 | TCP_NODELAY, Keep-alive | Low (MAY) |
| 5 | Blackbox ETH/ARP/IPv4/ICMPv4/UDP | Retroactive Scapy suites — **IMPLEMENTED** (5+8+7+7 tests, `run_blackbox.sh` runner) | ✅ Closed |
| 6 | Hardware fixture | Procure BOM, set up self-hosted runner | Medium |
| 7 | REQ-TLS-003 | TLS_CHACHA20_POLY1305_SHA256 (SHOULD) | Low |
| 8 | TLS | Client certificates, session tickets / 0-RTT, record_size_limit (RFC 8449) | Low |

---

## 6. Troubleshooting / Known Pitfalls

This section captures issues encountered during CI debugging so they are
not repeated.

---

### ❌ All blackbox tests ERROR: `ARP timeout: no reply from 10.0.0.2`

**Symptom:** Every test in `test_tcp_conform.py` reports `ERROR` (not
`FAILED`).  The conftest `ctx` fixture cannot resolve the SUT's MAC via
ARP and raises `RuntimeError: ARP timeout …`.

**Root cause:** The SUT (`tcp_echo_demo`) is not running — or is not
attached to the TAP interface — so no process is listening for ARP
requests on tap0.

**Diagnostic checklist:**

| Check | Command | Expected |
|---|---|---|
| SUT process alive? | `pgrep -a tcp_echo_demo` | Shows the PID |
| SUT log shows TAP open | check sut.log / stderr | `[TAP] Opened tap0 (fd=N)` |
| `/dev/net/tun` exists | `ls -la /dev/net/tun` | `crw-rw-rw- … 10, 200` |
| tap0 is UP | `ip link show tap0` | `state UP` or `state UNKNOWN` |
| SUT binary path correct? | `ls build/demo/tcp_echo_demo` | file exists |

**Most frequent cause — wrong binary path:**  
CMake mirrors the source tree.  `demo/tcp_echo/main.c` → binary at
`build/demo/tcp_echo_demo`, **not** `build/tcp_echo_demo`.

```sh
# WRONG — sudo silently exits with "command not found"
sudo ./build/tcp_echo_demo &

# CORRECT
sudo ./build/demo/tcp_echo_demo &
```

---

### ❌ `sudo: ./build/tcp_echo_demo: command not found`

The binary path is wrong.  CMake places every target in a directory that
mirrors its `CMakeLists.txt` location:

| Target | Source | Binary |
|---|---|---|
| `tcp_echo_demo` | `demo/tcp_echo/main.c` | `build/demo/tcp_echo_demo` |
| `frame_dump` | `demo/frame_dump/main.c` | `build/demo/frame_dump` |
| `test_tcp` | `tests/unit/test_tcp.c` | `build/tests/test_tcp` |

Always verify the full path with `find build/ -name tcp_echo_demo` after
a clean build.

---

### ❌ `tap_init: open /dev/net/tun: No such file or directory`

The Linux TUN/TAP kernel module is not loaded (or `/dev/net/tun` does
not exist as a device node).

- On **GitHub Actions ubuntu-latest**: TUN is always available.
- On **LXC containers** (e.g. Proxmox): TUN/TAP may not be forwarded
  into the container.  You must enable TUN in the container's Proxmox
  configuration (`lxc.cgroup2.devices.allow = c 10:200 rwm`), or use a
  KVM VM instead of an LXC container for blackbox testing.
- On a **bare-metal or KVM** machine without TUN loaded:
  `modprobe tun && ls /dev/net/tun` to verify.

---

### ❌ SUT starts but ARP still times out

If `[TAP] Opened tap0 (fd=N)` appears in the SUT log but ARP still
times out, investigate the data path:

```sh
# Watch all frames on tap0 while sending an ARP
sudo tcpdump -i tap0 -en &
sudo python3 -c "
from scapy.all import *
r = srp1(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst='10.0.0.2'),
         iface='tap0', timeout=5, verbose=True)
print('reply:', r)"
```

- If tcpdump shows the ARP request but no reply: SUT is not processing
  or not sending — check `arp_input()` logic and SUT's IP configuration.
- If tcpdump shows both request and reply but `srp1` times out: Scapy's
  AF_PACKET socket is not receiving the reply — check Scapy version and
  interface binding.

---

### CI Debugging: reading the SUT log from GitHub annotations

The `blackbox-linux` CI job emits the SUT's startup log as
`::notice::SUT:` annotations.  To read them without a browser:

```sh
# List recent runs
curl -s "https://api.github.com/repos/n9wxu/smallest_tcp/actions/runs?per_page=3" \
  | jq '.workflow_runs[] | {id, status, conclusion, head_sha}'

# Get job IDs for a run
curl -s "https://api.github.com/repos/n9wxu/smallest_tcp/actions/runs/<RUN_ID>/jobs" \
  | jq '.jobs[] | {id, name, conclusion}'

# Read annotations for the blackbox job
curl -s "https://api.github.com/repos/n9wxu/smallest_tcp/check-runs/<JOB_ID>/annotations" \
  | jq '.[].message'
```

---

*Last updated: 2026-09-27 — Milestone 13 (TLS 1.3); CMake-only host build.*
