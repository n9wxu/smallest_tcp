# Test Plan — smallest_tcp

---

## Overview

Four kinds of test verify the requirements; two measures say how far they
reach (§0):

| Layer | Framework | Location | Trigger |
|---|---|---|---|
| C Integration Tests (black box through the API) | `TEST`/`ASSERT` macros and a scripted link (`tests/integration/wire.h`), run by CTest (label `integration`) | `tests/integration/` | Every push/PR |
| C Unit Tests | Custom `TEST`/`ASSERT` macros (`tests/unit/test_main.h`), run by CTest | `tests/unit/` | Every push/PR |
| Blackbox Conformance | Python / Scapy (pytest) against the demos on a live link | `tests/blackbox/` | Every push/PR |
| Fuzz / Robustness | Python / Scapy `fuzz()` (pytest) | `tests/blackbox/` | Nightly / manual |

---

## 0. Policy, and the integration tests

**Tests verify requirements, through the API.**  A test drives the stack
only as an application or the network can — the public API (`net_init()`,
`net_poll()`, `net_tick()`, the protocol modules' functions) and frames on
the wire — and checks only what those show: frames sent, events, return
values, API-visible state.  Tests coupled to the implementation (calling
internal functions, inspecting private fields) test how the code works, not
what it must do, and break when it is refactored.  New tests are written
this way; an existing unit test is rewritten at the API level, and the old
one removed, when its area is worked on.

**Every test traces to requirements.**  Each test names the REQ IDs it
verifies; `scripts/trace.py --strict` (CI job `traceability`) fails if an
integration test names none or a test names an ID no requirement document
defines.

**An error found outside the tests becomes a test first.**  A bug found by
an audit, a review, interop or in the field gets a failing integration (or
blackbox) test traced to the requirement it breaks — adding the row if the
requirement had none — and then the fix.  A requirement not met yet gets
its test at once, run with `RUN_XFAIL`: the test must fail, and turns the
run red if it starts passing, until the fix makes it `RUN_TEST`.

**Quality is measured by coverage, not by the number of tests.**  Two
measures, both produced by CI on every push:

- *Requirements coverage*: of the MUST rows of each requirement document,
  how many a black-box test verifies, how many any test verifies, and how
  many none does.
- *Code coverage*: the lines and branches of `src/` that the black-box
  integration tests reach, through the API alone.  Code they never reach is
  code no application can reach either: dead, or a test missing.

### Requirements coverage

`scripts/trace.py` reads the rows of `docs/requirements/*.md`
(`| REQ-XXX-NNN | LEVEL | …`) and the REQ IDs the tests cite — in the
comment above each integration test, and anywhere in a unit test file or a
blackbox suite.  Per document it counts the MUST rows (MUST, MUST NOT,
SHALL, SHALL NOT, REQUIRED) cited by a black-box test (an integration test
or a blackbox suite), by any test, and by none.

```sh
python3 scripts/trace.py                   # the table, as text
python3 scripts/trace.py --markdown        # the table below
python3 scripts/trace.py --untested tcp    # also: the MUST rows of tcp.md no test cites
python3 scripts/trace.py --strict          # exit 1 on a test citing nothing or an unknown ID
```

The CI job `traceability` runs `--strict --markdown` and puts the table in
its summary, so every commit has its own.  The table here is a snapshot of
the tree this section was last regenerated from:

<!-- snapshot: python3 scripts/trace.py --markdown -->
| Requirements | MUST rows | Black-box test | Any test | None |
|---|---:|---:|---:|---:|
| arp | 30 | 13 | 13 | 17 |
| checksum | 21 | 1 | 6 | 15 |
| dhcpv4 | 90 | 45 | 90 | 0 |
| dhcpv6 | 38 | 27 | 30 | 8 |
| dns | 28 | 0 | 0 | 28 |
| dns-sd | 29 | 15 | 23 | 6 |
| dtls | 46 | 14 | 27 | 19 |
| ethernet | 23 | 3 | 6 | 17 |
| http | 51 | 41 | 50 | 1 |
| icmpv4 | 42 | 32 | 32 | 10 |
| icmpv6 | 36 | 9 | 9 | 27 |
| igmp | 13 | 13 | 13 | 0 |
| ipv4 | 73 | 41 | 41 | 32 |
| ipv6 | 43 | 5 | 5 | 38 |
| mdns | 73 | 59 | 70 | 3 |
| ndp | 59 | 13 | 13 | 46 |
| slaac | 33 | 11 | 12 | 21 |
| tcp | 155 | 76 | 129 | 26 |
| tftp | 32 | 4 | 27 | 5 |
| tls | 40 | 20 | 24 | 16 |
| udp | 41 | 20 | 21 | 20 |
| **Total** | **996** | **462** | **641** | **355** |
<!-- end snapshot -->

Reading it: a row counts as verified when a test cites its ID, so the table
is as good as the citations — a test cites a row only if it would fail were
the row not met.  `dns` is the DNS stub resolver, which is not implemented
(§5); its rows have no tests.  A MUST the design leaves out on purpose is
marked **deviation** in its row and still counts as a MUST row here.

### Code coverage

The CI job `coverage` builds the stack and the tests instrumented
(`-DSMALLEST_TCP_COVERAGE=ON`: `--coverage -O0`), runs the integration
tests alone and reports with [gcovr](https://gcovr.com) the lines and
branches of `src/` they reach; the MAC drivers (`src/driver/`) are left
out, since the scripted link stands in for them.  The job's summary has
the table of every commit, and its HTML report (which lines, which
branches) is the artifact `coverage-integration`.  Locally:

```sh
pip install gcovr                          # in a venv on macOS
rm -rf build-cov                           # counts add up over runs otherwise
cmake -S . -B build-cov -DSMALLEST_TCP_COVERAGE=ON
cmake --build build-cov -j8
ctest --test-dir build-cov -L integration
gcovr --root . --filter 'src/' --exclude 'src/driver/' \
      --exclude 'src/tls_crypto_mbedtls.c' build-cov \
      --markdown | sed -e 's/🔴 //g' -e 's/🟡 //g' -e 's/🟢 //g'
#   macOS (Apple clang): add  --gcov-executable "xcrun llvm-cov gcov"
#   which lines:         add  --html-details build-cov/coverage.html
```

The same with all of `ctest` in place of `ctest -L integration` gives the
coverage of the unit tests too; the blackbox suites run the demos, which
are not instrumented in CI.

A snapshot of the tree this section was last regenerated from, measured
with Apple clang and `llvm-cov` (GCC, which the CI job uses, counts lines
and branches a little differently):

<!-- snapshot: the gcovr command above, on macOS -->
| Metric        | Coverage |
|---------------|----------|
| **Lines**     | 5700/8228 (69.3%) |
| **Functions** | 611/766 (79.8%) |
| **Branches**  | 2799/5128 (54.6%) |

| File                   | Lines | Functions | Branches |
|------------------------|-------|-----------|----------|
| **`src/arp.c`** | 80/83 (96.4%) | 7/7 (100.0%) | 48/60 (80.0%) |
| **`src/dhcpv4_client.c`** | 283/300 (94.3%) | 38/38 (100.0%) | 111/144 (77.1%) |
| **`src/dhcpv4_server.c`** | 156/169 (92.3%) | 16/16 (100.0%) | 88/113 (77.9%) |
| **`src/dhcpv4_wire.h`** | 76/78 (97.4%) | 10/10 (100.0%) | 33/44 (75.0%) |
| **`src/dhcpv6_client.c`** | 0/319 (0.0%) | 0/21 (0.0%) | 0/196 (0.0%) |
| **`src/dns_wire.c`** | 228/275 (82.9%) | 25/27 (92.6%) | 103/150 (68.7%) |
| **`src/dtls.c`** | 0/715 (0.0%) | 0/58 (0.0%) | 0/465 (0.0%) |
| **`src/eth.c`** | 39/45 (86.7%) | 4/4 (100.0%) | 17/24 (70.8%) |
| **`src/http.c`** | 643/686 (93.7%) | 53/53 (100.0%) | 469/586 (80.0%) |
| **`src/http_tls.c`** | 31/32 (96.9%) | 9/10 (90.0%) | 3/6 (50.0%) |
| **`src/icmp.c`** | 82/88 (93.2%) | 9/9 (100.0%) | 40/58 (69.0%) |
| **`src/icmpv6.c`** | 11/81 (13.6%) | 1/7 (14.3%) | 1/48 (2.1%) |
| **`src/igmp.c`** | 88/94 (93.6%) | 9/9 (100.0%) | 45/57 (78.9%) |
| **`src/ipv4.c`** | 274/294 (93.2%) | 28/29 (96.6%) | 155/195 (79.5%) |
| **`src/ipv6.c`** | 188/252 (74.6%) | 23/25 (92.0%) | 82/162 (50.6%) |
| **`src/mdns.c`** | 1009/1100 (91.7%) | 86/86 (100.0%) | 642/818 (78.5%) |
| **`src/mld.c`** | 75/127 (59.1%) | 9/13 (69.2%) | 31/82 (37.8%) |
| **`src/ndp.c`** | 66/209 (31.6%) | 7/18 (38.9%) | 20/125 (16.0%) |
| **`src/net.c`** | 111/116 (95.7%) | 13/13 (100.0%) | 25/40 (62.5%) |
| **`src/net_cksum.c`** | 39/44 (88.6%) | 8/9 (88.9%) | 10/10 (100.0%) |
| **`src/net_text.c`** | 12/12 (100.0%) | 1/1 (100.0%) | 10/10 (100.0%) |
| **`src/tcp.c`** | 729/831 (87.7%) | 92/96 (95.8%) | 346/503 (68.8%) |
| **`src/tcp_buf_saw.c`** | 82/84 (97.6%) | 14/14 (100.0%) | 22/26 (84.6%) |
| **`src/tftp.c`** | 176/274 (64.2%) | 19/28 (67.9%) | 75/164 (45.7%) |
| **`src/tls.c`** | 240/356 (67.4%) | 27/33 (81.8%) | 118/224 (52.7%) |
| **`src/tls_client.c`** | 254/458 (55.5%) | 20/28 (71.4%) | 78/278 (28.1%) |
| **`src/tls_common.c`** | 48/102 (47.1%) | 12/18 (66.7%) | 16/42 (38.1%) |
| **`src/tls_crypto_mbedtls.c`** | 137/231 (59.3%) | 15/23 (65.2%) | 22/85 (25.9%) |
| **`src/tls_internal.h`** | 32/38 (84.2%) | 7/7 (100.0%) | 5/8 (62.5%) |
| **`src/tls_keys.c`** | 98/122 (80.3%) | 12/14 (85.7%) | 25/38 (65.8%) |
| **`src/tls_server.c`** | 275/457 (60.2%) | 17/21 (81.0%) | 110/293 (37.5%) |
| **`src/tls_tcp.c`** | 20/20 (100.0%) | 5/5 (100.0%) | 9/12 (75.0%) |
| **`src/udp.c`** | 118/136 (86.8%) | 15/16 (93.8%) | 40/62 (64.5%) |
<!-- end snapshot -->

Reading it: the IPv4 side — ARP, IPv4, ICMP, IGMP, UDP, TCP, DHCPv4, mDNS,
HTTP — is where the integration tests are.  The DHCPv6 client and DTLS
have none, and IPv6, ICMPv6, NDP and MLD are reached only as far as mDNS
and TCP over IPv6 take them; TLS is reached through the HTTPS tests alone.
Those modules are verified by their unit tests and blackbox suites (§1,
§2), which this measure leaves out on purpose.

### The scripted link (`tests/integration/wire.h`)

`wire_driver` is a MAC driver whose receive queue the test fills
(`wire_deliver()`, `itest_receive()`) and whose transmissions it records
(`wire_sent()`).  `itest_up()` initialises a `net_t` on it with frame buffers
of a chosen size; `itest_advance()` runs `net_tick()`; an `itest_t.service`
hook runs the application's own polling (`http_server_poll()`) after each
frame.  The peer side — Ethernet, IPv4 with options and fragments, UDP,
ICMP, TCP, ARP, DNS — is encoded and decoded by the harness's own code with
its own checksum, never the stack's, so the stack is checked against the
RFCs and not against itself.  `peer_client_t` is a TCP client on the wire
(connect, send, acknowledge and collect, close).

| Suite | Verifies |
|---|---|
| `itest_ipv4` | IPv4 destination and source checks, every broadcast form, options and source routes, reassembly and its timeout, MMS_R/MMS_S and the MTU, TTL/TOS, addresses never sent, the all-hosts group; ICMP echo (truncated), errors, Redirect and Address Mask ignored |
| `itest_link` | Ethernet (filter, dispatch, header, buffers, looped-back frames), ARP (replies, next hop, rate limit, gateway MAC expiry), UDP sending limits, checksums (the API and on the wire) |
| `itest_udp` | Every UDP row: length and checksum checks, dispatch by port, Port Unreachable, broadcasts both ways, datagrams copied and built in place, the source and destination addresses, TTL and TOS, ICMP errors to the application, the checksum over IPv6 |
| `itest_igmp` | Reports and leaves, queries answered, timers, suppression, IGMPv1 routers, all-hosts never reported |
| `itest_tcp` | The TCP state machine row by row: opens and closes in every state, segment acceptability, RST/SYN/ACK/FIN processing, RST generation, options and the MSS, windows (silly-window avoidance, probing), the retransmission schedule (R1/R2, the RTO), ISNs, the local address, TOS, PSH, ICMP and ICMPv6 errors, the MTU, the buffer interface, IPv6 |
| `itest_http` | Every HTTP row on the wire: the request line and field lines, framing (Content-Length, Transfer-Encoding), Host, methods and routes, status codes and their headers, Date, conditional requests, Expect, responses without bodies, the handler's response checked, slots freed and recycled, timeouts; with `SMALLEST_TCP_TLS`, HTTPS hosts (421) with the stack's own TLS client as the peer |
| `itest_dhcpv4` | Every observable DHCPv4 row, client and server: the state machine and its timers, options (in `file`/`sname`, split, the handler table), T1/T2, the address probe and DECLINE, the server's one client, reply routing and option order |
| `itest_tftp` | Every implemented TFTP row: the request, blocks and ACKs, transfer IDs, blksize negotiation, errors, the adaptive retransmission timeout, netascii |
| `itest_mdns` | The responder's rows on the wire: probing, conflicts and tiebreaking, announcing, answers and additionals, NSEC, rate limiting, known answers, unicast and legacy unicast, names and TXT strings, goodbyes, withdrawing records, malformed names; DNS-SD browsing and resolving as resolvers ask |
| `itest_mdns6` | mDNS over IPv6 (dual stack): ff02::fb, AAAA records and NSEC, answers on the query's family, addresses appearing and going |
| `itest_tls` | TLS 1.3 server and client through `tls.h`, against a peer written from RFC 8446 on Mbed TLS primitives (`tls_peer.c`, none of the stack's TLS code): handshakes with PSK and certificates, HelloRetryRequest, extensions (missing, duplicate, unsolicited, misplaced), alerts, record limits, KeyUpdate, close_notify, small buffers, calls out of place; over the stack's TCP with `tls_tcp_carry()` |
| `itest_dtls` | DTLS 1.3 server and client through `dtls.h`, against the same peer written from RFC 9147: epochs and record numbers, the replay window, flights, fragments and reassembly, retransmission, ACKs, the cookie exchange, KeyUpdate; the stack's two roles over a lossy, duplicating, reordering network.  Linked without the core, as REQ-DTLS-073 requires |

The suites on the scripted link are built over IPv4 (`itest_mdns6` dual
stack); `itest_tls` and `itest_dtls` need `SMALLEST_TCP_TLS`, and
`itest_dtls` runs in an IPv6-only build too.

---

## 1. C Unit Tests

Every suite is an executable CTest runs (`tests/CMakeLists.txt`).  CMake is
the only host build.  The TLS suites and `test_dtls` need
`SMALLEST_TCP_TLS` (Mbed TLS; `test_dtls` also `SMALLEST_TCP_DTLS`), the
IPv6 suites `SMALLEST_TCP_IPV6`, and the suites of IPv4 and of what runs
over it `SMALLEST_TCP_IPV4`: the IPv4-only CI job (`cmake-ipv4-only`,
without TLS) and the IPv6-only job (`cmake-ipv6-only`) each run the suites
their build has.  `test_rawsock` has portable tests, socket tests that run
on Linux, and live tests on a veth pair that run only as root (CI runs
them with `sudo` in `cmake-linux`; an unprivileged `ctest` skips them).

CTest also checks that a configuration which cannot work fails to build:
mDNS without a multicast group slot (for either family), TFTP or the
DHCPv4 client without IPv4, and a build with neither IPv4 nor IPv6.

| Suite | File | Protocols Covered |
|---|---|---|
| `test_endian` | tests/unit/test_endian.c | Byte-order utilities |
| `test_checksum` | tests/unit/test_checksum.c | net_cksum (REQ-CKS-*) |
| `test_eth` | tests/unit/test_eth.c | Ethernet (REQ-ETH-*) |
| `test_net` | tests/unit/test_net.c | net init/dispatch (frame buffers too small for TCP or overlapping refused), `net_transmit()` of a busy driver, `net_hash()` against the HalfSipHash-2-4 reference vectors, `net_random()`, seeds that count every byte and add up, the key from the whole MAC |
| `test_arp` | tests/unit/test_arp.c | ARP (REQ-ARP-*) |
| `test_ipv4` | tests/unit/test_ipv4.c | IPv4 (REQ-IPV4-*) |
| `test_icmp` | tests/unit/test_icmp.c | ICMPv4 (REQ-ICMP-*) |
| `test_udp` | tests/unit/test_udp.c | UDP (REQ-UDP-*) |
| `test_tcp_buf` | tests/unit/test_tcp_buf.c | Stop-and-wait TX/RX buffers (incl. RX ring wrap; bytes in flight after a partial ACK, an ACK beyond the bytes sent) |
| `test_tcp` | tests/unit/test_tcp.c | TCP (REQ-TCP-*), incl. data/FIN retransmission, partial ACKs, frames the driver did not send (a SYN too), retransmissions counted per segment and not while the peer answers probes of a zero window, tcp_write/output, window updates (also from an ACK of nothing new), the FIN queued behind unsent data, MSS from the RX and TX buffers, RFC 6528 initial sequence numbers, in-order delivery (overlaps trimmed, segments and FINs after a gap not taken), no RST for a broadcast SYN |
| `test_dns_wire` | tests/unit/test_dns_wire.c | DNS names, compression, parsing (REQ-MDNS-003/043, REQ-DNSSD-031) |
| `test_mcast` | tests/unit/test_mcast.c | Multicast RX, per-packet TTL, IGMPv2 (REQ-MDNS-002/006) |
| `test_http` | tests/unit/test_http.c | The HTTP request parser and header formatter (REQ-HTTP-*) |
| `test_ipv6` | tests/unit/test_ipv6.c | IPv6 parse/build + extension headers, EUI-64 / solicited-node / multicast MAC, ICMPv6 echo + errors, NS/NA responder, DAD (REQ-IPv6-*, REQ-ICMPv6-*, REQ-NDP-*, REQ-SLAAC-004..013) |
| `test_udp6` | tests/unit/test_udp6.c | UDP over IPv6: `udp6_ports` dispatch, payload offset after extension headers, mandatory checksum (zero dropped, computed 0 sent as 0xFFFF), Port Unreachable, `udp6_send[_inplace]` within one Ethernet frame (REQ-IPv6-044,045, REQ-ICMPv6-016) |
| `test_tcp6` | tests/unit/test_tcp6.c | TCP over IPv6: passive/active open, data, RSTs, 4-tuple match by IPv6 address, retransmit, close, reply from the address used, one listener for both families, default MSS 1220, advertised MSS from the RX frame buffer and within the Ethernet MTU (1440), send MSS clamped to the TX frame buffer (IPv4 and IPv6) |
| `test_slaac` | tests/unit/test_slaac.c | Router Solicitation (format, 3 × 4 s, stops at an RA), Router Advertisement (router + MAC, hop limit, M/O, lifetime 0/expiry, validation), SLAAC (A flag, /64, DAD, link-local prefix, duplicate), lifetimes (deprecate, remove, infinite, 2-hour rule, preferred again), `ipv6_addr_add`, on-link test, reply from the global address (REQ-NDP-034..048, REQ-SLAAC-014..031) |
| `test_mld` | tests/unit/test_mld.c | MLDv2 report before the DAD probe (from ::), repeated once, one group per solicited-node address, `ipv6_mcast_join/leave` (report, frame filter, delivery), general / group queries (delay, validation), MLDv1 compatibility (v1 reports, Done, fallback timeout) — RFC 3810, RFC 2710 |
| `test_mdns6` | tests/unit/test_mdns6.c | mDNS over IPv6: ff02::fb joined, probes / announcements / goodbyes on both families, AAAA per usable address (not tentative), answers on the query's family, A ↔ AAAA and SRV → AAAA additionals, QU and legacy unicast over IPv6, known-answer suppression, NSEC with AAAA, delayed shared answers, explicit AAAA, conflicts, re-announcing (RFC 6762 §6.2, §8.4, §20) |
| `test_dhcpv6` | tests/unit/test_dhcpv6.c | DHCPv6 client: Information-Request (DUID-LL, Elapsed Time, ORO), §15 backoff with jitter, stateless Reply → handlers, xid / Client ID / truncated-option checks, Solicit (IA_NA, first RT > IRT), Advertise → Request, Reply → address + DAD, Renew at T1, Rebind at T2, expiry, Request gives up after 10, T1/T2 from the preferred lifetime, Release (REQ-DHCPv6-*) |
| `test_rawsock` | tests/unit/test_rawsock.c | Raw-socket driver: offloaded-checksum completion (portable); context and no-frame checks (Linux); live on a veth pair (Linux, root): send/receive, promiscuous mode, own/outgoing frames ignored, oversize frames dropped whole, kernel TCP/UDP checksums finished |
| `test_tls_crypto` | tests/unit/test_tls_crypto.c | Mbed TLS backend known answers: SHA-256, HMAC (RFC 4231), HKDF (RFC 5869), AES-128-GCM, the AES block (FIPS-197, for DTLS), X25519 (RFC 7748), P-256, ECDSA, RSA-PSS, certificate chains (alerts, IP names), random (REQ-TLS-006) |
| `test_tls_keys` | tests/unit/test_tls_keys.c | Key schedule and record protection against RFC 8448 §3 (all secrets, keys, IVs, Finished, eight records byte for byte), §4 (PSK binder, PSK + DHE), §5 (HRR transcript); malformed records (REQ-TLS-026..034); DTLS 1.3's `"dtls13"` labels and `"sn"` key (REQ-DTLS-006) |
| `test_tls_server` | tests/unit/test_tls_server.c | Server handshake against a scripted client: RFC 8448 ServerHellos byte for byte, every refusal, CCS, fragments, small tx, PSK, HelloRetryRequest, max_fragment_length, KeyUpdate (a request met by the peer's own), alerts, a failed key exchange leaving no secret (REQ-TLS-001, 018..025, 030, 031, 035..043) |
| `test_tls_client` | tests/unit/test_tls_client.c | Client handshake against our server (memory transport) and a scripted server with faults: ClientHello contents, chain/name/CertificateVerify/Finished checks, PSK, HRR, max_fragment_length, KeyUpdate, keys wiped after close_notify both ways and by `tls_release()` (REQ-TLS-010..017, 023, 031) |
| `test_dtls` | tests/unit/test_dtls.c | DTLS 1.3 (RFC 9147): records rebuilt from the backend's primitives, the unified header, record number encryption, sequence reconstruction, the replay window; our client and server over a network that loses, repeats and reorders datagrams — every datagram of the handshake lost in turn, fragments in any order and overlapping, small MTUs, the timer and its give-up, ACKs, the cookie, HRR, PSK; KeyUpdate acknowledged before use, close_notify, release (REQ-DTLS-*) |

### Running the C tests

```sh
cmake -S . -B build && cmake --build build
ctest --test-dir build --output-on-failure
ctest --test-dir build -L integration      # the integration tests alone

# IPv4 only, without TLS (what the cmake-ipv4-only CI job builds)
cmake -S . -B build-v4 -DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF
cmake --build build-v4 && ctest --test-dir build-v4 --output-on-failure

# IPv6 only (the cmake-ipv6-only CI job): the suites that need no IPv4
cmake -S . -B build-v6 -DSMALLEST_TCP_IPV4=OFF
cmake --build build-v6 && ctest --test-dir build-v6 --output-on-failure

# The raw-socket driver's live tests (Linux, root)
sudo ./build/tests/test_rawsock
```

The `Makefile` has no host targets: it builds the Cortex-M0 size benchmarks
(`make arm-size-all`, section 3).

### TCP Unit Test Coverage Matrix (REQ-TCP-*)

| REQ | Description | Test |
|---|---|---|
| 001 | 11 TCP states defined | test_tcp_passive_open_syn_synack_ack, test_tcp_active_open_syn_synack_ack |
| 002 | Passive open (LISTEN) | test_tcp_passive_open_syn_synack_ack |
| 003 | Active open (SYN_SENT) | test_tcp_active_open_syn_synack_ack |
| 005 | Active close (FIN_WAIT_1) | test_tcp_active_close |
| 006 | Passive close (CLOSE_WAIT) | test_tcp_passive_close |
| 008 | TIME_WAIT 2×MSL | test_tcp_timewait_expires |
| 014 | tcp_send() API | test_tcp_data_send |
| 015 | `tcp_close()`: FIN queued behind unsent data; LISTEN and SYN-SENT → CLOSED; in SYN-RECEIVED the FIN follows the ACK of our SYN (RFC 9293 §3.10.4) | test_tcp_close_sends_unsent_data_first, test_tcp_close_fin_waits_for_the_last_segment; itest_tcp_015_close_in_listen, itest_tcp_015_close_in_syn_sent, itest_tcp_015_close_in_syn_received |
| 016 | `tcp_abort()`: RST only where the peer holds the connection open (§3.10.5) | itest_tcp_016_abort_before_open_sends_nothing, itest_tcp_016_abort_in_syn_received_sends_rst |
| 018 | Checksum on TX | test_tcp_checksum_basic |
| 019 | Checksum verify on RX | test_tcp_checksum_basic |
| 028/029/153 | ISS = 4 µs clock + keyed hash (RFC 6528) | test_tcp_isn_is_clock_plus_keyed_hash, test_tcp_isn_depends_on_secret; test_tcp_153_iss_differs_across_connections (blackbox) |
| 031 | ACK in LISTEN → RST | test_tcp_ack_in_listen_generates_rst |
| 041/042 | Out-of-window → ACK only | test_tcp_out_of_window_gets_ack |
| 046/047 | RST in ESTABLISHED → CLOSED; in SYN-RECEIVED → LISTEN (passive open) or CLOSED (active) | test_tcp_rst_in_established_aborts; itest_tcp_046_rst_in_syn_received_listens_again, itest_tcp_046_rst_in_active_syn_received_closes, itest_tcp_090_syn_received_given_up_listens_again |
| 048 | RST in LAST_ACK → CLOSED | test_tcp_rst_in_last_ack_closes |
| 051 | SYN in ESTABLISHED → error; in a passive SYN-RECEIVED → LISTEN | test_tcp_syn_in_established_gets_rst; itest_tcp_051_syn_in_syn_received_listens_again |
| 053 | No ACK bit → discard | test_tcp_no_ack_bit_discarded |
| 054 | ESTABLISHED on ACK to SYN-ACK | test_tcp_passive_open_syn_synack_ack |
| 058 | Window update from an ACK of nothing new | test_tcp_window_update_resumes_sending |
| 059/071 | FIN exchange | test_tcp_active_close, test_tcp_passive_close |
| 072 | Unknown port → RST | test_tcp_rst_sent_for_unknown_port |
| 073 | RST.SEQ = ACK from LISTEN | test_tcp_ack_in_listen_generates_rst |
| 075 | RST in LISTEN discarded | test_tcp_no_rst_in_listen_for_rst |
| 076 | MSS option in SYN-ACK | test_tcp_synack_contains_mss |
| 077 | Advertised MSS ≤ 1460, from the RX frame buffer | test_tcp_synack_contains_mss, test_tcp_mss_advertised_from_rx_buffer, test_tcp6_our_mss_within_ethernet_mtu |
| 078 | Peer MSS stored | test_tcp_peer_mss_stored |
| 079 | Default MSS = 536 | test_tcp_default_peer_mss_536 |
| 081 | Segments fit the TX frame buffer | test_tcp_segments_fit_tx_buffer |
| 082/083 | Window advertised > 0 | test_tcp_window_advertised_nonzero |
| 085–087 | Zero-window persist timer; data in flight or our FIN resent into a zero window as probes, never given up while the peer answers (RFC 1122 §4.2.2.17) | test_tcp_persist_starts_on_zero_window, test_tcp_persist_probe_sent_on_timeout, test_tcp_persist_stops_when_window_opens, test_tcp_fin_into_zero_window_waits_while_peer_answers, test_tcp_data_into_shrunk_window_waits_while_peer_answers, test_tcp_fin_into_zero_window_given_up_when_peer_silent; test_tcp_085_persist_probe_on_zero_window (blackbox) |
| 090 | Retransmit on timeout | test_tcp_retransmit_on_timeout |
| 095 | RTO doubles on retry; the rest of a partly ACKed segment and a frame the driver did not send (an active open's SYN too) are resent | test_tcp_retransmit_on_timeout, test_tcp_partial_ack_resends_rest_in_place, test_tcp_unsent_frame_is_retransmitted, test_tcp_connect_with_busy_driver_resends_syn, test_tcp_connect_with_failing_driver_resends_syn |
| 097/098 | RTO stops on ACK; retransmissions counted per segment | test_tcp_rto_resets_on_ack, test_tcp_retransmissions_counted_per_segment |
| 109/111 | NOP/unknown option ignored | test_tcp_options_nop_unknown_ignored |
| 112 | MSS parsed from options | test_tcp_options_nop_unknown_ignored |
| 115 | Unknown option skipped | test_tcp_options_nop_unknown_ignored |

---

## 2. Blackbox Conformance Tests

### Architecture

The blackbox suites run a demo binary — the system under test (SUT) — on a
real link and talk to it from outside.  Most use **Scapy** to craft raw
Ethernet frames, so they can send what no host stack would; the HTTP, TLS
and DTLS suites use the test host's own TCP and UDP, with production peers
(Python ssl, OpenSSL, curl, wolfSSL).

```
Test harness (Scapy, our_ip=10.0.0.100)
         │  raw AF_PACKET / BPF frames
         ▼
  [ tap0, veth-test ↔ veth-sut, or feth0 ↔ feth1 ]
         │
         ▼
  SUT (a smallest_tcp demo, sut_ip=10.0.0.2)
```

- Scapy sends every frame from `our_ip` (10.0.0.100) and its capture
  socket sees all L2 traffic, whatever the destination address.
- The `ctx` fixture resolves the SUT's MAC with an ARP request first (the
  pre-flight).  The SUT, which keeps no ARP cache, sends each reply to the
  source MAC of the frame it answers.
- The host kernel must stay out of Scapy's hand-made TCP connections.  On
  macOS `our_ip` is not assigned to the interface, so the kernel ignores
  the SUT's replies.  On Linux `tests/blackbox/sut_net.sh` assigns it to
  the harness interface — the host's own tools (ping, nc, curl, Avahi) need
  it — and `--rst-drop` adds an iptables rule that drops the kernel's RSTs
  leaving through that interface only
  ([ci-debugging.md §3.6](ci-debugging.md)).  The suites whose client is
  the host's TCP stack run without the rule.

### Files

| File | Purpose |
|---|---|
| `tests/blackbox/conftest.py` | pytest fixtures, CLI options, ARP pre-flight, port allocator, the fixtures that launch SUTs, `sut_settle` autouse fixture |
| `tests/blackbox/helpers.py` | `TcpConn`, `tcp_connect()`, `send_recv()`, `silence()`, `start_sniffer()`, ARP/ICMP/UDP/IPv4 frame builders |
| `tests/blackbox/test_arp_conform.py` | ARP conformance (REQ-ARP-001..005) |
| `tests/blackbox/test_ipv4_conform.py` | IPv4 conformance (REQ-IPv4-002..044) |
| `tests/blackbox/test_icmp_conform.py` | ICMPv4 conformance (REQ-ICMPv4-001..034) |
| `tests/blackbox/test_udp_conform.py` | UDP conformance (REQ-UDP-001..021) |
| `tests/blackbox/test_tcp_conform.py` | TCP conformance (REQ-TCP-002..153) |
| `tests/blackbox/test_tcp_fuzz.py` | TCP fuzz tests (header fields, flags, options, truncation) |
| `tests/blackbox/test_dhcpv4_conform.py` | DHCPv4 client tests (SUT: `dhcp_echo_demo`, launched fresh per test) |
| `tests/blackbox/test_mdns_conform.py` | mDNS / DNS-SD tests over IPv4 and IPv6 (SUT: dual-stack `mdns_demo`, launched fresh per test) |
| `tests/blackbox/test_http_conform.py` | HTTP tests; the host's own TCP stack is the client, over IPv4 and IPv6 (SUT: `http_demo`) |
| `tests/blackbox/test_ipv6_conform.py` | IPv6 / ICMPv6 / NDP / DAD / UDP / TCP / SLAAC / DHCPv6 / MLD tests (SUT: dual-stack `tcp_echo_demo`, launched fresh per test) |
| `tests/blackbox/test_tls_conform.py` | TLS 1.3 server tests against `tls_echo_demo`: Python ssl, openssl s_client, hand-built records |
| `tests/blackbox/test_tls_client_conform.py` | TLS 1.3 client tests: `tls_client_demo` against Python ssl and openssl s_server |
| `tests/blackbox/test_https_conform.py` | HTTPS tests against `https_demo`: Python and curl |
| `tests/blackbox/test_dtls_conform.py` | DTLS 1.3 server tests against `dtls_echo_demo`: wolfSSL's client, and hand-built datagrams |
| `tests/blackbox/test_dtls_client_conform.py` | DTLS 1.3 client tests: `dtls_client_demo` against wolfSSL's server |
| `tests/blackbox/build_wolfssl.sh` | Builds the DTLS peer, wolfSSL, from its pinned release (SHA-256 checked); prints `WOLFSSL_CLIENT` / `WOLFSSL_SERVER` |
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

On Linux, as root (`sudo` / `CAP_NET_RAW`).  The README has the commands
for each suite that launches its own SUT, for the raw-socket driver and
for macOS.

```sh
# 1. Build the SUT binary
cmake -S . -B build
cmake --build build --target tcp_echo_demo
# Binary is at: build/demo/tcp_echo_demo   ← note the demo/ subdirectory

# 2. Install Python deps
pip install -r tests/blackbox/requirements.txt

# 3. Option A — the core suites (ARP, IPv4, ICMP, UDP, TCP) via the shell
#    runner: creates tap0, starts the SUT, runs each suite, stops the SUT,
#    removes tap0, prints a ✓/✗ summary
sudo tests/blackbox/run_blackbox.sh \
    --sut-bin ./build/demo/tcp_echo_demo \
    --setup-tap --teardown-tap -v

# 3. Option B — one suite by hand
eval "$(sudo tests/blackbox/sut_net.sh up tap --rst-drop)"   # TEST_IF, SUT_IF
sudo ./build/demo/tcp_echo_demo "$SUT_IF" &   # ← build/DEMO/tcp_echo_demo
sudo python3 -m pytest tests/blackbox/test_tcp_conform.py \
    --iface "$TEST_IF" --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v

# The fuzz tests against the same SUT (200 iterations, ~60 seconds)
sudo python3 -m pytest tests/blackbox/test_tcp_fuzz.py \
    --iface "$TEST_IF" --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
    --fuzz-count 200 -v

sudo pkill -x tcp_echo_demo
sudo tests/blackbox/sut_net.sh down tap
```

> ⚠️ **Common mistake:** CMake places the demo binary under
> `build/demo/tcp_echo_demo` (mirroring the `demo/` source subdirectory),
> **not** at `build/tcp_echo_demo`.  Using the wrong path causes `sudo`
> to silently fail, the SUT never starts, and every test ERRORs with
> `ARP timeout: no reply from 10.0.0.2`.  See
> [§6 Troubleshooting](#6-troubleshooting--known-pitfalls) for more.

The tables below name each test and the requirements it verifies.

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
| test_arp_003 | REQ-ARP-004 | who-has for unrelated IP → silence |
| test_arp_004 | REQ-ARP-029 | After an ARP exchange a ping is answered at our MAC |
| test_arp_005 | REQ-ARP-001 | Repeated who-has → consistent MAC returned |

### Blackbox IPv4 Conformance Coverage

| Test | REQ(s) | Description |
|---|---|---|
| test_ipv4_001 | REQ-IPv4-005 | Bad IP header checksum → silent drop |
| test_ipv4_002 | REQ-IPv4-011 | Wrong destination IP → silent drop |
| test_ipv4_003 | REQ-IPv4-020, REQ-ICMPv4-017 | Unknown protocol → ICMP Protocol Unreachable (type 3 code 2) |
| test_ipv4_004 | REQ-IPv4-024 | Non-first fragments alone → no response |
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
| test_udp_001 | REQ-UDP-001, 016 | Echo on port 7 — data returned verbatim |
| test_udp_002 | REQ-UDP-020, 021 | Echo reply has src/dst ports correctly swapped |
| test_udp_003 | REQ-UDP-017, REQ-ICMPv4-018 | Unknown port → ICMP Destination Unreachable, Port Unreachable (type 3 code 3) |
| test_udp_004 | REQ-ICMPv4-038 | ICMP Unreachable body contains original IP header + 8 UDP bytes |
| test_udp_005 | REQ-UDP-006, 007 | Bad UDP checksum → silent drop |
| test_udp_006 | REQ-UDP-008 | Zero UDP checksum (disabled) accepted and echoed |
| test_udp_007 | REQ-UDP-002, 005 | UDP Length < 8 → silent drop |

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

| Suite | Checks |
|---|---|
| test_tls_conform.py (server) | Handshake with CA and name checks; 40 kB and full 16 kB-record echoes; close_notify; IP-address name; five in a row; TLS 1.2, plain HTTP and a tampered record refused (protocol_version, unexpected_message, bad_record_mac); half a ClientHello then RST; a ClientHello in 7-byte segments; coalesced records; x25519 and P-256; OpenSSL's default (post-quantum) ClientHello; no middlebox mode; no common group / suite / signature (handshake_failure); KeyUpdate; HelloRetryRequest; max_fragment_length 512; PSK (openssl, Python 3.13+), wrong PSK, unknown identity → certificate; IPv6 |
| test_tls_client_conform.py (client) | SNI; 30 kB echo; RSA-PSS; no name check; max_fragment_length; KeyUpdate; wrong name (bad_certificate), untrusted chain (unknown_ca), TLS 1.2 server; optional and required client certificates; openssl s_server -rev; HRR from a P-256-only server; PSK against Python and certificate-less s_server (psk_dhe_ke, psk_ke), wrong PSK |
| test_https_conform.py | GET / JSON / 20000-byte body / HEAD / 404 / 405 + Allow over TLS 1.3; by address; curl by name; five in a row |

### Blackbox DTLS 1.3 Coverage

Run with `--dtls-sut-bin ./build/demo/dtls_echo_demo`, `--dtls-client-bin
./build/demo/dtls_client_demo`, and the wolfSSL example programs that
`tests/blackbox/build_wolfssl.sh` builds (`--wolfssl-client`,
`--wolfssl-server`) — OpenSSL and Mbed TLS have no DTLS 1.3.  The wolfSSL
programs run in their own source tree, which they insist on.

| Suite | Checks |
|---|---|
| test_dtls_conform.py (server) | wolfSSL's client: P-256 (with the cookie exchange), x25519, a HelloRetryRequest for the group, a KeyUpdate before its data, PSK psk_dhe_ke and psk_ke, three clients at once, the server's flight in 300-byte fragments, no cookie; hand-built datagrams over a UDP socket: the cookie HelloRetryRequest (versions, no session id), the same HelloRetryRequest to a repeated ClientHello, a wrong cookie, a legacy_cookie and DTLS 1.2 refused with illegal_parameter and protocol_version, no answer to four kinds of garbage |
| test_dtls_client_conform.py (client) | wolfSSL's echo server: 3000 bytes in datagrams, its cookie, a KeyUpdate from either side, 300-byte datagrams, PSK, a wrong name (bad_certificate) and an untrusted chain (unknown_ca) refused |

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
| `cmake-ipv6-only` | ci.yml | ubuntu-latest | ctest on an IPv6-only build (`-DSMALLEST_TCP_IPV4=OFF`): the suites that need no IPv4, TLS, and the checks that the IPv4-only protocols refuse to compile; then library-only builds without TCP and without UDP | push/PR |
| `cmake-linux` | ci.yml | ubuntu-latest | ctest (dual stack, TLS): unit and integration tests | push/PR |
| `cmake-macos` | ci.yml | macos-latest | ctest (dual stack, TLS): unit and integration tests | push/PR |
| `cmake-linux` (root step) | ci.yml | ubuntu-latest | `sudo test_rawsock`: raw-socket driver live tests on a veth pair | push/PR |
| `traceability` | ci.yml | ubuntu-latest | `scripts/trace.py --strict --markdown`: every integration test cites a requirement, every cited ID exists; the summary is the requirements coverage (§0) | push/PR |
| `coverage` | ci.yml | ubuntu-latest | An instrumented build (`-DSMALLEST_TCP_COVERAGE=ON`), `ctest -L integration`, gcovr: line and branch coverage of `src/` by the integration tests (§0); the HTML report is an artifact | push/PR |
| `blackbox-linux` | ci.yml | ubuntu-latest | Linux sanity (arping/ping/nc) + Scapy full conformance via `run_blackbox.sh` — once over TAP, once over the raw socket | push/PR |
| `blackbox-validate` | ci.yml | ubuntu-latest | Same Scapy suites against Linux kernel reference SUT (`socat` echo); `-m "not sut_specific"` | push/PR |
| `blackbox-ipv6` | ci.yml | ubuntu-latest | IPv6 / ICMPv6 / NDP / DAD / UDP / TCP / SLAAC / DHCPv6 suite against dual-stack `tcp_echo_demo`, then DHCPv6 interop with dnsmasq (TAP, raw socket); and against an IPv6-only `tcp_echo_demo` (TAP) | push/PR |
| `blackbox-dhcp` | ci.yml | ubuntu-latest | DHCPv4 client suite against `dhcp_echo_demo` (TAP, raw socket) | push/PR |
| `blackbox-mdns` | ci.yml | ubuntu-latest | mDNS/DNS-SD suite against `mdns_demo` (TAP, raw socket), then Avahi interop | push/PR |
| `blackbox-http` | ci.yml | ubuntu-latest | HTTP suite against `http_demo` (TAP, raw socket), then browse-by-name (Avahi + nss-mdns + curl) | push/PR |
| `blackbox-tls` | ci.yml | ubuntu-latest | TLS 1.3 server, client and HTTPS suites against `tls_echo_demo`, `tls_client_demo`, `https_demo` with Python ssl, OpenSSL 3 and curl (TAP, raw socket) | push/PR |
| `blackbox-dtls` | ci.yml | ubuntu-latest | DTLS 1.3 server and client suites against `dtls_echo_demo`, `dtls_client_demo` with wolfSSL, built from its pinned release by `build_wolfssl.sh` and cached (TAP, raw socket) | push/PR |
| `arm-size` | ci.yml | ubuntu-latest | `make arm-size-all`: Cortex-M0 size benchmark (UDP, UDP+TCP, UDP+mDNS, UDP+HTTP, dual stack, IPv6 only, TLS and DTLS server-only and both roles), then `arm-check-division` — fails if any object calls a library divide — and `arm-check-links` — fails if TLS's objects need DTLS's record layer or DTLS's TLS's | push/PR |
| `board-nucleo-f429zi` | ci.yml | ubuntu-latest | Builds the NUCLEO-F429ZI `tcp_echo_demo.elf` of the hardware fuzz job (§4) — build only | push/PR |
| `fetchcontent` | ci.yml | ubuntu-latest | Builds and runs `examples/fetchcontent` against the checkout | push/PR |
| `release-check` | ci.yml | ubuntu-latest | `scripts/release.py check` (version, `[Unreleased]`, a trial stamp); CMake and the library report the version | push/PR |
| `release` | release.yml | ubuntu-latest | Commits the next version, tags it and publishes the release for every push to `main` that passes CI ([release-process.md](release-process.md)) | CI completed on main |
| `fuzz-tcp-linux` | fuzz.yml | ubuntu-latest | Scapy fuzz + post-fuzz conformance (TAP, raw socket) | Nightly 02:00 UTC |
| `fuzz-tcp-hw` | fuzz.yml | self-hosted, hw-dut | Scapy fuzz and conformance on a NUCLEO-F429ZI (§4) | Nightly (when enabled) |

The Linux blackbox jobs and the nightly fuzz run as a two-leg matrix,
one leg per MAC driver.  `tests/blackbox/sut_net.sh up tap|raw` builds the
link and exports `TEST_IF` (tap0 / veth-test, for Scapy and the host) and
`SUT_IF` (tap0 / `raw:veth-sut`, the demos' interface argument).  A failure in
one leg only points at that driver or at link-specific behaviour: with the raw
socket, segments from the host kernel arrive with offloaded (partial)
checksums that the driver must finish.

The macOS blackbox run (`tests/blackbox/run_blackbox_macos.sh`, over a feth
pair) is not a CI job; it is run by hand.

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
| **Runner host** | Raspberry Pi 5 (4 GB) or x86 mini-PC with a second Ethernet port | Runs the GitHub Actions self-hosted runner; `eth1` faces the DUT |
| **DUT** | NUCLEO-F429ZI | STM32F429ZI (Cortex-M4) with the ETH MAC and a LAN8742A PHY on board, and an ST-LINK/V2-1 for SWD and a virtual COM port — the one board the port supports (`boards/nucleo-f429zi`) |
| **Cabling** | Direct cable, or a small unmanaged switch | Runner `eth1` and the DUT on one link |

**Estimated cost: about $30 for the DUT**, plus the runner.  The board
needs both an Ethernet MAC and a PHY: an STM32F446 has no MAC, and the
STM32F4-Discovery no PHY.  A USB relay to cut the DUT's power is optional:
the job resets it over SWD.

### Wiring Topology

```
┌───────────────────────────────────────────────┐
│  Self-hosted runner                            │
│  eth0 ─── LAN ─── GitHub                       │
│  eth1 (10.0.0.100/24) ──── NUCLEO-F429ZI RJ45  │  the DUT at 10.0.0.2
│  USB ───────────────────── NUCLEO ST-LINK      │  SWD + /dev/ttyACM0
└───────────────────────────────────────────────┘
```

### The firmware

`boards/nucleo-f429zi` is the board port, with the MAC driver
`src/driver/stm32f4_eth.c` ([mac-hal.md §6](design/mac-hal.md#6-bundled-drivers)):
start-up code, linker script, the 168 MHz clock from the HSI, SysTick,
USART3 on the ST-LINK's virtual COM port, the RMII pins, and
`tcp_echo_demo` — TCP and UDP echo on port 7 at 10.0.0.2 (IPv6 too), the
default MAC 02:00:00:de:ad:01, "ready" on the console (115200 8N1) once the
link is up, LD1 lit with the link.

```sh
cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake \
      -DSMALLEST_TCP_BOARD=nucleo-f429zi -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build-arm --target tcp_echo_demo     # build-arm/tcp_echo_demo.elf
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg \
        -c "program build-arm/tcp_echo_demo.elf verify reset exit"
```

**Status: built, not run on hardware.**  CI builds it on every push
(`board-nucleo-f429zi`); the register addresses and bits are checked
against ST's CMSIS header and legacy HAL; no frame has gone through it.
The first run on a board is the test.  MinSizeRel: 16.4 KB of flash and
14.8 KB of RAM, 9.3 KB of it the driver's DMA rings and frame buffers.

### GitHub Actions Integration

Add the self-hosted runner with labels `[self-hosted, hw-dut]` to the
repository, and set the Actions variable `HW_DUT_ENABLED = true` (and
`HW_DUT_SERIAL` if the virtual COM port is not `/dev/ttyACM0`).

The `fuzz.yml` workflow's `fuzz-tcp-hw` job then:
1. Cross-compiles the firmware with `arm-none-eabi-gcc` through
   `cmake/arm-none-eabi.cmake` and `-DSMALLEST_TCP_BOARD=nucleo-f429zi`
2. Flashes it with OpenOCD and waits for "ready" on the serial port
3. Runs the TCP fuzz suite over `eth1`
4. Resets the DUT over SWD, waits for "ready" again, and runs the ARP,
   IPv4, ICMP, UDP and TCP conformance suites

---

## 5. Open Items / Known Gaps

| # | Requirement(s) | Description | Priority |
|---|---|---|---|
| 1 | MUST rows no test cites (§0) | Above all IPv6, NDP, ICMPv6, SLAAC, IPv4, ARP, Ethernet and the checksum: `scripts/trace.py --untested <doc>` lists them | High |
| 2 | — | No integration tests for IPv6, ICMPv6, NDP, MLD, the DHCPv6 client, TLS (but through HTTPS) and DTLS: the code coverage of those files (§0) comes from unit tests and blackbox suites only | High |
| 3 | REQ-DNS-* | The DNS stub resolver is not implemented; its requirements have no tests | Medium |
| 4 | Hardware fixture | Procure BOM, set up self-hosted runner; the STM32F4 port has not run on a board (§4) | Medium |
| 5 | REQ-TCP-004/007 | Simultaneous open and close: verified by unit tests only, no black-box test | Low |
| 6 | REQ-TCP-113/114/117/122-124 | Window Scale, Timestamps, SACK options: not implemented (MAY) | Low |
| 7 | REQ-TCP-130/132-134 | TCP_NODELAY, Keep-alive: not implemented (MAY) | Low |
| 8 | REQ-TCP-155 | RST rate limiting (SHOULD): not implemented, no test | Low |
| 9 | REQ-TLS-003 | TLS_CHACHA20_POLY1305_SHA256 (SHOULD): not implemented | Low |
| 10 | TLS | Client certificates, session tickets / 0-RTT, record_size_limit (RFC 8449): not implemented | Low |
| 11 | REQ-DTLS-058 | DTLS: after a partial ACK, resend only what it leaves out (SHOULD); the timer resends the whole flight | Low |
| 12 | DTLS | Connection IDs (RFC 9146), backing off to smaller records when the PMTU is unknown, buffering out-of-order handshake messages (all optional); no fuzz suite for DTLS | Low |
| 13 | Fuzz | The fuzz suite covers TCP only | Low |

---

## 6. Troubleshooting / Known Pitfalls

The pitfalls of running the blackbox suites by hand.  CI failures and how
to read them are in [ci-debugging.md](ci-debugging.md).

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
  configuration (`lxc.cgroup2.devices.allow = c 10:200 rwm`), use a
  KVM VM instead of an LXC container, or use the raw-socket driver on a
  veth pair, which needs no TUN (`tests/blackbox/sut_net.sh up raw`).
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
