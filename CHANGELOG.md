# Changelog

Every release of smallest_tcp, newest first: CI releases every push to
`main` that passes, and moves what is under [Unreleased] into the release.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
while the major version is 0, a minor release may change the API, and the
entry says how.  How a release is made:
[docs/release-process.md](docs/release-process.md).

## [Unreleased]

The review of IPv6 — IPv6, ICMPv6, Neighbor Discovery, SLAAC, MLD and
DHCPv6: every requirement row against its RFC, the code and the tests
that verify it.

### Added

- ICMPv6 errors about UDP datagrams reach the application:
  `udp6_set_error_handler()` with `udp6_icmp_error_t` (ports, destination,
  type, code, the MTU of a Packet Too Big, the whole quote).
- `icmpv6_tick()`, which `ipv6_tick()` runs, and the settings
  `ICMPV6_ERROR_BURST` (10) and `ICMPV6_ERROR_INTERVAL_MS` (100) of the
  rate limit on ICMPv6 errors.
- Black-box integration suites for IPv6 (`itest_ipv6`, `itest_ndp`,
  `itest_mld`, `itest_dhcpv6`) on an IPv6 peer codec in the scripted link
  (`tests/integration/wire.h`).

### Changed

- `net_t` grows by a pointer with UDP over IPv6 (`udp6_error_handler`):
  268 bytes dual stack on Cortex-M0.
- `icmpv6_send_error()` returns `NET_ERR_BUSY` for an error the rate limit
  holds back.
- `scripts/trace.py --strict` fails for a MUST row that no test cites and
  that does not say why none can verify it (`not observable`,
  `not implemented`).

### Fixed

- ICMPv6: errors received reach UDP and TCP, errors of unknown type
  included (RFC 4443 §2.4(a)); a Packet Too Big with an MTU below 1280 is
  discarded (RFC 8201 §4).  Errors sent are rate-limited (RFC 4443
  §2.4(f)).  `icmpv6.c` compiles with neither UDP nor TCP.
- IPv6: a Routing header with segments left draws Parameter Problem,
  code 0 (RFC 8200 §4.4); nothing is sent to `::` — `udp6_send()`,
  `tcp6_connect()` and `ndp_send_ns()` refuse it.
- MLD: the groups are reported again from the link-local address once it
  is valid (RFC 3810 §5.2.13); routers discard the reports sent from `::`
  before that.
- DHCPv6: the start delay is at most 1 s, and a refreshing
  Information-request waits a random delay too; an IA_NA with T1 > T2 is
  discarded; SOL_MAX_RT is taken from an Advertise that refuses the client
  as well; the released address leaves the interface before the Release
  is sent.

## [0.1.9] - 2026-10-02

The review of TLS and DTLS.

### Added

- Black-box integration suites for TLS and DTLS (`itest_tls`,
  `itest_dtls`) against a peer written from the RFCs
  (`tests/integration/tls_peer.c`).

### Changed

- The coverage figure is of the stack: the Mbed TLS backend
  (`tls_crypto_mbedtls.c`) is left out of it.

### Fixed

- TLS: a ClientHello with `supported_groups` and no `key_share` is
  refused; the client refuses extensions in EncryptedExtensions it did not
  offer; the alerts for a PSK ServerHello without its key share, for an
  extension in the wrong message and for an empty alert record are the
  ones RFC 8446 names.
- DTLS: any record of the peer's next flight, not only a whole message,
  stops the retransmission of ours (RFC 9147 §7.2).

## [0.1.8] - 2026-10-02

The review of the HTTP server and of mDNS / DNS-SD.

### Changed

- mDNS and the HTTP server are tested black box (`itest_mdns`,
  `itest_http`); the unit tests that read their private fields are
  removed.  Requirement rows of HTTP, mDNS and DNS-SD: levels and wording
  as the RFCs have them.
- `scripts/trace.py` counts the MUST rows no test can verify (`not
  observable`, `not implemented`) apart, and with `--strict` checks that a
  test named in a row's Test ID column exists and cites the row.

### Fixed

- mDNS: a unicast response is taken only as an answer to our probes (RFC
  6762 §6); once running it changes nothing.

## [0.1.7] - 2026-10-02

The review of UDP and TCP.

### Added

- `tcp6_icmp_error()`: ICMPv6 errors reach the TCP connection they are
  about — Packet Too Big lowers the segment size, Port Unreachable
  aborts, the rest are soft errors; `tcp_last_error()` holds the ICMPv6
  type and code on an IPv6 connection.

### Changed

- `tcp_connect()` and `tcp6_connect_from()` return `NET_ERR_BUSY` on a
  connection in use.
- Requirement rows of UDP and TCP: levels and wording as the RFCs have
  them; every MUST row is verified black box (`itest_udp`, `itest_tcp`).

### Fixed

- TCP: an active open on a connection in use is refused, not started over
  it; a connection is matched by its local address too; the receive
  window's right edge moves only in steps of min(buffer / 2, MSS) on every
  ACK (receiver silly-window avoidance, RFC 9293 MUST-39).

## [0.1.6] - 2026-10-02

The review of the link and IP layer, DHCPv4 and TFTP: every requirement
row against its RFC, the code and the tests that verify it.

### Changed

- Requirement rows: levels and wording follow the RFC text; what the
  design leaves out is a **deviation** row; the Test ID column names the
  tests that verify each row, and every test cites its rows.
- TFTP and DHCPv4 are tested black box (`itest_tftp`, `itest_dhcpv4`);
  their unit suites, which read private fields, are removed.

### Fixed

- ICMP: an error whose quote is not a whole IPv4 header is discarded, not
  passed to UDP or TCP.
- `net_endian.h`: `NET_BIG_ENDIAN` or `NET_LITTLE_ENDIAN` defined by the
  application is honoured, as the error message for an unknown byte order
  says.
- TFTP: a DATA packet longer than the block size in force is dropped, not
  delivered with a length above `blksize`; an OACK with an unterminated
  option string is dropped whole.

## [0.1.5] - 2026-10-02

### Changed

- The documents describe the stack as it is, in the present tense; this
  file keeps the history.  The plan is the current scope and roadmap, not
  a task log.
- Test counts are no longer reported: requirements coverage
  (`scripts/trace.py`) and code coverage (the CI job `coverage`, built
  with TLS) are.
- The Cortex-M0 sizes in the documents are measured again.

## [0.1.4] - 2026-10-01

The RFC MUSTs the requirement documents left out: an inventory of RFC 1122,
791, 792, 826, 1112, 2236, 768, 9293, 6298, 2131, 2132, 1123, 1350, 9110,
9112, 6762 and 6763 added a row for each, a black-box integration test for
each, and the fixes below.  What the stack does not do by design is a
**deviation** row, with the behaviour it guarantees instead tested: one
default gateway and no route cache, Redirects ignored, source-routed
datagrams dropped, IP options not passed to the transports, no TCP urgent
data.

### Added

- **IPv4 reassembly** in a buffer the application gives
  (`ipv4_set_reassembly()`, `IPV4_REASSEMBLY_BUFFER(emtu_r)`): one datagram
  at a time, fragments in any order and overlapping, a 60 s timeout with
  Time Exceeded (code 1).  `ipv4_mms_r()` and `ipv4_mms_s()` give the
  largest message the buffers and the MTU allow; `net_t.mtu` (default
  1500) bounds every frame sent.
- **ICMP errors reach the transports.**  UDP: `udp_set_error_handler()`
  with `udp_icmp_error_t` (ports, type, code, next-hop MTU, the whole
  quote); `udp_rx_dst_ip()` gives a handler the datagram's destination.
  TCP: hard errors abort, soft ones raise `TCP_EVT_SOFT_ERROR`
  (`tcp_last_error()`), Fragmentation Needed lowers the segment size.
- **TCP:** `tcp_set_max_retransmits()` (R2; R1 is reported),
  `tcp_set_tos()`, `tcp6_connect_from()` (OPEN's local address).
- **UDP:** `udp_send_inplace_opts()` sets the TOS.
- **IGMP** answers queries: report delays, suppression by another host's
  report, IGMPv1 routers.
- **TFTP:** netascii (`tftp_client_set_mode()`); an adaptive
  retransmission timeout (RFC 1123 §4.2.3.2).
- **DHCPv4:** the client probes an offered address with ARP and declines
  it if it is in use (`DHCPV4_CLI_CHECKING`, `DHCPV4_EVT_DECLINED`);
  options in `file` and `sname`, and split options, are read.
- **HTTP:** a `Date` field from `http_server_t.clock`; 421 for an https
  request the connection cannot vouch for (`https_hosts`); `If-Match`,
  `If-None-Match`; `Expect: 100-continue`.

### Changed

- `udp_send*()` refuse a destination of 0.0.0.0, an address in 127/8, the
  broadcast MAC with a destination that is no IP broadcast or multicast,
  and a source other than our address or 0.0.0.0.
  `dhcpv4_server_init()` therefore requires `cfg->server_ip` to be
  `net->ipv4_addr`.
- `tcp_connect()` refuses a remote address that is no single host, and a
  host with no address; `tcp_listen()` refuses a connection in use
  (`NET_ERR_BUSY`); a connection keeps its local address, and is aborted if
  the host's changes.  `tcp_conn_t` grows by 8 bytes (4 dual-stack).
- The DHCPv4 client reports `DHCPV4_EVT_BOUND` one second after the ACK,
  once the address probe has found it free; the server keeps one client,
  known by its hardware address.
- `http_format_header()` takes a date; `HTTP_HDR_MAX` is 224.
- The all-hosts group 224.0.0.1 is always joined with a group table.
- mDNS multicasts a record at most once a second (goodbyes excepted), and
  a unique record set whole or not at all; TXT records' TTL is 75 minutes.
  In a conflict, `mdns_withdraw()` says goodbye to the shared records
  announced under the old name and keeps them for the renamed announcement.
  `mdns_t` grows from 48 to 96 bytes.

### Fixed

- ARP: broadcasts and multicasts go straight to the link; requests are
  rate-limited; a gateway MAC learned by ARP expires after 5 minutes.
- Ethernet: a frame we sent, looped back, is dropped.
- IPv4: our classful network's directed broadcasts are recognised;
  source-routed datagrams are dropped; an Echo Reply too long for one
  frame is truncated; no ICMP error is sent about an ICMP error.
- TCP: a RST is taken into a zero window; the segment that empties the
  send buffer carries PSH, and data written is never left unsent; after a
  SYN timed out, data starts with a 3 s RTO; a SYN from 0.0.0.0 is
  ignored.
- HTTP: bare CR, NUL, a bad Host value and an unframeable
  Transfer-Encoding are refused (400); a handler's response the server
  cannot send validly is refused.
- DHCPv4: an OFFER without a Server Identifier is dropped; T1 < T2 < the
  lease is enforced; the server's options follow the Parameter Request
  List.
- mDNS: probing starts again after a conflict, simultaneous probes are
  tiebroken, and after fifteen conflicts probes are five seconds apart;
  responses received before the first probe, off-link responses and
  messages with a non-zero OPCODE or RCODE are ignored; known answers
  suppress an answer only from its querier; names over 255 bytes and TXT
  strings RFC 6763 forbids are refused; legacy unicast replies do not
  compress the SRV target; only addresses usable on the interface are
  announced, with NSEC when there are none.

## [0.1.3] - 2026-10-01

### Changes

- docs, tests: the RFC MUSTs the link, IP and transport requirements left out

## [0.1.2] - 2026-10-01

### Added

- Black-box integration tests (`tests/integration/`): the stack driven only
  through its API and a scripted link, the network side encoded and decoded
  independently, each test traced to the requirements it verifies.  The bugs
  the V1 audit found are tested this way, each test checked to fail on the
  code before its fix.
- `scripts/trace.py` and the CI job `traceability`: tests to requirements;
  the CI job `coverage`: what the integration tests reach of `src/`.
- `SMALLEST_TCP_COVERAGE`: build for gcov.

## [0.1.1] - 2026-10-01

### Changed

- Every push to `main` that passes CI is released: CI commits the next
  patch version to `main`, tags it and publishes the release
  (`scripts/release.py`, `.github/workflows/release.yml`).  Pull before your
  next push.

## [0.1.0] - 2026-10-01

The first release: the V1 scope of the
[plan](https://github.com/n9wxu/smallest_tcp/blob/v0.1.0/tcpip-stack-plan.md),
Milestones 1–14, but for the DNS stub resolver.  Every component is listed,
with its tests, in the
[README](https://github.com/n9wxu/smallest_tcp/blob/v0.1.0/README.md#-current-status).

### Added

- **Core:** a portable C99 stack with no dynamic allocation and no static
  state: Ethernet II, ARP, IPv4 with multicast and IGMPv2, ICMPv4, UDP, and
  TCP (RFC 9293 state machine, one segment in flight, retransmission, zero
  window probes, RFC 6528 initial sequence numbers), over an abstract
  six-function MAC driver.
- **IPv6:** RFC 8200 with extension headers, ICMPv6, Neighbor Discovery with
  Duplicate Address Detection, router discovery and SLAAC, MLDv2 with MLDv1
  fallback; dual stack or IPv6 alone.
- **Application protocols:** a DHCPv4 client and minimal server, a DHCPv6
  client (stateless and stateful), a TFTP client, an mDNS responder with
  DNS-SD, and an HTTP/1.0 server.
- **Security:** TLS 1.3 (RFC 8446) and DTLS 1.3 (RFC 9147), client and server,
  over a crypto backend interface with Mbed TLS 3.6 bundled.
- **Drivers:** Linux TAP and raw socket, macOS BPF, the STM32F4 Ethernet MAC
  with a NUCLEO-F429ZI board port (built, not yet run on hardware), a stub.
- **Builds:** CMake libraries for FetchContent, protocol selection at
  compile and link time, Cortex-M0 size benchmarks: 3.0 KB of flash for a
  UDP echo server.
- **Tests:** 846 unit tests (857 on Linux as root), 209 blackbox conformance
  tests run over TAP and raw sockets in CI, nightly fuzzing, interop with
  Avahi, mDNSResponder, dnsmasq, OpenSSL, curl and wolfSSL.
- **Releases:** `net_version.h` holds the version (`NET_VERSION_STRING`,
  `NET_VERSION` for `#if`); a release is tagged and published automatically
  when CI passes on `main` for a version not yet released.
- `mdns_withdraw()` withdraws some records — one service, say — with a
  goodbye, while the rest stay.

### Changed

These differ from the stack as the milestones left it, and callers may need
to change:

- `net_random_seed(net, entropy, len)` takes a byte string, every byte of
  which counts, instead of a `uint32_t`; 8 random bytes fill the key that
  keys TCP's initial sequence numbers.  `net_init()` keys it from the whole
  MAC address.
- `tcp_close()` acts before the connection is open: LISTEN and SYN-SENT go to
  CLOSED, and in SYN-RECEIVED the FIN follows the ACK of our SYN.
  `tcp_abort()` sends a RST only where the peer holds the connection open.
- A connection opened with `tcp_listen()` that is reset, sees a SYN, or gives
  up in SYN-RECEIVED listens again instead of closing.
- `mdns_init()` returns `NET_ERR_BUF_TOO_SMALL` for a record that would not
  fit one message in the TX frame buffer.
- `udp_send()` and the in-place sends refuse a datagram larger than one
  Ethernet frame (1472 bytes of payload, 1452 over IPv6), and
  `udp_send_inplace*()` a TTL of 0.

### Fixed

- IPv4 accepted another subnet's directed broadcast, and with a /31 or /32
  mask took every address for a broadcast.
- Datagrams from a broadcast, multicast or class E source were accepted, and
  an ICMP error went back to them and to 0.0.0.0.  The echo reply copied the
  request's Code.
- HTTP: a HEAD request that failed before it was parsed got a body; a 204
  or 304 was sent with the handler's body; a 405 for a route allowing
  nothing had no `Allow` field; two `Host` lines were accepted.
- mDNS: the goodbye left out the service types' meta-query listing; a query
  with TC set was answered without waiting for its other known answers; a
  record too large for a packet was dropped without a word.
- ARP answered a request for 0.0.0.0 before an address was configured, and
  took a reply from 0.0.0.0 for the gateway's when there was none.
- The incremental checksum was wrong for pieces of odd length.
- Several blackbox tests cited the wrong requirement.

### Known limitations

- No DNS stub resolver.
- Received ICMP errors are dropped, so TCP and UDP never hear of them,
  Path MTU Discovery included: every packet has DF set and fits 1500 bytes.
- TCP keeps one segment in flight, with no RTT measurement or congestion
  control; IP fragments are dropped, not reassembled.
- Resolving MAC addresses (ARP retries, the next hop of a UDP send) is the
  application's job.

[Unreleased]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.9...HEAD
[0.1.9]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/n9wxu/smallest_tcp/releases/tag/v0.1.0
