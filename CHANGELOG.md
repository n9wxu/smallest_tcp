# Changelog

Every release of smallest_tcp, newest first: CI releases every push to
`main` that passes, and moves what is under [Unreleased] into the release.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
while the major version is 0, a minor release may change the API, and the
entry says how.  How a release is made:
[docs/release-process.md](docs/release-process.md).

## [Unreleased]

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

[Unreleased]: https://github.com/n9wxu/smallest_tcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/n9wxu/smallest_tcp/releases/tag/v0.1.0
