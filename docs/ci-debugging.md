# CI/CD Debugging Guide — smallest_tcp

This document lists the CI jobs, how to tell a test bug from a stack bug,
and the failures whose causes are known.  Consult it before looking at SUT
code: most blackbox failures are test or environment problems, not protocol
bugs.

---

## 0. The CI jobs

`.github/workflows/ci.yml` runs on every push and pull request to `main`.
CMake is the only host build; the `Makefile` is used only by `arm-size`.

| Job | What it does |
|---|---|
| `cmake-ipv4-only` | IPv4-only build without TLS (`-DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF`) and its tests; then library-only builds with `-DSMALLEST_TCP_TCP=OFF` and with `-DSMALLEST_TCP_UDP=OFF` |
| `cmake-ipv6-only` | IPv6-only build (`-DSMALLEST_TCP_IPV4=OFF`) and its tests, including the checks that the IPv4-only protocols refuse to compile; then library-only builds without TCP and without UDP |
| `arm-size` | `make arm-size-all`: the Cortex-M0 size benchmarks, `arm-check-division` (§3.10) and `arm-check-links` (TLS's objects must not need DTLS's record layer, nor DTLS's TLS's) |
| `board-nucleo-f429zi` | Cross-builds the NUCLEO-F429ZI firmware of the hardware fuzz job — build only |
| `cmake-linux`, `cmake-macos` | The default build (dual stack, TLS with Mbed TLS) and `ctest`; on Linux also `sudo ./build/tests/test_rawsock` for the raw-socket driver's live tests |
| `blackbox-linux` | ARP, IPv4, ICMP, UDP, TCP suites against `tcp_echo_demo` via `run_blackbox.sh`, once over TAP and once over the raw socket |
| `blackbox-validate` | The same suites against the Linux kernel as reference SUT (§1) |
| `blackbox-ipv6`, `blackbox-dhcp`, `blackbox-mdns`, `blackbox-http`, `blackbox-tls`, `blackbox-dtls` | The suites that launch their own demo SUTs, each over TAP and the raw socket, with their interop checks (DTLS against wolfSSL, built by `tests/blackbox/build_wolfssl.sh` and cached); the IPv6 suite also against an IPv6-only build |
| `fetchcontent` | Builds and runs `examples/fetchcontent` against the checkout |
| `traceability` | `scripts/trace.py --strict --markdown`: every integration test cites the requirements it verifies, every cited ID exists; the summary is the requirements coverage — per requirement document, the MUST rows verified by a black-box test, by any test, and by none ([test-plan.md §0](test-plan.md#0-policy-and-the-integration-tests)) |
| `coverage` | Builds with `-DSMALLEST_TCP_COVERAGE=ON`, runs the integration tests (`ctest -L integration`) and reports, with gcovr, the lines and branches of `src/` they reach — what the API reaches; the HTML report is an artifact |
| `release-check` | `scripts/release.py check`: the version in `net_version.h` parses, `CHANGELOG.md` has its `## [Unreleased]` section, and a trial stamp of the next version works; CMake and the compiled library report the version ([release-process.md](release-process.md)) |

`fuzz.yml` runs the TCP fuzz suite nightly.  `release.yml` runs when this
workflow completes on `main`: if every job passed and `main` is still the
tested commit, it commits the next version, tags it and publishes the
release.  The full matrix is in
[test-plan.md §3](test-plan.md#3-ci-job-matrix).

## 1. Two-Job Interpretation Rule

The core protocol suites (ARP, IPv4, ICMP, UDP, TCP) run in two CI jobs:

| Job | SUT | What a FAIL means |
|---|---|---|
| `blackbox-linux` | `smallest_tcp` binary (`tcp_echo_demo`) | **SUT bug** — our code is wrong |
| `blackbox-validate` | Linux kernel + `socat` (reference implementation) | **Test bug** — the test assertion is wrong |

The DHCPv4, mDNS, HTTP and IPv6 suites are excluded from
`blackbox-validate` (they drive our demos, not the kernel), and the TLS,
HTTPS and DTLS suites skip themselves there because no SUT binary is given.

**Always check `blackbox-validate` first.**  If the same test also fails
against the Linux kernel, fix the test — do not touch SUT code.  Only once
the test passes against Linux but still fails against our SUT is it safe to
conclude there is a protocol bug in the stack.

For example, `test_ipv4_003` expects ICMP Protocol Unreachable for an
unknown protocol on a unicast datagram.  Linux sends it, so the test is
right; if only `blackbox-linux` fails it, look at the default case of
`deliver()` in `src/ipv4.c`.

A bug found this way becomes a failing test first — an integration test
traced to the requirement it breaks — and then the fix
([test-plan.md §0](test-plan.md#0-policy-and-the-integration-tests)).

---

## 2. Diagnostic Workflow

```
CI failure reported
       │
       ▼
Does blackbox-validate also fail for this test?
   YES → Fix the test (assertion, timing, operator precedence)
    NO → SUT has a bug; continue to step 3
       │
       ▼
Is it ALL tests failing with "ARP timeout"?
   YES → SUT didn't start or TAP not up (see §3.1)
    NO → Continue to step 4
       │
       ▼
Is it exactly the FIRST test in a suite failing?
   YES → Race condition between socket open and stimulus (see §3.2)
    NO → Continue to step 5
       │
       ▼
Read the SUT log, arping/tcpdump the interface, isolate the failing exchange
```

---

## 3. Known Failures

### 3.1 All tests ERROR: `ARP timeout: no reply from 10.0.0.2`

**Symptom:** Every test in a suite reports `ERROR` (not `FAILED`).  The `ctx`
fixture raises `RuntimeError: ARP timeout …` during setup, before any test body
runs.

**Cause:** The SUT is not running, or is not attached to the TAP interface.
No process is answering ARP requests on `tap0`.

**Diagnostic checklist:**

| Check | Command | Expected output |
|---|---|---|
| SUT process alive? | `pgrep -a tcp_echo_demo` | Shows PID |
| SUT log shows TAP open | `cat /tmp/sut.log` | `[TAP] Opened tap0 (fd=N)` |
| `/dev/net/tun` available | `ls -la /dev/net/tun` | `crw-rw-rw- … 10, 200` |
| `tap0` is UP | `ip link show tap0` | `state UP` or `state UNKNOWN` |
| Binary path correct | `ls build/demo/tcp_echo_demo` | file exists |

**Most frequent cause — wrong binary path:**

CMake mirrors the source tree.  `demo/tcp_echo/main.c` → binary at
`build/demo/tcp_echo_demo`, **not** `build/tcp_echo_demo`.

```bash
# WRONG — sudo silently exits with "command not found"
sudo ./build/tcp_echo_demo &

# CORRECT
sudo ./build/demo/tcp_echo_demo &
```

After a clean build, always verify:
```bash
find build/ -name tcp_echo_demo
```

**LXC container issue:** `/dev/net/tun` may not be forwarded into LXC containers.
Use a KVM VM or enable TUN in the Proxmox container config:
```
lxc.cgroup2.devices.allow = c 10:200 rwm
```
— or use the raw-socket driver on a veth pair, which needs no TUN
(`tests/blackbox/sut_net.sh up raw`).

---

### 3.2 First test in a suite fails; subsequent tests pass (race condition)

**Symptom:** `test_arp_001` (or the first test of any suite) times out with
empty Scapy results; the next test passes.

**Cause:** the stimulus went out before the capture socket was open, so the
SUT's reply was missed.  On a loaded runner, opening Scapy's `AF_PACKET`
socket can take longer than any fixed sleep.

**How the suites avoid it:** `helpers.start_sniffer()` starts the
`AsyncSniffer` and returns only once Scapy's `started_callback` reports its
capture socket open; send the stimulus after it returns.  A test that
starts a sniffer itself and sleeps instead reintroduces the race.

**Key lesson:** If test N always fails and test N+1 always passes, the problem
is almost always a capture race, not a protocol bug.

---

### 3.3 A checksum check in a test that passes everything

A helper that verifies a reply's checksum must sum the message **with** the
checksum field in place: a valid one then sums to `0xFFFF` (all ones in
one's complement).  Zeroing the field before summing tests only whether the
stored checksum is 0 and accepts any reply (`_icmp_checksum_ok()` in
`test_icmp_conform.py`):

```python
# WRONG — zeros the checksum, only catches 0x0000
buf = bytearray(raw)
buf[2] = buf[3] = 0
s = sum(buf[i] | buf[i+1] << 8 for i in range(0, len(buf), 2))
return (~s & 0xFFFF) == 0xFFFF

# CORRECT — include the stored checksum in the sum
s = sum(raw[i] | raw[i+1] << 8 for i in range(0, len(raw), 2))
return s == 0xFFFF
```

Validate such helpers against `blackbox-validate`: Linux generates correct
checksums, and the helper must accept them and reject corrupt ones.

---

### 3.4 Python operator precedence: `/` vs `+` in Scapy expressions

**Symptom:** `TypeError: unsupported operand type` at runtime in a Scapy
frame builder, e.g.:

```python
pkt = IP(dst="10.0.0.2") / b"A" + b"B"   # TypeError
```

**Cause:** Python operator precedence.  `/` (used by Scapy for layer
stacking) binds *tighter* than `+` (bytes concatenation).  The expression
parses as `(IP / b"A") + b"B"`, where `+` tries to concatenate a Scapy
packet with a bytes object.

**Fix:** Parenthesise the bytes payload:

```python
pkt = IP(dst="10.0.0.2") / (b"A" + b"B")   # correct
```

Any Scapy expression mixing `/` and `+` or `-` needs explicit parentheses
around the bytes operand.

---

### 3.5 One suite list for every run of the core suites

`run_blackbox.sh` holds the list of core suites (`SUITES`: ARP, IPv4, ICMP,
UDP, TCP, and the fuzz tests with `--fuzz`).  `blackbox-linux` and the
nightly post-fuzz regression in `fuzz.yml` both run it rather than calling
pytest on single files, so a new core suite added to that list runs
everywhere.  A suite that drives its own demo gets its own job instead (§7).

---

### 3.6 TCP tests fail: "No data echoed" / "Expected ACK" — kernel auto-RSTs the SUT

**Symptom:** `test_tcp_014_data_echo_seq_ack`, `test_tcp_005_graceful_close_active`,
and `test_tcp_041_out_of_window_segment_gets_ack` fail.  Tests that only need
a SYN-ACK (e.g. `test_tcp_002`, `test_tcp_076`) continue to pass.
A capture on the harness interface (`tcpdump -i "$TEST_IF" -n tcp`) shows
a RST from 10.0.0.100 that the test never sent, between the SUT's SYN-ACK
and Scapy's ACK.

**Cause:** `10.0.0.100` (Scapy's source address) is **assigned to the
harness interface** (`sut_net.sh up` does `ip addr add 10.0.0.100/24`).
When the SUT sends its SYN-ACK, the Linux kernel sees a segment for a local
address with no socket on the ephemeral destination port (50001–50N), and
answers with a RST.  That RST reaches the SUT **before** Scapy's handshake
ACK, so the SUT returns to LISTEN, and every later data or FIN segment is
answered with a RST (ACK to LISTEN) instead of an echo.

Tests that pass despite this:
- `test_tcp_002/076/082` — only check the SYN-ACK, which arrives before the RST
- `test_tcp_078` — vacuously: no payload in the RST replies, so the
  `assert tcp_payload_len <= small_mss` loop never runs
- `test_tcp_097` — vacuously: no echo data → no ACK sent → no retransmits

**What prevents it:** `sut_net.sh up <driver> --rst-drop` drops the
kernel's RSTs leaving through the harness interface only (`blackbox-validate`
uses the same rule on `veth-test`):

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -o "$TEST_IF" -j DROP
```

Scoping it with `-o` is critical: the SUT's own RSTs (sport=7 →
dport=ephemeral) stay intact, so `test_tcp_031` and `test_tcp_072` still
see them.  `sut_net.sh down` removes the rule.  The HTTP, TLS and DTLS
suites use the host's own TCP stack as the client and run **without**
`--rst-drop`.

**Diagnostic tip:** a RST from 10.0.0.100 that the test did not send, right
after the SUT's SYN-ACK, is the kernel's; if the only RSTs are the test's
own, look elsewhere.

---

### 3.7 DHCP test fails: "XID changed across retransmit"

**Symptom:** `test_dhcpv4_conform.py::test_discover_retransmit` fails with:

```
AssertionError: XID changed across retransmit: 0xcd305e6a → 0x25dbfac1
```

**Cause:** the client chose a new transaction ID for a retransmission.
RFC 2131 §4.1 leaves that to the implementation; this client keeps one
`xid` for an exchange, so an OFFER that answers the first DISCOVER still
matches after a retransmission (the test is `sut_specific`).
`dhcpv4_client.c` draws a new `xid` only when an exchange starts
(`start_selecting()`, when discovery begins or begins again), never in the
retransmission path of `dhcpv4_client_tick()`.

A field that pairs a reply with a request (XID, sequence number, ISN) is
best kept for the life of the exchange; a request/response protocol gets a
retransmission test for it.

---

### 3.8 Raw-socket leg only: host-kernel traffic dropped, Scapy traffic fine

**Symptom:** in the `raw socket` leg, `ping`/`arping` and the Scapy suites
pass, but `nc`, the HTTP suite or the interop scripts time out — everything
where the *host kernel* sends TCP or UDP to the SUT.

**Cause:** checksum offload.  On a veth pair the kernel leaves the TCP/UDP
checksum partial for the "NIC" to finish; unfinished, the stack drops the
segment.  Scapy computes full checksums, so its tests are unaffected.
`src/driver/rawsock.c` reads each frame with a `virtio_net_hdr`
(`PACKET_VNET_HDR`) and finishes the checksum when the kernel flags it
(`VIRTIO_NET_HDR_F_NEEDS_CSUM`).  `test_rawsock`'s
`test_live_kernel_{udp,tcp}_checksum_valid` catch a regression here
without any blackbox run.

**Also:** a TAP device serves one process only; a raw socket does not.  A
leftover SUT (e.g. the last `dhcp_echo_demo`) makes the next TAP suite fail
to open `tap0` but goes unnoticed on the raw link.  `conftest.py` stops the
DHCP SUT at session end for this reason.

### 3.9 Raw-socket leg only: bulk transfers fail (TLS `bad_record_mac`)

**Symptom:** small exchanges pass, but a large transfer from the host (the
TLS suite's 40 kB echo or a full 16 kB record) fails in the `raw socket`
leg: the SUT sends `bad_record_mac`, or an echo comes back altered.

**Cause:** the kernel sends bulk data on a veth pair as GSO super-frames,
which the raw-socket driver drops (they exceed one Ethernet frame).  The
kernel then retransmits with different segment boundaries, so segments
overlap data already received.  TCP must take only the bytes from RCV.NXT
on: `data_input()` in `tcp.c` (RFC 9293 §3.10.7.4, step 7) skips the bytes
before RCV.NXT and drops a segment that starts after a gap, and
`fin_input()` takes a FIN only in sequence.  If overlapping bytes are
appended twice, TLS's record MAC catches it where a plain TCP echo would
pass the repeated bytes on silently — look at `data_input()` first.
`test_tcp`'s in-order delivery tests cover it.

**Also on a persistent test host:** only one of `tap0` / `veth-test` may
hold 10.0.0.100.  A downed `tap0` that keeps the address leaves a
`linkdown` route the kernel still uses, and the raw leg cannot reach the
SUT — `sut_net.sh down tap` before `up raw`.

### 3.10 `arm-size` fails: "These objects call a library divide"

**Symptom:** `make arm-size-all` ends with `These objects call a library
divide (no division on Cortex-M0):` and a list of object files.

**Cause:** a `/` or `%` on a run-time value in one of them.  Cortex-M0 has
no divide instruction, so the compiler calls a libgcc helper
(`__aeabi_uidiv`, `__aeabi_uidivmod`, …) — slow, and several hundred bytes
of flash.  `arm-check-division` runs `arm-none-eabi-nm -u` on every
benchmark object and on every source in `src/` compiled dual stack.

**Fix:** rewrite the expression without division — shifts and masks for
powers of two, a comparison and subtraction for wrap-around, scaling for
random ranges (`net_random_below()`), subtraction loops for decimal output
(`net_u32_to_dec()`).  See [coding-rules.md §4](design/coding-rules.md#4-no-run-time-division).
Reproduce locally with `rm -rf build/arm && make arm-check-division` (make
compares file times to the second, so remove the objects after an edit).

### 3.11 `cmake-ipv4-only` fails, `cmake-linux` passes

The code, a test or a demo uses something that exists only with
`NET_USE_IPV6` (for example `net->ip6`, the `udp6` API, or
`http_request_t.remote_ip6`) outside `#if NET_USE_IPV6`.  Reproduce with
`cmake -S . -B build-v4 -DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF`.
The same job's no-TCP and no-UDP builds catch the equivalent for
`NET_USE_TCP` and `NET_USE_UDP` in the libraries
([configuration.md §5](design/configuration.md#5-compile-time-protocol-selection)).
`cmake-ipv6-only` is the same for `NET_USE_IPV4`: reproduce with
`-DSMALLEST_TCP_IPV4=OFF`.

### 3.12 `traceability` fails

`scripts/trace.py --strict` prints a `problem:` line for each integration
test that cites no requirement and each test that cites an ID no document
under `docs/requirements/` defines.  Add the REQ IDs the test verifies to
the comment above it, or correct the ID.  Reproduce with
`python3 scripts/trace.py --strict`.

---

## 4. Reading CI Failures Without a Browser

```bash
# List last 5 runs and their conclusions
gh run list --limit 5 --json status,conclusion,databaseId,headSha,displayTitle \
  | jq '.[] | {id: .databaseId, conclusion, title: .displayTitle}'

# Show only the failing jobs' logs
gh run view <RUN_ID> --log-failed

# Get the full log for a specific job (e.g. blackbox-linux)
gh run view <RUN_ID> --job blackbox-linux --log | less

# The run_blackbox.sh summary is written to GITHUB_STEP_SUMMARY and
# also captured in /tmp/blackbox.out inside the runner.  The CI job
# appends the last 12 KB to the step summary — read it via:
gh run view <RUN_ID> --json jobs \
  | jq '.jobs[] | select(.name | contains("Blackbox")) | .steps[] | select(.name | contains("summary")) | .conclusion'
```

---

## 5. sut_specific Test Marker

Tests decorated with `@pytest.mark.sut_specific` depend on `smallest_tcp`'s
specific timer values or behaviour and are **excluded from
`blackbox-validate`**.

| Test | Why sut_specific |
|---|---|
| `test_tcp_090_syn_retransmit_on_timeout` | Waits 1.5 s, then up to 5 s, for the SYN-ACK retransmission; SUT initial RTO = 1 s (`NET_DEFAULT_TCP_RTO_INIT_MS`), Linux starts at 1–3 s |
| `test_tcp_085_persist_probe_on_zero_window` | Expects a probe within a few seconds; SUT persist interval starts at 1 s, Linux at 5 s |
| `test_tcp_078_sut_honors_our_mss` | The Linux kernel ignores a tiny peer MSS (100) on veth/loopback with TSO |
| `test_ipv4_003_unknown_proto_icmp_unreachable`, `test_ipv4_007_outbound_df_bit_set` | Behaviour of this stack that the kernel reference does not share |
| `test_http_021_idle_connection_times_out` | Waits for `http_demo`'s 10 s request timeout |
| `test_dhcpv4_conform.py`: `test_ack_binds_ip`, `test_nak_triggers_rediscover`, `test_wrong_xid_offer_ignored`, `test_discover_retransmit`, `test_request_contains_server_id` | Depend on `dhcp_echo_demo` |

When adding new timer-dependent tests, always ask: *"Would this pass against a
standard Linux kernel with default RFC-compliant timer values?"*  If not, add
`@pytest.mark.sut_specific`.

---

## 6. `sut_settle` Fixture Behaviour

Defined in `tests/blackbox/conftest.py`.  Autouse — runs for every test.

```
[test body runs]
After test:  sleep 100 ms  ← gives SUT time to reset state / re-enter LISTEN
```

If failures appear *between* tests (the SUT still in the previous test's
state), lengthen the post-test sleep.  Failures of the *first* test of a
session are a capture race instead (§3.2).

---

## 7. Adding a New Protocol Suite — Checklist

When implementing a new protocol and adding blackbox tests:

1. ☐ Write `tests/blackbox/test_<proto>_conform.py`; each test's docstring
   or comment names the REQ IDs it verifies (`scripts/trace.py`)
2. ☐ If it is a core suite run against `tcp_echo_demo`, add it to `SUITES`
   in `tests/blackbox/run_blackbox.sh` (§3.5)
3. ☐ Otherwise add a `blackbox-<proto>` job to `.github/workflows/ci.yml`, with the TAP and raw-socket matrix legs (`tests/blackbox/sut_net.sh`)
4. ☐ If the suite can run against the Linux kernel, let `blackbox-validate` run it; if it drives one of our demos, add it to that job's `--ignore` list (or make it skip without its SUT option)
5. ☐ Add a Linux sanity check or interop step (kernel tool, 2–5 s) to the new job
6. ☐ Update `docs/test-plan.md` in the same commit — suite table, CI matrix, coverage table
7. ☐ Update `README.md`'s blackbox instructions if the suite needs a new option or SUT
8. ☐ Add `@pytest.mark.sut_specific` to any timer-dependent tests
9. ☐ Verify `blackbox-validate` passes before merging (tests are correct)
