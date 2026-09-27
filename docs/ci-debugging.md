# CI/CD Debugging Guide — smallest_tcp

**Last updated:** 2026-09-27

This document captures every significant CI/CD failure encountered during
development, along with the diagnostic workflow that resolved each one.  Consult
this guide before spending time looking at SUT code — the majority of CI failures
turn out to be test bugs or environment issues, not protocol bugs.

---

## 0. The CI jobs

`.github/workflows/ci.yml` runs on every push and pull request to `main`.
CMake is the only host build; the `Makefile` is used only by `arm-size`.

| Job | What it does |
|---|---|
| `cmake-ipv4-only` | IPv4-only build without TLS (`-DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF`) and its unit tests; then library-only builds with `-DSMALLEST_TCP_TCP=OFF` and with `-DSMALLEST_TCP_UDP=OFF` |
| `arm-size` | `make arm-size-all`: the Cortex-M0 size benchmarks and `arm-check-division` (§3.12) |
| `cmake-linux`, `cmake-macos` | The default build (dual stack, TLS with Mbed TLS) and `ctest`; on Linux also `sudo ./build/tests/test_rawsock` for the raw-socket driver's live tests |
| `blackbox-linux` | ARP, IPv4, ICMP, UDP, TCP suites against `tcp_echo_demo` via `run_blackbox.sh`, once over TAP and once over the raw socket |
| `blackbox-validate` | The same suites against the Linux kernel as reference SUT (§1) |
| `blackbox-ipv6`, `blackbox-dhcp`, `blackbox-mdns`, `blackbox-http`, `blackbox-tls` | The suites that launch their own demo SUTs, each over TAP and the raw socket, with their interop checks |
| `fetchcontent` | Builds and runs `examples/fetchcontent` against the checkout |

`fuzz.yml` runs the TCP fuzz suite nightly.  The full matrix is in
[test-plan.md §3](test-plan.md#3-ci-job-matrix).

## 1. Two-Job Interpretation Rule

The core protocol suites (ARP, IPv4, ICMP, UDP, TCP) run in two CI jobs:

| Job | SUT | What a FAIL means |
|---|---|---|
| `blackbox-linux` | `smallest_tcp` binary (`tcp_echo_demo`) | **SUT bug** — our code is wrong |
| `blackbox-validate` | Linux kernel + `socat` (reference implementation) | **Test bug** — the test assertion is wrong |

The DHCPv4, mDNS, HTTP and IPv6 suites are excluded from
`blackbox-validate` (they drive our demos, not the kernel), and the TLS and
HTTPS suites skip themselves there because no SUT binary is given.

**Always check `blackbox-validate` first.**  If the same test also fails
against the Linux kernel, fix the test — do not touch SUT code.  Only once
the test passes against Linux but still fails against our SUT is it safe to
conclude there is a protocol bug in the stack.

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

## 3. Known Issues and Fixes

### 3.1 All tests ERROR: `ARP timeout: no reply from 10.0.0.2`

**Symptom:** Every test in a suite reports `ERROR` (not `FAILED`).  The `ctx`
fixture raises `RuntimeError: ARP timeout …` during setup, before any test body
runs.

**Root cause:** The SUT is not running, or is not attached to the TAP interface.
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

---

### 3.2 First test in a suite fails; subsequent tests pass (race condition)

**Symptom:** `test_arp_001` (or the first test of any suite) times out with
empty Scapy results.  `test_arp_002` (which runs ~3s later) passes immediately.

**Root cause:** The `sut_settle` autouse fixture previously only slept
*after* each test.  The very first test had zero settle time between the `ctx`
fixture's `srp1()` socket close and the test's `AsyncSniffer` open.  On a
loaded CI runner the kernel scheduling window can exceed the 20 ms sleep inside
`send_recv_arp()`, causing the SUT's reply to arrive before Scapy's AF_PACKET
socket was registered.

**Fix applied (`conftest.py`):** Added a 50 ms pre-yield sleep in `sut_settle`
so every test — including the first — has time for socket setup before stimulus
frames are sent.

**Key lesson:** If test N always fails and test N+1 always passes, the problem
is almost always a pre-test settle race, not a protocol bug.

---

### 3.3 ICMP checksum validation always passes (false negative)

**Symptom:** `test_icmp_004` passed even when the SUT sent an echo reply with
a corrupt checksum.

**Root cause:** `_icmp_checksum_ok()` zeroed the checksum field before summing,
then checked `(~s & 0xFFFF) == 0xFFFF`.  This is only true when the stored
checksum is `0x0000` — which means the test accepted any reply regardless of
the actual checksum value.

**Correct algorithm:** Sum all bytes *with* the checksum field intact; a valid
checksum produces `s == 0xFFFF` (all-ones in one's complement).

```python
# WRONG — zeros checksum, only catches 0x0000 case
buf = bytearray(raw)
buf[2] = buf[3] = 0
s = sum(buf[i] | buf[i+1] << 8 for i in range(0, len(buf), 2))
return (~s & 0xFFFF) == 0xFFFF

# CORRECT — include stored checksum in sum
s = sum(raw[i] | raw[i+1] << 8 for i in range(0, len(raw), 2))
return s == 0xFFFF
```

**Key lesson:** Always validate checksum test helpers against the
`blackbox-validate` job (Linux generates correct checksums; the helper should
accept them and reject corrupt ones).

---

### 3.4 Python operator precedence: `/` vs `+` in Scapy expressions

**Symptom:** `TypeError: unsupported operand type` at runtime in a Scapy
frame builder, e.g.:

```python
pkt = IP(dst="10.0.0.2") / b"A" + b"B"   # TypeError
```

**Root cause:** Python operator precedence.  `/` (used by Scapy for layer
stacking) binds *tighter* than `+` (bytes concatenation).  The expression
parses as `(IP / b"A") + b"B"`, where `+` tries to concatenate a Scapy
packet with a bytes object.

**Fix:** Parenthesise the bytes payload:

```python
pkt = IP(dst="10.0.0.2") / (b"A" + b"B")   # correct
```

**Key lesson:** Any Scapy expression mixing `/` and `+` or `-` needs explicit
parentheses around the bytes operand.

---

### 3.5 SUT behaviour is correct but test assertion is wrong (ICMP Protocol Unreachable)

**Symptom:** `test_ipv4_003` failed because the SUT sent no ICMP Protocol
Unreachable for an unknown protocol number.

**Investigation:** The `blackbox-validate` job confirmed the test passed against
Linux — Linux does send ICMP Protocol Unreachable for unknown protocols on
unicast destinations.  Therefore the SUT had a real bug.

**Root cause in SUT:** `ipv4_input()` had no `default` case for unknown protocol
numbers; it silently dropped the packet instead of calling
`icmp_send_dest_unreach(ICMP_CODE_PROTO_UNREACH, …)`.

**Fix applied (`src/ipv4.c`):** Added a default case that sends ICMP Protocol
Unreachable (type 3, code 2) for unicast destinations.

**Key lesson:** This is the canonical example of how the two-job pattern works:
`blackbox-validate` passes → test is correct → fix the SUT, not the test.

---

### 3.6 Post-fuzz regression missed protocol suites

**Symptom:** After a fuzz run, only `test_tcp_conform.py` was re-run as the
regression check.  Bugs introduced in (or exposed by) the fuzz that affected
ARP/IPv4/ICMP/UDP were not caught.

**Fix applied (`fuzz.yml`):** Replaced the single-suite pytest call with
`run_blackbox.sh` (all 5 suites) for the post-fuzz regression step.

**Key lesson:** Any time you add a new conformance suite, also update `fuzz.yml`
and `run_blackbox.sh` so the nightly regression is complete.  The canonical
pattern: `run_blackbox.sh` defines the complete suite list; both CI jobs and
fuzz.yml invoke it rather than calling pytest directly.

---

### 3.7 `docs/test-plan.md` stale after adding new suites

**Symptom:** After adding ARP/IPv4/ICMP/UDP blackbox suites (5+8+7+7 tests),
`docs/test-plan.md` still showed only the TCP conformance suite.

**Fix:** Always update `docs/test-plan.md` in the same commit that adds or
modifies a test suite.  The test plan is the authoritative list of what CI
validates; stale docs erode trust in the suite.

---

### 3.8 TCP tests fail: "No data echoed" / "Expected ACK" — kernel auto-RSTs the SUT

**Symptom:** `test_tcp_014_data_echo_seq_ack`, `test_tcp_005_graceful_close_active`,
and `test_tcp_041_out_of_window_segment_gets_ack` fail.  Tests that only need
a SYN-ACK (e.g. `test_tcp_002`, `test_tcp_076`) continue to pass.  The SUT
log (added to CI in 2026-03) shows a characteristic double-RST pattern:

```
tcp: SYN from 10.0.0.100:50005 → SYN_RECEIVED, ISS=...
tcp_input: 10.0.0.100:50005 → flags=0x04 ack=0        ← KERNEL AUTO-RST
tcp: listen on port 7
tcp_input: 10.0.0.100:50005 → flags=0x04 ack=<ISN+1>  ← our test RST (harmless)
```

**Root cause:** `10.0.0.100` (Scapy's phantom source IP) is **assigned to
`tap0`** via `ip addr add 10.0.0.100/24 dev tap0`.  When the SUT writes its
SYN-ACK to the TAP fd, the Linux kernel processes the packet as if it arrived
on the `tap0` interface.  Because `10.0.0.100` is a local address and no TCP
socket is listening on the ephemeral source port (50001–50N), the kernel
generates a RST segment addressed to the SUT.  This RST is written to the TAP
fd FIFO **before** our Scapy handshake ACK, so the SUT receives it first and
resets to LISTEN.  All subsequent data / FIN packets find the SUT in LISTEN,
which replies with RST (ACK-to-LISTEN behaviour) instead of echoing data.

Tests that PASS despite this bug:
- `test_tcp_002/076/082` — only check the SYN-ACK, which arrives before the RST
- `test_tcp_078` — vacuously passes: no payload in the RST replies,
  so the `assert tcp_payload_len <= small_mss` loop never fires
- `test_tcp_097` — vacuously passes: no echo data → `echo_pkts` is empty →
  no ACK sent → no retransmits → "no spurious retransmits" passes

**Fix applied (`.github/workflows/ci.yml`):** Drop kernel-generated RSTs on
`tap0` only (same rule that `blackbox-validate` uses for `veth-test`):

```yaml
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -o tap0 -j DROP
```

Scoping to `-o tap0` is critical: it only affects traffic leaving through
the TAP interface, leaving the SUT's own RSTs (sport=7 → dport=ephemeral)
intact so tests like `test_tcp_031` and `test_tcp_072` still work.

Cleanup in teardown:
```yaml
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -o tap0 -j DROP 2>/dev/null || true
```

**Diagnostic tip:** Enable the "Dump SUT log on failure" step in `ci.yml` (it is
already present from 2026-03) and look for the double-RST pattern above.  If you
see `flags=0x04 ack=0` immediately after `SYN_RECEIVED`, this is the kernel
auto-RST; if you only see one RST, look elsewhere.

**Key lesson:** When a TAP interface has the phantom IP assigned, the Linux
kernel participates in TCP for that address.  Always drop kernel RSTs on the
TAP interface when the phantom IP is local.

---

### 3.9 DHCP test fails: "XID changed across retransmit" (RFC 2131 §3.1 violation)

**Symptom:** `test_dhcpv4_conform.py::test_discover_retransmit` fails with:

```
AssertionError: XID changed across retransmit: 0xcd305e6a → 0x25dbfac1
```

**Root cause in SUT (`src/dhcpv4_client.c`):** The `DHCPV4_CLI_SELECTING`
retransmit case in `dhcpv4_client_tick()` called `c->xid = rand_xid()` before
every retransmit:

```c
case DHCPV4_CLI_SELECTING:
    c->xid = rand_xid();    // ← BUG: regenerates XID on every retransmit
    send_discover(net, c);
```

RFC 2131 §3.1 requires the XID to remain constant for all retransmits of the
same DISCOVER session.  A server that caches the initial DISCOVER's XID (or a
test that captures it) will never match subsequent retransmits, causing the
handshake to fail or the retransmit test to detect the changed XID.

**Fix applied:** Removed the `c->xid = rand_xid()` line from the retransmit
path.  The XID is correctly initialised once in `dhcpv4_client_start()` and
`restart_init()` (when starting a new session); it must not change during
retransmission of the same session.

```c
case DHCPV4_CLI_SELECTING:
    /* RFC 2131 §3.1: XID stays constant for all retransmits */
    send_discover(net, c);
    c->timer_ms = next_retry_ms(c->retries);
    …
```

**Key lesson:** Any field whose purpose is to correlate a response with a
request (XID, seq, ISN) must be stable for the lifetime of that transaction.
Always add a retransmit-XID conformance test when implementing request/response
protocols.

---

### 3.10 Raw-socket leg only: host-kernel traffic dropped, Scapy traffic fine

**Symptom:** in the `raw socket` leg, `ping`/`arping` and the Scapy suites
pass, but `nc`, the HTTP suite or the interop scripts time out — everything
where the *host kernel* sends TCP or UDP to the SUT.

**Cause:** checksum offload.  On a veth pair the kernel leaves the TCP/UDP
checksum partial for the "NIC" to finish; nothing ever does, so the stack
drops the segment.  Scapy computes full checksums, so its tests are
unaffected.  `src/driver/rawsock.c` reads each frame with a
`virtio_net_hdr` (`PACKET_VNET_HDR`) and finishes the checksum when the
kernel flags it (`VIRTIO_NET_HDR_F_NEEDS_CSUM`).
`test_rawsock`'s `test_live_kernel_{udp,tcp}_checksum_valid` catch a
regression here without any blackbox run.

**Also:** a TAP device serves one process only; a raw socket does not.  A
leftover SUT (e.g. the last `dhcp_echo_demo`) makes the next TAP suite fail
to open `tap0` but goes unnoticed on the raw link.  `conftest.py` stops the
DHCP SUT at session end for this reason.

### 3.11 Raw-socket leg only: bulk transfers fail (TLS `bad_record_mac`)

**Symptom:** small exchanges pass, but a large transfer from the host (the
TLS suite's 40 kB echo or a full 16 kB record) fails in the `raw socket`
leg: the SUT sends `bad_record_mac`, or an echo comes back altered.

**Cause (fixed in tcp.c):** the kernel sends bulk data on a veth pair as
GSO super-frames, which the raw-socket driver drops (they exceed one
Ethernet frame).  The kernel then retransmits with different segment
boundaries, so segments overlap data already received — and TCP used to
append every acceptable segment at RCV.NXT without trimming it, repeating
bytes.  TLS's record MAC caught what a plain TCP echo would have passed on
silently.  tcp.c now skips the bytes before RCV.NXT, drops a segment that
starts after a gap and processes a FIN only in sequence (`test_tcp`'s
in-order delivery tests).  If this reappears, look at step 7 of
`tcp_input_seg()` first.

**Also on a persistent test host:** only one of `tap0` / `veth-test` may
hold 10.0.0.100.  A downed `tap0` that keeps the address leaves a
`linkdown` route the kernel still uses, and the raw leg cannot reach the
SUT — `sut_net.sh down tap` before `up raw`.

### 3.12 `arm-size` fails: "These objects call a library divide"

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
Reproduce locally with `make arm-check-division`.

### 3.13 `cmake-ipv4-only` fails, `cmake-linux` passes

The code, a test or a demo uses something that exists only with
`NET_USE_IPV6` (for example `net->ip6`, the `udp6` API, or
`http_request_t.remote_ip6`) outside `#if NET_USE_IPV6`.  Reproduce with
`cmake -S . -B build-v4 -DSMALLEST_TCP_IPV6=OFF -DSMALLEST_TCP_TLS=OFF`.
The same job's no-TCP and no-UDP builds catch the equivalent for
`NET_USE_TCP` and `NET_USE_UDP` in the libraries
([configuration.md §5](design/configuration.md#5-compile-time-protocol-selection)).

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
specific timer values and are **excluded from `blackbox-validate`**.

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
Before test: sleep 50 ms   ← gives socket setup time (prevents first-test race)
[test body runs]
After test:  sleep 100 ms  ← gives SUT time to reset state / re-enter LISTEN
```

If you observe a timing-dependent failure on the *first* test of a session,
increase the pre-test sleep to 100 ms.  If failures appear *between* tests
(SUT stuck in wrong state), increase the post-test sleep.

---

## 7. Adding a New Protocol Suite — Checklist

When implementing a new protocol and adding blackbox tests:

1. ☐ Write `tests/blackbox/test_<proto>_conform.py`
2. ☐ Add to `SUITES` list in `tests/blackbox/run_blackbox.sh`
3. ☐ Add a `blackbox-<proto>` job to `.github/workflows/ci.yml`, with the TAP and raw-socket matrix legs (`tests/blackbox/sut_net.sh`)
4. ☐ If the suite can run against the Linux kernel, let `blackbox-validate` run it; if it drives one of our demos, add it to that job's `--ignore` list (or make it skip without its SUT option)
5. ☐ Add a Linux sanity check or interop step (kernel tool, 2–5 s) to the new job
6. ☐ Update `docs/test-plan.md` — suite table, CI matrix, coverage table
7. ☐ Update `README.md` — test count in summary line and status table
8. ☐ Add `@pytest.mark.sut_specific` to any timer-dependent tests
9. ☐ Verify `blackbox-validate` passes before merging (tests are correct)
