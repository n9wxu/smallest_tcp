# CI/CD Debugging Guide — smallest_tcp

**Last updated:** 2026-03-22

This document captures every significant CI/CD failure encountered during
development, along with the diagnostic workflow that resolved each one.  Consult
this guide before spending time looking at SUT code — the majority of CI failures
turn out to be test bugs or environment issues, not protocol bugs.

---

## 1. Two-Job Interpretation Rule

Every protocol has two CI jobs running the same test files:

| Job | SUT | What a FAIL means |
|---|---|---|
| `blackbox-linux` | `smallest_tcp` binary (`tcp_echo_demo`) | **SUT bug** — our code is wrong |
| `blackbox-validate` | Linux kernel + `socat` (reference implementation) | **Test bug** — the test assertion is wrong |

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
| `test_tcp_090_syn_retransmit_on_timeout` | Waits 2.5 s for retransmit; SUT RTO=500 ms, Linux RTO starts at 1–3 s |
| `test_tcp_085_persist_probe_on_zero_window` | `recv_tcp(timeout=3)`; SUT persist=~1 s, Linux persist starts at 5 s |

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
3. ☐ Add `blackbox-<proto>-linux` job to `.github/workflows/ci.yml`
4. ☐ Add `blackbox-<proto>-validate` job (reference SUT) to `ci.yml`
5. ☐ Add Linux sanity check step (kernel tool, 2–5 s) to `blackbox-<proto>-linux`
6. ☐ Update `docs/test-plan.md` — suite table, CI matrix, coverage table
7. ☐ Update `README.md` — test count in summary line and status table
8. ☐ Add `@pytest.mark.sut_specific` to any timer-dependent tests
9. ☐ Verify `blackbox-validate` passes before merging (tests are correct)
