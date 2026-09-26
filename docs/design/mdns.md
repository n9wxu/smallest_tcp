# mDNS + DNS-SD Design

**Protocols:** RFC 6762 (mDNS) + RFC 6763 (DNS-SD)  
**Milestone:** 10  
**Status:** Implemented (V1 responder)  
**Last updated:** 2026-09-26

---

## 1. Motivation

pyro_fw devices must be reachable on any local network without static IP configuration, a DNS server, or DHCP-provided hostname options.  mDNS provides zero-configuration hostname resolution (`<name>.local`); DNS-SD provides zero-configuration service discovery (`_pyro._tcp.local.`).  Together they allow a control application to find every pyro_fw device on the LAN by type, read its metadata (firmware version, serial number, capabilities), and connect — with no user-supplied IP address.

---

## 2. Scope for V1 (This Milestone)

| Feature | V1 | V2 |
|---|---|---|
| mDNS responder (answer `.local` queries) | ✅ | |
| Probing + conflict detection | ✅ | |
| Gratuitous announcements | ✅ | |
| Goodbye packets on shutdown | ✅ | |
| DNS-SD advertiser (PTR/SRV/TXT) | ✅ | |
| Service-type meta-query (`_services._dns-sd._udp.local.`) | ✅ | |
| Known-answer suppression, QU and legacy unicast responses | ✅ | |
| Simultaneous-probe tiebreak (RFC 6762 §8.2) | | ✅ |
| Multi-packet known-answer lists, NSEC negative answers | | ✅ |
| mDNS querier (resolve `.local` names) | | ✅ |
| DNS-SD browser (discover services by type) | | ✅ |
| IPv6 / AAAA records | | ✅ |

---

## 3. Module Layout

mDNS reuses the DNS wire format (RFC 1035 §4) byte-for-byte, so the wire code is a separate module the planned DNS stub resolver (`dns.c`) will share:

```
dns_wire.h / dns_wire.c   — names (with compression), header/question/RR read + write
igmp.h / igmp.c           — minimal IGMPv2 join/leave
mdns.h / mdns.c           — responder state machine, answering, DNS-SD composition
```

All three build into the optional `smallest_tcp_mdns` library (`smallest_tcp::mdns`).  They rely on two core-stack features added for this milestone:

- **Multicast receive:** `net_t` holds a fixed table of joined groups (`NET_MAX_MCAST_GROUPS`, default 1; 0 compiles multicast receive out).  `eth_input()` accepts the 01:00:5E MAC of a joined group and `ipv4_input()` the group address; unjoined groups and aliased MACs are dropped.  No ICMP errors or echo replies are ever sent for multicast destinations (RFC 1122 §3.2.2).
- **Per-packet TTL + in-place send:** `udp_send_inplace()` sends a payload the caller already wrote at `UDP_PAYLOAD_OFFSET` in `net->tx.buf`, with an explicit IP TTL (255 for mDNS, RFC 6762 §11).  `udp_send()` copies into place and calls it.

---

## 4. Memory Model

The application owns the record table and an `mdns_t` (40 bytes on 32-bit targets); the responder has no static state and never allocates.  Responses are built directly in `net->tx.buf`.

```c
static const char *const txt[] = {"txtvers=1", "fw=1.2.3", "serial=DEAD01", NULL};

static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A,   .ttl = MDNS_TTL_HOST,  .name = "pyro-dead01.local",
     .rdata.a = 0},                                     /* 0 = net->ipv4_addr */
    {.type = DNS_TYPE_PTR, .ttl = MDNS_TTL_OTHER, .name = "_pyro._tcp.local",
     .rdata.ptr = "Pyro Unit 1._pyro._tcp.local"},
    {.type = DNS_TYPE_SRV, .ttl = MDNS_TTL_HOST,  .name = "Pyro Unit 1._pyro._tcp.local",
     .rdata.srv = {0, 0, 80, "pyro-dead01.local"}},
    {.type = DNS_TYPE_TXT, .ttl = MDNS_TTL_HOST,  .name = "Pyro Unit 1._pyro._tcp.local",
     .rdata.txt = txt},
};

static mdns_t mdns;

mdns_init(&mdns, &net, records, 4, on_conflict, NULL);  /* validates the table */
mdns_start(&mdns);                                       /* once the IP is known */
```

- PTR records are **shared** (many hosts advertise the same service type); A, SRV and TXT records are **unique** and are probed for.
- An A record with `.rdata.a = 0` always answers with the current `net->ipv4_addr`, so a DHCP-assigned address needs no table update.
- `mdns_init()` rejects invalid names (empty label, label > 63 bytes, name > 255 bytes), TXT strings > 255 bytes, unsupported types and more than `MDNS_MAX_RECORDS` (32) records.  Record sets are tracked as 32-bit masks.
- Names are dotted strings; labels may contain spaces (`Pyro Unit 1`) but not dots.

### State Machine

```
STOPPED ──mdns_start()──► PROBING ──(3 probes, no conflict)──► ANNOUNCING ──(2nd announcement)──► RUNNING
                            │                                     │                                  │
                      (conflicting response)              (conflicting response)        (conflicting response)
                            └──────────────────────────► CONFLICT ◄──────────────────────────────────┘
                                                            │
                                   on_conflict(): app renames, calls mdns_start() ──► PROBING

any state ──mdns_stop()──► goodbye (if ANNOUNCING/RUNNING) + IGMP leave ──► STOPPED
```

The responder only answers in ANNOUNCING and RUNNING; it is silent while PROBING (it must not answer for names it has not yet claimed) and in CONFLICT.  Calling `mdns_start()` again re-probes and re-announces — use it after a link-up or an address change (REQ-MDNS-024).

---

## 5. Probing (RFC 6762 §8.1)

```
t0 = random 0–250 ms after mdns_start()
probe 1 at t0, probe 2 at t0 + 250 ms, probe 3 at t0 + 500 ms
no conflict by t0 + 750 ms → ANNOUNCING
```

A probe is a query (QR=0, ID=0) with one `ANY` question per distinct unique name, the unicast-response (QU) bit set, and the unique records in the Authority section (no cache-flush bit).  If the TX buffer cannot hold every name, names are packed greedily into several probe packets.

**Conflict while probing:** any response carrying a record under one of our unique names — of any type — that is not identical to our own record.  Goodbye records (TTL 0) from other hosts are ignored.

---

## 6. Announcing (RFC 6762 §8.3)

Two gratuitous responses (QR=1, AA=1, ID=0), one on entering ANNOUNCING and one 1 s later, each carrying every record.  Unique records carry the cache-flush bit (top bit of the class, RFC 6762 §10.2); shared PTR records do not.  The IGMP Membership Report is repeated when announcing starts (RFC 2236 §3 recommends one repeat).

---

## 7. Responding to Queries

For each question (class IN or ANY) the responder collects matching records: same name (case-insensitive) and same type, or any type for `ANY`.  A PTR/ANY question for `_services._dns-sd._udp.local.` answers one PTR per distinct advertised service type (RFC 6763 §9).

| Case | Response |
|---|---|
| Only unique records (A/SRV/TXT) asked | Multicast, **immediately** (RFC 6762 §6) |
| Shared records (PTR, meta-query) involved | Multicast after a random **20–120 ms**, aggregating further queries (RFC 6762 §6) |
| Every matching question has the QU bit | Unicast to the querier, port 5353 (querier at 0.0.0.0 → multicast instead) |
| Source port ≠ 5353 (legacy unicast, §6.7) | Unicast to the querier's port with its ID and question repeated, TTL capped at 10 s, no cache-flush bit (querier at 0.0.0.0 → ignored) |

> The requirements doc originally said 400–500 ms for all multicast responses.  In RFC 6762 §6 that delay applies only to queries with the TC bit set; unique answers go out immediately and shared answers after 20–120 ms.

**Additional records (RFC 6763 §12):** a PTR answer adds the instance's SRV and TXT; an SRV (answered or added) adds the A record of its target.  Additionals go in the last packet if they fit.

**Known-answer suppression (RFC 6762 §7.1):** a record is not sent if the query's Answer section already holds it (same name, type and data) with TTL ≥ half our TTL.  Meta-query answers are suppressed the same way.

**Size:** answers that do not fit are sent in further packets (REQ-MDNS-042); a single record too large for the TX buffer is dropped.

**Conflict while running (RFC 6762 §9):** a response with a record of the same name *and type* as one of our unique records but different data.  Other types under our name are not conflicts once we own it.

**Robustness:** every read is bounds-checked; malformed messages, pointer loops and absurd section counts are dropped without a reply.  Responses (QR=1) are never answered, and queries with a non-zero opcode are ignored.

---

## 8. DNS Name Encoding (`dns_wire`)

```
"pyro-dead01.local" → \x0b pyro-dead01 \x05 local \x00
```

```c
dns_writer_init(&w, buf, cap);
dns_write_header(&w, id, flags, qd, an, ns, ar);
dns_write_name(&w, "Pyro Unit 1._pyro._tcp.local");   /* compressed */
dns_write_u16 / dns_write_u32 / dns_write_bytes
dns_writer_mark / dns_writer_rollback                  /* back out a record that did not fit */

dns_name_equals(msg, len, off, "pyro-dead01.local");   /* case-insensitive, follows pointers */
dns_name_decode(msg, len, off, out, out_len);
dns_name_skip / dns_read_question / dns_read_rr / dns_name_wire_len
```

**Compression (RFC 1035 §4.1.4):** the writer remembers the offset of every label it writes (up to `DNS_COMPRESS_MAX`, default 16) and replaces the longest suffix that already appears in the message with a 2-byte pointer.  This covers owner names and the names inside PTR and SRV data, which RFC 6762 §18.14 requires mDNS implementations to decode.  In the demo's announcement the instance name is spelled out only once (unit-tested).

**Reading:** compressed names are compared and decoded without copying them into a buffer, following at most 32 pointer hops.

---

## 9. DNS-SD Record Composition

For `Pyro Unit 1._pyro._tcp.local.` on port 80:

```
_pyro._tcp.local.                 4500 IN PTR  Pyro Unit 1._pyro._tcp.local.
Pyro Unit 1._pyro._tcp.local.      120 IN SRV  0 0 80 pyro-dead01.local.
Pyro Unit 1._pyro._tcp.local.      120 IN TXT  "txtvers=1" "fw=1.2.3" "serial=DEAD01"
pyro-dead01.local.                 120 IN A    10.0.0.2
```

A PTR query returns the PTR in Answer and SRV + TXT + A in Additional — one round trip gives a browser the full picture (RFC 6763 §12.1).  A TXT record with no metadata is sent as a single zero byte (RFC 6763 §6.1).

---

## 10. Multicast and IGMP

1. **Join:** `mdns_start()` calls `igmp_join(net, 224.0.0.251)` — adds the group to `net_t`'s table and sends an IGMPv2 Membership Report (IP TTL 1, Router Alert option, RFC 2236 §2).  The report is repeated once when announcing starts.
2. **Leave:** `mdns_stop()` sends the goodbye first, then an IGMPv2 Leave Group to 224.0.0.2.
3. **Queries are not answered.**  224.0.0.251 is in the link-local control block (224.0.0.0/24), which IGMP-snooping switches must flood regardless of membership (RFC 4541 §2.1.2), so V1 only signals joins and leaves.
4. **Hardware MACs:** TAP and BPF deliver every frame.  A MAC with a multicast hash filter (e.g. ENC28J60) must be configured to pass 01:00:5E:00:00:FB.
5. **IP TTL 255** on every mDNS packet, including unicast responses (RFC 6762 §11), via `udp_send_inplace()`.
6. **Source address:** `net->ipv4_addr`.  Start the responder once the address is known (static, or on the DHCP BOUND event).

---

## 11. Integration with the Main Loop

```c
/* UDP handler for port 5353 — peek the payload, then hand it over */
static void mdns_udp(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, uint16_t off, uint16_t len) {
  static uint8_t buf[1500];
  int got = n->mac_driver->peek(n->mac_ctx, off, buf, len < sizeof(buf) ? len : sizeof(buf));
  if (got > 0)
    mdns_input(&mdns, src_ip, src_mac, src_port, buf, (uint16_t)got);
}

/* main loop */
mdns_tick(&mdns, elapsed_ms);   /* probes, announcements, delayed responses */

/* shutdown */
mdns_stop(&mdns);               /* goodbye + IGMP leave */
```

`mdns_tick()` takes elapsed milliseconds, like `tcp_tick()` and `dhcpv4_client_tick()`.  The conflict callback may rename (change the strings the record table points at) and call `mdns_start()` directly.  `demo/mdns_demo/main.c` is a complete example.

Random delays use an xorshift32 generator seeded from the MAC and IP, scaled rather than reduced with `%` so Cortex-M0 builds do not link a software divide.

---

## 12. Tests

### Unit tests

| Suite | Tests | Covers |
|---|---|---|
| `tests/unit/test_dns_wire.c` | 23 | Encoding, compression (suffix, whole name, prefix), limits, rollback, decode, pointer loops, truncation, question/RR parsing |
| `tests/unit/test_mcast.c` | 19 | Group table, multicast accept/drop (incl. aliased MACs), no ICMP errors / echo for multicast, `udp_send_inplace()` TTL, IGMP report/leave format |
| `tests/unit/test_mdns.c` | 44 | Table validation, probe timing and format, probe/announcement splitting, announcements, compression, conflicts (probing/running/callback restart/goodbyes), every answer type + additionals, meta-query, known-answer suppression, QU and legacy unicast, 0.0.0.0 queriers, malformed input, goodbye |

### Blackbox (`tests/blackbox/test_mdns_conform.py`, 18 tests)

Each test launches a fresh `mdns_demo` on tap0 so start-up and shutdown are observable:

| Test | Verifies |
|---|---|
| 001 hostname A query | A record with the SUT's IP, TTL 120, cache-flush |
| 002 PTR query | PTR answer + SRV, TXT, A in Additional |
| 003 SRV query | Port 80 on the host, A in Additional |
| 004 AA bit | QR=1, AA=1 on A/PTR/SRV/TXT responses |
| 005 ID zero | Multicast responses have ID 0 whatever the query ID |
| 006 IP TTL 255 | Responses sent with TTL 255 from port 5353 |
| 007 known-answer suppression | Fresh known answer suppresses, stale one does not |
| 008 goodbye | SIGTERM → every record with TTL 0 |
| 009 meta-query | `_services._dns-sd._udp.local` → `_pyro._tcp.local` |
| 010 probes | Three probes 150–450 ms apart, ANY/QU, records in Authority |
| 011 announcements | Two announcements 0.8–1.5 s apart after probing |
| 012 conflict | Rival A record during probing → renamed `pyro-dead01-2.local`, old name never announced |
| 013 IGMP join | IGMPv2 report for 224.0.0.251, TTL 1 |
| 014 legacy unicast | Reply to the querier's port with ID and question, TTL ≤ 10, no cache-flush |
| 015 QU | Unicast reply to the querier |
| 016 foreign names | No answer for `.example` or unknown `.local` names |
| 017 TXT | `txtvers=1`, `fw=1.2.3`, `serial=DEAD01` |
| 018 ANY | SRV + TXT for the instance |

### Interop (`tests/blackbox/mdns_interop.sh`)

Runs in CI after the Scapy suite, with `avahi-daemon` on tap0: `avahi-resolve` finds `pyro-dead01.local`, `avahi-browse` resolves the service (host, IP, port, TXT), the advertised TCP port answers, and the service is withdrawn when the SUT sends its goodbye.  On macOS, `tests/blackbox/mdns_interop_macos.sh` does the same with mDNSResponder (`dns-sd -B/-L/-G`) over a feth pair.

---

## 13. Decisions (were open questions)

1. **IGMP retransmit:** the report is sent on join and repeated once when announcing starts (~0.75 s later).  Queries are not answered (§10).
2. **Probe tiebreak (RFC 6762 §8.2):** deferred to V1.1.  Two hosts probing the same name at the same moment may both proceed; the first response each sees afterwards is detected as a conflict while running.
3. **Multiple interfaces:** V1 is single-interface — one `mdns_t` per `net_t`.
4. **Address change:** the A record can follow `net->ipv4_addr` (`.rdata.a = 0`); call `mdns_start()` after a DHCP renumbering to re-probe and re-announce.
