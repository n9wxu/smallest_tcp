# mDNS + DNS-SD Design

**Protocols:** RFC 6762 (mDNS) + RFC 6763 (DNS-SD)  
**Milestone:** 10  
**Status:** Planned  
**Last updated:** 2026-03-23

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
| mDNS querier (resolve `.local` names) | | ✅ |
| DNS-SD browser (discover services by type) | | ✅ |
| IPv6 / AAAA records | | ✅ |

---

## 3. Wire Format

mDNS reuses the DNS wire format (RFC 1035 §4) byte-for-byte.  The only structural difference is the multicast transport.  The existing DNS stub-resolver parser (`dns.c`, planned for Milestone 11) will be split into:

```
dns_wire.h / dns_wire.c   — shared parse/build helpers (name encoding, RR read/write)
dns.c                     — stub resolver (unicast, port 53)
mdns.c                    — mDNS responder/querier (multicast, port 5353)
```

This avoids duplicating label encoding, name-compression, and RR parsing logic.

---

## 4. Memory Model

Consistent with the zero-allocation principle — the application owns all memory:

```c
/* Application-provided hostname + record set */
static const mdns_record_t records[] = {
    { MDNS_A,   "pyro-dead01.local.",   .rdata.a   = { .ip = IP4(10,0,0,2) }, .ttl = 120 },
    { MDNS_PTR, "_pyro._tcp.local.",    .rdata.ptr = "Pyro Unit 1._pyro._tcp.local.", .ttl = 4500 },
    { MDNS_SRV, "Pyro Unit 1._pyro._tcp.local.",
                .rdata.srv = { .priority=0, .weight=0, .port=80, .target="pyro-dead01.local." }, .ttl=120 },
    { MDNS_TXT, "Pyro Unit 1._pyro._tcp.local.",
                .rdata.txt = (const char*[]){"txtvers=1","fw=1.2.3","serial=DEAD01",NULL}, .ttl=120 },
};

static mdns_t mdns;   /* 10-20 bytes of state */

void app_init(void) {
    mdns_init(&mdns, &net, records, ARRAY_LEN(records), on_conflict);
}
```

### State Machine (per `mdns_t` instance)

```
INIT ──(link up)──► PROBING ──(3 probes, no conflict)──► ANNOUNCING ──► RUNNING
                       │                                        │
                 (conflict)                            (link down)
                       ▼                                        ▼
                  CONFLICT ──(app renames)──► PROBING       INIT
```

State is stored in `mdns_t` (a small struct); no heap allocation.

---

## 5. Probing Algorithm

RFC 6762 §8.1:

```
t = random(0, 250 ms)    ; initial random delay
send probe 1 at t
send probe 2 at t + 250 ms
send probe 3 at t + 500 ms
if no conflict after probe 3 → enter ANNOUNCING
```

**Probe packet format:** DNS query (QR=0) with:
- Question section: `<name> ANY QCLASS=IN` with QU (unicast-response) bit set
- Authority section: the intended record(s), giving notice of our intent

Any answer received for the same name during probing triggers conflict handling.

---

## 6. Announcement Algorithm

RFC 6762 §8.3:

```
send announcement 1 immediately
send announcement 2 after 1 s
(optional) repeat at 2 s, 4 s, 8 s for robustness
```

Announcements are gratuitous multicast responses (QR=1, AA=1) containing all of the device's records in the Answer section.

---

## 7. Responding to Queries

```
receive mDNS query on 224.0.0.251:5353
    for each question:
        if question.name matches one of our records:
            schedule delayed response (400–500 ms random)
    at response time:
        build DNS response with all matching records
        include Additional records (SRV→A, PTR→SRV+TXT)
        send to 224.0.0.251:5353 (or unicast if QU bit and recently announced)
```

**Known-answer suppression:** If the query's Known-Answers section contains our record with TTL > half its original TTL, skip that record — the querier already has a fresh copy.

---

## 8. DNS Name Encoding

DNS names use length-prefixed labels terminated by a zero-length label:

```
"pyro-dead01.local." → \x0b pyro-dead01 \x05 local \x00
                           11 bytes        5 bytes
```

**Name compression** (RFC 1035 §4.1.4) replaces a suffix with a 2-byte pointer (top 2 bits = `11`, remaining 14 bits = offset from start of message).  This is critical for DNS-SD responses which repeat the same long names many times.

The `dns_wire` helper will provide:
```c
int dns_name_encode(uint8_t *buf, size_t buf_len, const char *name);
int dns_name_encode_compressed(uint8_t *buf, size_t buf_len, size_t msg_start,
                               const char *name, dns_compress_ctx_t *ctx);
int dns_name_decode(const uint8_t *msg, size_t msg_len, size_t offset,
                    char *out, size_t out_len, size_t *consumed);
```

---

## 9. DNS-SD Record Composition

For a device advertising `Pyro Unit 1._pyro._tcp.local.` on port 80:

```
; PTR — service enumeration
_pyro._tcp.local.  4500 IN PTR  "Pyro Unit 1._pyro._tcp.local."

; SRV — host + port
"Pyro Unit 1._pyro._tcp.local."  120 IN SRV  0 0 80 pyro-dead01.local.

; TXT — metadata
"Pyro Unit 1._pyro._tcp.local."  120 IN TXT  "txtvers=1" "fw=1.2.3" "serial=DEAD01"

; A — address (shared with hostname record)
pyro-dead01.local.  120 IN A  10.0.0.2
```

When a PTR query arrives, the response includes:
- **Answer:** PTR record
- **Additional:** SRV + TXT for the instance
- **Additional:** A record for the hostname named in the SRV

This "one query, full picture" pattern (RFC 6763 §12.1) lets browsers resolve a service in a single round trip.

---

## 10. Multicast UDP Integration

mDNS requires:

1. **IGMP join** for 224.0.0.251 — the IP layer (or MAC driver) must send an IGMP Membership Report when mDNS initialises.  The TAP driver on Linux and BPF driver on macOS receive multicast frames addressed to 01:00:5E:00:00:FB (the Ethernet multicast for 224.0.0.251).

2. **IP TTL = 255** on all outgoing mDNS packets (RFC 6762 §11.3).  This is enforced at the mDNS send path, not the generic UDP send path.

3. **IP src = device IP** (even for probes, where the device may not yet have a stable IP from DHCP).  If DHCP hasn't completed, probes use 0.0.0.0 as source.

### IGMP (Minimal)

A minimal IGMPv2 "Join" packet (type 0x16) is sufficient for most switches and routers to forward 224.0.0.251 traffic.  A full IGMPv3 implementation is not required for V1.

---

## 11. Integration with net_poll()

mDNS is driven by `net_poll()` / `net_tick()` like other protocol modules:

```c
void mdns_tick(mdns_t *m, net_t *net, uint32_t now_ms);
void mdns_input(mdns_t *m, net_t *net, const uint8_t *pkt, size_t len);
```

`mdns_tick` handles:
- Probe timer (250 ms intervals)
- Announcement timer (1 s after last probe)
- Response delay timer (400–500 ms from query)
- Goodbye generation on state change

`mdns_input` is registered as the UDP handler for port 5353.

---

## 12. Test Strategy

### Unit tests (`tests/unit/test_mdns.c`)

- Probe packet format (QR=0, AA=0, question + authority)
- Announcement packet format (QR=1, AA=1, all records in Answer)
- Query matching (name + type)
- Known-answer suppression logic
- Goodbye packet (TTL=0)
- DNS name encoding + compression round-trip
- DNS-SD PTR/SRV/TXT record composition
- Conflict state machine transitions

### Blackbox conformance tests (`tests/blackbox/test_mdns_conform.py`)

Using Scapy to send mDNS queries and inspect responses on the TAP interface:

| Test | What it verifies |
|---|---|
| `test_mdns_001_hostname_a_query` | `pyro-dead01.local. A` → A record with correct IP |
| `test_mdns_002_ptr_query` | `_pyro._tcp.local. PTR` → PTR answer + SRV+TXT+A additional |
| `test_mdns_003_srv_query` | SRV query for instance → SRV + A in response |
| `test_mdns_004_aa_bit_set` | All responses have AA=1 |
| `test_mdns_005_id_zero` | All multicast responses have ID=0 |
| `test_mdns_006_ttl_255` | IP TTL = 255 on all outgoing mDNS packets |
| `test_mdns_007_known_answer_suppression` | Response omits record present in query's Known-Answers |
| `test_mdns_008_goodbye_ttl_zero` | After `mdns_stop()`, device sends TTL=0 Goodbye packets |
| `test_mdns_009_meta_query` | `_services._dns-sd._udp.local.` → returns `_pyro._tcp.local.` |

### Integration / interop

- `dns-sd -B _pyro._tcp local` (macOS) discovers the demo
- `avahi-browse -r _pyro._tcp` (Linux) discovers the demo

---

## 13. File Layout

```
include/
  mdns.h              — public API (mdns_t, mdns_record_t, mdns_init, mdns_tick, mdns_stop)
  dns_wire.h          — shared DNS wire-format helpers (name encode/decode, RR read/write)
src/
  mdns.c              — mDNS responder state machine, probing, announcing, responding
  dns_wire.c          — DNS name encoding, label compression, RR serialise/parse
  igmp.c              — minimal IGMPv2 join (new, single-purpose)
demo/
  mdns_demo/
    main.c            — announce "pyro-dead01.local." + "_pyro._tcp" service, echo on port 80
tests/
  unit/test_mdns.c
  blackbox/test_mdns_conform.py
```

---

## 14. Open Questions / Decisions Deferred to Implementation

1. **IGMP retransmit:** RFC 2236 §3 requires sending the Join twice (initial + 1 repeat).  How many repeats for minimal robustness?
2. **Probe conflict tiebreak:** RFC 6762 §8.2 defines a lexicographic tiebreak for simultaneous probes.  Required for production; can be deferred to V1.1.
3. **Multiple interfaces:** V1 is single-interface (one `net_t`).  Multi-interface requires per-interface mDNS state.
4. **Record update at runtime:** If the device's IP changes (DHCP rebind), should mDNS automatically re-probe and re-announce?  Yes — this should be driven by a `mdns_update_address()` call from the DHCP client callback.
