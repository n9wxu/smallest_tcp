# mDNS + DNS-SD Design

**Protocols:** RFC 6762 (mDNS) + RFC 6763 (DNS-SD)  
**Milestone:** 10 (IPv6: Milestone 12)  
**Status:** Implemented (responder, dual stack)  
**Files:** `include/mdns.h`, `src/mdns.c`, `include/dns_wire.h`, `src/dns_wire.c`, `include/igmp.h`, `src/igmp.c`  
**Last updated:** 2026-10-01 (the RFC 6762 / 6763 MUSTs the requirements left out: REQ-MDNS-044..079, REQ-DNSSD-033..038)

---

## 1. Motivation

pyro_fw devices must be reachable on any local network without static IP configuration, a DNS server, or DHCP-provided hostname options.  mDNS provides zero-configuration hostname resolution (`<name>.local`); DNS-SD provides zero-configuration service discovery (`_pyro._tcp.local.`).  Together they allow a control application to find every pyro_fw device on the LAN by type, read its metadata (firmware version, serial number, capabilities), and connect — with no user-supplied IP address.

---

## 2. Scope

The module is a **responder**: it probes for its unique names, announces its records, answers queries on 224.0.0.251:5353 (and [ff02::fb]:5353 in dual-stack builds), and withdraws the records with goodbye packets on shutdown.

| Feature | Status |
|---|---|
| mDNS responder (answer `.local` queries) | ✅ |
| Probing + conflict detection | ✅ |
| Gratuitous announcements | ✅ |
| Goodbye packets on shutdown, and for records withdrawn while running (`mdns_withdraw()`) | ✅ |
| DNS-SD advertiser (PTR/SRV/TXT) | ✅ |
| Service-type meta-query (`_services._dns-sd._udp.local.`) | ✅ |
| Known-answer suppression, QU and legacy unicast responses | ✅ |
| NSEC negative answers for types a name lacks (RFC 6762 §6.1) | ✅ |
| IPv6: ff02::fb, AAAA records, both families (§11) | ✅ (Milestone 12) |
| Simultaneous-probe tiebreak (RFC 6762 §8.2) | ✅ |
| Multi-packet known-answer lists (TC bit, §7.2) | ✅ (answering; never sent) |
| mDNS querier (resolve `.local` names), DNS-SD browser | — |

Also not implemented, as simplifications of the responder:

- **Duplicate-answer suppression** (§7.4): a delayed answer is sent even if another responder multicasts the same record meanwhile.
- **QU answers are always unicast**; the §5.4 rule to multicast instead when the record has not been multicast within a quarter of its TTL is not applied.
- **QU answers to off-subnet queriers** (§11): a QU query from a source off our subnet is answered by unicast, where §11 recommends multicast.  Responses, which §11 requires to come from the local link, are checked (§7.1).

---

## 3. Module Layout

mDNS reuses the DNS wire format (RFC 1035 §4) byte-for-byte, so the wire code is a separate module the planned DNS stub resolver (`dns.c`) will share:

```
dns_wire.h / dns_wire.c   — names (with compression), header/question/RR read + write
igmp.h / igmp.c           — IGMPv2 host: join/leave, queries answered
mdns.h / mdns.c           — responder state machine, answering, DNS-SD composition
```

All three build into the optional `smallest_tcp_mdns` library (`smallest_tcp::mdns`).  They rely on core-stack features:

- **Multicast receive:** `net_t` holds a fixed table of joined IPv4 groups (`NET_MAX_MCAST_GROUPS`, default 1; `mdns.c` refuses to compile with 0).  `eth_input()` accepts the 01:00:5E MAC of a joined group and `ipv4_input()` the group address; unjoined groups and aliased MACs are dropped.  No ICMP errors or echo replies are ever sent for multicast destinations (RFC 1122 §3.2.2).  IPv6 groups are joined with `ipv6_mcast_join()` ([ipv6.md](ipv6.md#9-mld-and-multicast-groups-stage-6a)); a dual-stack `mdns.c` likewise refuses to compile with `NET_MAX_MCAST6_GROUPS` 0.
- **Per-packet TTL + in-place send:** `udp_send_inplace()` / `udp6_send_inplace()` send a payload the caller already wrote at `UDP_PAYLOAD_OFFSET` / `UDP6_PAYLOAD_OFFSET` in `net->tx.buf`, with an explicit TTL or Hop Limit (255 for mDNS, RFC 6762 §11).
- **Randomness:** the probe and response delays come from `net_random_below()`, the stack's one generator (§12).

---

## 4. Memory Model

The application owns the record table and an `mdns_t` (96 bytes on 32-bit targets, IPv4-only or dual stack); the responder has no static state and never allocates.  Responses are built directly in `net->tx.buf`; queries are read in place from `net->rx.buf`.

```c
static const char *const txt[] = {"txtvers=1", "fw=1.2.3", "serial=DEAD01", NULL};

static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A,   .ttl = MDNS_TTL_HOST,  .name = "pyro-dead01.local",
     .rdata.a = 0},                                     /* 0 = net->ipv4_addr */
    {.type = DNS_TYPE_PTR, .ttl = MDNS_TTL_OTHER, .name = "_pyro._tcp.local",
     .rdata.ptr = "Pyro Unit 1._pyro._tcp.local"},
    {.type = DNS_TYPE_SRV, .ttl = MDNS_TTL_HOST,  .name = "Pyro Unit 1._pyro._tcp.local",
     .rdata.srv = {0, 0, 80, "pyro-dead01.local"}},
    {.type = DNS_TYPE_TXT, .ttl = MDNS_TTL_OTHER, .name = "Pyro Unit 1._pyro._tcp.local",
     .rdata.txt = txt},
};

static mdns_t mdns;

mdns_init(&mdns, &net, records, 4, on_conflict, NULL);  /* validates the table */
mdns_start(&mdns);                                       /* once the IPv4 address is known */
```

- PTR records are **shared** (many hosts advertise the same service type); A, AAAA, SRV and TXT records are **unique** and are probed for (`is_shared()`).
- An A record with `.rdata.a = 0` always answers with the current `net->ipv4_addr`, so a DHCP-assigned address needs no table update.  Address records carry only addresses valid on the interface (RFC 6762 §6.2, `rec_addr()`, `aaaa_addrs()`): a fixed `.rdata.a` only while it is `net->ipv4_addr`, a fixed `.rdata.aaaa` only while it is one of the interface's usable addresses (`ipv6_is_ours()`).  An address record with no valid address stands for no RR (`rr_count()`): it is left out of announcements, probes and answers, out of the NSEC type bitmap, and a query for its type gets an NSEC instead (§6.1) — before, an A record answered 0.0.0.0 while the interface had no address, and an AAAA query with no usable address got nothing at all.  In IPv6 builds, `{.type = DNS_TYPE_AAAA, .ttl = MDNS_TTL_HOST, .name = "pyro-dead01.local", .rdata.aaaa = NULL}` does the same for every usable IPv6 address (§11); an IPv4-only build rejects AAAA records, and an IPv6-only build A records.
- `mdns_init()` rejects (`NET_ERR_INVALID_PARAM`, `record_ok()`) invalid names (empty label, label > 63 bytes, name > 255 bytes before its terminating zero — RFC 6762 App. C counts 255 without it, so a 256-byte name with the zero is valid); names that are not well-formed UTF-8 (RFC 6762 §16: overlong forms, surrogates, code points above U+10FFFF and stray continuation bytes are refused), that hold an ASCII control character (RFC 6763 §4.1.1) or that start a label with U+FEFF, a byte order mark (elsewhere it is a literal zero-width no-break space); an SRV target that is the root label (RFC 6763 §8); TXT strings > 255 bytes, without a key of at least one printable US-ASCII character before the first `=`, or empty among others (RFC 6763 §6.4 — an empty string alone is the empty TXT record); types other than A, PTR, SRV, TXT (and AAAA in IPv6 builds); and more than `MDNS_MAX_RECORDS` (32) records.  Whether names are precomposed (Unicode NFC) is not checked: that would take Unicode tables.
- It also rejects, with `NET_ERR_BUF_TOO_SMALL`, a record that no message could carry in the TX frame buffer after the largest family's headers (REQ-DNSSD-029, `fits_alone()`): a response with the record alone and the question repeated, as legacy replies have it; for a unique name its probe (every record of the name) and its NSEC; for a service type its meta-query PTR.  Names are counted uncompressed, and an AAAA record standing for the interface's addresses as `NET_IPV6_ADDRS` of them, so the bound holds whatever the packet.  Such a record used to be dropped silently from every announcement.
- Names are dotted strings; labels may contain spaces (`Pyro Unit 1`) but not dots: every `.` separates labels, so an instance name with a dot, which RFC 6763 §4.1.1 allows, cannot be given (REQ-DNSSD-034, a recorded deviation).
- **Record sets are 32-bit masks**, bit *i* = `records[i]`: what a query wants, what a delayed response owes, which names get NSEC.  A unique *name* is represented by its first unique record (`name_rep()`); probes ask one question per representative, and NSEC answers are keyed by it.

### State Machine

```
STOPPED ─mdns_start()─► PROBING ─3 probes, no conflict─► ANNOUNCING ─2nd announcement─► RUNNING
                         │  ▲                              │  ▲                            │
                         │  │                              │  └──── mdns_readdress6() ─────┤
                         │  └── conflict on a name we hold: probe for it again ────────────┤
                         │                                                                 │
                         └── conflicting response to a probe ──► CONFLICT                  │

CONFLICT ─on_conflict(): the app renames and calls mdns_start()─► PROBING
any state ─mdns_stop()─► goodbye (for what was sent) + IGMP/MLD leave ─► STOPPED
```

`mdns_t.claim` holds the records being probed for and then announced: every record in use after `mdns_start()`, or only the records of a name probed for again after a conflict while running (REQ-MDNS-057, RFC 6762 §9).  While PROBING the responder does not answer for the claimed records (`answerable()`: it must not answer for names it has not yet claimed) but answers for the others as usual, and the announcements that follow carry the claimed records only.  In STOPPED and CONFLICT it is silent, and `mdns_tick()` does nothing either.  Calling `mdns_start()` again re-probes and re-announces everything — use it after a link-up or an IPv4 address change (REQ-MDNS-024, 059).

`mdns_t.announced` holds the records that have been sent (announced, or answered other than to a legacy query) and not said goodbye to since: a goodbye goes only to those, whatever the state (`goodbye()`).

---

## 5. Probing (RFC 6762 §8.1)

```
t0 = random 0–250 ms after mdns_start()
probe 1 at t0, probe 2 at t0 + 250 ms, probe 3 at t0 + 500 ms
no conflict by t0 + 750 ms → ANNOUNCING, first announcement at once
```

A probe is a query (QR=0, ID=0) with one `ANY` question per distinct unique name, the unicast-response (QU) bit set, and the unique records in the Authority section (no cache-flush bit).  `send_probes()` sends one set per address family (§11).  If the TX buffer cannot hold every name, `send_probes_to()` packs names greedily into several probe packets, retrying `build_probe()` with one name more each time; a name that does not fit even alone is not probed.

**Conflict while probing** (`check_conflicts()`): any record in a response — Answer, Authority or Additional section — under one of our unique names, of any type, that is not identical to one of our records.  Goodbye records (TTL 0) and classes other than IN are ignored, and so is a response that arrives before the first probe is sent (§8.1: it may be a stale packet, the host's own even).  It is the probing that fails: the responder enters CONFLICT and calls the conflict callback with the index of the name's first unique record (§8.1: the probing host MUST defer to the existing one).

**Fifteen conflicts in ten seconds** (§8.1, REQ-MDNS-054): from then on every probe attempt waits at least five seconds, so that a host that keeps losing — or is made to — does not flood the link.  `mdns_t.conflicts` counts conflicts (a probe answered, a conflict while running) and is forgotten once `quiet_ms` — ten seconds, restarted by each conflict — runs out; fifteen within any ten seconds are therefore always counted (more is counted when they keep coming, which only slows probing further).  While the count is 15 or more, `probe_delay()` gives `MDNS_SLOW_PROBE_MS` (5 s) instead of 0-250 ms before the first probe of `mdns_start()`, of probing again after a conflict, and after a lost tiebreak.  The count lives in `mdns_t` and survives `mdns_start()`; only `mdns_init()` clears it.

**Simultaneous probes** (`probe_tiebreak()`, §8.2): two hosts probing for the same name at once would hear no answer and both take it.  So a query that arrives while PROBING, with a question for a name we are probing for and records of that name in its Authority section, is another host's probe: its proposed records are compared with ours, and the lexicographically later set wins.  Ours are those our probe carries — `build_probe()` writes them into `net->tx.buf`, free while a message is read — so both sides are records in a DNS message, compared alike.  Records are ordered by class (without the cache-flush bit), type, then rdata byte by byte with names uncompressed (`dns_rdata_compare()`: a compression pointer says where a name is, not what it is); each set is sorted and the two compared pairwise until a difference, a set that runs out first losing (§8.2.1).  `compare_sets()` does this without sorting or storage: it walks the values from the smallest up, each step finding the next larger value in both sets and counting each set's copies of it, until the counts differ — then the set with fewer copies wins if a later record follows them, else loses.  If ours are earlier the responder defers: it waits `MDNS_TIEBREAK_WAIT_MS` (1 s) and probes again from the first probe — a real winner will by then answer, a stale echo of our own probe will not.  If ours are later, or the sets are the same (§8.2.1: no conflict), the other probe is ignored.

---

## 6. Announcing (RFC 6762 §8.3)

Two gratuitous responses (QR=1, AA=1, ID=0), one on entering ANNOUNCING and one 1 s later, each carrying every record (`announce()`).  Unique records carry the cache-flush bit (top bit of the class, RFC 6762 §10.2); shared PTR records do not.  They go to the groups in `announce_families` — both families after `mdns_start()`, possibly only IPv6 after `mdns_readdress6()` (§11).  The IGMP Membership Report is repeated when announcing starts (RFC 2236 §3 recommends one repeat).

---

## 7. Responding to Queries

### 7.1 From datagram to answer

```
mdns_input() / mdns_input6()  →  input()
    OPCODE or RCODE not 0          → ignored (§18.3, §18.11)
    QR = 1, from port 5353 and the local link; unicast only while PROBING → check_conflicts()
    QR = 0, not PROBING            → query_input()
        each question of class IN or ANY → match_question()        fills wanted_t
        suppress_known_answers()          (the query's Answer section)
        answer()                          legacy unicast | QU unicast | multicast now | owe_response()
```

`wanted_t` collects, across the questions: `answers` (records asked for), `service_types` (PTR records to list for the meta-query), `nsec` (our names asked for a type they lack), `all_unicast` (every question we answer has the QU bit) and the first answered question's name and type, which a legacy reply repeats.

**`match_question()`**: records with the question's name (case-insensitive) and type, or any type for `ANY`, are answers.  A PTR or `ANY` question for `_services._dns-sd._udp.local.` selects every service-type PTR (owner name beginning with `_`; RFC 6763 §9).  A question that matches nothing, is not `ANY`, and names one of our unique names is owed an NSEC.  A question that matches nothing at all does not affect `all_unicast`.

**`suppress_known_answers()`** (RFC 6762 §7.1): an answer is dropped if the query's Answer section already holds it (same name, type and data) with a TTL of at least half ours; meta-query answers likewise, against PTR records for `_services._dns-sd._udp.local.`.  NSEC is not suppressed.  A unique RRSet — several table entries of one name and type, two SRV records say — is dropped only if every member is known (`rrsets()`): sent in part, with the cache-flush bit, it would delete the rest from the querier's cache (§10.2).

**`answer()`** picks one of four ways:

| Case | Response |
|---|---|
| Source port ≠ 5353 (legacy unicast, §6.7) | Unicast to the querier's address, MAC and port, at once, with its ID and the first answered question; TTLs capped at 10 s, no cache-flush bit, the SRV target not compressed (§18.14).  A querier at 0.0.0.0 or `::` is ignored |
| Every answered question has the QU bit and the querier has an address | Unicast to the querier, port 5353, at once |
| The query has the TC bit set: more known answers follow (§7.2) | Owed: multicast after a random **400–500 ms**, and what is owed already waits with it |
| Shared records involved (PTR or meta-query answers) | Owed: multicast after a random **20–120 ms**, aggregated (§7.2) |
| Otherwise — unique records and NSEC only | Multicast **at once** (§6), to the group of the family the query came on — but not a record multicast within the last second (§7.3); a probe's such answer goes 250 ms later |

A QU query from a querier still at 0.0.0.0 falls through to the multicast rows.

**Truncated queries** (§7.2).  A querier whose known answers do not fit one packet sets TC and sends the rest in packets without questions.  A query from port 5353 with TC set is owed rather than answered, whatever it asks, and the owed response waits 400–500 ms.  A query packet without questions that arrives while a response is owed goes through `suppress_known_answers()` against what is owed (`more_known_answers()`), so an answer the querier listed is not sent — if it comes from the querier, and only for answers no other host waits for (§7.2, REQ-MDNS-077).  `mdns_pending_t` keeps the querier — the last host to send a truncated query, else the first to ask; its IPv4 address, or a keyed hash of its IPv6 address (`host_of()`) — and `others`, the answers and service types another host asked for too, which known answers cannot strike.  When a second host sends a truncated query, it becomes the querier and everything owed so far goes into `others`.  The responder never sets TC itself: its answers are split into packets instead (REQ-MDNS-042).

> The requirements doc originally said 400–500 ms for all multicast responses.  In RFC 6762 §6 that delay applies only to queries with the TC bit set; unique answers go out immediately and shared answers after 20–120 ms.

### 7.2 Delayed responses (`mdns_pending_t`)

```c
typedef struct {
  uint32_t timer_ms;      /* until it is sent; 0 = nothing owed */
  uint32_t answers;       /* record sets owed (bit i = records[i]) */
  uint32_t service_types; /* answers to the meta-query */
  uint32_t nsec;          /* names owed a negative answer */
  uint32_t querier;       /* whose known answers count (§7.2) */
  uint32_t others;        /* answers other hosts wait for too */
  uint32_t defend;        /* answers to a probe, owed whatever the rate limit */
  uint32_t repair;        /* records another host sent with too low a TTL (§6.6) */
  uint8_t families;       /* MDNS_FAMILY_V4 | MDNS_FAMILY_V6: where the queries came from */
} mdns_pending_t;
```

`mdns_t` holds one, `pending`.  `owe_response()` ORs a query's wants and its family into it and starts the timer — 20 ms plus `net_random_below()` of 101 — only if none is running, so later queries join the response instead of postponing it.  When `mdns_tick()` runs the timer out, `send_pending()` takes a copy, clears `pending`, and multicasts the owed records to every family that asked.  `mdns_start()`, a conflict and `mdns_stop()` clear it.  Known answers in a later query do not remove what an earlier query is owed.

### 7.3 The multicast rate limit (RFC 6762 §6)

A responder MUST NOT multicast a record until at least a second after it last multicast it — except to answer a probe, which must be quick and needs only 250 ms (REQ-MDNS-063).  A timestamp per record would take 64 bytes or more; the responder keeps two bit sets instead.  `recent[0]` holds the records multicast in the current second, `recent[1]` those of the second before; `age_recent()`, from `mdns_tick()`, moves `recent[0]` to `recent[1]` each second (`second_ms`) and drops the old `recent[1]`.  A record is *held* while it is in either: from its multicast until the end of the next second — between one and two seconds, never less than one.  `recent_synth[]` does the same for the records the responder makes up: an NSEC (the bit of its name) and a meta-query PTR (the bit of the service type's PTR) — so that an NSEC for AAAA does not hold the A record.

`send_to_groups()` sends every multicast response, in one of three ways:

| How | Used by | Held records |
|---|---|---|
| `SEND_LIMITED` | Answers, at once or owed | Left out — a unique RRSet whole (§10.2) — answers, additionals, NSEC and meta-query PTRs alike.  A querier that missed the earlier multicast asks again |
| `SEND_FORCED` | Announcements, probe defences | Sent: their timing keeps the rule (below) |
| `SEND_GOODBYE` | `mdns_withdraw()`, `mdns_stop()` | Sent at once, without marking: the records are going, and `mdns_stop()` cannot wait.  This is the one case where a record can be multicast less than a second after the last time |

What it sends goes into `recent[0]` (goodbyes excepted).

**Announcements** wait until none of their records is held (`timer_fired()` puts the announcement off to the end of the second, as often as needed) — after `mdns_readdress6()`, say, or a conflict while running.  Then `announce()` starts the second over: every mark goes into `recent[1]`, to be dropped exactly a second later — when the next announcement, `MDNS_ANNOUNCE_WAIT_MS` (1 s) later, finds its records free.  Every mark so dropped was made at most then, so none is dropped less than a second after its multicast.

**Probe defences.**  A query whose Authority section holds a record of a name it asks about is a probe (`is_probe()`).  A held answer to it is not left out but owed to `pending.defend` 250 ms from now (`owe_defence()`), and marked held at once so that nothing else multicasts it meanwhile: it goes out at least 250 ms after the record's last multicast, and well within the 750 ms the probing host waits.  Probes asking for unicast (QU, as RFC 6762 recommends) are answered by unicast, and unicast is not limited.

**Correcting a low TTL** (§6.6, REQ-MDNS-075).  When another host multicasts one of our records — same name, type and rdata — with less than half our TTL, a goodbye included, queriers would drop the record too early: the responder MUST multicast it itself.  `check_conflicts()` notes the record's RRSet in `pending.repair` (`owe_repair()`, 20-120 ms); `send_pending()` sends it with the answers if it is not held, else keeps it owed until the end of the second.  Any multicast of the record in between does the job and clears it.

### 7.4 Building responses

**Fan-out.**  `send_to_groups(m, families, answers, service_types, nsec, how)` sends one response per family in the set, each to that family's group (`family_group()`: 224.0.0.251:5353 or [ff02::fb]:5353), after the rate limit of §7.3.  Announcements, goodbyes, answers at once and delayed responses all go through it; it replaced three copies of the IPv4/IPv6 fan-out code.  Unicast replies are sent by `send_response()` directly to the querier.  A response sent to both families counts as one multicast on the interface.

**`send_response()`** writes, in order: the answers (table order), the NSEC records, one PTR per distinct service type (`_services._dns-sd._udp.local.` → the type, TTL 4500), and last the additionals.  The header has QR and AA set and ID 0, except in legacy replies, which echo the ID and carry the question.  `rr_ttl()` makes goodbye TTLs 0 and caps legacy TTLs; `rr_class()` sets the cache-flush bit on unique records except in legacy replies.  A packet with no answer is not sent.

**Size** (REQ-MDNS-042).  `add_answer()` writes an answer; when it does not fit, the packet so far is sent and a new one begun with the same header (and, for legacy, the same question).  A single record too large for an empty packet cannot occur: `mdns_init()` refused it.  Every record is written with a writer mark and rolled back on overflow (`write_one()`, `write_rr()`, `write_nsec()`), so a record never goes out half-written.  Additionals go in the last packet only, and only those that fit — a unique RRSet whole or not at all (§10.2: a response with some members of a unique RRSet carries all of them).

**Additional records** (`additionals_for()`, RFC 6763 §12): a PTR answer adds the instance's SRV and TXT; an SRV (answered or added) adds the A and AAAA records of its target; in IPv6 builds an A answer adds the name's AAAA records and vice versa (RFC 6762 §6.2).  Records already in the answers are not repeated.

**Negative answers** (`write_nsec()`, RFC 6762 §6.1): a question for one of our unique names asking for a type the name does not have (e.g. AAAA for the host in an IPv4-only build, or while the interface has no usable IPv6 address) is answered with an NSEC record in the restricted form: Next Domain Name = the name itself, one bitmap block (0) of 1-32 bytes listing the types it does have (an address type only while it has a valid address), never the NSEC bit.  Without it, dual-stack resolvers (curl, browsers) waited 5 s for an AAAA answer before using the A record; with it the first lookup took 0.4 s and later ones about 8 ms.  No NSEC is sent for foreign or shared (PTR) names, for ANY, or while probing.

**Conflict while running** (RFC 6762 §9): a response with a record of the same name *and type* as one of our unique records but different data.  Other types under our name are not conflicts once we own it.  §9 says the host MUST reset the conflicted record to probing and go through probing and announcing again; only if the probing fails MUST it cease using the name.  So `probe_again()` adds the name's unique records to `claim` and goes back to PROBING (random 0-250 ms, then three probes), the other records answered meanwhile; the callback is called only if a probe meets a conflicting response — with the index of the name's first unique record.  Unanswered, the records are announced again and the name kept.  Before, the callback was called at the first conflicting response, and a single stale or spoofed packet cost the name.

**Robustness:** every read is bounds-checked; malformed messages, pointer loops and absurd section counts end processing without a reply.  Responses (QR=1) are never answered.  Messages with a non-zero OPCODE or RCODE are ignored, queries and responses alike (RFC 6762 §18.3, §18.11).

**Which responses count** (`response_acceptable()`): only those from UDP port 5353 (§6) and from the local link (§11) — sent to 224.0.0.251 or ff02::fb, whatever the source, or else by unicast from a source on our IPv4 subnet, link-local, or on the /64 of one of our IPv6 addresses (`ipv6_on_link()`).  A unicast response counts only as the answer to a recent query that asked for unicast responses (§6, REQ-MDNS-080), and the responder asks only with its probes' QU questions: unicast responses are taken while PROBING, once the first probe is out, and ignored in every other state.  The UDP handlers do not pass the destination address, so `sent_to_group()` reads it from the frame in `net->rx.buf`, where the payload pointer they pass points (fixed offsets: the Ethernet header is always 14 bytes, and the destination field sits before any IPv4 option or IPv6 extension header).  A message handed to `mdns_input()` from anywhere else counts as unicast.

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

dns_name_equals(msg, len, off, "pyro-dead01.local");   /* wire vs dotted, case-insensitive, follows pointers */
dns_dotted_equal("Pyro-Dead01.local.", "pyro-dead01.local");  /* dotted vs dotted */
dns_name_decode(msg, len, off, out, out_len);
dns_name_skip / dns_read_question / dns_read_rr / dns_name_wire_len
dns_rdata_compare(ma, la, &a, mb, lb, &b);             /* RFC 6762 §8.2 order, names uncompressed */
```

**Compression (RFC 1035 §4.1.4):** the writer remembers the offset of every label it writes (up to `DNS_COMPRESS_MAX`, default 16) and replaces the longest suffix that already appears in the message with a 2-byte pointer.  This covers owner names and the names inside PTR and SRV data, which RFC 6762 §18.14 requires mDNS implementations to decode — except the SRV target in a legacy unicast reply, which §18.14 forbids compressing: `dns_write_name_flat()` writes it in full (later names may still point into it).  In the demo's announcement the instance name is spelled out only once (unit-tested).

**Reading:** compressed names are compared and decoded without copying them into a buffer, following at most 32 pointer hops.

**Comparing names.**  `dns_dotted_equal()` compares two dotted names label by label, case-insensitively, with the trailing dot optional; mDNS uses it to relate its own records to each other (name representatives, the NSEC type bitmap, additionals, service-type deduplication).  It replaced a private `names_equal()` in `mdns.c`; both comparisons now use `net_tolower()` from `net_text.h` instead of their own copies (there were three, with `http.c`'s).

---

## 9. DNS-SD Record Composition

For `Pyro Unit 1._pyro._tcp.local.` on port 80:

```
_pyro._tcp.local.                 4500 IN PTR  Pyro Unit 1._pyro._tcp.local.
Pyro Unit 1._pyro._tcp.local.      120 IN SRV  0 0 80 pyro-dead01.local.
Pyro Unit 1._pyro._tcp.local.     4500 IN TXT  "txtvers=1" "fw=1.2.3" "serial=DEAD01"
pyro-dead01.local.                 120 IN A    10.0.0.2
```

TTLs follow RFC 6762 §10 (REQ-DNSSD-017): 120 s for records with a host name as their name or in their rdata (A, AAAA, SRV), 75 minutes for the others (PTR, TXT) — `MDNS_TTL_HOST` and `MDNS_TTL_OTHER`.  The table gives each record's TTL; the demo used to give TXT 120 s.

A PTR query returns the PTR in Answer and SRV + TXT + A (and AAAA) in Additional — one round trip gives a browser the full picture (RFC 6763 §12.1).  A TXT record with no metadata is sent as a single zero byte (RFC 6763 §6.1).

**Withdrawing a service** while the host stays: `mdns_withdraw(&mdns, mask)` with the bits of its PTR, SRV and TXT (REQ-DNSSD-018).  If they were sent (`announced`), one goodbye carries them with TTL 0 — and the meta-query PTR of the service type if no other record in use still offers it — to both families, without additionals.  `mdns_t.live` then lacks their bits, and every walk over the table skips them: answers, NSEC (a withdrawn name is no longer ours), additionals, announcements, probes, conflict checks and the pending response.  They stay out through `mdns_start()`; a new `mdns_init()` brings the table back whole, and `mdns_stop()` says goodbye to what is still in use.

**Renaming an instance after a conflict** changes its PTR record's rdata (`_pyro._tcp.local PTR Pyro Unit 1 (2)._pyro._tcp.local`), and for a shared record RFC 6762 §8.4 requires a goodbye for the old rdata before the new is announced (REQ-MDNS-060): caches would otherwise list the old instance, which another host now owns, for 75 minutes.  The responder cannot know what the application will rename, so the application says it: in the CONFLICT state — from the conflict callback, before renaming — `mdns_withdraw()` sends the goodbye for the shared records among its bits that were sent, with their current rdata, and leaves them in use, so that `mdns_start()` announces them with the new rdata.  (A withdrawal in the CONFLICT state is only that goodbye: withdrawing for good there would leave the application only `mdns_init()` to bring the PTR back, which resets the whole responder — the conflict count of §5 included.)

---

## 10. Multicast, IGMP and MLD

1. **Join:** `mdns_start()` calls `igmp_join(net, 224.0.0.251)` — adds the group to `net_t`'s table and sends an IGMPv2 Membership Report (IP TTL 1, Router Alert option, RFC 2236 §2) every time it runs.  In IPv6 builds it also calls `ipv6_mcast_join(net, ff02::fb)`; MLD reports a new membership and repeats it once after 1 s.  A join before `ipv6_start()` is kept and reported with the first MLD report.
2. **Repeat:** the IGMP report is repeated once when announcing starts (~0.75 s after the join).
3. **Leave:** `mdns_stop()` sends the goodbye first — every record with TTL 0, and each service type's PTR under `_services._dns-sd._udp.local.`, which a querier may have cached from a meta-query answer — then an IGMPv2 Leave Group to 224.0.0.2 and the MLD leave for ff02::fb.
4. **Queries are answered.**  Once `igmp_join()` has run, IGMP answers General and Group-Specific queries for 224.0.0.251 (and any other joined group) after a random delay within the query's Max Response Time, stays quiet if another host's report is heard first, and speaks IGMPv1 for 400 s after an IGMPv1 query ([igmp.md](../requirements/igmp.md), `igmp.h`).  224.0.0.251 is in the link-local control block (224.0.0.0/24), which IGMP-snooping switches flood regardless of membership (RFC 4541 §2.1.2), so the answers matter mostly to multicast routers.  MLD queries are answered by `mld.c` for every joined group, ff02::fb included.
5. **Hardware MACs:** TAP and BPF deliver every frame.  A MAC with a multicast hash filter (e.g. ENC28J60) must be configured to pass 01:00:5E:00:00:FB, and 33:33:00:00:00:FB for IPv6.
6. **TTL / Hop Limit 255** on every mDNS packet, including unicast responses (RFC 6762 §11).
7. **Source address:** `net->ipv4_addr` over IPv4; over IPv6, `ipv6_src_for()` — the link-local address, the group being link-scope.  Start the responder once the IPv4 address is known (static, or on the DHCP BOUND event).
8. **Configuration:** dual-stack mDNS needs `NET_MAX_MCAST6_GROUPS` ≥ 1 (the default), as it needs `NET_MAX_MCAST_GROUPS` ≥ 1 for IPv4.  Both are checked at compile time: without a slot `ipv6_mcast_join()` would fail and nothing would arrive on ff02::fb, so `mdns.c` stops the build with `#error` rather than produce a responder that hears nothing.  Two CTest cases (`mdns_needs_ipv4_group_slot`, `mdns_needs_ipv6_group_slot` in `tests/CMakeLists.txt`) compile `mdns.c` with each count at 0 and pass when the compiler reports the error.

---

## 11. Dual Stack (IPv6)

With `NET_USE_IPV6` (RFC 6762 §6.2, §20):

- **Input:** the udp6 port-5353 handler feeds datagrams to `mdns_input6()`, which takes the sender's 16-byte address.  Both entry points fill the same `dest_t` and share one `input()`.
- **AAAA records:** `.rdata.aaaa = NULL` stands for every usable (preferred or deprecated, never tentative, RFC 4862 §5.4) IPv6 address of the interface — `aaaa_addrs()` — and is written as one AAAA RR each.  Known answers and conflicts compare against any of them, so a querier that already knows one of our addresses suppresses the whole record.  A fixed address can be given instead.
- **Families:** probes, announcements and goodbyes go to 224.0.0.251 and to ff02::fb; answers go back on the family the query came on (multicast, QU unicast or legacy unicast), and a delayed response remembers which families asked (`mdns_pending_t.families`).  Responses over either family carry all the interface's addresses, A and AAAA alike.  The family set is a bitmask (`MDNS_FAMILY_V4`, `MDNS_FAMILY_V6`) in single-stack builds too, where `family_group()` always returns the one group.  An IPv6-only build joins no IPv4 group, sends no IGMP, and has no `mdns_input()`.
- **No source yet:** an IPv6 packet needs a usable link-local address.  Until DAD has finished, `udp6_send_inplace()` finds no source and the IPv6 copy of a probe or announcement is simply not sent.
- **`mdns_readdress6()`** re-announces over IPv6 when an address becomes usable or stops being usable (RFC 6762 §8.4: a changed address MUST be re-announced; REQ-MDNS-059), without re-probing — the demo calls it when the link-local, SLAAC or DHCPv6 address comes up or goes.  The AAAA records of the announcement list the addresses usable then, with the cache-flush bit, which removes a lost one from caches.  While RUNNING: back to ANNOUNCING with `announce_families` = IPv6 only; the first announcement goes out on the next tick, the second 1 s later.  While ANNOUNCING: IPv6 joins the set and the sequence starts over, so IPv4 still gets both announcements.  While PROBING: nothing — the announcements to come include both families.  `mdns_start()` and `mdns_stop()` reset the set to both families, so goodbyes always go to both.

---

## 12. Integration with the Main Loop

The responder is integrated like every protocol module ([integrating-modules.md](../integrating-modules.md)).  The UDP handlers receive the message as a pointer into `net->rx.buf`, valid during the call, and pass it straight on — nothing is copied:

```c
static void mdns_udp(net_t *n, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *payload, uint16_t len) {
  mdns_input(&mdns, src_ip, src_mac, src_port, payload, len);
}
static void mdns_udp6(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                      const uint8_t *src_mac, const uint8_t *payload, uint16_t len) {
  mdns_input6(&mdns, src_ip, src_mac, src_port, payload, len);   /* IPv6 builds */
}
static const udp_port_entry_t udp_ports[] = {{MDNS_PORT, mdns_udp}};
static const udp6_port_entry_t udp6_ports[] = {{MDNS_PORT, mdns_udp6}};

udp_set_ports(&net, udp_ports, 1);
udp6_set_ports(&net, udp6_ports, 1);

/* main loop */
mdns_tick(&mdns, elapsed_ms);   /* probes, announcements, delayed responses */

/* shutdown */
mdns_withdraw(&mdns, 0x0Eu);    /* one service gone: records 1..3 */
mdns_stop(&mdns);               /* goodbye + IGMP/MLD leave */
```

`mdns_tick()` takes elapsed milliseconds, like `net_tick()` and `dhcpv4_client_tick()`.  The conflict callback may rename (change the strings the record table points at) and call `mdns_start()` directly: the responder enters CONFLICT before calling back and does nothing more with the message afterwards.  Before renaming an instance, it calls `mdns_withdraw()` for the instance's PTR record, which says goodbye to the old rdata (§9).  `demo/mdns_demo/main.c` is a complete, dual-stack example.

Random delays — the 0–250 ms probe start and the 20–120 ms response delay — come from `net_random_below()`, which scales rather than reduces with `%` so Cortex-M0 builds do not link a software divide.  The generator is the stack's one keyed hash (`net_random()`: HalfSipHash-2-4 of an output count, [architecture.md §9](../architecture.md#9-randomness)), keyed from the MAC by `net_init()`; an application with a real entropy source adds it with `net_random_seed()`.  mDNS used to keep its own generator, seeded from the MAC and the IPv4 address.

---

## 13. Tests

### Integration tests (black box through the API)

| Suite | Tests | Covers |
|---|---|---|
| `tests/integration/itest_mdns.c` | 50 | The requirements of `docs/requirements/mdns.md` and `dns-sd.md` through `mdns_*()` and the wire (224.0.0.251): message format and the header bits sent and ignored, compressed names decoded, names (UTF-8, byte order mark, control characters, 255 bytes, dots as label separators), TXT keys, the SRV target, what is ignored on reception (OPCODE, RCODE, port, off-link responses, questions in responses), probing (conflicts before the first probe, any type, fifteen conflicts, simultaneous probes lost and won with compressed rdata), a conflict while running probed again, goodbye for a renamed PTR, no periodic announcements, a new address announced, the one-second rate limit and probe defences, positive and negative answers (NSEC form, owned names only, unparseable NSEC), destinations, ANY, several questions, address validity, the TTL repair of §6.6, legacy replies, known answers from the querier only, cache-flush bits, whole RRSets, goodbyes and withdrawals, truncated queries |
| `tests/integration/itest_mdns6.c` | 4 | Dual stack, with the harness's own IPv6 frames: a lost IPv6 address re-announced, IPv6 responses only from the link, NSEC for AAAA without an address, AAAA only for usable addresses |

### Unit tests

| Suite | Tests | Covers |
|---|---|---|
| `tests/unit/test_dns_wire.c` | 22 | Encoding, compression (suffix, whole name, prefix), limits, rollback, decode, pointer loops, truncation, question/RR parsing |
| `tests/unit/test_mcast.c` | 19 | Group table, multicast accept/drop (incl. aliased MACs), no ICMP errors / echo for multicast, `udp_send_inplace()` TTL, IGMP report/leave format |
| `tests/unit/test_mdns.c` | 46 | Table validation (a record too big for any packet), probe timing and format, probe/announcement splitting, announcements, compression, conflicts (probing/callback restart/goodbyes), every answer type + additionals, meta-query, known-answer suppression (after a truncated query too), QU and legacy unicast, 0.0.0.0 queriers, malformed input, goodbye, withdrawing a service (goodbye, no answers or NSEC, the type kept while another instance offers it, before announcing) |
| `tests/unit/test_mdns6.c` | 19 | ff02::fb join, probes and goodbyes on both families, one AAAA per usable address (none for tentative ones), AAAA over either family, AAAA added to an A answer, SRV additionals, QU and legacy over IPv6, known answers, NSEC listing AAAA, delayed response on IPv6 only, explicit AAAA address, AAAA conflicts, `mdns_readdress6()` while running and while announcing |

### Blackbox (`tests/blackbox/test_mdns_conform.py`, 21 tests)

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
| 008 goodbye | SIGTERM → every record with TTL 0, the meta-query's PTR too |
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
| 019 NSEC | HINFO for the host → NSEC answer, TTL 120, cache-flush |
| 020 AAAA over IPv6 | Query to ff02::fb → answer to ff02::fb, Hop Limit 255, link-local address, A in Additional (skipped if the SUT is not dual stack) |
| 021 announced over IPv6 | Announcement to ff02::fb with AAAA and A (skipped if not dual stack) |

### Interop (`tests/blackbox/mdns_interop.sh`)

Runs in CI after the Scapy suite, with `avahi-daemon` on tap0: `avahi-resolve` finds `pyro-dead01.local`, `avahi-browse` resolves the service (host, IP, port, TXT), the advertised TCP port answers, and the service is withdrawn when the SUT sends its goodbye.  On macOS, `tests/blackbox/mdns_interop_macos.sh` does the same with mDNSResponder (`dns-sd -B/-L/-G`) over a feth pair.

---

## 14. Decisions (were open questions)

1. **IGMP retransmit:** the report is sent on join and repeated once when announcing starts (~0.75 s later).  Queries are not answered (§10).
2. **Probe tiebreak (RFC 6762 §8.2):** implemented (§5): `compare_sets()` walks both record sets in order without sorting them.
3. **Multiple interfaces:** single-interface — one `mdns_t` per `net_t`.
4. **Address and rdata changes** (RFC 6762 §8.4, REQ-MDNS-059): the A record can follow `net->ipv4_addr` (`.rdata.a = 0`); call `mdns_start()` after a DHCP renumbering to re-probe and re-announce — and after changing a record's rdata (TXT strings, a port), which must be announced again.  AAAA records follow the interface's IPv6 addresses (`.rdata.aaaa = NULL`); call `mdns_readdress6()` when one becomes usable or stops being usable.
