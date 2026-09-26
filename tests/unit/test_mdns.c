/**
 * @file test_mdns.c
 * @brief Unit tests for the mDNS responder / DNS-SD advertiser.
 *
 * Tests REQ-MDNS-001..033, 041-043 and REQ-DNSSD-001..018, 030-032
 * (V1 responder scope).
 */

#include "dns_wire.h"
#include "igmp.h"
#include "ipv4.h"
#include "mdns.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

/* ── Stub MAC driver: captures every sent frame ───────────────────── */

#define MAX_FRAMES 16
static uint8_t frames[MAX_FRAMES][1514];
static uint16_t frame_lens[MAX_FRAMES];
static int n_frames;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  if (n_frames < MAX_FRAMES) {
    memcpy(frames[n_frames], f, l);
    frame_lens[n_frames] = l;
  }
  n_frames++;
  return l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t off, uint8_t *buf, uint16_t n) {
  (void)ctx;
  (void)off;
  (void)buf;
  (void)n;
  return -1;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }

static const net_mac_t stub_mac = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Fixtures ─────────────────────────────────────────────────────── */

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"
#define OUR_IP 0x0A000002u  /* 10.0.0.2 (net_config default) */
#define PEER_IP 0x0A000064u /* 10.0.0.100 */

static const uint8_t peer_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t mdns_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};

static const char *const txt_entries[] = {"txtvers=1", "fw=1.2.3",
                                          "serial=DEAD01", NULL};

enum { REC_A, REC_PTR, REC_SRV, REC_TXT, N_RECS };

static const mdns_record_t records[N_RECS] = {
    {.type = DNS_TYPE_A, .ttl = MDNS_TTL_HOST, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_PTR,
     .ttl = MDNS_TTL_OTHER,
     .name = SVC,
     .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = MDNS_TTL_HOST,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT,
     .ttl = MDNS_TTL_HOST,
     .name = INST,
     .rdata.txt = txt_entries},
};

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;
static mdns_t m;

static int conflict_calls;
static uint8_t conflict_index;
static int restart_on_conflict;

static void on_conflict(mdns_t *mm, uint8_t idx, void *ctx) {
  (void)ctx;
  conflict_calls++;
  conflict_index = idx;
  if (restart_on_conflict)
    mdns_start(mm);
}

static void setup_with(const mdns_record_t *recs, uint8_t count,
                       uint16_t tx_size) {
  static int ctx;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, tx_size, NULL, &stub_mac,
           &ctx);
  n_frames = 0;
  conflict_calls = 0;
  conflict_index = 0xFF;
  restart_on_conflict = 0;
  mdns_init(&m, &net, recs, count, on_conflict, NULL);
}

static void setup(void) { setup_with(records, N_RECS, sizeof(tx_buf)); }

/* Start, run the three probes and both announcements, clear capture. */
static void to_running(void) {
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* probe 1 */
  mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* probe 2 */
  mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* probe 3 */
  mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* announcement 1 */
  mdns_tick(&m, MDNS_ANNOUNCE_WAIT_MS); /* announcement 2 */
  n_frames = 0;
}

/* ── Captured-frame helpers ───────────────────────────────────────── */

static int is_igmp(int i, uint8_t type) {
  const uint8_t *f = frames[i];
  return frame_lens[i] >= IGMP_FRAME_SIZE && f[14 + IPV4_OFF_PROTO] == 2 &&
         f[14 + 24] == type;
}

static int is_mdns(int i) {
  const uint8_t *f = frames[i];
  return frame_lens[i] >= UDP_PAYLOAD_OFFSET + DNS_HDR_SIZE &&
         f[14 + IPV4_OFF_PROTO] == IPV4_PROTO_UDP &&
         net_read16be(f + 34) == MDNS_PORT;
}

static int count_mdns(void) {
  int i, n = 0;
  for (i = 0; i < n_frames && i < MAX_FRAMES; i++)
    n += is_mdns(i);
  return n;
}

/* Index of the k-th mDNS frame, or -1 */
static int mdns_frame(int k) {
  int i;
  for (i = 0; i < n_frames && i < MAX_FRAMES; i++) {
    if (is_mdns(i) && k-- == 0)
      return i;
  }
  return -1;
}

static const uint8_t *dns_msg(int i, uint16_t *len) {
  *len = (uint16_t)(frame_lens[i] - UDP_PAYLOAD_OFFSET);
  return frames[i] + UDP_PAYLOAD_OFFSET;
}

static uint16_t hdr16(const uint8_t *msg, uint16_t off) {
  return net_read16be(msg + off);
}

/* Offset of the first RR (after the question section), or -1 */
static int first_rr(const uint8_t *msg, uint16_t len) {
  int off = DNS_HDR_SIZE;
  uint16_t i, qd = hdr16(msg, DNS_OFF_QDCOUNT);
  dns_question_t q;
  for (i = 0; i < qd; i++) {
    off = dns_read_question(msg, len, (uint16_t)off, &q);
    if (off < 0)
      return -1;
  }
  return off;
}

/* Find an RR by name + type in section 0=answer, 1=authority, 2=additional */
static int find_rr(const uint8_t *msg, uint16_t len, int section,
                   const char *name, uint16_t type, dns_rr_t *out) {
  uint16_t counts[3] = {hdr16(msg, DNS_OFF_ANCOUNT),
                        hdr16(msg, DNS_OFF_NSCOUNT),
                        hdr16(msg, DNS_OFF_ARCOUNT)};
  int off = first_rr(msg, len);
  int s;
  uint16_t i;
  for (s = 0; s < 3 && off >= 0; s++) {
    for (i = 0; i < counts[s] && off >= 0; i++) {
      dns_rr_t rr;
      off = dns_read_rr(msg, len, (uint16_t)off, &rr);
      if (off < 0)
        return 0;
      if (s == section && rr.type == type &&
          dns_name_equals(msg, len, rr.name_off, name)) {
        *out = rr;
        return 1;
      }
    }
  }
  return 0;
}

/* ── Query builder ────────────────────────────────────────────────── */

static uint8_t qbuf[512];
static dns_writer_t qw;
static uint16_t q_qd, q_an, q_ns, q_ar;

static void q_begin(uint16_t id, uint16_t flags) {
  dns_writer_init(&qw, qbuf, sizeof(qbuf));
  dns_write_header(&qw, id, flags, 0, 0, 0, 0);
  q_qd = q_an = q_ns = q_ar = 0;
}

static void q_question(const char *name, uint16_t type, int qu) {
  dns_write_name(&qw, name);
  dns_write_u16(&qw, type);
  dns_write_u16(&qw, (uint16_t)(DNS_CLASS_IN | (qu ? DNS_CLASS_TOPBIT : 0)));
  q_qd++;
}

static void count_section(int section) {
  if (section == 0)
    q_an++;
  else if (section == 1)
    q_ns++;
  else
    q_ar++;
}

/* RR header up to (not including) RDLENGTH; returns RDLENGTH offset */
static uint16_t q_rr_head(int section, const char *name, uint16_t type,
                          uint32_t ttl) {
  dns_write_name(&qw, name);
  dns_write_u16(&qw, type);
  dns_write_u16(&qw, DNS_CLASS_IN);
  dns_write_u32(&qw, ttl);
  uint16_t rdlen_off = qw.len;
  dns_write_u16(&qw, 0);
  count_section(section);
  return rdlen_off;
}

static void q_rr_end(uint16_t rdlen_off) {
  net_write16be(qbuf + rdlen_off, (uint16_t)(qw.len - rdlen_off - 2));
}

static void q_rr_a(int section, const char *name, uint32_t ip, uint32_t ttl) {
  uint16_t o = q_rr_head(section, name, DNS_TYPE_A, ttl);
  dns_write_u32(&qw, ip);
  q_rr_end(o);
}

static void q_rr_ptr(int section, const char *name, const char *target,
                     uint32_t ttl) {
  uint16_t o = q_rr_head(section, name, DNS_TYPE_PTR, ttl);
  dns_write_name(&qw, target);
  q_rr_end(o);
}

static void q_rr_srv(int section, const char *name, uint16_t port,
                     const char *target, uint32_t ttl) {
  uint16_t o = q_rr_head(section, name, DNS_TYPE_SRV, ttl);
  dns_write_u16(&qw, 0);
  dns_write_u16(&qw, 0);
  dns_write_u16(&qw, port);
  dns_write_name(&qw, target);
  q_rr_end(o);
}

static void q_rr_raw(int section, const char *name, uint16_t type,
                     const uint8_t *rdata, uint16_t rdlen) {
  uint16_t o = q_rr_head(section, name, type, 120);
  dns_write_bytes(&qw, rdata, rdlen);
  q_rr_end(o);
}

static void feed_as(uint32_t src_ip, uint16_t sport) {
  dns_set_counts(qbuf, q_qd, q_an, q_ns, q_ar);
  mdns_input(&m, src_ip, peer_mac, sport, qbuf, qw.len);
}

static void feed_from(uint16_t sport) { feed_as(PEER_IP, sport); }

static void feed(void) { feed_from(MDNS_PORT); }

/* Send a one-question query from port 5353 */
static void query(const char *name, uint16_t type) {
  q_begin(0, 0);
  q_question(name, type, 0);
  feed();
}

/* Check the IP/UDP envelope of a multicast mDNS frame */
static int multicast_envelope_ok(int i) {
  const uint8_t *f = frames[i];
  return memcmp(f, mdns_mac, 6) == 0 && f[14 + IPV4_OFF_TTL] == MDNS_IP_TTL &&
         net_read32be(f + 14 + IPV4_OFF_DST) == MDNS_GROUP &&
         net_read32be(f + 14 + IPV4_OFF_SRC) == OUR_IP &&
         net_read16be(f + 34) == MDNS_PORT && net_read16be(f + 36) == MDNS_PORT;
}

/* ══ Initialisation ═══════════════════════════════════════════════════ */

TEST(test_init_validates_table) {
  static char long_entry[257]; /* REQ-DNSSD-032: TXT strings <= 255 bytes */
  static const char *long_txt[2] = {long_entry, NULL};
  mdns_record_t bad_txt[1];
  memset(long_entry, 'x', 256);
  long_entry[256] = '\0';
  memset(bad_txt, 0, sizeof(bad_txt));
  bad_txt[0].type = DNS_TYPE_TXT;
  bad_txt[0].ttl = 120;
  bad_txt[0].name = INST;
  bad_txt[0].rdata.txt = long_txt;
  static const mdns_record_t bad_name[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = "a..local", .rdata.a = 0}};
  static const mdns_record_t bad_type[] = {/* HINFO: never supported */
      {.type = 13, .ttl = 120, .name = HOST, .rdata.a = 0}};
  static const mdns_record_t bad_target[] = {
      {.type = DNS_TYPE_PTR, .ttl = 120, .name = SVC, .rdata.ptr = NULL}};
  static int ctx;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_mac, &ctx);
  n_frames = 0;
  ASSERT_EQ(mdns_init(&m, &net, records, 0, NULL, NULL), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(mdns_init(&m, &net, records, MDNS_MAX_RECORDS + 1, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(mdns_init(&m, &net, bad_txt, 1, NULL, NULL), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(mdns_init(&m, &net, bad_name, 1, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(mdns_init(&m, &net, bad_type, 1, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(mdns_init(&m, &net, bad_target, 1, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(mdns_init(&m, &net, records, N_RECS, NULL, NULL), NET_OK);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_STOPPED);
  ASSERT_EQ(n_frames, 0);
}

TEST(test_stopped_is_silent) {
  setup();
  mdns_tick(&m, 5000);
  query(HOST, DNS_TYPE_A);
  ASSERT_EQ(n_frames, 0);
}

/* ══ Probing (REQ-MDNS-002, 016..021) ═════════════════════════════════ */

TEST(test_start_joins_group) {
  setup();
  mdns_start(&m);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  ASSERT_TRUE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(is_igmp(0, IGMP_TYPE_V2_REPORT));
}

/* REQ-MDNS-017: first probe within 0-250 ms */
TEST(test_first_probe_within_250ms) {
  setup();
  mdns_start(&m);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(is_mdns(0));
}

TEST(test_probe_format) {
  uint16_t len;
  dns_question_t q;
  dns_rr_t rr;
  setup();
  mdns_start(&m);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(count_mdns(), 1);
  ASSERT_TRUE(multicast_envelope_ok(0)); /* REQ-MDNS-001, 006 */
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ID), 0);    /* REQ-MDNS-005 */
  ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), 0); /* query */
  ASSERT_EQ(hdr16(msg, DNS_OFF_QDCOUNT), 2); /* host + instance */
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 0);
  ASSERT_EQ(hdr16(msg, DNS_OFF_NSCOUNT), 3); /* unique: A, SRV, TXT */
  int off = dns_read_question(msg, len, DNS_HDR_SIZE, &q);
  ASSERT_TRUE(off > 0);
  ASSERT_TRUE(dns_name_equals(msg, len, q.name_off, HOST));
  ASSERT_EQ(q.type, DNS_TYPE_ANY);
  ASSERT_EQ(q.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT); /* QU */
  off = dns_read_question(msg, len, (uint16_t)off, &q);
  ASSERT_TRUE(off > 0);
  ASSERT_TRUE(dns_name_equals(msg, len, q.name_off, INST));
  ASSERT_TRUE(find_rr(msg, len, 1, HOST, DNS_TYPE_A, &rr));
  ASSERT_EQ(net_read32be(msg + rr.rdata_off), OUR_IP); /* .a = 0 → our IP */
  ASSERT_EQ(rr.class_, DNS_CLASS_IN);                  /* no cache flush */
  ASSERT_TRUE(find_rr(msg, len, 1, INST, DNS_TYPE_SRV, &rr));
  ASSERT_TRUE(find_rr(msg, len, 1, INST, DNS_TYPE_TXT, &rr));
  ASSERT_FALSE(find_rr(msg, len, 1, SVC, DNS_TYPE_PTR, &rr)); /* shared */
}

/* REQ-MDNS-016, 018: three probes, 250 ms apart */
TEST(test_three_probes_250ms_apart) {
  setup();
  mdns_start(&m);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(count_mdns(), 1);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS - 1);
  ASSERT_EQ(count_mdns(), 1);
  mdns_tick(&m, 1);
  ASSERT_EQ(count_mdns(), 2);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(count_mdns(), 3);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS - 1);
  ASSERT_EQ(count_mdns(), 3); /* still waiting after the third probe */
}

/* REQ-MDNS-021..023: announce after probing succeeds */
TEST(test_announcement_after_probes) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_ANNOUNCING);
  ASSERT_EQ(count_mdns(), 1);
  int i = mdns_frame(0);
  ASSERT_TRUE(multicast_envelope_ok(i));
  const uint8_t *msg = dns_msg(i, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ID), 0);
  ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), DNS_FLAG_QR | DNS_FLAG_AA);
  ASSERT_EQ(hdr16(msg, DNS_OFF_QDCOUNT), 0);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), N_RECS);
  /* unique records carry the cache-flush bit, shared PTR does not */
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_A, &rr));
  ASSERT_EQ(rr.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  ASSERT_EQ(rr.ttl, (uint32_t)MDNS_TTL_HOST);
  ASSERT_TRUE(find_rr(msg, len, 0, SVC, DNS_TYPE_PTR, &rr));
  ASSERT_EQ(rr.class_, DNS_CLASS_IN);
  ASSERT_EQ(rr.ttl, (uint32_t)MDNS_TTL_OTHER);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_SRV, &rr));
  ASSERT_EQ(rr.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_TXT, &rr));
  /* RFC 2236 §3: the IGMP report is repeated once after a short delay */
  int j, igmp = 0;
  for (j = 0; j < n_frames; j++)
    igmp += is_igmp(j, IGMP_TYPE_V2_REPORT);
  ASSERT_EQ(igmp, 1);
}

/* REQ-MDNS-022: second announcement one second later, then quiet */
TEST(test_second_announcement_after_1s) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  mdns_tick(&m, MDNS_ANNOUNCE_WAIT_MS - 1);
  ASSERT_EQ(count_mdns(), 0);
  mdns_tick(&m, 1);
  ASSERT_EQ(count_mdns(), 1);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  mdns_tick(&m, 60000);
  ASSERT_EQ(count_mdns(), 1);
}

/* REQ-MDNS-043: names in the announcement are compressed */
TEST(test_announcement_uses_compression) {
  uint16_t len;
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  const uint8_t *msg = dns_msg(mdns_frame(0), &len);
  /* the full instance name is spelled out only once */
  int i, spelled = 0;
  for (i = 0; i + 11 <= len; i++)
    spelled += memcmp(msg + i, "Pyro Unit 1", 11) == 0;
  ASSERT_EQ(spelled, 1);
  ASSERT_TRUE(len < 180);
}

/* REQ-MDNS-019: a conflicting response during probing stops the claim */
TEST(test_conflict_during_probing) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_a(0, HOST, 0x0A000063u, 120); /* another host owns the name */
  feed();
  ASSERT_EQ(conflict_calls, 1); /* REQ-MDNS-020 */
  ASSERT_EQ(conflict_index, REC_A);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);
  n_frames = 0;
  mdns_tick(&m, 5000);
  query(HOST, DNS_TYPE_A);
  ASSERT_EQ(count_mdns(), 0);
}

TEST(test_identical_record_is_not_conflict) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_a(0, HOST, OUR_IP, 120);
  feed();
  ASSERT_EQ(conflict_calls, 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
}

/* Probing: any other record type under our name is also a conflict */
TEST(test_other_type_same_name_conflicts_while_probing) {
  static const uint8_t txt[] = {3, 'a', '=', 'b'};
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_raw(0, HOST, DNS_TYPE_TXT, txt, sizeof(txt));
  feed();
  ASSERT_EQ(conflict_calls, 1);
  ASSERT_EQ(conflict_index, REC_A);
}

/* The callback may rename and restart from inside the callback */
TEST(test_conflict_callback_can_restart) {
  setup();
  restart_on_conflict = 1;
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_srv(0, INST, 8080, "elsewhere.local", 120);
  feed();
  ASSERT_EQ(conflict_calls, 1);
  ASSERT_EQ(conflict_index, REC_SRV);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(count_mdns(), 1); /* probing again */
}

/* Goodbye records (TTL 0) from others are not conflicts */
TEST(test_goodbye_from_other_host_ignored) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_a(0, HOST, 0x0A000063u, 0);
  feed();
  ASSERT_EQ(conflict_calls, 0);
}

TEST(test_no_answers_while_probing) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  query(HOST, DNS_TYPE_A);
  mdns_tick(&m, 1);
  ASSERT_EQ(n_frames, 0);
}

/* ══ Responding (REQ-MDNS-004..006, 025..031) ═════════════════════════ */

TEST(test_a_query_answered_immediately) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  query(HOST, DNS_TYPE_A);
  ASSERT_EQ(n_frames, 1); /* unique record: no delay */
  ASSERT_TRUE(multicast_envelope_ok(0));
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ID), 0);
  ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), DNS_FLAG_QR | DNS_FLAG_AA);
  ASSERT_EQ(hdr16(msg, DNS_OFF_QDCOUNT), 0);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 1);
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_A, &rr));
  ASSERT_EQ(rr.rdlen, 4);
  ASSERT_EQ(net_read32be(msg + rr.rdata_off), OUR_IP);
  ASSERT_EQ(rr.ttl, (uint32_t)MDNS_TTL_HOST);
  ASSERT_EQ(rr.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
}

TEST(test_answers_during_announcing) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_ANNOUNCING);
  n_frames = 0;
  query(HOST, DNS_TYPE_A);
  ASSERT_EQ(count_mdns(), 1);
}

TEST(test_query_name_case_insensitive) {
  setup();
  to_running();
  query("PYRO-DEAD01.Local.", DNS_TYPE_A);
  ASSERT_EQ(n_frames, 1);
}

TEST(test_a_record_tracks_address_change) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  net.ipv4_addr = 0x0A00004Du; /* e.g. DHCP renumbering */
  query(HOST, DNS_TYPE_A);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_A, &rr));
  ASSERT_EQ(net_read32be(msg + rr.rdata_off), 0x0A00004Du);
}

/* REQ-MDNS-030: unknown names / other domains are ignored silently */
TEST(test_unknown_names_ignored) {
  setup();
  to_running();
  query("other.local", DNS_TYPE_A);
  query("pyro-dead01.example", DNS_TYPE_A);
  query("pyro-dead01", DNS_TYPE_A);
  mdns_tick(&m, 200);
  ASSERT_EQ(n_frames, 0);
}

/* ══ Negative responses (RFC 6762 §6.1, restricted NSEC form) ═════════ */

#define DNS_TYPE_NSEC 47

/* Our name, a type we don't have → NSEC listing the types we do have.
 * Without it a dual-stack lookup of HOST waits ~5 s for an AAAA answer. */
TEST(test_nsec_for_missing_type) {
  static const uint8_t bitmap[] = {0x00, 0x01, 0x40}; /* block 0: A */
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  query(HOST, DNS_TYPE_AAAA);
  ASSERT_EQ(n_frames, 1); /* unique name: immediate */
  ASSERT_TRUE(multicast_envelope_ok(0));
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 1);
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_NSEC, &rr));
  ASSERT_EQ(rr.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  ASSERT_EQ(rr.ttl, (uint32_t)MDNS_TTL_HOST);
  ASSERT_TRUE(dns_name_equals(msg, len, rr.rdata_off, HOST)); /* next = own */
  int after = dns_name_skip(msg, len, rr.rdata_off);
  ASSERT_TRUE(after > 0);
  ASSERT_EQ(rr.rdata_off + rr.rdlen - after, (int)sizeof(bitmap));
  ASSERT_MEM_EQ(msg + after, bitmap, sizeof(bitmap));
}

TEST(test_nsec_bitmap_for_instance) {
  /* TXT (16) → byte 2 bit 0x80; SRV (33) → byte 4 bit 0x40 */
  static const uint8_t bitmap[] = {0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x40};
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  query(INST, DNS_TYPE_A);
  ASSERT_EQ(n_frames, 1);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_NSEC, &rr));
  int after = dns_name_skip(msg, len, rr.rdata_off);
  ASSERT_EQ(rr.rdata_off + rr.rdlen - after, (int)sizeof(bitmap));
  ASSERT_MEM_EQ(msg + after, bitmap, sizeof(bitmap));
}

/* A + AAAA in one query: the A record and the NSEC travel together */
TEST(test_nsec_with_positive_answer_in_same_query) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  q_begin(0, 0);
  q_question(HOST, DNS_TYPE_A, 0);
  q_question(HOST, DNS_TYPE_AAAA, 0);
  feed();
  ASSERT_EQ(n_frames, 1);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 2);
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_A, &rr));
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_NSEC, &rr));
}

/* No NSEC for names we don't own, shared names, or ANY queries */
TEST(test_no_nsec_where_not_owned) {
  setup();
  to_running();
  query("other.local", DNS_TYPE_AAAA);
  query(SVC, DNS_TYPE_A); /* shared PTR name, not ours alone */
  mdns_tick(&m, 200);
  ASSERT_EQ(n_frames, 0);
  query(HOST, DNS_TYPE_ANY);
  ASSERT_EQ(n_frames, 1);
  uint16_t len;
  dns_rr_t rr;
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_FALSE(find_rr(msg, len, 0, HOST, DNS_TYPE_NSEC, &rr));
}

/* Not while probing: the name isn't ours yet */
TEST(test_no_nsec_while_probing) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  query(HOST, DNS_TYPE_AAAA);
  ASSERT_EQ(n_frames, 0);
}

/* REQ-DNSSD-001, 007: PTR answer + SRV/TXT/A additionals, delayed */
TEST(test_ptr_query_delayed_with_additionals) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  query(SVC, DNS_TYPE_PTR);
  ASSERT_EQ(n_frames, 0); /* shared record: 20-120 ms delay (RFC 6762 §6) */
  mdns_tick(&m, MDNS_RESP_DELAY_MIN_MS - 1);
  ASSERT_EQ(n_frames, 0);
  mdns_tick(&m, MDNS_RESP_DELAY_MAX_MS - MDNS_RESP_DELAY_MIN_MS + 1);
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(multicast_envelope_ok(0));
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 1);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ARCOUNT), 3);
  ASSERT_TRUE(find_rr(msg, len, 0, SVC, DNS_TYPE_PTR, &rr));
  ASSERT_TRUE(dns_name_equals(msg, len, rr.rdata_off, INST));
  ASSERT_EQ(rr.ttl, (uint32_t)MDNS_TTL_OTHER);
  ASSERT_TRUE(find_rr(msg, len, 2, INST, DNS_TYPE_SRV, &rr));
  ASSERT_TRUE(find_rr(msg, len, 2, INST, DNS_TYPE_TXT, &rr));
  ASSERT_TRUE(find_rr(msg, len, 2, HOST, DNS_TYPE_A, &rr));
  mdns_tick(&m, 1000);
  ASSERT_EQ(n_frames, 1); /* sent once */
}

/* REQ-DNSSD-002, 008: SRV answer + A additional */
TEST(test_srv_query_with_a_additional) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  query(INST, DNS_TYPE_SRV);
  ASSERT_EQ(n_frames, 1);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 1);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ARCOUNT), 1);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_SRV, &rr));
  ASSERT_EQ(net_read16be(msg + rr.rdata_off), 0);     /* priority */
  ASSERT_EQ(net_read16be(msg + rr.rdata_off + 2), 0); /* weight */
  ASSERT_EQ(net_read16be(msg + rr.rdata_off + 4), 80);
  ASSERT_TRUE(dns_name_equals(msg, len, rr.rdata_off + 6, HOST));
  ASSERT_TRUE(find_rr(msg, len, 2, HOST, DNS_TYPE_A, &rr));
}

/* REQ-DNSSD-003, 011: TXT rdata is length-prefixed key=value strings */
TEST(test_txt_rdata_format) {
  static const uint8_t expect[] = {9,   't', 'x', 't', 'v', 'e', 'r', 's', '=',
                                   '1', 8,   'f', 'w', '=', '1', '.', '2', '.',
                                   '3', 13,  's', 'e', 'r', 'i', 'a', 'l', '=',
                                   'D', 'E', 'A', 'D', '0', '1'};
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  query(INST, DNS_TYPE_TXT);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_TXT, &rr));
  ASSERT_EQ(rr.rdlen, sizeof(expect));
  ASSERT_MEM_EQ(msg + rr.rdata_off, expect, sizeof(expect));
}

/* REQ-DNSSD-012: no metadata → a single zero byte */
TEST(test_empty_txt_is_single_zero_byte) {
  static const char *const none[] = {NULL};
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_TXT, .ttl = 120, .name = "a._x._tcp.local",
       .rdata.txt = NULL},
      {.type = DNS_TYPE_TXT, .ttl = 120, .name = "b._x._tcp.local",
       .rdata.txt = none},
  };
  uint16_t len;
  dns_rr_t rr;
  setup_with(recs, 2, sizeof(tx_buf));
  to_running();
  query("a._x._tcp.local", DNS_TYPE_TXT);
  query("b._x._tcp.local", DNS_TYPE_TXT);
  ASSERT_EQ(n_frames, 2);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_TRUE(find_rr(msg, len, 0, "a._x._tcp.local", DNS_TYPE_TXT, &rr));
  ASSERT_EQ(rr.rdlen, 1);
  ASSERT_EQ(msg[rr.rdata_off], 0);
  msg = dns_msg(1, &len);
  ASSERT_TRUE(find_rr(msg, len, 0, "b._x._tcp.local", DNS_TYPE_TXT, &rr));
  ASSERT_EQ(rr.rdlen, 1);
}

TEST(test_any_query_returns_all_types_for_name) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  query(INST, DNS_TYPE_ANY);
  ASSERT_EQ(n_frames, 1);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 2);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_SRV, &rr));
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_TXT, &rr));
  ASSERT_TRUE(find_rr(msg, len, 2, HOST, DNS_TYPE_A, &rr));
}

/* REQ-DNSSD-014, 015: service type enumeration, one PTR per type */
TEST(test_meta_query_lists_service_types) {
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
      {.type = DNS_TYPE_PTR,
       .ttl = 4500,
       .name = SVC,
       .rdata.ptr = "Pyro Unit 2._pyro._tcp.local"},
      {.type = DNS_TYPE_PTR,
       .ttl = 4500,
       .name = "_http._tcp.local",
       .rdata.ptr = "Web._http._tcp.local"},
  };
  uint16_t len;
  dns_rr_t rr;
  setup_with(recs, 4, sizeof(tx_buf));
  to_running();
  query(MDNS_META_QUERY, DNS_TYPE_PTR);
  ASSERT_EQ(n_frames, 0);
  mdns_tick(&m, MDNS_RESP_DELAY_MAX_MS);
  ASSERT_EQ(n_frames, 1);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), 2);
  ASSERT_TRUE(find_rr(msg, len, 0, MDNS_META_QUERY, DNS_TYPE_PTR, &rr));
  int off = first_rr(msg, len), seen_pyro = 0, seen_http = 0, k;
  for (k = 0; k < 2; k++) {
    off = dns_read_rr(msg, len, (uint16_t)off, &rr);
    ASSERT_TRUE(off > 0);
    seen_pyro += dns_name_equals(msg, len, rr.rdata_off, SVC);
    seen_http += dns_name_equals(msg, len, rr.rdata_off, "_http._tcp.local");
  }
  ASSERT_EQ(seen_pyro, 1);
  ASSERT_EQ(seen_http, 1);
}

/* REQ-MDNS-029: suppress answers the querier already has at >= half TTL */
TEST(test_known_answer_suppression) {
  setup();
  to_running();
  q_begin(0, 0);
  q_question(SVC, DNS_TYPE_PTR, 0);
  q_rr_ptr(0, SVC, INST, MDNS_TTL_OTHER / 2);
  feed();
  mdns_tick(&m, MDNS_RESP_DELAY_MAX_MS);
  ASSERT_EQ(n_frames, 0);

  q_begin(0, 0);
  q_question(SVC, DNS_TYPE_PTR, 0);
  q_rr_ptr(0, SVC, INST, MDNS_TTL_OTHER / 2 - 1); /* stale: answer again */
  feed();
  mdns_tick(&m, MDNS_RESP_DELAY_MAX_MS);
  ASSERT_EQ(n_frames, 1);
}

TEST(test_known_answer_other_rdata_not_suppressed) {
  setup();
  to_running();
  q_begin(0, 0);
  q_question(SVC, DNS_TYPE_PTR, 0);
  q_rr_ptr(0, SVC, "Someone Else._pyro._tcp.local", MDNS_TTL_OTHER);
  feed();
  mdns_tick(&m, MDNS_RESP_DELAY_MAX_MS);
  ASSERT_EQ(n_frames, 1);
}

TEST(test_known_answer_unique_record) {
  setup();
  to_running();
  q_begin(0, 0);
  q_question(HOST, DNS_TYPE_A, 0);
  q_rr_a(0, HOST, OUR_IP, MDNS_TTL_HOST);
  feed();
  ASSERT_EQ(n_frames, 0);
}

/* REQ-MDNS-028: QU question → unicast reply to the querier */
TEST(test_qu_question_gets_unicast_reply) {
  const uint8_t *f;
  setup();
  to_running();
  q_begin(0, 0);
  q_question(HOST, DNS_TYPE_A, 1);
  feed();
  ASSERT_EQ(n_frames, 1);
  f = frames[0];
  ASSERT_MEM_EQ(f, peer_mac, 6);
  ASSERT_EQ(net_read32be(f + 14 + IPV4_OFF_DST), PEER_IP);
  ASSERT_EQ(f[14 + IPV4_OFF_TTL], MDNS_IP_TTL);
  ASSERT_EQ(net_read16be(f + 36), MDNS_PORT);
}

/* Legacy unicast (source port != 5353, RFC 6762 §6.7) */
TEST(test_legacy_unicast_query) {
  const uint8_t *f;
  uint16_t len;
  dns_question_t q;
  dns_rr_t rr;
  setup();
  to_running();
  q_begin(0x1234, 0);
  q_question(HOST, DNS_TYPE_A, 0);
  feed_from(49152);
  ASSERT_EQ(n_frames, 1);
  f = frames[0];
  ASSERT_MEM_EQ(f, peer_mac, 6);
  ASSERT_EQ(net_read32be(f + 14 + IPV4_OFF_DST), PEER_IP);
  ASSERT_EQ(net_read16be(f + 34), MDNS_PORT);
  ASSERT_EQ(net_read16be(f + 36), 49152);
  const uint8_t *msg = dns_msg(0, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ID), 0x1234);
  ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), DNS_FLAG_QR | DNS_FLAG_AA);
  ASSERT_EQ(hdr16(msg, DNS_OFF_QDCOUNT), 1); /* question repeated */
  ASSERT_TRUE(dns_read_question(msg, len, DNS_HDR_SIZE, &q) > 0);
  ASSERT_TRUE(dns_name_equals(msg, len, q.name_off, HOST));
  ASSERT_EQ(q.type, DNS_TYPE_A);
  ASSERT_EQ(q.class_, DNS_CLASS_IN);
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_A, &rr));
  ASSERT_EQ(rr.ttl, (uint32_t)MDNS_LEGACY_TTL_MAX);
  ASSERT_EQ(rr.class_, DNS_CLASS_IN); /* no cache-flush bit */
}

/* A querier without an address yet (0.0.0.0) cannot take unicast */
TEST(test_qu_from_unspecified_source_is_multicast) {
  setup();
  to_running();
  q_begin(0, 0);
  q_question(HOST, DNS_TYPE_A, 1);
  feed_as(0, MDNS_PORT);
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(multicast_envelope_ok(0));
}

TEST(test_legacy_from_unspecified_source_ignored) {
  setup();
  to_running();
  q_begin(0x1234, 0);
  q_question(HOST, DNS_TYPE_A, 0);
  feed_as(0, 49152);
  ASSERT_EQ(n_frames, 0);
}

/* Responses are not queries: never answered */
TEST(test_responses_not_answered) {
  setup();
  to_running();
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_question(HOST, DNS_TYPE_A, 0);
  feed();
  mdns_tick(&m, 200);
  ASSERT_EQ(n_frames, 0);
}

TEST(test_nonzero_opcode_ignored) {
  setup();
  to_running();
  q_begin(0, 0x2800); /* opcode 5 (UPDATE) */
  q_question(HOST, DNS_TYPE_A, 0);
  feed();
  ASSERT_EQ(n_frames, 0);
}

/* REQ-MDNS-041: malformed input is dropped without a reply */
TEST(test_malformed_messages_ignored) {
  static const uint8_t short_msg[5] = {0};
  static const uint8_t no_question[12] = {0, 0, 0, 0, 0, 1};
  static const uint8_t loop[] = {0, 0, 0,    0, 0, 1, 0, 0, 0, 0, 0,
                                 0, 1, 'a', 0xC0, 12, 0, 1, 0, 1};
  static const uint8_t huge_counts[12] = {0, 0, 0, 0, 0xFF, 0xFF,
                                          0xFF, 0xFF, 0, 0, 0, 0};
  setup();
  to_running();
  mdns_input(&m, PEER_IP, peer_mac, MDNS_PORT, short_msg, sizeof(short_msg));
  mdns_input(&m, PEER_IP, peer_mac, MDNS_PORT, no_question,
             sizeof(no_question));
  mdns_input(&m, PEER_IP, peer_mac, MDNS_PORT, loop, sizeof(loop));
  mdns_input(&m, PEER_IP, peer_mac, MDNS_PORT, huge_counts,
             sizeof(huge_counts));
  mdns_tick(&m, 200);
  ASSERT_EQ(n_frames, 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* ══ Conflicts while running (RFC 6762 §9) ════════════════════════════ */

TEST(test_conflict_while_running) {
  setup();
  to_running();
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_srv(0, INST, 8080, HOST, 120);
  feed();
  ASSERT_EQ(conflict_calls, 1);
  ASSERT_EQ(conflict_index, REC_SRV);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);
  query(HOST, DNS_TYPE_A);
  ASSERT_EQ(n_frames, 0);
}

TEST(test_running_other_type_not_conflict) {
  static const uint8_t aaaa[16] = {0xFE, 0x80};
  setup();
  to_running();
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_raw(0, HOST, DNS_TYPE_AAAA, aaaa, sizeof(aaaa));
  q_rr_a(2, HOST, OUR_IP, 120); /* our own data echoed: fine */
  feed();
  ASSERT_EQ(conflict_calls, 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* Shared PTR records never conflict */
TEST(test_shared_ptr_never_conflicts) {
  setup();
  to_running();
  q_begin(0, DNS_FLAG_QR | DNS_FLAG_AA);
  q_rr_ptr(0, SVC, "Other Unit._pyro._tcp.local", 4500);
  feed();
  ASSERT_EQ(conflict_calls, 0);
}

/* ══ Goodbye (REQ-MDNS-032, 033, REQ-DNSSD-018) ═══════════════════════ */

TEST(test_stop_sends_goodbye_and_leaves) {
  uint16_t len;
  dns_rr_t rr;
  setup();
  to_running();
  mdns_stop(&m);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_STOPPED);
  ASSERT_FALSE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_EQ(count_mdns(), 1);
  int i = mdns_frame(0);
  ASSERT_TRUE(multicast_envelope_ok(i));
  const uint8_t *msg = dns_msg(i, &len);
  ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), DNS_FLAG_QR | DNS_FLAG_AA);
  ASSERT_EQ(hdr16(msg, DNS_OFF_ANCOUNT), N_RECS);
  ASSERT_TRUE(find_rr(msg, len, 0, HOST, DNS_TYPE_A, &rr));
  ASSERT_EQ(rr.ttl, 0u);
  ASSERT_TRUE(find_rr(msg, len, 0, SVC, DNS_TYPE_PTR, &rr));
  ASSERT_EQ(rr.ttl, 0u);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_SRV, &rr));
  ASSERT_EQ(rr.ttl, 0u);
  ASSERT_TRUE(find_rr(msg, len, 0, INST, DNS_TYPE_TXT, &rr));
  ASSERT_EQ(rr.ttl, 0u);
  ASSERT_TRUE(is_igmp(n_frames - 1, IGMP_TYPE_LEAVE));
  mdns_tick(&m, 5000);
  query(HOST, DNS_TYPE_A);
  ASSERT_EQ(count_mdns(), 1); /* silent after stop */
}

/* Nothing was announced yet, so there is nothing to withdraw */
TEST(test_stop_while_probing_sends_no_goodbye) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  mdns_stop(&m);
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(is_igmp(0, IGMP_TYPE_LEAVE));
}

/* A delayed response pending at stop is dropped */
TEST(test_stop_cancels_pending_response) {
  setup();
  to_running();
  query(SVC, DNS_TYPE_PTR);
  mdns_stop(&m);
  n_frames = 0;
  mdns_tick(&m, 1000);
  ASSERT_EQ(n_frames, 0);
}

/* ══ Size limits (REQ-MDNS-042, REQ-DNSSD-030) ════════════════════════ */

static const char *const t1[] = {"k=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                 NULL};
static const char *const t2[] = {"k=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                 NULL};
static const char *const t3[] = {"k=ccccccccccccccccccccccccccccccccccccccccccc",
                                 NULL};
static const mdns_record_t many[] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_TXT, .ttl = 120, .name = "one.local", .rdata.txt = t1},
    {.type = DNS_TYPE_TXT, .ttl = 120, .name = "two.local", .rdata.txt = t2},
    {.type = DNS_TYPE_TXT, .ttl = 120, .name = "three.local", .rdata.txt = t3},
};
#define SMALL_TX (UDP_PAYLOAD_OFFSET + 120)

TEST(test_announcement_split_across_packets) {
  int k, total_an = 0, frames_seen = 0;
  setup_with(many, 4, SMALL_TX);
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* announcement */
  for (k = 0; mdns_frame(k) >= 0; k++) {
    uint16_t len;
    int i = mdns_frame(k);
    const uint8_t *msg = dns_msg(i, &len);
    ASSERT_TRUE(frame_lens[i] <= SMALL_TX);
    ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), DNS_FLAG_QR | DNS_FLAG_AA);
    total_an += hdr16(msg, DNS_OFF_ANCOUNT);
    frames_seen++;
  }
  ASSERT_TRUE(frames_seen >= 2);
  ASSERT_EQ(total_an, 4);
}

TEST(test_probe_split_across_packets) {
  int k, total_qd = 0, total_ns = 0;
  setup_with(many, 4, SMALL_TX);
  mdns_start(&m);
  n_frames = 0;
  mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* first probe round */
  ASSERT_TRUE(count_mdns() >= 2);
  for (k = 0; mdns_frame(k) >= 0; k++) {
    uint16_t len;
    int i = mdns_frame(k);
    const uint8_t *msg = dns_msg(i, &len);
    ASSERT_TRUE(frame_lens[i] <= SMALL_TX);
    ASSERT_EQ(hdr16(msg, DNS_OFF_FLAGS), 0);
    total_qd += hdr16(msg, DNS_OFF_QDCOUNT);
    total_ns += hdr16(msg, DNS_OFF_NSCOUNT);
  }
  ASSERT_EQ(total_qd, 4);
  ASSERT_EQ(total_ns, 4);
}

int main(void) {
  RUN_TEST(test_init_validates_table);
  RUN_TEST(test_stopped_is_silent);
  RUN_TEST(test_start_joins_group);
  RUN_TEST(test_first_probe_within_250ms);
  RUN_TEST(test_probe_format);
  RUN_TEST(test_three_probes_250ms_apart);
  RUN_TEST(test_announcement_after_probes);
  RUN_TEST(test_second_announcement_after_1s);
  RUN_TEST(test_announcement_uses_compression);
  RUN_TEST(test_conflict_during_probing);
  RUN_TEST(test_identical_record_is_not_conflict);
  RUN_TEST(test_other_type_same_name_conflicts_while_probing);
  RUN_TEST(test_conflict_callback_can_restart);
  RUN_TEST(test_goodbye_from_other_host_ignored);
  RUN_TEST(test_no_answers_while_probing);
  RUN_TEST(test_a_query_answered_immediately);
  RUN_TEST(test_answers_during_announcing);
  RUN_TEST(test_query_name_case_insensitive);
  RUN_TEST(test_a_record_tracks_address_change);
  RUN_TEST(test_unknown_names_ignored);
  RUN_TEST(test_nsec_for_missing_type);
  RUN_TEST(test_nsec_bitmap_for_instance);
  RUN_TEST(test_nsec_with_positive_answer_in_same_query);
  RUN_TEST(test_no_nsec_where_not_owned);
  RUN_TEST(test_no_nsec_while_probing);
  RUN_TEST(test_ptr_query_delayed_with_additionals);
  RUN_TEST(test_srv_query_with_a_additional);
  RUN_TEST(test_txt_rdata_format);
  RUN_TEST(test_empty_txt_is_single_zero_byte);
  RUN_TEST(test_any_query_returns_all_types_for_name);
  RUN_TEST(test_meta_query_lists_service_types);
  RUN_TEST(test_known_answer_suppression);
  RUN_TEST(test_known_answer_other_rdata_not_suppressed);
  RUN_TEST(test_known_answer_unique_record);
  RUN_TEST(test_qu_question_gets_unicast_reply);
  RUN_TEST(test_legacy_unicast_query);
  RUN_TEST(test_qu_from_unspecified_source_is_multicast);
  RUN_TEST(test_legacy_from_unspecified_source_ignored);
  RUN_TEST(test_responses_not_answered);
  RUN_TEST(test_nonzero_opcode_ignored);
  RUN_TEST(test_malformed_messages_ignored);
  RUN_TEST(test_conflict_while_running);
  RUN_TEST(test_running_other_type_not_conflict);
  RUN_TEST(test_shared_ptr_never_conflicts);
  RUN_TEST(test_stop_sends_goodbye_and_leaves);
  RUN_TEST(test_stop_while_probing_sends_no_goodbye);
  RUN_TEST(test_stop_cancels_pending_response);
  RUN_TEST(test_announcement_split_across_packets);
  RUN_TEST(test_probe_split_across_packets);
  TEST_REPORT();
  return test_failures;
}
