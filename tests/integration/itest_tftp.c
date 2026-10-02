/**
 * @file itest_tftp.c
 * @brief The TFTP client, black box: a server on the wire — RRQ, DATA,
 *        ACK, ERROR and OACK built and read by the peer's own codec below
 *        — and the tftp_client_* API.
 */

#include "itest.h"
#include "tcp.h" /* TCP_MIN_FRAME: the smallest frame buffer net_init() takes */
#include "tftp.h"
#include "udp.h"
#include <string.h>

#define OP_RRQ 1
#define OP_DATA 3
#define OP_ACK 4
#define OP_ERROR 5
#define OP_OACK 6

#define LOCAL_PORT 50000
#define SERVER_TID 40000 /* the server's transfer port */

/* A host that is not the server */
static const uint8_t stray_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x63};

static itest_t t;
static tftp_client_t c;

/* What the application was told */
static int done_calls;
static uint8_t done_ok;
static uint16_t done_code;
static char done_msg[64];
static uint8_t got[2048];
static uint32_t got_len;
static int data_calls;
static uint16_t data_block, data_len;

static void on_done(uint8_t ok, uint16_t code, const char *msg, void *ctx) {
  (void)ctx;
  done_calls++;
  done_ok = ok;
  done_code = code;
  strncpy(done_msg, msg, sizeof(done_msg) - 1);
  done_msg[sizeof(done_msg) - 1] = '\0';
}

static void on_data(uint16_t block, const uint8_t *data, uint16_t len,
                    void *ctx) {
  (void)ctx;
  data_calls++;
  data_block = block;
  data_len = len;
  if (got_len + len <= sizeof(got))
    memcpy(got + got_len, data, len);
  got_len += len;
}

static void on_port(net_t *net, uint32_t src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  tftp_client_input(net, &c, src_ip, src_mac, src_port, data, len);
}

static const udp_port_entry_t ports[] = {{LOCAL_PORT, on_port}};

/* The stack up with frame buffers of @p rx and @p tx bytes, the client
 * initialised and nothing asked for yet */
static void up(uint16_t rx, uint16_t tx) {
  itest_up(&t, rx, tx);
  udp_set_ports(&t.net, ports, 1);
  tftp_client_init(&c, LOCAL_PORT, on_data, on_done, NULL);
  done_calls = data_calls = 0;
  done_ok = 0;
  done_code = 0;
  done_msg[0] = '\0';
  got_len = 0;
}

/* A transfer of @p file started — with the blksize option if
 * @p blksize_opt — and its RRQ forgotten: the wire is clear */
static void start(const char *file, uint8_t blksize_opt) {
  up(1514, 1514);
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, file, blksize_opt);
  wire_clear(&t);
}

/* A transfer of 512-byte blocks started: the RRQ on the wire */
static void get(void) {
  up(1514, 1514);
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "image.bin", 0);
}

/* A TFTP packet from @p ip (at @p mac), port @p port, to the client */
static void from(uint32_t ip, const uint8_t *mac, uint16_t port,
                 const void *pkt, uint16_t len) {
  static uint8_t dgram[1600], f[1700];
  peer_ip_t iph = peer_ip(ip, t.net.ipv4_addr, 17);
  uint16_t n = peer_udp(dgram, &iph, port, LOCAL_PORT, pkt, len);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, mac, &iph, dgram, n));
}

/* A TFTP packet from the server's transfer port */
static void server(const void *pkt, uint16_t len) {
  from(PEER_IP, peer_mac, SERVER_TID, pkt, len);
}

/* DATA @p block of @p n bytes, each (uint8_t)(block + its index) */
static uint16_t make_data(uint8_t *pkt, uint16_t block, uint16_t n) {
  uint16_t i;
  peer_put16(pkt, OP_DATA);
  peer_put16(pkt + 2, block);
  for (i = 0; i < n; i++)
    pkt[4 + i] = (uint8_t)(block + i);
  return (uint16_t)(4 + n);
}

static void data(uint16_t block, uint16_t n) {
  static uint8_t pkt[4 + 1500];
  server(pkt, make_data(pkt, block, n));
}

/* DATA @p block — a full block, so not the last — from the server's TID */
static void data_block_512(uint16_t block) { data(block, 512); }

/* DATA @p block carrying @p n bytes from the server's TID */
static void data_bytes(uint16_t block, const void *bytes, uint16_t n) {
  static uint8_t pkt[4 + 512];
  peer_put16(pkt, OP_DATA);
  peer_put16(pkt + 2, block);
  memcpy(pkt + 4, bytes, n);
  server(pkt, (uint16_t)(4 + n));
}

/* ERROR @p code with @p msg and its NUL */
static uint16_t make_error(uint8_t *pkt, uint16_t code, const char *msg) {
  peer_put16(pkt, OP_ERROR);
  peer_put16(pkt + 2, code);
  memcpy(pkt + 4, msg, strlen(msg) + 1);
  return (uint16_t)(4 + strlen(msg) + 1);
}

/* An OACK whose options are the @p len bytes at @p options: names and
 * values, each with its NUL */
static void oack(const char *options, uint16_t len) {
  uint8_t pkt[128];
  peer_put16(pkt, OP_OACK);
  memcpy(pkt + 2, options, len);
  server(pkt, (uint16_t)(2 + len));
}

/* A packet the client sent */
typedef struct {
  const uint8_t *eth_dst;
  uint32_t dst;
  uint16_t sport, dport;
  uint16_t op, arg; /* the opcode; the block number or error code */
  const uint8_t *pkt;
  uint16_t len;
} sent_t;

/* Frame @p i of those sent, read as TFTP: 1 if it is */
static int sent(uint16_t i, sent_t *s) {
  peer_ip_t ip;
  peer_udp_t udp;
  const wire_frame_t *f = wire_sent(&t, i);
  if (!f || !peer_parse_ipv4(f, &ip) || !peer_parse_udp(&ip, &udp) ||
      !ip.header_cksum_ok || !udp.cksum_ok || udp.data_len < 4)
    return 0;
  s->eth_dst = f->data;
  s->dst = ip.dst;
  s->sport = udp.sport;
  s->dport = udp.dport;
  s->op = peer_get16(udp.data);
  s->arg = peer_get16(udp.data + 2);
  s->pkt = udp.data;
  s->len = udp.data_len;
  return 1;
}

/* 1 if the client sent exactly one packet since the wire was cleared: an
 * ACK of @p block to the server's transfer port — and clears the wire */
static int acked(uint16_t block) {
  sent_t s;
  int ok = t.wire.tx_count == 1 && sent(0, &s) && s.op == OP_ACK &&
           s.arg == block && s.len == 4 && s.dst == PEER_IP &&
           s.dport == SERVER_TID && s.sport == LOCAL_PORT &&
           memcmp(s.eth_dst, peer_mac, 6) == 0;
  wire_clear(&t);
  return ok;
}

/* 1 if the client refused the server's OACK: one ERROR 8 to the server's
 * transfer port, and the application told */
static int refused(void) {
  sent_t s;
  return t.wire.tx_count == 1 && sent(0, &s) && s.op == OP_ERROR &&
         s.arg == TFTP_ERR_OPTION_NEGOTIATION && s.dst == PEER_IP &&
         s.dport == SERVER_TID && s.pkt[s.len - 1] == '\0' && done_calls == 1 &&
         !done_ok && done_code == TFTP_ERR_OPTION_NEGOTIATION &&
         tftp_client_state(&c) == TFTP_STATE_ERROR;
}

/* The opcode of the last packet the client sent, its block in @p block;
 * 0 if it sent none */
static uint16_t last_sent(uint16_t *block) {
  sent_t s;
  if (!t.wire.tx_count || !sent((uint16_t)(t.wire.tx_count - 1u), &s))
    return 0;
  *block = s.arg;
  return s.op;
}

/* Tick @p step ms at a time, at most @p limit ms: the time until the
 * client sends (the wire cleared first); 0 if it does not */
static uint32_t ms_to_send(uint32_t limit, uint32_t step) {
  uint32_t ms;
  wire_clear(&t);
  for (ms = step; ms <= limit; ms += step) {
    tftp_client_tick(&t.net, &c, step);
    if (t.wire.tx_count)
      return ms;
  }
  return 0;
}

/* ── The read request ─────────────────────────────────────────────── */

/* REQ-TFTP-001, 002, 003, 035: the RRQ is opcode 1, the file name and
 * "octet", each with its NUL and nothing after; it goes from the local
 * port to port 69 of the server, at the MAC the application resolved */
TEST(itest_tftp_001_rrq) {
  static const char rrq[] = "\0\1firmware.bin\0octet";
  sent_t s;
  up(1514, 1514);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_IDLE);
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "firmware.bin", 0),
            NET_OK);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.len, sizeof(rrq));
  ASSERT_MEM_EQ(s.pkt, rrq, sizeof(rrq));
  ASSERT_EQ(s.dst, PEER_IP);
  ASSERT_EQ(s.dport, 69);
  ASSERT_EQ(s.sport, LOCAL_PORT);
  ASSERT_MEM_EQ(s.eth_dst, peer_mac, 6);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_REQUESTING);
}

/* REQ-TFTP-001: one transfer at a time — a second request while one runs
 * is refused and sends nothing; when the transfer has ended, the next
 * RRQ goes to port 69 again */
TEST(itest_tftp_001_one_transfer_at_a_time) {
  sent_t s;
  start("a.bin", 0);
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "b.bin", 0),
            NET_ERR_INVALID_PARAM);
  data(1, 512);
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "b.bin", 0),
            NET_ERR_INVALID_PARAM);
  ASSERT_TRUE(acked(1));
  data(2, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_DONE);
  wire_clear(&t);
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "b.bin", 0), NET_OK);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.op, OP_RRQ);
  ASSERT_EQ(s.dport, 69);
  ASSERT_MEM_EQ(s.pkt + 2, "b.bin\0octet", 12);
  /* and the new transfer starts at block 1 */
  wire_clear(&t);
  data(1, 10);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 2);
}

/* REQ-TFTP-001: an RRQ that does not fit the TX frame buffer is not
 * sent, and tftp_client_get() says so */
TEST(itest_tftp_001_rrq_too_long_for_tx_buffer) {
  char name[TFTP_MAX_FILENAME];
  up(1514, TCP_MIN_FRAME);
  memset(name, 'n', sizeof(name) - 1);
  name[sizeof(name) - 1] = '\0';
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, name, 0),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TFTP-004 (RFC 1350 §2, RFC 1123 §4.2.4): netascii is asked for, and
 * the text arrives with local newlines — CR LF as '\n', CR NUL as '\r',
 * also when a block ends between the two */
TEST(itest_tftp_004_netascii) {
  static const char rrq[] = "\0\1text.txt\0netascii\0";
  static uint8_t blk1[512];
  static char want[600];
  sent_t s;
  up(1514, 1514);
  ASSERT_EQ(tftp_client_set_mode(&c, TFTP_MODE_NETASCII), NET_OK);
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "text.txt", 0),
            NET_OK);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.len, sizeof(rrq) - 1);
  ASSERT_MEM_EQ(s.pkt, rrq, sizeof(rrq) - 1);

  memcpy(blk1, "ab\r\ncd\r\0", 8);
  memset(blk1 + 8, 'x', 503);
  blk1[511] = '\r'; /* its LF opens the next block */
  data_bytes(1, blk1, sizeof(blk1));
  data_bytes(2, "\nend\r\n", 6);
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_DONE);
  memcpy(want, "ab\ncd\r", 6);
  memset(want + 6, 'x', 503);
  memcpy(want + 509, "\nend\n", 5);
  ASSERT_EQ(got_len, 514);
  ASSERT_MEM_EQ(got, want, 514);
}

/* REQ-TFTP-004: in netascii a CR followed by neither LF nor NUL stays a
 * CR, and so does one that ends the file */
TEST(itest_tftp_004_netascii_bare_cr) {
  up(1514, 1514);
  tftp_client_set_mode(&c, TFTP_MODE_NETASCII);
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "text.txt", 0);
  data_bytes(1, "a\rb\r", 4);
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(got_len, 4);
  ASSERT_MEM_EQ(got, "a\rb\r", 4);
}

/* REQ-TFTP-004: a CR that ends a block is decided by the next block's
 * first byte — CR NUL across the boundary is one CR, CR and another
 * character are both kept */
TEST(itest_tftp_004_netascii_cr_across_blocks) {
  static uint8_t blk[512];
  up(1514, 1514);
  tftp_client_set_mode(&c, TFTP_MODE_NETASCII);
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "text.txt", 0);
  memset(blk, 'x', 511);
  blk[511] = '\r';
  data_bytes(1, blk, 512);
  blk[0] = '\0'; /* CR NUL: a CR */
  data_bytes(2, blk, 512);
  data_bytes(3, "z", 1); /* CR z: both */
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(got_len, 511 + 1 + 510 + 1 + 1);
  ASSERT_EQ(got[511], '\r');
  ASSERT_EQ(got[512], 'x');
  ASSERT_EQ(got[1022], '\r');
  ASSERT_EQ(got[1023], 'z');
}

/* REQ-TFTP-003, 004: octet stays the default, and the bytes are
 * untouched */
TEST(itest_tftp_004_octet_untouched) {
  sent_t s;
  up(1514, 1514);
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "image.bin", 0);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_MEM_EQ(s.pkt + 2, "image.bin\0octet\0", 16);
  data_bytes(1, "a\r\nb\r", 5);
  ASSERT_EQ(got_len, 5);
  ASSERT_MEM_EQ(got, "a\r\nb\r", 5);
  ASSERT_EQ(tftp_client_set_mode(&c, 7), NET_ERR_INVALID_PARAM);
}

/* ── DATA and ACK ─────────────────────────────────────────────────── */

/* REQ-TFTP-005, 006, 007, 009, 012, 014, 015, 036: the server answers
 * from a port of its own; its DATA 1 reaches the application, and the
 * ACK — opcode 4 and the block number, 4 bytes — goes to that port, not
 * 69, at the server's MAC; so does every ACK after it */
TEST(itest_tftp_005_data_acked_to_the_servers_port) {
  uint8_t want[512];
  uint16_t i;
  start("x", 0);
  data(1, 512);
  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(data_block, 1);
  ASSERT_EQ(data_len, 512);
  for (i = 0; i < 512; i++)
    want[i] = (uint8_t)(1 + i);
  ASSERT_MEM_EQ(got, want, 512);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
  data(2, 512);
  ASSERT_EQ(data_block, 2);
  ASSERT_TRUE(acked(2));
}

/* REQ-TFTP-010, 011: without options a block is 512 bytes — a full one
 * is not the last, a shorter one ends the transfer, acknowledged */
TEST(itest_tftp_010_short_block_ends_the_transfer) {
  start("x", 0);
  data(1, 512);
  ASSERT_EQ(done_calls, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
  wire_clear(&t);
  data(2, 511);
  ASSERT_TRUE(acked(2));
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 1);
  ASSERT_EQ(done_code, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_DONE);
  ASSERT_EQ(got_len, 1023);
}

/* REQ-TFTP-010: a file of a whole number of blocks ends with an empty
 * one, which is acknowledged too */
TEST(itest_tftp_010_empty_block_ends_the_transfer) {
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  data(2, 0);
  ASSERT_TRUE(acked(2));
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 1);
  ASSERT_EQ(got_len, 512);
}

/* REQ-TFTP-010: when the transfer has ended nothing more is taken or
 * answered, and no timer runs */
TEST(itest_tftp_010_nothing_after_the_end) {
  start("x", 0);
  data(1, 100);
  wire_clear(&t);
  data(2, 100);
  tftp_client_tick(&t.net, &c, 60000);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(done_calls, 1);
}

/* REQ-TFTP-007, 008: only DATA with the next block number moves the
 * transfer on — a block from further ahead, or a packet of another kind
 * from the server's port, is neither delivered nor acknowledged */
TEST(itest_tftp_008_only_the_next_block_is_taken) {
  static const uint8_t ack[] = {0, OP_ACK, 0, 2};
  static const uint8_t unknown[] = {0, 9, 0, 2};
  static const uint8_t one_byte[] = {0};
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  data(3, 512);
  server(ack, sizeof(ack));
  server(unknown, sizeof(unknown));
  server(one_byte, sizeof(one_byte));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(data_calls, 1);
  data(2, 512);
  ASSERT_EQ(data_calls, 2);
  ASSERT_TRUE(acked(2));
}

/* REQ-TFTP-008: after block 65535 the next is block 0 — the previous
 * one, a duplicate, is still acknowledged across the wrap */
TEST(itest_tftp_008_block_number_wraps) {
  uint32_t b;
  start("big.bin", 1);
  oack("blksize\0"
       "8",
       10);
  for (b = 1; b <= 65535u; b++)
    data((uint16_t)b, 8);
  ASSERT_EQ(data_calls, 65535);
  wire_clear(&t);
  data(65535u, 8);
  ASSERT_TRUE(acked(65535u));
  data(0, 8);
  ASSERT_EQ(data_block, 0);
  ASSERT_TRUE(acked(0));
  data(1, 3);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_ok, 1);
  ASSERT_EQ(data_calls, 65537);
}

/* REQ-TFTP-013: a block that arrives again — the server missed our ACK —
 * is acknowledged again and not delivered twice */
TEST(itest_tftp_013_duplicate_block_acked_not_delivered) {
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  data(1, 512);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(got_len, 512);
}

/* REQ-TFTP-041: a DATA packet that carries more than the block size in
 * force — 512 without options — is not a block: it is neither delivered
 * nor acknowledged, and the block expected is still taken */
TEST(itest_tftp_041_oversize_data_dropped) {
  start("x", 0);
  data(1, 513);
  ASSERT_EQ(data_calls, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  data(1, 512);
  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(data_len, 512);
  ASSERT_TRUE(acked(1));
}

/* REQ-TFTP-041, 028: nor more than the size the OACK set */
TEST(itest_tftp_041_data_above_the_negotiated_size_dropped) {
  start("x", 1);
  oack("blksize\0"
       "256",
       12);
  wire_clear(&t);
  data(1, 512);
  ASSERT_EQ(data_calls, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(done_calls, 0);
  data(1, 256);
  ASSERT_TRUE(acked(1));
}

/* ── Errors and transfer IDs ──────────────────────────────────────── */

/* REQ-TFTP-016, 017: an ERROR from the server ends the transfer; the
 * application gets its code and message, and nothing is sent back */
TEST(itest_tftp_016_error_ends_the_transfer) {
  uint8_t pkt[64];
  start("missing.bin", 0);
  server(pkt, make_error(pkt, 1, "File not found"));
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(done_code, TFTP_ERR_FILE_NOT_FOUND);
  ASSERT_EQ(strcmp(done_msg, "File not found"), 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_ERROR);
  ASSERT_EQ(t.wire.tx_count, 0);
  /* no retransmission of the RRQ either */
  tftp_client_tick(&t.net, &c, 60000);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TFTP-016: also in the middle of a transfer */
TEST(itest_tftp_016_error_while_receiving) {
  uint8_t pkt[64];
  start("x", 0);
  data(1, 512);
  server(pkt, make_error(pkt, 3, "Disk full"));
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(done_code, TFTP_ERR_DISK_FULL);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_ERROR);
}

/* REQ-TFTP-019: every error code of RFC 1350 is reported as it is */
TEST(itest_tftp_019_every_error_code_reported) {
  static const char *const text[8] = {
      "Not defined",         "File not found",    "Access violation",
      "Disk full",           "Illegal operation", "Unknown transfer ID",
      "File already exists", "No such user"};
  uint8_t pkt[64];
  uint16_t code;
  for (code = 0; code < 8; code++) {
    start("x", 0);
    server(pkt, make_error(pkt, code, text[code]));
    ASSERT_EQ(done_calls, 1);
    ASSERT_EQ(done_ok, 0);
    ASSERT_EQ(done_code, code);
    ASSERT_EQ(strcmp(done_msg, text[code]), 0);
  }
}

/* REQ-TFTP-017: a message whose NUL is not in the datagram is reported
 * as empty — the bytes that follow the datagram in its frame are not
 * the message */
TEST(itest_tftp_017_unterminated_message_reported_empty) {
  static uint8_t dgram[64], f[128];
  uint8_t pkt[32];
  peer_ip_t iph;
  uint16_t n, len;
  start("x", 0);
  iph = peer_ip(PEER_IP, t.net.ipv4_addr, 17);
  n = (uint16_t)(make_error(pkt, 1, "File not found") - 1u); /* no NUL */
  n = peer_udp(dgram, &iph, SERVER_TID, LOCAL_PORT, pkt, n);
  len = peer_ipv4_frame(f, t.net.mac, peer_mac, &iph, dgram, n);
  memcpy(f + len, "!!!", 4); /* a trailer after the IP datagram */
  itest_receive(&t, f, (uint16_t)(len + 4));
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(done_code, 1);
  ASSERT_EQ(strcmp(done_msg, ""), 0);
}

/* REQ-TFTP-016, 017, 007: an ERROR too short for its code, or a DATA too
 * short for its block number, is malformed and dropped — it ends
 * nothing, and is not taken for the server's first answer */
TEST(itest_tftp_017_truncated_packets_dropped) {
  static const uint8_t err2[] = {0, OP_ERROR}, err3[] = {0, OP_ERROR, 0};
  static const uint8_t data3[] = {0, OP_DATA, 0};
  start("x", 0);
  server(err2, sizeof(err2));
  server(err3, sizeof(err3));
  from(PEER_IP, peer_mac, SERVER_TID + 7, data3, sizeof(data3));
  ASSERT_EQ(done_calls, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_REQUESTING);
  data(1, 100);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_ok, 1);
}

/* REQ-TFTP-006: a datagram from port 0 is not the server's answer (a
 * source port of 0 asks for no reply, RFC 768): it is dropped, unanswered,
 * and the port the server does answer from becomes its transfer ID */
TEST(itest_tftp_006_port_0_is_no_transfer_id) {
  uint8_t pkt[4 + 512];
  start("x", 0);
  from(PEER_IP, peer_mac, 0, pkt, make_data(pkt, 1, 512));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(data_calls, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_REQUESTING);
  data(1, 512);
  ASSERT_EQ(data_calls, 1);
  ASSERT_TRUE(acked(1));
}

/* REQ-TFTP-018: a packet from another port of the server is answered
 * with ERROR 5 to that port, and the transfer goes on undisturbed */
TEST(itest_tftp_018_wrong_port_gets_error_5) {
  uint8_t pkt[4 + 512];
  sent_t s;
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  from(PEER_IP, peer_mac, SERVER_TID + 1, pkt, make_data(pkt, 2, 10));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.op, OP_ERROR);
  ASSERT_EQ(s.arg, TFTP_ERR_UNKNOWN_TID);
  ASSERT_EQ(s.pkt[s.len - 1], '\0');
  ASSERT_EQ(s.dst, PEER_IP);
  ASSERT_EQ(s.dport, SERVER_TID + 1);
  ASSERT_EQ(s.sport, LOCAL_PORT);
  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(done_calls, 0);
  wire_clear(&t);
  data(2, 10);
  ASSERT_TRUE(acked(2));
  ASSERT_EQ(done_ok, 1);
}

/* REQ-TFTP-018: a packet from another host is answered with ERROR 5 to
 * that host — its address, its port, the MAC its frame came from */
TEST(itest_tftp_018_wrong_host_gets_error_5) {
  uint8_t pkt[4 + 512];
  sent_t s;
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  from(PEER2_IP, stray_mac, SERVER_TID, pkt, make_data(pkt, 2, 10));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.op, OP_ERROR);
  ASSERT_EQ(s.arg, TFTP_ERR_UNKNOWN_TID);
  ASSERT_EQ(s.dst, PEER2_IP);
  ASSERT_EQ(s.dport, SERVER_TID);
  ASSERT_MEM_EQ(s.eth_dst, stray_mac, 6);
  ASSERT_EQ(data_calls, 1);
  wire_clear(&t);
  data(2, 10);
  ASSERT_TRUE(acked(2));
  ASSERT_EQ(done_ok, 1);
}

/* REQ-TFTP-018, 005: before the server has answered, a packet from
 * another host is a stray too, and does not become the transfer */
TEST(itest_tftp_018_stray_before_the_first_answer) {
  uint8_t pkt[4 + 512];
  sent_t s;
  start("x", 0);
  from(PEER2_IP, stray_mac, 3000, pkt, make_data(pkt, 1, 10));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.op, OP_ERROR);
  ASSERT_EQ(s.arg, TFTP_ERR_UNKNOWN_TID);
  ASSERT_EQ(s.dst, PEER2_IP);
  ASSERT_EQ(s.dport, 3000);
  ASSERT_EQ(data_calls, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_REQUESTING);
  wire_clear(&t);
  data(1, 10);
  ASSERT_TRUE(acked(1));
}

/* REQ-TFTP-018: an ERROR from a stray port is dropped without an answer
 * — two hosts must not exchange ERRORs for ever — and ends nothing */
TEST(itest_tftp_018_stray_error_not_answered) {
  uint8_t pkt[64];
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  from(PEER_IP, peer_mac, SERVER_TID + 1, pkt,
       make_error(pkt, 5, "Unknown transfer ID"));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(done_calls, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
}

/* REQ-TFTP-040 (RFC 1123 §4.2.3.1): the client only reads, so it has no
 * DATA to send again — an ACK from the server, and the same ACK again,
 * draw nothing */
TEST(itest_tftp_040_duplicate_ack_draws_no_data) {
  static const uint8_t ack[] = {0, OP_ACK, 0, 1};
  start("x", 0);
  data(1, 512);
  wire_clear(&t);
  server(ack, sizeof(ack));
  server(ack, sizeof(ack));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
}

/* ── Timeout and retransmission ───────────────────────────────────── */

/* REQ-TFTP-039, 021, 022: an unanswered RRQ goes again after the first
 * timeout (3 s), then each time after twice the wait before (RFC 1123
 * §4.2.3.2) — the same RRQ, to port 69 */
TEST(itest_tftp_039_retransmission_backs_off) {
  uint16_t block;
  sent_t first, again;
  get();
  ASSERT_TRUE(sent(0, &first));
  ASSERT_EQ(ms_to_send(30000, 10), 3000u);
  ASSERT_EQ(last_sent(&block), OP_RRQ);
  ASSERT_TRUE(sent(0, &again));
  ASSERT_EQ(again.dport, 69);
  ASSERT_EQ(again.len, 18);
  ASSERT_MEM_EQ(again.pkt, "\0\1image.bin\0octet", 18);
  ASSERT_EQ(ms_to_send(30000, 10), 6000u);
  ASSERT_EQ(ms_to_send(30000, 10), 12000u);
  ASSERT_EQ(last_sent(&block), OP_RRQ);
}

/* REQ-TFTP-039, 020: a server that answers within 10 ms: the timeout
 * follows its round trips down to the 1 s floor, and a lost block is
 * asked for again — the last ACK repeated — after 1 s */
TEST(itest_tftp_039_timeout_shrinks_for_a_fast_server) {
  uint16_t b, block = 0;
  get();
  for (b = 1; b <= 8; b++) {
    tftp_client_tick(&t.net, &c, 10);
    data_block_512(b);
  }
  ASSERT_EQ(ms_to_send(5000, 10), 1000u);
  ASSERT_EQ(last_sent(&block), OP_ACK);
  ASSERT_EQ(block, 8);
}

/* REQ-TFTP-039: a server slower than the first timeout (4 s round trips):
 * the RRQ is sent again once, then the timeout grows past the round trip
 * and nothing more is (RFC 1123 §4.2.3.2) */
TEST(itest_tftp_039_timeout_grows_for_a_slow_server) {
  uint16_t b;
  uint32_t ms;
  int resent = 0;
  get();
  for (b = 1; b <= 6; b++) {
    wire_clear(&t);
    for (ms = 0; ms < 4000; ms += 100)
      tftp_client_tick(&t.net, &c, 100);
    resent += t.wire.tx_count;
    data_block_512(b);
  }
  ASSERT_EQ(resent, 1);
  ASSERT_EQ(done_calls, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
}

/* REQ-TFTP-039: the timeout doubles up to its ceiling (16 s) and stays
 * there */
TEST(itest_tftp_039_backoff_stops_at_the_ceiling) {
  get();
  ASSERT_EQ(ms_to_send(30000, 100), 3000u);
  ASSERT_EQ(ms_to_send(30000, 100), 6000u);
  ASSERT_EQ(ms_to_send(30000, 100), 12000u);
  ASSERT_EQ(ms_to_send(30000, 100), (uint32_t)TFTP_RTO_MAX_MS);
  ASSERT_EQ(ms_to_send(30000, 100), (uint32_t)TFTP_RTO_MAX_MS);
}

/* REQ-TFTP-020: while DATA is awaited the last ACK is sent again when
 * the timer runs out, to the server's transfer port */
TEST(itest_tftp_020_last_ack_retransmitted) {
  start("x", 0);
  data(1, 512);
  data(2, 512);
  ASSERT_TRUE(ms_to_send(5000, 100) != 0);
  ASSERT_TRUE(acked(2));
}

/* REQ-TFTP-020: only progress restarts the timer — a duplicate block
 * (answered with its ACK), a packet of an unknown kind or a stray does
 * not, so the retransmission comes when it was due */
TEST(itest_tftp_020_timer_restarted_only_by_progress) {
  static const uint8_t unknown[] = {0, 9, 0, 0};
  uint8_t pkt[4 + 512];
  start("x", 0);
  data(1, 512); /* answered at once: the timeout is 1 s from here */
  tftp_client_tick(&t.net, &c, 900);
  data(1, 512);
  server(unknown, sizeof(unknown));
  from(PEER2_IP, stray_mac, 3000, pkt, make_data(pkt, 2, 512));
  wire_clear(&t);
  tftp_client_tick(&t.net, &c, 99);
  ASSERT_EQ(t.wire.tx_count, 0);
  tftp_client_tick(&t.net, &c, 1);
  ASSERT_TRUE(acked(1));
  /* the block expected does restart it */
  tftp_client_tick(&t.net, &c, 1900);
  data(2, 512);
  wire_clear(&t);
  tftp_client_tick(&t.net, &c, 900);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TFTP-023, 024, 021: a silent server is asked 5 more times, then
 * given up on, and the application told: not ok, code 0, "Timeout" */
TEST(itest_tftp_023_gives_up_after_5_retransmissions) {
  uint16_t i, block;
  sent_t s;
  get();
  wire_clear(&t);
  for (i = 0; i < TFTP_MAX_RETRIES; i++) {
    tftp_client_tick(&t.net, &c, TFTP_RTO_MAX_MS);
    ASSERT_EQ(t.wire.tx_count, i + 1);
    ASSERT_EQ(last_sent(&block), OP_RRQ);
    ASSERT_TRUE(sent(i, &s));
    ASSERT_EQ(s.dport, 69);
  }
  ASSERT_EQ(done_calls, 0);
  tftp_client_tick(&t.net, &c, TFTP_RTO_MAX_MS);
  ASSERT_EQ(t.wire.tx_count, TFTP_MAX_RETRIES);
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(done_code, 0);
  ASSERT_EQ(strcmp(done_msg, "Timeout"), 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_ERROR);
  /* and no more after that */
  tftp_client_tick(&t.net, &c, 60000);
  ASSERT_EQ(t.wire.tx_count, TFTP_MAX_RETRIES);
}

/* REQ-TFTP-023, 024, 020: so is a server that only repeats what it sent
 * — each duplicate is acknowledged, none counts as an answer */
TEST(itest_tftp_023_gives_up_on_a_server_that_only_repeats) {
  uint16_t i;
  start("x", 0);
  data(1, 512);
  for (i = 0; i <= TFTP_MAX_RETRIES; i++) {
    ASSERT_EQ(done_calls, 0);
    data(1, 512);
    tftp_client_tick(&t.net, &c, TFTP_RTO_MAX_MS);
  }
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(strcmp(done_msg, "Timeout"), 0);
}

/* ── The blksize option ───────────────────────────────────────────── */

/* The RRQ sent with RX and TX frame buffers of @p rx and 1514 bytes, the
 * blksize option on: its options (after "x" and "octet") in @p options;
 * their length, or -1 */
static int rrq_options(uint16_t rx, const uint8_t **options) {
  sent_t s;
  up(rx, 1514);
  if (tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "x", 1) != NET_OK ||
      !sent(0, &s) || s.op != OP_RRQ || s.len < 10 ||
      memcmp(s.pkt + 2, "x\0octet", 8) != 0)
    return -1;
  *options = s.pkt + 10;
  return s.len - 10;
}

/* REQ-TFTP-025, 026, 037: the block size asked for is the largest DATA
 * the RX frame buffer holds — its size less the Ethernet, IP, UDP and
 * TFTP headers (46 bytes) — and never more than one Ethernet frame
 * carries (1468) */
TEST(itest_tftp_026_blksize_fits_the_rx_buffer) {
  const uint8_t *o = NULL;
  ASSERT_EQ(rrq_options(1514, &o), 13);
  ASSERT_MEM_EQ(o,
                "blksize\0"
                "1468",
                13);
  ASSERT_EQ(rrq_options(2048, &o), 13);
  ASSERT_MEM_EQ(o,
                "blksize\0"
                "1468",
                13);
  ASSERT_EQ(rrq_options(300, &o), 12);
  ASSERT_MEM_EQ(o,
                "blksize\0"
                "254",
                12);
  ASSERT_EQ(rrq_options(1070, &o), 13);
  ASSERT_MEM_EQ(o,
                "blksize\0"
                "1024",
                13);
}

/* REQ-TFTP-025, 011: a buffer that holds exactly the default block asks
 * for nothing, and neither does a transfer started without the option */
TEST(itest_tftp_025_default_size_not_asked_for) {
  const uint8_t *o = NULL;
  sent_t s;
  ASSERT_EQ(rrq_options(558, &o), 0);
  up(1514, 1514);
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "x", 0);
  ASSERT_TRUE(sent(0, &s));
  ASSERT_EQ(s.len, 10);
}

/* REQ-TFTP-027, 028: the server's OACK is acknowledged with ACK 0 to its
 * transfer port, and the block size is the one it gave: a block of that
 * size is not the last, a shorter one is */
TEST(itest_tftp_027_oack_acked_with_block_0) {
  start("x", 1);
  oack("blksize\0"
       "256",
       12);
  ASSERT_TRUE(acked(0));
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
  data(1, 256);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 0);
  data(2, 255);
  ASSERT_TRUE(acked(2));
  ASSERT_EQ(done_ok, 1);
  ASSERT_EQ(got_len, 511);
}

/* REQ-TFTP-028: the option's name is case-insensitive (RFC 2347), and
 * the size asked for may be granted as it is */
TEST(itest_tftp_028_oack_name_in_any_case) {
  start("x", 1);
  oack("BlkSize\0"
       "1468",
       13);
  ASSERT_TRUE(acked(0));
  data(1, 1468);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 0);
  ASSERT_EQ(data_len, 1468);
}

/* REQ-TFTP-027: an OACK that comes again — our ACK 0 was lost — is
 * acknowledged again until DATA 1 arrives, and not after */
TEST(itest_tftp_027_repeated_oack_acked_again) {
  start("x", 1);
  oack("blksize\0"
       "256",
       12);
  wire_clear(&t);
  oack("blksize\0"
       "256",
       12);
  ASSERT_TRUE(acked(0));
  data(1, 256);
  ASSERT_TRUE(acked(1));
  oack("blksize\0"
       "256",
       12);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(done_calls, 0);
}

/* REQ-TFTP-027, 020: ACK 0 is what the timer repeats until DATA 1 */
TEST(itest_tftp_027_ack_0_retransmitted) {
  start("x", 1);
  oack("blksize\0"
       "256",
       12);
  ASSERT_TRUE(ms_to_send(5000, 100) != 0);
  ASSERT_TRUE(acked(0));
}

/* REQ-TFTP-028: a block size above the one asked for is refused with
 * ERROR 8, and the transfer ends */
TEST(itest_tftp_028_larger_blksize_refused) {
  start("x", 1);
  oack("blksize\0"
       "1469",
       13);
  ASSERT_TRUE(refused());
  ASSERT_EQ(strcmp(done_msg, "Bad blksize"), 0);
  ASSERT_EQ(data_calls, 0);
}

/* REQ-TFTP-028, 038: so is one below 8, the least RFC 2348 allows; 8
 * itself is taken */
TEST(itest_tftp_038_blksize_below_8_refused) {
  start("x", 1);
  oack("blksize\0"
       "7",
       10);
  ASSERT_TRUE(refused());
  start("x", 1);
  oack("blksize\0"
       "8",
       10);
  ASSERT_TRUE(acked(0));
  data(1, 8);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 0);
}

/* REQ-TFTP-028: a value that is not all digits is no size — "512abc" is
 * not 512 — nor is a number too long to be one */
TEST(itest_tftp_028_blksize_not_a_number_refused) {
  static const char *const values[] = {
      "512abc", "", " 512", "5 12", "-512", "99999999999999999999"};
  char options[40];
  unsigned i;
  for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    uint16_t n = (uint16_t)(strlen(values[i]) + 1);
    start("x", 1);
    memcpy(options, "blksize", 8);
    memcpy(options + 8, values[i], n);
    oack(options, (uint16_t)(8 + n));
    ASSERT_TRUE(refused());
  }
}

/* REQ-TFTP-028: a blksize the RRQ did not ask for is refused */
TEST(itest_tftp_028_unrequested_blksize_refused) {
  start("x", 0);
  oack("blksize\0"
       "256",
       12);
  ASSERT_TRUE(refused());
}

/* REQ-TFTP-028: so is any option the RRQ did not ask for (RFC 2347: the
 * server acknowledges only what the client requested) */
TEST(itest_tftp_028_unrequested_option_refused) {
  start("x", 1);
  oack("blksize\0"
       "1024\0tsize\0"
       "900",
       23);
  ASSERT_TRUE(refused());
  ASSERT_EQ(strcmp(done_msg, "Option not requested"), 0);
}

/* REQ-TFTP-028: an OACK without blksize declines it — the blocks are 512
 * bytes, and a 512-byte block is not the last */
TEST(itest_tftp_028_oack_without_blksize_means_512) {
  start("x", 1);
  oack("", 0);
  ASSERT_TRUE(acked(0));
  data(1, 512);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 0);
  data(2, 100);
  ASSERT_EQ(done_ok, 1);
  ASSERT_EQ(got_len, 612);
}

/* REQ-TFTP-028: an OACK whose last name or value has no NUL is malformed
 * and dropped: it sets no block size and draws no ACK 0, and the server's
 * well-formed OACK is still taken */
TEST(itest_tftp_028_malformed_oack_dropped) {
  start("x", 1);
  oack("blksize\0"
       "256",
       11); /* the value unterminated */
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(done_calls, 0);
  oack("blksize", 7); /* a name alone, unterminated */
  oack("blksize", 8); /* a name without its value */
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_REQUESTING);
  oack("blksize\0"
       "256",
       12);
  ASSERT_TRUE(acked(0));
  data(1, 256);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 0);
}

/* REQ-TFTP-031: a server that knows no options answers the RRQ with
 * DATA 1: the blocks are 512 bytes, whatever was asked for */
TEST(itest_tftp_031_data_instead_of_oack_means_512) {
  start("x", 1);
  data(1, 512);
  ASSERT_TRUE(acked(1));
  ASSERT_EQ(done_calls, 0);
  data(2, 511);
  ASSERT_TRUE(acked(2));
  ASSERT_EQ(done_ok, 1);
}

int main(void) {
  fprintf(stderr, "=== itest_tftp ===\n");
  RUN_TEST(itest_tftp_001_rrq);
  RUN_TEST(itest_tftp_001_one_transfer_at_a_time);
  RUN_TEST(itest_tftp_001_rrq_too_long_for_tx_buffer);
  RUN_TEST(itest_tftp_004_netascii);
  RUN_TEST(itest_tftp_004_netascii_bare_cr);
  RUN_TEST(itest_tftp_004_netascii_cr_across_blocks);
  RUN_TEST(itest_tftp_004_octet_untouched);
  RUN_TEST(itest_tftp_005_data_acked_to_the_servers_port);
  RUN_TEST(itest_tftp_010_short_block_ends_the_transfer);
  RUN_TEST(itest_tftp_010_empty_block_ends_the_transfer);
  RUN_TEST(itest_tftp_010_nothing_after_the_end);
  RUN_TEST(itest_tftp_008_only_the_next_block_is_taken);
  RUN_TEST(itest_tftp_008_block_number_wraps);
  RUN_TEST(itest_tftp_013_duplicate_block_acked_not_delivered);
  RUN_TEST(itest_tftp_041_oversize_data_dropped);
  RUN_TEST(itest_tftp_041_data_above_the_negotiated_size_dropped);
  RUN_TEST(itest_tftp_016_error_ends_the_transfer);
  RUN_TEST(itest_tftp_016_error_while_receiving);
  RUN_TEST(itest_tftp_019_every_error_code_reported);
  RUN_TEST(itest_tftp_017_unterminated_message_reported_empty);
  RUN_TEST(itest_tftp_017_truncated_packets_dropped);
  RUN_TEST(itest_tftp_006_port_0_is_no_transfer_id);
  RUN_TEST(itest_tftp_018_wrong_port_gets_error_5);
  RUN_TEST(itest_tftp_018_wrong_host_gets_error_5);
  RUN_TEST(itest_tftp_018_stray_before_the_first_answer);
  RUN_TEST(itest_tftp_018_stray_error_not_answered);
  RUN_TEST(itest_tftp_040_duplicate_ack_draws_no_data);
  RUN_TEST(itest_tftp_039_retransmission_backs_off);
  RUN_TEST(itest_tftp_039_timeout_shrinks_for_a_fast_server);
  RUN_TEST(itest_tftp_039_timeout_grows_for_a_slow_server);
  RUN_TEST(itest_tftp_039_backoff_stops_at_the_ceiling);
  RUN_TEST(itest_tftp_020_last_ack_retransmitted);
  RUN_TEST(itest_tftp_020_timer_restarted_only_by_progress);
  RUN_TEST(itest_tftp_023_gives_up_after_5_retransmissions);
  RUN_TEST(itest_tftp_023_gives_up_on_a_server_that_only_repeats);
  RUN_TEST(itest_tftp_026_blksize_fits_the_rx_buffer);
  RUN_TEST(itest_tftp_025_default_size_not_asked_for);
  RUN_TEST(itest_tftp_027_oack_acked_with_block_0);
  RUN_TEST(itest_tftp_028_oack_name_in_any_case);
  RUN_TEST(itest_tftp_027_repeated_oack_acked_again);
  RUN_TEST(itest_tftp_027_ack_0_retransmitted);
  RUN_TEST(itest_tftp_028_larger_blksize_refused);
  RUN_TEST(itest_tftp_038_blksize_below_8_refused);
  RUN_TEST(itest_tftp_028_blksize_not_a_number_refused);
  RUN_TEST(itest_tftp_028_unrequested_blksize_refused);
  RUN_TEST(itest_tftp_028_unrequested_option_refused);
  RUN_TEST(itest_tftp_028_oack_without_blksize_means_512);
  RUN_TEST(itest_tftp_028_malformed_oack_dropped);
  RUN_TEST(itest_tftp_031_data_instead_of_oack_means_512);
  ITEST_REPORT();
  return test_failures;
}
