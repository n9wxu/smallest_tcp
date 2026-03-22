/**
 * @file test_tftp.c
 * @brief Unit tests for the TFTP client (RFC 1350 / RFC 2348).
 *
 * Tests cover:
 *   REQ-TFTP-001..003  RRQ format (opcode, filename, "octet" mode)
 *   REQ-TFTP-002       RRQ sent to port 69
 *   REQ-TFTP-005,006   Server TID recorded from first DATA reply
 *   REQ-TFTP-007..010  DATA reception: ACK, last-block detection
 *   REQ-TFTP-011       Default block size 512
 *   REQ-TFTP-012       Data delivered to application callback
 *   REQ-TFTP-013       Duplicate block re-ACK (no double delivery)
 *   REQ-TFTP-014,015   ACK format and destination port (server TID)
 *   REQ-TFTP-016,017   ERROR packet → abort + error callback
 *   REQ-TFTP-018       Wrong TID → ERROR(5) sent
 *   REQ-TFTP-020,021   Tick retransmits last ACK / RRQ
 *   REQ-TFTP-023,024   Max retries → timeout reported
 *   REQ-TFTP-025,026   blksize option in RRQ
 *   REQ-TFTP-027,028   OACK: ACK(0) sent, blksize updated
 *   REQ-TFTP-031       Server ignores blksize option (DATA(1) without OACK)
 */

#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "tftp.h"
#include "udp.h"
#include <string.h>

/* ── Stub MAC driver ──────────────────────────────────────────────── */

#define MAX_SENT_FRAMES 16
static uint8_t sent_frames[MAX_SENT_FRAMES][1514];
static uint16_t sent_lens[MAX_SENT_FRAMES];
static int send_count;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}

static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  if (send_count < MAX_SENT_FRAMES) {
    memcpy(sent_frames[send_count], f, l);
    sent_lens[send_count] = l;
    send_count++;
  }
  return (int)l;
}

/* Stub rx frame (for peek — unused in TFTP unit tests) */
static uint8_t stub_rx[1514];

static int stub_peek(void *ctx, uint16_t off, uint8_t *buf, uint16_t len) {
  (void)ctx;
  if (off >= sizeof(stub_rx))
    return -1;
  uint16_t avail = (uint16_t)(sizeof(stub_rx) - off);
  if (len > avail)
    len = avail;
  memcpy(buf, stub_rx + off, len);
  return (int)len;
}

static const net_mac_t stub_drv = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Shared test state ────────────────────────────────────────────── */

static uint8_t net_rx_mem[1514], net_tx_mem[1514];
static net_t net;
static int ctx_dummy;

static tftp_client_t client;

/* Callback tracking */
static int data_calls;
static uint16_t data_blocks[32];
static uint16_t data_lens[32];
static uint8_t data_buf[32][600];

static int done_called;
static uint8_t done_ok;
static uint16_t done_err_code;
static char done_msg[128];

static void on_data(uint16_t block, const uint8_t *d, uint16_t len, void *ctx) {
  (void)ctx;
  if (data_calls < 32) {
    data_blocks[data_calls] = block;
    data_lens[data_calls] = len;
    uint16_t copy = (len < 600) ? len : 600;
    memcpy(data_buf[data_calls], d, copy);
    data_calls++;
  }
}

static void on_done(uint8_t ok, uint16_t code, const char *msg, void *ctx) {
  (void)ctx;
  done_called = 1;
  done_ok = ok;
  done_err_code = code;
  if (msg) {
    size_t l = strlen(msg);
    if (l >= sizeof(done_msg))
      l = sizeof(done_msg) - 1;
    memcpy(done_msg, msg, l);
    done_msg[l] = '\0';
  } else {
    done_msg[0] = '\0';
  }
}

static const uint32_t SERVER_IP = (10u << 24) | (0u << 16) | (0u << 8) | 1u;
static const uint8_t SERVER_MAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
#define CLIENT_PORT 6900u
#define SERVER_TID 4567u /* server's ephemeral port */

static void setup(void) {
  memset(&net, 0, sizeof(net));
  memset(sent_frames, 0, sizeof(sent_frames));
  memset(sent_lens, 0, sizeof(sent_lens));
  send_count = 0;
  data_calls = 0;
  done_called = 0;
  done_ok = 0;
  done_err_code = 0;
  done_msg[0] = '\0';

  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, &stub_drv, &ctx_dummy);

  tftp_client_init(&client, CLIENT_PORT, on_data, on_done, NULL);
}

/* ── Helpers to inspect sent UDP frames ──────────────────────────── */

/* Returns pointer to TFTP payload of sent frame [idx], sets *len */
static const uint8_t *get_tftp_payload(int idx, uint16_t *out_len) {
  /* ETH(14) + IP(20) + UDP(8) = 42 bytes of header before TFTP */
  if (sent_lens[idx] < 42) {
    *out_len = 0;
    return NULL;
  }
  *out_len = (uint16_t)(sent_lens[idx] - 42u);
  return sent_frames[idx] + 42;
}

static uint16_t get_udp_dport(int idx) {
  /* ETH(14) + IP(20) + UDP dport at byte 2 */
  if (sent_lens[idx] < 14 + 20 + 4)
    return 0;
  return net_read16be(sent_frames[idx] + 14 + 20 + 2);
}

/* Build a raw TFTP DATA packet (used as input to tftp_client_input) */
static uint16_t make_data(uint8_t *buf, uint16_t block, const uint8_t *data,
                          uint16_t dlen) {
  net_write16be(buf, TFTP_OP_DATA);
  net_write16be(buf + 2, block);
  memcpy(buf + 4, data, dlen);
  return (uint16_t)(4u + dlen);
}

static uint16_t make_error(uint8_t *buf, uint16_t code, const char *msg) {
  net_write16be(buf, TFTP_OP_ERROR);
  net_write16be(buf + 2, code);
  size_t mlen = strlen(msg);
  memcpy(buf + 4, msg, mlen);
  buf[4 + mlen] = '\0';
  return (uint16_t)(4 + mlen + 1);
}

static uint16_t make_oack_blksize(uint8_t *buf, uint16_t blksize) {
  /* OACK: opcode(2) + "blksize\0<value>\0" */
  net_write16be(buf, TFTP_OP_OACK);
  uint16_t pos = 2;
  memcpy(buf + pos, "blksize", 7);
  pos += 7;
  buf[pos++] = '\0';
  /* decimal value */
  char tmp[8];
  uint8_t ti = 0;
  uint16_t v = blksize;
  if (v == 0) {
    tmp[ti++] = '0';
  } else {
    uint8_t s = ti;
    while (v > 0) {
      tmp[ti++] = (char)('0' + (v % 10));
      v /= 10;
    }
    uint8_t lo = s, hi = (uint8_t)(ti - 1);
    while (lo < hi) {
      char t = tmp[lo];
      tmp[lo] = tmp[hi];
      tmp[hi] = t;
      lo++;
      hi--;
    }
  }
  memcpy(buf + pos, tmp, ti);
  pos += ti;
  buf[pos++] = '\0';
  return pos;
}

/* ════════════════════════════════════════════════════════════════════
 * Tests
 * ════════════════════════════════════════════════════════════════════ */

/* REQ-TFTP-001,002,003 — RRQ format */
TEST(test_tftp_rrq_format) {
  setup();
  net_err_t err =
      tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "firmware.bin", 0);
  ASSERT_EQ(err, NET_OK);
  ASSERT_EQ(send_count, 1);

  uint16_t plen;
  const uint8_t *p = get_tftp_payload(0, &plen);
  ASSERT_NE(p, NULL);

  /* REQ-TFTP-001: opcode 1 */
  ASSERT_EQ(net_read16be(p), (uint16_t)TFTP_OP_RRQ);

  /* Filename "firmware.bin\0" */
  ASSERT_EQ(memcmp(p + 2, "firmware.bin", 12), 0);
  ASSERT_EQ(p[14], '\0');

  /* REQ-TFTP-003: mode "octet\0" */
  ASSERT_EQ(memcmp(p + 15, "octet", 5), 0);
  ASSERT_EQ(p[20], '\0');

  /* REQ-TFTP-002: sent to server port 69 */
  ASSERT_EQ(get_udp_dport(0), (uint16_t)TFTP_SERVER_PORT);

  ASSERT_EQ(client.state, TFTP_STATE_REQUESTING);
}

/* REQ-TFTP-011 — default block size 512 */
TEST(test_tftp_default_blksize) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  ASSERT_EQ(client.blksize, (uint16_t)TFTP_DEFAULT_BLKSIZE);
}

/* REQ-TFTP-005,006,007,008,009,012 — DATA(1) received → ACK(1), callback */
TEST(test_tftp_data_block1_ack) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  send_count = 0; /* clear the RRQ */

  uint8_t payload[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, payload, 10);

  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  /* REQ-TFTP-012: data callback called */
  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(data_blocks[0], 1);
  ASSERT_EQ(data_lens[0], 10);
  ASSERT_MEM_EQ(data_buf[0], payload, 10);

  /* REQ-TFTP-009: ACK sent */
  ASSERT_EQ(send_count, 1);
  uint16_t alen;
  const uint8_t *a = get_tftp_payload(0, &alen);
  ASSERT_NE(a, NULL);
  ASSERT_EQ(net_read16be(a), (uint16_t)TFTP_OP_ACK);
  ASSERT_EQ(net_read16be(a + 2), (uint16_t)1);

  /* REQ-TFTP-015: ACK sent to server TID, not 69 */
  ASSERT_EQ(get_udp_dport(0), (uint16_t)SERVER_TID);

  /* REQ-TFTP-006: server TID recorded */
  ASSERT_EQ(client.server_tid, (uint16_t)SERVER_TID);

  /* State still RECEIVING (block < 512 bytes but == blksize check deferred
   * until we see a short block) */
  /* NOTE: 10 bytes < 512 = last block, so actually done */
  ASSERT_EQ(client.state, TFTP_STATE_DONE);
  ASSERT_EQ(done_called, 1);
  ASSERT_EQ(done_ok, 1);
}

/* REQ-TFTP-010 — last block is exactly blksize bytes (next block needed) */
TEST(test_tftp_full_block_not_last) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  send_count = 0;

  /* Send a full 512-byte block — NOT the last block */
  uint8_t payload[512];
  memset(payload, 0xAB, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, payload, 512);

  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  ASSERT_EQ(data_calls, 1);
  ASSERT_EQ(data_lens[0], 512);
  ASSERT_EQ(done_called, 0); /* not finished yet */
  ASSERT_EQ(client.state, TFTP_STATE_RECEIVING);
  ASSERT_EQ(client.next_block, (uint16_t)2); /* advanced */
}

/* REQ-TFTP-010 — short final block → done */
TEST(test_tftp_last_block_short) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  send_count = 0;

  /* Full block 1 */
  uint8_t full[512];
  memset(full, 0x11, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, full, 512);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  /* Short block 2 (100 bytes = last) */
  uint8_t last[100];
  memset(last, 0x22, 100);
  plen = make_data(pkt, 2, last, 100);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  ASSERT_EQ(data_calls, 2);
  ASSERT_EQ(data_lens[1], 100);
  ASSERT_EQ(done_called, 1);
  ASSERT_EQ(done_ok, 1);
  ASSERT_EQ(client.state, TFTP_STATE_DONE);
}

/* REQ-TFTP-013 — duplicate block re-ACK without re-delivery */
TEST(test_tftp_duplicate_block) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  send_count = 0;

  /* First full block */
  uint8_t full[512];
  memset(full, 0x55, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, full, 512);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);
  ASSERT_EQ(data_calls, 1);

  send_count = 0;

  /* Duplicate block 1 */
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  /* REQ-TFTP-013: re-ACK but no new data delivery */
  ASSERT_EQ(data_calls, 1); /* still only 1 delivery */
  ASSERT_EQ(send_count, 1); /* but ACK was sent */
  uint16_t alen;
  const uint8_t *a = get_tftp_payload(0, &alen);
  ASSERT_EQ(net_read16be(a + 2), (uint16_t)1); /* ACK 1 again */
}

/* REQ-TFTP-016,017 — ERROR from server → abort */
TEST(test_tftp_error_packet_aborts) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "missing.bin", 0);
  send_count = 0;

  uint8_t pkt[128];
  uint16_t plen = make_error(pkt, TFTP_ERR_FILE_NOT_FOUND, "File not found");
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  ASSERT_EQ(done_called, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(done_err_code, (uint16_t)TFTP_ERR_FILE_NOT_FOUND);
  ASSERT_EQ(client.state, TFTP_STATE_ERROR);
}

/* REQ-TFTP-018 — wrong TID → ERROR(5) sent, transfer continues */
TEST(test_tftp_wrong_tid_sends_error5) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);

  /* First packet sets server TID */
  uint8_t full[512];
  memset(full, 0xCC, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, full, 512);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  send_count = 0;

  /* Packet from a DIFFERENT source port (wrong TID) */
  uint16_t wrong_tid = SERVER_TID + 1u;
  uint8_t small[10];
  memset(small, 0, 10);
  plen = make_data(pkt, 2, small, 10);
  tftp_client_input(&net, &client, SERVER_IP, wrong_tid, pkt, plen);

  /* REQ-TFTP-018: ERROR(5) was sent */
  ASSERT_TRUE(send_count >= 1);
  uint16_t elen;
  const uint8_t *e = get_tftp_payload(0, &elen);
  ASSERT_NE(e, NULL);
  ASSERT_EQ(net_read16be(e), (uint16_t)TFTP_OP_ERROR);
  ASSERT_EQ(net_read16be(e + 2), (uint16_t)TFTP_ERR_UNKNOWN_TID);

  /* Transfer did NOT advance (block from wrong TID discarded) */
  ASSERT_EQ(client.state, TFTP_STATE_RECEIVING);
}

/* REQ-TFTP-027,028 — OACK: blksize updated, ACK(0) sent */
TEST(test_tftp_oack_updates_blksize) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x",
                  1); /* blksize_opt=1 */
  send_count = 0;

  uint8_t oack[64];
  uint16_t olen = make_oack_blksize(oack, 256);

  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, oack, olen);

  /* REQ-TFTP-028: blksize updated */
  ASSERT_EQ(client.blksize, (uint16_t)256);

  /* REQ-TFTP-027: ACK(0) sent */
  ASSERT_EQ(send_count, 1);
  uint16_t alen;
  const uint8_t *a = get_tftp_payload(0, &alen);
  ASSERT_NE(a, NULL);
  ASSERT_EQ(net_read16be(a), (uint16_t)TFTP_OP_ACK);
  ASSERT_EQ(net_read16be(a + 2), (uint16_t)0);

  ASSERT_EQ(client.state, TFTP_STATE_RECEIVING);
}

/* REQ-TFTP-031 — server sends DATA(1) without OACK: fall back to 512 */
TEST(test_tftp_fallback_no_oack) {
  setup();
  /* Request with blksize_opt=1; server ignores option and sends DATA(1) */
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 1);
  /* Pretend server agreed to 1000-byte blocks (our request) */
  uint16_t negotiated = client.blksize;
  send_count = 0;

  /* Server sends DATA block 1 without OACK — uses its default 512 */
  uint8_t payload[512];
  memset(payload, 0x77, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, payload, 512);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);

  (void)negotiated; /* silence unused warning */

  /* REQ-TFTP-031: blksize reset to 512 */
  ASSERT_EQ(client.blksize, (uint16_t)TFTP_DEFAULT_BLKSIZE);
  ASSERT_EQ(client.state, TFTP_STATE_RECEIVING); /* full block, not done */
}

/* REQ-TFTP-025,026 — blksize option appears in RRQ when enabled */
TEST(test_tftp_rrq_contains_blksize_option) {
  setup();
  /* Force a specific tx buf size that gives a known max blksize */
  /* Default tx buf is 1514 bytes; max_blk = 1514 - 14 - 20 - 8 - 4 = 1468 */
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 1);

  uint16_t plen;
  const uint8_t *p = get_tftp_payload(0, &plen);
  ASSERT_NE(p, NULL);
  ASSERT_EQ(net_read16be(p), (uint16_t)TFTP_OP_RRQ);

  /* Scan for "blksize" option string in the packet */
  int found = 0;
  uint16_t i;
  for (i = 2; i + 8 < plen; i++) {
    if (memcmp(p + i, "blksize", 7) == 0 && p[i + 7] == '\0') {
      found = 1;
      break;
    }
  }
  ASSERT_TRUE(found);
}

/* REQ-TFTP-021 — tick retransmits RRQ while in REQUESTING state */
TEST(test_tftp_tick_retransmits_rrq) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  ASSERT_EQ(send_count, 1); /* initial RRQ */
  send_count = 0;

  /* Advance time past timeout */
  tftp_client_tick(&net, &client, TFTP_TIMEOUT_MS + 1u);

  /* REQ-TFTP-021: RRQ retransmitted */
  ASSERT_EQ(send_count, 1);
  uint16_t plen;
  const uint8_t *p = get_tftp_payload(0, &plen);
  ASSERT_EQ(net_read16be(p), (uint16_t)TFTP_OP_RRQ);
  ASSERT_EQ(client.retries, (uint8_t)1);
}

/* REQ-TFTP-020 — tick retransmits last ACK while in RECEIVING state */
TEST(test_tftp_tick_retransmits_ack) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);

  /* Receive full block 1 */
  uint8_t full[512];
  memset(full, 0xAA, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, full, 512);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);
  ASSERT_EQ(client.state, TFTP_STATE_RECEIVING);
  send_count = 0;

  tftp_client_tick(&net, &client, TFTP_TIMEOUT_MS + 1u);

  /* REQ-TFTP-020: ACK(1) re-sent */
  ASSERT_EQ(send_count, 1);
  uint16_t alen;
  const uint8_t *a = get_tftp_payload(0, &alen);
  ASSERT_EQ(net_read16be(a), (uint16_t)TFTP_OP_ACK);
  ASSERT_EQ(net_read16be(a + 2), (uint16_t)1);
}

/* REQ-TFTP-023,024 — max retries exceeded → timeout failure */
TEST(test_tftp_max_retries_timeout) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  ASSERT_EQ(client.state, TFTP_STATE_REQUESTING);

  /* Drive TFTP_MAX_RETRIES + 1 timeouts */
  uint8_t i;
  for (i = 0; i <= TFTP_MAX_RETRIES; i++) {
    tftp_client_tick(&net, &client, TFTP_TIMEOUT_MS + 1u);
  }

  ASSERT_EQ(done_called, 1);
  ASSERT_EQ(done_ok, 0);
  ASSERT_EQ(client.state, TFTP_STATE_ERROR);
}

/* REQ-TFTP-020 — timer does NOT fire if packet received before timeout */
TEST(test_tftp_timer_reset_on_data) {
  setup();
  tftp_client_get(&net, &client, SERVER_IP, SERVER_MAC, "x", 0);
  send_count = 0;

  /* Advance partway through the timeout */
  tftp_client_tick(&net, &client, TFTP_TIMEOUT_MS / 2u);
  ASSERT_EQ(send_count, 0); /* no retransmit yet */

  /* Receive a packet — resets timer */
  uint8_t full[512];
  memset(full, 0, 512);
  uint8_t pkt[600];
  uint16_t plen = make_data(pkt, 1, full, 512);
  tftp_client_input(&net, &client, SERVER_IP, SERVER_TID, pkt, plen);
  send_count = 0;

  /* Advance less than one full timeout after the reset */
  tftp_client_tick(&net, &client, TFTP_TIMEOUT_MS / 2u);
  ASSERT_EQ(send_count, 0); /* still no retransmit */
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_tftp ===\n");
  RUN_TEST(test_tftp_rrq_format);
  RUN_TEST(test_tftp_default_blksize);
  RUN_TEST(test_tftp_data_block1_ack);
  RUN_TEST(test_tftp_full_block_not_last);
  RUN_TEST(test_tftp_last_block_short);
  RUN_TEST(test_tftp_duplicate_block);
  RUN_TEST(test_tftp_error_packet_aborts);
  RUN_TEST(test_tftp_wrong_tid_sends_error5);
  RUN_TEST(test_tftp_oack_updates_blksize);
  RUN_TEST(test_tftp_fallback_no_oack);
  RUN_TEST(test_tftp_rrq_contains_blksize_option);
  RUN_TEST(test_tftp_tick_retransmits_rrq);
  RUN_TEST(test_tftp_tick_retransmits_ack);
  RUN_TEST(test_tftp_max_retries_timeout);
  RUN_TEST(test_tftp_timer_reset_on_data);
  TEST_REPORT();
  return test_failures;
}
