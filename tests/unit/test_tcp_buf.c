/**
 * @file test_tcp_buf.c
 * @brief Unit tests for the TCP stop-and-wait buffer (tcp_buf_saw.c).
 *
 * These tests exercise the vtable contract defined in tcp_buf.h and the
 * concrete SAW implementation. They do not depend on tcp.c — they test
 * the buffer layer in complete isolation.
 *
 * REQ-TCP-142..145.
 */

#include "tcp_buf.h"
#include "test_main.h"
#include <string.h>

/* ── Helpers ─────────────────────────────────────────────────────── */

#define BUF_SIZE 64u

static uint8_t tx_mem[BUF_SIZE];
static uint8_t rx_mem[BUF_SIZE];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;

static void setup_tx(void) {
  memset(tx_mem, 0, sizeof(tx_mem));
  tcp_saw_tx_init(&tx_ctx, tx_mem, BUF_SIZE);
}

static void setup_rx(void) {
  memset(rx_mem, 0, sizeof(rx_mem));
  tcp_saw_rx_init(&rx_ctx, rx_mem, BUF_SIZE);
}

/* ══════════════════════════════════════════════════════════════════
 * TX buffer tests
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_saw_tx_init_state) {
  setup_tx();
  /* After init: nothing in-flight, full capacity writable */
  ASSERT_EQ(tcp_saw_tx_ops.in_flight(&tx_ctx), 0);
  ASSERT_EQ(tcp_saw_tx_ops.writable(&tx_ctx), BUF_SIZE);
}

TEST(test_saw_tx_write_basic) {
  setup_tx();
  uint8_t data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  uint16_t n = tcp_saw_tx_ops.write(&tx_ctx, data, 10);
  ASSERT_EQ(n, 10);
  ASSERT_EQ(tcp_saw_tx_ops.writable(&tx_ctx), (uint16_t)(BUF_SIZE - 10));
}

TEST(test_saw_tx_write_clamped_to_capacity) {
  setup_tx();
  /* Try writing more than capacity */
  uint8_t data[BUF_SIZE + 20];
  memset(data, 0xAA, sizeof(data));
  uint16_t n = tcp_saw_tx_ops.write(&tx_ctx, data, sizeof(data));
  ASSERT_EQ(n, BUF_SIZE); /* Clamped to capacity */
}

TEST(test_saw_tx_next_segment_basic) {
  setup_tx();
  uint8_t data[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01};
  tcp_saw_tx_ops.write(&tx_ctx, data, 8);

  const uint8_t *seg = NULL;
  uint16_t len = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460);
  ASSERT_EQ(len, 8);
  ASSERT_TRUE(seg != NULL);
  ASSERT_MEM_EQ(seg, data, 8);

  /* After next_segment: in_flight == data_len */
  ASSERT_EQ(tcp_saw_tx_ops.in_flight(&tx_ctx), 8);
  /* While in-flight: no more segments, no writability */
  ASSERT_EQ(tcp_saw_tx_ops.writable(&tx_ctx), 0);
}

TEST(test_saw_tx_next_segment_mss_clamping) {
  setup_tx();
  uint8_t data[20];
  memset(data, 0x55, sizeof(data));
  tcp_saw_tx_ops.write(&tx_ctx, data, 20);

  const uint8_t *seg = NULL;
  uint16_t len = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 10); /* MSS=10 */
  ASSERT_EQ(len, 10); /* Clamped to MSS */
}

TEST(test_saw_tx_no_segment_when_empty) {
  setup_tx();
  const uint8_t *seg = NULL;
  uint16_t len = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460);
  ASSERT_EQ(len, 0);
}

TEST(test_saw_tx_no_segment_when_in_flight) {
  setup_tx();
  uint8_t data[4] = {1, 2, 3, 4};
  tcp_saw_tx_ops.write(&tx_ctx, data, 4);

  const uint8_t *seg = NULL;
  tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460); /* puts in flight */

  /* Second call must return 0 — stop and wait */
  uint16_t len = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460);
  ASSERT_EQ(len, 0);
}

TEST(test_saw_tx_write_blocked_when_in_flight) {
  setup_tx();
  uint8_t data[4] = {1, 2, 3, 4};
  tcp_saw_tx_ops.write(&tx_ctx, data, 4);

  const uint8_t *seg = NULL;
  tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460); /* in flight */

  /* Cannot write new data while in flight */
  uint16_t n = tcp_saw_tx_ops.write(&tx_ctx, data, 4);
  ASSERT_EQ(n, 0);
}

TEST(test_saw_tx_ack_full_clears_buffer) {
  setup_tx();
  uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  tcp_saw_tx_ops.write(&tx_ctx, data, 8);

  const uint8_t *seg = NULL;
  tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460);
  tcp_saw_tx_ops.ack(&tx_ctx, 8); /* ACK all 8 bytes */

  ASSERT_EQ(tcp_saw_tx_ops.in_flight(&tx_ctx), 0);
  ASSERT_EQ(tcp_saw_tx_ops.writable(&tx_ctx), BUF_SIZE);
}

TEST(test_saw_tx_ack_partial_shifts_buffer) {
  setup_tx();
  uint8_t data[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
  tcp_saw_tx_ops.write(&tx_ctx, data, 8);

  const uint8_t *seg = NULL;
  tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460);
  tcp_saw_tx_ops.ack(&tx_ctx, 4); /* Partial ACK: 4 bytes */

  /* 4 bytes remain; in_flight cleared (allow resend) */
  ASSERT_EQ(tcp_saw_tx_ops.in_flight(&tx_ctx), 0);

  /* Remaining data is the un-ACKed tail */
  const uint8_t *seg2 = NULL;
  uint16_t len2 = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg2, 1460);
  ASSERT_EQ(len2, 4);
  ASSERT_EQ(seg2[0], 0x50);
  ASSERT_EQ(seg2[3], 0x80);
}

TEST(test_saw_tx_mark_retransmit) {
  setup_tx();
  uint8_t data[4] = {0xAA, 0xBB, 0xCC, 0xDD};
  tcp_saw_tx_ops.write(&tx_ctx, data, 4);

  const uint8_t *seg = NULL;
  uint16_t len1 = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg, 1460);
  ASSERT_EQ(len1, 4);
  ASSERT_EQ(tcp_saw_tx_ops.in_flight(&tx_ctx), 4);

  /* Timeout — mark for retransmit */
  tcp_saw_tx_ops.mark_retransmit(&tx_ctx);
  ASSERT_EQ(tcp_saw_tx_ops.in_flight(&tx_ctx), 0);

  /* next_segment returns the same data again */
  const uint8_t *seg2 = NULL;
  uint16_t len2 = tcp_saw_tx_ops.next_segment(&tx_ctx, &seg2, 1460);
  ASSERT_EQ(len2, 4);
  ASSERT_MEM_EQ(seg2, data, 4);
}

/* ══════════════════════════════════════════════════════════════════
 * RX buffer tests
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_saw_rx_init_state) {
  setup_rx();
  ASSERT_EQ(tcp_saw_rx_ops.readable(&rx_ctx), 0);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), BUF_SIZE);
}

TEST(test_saw_rx_deliver_basic) {
  setup_rx();
  uint8_t data[6] = {10, 20, 30, 40, 50, 60};
  uint16_t n = tcp_saw_rx_ops.deliver(&rx_ctx, data, 6);
  ASSERT_EQ(n, 6);
  ASSERT_EQ(tcp_saw_rx_ops.readable(&rx_ctx), 6);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), (uint16_t)(BUF_SIZE - 6));
}

TEST(test_saw_rx_deliver_clamped_when_full) {
  setup_rx();
  uint8_t data[BUF_SIZE + 10];
  memset(data, 0x77, sizeof(data));
  uint16_t n = tcp_saw_rx_ops.deliver(&rx_ctx, data, sizeof(data));
  ASSERT_EQ(n, BUF_SIZE); /* Clamped to capacity */
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), 0);
}

TEST(test_saw_rx_read_basic) {
  setup_rx();
  uint8_t data[5] = {1, 2, 3, 4, 5};
  tcp_saw_rx_ops.deliver(&rx_ctx, data, 5);

  uint8_t out[8] = {0};
  uint16_t n = tcp_saw_rx_ops.read(&rx_ctx, out, sizeof(out));
  ASSERT_EQ(n, 5);
  ASSERT_MEM_EQ(out, data, 5);
  ASSERT_EQ(tcp_saw_rx_ops.readable(&rx_ctx), 0);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), BUF_SIZE);
}

TEST(test_saw_rx_read_partial) {
  setup_rx();
  uint8_t data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  tcp_saw_rx_ops.deliver(&rx_ctx, data, 10);

  uint8_t out[4];
  uint16_t n = tcp_saw_rx_ops.read(&rx_ctx, out, 4);
  ASSERT_EQ(n, 4);
  ASSERT_MEM_EQ(out, data, 4);
  ASSERT_EQ(tcp_saw_rx_ops.readable(&rx_ctx), 6);
}

TEST(test_saw_rx_read_empty_returns_zero) {
  setup_rx();
  uint8_t out[4];
  uint16_t n = tcp_saw_rx_ops.read(&rx_ctx, out, 4);
  ASSERT_EQ(n, 0);
}

TEST(test_saw_rx_deliver_read_multiple_cycles) {
  setup_rx();
  /* Fill, drain, fill again — verifies no state corruption across cycles */
  uint8_t data[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};

  tcp_saw_rx_ops.deliver(&rx_ctx, data, 8);
  uint8_t out[8];
  tcp_saw_rx_ops.read(&rx_ctx, out, 8);
  ASSERT_MEM_EQ(out, data, 8);

  /* Second cycle */
  uint8_t data2[4] = {'W', 'X', 'Y', 'Z'};
  tcp_saw_rx_ops.deliver(&rx_ctx, data2, 4);
  uint8_t out2[4];
  tcp_saw_rx_ops.read(&rx_ctx, out2, 4);
  ASSERT_MEM_EQ(out2, data2, 4);

  ASSERT_EQ(tcp_saw_rx_ops.readable(&rx_ctx), 0);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), BUF_SIZE);
}

TEST(test_saw_rx_window_tracks_available) {
  setup_rx();
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), BUF_SIZE);

  uint8_t d[20];
  memset(d, 0, sizeof(d));
  tcp_saw_rx_ops.deliver(&rx_ctx, d, 20);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), (uint16_t)(BUF_SIZE - 20));

  uint8_t out[10];
  tcp_saw_rx_ops.read(&rx_ctx, out, 10);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), (uint16_t)(BUF_SIZE - 10));

  tcp_saw_rx_ops.read(&rx_ctx, out, 10);
  ASSERT_EQ(tcp_saw_rx_ops.available(&rx_ctx), BUF_SIZE);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_tcp_buf ===\n");
  RUN_TEST(test_saw_tx_init_state);
  RUN_TEST(test_saw_tx_write_basic);
  RUN_TEST(test_saw_tx_write_clamped_to_capacity);
  RUN_TEST(test_saw_tx_next_segment_basic);
  RUN_TEST(test_saw_tx_next_segment_mss_clamping);
  RUN_TEST(test_saw_tx_no_segment_when_empty);
  RUN_TEST(test_saw_tx_no_segment_when_in_flight);
  RUN_TEST(test_saw_tx_write_blocked_when_in_flight);
  RUN_TEST(test_saw_tx_ack_full_clears_buffer);
  RUN_TEST(test_saw_tx_ack_partial_shifts_buffer);
  RUN_TEST(test_saw_tx_mark_retransmit);
  RUN_TEST(test_saw_rx_init_state);
  RUN_TEST(test_saw_rx_deliver_basic);
  RUN_TEST(test_saw_rx_deliver_clamped_when_full);
  RUN_TEST(test_saw_rx_read_basic);
  RUN_TEST(test_saw_rx_read_partial);
  RUN_TEST(test_saw_rx_read_empty_returns_zero);
  RUN_TEST(test_saw_rx_deliver_read_multiple_cycles);
  RUN_TEST(test_saw_rx_window_tracks_available);
  TEST_REPORT();
  return test_failures;
}
