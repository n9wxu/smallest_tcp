/**
 * @file tftp.h
 * @brief TFTP client — RFC 1350 with optional blksize option (RFC 2348).
 *
 * Usage:
 *   1. Declare a tftp_client_t (static or stack).
 *   2. Call tftp_client_init() with data/done callbacks and local port.
 *   3. Register your local port in udp_port_table_t; the handler calls
 *      tftp_client_input() with the raw UDP payload.
 *   4. Call tftp_client_get() with resolved server IP + MAC to start.
 *   5. Call tftp_client_tick() each main loop iteration with elapsed ms.
 *
 * Zero allocation: all state lives in the application-owned tftp_client_t.
 * Payload bytes are delivered to the on_data callback one block at a time.
 *
 * REQ-TFTP-001..038
 */

#ifndef TFTP_H
#define TFTP_H

#include "net.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── TFTP client states ───────────────────────────────────────────── */

#define TFTP_STATE_IDLE 0       /**< Not started */
#define TFTP_STATE_REQUESTING 1 /**< RRQ sent, waiting for DATA(1) or OACK */
#define TFTP_STATE_RECEIVING 2  /**< Receiving DATA blocks */
#define TFTP_STATE_DONE 3       /**< Transfer complete */
#define TFTP_STATE_ERROR 4      /**< Error received or timed out */

/* ── TFTP opcodes (RFC 1350 §5) ──────────────────────────────────── */

#define TFTP_OP_RRQ 1
#define TFTP_OP_WRQ 2
#define TFTP_OP_DATA 3
#define TFTP_OP_ACK 4
#define TFTP_OP_ERROR 5
#define TFTP_OP_OACK 6

/* ── TFTP error codes (RFC 1350 §5) ──────────────────────────────── */

#define TFTP_ERR_NOT_DEFINED 0
#define TFTP_ERR_FILE_NOT_FOUND 1
#define TFTP_ERR_ACCESS_VIOLATION 2
#define TFTP_ERR_DISK_FULL 3
#define TFTP_ERR_ILLEGAL_OP 4
#define TFTP_ERR_UNKNOWN_TID 5
#define TFTP_ERR_FILE_EXISTS 6
#define TFTP_ERR_NO_SUCH_USER 7

/* ── TFTP constants ───────────────────────────────────────────────── */

#define TFTP_SERVER_PORT 69      /**< Well-known TFTP port */
#define TFTP_DEFAULT_BLKSIZE 512 /**< Default block size (REQ-TFTP-011) */
#define TFTP_TIMEOUT_MS 3000     /**< Retransmit timeout in ms (REQ-TFTP-022) */
#define TFTP_MAX_RETRIES                                                       \
  5 /**< Max retransmissions before abort (REQ-TFTP-023) */
#define TFTP_MAX_FILENAME 128 /**< Max filename length including NUL */

/* ── Application callbacks ───────────────────────────────────────── */

/**
 * Called for each received DATA block (REQ-TFTP-012).
 *
 * @param block_num  1-based block number.
 * @param data       Pointer to raw block payload bytes.
 * @param len        Number of data bytes (0 ≤ len ≤ blksize).
 * @param ctx        Application context pointer.
 */
typedef void (*tftp_data_fn_t)(uint16_t block_num, const uint8_t *data,
                               uint16_t len, void *ctx);

/**
 * Called when the transfer completes or fails (REQ-TFTP-017, REQ-TFTP-024).
 *
 * @param ok        1 = success (all blocks received), 0 = error/timeout.
 * @param err_code  TFTP error code (TFTP_ERR_*). Valid only when ok==0 and
 *                  the failure was caused by a server ERROR packet.
 * @param msg       Null-terminated error message, or "" on timeout.
 * @param ctx       Application context pointer.
 */
typedef void (*tftp_done_fn_t)(uint8_t ok, uint16_t err_code, const char *msg,
                               void *ctx);

/* ── Client state (application owns) ─────────────────────────────── */

/**
 * @brief TFTP client state.  Zero-initialise then call tftp_client_init().
 */
typedef struct {
  uint8_t state;                    /**< TFTP_STATE_* */
  uint16_t local_port;              /**< Our UDP source port */
  uint16_t server_tid;              /**< Server's ephemeral reply port */
  uint16_t next_block;              /**< Next expected block number (1-based) */
  uint16_t blksize;                 /**< Negotiated/used block size */
  uint8_t blksize_opt;              /**< 1 = send blksize option in RRQ */
  uint32_t server_ip;               /**< TFTP server IPv4 (host byte order) */
  uint8_t server_mac[6];            /**< Resolved server MAC address */
  uint32_t timer_ms;                /**< Retransmit countdown */
  uint8_t retries;                  /**< Retransmit attempt counter */
  char filename[TFTP_MAX_FILENAME]; /**< Filename to request */
  tftp_data_fn_t on_data;           /**< Block delivery callback */
  tftp_done_fn_t on_done;           /**< Completion/error callback */
  void *cb_ctx;                     /**< Passed unchanged to callbacks */
} tftp_client_t;

/* ── API ──────────────────────────────────────────────────────────── */

/**
 * Initialise client state.  Must be called before tftp_client_get().
 *
 * @param c           Application-owned client struct.
 * @param local_port  Our UDP source port (app registers this in
 *                    udp_port_table_t with a handler that calls
 *                    tftp_client_input).
 * @param on_data     Block delivery callback (may be NULL if only
 *                    interested in completion).
 * @param on_done     Completion/error callback (may be NULL).
 * @param ctx         Passed unchanged to both callbacks.
 */
void tftp_client_init(tftp_client_t *c, uint16_t local_port,
                      tftp_data_fn_t on_data, tftp_done_fn_t on_done,
                      void *ctx);

/**
 * Start a TFTP GET (RRQ) transfer.
 *
 * @param net         Network context.
 * @param c           Client state (must have been init'd).
 * @param server_ip   TFTP server IPv4 address (host byte order).
 * @param server_mac  Pre-resolved server MAC address (6 bytes).
 * @param filename    NUL-terminated filename to request.
 * @param blksize_opt 0 = use RFC 1350 default (512 bytes);
 *                    1 = negotiate blksize from tx buffer capacity
 *                        (REQ-TFTP-025,026,037).
 * @return NET_OK, or a net_err_t code on failure.
 *
 * REQ-TFTP-001..006, REQ-TFTP-035
 */
net_err_t tftp_client_get(net_t *net, tftp_client_t *c, uint32_t server_ip,
                          const uint8_t *server_mac, const char *filename,
                          uint8_t blksize_opt);

/**
 * Feed an incoming UDP payload to the client.
 *
 * Call from the application's UDP port handler for local_port.
 *
 * @param net       Network context.
 * @param c         Client state.
 * @param src_ip    Source IP of the incoming datagram.
 * @param src_port  Source port of the incoming datagram (server TID).
 * @param data      UDP payload bytes (TFTP packet, starting at opcode).
 * @param len       Number of bytes.
 *
 * REQ-TFTP-007..018, REQ-TFTP-027,028,031
 */
void tftp_client_input(net_t *net, tftp_client_t *c, uint32_t src_ip,
                       uint16_t src_port, const uint8_t *data, uint16_t len);

/**
 * Drive retransmit timers.  Call with elapsed milliseconds each main loop.
 *
 * REQ-TFTP-020,021,023,024
 */
void tftp_client_tick(net_t *net, tftp_client_t *c, uint32_t ms);

/**
 * Return the current client state (TFTP_STATE_*).
 */
static inline uint8_t tftp_client_state(const tftp_client_t *c) {
  return c->state;
}

#ifdef __cplusplus
}
#endif

#endif /* TFTP_H */
