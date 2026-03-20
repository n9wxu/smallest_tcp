/**
 * @file tcp.h
 * @brief TCP — Transmission Control Protocol (RFC 9293).
 *
 * Application-managed connections. The application allocates all memory
 * (connection structs, TX/RX buffers) and injects a buffer implementation
 * at init time via compile-time dependency injection (tcp_buf.h).
 *
 * Implements REQ-TCP-001 through REQ-TCP-155.
 * RFC references: RFC 9293 (primary), RFC 5681 (congestion), RFC 6298 (RTO).
 *
 * ── Quick start ────────────────────────────────────────────────────
 *
 *  // 1. Allocate memory (static or stack)
 *  static uint8_t tx_mem[600], rx_mem[600];
 *  static tcp_saw_tx_ctx_t tx_ctx;
 *  static tcp_saw_rx_ctx_t rx_ctx;
 *  static tcp_conn_t conn;
 *  static tcp_conn_t *conn_table[1] = { &conn };
 *
 *  // 2. Wire up buffer implementation (compile-time DI)
 *  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof(tx_mem));
 *  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
 *
 *  // 3. Initialize connection and register with stack
 *  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx,
 *                       &tcp_saw_rx_ops, &rx_ctx, my_event_cb);
 *  tcp_connections.conns = conn_table;
 *  tcp_connections.count = 1;
 *
 *  // 4. Listen
 *  tcp_listen(&conn, 7);
 *
 *  // 5. In main loop: call eth_input() which dispatches to tcp_input()
 *  //    Call tcp_tick() periodically for retransmit timers
 */

#ifndef TCP_H
#define TCP_H

#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include "tcp_buf.h"
#include <stdint.h>

/* ── TCP header offsets ──────────────────────────────────────────── */

#define TCP_OFF_SPORT 0   /**< Source port (2 bytes) */
#define TCP_OFF_DPORT 2   /**< Destination port (2 bytes) */
#define TCP_OFF_SEQ 4     /**< Sequence number (4 bytes) */
#define TCP_OFF_ACK 8     /**< Acknowledgment number (4 bytes) */
#define TCP_OFF_DOFF 12   /**< Data offset (high nibble) + reserved */
#define TCP_OFF_FLAGS 13  /**< Control flags byte */
#define TCP_OFF_WINDOW 14 /**< Window size (2 bytes) */
#define TCP_OFF_CKSUM 16  /**< Checksum (2 bytes) */
#define TCP_OFF_URG 18    /**< Urgent pointer (2 bytes) */
#define TCP_OFF_OPT 20    /**< Options start (if data offset > 5) */
#define TCP_HDR_SIZE 20   /**< Minimum header: 5 × 32-bit words */

/* ── TCP control flags (offset 13) ──────────────────────────────── */

#define TCP_FLAG_FIN 0x01u
#define TCP_FLAG_SYN 0x02u
#define TCP_FLAG_RST 0x04u
#define TCP_FLAG_PSH 0x08u
#define TCP_FLAG_ACK 0x10u
#define TCP_FLAG_URG 0x20u
#define TCP_FLAG_ECE 0x40u
#define TCP_FLAG_CWR 0x80u

/* ── TCP option kinds ────────────────────────────────────────────── */

#define TCP_OPT_EOL 0 /**< End of Option List */
#define TCP_OPT_NOP 1 /**< No-Operation (padding) */
#define TCP_OPT_MSS 2 /**< Maximum Segment Size (Length=4) */

/* ── TCP connection states (REQ-TCP-001) ─────────────────────────── */

typedef enum {
  TCP_CLOSED,       /**< No connection */
  TCP_LISTEN,       /**< Waiting for incoming SYN */
  TCP_SYN_SENT,     /**< Active open — SYN sent, waiting for SYN-ACK */
  TCP_SYN_RECEIVED, /**< SYN received, SYN-ACK sent */
  TCP_ESTABLISHED,  /**< Connection open — data transfer */
  TCP_FIN_WAIT_1,   /**< We sent FIN, waiting for ACK */
  TCP_FIN_WAIT_2,   /**< Our FIN ACKed, waiting for remote FIN */
  TCP_CLOSE_WAIT,   /**< Remote sent FIN; app must still close */
  TCP_CLOSING,      /**< Both sides sent FIN simultaneously */
  TCP_LAST_ACK,     /**< Waiting for ACK of our FIN (passive close) */
  TCP_TIME_WAIT,    /**< Waiting 2×MSL before final close */
} tcp_state_t;

/* ── Application event codes ─────────────────────────────────────── */

#define TCP_EVT_CONNECTED 0x01u /**< Connection established */
#define TCP_EVT_DATA 0x02u      /**< Data available to read */
#define TCP_EVT_WRITABLE 0x04u  /**< TX buffer has space (after ACK) */
#define TCP_EVT_CLOSED 0x08u    /**< Connection fully closed */
#define TCP_EVT_RESET 0x10u     /**< Connection reset by peer */
#define TCP_EVT_ERROR 0x20u     /**< Protocol error */

/* ── TCP connection structure (REQ-TCP-010) ──────────────────────── */

/**
 * @brief Application-owned TCP connection state.
 *
 * The application allocates one of these per connection (static or stack).
 * All buffer memory is also application-owned and injected via the
 * txbuf_ops / rxbuf_ops pointers (compile-time dependency injection).
 *
 * Initialize with tcp_conn_init(), then call tcp_listen() or tcp_connect().
 */
typedef struct tcp_conn_s {
  /* ── Connection identity ──────────────────────────────────── */
  tcp_state_t state;     /**< Current connection state */
  uint16_t local_port;   /**< Local port number (host byte order) */
  uint16_t remote_port;  /**< Remote port (host byte order; 0 in LISTEN) */
  uint32_t remote_ip;    /**< Remote IPv4 (host byte order; 0 in LISTEN) */
  uint8_t remote_mac[6]; /**< Remote MAC address */
  uint8_t mac_valid;     /**< 1 if remote_mac is known */

  /* ── Send sequence variables (REQ-TCP-024) ────────────────── */
  uint32_t iss;     /**< Initial Send Sequence Number */
  uint32_t snd_una; /**< Oldest unACKed sequence number */
  uint32_t snd_nxt; /**< Next sequence number to send */
  uint32_t snd_wnd; /**< Peer's advertised window */
  uint16_t snd_mss; /**< Peer's MSS (from SYN option, or 536) */

  /* ── Receive sequence variables (REQ-TCP-025) ─────────────── */
  uint32_t irs;     /**< Initial Receive Sequence Number */
  uint32_t rcv_nxt; /**< Next expected sequence number */
  uint32_t rcv_wnd; /**< Our receive window (from RX buffer) */
  uint16_t our_mss; /**< Our MSS (sent in SYN/SYN-ACK) */

  /* ── Window update tracking (REQ-TCP-058) ─────────────────── */
  uint32_t snd_wl1; /**< Seq number used for last window update */
  uint32_t snd_wl2; /**< ACK number used for last window update */

  /* ── Retransmission timer (REQ-TCP-090..100) ──────────────── */
  uint32_t rto_ms; /**< Current RTO (starts at NET_DEFAULT_TCP_RTO_INIT_MS) */
  uint32_t rto_remaining_ms; /**< Countdown — decremented by tcp_tick() */
  uint8_t rto_active;        /**< 1 if timer is running */
  uint8_t retransmit_count;  /**< Consecutive timeouts (for abort) */

  /* ── TIME-WAIT timer (REQ-TCP-008) ────────────────────────── */
  uint32_t timewait_remaining_ms; /**< 2×MSL countdown */

  /* ── Buffer implementation (compile-time DI, REQ-TCP-142) ─── */
  const tcp_txbuf_ops_t *txbuf_ops; /**< TX buffer vtable (injected) */
  void *txbuf_ctx;                  /**< TX buffer context (injected) */
  const tcp_rxbuf_ops_t *rxbuf_ops; /**< RX buffer vtable (injected) */
  void *rxbuf_ctx;                  /**< RX buffer context (injected) */

  /* ── Application event callback ────────────────────────────── */
  /**
   * Called by tcp_input() / tcp_tick() when something notable happens.
   * @param conn   The connection that generated the event.
   * @param event  Bitmask of TCP_EVT_* flags.
   *
   * Called from within tcp_input() or tcp_tick() — do not call
   * tcp_send() / tcp_close() from inside an on_event callback.
   * Instead, set a flag and act in the main loop.
   */
  void (*on_event)(struct tcp_conn_s *conn, uint8_t event);
} tcp_conn_t;

/* ── Connection table (REQ-TCP-150) ──────────────────────────────── */

/**
 * @brief Application-provided array of active connections.
 *
 * tcp_input() scans this table to match incoming segments.
 * Set before calling tcp_listen() / tcp_connect().
 *
 * Example:
 *   static tcp_conn_t *my_conns[2] = { &server_conn, &client_conn };
 *   tcp_connections.conns = my_conns;
 *   tcp_connections.count = 2;
 */
typedef struct {
  tcp_conn_t **conns; /**< Array of pointers to connection structs */
  uint8_t count;      /**< Number of entries */
} tcp_conn_table_t;

/** Global connection table — application sets this before using TCP. */
extern tcp_conn_table_t tcp_connections;

/* ── Factory / Init ──────────────────────────────────────────────── */

/**
 * Initialize a TCP connection structure.
 *
 * Wires up the buffer ops (compile-time DI) and sets state to CLOSED.
 * Must be called before tcp_listen() or tcp_connect().
 *
 * REQ-TCP-011.
 *
 * @param conn      Application-owned connection struct to initialize.
 * @param tx_ops    TX buffer ops vtable (e.g. &tcp_saw_tx_ops).
 * @param tx_ctx    TX buffer context (e.g. &my_saw_tx_ctx).
 * @param rx_ops    RX buffer ops vtable (e.g. &tcp_saw_rx_ops).
 * @param rx_ctx    RX buffer context (e.g. &my_saw_rx_ctx).
 * @param on_event  Application callback for connection events (may be NULL).
 * @return NET_OK on success.
 */
net_err_t tcp_conn_init(tcp_conn_t *conn, const tcp_txbuf_ops_t *tx_ops,
                        void *tx_ctx, const tcp_rxbuf_ops_t *rx_ops,
                        void *rx_ctx, void (*on_event)(tcp_conn_t *, uint8_t));

/* ── Application API ─────────────────────────────────────────────── */

/**
 * Put a connection into LISTEN state on the specified local port.
 *
 * The connection will accept the first incoming SYN. For multiple
 * simultaneous connections, use multiple tcp_conn_t structs.
 *
 * REQ-TCP-002, REQ-TCP-012.
 *
 * @param conn        Initialized connection struct.
 * @param local_port  Port to listen on (host byte order).
 * @return NET_OK or NET_ERR_INVALID_PARAM.
 */
net_err_t tcp_listen(tcp_conn_t *conn, uint16_t local_port);

/**
 * Initiate an active open (connect to a remote host).
 *
 * Sends a SYN and transitions to SYN_SENT. The on_event callback will
 * receive TCP_EVT_CONNECTED when the handshake completes.
 *
 * REQ-TCP-003, REQ-TCP-013.
 *
 * @param net         Network context.
 * @param conn        Initialized connection struct.
 * @param remote_ip   Destination IPv4 address (host byte order).
 * @param remote_mac  Destination MAC (must be valid — resolve via ARP first).
 * @param remote_port Destination port (host byte order).
 * @param local_port  Source port (host byte order).
 * @return NET_OK or error.
 */
net_err_t tcp_connect(net_t *net, tcp_conn_t *conn, uint32_t remote_ip,
                      const uint8_t *remote_mac, uint16_t remote_port,
                      uint16_t local_port);

/**
 * Initiate a graceful close (send FIN).
 *
 * Transitions from ESTABLISHED → FIN_WAIT_1 (active close), or
 * from CLOSE_WAIT → LAST_ACK (passive close, after remote FIN).
 *
 * REQ-TCP-005, REQ-TCP-015.
 *
 * @param net   Network context.
 * @param conn  Connection to close.
 * @return NET_OK or error.
 */
net_err_t tcp_close(net_t *net, tcp_conn_t *conn);

/**
 * Abort a connection immediately (send RST, go to CLOSED).
 *
 * REQ-TCP-016.
 *
 * @param net   Network context.
 * @param conn  Connection to abort.
 * @return NET_OK.
 */
net_err_t tcp_abort(net_t *net, tcp_conn_t *conn);

/**
 * Return the current connection state.
 *
 * REQ-TCP-017.
 */
tcp_state_t tcp_status(const tcp_conn_t *conn);

/**
 * Send data on an ESTABLISHED connection.
 *
 * Data is written to the TX buffer via the injected txbuf_ops->write().
 * If the buffer is full or a segment is still in flight (stop-and-wait),
 * fewer than len bytes may be accepted — check the return value.
 *
 * After writing, tcp_send() immediately tries to transmit a segment.
 *
 * REQ-TCP-014.
 *
 * @param net   Network context.
 * @param conn  ESTABLISHED connection.
 * @param data  Data to send.
 * @param len   Length of data.
 * @return Number of bytes accepted (0..len), or negative on error.
 */
int tcp_send(net_t *net, tcp_conn_t *conn, const uint8_t *data, uint16_t len);

/**
 * Read received data from an ESTABLISHED or CLOSE_WAIT connection.
 *
 * Delegates to rxbuf_ops->read(). Returns 0 if no data is available.
 *
 * @param conn    Connection to read from.
 * @param buf     Destination buffer.
 * @param maxlen  Maximum bytes to read.
 * @return Bytes copied.
 */
uint16_t tcp_recv(tcp_conn_t *conn, uint8_t *buf, uint16_t maxlen);

/* ── Stack entry points ──────────────────────────────────────────── */

/**
 * Process a received TCP segment (called from ipv4_input).
 *
 * Validates checksum and header, matches to a connection, then runs
 * the full RFC 9293 §3.10.7 state machine.
 *
 * REQ-TCP-018..REQ-TCP-071.
 *
 * @param net  Network context.
 * @param ip   Parsed IPv4 header (src/dst IPs, payload pointer).
 * @param eth  Parsed Ethernet frame (src MAC).
 */
void tcp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/**
 * Advance all TCP timers by elapsed_ms milliseconds.
 *
 * Must be called periodically from the application's main loop.
 * Handles retransmit timeouts, TIME-WAIT expiry, and persist probes.
 *
 * REQ-TCP-090..REQ-TCP-100, REQ-TCP-008.
 *
 * @param net         Network context.
 * @param elapsed_ms  Milliseconds elapsed since last call.
 */
void tcp_tick(net_t *net, uint32_t elapsed_ms);

/* ── Checksum ────────────────────────────────────────────────────── */

/**
 * Compute TCP checksum over pseudo-header + TCP header + data.
 *
 * IPv4 pseudo-header: src_ip (4) + dst_ip (4) + 0x00 + 0x06 + tcp_len (2).
 * The checksum field in tcp_seg must be 0x0000 before calling.
 *
 * REQ-TCP-018, REQ-TCP-019, REQ-TCP-139.
 *
 * @param src_ip   Source IPv4 (host byte order).
 * @param dst_ip   Destination IPv4 (host byte order).
 * @param tcp_seg  Pointer to TCP segment (header + data).
 * @param tcp_len  Total TCP length (header + data).
 * @return Checksum in network byte order.
 */
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *tcp_seg,
                      uint16_t tcp_len);

#endif /* TCP_H */
