/**
 * @file tcp.h
 * @brief TCP (RFC 9293) over IPv4 and IPv6.
 *
 * The application owns every connection and its buffers; the buffer
 * implementation is chosen per connection (tcp_buf.h).  Bind the
 * connections with tcp_set_connections(), then tcp_listen() or
 * tcp_connect(); net_poll() delivers segments and net_tick() runs the
 * timers.  See docs/design/tcp.md.
 */

#ifndef TCP_H
#define TCP_H

#include "eth.h"
#include "net.h"
#include "tcp_buf.h"
#include <stdint.h>

#if NET_USE_IPV4
#include "ipv4.h"
#endif
#if NET_USE_IPV6
#include "ipv6.h"
#endif

#define TCP_OFF_SPORT 0
#define TCP_OFF_DPORT 2
#define TCP_OFF_SEQ 4
#define TCP_OFF_ACK 8
#define TCP_OFF_DOFF 12 /**< Data offset (high nibble) */
#define TCP_OFF_FLAGS 13
#define TCP_OFF_WINDOW 14
#define TCP_OFF_CKSUM 16
#define TCP_OFF_URG 18
#define TCP_OFF_OPT 20
#define TCP_HDR_SIZE 20 /**< Without options */
#define TCP_HDR_MAX 60  /**< With the most options (data offset 15) */

/**
 * The smallest frame buffers TCP works with; net_init() refuses smaller
 * ones.  The RX buffer must take any peer's SYN, whose header may carry 40
 * bytes of options, over IPv6 when that is compiled in; a TX buffer the
 * same size carries 40 bytes a segment.
 */
#if NET_USE_IPV6
#define TCP_MIN_FRAME (ETH_HDR_SIZE + IPV6_HDR_SIZE + TCP_HDR_MAX)
#else
#define TCP_MIN_FRAME (ETH_HDR_SIZE + IPV4_HDR_SIZE + TCP_HDR_MAX)
#endif

#define TCP_FLAG_FIN 0x01u
#define TCP_FLAG_SYN 0x02u
#define TCP_FLAG_RST 0x04u
#define TCP_FLAG_PSH 0x08u
#define TCP_FLAG_ACK 0x10u
#define TCP_FLAG_URG 0x20u
#define TCP_FLAG_ECE 0x40u
#define TCP_FLAG_CWR 0x80u

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2

/** Connection states (RFC 9293 §3.3.2). */
typedef enum {
  TCP_CLOSED,
  TCP_LISTEN,
  TCP_SYN_SENT,
  TCP_SYN_RECEIVED,
  TCP_ESTABLISHED,
  TCP_FIN_WAIT_1,
  TCP_FIN_WAIT_2,
  TCP_CLOSE_WAIT,
  TCP_CLOSING,
  TCP_LAST_ACK,
  TCP_TIME_WAIT,
} tcp_state_t;

/* Which timer a connection runs (tcp_conn_t.timer) */
#define TCP_TIMER_RETRANSMIT 0
#define TCP_TIMER_PERSIST 1   /**< Zero-window probe (REQ-TCP-085) */
#define TCP_TIMER_TIME_WAIT 2 /**< 2×MSL (REQ-TCP-008) */

/* Events passed to on_event, a bitmask */
#define TCP_EVT_CONNECTED 0x01u
#define TCP_EVT_DATA 0x02u     /**< Data to read */
#define TCP_EVT_WRITABLE 0x04u /**< TX buffer space freed by an ACK */
#define TCP_EVT_CLOSED                                                         \
  0x08u /**< The peer closed (CLOSE_WAIT), or the                              \
             connection reached CLOSED */
#define TCP_EVT_RESET 0x10u
#define TCP_EVT_ERROR                                                          \
  0x20u /**< Protocol error or retransmissions exhausted                       \
         */
/** A soft error: an ICMP error that does not abort, or retransmissions
 *  reaching R1 — tcp_last_error() says which (RFC 9293 MUST-47) */
#define TCP_EVT_SOFT_ERROR 0x40u

/** tcp_last_error() after retransmissions reached R1 */
#define TCP_SOFT_RETRANSMITTING 0xFFFFu

/** One connection; initialise with tcp_conn_init(). */
typedef struct tcp_conn_s {
  tcp_state_t state;
  uint16_t local_port;
  uint16_t remote_port; /**< 0 while listening */
#if NET_USE_IPV4
  uint32_t remote_ip; /**< IPv4 peer, host byte order; 0 while listening */
  uint32_t local_ip;  /**< Our IPv4 address, for the connection's life: if
                           the host's changes, the connection is aborted
                           (REQ-TCP-171) */
#endif
  uint8_t remote_mac[6];
  uint8_t mac_valid;
  uint8_t passive; /**< Opened by tcp_listen(): reset in SYN-RECEIVED, it
                        listens again */
  uint16_t last_error; /**< tcp_last_error() */
  uint8_t unsent;      /**< The driver was busy (NET_ERR_BUSY) for our SYN, data
                            or FIN: it goes at the next tick (REQ-TCP-184) */
  uint8_t rtt_flags;   /**< A segment's round trip is being timed; SRTT and
                            RTTVAR hold a measurement */
#if NET_USE_IPV6
  uint8_t ip_ver;     /**< 4 or 6; always 6 without IPv4 */
  uint8_t local_slot; /**< IPv6: our address the peer used, in ip6.addr */
  uint8_t remote_ip6[16];
#endif

  /* Send sequence space (RFC 9293 §3.3.1) */
  uint32_t iss;
  uint32_t snd_una;
  uint32_t snd_nxt;
  uint32_t snd_wnd;
  uint32_t snd_wl1; /**< Segment sequence number of the last window update */
  uint32_t snd_wl2; /**< Segment acknowledgment number of it */
  uint32_t snd_max; /**< The furthest SND.NXT has been: what lies before it
                         has been sent, and is never timed again (Karn) */
  uint16_t snd_mss; /**< The peer's MSS, at most what our TX buffer carries */
  uint8_t fin_sent; /**< Our FIN is SND.NXT - 1; until then it waits for the
                         data queued before it */
  uint8_t close_queued; /**< tcp_close() in SYN-RECEIVED: the FIN follows the
                             ACK of our SYN */

  /* Receive sequence space */
  uint32_t irs;
  uint32_t rcv_nxt;
  uint16_t rcv_wnd; /**< The window on offer: at most the RX buffer's room */
  uint16_t our_mss; /**< What our RX buffer takes; in our SYN */

  /* One timer at a time: retransmission, zero-window probe or TIME-WAIT */
  uint32_t timer_ms;   /**< Until it fires; 0 = stopped */
  uint8_t timer;       /**< TCP_TIMER_* */
  uint8_t retransmits; /**< Consecutive retransmission timeouts */
  uint8_t r2;          /**< tcp_set_max_retransmits(); 0: the default */
  uint8_t tos;         /**< tcp_set_tos() */
  uint32_t rto_ms;     /**< Retransmission timeout: from the measured round
                            trip (RFC 6298), doubled per expiry */
  uint32_t persist_ms; /**< Zero-window probe interval, doubled per probe */
  uint32_t srtt8;      /**< Smoothed round-trip time × 8, in ms */
  uint32_t rttvar4;    /**< Round-trip time variation × 4, in ms */
  uint32_t rtt_seq;    /**< The timed segment's first sequence number */
  uint32_t rtt_sent;   /**< net->tcp_clock when it left */

  const tcp_txbuf_ops_t *txbuf_ops;
  void *txbuf_ctx;
  const tcp_rxbuf_ops_t *rxbuf_ops;
  void *rxbuf_ctx;

  /**
   * TCP_EVT_* events, called from net_poll() and net_tick().  It must not
   * send or close: set a flag and act from the main loop.
   */
  void (*on_event)(struct tcp_conn_s *conn, uint8_t events);
} tcp_conn_t;

/**
 * Bind the application's connections: segments are matched
 * against them, and tcp_tick() runs their timers.
 */
static inline void tcp_set_connections(net_t *net, tcp_conn_t *const *conns,
                                       uint8_t count) {
  net->tcp_conns = conns;
  net->tcp_conn_count = count;
}

/**
 * Initialise a connection (CLOSED) with its buffers, e.g. &tcp_saw_tx_ops
 * and a tcp_saw_tx_ctx_t.
 * @param on_event  May be NULL.
 */
net_err_t tcp_conn_init(tcp_conn_t *conn, const tcp_txbuf_ops_t *tx_ops,
                        void *tx_ctx, const tcp_rxbuf_ops_t *rx_ops,
                        void *rx_ctx, void (*on_event)(tcp_conn_t *, uint8_t));

/** Accept the first SYN to @p local_port.
 *  @return NET_OK; NET_ERR_BUSY if @p conn is in use — neither CLOSED nor
 *          LISTEN (RFC 9293 MUST-41): tcp_conn_init() frees it. */
net_err_t tcp_listen(tcp_conn_t *conn, uint16_t local_port);

#if NET_USE_IPV4
/**
 * Active open over IPv4, from net->ipv4_addr; TCP_EVT_CONNECTED follows.  A
 * SYN the driver is too busy to take goes at the next tick (REQ-TCP-184).
 * @param remote_mac  The peer's or the gateway's MAC, already resolved.
 * @return NET_OK; NET_ERR_INVALID_PARAM — also for a @p remote_ip that
 *         is no single host (a broadcast, a group, 0.0.0.0, 127/8;
 *         RFC 9293 MUST-46) and while the host has no address;
 *         NET_ERR_BUSY if @p conn is in use — neither CLOSED nor LISTEN
 *         (RFC 9293 §3.10.1): tcp_conn_init() frees it.
 */
net_err_t tcp_connect(net_t *net, tcp_conn_t *conn, uint32_t remote_ip,
                      const uint8_t *remote_mac, uint16_t remote_port,
                      uint16_t local_port);
#endif

#if NET_USE_IPV6
/**
 * Active open over IPv6, from the address ipv6_src_for() picks; otherwise
 * as tcp_connect().
 * @return NET_OK; NET_ERR_INVALID_PARAM (also: no usable source);
 *         NET_ERR_BUSY.
 */
net_err_t tcp6_connect(net_t *net, tcp_conn_t *conn, const uint8_t *remote_ip,
                       const uint8_t *remote_mac, uint16_t remote_port,
                       uint16_t local_port);

/**
 * As tcp6_connect(), from @p local_ip, the OPEN call's optional local
 * address (RFC 9293 MUST-43): one of ours, usable (ipv6_is_ours()).
 * @return NET_OK; NET_ERR_INVALID_PARAM — also for a @p local_ip that
 *         is not ours; NET_ERR_BUSY.
 */
net_err_t tcp6_connect_from(net_t *net, tcp_conn_t *conn,
                            const uint8_t *local_ip, const uint8_t *remote_ip,
                            const uint8_t *remote_mac, uint16_t remote_port,
                            uint16_t local_port);
#endif

/** Close our side: ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK.  The
 *  FIN follows the data already written (RFC 9293 §3.10.4). */
net_err_t tcp_close(net_t *net, tcp_conn_t *conn);

/** Send RST and go to CLOSED at once. */
net_err_t tcp_abort(net_t *net, tcp_conn_t *conn);

tcp_state_t tcp_status(const tcp_conn_t *conn);

/** The last error: ICMP type << 8 | code (ICMPv6's, on a connection over
 *  IPv6), TCP_SOFT_RETRANSMITTING, or 0 for none. */
uint16_t tcp_last_error(const tcp_conn_t *conn);

/** The TOS (DSCP) byte of the connection's IPv4 segments (RFC 9293
 *  MUST-48); 0 by default.  tcp_conn_init() resets it. */
net_err_t tcp_set_tos(tcp_conn_t *conn, uint8_t tos);

/** R2: how many retransmissions of one segment before the connection is
 *  given up (RFC 9293 MUST-21); TCP_MAX_RETRANSMITS (8) by default, and a
 *  SYN is retransmitted at least that often — over 3 minutes with the
 *  default RTOs — whatever R2 is (MUST-23).  At TCP_R1 (3) retransmissions
 *  the application gets TCP_EVT_SOFT_ERROR.  tcp_conn_init() resets it.
 *  @return NET_ERR_INVALID_PARAM for 0. */
net_err_t tcp_set_max_retransmits(tcp_conn_t *conn, uint8_t r2);

/**
 * Queue data without sending it, e.g. to build one segment from several
 * pieces; tcp_output() sends.  The stop-and-wait buffer takes nothing
 * while a segment is in flight.
 * @return Bytes accepted, or < 0 unless ESTABLISHED or CLOSE-WAIT.
 */
int tcp_write(tcp_conn_t *conn, const uint8_t *data, uint16_t len);

/** Send one segment of queued data, as the peer's MSS and window allow. */
void tcp_output(net_t *net, tcp_conn_t *conn);

/** tcp_write() then tcp_output(). */
int tcp_send(net_t *net, tcp_conn_t *conn, const uint8_t *data, uint16_t len);

/** Everything written has been sent and acknowledged. */
int tcp_tx_idle(const tcp_conn_t *conn);

/** Copy out received data; returns the byte count. */
uint16_t tcp_recv(tcp_conn_t *conn, uint8_t *buf, uint16_t maxlen);

/**
 * Advertise space freed by tcp_recv() — call it after reading.  An ACK
 * carries the new window once it has grown by min(buffer / 2, MSS)
 * (receiver silly-window avoidance, RFC 9293 §3.8.6.2.2).
 */
void tcp_window_update(net_t *net, tcp_conn_t *conn);

#if NET_USE_IPV4
/** A segment from IPv4. */
void tcp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/** From icmp_input(): an ICMP error quoting a segment we sent — @p quote
 *  is the quoted IP header and data.  Hard errors abort the connection,
 *  soft ones are reported (TCP_EVT_SOFT_ERROR), Fragmentation Needed with
 *  a next-hop @p mtu lowers its segment size (RFC 1191). */
void tcp_icmp_error(net_t *net, uint8_t type, uint8_t code, uint16_t mtu,
                    const uint8_t *quote, uint16_t quote_len);
#endif

#if NET_USE_IPV6
/** A segment from IPv6; a listener accepts peers of either family. */
void tcp6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth);

/** From icmpv6_input(): an ICMPv6 error quoting a segment we sent —
 *  @p quote is the quoted IPv6 header and data, @p param a Packet Too
 *  Big's MTU (at least 1280: icmpv6_input() discards a smaller one), else
 *  0.  Packet Too Big lowers the
 *  connection's segment size (RFC 8201); Port Unreachable aborts it; the
 *  rest is reported (TCP_EVT_SOFT_ERROR). */
void tcp6_icmp_error(net_t *net, uint8_t type, uint8_t code, uint32_t param,
                     const uint8_t *quote, uint16_t quote_len);
#endif

/** Run retransmission, zero-window probe and TIME-WAIT timers, and send
 *  data written but not yet sent; called by net_tick(). */
void tcp_tick(net_t *net, uint32_t elapsed_ms);

#endif /* TCP_H */
