/**
 * @file net_mac.h
 * @brief MAC Hardware Abstraction Layer — vtable interface.
 *
 * Abstracts the physical network interface so the protocol stack works
 * identically on Linux TAP, macOS feth+BPF, ENC28J60 (SPI), CDC-ECM
 * (USB), or any other Ethernet-capable device.
 *
 * ── RX Interface Philosophy ──────────────────────────────────────────
 *
 * The MAC interface does NOT expose an RX buffer to the caller.  All
 * receive data access is through peek() + discard():
 *
 *   poll()            — Is there a frame waiting?  How long?
 *   peek(off,buf,len) — Block-read bytes at offset into any caller buffer.
 *   discard()         — Release the current frame (advance RX pointer).
 *
 * This is uniform across two driver implementation models:
 *
 *  Caching driver  — Driver maintains its own internal frame buffer
 *                    (e.g. TAP, BPF, ENC28J60 with DMA cache).
 *                    poll() fills the internal buffer from hardware.
 *                    peek() is a fast memcpy from the internal buffer.
 *                    discard() clears the internal buffer.
 *
 *  Pure-peek driver — Driver has no internal frame buffer.
 *                    poll() checks the hardware RX pointer.
 *                    peek() issues SPI/DMA reads directly from
 *                    hardware SRAM at the specified offset.
 *                    discard() advances the hardware RX pointer.
 *
 * The protocol stack never knows which model is in use.  peek() with a
 * caller-provided buffer is the universal block-read primitive:
 *
 *   peek(ctx, 12, etype, 2)                  — 2-byte ethertype, stack-local
 *   peek(ctx, 22, conn->remote_mac, 6)       — 6B MAC into connection struct
 *   peek(ctx,  0, arp_scratch, 42)           — full ARP, 42B stack scratch
 *   peek(ctx,  0, net->rx.buf, frame_len)    — full IPv4 into app MTU buffer
 *   peek(ctx, payload_off, tcp_rx_ptr, len)  — TCP payload → tcp_rx_mem
 *
 * For streaming checksum on a pure-peek SPI driver (zero frame buffer):
 *   uint8_t chunk[8];
 *   for (off = 0; off < tcp_len; off += 8) {
 *       peek(ctx, tcp_start + off, chunk, MIN(8, tcp_len-off));
 *       net_cksum_add(&cksum, chunk, n);   // accumulate; discard bytes
 *   }
 *
 * ── Application Layer Responsibility ────────────────────────────────
 *
 * After net_poll() raises TCP_EVT_DATA (or any event via on_event()),
 * the layer above MUST consume the received data before the next call
 * to net_poll().  Delay blocks the RX drain and risks MAC buffer
 * overflow on hardware with small ring buffers (e.g. ENC28J60 8 KB).
 * Treat it like an interrupt handler — be fast.
 *
 * ── TX Interface ─────────────────────────────────────────────────────
 *
 * send() takes a complete Ethernet frame from the application's TX
 * buffer.  The MAC driver may maintain an internal TX buffer, or it
 * may accept the caller's buffer directly (e.g. SPI DMA from MCU RAM).
 * This is a driver implementation detail invisible to the caller.
 */

#ifndef NET_MAC_H
#define NET_MAC_H

#include <stdint.h>

/**
 * @brief MAC driver vtable.
 *
 * One instance per driver type (e.g. tap_mac_ops, bpf_mac_ops).
 * Drivers are stateless — all mutable state lives in the driver context
 * struct (tap_ctx_t, bpf_ctx_t, etc.) passed as void *ctx.
 */
typedef struct {
  /**
   * Initialize the hardware interface.
   * @return 0 on success, <0 on error.
   */
  int (*init)(void *ctx);

  /**
   * Transmit a complete Ethernet frame.
   * The frame buffer must remain valid until this call returns.
   * @param frame  Pointer to the Ethernet frame (ETH header + payload).
   * @param len    Total frame length in bytes.
   * @return Bytes transmitted (>0), 0 if temporarily busy, <0 on error.
   */
  int (*send)(void *ctx, const uint8_t *frame, uint16_t len);

  /**
   * Check whether an RX frame is available.
   *
   * For caching drivers: reads the next frame from the hardware into
   * the driver's internal buffer (if not already buffered), then
   * returns its length.
   *
   * For pure-peek drivers: inspects the hardware RX pointer and
   * returns the length of the waiting frame, touching no MCU RAM.
   *
   * Non-blocking: returns 0 immediately if no frame is pending.
   *
   * @return Frame length in bytes if a frame is ready, 0 if the RX
   *         queue is empty, <0 on hardware error.
   */
  int (*poll)(void *ctx);

  /**
   * Block-read bytes from the current RX frame without consuming it.
   *
   * Reads up to @p len bytes starting at byte @p offset within the
   * current frame.  The frame remains "current" until discard() is
   * called; peek() may be called multiple times on the same frame.
   *
   * For caching drivers: memcpy from the internal frame buffer.
   * For pure-peek drivers: SPI/DMA read directly from hardware SRAM.
   *
   * @param offset  Byte offset within the current frame (0 = first byte).
   * @param buf     Destination buffer (caller-provided, any size).
   * @param len     Number of bytes to read.
   * @return Bytes copied (may be < len if offset+len > frame_len),
   *         <0 if no current frame.
   */
  int (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);

  /**
   * Release the current RX frame.
   *
   * For caching drivers: clears the internal frame buffer.
   * For pure-peek drivers: advances the hardware RX ring pointer,
   * freeing the hardware SRAM slot for the next incoming frame.
   *
   * Must be called after poll() returns >0, even if the frame was
   * not read (this allows fast discard of frames not addressed to us).
   */
  void (*discard)(void *ctx);

  /**
   * Shut down the interface and release all resources.
   */
  void (*close)(void *ctx);

} net_mac_t;

#endif /* NET_MAC_H */
