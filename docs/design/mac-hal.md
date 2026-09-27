# MAC Hardware Abstraction Layer — Design

**Files:** `include/net_mac.h`, `src/net.c` (`net_poll()`, `net_transmit()`),
`include/driver/*.h`, `src/driver/*.c`
**Last updated:** 2026-09-27

## 1. Overview

The stack reaches the network hardware through one interface, `net_mac_t`: a
table of six function pointers.  A driver provides one `const` instance of the
table per driver *type* (`tap_mac_ops`, `rawsock_mac_ops`, `bpf_mac_ops`,
`stub_mac_ops`); all of its mutable state lives in a context struct the
application allocates (`tap_ctx_t`, `rawsock_ctx_t`, `bpf_ctx_t`) and passes
to `net_init()` as `void *driver_ctx`.  The stack never knows the concrete
context type, so the tables can live in flash and one driver can serve several
interfaces.

The stack itself calls only `poll`, `peek` and `discard` (from `net_poll()`)
and `send` (from `net_transmit()`).  `init` and `close` are for the
application: **`net_init()` does not open the interface** — call
`driver->init(ctx)` yourself, and `driver->close(ctx)` on shutdown.

## 2. Interface

```c
typedef struct {
  int  (*init)(void *ctx);
  int  (*send)(void *ctx, const uint8_t *frame, uint16_t len);
  int  (*poll)(void *ctx);
  int  (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);
  void (*discard)(void *ctx);
  void (*close)(void *ctx);
} net_mac_t;
```

| Function | Returns | Contract |
|---|---|---|
| `init` | 0, or < 0 on error | Open the interface and bring it up. |
| `send` | bytes sent, 0 if busy, < 0 on error | Transmit one complete Ethernet frame (no FCS).  `frame` need only stay valid during the call. |
| `poll` | frame length, 0 if none, < 0 on error | Make the next received frame *current*, without blocking.  Until `discard()` the same frame stays current and `poll()` keeps returning its length. |
| `peek` | bytes copied (fewer past the end), < 0 if no frame | Copy `len` bytes from `offset` of the current frame into `buf`.  May be called any number of times on the same frame. |
| `discard` | — | Release the current frame; the next `poll()` moves on. |
| `close` | — | Shut the interface down and release its resources. |

## 3. The receive lifecycle: `net_poll()`

`net_poll()` owns a received frame from start to finish:

```
net_poll(net)
  len = poll()                       0: nothing waiting, < 0: driver error
  len = min(len, net->rx.capacity)
  peek(0, net->rx.buf, len)          the whole frame, one copy
  eth_input(net, net->rx.buf, len)   dispatch through every layer
  discard()                          release the frame
  return len
```

It handles at most one frame per call; drain the MAC with
`while (net_poll(&net) > 0) {}`.  Nothing in the stack calls `peek()` or
`discard()` anywhere else, and `eth_input()` no longer discards.

Consequences and invariants:

- **One copy.**  Every layer parses the frame in place in `net->rx.buf`;
  handlers receive pointers into it (`eth_frame_t`, `ipv4_hdr_t`,
  `ipv6_hdr_t`, the UDP payload pointer, the TCP segment).  The copy from the
  driver is the only one on the receive path until TCP delivers data into a
  connection's own buffer.
- **Pointers are valid only during dispatch.**  Anything a handler is given
  points into `net->rx.buf` and is overwritten by the next `net_poll()`.
  Copy out what must outlive the call.
- **Handlers run before `discard()`.**  The driver's receive slot is held
  while UDP handlers, TCP event callbacks and module `*_input()` functions
  run.  Treat them like interrupt handlers: do the minimum, set a flag, act
  from the main loop.  (TCP's `on_event` additionally must not send or close;
  see `tcp.h`.)
- **Poll often enough to drain the MAC.**  TCP data is copied into the
  connection's RX buffer during `net_poll()` and flow-controlled by the
  advertised window, so the application may read it later.  The hardware
  queue has no such protection: a main loop that calls `net_poll()` too
  rarely lets a small hardware ring (an ENC28J60 has 8 KB) overflow, and
  frames are lost.
- **Oversize frames.**  A frame longer than `rx.capacity` is truncated to it.
  IPv4 and IPv6 then reject it (the datagram's own length exceeds the bytes
  present), so an undersized RX buffer drops large datagrams rather than
  delivering partial data.  ARP (42 bytes) still works in any buffer that can
  hold it.
- **A short `peek()`.**  `net_poll()` hands `eth_input()` the byte count
  `peek()` returned, not the length `poll()` reported; a frame with nothing
  to read is discarded unprocessed.
- **`rx.buf` and `tx.buf` must not overlap.**  Replies are built in
  `net->tx.buf` while the request is still being read from `net->rx.buf`
  (an echo reply copies one into the other).  `net_init()` does not check
  this.

`eth_input(net, frame, len)` is public, and the unit tests call it directly
with frames in memory.  A platform whose MAC delivers frames into RAM by DMA
could do the same and skip the copy, provided the frame stays valid and
unmodified until `eth_input()` returns and the platform releases the DMA
buffer itself afterwards.  None of the bundled drivers work that way.

## 4. Driver models

`poll`/`peek`/`discard` fit two ways of building a driver; the stack cannot
tell them apart.

| | Caching driver | Pure-peek driver |
|---|---|---|
| Frame storage | Its own RAM buffer | The MAC's SRAM only |
| `poll()` | Reads the next frame from the device into its buffer (if not already there) and returns its length | Checks the hardware RX pointer and returns the waiting frame's length, touching no MCU RAM |
| `peek()` | `memcpy` from its buffer | An SPI/DMA read from the MAC's SRAM at `offset` |
| `discard()` | Marks its buffer empty | Advances the hardware RX pointer, freeing the slot |
| Examples | `tap.c`, `rawsock.c`, `bpf.c` | ENC28J60 over SPI (not written) |

Because `net_poll()` copies the whole frame (up to `rx.capacity`), a
pure-peek driver still moves every byte across its bus, even for frames
`eth_input()` then drops as not addressed to us.  The pure-peek model exists so
that a future receive path could read only the bytes it needs; see
[§8](#8-future-work).

## 5. Transmit: `net_transmit()`

Every frame is built in place in `net->tx.buf` — Ethernet header, IP header,
transport header, payload — and handed over with
`net_transmit(net, frame_len)`, which calls `send()` once.  A driver may copy
the frame into its own TX buffer or start a DMA from the caller's buffer, but
it must be finished with `frame` when `send()` returns: the next frame is
built in the same memory.

`net_transmit()` maps `send()`'s result: > 0 is `NET_OK`, 0 — the driver had
no room — is `NET_ERR_BUSY`, and < 0 is `NET_ERR_NO_FRAME`.  Either error
means the frame was not sent.  What happens next depends on the caller:

- **The application's own sends** — `udp_send()`, `udp6_send()` and their
  in-place forms, `arp_request()` — return the error, and the application may
  try again.  An in-place payload is still in `tx.buf` only until the next
  frame is built there.
- **TCP** ignores it.  Every segment counts as sent and lost: SYN (an
  active open's first included), SYN,ACK, data, FIN and window probes are
  sent again by the retransmission or persist timer
  ([tcp.md §4.3](tcp.md#43-output-flush-and-send_data)), and a lost ACK or
  RST is repeated when the peer retransmits.
- **Messages the stack sends on its own** — ARP replies, ICMP and ICMPv6
  echo replies and errors, neighbor discovery and MLD messages — are lost, as
  they would be on a congested wire.

`net_transmit()` used to return `NET_OK` for a busy driver, so the frame was
lost with no one told.

## 6. Bundled drivers

| Driver | Platform | Model | Notes |
|---|---|---|---|
| `tap.c` | Linux | caching | `/dev/net/tun`, `IFF_TAP \| IFF_NO_PI`, non-blocking; one frame per `read()`.  A TAP fd never reads back its own writes. |
| `rawsock.c` | Linux | caching | `AF_PACKET` on an existing interface: a NIC or one end of a veth pair.  Needs root or `CAP_NET_RAW`. |
| `bpf.c` | macOS | caching | `/dev/bpfN` bound to an interface, typically one end of a `feth` pair. |
| `stub.c` | any | — | Does nothing; links the stack for ARM size measurement (`bench/`). |

All three real drivers keep a 1514-byte frame buffer in their context (the
largest Ethernet II frame without FCS).

### Raw socket (`rawsock.c`)

An `AF_PACKET` socket sees what the host sees, which differs from a NIC in
three ways the driver hides from the stack:

- **Its own MAC.**  The stack answers to its configured MAC, not the
  interface's, so `init` adds a `PACKET_MR_PROMISC` membership.  The kernel
  drops it when the socket closes.  The socket is created with protocol 0 so
  nothing from another interface is queued before `bind()` names this one.
- **Our own sends.**  Frames this host transmits are delivered to packet
  sockets too.  `poll()` skips `PACKET_OUTGOING` frames; on Linux 4.20+
  `PACKET_IGNORE_OUTGOING` stops the kernel queuing them at all.
- **Checksum offload.**  With `PACKET_VNET_HDR`, every frame arrives behind a
  `struct virtio_net_hdr`.  Frames the local kernel sent (from the veth peer,
  or towards a local TAP) can carry a TCP/UDP checksum left *partial* for hardware
  that will never see it; the header flags this (`VIRTIO_NET_HDR_F_NEEDS_CSUM`)
  and gives `csum_start` and `csum_offset`.  The kernel has already stored the
  folded pseudo-header sum in the checksum field, so the Internet checksum of
  `frame[csum_start..len)`, *including* that field, is the finished checksum;
  `rawsock_csum_complete()` computes it and writes it in, as the NIC would
  have.  That function is portable, so it is unit-tested on every platform.

  GSO/GRO super-frames (`gso_type` set), frames larger than 1514 bytes, and
  frames whose partial checksum lies outside the frame are dropped whole —
  never truncated — and counted in `rx_dropped`.  Sends carry
  an all-zero `virtio_net_hdr`: no offload requested.  `ENOBUFS`/`EAGAIN` on
  send return 0 (busy).

### BPF (`bpf.c`)

One `read()` of a BPF descriptor returns a *batch* of frames, each behind a
`struct bpf_hdr` and padded to `BPF_WORDALIGN`.  The driver reads a batch into
`read_buf[]` (4 KB) and extracts one frame at a time into `cur_frame[]`:
`poll()` returns the current frame if there is one, else extracts the next
from the batch, else reads a new batch.  `discard()` empties `cur_frame[]`, so
the next `poll()` advances within the batch.  Unlike `rawsock.c`, a captured
frame longer than 1514 bytes is truncated to it (and then rejected by IP, as
in §3).

`init` sets `BIOCIMMEDIATE` (deliver frames as they arrive), `BIOCSHDRCMPLT`
(we supply the Ethernet source address), `BIOCPROMISC` (the stack's own MAC),
and `BIOCSSEESENT = 0` (macOS would otherwise deliver our own transmissions,
which a TAP fd never does).

Creating a `feth` pair (the tests use `feth0`, the demos open `feth1`):

```sh
sudo ifconfig feth0 create && sudo ifconfig feth1 create
sudo ifconfig feth0 peer feth1
sudo ifconfig feth0 inet 10.0.0.1/24 up && sudo ifconfig feth1 up
```

## 7. Writing a driver

1. Define a context struct holding every piece of mutable state, and one
   `const net_mac_t` table.
2. Make `poll()` non-blocking and idempotent: until `discard()`, return the
   same frame's length.
3. Make `peek()` bounds-checked: copy at most up to the end of the frame, and
   return < 0 when there is no current frame.
4. Drop frames the stack cannot use rather than truncating them, if the
   hardware allows (as `rawsock.c` does).
5. Return 0 from `send()` when the hardware is momentarily busy and < 0 only
   for real failures.
6. If the MAC has a multicast filter, program it with the groups the
   application joins: `ipv4_mcast_mac()` for IPv4 groups; for IPv6,
   `ipv6_mcast_mac()` of all-nodes, of each address's solicited-node group
   and of each joined group.  The stack filters again in `eth_input()`, so an
   open (promiscuous or all-multicast) filter is always correct.

Possible future drivers include the ENC28J60 (SPI, pure-peek), USB CDC-ECM
(the use case `dhcpv4_server` was written for), and MCU EMACs with DMA
descriptor rings.  None are in the tree.

## 8. Future work

### Checksum offload (not implemented)

There are no capability flags.  Earlier versions of this document and of
`net_config.h` described compile-time `NET_MAC_CAP_TX_CKSUM_*` /
`NET_MAC_CAP_RX_CKSUM_OK` switches, but no code ever read them and they have
been removed.  Every checksum is computed and verified in software.  Adding
offload would mean, per protocol, a compile-time switch that writes the
field for the MAC to fill (TX) or skips verification (RX), in
`ipv4_build_ttl()`, `udp_send_inplace_from()`, `udp6_send_inplace()`, TCP's
`frame_send()`, `icmpv6_send()`, and the input paths.  A compile-time switch
rather than a run-time query remains the right shape: a device's MAC does not
change, and the compiler removes the unused path.

### Scatter-gather transmit

`send(ctx, frame, len)` takes one contiguous frame, so every payload is
copied into `net->tx.buf` after its headers, and the TX buffer must hold the
largest frame sent (342 bytes for DHCP; 554 for a 512-byte UDP payload).  An
optional vtable entry

```c
typedef struct { const uint8_t *base; uint16_t len; } net_iov_t;
int (*send_iov)(void *ctx, const net_iov_t *iov, uint8_t iovcnt);
```

would let the stack build only the headers in `tx.buf` and pass the payload —
possibly in flash — as a second region.  The checksum can still be computed
across both regions with the incremental API.  TAP could use `writev()`,
`rawsock.c` already sends with an iovec, an ENC28J60 writes header then
payload into its SRAM, and DMA EMACs chain descriptors; BPF would need a
combine buffer.  A NULL `send_iov` would fall back to today's copy.

### Streaming receive

A pure-peek driver could let `rx.buf` shrink to the size of the largest header
region, with each layer peeking only its own header and checksums accumulated
over chunked `peek()` reads.  That needs a different handler interface than
today's payload pointer; the trade-offs are in the decision record in
[udp.md §10](udp.md#101-decision-record-payload-pointers-not-frame-offsets).
