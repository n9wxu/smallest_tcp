# MAC Hardware Abstraction Layer — Design

**Files:** `include/net_mac.h`, `src/net.c` (`net_poll()`, `net_transmit()`),
`include/driver/*.h`, `src/driver/*.c`

## 1. Overview

The stack reaches the network hardware through one interface, `net_mac_t`: a
table of six function pointers.  A driver provides one `const` instance of the
table per driver *type* (`tap_mac_ops`, `rawsock_mac_ops`, `bpf_mac_ops`,
`stm32f4_eth_ops`, `sam4e_gmac_ops`, `stub_mac_ops`); all of its mutable state lives in a
context struct the application allocates (`tap_ctx_t`, `rawsock_ctx_t`,
`bpf_ctx_t`, `stm32f4_eth_ctx_t`, `sam4e_gmac_ctx_t`) and passes to `net_init()` as
`void *driver_ctx`.  The stack never knows the concrete
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
| `peek` | bytes copied (fewer past the end), < 0 if no frame | Copy `len` bytes from `offset` of the current frame into `buf`.  May be called any number of times on the same frame.  The stack reads from offset 0 only; for an `offset` at or past the frame's end the hosted drivers return < 0 and `stm32f4_eth.c` returns 0. |
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
`discard()` anywhere else: `eth_input()` and the layers above it only read
the frame in `net->rx.buf`.

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
  hold it.  `net_poll()` returns the length it read, not the frame's.
- **A short `peek()`.**  `net_poll()` hands `eth_input()` the byte count
  `peek()` returned, not the length `poll()` reported; a frame with nothing
  to read is discarded unprocessed.
- **`rx.buf` and `tx.buf` must not overlap.**  Replies are built in
  `net->tx.buf` while the request is still being read from `net->rx.buf`
  (an echo reply copies one into the other).  `net_init()` refuses buffers
  that share a byte with `NET_ERR_INVALID_PARAM`; they may touch.

`eth_input(net, frame, len)` is public, and the unit tests call it directly
with frames in memory.  A platform whose MAC delivers frames into RAM by DMA
could do the same and skip the copy, provided the frame stays valid and
unmodified until `eth_input()` returns and the platform releases the DMA
buffer itself afterwards (REQ-ETH-026: nothing is read from `net->rx.buf`
on the stack's own account; `net->rx.capacity` still bounds what TCP and
IPv4 say the host can receive).  None of the bundled drivers work that way;
a driver for TinyUSB's network device, outside this tree, does
([§7](#drivers-on-hardware)).

Such a platform needs no RX buffer at all (REQ-ETH-027).
`net_init(net, NULL, rx_size, ...)` takes `rx_size` as the largest frame
the driver will deliver: it becomes `net->rx.capacity`, so TCP advertises
the MSS that size allows, and no memory is reserved for it.  `net_poll()`
then has nowhere to read a frame to, and returns `NET_ERR_INVALID_PARAM`
without asking the driver; the platform calls `eth_input()` for every frame
instead, and must not hand it one longer than `rx_size`.

## 4. Driver models

`poll`/`peek`/`discard` fit two ways of building a driver; the stack cannot
tell them apart.

| | Caching driver | Pure-peek driver |
|---|---|---|
| Frame storage | Its own RAM buffer | The MAC's SRAM only |
| `poll()` | Reads the next frame from the device into its buffer (if not already there) and returns its length | Checks the hardware RX pointer and returns the waiting frame's length, touching no MCU RAM |
| `peek()` | `memcpy` from its buffer | An SPI/DMA read from the MAC's SRAM at `offset` |
| `discard()` | Marks its buffer empty | Advances the hardware RX pointer, freeing the slot |
| Examples | `tap.c`, `rawsock.c`, `bpf.c`, `stm32f4_eth.c`, `sam4e_gmac.c` | ENC28J60 over SPI (not written) |

`stm32f4_eth.c` and `sam4e_gmac.c` are caching drivers whose buffers the
MAC's DMA fills ([§6](#sam4e-gmac-sam4e_gmacc)).

Because `net_poll()` copies the whole frame (up to `rx.capacity`), a
pure-peek driver still moves every byte across its bus, even for frames
`eth_input()` then drops as not addressed to us.  The pure-peek model exists so
that a receive path could read only the bytes it needs; see
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
- **TCP** returns no error for it.  What a busy driver refused has simply
  not been sent yet: the connection notes whether it was a SYN (an active
  open's first included) or data, a FIN, or an ACK, and sends it at the
  next tick, without waiting for the retransmission timeout (REQ-TCP-184,
  186; [tcp.md §4.3](tcp.md#43-output-flush-and-send_data)).  A segment
  the driver failed to send (< 0), and a RST it was too busy for, count as
  lost on the wire: the retransmission or persist timer sends data again,
  and an ACK or RST is repeated when the peer retransmits.  So a driver
  whose link is busy for a moment after every frame — a USB endpoint, a
  polled bus — needs no transmit queue for TCP's sake, though a short one
  spares each refused frame the wait for a tick.
- **Messages the stack sends on its own** — ARP replies, ICMP and ICMPv6
  echo replies and errors, neighbor discovery and MLD messages — are lost, as
  they would be on a congested wire.

## 6. Bundled drivers

| Driver | Platform | Model | Notes |
|---|---|---|---|
| `tap.c` | Linux | caching | `/dev/net/tun`, `IFF_TAP \| IFF_NO_PI`, non-blocking; one frame per `read()`.  A TAP fd never reads back its own writes. |
| `rawsock.c` | Linux | caching | `AF_PACKET` on an existing interface: a NIC or one end of a veth pair.  Needs root or `CAP_NET_RAW`. |
| `bpf.c` | macOS | caching | `/dev/bpfN` bound to an interface, typically one end of a `feth` pair. |
| `stm32f4_eth.c` | STM32F4 (bare metal) | DMA | The ETH peripheral over RMII, the PHY on MDIO; polled.  The NUCLEO-F429ZI port (`boards/nucleo-f429zi`) uses it.  **Not yet run on hardware.** |
| `sam4e_gmac.c` | SAM4E (bare metal) | DMA | The GMAC peripheral over MII, the PHY on MDIO; polled.  The SAM4E Xplained Pro port (`boards/sam4e-xplained-pro`) uses it: the board of the hardware job, and the one bundled driver that has run on hardware. |
| `stub.c` | any | — | Does nothing; links the stack for ARM size measurement (`bench/`). |

The three hosted drivers keep a 1514-byte frame buffer in their context (the
largest Ethernet II frame without FCS); `stm32f4_eth.c` and `sam4e_gmac.c`
read the frame where the DMA put it.

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

### SAM4E GMAC (`sam4e_gmac.c`)

A driver for the SAM4E's GMAC peripheral (the Cadence 10/100 MAC; SAM4E
datasheet §41), written for and run on a SAM4E Xplained Pro — an
ATSAM4E16E with a KSZ8081MNX PHY — the DUT of the hardware job
([test-plan.md §4](../test-plan.md#4-hardware-test-fixture)).

- **Model.**  A DMA driver: rings of two-word descriptors — four RX, two
  TX, the last of each marked as the wrap — each with a 1536-byte buffer
  in the context (`sam4e_gmac_ctx_t`).  The MAC is told buffers of that
  size (`DCFGR.DRBS`), so a frame is never split; it stores no frame with
  an error, and strips the CRC.  `poll()` returns the frame of the current
  RX descriptor once the MAC has marked it; `peek()` copies from that
  buffer; `discard()` hands it back.  A MAC that ran out of buffers takes
  the next frame by itself.  `send()` copies the frame into the next TX
  buffer, or returns 0 (busy) while the MAC still has it; the MAC pads a
  short frame and appends the CRC.
- **The transmitter stalls, and is started again.**  The MAC stops at a
  descriptor it finds used, and a start bit written while it is still
  going does nothing.  A second frame queued at that moment — an ACK and
  the data behind it, 70 µs apart — would stay in the ring until the next
  one is sent.  `poll()` and `send()` therefore start the transmitter
  whenever a frame waits and it is idle (`tx_kick()`).
- **A descriptor is read in the MAC's order.**  The MAC writes a
  descriptor's status and then marks it ours in the address word, at any
  moment.  `poll()` reads the mark first and the status only after it:
  read the other way round, a frame that completes between the two reads
  has a mark and no length.
- **Bring-up** (`init`): the peripheral's clock, MII selected
  (`GMAC_UR`), the address filter (our address, broadcast, and all
  multicast through a hash of all ones: the stack filters the rest), the
  rings, the MDIO port, then the PHY's reset and auto-negotiation.
- **Link.**  As the STM32F4 driver's: `sam4e_gmac_link_poll()`, every
  half second, reads the PHY's standard registers and gives the MAC the
  best mode both ends advertised.
- **Not done.**  Interrupts, checksum offload, the hardware multicast
  filter, frames larger than one buffer, RMII (the SAM4E's GMAC has MII
  only).

The board (`boards/sam4e-xplained-pro`) provides the rest: start-up code
and linker scripts (for flash, and for RAM), the watchdog off, 120 MHz
from the 12 MHz crystal, SysTick milliseconds, the MII pins, the console on
the EDBG's virtual COM port, `flash.sh`, and the `tcp_echo_demo` firmware.
The SAM4E has no random number generator: the firmware seeds the stack
from the chip's identity and from when the link came up, which is no
secret — enough for a test fixture, not for a product.

### STM32F4 Ethernet (`stm32f4_eth.c`)

A driver for the STM32F4's ETH peripheral (RM0090 §33), written for the
hardware job when its DUT was to be a NUCLEO-F429ZI, and **not yet run on
hardware**: it builds in CI (`board-nucleo-f429zi`), and its register
addresses and bits were checked against ST's CMSIS header and legacy HAL,
but no frame has gone through it.

- **Model.**  A DMA driver: chained rings of normal descriptors — four RX,
  two TX — each with a 1524-byte buffer in the context
  (`stm32f4_eth_ctx_t`), which must therefore be in SRAM, where the DMA
  reaches (not the core-coupled RAM).  `poll()` returns the frame of the
  current RX descriptor once the DMA has released it, without its CRC;
  `peek()` copies from that buffer; `discard()` hands it back to the DMA
  and resumes a DMA that had run out of buffers.  A buffer takes a whole
  frame, so a frame is never split; a frame with an error is dropped.
  `send()` copies the frame into the next TX buffer, or returns 0 (busy)
  while the DMA still owns it.
- **Bring-up** (`init`): the SYSCFG and MAC clocks, RMII selected while
  the MAC is held in reset, the DMA's software reset — which completes
  only with the PHY's 50 MHz reference clock, so its timeout means no PHY
  or unset RMII pins — then the PHY reset and auto-negotiation over MDIO,
  the MAC's address filter (our address, broadcast, all multicast: the
  stack filters the rest), store-and-forward DMA, and the MAC's and DMA's
  transmit and receive paths started.  Configuration registers are written
  twice with a pause between, as ST's HAL does (RM0090: a second write
  within four TX/RX clock cycles may be lost).
- **Link.**  `init` does not wait for a link.  `stm32f4_eth_link_poll()`,
  called from the main loop every half second, reads the PHY's status and,
  when the link comes up, sets the MAC to the best mode both ends
  advertised (the standard auto-negotiation registers, so any clause-22
  PHY — the Nucleo's LAN8742A, a DP83848).
- **Not done.**  Interrupts, checksum offload, the hardware multicast
  filter, frames larger than one buffer.

The board (`boards/nucleo-f429zi`) provides the rest: start-up code and
linker script, the 168 MHz clock from the HSI, SysTick milliseconds, the
RMII pins, the ST-LINK console, and the `tcp_echo_demo` firmware
([test-plan.md §4](../test-plan.md#4-hardware-test-fixture)).

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

Drivers the tree does not have: the ENC28J60 (SPI, pure-peek) and USB
CDC-ECM (the use case `dhcpv4_server` was written for).

### Drivers on hardware

Of the bundled drivers for a microcontroller, `sam4e_gmac.c` has run on
its board.  The drivers the stack runs on in other projects are theirs;
together they show the two shapes a driver takes:

| Driver | Device and link | Shape |
|---|---|---|
| `sam4e_gmac.c`, in this tree | SAM4E Xplained Pro, 10/100 Ethernet | A caching `net_mac_t` on the MAC's DMA (§6).  The one the conformance and fuzz suites run against |
| `net_glue.c` in [pyro_fw](https://github.com/n9wxu/pyro_fw) | RP2040, a USB CDC-ECM / RNDIS network gadget (TinyUSB) under FreeRTOS | The table's `poll()` reports nothing and `net_poll()` is never called: TinyUSB's receive callback keeps the frame, and the network task hands it to `eth_input()` in TinyUSB's buffer (§3).  `send()` gives the frame to the USB endpoint |
| `link485.c` in [halfduplex-tcpip](https://github.com/n9wxu/halfduplex-tcpip), also used by [ve.direct-concentrator](https://github.com/n9wxu/ve.direct-concentrator) | SAMD21, the polled slave of an RS-485 master: one Ethernet frame each way per poll | A caching `net_mac_t` (§4): `poll()` returns the frame the last poll carried, and `send()` queues a frame for the next answers, and returns 0 when it has no room |

On the RP2040 (a macOS host) ARP, ping, the DHCPv4 server, mDNS with a
DNS-SD service and an HTTP server over 16 connections run at 457-592 kB/s
against lwIP's 516-668 kB/s on the same board
([the measurements](https://github.com/n9wxu/smallest_tcp/issues/6), with
what was not tested).  What these links ask of the stack:

- a frame in the driver's own memory (REQ-ETH-026), and no receive buffer
  reserved for such a driver (REQ-ETH-027);
- a busy driver costs TCP no retransmission timeout: a SYN or data
  (REQ-TCP-184), a FIN and an ACK (REQ-TCP-186) go at the next tick;
- a ring buffer sends full segments across its wrap (REQ-TCP-185), a
  simultaneous close waits for no timer (REQ-TCP-183), and every data
  segment carries PSH for a host that delays its ACK of one without
  (REQ-TCP-187);
- the API under a prefix, beside an application's own names
  (`NET_API_PREFIX`,
  [configuration.md §7](configuration.md#7-the-api-under-a-prefix));
- on the RS-485 link, whose master drops a frame now and then, a
  retransmission timeout that follows the measured round trip and comes
  back down after a loss (RFC 6298, REQ-TCP-091, 099).  Damage on such a
  link is the link's to repair: that project resends a damaged frame
  within milliseconds, and TCP's timer stays the end-to-end backstop.

For a gadget's point-to-point link, `MDNS_TIEBREAK` 0 saves 0.9 KB
([mdns.md §5](mdns.md)).

## 8. Future work

### Checksum offload (not implemented)

There are no capability flags, in `net_mac_t` or in `net_config.h`: every
checksum is computed and verified in software (REQ-CKSUM-022..025).  Adding
offload would mean, per protocol, a compile-time switch that writes the
field for the MAC to fill (TX) or skips verification (RX), in
`ipv4_build_tos()` and `ipv4_build_router_alert()`,
`udp_send_inplace_opts()`, `udp6_send_inplace()`, TCP's `frame_send()`,
`icmp_send()`, `igmp_send()`, `icmpv6_send()`, and the input paths.  A
compile-time switch rather than a run-time query is the right shape: a
device's MAC does not change, and the compiler removes the unused path.

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
combine buffer.  A NULL `send_iov` would fall back to the copy.

### Streaming receive

A pure-peek driver could let `rx.buf` shrink to the size of the largest header
region, with each layer peeking only its own header and checksums accumulated
over chunked `peek()` reads.  That needs a different handler interface than
the payload pointer handlers are given; the trade-offs are in the decision
record in
[udp.md §10](udp.md#101-payload-pointers-not-frame-offsets).
