# Coding Rules

**Applies to:** everything under `src/` and `include/`

These rules keep the stack portable to 8- and 32-bit microcontrollers,
small, and safe against hostile input.  Each has a reason; the reason is
what to weigh if a rule ever seems to be in the way.

## 1. Language and build

- **C99, no extensions.**  Every file compiles with
  `-std=c99 -Wall -Wextra -Werror -pedantic` (the CMake targets when built
  as the top-level project, and the Makefile's Cortex-M0 builds).  No GCC
  attributes, no packed structs, no statement expressions, no
  `_Static_assert` (C11).
- **Wire formats by hand.**  Protocol fields are read and written byte by
  byte with `net_read16be()`, `net_write32be()` and friends
  (`net_endian.h`), at named offsets (`UDP_OFF_LEN`, `IPV4_OFF_TTL`, …).
  Never overlay a struct on a packet: layout, padding, alignment and byte
  order all vary by compiler and target ([byte-order.md](byte-order.md)).
- **Style.**  Two-space indent, 80 columns, as clang-format's default LLVM
  style produces.  Public names carry their module's prefix (`udp_`,
  `tcp_`, `ipv6_`, `net_`); internal functions are `static`; constants are
  upper case with the same prefix.  Headers private to the library live in
  `src/` (`dhcpv4_wire.h`, `tls_internal.h`).
- **Tunables** are `#ifndef` defaults, in `net_config.h` or in the module's
  header, so an application can override them
  ([configuration.md](configuration.md)).

## 2. Memory

- **No dynamic allocation.**  No `malloc()`, no variable-length arrays, no
  `alloca()`.  Every object is supplied by the application
  ([memory-model.md](memory-model.md)).
- **No global mutable state.**  State lives in `net_t` or in a structure the
  application passed in.  File-scope data is `const`.
- **Build messages in place.**  An outgoing frame is written directly into
  `net->tx.buf` at its final offset (`UDP_PAYLOAD_OFFSET`, `ICMPV6_OFFSET`,
  …), headers around it, then sent with `net_transmit()`.  Do not assemble a
  message in a local buffer to copy it in afterwards.
- **Check capacity before writing.**  Every builder compares the finished
  frame's length with `net->tx.capacity` before it writes, computing in
  `uint32_t` so the sum cannot wrap:
  `if ((uint32_t)UDP_PAYLOAD_OFFSET + data_len > net->tx.capacity)`.
- **Bounded stack use.**  Locals are small and fixed-size.  The largest are
  listed in [memory-model.md §4](memory-model.md#4-per-module-memory); a new
  one of more than a few dozen bytes needs a reason.

## 3. Parsing received data

Every byte that arrives is untrusted.

- **Trust only the length the layer below vouched for.**  A layer parses
  within the `payload_len` it was handed, and validates every length field
  from the wire against it before use: IPv4 total length and header length
  (`ipv4_parse()`), the IPv6 payload length and each extension header
  (`ipv6_parse()`), the UDP length (`udp_length()`), the TCP data offset
  (`parse_segment()`), every option walk (TCP options in `peer_mss()`, NDP
  options in `options_valid()`, DHCP options), DNS names (compression
  pointers are followed with a hop limit), TFTP strings (`next_string()`
  stops at the end of the datagram).
- **Widen before adding.**  Offsets and lengths are `uint16_t`; sums that
  could exceed 65535 are computed in `uint32_t` (`ipv6_parse()` keeps `off`
  and `end` in `uint32_t`).
- **Reject, don't repair.**  A malformed packet is dropped, silently, as the
  RFCs require.  Never adjust an inconsistent length field to make a packet
  fit.
- **Do not modify the received frame.**  Parsers treat `net->rx.buf` as read
  only; replies are built in `net->tx.buf`.

## 4. No run-time division

Stack code uses `/` and `%` only with a power-of-two constant divisor, which
compiles to a shift or a mask.

Cortex-M0 (ARMv6-M) has no divide instruction, and no 32×32→64 multiply
either, so GCC turns *any* other division — even `x / 10u` — into a call to
libgcc's `__aeabi_uidiv` or `__aeabi_uidivmod`: code the size benchmarks
would carry for one expression, and a slow loop at run time.  The places
that need a division use a helper instead:

| Need | Helper | How |
|---|---|---|
| Decimal text of a number | `net_u32_to_dec()` (`net_text.c`) | Subtracts powers of ten |
| Random number below *n* | `net_random_below()` (`net.c`) | `((r & 0xFFFF) * n) >> 16` — scaling, for *n* ≤ 65536 |
| Milliseconds to whole seconds | `net_whole_seconds()` (`net.c`) | Subtracts 1000 in a loop, keeping the remainder |
| Ring-buffer wrap | `ring_advance()` (`tcp_buf_saw.c`) | One conditional subtraction (`pos < capacity`, `n ≤ capacity`) |
| A tenth, for DHCPv6 jitter | `tenth()` (`dhcpv6_client.c`) | `(v * 205) >> 11` ≈ *v* × 0.1001 (reordered for large *v* to avoid overflow) |

`make arm-check-division` enforces the rule: it compiles every source in
`src/` for Cortex-M0 (dual stack), plus each size-benchmark configuration,
and fails if any object references a library divide (`__aeabi_uidiv`,
`__aeabi_uidivmod`, their signed and 64-bit variants, or the older
`__udivsi3` family).  CI runs it as part of `make arm-size-all`.  The
Mbed TLS crypto backend is excluded; it is not stack code.

## 5. Comments

Long comments in code tend to stand in for clear structure, and drift from
what the code does.  The rules:

- **Prefer structure to comments.**  A well-named function or variable, or
  a condition extracted into a predicate (`sent_to_many()`,
  `destination_is_us()`, `acks_our_syn()`), says what a comment would have.
  Restructure before explaining.
- **Comments say why, not what.**  A comment earns its place by stating a
  reason, an RFC rule, or a trap the code cannot show: *"one subtraction
  wraps it (no '%', which Cortex-M0 would have to call a library divide
  for)"*, *"MLD first: a report that ND sends now is then repeated a full
  interval later"*.
- **RFC requirement tags once per function.**  The `REQ-xxx` identifiers a
  function implements are listed in the comment above it
  (`/* REQ-UDP-032, 033 */`), not sprinkled on individual statements.  The
  file header lists the range the file covers.
- **File headers are a one-paragraph brief**: what the file is, its RFCs,
  and, where it helps, a pointer to its design document.
- **Long explanations live in `docs/`.**  Driver models, receive and
  transmit paths, decision records, timer semantics and the like belong in
  the design documents, where they can be kept current as a whole.  A header
  may point there (`See docs/design/mac-hal.md`).
- **API comments state the contract**: what the caller must provide, what is
  returned, what pointers remain valid for how long — not how the function
  works inside.
