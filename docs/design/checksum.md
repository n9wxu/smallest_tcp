# Checksum Design

**Files:** `include/net_cksum.h`, `src/net_cksum.c`; pseudo-headers in
`ipv4_cksum()` (`src/ipv4.c`) and `ipv6_cksum()` (`src/ipv6.c`)
**RFCs:** RFC 1071 (computing the Internet checksum), RFC 1624 (incremental
update), RFC 768 / RFC 9293 / RFC 8200 §8.1 (pseudo-headers)
**Requirements:** [checksum.md](../requirements/checksum.md)

## 1. API

```c
typedef struct {
  uint32_t sum;
  uint8_t odd;   /* the last piece ended half-way through a word */
} net_cksum_t;

void     net_cksum_init(net_cksum_t *c);
void     net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len);
void     net_cksum_add_u16(net_cksum_t *c, uint16_t val);
void     net_cksum_add_u32(net_cksum_t *c, uint32_t val);
uint16_t net_cksum_finalize(net_cksum_t *c);

uint16_t net_cksum(const uint8_t *data, uint16_t len);      /* one block */
int      net_cksum_verify(const uint8_t *data, uint16_t len); /* 1 if it is 0 */

uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val,
                          uint16_t new_val);                  /* RFC 1624 */

/* Upper-layer checksums over a pseudo-header */
uint16_t ipv4_cksum(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                    const uint8_t *data, uint16_t len);
uint16_t ipv6_cksum(const uint8_t *src, const uint8_t *dst,
                    uint8_t next_header, const uint8_t *data, uint16_t len);
```

The incremental form exists so that pseudo-headers and discontiguous pieces
add up without being copied into one buffer.

## 2. Implementation

- **32-bit accumulator, fold at the end.**  `net_cksum_add()` adds 16-bit
  big-endian words into a `uint32_t` without folding; `net_cksum_finalize()`
  folds the carries back in (end-around carry) until the value fits in 16
  bits, then complements it.  One fold at the end is cheaper than a carry
  check per word.  The accumulator cannot overflow before about 65,537 words
  (131 KB) have been added, far beyond any frame.
- **Byte-wise, alignment-free.**  Each word is composed from two bytes
  (`data[i] << 8 | data[i + 1]`), so the data may start at any address and
  the result does not depend on host byte order.  An odd length is padded with
  a zero byte, as RFC 1071 specifies — and `odd` remembers it, so the next
  piece's first byte goes in as the low half of that word (REQ-CKSUM-006).
  Pieces may therefore be cut anywhere; the word helpers go through the same
  path.
- **Host-order word helpers.**  `net_cksum_add_u16()` and
  `net_cksum_add_u32()` add values in host order as if they had been read
  big-endian, which is what the pseudo-header needs for addresses and
  lengths held in host order.

## 3. Verifying: why a valid packet sums to 0

Write `+'` for one's complement addition (add, then fold the carry back in)
and `~` for bitwise complement.

A sender computes `S`, the one's complement sum of every 16-bit word of the
message with the checksum field set to 0, and stores `C = ~S`.

A receiver sums the message *as received*, checksum field included:

```
S +' C  =  S +' ~S  =  0xFFFF
```

because a number plus its complement is all ones — in one's complement
arithmetic `0xFFFF` is "negative zero".  `net_cksum_finalize()` then returns
`~0xFFFF = 0x0000`.  So verification is a single comparison with 0, whether
the checksum covers a header or message (`net_cksum_verify()` for the IPv4
header, ICMPv4 and IGMP) or a pseudo-header and segment (`ipv4_cksum(...) != 0` in
`udp_input()` and TCP's `parse_segment()`; `ipv6_cksum(...) != 0` in
`udp6_input()`, `icmpv6_input()` and TCP).

A finalized `0xFFFF` is not accepted as valid.  That value means the folded
sum was `0x0000`, which an end-around-carry sum reaches only when every word
added — checksum field included — is zero: not a correctly checksummed
message, and impossible anyway once a pseudo-header with a non-zero protocol
number is part of the sum.  Comparing with 0 is exact.

The same identity is why a computed checksum is written into a field that
holds 0: the value to store and the verification use the same function.

## 4. Pseudo-headers

TCP and UDP checksums (and ICMPv6's) cover a pseudo-header of IP fields so
that a segment delivered to the wrong address or protocol fails the check.
Both functions take the upper-layer data with its checksum field — 0 when
sending, as received when verifying.

**IPv4** (RFC 768, RFC 9293 §3.1), in `ipv4_cksum()`:

```
+--------+--------+--------+--------+
|          source address           |   net_cksum_add_u32(src_ip)
|        destination address        |   net_cksum_add_u32(dst_ip)
|  zero  |protocol|  upper length   |   net_cksum_add_u16(protocol)
+--------+--------+--------+--------+   net_cksum_add_u16(len)
then the TCP/UDP header and data        net_cksum_add(data, len)
```

**IPv6** (RFC 8200 §8.1), in `ipv6_cksum()`:

```
source address (16)                     net_cksum_add(src, 16)
destination address (16)                net_cksum_add(dst, 16)
upper-layer packet length (32 bits)     net_cksum_add_u32(len)
zero (24 bits) | next header (8 bits)   net_cksum_add_u32(next_header)
then the upper-layer header and data    net_cksum_add(data, len)
```

The next header in the IPv6 pseudo-header is the *upper-layer* protocol, not
the first Next Header of the packet; `ipv6_parse()` returns it after walking
the extension headers (`ipv6_hdr_t.next_header`).  The length is the
upper-layer length, which is the UDP Length or the TCP segment length.

Where each checksum is computed:

| Checksum | Covers | Send | Verify |
|---|---|---|---|
| IPv4 header | Header incl. options | `ipv4_build_tos()` / `ipv4_build_router_alert()` (`build_header()` in `ipv4.c`): `net_cksum()` | `ipv4_input()` and `ipv4_parse()`: `net_cksum_verify()` |
| ICMPv4 | Message | `icmp_send()`: `net_cksum()` | `icmp_input()`: `net_cksum_verify()` |
| IGMP | Message | `igmp_send()`: `net_cksum()` | `igmp_input()`: `net_cksum_verify()` |
| UDP / TCP over IPv4 | Pseudo-header + segment | `ipv4_cksum()` | `ipv4_cksum() == 0` |
| UDP / TCP / ICMPv6 (NDP and MLD included) over IPv6 | Pseudo-header + message | `ipv6_cksum()` | `ipv6_cksum() == 0` |

UDP and TCP have no checksum functions of their own: both use
`ipv4_cksum()` / `ipv6_cksum()`.

## 5. The UDP zero rule

A UDP checksum field of 0 means "no checksum was computed" (RFC 768).  So:

- **Sending** (IPv4 and IPv6): if the computed checksum is `0x0000`,
  `0xFFFF` is sent instead (`udp_wire_cksum()` in `udp.c`).  Both are zero in
  one's complement, so the receiver's sum is unchanged: the computed 0 means
  `S` folded to `0xFFFF`, and `0xFFFF +' 0xFFFF = 0xFFFF`, which finalizes
  to 0 as in §3.
- **Receiving over IPv4:** a zero field is accepted without verification.
- **Receiving over IPv6:** a zero field is invalid and the datagram is
  dropped (RFC 8200 §8.1).

TCP has no such rule; its checksum field is always meaningful.

## 6. Incremental update (RFC 1624)

```c
uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val,
                          uint16_t new_val);
```

When one 16-bit field of a checksummed message changes from `m` to `m'`, the
new checksum is RFC 1624 equation 3:

```
HC' = ~(~HC +' ~m +' m')
```

This is the form that is correct in every case.  The older RFC 1141 form,
`HC' = HC +' m +' ~m'`, works on the stored checksum directly and can yield
`0x0000` where the correct checksum is `0xFFFF` — the boundary case RFC 1624
was written to fix.  Working on `~HC` (the sum itself) and complementing at
the end avoids the negative-zero problem.

The stack does not use it: it never forwards packets, so it never
decrements a TTL, and the one "modify and send back" case — an ICMP echo
reply, which only changes the type — recomputes the checksum in full, which
keeps `icmp_send()` shared by echo replies and errors.  It is there, and unit
tested, for applications that patch a field of a prebuilt frame.

## 7. Hardware offload (not implemented)

Every checksum is computed and verified in software; `net_config.h` and
`net_mac_t` have no offload switches or capability flags
(REQ-CKSUM-022..025).  The only offload handling is in the Linux raw-socket
driver, which *completes* checksums that the local kernel left partial, so
the stack sees ordinary frames
([mac-hal.md §6](mac-hal.md#6-bundled-drivers)).  What adding offload would
take is in [mac-hal.md §8](mac-hal.md#8-future-work).
