#!/bin/bash
# Build lwIP for ARM Cortex-M0 size comparison
# Usage: bash bench/build_lwip.sh

set -e
CC=arm-none-eabi-gcc
SIZE=arm-none-eabi-size
LWIP=build/lwip/src
OUT=build/arm/lwip

mkdir -p $OUT

SRCS="
  $LWIP/core/init.c
  $LWIP/core/mem.c
  $LWIP/core/memp.c
  $LWIP/core/netif.c
  $LWIP/core/pbuf.c
  $LWIP/core/inet_chksum.c
  $LWIP/core/ip.c
  $LWIP/core/def.c
  $LWIP/core/timeouts.c
  $LWIP/core/ipv4/etharp.c
  $LWIP/core/ipv4/icmp.c
  $LWIP/core/ipv4/ip4.c
  $LWIP/core/ipv4/ip4_addr.c
  $LWIP/core/ipv4/ip4_frag.c
  $LWIP/core/udp.c
  $LWIP/netif/ethernet.c
"

echo "=== Compiling lwIP for ARM Cortex-M0 ==="
for f in $SRCS; do
  base=$(basename $f .c)
  echo "  CC $base.c"
  $CC -std=c99 -Os -mthumb -mcpu=cortex-m0 \
      -ffreestanding -ffunction-sections -fdata-sections \
      -I$LWIP/include -Ibench/lwip \
      -w \
      -c -o $OUT/$base.o $f
done

echo ""
echo "=== lwIP ARM Cortex-M0 Per-Module Sizes (UDP only, -Os -mthumb) ==="
$SIZE $OUT/*.o

echo ""
echo "=== lwIP Total (all .o combined) ==="
$SIZE $OUT/*.o | tail -n +2 | awk '{t+=$1; d+=$2; b+=$3} END {printf "   text\t   data\t    bss\t    dec\n"; printf "%7d\t%7d\t%7d\t%7d\n", t, d, b, t+d+b}'
