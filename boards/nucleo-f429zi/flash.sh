#!/bin/sh
# Flash the NUCLEO-F429ZI through its ST-LINK (OpenOCD), or reset it:
#   boards/nucleo-f429zi/flash.sh build-arm/tcp_echo_demo.elf
#   boards/nucleo-f429zi/flash.sh --reset
set -eu

OPENOCD=${OPENOCD:-openocd}

case ${1:-} in
--reset)
    "$OPENOCD" -f interface/stlink.cfg -f target/stm32f4x.cfg \
        -c "init; reset run; exit"
    ;;
"")
    echo "usage: $0 <elf> | --reset" >&2
    exit 2
    ;;
*)
    "$OPENOCD" -f interface/stlink.cfg -f target/stm32f4x.cfg \
        -c "program $1 verify reset exit"
    ;;
esac
