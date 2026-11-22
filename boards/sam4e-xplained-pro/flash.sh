#!/bin/sh
# Flash the SAM4E Xplained Pro through its EDBG debugger (OpenOCD 0.12 with
# CMSIS-DAP), or reset it:
#   boards/sam4e-xplained-pro/flash.sh build-arm/tcp_echo_demo.elf
#   boards/sam4e-xplained-pro/flash.sh --reset
#   boards/sam4e-xplained-pro/flash.sh --ram build-arm/tcp_echo_demo.elf
#
# GPNVM bit 1 makes the chip boot from flash and not from the SAM-BA ROM;
# an erased chip has it clear, so it is set at every flash.
#
# The ERASE jumper must be OFF.  Fitted, it holds the flash erased: every
# write is accepted and none is kept, and verification fails with 0xff
# read back everywhere.  --ram is for that board, and for trying a build
# without wearing the flash: it loads an ELF linked for RAM (the linker
# script with FLASH at 0x20000000) and starts it; a reset ends it.
#
# OPENOCD names the program; HW_DUT_PROBE the EDBG's serial number, where
# the host has more than one CMSIS-DAP probe.
set -eu

OPENOCD=${OPENOCD:-openocd}
probe=${HW_DUT_PROBE:+-c "adapter serial $HW_DUT_PROBE"}

ocd() {
    # shellcheck disable=SC2086
    eval "$OPENOCD" -f interface/cmsis-dap.cfg $probe \
        -c "'transport select swd'" -c "'set CHIPNAME atsam4e16e'" \
        -f target/at91sam4sXX.cfg -c "'$1'"
}

case ${1:-} in
--reset)
    ocd "init; reset run; exit"
    ;;
--ram)
    elf=${2:?"usage: $0 --ram <elf linked for RAM>"}
    pc=0x$(arm-none-eabi-nm "$elf" | awk '$3 == "reset_handler" {print $1}')
    sp=0x$(arm-none-eabi-nm "$elf" | awk '$3 == "_estack" {print $1}')
    # the boot ROM leaves the PMC write-protected; the vector table is ours
    ocd "init; reset halt; mww 0x400e04e4 0x504d4300; load_image $elf; \
         mww 0xe000ed08 0x20000000; reg sp $sp; reg pc $pc; resume; exit"
    ;;
"")
    echo "usage: $0 <elf> | --reset | --ram <elf>" >&2
    exit 2
    ;;
*)
    ocd "init; reset halt; flash write_image erase $1; verify_image $1; \
         at91sam4 gpnvm set 1; reset run; exit"
    ;;
esac
