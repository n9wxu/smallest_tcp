/* Minimal linker script for Cortex-M0 size measurement */
/* Representative of STM32F042 (32KB flash, 6KB RAM) */
MEMORY {
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 32K
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 6K
}

ENTRY(_start)

SECTIONS {
  .vectors : { KEEP(*(.vectors)) } > FLASH
  .text    : { *(.text .text.*) } > FLASH
  .rodata  : { *(.rodata .rodata.*) } > FLASH
  .data    : { *(.data .data.*) } > RAM AT > FLASH
  .bss     : { *(.bss .bss.* COMMON) } > RAM
  /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.eh_frame) }
}
