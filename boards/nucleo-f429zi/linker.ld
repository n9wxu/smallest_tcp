/* STM32F429ZI: 2 MB of flash, 192 KB of SRAM (SRAM1, 2 and 3, contiguous
   and reachable by the Ethernet DMA).  The 64 KB of core-coupled RAM at
   0x10000000 is left unused: the DMA cannot reach it. */
MEMORY {
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 2048K
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
}

ENTRY(reset_handler)

_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS {
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
  .text : {
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH
  .ARM.exidx : { *(.ARM.exidx*) } > FLASH

  .data : {
    . = ALIGN(4);
    _sdata = .;
    *(.data .data.*)
    . = ALIGN(4);
    _edata = .;
  } > RAM AT > FLASH
  _sidata = LOADADDR(.data);

  .bss (NOLOAD) : {
    . = ALIGN(4);
    _sbss = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM
  end = _ebss;

  /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.eh_frame) }
}
