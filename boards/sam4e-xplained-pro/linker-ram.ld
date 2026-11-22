/* ATSAM4E16E, run from RAM (flash.sh --ram): the image in the lower half of
   the 128 KB of SRAM, data and stack in the upper.  Compare linker.ld:
   1 MB of flash at 0x00400000 (where the chip boots once
   GPNVM bit 1 is set: flash.sh), 128 KB of SRAM. */
MEMORY {
  FLASH (rx) : ORIGIN = 0x20000000, LENGTH = 64K
  RAM  (rwx) : ORIGIN = 0x20010000, LENGTH = 64K
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
