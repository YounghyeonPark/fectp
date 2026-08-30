/* A generic Cortex-M4F layout. The addresses are only plausible, not any
   particular part: what is being measured is how much flash the code occupies
   once the linker has discarded what nothing reaches, and that does not depend
   on where the regions sit. */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 512K
  RAM   : ORIGIN = 0x20000000, LENGTH = 128K
}

ENTRY(reset);

SECTIONS
{
  .vector_table ORIGIN(FLASH) : { KEEP(*(.vector_table)); } > FLASH
  .text   : { *(.text .text.*); }   > FLASH
  .rodata : { *(.rodata .rodata.*); } > FLASH
  .data   : { *(.data .data.*); }   > RAM AT > FLASH
  .bss    : { *(.bss .bss.*); }     > RAM
  /DISCARD/ : { *(.ARM.exidx .ARM.exidx.*); }
}
