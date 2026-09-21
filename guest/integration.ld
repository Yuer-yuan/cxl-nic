OUTPUT_ARCH(riscv)
ENTRY(_start)

PHDRS
{
    code PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x80000000;
    .text : { KEEP(*(.text.start)) *(.text .text.*) } :code
    .rodata : { *(.rodata .rodata.*) } :code
    . = ALIGN(4096);
    .data : { *(.data .data.*) *(.sdata .sdata.*) } :data
    PROVIDE(__global_pointer$ = . + 0x800);
    .bss (NOLOAD) :
    {
        . = ALIGN(8);
        __bss_start = .;
        *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } :data
    .stack (NOLOAD) :
    {
        . = ALIGN(16);
        . += 65536;
        __stack_top = .;
    } :data
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
