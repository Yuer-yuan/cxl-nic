/* The SiFive U reset vector jumps to DRAM at 0x80000000 in M mode. */
.section .text.start, "ax", @progbits
.globl _start
.type _start, @function
_start:
    csrr t0, mhartid
    li t1, 1
    bne t0, t1, .Lpark
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    la t0, __bss_start
    la t1, __bss_end
.Lzero:
    bgeu t0, t1, .Lready
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lzero
.Lready:
    la t0, .Ltrap
    csrw mtvec, t0
    call guest_main
.Lpark:
    wfi
    j .Lpark
.balign 4
.Ltrap:
    csrr a0, mcause
    csrr a1, mepc
    csrr a2, mtval
    call guest_trap
    j .Lpark
.size _start, . - _start

.section .note.GNU-stack, "", @progbits
