.section .hyp.text, "ax"
.align 11
.global rhino_arm64_hyp_enter_guest

rhino_arm64_hyp_enter_guest:
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, lr,  [sp, #-16]!

    mov x19, x0

    ldr x1, [x19, #0x00]
    ldr x2, [x19, #0x08]
    msr vttbr_el2, x1
    msr vtcr_el2,  x2
    isb

    ldp x0,  x1,  [x19, #0x20]
    ldp x2,  x3,  [x19, #0x30]
    ldp x4,  x5,  [x19, #0x40]
    ldp x6,  x7,  [x19, #0x50]
    ldp x8,  x9,  [x19, #0x60]
    ldp x10, x11, [x19, #0x70]
    ldp x12, x13, [x19, #0x80]
    ldp x14, x15, [x19, #0x90]
    ldp x16, x17, [x19, #0xA0]
    ldr x18,      [x19, #0xB0]

    eret

rhino_hyp_exit_guest:
    stp x0, x1, [sp, #-16]!
    mrs x0, esr_el2
    mrs x1, far_el2

    str x0, [x19, #0x100]
    str x1, [x19, #0x108]

    ldp x0, x1, [sp], #16

    ldp x29, lr,  [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret