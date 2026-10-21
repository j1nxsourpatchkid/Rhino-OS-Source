.section .text
.align 16
.global rhino_irq_entry_stub
.global rhino_ret_from_trap

rhino_irq_entry_stub:
    cld
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %rbp
    pushq %rbx
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi

    movq %rsp, %rdi
    movq %rsp, %rbx
    andq $-16, %rsp
    
    call rhino_x86_dispatch_irq

    movq %rbx, %rsp

rhino_ret_from_trap:
    movq 120(%rsp), %rax
    testb $3, %al
    jz 1f

    movq %gs:0x20, %rbx
    movl 0x8(%rbx), %eax
    testl %eax, %eax
    jnz 2f

1:
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %rbx
    popq %rbp
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    addq $16, %rsp
    iretq

2:
    call rhino_sched_preempt_user
    jmp rhino_ret_from_trap