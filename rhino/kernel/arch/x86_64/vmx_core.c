#include <rhino/kernel/arch/x86_64/vmx.h>
#include <rhino/kernel/arch/x86_64/msr.h>
#include <rhino/kernel/arch/x86_64/cr.h>
#include <rhino/kernel/sched/sched.h>

static inline void rhino_vmcs_write(uint64_t field, uint64_t val) {
    uint8_t err;
    __asm__ volatile("vmwrite %1, %2; setna %0" : "=q"(err) : "r"(val), "r"(field) : "cc");
    if (unlikely(err)) {
        rhino_panic_subsystem(RHINO_PANIC_VMX, field);
    }
}

static inline uint64_t rhino_vmcs_read(uint64_t field) {
    uint64_t val;
    uint8_t err;
    __asm__ volatile("vmread %2, %0; setna %1" : "=r"(val), "=q"(err) : "r"(field) : "cc");
    if (unlikely(err)) {
        rhino_panic_subsystem(RHINO_PANIC_VMX, field);
    }
    return val;
}

rhino_status_t rhino_vmx_run_vcpu(struct rhino_vcpu *vcpu) {
    uint64_t host_rsp;
    
    for (;;) {
        __asm__ volatile(
            "mov %%rsp, %0\n\t"
            : "=r"(host_rsp)
        );

        rhino_vmcs_write(RHINO_VMX_HOST_RSP, host_rsp);
        rhino_vmcs_write(RHINO_VMX_HOST_RIP, (uint64_t)&&rhino_vmx_exit_point);

        __asm__ volatile(
            "movq %0, %%r15\n\t"
            "movq 0x00(%%r15), %%rax\n\t"
            "movq 0x08(%%r15), %%rbx\n\t"
            "movq 0x10(%%r15), %%rcx\n\t"
            "movq 0x18(%%r15), %%rdx\n\t"
            "movq 0x20(%%r15), %%rsi\n\t"
            "movq 0x28(%%r15), %%rdi\n\t"
            "movq 0x30(%%r15), %%rbp\n\t"
            "movq 0x38(%%r15), %%r8\n\t"
            "movq 0x40(%%r15), %%r9\n\t"
            "movq 0x48(%%r15), %%r10\n\t"
            "movq 0x50(%%r15), %%r11\n\t"
            "movq 0x58(%%r15), %%r12\n\t"
            "movq 0x60(%%r15), %%r13\n\t"
            "movq 0x68(%%r15), %%r14\n\t"
            "movq 0x70(%%r15), %%r15\n\t"
            "testb $1, %1\n\t"
            "jnz 1f\n\t"
            "vmlaunch\n\t"
            "jmp 2f\n\t"
            "1: vmresume\n\t"
            "2:\n\t"
            :
            : "r"(&vcpu->regs), "m"(vcpu->launched)
            : "cc", "memory"
        );

        return RHINO_ERR_VMX_LAUNCH_FAIL;

rhino_vmx_exit_point:
        __asm__ volatile(
            "pushq %%r15\n\t"
            "movq 8(%%rsp), %%r15\n\t"
            "movq %%rax, 0x00(%%r15)\n\t"
            "movq %%rbx, 0x08(%%r15)\n\t"
            "movq %%rcx, 0x10(%%r15)\n\t"
            "movq %%rdx, 0x18(%%r15)\n\t"
            "movq %%rsi, 0x20(%%r15)\n\t"
            "movq %%rdi, 0x28(%%r15)\n\t"
            "movq %%rbp, 0x30(%%r15)\n\t"
            "movq %%r8,  0x38(%%r15)\n\t"
            "movq %%r9,  0x40(%%r15)\n\t"
            "movq %%r10, 0x48(%%r15)\n\t"
            "movq %%r11, 0x50(%%r15)\n\t"
            "movq %%r12, 0x58(%%r15)\n\t"
            "movq %%r13, 0x60(%%r15)\n\t"
            "movq %%r14, 0x68(%%r15)\n\t"
            "popq %%rax\n\t"
            "movq %%rax, 0x70(%%r15)\n\t"
            :
            : "r"(&vcpu->regs)
            : "cc", "memory"
        );

        vcpu->launched = 1;
        uint32_t exit_reason = (uint32_t)rhino_vmcs_read(RHINO_VMX_EXIT_REASON);
        uint64_t exit_qual = rhino_vmcs_read(RHINO_VMX_EXIT_QUALIFICATION);

        if (exit_reason == RHINO_EXIT_REASON_EPT_VIOLATION) {
            uint64_t gpa = rhino_vmcs_read(RHINO_VMX_GUEST_PHYSICAL_ADDR);
            if (rhino_mm_handle_ept_fault(vcpu->domain, gpa, exit_qual) != RHINO_OK) {
                return RHINO_ERR_VMX_NESTED_FAULT;
            }
        } else if (exit_reason == RHINO_EXIT_REASON_VMCALL) {
            rhino_hypercall_dispatch(vcpu);
            uint64_t rip = rhino_vmcs_read(RHINO_VMX_GUEST_RIP);
            uint32_t inst_len = (uint32_t)rhino_vmcs_read(RHINO_VMX_EXIT_INSTRUCTION_LEN);
            rhino_vmcs_write(RHINO_VMX_GUEST_RIP, rip + inst_len);
        } else if (exit_reason == RHINO_EXIT_REASON_EXTERNAL_INTERRUPT) {
            rhino_arch_dispatch_pending_irq();
            if (rhino_sched_needs_resched()) {
                rhino_sched_yield();
            }
        } else {
            return RHINO_ERR_VMX_UNHANDLED_INTERCEPT;
        }
    }
}