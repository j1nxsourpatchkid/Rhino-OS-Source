#include <rhino/kernel/debug/crash.h>
#include <rhino/kernel/arch/x86_64/msr.h>
#include <rhino/kernel/arch/io.h>
#include <rhino/kernel/sync/atomic.h>

static _Atomic uint32_t panic_gate = 0;

struct rhino_crash_record {
    uint64_t signature;
    uint32_t cpu_index;
    uint32_t reason_code;
    uint64_t timestamp;
    uint64_t cr0, cr2, cr3, cr4, cr8;
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
    uint8_t stack_snapshot[4096];
} __attribute__((packed, aligned(4096)));

static struct rhino_crash_record primary_vault_record;

void rhino_panic_nmi_flush_state(uint32_t reason, struct rhino_trap_frame *frame) {
    if (atomic_exchange_explicit(&panic_gate, 1, memory_order_seq_cst) != 0) {
        for (;;) {
            __asm__ volatile("cli; hlt");
        }
    }

    rhino_arch_smp_send_stop_broadcast();

    primary_vault_record.signature = 0x5248494E4F44554DULL;
    primary_vault_record.cpu_index = rhino_arch_cpu_id();
    primary_vault_record.reason_code = reason;
    primary_vault_record.timestamp = rhino_arch_read_tsc();

    __asm__ volatile("mov %%cr0, %0" : "=r"(primary_vault_record.cr0));
    __asm__ volatile("mov %%cr2, %0" : "=r"(primary_vault_record.cr2));
    __asm__ volatile("mov %%cr3, %0" : "=r"(primary_vault_record.cr3));
    __asm__ volatile("mov %%cr4, %0" : "=r"(primary_vault_record.cr4));
    __asm__ volatile("mov %%cr8, %0" : "=r"(primary_vault_record.cr8));

    if (frame) {
        primary_vault_record.rax = frame->rax;
        primary_vault_record.rbx = frame->rbx;
        primary_vault_record.rcx = frame->rcx;
        primary_vault_record.rdx = frame->rdx;
        primary_vault_record.rsi = frame->rsi;
        primary_vault_record.rdi = frame->rdi;
        primary_vault_record.rbp = frame->rbp;
        primary_vault_record.r8  = frame->r8;
        primary_vault_record.r9  = frame->r9;
        primary_vault_record.r10 = frame->r10;
        primary_vault_record.r11 = frame->r11;
        primary_vault_record.r12 = frame->r12;
        primary_vault_record.r13 = frame->r13;
        primary_vault_record.r14 = frame->r14;
        primary_vault_record.r15 = frame->r15;
        primary_vault_record.rip = frame->rip;
        primary_vault_record.rsp = frame->rsp;
        primary_vault_record.rflags = frame->rflags;
        primary_vault_record.cs  = frame->cs;
        primary_vault_record.ss  = frame->ss;

        if (frame->rsp && (frame->rsp < (uint64_t)-0x1000000000ULL)) {
            memcpy(primary_vault_record.stack_snapshot, (const void *)frame->rsp, sizeof(primary_vault_record.stack_snapshot));
        }
    }

    uint64_t mmio_addr = RHINO_EMERGENCY_STORAGE_BAR0_BASE;
    if (mmio_addr) {
        volatile uint32_t *doorbell = (volatile uint32_t *)(mmio_addr + 0x1000);
        volatile uint64_t *sqe_dma = (volatile uint64_t *)(mmio_addr + 0x2000);

        sqe_dma[0] = 0x01 | (0x02 << 8);
        sqe_dma[1] = 0;
        sqe_dma[2] = 0;
        sqe_dma[3] = rhino_virt_to_phys((uint64_t)&primary_vault_record);
        sqe_dma[4] = (sizeof(struct rhino_crash_record) >> 9) - 1;
        sqe_dma[5] = 0;

        rhino_arch_sfence();
        *doorbell = 1;
    }

    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}