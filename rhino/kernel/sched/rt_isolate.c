#include <rhino/kernel/sched/sched.h>
#include <rhino/kernel/arch/x86_64/msr.h>
#include <rhino/kernel/arch/cpu.h>

#define RHINO_IA32_L3_QOS_MASK_0 0xC90
#define RHINO_IA32_PQR_ASSOC     0xC8F

struct rhino_rt_domain {
    uint32_t domain_id;
    uint32_t assigned_clos;
    uint64_t l3_bitmask;
    uint64_t runtime_budget_ns;
    uint64_t period_ns;
    uint64_t deadline_ns;
    struct rhino_task *pinned_task;
};

rhino_status_t rhino_rt_isolate_core_enter(uint32_t cpu_id, struct rhino_rt_domain *domain) {
    if (cpu_id != rhino_arch_cpu_id()) {
        return RHINO_ERR_CROSS_CORE_CALL_INVALID;
    }

    rhino_arch_cli();

    uint64_t pqr_val = ((uint64_t)domain->assigned_clos << 32);
    rhino_msr_write(RHINO_IA32_PQR_ASSOC, pqr_val);

    uint32_t mask_msr = RHINO_IA32_L3_QOS_MASK_0 + domain->assigned_clos;
    rhino_msr_write(mask_msr, domain->l3_bitmask);

    uint64_t lapic_base = rhino_msr_read(0x1B) & 0xFFFFF000ULL;
    volatile uint32_t *lapic_timer_icr = (volatile uint32_t *)(phys_to_virt(lapic_base) + 0x380);
    volatile uint32_t *lapic_timer_lvt = (volatile uint32_t *)(phys_to_virt(lapic_base) + 0x320);

    *lapic_timer_lvt = 0x000200EF;
    uint64_t ticks_for_budget = (domain->runtime_budget_ns * rhino_get_lapic_frequency()) / 1000000000ULL;
    *lapic_timer_icr = (uint32_t)ticks_for_budget;

    struct rhino_task *target = domain->pinned_task;
    target->state = RHINO_TASK_STATE_RUNNING;
    target->se.sched_policy = RHINO_SCHED_POLICY_DEADLINE;

    current_rhino_thread = target;

    rhino_arch_switch_mm_context(target->process->cr3);
    rhino_arch_fast_sysret(&target->user_context);

    return RHINO_ERR_CONTROL_FLOW_VIOLATION;
}

void rhino_rt_enforce_budget_irq_handler(void) {
    uint32_t cpu_id = rhino_arch_cpu_id();
    struct rhino_rt_domain *domain = rhino_percpu_rt_domain(cpu_id);

    if (unlikely(!domain || !domain->pinned_task)) {
        return;
    }

    uint64_t now = rhino_arch_read_tsc();
    if (now >= domain->deadline_ns) {
        domain->pinned_task->state = RHINO_TASK_STATE_THROTTLED;
        domain->deadline_ns += domain->period_ns;
        
        rhino_msr_write(RHINO_IA32_PQR_ASSOC, 0);
        rhino_sched_switch_to_recovery(cpu_id);
    }
}