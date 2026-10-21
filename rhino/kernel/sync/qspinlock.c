#include <rhino/kernel/sync/qspinlock.h>
#include <rhino/kernel/arch/cpu.h>
#include <rhino/kernel/sync/barrier.h>

#define RHINO_LOCKED_VAL     0x0001
#define RHINO_PENDED_VAL     0x0100
#define RHINO_TAIL_MASK      0xFFFF0000
#define RHINO_TAIL_SHIFT     16

void rhino_qspinlock_lock_slowpath(rhino_qspinlock_t *lock, uint32_t val) {
    unsigned int cpu_id = rhino_cpu_id();
    struct rhino_mcs_node *node = rhino_percpu_ptr(rhino_mcs_nodes, cpu_id);
    
    node->locked = 0;
    node->next = NULL;

    uint32_t tail_encoded = (cpu_id + 1) << RHINO_TAIL_SHIFT;
    uint32_t old = atomic_exchange_explicit((_Atomic uint32_t *)lock, tail_encoded | (val & ~RHINO_TAIL_MASK), memory_order_acq_rel);

    if (old & RHINO_TAIL_MASK) {
        struct rhino_mcs_node *prev;
        unsigned int prev_cpu = ((old & RHINO_TAIL_MASK) >> RHINO_TAIL_SHIFT) - 1;
        prev = rhino_percpu_ptr(rhino_mcs_nodes, prev_cpu);

        atomic_store_explicit((_Atomic(struct rhino_mcs_node *)*)&prev->next, node, memory_order_release);

        while (!atomic_load_explicit(&node->locked, memory_order_acquire)) {
            rhino_cpu_relax();
        }
    }

    while ((val = atomic_load_explicit((_Atomic uint32_t *)lock, memory_order_relaxed)) & RHINO_LOCKED_VAL) {
        rhino_cpu_relax();
    }

    for (;;) {
        if (atomic_compare_exchange_weak_explicit((_Atomic uint32_t *)lock, &val, val | RHINO_LOCKED_VAL, memory_order_acquire, memory_order_relaxed)) {
            break;
        }
        rhino_cpu_relax();
    }
}