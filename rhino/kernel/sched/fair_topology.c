#include <rhino/kernel/sched/sched.h>
#include <rhino/kernel/arch/cpu.h>
#include <rhino/kernel/sync/atomic.h>

#define RHINO_SCHED_SCALE_WEIGHT 1024

extern struct rhino_runqueue rhino_cpu_runqueues[RHINO_MAX_CPUS];

static inline uint64_t rhino_sched_decay(uint64_t initial, uint64_t delta_time, uint64_t half_life) {
    if (delta_time >= half_life * 8) return 0;
    return (initial * (RHINO_SCHED_SCALE_WEIGHT - ((delta_time * RHINO_SCHED_SCALE_WEIGHT) / half_life))) >> 10;
}

void rhino_sched_account_runtime(struct rhino_task *curr, uint64_t delta_ns) {
    curr->se.vruntime += (delta_ns * RHINO_SCHED_SCALE_WEIGHT) / curr->se.load_weight;
    
    struct rhino_sched_entity *se = &curr->se;
    uint64_t now = rhino_arch_timer_read_ns();
    uint64_t delta_exec = now - se->last_update_time;
    
    if (unlikely(delta_exec > 0)) {
        se->util_sum = rhino_sched_decay(se->util_sum, delta_exec, 32000000) + (delta_ns << 10);
        se->util_avg = se->util_sum / 32000000;
        se->last_update_time = now;
    }
}

struct rhino_task *rhino_sched_select_next_task(struct rhino_runqueue *rq) {
    if (unlikely(rq->active_count == 0)) {
        return rq->idle_task;
    }

    uint64_t mask = rq->bitmap;
    if (mask == 0) {
        return rq->idle_task;
    }

    int highest_prio = __builtin_ctzll(mask);
    struct rhino_task_prio_array *array = &rq->active_prio_slots[highest_prio];
    
    struct rhino_task *next = array->head;
    array->head = next->sched_next;
    
    if (!array->head) {
        array->tail = NULL;
        rq->bitmap &= ~(1ULL << highest_prio);
    } else {
        array->head->sched_prev = NULL;
    }
    
    rq->active_count--;
    next->sched_next = NULL;
    next->sched_prev = NULL;
    
    return next;
}
