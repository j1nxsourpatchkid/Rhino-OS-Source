#include <rhino/kernel/mm/vm_zone.h>
#include <rhino/kernel/arch/mmu.h>
#include <rhino/kernel/sync/spinlock.h>
#include <rhino/kernel/trace.h>

struct rhino_vm_zone_node rhino_n_nodes[RHINO_VM_MAX_NUMA_NODES];

static inline struct rhino_vm_page *__rhino_zone_dequeue_order(struct rhino_vm_zone *zone, unsigned int order, uint32_t flags) {
    struct rhino_vm_freelist *list = &zone->free_orders[order];
    if (unlikely(list->count == 0)) {
        return NULL;
    }

    struct rhino_vm_page *head = list->head;
    struct rhino_vm_page *next = head->next;

    if (next) {
        next->prev = NULL;
        list->head = next;
    } else {
        list->head = NULL;
        list->tail = NULL;
    }

    list->count--;
    zone->total_free -= (1UL << order);
    
    head->next = NULL;
    head->prev = NULL;
    head->flags = (head->flags & ~RHINO_PAGE_ORDER_MASK) | (order & RHINO_PAGE_ORDER_MASK);
    head->flags |= RHINO_PAGE_STATE_ALLOCATED;

    return head;
}

struct rhino_vm_page *rhino_vm_zone_allocate_pages(int node_id, unsigned int order, uint32_t flags) {
    if (unlikely(order >= RHINO_VM_MAX_ORDER)) {
        return NULL;
    }

    struct rhino_vm_zone_node *node = &rhino_n_nodes[node_id];
    struct rhino_vm_page *page = NULL;

    rhino_spin_lock_irqsave(&node->lock);

    for (unsigned int current_order = order; current_order < RHINO_VM_MAX_ORDER; ++current_order) {
        page = __rhino_zone_dequeue_order(&node->zones[RHINO_VM_ZONE_NORMAL], current_order, flags);
        if (page) {
            while (current_order > order) {
                current_order--;
                size_t split_size = 1UL << current_order;
                struct rhino_vm_page *buddy = page + split_size;
                
                buddy->flags = (buddy->flags & ~RHINO_PAGE_ORDER_MASK) | (current_order & RHINO_PAGE_ORDER_MASK);
                buddy->flags |= RHINO_PAGE_STATE_BUDDY;

                struct rhino_vm_freelist *split_list = &node->zones[RHINO_VM_ZONE_NORMAL].free_orders[current_order];
                buddy->next = split_list->head;
                buddy->prev = NULL;

                if (split_list->head) {
                    split_list->head->prev = buddy;
                } else {
                    split_list->tail = buddy;
                }
                split_list->head = buddy;
                split_list->count++;
                node->zones[RHINO_VM_ZONE_NORMAL].total_free += split_size;
            }
            break;
        }
    }

    rhino_spin_unlock_irqrestore(&node->lock);

    if (!page && !(flags & RHINO_VM_ALLOC_NO_FALLBACK)) {
        for (int fallback_id = 0; fallback_id < RHINO_VM_MAX_NUMA_NODES; ++fallback_id) {
            if (fallback_id == node_id) continue;
            page = rhino_vm_zone_allocate_pages(fallback_id, order, flags | RHINO_VM_ALLOC_NO_FALLBACK);
            if (page) break;
        }
    }

    return page;
}
