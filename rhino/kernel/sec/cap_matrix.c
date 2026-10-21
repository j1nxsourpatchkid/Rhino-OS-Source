#include <rhino/kernel/security/capability.h>
#include <rhino/kernel/sync/rcu.h>

struct rhino_cap_table rhino_global_cap_table;

rhino_status_t rhino_cap_revoke_subtree(struct rhino_cap_node *root) {
    if (unlikely(!root)) {
        return RHINO_ERR_INVALID_ARG;
    }

    rhino_spin_lock(&root->mutation_lock);

    struct rhino_cap_node *curr = root->child;
    while (curr) {
        struct rhino_cap_node *next_sibling = curr->sibling;
        
        atomic_store_explicit(&curr->rights_mask, 0, memory_order_release);
        curr->generation_marker = atomic_fetch_add(&rhino_global_cap_table.epoch, 1);
        
        if (curr->child) {
            rhino_cap_revoke_subtree(curr);
        }

        atomic_store_explicit(&curr->state, RHINO_CAP_STATE_REVOKED, memory_order_relaxed);
        rhino_rcu_call(&curr->rcu_head, rhino_cap_node_reclaim_rcu);
        
        curr = next_sibling;
    }

    root->child = NULL;
    rhino_spin_unlock(&root->mutation_lock);
    return RHINO_OK;
}

rhino_status_t rhino_cap_mint(struct rhino_cap_node *parent, uint64_t target_rights, struct rhino_cap_node **out) {
    if ((parent->rights_mask & target_rights) != target_rights) {
        return RHINO_ERR_RIGHTS_EXCEEDED;
    }

    struct rhino_cap_node *child = rhino_slab_alloc(sizeof(struct rhino_cap_node));
    if (!child) return RHINO_ERR_OUT_OF_MEMORY;

    child->rights_mask = target_rights;
    child->parent = parent;
    child->child = NULL;
    child->target_object = parent->target_object;
    atomic_init(&child->refcnt, 1);
    atomic_store(&child->state, RHINO_CAP_STATE_ACTIVE);

    rhino_spin_lock(&parent->mutation_lock);
    child->sibling = parent->child;
    parent->child = child;
    rhino_spin_unlock(&parent->mutation_lock);

    *out = child;
    return RHINO_OK;
}