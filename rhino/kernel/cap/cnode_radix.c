#include <rhino/kernel/security/capability.h>
#include <rhino/kernel/sync/atomic.h>
#include <rhino/kernel/mm/vm.h>

#define RHINO_CNODE_GUARD_MAX_BITS 58
#define RHINO_CAP_SLOT_EMPTY 0x00

struct rhino_cnode_entry {
    uint64_t type_and_rights;
    uint64_t object_ptr;
    uint64_t badge;
    uint64_t derivation_ptr;
};

struct rhino_cnode {
    uint8_t radix_bits;
    uint8_t guard_bits;
    uint64_t guard_value;
    struct rhino_cnode_entry slots[];
};

rhino_status_t rhino_cnode_resolve_cap(struct rhino_cnode *root, uint64_t cptr, uint8_t depth, struct rhino_cnode_entry *out_entry) {
    if (unlikely(!root || depth > 64)) {
        return RHINO_ERR_INVALID_CPTR;
    }

    struct rhino_cnode *curr_cnode = root;
    uint8_t remaining_depth = depth;

    while (curr_cnode) {
        uint8_t guard_len = curr_cnode->guard_bits;
        if (guard_len > 0) {
            if (remaining_depth < guard_len) {
                return RHINO_ERR_GUARD_MISMATCH;
            }

            uint64_t cptr_guard = (cptr >> (remaining_depth - guard_len)) & ((1ULL << guard_len) - 1);
            if (cptr_guard != curr_cnode->guard_value) {
                return RHINO_ERR_GUARD_MISMATCH;
            }
            remaining_depth -= guard_len;
        }

        uint8_t radix = curr_cnode->radix_bits;
        if (remaining_depth < radix) {
            return RHINO_ERR_DEPTH_EXHAUSTED;
        }

        size_t index = (cptr >> (remaining_depth - radix)) & ((1ULL << radix) - 1);
        remaining_depth -= radix;

        struct rhino_cnode_entry *entry = &curr_cnode->slots[index];
        uint64_t entry_type = atomic_load_explicit((_Atomic uint64_t *)&entry->type_and_rights, memory_order_acquire);

        if ((entry_type & RHINO_CAP_TYPE_MASK) == RHINO_CAP_TYPE_NONE) {
            return RHINO_ERR_EMPTY_SLOT;
        }

        if (remaining_depth == 0) {
            out_entry->type_and_rights = entry_type;
            out_entry->object_ptr = atomic_load_explicit((_Atomic uint64_t *)&entry->object_ptr, memory_order_acquire);
            out_entry->badge = entry->badge;
            out_entry->derivation_ptr = entry->derivation_ptr;
            return RHINO_OK;
        }

        if ((entry_type & RHINO_CAP_TYPE_MASK) != RHINO_CAP_TYPE_CNODE) {
            return RHINO_ERR_NOT_A_CNODE;
        }

        curr_cnode = (struct rhino_cnode *)phys_to_virt(entry->object_ptr);
    }

    return RHINO_ERR_UNRESOLVABLE_PATH;
}

rhino_status_t rhino_cnode_delete_slot(struct rhino_cnode *root, uint64_t cptr, uint8_t depth) {
    struct rhino_cnode_entry resolved;
    rhino_status_t status = rhino_cnode_resolve_cap(root, cptr, depth, &resolved);
    if (status != RHINO_OK) return status;

    uint64_t *raw_slot = (uint64_t *)&root->slots[(cptr & ((1ULL << root->radix_bits) - 1))];

    uint64_t expected = resolved.type_and_rights;
    if (!atomic_compare_exchange_strong_explicit((_Atomic uint64_t *)raw_slot, &expected, RHINO_CAP_SLOT_EMPTY, memory_order_acq_rel, memory_order_relaxed)) {
        return RHINO_ERR_CONCURRENT_MUTATION;
    }

    if (resolved.derivation_ptr) {
        rhino_cap_sever_derivation_node((struct rhino_cap_derivation *)resolved.derivation_ptr);
    }

    return RHINO_OK;
}