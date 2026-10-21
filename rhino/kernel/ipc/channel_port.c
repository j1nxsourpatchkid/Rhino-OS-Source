#include <rhino/kernel/ipc/channel.h>
#include <rhino/kernel/security/capability.h>
#include <rhino/kernel/sync/barrier.h>
#include <rhino/kernel/mm/vm.h>

rhino_status_t rhino_ipc_channel_write(rhino_handle_t ch_handle, const void *ubuf, size_t sz, rhino_handle_t *hndls, size_t hndl_cnt) {
    if (unlikely(sz > RHINO_IPC_MAX_PAYLOAD || hndl_cnt > RHINO_IPC_MAX_HANDLES)) {
        return RHINO_ERR_INVALID_SIZE;
    }

    struct rhino_capability *cap;
    rhino_status_t err = rhino_cap_lookup_validate(ch_handle, RHINO_CAP_RIGHT_WRITE, &cap);
    if (unlikely(err != RHINO_OK)) {
        return err;
    }

    struct rhino_channel_endpoint *src = cap->target_object;
    struct rhino_channel_endpoint *dst = src->peer;

    if (!dst || (atomic_load_explicit(&dst->state, memory_order_acquire) & RHINO_CH_PEER_CLOSED)) {
        rhino_cap_release(cap);
        return RHINO_ERR_PEER_CLOSED;
    }

    rhino_spin_lock(&dst->ring.lock);

    uint32_t head = dst->ring.buffer->head;
    uint32_t tail = dst->ring.buffer->tail;
    uint32_t next_head = (head + 1) & dst->ring.capacity_mask;

    if (next_head == tail) {
        rhino_spin_unlock(&dst->ring.lock);
        rhino_cap_release(cap);
        return RHINO_ERR_RING_FULL;
    }

    struct rhino_ipc_packet *slot = &dst->ring.packets[head];
    slot->payload_size = (uint32_t)sz;
    slot->handle_count = (uint32_t)hndl_cnt;
    slot->sender_domain = current_rhino_thread->domain_id;

    if (sz > 0) {
        if (!rhino_vm_copyin(slot->inline_data, ubuf, sz)) {
            rhino_spin_unlock(&dst->ring.lock);
            rhino_cap_release(cap);
            return RHINO_ERR_ACCESS_VIOLATION;
        }
    }

    for (size_t i = 0; i < hndl_cnt; ++i) {
        struct rhino_capability *xfer_cap;
        err = rhino_cap_transfer_extract(hndls[i], &xfer_cap);
        slot->attached_caps[i] = (err == RHINO_OK) ? xfer_cap : NULL;
    }

    atomic_store_explicit(&dst->ring.buffer->head, next_head, memory_order_release);
    rhino_spin_unlock(&dst->ring.lock);

    rhino_wait_queue_wake(&dst->waiters);
    rhino_cap_release(cap);

    return RHINO_OK;
}