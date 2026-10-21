#include <rhino/kernel/fs/wal.h>
#include <rhino/kernel/drivers/nvme.h>
#include <rhino/kernel/sync/atomic.h>

rhino_status_t rhino_wal_commit_transaction(struct rhino_wal_log *wal, struct rhino_wal_txn *txn) {
    uint64_t payload_bytes = txn->stream_size;
    uint64_t full_block_bytes = align_up(payload_bytes + sizeof(struct rhino_wal_header), 4096);
    
    uint64_t ticket = atomic_fetch_add_explicit(&wal->seq_ticket, full_block_bytes, memory_order_relaxed);
    uint64_t write_offset = ticket % wal->ring_capacity;

    if ((ticket + full_block_bytes) - atomic_load_explicit(&wal->tail_flushed, memory_order_acquire) > wal->ring_capacity) {
        return RHINO_ERR_LOG_SATURATED;
    }

    struct rhino_wal_header *hdr = (struct rhino_wal_header *)(wal->mmap_base + write_offset);
    hdr->magic = RHINO_WAL_HEADER_MAGIC;
    hdr->transaction_id = txn->id;
    hdr->payload_len = payload_bytes;
    hdr->crc32c = rhino_crypto_crc32(txn->data_ptr, payload_bytes);

    memcpy((void *)(hdr + 1), txn->data_ptr, payload_bytes);

    rhino_arch_clwb_range(hdr, full_block_bytes);
    rhino_arch_sfence();

    atomic_fetch_add_explicit(&wal->in_flight_commits, 1, memory_order_release);

    while (atomic_load_explicit(&wal->current_commit_drain, memory_order_acquire) != ticket) {
        rhino_cpu_relax();
    }

    struct rhino_nvme_sqe sqe;
    sqe.opcode = NVME_OPC_WRITE;
    sqe.slba = (wal->device_lba_offset + write_offset) >> 9;
    sqe.length = (uint16_t)(full_block_bytes >> 9);
    sqe.prp1 = rhino_virt_to_phys((uint64_t)hdr);

    rhino_nvme_submit_cmd(wal->nvme_queue, &sqe);
    atomic_store_explicit(&wal->current_commit_drain, ticket + full_block_bytes, memory_order_release);

    return RHINO_OK;
}