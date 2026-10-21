#include <rhino/kernel/net/pipeline.h>
#include <rhino/kernel/drivers/pci.h>
#include <rhino/kernel/sync/atomic.h>

size_t rhino_net_poll_rx_batch(struct rhino_rx_ring *ring, struct rhino_net_packet *pkts, size_t max_budget) {
    uint32_t cons = ring->consumer_idx;
    size_t processed = 0;

    while (processed < max_budget) {
        volatile struct rhino_rx_desc *desc = &ring->desc_array[cons];
        uint32_t status_flags = desc->status;

        if (!(status_flags & RHINO_RXD_STAT_DD)) {
            break;
        }

        uint16_t len = desc->length;
        uint64_t paddr = desc->phys_buffer_addr;

        pkts[processed].vaddr = (void *)rhino_phys_to_virt(paddr);
        pkts[processed].len = len;
        pkts[processed].hash = desc->rss_hash;
        pkts[processed].flags = 0;

        if (status_flags & RHINO_RXD_STAT_IPV4_CSUM_OK) {
            pkts[processed].flags |= RHINO_PKT_HW_CSUM_IP;
        }
        if (status_flags & RHINO_RXD_STAT_TCP_CSUM_OK) {
            pkts[processed].flags |= RHINO_PKT_HW_CSUM_TCP;
        }

        uint64_t fresh_page = rhino_pmm_alloc_fast_numa(ring->numa_node);
        desc->phys_buffer_addr = fresh_page;
        desc->status = 0;

        cons = (cons + 1) & ring->size_mask;
        processed++;
    }

    if (processed > 0) {
        ring->consumer_idx = cons;
        rhino_mmio_write32(ring->doorbell_reg, (cons - 1) & ring->size_mask);
    }

    return processed;
}