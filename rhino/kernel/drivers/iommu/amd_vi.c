#include <rhino/kernel/drivers/iommu.h>
#include <rhino/kernel/arch/io.h>
#include <rhino/kernel/sync/atomic.h>

#define RHINO_AMD_IOMMU_DEVTBL_SIZE 32
#define RHINO_AMD_PTE_V  (1ULL << 0)
#define RHINO_AMD_PTE_TV (1ULL << 1)
#define RHINO_AMD_PTE_IR (1ULL << 61)
#define RHINO_AMD_PTE_IW (1ULL << 62)

int rhino_amd_iommu_set_domain_page(struct rhino_amd_iommu *iommu, uint16_t devid, uint64_t iova, uint64_t pa, uint64_t flags) {
    uint8_t *dev_entry = iommu->device_table + (devid * RHINO_AMD_IOMMU_DEVTBL_SIZE);
    uint64_t *root_dte = (uint64_t *)dev_entry;

    if (!(*root_dte & RHINO_AMD_PTE_V)) {
        uint64_t pt_root = rhino_pmm_alloc_zero_frame();
        if (!pt_root) return -1;

        uint64_t dte = pt_root | RHINO_AMD_PTE_V | RHINO_AMD_PTE_TV | (1ULL << 9);
        dte |= (flags & RHINO_IOMMU_DOMAIN_ISOLATE) ? (1ULL << 60) : 0;

        atomic_store_explicit((_Atomic uint64_t *)root_dte, dte, memory_order_release);
    }

    uint64_t *lvl = (uint64_t *)rhino_phys_to_virt(*root_dte & 0x000FFFFFFFFFF000ULL);
    for (int l = 6; l > 1; --l) {
        size_t idx = (iova >> (12 + (l - 1) * 9)) & 0x1FF;
        if (!(lvl[idx] & RHINO_AMD_PTE_V)) {
            uint64_t next = rhino_pmm_alloc_zero_frame();
            if (!next) return -1;
            lvl[idx] = next | RHINO_AMD_PTE_V | RHINO_AMD_PTE_IR | RHINO_AMD_PTE_IW;
        }
        lvl = (uint64_t *)rhino_phys_to_virt(lvl[idx] & 0x000FFFFFFFFFF000ULL);
    }

    size_t leaf = (iova >> 12) & 0x1FF;
    uint64_t val = (pa & 0x000FFFFFFFFFF000ULL) | RHINO_AMD_PTE_V;

    if (flags & RHINO_IOMMU_PROT_READ)  val |= RHINO_AMD_PTE_IR;
    if (flags & RHINO_IOMMU_PROT_WRITE) val |= RHINO_AMD_PTE_IW;

    atomic_store_explicit((_Atomic uint64_t *)&lvl[leaf], val, memory_order_seq_cst);

    struct rhino_iommu_cmd cmd;
    cmd.data[0] = devid;
    cmd.data[1] = (uint32_t)(iova & 0xFFFFF000ULL) | 1;
    cmd.data[2] = (uint32_t)(iova >> 32);
    cmd.data[3] = (0x03 << 28);

    return rhino_amd_iommu_submit_cmd(iommu, &cmd);
}