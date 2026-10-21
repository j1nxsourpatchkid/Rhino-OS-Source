#include <rhino/kernel/arch/x86_64/mmu.h>
#include <rhino/kernel/arch/x86_64/msr.h>

#define RHINO_PML4_IDX(va) (((va) >> 39) & 0x1FF)
#define RHINO_PDPT_IDX(va) (((va) >> 30) & 0x1FF)
#define RHINO_PD_IDX(va)   (((va) >> 21) & 0x1FF)
#define RHINO_PT_IDX(va)   (((va) >> 12) & 0x1FF)

int rhino_x86_64_map_page(rhino_pml4_t *root, uint64_t va, uint64_t pa, uint64_t flags) {
    rhino_pte_t *pml4e = &root->entries[RHINO_PML4_IDX(va)];
    rhino_pdpt_t *pdpt;

    if (!(*pml4e & RHINO_PTE_PRESENT)) {
        uint64_t new_table = rhino_pmm_alloc_zero_frame();
        if (!new_table) return -1;
        *pml4e = new_table | RHINO_PTE_PRESENT | RHINO_PTE_WRITE | (flags & RHINO_PTE_USER);
        pdpt = (rhino_pdpt_t *)rhino_phys_to_virt(new_table);
    } else {
        pdpt = (rhino_pdpt_t *)rhino_phys_to_virt(*pml4e & RHINO_PTE_FRAME_ADDR_MASK);
    }

    rhino_pte_t *pdpte = &pdpt->entries[RHINO_PDPT_IDX(va)];
    rhino_pd_t *pd;

    if (!(*pdpte & RHINO_PTE_PRESENT)) {
        uint64_t new_table = rhino_pmm_alloc_zero_frame();
        if (!new_table) return -1;
        *pdpte = new_table | RHINO_PTE_PRESENT | RHINO_PTE_WRITE | (flags & RHINO_PTE_USER);
        pd = (rhino_pd_t *)rhino_phys_to_virt(new_table);
    } else {
        pd = (rhino_pd_t *)rhino_phys_to_virt(*pdpte & RHINO_PTE_FRAME_ADDR_MASK);
    }

    rhino_pte_t *pde = &pd->entries[RHINO_PD_IDX(va)];
    rhino_pt_t *pt;

    if (!(*pde & RHINO_PTE_PRESENT)) {
        uint64_t new_table = rhino_pmm_alloc_zero_frame();
        if (!new_table) return -1;
        *pde = new_table | RHINO_PTE_PRESENT | RHINO_PTE_WRITE | (flags & RHINO_PTE_USER);
        pt = (rhino_pt_t *)rhino_phys_to_virt(new_table);
    } else {
        pt = (rhino_pt_t *)rhino_phys_to_virt(*pde & RHINO_PTE_FRAME_ADDR_MASK);
    }

    rhino_pte_t *pte = &pt->entries[RHINO_PT_IDX(va)];
    *pte = (pa & RHINO_PTE_FRAME_ADDR_MASK) | flags | RHINO_PTE_PRESENT;

    __asm__ volatile("invlpg (%0)" :: "r"(va) : "memory");

    return 0;
}