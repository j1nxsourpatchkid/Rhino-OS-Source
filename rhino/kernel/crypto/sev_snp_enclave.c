#include <rhino/kernel/security/enclave.h>
#include <rhino/kernel/arch/x86_64/msr.h>

#define RHINO_RMP_PAGE_SIZE_4K 0
#define RHINO_RMP_PAGE_SIZE_2M 1
#define RHINO_RMP_REQ_VMPL0    0

int rhino_snp_rmp_assign(uint64_t pa, uint64_t gpa, uint64_t asid, int page_sz) {
    struct {
        uint64_t gpa;
        uint64_t asid : 16;
        uint64_t vmpl0_perms : 8;
        uint64_t vmpl1_perms : 8;
        uint64_t vmpl2_perms : 8;
        uint64_t vmpl3_perms : 8;
        uint64_t page_size : 3;
        uint64_t reserved : 12;
        uint64_t immutable : 1;
    } __attribute__((packed)) val;

    val.gpa = gpa;
    val.asid = asid;
    val.vmpl0_perms = 0x7;
    val.vmpl1_perms = 0x0;
    val.vmpl2_perms = 0x0;
    val.vmpl3_perms = 0x0;
    val.page_size = page_sz;
    val.reserved = 0;
    val.immutable = 0;

    int ret;
    __asm__ volatile(
        "rmpupdate\n\t"
        "setz %b0\n\t"
        : "=q"(ret)
        : "a"(pa), "S"(&val)
        : "memory", "cc"
    );

    return ret ? 0 : -1;
}

int rhino_enclave_init_context(struct rhino_enclave *enc, uint64_t control_base) {
    if (unlikely(!enc || (control_base & 0xFFF))) {
        return -1;
    }

    enc->crypto_asid = rhino_asid_alloc_hw();
    if (enc->crypto_asid < 0) {
        return -2;
    }

    int ret = rhino_snp_rmp_assign(rhino_virt_to_phys(control_base), control_base, enc->crypto_asid, RHINO_RMP_PAGE_SIZE_4K);
    if (ret != 0) {
        rhino_asid_free_hw(enc->crypto_asid);
        return -3;
    }

    atomic_store_explicit(&enc->state, RHINO_ENCLAVE_READY, memory_order_seq_cst);
    return 0;
}