#include <rhino/kernel/security/tamper.h>
#include <rhino/kernel/security/crypto/kmac.h>
#include <rhino/kernel/security/crypto/sha3.h>
#include <rhino/kernel/arch/x86_64/msr.h>
#include <rhino/kernel/arch/x86_64/cr.h>
#include <rhino/kernel/arch/io.h>
#include <rhino/kernel/mm/vm.h>
#include <rhino/kernel/sync/atomic.h>
#include <rhino/kernel/sync/barrier.h>

#define RHINO_PUF_BASE_MMIO             0xFED40000ULL
#define RHINO_TAMPER_CTRL_REG           0x00000048ULL
#define RHINO_TAMPER_STATUS_REG         0x0000004CULL
#define RHINO_TAMPER_FUSE_BURN_REG      0x000000F0ULL
#define RHINO_MC_DRAM_SCRAMBLE_KEY0     0x00001080ULL
#define RHINO_MC_DRAM_SCRAMBLE_KEY1     0x00001088ULL
#define RHINO_MC_DRAM_SCRAMBLE_KEY2     0x00001090ULL
#define RHINO_MC_DRAM_SCRAMBLE_KEY3     0x00001098ULL

#define RHINO_MSR_PLATFORM_KEY_FIPS     0xC0011030
#define RHINO_MSR_SECURITY_STATUS       0xC0011032
#define RHINO_MSR_HARDWARE_EXT_STATUS   0xC0011033

#define RHINO_TAMPER_FLAG_VOLTAGE_FAULT (1U << 0)
#define RHINO_TAMPER_FLAG_CLOCK_GLITCH  (1U << 1)
#define RHINO_TAMPER_FLAG_TEMPERATURE   (1U << 2)
#define RHINO_TAMPER_FLAG_CHASSIS_OPEN  (1U << 3)
#define RHINO_TAMPER_FLAG_PROBE_DETECT  (1U << 4)
#define RHINO_TAMPER_FLAG_DEBUG_ATTACH  (1U << 5)
#define RHINO_TAMPER_FLAG_DRAIN_ABORT   (1U << 6)
#define RHINO_TAMPER_FLAG_SEC_FUSE_SET  (1U << 31)

#define RHINO_ZEROIZE_PATTERN_PASS1     0xAA55AA55AA55AA55ULL
#define RHINO_ZEROIZE_PATTERN_PASS2     0x55AA55AA55AA55AAULL
#define RHINO_ZEROIZE_PATTERN_PASS3     0x0000000000000000ULL

enum rhino_arbiter_state {
    RHINO_ARBITER_STATE_INITIALIZING   = 0x01,
    RHINO_ARBITER_STATE_ARMED          = 0x02,
    RHINO_ARBITER_STATE_CONTAINMENT    = 0x04,
    RHINO_ARBITER_STATE_ZEROIZING      = 0x08,
    RHINO_ARBITER_STATE_HALTED         = 0x10,
    RHINO_ARBITER_STATE_SILICON_KILLED = 0xFF
};

struct rhino_sensor_thresholds {
    uint32_t mv_min;
    uint32_t mv_max;
    uint32_t mhz_min;
    uint32_t mhz_max;
    int32_t  temp_c_max;
};

struct rhino_sec_identity {
    uint8_t  device_uuid[16];
    uint8_t  puf_derived_seed[64];
    uint8_t  active_session_auth_key[32];
    uint64_t monotonic_counter;
    uint64_t runtime_epoch;
    uint32_t security_profile_flags;
};

struct rhino_arbiter_context {
    _Atomic uint32_t state;
    _Atomic uint32_t lock_witness;
    struct rhino_sec_identity identity;
    struct rhino_sensor_thresholds thresholds;
    uint64_t text_segment_base;
    uint64_t text_segment_size;
    uint8_t  golden_text_digest[64];
    uint64_t mmio_tamper_vaddr;
    uint64_t mmio_mc_vaddr;
};

static struct rhino_arbiter_context g_rhino_arbiter;

static inline void rhino_sec_serialize(void) {
    __asm__ volatile("cpuid" : : "a"(0) : "rbx", "rcx", "rdx", "memory");
}

static inline void rhino_non_temporal_fill_64(volatile void *dst, uint64_t val) {
    __asm__ volatile(
        "movnti %1, 0(%0)\n\t"
        "movnti %1, 8(%0)\n\t"
        "movnti %1, 16(%0)\n\t"
        "movnti %1, 24(%0)\n\t"
        "movnti %1, 32(%0)\n\t"
        "movnti %1, 40(%0)\n\t"
        "movnti %1, 48(%0)\n\t"
        "movnti %1, 56(%0)\n\t"
        :
        : "r"(dst), "r"(val)
        : "memory"
    );
}

static inline void rhino_avx512_stream_clear(volatile void *dst, uint64_t qword_pattern) {
    __asm__ volatile(
        "vpbroadcastq %1, %%zmm0\n\t"
        "vmovntdq %%zmm0, 0(%0)\n\t"
        "vmovntdq %%zmm0, 64(%0)\n\t"
        "vmovntdq %%zmm0, 128(%0)\n\t"
        "vmovntdq %%zmm0, 192(%0)\n\t"
        :
        : "r"(dst), "r"(qword_pattern)
        : "zmm0", "memory"
    );
}

static rhino_status_t rhino_puf_synthesize_entropy(struct rhino_arbiter_context *ctx) {
    volatile uint32_t *puf_ctrl = (volatile uint32_t *)(ctx->mmio_tamper_vaddr + 0x10);
    volatile uint32_t *puf_stat = (volatile uint32_t *)(ctx->mmio_tamper_vaddr + 0x14);
    volatile uint32_t *puf_data = (volatile uint32_t *)(ctx->mmio_tamper_vaddr + 0x20);

    *puf_ctrl = 0x00000001;
    rhino_arch_sfence();

    size_t timeout = 1000000;
    while (!(*puf_stat & 0x00000002)) {
        if (--timeout == 0) {
            return RHINO_ERR_HARDWARE_TIMEOUT;
        }
        rhino_cpu_relax();
    }

    uint32_t raw_entropy[16];
    for (size_t i = 0; i < 16; ++i) {
        raw_entropy[i] = *puf_data;
    }

    *puf_ctrl = 0x00000000;

    struct rhino_kmac_ctx kctx;
    const uint8_t domain_sep[] = "RHINO-OS-PUF-DERIVATION-V4";
    rhino_kmac_init(&kctx, (const uint8_t *)"SILICON-ROOT", 12, domain_sep, sizeof(domain_sep));
    rhino_kmac_update(&kctx, (const uint8_t *)raw_entropy, sizeof(raw_entropy));
    rhino_kmac_final(&kctx, ctx->identity.puf_derived_seed, 64);

    rhino_memzero_explicit(raw_entropy, sizeof(raw_entropy));
    rhino_memzero_explicit(&kctx, sizeof(kctx));

    return RHINO_OK;
}

static void rhino_sec_burn_kill_fuses(struct rhino_arbiter_context *ctx) {
    volatile uint32_t *fuse_reg = (volatile uint32_t *)(ctx->mmio_tamper_vaddr + RHINO_TAMPER_FUSE_BURN_REG);
    
    *fuse_reg = 0xA5A50001;
    rhino_sec_serialize();
    *fuse_reg = 0x5A5A0002;
    rhino_sec_serialize();
    *fuse_reg = 0xFFFFFFFF;
    rhino_arch_sfence();

    rhino_msr_write(RHINO_MSR_PLATFORM_KEY_FIPS, 0xFFFFFFFFFFFFFFFFULL);
    rhino_msr_write(RHINO_MSR_SECURITY_STATUS, 0x0000000000000000ULL);
}

static void rhino_sec_scramble_memory_controller(struct rhino_arbiter_context *ctx) {
    if (!ctx->mmio_mc_vaddr) return;

    volatile uint64_t *k0 = (volatile uint64_t *)(ctx->mmio_mc_vaddr + RHINO_MC_DRAM_SCRAMBLE_KEY0);
    volatile uint64_t *k1 = (volatile uint64_t *)(ctx->mmio_mc_vaddr + RHINO_MC_DRAM_SCRAMBLE_KEY1);
    volatile uint64_t *k2 = (volatile uint64_t *)(ctx->mmio_mc_vaddr + RHINO_MC_DRAM_SCRAMBLE_KEY2);
    volatile uint64_t *k3 = (volatile uint64_t *)(ctx->mmio_mc_vaddr + RHINO_MC_DRAM_SCRAMBLE_KEY3);

    uint64_t entropy_val = rhino_arch_read_tsc() ^ 0xDEADBEEFCAFEBABEULL;

    *k0 = entropy_val;
    *k1 = ~entropy_val;
    *k2 = (entropy_val << 32) | (entropy_val >> 32);
    *k3 = entropy_val ^ 0x0123456789ABCDEFULL;

    rhino_arch_mfence();
}

static void rhino_sec_anti_forensic_zeroize_all(struct rhino_arbiter_context *ctx, uint32_t trigger_flags) {
    atomic_store_explicit(&ctx->state, RHINO_ARBITER_STATE_ZEROIZING, memory_order_seq_cst);

    rhino_arch_cli();
    rhino_sec_scramble_memory_controller(ctx);

    __asm__ volatile("wbinvd" ::: "memory");

    rhino_memzero_explicit(&ctx->identity, sizeof(struct rhino_sec_identity));

    size_t mem_ranges_count = 0;
    struct rhino_phys_mem_region *ranges = rhino_mm_get_physical_regions(&mem_ranges_count);

    for (size_t pass = 0; pass < 3; ++pass) {
        uint64_t pattern;
        switch (pass) {
            case 0: pattern = RHINO_ZEROIZE_PATTERN_PASS1; break;
            case 1: pattern = RHINO_ZEROIZE_PATTERN_PASS2; break;
            default: pattern = RHINO_ZEROIZE_PATTERN_PASS3; break;
        }

        for (size_t i = 0; i < mem_ranges_count; ++i) {
            uint64_t base = (uint64_t)rhino_phys_to_virt(ranges[i].base_phys);
            uint64_t length = ranges[i].length_bytes;

            uint64_t end = base + length;
            volatile uint64_t *ptr = (volatile uint64_t *)base;

            while ((uint64_t)ptr < end) {
                if (rhino_cpu_has_feature_avx512f()) {
                    rhino_avx512_stream_clear(ptr, pattern);
                    ptr += 32;
                } else {
                    rhino_non_temporal_fill_64(ptr, pattern);
                    ptr += 8;
                }
            }
        }
        rhino_arch_sfence();
    }

    __asm__ volatile("wbinvd" ::: "memory");

    if (trigger_flags & RHINO_TAMPER_FLAG_SEC_FUSE_SET) {
        rhino_sec_burn_kill_fuses(ctx);
        atomic_store_explicit(&ctx->state, RHINO_ARBITER_STATE_SILICON_KILLED, memory_order_seq_cst);
    } else {
        atomic_store_explicit(&ctx->state, RHINO_ARBITER_STATE_HALTED, memory_order_seq_cst);
    }

    uint64_t rst_cmd = 0x0000000EULL;
    rhino_io_out8(0xCF9, (uint8_t)rst_cmd);

    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

rhino_status_t rhino_sec_integrity_attest_text(struct rhino_arbiter_context *ctx) {
    if (unlikely(atomic_load_explicit(&ctx->state, memory_order_acquire) != RHINO_ARBITER_STATE_ARMED)) {
        return RHINO_ERR_INVALID_SYSTEM_STATE;
    }

    uint8_t runtime_digest[64];
    rhino_sha3_512((const uint8_t *)ctx->text_segment_base, ctx->text_segment_size, runtime_digest);

    uint64_t mismatch = 0;
    for (size_t i = 0; i < 64; ++i) {
        mismatch |= (runtime_digest[i] ^ ctx->golden_text_digest[i]);
    }

    if (unlikely(mismatch != 0)) {
        atomic_store_explicit(&ctx->state, RHINO_ARBITER_STATE_CONTAINMENT, memory_order_seq_cst);
        rhino_sec_anti_forensic_zeroize_all(ctx, RHINO_TAMPER_FLAG_DRAIN_ABORT | RHINO_TAMPER_FLAG_SEC_FUSE_SET);
        return RHINO_ERR_INTEGRITY_COMPROMISED;
    }

    return RHINO_OK;
}

void rhino_tamper_irq_entry(void) {
    uint32_t expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&g_rhino_arbiter.lock_witness, &expected, 1, memory_order_seq_cst, memory_order_relaxed)) {
        for (;;) {
            __asm__ volatile("pause");
        }
    }

    volatile uint32_t *tamper_status = (volatile uint32_t *)(g_rhino_arbiter.mmio_tamper_vaddr + RHINO_TAMPER_STATUS_REG);
    uint32_t flags = *tamper_status;

    if (flags & (RHINO_TAMPER_FLAG_VOLTAGE_FAULT | 
                 RHINO_TAMPER_FLAG_CLOCK_GLITCH  | 
                 RHINO_TAMPER_FLAG_PROBE_DETECT  | 
                 RHINO_TAMPER_FLAG_DEBUG_ATTACH)) {
        rhino_sec_anti_forensic_zeroize_all(&g_rhino_arbiter, flags | RHINO_TAMPER_FLAG_SEC_FUSE_SET);
    } else if (flags & RHINO_TAMPER_FLAG_CHASSIS_OPEN) {
        rhino_sec_anti_forensic_zeroize_all(&g_rhino_arbiter, flags);
    }

    *tamper_status = flags;
    atomic_store_explicit(&g_rhino_arbiter.lock_witness, 0, memory_order_release);
}

rhino_status_t rhino_arbiter_initialize(uint64_t text_base, uint64_t text_len, const uint8_t *golden_digest) {
    uint32_t current_state = atomic_load_explicit(&g_rhino_arbiter.state, memory_order_relaxed);
    if (current_state != 0) {
        return RHINO_ERR_ALREADY_INITIALIZED;
    }

    atomic_store_explicit(&g_rhino_arbiter.state, RHINO_ARBITER_STATE_INITIALIZING, memory_order_seq_cst);

    g_rhino_arbiter.text_segment_base = text_base;
    g_rhino_arbiter.text_segment_size = text_len;
    memcpy(g_rhino_arbiter.golden_text_digest, golden_digest, 64);

    g_rhino_arbiter.mmio_tamper_vaddr = (uint64_t)rhino_mmio_map(RHINO_PUF_BASE_MMIO, 0x1000);
    if (!g_rhino_arbiter.mmio_tamper_vaddr) {
        return RHINO_ERR_MMIO_MAP_FAILED;
    }

    g_rhino_arbiter.thresholds.mv_min = 950;
    g_rhino_arbiter.thresholds.mv_max = 1350;
    g_rhino_arbiter.thresholds.mhz_min = 800;
    g_rhino_arbiter.thresholds.mhz_max = 4800;
    g_rhino_arbiter.thresholds.temp_c_max = 98;

    rhino_status_t status = rhino_puf_synthesize_entropy(&g_rhino_arbiter);
    if (status != RHINO_OK) {
        return status;
    }

    volatile uint32_t *tamper_ctrl = (volatile uint32_t *)(g_rhino_arbiter.mmio_tamper_vaddr + RHINO_TAMPER_CTRL_REG);
    *tamper_ctrl = (RHINO_TAMPER_FLAG_VOLTAGE_FAULT | 
                    RHINO_TAMPER_FLAG_CLOCK_GLITCH  | 
                    RHINO_TAMPER_FLAG_PROBE_DETECT  | 
                    RHINO_TAMPER_FLAG_CHASSIS_OPEN  |
                    RHINO_TAMPER_FLAG_DEBUG_ATTACH);

    status = rhino_sec_integrity_attest_text(&g_rhino_arbiter);
    if (status != RHINO_OK) {
        return status;
    }

    atomic_store_explicit(&g_rhino_arbiter.state, RHINO_ARBITER_STATE_ARMED, memory_order_seq_cst);
    return RHINO_OK;
}

rhino_status_t rhino_compartment_isolate(uint64_t compartment_id, uint64_t mem_root, uint32_t execution_flags) {
    if (atomic_load_explicit(&g_rhino_arbiter.state, memory_order_acquire) != RHINO_ARBITER_STATE_ARMED) {
        return RHINO_ERR_SYSTEM_UNTRUSTED;
    }

    uint64_t cr0 = rhino_read_cr0();
    uint64_t cr4 = rhino_read_cr4();

    if (!(cr0 & (1ULL << 16)) || !(cr4 & (1ULL << 20))) {
        return RHINO_ERR_HARDENING_PREREQUISITE_FAILED;
    }

    uint64_t efer = rhino_msr_read(0xC0000080);
    if (!(efer & (1ULL << 11))) {
        return RHINO_ERR_NXE_DISABLED;
    }

    rhino_arch_cli();

    __asm__ volatile("movq %0, %%cr3" : : "r"(mem_root) : "memory");
    rhino_sec_serialize();

    uint64_t platform_status = rhino_msr_read(RHINO_MSR_SECURITY_STATUS);
    if ((platform_status & 0x07) != 0x07) {
        rhino_sec_anti_forensic_zeroize_all(&g_rhino_arbiter, RHINO_TAMPER_FLAG_DRAIN_ABORT);
        return RHINO_ERR_SECURITY_VIOLATION;
    }

    return RHINO_OK;
}