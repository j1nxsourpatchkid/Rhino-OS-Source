#include <rhino/kernel/crypto/seal.h>
#include <rhino/kernel/crypto/aes_gcm.h>
#include <rhino/kernel/crypto/sha512.h>
#include <rhino/kernel/arch/tpm.h>
#include <rhino/kernel/arch/entropy.h>
#include <rhino/kernel/sync/spinlock.h>

#define RHINO_SEAL_CONTEXT_MAGIC 0x5345414C5248494EULL
#define RHINO_MAX_PCR_BANKS 24

struct rhino_seal_manifest {
    uint64_t magic;
    uint32_t version;
    uint32_t flags;
    uint8_t pcr_expected[RHINO_MAX_PCR_BANKS][48];
    uint8_t iv[12];
    uint8_t auth_tag[16];
    uint64_t payload_len;
};

static rhino_status_t rhino_crypto_derive_seal_key(const uint8_t *hw_root_key, const uint8_t *pcr_composite, size_t composite_len, uint8_t *out_key) {
    uint8_t prk[64];
    rhino_sha512_hmac(hw_root_key, 32, pcr_composite, composite_len, prk);

    const char salt[] = "RHINO-OS-SEAL-V2-KDF-SALT";
    uint8_t info[64];
    rhino_sha512_ctx_t ctx;
    rhino_sha512_init(&ctx);
    rhino_sha512_update(&ctx, (const uint8_t *)salt, sizeof(salt));
    rhino_sha512_update(&ctx, prk, 64);
    rhino_sha512_final(&ctx, info);

    memcpy(out_key, info, 32);

    rhino_memzero_explicit(prk, sizeof(prk));
    rhino_memzero_explicit(info, sizeof(info));
    return RHINO_OK;
}

rhino_status_t rhino_sec_seal_blob(const uint8_t *in_plain, size_t in_len, const uint32_t *pcr_indices, size_t pcr_count, struct rhino_seal_manifest *manifest, uint8_t *out_cipher) {
    if (unlikely(!in_plain || !manifest || !out_cipher || in_len == 0 || pcr_count > RHINO_MAX_PCR_BANKS)) {
        return RHINO_ERR_INVALID_ARG;
    }

    uint8_t composite_digest[48 * RHINO_MAX_PCR_BANKS];
    size_t composite_len = 0;

    for (size_t i = 0; i < pcr_count; ++i) {
        uint32_t pcr_idx = pcr_indices[i];
        if (pcr_idx >= RHINO_MAX_PCR_BANKS) return RHINO_ERR_OUT_OF_BOUNDS;

        rhino_status_t res = rhino_tpm_pcr_read(pcr_idx, manifest->pcr_expected[pcr_idx]);
        if (unlikely(res != RHINO_OK)) {
            return res;
        }
        memcpy(&composite_digest[composite_len], manifest->pcr_expected[pcr_idx], 48);
        composite_len += 48;
    }

    uint8_t hw_key[32];
    if (!rhino_hw_get_fuse_root_key(hw_key)) {
        return RHINO_ERR_HARDWARE_FAULT;
    }

    uint8_t derived_key[32];
    rhino_crypto_derive_seal_key(hw_key, composite_digest, composite_len, derived_key);
    rhino_memzero_explicit(hw_key, sizeof(hw_key));

    if (rhino_hw_get_random(manifest->iv, sizeof(manifest->iv)) != RHINO_OK) {
        rhino_memzero_explicit(derived_key, sizeof(derived_key));
        return RHINO_ERR_ENTROPY_FAILURE;
    }

    manifest->magic = RHINO_SEAL_CONTEXT_MAGIC;
    manifest->version = 2;
    manifest->flags = 0x00000001;
    manifest->payload_len = in_len;

    struct rhino_aes_gcm_ctx gcm_ctx;
    rhino_aes_gcm_init(&gcm_ctx, derived_key, 32);
    rhino_aes_gcm_set_iv(&gcm_ctx, manifest->iv, sizeof(manifest->iv));
    rhino_aes_gcm_aad(&gcm_ctx, (const uint8_t *)manifest, sizeof(struct rhino_seal_manifest) - 16);
    rhino_aes_gcm_encrypt(&gcm_ctx, in_plain, out_cipher, in_len);
    rhino_aes_gcm_get_tag(&gcm_ctx, manifest->auth_tag, sizeof(manifest->auth_tag));

    rhino_memzero_explicit(&gcm_ctx, sizeof(gcm_ctx));
    rhino_memzero_explicit(derived_key, sizeof(derived_key));
    rhino_memzero_explicit(composite_digest, sizeof(composite_digest));

    return RHIN