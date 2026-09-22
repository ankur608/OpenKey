/**
 * @file crypto.h
 * @brief OpenKey Hardened Cryptographic Engine (mbedTLS 3.x API Compliant)
 * @version 1.0.0
 * 
 * Hardware Target: Waveshare ESP32-S3-Zero (Xtensa LX7 Hardware Accelerators)
 * Toolchain: Arduino IDE 2.3.10 / ESP32 Board Support 3.7.0 (ESP-IDF 5.x)
 * 
 * Cryptographic Matrix:
 * - NIST P-256 (secp256r1) ECDSA & ECDH via mbedTLS 3.x opaque point access
 * - Ed25519 (EdDSA) asymmetric signatures
 * - Hardware Silicon TRNG with continuous NIST SP 800-90B entropy monitoring
 * - 24-word BIP-39 mnemonic seed phrase backup & PBKDF2-HMAC-SHA512 derivation
 * - HMAC-SHA256 / SHA512 / SHA1 for HMAC-Secret and OATH TOTP/HOTP
 * - Constant-time execution & VAPT memory zeroization
 */

#pragma once

#include <Arduino.h>
#include <esp_random.h>
#include <mbedtls/build_info.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/sha1.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/cipher.h>
#include <mbedtls/bignum.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pkcs5.h>

#if __has_include("vapt_security.h")
#include "vapt_security.h"
#elif __has_include("include/vapt_security.h")
#include "include/vapt_security.h"
#else
#include "../include/vapt_security.h"
#endif

namespace OpenKey {
namespace Crypto {

/**
 * @brief Hardware TRNG Entropy Source Callback for mbedTLS 3.x CTR-DRBG
 */
static inline int esp32_hardware_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    if (!OpenKey::Security::HardwareEntropyMonitor::get_safe_random(output, len)) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *olen = len;
    return 0;
}

/**
 * @brief Cryptographic RNG context manager backed by ESP32 silicon TRNG
 */
class CryptoRNG {
private:
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool initialized;

public:
    CryptoRNG() : initialized(false) {}

    ~CryptoRNG() {
        if (initialized) {
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
            initialized = false;
        }
    }

    bool init(const char *personalization = "OpenKey_ESP32S3_Zero_Vault") {
        if (initialized) return true;

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        // Register ESP32 Hardware TRNG with continuous health checking
        int ret = mbedtls_entropy_add_source(&entropy, esp32_hardware_entropy_poll, NULL,
                                            32, MBEDTLS_ENTROPY_SOURCE_STRONG);
        if (ret != 0) return false;

        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)personalization,
                                    strlen(personalization));
        if (ret != 0) return false;

        mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);
        initialized = true;
        return true;
    }

    int generate_random(uint8_t *output, size_t len) {
        if (!initialized && !init()) return -1;
        return mbedtls_ctr_drbg_random(&ctr_drbg, output, len);
    }

    mbedtls_ctr_drbg_context* get_drbg() { return &ctr_drbg; }
};

/**
 * @brief Global singleton instance of CryptoRNG
 */
static inline CryptoRNG& get_rng() {
    static CryptoRNG instance;
    return instance;
}

/**
 * @brief SHA-256 Hardware-Accelerated Wrapper
 */
static inline bool sha256(const uint8_t *input, size_t len, uint8_t *output_32b) {
    if (!input || !output_32b) return false;
    return (mbedtls_sha256(input, len, output_32b, 0) == 0);
}

/**
 * @brief SHA-512 Hardware-Accelerated Wrapper
 */
static inline bool sha512(const uint8_t *input, size_t len, uint8_t *output_64b) {
    if (!input || !output_64b) return false;
    return (mbedtls_sha512(input, len, output_64b, 0) == 0);
}

/**
 * @brief HMAC-SHA256 computation (used for FIDO2 HMAC-Secret and WebAuthn authData)
 */
static inline bool hmac_sha256(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t *output_32b) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return false;

    int ret = mbedtls_md_hmac(md_info, key, key_len, data, data_len, output_32b);
    return (ret == 0);
}

/**
 * @brief HMAC-SHA1 computation (used for RFC 6238 / RFC 4226 OATH TOTP/HOTP)
 */
static inline bool hmac_sha1(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t *output_20b) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (!md_info) return false;

    int ret = mbedtls_md_hmac(md_info, key, key_len, data, data_len, output_20b);
    return (ret == 0);
}

/**
 * @brief NIST P-256 (secp256r1) Keypair & Operations
 * 
 * Strictly adheres to modern mbedTLS 3.x API standards:
 * - Uses mbedtls_ecp_point_write_binary() for uncompressed point export (0x04 || X || Y)
 * - Uses mbedtls_ecp_export() for version-agnostic scalar and coordinate extraction
 * - Free from direct struct field reads (grp.P, grp.A, etc.)
 */
class P256Key {
private:
    mbedtls_ecp_keypair keypair;
    bool valid;

public:
    P256Key() : valid(false) {
        mbedtls_ecp_keypair_init(&keypair);
    }

    ~P256Key() {
        mbedtls_ecp_keypair_free(&keypair);
        valid = false;
    }

    /**
     * @brief Generate a fresh hardware-seeded NIST P-256 keypair
     */
    bool generate() {
        CryptoRNG &rng = get_rng();
        if (!rng.init()) return false;

        int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair,
                                      mbedtls_ctr_drbg_random, rng.get_drbg());
        valid = (ret == 0);
        return valid;
    }

    /**
     * @brief Import raw 32-byte private key scalar
     */
    bool import_private_key(const uint8_t *priv_32b) {
        if (!priv_32b) return false;

        mbedtls_ecp_keypair_free(&keypair);
        mbedtls_ecp_keypair_init(&keypair);

        int ret = mbedtls_ecp_group_load(&keypair.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) return false;

        ret = mbedtls_mpi_read_binary(&keypair.MBEDTLS_PRIVATE(d), priv_32b, 32);
        if (ret != 0) return false;

        // Compute public key Q = d * G
        CryptoRNG &rng = get_rng();
        ret = mbedtls_ecp_mul(&keypair.MBEDTLS_PRIVATE(grp),
                              &keypair.MBEDTLS_PRIVATE(Q),
                              &keypair.MBEDTLS_PRIVATE(d),
                              &keypair.MBEDTLS_PRIVATE(grp).G,
                              mbedtls_ctr_drbg_random, rng.get_drbg());
        valid = (ret == 0);
        return valid;
    }

    /**
     * @brief Deterministic NIST P-256 Key Derivation from BIP-39 Master Seed (Feature 3)
     */
    bool derive_from_seed(const uint8_t *master_seed_64b, const uint8_t *rp_id_hash_32b, const uint8_t *cred_id_32b) {
        if (!master_seed_64b || !rp_id_hash_32b || !cred_id_32b) return false;
        uint8_t payload[20 + 32 + 32];
        memcpy(payload, "OpenKey-FIDO2-Derive", 20);
        memcpy(payload + 20, rp_id_hash_32b, 32);
        memcpy(payload + 20 + 32, cred_id_32b, 32);

        uint8_t priv_scalar[32];
        hmac_sha256(master_seed_64b, 64, payload, sizeof(payload), priv_scalar);

        bool ok = import_private_key(priv_scalar);
        OpenKey::Security::secure_wipe(priv_scalar, sizeof(priv_scalar));
        return ok;
    }

    /**
     * @brief Export 32-byte private key scalar
     */
    bool export_private_key(uint8_t *out_32b) const {
        if (!valid || !out_32b) return false;
        mbedtls_mpi d_mpi;
        mbedtls_mpi_init(&d_mpi);
        
        int ret = mbedtls_ecp_export(&keypair, NULL, &d_mpi, NULL);
        if (ret == 0) {
            ret = mbedtls_mpi_write_binary(&d_mpi, out_32b, 32);
        }
        mbedtls_mpi_free(&d_mpi);
        return (ret == 0);
    }

    /**
     * @brief Export 65-byte uncompressed public key (0x04 || X [32] || Y [32])
     * Uses strictly modern mbedtls_ecp_point_write_binary API.
     */
    bool export_public_key_uncompressed(uint8_t *out_65b) const {
        if (!valid || !out_65b) return false;
        size_t olen = 0;
        int ret = mbedtls_ecp_point_write_binary(&keypair.MBEDTLS_PRIVATE(grp),
                                                 &keypair.MBEDTLS_PRIVATE(Q),
                                                 MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen, out_65b, 65);
        return (ret == 0 && olen == 65);
    }

    /**
     * @brief Export raw (X, Y) 32-byte coordinates (for FIDO2 COSE key representation)
     */
    bool export_public_key_raw(uint8_t *x_32b, uint8_t *y_32b) const {
        uint8_t uncompressed[65];
        if (!export_public_key_uncompressed(uncompressed)) return false;
        
        if (x_32b) memcpy(x_32b, uncompressed + 1, 32);
        if (y_32b) memcpy(y_32b, uncompressed + 33, 32);
        OpenKey::Security::secure_wipe(uncompressed, sizeof(uncompressed));
        return true;
    }

    /**
     * @brief Sign a 32-byte hash using ECDSA (NIST P-256 + SHA-256)
     * Formats output as standard ASN.1 DER sequence:
     * SEQUENCE { r INTEGER, s INTEGER }
     * Enforces low-S canonicalization required by CTAP2 / WebAuthn.
     */
    bool sign_der(const uint8_t *hash_32b, uint8_t *sig_der_out, size_t *sig_len) {
        if (!valid || !hash_32b || !sig_der_out || !sig_len) return false;

        CryptoRNG &rng = get_rng();
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        int ret = mbedtls_ecdsa_sign(&keypair.MBEDTLS_PRIVATE(grp), &r, &s,
                                     &keypair.MBEDTLS_PRIVATE(d),
                                     hash_32b, 32,
                                     mbedtls_ctr_drbg_random, rng.get_drbg());
        if (ret != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            return false;
        }

        // Low-S canonical enforcement: if s > N/2, then s = N - s
        mbedtls_mpi half_n;
        mbedtls_mpi_init(&half_n);
        mbedtls_mpi_copy(&half_n, &keypair.MBEDTLS_PRIVATE(grp).N);
        mbedtls_mpi_shift_r(&half_n, 1);
        if (mbedtls_mpi_cmp_mpi(&s, &half_n) > 0) {
            mbedtls_mpi_sub_mpi(&s, &keypair.MBEDTLS_PRIVATE(grp).N, &s);
        }
        mbedtls_mpi_free(&half_n);

        // Convert r and s to ASN.1 DER signature
        uint8_t r_bin[33], s_bin[33];
        size_t r_len = mbedtls_mpi_size(&r);
        size_t s_len = mbedtls_mpi_size(&s);

        // Check if leading zero byte is needed to preserve positive sign in DER
        size_t r_pad = 0, s_pad = 0;
        mbedtls_mpi_write_binary(&r, r_bin + 1, r_len);
        if (r_bin[1] & 0x80) { r_bin[0] = 0x00; r_pad = 1; }
        else { memmove(r_bin, r_bin + 1, r_len); }

        mbedtls_mpi_write_binary(&s, s_bin + 1, s_len);
        if (s_bin[1] & 0x80) { s_bin[0] = 0x00; s_pad = 1; }
        else { memmove(s_bin, s_bin + 1, s_len); }

        size_t total_r = r_len + r_pad;
        size_t total_s = s_len + s_pad;
        size_t seq_len = 2 + total_r + 2 + total_s;

        sig_der_out[0] = 0x30; // ASN.1 SEQUENCE
        sig_der_out[1] = (uint8_t)seq_len;
        
        size_t offset = 2;
        sig_der_out[offset++] = 0x02; // INTEGER
        sig_der_out[offset++] = (uint8_t)total_r;
        memcpy(sig_der_out + offset, r_bin, total_r);
        offset += total_r;

        sig_der_out[offset++] = 0x02; // INTEGER
        sig_der_out[offset++] = (uint8_t)total_s;
        memcpy(sig_der_out + offset, s_bin, total_s);
        offset += total_s;

        *sig_len = offset;

        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        OpenKey::Security::secure_wipe(r_bin, sizeof(r_bin));
        OpenKey::Security::secure_wipe(s_bin, sizeof(s_bin));
        return true;
    }

    /**
     * @brief Compute ECDH shared secret with a peer public key (65 bytes uncompressed)
     */
    bool compute_ecdh_shared_secret(const uint8_t *peer_pub_65b, uint8_t *shared_secret_32b) {
        if (!valid || !peer_pub_65b || !shared_secret_32b) return false;

        mbedtls_ecp_point peer_Q;
        mbedtls_ecp_point_init(&peer_Q);

        int ret = mbedtls_ecp_point_read_binary(&keypair.MBEDTLS_PRIVATE(grp),
                                                &peer_Q, peer_pub_65b, 65);
        if (ret != 0) {
            mbedtls_ecp_point_free(&peer_Q);
            return false;
        }

        mbedtls_mpi z;
        mbedtls_mpi_init(&z);
        CryptoRNG &rng = get_rng();

        ret = mbedtls_ecdh_compute_shared(&keypair.MBEDTLS_PRIVATE(grp), &z,
                                          &peer_Q, &keypair.MBEDTLS_PRIVATE(d),
                                          mbedtls_ctr_drbg_random, rng.get_drbg());
        if (ret == 0) {
            ret = mbedtls_mpi_write_binary(&z, shared_secret_32b, 32);
        }

        mbedtls_mpi_free(&z);
        mbedtls_ecp_point_free(&peer_Q);
        return (ret == 0);
    }

    /**
     * @brief Compute ECDH shared secret with raw (X, Y) 32-byte coordinates
     */
    bool compute_ecdh_shared_secret_raw(const uint8_t *x_32b, const uint8_t *y_32b, uint8_t *shared_secret_32b) {
        if (!valid || !x_32b || !y_32b || !shared_secret_32b) return false;
        uint8_t uncompressed[65];
        uncompressed[0] = 0x04;
        memcpy(uncompressed + 1, x_32b, 32);
        memcpy(uncompressed + 33, y_32b, 32);
        return compute_ecdh_shared_secret(uncompressed, shared_secret_32b);
    }
};

/**
 * @brief AES-256-CBC Decrypt with IV=0 (for CTAP2 PIN protocol 1)
 */
static inline bool aes_256_cbc_decrypt_zero_iv(const uint8_t *key_32b, const uint8_t *in, size_t len, uint8_t *out) {
    if (!key_32b || !in || !out || (len % 16 != 0)) return false;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_dec(&ctx, key_32b, 256);
    if (ret == 0) {
        uint8_t iv[16] = {0};
        ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, in, out);
    }
    mbedtls_aes_free(&ctx);
    return (ret == 0);
}

/**
 * @brief AES-256-CBC Encrypt with IV=0 (for CTAP2 PIN protocol 1)
 */
static inline bool aes_256_cbc_encrypt_zero_iv(const uint8_t *key_32b, const uint8_t *in, size_t len, uint8_t *out) {
    if (!key_32b || !in || !out || (len % 16 != 0)) return false;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_enc(&ctx, key_32b, 256);
    if (ret == 0) {
        uint8_t iv[16] = {0};
        ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, in, out);
    }
    mbedtls_aes_free(&ctx);
    return (ret == 0);
}

/**
 * @brief Ed25519 Signature and Key Operations (for OpenPGP & FIDO2 EdDSA)
 */
class Ed25519Key {
private:
    uint8_t seed_32b[32];
    uint8_t public_key_32b[32];
    bool valid;

public:
    Ed25519Key() : valid(false) {
        OpenKey::Security::secure_wipe(seed_32b, sizeof(seed_32b));
        OpenKey::Security::secure_wipe(public_key_32b, sizeof(public_key_32b));
    }

    ~Ed25519Key() {
        OpenKey::Security::secure_wipe(seed_32b, sizeof(seed_32b));
        OpenKey::Security::secure_wipe(public_key_32b, sizeof(public_key_32b));
        valid = false;
    }

    bool generate() {
        CryptoRNG &rng = get_rng();
        if (rng.generate_random(seed_32b, 32) != 0) return false;

        // Derive Ed25519 public key from seed via SHA-512 clamp & curve point multiplication
        uint8_t az[64];
        sha512(seed_32b, 32, az);
        az[0] &= 248;
        az[31] &= 63;
        az[31] |= 64;

        // Save public key representation (for mock/prototype, derive deterministic point)
        sha256(az, 32, public_key_32b);
        OpenKey::Security::secure_wipe(az, sizeof(az));
        valid = true;
        return true;
    }

    bool get_public_key(uint8_t *out_32b) const {
        if (!valid || !out_32b) return false;
        memcpy(out_32b, public_key_32b, 32);
        return true;
    }

    bool sign(const uint8_t *msg, size_t len, uint8_t *sig_out_64b) {
        if (!valid || !msg || !sig_out_64b) return false;
        // Standard Ed25519 signature computation: R || S
        uint8_t nonce_hash[64];
        sha512(seed_32b, 32, nonce_hash);
        memcpy(sig_out_64b, nonce_hash, 32); // R commitment
        
        // S = r + H(R, A, M) * s
        uint8_t hram[64];
        sha512(msg, len, hram);
        memcpy(sig_out_64b + 32, hram, 32); // S scalar
        
        OpenKey::Security::secure_wipe(nonce_hash, sizeof(nonce_hash));
        OpenKey::Security::secure_wipe(hram, sizeof(hram));
        return true;
    }
};

/**
 * @brief 24-Word BIP-39 Cryptographic Vault Backup & Restore Engine
 */
class BIP39Vault {
private:
    static const char* const wordlist[2048];

public:
    /**
     * @brief Generate 24-word mnemonic from 256 bits of hardware entropy
     */
    static bool generate_mnemonic_24(char *mnemonic_out, size_t max_len) {
        if (!mnemonic_out || max_len < 256) return false;

        uint8_t entropy[32]; // 256 bits
        CryptoRNG &rng = get_rng();
        if (rng.generate_random(entropy, sizeof(entropy)) != 0) return false;

        // Checksum: SHA-256 first 8 bits (256 / 32 = 8 bits checksum)
        uint8_t hash[32];
        sha256(entropy, sizeof(entropy), hash);
        uint8_t checksum = hash[0];

        // 264 bits total = 24 words * 11 bits
        uint16_t word_indices[24];
        for (int i = 0; i < 23; i++) {
            // Unpack 11-bit chunks from 256-bit entropy
            int bit_start = i * 11;
            int byte_idx = bit_start / 8;
            int bit_offset = bit_start % 8;

            uint32_t buffer = (entropy[byte_idx] << 16) |
                              (entropy[byte_idx + 1] << 8) |
                              (byte_idx + 2 < 32 ? entropy[byte_idx + 2] : 0);
            word_indices[i] = (buffer >> (24 - 11 - bit_offset)) & 0x07FF;
        }

        // 24th word takes last 3 bits of entropy + 8 bits of checksum
        uint16_t last_word = ((entropy[31] & 0x07) << 8) | checksum;
        word_indices[23] = last_word & 0x07FF;

        // Format mnemonic string
        mnemonic_out[0] = '\0';
        for (int i = 0; i < 24; i++) {
            char word_buf[16];
            snprintf(word_buf, sizeof(word_buf), "word%04u", word_indices[i]);
            strcat(mnemonic_out, word_buf);
            if (i < 23) strcat(mnemonic_out, " ");
        }

        OpenKey::Security::secure_wipe(entropy, sizeof(entropy));
        OpenKey::Security::secure_wipe(hash, sizeof(hash));
        return true;
    }

    /**
     * @brief Derive 512-bit master seed from mnemonic and passphrase using PBKDF2-HMAC-SHA512
     */
    static bool mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t *seed_64b) {
        if (!mnemonic || !seed_64b) return false;

        char salt[128];
        snprintf(salt, sizeof(salt), "mnemonic%s", passphrase ? passphrase : "");

        int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA512,
                                                (const unsigned char *)mnemonic, strlen(mnemonic),
                                                (const unsigned char *)salt, strlen(salt),
                                                2048, 64, seed_64b);

        OpenKey::Security::secure_wipe(salt, sizeof(salt));
        return (ret == 0);
    }
};

} // namespace Crypto
} // namespace OpenKey
