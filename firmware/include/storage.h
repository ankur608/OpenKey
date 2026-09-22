/**
 * @file storage.h
 * @brief OpenKey Raw NVS Storage Engine & Flash Security Hooks
 * @version 1.0.0
 * 
 * Target: Waveshare ESP32-S3-Zero (4MB SPI Flash)
 * Uses native raw NVS (Non-Volatile Storage) namespaces to bypass SPIFFS/FAT overhead.
 * Hardware-enforced AES-XTS Flash Encryption hooks and zero-leak memory isolation.
 */

#pragma once

#include <Arduino.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <esp_flash_encrypt.h>
#include <mbedtls/sha256.h>

#if __has_include("vapt_security.h")
#include "vapt_security.h"
#elif __has_include("include/vapt_security.h")
#include "include/vapt_security.h"
#else
#include "../include/vapt_security.h"
#endif

#define NVS_PART_FIDO       "fido_nvs"
#define NVS_NS_CONFIG       "ok_cfg"
#define NVS_NS_FIDO_RK      "ok_fido_rk"
#define NVS_NS_BLOBS        "ok_blobs"

#define MAX_RESIDENT_KEYS   1000
#define MAX_LARGE_BLOB_SIZE 2048

namespace OpenKey {
namespace Storage {

/**
 * @brief FIDO2 Resident Key Data Structure stored in Raw NVS
 */
struct __attribute__((packed)) FidoResidentKeyRecord {
    uint8_t rp_id_hash[32];      // SHA-256(rp.id)
    uint8_t credential_id[32];   // Unique credential ID
    uint8_t private_key[32];     // NIST P-256 scalar or Ed25519 seed
    uint8_t user_id[32];         // User Entity ID
    uint8_t user_id_len;
    char user_name[64];          // Display name
    uint32_t sign_counter;       // Monotonic counter per credential
    uint8_t algorithm;           // -7 (ES256) or -8 (EdDSA)
    uint8_t cred_protect;        // CTAP 2.1 CredProtect level (1..3)
    uint8_t is_active;           // 0x01 = valid, 0x00 = deleted
};

/**
 * @brief Device Global Configuration & Security Vault Parameters
 */
struct __attribute__((packed)) DeviceConfig {
    uint8_t initialized;         // 0xA5 = initialized
    uint8_t pin_hash[32];        // SHA-256(PIN) or CTAP2 pinAuth
    uint8_t duress_pin_hash[32]; // Secondary Duress / Panic PIN
    uint8_t duress_pin_set;      // 0x01 = configured, 0x00 = none
    uint8_t pin_retries_remaining;
    uint8_t min_pin_length;      // CTAP 2.1 minPinLength policy
    uint32_t global_sign_counter;// Anti-replay monotonic counter
    uint8_t master_seed[64];     // BIP-39 root seed
    uint8_t seed_configured;     // 0x01 = seed active, 0x00 = none
    uint8_t stealth_aaguid_mode; // 0x00 = standard enterprise, 0x01 = stealth ephemeral
    uint8_t seed_fingerprint[4]; // First 4 bytes of SHA-256(master_seed)
    uint8_t large_blob[MAX_LARGE_BLOB_SIZE];
    size_t large_blob_len;
};

class FlashVault {
private:
    DeviceConfig config;
    bool nvs_ready;

public:
    FlashVault() : nvs_ready(false) {
        memset(&config, 0, sizeof(config));
    }

    bool init() {
        esp_err_t err = nvs_flash_init();
        if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            nvs_flash_erase();
            err = nvs_flash_init();
        }
        if (err != ESP_OK) return false;

        err = nvs_flash_init_partition(NVS_PART_FIDO);
        if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            nvs_flash_erase_partition(NVS_PART_FIDO);
            err = nvs_flash_init_partition(NVS_PART_FIDO);
        }
        if (err != ESP_OK) return false;

        nvs_ready = true;
        load_config();
        return true;
    }

    /**
     * @brief Inspect and report hardware Flash Encryption state
     */
    bool is_flash_encryption_enabled() const {
        return esp_flash_encryption_enabled();
    }

    void load_config() {
        nvs_handle_t handle;
        if (nvs_open_from_partition(NVS_PART_FIDO, NVS_NS_CONFIG, NVS_READWRITE, &handle) != ESP_OK) return;

        size_t size = sizeof(config);
        esp_err_t err = nvs_get_blob(handle, "cfg", &config, &size);
        if (err != ESP_OK || config.initialized != 0xA5) {
            // First time boot initialization
            memset(&config, 0, sizeof(config));
            config.initialized = 0xA5;
            config.pin_retries_remaining = OpenKey::Security::PinSecurityPolicy::MAX_PIN_RETRIES;
            config.min_pin_length = OpenKey::Security::PinSecurityPolicy::MIN_PIN_LENGTH;
            config.global_sign_counter = 1;
            config.large_blob_len = 0;
            nvs_set_blob(handle, "cfg", &config, sizeof(config));
            nvs_commit(handle);
        }
        nvs_close(handle);
    }

    void save_config() {
        nvs_handle_t handle;
        if (nvs_open_from_partition(NVS_PART_FIDO, NVS_NS_CONFIG, NVS_READWRITE, &handle) != ESP_OK) return;
        nvs_set_blob(handle, "cfg", &config, sizeof(config));
        nvs_commit(handle);
        nvs_close(handle);
    }

    uint32_t increment_global_counter() {
        config.global_sign_counter++;
        save_config();
        return config.global_sign_counter;
    }

    uint32_t get_global_counter() const {
        return config.global_sign_counter;
    }

    bool is_pin_set() const {
        for (int i = 0; i < 32; i++) {
            if (config.pin_hash[i] != 0) return true;
        }
        return false;
    }

    uint8_t get_pin_retries() const {
        return config.pin_retries_remaining;
    }

    uint8_t get_min_pin_length() const {
        return config.min_pin_length;
    }

    bool set_pin(const uint8_t *new_pin_hash_32b, uint8_t min_len = 4) {
        if (!new_pin_hash_32b) return false;
        memcpy(config.pin_hash, new_pin_hash_32b, 32);
        config.pin_retries_remaining = OpenKey::Security::PinSecurityPolicy::MAX_PIN_RETRIES;
        config.min_pin_length = min_len;
        save_config();
        return true;
    }

    /**
     * @brief Constant-time PIN Verification with Monotonic Rate Limiting
     * Supports both 16-byte CTAP2 pinHash and full 32-byte hashes
     */
    bool set_duress_pin(const uint8_t *new_duress_hash_32b) {
        if (!new_duress_hash_32b) return false;
        memcpy(config.duress_pin_hash, new_duress_hash_32b, 32);
        config.duress_pin_set = 0x01;
        save_config();
        return true;
    }

    bool is_duress_pin_set() const {
        return config.duress_pin_set == 0x01;
    }

    bool check_and_execute_duress_wipe(const uint8_t *candidate_hash, size_t len = 16) {
        if (config.duress_pin_set != 0x01) return false;
        if (OpenKey::Security::constant_time_memcmp(candidate_hash, config.duress_pin_hash, len) == 0) {
            // Duress PIN triggered: Execute silent hardware erase of fido_nvs partition
            factory_reset();
            return true;
        }
        return false;
    }

    /**
     * @brief Constant-time PIN Verification with Monotonic Rate Limiting and Duress Trap
     * Supports both 16-byte CTAP2 pinHash and full 32-byte hashes
     */
    bool verify_pin(const uint8_t *candidate_pin_hash, size_t len = 16) {
        if (check_and_execute_duress_wipe(candidate_pin_hash, len)) {
            // Duress wipe completed silently. Return false to mimic invalid PIN to adversary
            return false;
        }

        if (!is_pin_set()) return false;
        if (config.pin_retries_remaining == 0) return false; // Hard lockout

        // Apply penalty backoff delay
        uint32_t delay_ms = OpenKey::Security::PinSecurityPolicy::get_penalty_delay_ms(config.pin_retries_remaining);
        if (delay_ms > 0) delay(delay_ms);

        // Constant-time comparison
        int cmp = OpenKey::Security::constant_time_memcmp(candidate_pin_hash, config.pin_hash, len);
        if (cmp == 0) {
            // Success: Reset retry counter
            config.pin_retries_remaining = OpenKey::Security::PinSecurityPolicy::MAX_PIN_RETRIES;
            save_config();
            return true;
        } else {
            // Failure: Decrement retries monotonically
            config.pin_retries_remaining--;
            save_config();
            if (config.pin_retries_remaining == 0) {
                // Brute-force lockout triggered - wipe credentials to prevent leak
                factory_reset();
            }
            return false;
        }
    }

    /**
     * @brief Save FIDO2 Resident Key to NVS row
     */
    bool save_resident_key(const FidoResidentKeyRecord &rec) {
        nvs_handle_t handle;
        if (nvs_open_from_partition(NVS_PART_FIDO, NVS_NS_FIDO_RK, NVS_READWRITE, &handle) != ESP_OK) return false;

        char key_str[16];
        int first_free_slot = -1;

        // Pass 1: Overwrite existing credential for same RP ID hash if present
        for (int i = 0; i < MAX_RESIDENT_KEYS; i++) {
            snprintf(key_str, sizeof(key_str), "rk_%04d", i);
            FidoResidentKeyRecord slot;
            size_t size = sizeof(slot);
            esp_err_t err = nvs_get_blob(handle, key_str, &slot, &size);
            if (err == ESP_OK && slot.is_active != 0) {
                if (OpenKey::Security::constant_time_memcmp(slot.rp_id_hash, rec.rp_id_hash, 32) == 0) {
                    nvs_set_blob(handle, key_str, &rec, sizeof(rec));
                    nvs_commit(handle);
                    nvs_close(handle);
                    return true;
                }
            } else if (first_free_slot == -1) {
                first_free_slot = i;
            }
        }

        // Pass 2: Use free slot
        int target_slot = (first_free_slot >= 0) ? first_free_slot : 0; // Overwrite slot 0 if full
        snprintf(key_str, sizeof(key_str), "rk_%04d", target_slot);
        nvs_set_blob(handle, key_str, &rec, sizeof(rec));
        nvs_commit(handle);
        nvs_close(handle);
        return true;
    }

    /**
     * @brief Search for Resident Key by RP ID Hash
     */
    bool find_resident_key_by_rp(const uint8_t *rp_id_hash_32b, FidoResidentKeyRecord *out_rec) {
        nvs_handle_t handle;
        if (nvs_open_from_partition(NVS_PART_FIDO, NVS_NS_FIDO_RK, NVS_READONLY, &handle) != ESP_OK) return false;

        char key_str[16];
        for (int i = 0; i < MAX_RESIDENT_KEYS; i++) {
            snprintf(key_str, sizeof(key_str), "rk_%04d", i);
            FidoResidentKeyRecord slot;
            size_t size = sizeof(slot);
            if (nvs_get_blob(handle, key_str, &slot, &size) == ESP_OK) {
                if (slot.is_active && OpenKey::Security::constant_time_memcmp(slot.rp_id_hash, rp_id_hash_32b, 32) == 0) {
                    if (out_rec) *out_rec = slot;
                    nvs_close(handle);
                    return true;
                }
            }
        }
        nvs_close(handle);
        return false;
    }

    /**
     * @brief Search for Resident Key by Credential ID
     */
    bool find_resident_key_by_id(const uint8_t *cred_id_32b, FidoResidentKeyRecord *out_rec) {
        nvs_handle_t handle;
        if (nvs_open_from_partition(NVS_PART_FIDO, NVS_NS_FIDO_RK, NVS_READONLY, &handle) != ESP_OK) return false;

        char key_str[16];
        for (int i = 0; i < MAX_RESIDENT_KEYS; i++) {
            snprintf(key_str, sizeof(key_str), "rk_%04d", i);
            FidoResidentKeyRecord slot;
            size_t size = sizeof(slot);
            if (nvs_get_blob(handle, key_str, &slot, &size) == ESP_OK) {
                if (slot.is_active && OpenKey::Security::constant_time_memcmp(slot.credential_id, cred_id_32b, 32) == 0) {
                    if (out_rec) *out_rec = slot;
                    nvs_close(handle);
                    return true;
                }
            }
        }
        nvs_close(handle);
        return false;
    }

    bool find_resident_key(const uint8_t *cred_id_32b, const uint8_t *rp_id_hash_32b, FidoResidentKeyRecord *out_rec) {
        if (cred_id_32b && find_resident_key_by_id(cred_id_32b, out_rec)) return true;
        if (rp_id_hash_32b && find_resident_key_by_rp(rp_id_hash_32b, out_rec)) return true;
        return false;
    }

    /**
     * @brief Check if a Relying Party (domain) is already registered on this key
     */
    bool is_rp_registered(const uint8_t *rp_id_hash_32b) {
        if (!rp_id_hash_32b) return false;
        FidoResidentKeyRecord dummy;
        return find_resident_key_by_rp(rp_id_hash_32b, &dummy);
    }

    /**
     * @brief WebAuthn LargeBlobs Storage Extension: Read & Write
     */
    bool write_large_blob(const uint8_t *data, size_t len) {
        if (len > MAX_LARGE_BLOB_SIZE) return false;
        memcpy(config.large_blob, data, len);
        config.large_blob_len = len;
        save_config();
        return true;
    }

    size_t read_large_blob(uint8_t *dest, size_t max_len) {
        if (!dest) return 0;
        size_t to_copy = (config.large_blob_len < max_len) ? config.large_blob_len : max_len;
        memcpy(dest, config.large_blob, to_copy);
        return to_copy;
    }

    /**
     * @brief Feature 3: Set BIP-39 Master Seed & Derive Fingerprint
     */
    bool set_master_seed(const uint8_t *seed_64b) {
        if (!seed_64b) return false;
        memcpy(config.master_seed, seed_64b, 64);
        config.seed_configured = 0x01;
        uint8_t hash[32];
        mbedtls_sha256(seed_64b, 64, hash, 0);
        memcpy(config.seed_fingerprint, hash, 4);
        save_config();
        return true;
    }

    bool is_seed_configured() const {
        return config.seed_configured == 0x01;
    }

    bool get_master_seed(uint8_t *out_seed_64b) const {
        if (!out_seed_64b || config.seed_configured != 0x01) return false;
        memcpy(out_seed_64b, config.master_seed, 64);
        return true;
    }

    bool get_seed_fingerprint(uint8_t *out_fp_4b) const {
        if (!out_fp_4b) return false;
        memcpy(out_fp_4b, config.seed_fingerprint, 4);
        return true;
    }

    /**
     * @brief Feature 6 & FIDO MDS: Set AAGUID Profile
     * 0 = Native OpenKey AAGUID (4f70656e-4b65-7953-3330-000000000001)
     * 1 = Stealth Mode / Ephemeral Anti-Tracking
     * 2 = FIDO MDS L2 Compatible Profile (a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa)
     */
    void set_stealth_mode(uint8_t mode) {
        config.stealth_aaguid_mode = (mode <= 2) ? mode : 0x00;
        save_config();
    }

    uint8_t get_stealth_mode() const {
        return config.stealth_aaguid_mode;
    }

    uint16_t get_active_resident_key_count() {
        nvs_handle_t handle;
        if (nvs_open_from_partition(NVS_PART_FIDO, NVS_NS_FIDO_RK, NVS_READONLY, &handle) != ESP_OK) return 0;
        uint16_t count = 0;
        char key_str[16];
        for (int i = 0; i < MAX_RESIDENT_KEYS; i++) {
            snprintf(key_str, sizeof(key_str), "rk_%04d", i);
            FidoResidentKeyRecord slot;
            size_t size = sizeof(slot);
            if (nvs_get_blob(handle, key_str, &slot, &size) == ESP_OK) {
                if (slot.is_active) count++;
            }
        }
        nvs_close(handle);
        return count;
    }

    /**
     * @brief Factory Reset: Wipes all NVS cryptographic keys, PINs, and accounts
     */
    void factory_reset() {
        nvs_flash_erase_partition(NVS_PART_FIDO);
        nvs_flash_init_partition(NVS_PART_FIDO);
        memset(&config, 0, sizeof(config));
        config.initialized = 0xA5;
        config.pin_retries_remaining = OpenKey::Security::PinSecurityPolicy::MAX_PIN_RETRIES;
        config.min_pin_length = OpenKey::Security::PinSecurityPolicy::MIN_PIN_LENGTH;
        config.global_sign_counter = 1;
        save_config();
    }
};

/**
 * @brief Global singleton instance of FlashVault
 */
static inline FlashVault& get_vault() {
    static FlashVault instance;
    return instance;
}

} // namespace Storage
} // namespace OpenKey
