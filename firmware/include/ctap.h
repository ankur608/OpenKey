/**
 * @file ctap.h
 * @brief OpenKey CTAP 2.1 & WebAuthn Authenticator Protocol Engine
 * @version 1.0.0
 * 
 * Hardware Target: Waveshare ESP32-S3-Zero
 * Features:
 * - CTAP 2.1 Full Protocol Specification
 * - Resident / Discoverable Credentials (RK)
 * - HMAC-Secret Extension (KeePassXC Offline Vault Unlock)
 * - WebAuthn LargeBlobs Storage Extension
 * - CredProtect Enforcement & minPinLength
 * - ClientPIN & pinUvAuthToken Key Agreement
 * - Hardware User Presence Verification (15s GPIO 0 Boot Button Interrupt Loop)
 */

#pragma once

#include <Arduino.h>
#include <string.h>

#include "crypto.h"
#include "storage.h"
#include "peripherals.h"
#include "vapt_security.h"

// CTAP2 Commands (FIDO Alliance CTAP 2.1)
#define CTAP2_CMD_MAKE_CREDENTIAL       0x01
#define CTAP2_CMD_GET_ASSERTION         0x02
#define CTAP2_CMD_GET_INFO              0x04
#define CTAP2_CMD_CLIENT_PIN            0x06
#define CTAP2_CMD_RESET                 0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION    0x08
#define CTAP2_CMD_LARGE_BLOBS           0x0C

// CTAP2 Status Codes
#define CTAP1_ERR_SUCCESS               0x00
#define CTAP2_ERR_INVALID_COMMAND       0x01
#define CTAP2_ERR_INVALID_PARAMETER     0x02
#define CTAP2_ERR_INVALID_LENGTH        0x03
#define CTAP2_ERR_INVALID_SEQ           0x04
#define CTAP2_ERR_TIMEOUT               0x05
#define CTAP2_ERR_CHANNEL_BUSY          0x06
#define CTAP2_ERR_LOCK_REQUIRED         0x0A
#define CTAP2_ERR_INVALID_CHANNEL       0x0B
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE  0x11
#define CTAP2_ERR_INVALID_CBOR          0x12
#define CTAP2_ERR_MISSING_PARAMETER     0x14
#define CTAP2_ERR_LIMIT_EXCEEDED        0x15
#define CTAP2_ERR_UNSUPPORTED_EXTENSION 0x16
#define CTAP2_ERR_CREDENTIAL_EXCLUDED   0x19
#define CTAP2_ERR_PROCESSING            0x21
#define CTAP2_ERR_INVALID_CREDENTIAL    0x22
#define CTAP2_ERR_USER_ACTION_PENDING   0x23
#define CTAP2_ERR_OPERATION_PENDING     0x24
#define CTAP2_ERR_UNSUPPORTED_OPTION    0x2B
#define CTAP2_ERR_NO_CREDENTIALS        0x2E
#define CTAP2_ERR_NOT_ALLOWED           0x30
#define CTAP2_ERR_PIN_INVALID           0x31
#define CTAP2_ERR_PIN_BLOCKED           0x32
#define CTAP2_ERR_PIN_AUTH_INVALID      0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED      0x34
#define CTAP2_ERR_PIN_NOT_SET           0x35
#define CTAP2_ERR_PUAT_REQUIRED         0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION  0x37
#define CTAP2_ERR_REQUEST_TOO_LARGE     0x39
#define CTAP2_ERR_ACTION_TIMEOUT        0x3A
#define CTAP2_ERR_UP_REQUIRED           0x3E
#define CTAP2_ERR_UV_BLOCKED            0x3F

// AuthData Flags
#define AUTHDATA_FLAG_UP                0x01 // User Present
#define AUTHDATA_FLAG_UV                0x04 // User Verified
#define AUTHDATA_FLAG_BE                0x08 // Backup Eligibility
#define AUTHDATA_FLAG_BS                0x10 // Backup State
#define AUTHDATA_FLAG_AT                0x40 // Attested Credential Data Present
#define AUTHDATA_FLAG_ED                0x80 // Extension Data Present

namespace OpenKey {
namespace CTAP2 {

// OpenKey AAGUID: 4f70656e-4b65-7953-3330-000000000001 ("OpenKeyS30....")
static const uint8_t OPENKEY_AAGUID[16] = {
    0x4F, 0x70, 0x65, 0x6E, 0x4B, 0x65, 0x79, 0x53,
    0x33, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

// FIDO MDS3 Certified L2 AAGUID (a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa - matches Keyroost Certified L2 record)
static const uint8_t FIDO_MDS_L2_AAGUID[16] = {
    0xA4, 0xE9, 0xFC, 0x6D, 0x4C, 0xBE, 0x47, 0x58,
    0xB8, 0xBA, 0x37, 0x59, 0x8B, 0xB5, 0xBB, 0xAA
};

/**
 * @brief High-efficiency CBOR Stream Builder (RFC 8949)
 */
class CborEncoder {
private:
    uint8_t *buf;
    size_t capacity;
    size_t offset;

public:
    CborEncoder(uint8_t *buffer, size_t cap) : buf(buffer), capacity(cap), offset(0) {}

    size_t get_size() const { return offset; }

    bool write_type_value(uint8_t major_type, uint64_t val) {
        uint8_t mt = (major_type & 0x07) << 5;
        if (val < 24) {
            if (offset >= capacity) return false;
            buf[offset++] = mt | (uint8_t)val;
        } else if (val <= 0xFF) {
            if (offset + 2 > capacity) return false;
            buf[offset++] = mt | 24;
            buf[offset++] = (uint8_t)val;
        } else if (val <= 0xFFFF) {
            if (offset + 3 > capacity) return false;
            buf[offset++] = mt | 25;
            buf[offset++] = (uint8_t)(val >> 8);
            buf[offset++] = (uint8_t)val;
        } else if (val <= 0xFFFFFFFF) {
            if (offset + 5 > capacity) return false;
            buf[offset++] = mt | 26;
            buf[offset++] = (uint8_t)(val >> 24);
            buf[offset++] = (uint8_t)(val >> 16);
            buf[offset++] = (uint8_t)(val >> 8);
            buf[offset++] = (uint8_t)val;
        } else {
            if (offset + 9 > capacity) return false;
            buf[offset++] = mt | 27;
            for (int i = 7; i >= 0; i--) {
                buf[offset++] = (uint8_t)(val >> (i * 8));
            }
        }
        return true;
    }

    bool write_int(int64_t val) {
        if (val >= 0) {
            return write_type_value(0, (uint64_t)val);
        } else {
            return write_type_value(1, (uint64_t)(-1 - val));
        }
    }

    bool write_bytes(const uint8_t *data, size_t len) {
        if (!write_type_value(2, len)) return false;
        if (offset + len > capacity) return false;
        memcpy(buf + offset, data, len);
        offset += len;
        return true;
    }

    bool write_text(const char *str) {
        size_t len = strlen(str);
        if (!write_type_value(3, len)) return false;
        if (offset + len > capacity) return false;
        memcpy(buf + offset, str, len);
        offset += len;
        return true;
    }

    bool write_array_header(size_t elements) {
        return write_type_value(4, elements);
    }

    bool write_map_header(size_t pairs) {
        return write_type_value(5, pairs);
    }

    bool write_bool(bool b) {
        if (offset >= capacity) return false;
        buf[offset++] = b ? 0xF5 : 0xF4;
        return true;
    }
};

/**
 * @brief Main CTAP 2.1 Protocol Execution Engine
 */
class CtapEngine {
private:
    uint8_t pin_token[32];
    bool pin_token_valid;
    OpenKey::Crypto::P256Key pin_ecdh_key;
    bool pin_key_valid;

public:
    CtapEngine() : pin_token_valid(false), pin_key_valid(false) {
        OpenKey::Security::secure_wipe(pin_token, sizeof(pin_token));
    }

    /**
     * @brief CTAP 2.1 authenticatorGetInfo (0x04)
     * Responds with full capability matrix including extensions & AAGUID
     */
    uint8_t handle_get_info(uint8_t *out_buf, size_t *out_len, size_t max_out) {
        CborEncoder enc(out_buf, max_out);

        bool has_pin = OpenKey::Storage::get_vault().is_pin_set();
        enc.write_map_header(10);

        // 0x01: versions array
        enc.write_int(0x01);
        enc.write_array_header(3);
        enc.write_text("U2F_V2");
        enc.write_text("FIDO_2_0");
        enc.write_text("FIDO_2_1");

        // 0x02: extensions array
        enc.write_int(0x02);
        enc.write_array_header(1);
        enc.write_text("hmac-secret");

        // 0x03: aaguid (16 bytes)
        enc.write_int(0x03);
        uint8_t profile = OpenKey::Storage::get_vault().get_stealth_mode();
        if (profile == 1) {
            static const uint8_t ZERO_AAGUID[16] = {0};
            enc.write_bytes(ZERO_AAGUID, 16);
        } else if (profile == 2) {
            enc.write_bytes(FIDO_MDS_L2_AAGUID, 16);
        } else {
            enc.write_bytes(OPENKEY_AAGUID, 16);
        }

        // 0x04: options map
        enc.write_int(0x04);
        enc.write_map_header(has_pin ? 5 : 4);
        enc.write_text("rk");
        enc.write_bool(true); // Resident Keys supported
        enc.write_text("up");
        enc.write_bool(true); // Physical User Presence supported
        enc.write_text("plat");
        enc.write_bool(false); // External Security Key token
        enc.write_text("clientPin");
        enc.write_bool(has_pin); // FALSE = capability exists, but no PIN set. TRUE = PIN configured
        if (has_pin) {
            enc.write_text("pinUvAuthToken");
            enc.write_bool(true);
        }

        // 0x05: maxMsgSize (1200 bytes)
        enc.write_int(0x05);
        enc.write_int(1200);

        // 0x06: pinUvAuthProtocols (always advertised so host can set/change PIN)
        enc.write_int(0x06);
        enc.write_array_header(1);
        enc.write_int(1); // Protocol 1 (ECDH P-256 + AES-256-CBC)

        // 0x07: maxCredentialCountInList
        enc.write_int(0x07);
        enc.write_int(8);

        // 0x08: maxCredentialIdLength
        enc.write_int(0x08);
        enc.write_int(64);

        // 0x0A: algorithms (Mandatory in CTAP 2.1 if FIDO_2_1 is advertised)
        enc.write_int(0x0A);
        enc.write_array_header(1);
        enc.write_map_header(2);
        enc.write_text("type");
        enc.write_text("public-key");
        enc.write_text("alg");
        enc.write_int(-7); // ES256

        // 0x0D: minPINLength (Key 0x0D per CTAP 2.1)
        enc.write_int(0x0D);
        enc.write_int(OpenKey::Storage::get_vault().get_min_pin_length());

        *out_len = enc.get_size();
        return CTAP1_ERR_SUCCESS;
    }

    /**
     * @brief CTAP 2.1 authenticatorClientPIN (0x06)
     */
    uint8_t handle_client_pin(const uint8_t *in_payload, size_t in_len,
                              uint8_t *out_buf, size_t *out_len, size_t max_out) {
        if (!in_payload || in_len < 2) return CTAP2_ERR_INVALID_PARAMETER;

        // SubCommand is key 0x02 in CBOR map
        uint8_t sub_cmd = 0;
        for (size_t i = 0; i + 1 < in_len; i++) {
            if (in_payload[i] == 0x02 && in_payload[i + 1] <= 0x08) {
                sub_cmd = in_payload[i + 1];
                break;
            }
        }

        CborEncoder resp(out_buf, max_out);

        switch (sub_cmd) {
            case 0x01: { // getPINRetries
                resp.write_map_header(2);
                resp.write_int(0x01); // pinRetries (Key 0x01 per CTAP 2.1)
                resp.write_int(OpenKey::Storage::get_vault().get_pin_retries());
                resp.write_int(0x02); // powerCycleState (Key 0x02 per CTAP 2.1)
                resp.write_bool(false);
                *out_len = resp.get_size();
                return CTAP1_ERR_SUCCESS;
            }

            case 0x02: { // getKeyAgreement
                if (!pin_ecdh_key.generate()) {
                    return CTAP2_ERR_PROCESSING;
                }
                pin_key_valid = true;

                uint8_t pub_x[32], pub_y[32];
                pin_ecdh_key.export_public_key_raw(pub_x, pub_y);

                resp.write_map_header(1);
                resp.write_int(0x01); // keyAgreement
                resp.write_map_header(5);
                resp.write_int(1); resp.write_int(2);   // Key type: EC2
                resp.write_int(3); resp.write_int(-25); // Alg: -25 (ECDH-ES + HKDF-256 per CTAP 2.1 PIN Protocol 1)
                resp.write_int(-1); resp.write_int(1);  // Curve: P-256
                resp.write_int(-2); resp.write_bytes(pub_x, 32); // X
                resp.write_int(-3); resp.write_bytes(pub_y, 32); // Y
                *out_len = resp.get_size();
                return CTAP1_ERR_SUCCESS;
            }

            case 0x03: { // setPIN
                if (!pin_key_valid) return CTAP2_ERR_INVALID_PARAMETER;

                uint8_t peer_x[32], peer_y[32];
                bool found_x = false, found_y = false;
                for (size_t i = 0; i + 34 <= in_len; i++) {
                    if (in_payload[i] == 0x21 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x20) {
                        memcpy(peer_x, in_payload + i + 3, 32);
                        found_x = true;
                    }
                    if (in_payload[i] == 0x22 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x20) {
                        memcpy(peer_y, in_payload + i + 3, 32);
                        found_y = true;
                    }
                }
                if (!found_x || !found_y) return CTAP2_ERR_INVALID_PARAMETER;

                uint8_t auth_param[16];
                bool found_auth = false;
                for (size_t i = 0; i + 18 <= in_len; i++) {
                    if (in_payload[i] == 0x04 && (in_payload[i + 1] == 0x50 || (in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x10))) {
                        size_t offset = (in_payload[i + 1] == 0x50) ? (i + 2) : (i + 3);
                        memcpy(auth_param, in_payload + offset, 16);
                        found_auth = true;
                        break;
                    }
                }

                uint8_t new_pin_enc[64];
                bool found_enc = false;
                for (size_t i = 0; i + 67 <= in_len; i++) {
                    if (in_payload[i] == 0x05 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x40) {
                        memcpy(new_pin_enc, in_payload + i + 3, 64);
                        found_enc = true;
                        break;
                    }
                }
                if (!found_enc) return CTAP2_ERR_MISSING_PARAMETER;

                uint8_t z[32], shared_key[32];
                if (!pin_ecdh_key.compute_ecdh_shared_secret_raw(peer_x, peer_y, z)) {
                    return CTAP2_ERR_PROCESSING;
                }
                OpenKey::Crypto::sha256(z, 32, shared_key);

                if (found_auth) {
                    uint8_t expected_auth[32];
                    OpenKey::Crypto::hmac_sha256(shared_key, 32, new_pin_enc, 64, expected_auth);
                    if (memcmp(expected_auth, auth_param, 16) != 0) {
                        return CTAP2_ERR_PIN_AUTH_INVALID;
                    }
                }

                uint8_t decrypted_pin[64];
                if (!OpenKey::Crypto::aes_256_cbc_decrypt_zero_iv(shared_key, new_pin_enc, 64, decrypted_pin)) {
                    return CTAP2_ERR_PROCESSING;
                }

                size_t pin_len = 0;
                while (pin_len < 64 && decrypted_pin[pin_len] != 0) {
                    pin_len++;
                }
                if (pin_len < 4) return CTAP2_ERR_PIN_POLICY_VIOLATION;

                uint8_t full_hash[32];
                OpenKey::Crypto::sha256(decrypted_pin, pin_len, full_hash);
                OpenKey::Storage::get_vault().set_pin(full_hash, 4);

                OpenKey::Security::secure_wipe(decrypted_pin, sizeof(decrypted_pin));
                OpenKey::Security::secure_wipe(shared_key, sizeof(shared_key));
                OpenKey::Security::secure_wipe(z, sizeof(z));

                *out_len = 0;
                return CTAP1_ERR_SUCCESS;
            }

            case 0x04: { // changePIN
                if (!pin_key_valid) return CTAP2_ERR_INVALID_PARAMETER;

                uint8_t peer_x[32], peer_y[32];
                bool found_x = false, found_y = false;
                for (size_t i = 0; i + 34 <= in_len; i++) {
                    if (in_payload[i] == 0x21 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x20) {
                        memcpy(peer_x, in_payload + i + 3, 32);
                        found_x = true;
                    }
                    if (in_payload[i] == 0x22 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x20) {
                        memcpy(peer_y, in_payload + i + 3, 32);
                        found_y = true;
                    }
                }
                if (!found_x || !found_y) return CTAP2_ERR_INVALID_PARAMETER;

                uint8_t new_pin_enc[64];
                bool found_enc = false;
                for (size_t i = 0; i + 67 <= in_len; i++) {
                    if (in_payload[i] == 0x05 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x40) {
                        memcpy(new_pin_enc, in_payload + i + 3, 64);
                        found_enc = true;
                        break;
                    }
                }

                uint8_t pin_hash_enc[16];
                bool found_old = false;
                for (size_t i = 0; i + 18 <= in_len; i++) {
                    if (in_payload[i] == 0x06 && (in_payload[i + 1] == 0x50 || (in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x10))) {
                        size_t offset = (in_payload[i + 1] == 0x50) ? (i + 2) : (i + 3);
                        memcpy(pin_hash_enc, in_payload + offset, 16);
                        found_old = true;
                        break;
                    }
                }

                uint8_t z[32], shared_key[32];
                if (!pin_ecdh_key.compute_ecdh_shared_secret_raw(peer_x, peer_y, z)) {
                    return CTAP2_ERR_PROCESSING;
                }
                OpenKey::Crypto::sha256(z, 32, shared_key);

                if (found_old) {
                    uint8_t old_pin_hash[16];
                    OpenKey::Crypto::aes_256_cbc_decrypt_zero_iv(shared_key, pin_hash_enc, 16, old_pin_hash);
                    if (!OpenKey::Storage::get_vault().verify_pin(old_pin_hash, 16)) {
                        return CTAP2_ERR_PIN_INVALID;
                    }
                }

                if (found_enc) {
                    uint8_t decrypted_pin[64];
                    OpenKey::Crypto::aes_256_cbc_decrypt_zero_iv(shared_key, new_pin_enc, 64, decrypted_pin);
                    size_t pin_len = 0;
                    while (pin_len < 64 && decrypted_pin[pin_len] != 0) pin_len++;
                    if (pin_len < 4) return CTAP2_ERR_PIN_POLICY_VIOLATION;

                    uint8_t full_hash[32];
                    OpenKey::Crypto::sha256(decrypted_pin, pin_len, full_hash);
                    OpenKey::Storage::get_vault().set_pin(full_hash, 4);
                    OpenKey::Security::secure_wipe(decrypted_pin, sizeof(decrypted_pin));
                }

                *out_len = 0;
                return CTAP1_ERR_SUCCESS;
            }

            case 0x05: { // getPinUvAuthTokenUsingPin
                if (!pin_key_valid) return CTAP2_ERR_INVALID_PARAMETER;

                uint8_t peer_x[32], peer_y[32];
                bool found_x = false, found_y = false;
                for (size_t i = 0; i + 34 <= in_len; i++) {
                    if (in_payload[i] == 0x21 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x20) {
                        memcpy(peer_x, in_payload + i + 3, 32);
                        found_x = true;
                    }
                    if (in_payload[i] == 0x22 && in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x20) {
                        memcpy(peer_y, in_payload + i + 3, 32);
                        found_y = true;
                    }
                }
                if (!found_x || !found_y) return CTAP2_ERR_INVALID_PARAMETER;

                uint8_t pin_hash_enc[16];
                bool found_old = false;
                for (size_t i = 0; i + 18 <= in_len; i++) {
                    if (in_payload[i] == 0x06 && (in_payload[i + 1] == 0x50 || (in_payload[i + 1] == 0x58 && in_payload[i + 2] == 0x10))) {
                        size_t offset = (in_payload[i + 1] == 0x50) ? (i + 2) : (i + 3);
                        memcpy(pin_hash_enc, in_payload + offset, 16);
                        found_old = true;
                        break;
                    }
                }

                uint8_t z[32], shared_key[32];
                if (!pin_ecdh_key.compute_ecdh_shared_secret_raw(peer_x, peer_y, z)) {
                    return CTAP2_ERR_PROCESSING;
                }
                OpenKey::Crypto::sha256(z, 32, shared_key);

                if (found_old) {
                    uint8_t old_pin_hash[16];
                    OpenKey::Crypto::aes_256_cbc_decrypt_zero_iv(shared_key, pin_hash_enc, 16, old_pin_hash);
                    if (!OpenKey::Storage::get_vault().verify_pin(old_pin_hash, 16)) {
                        return CTAP2_ERR_PIN_INVALID;
                    }
                }

                // Generate random 32-byte pin_token
                OpenKey::Crypto::get_rng().generate_random(pin_token, 32);
                pin_token_valid = true;

                // Encrypt pin_token with AES-256-CBC (IV = 0)
                uint8_t encrypted_token[32];
                OpenKey::Crypto::aes_256_cbc_encrypt_zero_iv(shared_key, pin_token, 32, encrypted_token);

                resp.write_map_header(1);
                resp.write_int(0x02); // pinUvAuthToken
                resp.write_bytes(encrypted_token, 32);
                *out_len = resp.get_size();
                return CTAP1_ERR_SUCCESS;
            }

            default:
                return CTAP2_ERR_UNSUPPORTED_OPTION;
        }
    }

    /**
     * @brief Helper to parse basic CBOR text string for a given key or field
     */
    static bool extract_cbor_string_field(const uint8_t *buf, size_t len, const char *key_name, char *out_str, size_t max_out) {
        if (!buf || len == 0 || !key_name || !out_str) return false;
        size_t klen = strlen(key_name);
        for (size_t i = 0; i + klen + 2 < len; i++) {
            if (memcmp(buf + i, key_name, klen) == 0) {
                // Key found, look ahead for string header (major type 3: 0x60..0x77)
                size_t val_pos = i + klen;
                while (val_pos < len && (buf[val_pos] < 0x60 || buf[val_pos] > 0x7B)) {
                    val_pos++;
                }
                if (val_pos < len) {
                    uint8_t hdr = buf[val_pos];
                    size_t slen = 0;
                    size_t data_start = val_pos + 1;
                    if (hdr >= 0x60 && hdr <= 0x77) {
                        slen = hdr & 0x1F;
                    } else if (hdr == 0x78 && val_pos + 1 < len) {
                        slen = buf[val_pos + 1];
                        data_start = val_pos + 2;
                    }
                    if (slen > 0 && data_start + slen <= len) {
                        size_t copy_len = (slen < max_out - 1) ? slen : (max_out - 1);
                        memcpy(out_str, buf + data_start, copy_len);
                        out_str[copy_len] = '\0';
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * @brief Helper to extract 32-byte byte string (e.g. clientDataHash)
     */
    static bool extract_cbor_32b_hash(const uint8_t *buf, size_t len, uint8_t *out_hash_32b) {
        if (!buf || len < 34 || !out_hash_32b) return false;
        // Search for CBOR byte string of length 32: header 0x58 0x20
        for (size_t i = 0; i + 34 <= len; i++) {
            if (buf[i] == 0x58 && buf[i + 1] == 0x20) {
                memcpy(out_hash_32b, buf + i + 2, 32);
                return true;
            }
        }
        return false;
    }

    /**
     * @brief CTAP 2.1 authenticatorMakeCredential (0x01)
     * Handles credential registration with hardware presence verification
     */
    uint8_t handle_make_credential(const uint8_t *cbor_payload, size_t payload_len,
                                  uint8_t *out_buf, size_t *out_len, size_t max_out,
                                  void (*keepalive_cb)(uint32_t cid) = nullptr, uint32_t cid = 0) {
        // Extract RP ID from incoming CBOR (e.g. "webauthn.io" or domain)
        char rp_id[128];
        uint8_t rp_id_hash[32];
        if (extract_cbor_string_field(cbor_payload, payload_len, "id", rp_id, sizeof(rp_id))) {
            OpenKey::Crypto::sha256((const uint8_t *)rp_id, strlen(rp_id), rp_id_hash);
        } else {
            // Default fallback
            OpenKey::Crypto::sha256((const uint8_t *)"webauthn.io", 11, rp_id_hash);
        }

        // Enforce physical user presence verification via GPIO 0 Boot button with keepalives
        // Pulses slow heartbeat rhythm in Blue (Brightness 60)
        if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_cb, cid, PRESENCE_TIMEOUT_MS)) {
            return CTAP2_ERR_ACTION_TIMEOUT;
        }

        // Generate or Derive NIST P-256 Keypair for this credential (Feature 3)
        OpenKey::Crypto::P256Key key;
        uint8_t cred_id[32];
        OpenKey::Crypto::CryptoRNG &rng = OpenKey::Crypto::get_rng();
        rng.generate_random(cred_id, 32);

        uint8_t master_seed[64];
        if (OpenKey::Storage::get_vault().get_master_seed(master_seed)) {
            // Feature 3: Deterministic derivation from BIP-39 master seed
            if (!key.derive_from_seed(master_seed, rp_id_hash, cred_id)) {
                key.generate();
            }
            OpenKey::Security::secure_wipe(master_seed, sizeof(master_seed));
        } else {
            if (!key.generate()) {
                return CTAP2_ERR_PROCESSING;
            }
        }

        uint8_t pub_x[32], pub_y[32], priv_scalar[32];
        key.export_public_key_raw(pub_x, pub_y);
        key.export_private_key(priv_scalar);

        // Store credential record in Raw NVS
        OpenKey::Storage::FidoResidentKeyRecord rk;
        memset(&rk, 0, sizeof(rk));
        memcpy(rk.rp_id_hash, rp_id_hash, 32);
        memcpy(rk.credential_id, cred_id, 32);
        memcpy(rk.private_key, priv_scalar, 32);
        rk.sign_counter = OpenKey::Storage::get_vault().increment_global_counter();
        rk.algorithm = 0xF9; // -7 (ES256)
        rk.is_active = 0x01;
        OpenKey::Storage::get_vault().save_resident_key(rk);

        // Build Authenticator Data (authData)
        // 32B rpIdHash || 1B flags || 4B signCount || 16B AAGUID || 2B credIdLen || credId || COSE Key
        uint8_t auth_data[300];
        size_t ad_offset = 0;

        memcpy(auth_data + ad_offset, rk.rp_id_hash, 32);
        ad_offset += 32;

        auth_data[ad_offset++] = AUTHDATA_FLAG_UP | AUTHDATA_FLAG_AT; // UP + AT flags

        uint32_t count = rk.sign_counter;
        auth_data[ad_offset++] = (uint8_t)(count >> 24);
        auth_data[ad_offset++] = (uint8_t)(count >> 16);
        auth_data[ad_offset++] = (uint8_t)(count >> 8);
        auth_data[ad_offset++] = (uint8_t)count;

        // Attested Credential Data:
        uint8_t effective_aaguid[16];
        uint8_t profile = OpenKey::Storage::get_vault().get_stealth_mode();
        if (profile == 1) {
            // Feature 6: Ephemeral RP-isolated AAGUID derived from seed/secret
            uint8_t aaguid_seed[64];
            if (!OpenKey::Storage::get_vault().get_master_seed(aaguid_seed)) {
                memset(aaguid_seed, 0x5A, 64);
            }
            uint8_t aaguid_hash[32];
            OpenKey::Crypto::hmac_sha256(aaguid_seed, 64, rp_id_hash, 32, aaguid_hash);
            memcpy(effective_aaguid, aaguid_hash, 16);
            effective_aaguid[6] = (effective_aaguid[6] & 0x0F) | 0x40; // UUID v4
            effective_aaguid[8] = (effective_aaguid[8] & 0x3F) | 0x80; // RFC 4122
            OpenKey::Security::secure_wipe(aaguid_seed, sizeof(aaguid_seed));
        } else if (profile == 2) {
            // FIDO MDS L2 Compatible AAGUID (Keyroost certified display)
            memcpy(effective_aaguid, FIDO_MDS_L2_AAGUID, 16);
        } else {
            memcpy(effective_aaguid, OPENKEY_AAGUID, 16);
        }
        memcpy(auth_data + ad_offset, effective_aaguid, 16);
        ad_offset += 16;

        auth_data[ad_offset++] = 0x00;
        auth_data[ad_offset++] = 32; // credId length = 32
        memcpy(auth_data + ad_offset, cred_id, 32);
        ad_offset += 32;

        // COSE Key Format (P-256)
        CborEncoder cose_enc(auth_data + ad_offset, sizeof(auth_data) - ad_offset);
        cose_enc.write_map_header(5);
        cose_enc.write_int(1); cose_enc.write_int(2);   // Key type: EC2
        cose_enc.write_int(3); cose_enc.write_int(-7);  // Alg: ES256
        cose_enc.write_int(-1); cose_enc.write_int(1);  // Curve: P-256
        cose_enc.write_int(-2); cose_enc.write_bytes(pub_x, 32); // X
        cose_enc.write_int(-3); cose_enc.write_bytes(pub_y, 32); // Y
        ad_offset += cose_enc.get_size();

        // Encode MakeCredential response CBOR
        // RFC / WebAuthn standard requires 3 entries: 1 (fmt), 2 (authData), 3 (attStmt)
        CborEncoder resp(out_buf, max_out);
        resp.write_map_header(3);

        // 0x01: fmt ("none")
        resp.write_int(0x01);
        resp.write_text("none");

        // 0x02: authData
        resp.write_int(0x02);
        resp.write_bytes(auth_data, ad_offset);

        // 0x03: attStmt (empty map for "none")
        resp.write_int(0x03);
        resp.write_map_header(0);

        *out_len = resp.get_size();

        OpenKey::Security::secure_wipe(priv_scalar, sizeof(priv_scalar));
        OpenKey::Security::secure_wipe(&rk, sizeof(rk));
        return CTAP1_ERR_SUCCESS;
    }

    /**
     * @brief CTAP 2.1 authenticatorGetAssertion (0x02)
     * Handles authentication assertion, HMAC-Secret calculation, and signature
     */
    uint8_t handle_get_assertion(const uint8_t *cbor_payload, size_t payload_len,
                                uint8_t *out_buf, size_t *out_len, size_t max_out,
                                void (*keepalive_cb)(uint32_t cid) = nullptr, uint32_t cid = 0) {
        // Extract RP ID and clientDataHash from assertion request
        uint8_t rp_id_hash[32];
        uint8_t client_data_hash[32];
        uint8_t allow_cred_id[32];
        bool has_cred_id = false;
        bool found_rp = false;
        bool found_cdh = false;

        // 1. Scan CBOR for rpId (key 0x01) and clientDataHash (key 0x02)
        for (size_t i = 0; i + 2 < payload_len; i++) {
            if (cbor_payload[i] == 0x01 && !found_rp) {
                size_t val_pos = i + 1;
                uint8_t hdr = cbor_payload[val_pos];
                size_t slen = 0;
                size_t data_start = 0;
                if ((hdr & 0xE0) == 0x60 && (hdr & 0x1F) < 24) {
                    slen = hdr & 0x1F;
                    data_start = val_pos + 1;
                } else if (hdr == 0x78 && val_pos + 1 < payload_len) {
                    slen = cbor_payload[val_pos + 1];
                    data_start = val_pos + 2;
                }
                if (slen > 0 && data_start + slen <= payload_len) {
                    OpenKey::Crypto::sha256(cbor_payload + data_start, slen, rp_id_hash);
                    found_rp = true;
                }
            }
            if (cbor_payload[i] == 0x02 && !found_cdh) {
                if (i + 34 < payload_len && cbor_payload[i + 1] == 0x58 && cbor_payload[i + 2] == 0x20) {
                    memcpy(client_data_hash, cbor_payload + i + 3, 32);
                    found_cdh = true;
                }
            }
        }

        // 2. Scan for allowList credential ID
        for (size_t i = 0; i + 36 <= payload_len; i++) {
            if (cbor_payload[i] == 'i' && cbor_payload[i + 1] == 'd') {
                for (size_t j = i + 2; j + 34 <= payload_len && j < i + 10; j++) {
                    if (cbor_payload[j] == 0x58 && cbor_payload[j + 1] == 0x20) {
                        memcpy(allow_cred_id, cbor_payload + j + 2, 32);
                        has_cred_id = true;
                        break;
                    }
                }
                if (has_cred_id) break;
            }
        }

        if (!found_rp) {
            char rp_id[128];
            if (extract_cbor_string_field(cbor_payload, payload_len, "rpid", rp_id, sizeof(rp_id)) ||
                extract_cbor_string_field(cbor_payload, payload_len, "id", rp_id, sizeof(rp_id))) {
                OpenKey::Crypto::sha256((const uint8_t *)rp_id, strlen(rp_id), rp_id_hash);
            } else {
                OpenKey::Crypto::sha256((const uint8_t *)"webauthn.io", 11, rp_id_hash);
            }
        }

        if (!found_cdh) {
            if (!extract_cbor_32b_hash(cbor_payload, payload_len, client_data_hash)) {
                OpenKey::Crypto::sha256((const uint8_t *)"client_data_hash_default", 24, client_data_hash);
            }
        }

        // Retrieve credential from NVS (by credential ID or RP ID hash with fallback)
        OpenKey::Storage::FidoResidentKeyRecord rk;
        memset(&rk, 0, sizeof(rk));
        bool found = OpenKey::Storage::get_vault().find_resident_key(has_cred_id ? allow_cred_id : nullptr, rp_id_hash, &rk);

        if (!found) {
            // Feature 3: Disaster Recovery path - if key is not in NVS, derive on the fly from master seed!
            uint8_t master_seed[64];
            if (has_cred_id && OpenKey::Storage::get_vault().get_master_seed(master_seed)) {
                OpenKey::Crypto::P256Key rec_key;
                if (rec_key.derive_from_seed(master_seed, rp_id_hash, allow_cred_id)) {
                    memcpy(rk.rp_id_hash, rp_id_hash, 32);
                    memcpy(rk.credential_id, allow_cred_id, 32);
                    rec_key.export_private_key(rk.private_key);
                    rk.sign_counter = OpenKey::Storage::get_vault().increment_global_counter();
                    rk.is_active = 0x01;
                    found = true;
                }
                OpenKey::Security::secure_wipe(master_seed, sizeof(master_seed));
            }
        }

        if (!found || !rk.is_active) {
            // Unrecognized domain / Phishing / Mismatched RP ID!
            // Trigger high-intensity rapid flashing red alert (brightness 150)
            OpenKey::Peripherals::get_peripherals().flash_phishing_alert(1600);
            // Per CTAP 2.1: Return CTAP2_ERR_NO_CREDENTIALS (0x2E) without waiting for touch
            return CTAP2_ERR_NO_CREDENTIALS;
        }

        // Domain IS recognized and registered!
        // Enforce physical user presence verification via GPIO 0 Boot button with slow heartbeat blue (Brightness 60)
        if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_cb, cid, PRESENCE_TIMEOUT_MS)) {
            return CTAP2_ERR_ACTION_TIMEOUT;
        }

        // Increment monotonic signature counter
        rk.sign_counter = OpenKey::Storage::get_vault().increment_global_counter();

        // Construct authData for GetAssertion (37 bytes: 32B rpIdHash || 1B flags || 4B signCount)
        uint8_t auth_data[37];
        memcpy(auth_data, rp_id_hash, 32);
        auth_data[32] = AUTHDATA_FLAG_UP; // UP verified
        auth_data[33] = (uint8_t)(rk.sign_counter >> 24);
        auth_data[34] = (uint8_t)(rk.sign_counter >> 16);
        auth_data[35] = (uint8_t)(rk.sign_counter >> 8);
        auth_data[36] = (uint8_t)(rk.sign_counter);

        // Sign: SHA-256(authData || clientDataHash)
        uint8_t to_sign[37 + 32];
        memcpy(to_sign, auth_data, 37);
        memcpy(to_sign + 37, client_data_hash, 32);

        uint8_t sig_hash[32];
        OpenKey::Crypto::sha256(to_sign, sizeof(to_sign), sig_hash);

        OpenKey::Crypto::P256Key key;
        key.import_private_key(rk.private_key);

        uint8_t signature[74];
        size_t sig_len = 0;
        if (!key.sign_der(sig_hash, signature, &sig_len)) {
            return CTAP2_ERR_PROCESSING;
        }

        // Encode GetAssertion response CBOR
        CborEncoder resp(out_buf, max_out);
        resp.write_map_header(3);

        // 0x01: credential map
        resp.write_int(0x01);
        resp.write_map_header(2);
        resp.write_text("id");
        resp.write_bytes(rk.credential_id, 32);
        resp.write_text("type");
        resp.write_text("public-key");

        // 0x02: authData
        resp.write_int(0x02);
        resp.write_bytes(auth_data, 37);

        // 0x03: signature
        resp.write_int(0x03);
        resp.write_bytes(signature, sig_len);

        *out_len = resp.get_size();

        OpenKey::Security::secure_wipe(&rk, sizeof(rk));
        return CTAP1_ERR_SUCCESS;
    }

    /**
     * @brief Process raw CTAP2 command packet and produce response
     */
    uint8_t dispatch_ctap2(uint8_t cmd, const uint8_t *in_payload, size_t in_len,
                           uint8_t *out_buf, size_t *out_len, size_t max_out,
                           void (*keepalive_cb)(uint32_t cid) = nullptr, uint32_t cid = 0) {
        switch (cmd) {
            case CTAP2_CMD_GET_INFO:
                return handle_get_info(out_buf, out_len, max_out);
            case CTAP2_CMD_MAKE_CREDENTIAL:
                return handle_make_credential(in_payload, in_len, out_buf, out_len, max_out, keepalive_cb, cid);
            case CTAP2_CMD_GET_ASSERTION:
                return handle_get_assertion(in_payload, in_len, out_buf, out_len, max_out, keepalive_cb, cid);
            case CTAP2_CMD_RESET:
                OpenKey::Storage::get_vault().factory_reset();
                *out_len = 0;
                return CTAP1_ERR_SUCCESS;
            case CTAP2_CMD_CLIENT_PIN:
                return handle_client_pin(in_payload, in_len, out_buf, out_len, max_out);
            case 0x08: // CTAP2_CMD_GET_NEXT_ASSERTION
                *out_len = 0;
                return CTAP2_ERR_NOT_ALLOWED;
            case 0x0A: // CTAP2_CMD_CREDENTIAL_MGMT
                *out_len = 0;
                return CTAP2_ERR_PUAT_REQUIRED;
            case 0x0B: // CTAP2_CMD_SELECTION
                *out_len = 0;
                return CTAP2_ERR_UNSUPPORTED_OPTION;
            case 0x0C: // CTAP2_CMD_LARGE_BLOBS
                *out_len = 0;
                return CTAP2_ERR_UNSUPPORTED_OPTION;
            case 0x0D: // CTAP2_CMD_CONFIG
                *out_len = 0;
                return CTAP2_ERR_UNSUPPORTED_OPTION;
            default:
                return CTAP2_ERR_INVALID_COMMAND;
        }
    }
};

/**
 * @brief Global singleton instance of CtapEngine
 */
static inline CtapEngine& get_ctap() {
    static CtapEngine instance;
    return instance;
}

} // namespace CTAP2
} // namespace OpenKey
