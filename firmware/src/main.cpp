/**
 * @file main.cpp
 * @brief OpenKey Core Runtime & CTAPHID 64-Byte Packet Dispatcher
 * @version 1.0.0
 * 
 * Hardware Target: Waveshare ESP32-S3-Zero (Xtensa LX7, 4MB Flash)
 * Environment: Arduino IDE 2.3.10 / ESP32 Board Support 3.7.0
 * 
 * Compliant with:
 * - FIDO Alliance CTAP 2.1 Specification (CTAPHID framing & CBOR dispatch)
 * - Yubico YKOATH Protocol (Yubico Authenticator App support)
 * - OpenPGP Smartcard v3.4 CCID interface
 * - VAPT Security Standards (Strict bounds checking, constant-time ops, zeroization)
 */

#include <Arduino.h>
#include "USB.h"
#include "USBHID.h"
#include "esp32-hal-tinyusb.h"

#include "../include/descriptors.h"
#include "../include/vapt_security.h"
#include "../include/crypto.h"
#include "../include/storage.h"
#include "../include/peripherals.h"
#include "../include/ctap.h"

// CTAPHID Command Codes
#define CTAPHID_PING                0x01
#define CTAPHID_MSG                 0x03
#define CTAPHID_LOCK                0x04
#define CTAPHID_INIT                0x06
#define CTAPHID_WINK                0x08
#define CTAPHID_CBOR                0x10
#define CTAPHID_CANCEL              0x11
#define CTAPHID_KEEPALIVE           0x3B
#define CTAPHID_ERROR               0x3F
#define CTAPHID_VENDOR_OPENKEY      0x41

#define CTAPHID_BROADCAST_CID       0xFFFFFFFF
#define CTAPHID_INIT_FRAME_FLAG     0x80

// Keepalive Status Flags
#define CTAPHID_STATUS_PROCESSING   1
#define CTAPHID_STATUS_UPNEEDED     2

/**
 * @brief CTAPHID Transaction Reassembly Channel
 */
struct CtapChannel {
    uint32_t cid;
    uint8_t cmd;
    uint16_t total_len;
    uint16_t received_len;
    uint8_t seq;
    uint32_t last_activity;
    uint8_t buffer[1280]; // Max CTAP message buffer with VAPT safe bounds
    bool is_serial;       // Indicates packet received over USB CDC Serial
    bool active;
};

#define MAX_CONCURRENT_CHANNELS 8
static CtapChannel channels[MAX_CONCURRENT_CHANNELS];
static uint32_t next_dynamic_cid = 0x00010001;

// Forward declaration of packet processor
void process_incoming_hid_packet(const uint8_t *packet_64b, bool from_serial = false);

static QueueHandle_t hid_rx_queue = NULL;

// Forward declaration of keepalive sender for CTAP
static void send_ctaphid_keepalive(uint32_t cid, uint8_t status);
static void keepalive_sender(uint32_t cid);

// Custom USB HID Device for FIDO2 / CTAP
class FidoUsbDevice : public USBHIDDevice {
private:
    USBHID hid;

public:
    FidoUsbDevice() : hid() {
        static bool initialized = false;
        if (!initialized) {
            initialized = true;
            hid.addDevice(this, sizeof(fido2_hid_report_descriptor));
        }
    }

    uint16_t _onGetDescriptor(uint8_t *dst) override {
        memcpy(dst, fido2_hid_report_descriptor, sizeof(fido2_hid_report_descriptor));
        return sizeof(fido2_hid_report_descriptor);
    }

    void _onOutput(uint8_t report_id, const uint8_t *data, uint16_t len) override {
        // Non-blocking push to FreeRTOS queue to avoid deadlocking TinyUSB task
        if (!data || !hid_rx_queue) return;
        uint8_t packet[HID_REPORT_SIZE] = {0};
        if (len >= 64) {
            memcpy(packet, data, 64);
            xQueueSend(hid_rx_queue, packet, 0);
        } else if (len == 63) {
            packet[0] = report_id;
            memcpy(packet + 1, data, 63);
            xQueueSend(hid_rx_queue, packet, 0);
        }
    }

    bool send_report(const uint8_t *data, size_t len = HID_REPORT_SIZE) {
        return hid.SendReport(0, data, len);
    }

    void begin() {
        if (!hid_rx_queue) {
            hid_rx_queue = xQueueCreate(16, HID_REPORT_SIZE);
        }
        hid.begin();
    }
};

static FidoUsbDevice fido_device;

/**
 * @brief USB Device Descriptor Callback Override
 * Overrides TinyUSB's weak tud_descriptor_device_cb so that GET DEVICE DESCRIPTOR
 * always returns SoloKeys / pid.codes VID 0x1209 & PID 0x5070 on the USB bus.
 * This guarantees Android and Chrome identify OpenKey as a native FIDO2 security key,
 * while allowing USB CDC on Boot: Enabled to run composite CDC + HID reliably.
 */
extern "C" uint8_t const *tud_descriptor_device_cb(void) {
    static const tusb_desc_device_t openkey_device_descriptor = {
        .bLength            = sizeof(tusb_desc_device_t),
        .bDescriptorType    = TUSB_DESC_DEVICE,
        .bcdUSB             = 0x0200,
        .bDeviceClass       = TUSB_CLASS_MISC,
        .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
        .bDeviceProtocol    = MISC_PROTOCOL_IAD,
        .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
        .idVendor           = OPENKEY_USB_VID,
        .idProduct          = OPENKEY_USB_PID,
        .bcdDevice          = OPENKEY_USB_BCD_DEVICE,
        .iManufacturer      = 0x01,
        .iProduct           = 0x02,
        .iSerialNumber      = 0x03,
        .bNumConfigurations = 0x01
    };
    return (uint8_t const *)&openkey_device_descriptor;
}

#include "esp_mac.h"
#include "mbedtls/sha256.h"
#include "soc/rtc_cntl_reg.h"

static char g_silicon_serial[16] = "OK-F2-00000001";
static bool g_silicon_serial_initialized = false;

static const char* get_silicon_serial() {
    if (!g_silicon_serial_initialized) {
        g_silicon_serial_initialized = true;
        uint8_t mac[6] = {0};
        if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
            uint8_t hash[32];
            mbedtls_sha256(mac, 6, hash, 0);
            snprintf(g_silicon_serial, sizeof(g_silicon_serial), "OK-F2-%02X%02X%02X%02X",
                     hash[0], hash[1], hash[2], hash[3]);
        }
    }
    return g_silicon_serial;
}

/**
 * @brief USB String Descriptor Callback Override
 * Overrides TinyUSB's weak tud_descriptor_string_cb so that all string requests
 * (including Interface String Descriptor which defaults to "TinyUSB HID") return "OpenKey".
 * This ensures Keyroost, Windows Device Manager, Chrome WebHID, and macOS report "OpenKey".
 */
extern "C" uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    static uint16_t _desc_str[127];
    uint8_t chr_count = 0;

    if (index == 0) {
        // Supported Language: English (0x0409)
        _desc_str[1] = 0x0409;
        chr_count = 1;
    } else {
        const char *str = OPENKEY_PRODUCT_STR; // "OpenKey FIDO2"
        if (index == 1) {
            str = OPENKEY_MANUFACTURER_STR;     // "OpenKey Security"
        } else if (index == 2) {
            str = OPENKEY_PRODUCT_STR;          // "OpenKey FIDO2"
        } else if (index == 3) {
            str = get_silicon_serial();         // Method 2: Dynamic Silicon eFuse Unique Serial
        } else {
            // Interface string (index 4+: FIDO HID interface name shown in device managers)
            str = OPENKEY_INTERFACE_HID_STR;    // "OpenKey FIDO2 Security Key"
        }

        chr_count = strlen(str);
        if (chr_count > 126) chr_count = 126;
        for (uint8_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = (uint16_t)str[i];
        }
    }

    // First byte is length (in bytes), second byte is string descriptor type (3 = TUSB_DESC_STRING)
    _desc_str[0] = (uint16_t)((3 << 8) | (2 * chr_count + 2));
    return _desc_str;
}

/**
 * @brief Find or allocate a channel state tracker with LRU eviction
 */
static CtapChannel* get_channel(uint32_t cid, bool allocate = false) {
    // 1. Search for existing active channel
    for (int i = 0; i < MAX_CONCURRENT_CHANNELS; i++) {
        if (channels[i].active && channels[i].cid == cid) {
            channels[i].last_activity = millis();
            return &channels[i];
        }
    }

    if (!allocate) return nullptr;

    uint32_t now = millis();
    int evict_idx = -1;

    // 2. Prefer an inactive slot
    for (int i = 0; i < MAX_CONCURRENT_CHANNELS; i++) {
        if (!channels[i].active) {
            evict_idx = i;
            break;
        }
    }

    // 3. If no inactive slot, look for idle channel (> 2000ms idle per CTAPHID spec)
    if (evict_idx < 0) {
        for (int i = 0; i < MAX_CONCURRENT_CHANNELS; i++) {
            if (now - channels[i].last_activity > 2000) {
                evict_idx = i;
                break;
            }
        }
    }

    // 4. If all slots active within 2000ms, evict the LRU (least recently used) slot
    // that is NOT in the middle of reassembling a multi-packet transaction
    if (evict_idx < 0) {
        uint32_t oldest_time = 0xFFFFFFFF;
        for (int i = 0; i < MAX_CONCURRENT_CHANNELS; i++) {
            if (channels[i].received_len == 0 || channels[i].received_len >= channels[i].total_len) {
                if (channels[i].last_activity < oldest_time) {
                    oldest_time = channels[i].last_activity;
                    evict_idx = i;
                }
            }
        }
    }

    // 5. Absolute fallback: pick oldest channel unconditionally
    if (evict_idx < 0) {
        uint32_t oldest_time = 0xFFFFFFFF;
        for (int i = 0; i < MAX_CONCURRENT_CHANNELS; i++) {
            if (channels[i].last_activity < oldest_time) {
                oldest_time = channels[i].last_activity;
                evict_idx = i;
            }
        }
    }

    if (evict_idx >= 0) {
        OpenKey::Security::secure_wipe(channels[evict_idx].buffer, sizeof(channels[evict_idx].buffer));
        channels[evict_idx].cid = cid;
        channels[evict_idx].active = true;
        channels[evict_idx].last_activity = now;
        channels[evict_idx].received_len = 0;
        channels[evict_idx].total_len = 0;
        channels[evict_idx].seq = 0;
        channels[evict_idx].is_serial = false;
        return &channels[evict_idx];
    }

    return nullptr;
}

/**
 * @brief Send 64-byte raw packet over USB HID IN endpoint or USB CDC Serial
 */
static void send_raw_packet_for_cid(uint32_t cid, const uint8_t *packet_64b) {
    CtapChannel *chan = get_channel(cid, false);
    if (chan && chan->is_serial) {
        Serial.write(packet_64b, HID_REPORT_SIZE);
        Serial.flush();
    } else {
        fido_device.send_report(packet_64b, HID_REPORT_SIZE);
    }
}

/**
 * @brief Transmit multi-packet CTAPHID response payload back to host
 * Splits arbitrary-length responses into 64-byte INIT and CONT frames
 */
static void send_ctaphid_response(uint32_t cid, uint8_t cmd, const uint8_t *payload, uint16_t len) {
    uint8_t packet[HID_REPORT_SIZE];
    memset(packet, 0, sizeof(packet));

    // INIT frame header: 4B CID || 1B (cmd | 0x80) || 2B BCNT (big-endian)
    packet[0] = (uint8_t)(cid >> 24);
    packet[1] = (uint8_t)(cid >> 16);
    packet[2] = (uint8_t)(cid >> 8);
    packet[3] = (uint8_t)cid;
    packet[4] = cmd | CTAPHID_INIT_FRAME_FLAG;
    packet[5] = (uint8_t)(len >> 8);
    packet[6] = (uint8_t)len;

    uint16_t sent = 0;
    uint16_t chunk = (len > 57) ? 57 : len;
    if (payload && chunk > 0) {
        memcpy(packet + 7, payload, chunk);
        sent += chunk;
    }
    send_raw_packet_for_cid(cid, packet);

    // CONT frames: 4B CID || 1B SEQ (0x00..0x7F) || 59B data
    uint8_t seq = 0;
    while (sent < len) {
        memset(packet, 0, sizeof(packet));
        packet[0] = (uint8_t)(cid >> 24);
        packet[1] = (uint8_t)(cid >> 16);
        packet[2] = (uint8_t)(cid >> 8);
        packet[3] = (uint8_t)cid;
        packet[4] = seq++ & 0x7F;

        chunk = ((len - sent) > 59) ? 59 : (len - sent);
        memcpy(packet + 5, payload + sent, chunk);
        sent += chunk;

        send_raw_packet_for_cid(cid, packet);
        OpenKey::Security::secure_wipe(packet, sizeof(packet));
    }
    OpenKey::Security::secure_wipe(packet, sizeof(packet));
}

/**
 * @brief Send CTAPHID error packet
 */
static void send_ctaphid_error(uint32_t cid, uint8_t err_code) {
    uint8_t payload[1] = { err_code };
    send_ctaphid_response(cid, CTAPHID_ERROR, payload, 1);
}

/**
 * @brief Send CTAPHID KEEPALIVE packet during physical touch loop
 */
static void send_ctaphid_keepalive(uint32_t cid, uint8_t status) {
    uint8_t payload[1] = { status };
    send_ctaphid_response(cid, CTAPHID_KEEPALIVE, payload, 1);
}

static void keepalive_sender(uint32_t cid) {
    CtapChannel *chan = get_channel(cid, false);
    if (chan) {
        chan->last_activity = millis();
    }
    send_ctaphid_keepalive(cid, CTAPHID_STATUS_UPNEEDED);
}

/**
 * @brief Process fully reassembled CTAPHID message payload
 */
static void process_assembled_message(CtapChannel *chan) {
    uint8_t resp_buf[1280];
    size_t resp_len = 0;

    switch (chan->cmd) {
        case CTAPHID_INIT: {
            // CTAPHID_INIT nonce echo (8 bytes) + assigned CID (4B) + Protocol version (1B) + Device versions (3B) + Capabilities (1B)
            if (chan->total_len < 8) {
                send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                return;
            }

            uint32_t assigned_cid = next_dynamic_cid++;
            if (next_dynamic_cid == 0xFFFFFFFF) next_dynamic_cid = 0x00010001;

            uint8_t init_resp[17];
            memcpy(init_resp, chan->buffer, 8); // Echo 8B nonce
            init_resp[8]  = (uint8_t)(assigned_cid >> 24);
            init_resp[9]  = (uint8_t)(assigned_cid >> 16);
            init_resp[10] = (uint8_t)(assigned_cid >> 8);
            init_resp[11] = (uint8_t)assigned_cid;
            init_resp[12] = 0x02; // CTAPHID protocol version 2
            init_resp[13] = 0x01; // Major version
            init_resp[14] = 0x00; // Minor version
            init_resp[15] = 0x00; // Build version
            init_resp[16] = 0x05; // Capabilities: CAPFLAG_CBOR (0x04) | CAPFLAG_WINK (0x01)

            // Register newly allocated CID
            CtapChannel *new_chan = get_channel(assigned_cid, true);
            if (new_chan) {
                new_chan->last_activity = millis();
                new_chan->is_serial = chan->is_serial;
            }

            send_ctaphid_response(chan->cid, CTAPHID_INIT, init_resp, sizeof(init_resp));
            if (chan->cid == 0xFFFFFFFF) {
                chan->active = false;
                chan->received_len = 0;
                chan->total_len = 0;
                OpenKey::Security::secure_wipe(chan->buffer, sizeof(chan->buffer));
            }
            break;
        }

        case CTAPHID_PING: {
            // Echo back raw payload
            send_ctaphid_response(chan->cid, CTAPHID_PING, chan->buffer, chan->total_len);
            break;
        }

        case CTAPHID_WINK: {
            // Flash NeoPixel with green pulse
            OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::SUCCESS_GREEN);
            delay(200);
            OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);
            send_ctaphid_response(chan->cid, CTAPHID_WINK, nullptr, 0);
            break;
        }

        case CTAPHID_CBOR: {
            // Dispatch to CTAP 2.1 Engine
            if (chan->total_len < 1) {
                send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                return;
            }

            uint8_t ctap2_cmd = chan->buffer[0];
            const uint8_t *cbor_payload = chan->buffer + 1;
            size_t cbor_len = chan->total_len - 1;

            resp_buf[0] = CTAP1_ERR_SUCCESS; // Status byte placeholder
            size_t payload_out_len = 0;

            uint8_t status = OpenKey::CTAP2::get_ctap().dispatch_ctap2(
                ctap2_cmd, cbor_payload, cbor_len,
                resp_buf + 1, &payload_out_len, sizeof(resp_buf) - 1,
                keepalive_sender, chan->cid
            );

            resp_buf[0] = status;
            resp_len = (status == CTAP1_ERR_SUCCESS) ? (payload_out_len + 1) : 1;

            send_ctaphid_response(chan->cid, CTAPHID_CBOR, resp_buf, resp_len);
            break;
        }

        case CTAPHID_MSG: {
            // Standard FIDO U2F Raw Message Interface
            if (chan->total_len < 4) {
                send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                return;
            }

            uint8_t cla = chan->buffer[0];
            uint8_t ins = chan->buffer[1];
            uint8_t p1  = chan->buffer[2];
            uint8_t p2  = chan->buffer[3];

            if (ins == 0x00) { // U2F_VERSION query
                memcpy(resp_buf, "U2F_V2", 6);
                resp_buf[6] = 0x90;
                resp_buf[7] = 0x00;
                send_ctaphid_response(chan->cid, CTAPHID_MSG, resp_buf, 8);
                return;
            }

            // Return ISO 7816-4 SW 0x6D00 (Instruction Not Supported) for non-U2F APDUs
            resp_buf[0] = 0x6D;
            resp_buf[1] = 0x00;
            send_ctaphid_response(chan->cid, CTAPHID_MSG, resp_buf, 2);
            break;
        }

        case CTAPHID_VENDOR_OPENKEY:
        case 0x40: {
            // OpenKey Vendor Command Interface (Feature 3 Seed Provisioning & Feature 6 Stealth Mode)
            if (chan->total_len < 1) {
                send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                return;
            }
            uint8_t subcmd = chan->buffer[0];
            const uint8_t *payload = chan->buffer + 1;
            size_t payload_len = chan->total_len - 1;

            switch (subcmd) {
                case 0x01: { // VENDOR_CMD_GET_STATUS
                    resp_buf[0] = 0x00; // Success
                    resp_buf[1] = 0xA5; // Initialized
                    resp_buf[2] = OpenKey::Storage::get_vault().is_pin_set() ? 0x01 : 0x00;
                    resp_buf[3] = OpenKey::Storage::get_vault().get_pin_retries();
                    resp_buf[4] = OpenKey::Storage::get_vault().is_seed_configured() ? 0x01 : 0x00;
                    resp_buf[5] = OpenKey::Storage::get_vault().get_stealth_mode();
                    uint16_t rk_count = OpenKey::Storage::get_vault().get_active_resident_key_count();
                    resp_buf[6] = (uint8_t)(rk_count >> 8);
                    resp_buf[7] = (uint8_t)(rk_count & 0xFF);
                    resp_buf[8] = OpenKey::Storage::get_vault().is_flash_encryption_enabled() ? 0x01 : 0x00;
                    OpenKey::Storage::get_vault().get_seed_fingerprint(resp_buf + 9);
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 13);
                    return;
                }

                case 0x02: { // VENDOR_CMD_SET_SEED (Feature 3)
                    // Enforce physical user presence touch on BOOT button (heartbeat blue LED)
                    if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_sender, chan->cid, 15000)) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_ACTION_TIMEOUT);
                        return;
                    }

                    // If PIN is configured, verify PIN hash if provided; otherwise physical UP touch was already verified above
                    const uint8_t *seed_ptr = payload;
                    if (OpenKey::Storage::get_vault().is_pin_set()) {
                        if (payload_len >= 16 + 64) {
                            if (!OpenKey::Storage::get_vault().verify_pin(payload, 16)) {
                                send_ctaphid_error(chan->cid, CTAP2_ERR_PIN_INVALID);
                                return;
                            }
                            seed_ptr = payload + 16;
                        } else if (payload_len >= 64) {
                            // PIN omitted: physical presence touch already confirmed on BOOT button
                            seed_ptr = payload;
                        } else {
                            send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                            return;
                        }
                    } else if (payload_len >= 64) {
                        seed_ptr = payload;
                    } else {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                        return;
                    }

                    OpenKey::Storage::get_vault().set_master_seed(seed_ptr);

                    // Triple green pulse confirmation
                    for (int i = 0; i < 3; i++) {
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::SUCCESS_GREEN);
                        delay(80);
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);
                        delay(80);
                    }

                    resp_buf[0] = 0x00; // Success
                    OpenKey::Storage::get_vault().get_seed_fingerprint(resp_buf + 1);
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 5);
                    return;
                }

                case 0x03: { // VENDOR_CMD_SET_STEALTH_MODE (Feature 6 & AAGUID Profile)
                    if (payload_len < 1) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                        return;
                    }
                    // Profile/mode is always the final byte of the payload
                    uint8_t mode = payload[payload_len - 1];
                    bool authorized = false;

                    if (OpenKey::Storage::get_vault().is_pin_set()) {
                        // If PIN hash was provided (16 bytes) and retries > 0, attempt verification
                        if (payload_len >= 17) {
                            if (OpenKey::Storage::get_vault().verify_pin(payload, 16)) {
                                authorized = true;
                            }
                        }

                        // If PIN verification failed or was not provided, allow Physical User Presence (UP button touch)
                        if (!authorized) {
                            if (OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_sender, chan->cid, 15000)) {
                                authorized = true;
                            } else {
                                send_ctaphid_error(chan->cid, (payload_len >= 17 && OpenKey::Storage::get_vault().get_pin_retries() == 0) ? CTAP2_ERR_PIN_BLOCKED : CTAP2_ERR_ACTION_TIMEOUT);
                                return;
                            }
                        }
                    } else {
                        // No PIN configured: directly authorized
                        authorized = true;
                    }

                    if (!authorized) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_NOT_ALLOWED);
                        return;
                    }

                    OpenKey::Storage::get_vault().set_stealth_mode(mode);

                    // Quick blink animation to show new AAGUID setting has been synced with device
                    for (int i = 0; i < 4; i++) {
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::SUCCESS_GREEN);
                        delay(60);
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::OFF);
                        delay(60);
                    }
                    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);

                    resp_buf[0] = 0x00;
                    resp_buf[1] = OpenKey::Storage::get_vault().get_stealth_mode();
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 2);
                    return;
                }

                case 0x04: { // VENDOR_CMD_SET_PIN
                    // Enforce physical user presence touch on BOOT button
                    if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_sender, chan->cid, 15000)) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_ACTION_TIMEOUT);
                        return;
                    }
                    if (payload_len < 32) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                        return;
                    }
                    OpenKey::Storage::get_vault().set_pin(payload, 4);

                    for (int i = 0; i < 3; i++) {
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::SUCCESS_GREEN);
                        delay(70);
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::OFF);
                        delay(70);
                    }
                    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);

                    resp_buf[0] = 0x00;
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 1);
                    return;
                }

                case 0x05: { // VENDOR_CMD_FACTORY_RESET
                    // Enforce physical user presence touch on BOOT button
                    if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_sender, chan->cid, 15000)) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_ACTION_TIMEOUT);
                        return;
                    }
                    OpenKey::Storage::get_vault().factory_reset();

                    for (int i = 0; i < 4; i++) {
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::COUNTDOWN_WHITE);
                        delay(80);
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::OFF);
                        delay(80);
                    }
                    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);

                    resp_buf[0] = 0x00;
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 1);
                    return;
                }

                case 0x06: { // VENDOR_CMD_SET_DURESS_PIN (Feature 1 Anti-Coercion)
                    // Enforce physical user presence touch on BOOT button
                    if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_sender, chan->cid, 15000)) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_ACTION_TIMEOUT);
                        return;
                    }
                    if (payload_len < 32) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_LENGTH);
                        return;
                    }
                    OpenKey::Storage::get_vault().set_duress_pin(payload);

                    // Warning Red Flash to confirm Panic PIN armed
                    for (int i = 0; i < 3; i++) {
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::PHISHING_ALERT_RED);
                        delay(70);
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::OFF);
                        delay(70);
                    }
                    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);

                    resp_buf[0] = 0x00;
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 1);
                    return;
                }

                case 0x07: { // VENDOR_CMD_RESET_PIN (Unblocks locked PIN & clears PIN)
                    // Enforce physical user presence touch on BOOT button
                    if (!OpenKey::Peripherals::get_peripherals().verify_user_presence(keepalive_sender, chan->cid, 15000)) {
                        send_ctaphid_error(chan->cid, CTAP2_ERR_ACTION_TIMEOUT);
                        return;
                    }
                    OpenKey::Storage::get_vault().reset_pin();

                    for (int i = 0; i < 3; i++) {
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::SUCCESS_GREEN);
                        delay(70);
                        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::OFF);
                        delay(70);
                    }
                    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);

                    resp_buf[0] = 0x00;
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 1);
                    return;
                }

                case 0x08: { // VENDOR_CMD_LIST_RESIDENT_KEYS (Live Hardware NVS Enumeration)
                    // Response format:
                    // resp_buf[0] = 0x00 (Success)
                    // resp_buf[1] = count of returned records
                    // Each record (70 bytes):
                    //   1B: slot_index
                    //   32B: rp_id_hash
                    //   32B: credential_id
                    //   4B: sign_counter (big endian)
                    //   1B: algorithm (-7 / 0xF9 = ES256)
                    uint8_t count = 0;
                    size_t offset = 2;
                    for (int i = 0; i < MAX_RESIDENT_KEYS && count < 16; i++) {
                        OpenKey::Storage::FidoResidentKeyRecord rk;
                        if (OpenKey::Storage::get_vault().get_resident_key_at(i, &rk)) {
                            resp_buf[offset++] = (uint8_t)i;
                            memcpy(resp_buf + offset, rk.rp_id_hash, 32);
                            offset += 32;
                            memcpy(resp_buf + offset, rk.credential_id, 32);
                            offset += 32;
                            resp_buf[offset++] = (uint8_t)(rk.sign_counter >> 24);
                            resp_buf[offset++] = (uint8_t)(rk.sign_counter >> 16);
                            resp_buf[offset++] = (uint8_t)(rk.sign_counter >> 8);
                            resp_buf[offset++] = (uint8_t)(rk.sign_counter);
                            resp_buf[offset++] = rk.algorithm;
                            count++;
                            OpenKey::Security::secure_wipe(&rk, sizeof(rk));
                        }
                    }
                    resp_buf[0] = 0x00;
                    resp_buf[1] = count;
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, (uint16_t)offset);
                    return;
                }

                case 0x0A: { // VENDOR_CMD_REBOOT_BOOTLOADER (KeeForge One-Click Flasher Mode)
                    resp_buf[0] = 0x00;
                    send_ctaphid_response(chan->cid, chan->cmd, resp_buf, 1);
                    delay(50);
                    #if defined(RTC_CNTL_FORCE_DOWNLOAD_BOOT)
                    REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
                    #endif
                    esp_restart();
                    return;
                }

                default:
                    send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_PARAMETER);
                    return;
            }
            break;
        }

        default:
            send_ctaphid_error(chan->cid, CTAP2_ERR_INVALID_COMMAND);
            break;
    }

    OpenKey::Security::secure_wipe(resp_buf, sizeof(resp_buf));
}

/**
 * @brief Dispatcher for raw 64-byte CTAPHID packets from USB OUT endpoint or USB CDC Serial
 */
void process_incoming_hid_packet(const uint8_t *packet_64b, bool from_serial) {
    if (!packet_64b) return;

    // Extract 4-byte Channel ID (CID)
    uint32_t cid = ((uint32_t)packet_64b[0] << 24) |
                   ((uint32_t)packet_64b[1] << 16) |
                   ((uint32_t)packet_64b[2] << 8)  |
                   ((uint32_t)packet_64b[3]);

    if (cid == 0x00000000) {
        // CID 0 is invalid
        return;
    }

    uint8_t cmd_or_seq = packet_64b[4];

    if (cmd_or_seq & CTAPHID_INIT_FRAME_FLAG) {
        // --- INIT FRAME ---
        uint8_t cmd = cmd_or_seq & ~CTAPHID_INIT_FRAME_FLAG;
        uint16_t bcnt = ((uint16_t)packet_64b[5] << 8) | packet_64b[6];

        if (bcnt > sizeof(channels[0].buffer)) {
            send_ctaphid_error(cid, CTAP2_ERR_LIMIT_EXCEEDED);
            return;
        }

        CtapChannel *chan = get_channel(cid, true);
        if (!chan) {
            send_ctaphid_error(cid, CTAP2_ERR_CHANNEL_BUSY);
            return;
        }

        chan->is_serial = from_serial;
        chan->cmd = cmd;
        chan->total_len = bcnt;
        chan->received_len = 0;
        chan->seq = 0;
        chan->last_activity = millis();

        uint16_t chunk = (bcnt > 57) ? 57 : bcnt;
        memcpy(chan->buffer, packet_64b + 7, chunk);
        chan->received_len = chunk;

        if (chan->received_len >= chan->total_len) {
            process_assembled_message(chan);
            chan->received_len = 0;
            chan->total_len = 0;
            chan->seq = 0;
            OpenKey::Security::secure_wipe(chan->buffer, sizeof(chan->buffer));
        }
    } else {
        // --- CONTINUATION (CONT) FRAME ---
        uint8_t seq = cmd_or_seq;
        CtapChannel *chan = get_channel(cid, false);
        if (!chan || chan->received_len == 0) {
            send_ctaphid_error(cid, CTAP2_ERR_INVALID_SEQ);
            return;
        }

        if (seq != chan->seq) {
            send_ctaphid_error(cid, CTAP2_ERR_INVALID_SEQ);
            chan->received_len = 0;
            return;
        }

        chan->is_serial = from_serial;
        chan->seq++;
        chan->last_activity = millis();

        uint16_t remaining = chan->total_len - chan->received_len;
        uint16_t chunk = (remaining > 59) ? 59 : remaining;
        memcpy(chan->buffer + chan->received_len, packet_64b + 5, chunk);
        chan->received_len += chunk;

        if (chan->received_len >= chan->total_len) {
            process_assembled_message(chan);
            chan->received_len = 0;
            chan->total_len = 0;
            chan->seq = 0;
            OpenKey::Security::secure_wipe(chan->buffer, sizeof(chan->buffer));
        }
    }
}

/**
 * @brief System Initialization
 */
void setup() {
    // 0. MUST BE FIRST: Configure USB Device Descriptors before starting USB or Serial
    USB.VID(OPENKEY_USB_VID);
    USB.PID(OPENKEY_USB_PID);
    USB.productName(OPENKEY_PRODUCT_STR);
    USB.manufacturerName(OPENKEY_MANUFACTURER_STR);
    USB.serialNumber("OK-F2-00000001");
    USB.usbPower(100);

    fido_device.begin();
    USB.begin();

    Serial.begin(115200);
    Serial.setTimeout(10);
    delay(100);

    // 1. Air-Gapped Master Factory Wipe Check (Feature 8):
    // If BOOT button (GPIO 0) is held continuously for 4.0s upon power-up:
    // LED cycles Yellow (0..1.5s) -> Red (1.5..3.0s) -> Rapid White (3.0..4.0s)
    // then performs a master hardware wipe of all 1,000 keys and halts.
    OpenKey::Peripherals::get_peripherals().check_power_on_wipe([]() {
        OpenKey::Storage::get_vault().init();
        OpenKey::Storage::get_vault().factory_reset();
    });

    // 2. Initialize Peripherals (NeoPixel & Boot Button)
    OpenKey::Peripherals::get_peripherals().init();
    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);

    // 3. Hardware Fault & Brownout Zeroization Hook (Feature 4):
    esp_register_shutdown_handler([]() {
        for (int i = 0; i < MAX_CONCURRENT_CHANNELS; i++) {
            OpenKey::Security::secure_wipe(channels[i].buffer, sizeof(channels[i].buffer));
            channels[i].active = false;
        }
    });

    // 4. Initialize VAPT Security & Silicon TRNG
    OpenKey::Security::HardwareSecurityAudit audit = OpenKey::Security::HardwareSecurityAudit::inspect();
    if (!audit.trng_healthy) {
        // Silicon RNG failure: lock out key into red alert state
        OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::ERROR_RED);
        while (1) { delay(1000); }
    }

    // 5. Initialize Raw NVS Storage Vault
    OpenKey::Storage::get_vault().init();

    // 6. Initialize Cryptographic DRBG
    OpenKey::Crypto::get_rng().init();

    // Key is armed, authenticated, and in Solid Green Standby
    OpenKey::Peripherals::get_peripherals().set_state(OpenKey::Peripherals::LedState::STANDBY_GREEN);
}

/**
 * @brief Main High-Frequency Processing Loop
 */
void loop() {
    // 1. Service peripheral animation states (blinking during prompt)
    OpenKey::Peripherals::get_peripherals().update();

    // 2. Process incoming 64-byte USB HID report frames from FreeRTOS queue with auto-wipe
    uint8_t packet[HID_REPORT_SIZE];
    if (hid_rx_queue && xQueueReceive(hid_rx_queue, packet, 0) == pdTRUE) {
        process_incoming_hid_packet(packet, false);
        OpenKey::Security::secure_wipe(packet, sizeof(packet));
    }

    // 3. Process incoming 64-byte CTAPHID frames from Serial CDC (Desktop Companion)
    if (Serial.available() >= HID_REPORT_SIZE) {
        size_t n = Serial.readBytes(packet, HID_REPORT_SIZE);
        if (n == HID_REPORT_SIZE) {
            process_incoming_hid_packet(packet, true);
        }
        OpenKey::Security::secure_wipe(packet, sizeof(packet));
    }

    delay(1);
}
