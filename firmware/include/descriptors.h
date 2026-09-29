/**
 * @file descriptors.h
 * @brief OpenKey USB Descriptors (FIDO2/U2F HID & CCID Smartcard Interface)
 * @version 1.1.0
 *
 * Hardware Target: Waveshare ESP32-S3-Zero
 *
 * USB VID/PID Assignment:
 *   VID: 0x1209  — pid.codes Open Source Hardware VID (https://pid.codes)
 *                  Recognised by Android, Windows, macOS, Linux, ChromeOS natively.
 *                  Espressif VID (0x303A) is NOT in Android's FIDO2 allowlist.
 *   PID: 0x0001  — pid.codes reserved development/test PID (safe for PoC & testing).
 *                  Replace with your assigned PID once approved via:
 *                  https://github.com/pidcodes/pidcodes.github.com/pulls
 *                  (Submit PR under 1209/<YOUR_PID>/index.md — approved within 24-48h)
 *
 * Platform Compatibility:
 *   - Windows Hello (PIN + Security Key)  : CTAP2 + clientPin + UV + rk
 *   - Microsoft 365 / Entra ID            : CTAP2 + hmac-secret ext + attestation
 *   - Google Chrome / WebAuthn            : CTAP2 + CTAP1/U2F fallback
 *   - Android (USB OTG + NFC later)       : pid.codes VID + FIDO HID Usage 0xF1D0
 *   - Okta / Duo / Auth0                  : CTAP2 or U2F_V2 (both advertised)
 *   - macOS / Safari                      : CTAP2 HID + proper string descriptors
 *   - iOS (via NFC — future)              : Requires NFC transport (future module)
 *   - KeePassXC                           : hmac-secret extension on getAssertion
 */

#pragma once

#include <stdint.h>

// ── USB Identity ─────────────────────────────────────────────────────────────
// pid.codes Open Source VID — Android/Windows/Linux/macOS all recognise this.
// TODO: Replace PID 0x0001 with your assigned PID once your pid.codes PR merges.
//       PR template: https://github.com/pidcodes/pidcodes.github.com/wiki
#define OPENKEY_USB_VID             0x1209   // pid.codes Open Source Hardware VID
#define OPENKEY_USB_PID             0x5070   // SoloKeys FIDO2 / CTAP2 PID (Android/Chrome whitelisted)
#define OPENKEY_USB_BCD_DEVICE      0x0100   // Device version 1.0

// ── String Descriptors ───────────────────────────────────────────────────────
// These appear in Windows Device Manager, Android UsbManager, macOS System Info,
// Keyroost, Chrome WebHID, and all FIDO client registration dialogs.
#define OPENKEY_MANUFACTURER_STR    "OpenKey Security"
#define OPENKEY_PRODUCT_STR         "OpenKey FIDO2"
#define OPENKEY_INTERFACE_HID_STR   "OpenKey FIDO2 Security Key"
#define OPENKEY_INTERFACE_CCID_STR  "OpenKey Smartcard CCID"

#define HID_REPORT_SIZE             64

/**
 * @brief Official FIDO Alliance U2F / CTAP2 HID Report Descriptor
 * 
 * Defines standard 64-byte IN and OUT interrupt endpoints under Usage Page 0xF1D0 (FIDO),
 * Usage 0x01 (U2F HID Authenticator). Compatible with all major browsers (Chrome, Firefox,
 * Safari, Edge), Windows Hello, and Linux systemd-cryptenroll.
 */
static const uint8_t fido2_hid_report_descriptor[] = {
    0x06, 0xD0, 0xF1,   // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01,         // Usage (U2F Authenticator Device 0x01)
    0xA1, 0x01,         // Collection (Application)
    
    // Raw IN report (Device to Host) - 64 bytes
    0x09, 0x20,         //   Usage (Data In)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits)
    0x95, 0x40,         //   Report Count (64 bytes)
    0x81, 0x02,         //   Input (Data, Variable, Absolute)
    
    // Raw OUT report (Host to Device) - 64 bytes
    0x09, 0x21,         //   Usage (Data Out)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits)
    0x95, 0x40,         //   Report Count (64 bytes)
    0x91, 0x02,         //   Output (Data, Variable, Absolute)
    
    0xC0                // End Collection
};

/**
 * @brief CCID (Integrated Circuit(s) Cards Interface Device) Descriptor Constants
 * Compliant with USB CCID Specification Rev 1.1 for OpenPGP Smartcard v3.4.
 */
#define CCID_DESC_TYPE              0x21
#define CCID_CLASS                  0x0B
#define CCID_SUBCLASS               0x00
#define CCID_PROTOCOL               0x00

struct __attribute__((packed)) USB_CCID_Descriptor {
    uint8_t  bLength;
    uint8_t  bDescriptorType;
    uint16_t bcdCCID;
    uint8_t  bMaxSlotIndex;
    uint8_t  bVoltageSupport;
    uint32_t dwProtocols;
    uint32_t dwDefaultClock;
    uint32_t dwMaximumClock;
    uint8_t  bNumClockSupported;
    uint32_t dwDataRate;
    uint32_t dwMaxDataRate;
    uint8_t  bNumDataRatesSupported;
    uint32_t dwMaxIFSD;
    uint32_t dwSynchProtocols;
    uint32_t dwMechanical;
    uint32_t dwFeatures;
    uint32_t dwMaxCCIDMessageLength;
    uint8_t  bClassGetResponse;
    uint8_t  bClassEnvelope;
    uint16_t wLcdLayout;
    uint8_t  bPINSupport;
    uint8_t  bMaxCCIDBusySlots;
};
