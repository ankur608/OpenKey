/**
 * @file descriptors.h
 * @brief OpenKey USB Descriptors (FIDO2/U2F HID & CCID Smartcard Interface)
 * @version 1.0.0
 * 
 * Hardware Target: Waveshare ESP32-S3-Zero
 * VID: 0x303A (Espressif) | PID: 0x1002 (OpenKey Security Key)
 */

#pragma once

#include <stdint.h>

#define OPENKEY_USB_VID             0x303A
#define OPENKEY_USB_PID             0x1002
#define OPENKEY_USB_BCD_DEVICE      0x0100

#define OPENKEY_MANUFACTURER_STR    "OpenKey Security"
#define OPENKEY_PRODUCT_STR         "OpenKey"
#define OPENKEY_INTERFACE_HID_STR   "OpenKey"
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
