# OpenKey - Open-Source Hardware Security Key

OpenKey is an independent, 100% open-source FIDO2 / WebAuthn hardware security key implementation written natively in C++ for the Espressif ESP32-S3 silicon, designed to provide the rigorous CTAP 2.1 standard compliance seen in projects like Google OpenSK, but optimized specifically for ESP32 hardware cryptographic accelerators.

## Target Hardware
- **Silicon**: ESP32-S3 (Xtensa LX7 dual-core @ 240MHz, 4MB Flash, USB-OTG Full Speed, Hardware Crypto Accelerator, Die TRNG)
- **Status LED**: Onboard WS2812B on **GPIO 21**
- **User Presence Button**: Onboard BOOT button on **GPIO 0** (Active-low, internal pull-up)

---

## Toolchain & Compiler Setup (Arduino IDE 2.3.10)

1. **Install Arduino IDE 2.3.10**:
   - Download and install Arduino IDE 2.3.10.
2. **Install ESP32 Board Support 3.7.0**:
   - Open **Settings** -> **Additional boards manager URLs**:
     ```
     https://espressif.github.io/arduino-esp32/package_esp32_index.json
     ```
   - Open **Tools** -> **Board** -> **Boards Manager**, search for `esp32` by Espressif Systems and select version **3.7.0**.
3. **Board & Partition Configuration**:
   - **Board**: Select **`"Waveshare ESP32-S3-Zero"`** directly from the **Tools -> Board -> esp32** list.
   - **USB Mode**: `"USB-OTG (TinyUSB)"`
   - **USB CDC On Boot**: `"Enabled"`
   - **Flash Size**: `"4MB (32Mb)"`
   - **Partition Scheme**: The sketch includes a custom `partitions.csv` allocating **2 MB** for dedicated FIDO2 Non-Volatile Storage, unlocking **1,000 resident passkeys**.
   - **Upload Speed**: `921600` (or default)
4. **Compile & Flash**:
   - Open `firmware/firmware.ino` in Arduino IDE 2.3.10.
   - Plug in the Waveshare ESP32-S3-Zero into your USB port.
   - Click **Verify**, then **Upload**.
(more tests to be performed on other modules soon, let me know, if custom board is to be supported)
---

## Security & Cryptographic Hardening Compliance

| Vector / Attack Profile | Vulnerability Class | OpenKey Hardened Countermeasure |
|:---|:---|:---|
| **Timing Side-Channels** | CWE-385 / Timing Leaks | `OpenKey::Security::constant_time_memcmp` evaluates PINs, MACs, RP IDs, and credentials with fixed-time bitwise operations independent of byte equality locations. |
| **Compiler Dead-Code Elimination** | CWE-14 / Memory Retention | `OpenKey::Security::secure_wipe` couples `mbedtls_platform_zeroize` with volatile memory write barriers to prevent memory retention of keys and records after scope exit. |
| **Origin / Credential Confusion** | CWE-346 / Origin Leaks | Strict Relying Party hash matching (`rp_id_hash`) and credential ID matching prevents cross-origin authentication leaks across all 1,000 key slots. |
| **EMFI / Silicon TRNG Faults** | NIST SP 800-90B / Weak Keys | `HardwareEntropyMonitor` continuously runs Repetition Count health tests on die TRNG samples, preventing weak key generation under EMFI/fault injection. |
| **PIN Brute-Force** | CWE-307 / Credential Stuffing | Monotonic retry counter in raw NVS with exponential backoff delays (1s..15s) and permanent factory wipe after 8 consecutive failed attempts. |
| **Flash Dumping / Cold Boot** | Physical Extraction | Direct raw NVS rows under `esp_flash_encryption_enabled()` (AES-XTS hardware eFuse key). Avoids vulnerable flat filesystems. |
| **Headless / Malware Spoofing** | Unauthorized Assertion | Hardware-enforced 15-second physical touch requirement on GPIO 0 with software debouncing; aborts on timeout. |

---

## Protocol Matrix

### 1. FIDO2 / WebAuthn / CTAP 2.1
- **Credential Storage Capacity**: **1,000 Resident Passkeys** (Discoverable Credentials) stored in a dedicated 1.875 MB `fido_nvs` partition with wear-leveling endurance, extending the established credential benchmark.
- **Commands**: `authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorGetInfo`, `authenticatorClientPIN`, `authenticatorReset`, `authenticatorLargeBlobs`.
- **Extensions**:
  - `hmac-secret`: Derives deterministic HMAC-SHA256 secrets for KeePassXC offline database unlocks.
  - `largeBlobs`: Raw on-key data storage.
  - `credProtect`: Enterprise credential access levels.
  - `minPinLength`: Configurable minimum PIN length enforcement.
- **Algorithms**: NIST P-256 (ES256) with low-S canonical DER formatting.
- **Client PIN**: PIN Protocol 1 (ECDH P-256 + AES-256-CBC with SHA-256 and monotonic rate limiting).
- **Physical Touch Policy**: GPIO 0 BOOT button with WS2812B NeoPixel breathing heartbeat blue challenge.
  
