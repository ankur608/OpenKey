# ⚡ KeeForge — Zero-Install Hardware Onboarding & Web Flasher

**KeeForge** is a standalone, client-side browser utility for flashing, provisioning, and onboarding off-the-shelf ESP32-S3 boards (such as the Waveshare ESP32-S3-Zero) into hardened **OpenKey FIDO2 / WebAuthn Hardware Security Keys**.

---

## 🚀 Key Capabilities

- **Zero-Install Web Serial Flasher**: Runs 100% inside your browser via the Web Serial API (Chrome, Edge, Brave, Opera). No Arduino IDE, Python, `esptool.py`, or driver installations needed.
- **Intel HEX & Raw Binary Support**: Built-in parser for `.hex` (Intel HEX record types `00`, `02`, `04`) and raw `.bin` firmware files exported from Arduino IDE or PlatformIO.
- **Method 2 Silicon eFuse Fingerprint**: Reads the immutable 48-bit factory MAC address from silicon hardware eFuses, derives a collision-free SHA-256 unique serial number (`OK-F2-XXXXXXXX`), and displays it prior to flashing.
- **One-Click Reboot to Bootloader (Cmd 0x0A)**: Dispatches CTAPHID Vendor Command `0x0A` to trigger an active OpenKey into ROM download mode without pressing physical hardware buttons.
- **Supply-Chain Integrity**: Real-time SHA-256 hash digest calculation and Ed25519 signature validation.
- **Sensory Audio-Haptic Feedback**: Web Audio API synthesizer generates harmonic sine chords on completion.

---

## 🛠️ Usage Guide

### 1. Launching KeeForge
Open `index.html` in this folder via any local HTTP server or via GitHub Pages:
```bash
# Serve locally
python -m http.server 8000 --directory keeforge
```
Or open via the OpenKey Web Companion navigation links.

### 2. First-Time Setup on a Fresh ESP32-S3 Board
1. Hold down the physical **BOOT** button on your Waveshare ESP32-S3 board while inserting the USB-C cable into your computer.
2. Click **Connect ESP32-S3 (Bootloader)** and select your USB Serial device from the browser prompt.
3. The board identity card will instantly populate:
   - Chip Architecture (e.g. `ESP32-S3`)
   - Factory eFuse MAC Address
   - Unique Silicon Serial (e.g. `OK-F2-7E64D054`)
4. Under **Step 2**, select **Load OpenKey v1.0.5 Payload** (or drag & drop your custom compiled `.hex` / `.bin`).
5. Click **⚡ Flash OpenKey Now**.
6. When flashing completes, a harmonic chime plays, the ESP32-S3 reboots automatically, and your OpenKey is ready to use!

---

## 🔒 Security Architecture

1. **Decentralized & Client-Side**: No firmware files or telemetry are transmitted to any cloud servers. Flashing occurs directly between your browser process and the USB COM port.
2. **Immutable Silicon Identity**: The device serial number is derived from hardware eFuse blocks permanently burnt at the TSMC/Espressif wafer fab.
3. **Protected Storage**: Flashing respects the OpenKey partition map (`0x00010000` app offset), leaving resident credentials and BIP-39 vaults in their dedicated NVS sectors (`fido_rk`).
