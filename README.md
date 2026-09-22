# OpenKey - FIDO2 / WebAuthn Hardware Security Key
<img width="1867" height="442" alt="image" src="https://github.com/user-attachments/assets/60ff640d-fe35-4ebf-a18d-a02e482c1a07" />

Open-source FIDO2 / WebAuthn hardware authenticator and companion application. It delivers enterprise-grade passwordless authentication, hardware-enforced encryption, anti-tracking pseudonymity, and cryptographic duress countermeasures.

Present version supports the **ESP32-S3** platform, more to be added soon..

<img width="1897" height="857" alt="image" src="https://github.com/user-attachments/assets/efdd2fc2-e56d-4b5f-bd74-6def515ec3df" />

---

## Architecture Overview

### 1. Hardware Security Engine (`firmware/`)
- **Micro-controller**: Espressif ESP32-S3 (Xtensa Dual-Core LX7 @ 240MHz).
- **Cryptographic Protocols**: FIDO2 (CTAP 2.0 / 2.1), U2F (CTAP 1), WebAuthn Level 3.
- **Algorithms**: ES256 (ECDSA P-256 with SHA-256), Ed25519 (COSE -8), RS256.
- **Hardware Security Enforcements**:
  - `eFuse`-enforced AES-256-XTS flash encryption.
  - Die True Random Number Generator (TRNG - NIST SP 800-90B compliant).
  - Capacitive Touch User Presence (`UP`) verification on GPIO 1.
  - Hardware NeoPixel status & identification signaling on GPIO 21.
  - **Resident Passkey Capacity**: 1,000 discoverable credentials stored in wear-leveled flash (1.875 MB allocated).
  - **Anti-Coercion Duress PIN**: Instant hardware zeroization (~15 ms) upon coercion emergency.
  - **Stealth / FIDO MDS Attestation Profiles**: Dynamic AAGUID profile switching.

### 2. Desktop Companion App (`desktop_manager/`)
<img width="1915" height="865" alt="image" src="https://github.com/user-attachments/assets/8f364d1b-4b8e-48dc-ba7e-d0ef7e1e4ff1" />

- **Framework**: Tauri v1.5 + Rust backend.
- **Cross-Platform**: Native standalone binaries for **Windows** (`.exe`, `.msi`), **macOS** (`.dmg`, `.app`), and **Linux** (`.AppImage`, `.deb`).
- **Features**:
  - Real-time hardware telemetry and resident key inventory gauge.
  - Device identification toggle (WS2812B).
  - Device PIN and Duress PIN management.
  - BIP-39 deterministic seed backup & restore.
  - FIDO MDS (Metadata Service) attestation and specification inspection.

---

## 📦 Releases & Downloads

Precompiled native packages and standalone binaries are available for **Windows**, **macOS**, and **Linux** under [GitHub Releases](https://github.com/ankur608/OpenKey/releases).

| Operating System | Package Type | Architecture | Direct Download |
| :--- | :--- | :--- | :--- |
| **Windows** | Native Installer (`.msi`) | x64 | [⬇️ **Download `OpenKey.Manager.msi`**](https://github.com/ankur608/OpenKey/releases/download/v1.0.2/OpenKey.Manager_1.0.0_x64_en-US.msi) |
| **macOS** | Disk Image (`.dmg`) | Apple Silicon | [⬇️ **Download `OpenKey.Manager.dmg`**](https://github.com/ankur608/OpenKey/releases/download/v1.0.2/OpenKey.Manager_1.0.0_aarch64.dmg) |
| **Linux** | Universal Binary (`.AppImage`) | x64 / amd64 | [⬇️ **Download `open-key-manager.AppImage`**](https://github.com/ankur608/OpenKey/releases/download/v1.0.2/open-key-manager_1.0.0_amd64.AppImage) |
| **Linux** | Debian / Ubuntu (`.deb`) | x64 / amd64 | [⬇️ **Download `open-key-manager.deb`**](https://github.com/ankur608/OpenKey/releases/download/v1.0.2/open-key-manager_1.0.0_amd64.deb) |

> [!TIP]
> You can also download raw standalone packages (including standalone `.exe` and `.app` bundles) directly from the [GitHub Actions Artifacts](https://github.com/ankur608/OpenKey/actions/runs/35674972353).

### Quick Install Guide

#### Windows
Download and run the `.msi` installer. OpenKey Manager will be added to your Start Menu and Desktop.

#### macOS
Open the `.dmg` file and drag `OpenKey Manager` into `/Applications`.  
*(On first launch, if prompted by macOS Gatekeeper, right-click the app in Finder and choose **Open**, or allow via **System Settings -> Privacy & Security**).*

#### Linux
- **AppImage**: Make executable and run:
  ```bash
  chmod +x open-key-manager_1.0.0_amd64.AppImage
  ./open-key-manager_1.0.0_amd64.AppImage
  ```
- **Debian / Ubuntu**: Install with dpkg:
  ```bash
  sudo dpkg -i open-key-manager_1.0.0_amd64.deb
  ```

---

## 🛠️ Multi-OS Builds & CI/CD

Automated multi-platform builds are handled via GitHub Actions matrix workflow ([`.github/workflows/release-companion.yml`](.github/workflows/release-companion.yml)). Pushing any version tag automatically compiles and publishes assets across all three platforms:

```bash
git tag v1.0.3
git push origin v1.0.3
```

### Local Compilation (Windows)
To build the desktop manager locally on Windows:
```cmd
desktop_manager\build_release_windows.bat
```

For macOS and Linux developer build instructions, see [PACKAGING_GUIDE.md](desktop_manager/PACKAGING_GUIDE.md).

---

## License

Open source under the Apache License 2.0.
