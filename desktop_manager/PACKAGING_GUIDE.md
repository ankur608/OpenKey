# OpenKey Companion App: Multi-OS Packaging & Export Guide

This guide explains how to compile and export the **OpenKey Desktop Companion** as native standalone executables and installer packages for **Windows**, **macOS**, and **Linux**.

---

## 1. Supported Executable Formats by OS

| Target OS | Architecture | Primary Packages | Output Directory |
| :--- | :--- | :--- | :--- |
| **Windows** | x86_64 (64-bit) | `.exe` (Portable), `.msi` (Windows Installer) | `src-tauri/target/release/bundle/msi/`<br>`src-tauri/target/release/openkey-desktop-manager.exe` |
| **macOS** | Apple Silicon (`aarch64`) & Intel (`x86_64`) | `.dmg` (Disk Image), `.app` (Application Bundle) | `src-tauri/target/release/bundle/dmg/`<br>`src-tauri/target/release/bundle/macos/` |
| **Linux** | x86_64 / aarch64 | `.AppImage` (Universal Portable), `.deb` (Debian/Ubuntu) | `src-tauri/target/release/bundle/appimage/`<br>`src-tauri/target/release/bundle/deb/` |

---

## 2. Automated Multi-OS Build via GitHub Actions (Recommended)

Because building native macOS (`.dmg`) and Linux (`.AppImage`) requires host platform toolchains, the most reliable and automated way to generate all binaries simultaneously is via the included **GitHub Actions CI/CD pipeline**.

### How to Trigger:
A turnkey workflow is pre-configured at:
[`.github/workflows/release-companion.yml`](file:///d:/Project%20SOKBSEMI/OpenKey/.github/workflows/release-companion.yml)

1. Push your repository to GitHub.
2. Create and push a version tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. GitHub Actions automatically spins up clean virtual runners on:
   - `windows-latest`
   - `macos-latest`
   - `ubuntu-22.04`
4. The workflow builds all artifacts, codesigns (if secrets are set), and creates a **GitHub Release** containing the downloadable `.msi`, `.exe`, `.dmg`, `.AppImage`, and `.deb` files.

---

## 3. Local OS Compilation Steps

### A. Windows (Building `.exe` & `.msi`)

#### Prerequisites:
1. **Node.js**: v18+ or v20+ (already installed on this machine).
2. **Rust & Cargo**:
   - Install via PowerShell:
     ```powershell
     winget install Rustlang.Rustup
     ```
   - Or download and run `rustup-init.exe` from [https://rustup.rs](https://rustup.rs) (choose default MSVC).
3. **C++ Build Tools**:
   - Install [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the *"Desktop development with C++"* workload selected.
4. **WebView2 Runtime**:
   - Pre-installed on Windows 10 & 11 by default.

#### Compilation:
Simply run the included batch script:
```cmd
build_release_windows.bat
```
Or execute manually:
```bash
cd desktop_manager
npm install
npm run build
```
The compiled standalone executable and installer will be located in:
- `src-tauri/target/release/openkey-desktop-manager.exe`
- `src-tauri/target/release/bundle/msi/OpenKey Manager_1.0.0_x64_en-US.msi`

---

### B. macOS (Building `.dmg` & `.app`)

#### Prerequisites:
1. **Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```
2. **Rust & Cargo**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
3. **Node.js**:
   ```bash
   brew install node
   ```

#### Universal Binary Build (Intel + Apple Silicon):
```bash
# Add both target architectures
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cd desktop_manager
npm install
# Build for Apple Silicon (M1/M2/M3/M4)
npm run build -- --target aarch64-apple-darwin

# Build for Intel
npm run build -- --target x86_64-apple-darwin
```
Outputs:
- `src-tauri/target/aarch64-apple-darwin/release/bundle/dmg/OpenKey Manager_1.0.0_aarch64.dmg`
- `src-tauri/target/x86_64-apple-darwin/release/bundle/dmg/OpenKey Manager_1.0.0_x64.dmg`

---

### C. Linux (Building `.AppImage` & `.deb`)

#### Prerequisites (Ubuntu / Debian / Linux Mint):
```bash
sudo apt-get update
sudo apt-get install -y \
  libwebkit2gtk-4.0-dev \
  build-essential \
  curl \
  wget \
  file \
  libssl-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libudev-dev \
  libhidapi-dev
```

#### Compilation:
```bash
cd desktop_manager
npm install
npm run build
```
Outputs:
- `src-tauri/target/release/bundle/appimage/openkey-desktop-manager_1.0.0_amd64.AppImage`
- `src-tauri/target/release/bundle/deb/openkey-desktop-manager_1.0.0_amd64.deb`

#### USB HID Permissions (udev rules on Linux):
To allow non-root users to talk to the OpenKey hardware key over raw WebAuthn/FIDO2 HID, provide `/etc/udev/rules.d/70-openkey.rules`:
```udev
# OpenKey ESP32-S3 Hardware Security Token
KERNEL=="hidraw*", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", MODE="0666", TAG+="uaccess"
KERNEL=="hidraw*", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666", TAG+="uaccess"
```
Reload rules with: `sudo udevadm control --reload-rules && sudo udevadm trigger`.

---

## 4. Code Signing & Distribution Checklist

1. **Windows Authenticode**:
   - Set environment variables `TAURI_PRIVATE_KEY` and `TAURI_KEY_PASSWORD` in GitHub Secrets or use `signtool.exe` with your Sectigo/DigiCert Code Signing Certificate to eliminate Windows SmartScreen warnings.
2. **macOS Notarization**:
   - Set `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, and `APPLE_PASSWORD` in your build environment. Tauri will automatically notarize the `.dmg` via Apple `notarytool` so Gatekeeper approves the app without warnings.
