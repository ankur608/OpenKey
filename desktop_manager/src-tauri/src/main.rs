// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ctap_hid;
mod ykoath_client;
mod openpgp_client;
mod bip39_util;

use ctap_hid::{CtapHidConnection, DeviceSummary};
use ykoath_client::{OathAccount, YkOathClient};
use openpgp_client::{OpenPgpCardStatus, OpenPgpClient};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub manufacturer: String,
    pub product: String,
    pub aaguid: String,
    pub firmware_version: String,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub rk_supported: bool,
    pub pin_set: bool,
    pub min_pin_length: u8,
    pub flash_encryption_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenKeyStatus {
    pub initialized: bool,
    pub pin_set: bool,
    pub pin_retries: u8,
    pub seed_configured: bool,
    pub stealth_aaguid_mode: bool,
    pub aaguid_profile: u8,
    pub resident_key_count: u16,
    pub flash_encryption_active: bool,
    pub seed_fingerprint: String,
}

#[tauri::command]
fn scan_devices() -> Result<Vec<DeviceSummary>, String> {
    CtapHidConnection::enumerate_devices()
}

#[tauri::command]
fn wink_device(device_path: String) -> Result<String, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    conn.wink()?;
    Ok("Wink command dispatched to NeoPixel".into())
}

#[tauri::command]
fn get_device_info(device_path: String) -> Result<DeviceInfo, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    let _raw_cbor = conn.send_cbor(0x04, &[]).unwrap_or_default();

    Ok(DeviceInfo {
        manufacturer: "OpenKey Security Foundation".to_string(),
        product: "OpenKey ESP32-S3 Security Key".to_string(),
        aaguid: "4f70656e-4b65-7953-3330-000000000001".to_string(),
        firmware_version: "v1.0.0 (mbedTLS 3.x / ESP32 Core 3.0.7)".to_string(),
        versions: vec!["U2F_V2".into(), "FIDO_2_0".into(), "FIDO_2_1".into()],
        extensions: vec![
            "hmac-secret".into(),
            "largeBlobs".into(),
            "credProtect".into(),
            "minPinLength".into(),
        ],
        rk_supported: true,
        pin_set: false,
        min_pin_length: 4,
        flash_encryption_active: true,
    })
}

#[tauri::command]
fn get_openkey_status(device_path: String) -> Result<OpenKeyStatus, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    let resp = conn.send_vendor_cmd(0x01, &[])?;
    if resp.len() < 13 || resp[0] != 0x00 {
        return Err("Invalid status response from OpenKey".into());
    }

    let rk_count = ((resp[6] as u16) << 8) | (resp[7] as u16);
    let fp = hex::encode(&resp[9..13]);
    let profile = resp[5];

    Ok(OpenKeyStatus {
        initialized: resp[1] == 0xA5,
        pin_set: resp[2] != 0,
        pin_retries: resp[3],
        seed_configured: resp[4] != 0,
        stealth_aaguid_mode: profile == 1,
        aaguid_profile: profile,
        resident_key_count: rk_count,
        flash_encryption_active: resp[8] != 0,
        seed_fingerprint: fp,
    })
}

#[tauri::command]
fn set_aaguid_profile(device_path: String, pin: String, profile: u8) -> Result<u8, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    let mut payload = Vec::new();
    if !pin.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(pin.as_bytes());
        let hash = hasher.finalize();
        payload.extend_from_slice(&hash[0..16]);
    }
    payload.push(profile);

    let resp = conn.send_vendor_cmd(0x03, &payload)?;
    if resp.is_empty() || resp[0] != 0x00 {
        return Err("Failed to update AAGUID profile on hardware (verify PIN)".into());
    }
    Ok(profile)
}

#[tauri::command]
fn set_stealth_mode(device_path: String, pin: String, enabled: bool) -> Result<bool, String> {
    let profile = if enabled { 1 } else { 0 };
    set_aaguid_profile(device_path, pin, profile).map(|p| p == 1)
}

#[tauri::command]
fn generate_bip39_words() -> Result<Vec<String>, String> {
    bip39_util::generate_mnemonic_24()
}

#[tauri::command]
fn validate_bip39_words(words: Vec<String>) -> Result<bool, String> {
    bip39_util::validate_mnemonic_24(&words).map(|_| true)
}

#[tauri::command]
fn provision_bip39_seed(
    device_path: String,
    pin: String,
    words: Vec<String>,
    passphrase: Option<String>,
) -> Result<String, String> {
    bip39_util::validate_mnemonic_24(&words)?;

    let pass = passphrase.unwrap_or_default();
    let seed = bip39_util::mnemonic_to_seed(&words, &pass);

    let conn = CtapHidConnection::open(&device_path)?;
    let mut payload = Vec::new();
    if !pin.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(pin.as_bytes());
        let hash = hasher.finalize();
        payload.extend_from_slice(&hash[0..16]);
    }
    payload.extend_from_slice(&seed);

    let resp = conn.send_vendor_cmd(0x02, &payload)?;
    if resp.is_empty() || resp[0] != 0x00 {
        return Err("OpenKey rejected seed provisioning (verify PIN and tap physical button)".into());
    }

    let fp = if resp.len() >= 5 {
        hex::encode(&resp[1..5])
    } else {
        "OK".into()
    };

    Ok(format!("BIP-39 Master Seed successfully provisioned! Fingerprint: {}", fp))
}

#[tauri::command]
fn verify_seed_match(
    device_path: String,
    words: Vec<String>,
    passphrase: Option<String>,
) -> Result<bool, String> {
    bip39_util::validate_mnemonic_24(&words)?;
    let pass = passphrase.unwrap_or_default();
    let seed = bip39_util::mnemonic_to_seed(&words, &pass);

    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let hash = hasher.finalize();
    let candidate_fp = hex::encode(&hash[0..4]);

    let conn = CtapHidConnection::open(&device_path)?;
    let resp = conn.send_vendor_cmd(0x01, &[])?;
    if resp.len() < 13 || resp[0] != 0x00 {
        return Err("Failed to query OpenKey status".into());
    }
    let dev_fp = hex::encode(&resp[9..13]);

    Ok(candidate_fp.eq_ignore_ascii_case(&dev_fp))
}

#[tauri::command]
fn generate_bip39_vault_words() -> Result<Vec<String>, String> {
    bip39_util::generate_mnemonic_24()
}

#[tauri::command]
fn list_oath(device_path: String) -> Result<Vec<OathAccount>, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    YkOathClient::list_and_calculate(&conn)
}

#[tauri::command]
fn add_oath_account(
    device_path: String,
    name: String,
    secret_base32: String,
    digits: u8,
    require_touch: bool,
) -> Result<String, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    let clean_secret: String = secret_base32.chars().filter(|c| !c.is_whitespace()).collect();
    let secret_bytes = match decode_base32(&clean_secret) {
        Some(b) => b,
        None => return Err("Invalid Base32 secret string".into()),
    };
    YkOathClient::add_account(&conn, &name, &secret_bytes, digits, require_touch)?;
    Ok(format!("Account '{}' saved successfully", name))
}

#[tauri::command]
fn delete_oath_account(device_path: String, name: String) -> Result<String, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    YkOathClient::delete_account(&conn, &name)?;
    Ok(format!("Account '{}' deleted", name))
}

#[tauri::command]
fn get_openpgp_details(device_path: String) -> Result<OpenPgpCardStatus, String> {
    let conn = CtapHidConnection::open(&device_path)?;
    OpenPgpClient::get_status(&conn)
}

fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut bit_count = 0;
    let mut output = Vec::new();

    for c in input.to_ascii_uppercase().chars() {
        if c == '=' { break; }
        let val = base32_chars.find(c)? as u32;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(output)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_devices,
            wink_device,
            get_device_info,
            get_openkey_status,
            set_stealth_mode,
            set_aaguid_profile,
            generate_bip39_words,
            validate_bip39_words,
            provision_bip39_seed,
            verify_seed_match,
            generate_bip39_vault_words,
            list_oath,
            add_oath_account,
            delete_oath_account,
            get_openpgp_details
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenKey Tauri Desktop Manager");
}
