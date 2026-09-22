//! YKOATH Protocol Client
//! Communicates with OpenKey and YubiKey devices over standard YKOATH byte sequences.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::ctap_hid::CtapHidConnection;

const YKOATH_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_RESET: u8 = 0x04;
const INS_CALCULATE: u8 = 0x08;
const INS_LIST: u8 = 0x0A;

const TAG_NAME: u8 = 0x71;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_TRUNCATED: u8 = 0x76;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OathAccount {
    pub name: String,
    pub issuer: String,
    pub account: String,
    pub algorithm: String,
    pub digits: u8,
    pub code: Option<String>,
    pub seconds_remaining: u32,
}

pub struct YkOathClient;

impl YkOathClient {
    /// Select the YKOATH applet on the security key
    pub fn select(conn: &CtapHidConnection) -> Result<(), String> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x07];
        apdu.extend_from_slice(&YKOATH_AID);
        
        let resp = conn.send_apdu(&apdu)?;
        if resp.len() < 2 {
            return Err("Empty response selecting YKOATH applet".into());
        }

        let sw = ((resp[resp.len() - 2] as u16) << 8) | (resp[resp.len() - 1] as u16);
        if sw != 0x9000 {
            return Err(format!("YKOATH selection failed with status 0x{:04X}", sw));
        }

        Ok(())
    }

    /// List and calculate all TOTP accounts saved on the key
    pub fn list_and_calculate(conn: &CtapHidConnection) -> Result<Vec<OathAccount>, String> {
        Self::select(conn)?;

        // Timestamp challenge: 30s counter
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let counter = now_secs / 30;
        let seconds_remaining = 30 - (now_secs % 30) as u32;

        let mut challenge_apdu = vec![0x00, INS_CALCULATE, 0x00, 0x01]; // CALCULATE ALL
        challenge_apdu.push(10); // Lc = 10 (Tag 0x74 + Len 0x08 + 8B timestamp)
        challenge_apdu.push(TAG_CHALLENGE);
        challenge_apdu.push(8);
        for i in (0..8).rev() {
            challenge_apdu.push((counter >> (i * 8)) as u8);
        }

        let resp = conn.send_apdu(&challenge_apdu)?;
        if resp.len() < 2 {
            return Err("Invalid response from calculate".into());
        }

        let sw = ((resp[resp.len() - 2] as u16) << 8) | (resp[resp.len() - 1] as u16);
        if sw != 0x9000 {
            // Fallback to simple LIST if CALCULATE_ALL not supported
            return Self::list_accounts(conn);
        }

        let payload = &resp[..resp.len() - 2];
        let mut accounts = Vec::new();
        let mut idx = 0;

        while idx < payload.len() {
            if payload[idx] != TAG_NAME {
                break;
            }
            idx += 1;
            if idx >= payload.len() { break; }
            let name_len = payload[idx] as usize;
            idx += 1;
            if idx + name_len > payload.len() { break; }

            let full_name = String::from_utf8_lossy(&payload[idx..idx + name_len]).to_string();
            idx += name_len;

            let mut code_str = None;
            let mut digits = 6;

            // Next tag: 0x76 (Truncated Code) or 0x7c (Touch Required)
            if idx < payload.len() && payload[idx] == TAG_TRUNCATED {
                idx += 1;
                if idx < payload.len() {
                    let t_len = payload[idx] as usize;
                    idx += 1;
                    if idx + t_len <= payload.len() && t_len >= 5 {
                        digits = payload[idx];
                        let code_val = ((payload[idx + 1] as u32) << 24)
                            | ((payload[idx + 2] as u32) << 16)
                            | ((payload[idx + 3] as u32) << 8)
                            | (payload[idx + 4] as u32);
                        code_str = Some(format!("{:0width$}", code_val, width = digits as usize));
                        idx += t_len;
                    }
                }
            }

            let parts: Vec<&str> = full_name.splitn(2, ':').collect();
            let (issuer, account) = if parts.len() == 2 {
                (parts[0].trim().to_string(), parts[1].trim().to_string())
            } else {
                ("General".to_string(), full_name.clone())
            };

            accounts.push(OathAccount {
                name: full_name,
                issuer,
                account,
                algorithm: "SHA-1".to_string(),
                digits,
                code: code_str,
                seconds_remaining,
            });
        }

        Ok(accounts)
    }

    /// List account names without calculation
    pub fn list_accounts(conn: &CtapHidConnection) -> Result<Vec<OathAccount>, String> {
        let apdu = vec![0x00, INS_LIST, 0x00, 0x00, 0x00];
        let resp = conn.send_apdu(&apdu)?;
        if resp.len() < 2 {
            return Err("Empty response".into());
        }

        let payload = &resp[..resp.len() - 2];
        let mut accounts = Vec::new();
        let mut idx = 0;

        while idx < payload.len() {
            let tag = payload[idx];
            idx += 1;
            if idx >= payload.len() { break; }
            let len = payload[idx] as usize;
            idx += 1;
            if idx + len > payload.len() { break; }

            if tag == 0x72 || tag == TAG_NAME {
                let name = String::from_utf8_lossy(&payload[idx..idx + len]).to_string();
                let parts: Vec<&str> = name.splitn(2, ':').collect();
                let (issuer, account) = if parts.len() == 2 {
                    (parts[0].trim().to_string(), parts[1].trim().to_string())
                } else {
                    ("General".to_string(), name.clone())
                };

                accounts.push(OathAccount {
                    name,
                    issuer,
                    account,
                    algorithm: "SHA-1".to_string(),
                    digits: 6,
                    code: None,
                    seconds_remaining: 30,
                });
            }
            idx += len;
        }

        Ok(accounts)
    }

    /// Add a new TOTP account to the security key
    pub fn add_account(
        conn: &CtapHidConnection,
        name: &str,
        secret: &[u8],
        digits: u8,
        require_touch: bool,
    ) -> Result<(), String> {
        Self::select(conn)?;

        let mut apdu = vec![0x00, INS_PUT, 0x00, 0x00];
        let name_bytes = name.as_bytes();
        
        let mut data = Vec::new();
        // Tag 0x71: Name
        data.push(TAG_NAME);
        data.push(name_bytes.len() as u8);
        data.extend_from_slice(name_bytes);

        // Tag 0x73: Key (Alg 0x01 SHA1, Digits 6/8, Type 0x02 TOTP)
        data.push(TAG_KEY);
        data.push((secret.len() + 3) as u8);
        data.push(0x01); // SHA-1
        data.push(digits);
        data.push(0x02); // TOTP
        data.extend_from_slice(secret);

        // Tag 0x78: Property (Touch)
        if require_touch {
            data.push(0x78);
            data.push(0x01);
            data.push(0x02); // Require touch
        }

        apdu.push(data.len() as u8);
        apdu.extend_from_slice(&data);

        let resp = conn.send_apdu(&apdu)?;
        if resp.len() < 2 {
            return Err("Empty response adding account".into());
        }

        let sw = ((resp[resp.len() - 2] as u16) << 8) | (resp[resp.len() - 1] as u16);
        if sw != 0x9000 {
            return Err(format!("Failed to add account, status: 0x{:04X}", sw));
        }

        Ok(())
    }

    /// Delete an account by name
    pub fn delete_account(conn: &CtapHidConnection, name: &str) -> Result<(), String> {
        Self::select(conn)?;

        let mut apdu = vec![0x00, INS_DELETE, 0x00, 0x00];
        let name_bytes = name.as_bytes();

        let mut data = Vec::new();
        data.push(TAG_NAME);
        data.push(name_bytes.len() as u8);
        data.extend_from_slice(name_bytes);

        apdu.push(data.len() as u8);
        apdu.extend_from_slice(&data);

        let resp = conn.send_apdu(&apdu)?;
        if resp.len() < 2 {
            return Err("Empty response deleting account".into());
        }

        let sw = ((resp[resp.len() - 2] as u16) << 8) | (resp[resp.len() - 1] as u16);
        if sw != 0x9000 {
            return Err(format!("Failed to delete account, status: 0x{:04X}", sw));
        }

        Ok(())
    }
}
