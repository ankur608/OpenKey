//! BIP-39 Cryptographic Mnemonic & Seed Engine
//! Full RFC-compliant 24-word mnemonic generation, validation, and PBKDF2-HMAC-SHA512 seed derivation.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;

const BIP39_WORDLIST_RAW: &str = include_str!("bip39_words.txt");

pub fn get_word_list() -> Vec<&'static str> {
    BIP39_WORDLIST_RAW.lines().map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
}

/// Generate 24 standard BIP-39 words from 256 bits of cryptographically secure OS entropy
pub fn generate_mnemonic_24() -> Result<Vec<String>, String> {
    let wordlist = get_word_list();
    if wordlist.len() != 2048 {
        return Err("BIP-39 wordlist must contain exactly 2048 words".into());
    }

    // 256 bits of entropy (32 bytes) via native OS CSPRNG
    let mut entropy = [0u8; 32];
    #[cfg(target_os = "windows")]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(h_algorithm: *mut std::ffi::c_void, pb_buffer: *mut u8, cb_buffer: u32, dw_flags: u32) -> i32;
        }
        unsafe {
            let res = BCryptGenRandom(std::ptr::null_mut(), entropy.as_mut_ptr(), 32, 2 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */);
            if res != 0 {
                return Err("Failed to generate secure entropy via Windows BCrypt RNG".into());
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::fs::File;
        use std::io::Read;
        let mut f = File::open("/dev/urandom").map_err(|e| e.to_string())?;
        f.read_exact(&mut entropy).map_err(|e| e.to_string())?;
    }

    // Checksum: first 8 bits of SHA-256(entropy)
    let mut hasher = Sha256::new();
    hasher.update(&entropy);
    let hash = hasher.finalize();
    let checksum = hash[0]; // 8 bits

    // Assemble 264 bits: 256 bits of entropy + 8 bits of checksum
    let mut bits = Vec::with_capacity(264);
    for byte in &entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in (0..8).rev() {
        bits.push((checksum >> i) & 1);
    }

    // Split into 24 groups of 11 bits (24 * 11 = 264)
    let mut words = Vec::with_capacity(24);
    for chunk in bits.chunks(11) {
        let mut idx = 0usize;
        for &b in chunk {
            idx = (idx << 1) | (b as usize);
        }
        words.push(wordlist[idx].to_string());
    }

    Ok(words)
}

/// Validate 24-word BIP-39 mnemonic phrase and verify SHA-256 checksum
pub fn validate_mnemonic_24(words: &[String]) -> Result<(), String> {
    if words.len() != 24 {
        return Err(format!("Expected 24 words, but got {}", words.len()));
    }

    let wordlist = get_word_list();
    let mut indices = Vec::with_capacity(24);

    for (i, word) in words.iter().enumerate() {
        let clean = word.trim().to_lowercase();
        match wordlist.iter().position(|&w| w == clean) {
            Some(idx) => indices.push(idx),
            None => return Err(format!("Word #{} '{}' is not in the BIP-39 dictionary", i + 1, word)),
        }
    }

    // Reassemble 264 bits
    let mut bits = Vec::with_capacity(264);
    for idx in indices {
        for i in (0..11).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
    }

    // Extract 32 bytes entropy
    let mut entropy = [0u8; 32];
    for (i, byte) in entropy.iter_mut().enumerate() {
        for bit in 0..8 {
            *byte = (*byte << 1) | bits[i * 8 + bit];
        }
    }

    // Extract 8-bit checksum
    let mut checksum = 0u8;
    for bit in 0..8 {
        checksum = (checksum << 1) | bits[256 + bit];
    }

    // Verify SHA-256 checksum
    let mut hasher = Sha256::new();
    hasher.update(&entropy);
    let hash = hasher.finalize();
    let expected_checksum = hash[0];

    if checksum != expected_checksum {
        return Err("Mnemonic checksum verification failed. Please verify words and ordering.".into());
    }

    Ok(())
}

/// Derive standard 64-byte binary seed from mnemonic using PBKDF2-HMAC-SHA512 (2048 iterations)
pub fn mnemonic_to_seed(words: &[String], passphrase: &str) -> [u8; 64] {
    let mnemonic = words.join(" ");
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac_sha512(mnemonic.as_bytes(), salt.as_bytes(), 2048)
}

/// Standard PBKDF2-HMAC-SHA512 implementation
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut hmac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key size");
    hmac.update(salt);
    hmac.update(&[0, 0, 0, 1]);
    let mut u = hmac.finalize().into_bytes();
    out.copy_from_slice(&u);

    for _ in 1..iterations {
        let mut h = HmacSha512::new_from_slice(password).expect("HMAC accepts any key size");
        h.update(&u);
        u = h.finalize().into_bytes();
        for i in 0..64 {
            out[i] ^= u[i];
        }
    }
    out
}
