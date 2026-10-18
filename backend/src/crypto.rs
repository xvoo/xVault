//! Server-side cryptography.
//!
//! The server never sees a
//! password, a vault key, or any vault plaintext. The browser derives, from
//! the master password, an *auth key* (sent to the server as a login proof)
//! and a separate *wrap key* (never leaves the browser). The server only:
//!
//! * stores an Argon2id hash of the auth key / recovery proofs, and verifies
//!   them in constant time,
//! * stores opaque, client-encrypted blobs (vault, wrapped vault keys).
//!

use argon2::password_hash::rand_core::OsRng as PhcRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::sync::OnceLock;

/// Server-side Argon2id cost for hashing auth keys / recovery proofs. The
/// inputs are 256-bit client-derived keys (the expensive, memory-hard
/// password stretching already happened in the browser), so this layer is
/// defence in depth against a database leak, tuned to the OWASP minimum.
fn server_argon2() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hashes a client proof (auth key, recovery proof, ...) into a PHC string.
pub fn hash_secret(secret: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut PhcRng);
    server_argon2()
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "Failed to hash secret".to_string())
}

/// Constant-time verification of a client proof against a stored PHC hash.
pub fn verify_secret(secret: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    server_argon2()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok()
}

/// Burns the same CPU/memory as a real verification. Used when the account
/// does not exist so response timing does not reveal valid login IDs.
pub fn dummy_verify(secret: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let phc = DUMMY.get_or_init(|| hash_secret("xvault-dummy-proof").unwrap_or_default());
    let _ = verify_secret(secret, phc);
}

/// Deterministic, per-login-ID fake KDF salt for unknown accounts, so the
/// pre-login endpoint answers identically whether or not an account exists.
pub fn fake_kdf_salt(server_secret: &[u8], login_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(server_secret).expect("hmac accepts any key");
    mac.update(b"xvault-fake-kdf-salt:");
    mac.update(login_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    BASE64.encode(&digest[..16])
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generates a random session token (256 bits, hex).
pub fn random_token() -> String {
    hex::encode(random_bytes::<32>())
}

pub const USERNAME_MIN: usize = 3;
pub const USERNAME_MAX: usize = 32;

/// Usernames are chosen by the user and case-insensitive: they are stored
/// lowercase. Allowed: a-z, 0-9 and `.`, `_`, `-` (not first or last),
/// 3 to 32 characters. Returns None when the input is not a valid username.
pub fn normalize_username(raw: &str) -> Option<String> {
    let name = raw.trim().to_ascii_lowercase();
    let bytes = name.as_bytes();
    let valid_len = (USERNAME_MIN..=USERNAME_MAX).contains(&bytes.len());
    let valid_chars = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    let valid_edges = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric);
    (valid_len && valid_chars && valid_edges).then_some(name)
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A client proof is always a 256-bit key encoded as 64 lowercase hex chars.
pub fn is_valid_proof(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Client KDF parameters (validated, then stored as normalized JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

pub const DEFAULT_KDF_MEMORY_KIB: u32 = 64 * 1024;
pub const DEFAULT_KDF_ITERATIONS: u32 = 3;
pub const DEFAULT_KDF_PARALLELISM: u32 = 1;

impl KdfParams {
    /// Accepts only Argon2id with sane bounds: strong enough to resist
    /// offline guessing, small enough to run in a phone browser.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let params: KdfParams =
            serde_json::from_value(value.clone()).map_err(|_| "Invalid KDF parameters".to_string())?;
        if params.algorithm != "argon2id" {
            return Err("Unsupported KDF algorithm".into());
        }
        let salt = BASE64
            .decode(&params.salt)
            .map_err(|_| "Invalid KDF salt".to_string())?;
        if !(16..=64).contains(&salt.len()) {
            return Err("Invalid KDF salt".into());
        }
        if !(19 * 1024..=1024 * 1024).contains(&params.memory)
            || !(1..=20).contains(&params.iterations)
            || !(1..=8).contains(&params.parallelism)
        {
            return Err("KDF parameters out of range".into());
        }
        Ok(params)
    }

    pub fn fake(server_secret: &[u8], login_id: &str) -> Self {
        KdfParams {
            algorithm: "argon2id".into(),
            salt: fake_kdf_salt(server_secret, login_id),
            memory: DEFAULT_KDF_MEMORY_KIB,
            iterations: DEFAULT_KDF_ITERATIONS,
            parallelism: DEFAULT_KDF_PARALLELISM,
        }
    }
}

/// Client-encrypted blobs are opaque to the server; only their shape and
/// size are checked (printable ASCII, bounded length).
pub fn is_valid_blob(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hash_roundtrip() {
        let proof = "a".repeat(64);
        let phc = hash_secret(&proof).unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_secret(&proof, &phc));
        assert!(!verify_secret(&"b".repeat(64), &phc));
        assert!(!verify_secret(&proof, "not-a-phc-string"));
    }

    #[test]
    fn hashes_are_salted_per_call() {
        let proof = "c".repeat(64);
        assert_ne!(hash_secret(&proof).unwrap(), hash_secret(&proof).unwrap());
    }

    #[test]
    fn proof_format() {
        assert!(is_valid_proof(&"0123456789abcdef".repeat(4)));
        assert!(!is_valid_proof(&"0123456789ABCDEF".repeat(4)));
        assert!(!is_valid_proof(""));
        assert!(!is_valid_proof(&"a".repeat(63)));
    }

    #[test]
    fn kdf_params_validation() {
        let ok = serde_json::json!({
            "algorithm": "argon2id",
            "salt": BASE64.encode([7u8; 16]),
            "memory": 65536, "iterations": 3, "parallelism": 1
        });
        assert!(KdfParams::from_json(&ok).is_ok());

        let weak = serde_json::json!({
            "algorithm": "argon2id",
            "salt": BASE64.encode([7u8; 16]),
            "memory": 8, "iterations": 1, "parallelism": 1
        });
        assert!(KdfParams::from_json(&weak).is_err());

        let other = serde_json::json!({
            "algorithm": "pbkdf2", "salt": BASE64.encode([7u8; 16]),
            "memory": 65536, "iterations": 3, "parallelism": 1
        });
        assert!(KdfParams::from_json(&other).is_err());
    }

    #[test]
    fn fake_salt_is_stable_and_scoped() {
        let secret = [9u8; 32];
        assert_eq!(fake_kdf_salt(&secret, "ABC"), fake_kdf_salt(&secret, "ABC"));
        assert_ne!(fake_kdf_salt(&secret, "ABC"), fake_kdf_salt(&secret, "ABD"));
    }

    #[test]
    fn username_rules() {
        assert_eq!(normalize_username("  Matthew.Dev "), Some("matthew.dev".into()));
        assert_eq!(normalize_username("a_b-c9"), Some("a_b-c9".into()));
        assert_eq!(normalize_username("ab"), None);
        assert_eq!(normalize_username(&"a".repeat(33)), None);
        assert_eq!(normalize_username(".dot"), None);
        assert_eq!(normalize_username("dot."), None);
        assert_eq!(normalize_username("spa ce"), None);
        assert_eq!(normalize_username("émile"), None);
    }
}
