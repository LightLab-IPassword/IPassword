//! Thin, boring wrappers over vetted RustCrypto primitives. No custom crypto.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

/// A 256-bit key that is wiped from memory when dropped.
pub type Key = Zeroizing<[u8; KEY_LEN]>;

/// Argon2id cost parameters. Stored in the vault header so they can be raised
/// later without breaking old vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane. Above the OWASP minimums for Argon2id.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// Absurdly cheap parameters for tests. Only exists in test builds or with
    /// the `insecure-fast-kdf` feature.
    #[cfg(any(test, feature = "insecure-fast-kdf"))]
    pub const INSECURE_FAST: KdfParams = KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
    const MAX_T_COST: u32 = 16;
    const MAX_P_COST: u32 = 16;

    /// Checked whenever parameters are read from disk. The upper bounds stop a
    /// malicious vault file from making us allocate absurd amounts of memory.
    pub(crate) fn validate_bounds(&self) -> Result<()> {
        if self.p_cost == 0 || self.p_cost > Self::MAX_P_COST {
            return Err(Error::InvalidHeader("argon2 parallelism out of range"));
        }
        if self.t_cost == 0 || self.t_cost > Self::MAX_T_COST {
            return Err(Error::InvalidHeader("argon2 pass count out of range"));
        }
        if self.m_cost_kib < 8 * self.p_cost || self.m_cost_kib > Self::MAX_M_COST_KIB {
            return Err(Error::InvalidHeader("argon2 memory cost out of range"));
        }
        Ok(())
    }

    /// Checked when creating a vault or changing a password: refuses settings
    /// weaker than a sane floor (except in test builds).
    pub(crate) fn validate_for_creation(&self) -> Result<()> {
        self.validate_bounds()
            .map_err(|_| Error::Invalid("argon2 parameters out of range"))?;
        if !cfg!(any(test, feature = "insecure-fast-kdf"))
            && (self.m_cost_kib < 19 * 1024 || self.t_cost < 2)
        {
            return Err(Error::Invalid("argon2 parameters are too weak"));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

pub fn random_key() -> Result<Key> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::getrandom(&mut key[..]).map_err(|_| Error::Rng)?;
    Ok(key)
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}

/// Master password -> 256-bit key, via Argon2id. Deterministic for a given
/// (password, salt, params), which is what lets us re-derive it on login.
pub fn derive_password_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key> {
    params.validate_bounds()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut out[..])
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

/// HKDF-SHA256 subkey with a domain-separation label, so the file-name key and
/// the encryption key are unrelated even though both come from the vault key.
pub fn derive_subkey(vault_key: &Key, info: &[u8]) -> Result<Key> {
    let hk = Hkdf::<Sha256>::new(None, &vault_key[..]);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, &mut out[..])
        .map_err(|_| Error::Crypto("hkdf expand failed"))?;
    Ok(out)
}

/// HMAC-SHA256(key, label || 0x00 || message), truncated to 128 bits and
/// hex-encoded. Used for file and folder names.
pub fn keyed_id(key: &[u8], label: &[u8], message: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(label);
    mac.update(&[0]);
    mac.update(message.as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..16])
}

/// AES-256-GCM with a fresh random 96-bit nonce. `aad` is authenticated but
/// not encrypted: we use it to bind ciphertexts to their context.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher =
        Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto("bad key length"))?;
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("encryption failed"))?;
    Ok((nonce, ciphertext))
}

/// Returns `Error::Decrypt` if the tag doesn't verify (wrong key, wrong AAD,
/// or modified ciphertext). Nothing is ever returned on failure.
pub fn open(
    key: &Key,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Crypto("bad nonce length"));
    }
    let cipher =
        Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto("bad key length"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;

    #[test]
    fn password_key_is_deterministic_and_input_sensitive() {
        let salt = [7u8; SALT_LEN];
        let a = derive_password_key(b"pw", &salt, FAST).unwrap();
        let b = derive_password_key(b"pw", &salt, FAST).unwrap();
        assert_eq!(a[..], b[..]);

        let other_pw = derive_password_key(b"pW", &salt, FAST).unwrap();
        assert_ne!(a[..], other_pw[..]);

        let other_salt = derive_password_key(b"pw", &[8u8; SALT_LEN], FAST).unwrap();
        assert_ne!(a[..], other_salt[..]);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key().unwrap();
        let (nonce, ct) = seal(&key, b"ctx", b"hello").unwrap();
        let pt = open(&key, &nonce, b"ctx", &ct).unwrap();
        assert_eq!(&pt[..], b"hello");
    }

    #[test]
    fn open_rejects_wrong_key_wrong_aad_and_tampering() {
        let key = random_key().unwrap();
        let (nonce, mut ct) = seal(&key, b"ctx", b"hello").unwrap();

        let wrong_key = random_key().unwrap();
        assert!(matches!(
            open(&wrong_key, &nonce, b"ctx", &ct),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            open(&key, &nonce, b"other", &ct),
            Err(Error::Decrypt)
        ));

        ct[0] ^= 1;
        assert!(matches!(
            open(&key, &nonce, b"ctx", &ct),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn nonces_are_not_reused() {
        let key = random_key().unwrap();
        let (n1, _) = seal(&key, b"", b"x").unwrap();
        let (n2, _) = seal(&key, b"", b"x").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let vk = random_key().unwrap();
        let a = derive_subkey(&vk, b"label-a").unwrap();
        let b = derive_subkey(&vk, b"label-b").unwrap();
        assert_ne!(a[..], b[..]);
        assert_ne!(a[..], vk[..]);
    }

    #[test]
    fn keyed_id_depends_on_key_label_and_message() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let base = keyed_id(&k1, b"l", "netflix");
        assert_eq!(base, keyed_id(&k1, b"l", "netflix"));
        assert_ne!(base, keyed_id(&k2, b"l", "netflix"));
        assert_ne!(base, keyed_id(&k1, b"m", "netflix"));
        assert_ne!(base, keyed_id(&k1, b"l", "netflix2"));
        assert_eq!(base.len(), 32);
    }

    #[test]
    fn hostile_kdf_params_are_rejected() {
        let huge = KdfParams {
            m_cost_kib: 4_000_000,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(matches!(
            derive_password_key(b"pw", &[0u8; SALT_LEN], huge),
            Err(Error::InvalidHeader(_))
        ));
        let zero = KdfParams {
            m_cost_kib: 8,
            t_cost: 0,
            p_cost: 1,
        };
        assert!(zero.validate_bounds().is_err());
    }
}
