use crate::error::{Error, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::sync::Once;

static RUSTLS_PROVIDER_INIT: Once = Once::new();

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Config(format!("password hash error: {e}")))?;
    Ok(hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| Error::Config(format!("invalid stored password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn ensure_rustls_crypto_provider() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub fn derive_secret_box_key(passphrase: &str) -> [u8; 32] {
    let digest = Sha256::digest(passphrase.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

#[derive(Clone)]
pub struct SecretBox {
    key: [u8; 32],
}

impl SecretBox {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        Self::new(derive_secret_box_key(passphrase))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce_bytes = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let mut payload = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Storage(format!("secret encryption failed: {e}")))?;
        let mut output = nonce_bytes.to_vec();
        output.append(&mut payload);
        Ok(output)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 24 {
            return Err(Error::Storage("ciphertext too short".to_string()));
        }
        let (nonce_bytes, payload) = ciphertext.split_at(24);
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let nonce = XNonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| Error::Storage(format!("secret decryption failed: {e}")))
    }
}
