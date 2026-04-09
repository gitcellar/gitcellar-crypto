//! Encryption module for vault-core
//!
//! Provides two encryption backends:
//!
//! - **GPG/OpenPGP** (default): Uses Sequoia OpenPGP for full GPG compatibility
//! - **AES-256-GCM** (feature: `aes-only`): Simpler key management without GPG
//!
//! # Encryption Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    EncryptionEngine                     │
//! │                      (trait)                            │
//! └─────────────────────────────────────────────────────────┘
//!              │                        │
//!    ┌─────────▼─────────┐    ┌─────────▼─────────┐
//!    │ GpgEncryptionEngine│    │ AesEncryptionEngine│
//!    │   (Sequoia)       │    │   (AES-256-GCM)   │
//!    └───────────────────┘    └───────────────────┘
//! ```
//!
//! # Example: AES Encryption
//!
//! ```rust,no_run
//! use vault_core::encryption::{AesEncryptionEngine, EncryptionEngine};
//!
//! // Generate a random key
//! let key = AesEncryptionEngine::generate_key();
//!
//! // Create engine
//! let engine = AesEncryptionEngine::new(&key).unwrap();
//!
//! // Encrypt data
//! let plaintext = b"Hello, encrypted world!";
//! let encrypted = engine.encrypt(plaintext).unwrap();
//!
//! // Decrypt data
//! let decrypted = engine.decrypt(&encrypted).unwrap();
//! assert_eq!(plaintext.to_vec(), decrypted);
//! ```

use crate::chunking::Chunk;
use crate::error::{VaultError, VaultResult};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use tracing::{debug, info};

/// Encryption engine trait
///
/// All encryption backends implement this trait for uniform API.
pub trait EncryptionEngine: Send + Sync {
    /// Encrypt raw data
    fn encrypt(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>>;

    /// Decrypt raw data
    fn decrypt(&self, ciphertext: &[u8]) -> VaultResult<Vec<u8>>;

    /// Get the key identifier (for logging/tracking)
    fn key_id(&self) -> &str;

    /// Encrypt a chunk
    fn encrypt_chunk(&self, chunk: &Chunk) -> VaultResult<Vec<u8>> {
        debug!(
            "Encrypting chunk: {} ({} bytes)",
            &chunk.hash[..16],
            chunk.size
        );
        self.encrypt(&chunk.data)
    }

    /// Decrypt chunk data
    fn decrypt_chunk(&self, encrypted_data: &[u8]) -> VaultResult<Vec<u8>> {
        debug!("Decrypting chunk ({} bytes)", encrypted_data.len());
        self.decrypt(encrypted_data)
    }
}

// ============================================================================
// AES-256-GCM Encryption Engine
// ============================================================================

/// AES-256-GCM encryption engine
///
/// Provides authenticated encryption without requiring GPG.
/// Keys are 32 bytes (256 bits).
///
/// # Wire Format
///
/// Encrypted data format:
/// ```text
/// [nonce: 12 bytes][ciphertext + auth tag]
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use vault_core::encryption::{AesEncryptionEngine, EncryptionEngine};
///
/// let key = AesEncryptionEngine::generate_key();
/// let engine = AesEncryptionEngine::new(&key).unwrap();
///
/// let encrypted = engine.encrypt(b"secret data").unwrap();
/// let decrypted = engine.decrypt(&encrypted).unwrap();
/// ```
pub struct AesEncryptionEngine {
    cipher: Aes256Gcm,
    key_id: String,
}

impl AesEncryptionEngine {
    /// Nonce size for AES-GCM (96 bits / 12 bytes)
    pub const NONCE_SIZE: usize = 12;

    /// Key size for AES-256 (256 bits / 32 bytes)
    pub const KEY_SIZE: usize = 32;

    /// Create a new AES encryption engine
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    ///
    /// # Errors
    /// Returns error if key is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> VaultResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(VaultError::Key(format!(
                "AES-256 key must be {} bytes, got {}",
                Self::KEY_SIZE,
                key.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VaultError::Key(format!("Failed to create cipher: {}", e)))?;

        // Use first 8 bytes of key hash as key ID (for logging)
        let key_hash = crate::chunking::ChunkEngine::compute_hash(key);
        let key_id = key_hash[..16].to_string();

        Ok(Self { cipher, key_id })
    }

    /// Generate a random 256-bit key
    pub fn generate_key() -> [u8; Self::KEY_SIZE] {
        let mut key = [0u8; Self::KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Derive a key from a passphrase using Argon2id
    ///
    /// # Arguments
    /// * `passphrase` - User-provided passphrase
    /// * `salt` - 16+ byte salt (should be stored alongside encrypted data)
    ///
    /// # Security
    /// Uses Argon2id with recommended parameters for key derivation.
    pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> VaultResult<[u8; Self::KEY_SIZE]> {
        use argon2::{Algorithm, Argon2, Params, Version};

        // Argon2id parameters (OWASP recommendations)
        let params = Params::new(
            65536,  // 64 MiB memory
            3,      // 3 iterations
            4,      // 4 parallel lanes
            Some(Self::KEY_SIZE),
        )
        .map_err(|e| VaultError::Key(format!("Invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; Self::KEY_SIZE];
        argon2
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| VaultError::Key(format!("Key derivation failed: {}", e)))?;

        Ok(key)
    }

    /// Generate a random salt for key derivation
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }
}

impl EncryptionEngine for AesEncryptionEngine {
    fn encrypt(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::Encryption(format!("AES encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(Self::NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        debug!(
            "Encrypted: {} bytes → {} bytes",
            plaintext.len(),
            result.len()
        );

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
        if ciphertext.len() < Self::NONCE_SIZE {
            return Err(VaultError::Decryption(
                "Ciphertext too short (missing nonce)".to_string(),
            ));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted) = ciphertext.split_at(Self::NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| VaultError::Decryption(format!("AES decryption failed: {}", e)))?;

        debug!(
            "Decrypted: {} bytes → {} bytes",
            ciphertext.len(),
            plaintext.len()
        );

        Ok(plaintext)
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }
}

// ============================================================================
// GPG/OpenPGP Encryption Engine
// ============================================================================

#[cfg(feature = "gpg")]
mod gpg {
    use super::*;
    use sequoia_openpgp as openpgp;
    use openpgp::crypto::SessionKey;
    use openpgp::parse::Parse;
    use openpgp::parse::stream::{DecryptorBuilder, MessageStructure};
    use openpgp::policy::Policy;
    use openpgp::policy::StandardPolicy as P;
    use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
    use std::io::Write;
    use std::path::PathBuf;

    /// GPG/OpenPGP encryption engine using Sequoia
    ///
    /// Provides full GPG compatibility for encrypting to GPG keys.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vault_core::encryption::{GpgEncryptionEngine, EncryptionEngine};
    ///
    /// // Load key from GPG keyring
    /// let engine = GpgEncryptionEngine::new("user@example.com".to_string()).unwrap();
    ///
    /// let encrypted = engine.encrypt(b"secret data").unwrap();
    /// ```
    pub struct GpgEncryptionEngine {
        key_id: String,
        cert: openpgp::Cert,
        policy: P<'static>,
    }

    impl GpgEncryptionEngine {
        /// Create a new GPG encryption engine
        ///
        /// Loads the certificate from the system GPG keyring.
        ///
        /// # Arguments
        /// * `key_id` - GPG key identifier (email, fingerprint, or key ID)
        pub fn new(key_id: String) -> VaultResult<Self> {
            let policy = P::new();
            let cert = Self::load_cert_from_keyring(&key_id)?;

            Ok(Self {
                key_id,
                cert,
                policy,
            })
        }

        /// Create from an existing certificate
        ///
        /// Use this when you have the certificate already loaded.
        pub fn from_cert(key_id: String, cert: openpgp::Cert) -> VaultResult<Self> {
            let policy = P::new();
            Ok(Self {
                key_id,
                cert,
                policy,
            })
        }

        /// Load from ASCII-armored key file
        pub fn from_armored_key(key_id: String, armored_key: &str) -> VaultResult<Self> {
            let cert = openpgp::Cert::from_bytes(armored_key.as_bytes())
                .map_err(|e| VaultError::Key(format!("Failed to parse armored key: {}", e)))?;

            Self::from_cert(key_id, cert)
        }

        /// Export the public key as ASCII-armored string
        pub fn export_public_key(&self) -> VaultResult<String> {
            use openpgp::armor;
            use openpgp::serialize::Serialize;

            let mut output = Vec::new();

            {
                let mut writer = armor::Writer::new(&mut output, armor::Kind::PublicKey)
                    .map_err(|e| VaultError::Key(format!("Failed to create armor writer: {}", e)))?;

                self.cert
                    .serialize(&mut writer)
                    .map_err(|e| VaultError::Key(format!("Failed to serialize certificate: {}", e)))?;

                writer
                    .finalize()
                    .map_err(|e| VaultError::Key(format!("Failed to finalize armored output: {}", e)))?;
            }

            String::from_utf8(output)
                .map_err(|e| VaultError::Key(format!("Failed to convert to UTF-8: {}", e)))
        }

        /// Load certificate from GPG keyring
        fn load_cert_from_keyring(key_id: &str) -> VaultResult<openpgp::Cert> {
            debug!("Loading GPG certificate for key: {}", key_id);

            // Find GPG home directory
            let gnupg_home = std::env::var("GNUPGHOME")
                .map(PathBuf::from)
                .ok()
                .filter(|p| p.exists())
                .or_else(|| {
                    dirs::home_dir()
                        .map(|p| p.join(".gnupg"))
                        .filter(|p| p.exists())
                })
                .or_else(|| {
                    if cfg!(windows) {
                        std::env::var("APPDATA")
                            .map(|p| PathBuf::from(p).join("gnupg"))
                            .ok()
                            .filter(|p| p.exists())
                    } else {
                        None
                    }
                });

            let gnupg_home = gnupg_home.ok_or_else(|| {
                VaultError::Key("Could not determine GPG home directory".to_string())
            })?;

            debug!("Looking for GPG keys in: {:?}", gnupg_home);

            // Try to find the key in pubring
            let pubring_paths = vec![
                gnupg_home.join("pubring.kbx"),
                gnupg_home.join("pubring.gpg"),
            ];

            for pubring_path in &pubring_paths {
                if !pubring_path.exists() {
                    continue;
                }

                let keyring_data = std::fs::read(pubring_path)
                    .map_err(|e| VaultError::Key(format!("Failed to read {:?}: {}", pubring_path, e)))?;

                // Try parsing as keyring
                let result: Option<openpgp::Cert> = {
                    let parser = match openpgp::cert::CertParser::from_bytes(&keyring_data) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let mut found = None;
                    for cert_result in parser {
                        if let Ok(cert) = cert_result {
                            if Self::cert_matches(&cert, key_id) {
                                found = Some(cert);
                                break;
                            }
                        }
                    }
                    found
                };
                if let Some(cert) = result {
                    info!("Loaded GPG certificate for key: {}", key_id);
                    return Ok(cert);
                }
            }

            Err(VaultError::Key(format!(
                "Could not find GPG key {} in keyring at {:?}",
                key_id, gnupg_home
            )))
        }

        /// Check if a certificate matches the key identifier
        fn cert_matches(cert: &openpgp::Cert, key_id: &str) -> bool {
            // Check fingerprint
            let fingerprint = cert.fingerprint().to_hex();
            if fingerprint.to_uppercase().ends_with(&key_id.to_uppercase()) {
                return true;
            }

            // Check key ID (last 16 chars)
            if fingerprint.len() >= 16 {
                let fp_key_id = &fingerprint[fingerprint.len() - 16..];
                if fp_key_id.eq_ignore_ascii_case(key_id) {
                    return true;
                }
            }

            // Check user IDs (email)
            for uid in cert.userids() {
                if let Ok(email) = std::str::from_utf8(uid.value()) {
                    if email.contains(key_id) {
                        return true;
                    }
                }
            }

            false
        }
    }

    impl EncryptionEngine for GpgEncryptionEngine {
        fn encrypt(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
            // Get encryption-capable subkeys
            let recipients = self
                .cert
                .keys()
                .with_policy(&self.policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .map(|ka| ka.key());

            let recipient_list: Vec<_> = recipients.collect();

            if recipient_list.is_empty() {
                return Err(VaultError::Key(format!(
                    "No encryption-capable keys found for {}",
                    self.key_id
                )));
            }

            // Create encrypted output
            let mut encrypted_data = Vec::new();

            {
                let message = Message::new(&mut encrypted_data);
                let message = Armorer::new(message)
                    .build()
                    .map_err(|e| VaultError::Encryption(e.to_string()))?;

                let message = Encryptor2::for_recipients(message, recipient_list)
                    .build()
                    .map_err(|e| VaultError::Encryption(format!("Failed to create encryptor: {}", e)))?;

                let mut message = LiteralWriter::new(message)
                    .build()
                    .map_err(|e| VaultError::Encryption(format!("Failed to create literal writer: {}", e)))?;

                message
                    .write_all(plaintext)
                    .map_err(|e| VaultError::Encryption(format!("Failed to write data: {}", e)))?;

                message
                    .finalize()
                    .map_err(|e| VaultError::Encryption(format!("Failed to finalize: {}", e)))?;
            }

            debug!(
                "Encrypted: {} bytes → {} bytes",
                plaintext.len(),
                encrypted_data.len()
            );

            Ok(encrypted_data)
        }

        fn decrypt(&self, ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
            // Load secret keys from keyring for decryption
            let gnupg_home = if cfg!(windows) {
                std::env::var("APPDATA")
                    .ok()
                    .map(|p| PathBuf::from(p).join("gnupg"))
                    .or_else(|| dirs::home_dir().map(|p| p.join(".gnupg")))
            } else {
                dirs::home_dir().map(|p| p.join(".gnupg"))
            }
            .ok_or_else(|| VaultError::Key("Could not determine GPG home directory".to_string()))?;

            // Decryption helper
            struct Helper<'a> {
                policy: &'a dyn Policy,
                secret_keys: Vec<openpgp::Cert>,
            }

            impl<'a> openpgp::parse::stream::DecryptionHelper for Helper<'a> {
                fn decrypt<D>(
                    &mut self,
                    pkesks: &[openpgp::packet::PKESK],
                    _skesks: &[openpgp::packet::SKESK],
                    sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
                    mut decrypt: D,
                ) -> openpgp::Result<Option<openpgp::Fingerprint>>
                where
                    D: FnMut(openpgp::types::SymmetricAlgorithm, &SessionKey) -> bool,
                {
                    for pkesk in pkesks {
                        for cert in &self.secret_keys {
                            for ka in cert
                                .keys()
                                .with_policy(self.policy, None)
                                .supported()
                                .for_transport_encryption()
                                .secret()
                            {
                                let mut keypair = ka
                                    .key()
                                    .clone()
                                    .into_keypair()
                                    .expect("Failed to create keypair");

                                if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                                    if decrypt(algo, &session_key) {
                                        return Ok(None);
                                    }
                                }
                            }
                        }
                    }
                    Err(anyhow::anyhow!("No matching secret key found").into())
                }
            }

            impl<'a> openpgp::parse::stream::VerificationHelper for Helper<'a> {
                fn get_certs(
                    &mut self,
                    _ids: &[openpgp::KeyHandle],
                ) -> openpgp::Result<Vec<openpgp::Cert>> {
                    Ok(self.secret_keys.clone())
                }

                fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
                    Ok(())
                }
            }

            // Load secret keys
            let mut secret_keys = Vec::new();
            let secring_path = gnupg_home.join("secring.gpg");

            if secring_path.exists() {
                let keyring_data = std::fs::read(&secring_path)
                    .map_err(|e| VaultError::Key(format!("Failed to read secret keyring: {}", e)))?;

                // Parse in a block to ensure parser is dropped before keyring_data
                let certs: Vec<openpgp::Cert> = {
                    if let Ok(parser) = openpgp::cert::CertParser::from_bytes(&keyring_data) {
                        parser.filter_map(|r| r.ok()).collect()
                    } else {
                        Vec::new()
                    }
                };
                secret_keys.extend(certs);
            }

            if secret_keys.is_empty() {
                return Err(VaultError::Key(format!(
                    "No secret keys found in {:?}",
                    gnupg_home
                )));
            }

            let helper = Helper {
                policy: &self.policy,
                secret_keys,
            };

            let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
                .map_err(|e| VaultError::Decryption(e.to_string()))?
                .with_policy(&self.policy, None, helper)
                .map_err(|e| VaultError::Decryption(e.to_string()))?;

            let mut decrypted_data = Vec::new();
            std::io::copy(&mut decryptor, &mut decrypted_data)
                .map_err(|e| VaultError::Decryption(format!("Failed to decrypt: {}", e)))?;

            debug!(
                "Decrypted: {} bytes → {} bytes",
                ciphertext.len(),
                decrypted_data.len()
            );

            Ok(decrypted_data)
        }

        fn key_id(&self) -> &str {
            &self.key_id
        }
    }
}

// Re-export GPG engine when feature enabled
#[cfg(feature = "gpg")]
pub use gpg::GpgEncryptionEngine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let plaintext = b"Hello, encrypted world!";
        let encrypted = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_different_nonces() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let plaintext = b"Same plaintext";
        let encrypted1 = engine.encrypt(plaintext).unwrap();
        let encrypted2 = engine.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertext (different nonces)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt correctly
        assert_eq!(engine.decrypt(&encrypted1).unwrap(), plaintext.to_vec());
        assert_eq!(engine.decrypt(&encrypted2).unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_aes_invalid_key_size() {
        let short_key = [0u8; 16]; // 128-bit key, should fail
        let result = AesEncryptionEngine::new(&short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_key_derivation() {
        let passphrase = b"my-secure-passphrase";
        let salt = AesEncryptionEngine::generate_salt();

        let key1 = AesEncryptionEngine::derive_key(passphrase, &salt).unwrap();
        let key2 = AesEncryptionEngine::derive_key(passphrase, &salt).unwrap();

        // Same passphrase + salt should produce same key
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let different_salt = AesEncryptionEngine::generate_salt();
        let key3 = AesEncryptionEngine::derive_key(passphrase, &different_salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_aes_chunk_encryption() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let chunk = Chunk {
            hash: "abc123".to_string(),
            data: vec![1, 2, 3, 4, 5],
            size: 5,
            offset: 0,
        };

        let encrypted = engine.encrypt_chunk(&chunk).unwrap();
        let decrypted = engine.decrypt_chunk(&encrypted).unwrap();

        assert_eq!(chunk.data, decrypted);
    }

    #[test]
    fn test_aes_large_data() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        // 1MB of random-ish data
        let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

        let encrypted = engine.encrypt(&plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_tampered_ciphertext() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let plaintext = b"Original data";
        let mut encrypted = engine.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        // Decryption should fail (authentication tag won't match)
        let result = engine.decrypt(&encrypted);
        assert!(result.is_err());
    }
}
