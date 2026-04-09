//! Chunk encryption and decryption
//!
//! Provides Sequoia-based encryption for GitCellar chunks.
//! All encryption uses the identity stored in GitCellar's config directory.

use crate::error::{CryptoError, Result};
use crate::Identity;
use sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::parse::Parse;
use openpgp::parse::stream::{DecryptorBuilder, MessageStructure};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
use std::io::Write;
use tracing::{debug, info};
use vault_core::chunking::Chunk;

/// Encryption engine using Sequoia OpenPGP
pub struct EncryptionEngine {
    identity: Identity,
    policy: StandardPolicy<'static>,
}

impl EncryptionEngine {
    /// Create an encryption engine from an identity
    pub fn new(identity: Identity) -> Result<Self> {
        if !identity.has_encryption_key() {
            return Err(CryptoError::NoEncryptionKey);
        }

        Ok(Self {
            identity,
            policy: StandardPolicy::new(),
        })
    }

    /// Create an encryption engine from the default identity location
    ///
    /// Loads identity for the active user from `~/.config/gitcellar/users/{username}/identity/`
    pub fn from_default_identity() -> Result<Self> {
        let identity = gitcellar_identity::identity::load_active()?;
        Self::new(identity)
    }

    /// Create an encryption engine directly from a Sequoia Cert
    ///
    /// This bypasses the Identity wrapper and works directly with the Cert.
    /// Used primarily for per-repository keys that aren't stored in the identity dir.
    pub fn from_cert(cert: openpgp::Cert) -> Result<Self> {
        // Create identity from cert without serialization round-trip
        let user_id = cert.userids()
            .next()
            .and_then(|uid| String::from_utf8(uid.value().to_vec()).ok())
            .unwrap_or_else(|| "unknown".to_string());

        let identity = Identity::from_cert(cert, user_id)?;

        // Skip has_encryption_key check - the encryption will fail naturally if no keys
        Ok(Self {
            identity,
            policy: StandardPolicy::new(),
        })
    }

    /// Get the identity used by this engine
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get the fingerprint of the identity
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Get the key ID of the identity
    pub fn key_id(&self) -> String {
        self.identity.key_id()
    }

    /// Export the public key as ASCII-armored string
    pub fn export_public_key(&self) -> Result<String> {
        Ok(self.identity.export_public_key()?)
    }

    /// Encrypt arbitrary data
    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        debug!("Encrypting {} bytes", data.len());

        let cert = self.identity.cert();

        // Get encryption-capable subkeys
        let recipients: Vec<_> = cert
            .keys()
            .with_policy(&self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .map(|ka| ka.key())
            .collect();

        if recipients.is_empty() {
            return Err(CryptoError::NoEncryptionKey);
        }

        // Create encrypted output
        let mut encrypted_data = Vec::new();

        {
            let message = Message::new(&mut encrypted_data);
            let message = Armorer::new(message).build()
                .map_err(|e| CryptoError::Encryption(format!("Failed to create armor writer: {}", e)))?;

            let message = Encryptor2::for_recipients(message, recipients)
                .build()
                .map_err(|e| CryptoError::Encryption(format!("Failed to create encryptor: {}", e)))?;

            let mut message = LiteralWriter::new(message)
                .build()
                .map_err(|e| CryptoError::Encryption(format!("Failed to create literal writer: {}", e)))?;

            message.write_all(data)
                .map_err(|e| CryptoError::Encryption(format!("Failed to write data: {}", e)))?;

            message.finalize()
                .map_err(|e| CryptoError::Encryption(format!("Failed to finalize: {}", e)))?;
        }

        debug!("Encrypted {} bytes → {} bytes", data.len(), encrypted_data.len());

        Ok(encrypted_data)
    }

    /// Decrypt data
    pub fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        debug!("Decrypting {} bytes", encrypted_data.len());

        // Create decryption helper
        struct Helper<'a> {
            policy: &'a dyn Policy,
            identity: &'a Identity,
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
                let cert = self.identity.cert();

                for pkesk in pkesks {
                    for ka in cert
                        .keys()
                        .with_policy(self.policy, None)
                        .supported()
                        .for_transport_encryption()
                        .for_storage_encryption()
                        .secret()
                    {
                        let mut keypair = ka
                            .key()
                            .clone()
                            .into_keypair()
                            .map_err(|e| openpgp::Error::InvalidKey(format!("Failed to create keypair: {}", e)))?;

                        if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                            if decrypt(algo, &session_key) {
                                return Ok(None);
                            }
                        }
                    }
                }

                Err(openpgp::Error::MissingSessionKey(
                    "Failed to decrypt: no matching secret key found".to_string()
                ).into())
            }
        }

        impl<'a> openpgp::parse::stream::VerificationHelper for Helper<'a> {
            fn get_certs(
                &mut self,
                _ids: &[openpgp::KeyHandle],
            ) -> openpgp::Result<Vec<openpgp::Cert>> {
                Ok(vec![self.identity.cert().clone()])
            }

            fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
                Ok(())
            }
        }

        let helper = Helper {
            policy: &self.policy,
            identity: &self.identity,
        };

        let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data)
            .map_err(|e| CryptoError::Decryption(format!("Failed to parse message: {}", e)))?
            .with_policy(&self.policy, None, helper)
            .map_err(|e| CryptoError::Decryption(format!("Failed to create decryptor: {}", e)))?;

        let mut decrypted_data = Vec::new();
        std::io::copy(&mut decryptor, &mut decrypted_data)
            .map_err(|e| CryptoError::Decryption(format!("Failed to read decrypted data: {}", e)))?;

        debug!("Decrypted {} bytes → {} bytes", encrypted_data.len(), decrypted_data.len());

        Ok(decrypted_data)
    }

    /// Encrypt a chunk
    pub fn encrypt_chunk(&self, chunk: &Chunk) -> Result<Vec<u8>> {
        debug!("Encrypting chunk: {} ({} bytes)", &chunk.hash[..16.min(chunk.hash.len())], chunk.size);
        self.encrypt_data(&chunk.data)
    }

    /// Decrypt chunk data
    pub fn decrypt_chunk(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_data(encrypted_data)
    }

    /// Encrypt multiple chunks in parallel
    pub async fn encrypt_chunks_parallel(&self, chunks: &[Chunk]) -> Result<Vec<Vec<u8>>> {
        info!("Encrypting {} chunks in parallel", chunks.len());

        use tokio::task;

        let mut tasks = Vec::new();

        for chunk in chunks {
            let chunk = chunk.clone();
            let identity = self.identity.clone();

            let task = task::spawn_blocking(move || {
                // Use from_cert to bypass has_encryption_key check - we already validated
                // the parent engine, and from_cert handles keys loaded via KeyManager
                let engine = EncryptionEngine::from_cert(identity.cert().clone())?;
                engine.encrypt_chunk(&chunk)
            });

            tasks.push(task);
        }

        let mut encrypted_chunks = Vec::new();
        for task in tasks {
            let encrypted = task.await
                .map_err(|e| CryptoError::Encryption(format!("Task failed: {}", e)))??;
            encrypted_chunks.push(encrypted);
        }

        info!("Encrypted {} chunks successfully", encrypted_chunks.len());
        Ok(encrypted_chunks)
    }

    /// Decrypt multiple chunks in parallel
    pub async fn decrypt_chunks_parallel(&self, encrypted_chunks: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        info!("Decrypting {} chunks in parallel", encrypted_chunks.len());

        use tokio::task;

        let mut tasks = Vec::new();

        for encrypted_data in encrypted_chunks {
            let encrypted_data = encrypted_data.clone();
            let identity = self.identity.clone();

            let task = task::spawn_blocking(move || {
                // Use from_cert to bypass has_encryption_key check - we already validated
                // the parent engine, and from_cert handles keys loaded via KeyManager
                let engine = EncryptionEngine::from_cert(identity.cert().clone())?;
                engine.decrypt_chunk(&encrypted_data)
            });

            tasks.push(task);
        }

        let mut decrypted_chunks = Vec::new();
        for task in tasks {
            let decrypted = task.await
                .map_err(|e| CryptoError::Decryption(format!("Task failed: {}", e)))??;
            decrypted_chunks.push(decrypted);
        }

        info!("Decrypted {} chunks successfully", decrypted_chunks.len());
        Ok(decrypted_chunks)
    }

    /// Sign data (for protocol message authentication)
    ///
    /// Creates a detached OpenPGP signature over the provided data.
    /// For detached signatures, we write directly to the Signer (no LiteralWriter).
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        use openpgp::serialize::stream::{Signer, Message};

        debug!("Signing {} bytes", data.len());

        let cert = self.identity.cert();

        // Find a signing-capable key
        let signing_keypair = cert.keys()
            .with_policy(&self.policy, None)
            .supported()
            .for_signing()
            .secret()
            .next()
            .ok_or(CryptoError::NoSigningKey)?
            .key()
            .clone()
            .into_keypair()
            .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to create keypair: {}", e)))?;

        let mut signature_bytes = Vec::new();

        {
            let message = Message::new(&mut signature_bytes);

            // For detached signatures, write directly to the Signer (no LiteralWriter)
            let mut signer = Signer::new(message, signing_keypair)
                .detached()
                .build()
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to create signer: {}", e)))?;

            // Write the data to be signed directly to the signer
            signer.write_all(data)
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to write data: {}", e)))?;

            signer.finalize()
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to finalize: {}", e)))?;
        }

        debug!("Created signature: {} bytes", signature_bytes.len());

        Ok(signature_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::chunking::{ChunkConfig, ChunkEngine};

    fn create_test_identity() -> Identity {
        Identity::generate("test@example.com").unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let original = b"Hello, encrypted world!";
        let encrypted = engine.encrypt_data(original).unwrap();

        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, original);

        let decrypted = engine.decrypt_data(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_decrypt_chunk() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let chunk_engine = ChunkEngine::new(ChunkConfig::default());
        let data = b"Hello, chunked and encrypted world!";
        let chunks = chunk_engine.chunk_data(data).unwrap();

        let encrypted = engine.encrypt_chunk(&chunks[0]).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted = engine.decrypt_chunk(&encrypted).unwrap();
        assert_eq!(decrypted, chunks[0].data);
    }

    #[test]
    fn test_encrypt_empty_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let encrypted = engine.encrypt_data(b"").unwrap();
        let decrypted = engine.decrypt_data(&encrypted).unwrap();

        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_encrypt_large_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let encrypted = engine.encrypt_data(&original).unwrap();
        let decrypted = engine.decrypt_data(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[tokio::test]
    async fn test_parallel_encryption() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let chunk_engine = ChunkEngine::new(ChunkConfig::default());
        let data = vec![42u8; 1024 * 1024]; // 1MB
        let chunks = chunk_engine.chunk_data(&data).unwrap();

        let encrypted = engine.encrypt_chunks_parallel(&chunks).await.unwrap();
        assert_eq!(encrypted.len(), chunks.len());

        // Verify each chunk can be decrypted
        for (i, enc) in encrypted.iter().enumerate() {
            let dec = engine.decrypt_chunk(enc).unwrap();
            assert_eq!(dec, chunks[i].data);
        }
    }

    #[test]
    fn test_sign_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let data = b"Data to be signed";
        let signature = engine.sign_data(data).unwrap();

        assert!(!signature.is_empty());
    }

    #[test]
    fn test_export_public_key() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let public_key = engine.export_public_key().unwrap();
        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }
}
