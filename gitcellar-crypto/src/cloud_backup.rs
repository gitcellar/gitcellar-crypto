//! Cloud Backup Bundle for Identity Recovery
//!
//! Provides encrypted identity backup that can be stored on gitcellar.com
//! and recovered using either a recovery code or passkey.
//!
//! # Design
//!
//! The bundle contains the identity encrypted with one or more mechanisms:
//! - Recovery code: Uses a key derived from 24-word BIP39 mnemonic
//! - Passkey: Uses a key derived from WebAuthn PRF extension — **STRUCK, DO NOT WIRE UP.
//!   See the warning below.**
//!
//! Each mechanism has its own encrypted copy of the identity, so either
//! can decrypt independently. This provides redundancy without requiring
//! both to be present.
//!
//! # ⛔ The passkey path is implemented but MUST NOT be wired up (2026-07-15)
//!
//! [`CloudBackupBundle::add_passkey_encryption`] and
//! [`CloudBackupBundle::decrypt_with_passkey`] are complete, unit-tested, and
//! exported — and **using them as a recovery mechanism would silently destroy user
//! data.** They are retained only because the format is sound; the *mechanism that
//! would feed them* is not. A feasibility spike (2026-07-15) struck this path:
//!
//! - **Windows Hello passkeys are TPM-bound and non-exportable** — the PRF secret dies
//!   with the machine, i.e. it fails in exactly the scenario recovery exists for. No
//!   synced, PRF-capable passkey path exists on Windows today (the OS plugin API plumbs
//!   PRF; no provider has implemented it).
//! - **Cross-device PRF stability is guaranteed by nobody.** Apple Developer Forums
//!   #774111: the same iCloud-synced passkey and salt yielded *different* PRF outputs
//!   across devices (fixed in iOS/macOS 18.4+). It failed **silently** — and a silently
//!   wrong 32 bytes here does not error, it produces a bundle that can never be
//!   decrypted. The user discovers this at the only moment it matters.
//! - **No shipping E2EE product uses PRF as recovery.** 1Password ships PRF to others
//!   and refused it for their own unlock. Bitwarden falls back to a master password;
//!   Dashlane and Apple ADP fall back to a long recovery key.
//!
//! Recovery is the 24-word phrase (Path A) + enrolled-device cross-signing (ADR-019
//! Path C). If PRF is ever unstruck, it may only be an *opportunistic convenience
//! unlock layered over Path A* — never the root of the hierarchy, never a sole escrow.
//!
//! The full analysis and the revisit trigger are recorded in the Multi-Device
//! Recovery specification (§ "Recovery Surfaces").
//!
//! # Zero-Access Property
//!
//! The bundle is encrypted client-side before upload. The server only ever
//! sees ciphertext and cannot decrypt without the user's recovery code or
//! passkey.

use crate::error::{CryptoError, Result};
use crate::Identity;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, info};

/// Current bundle format version
const BUNDLE_VERSION: &str = "1.0";

/// Salt size for HKDF (32 bytes)
const SALT_SIZE: usize = 32;

/// Nonce size for AES-256-GCM (12 bytes)
const NONCE_SIZE: usize = 12;

/// Context string for recovery code key derivation
const RECOVERY_CODE_CONTEXT: &[u8] = b"gitcellar-cloud-backup-recovery-code-v1";

/// Context string for passkey key derivation
const PASSKEY_CONTEXT: &[u8] = b"gitcellar-cloud-backup-passkey-v1";

/// Encrypted payload for a single recovery mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Salt used for key derivation (base64)
    pub salt: String,
    /// Nonce for AES-GCM (base64)
    pub nonce: String,
    /// Encrypted identity data (base64)
    pub ciphertext: String,
}

/// Passkey-specific payload with credential ID for lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyPayload {
    /// WebAuthn credential ID (base64) - used to request PRF during recovery
    pub credential_id: String,
    /// The encrypted payload
    #[serde(flatten)]
    pub encrypted: EncryptedPayload,
}

/// Cloud backup bundle containing encrypted identity
///
/// This is the structure stored on gitcellar.com. It contains the identity
/// encrypted with one or more recovery mechanisms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudBackupBundle {
    /// Bundle format version
    pub version: String,

    /// Identity fingerprint (for verification after decryption)
    pub fingerprint: String,

    /// User ID from identity
    pub user_id: String,

    /// Creation timestamp (RFC3339)
    pub created_at: String,

    /// Recovery code encrypted payload (always present)
    pub recovery_code: Option<EncryptedPayload>,

    /// Passkey encrypted payload (optional, added in Phase 2)
    pub passkey: Option<PasskeyPayload>,
}

impl CloudBackupBundle {
    /// Create a new backup bundle with recovery code encryption
    ///
    /// # Arguments
    /// * `identity` - The identity to backup
    /// * `recovery_key_material` - 32-byte key derived from recovery code
    ///   (e.g., from `derive_recovery_passphrase()` in recovery.rs)
    ///
    /// # Returns
    /// A bundle ready to upload to gitcellar.com
    pub fn create_with_recovery_code(
        identity: &Identity,
        recovery_key_material: &[u8],
    ) -> Result<Self> {
        if recovery_key_material.len() != 32 {
            return Err(CryptoError::Encryption(format!(
                "Recovery key material must be 32 bytes, got {}",
                recovery_key_material.len()
            )));
        }

        info!("Creating cloud backup bundle with recovery code encryption");

        // Serialize the identity
        let identity_data = serialize_identity(identity)?;

        // Encrypt with recovery code
        let recovery_payload = encrypt_payload(&identity_data, recovery_key_material, RECOVERY_CODE_CONTEXT)?;

        Ok(Self {
            version: BUNDLE_VERSION.to_string(),
            fingerprint: identity.fingerprint(),
            user_id: identity.user_id().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            recovery_code: Some(recovery_payload),
            passkey: None,
        })
    }

    /// Add passkey encryption to an existing bundle
    ///
    /// # ⛔ STRUCK — do not call from production code (2026-07-15)
    ///
    /// This works. That is the problem. There is no safe source for
    /// `passkey_key_material` today: Windows Hello passkeys are TPM-bound (the secret
    /// dies with the machine), and cross-device PRF stability is guaranteed by no
    /// vendor — Apple shipped a bug where the same synced passkey returned *different*
    /// PRF outputs per device, **silently**. Silently-wrong key material here does not
    /// error; it writes a bundle that can never be decrypted, and the user finds out
    /// during recovery. See the module-level warning for the full finding.
    ///
    /// Kept for format completeness and unit tests only. If PRF is ever unstruck, it
    /// may only layer *over* the recovery phrase — never replace it.
    ///
    /// # Arguments
    /// * `identity` - The identity (must match existing fingerprint)
    /// * `passkey_key_material` - 32-byte key from WebAuthn PRF
    /// * `credential_id` - The WebAuthn credential ID for this passkey
    pub fn add_passkey_encryption(
        &mut self,
        identity: &Identity,
        passkey_key_material: &[u8],
        credential_id: &[u8],
    ) -> Result<()> {
        if passkey_key_material.len() != 32 {
            return Err(CryptoError::Encryption(format!(
                "Passkey key material must be 32 bytes, got {}",
                passkey_key_material.len()
            )));
        }

        // Verify fingerprint matches
        if identity.fingerprint() != self.fingerprint {
            return Err(CryptoError::Encryption(
                "Identity fingerprint does not match bundle".to_string(),
            ));
        }

        info!("Adding passkey encryption to cloud backup bundle");

        // Serialize the identity
        let identity_data = serialize_identity(identity)?;

        // Encrypt with passkey
        let encrypted = encrypt_payload(&identity_data, passkey_key_material, PASSKEY_CONTEXT)?;

        self.passkey = Some(PasskeyPayload {
            credential_id: BASE64.encode(credential_id),
            encrypted,
        });

        Ok(())
    }

    /// Decrypt the bundle using a recovery code
    ///
    /// # Arguments
    /// * `recovery_key_material` - 32-byte key derived from recovery code
    ///
    /// # Returns
    /// The decrypted identity
    pub fn decrypt_with_recovery_code(&self, recovery_key_material: &[u8]) -> Result<Identity> {
        if recovery_key_material.len() != 32 {
            return Err(CryptoError::Decryption(format!(
                "Recovery key material must be 32 bytes, got {}",
                recovery_key_material.len()
            )));
        }

        let payload = self.recovery_code.as_ref().ok_or_else(|| {
            CryptoError::Decryption("Bundle does not contain recovery code encryption".to_string())
        })?;

        info!("Decrypting cloud backup bundle with recovery code");

        let identity_data = decrypt_payload(payload, recovery_key_material, RECOVERY_CODE_CONTEXT)?;
        let identity = deserialize_identity(&identity_data)?;

        // Verify fingerprint
        if identity.fingerprint() != self.fingerprint {
            return Err(CryptoError::Decryption(
                "Decrypted identity fingerprint does not match bundle".to_string(),
            ));
        }

        debug!("Successfully decrypted identity with fingerprint: {}", identity.fingerprint());
        Ok(identity)
    }

    /// Decrypt the bundle using a passkey
    ///
    /// # ⛔ STRUCK — do not call from production code (2026-07-15)
    ///
    /// Counterpart to [`Self::add_passkey_encryption`]; struck for the same reason. No
    /// bundle written by this crate's supported paths carries a passkey payload, so in
    /// practice this returns `Err` ("Bundle does not contain passkey encryption"). See
    /// the module-level warning before wiring up anything that would change that.
    ///
    /// # Arguments
    /// * `passkey_key_material` - 32-byte key from WebAuthn PRF
    ///
    /// # Returns
    /// The decrypted identity
    pub fn decrypt_with_passkey(&self, passkey_key_material: &[u8]) -> Result<Identity> {
        if passkey_key_material.len() != 32 {
            return Err(CryptoError::Decryption(format!(
                "Passkey key material must be 32 bytes, got {}",
                passkey_key_material.len()
            )));
        }

        let passkey_payload = self.passkey.as_ref().ok_or_else(|| {
            CryptoError::Decryption("Bundle does not contain passkey encryption".to_string())
        })?;

        info!("Decrypting cloud backup bundle with passkey");

        let identity_data = decrypt_payload(&passkey_payload.encrypted, passkey_key_material, PASSKEY_CONTEXT)?;
        let identity = deserialize_identity(&identity_data)?;

        // Verify fingerprint
        if identity.fingerprint() != self.fingerprint {
            return Err(CryptoError::Decryption(
                "Decrypted identity fingerprint does not match bundle".to_string(),
            ));
        }

        debug!("Successfully decrypted identity with fingerprint: {}", identity.fingerprint());
        Ok(identity)
    }

    /// Get the passkey credential ID if passkey encryption is configured
    pub fn passkey_credential_id(&self) -> Option<Vec<u8>> {
        self.passkey.as_ref().and_then(|p| BASE64.decode(&p.credential_id).ok())
    }

    /// Check if recovery code encryption is available
    pub fn has_recovery_code(&self) -> bool {
        self.recovery_code.is_some()
    }

    /// Check if passkey encryption is available
    pub fn has_passkey(&self) -> bool {
        self.passkey.is_some()
    }

    /// Serialize the bundle to JSON for upload
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            CryptoError::Encryption(format!("Failed to serialize bundle: {}", e))
        })
    }

    /// Deserialize a bundle from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            CryptoError::BundleFormat(format!("Failed to parse bundle JSON: {}", e))
        })
    }
}

/// Serialize an identity to bytes for encryption
fn serialize_identity(identity: &Identity) -> Result<Vec<u8>> {
    // Export the secret key in armored format
    let secret_key = identity.export_secret_key()?;
    Ok(secret_key.into_bytes())
}

/// Deserialize an identity from decrypted bytes
fn deserialize_identity(data: &[u8]) -> Result<Identity> {
    let secret_key_str = String::from_utf8(data.to_vec()).map_err(|e| {
        CryptoError::Decryption(format!("Invalid UTF-8 in decrypted identity: {}", e))
    })?;

    Ok(Identity::from_armored_secret_key(&secret_key_str)?)
}

/// Encrypt data with a key material using HKDF + AES-256-GCM.
///
/// # Key-material (IKM) contract — IC-4 AC-IC4.3
///
/// `key_material` is the HKDF **input keying material (IKM)** and MUST be
/// CSPRNG-derived high-entropy bytes — *never* a user-chosen passphrase.
/// Today's two callers both honour this:
/// - recovery-code path → BIP-39 mnemonic over 256 bits of `OsRng` entropy
///   (`passkey_core::recovery::generate_recovery_code`);
/// - passkey path (future) → 32-byte WebAuthn-PRF output.
///
/// HKDF is a key-derivation function, **not** a password-hashing function: it
/// performs no work-factor stretching. Feeding it a low-entropy passphrase
/// would silently make the cloud-backup bundle brute-forceable (a latent P0).
/// A future passphrase-backed caller MUST route through a memory-hard KDF
/// (Argon2id) first and pass the *stretched* output here — do not pass a
/// passphrase directly. The `debug_assert` below is a development trip-wire,
/// not a security boundary.
fn encrypt_payload(data: &[u8], key_material: &[u8], context: &[u8]) -> Result<EncryptedPayload> {
    debug_assert!(
        key_material.len() >= 32,
        "cloud-backup HKDF IKM must be CSPRNG-derived high-entropy material (>=32 bytes), \
         never a user passphrase (IC-4 AC-IC4.3); got {} bytes",
        key_material.len()
    );
    let mut rng = rand::thread_rng();

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill(&mut salt);
    rng.fill(&mut nonce_bytes);

    // Derive encryption key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(&salt), key_material);
    let mut encryption_key = [0u8; 32];
    hk.expand(context, &mut encryption_key)
        .map_err(|_| CryptoError::Encryption("HKDF expansion failed".to_string()))?;

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| CryptoError::Encryption(format!("Cipher creation failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptoError::Encryption(format!("Encryption failed: {}", e)))?;

    Ok(EncryptedPayload {
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

/// Decrypt an encrypted payload using HKDF + AES-256-GCM
fn decrypt_payload(payload: &EncryptedPayload, key_material: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    // Decode base64 fields
    let salt = BASE64.decode(&payload.salt).map_err(|e| {
        CryptoError::BundleFormat(format!("Invalid salt encoding: {}", e))
    })?;
    let nonce_bytes = BASE64.decode(&payload.nonce).map_err(|e| {
        CryptoError::BundleFormat(format!("Invalid nonce encoding: {}", e))
    })?;
    let ciphertext = BASE64.decode(&payload.ciphertext).map_err(|e| {
        CryptoError::BundleFormat(format!("Invalid ciphertext encoding: {}", e))
    })?;

    // Derive encryption key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(&salt), key_material);
    let mut encryption_key = [0u8; 32];
    hk.expand(context, &mut encryption_key)
        .map_err(|_| CryptoError::Decryption("HKDF expansion failed".to_string()))?;

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| CryptoError::Decryption(format!("Cipher creation failed: {}", e)))?;

    if nonce_bytes.len() != NONCE_SIZE {
        return Err(CryptoError::BundleFormat(format!(
            "Invalid nonce size: {} (expected {})",
            nonce_bytes.len(),
            NONCE_SIZE
        )));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> Identity {
        Identity::generate("test@example.com").unwrap()
    }

    fn create_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        key
    }

    #[test]
    fn test_create_and_decrypt_with_recovery_code() {
        let identity = create_test_identity();
        let original_fp = identity.fingerprint();
        let key = create_test_key();

        // Create bundle
        let bundle = CloudBackupBundle::create_with_recovery_code(&identity, &key).unwrap();

        // Verify metadata
        assert_eq!(bundle.version, BUNDLE_VERSION);
        assert_eq!(bundle.fingerprint, original_fp);
        assert!(bundle.has_recovery_code());
        assert!(!bundle.has_passkey());

        // Decrypt
        let recovered = bundle.decrypt_with_recovery_code(&key).unwrap();
        assert_eq!(recovered.fingerprint(), original_fp);
    }

    #[test]
    fn test_wrong_key_fails() {
        let identity = create_test_identity();
        let key = create_test_key();
        let wrong_key = create_test_key();

        let bundle = CloudBackupBundle::create_with_recovery_code(&identity, &key).unwrap();

        // Decrypt with wrong key should fail
        let result = bundle.decrypt_with_recovery_code(&wrong_key);
        assert!(matches!(result, Err(CryptoError::InvalidPassword)));
    }

    #[test]
    fn test_add_passkey_encryption() {
        let identity = create_test_identity();
        let original_fp = identity.fingerprint();
        let recovery_key = create_test_key();
        let passkey_key = create_test_key();
        let credential_id = b"test-credential-id";

        // Create bundle with recovery code
        let mut bundle = CloudBackupBundle::create_with_recovery_code(&identity, &recovery_key).unwrap();
        assert!(!bundle.has_passkey());

        // Add passkey
        bundle.add_passkey_encryption(&identity, &passkey_key, credential_id).unwrap();
        assert!(bundle.has_passkey());

        // Decrypt with passkey
        let recovered = bundle.decrypt_with_passkey(&passkey_key).unwrap();
        assert_eq!(recovered.fingerprint(), original_fp);

        // Decrypt with recovery code still works
        let recovered2 = bundle.decrypt_with_recovery_code(&recovery_key).unwrap();
        assert_eq!(recovered2.fingerprint(), original_fp);
    }

    #[test]
    fn test_json_serialization() {
        let identity = create_test_identity();
        let key = create_test_key();

        let bundle = CloudBackupBundle::create_with_recovery_code(&identity, &key).unwrap();
        let json = bundle.to_json().unwrap();

        // Parse back
        let parsed = CloudBackupBundle::from_json(&json).unwrap();
        assert_eq!(parsed.fingerprint, bundle.fingerprint);
        assert_eq!(parsed.version, bundle.version);

        // Can still decrypt
        let recovered = parsed.decrypt_with_recovery_code(&key).unwrap();
        assert_eq!(recovered.fingerprint(), bundle.fingerprint);
    }

    #[test]
    fn test_invalid_key_length() {
        let identity = create_test_identity();
        let short_key = [0u8; 16]; // Too short

        let result = CloudBackupBundle::create_with_recovery_code(&identity, &short_key);
        assert!(matches!(result, Err(CryptoError::Encryption(_))));
    }

    #[test]
    fn test_credential_id_retrieval() {
        let identity = create_test_identity();
        let recovery_key = create_test_key();
        let passkey_key = create_test_key();
        let credential_id = b"my-passkey-credential";

        let mut bundle = CloudBackupBundle::create_with_recovery_code(&identity, &recovery_key).unwrap();
        bundle.add_passkey_encryption(&identity, &passkey_key, credential_id).unwrap();

        let retrieved = bundle.passkey_credential_id().unwrap();
        assert_eq!(retrieved, credential_id);
    }
}
