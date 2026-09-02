//! Identity management for passkey-core
//!
//! Handles generation, loading, and saving of OpenPGP Ed25519/X25519 keys.
//! Keys are stored in the application's config directory, not the system GPG keyring.
//!
//! # Key Structure
//!
//! Each identity contains:
//! - A primary Ed25519 signing key
//! - An X25519 encryption subkey (for transport encryption)
//! - An X25519 encryption subkey (for storage encryption)
//!
//! # Storage
//!
//! Keys are stored as OpenPGP certificates in:
//! - `{config}/users/{username}/identity/secret.pgp` - Full certificate with secret material
//! - `{config}/users/{username}/identity/public.pgp` - Public key only

mod storage;
mod export;

pub use storage::*;
pub use export::*;

use crate::error::{PasskeyError, Result};
use crate::paths::PasskeyConfig;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use std::path::Path;
use tracing::{debug, info};

/// Secret key filename
const SECRET_KEY_FILE: &str = "secret.pgp";
/// Public key filename
const PUBLIC_KEY_FILE: &str = "public.pgp";

/// Represents a passkey identity (OpenPGP certificate)
///
/// An identity contains Ed25519 signing and X25519 encryption keys
/// in OpenPGP certificate format.
#[derive(Clone)]
pub struct Identity {
    /// The OpenPGP certificate (contains both public and secret key material)
    cert: openpgp::Cert,
    /// User ID (typically email or username)
    user_id: String,
}

impl Identity {
    /// Generate a new identity with Ed25519/X25519 keys
    ///
    /// Creates a primary Ed25519 signing key and X25519 encryption subkeys.
    /// Uses modern Curve25519 cryptography.
    ///
    /// # Arguments
    /// * `user_id` - User identifier, typically an email address
    ///
    /// # Example
    /// ```ignore
    /// use passkey_core::Identity;
    /// let identity = Identity::generate("user@example.com")?;
    /// ```
    pub fn generate(user_id: &str) -> Result<Self> {
        info!("Generating new identity for: {}", user_id);

        // Pin the OpenPGP key version to v4 (RFC 4880). Sequoia 2.x added
        // RFC 9580 ("v6") key support behind a `Profile`; v4 is 2.4.x's default
        // but pinning it explicitly means a future upstream default flip cannot
        // silently change our fingerprint format and break interop with every
        // already-stored identity. Asserted by `identity_generates_v4_keys`
        // (tests/cert_profile_v4.rs).
        let (cert, _revocation) = CertBuilder::new()
            .set_profile(openpgp::Profile::RFC4880)
            .map_err(|e| PasskeyError::KeyGeneration(e.to_string()))?
            .add_userid(user_id)
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_storage_encryption_subkey()
            .generate()
            .map_err(|e| PasskeyError::KeyGeneration(e.to_string()))?;

        let fingerprint = cert.fingerprint();
        info!("Generated identity with fingerprint: {}", fingerprint);

        Ok(Self {
            cert,
            user_id: user_id.to_string(),
        })
    }

    /// Load identity for a specific user
    ///
    /// # Arguments
    /// * `config` - PasskeyConfig with path settings
    /// * `username` - The username to load identity for
    pub fn load_user(config: &PasskeyConfig, username: &str) -> Result<Self> {
        let identity_path = config.identity_dir(username);
        Self::load_from(&identity_path)
    }

    /// Load identity from a specific directory
    ///
    /// # Arguments
    /// * `path` - Directory containing secret.pgp and public.pgp
    pub fn load_from(path: &Path) -> Result<Self> {
        let secret_path = path.join(SECRET_KEY_FILE);

        if !secret_path.exists() {
            return Err(PasskeyError::IdentityNotFound);
        }

        debug!("Loading identity from: {:?}", secret_path);

        let raw = std::fs::read(&secret_path)
            .map_err(|e| PasskeyError::KeyLoad(format!("Failed to read {}: {}", secret_path.display(), e)))?;

        // F5 (DEC-LD-03): open the at-rest seal. A legacy (pre-F5) plaintext
        // secret.pgp lacks the wrap magic and passes through unchanged, so
        // existing identities keep loading and are re-sealed on the next save.
        let cert_data: Vec<u8> = {
            #[cfg(feature = "keyring")]
            {
                if crate::keywrap::is_wrapped(&raw) {
                    crate::keywrap::unwrap_at_rest(&raw)
                        .map_err(|e| PasskeyError::KeyLoad(format!("Failed to open sealed secret key: {}", e)))?
                } else {
                    raw
                }
            }
            #[cfg(not(feature = "keyring"))]
            {
                raw
            }
        };

        let cert = openpgp::Cert::from_bytes(&cert_data)
            .map_err(|e| PasskeyError::KeyLoad(format!("Failed to parse certificate: {}", e)))?;

        // Extract user ID
        let user_id = cert.userids()
            .next()
            .and_then(|uid| String::from_utf8(uid.userid().value().to_vec()).ok())
            .unwrap_or_else(|| "unknown".to_string());

        info!("Loaded identity: {} ({})", user_id, cert.fingerprint());

        Ok(Self { cert, user_id })
    }

    /// Check if an identity exists for a specific user
    pub fn exists_for_user(config: &PasskeyConfig, username: &str) -> bool {
        config.identity_dir(username).join(SECRET_KEY_FILE).exists()
    }

    /// Save identity for a specific user
    ///
    /// # Arguments
    /// * `config` - PasskeyConfig with path settings
    /// * `username` - The username to save identity for
    pub fn save_for_user(&self, config: &PasskeyConfig, username: &str) -> Result<()> {
        let identity_path = config.identity_dir(username);
        self.save_to(&identity_path)
    }

    /// Save identity to a specific directory
    ///
    /// # Arguments
    /// * `path` - Directory to save secret.pgp and public.pgp
    pub fn save_to(&self, path: &Path) -> Result<()> {
        use openpgp::serialize::Serialize;

        // Create directory if it doesn't exist
        std::fs::create_dir_all(path)
            .map_err(|e| PasskeyError::KeySave(format!("Failed to create directory {:?}: {}", path, e)))?;

        let secret_path = path.join(SECRET_KEY_FILE);
        let public_path = path.join(PUBLIC_KEY_FILE);

        // Serialize the full TSK (secret material) to a buffer so it can be
        // sealed at rest (F5 / AC-F5.4) before touching disk.
        let mut tsk_bytes: Vec<u8> = Vec::new();
        self.cert.as_tsk().serialize(&mut tsk_bytes)
            .map_err(|e| PasskeyError::KeySave(format!("Failed to write secret key: {}", e)))?;

        // F5 (AC-F5.4, DEC-LD-03): seal the secret key with the OS-keyring/DPAPI
        // -backed Local Protection Key. The on-disk bytes become AES-256-GCM
        // ciphertext, so an infostealer reading the file gets nothing usable —
        // protection no longer relies on the inherited ACL alone. If the OS
        // keyring is unavailable (rare; headless/CI without Secret-Service), fall
        // back to a plaintext write + warning to preserve availability.
        let secret_to_write: Vec<u8> = {
            #[cfg(feature = "keyring")]
            {
                match crate::keywrap::wrap_at_rest(&tsk_bytes) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        tracing::warn!(
                            "At-rest wrap unavailable for secret key ({}); writing unsealed. \
                             Key material protected by filesystem permissions only.",
                            e
                        );
                        tsk_bytes
                    }
                }
            }
            #[cfg(not(feature = "keyring"))]
            {
                tsk_bytes
            }
        };

        debug!("Saving secret key to: {:?}", secret_path);
        std::fs::write(&secret_path, &secret_to_write)
            .map_err(|e| PasskeyError::KeySave(format!("Failed to create {}: {}", secret_path.display(), e)))?;

        // Set restrictive permissions on secret key (Unix only). Best-effort
        // defence-in-depth; the at-rest seal above is the primary protection
        // and closes the Windows inherited-ACL gap (AC-F5.4).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&secret_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&secret_path, perms)?;
        }

        // Save public key (certificate without secret material)
        debug!("Saving public key to: {:?}", public_path);
        let mut public_file = std::fs::File::create(&public_path)
            .map_err(|e| PasskeyError::KeySave(format!("Failed to create {}: {}", public_path.display(), e)))?;

        self.cert.serialize(&mut public_file)
            .map_err(|e| PasskeyError::KeySave(format!("Failed to write public key: {}", e)))?;

        info!("Identity saved to: {:?}", path);

        Ok(())
    }

    /// Get the fingerprint of this identity (40 hex characters)
    pub fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    /// Get the key ID (last 16 hex chars of fingerprint)
    pub fn key_id(&self) -> String {
        let fp = self.fingerprint();
        if fp.len() >= 16 {
            fp[fp.len() - 16..].to_string()
        } else {
            fp
        }
    }

    /// Get the user ID (email/username)
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get the underlying OpenPGP certificate
    pub fn cert(&self) -> &openpgp::Cert {
        &self.cert
    }

    /// Check if the identity has an encryption-capable secret key
    pub fn has_encryption_key(&self) -> bool {
        let policy = StandardPolicy::new();
        self.cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .secret()
            .next()
            .is_some()
    }

    /// Check if the identity has a signing-capable secret key
    pub fn has_signing_key(&self) -> bool {
        let policy = StandardPolicy::new();
        self.cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .is_some()
    }

    /// Create identity from an existing OpenPGP certificate
    ///
    /// Used when you already have a Cert in memory.
    pub fn from_cert(cert: openpgp::Cert, user_id: String) -> Result<Self> {
        Ok(Self { cert, user_id })
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .field("user_id", &self.user_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_identity() {
        let identity = Identity::generate("test@example.com").unwrap();

        assert_eq!(identity.user_id(), "test@example.com");
        assert!(!identity.fingerprint().is_empty());
        assert_eq!(identity.key_id().len(), 16);
        assert!(identity.has_encryption_key());
        assert!(identity.has_signing_key());
    }

    #[test]
    fn test_fingerprint_format() {
        let identity = Identity::generate("test@example.com").unwrap();
        let fp = identity.fingerprint();

        // Should be 40 hex characters
        assert_eq!(fp.len(), 40);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // Generate and save
        let original = Identity::generate("test@example.com").unwrap();
        original.save_to(path).unwrap();

        // Verify files exist
        assert!(path.join(SECRET_KEY_FILE).exists());
        assert!(path.join(PUBLIC_KEY_FILE).exists());

        // Load and compare
        let loaded = Identity::load_from(path).unwrap();
        assert_eq!(loaded.fingerprint(), original.fingerprint());
        assert_eq!(loaded.user_id(), original.user_id());
    }

    #[test]
    fn test_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let result = Identity::load_from(temp_dir.path());
        assert!(matches!(result, Err(PasskeyError::IdentityNotFound)));
    }

    #[test]
    fn test_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf());

        let username = "alice";

        // Generate and save
        let identity = Identity::generate("alice@example.com").unwrap();
        identity.save_for_user(&config, username).unwrap();

        // Check exists
        assert!(Identity::exists_for_user(&config, username));

        // Load
        let loaded = Identity::load_user(&config, username).unwrap();
        assert_eq!(loaded.fingerprint(), identity.fingerprint());
    }
}
