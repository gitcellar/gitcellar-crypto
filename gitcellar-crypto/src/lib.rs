//! GitCellar Crypto - Unified encryption library
//!
//! This crate provides identity management and encryption for GitCellar.
//! All encryption uses Sequoia (Rust OpenPGP) with GitCellar-managed keys.
//!
//! # Architecture
//!
//! This crate re-exports identity/recovery functionality from `gitcellar-identity`
//! (which wraps `passkey-core`) and provides GitCellar-specific encryption on top.
//!
//! # Key Storage (Multi-User)
//!
//! Keys are stored in the GitCellar config directory with multi-user support:
//! - Windows: `C:\Users\{user}\AppData\Roaming\gitcellar\users\{username}\identity\`
//! - macOS/Linux: `~/.config/gitcellar/users/{username}/identity/`
//!
//! # Example
//!
//! ```ignore
//! use gitcellar_crypto::{Identity, EncryptionEngine};
//!
//! // Generate a new identity
//! let identity = Identity::generate("user@example.com")?;
//! identity.save()?;
//!
//! // Create encryption engine
//! let engine = EncryptionEngine::from_default_identity()?;
//!
//! // Encrypt data
//! let encrypted = engine.encrypt_data(b"secret data")?;
//!
//! // Decrypt data
//! let decrypted = engine.decrypt_data(&encrypted)?;
//! ```

// Encryption-specific modules (GitCellar-specific, not in passkey-core)
pub mod encryption;
pub mod transfer;
pub mod cloud_backup;
pub mod broadcast;
pub mod canonical;
pub mod grant_signing;
mod error;

// Client machinery for an auditable append-only public-key log. In development
// and not yet shipped; feature-gated, and not included in the published crate.
#[cfg(feature = "key-directory")]
pub mod key_directory;
#[cfg(feature = "key-directory")]
pub use key_directory::*;

// Multi-Device Recovery (ADR-019) — hierarchical device identity.
// These modules are independent of the Sequoia OpenPGP encryption stack
// above and use raw Ed25519 over canonical CBOR for device-cert and
// revocation-cert transport. See the Multi-Device Recovery specification.
pub mod master;
pub mod device_cert;
pub mod revocation_cert;
pub mod keystore;
pub mod legacy_extract;

// Re-export identity types from gitcellar-identity (wraps passkey-core)
pub use gitcellar_identity::Identity;
pub use gitcellar_identity::PasskeyError;
pub use gitcellar_identity::PasskeyConfig;
pub use gitcellar_identity::config as gitcellar_config;
pub use gitcellar_identity::recovery::{RecoveryCode, generate_recovery_code, is_valid_phrase, find_invalid_words};
pub use gitcellar_identity::multi_user::{IdentityState, UserInfo};

// Re-export path functions from gitcellar-identity
pub use gitcellar_identity::{
    config_dir, users_dir, user_dir,
};

// L-3: the ONE machine-id derivation/validation pair (gitcellar-identity →
// passkey-core, `gcm` prefix, FULL fingerprint). Re-exported so consumers that
// only depend on gitcellar-crypto (the Service) delegate here instead of
// hand-rolling a copy — a second copy of a device-identity rule is exactly how
// the Service drifted to a 64-bit truncation while every other tier widened,
// and the Cloud then rejected every machine_id it claimed.
pub use gitcellar_identity::{is_valid_gcm_machine_id, machine_id as derive_machine_id};

// At-rest key wrap (F5 / DEC-LD-03) — re-exported so every consumer (desktop,
// cli, test-helper, migration) opens sealed key files through one entry point.
pub use gitcellar_identity::keywrap;

/// Open an at-rest-sealed OpenPGP secret key (`secret.pgp`), transparently
/// passing through a legacy (pre-F5) plaintext certificate (F5 / AC-F5.4).
///
/// Every raw reader of `secret.pgp` that parses the certificate (the MDR
/// migration, the grant-decrypt CLI, etc.) must funnel the file bytes through
/// this before `Cert::from_bytes`, so a sealed identity loads identically to a
/// legacy plaintext one.
pub fn open_secret_key_at_rest(raw: &[u8]) -> Result<Vec<u8>> {
    if keywrap::is_wrapped(raw) {
        keywrap::unwrap_at_rest(raw)
            .map_err(|e| CryptoError::KeyLoad(format!("secret key at-rest open failed: {e}")))
    } else {
        Ok(raw.to_vec())
    }
}
// Re-export identity module for load_active() etc.
pub use gitcellar_identity::identity as identity_ops;

// Convenience function for backward compatibility
/// Load the identity for the active user
///
/// This is a convenience function that wraps `gitcellar_identity::identity::load_active()`
pub fn load_active_identity() -> Result<Identity> {
    Ok(gitcellar_identity::identity::load_active()?)
}

/// Check if an identity exists for any user
///
/// Returns true if the system is in a ready or usable state
pub fn identity_exists() -> bool {
    match evaluate_state() {
        IdentityState::Ready { .. } => true,
        IdentityState::ReadyMultiUser { .. } => true,
        IdentityState::NeedsUserSelection { users } => !users.is_empty(),
        IdentityState::ActiveUserMissing { available, .. } => !available.is_empty(),
        IdentityState::NoIdentity | IdentityState::Corrupted { .. } => false,
    }
}

/// Get the identity directory for the current active user
///
/// Returns `config_dir()/users/{active_user}/identity/`
/// Falls back to `config_dir()/identity/` if no active user
pub fn identity_dir() -> PathBuf {
    if let Some(username) = get_active_user() {
        gitcellar_identity::identity_dir(&username)
    } else {
        // Fallback to legacy path
        config_dir().join("identity")
    }
}

/// Save identity for current active user, or create a default user
///
/// If no active user, creates "default" user and sets it as active
pub fn save_identity(identity: &Identity) -> Result<()> {
    let cfg = gitcellar_config();

    let username = if let Some(user) = get_active_user() {
        user
    } else {
        // Create default user if none exists
        let default_user = "default".to_string();
        if !user_exists(&default_user) {
            create_user(&default_user)?;
        }
        set_active_user(&default_user)?;
        default_user
    };

    identity.save_for_user(&cfg, &username)?;
    Ok(())
}
pub use gitcellar_identity::multi_user::{
    evaluate_state, list_users, get_active_user, set_active_user,
    get_user_info, get_current_user_info, is_multi_user,
    create_user, delete_user, user_exists, user_has_identity,
    clear_active_user, save_user_info,
};

// Local exports
pub use encryption::EncryptionEngine;
pub use encryption::object_key_prefix_hex;
// H-1: per-chunk identity bound into the AEAD — consumers construct this for
// every chunk seal/open (re-exported from vault-core).
pub use vault_core::chunk_format::ChunkAad;
pub use transfer::IdentityBundle;
pub use cloud_backup::{CloudBackupBundle, EncryptedPayload, PasskeyPayload};
pub use error::{CryptoError, Result};

// Multi-Device Recovery re-exports (ADR-019). Downstream consumers (Cloud API, Desktop
// migration and onboarding, Authorized Devices UI) import canonical types from these.
pub use master::{MasterKeyDerivation, MasterKeyError, MaterializedMaster};
pub use device_cert::{
    CertError, DeviceCertificate, DeviceCertificatePayload, SignerRole, MAX_LABEL_BYTES,
};
pub use revocation_cert::{
    RevocationCertError, RevocationCertificate, RevocationCertificatePayload, RevocationReason,
};
pub use keystore::{
    FileSystemKeystore, KeystoreBackend, KeystoreError, DEVICE_CERT_FILENAME,
    DEVICE_PRIVATE_FILENAME, DEVICE_PUBLIC_FILENAME, MASTER_PUBLIC_FILENAME,
};
pub use legacy_extract::{
    armored_public_key, extract_ed25519_keypair, extract_ed25519_public_key,
    LegacyEd25519Keypair, LegacyExtractError,
};
pub use broadcast::{
    action_url_allowed, verify_detached, BroadcastPayload, BroadcastTargeting, BroadcastTier,
    IncidentManifest, ManifestState, ManifestVerdict, ACTION_URL_ALLOWLIST,
    BROADCAST_PAYLOAD_VERSION, INCIDENT_MANIFEST_VERSION,
};

use std::path::PathBuf;

// GitCellar-specific path functions (not in passkey-core)

/// Get a user-specific data path
///
/// # Arguments
/// * `subpath` - The path relative to the user's data directory (e.g., "identity", "keyring")
///
/// # Multi-user mode
/// Returns `config_dir()/users/{active_user}/{subpath}`
///
/// # Single-user mode (fallback)
/// Returns `config_dir()/{subpath}` for backward compatibility
pub fn user_data_path(subpath: &str) -> PathBuf {
    if let Some(username) = get_active_user() {
        // Multi-user mode: users/<username>/<subpath>
        user_dir(&username).join(subpath)
    } else if is_multi_user() {
        // Multi-user structure exists but no active user - this shouldn't happen
        // Fall back to first user found
        let the_users_dir = config_dir().join("users");
        if let Ok(entries) = std::fs::read_dir(&the_users_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        return user_dir(name).join(subpath);
                    }
                }
            }
        }
        // Ultimate fallback
        config_dir().join(subpath)
    } else {
        // Single-user mode (legacy): config_dir/<subpath>
        config_dir().join(subpath)
    }
}

/// Get the keyring directory for the current user
///
/// In multi-user mode: `config_dir()/users/{active_user}/keyring/`
/// In single-user mode: `config_dir()/keyring/`
pub fn keyring_dir() -> PathBuf {
    user_data_path("keyring")
}

/// Get the registry database path for the current user
///
/// In multi-user mode: `config_dir()/users/{active_user}/registry.db`
/// In single-user mode: `config_dir()/registry.db`
pub fn registry_path() -> PathBuf {
    user_data_path("registry.db")
}

/// Get the user info path for the current user
///
/// In multi-user mode: `config_dir()/users/{active_user}/user_info.json`
/// In single-user mode: `config_dir()/identity/user_info.json` (legacy location)
pub fn user_info_path() -> PathBuf {
    if get_active_user().is_some() || is_multi_user() {
        user_data_path("user_info.json")
    } else {
        // Legacy: user_info.json was inside identity/
        config_dir().join("identity").join("user_info.json")
    }
}

/// Alias for gitcellar_identity::multi_user::UserInfo for backward compatibility
pub type StoredUserInfo = UserInfo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_dir_not_empty() {
        let dir = config_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn test_user_dir_is_subdir() {
        let config = config_dir();
        let user_path = user_dir("testuser");
        assert!(user_path.starts_with(&config));
    }

    #[test]
    fn test_user_dir_structure() {
        let user_path = user_dir("testuser");
        assert!(user_path.ends_with("users/testuser") || user_path.ends_with("users\\testuser"));
    }

    #[test]
    fn test_keyring_dir_is_subdir() {
        let config = config_dir();
        let keyring = keyring_dir();
        assert!(keyring.starts_with(&config));
    }

    #[test]
    fn test_registry_path_is_subpath() {
        let config = config_dir();
        let registry = registry_path();
        assert!(registry.starts_with(&config));
    }

    #[test]
    fn test_list_users_returns_vec() {
        // Should return an empty vec or a list of users, not panic
        let users = list_users();
        assert!(users.is_empty() || !users.is_empty());
    }
}
