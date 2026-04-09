//! passkey-core - Cross-platform PassKey-native authentication library
//!
//! Provides Ed25519 identity management, challenge-response authentication,
//! BIP39 recovery codes, and multi-user support.
//!
//! # Overview
//!
//! passkey-core eliminates passwords entirely by using Ed25519 keypairs for authentication:
//!
//! 1. **Identity** - Generate and manage Ed25519/X25519 OpenPGP certificates
//! 2. **Authentication** - Challenge-response signature verification
//! 3. **Recovery** - BIP39 24-word mnemonic phrases for account recovery
//! 4. **Multi-user** - Support for multiple identities on a single machine
//!
//! # Quick Start
//!
//! ```ignore
//! use passkey_core::{Identity, PasskeyConfig, generate_recovery_code};
//! use passkey_core::multi_user::{evaluate_state, IdentityState};
//!
//! // Configure for your application
//! let config = PasskeyConfig::new("myapp");
//!
//! // Check current identity state
//! match evaluate_state(&config) {
//!     IdentityState::NoIdentity => {
//!         // Onboarding flow
//!         let identity = Identity::generate("user@example.com")?;
//!         let recovery = generate_recovery_code()?;
//!         println!("Save this: {}", recovery.format_for_display());
//!
//!         identity.save_for_user(&config, "username")?;
//!     }
//!     IdentityState::Ready { username } => {
//!         println!("Ready with user: {}", username);
//!     }
//!     // ... handle other states
//! }
//! ```
//!
//! # Features
//!
//! - `keyring` (default) - OS keyring integration for credential storage
//! - `jwt` (default) - JWT token generation and validation
//! - `ffi` - C-compatible FFI exports
//!
//! # Directory Structure
//!
//! passkey-core uses a multi-user directory structure:
//!
//! ```text
//! {config_dir}/
//! ├── active_user           # Current username
//! ├── machine_id            # Machine identifier
//! └── users/
//!     └── {username}/
//!         ├── identity/
//!         │   ├── secret.pgp
//!         │   └── public.pgp
//!         └── user_info.json
//! ```
//!
//! # Platform Support
//!
//! - Windows (CNG crypto backend)
//! - macOS (Nettle crypto backend)
//! - Linux (Nettle crypto backend)

// Core modules
pub mod error;
pub mod paths;
pub mod identity;
pub mod recovery;
pub mod auth;
pub mod credential_store;
pub mod multi_user;

// Re-exports for convenience
pub use error::{PasskeyError, Result};
pub use paths::{PasskeyConfig, platform_config_dir, platform_data_dir, hostname, platform_name};

#[cfg(feature = "jwt")]
pub use paths::JwtConfig;

pub use identity::{Identity, parse_public_key};
pub use identity::{identity_exists_at, delete_identity_at, ensure_identity_dir};

pub use recovery::{RecoveryCode, generate_recovery_code, is_valid_phrase, find_invalid_words};
pub use recovery::{get_word_list, is_valid_word, get_word_suggestions, find_closest_word};
pub use recovery::RECOVERY_CODE_WORD_COUNT;

pub use auth::{generate_challenge, generate_timestamped_challenge, is_challenge_valid};
pub use auth::{derive_machine_id, derive_machine_id_from_identity, derive_machine_id_from_cert};
pub use auth::{verify_machine_id, is_valid_machine_id, is_valid_machine_id_format};
pub use auth::{verify_detached_signature, verify_detached_signature_with_cert};
pub use auth::{parse_signature_base64, parse_signature_hex};

#[cfg(feature = "jwt")]
pub use auth::{Claims, TokenPair, generate_access_token, generate_refresh_token,
               generate_token_pair, hash_refresh_token, validate_access_token};

#[cfg(feature = "keyring")]
pub use credential_store::CredentialStore;
pub use credential_store::{CredentialBackend, MemoryCredentialStore, keys as credential_keys};

pub use multi_user::{
    IdentityState, evaluate_state, repair_state,
    UserInfo, is_multi_user, get_active_user, set_active_user, clear_active_user,
    list_users, get_user_info, save_user_info, get_current_user_info,
    create_user, delete_user, user_exists, user_has_identity,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_full_workflow() {
        let temp_dir = TempDir::new().unwrap();
        let config = PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf());

        // Initially no identity
        assert_eq!(evaluate_state(&config), IdentityState::NoIdentity);

        // Generate identity and recovery code
        let identity = Identity::generate("test@example.com").unwrap();
        let recovery = generate_recovery_code().unwrap();

        // Create user and save identity
        let username = "testuser";
        create_user(&config, username).unwrap();
        identity.save_for_user(&config, username).unwrap();

        // Set as active
        set_active_user(&config, username).unwrap();

        // Should be ready now
        let state = evaluate_state(&config);
        assert!(matches!(state, IdentityState::Ready { .. }));
        assert!(state.is_ready());

        // Verify recovery code works
        let key1 = recovery.derive_key_material();
        let phrase = recovery.phrase();
        let recovered = RecoveryCode::from_phrase(&phrase).unwrap();
        let key2 = recovered.derive_key_material();
        assert_eq!(key1, key2);

        // Verify machine ID derivation
        let machine_id = derive_machine_id_from_identity(&config, &identity);
        assert!(is_valid_machine_id(&config, &machine_id));

        // Challenge generation
        let challenge = generate_challenge();
        assert_eq!(challenge.len(), 64);
    }

    #[test]
    fn test_config_gitcellar() {
        let config = PasskeyConfig::gitcellar();
        assert_eq!(config.app_name, "gitcellar");
        assert_eq!(config.machine_id_prefix, "gcm");
    }

    #[test]
    fn test_memory_credential_store() {
        let store = MemoryCredentialStore::new();

        store.store("key", "value").unwrap();
        assert_eq!(store.get("key").unwrap(), Some("value".to_string()));

        store.delete("key").unwrap();
        assert_eq!(store.get("key").unwrap(), None);
    }
}
