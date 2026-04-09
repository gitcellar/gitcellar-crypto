//! GitCellar Identity - GitCellar-specific wrapper for passkey-core
//!
//! This crate provides GitCellar-specific defaults for the passkey-core library,
//! making it easy to use identity management with GitCellar's conventions.
//!
//! # Quick Start
//!
//! ```ignore
//! use gitcellar_identity::{Identity, config};
//! use gitcellar_identity::multi_user::{evaluate_state, IdentityState};
//!
//! // Use GitCellar's pre-configured settings
//! let cfg = config();
//!
//! match evaluate_state(&cfg) {
//!     IdentityState::Ready { username } => {
//!         let identity = Identity::load_user(&cfg, &username)?;
//!         println!("Machine ID: {}", gitcellar_identity::machine_id(&identity));
//!     }
//!     IdentityState::NoIdentity => {
//!         // Show onboarding...
//!     }
//!     _ => {}
//! }
//! ```
//!
//! # Configuration
//!
//! GitCellar uses these defaults:
//! - App name: `gitcellar`
//! - Machine ID prefix: `gcm`
//! - Config directory: Platform default (`~/.config/gitcellar` or `%APPDATA%\gitcellar`)

// Re-export everything from passkey-core
pub use passkey_core::*;

/// Get the GitCellar-configured PasskeyConfig
///
/// Returns a config with GitCellar-specific defaults:
/// - app_name: "gitcellar"
/// - machine_id_prefix: "gcm"
///
/// # Example
/// ```
/// use gitcellar_identity::config;
/// let cfg = config();
/// assert_eq!(cfg.app_name, "gitcellar");
/// ```
pub fn config() -> PasskeyConfig {
    PasskeyConfig::gitcellar()
}

/// Alias for config() - returns GitCellar configuration
pub fn gitcellar_config() -> PasskeyConfig {
    config()
}

// Convenience functions that use GitCellar defaults

/// Generate machine ID from an identity using GitCellar prefix
pub fn machine_id(identity: &Identity) -> String {
    derive_machine_id_from_identity(&config(), identity)
}

/// Validate machine ID format using GitCellar prefix
pub fn is_valid_gcm_machine_id(machine_id: &str) -> bool {
    is_valid_machine_id(&config(), machine_id)
}

/// Check if identity exists for a user
pub fn identity_exists(username: &str) -> bool {
    Identity::exists_for_user(&config(), username)
}

/// Module with GitCellar-defaulted identity functions
pub mod identity {
    use super::*;

    /// Generate a new identity
    pub fn generate(user_id: &str) -> Result<Identity> {
        Identity::generate(user_id)
    }

    /// Load identity for a specific user
    pub fn load(username: &str) -> Result<Identity> {
        Identity::load_user(&config(), username)
    }

    /// Load identity for the active user
    pub fn load_active() -> Result<Identity> {
        let cfg = config();
        let username = get_active_user(&cfg)
            .ok_or(PasskeyError::NoActiveUser)?;
        Identity::load_user(&cfg, &username)
    }

    /// Check if identity exists for a user
    pub fn exists(username: &str) -> bool {
        Identity::exists_for_user(&config(), username)
    }

    /// Save identity for a user
    pub fn save(identity: &Identity, username: &str) -> Result<()> {
        identity.save_for_user(&config(), username)
    }
}

/// Module with GitCellar-defaulted multi-user functions
pub mod multi_user {
    pub use passkey_core::multi_user::*;
    use super::*;

    /// Evaluate identity state using GitCellar config
    pub fn evaluate_state() -> IdentityState {
        passkey_core::evaluate_state(&config())
    }

    /// Repair identity state issues
    pub fn repair_state() -> Result<IdentityState> {
        passkey_core::repair_state(&config())
    }

    /// List all users
    pub fn list_users() -> Vec<String> {
        passkey_core::list_users(&config())
    }

    /// Get active user
    pub fn get_active_user() -> Option<String> {
        passkey_core::get_active_user(&config())
    }

    /// Set active user
    pub fn set_active_user(username: &str) -> Result<()> {
        passkey_core::set_active_user(&config(), username)
    }

    /// Clear active user
    pub fn clear_active_user() -> Result<()> {
        passkey_core::clear_active_user(&config())
    }

    /// Check if multi-user mode is active
    pub fn is_multi_user() -> bool {
        passkey_core::is_multi_user(&config())
    }

    /// Get user info for a specific user
    pub fn get_user_info(username: &str) -> Option<UserInfo> {
        passkey_core::get_user_info(&config(), username)
    }

    /// Save user info for a specific user
    pub fn save_user_info(username: &str, info: &UserInfo) -> Result<()> {
        passkey_core::save_user_info(&config(), username, info)
    }

    /// Get user info for current active user
    pub fn get_current_user_info() -> Option<UserInfo> {
        passkey_core::get_current_user_info(&config())
    }

    /// Create a new user directory
    pub fn create_user(username: &str) -> Result<()> {
        passkey_core::create_user(&config(), username)
    }

    /// Delete a user and all their data
    pub fn delete_user(username: &str) -> Result<()> {
        passkey_core::delete_user(&config(), username)
    }

    /// Check if a user exists
    pub fn user_exists(username: &str) -> bool {
        passkey_core::user_exists(&config(), username)
    }

    /// Check if a user has an identity
    pub fn user_has_identity(username: &str) -> bool {
        passkey_core::user_has_identity(&config(), username)
    }
}

/// Module with GitCellar-defaulted auth functions
pub mod auth {
    pub use passkey_core::auth::*;
    use super::*;

    /// Derive machine ID from an identity
    pub fn derive_machine_id(identity: &Identity) -> String {
        derive_machine_id_from_identity(&config(), identity)
    }

    /// Derive machine ID from a public key
    pub fn derive_machine_id_from_public_key(public_key: &str) -> Result<String> {
        passkey_core::derive_machine_id(&config(), public_key)
    }

    /// Verify machine ID matches a public key
    pub fn verify_machine_id(public_key: &str, claimed_machine_id: &str) -> Result<bool> {
        passkey_core::verify_machine_id(&config(), public_key, claimed_machine_id)
    }

    /// Validate machine ID format (gcm-xxxx)
    pub fn is_valid_machine_id(machine_id: &str) -> bool {
        passkey_core::is_valid_machine_id(&config(), machine_id)
    }
}

/// Module with GitCellar-defaulted credential store
#[cfg(feature = "keyring")]
pub mod credentials {
    use super::*;

    /// Create credential store with GitCellar service name
    pub fn store() -> CredentialStore {
        CredentialStore::new(&config())
    }
}

/// Module with recovery code functions (re-exported as-is)
pub mod recovery {
    pub use passkey_core::recovery::*;
    pub use passkey_core::{generate_recovery_code, is_valid_phrase, find_invalid_words};
}

/// Get the GitCellar config directory path
pub fn config_dir() -> std::path::PathBuf {
    config().config_dir()
}

/// Get the users directory path
pub fn users_dir() -> std::path::PathBuf {
    config().users_dir()
}

/// Get a specific user's directory path
pub fn user_dir(username: &str) -> std::path::PathBuf {
    config().user_dir(username)
}

/// Get the identity directory for a specific user
pub fn identity_dir(username: &str) -> std::path::PathBuf {
    config().identity_dir(username)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_defaults() {
        let cfg = config();
        assert_eq!(cfg.app_name, "gitcellar");
        assert_eq!(cfg.machine_id_prefix, "gcm");
    }

    #[test]
    fn test_machine_id_generation() {
        let identity = Identity::generate("test@example.com").unwrap();
        let mid = machine_id(&identity);

        assert!(mid.starts_with("gcm-"));
        assert!(is_valid_gcm_machine_id(&mid));
    }

    #[test]
    fn test_identity_workflow() {
        // This test uses a temp directory to avoid affecting real config
        let temp_dir = TempDir::new().unwrap();
        let cfg = PasskeyConfig::gitcellar()
            .with_config_dir(temp_dir.path().to_path_buf());

        // Create user
        passkey_core::create_user(&cfg, "testuser").unwrap();

        // Generate and save identity
        let identity = Identity::generate("test@example.com").unwrap();
        identity.save_for_user(&cfg, "testuser").unwrap();

        // Set as active
        passkey_core::set_active_user(&cfg, "testuser").unwrap();

        // Verify state
        let state = passkey_core::evaluate_state(&cfg);
        assert!(matches!(state, IdentityState::Ready { username } if username == "testuser"));
    }

    #[test]
    fn test_recovery_code() {
        let code = generate_recovery_code().unwrap();
        let phrase = code.phrase();

        // Re-parse
        let restored = RecoveryCode::from_phrase(&phrase).unwrap();
        assert_eq!(code.derive_key_material(), restored.derive_key_material());
    }
}
