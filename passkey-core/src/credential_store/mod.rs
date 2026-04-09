//! OS Credential Store Integration
//!
//! Provides secure storage for authentication tokens using platform-native
//! credential management:
//! - Windows: Credential Manager
//! - macOS: Keychain
//! - Linux: Secret Service (GNOME Keyring, KWallet, etc.)
//!
//! This module stores JWT tokens and refresh tokens - NOT identity keys,
//! which are stored as files in the user's config directory.

#[cfg(feature = "keyring")]
mod keyring_impl;
mod memory;

pub use memory::*;

use crate::error::{PasskeyError, Result};
use crate::paths::PasskeyConfig;

/// Trait for credential storage backends
///
/// Implementations provide secure storage for credentials.
pub trait CredentialBackend: Send + Sync {
    /// Store a value
    fn store(&self, key: &str, value: &str) -> Result<()>;

    /// Retrieve a value
    fn get(&self, key: &str) -> Result<Option<String>>;

    /// Delete a value
    fn delete(&self, key: &str) -> Result<()>;
}

/// Credential keys stored in the OS credential store
pub mod keys {
    pub const ACCESS_TOKEN: &str = "access_token";
    pub const REFRESH_TOKEN: &str = "refresh_token";
    pub const USER_ID: &str = "user_id";
    pub const USER_EMAIL: &str = "user_email";
    pub const TOKEN_EXPIRES_AT: &str = "token_expires_at";
    pub const RECOVERY_HASH: &str = "recovery_hash";
}

/// OS Credential Store wrapper
///
/// Stores authentication tokens in the platform's secure credential storage,
/// keeping them out of plaintext configuration files.
#[cfg(feature = "keyring")]
pub struct CredentialStore {
    service_name: String,
}

#[cfg(feature = "keyring")]
impl CredentialStore {
    /// Create a new credential store for an application
    pub fn new(config: &PasskeyConfig) -> Self {
        Self {
            service_name: config.app_name.clone(),
        }
    }

    /// Create with a custom service name
    pub fn with_service_name(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    /// Store the JWT access token
    pub fn store_access_token(&self, token: &str) -> Result<()> {
        self.store(keys::ACCESS_TOKEN, token)
    }

    /// Retrieve the JWT access token
    pub fn get_access_token(&self) -> Result<Option<String>> {
        self.get(keys::ACCESS_TOKEN)
    }

    /// Store the refresh token
    pub fn store_refresh_token(&self, token: &str) -> Result<()> {
        self.store(keys::REFRESH_TOKEN, token)
    }

    /// Retrieve the refresh token
    pub fn get_refresh_token(&self) -> Result<Option<String>> {
        self.get(keys::REFRESH_TOKEN)
    }

    /// Store the user ID
    pub fn store_user_id(&self, user_id: &str) -> Result<()> {
        self.store(keys::USER_ID, user_id)
    }

    /// Retrieve the user ID
    pub fn get_user_id(&self) -> Result<Option<String>> {
        self.get(keys::USER_ID)
    }

    /// Store the user email
    pub fn store_user_email(&self, email: &str) -> Result<()> {
        self.store(keys::USER_EMAIL, email)
    }

    /// Retrieve the user email
    pub fn get_user_email(&self) -> Result<Option<String>> {
        self.get(keys::USER_EMAIL)
    }

    /// Store the token expiration timestamp (Unix seconds)
    pub fn store_token_expires_at(&self, expires_at: i64) -> Result<()> {
        self.store(keys::TOKEN_EXPIRES_AT, &expires_at.to_string())
    }

    /// Retrieve the token expiration timestamp
    pub fn get_token_expires_at(&self) -> Result<Option<i64>> {
        match self.get(keys::TOKEN_EXPIRES_AT)? {
            Some(s) => s.parse()
                .map(Some)
                .map_err(|_| PasskeyError::CredentialStore("Invalid expiration timestamp".to_string())),
            None => Ok(None),
        }
    }

    /// Store all credentials at once (convenience method for login)
    pub fn store_all(
        &self,
        access_token: &str,
        refresh_token: &str,
        user_id: &str,
        email: &str,
        expires_at: i64,
    ) -> Result<()> {
        self.store_access_token(access_token)?;
        self.store_refresh_token(refresh_token)?;
        self.store_user_id(user_id)?;
        self.store_user_email(email)?;
        self.store_token_expires_at(expires_at)?;

        tracing::info!("Stored credentials in OS credential store for user: {}", email);
        Ok(())
    }

    /// Check if user is logged in (has valid credentials stored)
    pub fn is_logged_in(&self) -> bool {
        self.get_access_token()
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    /// Store the recovery key hash
    pub fn store_recovery_hash(&self, hash: &str) -> Result<()> {
        self.store(keys::RECOVERY_HASH, hash)
    }

    /// Retrieve the recovery key hash
    pub fn get_recovery_hash(&self) -> Result<Option<String>> {
        self.get(keys::RECOVERY_HASH)
    }

    /// Clear all stored credentials (for logout)
    ///
    /// Note: Does NOT clear the recovery hash - that persists across logouts
    /// to support account recovery.
    pub fn clear_all(&self) -> Result<()> {
        let keys_to_clear = [
            keys::ACCESS_TOKEN,
            keys::REFRESH_TOKEN,
            keys::USER_ID,
            keys::USER_EMAIL,
            keys::TOKEN_EXPIRES_AT,
            // Note: RECOVERY_HASH is intentionally NOT cleared on logout
        ];

        for key in keys_to_clear {
            if let Err(e) = self.delete(key) {
                tracing::debug!("Could not delete credential '{}': {}", key, e);
            }
        }

        tracing::info!("Cleared all credentials from OS credential store");
        Ok(())
    }
}
