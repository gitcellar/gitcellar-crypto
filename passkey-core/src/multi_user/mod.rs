//! Multi-user identity management
//!
//! Provides support for multiple user identities on a single machine.
//! Each user has their own identity directory under `{config}/users/{username}/`.
//!
//! # Directory Structure
//!
//! ```text
//! {config}/
//! ├── active_user                  # Contains the current username
//! └── users/
//!     ├── alice/
//!     │   ├── identity/
//!     │   │   ├── secret.pgp
//!     │   │   └── public.pgp
//!     │   └── user_info.json
//!     └── bob/
//!         ├── identity/
//!         │   ├── secret.pgp
//!         │   └── public.pgp
//!         └── user_info.json
//! ```
//!
//! # Clean Slate Design
//!
//! This module implements only the multi-user structure. There are no
//! legacy single-user fallback paths - if an identity doesn't exist in
//! the multi-user structure, the state is `NoIdentity`.

mod state_machine;

pub use state_machine::*;

use crate::error::{PasskeyError, Result};
use crate::paths::PasskeyConfig;
use serde::{Deserialize, Serialize};

/// User info structure (matches user_info.json format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User's email address
    pub email: String,
    /// Username
    pub username: String,
    /// Machine ID (derived from identity)
    pub machine_id: String,
    /// Cloud API user ID (UUID string)
    pub user_id: String,
}

/// Check if this is a multi-user installation
///
/// Returns true if the `users/` directory exists and contains at least one user.
pub fn is_multi_user(config: &PasskeyConfig) -> bool {
    let users_dir = config.users_dir();
    if !users_dir.exists() {
        return false;
    }

    // Check if there's at least one user directory
    if let Ok(entries) = std::fs::read_dir(&users_dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                return true;
            }
        }
    }

    false
}

/// Get the active user's username
///
/// Reads from the `active_user` file in the config directory.
pub fn get_active_user(config: &PasskeyConfig) -> Option<String> {
    let active_user_path = config.active_user_path();

    if !active_user_path.exists() {
        return None;
    }

    std::fs::read_to_string(&active_user_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Set the active user
///
/// Writes the username to the `active_user` file.
pub fn set_active_user(config: &PasskeyConfig, username: &str) -> Result<()> {
    let active_user_path = config.active_user_path();

    // Ensure parent directory exists
    if let Some(parent) = active_user_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&active_user_path, username)?;
    tracing::info!("Set active user to: {}", username);
    Ok(())
}

/// Clear the active user
///
/// Removes the `active_user` file.
pub fn clear_active_user(config: &PasskeyConfig) -> Result<()> {
    let active_user_path = config.active_user_path();

    if active_user_path.exists() {
        std::fs::remove_file(&active_user_path)?;
        tracing::info!("Cleared active user");
    }

    Ok(())
}

/// List all users in the multi-user directory
///
/// Returns an empty vector if no users exist.
pub fn list_users(config: &PasskeyConfig) -> Vec<String> {
    let users_dir = config.users_dir();

    if !users_dir.exists() {
        return Vec::new();
    }

    let mut users = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&users_dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    users.push(name.to_string());
                }
            }
        }
    }

    users.sort();
    users
}

/// Get user info for a specific user
///
/// Reads from `{config}/users/{username}/user_info.json`
pub fn get_user_info(config: &PasskeyConfig, username: &str) -> Option<UserInfo> {
    let user_info_path = config.user_info_path(username);

    if !user_info_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&user_info_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save user info for a specific user
///
/// Writes to `{config}/users/{username}/user_info.json`
pub fn save_user_info(config: &PasskeyConfig, username: &str, info: &UserInfo) -> Result<()> {
    let user_info_path = config.user_info_path(username);

    // Ensure parent directory exists
    if let Some(parent) = user_info_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(info)
        .map_err(|e| PasskeyError::Other(format!("Failed to serialize user info: {}", e)))?;

    std::fs::write(&user_info_path, content)?;
    tracing::debug!("Saved user info for: {}", username);
    Ok(())
}

/// Get user info for the current active user
pub fn get_current_user_info(config: &PasskeyConfig) -> Option<UserInfo> {
    let username = get_active_user(config)?;
    get_user_info(config, &username)
}

/// Create a new user directory structure
///
/// Creates the user directory and identity subdirectory.
/// Does NOT create identity files - use Identity::save_for_user for that.
pub fn create_user(config: &PasskeyConfig, username: &str) -> Result<()> {
    let user_dir = config.user_dir(username);
    let identity_dir = config.identity_dir(username);

    std::fs::create_dir_all(&identity_dir)?;
    tracing::info!("Created user directory: {:?}", user_dir);

    Ok(())
}

/// Delete a user and all their data
///
/// Removes the entire user directory including identity files.
pub fn delete_user(config: &PasskeyConfig, username: &str) -> Result<()> {
    let user_dir = config.user_dir(username);

    if user_dir.exists() {
        std::fs::remove_dir_all(&user_dir)?;
        tracing::info!("Deleted user: {}", username);
    }

    // If this was the active user, clear the active user file
    if get_active_user(config).as_deref() == Some(username) {
        clear_active_user(config)?;
    }

    Ok(())
}

/// Check if a user exists
pub fn user_exists(config: &PasskeyConfig, username: &str) -> bool {
    config.user_dir(username).exists()
}

/// Check if a user has an identity
pub fn user_has_identity(config: &PasskeyConfig, username: &str) -> bool {
    config.identity_dir(username).join("secret.pgp").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use tempfile::TempDir;

    fn test_config(temp_dir: &TempDir) -> PasskeyConfig {
        PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf())
    }

    #[test]
    fn test_is_multi_user_empty() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        assert!(!is_multi_user(&config));
    }

    #[test]
    fn test_is_multi_user_with_users() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        // Create a user
        create_user(&config, "alice").unwrap();

        assert!(is_multi_user(&config));
    }

    #[test]
    fn test_active_user() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        // Initially none
        assert!(get_active_user(&config).is_none());

        // Set active user
        set_active_user(&config, "alice").unwrap();
        assert_eq!(get_active_user(&config), Some("alice".to_string()));

        // Change active user
        set_active_user(&config, "bob").unwrap();
        assert_eq!(get_active_user(&config), Some("bob".to_string()));

        // Clear active user
        clear_active_user(&config).unwrap();
        assert!(get_active_user(&config).is_none());
    }

    #[test]
    fn test_list_users() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        // Initially empty
        assert!(list_users(&config).is_empty());

        // Create users
        create_user(&config, "bob").unwrap();
        create_user(&config, "alice").unwrap();
        create_user(&config, "charlie").unwrap();

        let users = list_users(&config);
        assert_eq!(users, vec!["alice", "bob", "charlie"]); // Sorted
    }

    #[test]
    fn test_user_info() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user(&config, "alice").unwrap();

        let info = UserInfo {
            email: "alice@example.com".to_string(),
            username: "alice".to_string(),
            machine_id: "tst-1234567890abcdef".to_string(),
            user_id: "uuid-here".to_string(),
        };

        save_user_info(&config, "alice", &info).unwrap();

        let loaded = get_user_info(&config, "alice").unwrap();
        assert_eq!(loaded.email, "alice@example.com");
        assert_eq!(loaded.username, "alice");
    }

    #[test]
    fn test_create_and_delete_user() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        // Create user
        create_user(&config, "alice").unwrap();
        assert!(user_exists(&config, "alice"));
        assert!(!user_has_identity(&config, "alice")); // No identity yet

        // Add identity
        let identity = Identity::generate("alice@example.com").unwrap();
        identity.save_for_user(&config, "alice").unwrap();
        assert!(user_has_identity(&config, "alice"));

        // Set as active
        set_active_user(&config, "alice").unwrap();

        // Delete user
        delete_user(&config, "alice").unwrap();
        assert!(!user_exists(&config, "alice"));
        assert!(get_active_user(&config).is_none()); // Active user cleared
    }

    #[test]
    fn test_get_current_user_info() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        // No active user
        assert!(get_current_user_info(&config).is_none());

        // Create user and set active
        create_user(&config, "alice").unwrap();
        let info = UserInfo {
            email: "alice@example.com".to_string(),
            username: "alice".to_string(),
            machine_id: "tst-1234567890abcdef".to_string(),
            user_id: "uuid-here".to_string(),
        };
        save_user_info(&config, "alice", &info).unwrap();
        set_active_user(&config, "alice").unwrap();

        // Should get alice's info
        let current = get_current_user_info(&config).unwrap();
        assert_eq!(current.username, "alice");
    }
}
