//! Identity storage utilities
//!
//! Provides helper functions for managing identity files.

use crate::error::{PasskeyError, Result};
use crate::paths::PasskeyConfig;
use std::path::Path;

/// Check if identity files exist at a path
pub fn identity_exists_at(path: &Path) -> bool {
    path.join("secret.pgp").exists()
}

/// Delete identity files at a path
///
/// Removes both secret.pgp and public.pgp files.
/// Does NOT remove the directory itself.
pub fn delete_identity_at(path: &Path) -> Result<()> {
    let secret_path = path.join("secret.pgp");
    let public_path = path.join("public.pgp");

    if secret_path.exists() {
        std::fs::remove_file(&secret_path)
            .map_err(|e| PasskeyError::Io(e))?;
    }

    if public_path.exists() {
        std::fs::remove_file(&public_path)
            .map_err(|e| PasskeyError::Io(e))?;
    }

    Ok(())
}

/// Delete identity for a specific user
pub fn delete_user_identity(config: &PasskeyConfig, username: &str) -> Result<()> {
    let identity_path = config.identity_dir(username);
    delete_identity_at(&identity_path)
}

/// Ensure the identity directory exists for a user
pub fn ensure_identity_dir(config: &PasskeyConfig, username: &str) -> Result<()> {
    let identity_path = config.identity_dir(username);
    std::fs::create_dir_all(&identity_path)
        .map_err(|e| PasskeyError::Io(e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use tempfile::TempDir;

    #[test]
    fn test_identity_exists_at() {
        let temp_dir = TempDir::new().unwrap();

        // Initially doesn't exist
        assert!(!identity_exists_at(temp_dir.path()));

        // Create identity
        let identity = Identity::generate("test@example.com").unwrap();
        identity.save_to(temp_dir.path()).unwrap();

        // Now exists
        assert!(identity_exists_at(temp_dir.path()));
    }

    #[test]
    fn test_delete_identity() {
        let temp_dir = TempDir::new().unwrap();

        // Create identity
        let identity = Identity::generate("test@example.com").unwrap();
        identity.save_to(temp_dir.path()).unwrap();

        // Verify exists
        assert!(identity_exists_at(temp_dir.path()));

        // Delete
        delete_identity_at(temp_dir.path()).unwrap();

        // Verify gone
        assert!(!identity_exists_at(temp_dir.path()));
    }

    #[test]
    fn test_ensure_identity_dir() {
        let temp_dir = TempDir::new().unwrap();
        let config = PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf());

        // Directory shouldn't exist yet
        let identity_path = config.identity_dir("alice");
        assert!(!identity_path.exists());

        // Ensure it
        ensure_identity_dir(&config, "alice").unwrap();

        // Now exists
        assert!(identity_path.exists());
    }
}
