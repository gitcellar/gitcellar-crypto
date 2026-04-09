//! Path configuration for passkey-core
//!
//! Provides configurable paths for identity storage, credentials, and user data.
//! Applications configure passkey-core with their app name and preferences.

mod platform;

pub use platform::*;

use std::path::PathBuf;

/// Configuration for passkey-core
///
/// Applications create a PasskeyConfig to customize behavior for their needs.
/// All path-related operations use this config to determine storage locations.
#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    /// Application name (used for paths and credential store service name)
    /// Example: "gitcellar", "foldergami", "vetiqbox"
    pub app_name: String,

    /// Machine ID prefix (e.g., "gcm" for "gcm-a1b2c3d4...")
    pub machine_id_prefix: String,

    /// Base config directory (None = platform default)
    pub config_dir: Option<PathBuf>,

    /// JWT settings (for applications that use JWT)
    #[cfg(feature = "jwt")]
    pub jwt_config: Option<JwtConfig>,
}

/// JWT configuration
#[cfg(feature = "jwt")]
#[derive(Clone, Debug)]
pub struct JwtConfig {
    /// Secret key for signing JWTs
    pub secret: String,
    /// Access token expiry in seconds
    pub access_token_expiry_secs: i64,
    /// Refresh token expiry in seconds
    pub refresh_token_expiry_secs: i64,
}

impl PasskeyConfig {
    /// Create a new configuration for an application
    ///
    /// # Arguments
    /// * `app_name` - The application name (used for storage paths)
    ///
    /// # Example
    /// ```
    /// use passkey_core::PasskeyConfig;
    /// let config = PasskeyConfig::new("myapp");
    /// ```
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            machine_id_prefix: app_name.chars().take(3).collect::<String>().to_lowercase(),
            config_dir: None,
            #[cfg(feature = "jwt")]
            jwt_config: None,
        }
    }

    /// Create configuration for GitCellar (pre-configured defaults)
    pub fn gitcellar() -> Self {
        Self {
            app_name: "gitcellar".to_string(),
            machine_id_prefix: "gcm".to_string(),
            config_dir: None,
            #[cfg(feature = "jwt")]
            jwt_config: None,
        }
    }

    /// Set a custom machine ID prefix
    pub fn with_machine_id_prefix(mut self, prefix: &str) -> Self {
        self.machine_id_prefix = prefix.to_string();
        self
    }

    /// Set a custom config directory (overrides platform default)
    pub fn with_config_dir(mut self, path: PathBuf) -> Self {
        self.config_dir = Some(path);
        self
    }

    /// Set JWT configuration
    #[cfg(feature = "jwt")]
    pub fn with_jwt_config(mut self, jwt_config: JwtConfig) -> Self {
        self.jwt_config = Some(jwt_config);
        self
    }

    /// Get the base config directory
    ///
    /// If a custom config_dir is set, uses that. Otherwise uses platform default.
    pub fn config_dir(&self) -> PathBuf {
        self.config_dir
            .clone()
            .unwrap_or_else(|| platform_config_dir(&self.app_name))
    }

    /// Get the users directory
    ///
    /// Returns `{config_dir}/users/`
    pub fn users_dir(&self) -> PathBuf {
        self.config_dir().join("users")
    }

    /// Get the directory for a specific user's data
    ///
    /// Returns `{config_dir}/users/{username}/`
    pub fn user_dir(&self, username: &str) -> PathBuf {
        self.users_dir().join(username)
    }

    /// Get a user-specific data path
    ///
    /// # Arguments
    /// * `username` - The username
    /// * `subpath` - The path relative to the user's directory (e.g., "identity", "keyring")
    ///
    /// Returns `{config_dir}/users/{username}/{subpath}`
    pub fn user_data_path(&self, username: &str, subpath: &str) -> PathBuf {
        self.user_dir(username).join(subpath)
    }

    /// Get the identity directory for a specific user
    ///
    /// Returns `{config_dir}/users/{username}/identity/`
    pub fn identity_dir(&self, username: &str) -> PathBuf {
        self.user_data_path(username, "identity")
    }

    /// Get the path to the active_user file
    ///
    /// Returns `{config_dir}/active_user`
    pub fn active_user_path(&self) -> PathBuf {
        self.config_dir().join("active_user")
    }

    /// Get the path to the machine_id file
    ///
    /// Returns `{config_dir}/machine_id`
    pub fn machine_id_path(&self) -> PathBuf {
        self.config_dir().join("machine_id")
    }

    /// Get the user info path for a specific user
    ///
    /// Returns `{config_dir}/users/{username}/user_info.json`
    pub fn user_info_path(&self, username: &str) -> PathBuf {
        self.user_data_path(username, "user_info.json")
    }
}

#[cfg(feature = "jwt")]
impl JwtConfig {
    /// Create a new JWT configuration
    pub fn new(secret: &str, access_expiry_secs: i64, refresh_expiry_secs: i64) -> Self {
        Self {
            secret: secret.to_string(),
            access_token_expiry_secs: access_expiry_secs,
            refresh_token_expiry_secs: refresh_expiry_secs,
        }
    }

    /// Create JWT config with default expiry times (1 hour access, 30 days refresh)
    pub fn with_secret(secret: &str) -> Self {
        Self {
            secret: secret.to_string(),
            access_token_expiry_secs: 3600,           // 1 hour
            refresh_token_expiry_secs: 30 * 24 * 3600, // 30 days
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_new_config() {
        let config = PasskeyConfig::new("testapp");
        assert_eq!(config.app_name, "testapp");
        assert_eq!(config.machine_id_prefix, "tes"); // First 3 chars
    }

    #[test]
    fn test_gitcellar_config() {
        let config = PasskeyConfig::gitcellar();
        assert_eq!(config.app_name, "gitcellar");
        assert_eq!(config.machine_id_prefix, "gcm");
    }

    #[test]
    fn test_with_config_dir() {
        let temp_dir = TempDir::new().unwrap();
        let config = PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf());

        assert_eq!(config.config_dir(), temp_dir.path());
    }

    #[test]
    fn test_path_structure() {
        let temp_dir = TempDir::new().unwrap();
        let config = PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf());

        let users_dir = config.users_dir();
        assert!(users_dir.ends_with("users"));

        let user_dir = config.user_dir("alice");
        assert!(user_dir.ends_with("alice"));

        let identity_dir = config.identity_dir("alice");
        assert!(identity_dir.ends_with("identity"));

        let user_info = config.user_info_path("alice");
        assert!(user_info.ends_with("user_info.json"));
    }

    #[test]
    fn test_active_user_path() {
        let temp_dir = TempDir::new().unwrap();
        let config = PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf());

        let active_user = config.active_user_path();
        assert!(active_user.ends_with("active_user"));
    }
}
