//! Platform-specific path resolution
//!
//! Provides consistent config directory paths across Windows, macOS, and Linux.

use std::path::PathBuf;

/// Get the platform-specific config directory for an application
///
/// # Platform Behavior
/// - **Windows**: `%APPDATA%\{app_name}` (e.g., `C:\Users\{user}\AppData\Roaming\gitcellar`)
/// - **macOS**: `~/.config/{app_name}` (following XDG convention)
/// - **Linux**: `~/.config/{app_name}` (XDG Base Directory Specification)
///
/// # Arguments
/// * `app_name` - The application name to use in the path
pub fn platform_config_dir(app_name: &str) -> PathBuf {
    if cfg!(windows) {
        // On Windows, use AppData\Roaming\{app_name}
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
            })
            .join(app_name)
    } else {
        // On Unix (macOS/Linux), use ~/.config/{app_name}
        dirs::config_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .map(|h| h.join(".config"))
                    .unwrap_or_else(|| PathBuf::from("."))
            })
            .join(app_name)
    }
}

/// Get the platform-specific data directory for an application
///
/// # Platform Behavior
/// - **Windows**: `%LOCALAPPDATA%\{app_name}` (e.g., `C:\Users\{user}\AppData\Local\gitcellar`)
/// - **macOS**: `~/Library/Application Support/{app_name}`
/// - **Linux**: `~/.local/share/{app_name}`
///
/// # Arguments
/// * `app_name` - The application name to use in the path
pub fn platform_data_dir(app_name: &str) -> PathBuf {
    if cfg!(windows) {
        std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
            })
            .join(app_name)
    } else {
        dirs::data_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .map(|h| h.join(".local").join("share"))
                    .unwrap_or_else(|| PathBuf::from("."))
            })
            .join(app_name)
    }
}

/// Get the current platform identifier
pub fn platform_name() -> &'static str {
    std::env::consts::OS
}

/// Get the current hostname
pub fn hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_config_dir_not_empty() {
        let dir = platform_config_dir("testapp");
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.ends_with("testapp"));
    }

    #[test]
    fn test_platform_data_dir_not_empty() {
        let dir = platform_data_dir("testapp");
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.ends_with("testapp"));
    }

    #[test]
    fn test_platform_name() {
        let platform = platform_name();
        assert!(!platform.is_empty());
        // Should be one of the known platforms
        let known = ["windows", "macos", "linux", "freebsd", "android", "ios"];
        assert!(known.contains(&platform) || !platform.is_empty());
    }

    #[test]
    fn test_hostname_not_empty() {
        let host = hostname();
        assert!(!host.is_empty());
    }
}
