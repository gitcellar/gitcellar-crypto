//! Error types for vault-core
//!
//! Provides a unified error type that can be used across all modules
//! and converted to error codes for FFI.

use thiserror::Error;

/// Result type alias using VaultError
pub type VaultResult<T> = Result<T, VaultError>;

/// Unified error type for vault-core operations
#[derive(Error, Debug)]
pub enum VaultError {
    /// Chunking operation failed
    #[error("Chunking error: {0}")]
    Chunking(String),

    /// Encryption operation failed
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption operation failed
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Key not found or invalid
    #[error("Key error: {0}")]
    Key(String),

    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(String),

    /// Network/HTTP error
    #[error("Network error: {0}")]
    Network(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid input/argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Operation not supported
    #[error("Not supported: {0}")]
    NotSupported(String),

    /// Internal error (unexpected state)
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VaultError {
    /// Convert to an error code for FFI
    ///
    /// Error codes:
    /// - 0: Success (not an error)
    /// - 1: Chunking error
    /// - 2: Encryption error
    /// - 3: Decryption error
    /// - 4: Key error
    /// - 5: Storage error
    /// - 6: Network error
    /// - 7: Configuration error
    /// - 8: I/O error
    /// - 9: Invalid argument
    /// - 10: Not supported
    /// - 99: Internal/unknown error
    pub fn to_error_code(&self) -> i32 {
        match self {
            VaultError::Chunking(_) => 1,
            VaultError::Encryption(_) => 2,
            VaultError::Decryption(_) => 3,
            VaultError::Key(_) => 4,
            VaultError::Storage(_) => 5,
            VaultError::Network(_) => 6,
            VaultError::Config(_) => 7,
            VaultError::Io(_) => 8,
            VaultError::InvalidArgument(_) => 9,
            VaultError::NotSupported(_) => 10,
            VaultError::Internal(_) => 99,
        }
    }

    /// Create from an error code and message (for FFI)
    pub fn from_error_code(code: i32, message: String) -> Self {
        match code {
            1 => VaultError::Chunking(message),
            2 => VaultError::Encryption(message),
            3 => VaultError::Decryption(message),
            4 => VaultError::Key(message),
            5 => VaultError::Storage(message),
            6 => VaultError::Network(message),
            7 => VaultError::Config(message),
            8 => VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, message)),
            9 => VaultError::InvalidArgument(message),
            10 => VaultError::NotSupported(message),
            _ => VaultError::Internal(message),
        }
    }
}

// Conversion from anyhow::Error for easier integration
impl From<anyhow::Error> for VaultError {
    fn from(err: anyhow::Error) -> Self {
        VaultError::Internal(err.to_string())
    }
}

// Conversion from reqwest errors
impl From<reqwest::Error> for VaultError {
    fn from(err: reqwest::Error) -> Self {
        VaultError::Network(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let err = VaultError::Encryption("test".to_string());
        assert_eq!(err.to_error_code(), 2);

        let err = VaultError::Storage("test".to_string());
        assert_eq!(err.to_error_code(), 5);
    }

    #[test]
    fn test_error_roundtrip() {
        let original = VaultError::Key("missing key".to_string());
        let code = original.to_error_code();
        let restored = VaultError::from_error_code(code, "missing key".to_string());

        assert_eq!(code, 4);
        assert!(matches!(restored, VaultError::Key(_)));
    }

    #[test]
    fn test_error_display() {
        let err = VaultError::Chunking("file too small".to_string());
        assert_eq!(err.to_string(), "Chunking error: file too small");
    }
}
