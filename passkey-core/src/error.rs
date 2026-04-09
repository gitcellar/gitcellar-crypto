//! Error types for passkey-core
//!
//! Provides a unified error type for all passkey-core operations.

use thiserror::Error;

/// Result type for passkey-core operations
pub type Result<T> = std::result::Result<T, PasskeyError>;

/// Errors that can occur during passkey-core operations
#[derive(Error, Debug)]
pub enum PasskeyError {
    // Identity errors
    /// Identity not found at expected location
    #[error("Identity not found")]
    IdentityNotFound,

    /// Identity already exists at the specified location
    #[error("Identity already exists at {0}")]
    IdentityExists(String),

    /// Failed to generate cryptographic key
    #[error("Failed to generate key: {0}")]
    KeyGeneration(String),

    /// Failed to load key from storage
    #[error("Failed to load key: {0}")]
    KeyLoad(String),

    /// Failed to save key to storage
    #[error("Failed to save key: {0}")]
    KeySave(String),

    // Auth errors
    /// Invalid public key format or content
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Signature verification failed
    #[error("Invalid signature")]
    InvalidSignature,

    /// Machine ID format is invalid
    #[error("Invalid machine ID format")]
    InvalidMachineId,

    /// Challenge has expired
    #[error("Challenge expired")]
    ChallengeExpired,

    // JWT errors
    /// JWT token is invalid
    #[error("Invalid token")]
    InvalidToken,

    /// JWT token has expired
    #[error("Token expired")]
    TokenExpired,

    // Recovery errors
    /// Recovery code/phrase is invalid
    #[error("Invalid recovery code: {0}")]
    InvalidRecoveryCode(String),

    // Credential store errors
    /// Error accessing credential store
    #[error("Credential store error: {0}")]
    CredentialStore(String),

    // Multi-user errors
    /// No active user is set
    #[error("No active user")]
    NoActiveUser,

    /// Specified user was not found
    #[error("User not found: {0}")]
    UserNotFound(String),

    // General errors
    /// IO operation failed
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// OpenPGP operation failed
    #[error("OpenPGP error: {0}")]
    OpenPgp(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for PasskeyError {
    fn from(err: anyhow::Error) -> Self {
        PasskeyError::Other(err.to_string())
    }
}

impl From<sequoia_openpgp::Error> for PasskeyError {
    fn from(err: sequoia_openpgp::Error) -> Self {
        PasskeyError::OpenPgp(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PasskeyError::IdentityNotFound;
        assert_eq!(err.to_string(), "Identity not found");

        let err = PasskeyError::InvalidRecoveryCode("wrong word count".to_string());
        assert_eq!(err.to_string(), "Invalid recovery code: wrong word count");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: PasskeyError = io_err.into();
        assert!(matches!(err, PasskeyError::Io(_)));
    }
}
