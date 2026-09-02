//! Error types for gitcellar-crypto

use thiserror::Error;

/// Result type for gitcellar-crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors that can occur during crypto operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Identity not found at expected location
    #[error("Identity not found. Run `gitcellar init` to create one.")]
    IdentityNotFound,

    /// Identity already exists
    #[error("Identity already exists at {0}. Use --force to overwrite.")]
    IdentityExists(String),

    /// Failed to generate key
    #[error("Failed to generate key: {0}")]
    KeyGeneration(String),

    /// Failed to load key
    #[error("Failed to load key: {0}")]
    KeyLoad(String),

    /// Failed to save key
    #[error("Failed to save key: {0}")]
    KeySave(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// No encryption-capable key found
    #[error("No encryption-capable key found in identity")]
    NoEncryptionKey,

    /// No signing-capable key found
    #[error("No signing-capable key found in identity")]
    NoSigningKey,

    /// Invalid password
    #[error("Invalid password")]
    InvalidPassword,

    /// Bundle format error
    #[error("Invalid bundle format: {0}")]
    BundleFormat(String),

    /// Invalid recovery code
    #[error("Invalid recovery code: {0}")]
    InvalidRecoveryCode(String),

    /// Cloud backup not found or missing slot
    #[error("Cloud backup error: {0}")]
    CloudBackup(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Sequoia error
    #[error("OpenPGP error: {0}")]
    OpenPgp(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Broadcast payload / manifest validation error (broadcast-system)
    #[error("Broadcast error: {0}")]
    Broadcast(String),

    /// Other errors
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl From<sequoia_openpgp::Error> for CryptoError {
    fn from(err: sequoia_openpgp::Error) -> Self {
        CryptoError::OpenPgp(err.to_string())
    }
}

impl From<gitcellar_identity::PasskeyError> for CryptoError {
    fn from(err: gitcellar_identity::PasskeyError) -> Self {
        use gitcellar_identity::PasskeyError;
        match err {
            PasskeyError::IdentityNotFound => CryptoError::IdentityNotFound,
            PasskeyError::IdentityExists(path) => CryptoError::IdentityExists(path),
            PasskeyError::KeyGeneration(msg) => CryptoError::KeyGeneration(msg),
            PasskeyError::KeyLoad(msg) => CryptoError::KeyLoad(msg),
            PasskeyError::KeySave(msg) => CryptoError::KeySave(msg),
            PasskeyError::InvalidRecoveryCode(msg) => CryptoError::InvalidRecoveryCode(msg),
            PasskeyError::NoActiveUser => CryptoError::IdentityNotFound,
            PasskeyError::UserNotFound(_) => CryptoError::IdentityNotFound,
            PasskeyError::Io(e) => CryptoError::Io(e),
            PasskeyError::OpenPgp(msg) => CryptoError::OpenPgp(msg),
            PasskeyError::Other(msg) => CryptoError::Other(anyhow::anyhow!("{}", msg)),
            // Map other auth-related errors to generic form
            PasskeyError::InvalidPublicKey(msg) => CryptoError::KeyLoad(msg),
            PasskeyError::InvalidSignature => CryptoError::Other(anyhow::anyhow!("Invalid signature")),
            PasskeyError::InvalidMachineId => CryptoError::Other(anyhow::anyhow!("Invalid machine ID")),
            PasskeyError::ChallengeExpired => CryptoError::Other(anyhow::anyhow!("Challenge expired")),
            PasskeyError::InvalidToken => CryptoError::Other(anyhow::anyhow!("Invalid token")),
            PasskeyError::TokenExpired => CryptoError::Other(anyhow::anyhow!("Token expired")),
            PasskeyError::CredentialStore(msg) => CryptoError::Other(anyhow::anyhow!("Credential store: {}", msg)),
        }
    }
}
