//! # vault-core
//!
//! Cross-platform encrypted backup library providing:
//!
//! - **Content-defined chunking** for efficient deduplication
//! - **GPG/AES encryption** for zero-knowledge security
//! - **S3-compatible storage** backends (B2, Wasabi, MinIO, AWS S3)
//!
//! ## Overview
//!
//! vault-core is designed to be shared across multiple applications that need
//! encrypted cloud backup functionality:
//!
//! - **GitCellar**: Encrypted Git repository hosting
//! - **Foldergami**: Vantage Drive encrypted backup
//! - **Vetiqbox**: Dropbox-like encrypted file sync
//!
//! ## Quick Start (Rust)
//!
//! ```rust,no_run
//! use vault_core::{ChunkEngine, ChunkConfig, EncryptionEngine};
//! use vault_core::encryption::AesEncryptionEngine;
//! use vault_core::storage::{FileStorage, StorageBackend};
//!
//! # async fn example() -> vault_core::error::VaultResult<()> {
//! // 1. Chunk the data
//! let chunker = ChunkEngine::new(ChunkConfig::default());
//! let data = std::fs::read("large_file.bin")?;
//! let chunks = chunker.chunk_data(&data)?;
//!
//! // 2. Encrypt each chunk
//! let key = AesEncryptionEngine::generate_key();
//! let encryptor = AesEncryptionEngine::new(&key)?;
//! let mut encrypted_data = Vec::new();
//! for chunk in &chunks {
//!     encrypted_data = encryptor.encrypt_chunk(chunk)?;
//! }
//!
//! // 3. Upload to cloud storage
//! let storage = FileStorage::new("/tmp/vault-storage")?;
//! storage.upload("chunks/abc123", &encrypted_data).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - `gpg` (default): Enable GPG/OpenPGP encryption via Sequoia
//! - `aes-only`: AES-256-GCM encryption without GPG dependency
//! - `ffi`: Enable C-compatible FFI exports for cross-language use
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                      vault-core                         │
//! ├─────────────────────────────────────────────────────────┤
//! │  chunking     │  Content-defined chunking (CDC)         │
//! │  encryption   │  GPG or AES-256-GCM encryption          │
//! │  storage      │  S3-compatible storage backends         │
//! │  ffi          │  C-compatible exports (optional)        │
//! └─────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

// Core modules
pub mod chunking;
pub mod encryption;
pub mod storage;

// Error types
pub mod error;

// FFI exports (when feature enabled)
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export main types at crate root for convenience
pub use chunking::{Chunk, ChunkConfig, ChunkEngine, ChunkMetadata, StreamChunker};
pub use encryption::EncryptionEngine;
pub use error::{VaultError, VaultResult};
pub use storage::{FileStorage, StorageBackend};

// Conditional re-exports based on features
#[cfg(feature = "gpg")]
pub use encryption::GpgEncryptionEngine;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for convenient imports
///
/// ```rust
/// use vault_core::prelude::*;
/// ```
pub mod prelude {
    pub use crate::chunking::{Chunk, ChunkConfig, ChunkEngine, ChunkMetadata, StreamChunker};
    pub use crate::encryption::EncryptionEngine;
    pub use crate::error::{VaultError, VaultResult};
    pub use crate::storage::{FileStorage, StorageBackend};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_prelude_imports() {
        // Verify prelude exports compile
        use crate::prelude::*;
        let _ = ChunkConfig::default();
    }
}
