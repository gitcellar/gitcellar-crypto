//! # vault-core
//!
//! Cross-platform encrypted backup library providing:
//!
//! - **Content-defined chunking** for efficient deduplication
//! - **XChaCha20-Poly1305 chunk sealing** under a per-repo content key, with each
//!   chunk's identity bound in as AEAD associated data (`XChaChaChunkEngine`).
//!   AES-256-GCM remains only for the passphrase/FFI helper — not the chunk path
//! - **S3-compatible storage** backends (B2, Wasabi, MinIO, AWS S3)
//!
//! ## Overview
//!
//! vault-core is designed to be shared across multiple applications that need
//! encrypted cloud backup functionality:
//!
//! - **GitCellar**: encrypted Git repository hosting (Rust)
//! - .NET consumers, through the C bindings and the `VaultCore.Native` wrapper
//!
//! ## Quick Start (Rust)
//!
//! ```rust,no_run
//! use vault_core::{ChunkAad, ChunkConfig, ChunkEngine, ChunkKeying, EncryptionEngine};
//! use vault_core::encryption::XChaChaChunkEngine;
//! use vault_core::storage::{FileStorage, StorageBackend};
//!
//! # async fn example() -> vault_core::error::VaultResult<()> {
//! // Per-repo keys. In practice each is HKDF-SHA256 of the per-repo root key
//! // K_repo under its own info string; gitcellar-crypto derives them.
//! let k_repo = [0u8; 32];
//! let keying = ChunkKeying::derive(&[1u8; 32], &[2u8; 32]); // boundary key, naming key
//!
//! // The repository's immutable id (never its owner/name, which a rename
//! // changes) and the repository key version that seals.
//! let repo_uid = "5f0c9e7a2b1d4c3e8f6a0b9c7d2e1f30";
//! let key_version = 1;
//!
//! // 1. Keyed chunking: per-repo boundaries and HMAC-SHA256 chunk names
//! let chunker = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying);
//! let data = std::fs::read("large_file.bin")?;
//! let chunks = chunker.chunk_data(&data)?;
//!
//! // 2. Seal each chunk (XChaCha20-Poly1305, chunk format v3). Its identity is
//! //    bound into the AEAD as associated data (H-1), so a stored blob cannot be
//! //    spliced or substituted under another identity or key version.
//! let encryptor = XChaChaChunkEngine::new(&k_repo)?;
//! let storage = FileStorage::new("/tmp/vault-storage")?;
//! for chunk in &chunks {
//!     let aad = ChunkAad::content(repo_uid, &chunk.hash, key_version, chunk.size as u64)?;
//!     let sealed = encryptor.encrypt_chunk(chunk, &aad)?;
//!
//!     // 3. Upload to storage under the chunk's keyed name
//!     storage.upload(&format!("chunks/{}", chunk.hash), &sealed).await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - `gpg`: retained no-op (the GPG-per-chunk engine was retired, R-1; vault-core
//!   no longer contains OpenPGP code)
//! - `aes-only`: no-op, retained for compatibility (the AES passphrase/FFI helper is always built)
//! - `ffi`: Enable C-compatible FFI exports for cross-language use
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                      vault-core                         │
//! ├─────────────────────────────────────────────────────────┤
//! │  chunk_format │  Version-byte registry + dispatch (F6)  │
//! │  chunking     │  Content-defined chunking (CDC)         │
//! │  encryption   │  XChaCha20-Poly1305 chunk AEAD (F2)     │
//! │  storage      │  S3-compatible storage backends         │
//! │  ffi          │  C-compatible exports (optional)        │
//! └─────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

// Core modules
pub mod chunk_format;
pub mod chunking;
pub mod encryption;
pub mod pack;
pub mod storage;

// Error types
pub mod error;

// FFI exports (when feature enabled)
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export main types at crate root for convenience
pub use chunk_format::{ChunkAad, ChunkFormatVersion, V1_XCHACHA20_POLY1305, V2_KEYED_CDC_NAMING};
pub use chunking::{Chunk, ChunkConfig, ChunkEngine, ChunkKeying, ChunkMetadata, StreamChunker};
pub use encryption::{EncryptionEngine, XChaChaChunkEngine};
pub use pack::{pack_chunks, slice_chunk, BuiltPack, PackLocation, PackSet, DEFAULT_TARGET_PACK_SIZE};
pub use error::{VaultError, VaultResult};
pub use storage::{FileStorage, StorageBackend};

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
