//! Storage backend abstraction for encrypted data
//!
//! This module provides a unified interface for different storage backends:
//!
//! - **FileStorage**: Local filesystem (development/testing)
//! - **S3Storage**: S3-compatible cloud storage (B2, Wasabi, MinIO, AWS S3)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    StorageBackend                       │
//! │                      (trait)                            │
//! └─────────────────────────────────────────────────────────┘
//!              │                        │
//!    ┌─────────▼─────────┐    ┌─────────▼─────────┐
//!    │    FileStorage    │    │     S3Storage     │
//!    │   (filesystem)    │    │   (B2/Wasabi/S3)  │
//!    └───────────────────┘    └───────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use vault_core::storage::{FileStorage, StorageBackend};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let storage = FileStorage::new("/tmp/vault-storage")?;
//!
//! // Upload
//! storage.upload("chunks/abc123", b"encrypted data").await?;
//!
//! // Download
//! let data = storage.download("chunks/abc123").await?;
//!
//! // Check existence
//! let exists = storage.exists("chunks/abc123").await?;
//! # Ok(())
//! # }
//! ```

use crate::error::VaultResult;

/// Storage backend trait
///
/// All storage backends must implement this trait for a uniform API.
/// Implementations must be Send + Sync for use in async contexts.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Upload data to storage
    ///
    /// # Arguments
    /// * `path` - Storage path/key (e.g., "chunks/abc123")
    /// * `data` - Raw bytes to store
    async fn upload(&self, path: &str, data: &[u8]) -> VaultResult<()>;

    /// Download data from storage
    ///
    /// # Arguments
    /// * `path` - Storage path/key
    ///
    /// # Returns
    /// The stored bytes
    async fn download(&self, path: &str) -> VaultResult<Vec<u8>>;

    /// Check if path exists in storage
    ///
    /// # Arguments
    /// * `path` - Storage path/key
    async fn exists(&self, path: &str) -> VaultResult<bool>;

    /// List files with a prefix
    ///
    /// # Arguments
    /// * `prefix` - Path prefix to filter by (e.g., "chunks/")
    ///
    /// # Returns
    /// List of matching paths
    async fn list(&self, prefix: &str) -> VaultResult<Vec<String>>;

    /// Delete a file from storage
    ///
    /// # Arguments
    /// * `path` - Storage path/key
    async fn delete(&self, path: &str) -> VaultResult<()>;

    /// Get storage backend name (for logging)
    fn backend_name(&self) -> &str;
}

// Sub-modules
mod file;
mod s3;

// Re-export public types
pub use file::FileStorage;
pub use s3::{S3Config, S3Storage};
