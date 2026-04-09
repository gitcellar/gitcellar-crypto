//! Local filesystem storage backend
//!
//! Stores encrypted data on the local filesystem. Primarily used for
//! development and testing, but can also serve as a local cache.

use super::StorageBackend;
use crate::error::{VaultError, VaultResult};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

/// Local filesystem storage backend
///
/// Stores files in a directory structure matching the storage paths.
///
/// # Example
///
/// ```rust,no_run
/// use vault_core::storage::{FileStorage, StorageBackend};
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = FileStorage::new("/tmp/vault-storage")?;
///
/// // Stores to /tmp/vault-storage/chunks/abc123
/// storage.upload("chunks/abc123", b"data").await?;
/// # Ok(())
/// # }
/// ```
pub struct FileStorage {
    root: PathBuf,
}

impl FileStorage {
    /// Create a new file storage backend
    ///
    /// # Arguments
    /// * `root` - Root directory for storage
    ///
    /// # Errors
    /// Returns error if the directory cannot be created.
    pub fn new<P: AsRef<Path>>(root: P) -> VaultResult<Self> {
        let root = root.as_ref().to_path_buf();

        // Create root directory if it doesn't exist
        std::fs::create_dir_all(&root).map_err(|e| {
            VaultError::Storage(format!(
                "Failed to create storage directory {:?}: {}",
                root, e
            ))
        })?;

        info!("Initialized file storage at {:?}", root);

        Ok(Self { root })
    }

    /// Get the full filesystem path for a storage path
    fn full_path(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }

    /// Get the root directory
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[async_trait::async_trait]
impl StorageBackend for FileStorage {
    async fn upload(&self, path: &str, data: &[u8]) -> VaultResult<()> {
        let full_path = self.full_path(path);

        // Create parent directories
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                VaultError::Storage(format!("Failed to create directory {:?}: {}", parent, e))
            })?;
        }

        // Write file
        fs::write(&full_path, data).await.map_err(|e| {
            VaultError::Storage(format!("Failed to write {:?}: {}", full_path, e))
        })?;

        debug!("Uploaded {} bytes to {:?}", data.len(), full_path);

        Ok(())
    }

    async fn download(&self, path: &str) -> VaultResult<Vec<u8>> {
        let full_path = self.full_path(path);

        let data = fs::read(&full_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::Storage(format!("File not found: {:?}", full_path))
            } else {
                VaultError::Storage(format!("Failed to read {:?}: {}", full_path, e))
            }
        })?;

        debug!("Downloaded {} bytes from {:?}", data.len(), full_path);

        Ok(data)
    }

    async fn exists(&self, path: &str) -> VaultResult<bool> {
        let full_path = self.full_path(path);
        Ok(full_path.exists())
    }

    async fn list(&self, prefix: &str) -> VaultResult<Vec<String>> {
        let search_path = self.full_path(prefix);
        let mut results = Vec::new();

        // If the prefix points to a directory, list its contents
        // Otherwise, list files in the parent that start with the prefix
        let (dir_path, file_prefix) = if search_path.is_dir() {
            (search_path, String::new())
        } else {
            let parent = search_path.parent().unwrap_or(&self.root).to_path_buf();
            let file_name = search_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            (parent, file_name)
        };

        if !dir_path.exists() {
            return Ok(results);
        }

        let mut entries = fs::read_dir(&dir_path).await.map_err(|e| {
            VaultError::Storage(format!("Failed to read directory {:?}: {}", dir_path, e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            VaultError::Storage(format!("Failed to read entry: {}", e))
        })? {
            let file_name = entry.file_name().to_string_lossy().to_string();

            if file_prefix.is_empty() || file_name.starts_with(&file_prefix) {
                // Convert back to storage path
                let entry_path = entry.path();
                if let Ok(relative) = entry_path.strip_prefix(&self.root) {
                    results.push(relative.to_string_lossy().to_string().replace('\\', "/"));
                }
            }
        }

        Ok(results)
    }

    async fn delete(&self, path: &str) -> VaultResult<()> {
        let full_path = self.full_path(path);

        fs::remove_file(&full_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // Not an error if file doesn't exist
                return VaultError::Storage(format!("File not found: {:?}", full_path));
            }
            VaultError::Storage(format!("Failed to delete {:?}: {}", full_path, e))
        })?;

        debug!("Deleted {:?}", full_path);

        Ok(())
    }

    fn backend_name(&self) -> &str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_upload_download() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        let data = b"Hello, storage!";
        storage.upload("test/file.bin", data).await.unwrap();

        let downloaded = storage.download("test/file.bin").await.unwrap();
        assert_eq!(data.to_vec(), downloaded);
    }

    #[tokio::test]
    async fn test_exists() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        assert!(!storage.exists("nonexistent").await.unwrap());

        storage.upload("exists.txt", b"data").await.unwrap();
        assert!(storage.exists("exists.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        storage.upload("to_delete.txt", b"data").await.unwrap();
        assert!(storage.exists("to_delete.txt").await.unwrap());

        storage.delete("to_delete.txt").await.unwrap();
        assert!(!storage.exists("to_delete.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_list() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        storage.upload("chunks/a.bin", b"a").await.unwrap();
        storage.upload("chunks/b.bin", b"b").await.unwrap();
        storage.upload("other/c.bin", b"c").await.unwrap();

        let chunks = storage.list("chunks/").await.unwrap();
        assert_eq!(chunks.len(), 2);

        let all = storage.list("").await.unwrap();
        assert!(all.len() >= 2); // At least chunks/ and other/
    }

    #[tokio::test]
    async fn test_nested_paths() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        let path = "deeply/nested/path/to/file.bin";
        storage.upload(path, b"nested").await.unwrap();

        let data = storage.download(path).await.unwrap();
        assert_eq!(b"nested".to_vec(), data);
    }

    #[tokio::test]
    async fn test_download_nonexistent() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        let result = storage.download("does_not_exist.bin").await;
        assert!(result.is_err());
    }
}
